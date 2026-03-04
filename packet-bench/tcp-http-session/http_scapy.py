#!/usr/bin/env python3
"""Scapy-based HTTP benchmark.
Captures packets with Scapy, parses HTTP GETs, and tracks files loaded per session.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import json
import subprocess
import signal
import multiprocessing as mp
import queue
import re
import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load


from scapy.all import sniff, Raw, rdpcap, TCP, IP  # type: ignore

def analyze_tcp_http_pcap_inline(pcap_path: str, server_port: int = 18080) -> dict:
    """Native Scapy TCP handshake + simple seq-order reassembly check."""
    try:
        syn_n = synack_n = ack_n = 0
        c2s = {}
        s2c = {}

        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if IP not in pkt or TCP not in pkt:
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]

            if tcp.dport == server_port:
                flow = (ip.src, tcp.sport, ip.dst, tcp.dport)
                direction = 'c2s'
            elif tcp.sport == server_port:
                flow = (ip.dst, tcp.dport, ip.src, tcp.sport)
                direction = 's2c'
            else:
                continue

            syn = bool(tcp.flags & 0x02)
            ack = bool(tcp.flags & 0x10)
            if direction == 'c2s' and syn and not ack:
                syn_n += 1
            elif direction == 's2c' and syn and ack:
                synack_n += 1
            elif direction == 'c2s' and ack and not syn:
                ack_n += 1

            payload = bytes(tcp.payload or b'')
            if payload:
                if direction == 'c2s':
                    c2s.setdefault(flow, {})[int(tcp.seq)] = payload
                else:
                    s2c.setdefault(flow, {})[int(tcp.seq)] = payload

        def rebuild(frags):
            out = b''
            for seq in sorted(frags.keys()):
                out += frags[seq]
            return out

        get_flows = 0
        ok_flows = 0
        all_flows = set(c2s.keys()) | set(s2c.keys())
        for f in all_flows:
            req = rebuild(c2s.get(f, {}))
            rsp = rebuild(s2c.get(f, {}))
            if b'GET /' in req and b'HTTP/1.' in req:
                get_flows += 1
            if (b'HTTP/1.0 200' in rsp) or (b'HTTP/1.1 200' in rsp):
                ok_flows += 1

        return {
            'tcp_syn_packets': syn_n,
            'tcp_synack_packets': synack_n,
            'tcp_ack_packets': ack_n,
            'tcp_handshake_estimate': min(syn_n, synack_n, ack_n),
            'http_get_flows_after_reassembly': get_flows,
            'http_200_flows_after_reassembly': ok_flows,
        }
    except Exception as e:
        return {'error': str(e)}

GET_RE = re.compile(br'GET /(page\?sid=(\d+)|asset\?sid=(\d+)&i=\d+)')


def cap_worker(iface: str, port: int, run_for: float, q: mp.Queue):
    # Queue between packet-capture callback (producer) and parser thread (consumer).
    pkt_q: queue.Queue = queue.Queue(maxsize=30000)

    # Unique GET paths detected from reassembled request streams.
    seen = set()
    # Per-session map built from reassembled streams: sid -> set(paths).
    session_files = {}
    responses = 0
    req_frags = {}
    rsp_frags = {}
    stop = False
    dropped = 0
    enqueued = 0
    handled = 0
    done_sniff = False

    # Lock protects counters shared between producer/consumer.
    lock = threading.Lock()

    def consumer():
        """Collect per-flow TCP segments, then parse reassembled HTTP data."""
        nonlocal responses, handled
        while True:
            try:
                item = pkt_q.get(timeout=0.05)
            except queue.Empty:
                if done_sniff and pkt_q.empty():
                    break
                continue
            with lock:
                handled += 1

            direction, flow, seq, payload = item
            if not payload:
                continue
            if direction == 'c2s':
                req_frags.setdefault(flow, {})[seq] = payload
            else:
                rsp_frags.setdefault(flow, {})[seq] = payload

    cth = threading.Thread(target=consumer, daemon=True)
    cth.start()

    def on_pkt(pkt):
        """Producer callback: extract flow+seq+payload and enqueue for reassembly."""
        nonlocal dropped, enqueued
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload or b'')
            if tcp.dport == port:
                flow = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
                direction = 'c2s'
            elif tcp.sport == port:
                flow = (ip.dst, int(tcp.dport), ip.src, int(tcp.sport))
                direction = 's2c'
            else:
                return
            try:
                pkt_q.put_nowait((direction, flow, int(tcp.seq), payload))
                enqueued += 1
            except queue.Full:
                dropped += 1

    # Start packet capture on requested interface for the benchmark window.
    sniff(iface=iface, filter=f'tcp port {port}', prn=on_pkt, store=False, timeout=run_for)
    done_sniff = True

    # Wait until consumer drains buffered packets.
    deadline = time.time() + 10
    while time.time() < deadline:
        if pkt_q.empty() and handled >= enqueued:
            break
        time.sleep(0.01)

    stop = True
    cth.join(timeout=5)

    # Parse reassembled streams to extract GET paths and HTTP 200 responses.
    def rebuild(frags):
        out = b''
        for seq in sorted(frags.keys()):
            out += frags[seq]
        return out

    for flow in (set(req_frags.keys()) | set(rsp_frags.keys())):
        req = rebuild(req_frags.get(flow, {}))
        rsp = rebuild(rsp_frags.get(flow, {}))
        for m in GET_RE.finditer(req):
            path = m.group(1).decode('ascii', errors='ignore') if isinstance(m.group(1), (bytes, bytearray)) else m.group(1)
            sid = None
            if m.group(2):
                sid = m.group(2).decode('ascii', errors='ignore') if isinstance(m.group(2), (bytes, bytearray)) else m.group(2)
            elif m.group(3):
                sid = m.group(3).decode('ascii', errors='ignore') if isinstance(m.group(3), (bytes, bytearray)) else m.group(3)
            seen.add(path)
            if sid is not None:
                d = session_files.setdefault(str(sid), set())
                d.add(path)
        responses += rsp.count(b'HTTP/1.0 200') + rsp.count(b'HTTP/1.1 200')

    # Normalize session map into JSON-friendly payload.
    session_payload = {
        sid: {
            'files': sorted(files),
            'loaded_count': len(files),
            'asset_count': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')),
            'min1_asset_ok': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')) >= 1,
            'min2_asset_ok': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')) >= 2,
            'min20_ok': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')) >= 20,
        }
        for sid, files in session_files.items()
    }
    q.put((sorted(seen), session_payload, responses, dropped, enqueued, handled))


def main():
    # Parse CLI arguments for benchmark runtime/capture options.
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    # Start local HTTP server that serves /page and /asset endpoints.
    # Side capture for TCP handshake/reassembly validation.
    track_pcap=tempfile.mktemp(prefix='tcptrack_', suffix='.pcap')
    track_cap=subprocess.Popen(['tcpdump','-i',getattr(args,'iface','lo'),'-n','-s0','-w',track_pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    q = mp.Queue()
    p = mp.Process(target=cap_worker, args=(args.iface, args.port, args.duration + 1.5, q), daemon=True)

    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    p.start()
    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.3)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok = load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok = load_stats.get('sessions_ok', 0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')
    p.join(timeout=20)
    # Stop timer and shutdown local HTTP server for this run.
    # Stop side capture and run TCP reassembly check.
    track_cap.send_signal(signal.SIGINT)
    try:
        track_cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        track_cap.kill(); track_cap.wait(timeout=3)
    tcp_reassembly_check = analyze_tcp_http_pcap_inline(track_pcap, server_port=args.port)
    t1 = time.perf_counter()
    server.shutdown()

    seen_paths, sniff_sessions, responses, dropped, enqueued, handled = q.get() if not q.empty() else ([], {}, 0, 0, 0, 0)
    seen = len(set(seen_paths))
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'scapy-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'enqueued_packets': enqueued,
        'handled_packets': handled,
        'unhandled_packets': max(0, enqueued - handled),
        'http_get_seen': seen,
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'http_200_seen': responses,
        'capture_drop_queue': dropped,
        'get_seen_ratio': (seen / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'tcp_reassembly_check': tcp_reassembly_check,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    mp.set_start_method('fork')
    main()
