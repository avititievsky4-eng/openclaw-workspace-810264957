#!/usr/bin/env python3
"""tcpdump text-stream HTTP benchmark.
Parses live tcpdump output and builds per-session file tracking from sniffed GET paths.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import json
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map


def analyze_tcp_http_pcap_inline(pcap_path: str, server_port: int = 18080) -> dict:
    """Native Python PCAP parse: TCP handshake counters + simple stream reassembly."""
    import struct
    try:
        syn_n = synack_n = ack_n = 0
        c2s = {}
        s2c = {}

        with open(pcap_path, 'rb') as f:
            gh = f.read(24)
            if len(gh) < 24:
                return {'error': 'bad pcap global header'}
            magic = gh[:4]
            le = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
            ph_fmt = ('<' if le else '>') + 'IIII'

            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(ph_fmt, ph)
                pkt = f.read(incl_len)
                if len(pkt) < 14 + 20:
                    continue

                eth_type = int.from_bytes(pkt[12:14], 'big')
                if eth_type != 0x0800:
                    continue
                ip_off = 14
                ihl = (pkt[ip_off] & 0x0F) * 4
                if len(pkt) < ip_off + ihl + 20:
                    continue
                if pkt[ip_off + 9] != 6:
                    continue

                src_ip = pkt[ip_off + 12:ip_off + 16]
                dst_ip = pkt[ip_off + 16:ip_off + 20]
                tcp_off = ip_off + ihl
                sport = int.from_bytes(pkt[tcp_off:tcp_off + 2], 'big')
                dport = int.from_bytes(pkt[tcp_off + 2:tcp_off + 4], 'big')
                seq = int.from_bytes(pkt[tcp_off + 4:tcp_off + 8], 'big')
                flags = pkt[tcp_off + 13]
                data_off = ((pkt[tcp_off + 12] >> 4) & 0xF) * 4
                pay_off = tcp_off + data_off
                payload = pkt[pay_off:] if pay_off <= len(pkt) else b''

                if dport == server_port:
                    flow = (src_ip, sport, dst_ip, dport)
                    dir_c2s = True
                elif sport == server_port:
                    flow = (dst_ip, dport, src_ip, sport)
                    dir_c2s = False
                else:
                    continue

                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                if dir_c2s and syn and not ack:
                    syn_n += 1
                elif (not dir_c2s) and syn and ack:
                    synack_n += 1
                elif dir_c2s and ack and not syn:
                    ack_n += 1

                if payload:
                    if dir_c2s:
                        c2s.setdefault(flow, {})[seq] = payload
                    else:
                        s2c.setdefault(flow, {})[seq] = payload

        def rebuild(frags):
            out = b''
            for seq in sorted(frags.keys()):
                out += frags[seq]
            return out

        get_flows = 0
        ok_flows = 0
        for flow in (set(c2s.keys()) | set(s2c.keys())):
            req = rebuild(c2s.get(flow, {}))
            rsp = rebuild(s2c.get(flow, {}))
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

GET_RE = re.compile(r'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


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

    cmd = ['tcpdump', '-i', args.iface, '-n', '-s0', '-A', '-l', f'tcp port {args.port}']
    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='ignore')

    line_q: queue.Queue = queue.Queue(maxsize=100000)
    ids = set()
    responses = 0
    stream_buf = []
    dropped = 0
    enqueued = 0
    handled = 0
    stop = False
    producer_done = False

    lock = threading.Lock()

    def producer():
        nonlocal dropped, enqueued, producer_done
        try:
            while not stop:
                line = p.stdout.readline() if p.stdout else ''
                if not line:
                    break
                try:
                    line_q.put_nowait(line)
                    enqueued += 1
                except queue.Full:
                    dropped += 1
        finally:
            producer_done = True

    def consumer():
        nonlocal responses, handled
        while True:
            try:
                line = line_q.get(timeout=0.05)
            except queue.Empty:
                if producer_done and line_q.empty():
                    break
                continue
            with lock:
                handled += 1
            stream_buf.append(line)
            if 'HTTP/1.0 200 OK' in line or 'HTTP/1.1 200 OK' in line:
                responses += 1

    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.4)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok = load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok = load_stats.get('sessions_ok', 0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')

    stop = True
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=6)
    except subprocess.TimeoutExpired:
        # Hard-stop fallback in case capture tool does not terminate on SIGINT.
        p.kill(); p.wait(timeout=3)

    pth.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        if line_q.empty() and handled >= enqueued and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)

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

    # Parse accumulated payload text to detect all GET paths (not just per-line single match).
    blob = ''.join(stream_buf)
    for m in GET_RE.finditer(blob):
        ids.add(m.group(1))

    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions = build_sniff_session_map(ids)
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'tcpdump-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'enqueued_packets': enqueued,
        'handled_packets': handled,
        'unhandled_packets': max(0, enqueued - handled),
        'http_get_seen': len(ids),
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'http_200_seen': responses,
        'capture_drop_queue': dropped,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'tcp_reassembly_check': tcp_reassembly_check,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
