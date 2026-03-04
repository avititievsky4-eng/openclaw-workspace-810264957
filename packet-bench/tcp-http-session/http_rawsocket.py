#!/usr/bin/env python3
"""Raw-socket HTTP benchmark.
Processes packets from AF_PACKET and reconstructs per-session loaded files.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import json
import subprocess
import queue
import re
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map


def _run_tshark(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout or ''

def analyze_tcp_http_pcap_inline(pcap_path: str, server_port: int = 18080) -> dict:
    """Inline TCP handshake + HTTP reassembly summary (no external Python file import)."""
    try:
        syn = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.dstport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 0','-T','fields','-e','frame.number'])
        synack = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.srcport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 1','-T','fields','-e','frame.number'])
        ack = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.dstport == {server_port} && tcp.flags.syn == 0 && tcp.flags.ack == 1','-T','fields','-e','frame.number'])

        syn_n = len([x for x in syn.splitlines() if x.strip()])
        synack_n = len([x for x in synack.splitlines() if x.strip()])
        ack_n = len([x for x in ack.splitlines() if x.strip()])

        get_out = _run_tshark(['tshark','-r',pcap_path,'-Y',f'http.request.method == "GET" && tcp.dstport == {server_port}','-T','fields','-e','tcp.stream'])
        ok_out = _run_tshark(['tshark','-r',pcap_path,'-Y',f'http.response.code == 200 && tcp.srcport == {server_port}','-T','fields','-e','tcp.stream'])

        get_streams = {x.strip() for x in get_out.splitlines() if x.strip()}
        ok_streams = {x.strip() for x in ok_out.splitlines() if x.strip()}

        return {
            'tcp_syn_packets': syn_n,
            'tcp_synack_packets': synack_n,
            'tcp_ack_packets': ack_n,
            'tcp_handshake_estimate': min(syn_n, synack_n, ack_n),
            'http_get_streams_after_reassembly': len(get_streams),
            'http_200_streams_after_reassembly': len(ok_streams),
        }
    except Exception as e:
        return {'error': str(e)}

GET_RE = re.compile(br'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


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
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.bind((args.iface, 0))
    s.settimeout(0.01)

    pkt_q: queue.Queue = queue.Queue(maxsize=40000)
    ids = set()
    responses = 0
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
                try:
                    frame = s.recv(65535)
                    try:
                        pkt_q.put_nowait(frame)
                        enqueued += 1
                    except queue.Full:
                        dropped += 1
                except TimeoutError:
                    pass
                except Exception:
                    pass
        finally:
            producer_done = True

    def consumer():
        nonlocal responses, handled
        while True:
            try:
                frame = pkt_q.get(timeout=0.05)
            except queue.Empty:
                if producer_done and pkt_q.empty():
                    break
                continue
            with lock:
                handled += 1
            m = GET_RE.search(frame)
            if m:
                ids.add(m.group(1).decode('ascii', errors='ignore') if isinstance(m.group(1), (bytes, bytearray)) else m.group(1))
            if b'HTTP/1.' in frame and b' 200 OK' in frame:
                responses += 1

    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()
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

    stop = True
    pth.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        if pkt_q.empty() and handled >= enqueued and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)
    t1 = time.perf_counter()

    s.close()
    server.shutdown()
    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions = build_sniff_session_map(ids)
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'rawsocket-http',
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
