#!/usr/bin/env python3
"""pypcap-based HTTP benchmark.
Captures TCP/HTTP traffic and tracks detected files by session id.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import json
import subprocess
import signal
import queue
import re
import sys
import threading
import time
from pathlib import Path

import pcap  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map
from tcp_reassembly_check import analyze_tcp_http_pcap

GET_RE = re.compile(br'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


def main():
    # Parse CLI arguments for benchmark runtime/capture options.
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    # Start local HTTP server that serves /page and /asset endpoints.
    # Side capture for TCP handshake/reassembly validation.
    track_pcap=tempfile.mktemp(prefix='tcptrack_', suffix='.pcap')
    track_cap=subprocess.Popen(['tcpdump','-i',getattr(args,'iface','lo'),'-n','-s0','-w',track_pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)

    pc = pcap.pcap(name=args.iface, snaplen=262144, promisc=True, timeout_ms=1)
    pc.setfilter(f'tcp port {args.port}')

    qpk: queue.Queue = queue.Queue(maxsize=120000)
    ids = set()
    responses = 0
    enq = 0
    handled = 0
    drop = 0
    stop = False
    producer_done = False
    lock = threading.Lock()

    def producer():
        nonlocal enq, drop, producer_done
        try:
            for _ts, pkt in pc:
                if stop:
                    break
                try:
                    qpk.put_nowait(pkt)
                    enq += 1
                except queue.Full:
                    drop += 1
        finally:
            producer_done = True

    def consumer():
        nonlocal responses, handled
        while True:
            try:
                pkt = qpk.get(timeout=0.05)
            except queue.Empty:
                if producer_done and qpk.empty():
                    break
                continue
            with lock:
                handled += 1
            m = GET_RE.search(pkt)
            if m:
                ids.add(m.group(1).decode('ascii', errors='ignore') if isinstance(m.group(1), (bytes, bytearray)) else m.group(1))
            if b'HTTP/1.' in pkt and b' 200 OK' in pkt:
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
        if qpk.empty() and handled >= enq and producer_done:
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
    tcp_reassembly_check = analyze_tcp_http_pcap(track_pcap, server_port=args.port)
    t1 = time.perf_counter()
    server.shutdown()

    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions = build_sniff_session_map(ids)
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'pypcap-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'enqueued_packets': enq,
        'handled_packets': handled,
        'unhandled_packets': max(0, enq - handled),
        'capture_drop_queue': drop,
        'http_get_seen': len(ids),
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'http_200_seen': responses,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'tcp_reassembly_check': tcp_reassembly_check,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
