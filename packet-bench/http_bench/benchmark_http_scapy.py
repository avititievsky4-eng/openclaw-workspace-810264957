#!/usr/bin/env python3
"""Scapy-based HTTP benchmark.
Captures packets with Scapy, parses HTTP GETs, and tracks files loaded per session.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import json
import multiprocessing as mp
import queue
import re
import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load
from scapy.all import sniff, Raw  # type: ignore

GET_RE = re.compile(br'GET /(page\?sid=(\d+)|asset\?sid=(\d+)&i=\d+)')


def cap_worker(iface: str, port: int, run_for: float, q: mp.Queue):
    pkt_q: queue.Queue = queue.Queue(maxsize=30000)
    seen = set()
    session_files = {}
    responses = 0
    stop = False
    dropped = 0
    enqueued = 0
    handled = 0
    done_sniff = False

    lock = threading.Lock()

    def consumer():
        nonlocal responses, handled
        while True:
            try:
                data = pkt_q.get(timeout=0.05)
            except queue.Empty:
                if done_sniff and pkt_q.empty():
                    break
                continue
            with lock:
                handled += 1
            m = GET_RE.search(data)
            if m:
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
            if b'HTTP/1.' in data and b' 200 ' in data:
                responses += 1

    cth = threading.Thread(target=consumer, daemon=True)
    cth.start()

    def on_pkt(pkt):
        nonlocal dropped, enqueued
        if Raw in pkt:
            data = bytes(pkt[Raw].load)
            try:
                pkt_q.put_nowait(data)
                enqueued += 1
            except queue.Full:
                dropped += 1

    sniff(iface=iface, filter=f'tcp port {port}', prn=on_pkt, store=False, timeout=run_for)
    done_sniff = True

    # wait for full drain
    deadline = time.time() + 10
    while time.time() < deadline:
        if pkt_q.empty() and handled >= enqueued:
            break
        time.sleep(0.01)

    stop = True
    cth.join(timeout=5)
    session_payload = {
        sid: {
            'files': sorted(files),
            'loaded_count': len(files),
            'min20_ok': len(files) >= 20,
        }
        for sid, files in session_files.items()
    }
    q.put((sorted(seen), session_payload, responses, dropped, enqueued, handled))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    q = mp.Queue()
    p = mp.Process(target=cap_worker, args=(args.iface, args.port, args.duration + 1.5, q), daemon=True)

    t0 = time.perf_counter()
    p.start()
    time.sleep(0.3)
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    requests_ok = load_stats['requests_ok']
    sessions_ok = load_stats.get('sessions_ok', 0)
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')
    p.join(timeout=20)
    t1 = time.perf_counter()
    server.shutdown()

    seen_paths, sniff_sessions, responses, dropped, enqueued, handled = q.get() if not q.empty() else ([], {}, 0, 0, 0, 0)
    seen = len(set(seen_paths))
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
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    mp.set_start_method('fork')
    main()
