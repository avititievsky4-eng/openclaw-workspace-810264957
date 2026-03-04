#!/usr/bin/env python3
import argparse
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

GET_RE = re.compile(r'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)

    cmd = ['tcpdump', '-i', args.iface, '-n', '-s0', '-A', '-l', f'tcp port {args.port}']
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='ignore')

    line_q: queue.Queue = queue.Queue(maxsize=100000)
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
            m = GET_RE.search(line)
            if m:
                ids.add(m.group(1))
            if 'HTTP/1.0 200 OK' in line or 'HTTP/1.1 200 OK' in line:
                responses += 1

    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.4)
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    requests_ok = load_stats['requests_ok']
    sessions_ok = load_stats.get('sessions_ok', 0)
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')

    stop = True
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=6)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(timeout=3)

    pth.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        if line_q.empty() and handled >= enqueued and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)

    t1 = time.perf_counter()
    server.shutdown()

    sniff_sessions = build_sniff_session_map(ids)
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
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
