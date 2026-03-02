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
from common_http import start_http_server, generate_http_load

GET_RE = re.compile(r'GET /bench\?id=(\d+)')


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

    line_q: queue.Queue = queue.Queue(maxsize=50000)
    ids = set()
    responses = 0
    dropped = 0
    stop = False

    def producer():
        nonlocal dropped
        while not stop:
            line = p.stdout.readline() if p.stdout else ''
            if not line:
                break
            try:
                line_q.put_nowait(line)
            except queue.Full:
                dropped += 1

    def consumer():
        nonlocal responses
        while not stop or not line_q.empty():
            try:
                line = line_q.get(timeout=0.05)
            except queue.Empty:
                continue
            m = GET_RE.search(line)
            if m:
                ids.add(int(m.group(1)))
            if 'HTTP/1.0 200 OK' in line or 'HTTP/1.1 200 OK' in line:
                responses += 1

    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.4)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.6)

    stop = True
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=6)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(timeout=3)

    pth.join(timeout=2); cth.join(timeout=3)

    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'tcpdump-http',
        'requests_ok': requests_ok,
        'http_get_seen': len(ids),
        'http_200_seen': responses,
        'capture_drop_queue': dropped,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
