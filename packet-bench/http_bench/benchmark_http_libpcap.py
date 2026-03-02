#!/usr/bin/env python3
import argparse
import json
import queue
import re
import sys
import threading
import time
from pathlib import Path

import pcapy  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load

GET_RE = re.compile(br'GET /bench\?id=(\d+)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    cap = pcapy.open_live(args.iface, 262144, 1, 0)
    cap.setfilter(f'tcp port {args.port}')

    pkt_q: queue.Queue = queue.Queue(maxsize=20000)
    seen = set()
    responses = 0
    dropped = 0
    stop = False

    def producer():
        nonlocal dropped
        while not stop:
            try:
                _hdr, data = cap.next()
                if not data:
                    continue
                try:
                    pkt_q.put_nowait(data)
                except queue.Full:
                    dropped += 1
            except Exception:
                pass

    def consumer():
        nonlocal responses
        while not stop or not pkt_q.empty():
            try:
                data = pkt_q.get(timeout=0.05)
            except queue.Empty:
                continue
            m = GET_RE.search(data)
            if m:
                seen.add(int(m.group(1)))
            if b'HTTP/1.' in data and b' 200 ' in data:
                responses += 1

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()
    time.sleep(0.3)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.5)
    stop = True
    pth.join(timeout=2); cth.join(timeout=3)
    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'libpcap-http',
        'requests_ok': requests_ok,
        'http_get_seen': len(seen),
        'http_200_seen': responses,
        'capture_drop_queue': dropped,
        'get_seen_ratio': (len(seen) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
