#!/usr/bin/env python3
import argparse
import json
import queue
import re
import sys
import threading
import time
from pathlib import Path

import pcap  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load

GET_RE = re.compile(br'GET /bench\?id=(\d+)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)

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
                ids.add(int(m.group(1)))
            if b'HTTP/1.' in pkt and b' 200 OK' in pkt:
                responses += 1

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.3)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)

    stop = True
    pth.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        if qpk.empty() and handled >= enq and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)
    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'pypcap-http',
        'requests_ok': requests_ok,
        'enqueued_packets': enq,
        'handled_packets': handled,
        'unhandled_packets': max(0, enq - handled),
        'capture_drop_queue': drop,
        'http_get_seen': len(ids),
        'http_200_seen': responses,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
