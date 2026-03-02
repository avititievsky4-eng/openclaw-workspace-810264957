#!/usr/bin/env python3
import argparse
import collections
import json
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

    # Faster producer->consumer channel than Queue for hot path
    dq = collections.deque(maxlen=120000)
    cv = threading.Condition()

    seen = set()
    responses = 0
    stop = False

    captured_packets_total = 0
    enqueued_packets = 0
    dropped_queue = 0

    def producer():
        nonlocal captured_packets_total, enqueued_packets, dropped_queue

        def cb(_hdr, data):
            nonlocal captured_packets_total, enqueued_packets, dropped_queue
            if not data:
                return
            captured_packets_total += 1
            with cv:
                if len(dq) >= dq.maxlen:
                    dropped_queue += 1
                else:
                    dq.append(data)
                    enqueued_packets += 1
                    cv.notify()

        while not stop:
            try:
                # big batches to keep capture side hot
                cap.dispatch(8192, cb)
            except Exception:
                pass

    seen_lock = threading.Lock()
    resp_lock = threading.Lock()

    def consumer():
        nonlocal responses
        local_seen = set()
        local_resp = 0

        while True:
            with cv:
                while not dq and not stop:
                    cv.wait(timeout=0.05)
                if not dq and stop:
                    break
                data = dq.popleft() if dq else None

            if not data:
                continue

            m = GET_RE.search(data)
            if m:
                local_seen.add(int(m.group(1)))
            if b'HTTP/1.' in data and b' 200 ' in data:
                local_resp += 1

        if local_seen:
            with seen_lock:
                seen.update(local_seen)
        if local_resp:
            with resp_lock:
                responses += local_resp

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    consumers = [threading.Thread(target=consumer, daemon=True) for _ in range(2)]
    pth.start()
    for c in consumers:
        c.start()

    time.sleep(0.25)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.4)

    stop = True
    with cv:
        cv.notify_all()

    pth.join(timeout=2)
    for c in consumers:
        c.join(timeout=3)

    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'libpcap-http',
        'requests_ok': requests_ok,
        'captured_packets_total': captured_packets_total,
        'enqueued_packets': enqueued_packets,
        'capture_drop_queue': dropped_queue,
        'http_get_seen': len(seen),
        'http_200_seen': responses,
        'get_seen_ratio': (len(seen) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
