#!/usr/bin/env python3
import argparse
import json
import queue
import re
import socket
import sys
import threading
import time
from pathlib import Path

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
                ids.add(int(m.group(1)))
            if b'HTTP/1.' in frame and b' 200 OK' in frame:
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
        if pkt_q.empty() and handled >= enqueued and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)
    t1 = time.perf_counter()

    s.close()
    server.shutdown()
    result = {
        'tool': 'rawsocket-http',
        'requests_ok': requests_ok,
        'enqueued_packets': enqueued,
        'handled_packets': handled,
        'unhandled_packets': max(0, enqueued - handled),
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
