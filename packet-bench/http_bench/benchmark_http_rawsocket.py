#!/usr/bin/env python3
import argparse
import json
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

    ids = set()
    responses = 0
    stop = False

    def cap_loop():
        nonlocal responses
        while not stop:
            try:
                frame = s.recv(65535)
                m = GET_RE.search(frame)
                if m:
                    ids.add(int(m.group(1)))
                if b'HTTP/1.' in frame and b' 200 OK' in frame:
                    responses += 1
            except TimeoutError:
                pass
            except Exception:
                pass

    t0 = time.perf_counter()
    th = threading.Thread(target=cap_loop, daemon=True)
    th.start()
    time.sleep(0.3)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.4)
    stop = True
    th.join(timeout=2)
    t1 = time.perf_counter()

    s.close()
    server.shutdown()
    result = {
        'tool': 'rawsocket-http',
        'requests_ok': requests_ok,
        'http_get_seen': len(ids),
        'http_200_seen': responses,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
