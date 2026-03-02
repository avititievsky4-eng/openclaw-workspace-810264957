#!/usr/bin/env python3
import argparse
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
    cap = pcapy.open_live(args.iface, 65535, 1, 1)
    cap.setfilter(f'tcp port {args.port}')

    seen = set()
    responses = 0
    stop = False

    def capture_loop():
        nonlocal responses
        while not stop:
            try:
                _hdr, data = cap.next()
                if not data:
                    continue
                m = GET_RE.search(data)
                if m:
                    seen.add(int(m.group(1)))
                if b'HTTP/1.' in data and b' 200 ' in data:
                    responses += 1
            except Exception:
                pass

    t0 = time.perf_counter()
    th = threading.Thread(target=capture_loop, daemon=True)
    th.start()
    time.sleep(0.3)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.5)
    stop = True
    th.join(timeout=2)
    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'libpcap-http',
        'requests_ok': requests_ok,
        'http_get_seen': len(seen),
        'http_200_seen': responses,
        'get_seen_ratio': (len(seen) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
