#!/usr/bin/env python3
import argparse
import json
import re
import signal
import subprocess
import sys
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

    time.sleep(0.4)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.6)

    p.send_signal(signal.SIGINT)
    out = ''
    try:
        out, _ = p.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()

    ids = set(int(m.group(1)) for m in GET_RE.finditer(out))
    responses = out.count('HTTP/1.0 200 OK') + out.count('HTTP/1.1 200 OK')
    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'tcpdump-http',
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
