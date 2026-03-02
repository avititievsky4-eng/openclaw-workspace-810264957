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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)

    prog = (
        'tracepoint:sock:inet_sock_set_state '
        '/args->protocol==6 && args->newstate==1/ '
        '{ @http_sessions = count(); }'
    )

    t0 = time.perf_counter()
    p = subprocess.Popen(['bpftrace', '-e', prog], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    out_q: queue.Queue = queue.Queue(maxsize=10000)
    stop = False

    def producer(stream):
        while not stop:
            line = stream.readline()
            if not line:
                break
            try:
                out_q.put_nowait(line)
            except queue.Full:
                pass

    pth1 = threading.Thread(target=producer, args=(p.stdout,), daemon=True)
    pth2 = threading.Thread(target=producer, args=(p.stderr,), daemon=True)
    pth1.start(); pth2.start()

    time.sleep(0.35)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.4)

    stop = True
    p.send_signal(signal.SIGINT)
    try:
        out_rem, err_rem = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        out_rem, err_rem = p.communicate(timeout=3)

    pth1.join(timeout=2); pth2.join(timeout=2)

    text_parts = []
    while not out_q.empty():
        text_parts.append(out_q.get())
    text = ''.join(text_parts) + (out_rem or '') + (err_rem or '')
    sessions = 0
    m = re.search(r'@http_sessions:\s*(\d+)', text)
    if m:
        sessions = int(m.group(1))

    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'ebpf-http-session',
        'requests_ok': requests_ok,
        'http_sessions_established': sessions,
        'session_to_request_ratio': (sessions / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'note': 'Producer/consumer pipeline over bpftrace output; metric is TCP ESTABLISHED events.',
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
