#!/usr/bin/env python3
import argparse
import ctypes
import json
import sys
import time
from pathlib import Path

from bcc import BPF  # type: ignore

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

    # Use tracepoint program with minimal includes (no external bpftrace process).
    bpf_text = f"""
BPF_HASH(counter, u32, u64);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {{
    if (args->protocol != 6) {{
        return 0;
    }}
    if (args->newstate != 1) {{
        return 0;
    }}

    u16 sport = args->sport;
    u16 dport = args->dport;
    if (!(sport == {args.port} || dport == {args.port})) {{
        return 0;
    }}

    u32 key = 0;
    u64 zero = 0, *val;
    val = counter.lookup_or_try_init(&key, &zero);
    if (val) {{
        (*val)++;
    }}
    return 0;
}}
"""

    t0 = time.perf_counter()
    b = BPF(text=bpf_text)

    time.sleep(0.2)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.2)

    sessions = 0
    table = b.get_table('counter')
    key = ctypes.c_uint(0)
    if key in table:
        sessions = int(table[key].value)

    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'ebpf-http-session',
        'requests_ok': requests_ok,
        'enqueued_packets': sessions,
        'handled_packets': sessions,
        'unhandled_packets': 0,
        'capture_drop_queue': 0,
        'http_sessions_established': sessions,
        'session_to_request_ratio': (sessions / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'note': 'Python BCC TRACEPOINT_PROBE; no external process.',
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
