#!/usr/bin/env python3
"""Raw-socket HTTP benchmark.
Processes packets from AF_PACKET and reconstructs per-session loaded files.

This benchmark uses the shared long-load generator from common_http.py.
"""
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
from common_http import start_http_server, generate_http_load, build_sniff_session_map

GET_RE = re.compile(br'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


def parse_ipv4_tcp_payload(frame: bytes, server_port: int):
    if len(frame) < 14 + 20:
        return None
    if int.from_bytes(frame[12:14], 'big') != 0x0800:
        return None
    ip_off = 14
    ihl = (frame[ip_off] & 0x0F) * 4
    if len(frame) < ip_off + ihl + 20:
        return None
    if frame[ip_off + 9] != 6:
        return None
    tcp_off = ip_off + ihl
    sport = int.from_bytes(frame[tcp_off + 0:tcp_off + 2], 'big')
    dport = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
    if sport != server_port and dport != server_port:
        return None
    data_off = ((frame[tcp_off + 12] >> 4) & 0xF) * 4
    payload_off = tcp_off + data_off
    payload = frame[payload_off:] if payload_off < len(frame) else b''
    return sport, dport, payload


def main():
    # Parse CLI arguments for benchmark runtime/capture options.
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    # Start local HTTP server that serves /page and /asset endpoints.
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
            parsed = parse_ipv4_tcp_payload(frame, args.port)
            if parsed is None:
                continue
            sport, dport, payload = parsed

            m = GET_RE.search(payload)
            if m:
                ids.add(m.group(1).decode('ascii', errors='ignore') if isinstance(m.group(1), (bytes, bytearray)) else m.group(1))
            # Count HTTP 200 only from server->client direction.
            if sport == args.port and b'HTTP/1.' in payload and b' 200 ' in payload:
                responses += 1

    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()
    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.3)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok = load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok = load_stats.get('sessions_ok', 0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')

    stop = True
    pth.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        if pkt_q.empty() and handled >= enqueued and producer_done:
            break
        time.sleep(0.01)

    cth.join(timeout=5)
    t1 = time.perf_counter()

    responses = min(responses, requests_ok)

    s.close()
    server.shutdown()
    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions = build_sniff_session_map(ids)
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'rawsocket-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'enqueued_packets': enqueued,
        'handled_packets': handled,
        'unhandled_packets': max(0, enqueued - handled),
        'http_get_seen': len(ids),
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'http_200_seen': responses,
        'capture_drop_queue': dropped,
        'get_seen_ratio': (len(ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (responses / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
