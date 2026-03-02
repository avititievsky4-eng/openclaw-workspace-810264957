#!/usr/bin/env python3
import argparse
import collections
import json
import re
import struct
import sys
import threading
import time
from pathlib import Path

import pcapy  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load

GET_RE = re.compile(br'GET /bench\?id=(\d+)')


def parse_ipv4_tcp(frame: bytes):
    if len(frame) < 14 + 20:
        return None
    eth_type = int.from_bytes(frame[12:14], 'big')
    if eth_type != 0x0800:
        return None
    ip_off = 14
    ihl = (frame[ip_off] & 0x0F) * 4
    if len(frame) < ip_off + ihl + 20:
        return None
    proto = frame[ip_off + 9]
    if proto != 6:
        return None

    src_ip = frame[ip_off + 12:ip_off + 16]
    dst_ip = frame[ip_off + 16:ip_off + 20]

    tcp_off = ip_off + ihl
    src_port = int.from_bytes(frame[tcp_off:tcp_off + 2], 'big')
    dst_port = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
    data_off = ((frame[tcp_off + 12] >> 4) & 0xF) * 4
    payload_off = tcp_off + data_off
    if payload_off > len(frame):
        return None
    payload = frame[payload_off:]
    return src_ip, dst_ip, src_port, dst_port, payload


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

    dq = collections.deque(maxlen=150000)
    cv = threading.Condition()

    seen_get_ids = set()
    seen_resp_markers = set()
    stop = False
    producer_done = False

    captured_packets_total = 0
    enqueued_packets = 0
    handled_packets = 0
    dropped_queue = 0

    # Reassembly buffers per flow direction
    req_streams = {}
    resp_streams = {}

    def producer():
        nonlocal captured_packets_total, enqueued_packets, dropped_queue, producer_done

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

        try:
            while not stop:
                try:
                    cap.dispatch(8192, cb)
                except Exception:
                    pass
        finally:
            producer_done = True
            with cv:
                cv.notify_all()

    seen_lock = threading.Lock()
    handled_lock = threading.Lock()

    def consume_http_from_buffer(buf: bytes, is_request: bool):
        ids = set()
        resp_cnt = 0
        if is_request:
            for m in GET_RE.finditer(buf):
                ids.add(int(m.group(1)))
        else:
            resp_cnt = buf.count(b'HTTP/1.0 200 OK') + buf.count(b'HTTP/1.1 200 OK')
        return ids, resp_cnt

    def consumer():
        nonlocal handled_packets
        local_get = set()
        local_resp_markers = set()
        local_handled = 0

        while True:
            with cv:
                while not dq and not (stop and producer_done):
                    cv.wait(timeout=0.05)
                if not dq and stop and producer_done:
                    break
                frame = dq.popleft() if dq else None

            if not frame:
                continue

            local_handled += 1

            parsed = parse_ipv4_tcp(frame)
            if not parsed:
                continue
            src_ip, dst_ip, src_port, dst_port, payload = parsed
            if not payload:
                continue

            if dst_port == args.port:
                key = (src_ip, src_port, dst_ip, dst_port)
                b = req_streams.get(key, b'') + payload
                if len(b) > 65536:
                    b = b[-65536:]
                ids, _ = consume_http_from_buffer(b, True)
                if ids:
                    local_get.update(ids)
                    # keep tail only after parsing
                    b = b[-2048:]
                req_streams[key] = b

            elif src_port == args.port:
                key = (src_ip, src_port, dst_ip, dst_port)
                b = resp_streams.get(key, b'') + payload
                if len(b) > 65536:
                    b = b[-65536:]
                _, resp_cnt = consume_http_from_buffer(b, False)
                if resp_cnt:
                    # Use flow+count marker to reduce double counting artifacts.
                    local_resp_markers.add((key, resp_cnt, len(b)))
                    b = b[-2048:]
                resp_streams[key] = b

        with handled_lock:
            handled_packets += local_handled

        if local_get or local_resp_markers:
            with seen_lock:
                seen_get_ids.update(local_get)
                seen_resp_markers.update(local_resp_markers)

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    consumers = [threading.Thread(target=consumer, daemon=True) for _ in range(2)]
    pth.start()
    for c in consumers:
        c.start()

    time.sleep(0.25)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)

    # Stop producer first, then wait until queue is fully drained and handled.
    stop = True
    with cv:
        cv.notify_all()

    pth.join(timeout=5)

    drain_deadline = time.perf_counter() + 10.0
    while time.perf_counter() < drain_deadline:
        with cv:
            qlen = len(dq)
        with handled_lock:
            handled_now = handled_packets
        if producer_done and qlen == 0 and handled_now >= enqueued_packets:
            break
        time.sleep(0.01)

    with cv:
        cv.notify_all()

    for c in consumers:
        c.join(timeout=5)

    t1 = time.perf_counter()
    server.shutdown()

    # Approximate HTTP-200 seen from unique markers (still best-effort under loopback duplicates)
    http_200_seen = len(seen_resp_markers)

    result = {
        'tool': 'libpcap-http',
        'requests_ok': requests_ok,
        'captured_packets_total': captured_packets_total,
        'enqueued_packets': enqueued_packets,
        'handled_packets': handled_packets,
        'unhandled_packets': max(0, enqueued_packets - handled_packets),
        'capture_drop_queue': dropped_queue,
        'http_get_seen': len(seen_get_ids),
        'http_200_seen': http_200_seen,
        'get_seen_ratio': (len(seen_get_ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (http_200_seen / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'note': 'Producer-consumer + lightweight TCP stream buffering for better L7 GET detection.'
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
