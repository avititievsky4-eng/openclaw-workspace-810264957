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

GET_RE = re.compile(br'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


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
    if frame[ip_off + 9] != 6:
        return None

    src_ip = frame[ip_off + 12:ip_off + 16]
    dst_ip = frame[ip_off + 16:ip_off + 20]

    tcp_off = ip_off + ihl
    src_port = int.from_bytes(frame[tcp_off:tcp_off + 2], 'big')
    dst_port = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
    seq = int.from_bytes(frame[tcp_off + 4:tcp_off + 8], 'big')
    data_off = ((frame[tcp_off + 12] >> 4) & 0xF) * 4

    payload_off = tcp_off + data_off
    if payload_off > len(frame):
        return None
    payload = frame[payload_off:]
    return src_ip, dst_ip, src_port, dst_port, seq, payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    cap = pcapy.open_live(args.iface, 262144, 1, 1)
    cap.setfilter(f'tcp port {args.port}')

    dq = collections.deque(maxlen=200000)
    cv = threading.Condition()

    stop = False
    producer_done = False

    captured_packets_total = 0
    enqueued_packets = 0
    handled_packets = 0
    dropped_queue = 0

    seen_get_ids = set()
    http_200_seen = 0

    # flow -> {next_seq: int|None, frags: {seq:bytes}, buf: bytes}
    req_streams = {}
    resp_seen_chunks = set()

    def producer():
        nonlocal captured_packets_total, enqueued_packets, dropped_queue, producer_done
        try:
            while not stop:
                try:
                    _hdr, data = cap.next()
                    if not data:
                        continue
                    captured_packets_total += 1
                    with cv:
                        if len(dq) >= dq.maxlen:
                            dropped_queue += 1
                        else:
                            dq.append(data)
                            enqueued_packets += 1
                            cv.notify()
                except Exception:
                    pass
        finally:
            producer_done = True
            with cv:
                cv.notify_all()

    seen_lock = threading.Lock()
    handled_lock = threading.Lock()

    def reassemble_request(flow_key, seq, payload):
        st = req_streams.get(flow_key)
        if st is None:
            st = {'next_seq': None, 'frags': {}, 'buf': b''}
            req_streams[flow_key] = st

        if not payload:
            return b''

        # Initialize sequence cursor on first seen payload.
        if st['next_seq'] is None:
            st['next_seq'] = seq

        ns = st['next_seq']

        # Trim already-consumed overlap (retransmits / duplicates).
        if seq < ns:
            cut = ns - seq
            if cut >= len(payload):
                return b''
            payload = payload[cut:]
            seq = ns

        # Keep latest fragment for a given seq.
        st['frags'][seq] = payload

        emitted = b''
        while ns in st['frags']:
            chunk = st['frags'].pop(ns)
            emitted += chunk
            ns += len(chunk)
        st['next_seq'] = ns

        if emitted:
            st['buf'] += emitted
            if len(st['buf']) > 131072:
                st['buf'] = st['buf'][-131072:]
            out = st['buf']
            st['buf'] = st['buf'][-4096:]
            return out
        return b''

    def consumer():
        nonlocal handled_packets, http_200_seen
        local_get = set()
        local_200 = 0
        local_handled = 0

        while True:
            with cv:
                while not dq and not stop:
                    cv.wait(timeout=0.05)
                if not dq and stop:
                    break
                frame = dq.popleft() if dq else None

            if not frame:
                continue
            local_handled += 1

            parsed = parse_ipv4_tcp(frame)
            if not parsed:
                continue
            src_ip, dst_ip, src_port, dst_port, seq, payload = parsed
            if not payload:
                continue

            if dst_port == args.port:
                flow = (src_ip, src_port, dst_ip, dst_port)
                stream_data = reassemble_request(flow, seq, payload)
                if stream_data:
                    for m in GET_RE.finditer(stream_data):
                        local_get.add(m.group(1).decode('ascii', errors='ignore'))

            elif src_port == args.port:
                # best effort for responses; dedup with chunk hash
                marker = hash(payload)
                if marker not in resp_seen_chunks:
                    resp_seen_chunks.add(marker)
                    local_200 += payload.count(b'HTTP/1.0 200 OK') + payload.count(b'HTTP/1.1 200 OK')

        with handled_lock:
            handled_packets += local_handled

        if local_get or local_200:
            with seen_lock:
                seen_get_ids.update(local_get)
                http_200_seen += local_200

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    # Single consumer avoids shared-state races in per-flow TCP reassembly.
    consumers = [threading.Thread(target=consumer, daemon=True)]
    pth.start()
    for c in consumers:
        c.start()

    time.sleep(0.25)
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    requests_ok = load_stats['requests_ok']
    sessions_ok = load_stats.get('sessions_ok', 0)

    stop = True
    with cv:
        cv.notify_all()

    pth.join(timeout=5)

    drain_deadline = time.perf_counter() + 12.0
    while time.perf_counter() < drain_deadline:
        with cv:
            qlen = len(dq)
        with handled_lock:
            handled_now = handled_packets
        if qlen == 0 and handled_now >= enqueued_packets:
            break
        time.sleep(0.01)

    with cv:
        cv.notify_all()

    for c in consumers:
        c.join(timeout=5)

    t1 = time.perf_counter()
    server.shutdown()

    result = {
        'tool': 'libpcap-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
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
        'note': 'Producer-consumer + per-flow TCP sequence reassembly for request stream.'
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
