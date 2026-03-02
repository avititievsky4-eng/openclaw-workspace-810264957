#!/usr/bin/env python3
import argparse
import json
import mmap
import queue
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load

GET_RE = re.compile(br'GET /bench\?id=(\d+)')

# Linux packet socket constants
SOL_PACKET = 263
PACKET_VERSION = 10
PACKET_RX_RING = 5
TPACKET_V3 = 2
TP_STATUS_USER = 1


def parse_ipv4_tcp_http_payload(frame: bytes, port: int):
    if len(frame) < 14 + 20:
        return None
    eth_type = int.from_bytes(frame[12:14], 'big')
    if eth_type != 0x0800:
        return None
    ip_off = 14
    ihl = (frame[ip_off] & 0x0F) * 4
    if len(frame) < ip_off + ihl + 20:
        return None
    if frame[ip_off + 9] != 6:  # TCP
        return None
    tcp_off = ip_off + ihl
    dst_port = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
    if dst_port != port:
        return None
    data_off = ((frame[tcp_off + 12] >> 4) & 0xF) * 4
    payload_off = tcp_off + data_off
    if payload_off >= len(frame):
        return b''
    return frame[payload_off:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=6.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    # TPACKET_V3 ring setup
    s.setsockopt(SOL_PACKET, PACKET_VERSION, struct.pack('I', TPACKET_V3))

    block_size = 1 << 20   # 1MB
    block_nr = 16          # 16MB total ring
    frame_size = 2048
    frame_nr = (block_size * block_nr) // frame_size
    retire_tov = 64

    req3 = struct.pack('7I', block_size, block_nr, frame_size, frame_nr, retire_tov, 0, 0)
    s.setsockopt(SOL_PACKET, PACKET_RX_RING, req3)
    s.bind((args.iface, 0))

    ring_len = block_size * block_nr
    mm = mmap.mmap(s.fileno(), ring_len, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)

    pkt_q: queue.Queue = queue.Queue(maxsize=30000)
    ids = set()
    responses = 0
    dropped = 0
    stop = False

    def producer():
        nonlocal dropped
        blk = 0
        end_time = time.perf_counter() + args.duration + 1.5
        while not stop and time.perf_counter() < end_time:
            base = blk * block_size
            block_status = struct.unpack_from('<I', mm, base + 8)[0]
            if (block_status & TP_STATUS_USER) == 0:
                blk = (blk + 1) % block_nr
                time.sleep(0.0005)
                continue

            num_pkts = struct.unpack_from('<I', mm, base + 12)[0]
            off_first = struct.unpack_from('<I', mm, base + 16)[0]
            pkt_off = base + off_first

            for _ in range(num_pkts):
                tp_next_offset = struct.unpack_from('<I', mm, pkt_off + 0)[0]
                tp_snaplen = struct.unpack_from('<I', mm, pkt_off + 12)[0]
                tp_mac = struct.unpack_from('<H', mm, pkt_off + 24)[0]

                frame_off = pkt_off + tp_mac
                frame = mm[frame_off: frame_off + tp_snaplen]
                try:
                    pkt_q.put_nowait(bytes(frame))
                except queue.Full:
                    dropped += 1

                if tp_next_offset == 0:
                    break
                pkt_off += tp_next_offset

            # release block back to kernel
            struct.pack_into('<I', mm, base + 8, 0)
            blk = (blk + 1) % block_nr

    def consumer():
        nonlocal responses
        while not stop or not pkt_q.empty():
            try:
                frame = pkt_q.get(timeout=0.05)
            except queue.Empty:
                continue
            payload = parse_ipv4_tcp_http_payload(frame, args.port)
            if payload is None:
                continue
            m = GET_RE.search(payload)
            if m:
                ids.add(int(m.group(1)))
            if b'HTTP/1.' in payload and b' 200 ' in payload:
                responses += 1

    t0 = time.perf_counter()
    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.3)
    requests_ok = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    time.sleep(0.5)

    stop = True
    pth.join(timeout=3)
    cth.join(timeout=3)
    t1 = time.perf_counter()

    mm.close()
    s.close()
    server.shutdown()

    result = {
        'tool': 'rawsocket-http-tpacketv3',
        'requests_ok': requests_ok,
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
