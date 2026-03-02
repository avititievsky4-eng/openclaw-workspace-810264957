#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time


def send_packets(dst_ip: str, dst_port: int, duration: float, payload_size: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * payload_size
    sent = 0
    deadline = time.perf_counter() + duration
    while time.perf_counter() < deadline:
        sock.sendto(payload, (dst_ip, dst_port))
        sent += 1
    sock.close()
    return sent


def parse_udp_dst_port(frame: bytes):
    # Ethernet(14) + IPv4 + UDP parser
    if len(frame) < 14 + 20 + 8:
        return None
    eth_type = int.from_bytes(frame[12:14], "big")
    if eth_type != 0x0800:
        return None
    ip_start = 14
    ver_ihl = frame[ip_start]
    ihl = (ver_ihl & 0x0F) * 4
    if len(frame) < 14 + ihl + 8:
        return None
    proto = frame[ip_start + 9]
    if proto != 17:
        return None
    udp_start = 14 + ihl
    dst_port = int.from_bytes(frame[udp_start + 2: udp_start + 4], "big")
    return dst_port


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--payload", type=int, default=64)
    args = ap.parse_args()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((args.iface, 0))
    s.settimeout(0.02)

    captured = 0
    stop = False

    def capture_loop():
        nonlocal captured, stop
        while not stop:
            try:
                frame = s.recv(65535)
                dport = parse_udp_dst_port(frame)
                if dport == args.port:
                    captured += 1
            except TimeoutError:
                pass
            except Exception:
                pass

    t0 = time.perf_counter()
    th = threading.Thread(target=capture_loop, daemon=True)
    th.start()
    time.sleep(0.25)
    sent = send_packets("127.0.0.1", args.port, args.duration, args.payload)
    time.sleep(0.3)
    stop = True
    th.join(timeout=2)
    t1 = time.perf_counter()
    s.close()

    loss = max(0, sent - captured)
    result = {
        "tool": "raw_socket(AF_PACKET)",
        "iface": args.iface,
        "duration_s": args.duration,
        "payload_bytes": args.payload,
        "sent": sent,
        "captured": captured,
        "loss": loss,
        "capture_ratio": (captured / sent) if sent else 0.0,
        "send_pps": sent / args.duration,
        "captured_pps": captured / args.duration,
        "elapsed_s": t1 - t0,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
