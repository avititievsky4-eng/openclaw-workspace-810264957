#!/usr/bin/env python3
import argparse
import json
import multiprocessing as mp
import socket
import time
from scapy.all import sniff  # type: ignore


def capture_worker(iface: str, bpf_filter: str, run_for: float, q: mp.Queue):
    count = 0

    def on_pkt(_pkt):
        nonlocal count
        count += 1

    sniff(iface=iface, filter=bpf_filter, prn=on_pkt, store=False, timeout=run_for)
    q.put(count)


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--payload", type=int, default=64)
    args = ap.parse_args()

    q: mp.Queue = mp.Queue()
    bpf = f"udp and dst port {args.port}"
    capture_time = args.duration + 1.0
    p = mp.Process(target=capture_worker, args=(args.iface, bpf, capture_time, q), daemon=True)

    t0 = time.perf_counter()
    p.start()
    time.sleep(0.25)
    sent = send_packets("127.0.0.1", args.port, args.duration, args.payload)
    p.join(timeout=10)
    t1 = time.perf_counter()

    captured = q.get() if not q.empty() else 0
    loss = max(0, sent - captured)
    result = {
        "tool": "scapy",
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
    mp.set_start_method("fork")
    main()
