#!/usr/bin/env python3
import argparse
import json
import re
import signal
import socket
import subprocess
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--payload", type=int, default=64)
    args = ap.parse_args()

    filt = f"udp dst port {args.port}"
    # Write packets to /dev/null to avoid stdout bottleneck; parse summary from stderr.
    cmd = ["tcpdump", "-i", args.iface, "-n", "-q", "-w", "/dev/null", filt]

    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(0.3)
    sent = send_packets("127.0.0.1", args.port, args.duration, args.payload)
    time.sleep(0.5)

    p.send_signal(signal.SIGINT)
    try:
        _out, err = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        _out, err = p.communicate()

    captured = 0
    m = re.search(r"(\d+)\s+packets captured", err or "")
    if m:
        captured = int(m.group(1))

    t1 = time.perf_counter()

    loss = max(0, sent - captured)
    result = {
        "tool": "tcpdump(libpcap)",
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
