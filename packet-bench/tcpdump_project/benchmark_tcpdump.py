#!/usr/bin/env python3
import argparse
import json
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
    cmd = ["tcpdump", "-i", args.iface, "-n", "-q", filt]

    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(0.25)
    sent = send_packets("127.0.0.1", args.port, args.duration, args.payload)
    time.sleep(0.4)
    p.terminate()

    out = ""
    try:
        out, _ = p.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()

    captured = len([ln for ln in out.splitlines() if ln.strip()])
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
