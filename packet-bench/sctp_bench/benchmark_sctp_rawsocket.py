#!/usr/bin/env python3
import argparse
import json
import queue
import socket
import subprocess
import threading
import time


def is_sctp_ipv4(frame: bytes) -> bool:
    if len(frame) < 14 + 20:
        return False
    if int.from_bytes(frame[12:14], 'big') != 0x0800:
        return False
    ip_off = 14
    return frame[ip_off + 9] == 132


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((args.iface, 0))
    s.settimeout(0.01)

    q = queue.Queue(maxsize=80000)
    stop = False
    producer_done = False
    enq = 0
    handled = 0

    def producer():
        nonlocal enq, producer_done
        try:
            while not stop:
                try:
                    frame = s.recv(65535)
                    q.put_nowait(frame)
                    enq += 1
                except queue.Full:
                    pass
                except TimeoutError:
                    pass
                except Exception:
                    pass
        finally:
            producer_done = True

    def consumer():
        nonlocal handled
        while True:
            try:
                frame = q.get(timeout=0.05)
            except queue.Empty:
                if producer_done and q.empty():
                    break
                continue
            if is_sctp_ipv4(frame):
                handled += 1

    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.3)
    gen = subprocess.run([args.scapy_python, args.generator, '--duration', str(args.duration), '--payload', str(args.payload)], capture_output=True, text=True)
    sent = 0
    try:
        sent = json.loads(gen.stdout).get('sent', 0)
    except Exception:
        pass

    stop = True
    pth.join(timeout=5)
    deadline = time.time() + 5
    while time.time() < deadline:
        if q.empty() and producer_done:
            break
        time.sleep(0.01)
    cth.join(timeout=3)
    s.close()

    print(json.dumps({
        'tool': 'rawsocket-sctp',
        'sent': sent,
        'captured': handled,
        'capture_ratio': (handled/sent) if sent else 0.0,
    }, indent=2))


if __name__ == '__main__':
    main()
