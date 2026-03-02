#!/usr/bin/env python3
import argparse
import json
import queue
import subprocess
import threading
import time
import pcap  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--gen-threads', type=int, default=1)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    pc = pcap.pcap(name=args.iface, snaplen=262144, promisc=True, timeout_ms=1)
    pc.setfilter('sctp')

    q = queue.Queue(maxsize=80000)
    stop = False
    producer_done = False
    enq = 0
    handled = 0
    dropped = 0

    def producer():
        nonlocal enq, dropped, producer_done
        try:
            for _ts, pkt in pc:
                if stop:
                    break
                try:
                    q.put_nowait(pkt)
                    enq += 1
                except queue.Full:
                    dropped += 1
        finally:
            producer_done = True

    def consumer():
        nonlocal handled
        while True:
            try:
                _ = q.get(timeout=0.05)
                handled += 1
            except queue.Empty:
                if producer_done and q.empty():
                    break

    pth = threading.Thread(target=producer, daemon=True)
    cth = threading.Thread(target=consumer, daemon=True)
    pth.start(); cth.start()

    time.sleep(0.25)
    gen = subprocess.run([args.scapy_python, args.generator, '--iface', str(args.iface), '--duration', str(args.duration), '--payload', str(args.payload), '--threads', str(args.gen_threads)], capture_output=True, text=True)
    sent = 0
    try:
        sent = json.loads(gen.stdout).get('sent', 0)
    except Exception:
        pass

    stop = True
    pth.join(timeout=6)
    deadline = time.time() + 6
    while time.time() < deadline:
        if q.empty() and handled >= enq and producer_done:
            break
        time.sleep(0.01)
    cth.join(timeout=4)

    print(json.dumps({
        'tool': 'pypcap-sctp',
        'sent': sent,
        'captured': handled,
        'capture_ratio': (handled/sent) if sent else 0.0,
        'unhandled_packets': max(0, enq-handled),
        'capture_drop_queue': dropped,
    }, indent=2))


if __name__ == '__main__':
    main()
