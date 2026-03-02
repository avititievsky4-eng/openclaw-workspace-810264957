#!/usr/bin/env python3
import argparse
import json
import random
import threading
import time
from scapy.all import IP, SCTP, SCTPChunkData, send  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dst', default='127.0.0.1')
    ap.add_argument('--sport', type=int, default=2905)
    ap.add_argument('--dport', type=int, default=2905)
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--threads', type=int, default=1)
    args = ap.parse_args()

    total_sent = 0
    lock = threading.Lock()
    deadline = time.perf_counter() + args.duration

    def worker(seed):
        nonlocal total_sent
        local_sent = 0
        rnd = random.Random(seed)
        data = b'X' * args.payload
        while time.perf_counter() < deadline:
            tag = rnd.randint(1, 2**32 - 1)
            pkt = IP(dst=args.dst)/SCTP(sport=args.sport, dport=args.dport, tag=tag)/SCTPChunkData(data=data)
            send(pkt, verbose=False)
            local_sent += 1
        with lock:
            total_sent += local_sent

    ths = [threading.Thread(target=worker, args=(i+1,), daemon=True) for i in range(max(1, args.threads))]
    for t in ths: t.start()
    for t in ths: t.join()

    print(json.dumps({'sent': total_sent}))


if __name__ == '__main__':
    main()
