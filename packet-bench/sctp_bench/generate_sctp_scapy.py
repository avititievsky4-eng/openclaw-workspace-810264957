#!/usr/bin/env python3
import argparse
import json
import random
import time
from scapy.all import IP, SCTP, SCTPChunkData, send  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dst', default='127.0.0.1')
    ap.add_argument('--sport', type=int, default=2905)
    ap.add_argument('--dport', type=int, default=2905)
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    args = ap.parse_args()

    sent = 0
    deadline = time.perf_counter() + args.duration
    data = b'X' * args.payload
    tag = random.randint(1, 2**32 - 1)

    while time.perf_counter() < deadline:
        pkt = IP(dst=args.dst)/SCTP(sport=args.sport, dport=args.dport, tag=tag)/SCTPChunkData(data=data)
        send(pkt, verbose=False)
        sent += 1

    print(json.dumps({'sent': sent}))


if __name__ == '__main__':
    main()
