#!/usr/bin/env python3
import argparse
import json
import os
import random
import re
import subprocess
import tempfile
from pathlib import Path

from scapy.all import Ether, IP, SCTP, SCTPChunkData, wrpcap  # type: ignore


def build_pcap(path: str, dst: str, sport: int, dport: int, payload: int, count: int):
    pkts = []
    data = b'X' * payload
    rnd = random.Random(1234)
    for _ in range(count):
        tag = rnd.randint(1, 2**32 - 1)
        # Ethernet framing so tcpreplay can transmit on non-loopback NICs.
        pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst=dst)/SCTP(sport=sport, dport=dport, tag=tag)/SCTPChunkData(data=data))
    wrpcap(path, pkts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dst', default='127.0.0.1')
    ap.add_argument('--sport', type=int, default=2905)
    ap.add_argument('--dport', type=int, default=2905)
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--threads', type=int, default=1)
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--pcap-packets', type=int, default=2000)
    ap.add_argument('--pps', type=int, default=0)
    args = ap.parse_args()

    cache_dir = Path('/tmp/sctp_replay_cache')
    cache_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = cache_dir / f'sctp_{args.payload}_{args.pcap_packets}_{os.getpid()}.pcap'

    # Always build fresh file to avoid stale/permission-mismatched cached DLT files.
    build_pcap(str(pcap_path), args.dst, args.sport, args.dport, args.payload, args.pcap_packets)

    def run_once():
        speed_args = ['--topspeed'] if args.pps <= 0 else ['--pps', str(args.pps)]
        cmd = [
            'tcpreplay', '--intf1', args.iface, *speed_args,
            '--loop', '999999', '--duration', str(max(1, int(args.duration))),
            str(pcap_path)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        text = (proc.stdout or '') + '\n' + (proc.stderr or '')
        sent = 0
        m = re.search(r'Actual:\s*(\d+)\s+packets', text)
        if m:
            sent = int(m.group(1))
        else:
            m2 = re.search(r'(\d+)\s+packets sent', text)
            if m2:
                sent = int(m2.group(1))
        return sent, text

    sent, text = run_once()
    # Self-heal stale cached pcap with wrong DLT by rebuilding once.
    if sent == 0 and ('Unsupported DLT' in text or 'Unable to process unsupported DLT' in text):
        try:
            pcap_path.unlink(missing_ok=True)
        except Exception:
            pass
        build_pcap(str(pcap_path), args.dst, args.sport, args.dport, args.payload, args.pcap_packets)
        sent, text = run_once()

    try:
        pcap_path.unlink(missing_ok=True)
    except Exception:
        pass

    print(json.dumps({'sent': sent, 'generator': 'tcpreplay'}))


if __name__ == '__main__':
    main()
