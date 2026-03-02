#!/usr/bin/env python3
import argparse
import json
import os
import socket
import subprocess
import time
from bcc import BPF  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--gen-threads', type=int, default=1)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    # eBPF socket filter: accept IPv4 SCTP only (IP proto 132)
    bpf_text = r'''
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

int sctp_filter(struct __sk_buff *skb) {
    u8 proto = 0;

    // Ethernet + IPv4 protocol offset: 14 + 9
    if (bpf_skb_load_bytes(skb, 23, &proto, 1) < 0)
        return 0;

    if (proto == 132)
        return -1;   // pass packet to socket

    return 0;        // drop
}
'''

    b = BPF(text=bpf_text)
    fn = b.load_func('sctp_filter', BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(fn, args.iface)

    sock = socket.fromfd(fn.sock, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.setblocking(False)

    # Start traffic generator
    time.sleep(0.2)
    gen = subprocess.run([
        args.scapy_python, args.generator,
        '--iface', args.iface,
        '--duration', str(args.duration),
        '--payload', str(args.payload),
        '--threads', str(args.gen_threads),
        '--mode', 'data'
    ], capture_output=True, text=True)

    sent = 0
    try:
        sent = json.loads(gen.stdout).get('sent', 0)
    except Exception:
        pass

    # Drain accepted SCTP packets from socket
    captured = 0
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            _pkt = os.read(fn.sock, 65535)
            if _pkt:
                captured += 1
        except BlockingIOError:
            time.sleep(0.001)
        except Exception:
            break

    normalized = captured // 2 if args.iface == 'lo' else captured

    print(json.dumps({
        'tool': 'ebpf-sctp',
        'sent': sent,
        'captured': captured,
        'captured_normalized': normalized,
        'capture_ratio': (captured / sent) if sent else 0.0,
        'capture_ratio_normalized': (normalized / sent) if sent else 0.0,
        'note': 'eBPF SOCKET_FILTER attached to raw socket; filters SCTP in-kernel.'
    }, indent=2))


if __name__ == '__main__':
    main()
