#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import subprocess
import time
from bcc import BPF  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--dst', default='127.0.0.1')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--gen-threads', type=int, default=1)
    ap.add_argument('--gen-pps', type=int, default=0)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    bpf_text = r'''
#include <uapi/linux/bpf.h>

int sctp_filter(struct __sk_buff *skb) {
    u8 proto = 0;
    // Eth(14) + IPv4 proto byte(9)
    if (bpf_skb_load_bytes(skb, 23, &proto, 1) < 0)
        return 0;
    if (proto == 132)
        return -1;
    return 0;
}
'''

    b = BPF(text=bpf_text)
    fn = b.load_func('sctp_filter', BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(fn, args.iface)

    sock = socket.fromfd(fn.sock, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)

    gen_cmd = [
        args.scapy_python, args.generator,
        '--iface', args.iface,
        '--dst', str(args.dst),
        '--duration', str(args.duration),
        '--payload', str(args.payload),
        '--threads', str(args.gen_threads)
    ]
    if args.generator.endswith('generate_sctp_scapy.py'):
        gen_cmd += ['--mode', 'data']
    if args.gen_pps > 0:
        gen_cmd += ['--pps', str(args.gen_pps)]

    gen = subprocess.Popen(gen_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    captured = 0
    # Capture concurrently while generator runs
    while gen.poll() is None:
        try:
            pkt = os.read(fn.sock, 65535)
            if pkt:
                captured += 1
        except BlockingIOError:
            time.sleep(0.0002)
        except Exception:
            break

    # Drain tail
    drain_deadline = time.time() + 1.5
    while time.time() < drain_deadline:
        try:
            pkt = os.read(fn.sock, 65535)
            if pkt:
                captured += 1
                continue
            break
        except BlockingIOError:
            time.sleep(0.0002)
        except Exception:
            break

    out, err = gen.communicate(timeout=5)
    sent = 0
    try:
        sent = json.loads((out or '').strip()).get('sent', 0)
    except Exception:
        m = re.search(r'"sent"\s*:\s*(\d+)', (out or '') + '\n' + (err or ''))
        if m:
            sent = int(m.group(1))

    normalized = captured // 2 if args.iface == 'lo' else captured

    note = 'eBPF SOCKET_FILTER with concurrent recv loop and enlarged RCVBUF.'
    if sent == 0 and err:
        note += ' generator_parse_fallback_used'

    print(json.dumps({
        'tool': 'ebpf-sctp',
        'sent': sent,
        'captured': captured,
        'captured_normalized': normalized,
        'capture_ratio': (captured / sent) if sent else 0.0,
        'capture_ratio_normalized': (normalized / sent) if sent else 0.0,
        'note': note
    }, indent=2))


if __name__ == '__main__':
    main()
