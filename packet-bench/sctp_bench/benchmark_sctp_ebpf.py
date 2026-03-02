#!/usr/bin/env python3
import argparse
import ctypes
import json
import subprocess
import time
from bcc import BPF  # type: ignore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    sent = 0
    b = None
    err_note = None

    # Prefer tracepoint for portability; count SCTP protocol (=132) state changes.
    bpf_text = r'''
BPF_HASH(counter, u32, u64);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != 132) {
        return 0;
    }
    u32 key = 0;
    u64 zero = 0, *val;
    val = counter.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
'''

    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        err_note = f'ebpf attach failed: {e}'

    time.sleep(0.25)
    gen = subprocess.run([args.scapy_python, args.generator, '--duration', str(args.duration), '--payload', str(args.payload)], capture_output=True, text=True)
    try:
        sent = json.loads(gen.stdout).get('sent', 0)
    except Exception:
        pass

    time.sleep(0.25)

    captured = 0
    if b is not None:
        table = b.get_table('counter')
        key = ctypes.c_uint(0)
        if key in table:
            captured = int(table[key].value)

    normalized = captured // 2

    result = {
        'tool': 'ebpf-sctp',
        'sent': sent,
        'captured': captured,
        'captured_normalized': normalized,
        'capture_ratio': (captured/sent) if sent else 0.0,
        'capture_ratio_normalized': (normalized/sent) if sent else 0.0,
        'note': err_note or 'BCC tracepoint sock:inet_sock_set_state for SCTP protocol events.',
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
