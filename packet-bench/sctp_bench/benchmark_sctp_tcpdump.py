#!/usr/bin/env python3
import argparse
import json
import re
import signal
import subprocess
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--duration', type=float, default=3.0)
    ap.add_argument('--payload', type=int, default=64)
    ap.add_argument('--gen-threads', type=int, default=1)
    ap.add_argument('--scapy-python', default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator', default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_scapy.py')
    args = ap.parse_args()

    cap = subprocess.Popen(
        ['tcpdump', '-i', args.iface, '-n', '-w', '/dev/null', 'sctp'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.3)
    gen = subprocess.run(
        [args.scapy_python, args.generator, '--duration', str(args.duration), '--payload', str(args.payload), '--threads', str(args.gen_threads)],
        capture_output=True,
        text=True,
    )
    sent = 0
    try:
        sent = json.loads(gen.stdout).get('sent', 0)
    except Exception:
        pass

    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try:
        _o, err = cap.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
        _o, err = cap.communicate()

    captured = 0
    m = re.search(r'(\d+)\s+packets captured', err or '')
    if m:
        captured = int(m.group(1))

    print(json.dumps({
        'tool': 'tcpdump-sctp',
        'sent': sent,
        'captured': captured,
        'capture_ratio': (captured/sent) if sent else 0.0,
    }, indent=2))


if __name__ == '__main__':
    main()
