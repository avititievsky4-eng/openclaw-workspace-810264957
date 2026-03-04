#!/usr/bin/env python3
"""DPKT offline-parse HTTP benchmark.
Captures pcap then parses/reassembles flows with dpkt to detect loaded files per session.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import dpkt  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map
from tcp_reassembly_check import analyze_tcp_http_pcap

GET_RE = re.compile(br'GET /(page\?sid=\d+|asset\?sid=\d+&i=\d+)')


def main():
    # Parse CLI arguments for benchmark runtime/capture options.
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    server = start_http_server(args.host, args.port)
    # Start local HTTP server that serves /page and /asset endpoints.
    # Side capture for TCP handshake/reassembly validation.
    track_pcap=tempfile.mktemp(prefix='tcptrack_', suffix='.pcap')
    track_cap=subprocess.Popen(['tcpdump','-i',getattr(args,'iface','lo'),'-n','-s0','-w',track_pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    pcap_path = f"/tmp/http_dpkt_{int(time.time()*1000)}.pcap"

    cap = subprocess.Popen(
        ['tcpdump', '-i', args.iface, '-n', '-s0', '-B', '4096', '-w', pcap_path, f'tcp port {args.port}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.3)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok = load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok = load_stats.get('sessions_ok', 0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')
    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.4)

    # Graceful capture stop (flush and close pcap cleanly).
    cap.send_signal(signal.SIGINT)
    try:
        cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
        # Hard-stop fallback in case capture tool does not terminate on SIGINT.
        cap.kill()
        cap.wait(timeout=3)

    req_frags = defaultdict(dict)   # flow -> seq -> bytes
    resp_frags = defaultdict(dict)

    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for _ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp = ip.data
                except Exception:
                    continue

                payload = bytes(tcp.data or b'')
                if not payload:
                    continue

                src = (ip.src, tcp.sport)
                dst = (ip.dst, tcp.dport)
                flow = (src, dst)

                if tcp.dport == args.port:
                    req_frags[flow][tcp.seq] = payload
                elif tcp.sport == args.port:
                    resp_frags[flow][tcp.seq] = payload
    finally:
        try:
            os.remove(pcap_path)
        except Exception:
            pass

    def rebuild(frags):
        out = b''
        for seq in sorted(frags.keys()):
            out += frags[seq]
        return out

    get_ids = set()
    for fr in req_frags.values():
        stream = rebuild(fr)
        for m in GET_RE.finditer(stream):
            get_ids.add(m.group(1).decode('ascii', errors='ignore'))

    http200 = 0
    for fr in resp_frags.values():
        stream = rebuild(fr)
        http200 += stream.count(b'HTTP/1.0 200 OK') + stream.count(b'HTTP/1.1 200 OK')

    # Stop timer and shutdown local HTTP server for this run.
    # Stop side capture and run TCP reassembly check.
    track_cap.send_signal(signal.SIGINT)
    try:
        track_cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        track_cap.kill(); track_cap.wait(timeout=3)
    tcp_reassembly_check = analyze_tcp_http_pcap(track_pcap, server_port=args.port)
    t1 = time.perf_counter()
    server.shutdown()

    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions = build_sniff_session_map(get_ids)
    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'dpkt-http',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'http_get_seen': len(get_ids),
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'http_200_seen': http200,
        'get_seen_ratio': (len(get_ids) / requests_ok) if requests_ok else 0.0,
        'responses_seen_ratio': (http200 / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'tcp_reassembly_check': tcp_reassembly_check,
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
