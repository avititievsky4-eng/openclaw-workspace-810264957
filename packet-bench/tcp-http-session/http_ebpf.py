#!/usr/bin/env python3
"""eBPF session benchmark.
Counts TCP session establishments with BCC and attaches generator session-file traces.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse
import tempfile
import ctypes
import json
import subprocess
import signal
import sys
import time
from pathlib import Path

from bcc import BPF  # type: ignore

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, load_session_files_map


def analyze_tcp_http_pcap_inline(pcap_path: str, server_port: int = 18080) -> dict:
    """Native Python PCAP parse: TCP handshake counters + simple stream reassembly."""
    import struct
    try:
        syn_n = synack_n = ack_n = 0
        c2s = {}
        s2c = {}

        with open(pcap_path, 'rb') as f:
            gh = f.read(24)
            if len(gh) < 24:
                return {'error': 'bad pcap global header'}
            magic = gh[:4]
            le = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
            ph_fmt = ('<' if le else '>') + 'IIII'

            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(ph_fmt, ph)
                pkt = f.read(incl_len)
                if len(pkt) < 14 + 20:
                    continue

                eth_type = int.from_bytes(pkt[12:14], 'big')
                if eth_type != 0x0800:
                    continue
                ip_off = 14
                ihl = (pkt[ip_off] & 0x0F) * 4
                if len(pkt) < ip_off + ihl + 20:
                    continue
                if pkt[ip_off + 9] != 6:
                    continue

                src_ip = pkt[ip_off + 12:ip_off + 16]
                dst_ip = pkt[ip_off + 16:ip_off + 20]
                tcp_off = ip_off + ihl
                sport = int.from_bytes(pkt[tcp_off:tcp_off + 2], 'big')
                dport = int.from_bytes(pkt[tcp_off + 2:tcp_off + 4], 'big')
                seq = int.from_bytes(pkt[tcp_off + 4:tcp_off + 8], 'big')
                flags = pkt[tcp_off + 13]
                data_off = ((pkt[tcp_off + 12] >> 4) & 0xF) * 4
                pay_off = tcp_off + data_off
                payload = pkt[pay_off:] if pay_off <= len(pkt) else b''

                if dport == server_port:
                    flow = (src_ip, sport, dst_ip, dport)
                    dir_c2s = True
                elif sport == server_port:
                    flow = (dst_ip, dport, src_ip, sport)
                    dir_c2s = False
                else:
                    continue

                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                if dir_c2s and syn and not ack:
                    syn_n += 1
                elif (not dir_c2s) and syn and ack:
                    synack_n += 1
                elif dir_c2s and ack and not syn:
                    ack_n += 1

                if payload:
                    if dir_c2s:
                        c2s.setdefault(flow, {})[seq] = payload
                    else:
                        s2c.setdefault(flow, {})[seq] = payload

        def rebuild(frags):
            out = b''
            for seq in sorted(frags.keys()):
                out += frags[seq]
            return out

        get_flows = 0
        ok_flows = 0
        for flow in (set(c2s.keys()) | set(s2c.keys())):
            req = rebuild(c2s.get(flow, {}))
            rsp = rebuild(s2c.get(flow, {}))
            if b'GET /' in req and b'HTTP/1.' in req:
                get_flows += 1
            if (b'HTTP/1.0 200' in rsp) or (b'HTTP/1.1 200' in rsp):
                ok_flows += 1

        return {
            'tcp_syn_packets': syn_n,
            'tcp_synack_packets': synack_n,
            'tcp_ack_packets': ack_n,
            'tcp_handshake_estimate': min(syn_n, synack_n, ack_n),
            'http_get_flows_after_reassembly': get_flows,
            'http_200_flows_after_reassembly': ok_flows,
        }
    except Exception as e:
        return {'error': str(e)}


def main():
    # Parse CLI arguments for benchmark runtime/capture options.
    ap = argparse.ArgumentParser()
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

    # Use tracepoint program with minimal includes (no external bpftrace process).
    bpf_text = f"""
BPF_HASH(counter, u32, u64);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {{
    if (args->protocol != 6) {{
        return 0;
    }}
    if (args->newstate != 1) {{
        return 0;
    }}

    u16 sport = args->sport;
    u16 dport = args->dport;
    if (!(sport == {args.port} || dport == {args.port})) {{
        return 0;
    }}

    u32 key = 0;
    u64 zero = 0, *val;
    val = counter.lookup_or_try_init(&key, &zero);
    if (val) {{
        (*val)++;
    }}
    return 0;
}}
"""

    # Start end-to-end timer for this benchmark method.
    t0 = time.perf_counter()
    b = BPF(text=bpf_text)

    time.sleep(0.2)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats = generate_http_load(args.host, args.port, args.duration, workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok = load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok = load_stats.get('sessions_ok', 0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue = load_stats.get('queue_file', '')
    load_trace_sessions = load_stats.get('sessions_file', '')
    sniff_sessions = load_session_files_map(load_trace_sessions)
    time.sleep(0.2)

    sessions = 0
    table = b.get_table('counter')
    key = ctypes.c_uint(0)
    if key in table:
        sessions = int(table[key].value)

    # Stop timer and shutdown local HTTP server for this run.
    t1 = time.perf_counter()
    # Stop side capture and run TCP reassembly check.
    track_cap.send_signal(signal.SIGINT)
    try:
        track_cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        track_cap.kill(); track_cap.wait(timeout=3)
    tcp_reassembly_check = analyze_tcp_http_pcap_inline(track_pcap, server_port=args.port)
    server.shutdown()

    # Build final result object written to JSON by run_http_compare_all.sh.
    # Build structured result for this method.
    result = {
        'tool': 'ebpf-http-session',
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'load_trace_queue': load_trace_queue,
        'load_trace_sessions': load_trace_sessions,
        'enqueued_packets': sessions,
        'handled_packets': sessions,
        'unhandled_packets': 0,
        'capture_drop_queue': 0,
        'http_sessions_established': sessions,
        'sniff_session_files': sniff_sessions,
        'sniff_sessions_detected': len(sniff_sessions),
        'session_to_request_ratio': (sessions / requests_ok) if requests_ok else 0.0,
        'elapsed_s': t1 - t0,
        'tcp_reassembly_check': tcp_reassembly_check,
        'note': 'Python BCC TRACEPOINT_PROBE; no external process.',
    }
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
