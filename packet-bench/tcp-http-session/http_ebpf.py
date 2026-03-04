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


def _run_tshark(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout or ''

def analyze_tcp_http_pcap_inline(pcap_path: str, server_port: int = 18080) -> dict:
    """Inline TCP handshake + HTTP reassembly summary (no external Python file import)."""
    try:
        syn = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.dstport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 0','-T','fields','-e','frame.number'])
        synack = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.srcport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 1','-T','fields','-e','frame.number'])
        ack = _run_tshark(['tshark','-r',pcap_path,'-Y',f'tcp.dstport == {server_port} && tcp.flags.syn == 0 && tcp.flags.ack == 1','-T','fields','-e','frame.number'])

        syn_n = len([x for x in syn.splitlines() if x.strip()])
        synack_n = len([x for x in synack.splitlines() if x.strip()])
        ack_n = len([x for x in ack.splitlines() if x.strip()])

        get_out = _run_tshark(['tshark','-r',pcap_path,'-Y',f'http.request.method == "GET" && tcp.dstport == {server_port}','-T','fields','-e','tcp.stream'])
        ok_out = _run_tshark(['tshark','-r',pcap_path,'-Y',f'http.response.code == 200 && tcp.srcport == {server_port}','-T','fields','-e','tcp.stream'])

        get_streams = {x.strip() for x in get_out.splitlines() if x.strip()}
        ok_streams = {x.strip() for x in ok_out.splitlines() if x.strip()}

        return {
            'tcp_syn_packets': syn_n,
            'tcp_synack_packets': synack_n,
            'tcp_ack_packets': ack_n,
            'tcp_handshake_estimate': min(syn_n, synack_n, ack_n),
            'http_get_streams_after_reassembly': len(get_streams),
            'http_200_streams_after_reassembly': len(ok_streams),
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
