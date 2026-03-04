import signal
#!/usr/bin/env python3
"""Suricata-based HTTP benchmark.
Parses eve.json HTTP events and builds per-session loaded file map.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map


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
    ap=argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args=ap.parse_args()
    # args now contains host/port/duration/workers/iface as relevant.

    server=start_http_server(args.host,args.port)
    # Start local HTTP server that serves /page and /asset endpoints.
    # Side capture for TCP handshake/reassembly validation.
    track_pcap=tempfile.mktemp(prefix='tcptrack_', suffix='.pcap')
    track_cap=subprocess.Popen(['tcpdump','-i',getattr(args,'iface','lo'),'-n','-s0','-w',track_pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    pcap=f"/tmp/http_suricata_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tcpdump','-i',args.iface,'-n','-s0','-w',pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    t0=time.perf_counter(); # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.4)
    # Generator simulates long page-load sessions (page + 20 assets).
    load_stats=generate_http_load(args.host,args.port,args.duration,workers=args.workers)
    # Generate long-load sessions: page + 20 assets per session.
    requests_ok=load_stats['requests_ok']
    # Count successful HTTP responses from generator side.
    sessions_ok=load_stats.get('sessions_ok',0)
    # Count fully completed sessions (page + all assets).
    load_trace_queue=load_stats.get('queue_file','')
    load_trace_sessions=load_stats.get('sessions_file','')
    # Small warm-up delay so capture process attaches before load starts.
    time.sleep(0.4)
    # Graceful capture stop (flush and close pcap cleanly).
    cap.send_signal(signal.SIGINT)
    try: cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
        # Hard-stop fallback in case capture tool does not terminate on SIGINT.
        cap.kill(); cap.wait(timeout=3)

    outdir=tempfile.mkdtemp(prefix='http_suricata_')
    subprocess.run(['suricata','-r',pcap,'-l',outdir],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    eve=os.path.join(outdir,'eve.json')
    get_seen=0; rsp_seen=0
    sniff_paths=[]
    if os.path.exists(eve):
        with open(eve,'r',errors='ignore') as f:
            for line in f:
                try: j=json.loads(line)
                except: continue
                if j.get('event_type')=='http':
                    h=j.get('http',{})
                    if str(h.get('http_method','')).upper()=='GET':
                        get_seen += 1
                        u=str(h.get('url','') or '')
                        if u:
                            sniff_paths.append(u.lstrip('/'))
                    if str(h.get('status',''))=='200':
                        rsp_seen += 1

    # Map sniffed paths to per-session file lists + min20 checks.
    sniff_sessions=build_sniff_session_map(sniff_paths)
    try: os.remove(pcap)
    except: pass
    shutil.rmtree(outdir, ignore_errors=True)
    # Stop timer and shutdown local HTTP server for this run.
    # Stop side capture and run TCP reassembly check.
    track_cap.send_signal(signal.SIGINT)
    try:
        track_cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        track_cap.kill(); track_cap.wait(timeout=3)
    tcp_reassembly_check = analyze_tcp_http_pcap_inline(track_pcap, server_port=args.port)
    t1=time.perf_counter(); server.shutdown()
    # Emit final structured result for this benchmark method.
    # Emit structured JSON consumed by run_http_compare_all.sh.
    print(json.dumps({
        'tool':'suricata-http',
        'requests_ok':requests_ok,
        'sessions_ok':sessions_ok,
        'load_trace_queue':load_trace_queue,
        'load_trace_sessions':load_trace_sessions,
        'http_get_seen':get_seen,
        'sniff_session_files':sniff_sessions,
        'sniff_sessions_detected':len(sniff_sessions),
        'http_200_seen':rsp_seen,
        'get_seen_ratio':(get_seen/requests_ok if requests_ok else 0.0),
        'responses_seen_ratio':(rsp_seen/requests_ok if requests_ok else 0.0),
        'elapsed_s':t1-t0,
        'tcp_reassembly_check':tcp_reassembly_check,
    },indent=2))

if __name__=='__main__':
    main()
