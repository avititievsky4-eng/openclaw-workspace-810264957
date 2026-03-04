import signal
#!/usr/bin/env python3
"""Zeek-based HTTP benchmark.
Runs Zeek over pcap (if available) and reports detected HTTP files per session.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map
from tcp_reassembly_check import analyze_tcp_http_pcap


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
    pcap=f"/tmp/http_zeek_{int(time.time()*1000)}.pcap"
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

    if shutil.which('zeek') is None:
        try: os.remove(pcap)
        except: pass
        server.shutdown()
        # Emit structured JSON consumed by run_http_compare_all.sh.
        print(json.dumps({'tool':'zeek-http','requests_ok':requests_ok,
            'sessions_ok':sessions_ok,
            'load_trace_queue':load_trace_queue,
            'load_trace_sessions':load_trace_sessions,'http_get_seen':0,'sniff_session_files':{},'sniff_sessions_detected':0,'http_200_seen':0,'get_seen_ratio':0.0,'responses_seen_ratio':0.0,'unavailable':'zeek binary not found'}, indent=2))
        return

    outdir=tempfile.mkdtemp(prefix='http_zeek_')
    subprocess.run(['zeek','-r',pcap,f'Log::default_rotation_interval=0secs',f'Log::default_logdir={outdir}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    httplog=os.path.join(outdir,'http.log')
    get_seen=0; rsp_seen=0
    if os.path.exists(httplog):
        with open(httplog,'r',errors='ignore') as f:
            for line in f:
                if not line or line.startswith('#'):
                    continue
                parts=line.rstrip('\n').split('\t')
                # zeek http.log usually: method in col 8, status_code in col 9 (index 7,8)
                if len(parts) > 8:
                    if parts[7] == 'GET':
                        get_seen += 1
                    if parts[8] == '200':
                        rsp_seen += 1

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
    tcp_reassembly_check = analyze_tcp_http_pcap(track_pcap, server_port=args.port)
    t1=time.perf_counter(); server.shutdown()
    # Emit final structured result for this benchmark method.
    # Emit structured JSON consumed by run_http_compare_all.sh.
    print(json.dumps({
        'tool':'zeek-http',
        'requests_ok':requests_ok,
        'sessions_ok':sessions_ok,
        'load_trace_queue':load_trace_queue,
        'load_trace_sessions':load_trace_sessions,
        'http_get_seen':get_seen,
        'http_200_seen':rsp_seen,
        'get_seen_ratio':(get_seen/requests_ok if requests_ok else 0.0),
        'responses_seen_ratio':(rsp_seen/requests_ok if requests_ok else 0.0),
        'elapsed_s':t1-t0,
        'tcp_reassembly_check':tcp_reassembly_check,
    },indent=2))

if __name__=='__main__':
    main()
