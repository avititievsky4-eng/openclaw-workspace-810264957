#!/usr/bin/env python3
"""Suricata-based HTTP benchmark.
Parses eve.json HTTP events and builds per-session loaded file map.

This benchmark uses the shared long-load generator from common_http.py.
"""
import argparse, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load, build_sniff_session_map


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args=ap.parse_args()

    server=start_http_server(args.host,args.port)
    pcap=f"/tmp/http_suricata_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tcpdump','-i',args.iface,'-n','-s0','-w',pcap,f'tcp port {args.port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    t0=time.perf_counter(); time.sleep(0.4)
    load_stats=generate_http_load(args.host,args.port,args.duration,workers=args.workers)
    requests_ok=load_stats['requests_ok']
    sessions_ok=load_stats.get('sessions_ok',0)
    load_trace_queue=load_stats.get('queue_file','')
    load_trace_sessions=load_stats.get('sessions_file','')
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try: cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
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

    sniff_sessions=build_sniff_session_map(sniff_paths)
    try: os.remove(pcap)
    except: pass
    shutil.rmtree(outdir, ignore_errors=True)
    t1=time.perf_counter(); server.shutdown()
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
    },indent=2))

if __name__=='__main__':
    main()
