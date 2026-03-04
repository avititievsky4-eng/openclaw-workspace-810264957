#!/usr/bin/env python3
import argparse, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common_http import start_http_server, generate_http_load


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--iface', default='lo')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=18080)
    ap.add_argument('--duration', type=float, default=8.0)
    ap.add_argument('--workers', type=int, default=4)
    args=ap.parse_args()

    server=start_http_server(args.host,args.port)
    pcap=f"/tmp/http_zeek_{int(time.time()*1000)}.pcap"
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

    if shutil.which('zeek') is None:
        try: os.remove(pcap)
        except: pass
        server.shutdown()
        print(json.dumps({'tool':'zeek-http','requests_ok':requests_ok,
        'sessions_ok':sessions_ok,
        'load_trace_queue':load_trace_queue,
        'load_trace_sessions':load_trace_sessions,'http_get_seen':0,'http_200_seen':0,'get_seen_ratio':0.0,'responses_seen_ratio':0.0,'unavailable':'zeek binary not found'}, indent=2))
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
    t1=time.perf_counter(); server.shutdown()
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
    },indent=2))

if __name__=='__main__':
    main()
