#!/usr/bin/env python3
import argparse, json, os, signal, subprocess, sys, time
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
    pcap=f"/tmp/http_tshark_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tshark','-i',args.iface,'-f',f'tcp port {args.port}','-w',pcap],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    t0=time.perf_counter()
    time.sleep(0.4)
    requests_ok=generate_http_load(args.host,args.port,args.duration,workers=args.workers)
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try:
        cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
        cap.kill(); cap.wait(timeout=3)

    get_out=subprocess.run(['tshark','-r',pcap,'-Y',f'http.request.method == "GET" && tcp.dstport == {args.port}','-T','fields','-e','frame.number'],capture_output=True,text=True)
    rsp_out=subprocess.run(['tshark','-r',pcap,'-Y',f'http.response.code == 200 && tcp.srcport == {args.port}','-T','fields','-e','frame.number'],capture_output=True,text=True)
    get_seen=len([x for x in (get_out.stdout or '').splitlines() if x.strip()])
    rsp_seen=len([x for x in (rsp_out.stdout or '').splitlines() if x.strip()])

    try: os.remove(pcap)
    except: pass
    t1=time.perf_counter(); server.shutdown()
    print(json.dumps({
        'tool':'tshark-http',
        'requests_ok':requests_ok,
        'http_get_seen':get_seen,
        'http_200_seen':rsp_seen,
        'get_seen_ratio':(get_seen/requests_ok if requests_ok else 0.0),
        'responses_seen_ratio':(rsp_seen/requests_ok if requests_ok else 0.0),
        'elapsed_s':t1-t0,
    },indent=2))

if __name__=='__main__':
    main()
