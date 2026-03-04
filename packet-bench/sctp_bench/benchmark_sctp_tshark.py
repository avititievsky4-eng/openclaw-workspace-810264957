#!/usr/bin/env python3
import argparse, json, os, re, signal, subprocess, time

def run_generator(args):
    cmd=[args.scapy_python,args.generator,'--iface',args.iface,'--dst',args.dst,'--duration',str(args.duration),'--payload',str(args.payload),'--threads',str(args.gen_threads)]
    if args.gen_pps>0:
        cmd += ['--pps', str(args.gen_pps)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    text=(p.stdout or '')+'\n'+(p.stderr or '')
    m=re.search(r'"sent"\s*:\s*(\d+)',text)
    return int(m.group(1)) if m else 0


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--iface',default='eth0')
    ap.add_argument('--dst',default='127.0.0.1')
    ap.add_argument('--duration',type=float,default=3.0)
    ap.add_argument('--payload',type=int,default=512)
    ap.add_argument('--gen-threads',type=int,default=1)
    ap.add_argument('--gen-pps',type=int,default=0)
    ap.add_argument('--scapy-python',default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator',default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_tcpreplay.py')
    args=ap.parse_args()

    pcap=f"/tmp/sctp_tshark_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tshark','-i',args.iface,'-f','sctp','-w',pcap],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    time.sleep(0.4)
    sent=run_generator(args)
    time.sleep(0.5)
    cap.send_signal(signal.SIGINT)
    try:
        cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
        cap.kill(); cap.wait(timeout=3)

    out=subprocess.run(['tshark','-r',pcap,'-Y','sctp','-T','fields','-e','frame.number'],capture_output=True,text=True)
    lines=[x for x in (out.stdout or '').splitlines() if x.strip()]
    captured=len(lines)
    try: os.remove(pcap)
    except: pass

    norm=captured//2 if args.iface=='lo' else captured
    print(json.dumps({'tool':'tshark-sctp','sent':sent,'captured':captured,'captured_normalized':norm,'capture_ratio':(captured/sent if sent else 0.0),'capture_ratio_normalized':(norm/sent if sent else 0.0)},indent=2))

if __name__=='__main__':
    main()
