#!/usr/bin/env python3
import argparse, json, os, re, signal, subprocess, time
import dpkt  # type: ignore


def run_generator(args):
    cmd=[args.scapy_python,args.generator,'--iface',args.iface,'--dst',args.dst,'--duration',str(args.duration),'--payload',str(args.payload),'--threads',str(args.gen_threads)]
    if args.gen_pps>0:
        cmd += ['--pps', str(args.gen_pps)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    m=re.search(r'"sent"\s*:\s*(\d+)',(p.stdout or '')+'\n'+(p.stderr or ''))
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

    pcap=f"/tmp/sctp_dpkt_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tcpdump','-i',args.iface,'-n','-w',pcap,'sctp'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    time.sleep(0.3)
    sent=run_generator(args)
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try:
        cap.wait(timeout=6)
    except subprocess.TimeoutExpired:
        cap.kill(); cap.wait(timeout=3)

    captured=0
    with open(pcap,'rb') as f:
        r=dpkt.pcap.Reader(f)
        for _ts, buf in r:
            try:
                eth=dpkt.ethernet.Ethernet(buf)
                ip=eth.data
                if isinstance(ip, dpkt.ip.IP) and ip.p==132:
                    captured += 1
            except Exception:
                pass
    try: os.remove(pcap)
    except: pass

    norm=captured//2 if args.iface=='lo' else captured
    print(json.dumps({'tool':'dpkt-sctp','sent':sent,'captured':captured,'captured_normalized':norm,'capture_ratio':(captured/sent if sent else 0.0),'capture_ratio_normalized':(norm/sent if sent else 0.0)},indent=2))

if __name__=='__main__':
    main()
