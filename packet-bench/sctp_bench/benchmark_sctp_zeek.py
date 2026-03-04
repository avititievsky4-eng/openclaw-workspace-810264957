#!/usr/bin/env python3
import argparse, json, os, re, signal, subprocess, tempfile, time

def run_generator(args):
    cmd=[args.scapy_python,args.generator,'--iface',args.iface,'--dst',args.dst,'--duration',str(args.duration),'--payload',str(args.payload),'--threads',str(args.gen_threads)]
    if args.gen_pps>0: cmd += ['--pps',str(args.gen_pps)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    m=re.search(r'"sent"\s*:\s*(\d+)',(p.stdout or '')+'\n'+(p.stderr or ''))
    return int(m.group(1)) if m else 0

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--iface',default='eth0'); ap.add_argument('--dst',default='127.0.0.1')
    ap.add_argument('--duration',type=float,default=3.0); ap.add_argument('--payload',type=int,default=512)
    ap.add_argument('--gen-threads',type=int,default=1); ap.add_argument('--gen-pps',type=int,default=0)
    ap.add_argument('--scapy-python',default='/home/avi/.openclaw/workspace-810264957/packet-bench/scapy_project/.venv312/bin/python')
    ap.add_argument('--generator',default='/home/avi/.openclaw/workspace-810264957/packet-bench/sctp_bench/generate_sctp_tcpreplay.py')
    args=ap.parse_args()

    pcap=f"/tmp/sctp_zeek_{int(time.time()*1000)}.pcap"
    cap=subprocess.Popen(['tcpdump','-i',args.iface,'-n','-w',pcap,'sctp'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    time.sleep(0.3)
    sent=run_generator(args)
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try: cap.wait(timeout=6)
    except subprocess.TimeoutExpired: cap.kill(); cap.wait(timeout=3)

    outdir=tempfile.mkdtemp(prefix='zeek_sctp_')
    subprocess.run(['zeek','-r',pcap,f'Log::default_rotation_interval=0secs',f'Log::default_logdir={outdir}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
    conn=os.path.join(outdir,'conn.log')
    captured=0
    if os.path.exists(conn):
        txt=open(conn,errors='ignore').read().splitlines()
        for ln in txt:
            if ln.startswith('#'): continue
            if '\tsctp\t' in ln or '\tSCTP\t' in ln:
                captured += 1
    # cleanup
    try: os.remove(pcap)
    except: pass
    try:
        for fn in os.listdir(outdir): os.remove(os.path.join(outdir,fn))
        os.rmdir(outdir)
    except: pass

    norm=captured//2 if args.iface=='lo' else captured
    print(json.dumps({'tool':'zeek-sctp','sent':sent,'captured':captured,'captured_normalized':norm,'capture_ratio':(captured/sent if sent else 0.0),'capture_ratio_normalized':(norm/sent if sent else 0.0)},indent=2))

if __name__=='__main__': main()
