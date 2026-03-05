# HTTP pass-only table (keep-alive, 60s run)

| Method | pass@50 | pass@100 | pass@200 | pass@500 | pass@1000 | pass@2000 | capture_mode |
|---|---|---|---|---|---|---|---|
| dpkt-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | external capture + dpkt parse |
| ebpf-http-session | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | self (eBPF) |
| libpcap-http | 42/50 | 85/100 | 160/200 | 406/500 | 821/1000 | 1624/2000 | self (libpcap) |
| netsniff-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | external (netsniff-ng) |
| pypcap-http | 42/50 | 83/100 | 163/200 | 417/500 | 809/1000 | 1628/2000 | self (pypcap) |
| rawsocket-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | self (raw socket) |
| rawsocket-http-tpacketv3 | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | self (raw socket tpacketv3) |
| scapy-http | 43/50 | 81/100 | 151/200 | 399/500 | 788/1000 | 1582/2000 | self (scapy sniff) |
| suricata-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | external (suricata over pcap) |
| tcpdump-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | external (tcpdump stream) |
| tshark-http | 50/50 | 100/100 | 200/200 | 500/500 | 1000/1000 | 2000/2000 | external (tshark) |
