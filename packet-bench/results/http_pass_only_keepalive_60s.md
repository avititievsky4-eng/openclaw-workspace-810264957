# HTTP pass-only table (keep-alive, 60s run)

| Method | pass@50 | pass@100 | pass@200 | pass@500 | pass@1000 | pass@2000 | capture_mode |
|---|---|---|---|---|---|---|---|
| dpkt-http | 50/50 | - | 200/200 | - | 1000/1000 | 1999/2000 | external capture + dpkt parse |
| ebpf-http-session | 50/50 | - | 200/200 | - | 1000/1000 | 2000/2000 | self (eBPF) |
| libpcap-http | 43/50 | - | 187/200 | - | 801/1000 | 1465/2000 | self (libpcap) |
| netsniff-http | 50/50 | - | 200/200 | - | 999/1000 | 1999/2000 | external (netsniff-ng) |
| pypcap-http | 47/50 | - | 190/200 | - | 968/1000 | 1917/2000 | self (pypcap) |
| rawsocket-http | 50/50 | - | 185/200 | - | 520/1000 | 937/2000 | self (raw socket) |
| rawsocket-http-tpacketv3 | 50/50 | - | 200/200 | - | 1000/1000 | 2000/2000 | self (raw socket tpacketv3) |
| scapy-http | 20/50 | - | 51/200 | - | 188/1000 | 332/2000 | self (scapy sniff) |
| suricata-http | 50/50 | - | 200/200 | - | 1000/1000 | 2000/2000 | external (suricata over pcap) |
| tcpdump-http | 50/50 | - | 200/200 | - | 1000/1000 | 2000/2000 | external (tcpdump stream) |
| tshark-http | 50/50 | - | 200/200 | - | 999/1000 | 1999/2000 | \n external (tshark) |
