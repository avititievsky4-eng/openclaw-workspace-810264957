# Latest stress run (10s, payload=256)

- tcpdump(libpcap): captured=2,887,247 sent=2,887,505 ratio=99.99% captured_pps=288,725
- libpcap(pcapy-ng): captured=2,141,126 sent=2,141,126 ratio=100.00% captured_pps=214,113
- raw_socket(AF_PACKET): captured=1,108,097 sent=1,109,843 ratio=99.84% captured_pps=110,810
- scapy: captured=55,315 sent=3,020,541 ratio=1.83% captured_pps=5,532

Winner by captured packets: tcpdump(libpcap)
