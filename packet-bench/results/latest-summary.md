# Latest stress run (10s, payload=256)

- ebpf(bpftrace_tracepoint): captured=7,042,744 sent=3,521,354 ratio=200.00% captured_pps=704,274
- tcpdump(libpcap): captured=2,897,477 sent=2,897,649 ratio=99.99% captured_pps=289,748
- libpcap(pcapy-ng): captured=2,080,190 sent=2,080,190 ratio=100.00% captured_pps=208,019
- raw_socket(AF_PACKET): captured=1,120,452 sent=1,134,921 ratio=98.73% captured_pps=112,045
- scapy: captured=60,179 sent=3,182,191 ratio=1.89% captured_pps=6,018

Winner by captured packets: ebpf(bpftrace_tracepoint)

Note: eBPF method here counts loopback interface receive tracepoint events (can include multiple events per packet on `lo`), so ratio can exceed 100% and should be compared as event throughput, not exact packet count.
