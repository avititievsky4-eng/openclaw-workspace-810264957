# Latest HTTP session benchmark (6s, workers=4)

## L7 parsing methods
- scapy-http: req_ok=7,029 GET_seen=4,112 200_seen=9,380 GET_ratio=58.50%
- libpcap-http: req_ok=5,744 GET_seen=2,748 200_seen=2,950 GET_ratio=47.84%
- rawsocket-http: req_ok=5,893 GET_seen=1,876 200_seen=2,979 GET_ratio=31.83%
- tcpdump-http: req_ok=6,850 GET_seen=25 200_seen=23 GET_ratio=0.36%

Winner by HTTP GET parsed: scapy-http

## eBPF session tracker
- ebpf-http-session: req_ok=6,860 sessions=13,720 ratio=200.00%

Note: eBPF method here tracks TCP ESTABLISHED events from tracepoint (session-level events), not HTTP payload parsing.
