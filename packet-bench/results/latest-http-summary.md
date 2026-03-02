# Latest HTTP session benchmark (8s, workers=6)

## L7 parsing methods
- tcpdump-http: req_ok=9,100 GET_seen=9,073 200_seen=9,070 GET_ratio=99.70%
- scapy-http: req_ok=9,381 GET_seen=5,383 200_seen=12,556 GET_ratio=57.38%
- libpcap-http: req_ok=7,593 GET_seen=4,021 200_seen=4,040 GET_ratio=52.96%
- rawsocket-http: req_ok=7,595 GET_seen=2,471 200_seen=3,787 GET_ratio=32.53%

Winner by HTTP GET parsed: tcpdump-http

## eBPF session tracker
- ebpf-http-session: req_ok=9,032 sessions=18,064 ratio=200.00%

Note: eBPF method tracks TCP ESTABLISHED events (session-level), not HTTP payload parsing.
