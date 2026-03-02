# Latest HTTP session benchmark (3s, workers=4) — Producer/Consumer in all methods

## L7 parsing methods
- tcpdump-http: req_ok=2,924 GET_seen=2,924 200_seen=2,924 GET_ratio=100.00%
- scapy-http: req_ok=3,313 GET_seen=1,737 200_seen=3,866 GET_ratio=52.43%
- libpcap-http: req_ok=2,556 GET_seen=1,261 200_seen=1,263 GET_ratio=49.33%
- rawsocket-http: req_ok=2,553 GET_seen=712 200_seen=909 GET_ratio=27.89%

Winner by HTTP GET parsed: tcpdump-http

## eBPF session tracker (producer/consumer over bpftrace output)
- ebpf-http-session: req_ok=3,325 sessions=6,650 ratio=200.00%

Note: eBPF metric counts TCP ESTABLISHED events (session-level), not HTTP payload parsing.
