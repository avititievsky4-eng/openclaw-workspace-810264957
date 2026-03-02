# Latest HTTP session benchmark (3s, workers=4) — producer/consumer + TPACKET_V3

## L7 parsing methods
- tcpdump-http: req_ok=2,896 GET_seen=2,896 200_seen=2,896 GET_ratio=100.00%
- rawsocket-http-tpacketv3: req_ok=2,881 GET_seen=2,881 200_seen=0 GET_ratio=100.00%
- scapy-http: req_ok=3,255 GET_seen=1,660 200_seen=3,765 GET_ratio=51.00%
- libpcap-http: req_ok=2,550 GET_seen=1,264 200_seen=1,263 GET_ratio=49.57%
- rawsocket-http: req_ok=2,614 GET_seen=674 200_seen=974 GET_ratio=25.78%

Winner by HTTP GET parsed: tcpdump-http (tie on GET ratio with rawsocket-http-tpacketv3)

## eBPF session tracker
- ebpf-http-session: req_ok=3,261 sessions=0 ratio=0.00%

Note: `rawsocket-http-tpacketv3` currently filters request direction (dst port), so `HTTP 200` response parsing is expected to be 0 in this metric.
