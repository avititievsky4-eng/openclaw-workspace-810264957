# HTTP latest all-methods summary (120s, workers=10)

| Method | requests_ok | GET_seen | 200_seen | GET ratio | Notes |
|---|---:|---:|---:|---:|---|
| rawsocket-http-tpacketv3 | 50,107 | 50,107 | 0 | 100.00% |  |
| tcpdump-http | 43,693 | 43,693 | 43,693 | 100.00% |  |
| dpkt-http | 45,074 | 45,071 | 45,068 | 99.99% |  |
| netsniff-http | 45,939 | 45,930 | 45,930 | 99.98% |  |
| tshark-http | 45,262 | 45,242 | 45,242 | 99.96% |  |
| suricata-http | 45,610 | 45,519 | 45,519 | 99.80% |  |
| pypcap-http | 74,685 | 73,202 | 73,711 | 98.01% |  |
| rawsocket-http | 73,230 | 44,295 | 97,235 | 60.49% |  |
| scapy-http | 84,645 | 22,372 | 120,333 | 26.43% |  |
| libpcap-http | 73,965 | 14,074 | 244 | 19.03% |  |
| ebpf-http-session | 45,417 | 0 | 0 | 0.00% |  |
