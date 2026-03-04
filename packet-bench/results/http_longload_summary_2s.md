# HTTP long-load summary (HTML + images)

Scenario: each session loads `/page?sid=...` + 20 image assets `/asset?...` with delay.

| Method | requests_ok | sessions_ok | GET_seen | GET ratio | Notes |
|---|---:|---:|---:|---:|---|
| libpcap-http | 210 | 10 | 210 | 100.00% |  |\n| netsniff-http | 210 | 10 | 210 | 100.00% |  |\n| pypcap-http | 210 | 10 | 210 | 100.00% |  |\n| rawsocket-http | 210 | 10 | 210 | 100.00% |  |\n| tshark-http | 210 | 10 | 210 | 100.00% |  |\n| dpkt-http | 210 | 10 | 209 | 99.52% |  |\n| rawsocket-http-tpacketv3 | 210 | 10 | 208 | 99.05% |  |\n| scapy-http | 210 | 10 | 208 | 99.05% |  |\n| tcpdump-http | 210 | 10 | 206 | 98.10% |  |\n| suricata-http | 210 | 10 | 125 | 59.52% |  |\n| ebpf-http-session | 210 | 10 | 0 | 0.00% |  |\n| zeek-http | 210 | 10 | 0 | 0.00% | zeek binary not found |\n