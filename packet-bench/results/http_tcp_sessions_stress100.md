# HTTP TCP sessions stress report (target: first 100 sessions)

| Method | sessions_detected | sessions_checked | tcp_sessions_success_min2asset | success_rate | Notes |
|---|---:|---:|---:|---:|---|
| ebpf-http-session | 45 | 45 | 45 | 100.00% |  |
| libpcap-http | 43 | 43 | 43 | 100.00% |  |
| netsniff-http | 44 | 44 | 44 | 100.00% |  |
| pypcap-http | 44 | 44 | 44 | 100.00% |  |
| rawsocket-http | 40 | 40 | 40 | 100.00% |  |
| rawsocket-http-tpacketv3 | 45 | 45 | 45 | 100.00% |  |
| scapy-http | 46 | 46 | 46 | 100.00% |  |
| tshark-http | 45 | 45 | 45 | 100.00% |  |
| dpkt-http | 45 | 45 | 44 | 97.78% |  |
| tcpdump-http | 45 | 45 | 44 | 97.78% |  |
| suricata-http | 41 | 41 | 40 | 97.56% |  |
| zeek-http | 0 | 0 | 0 | 0.00% | zeek binary not found |
