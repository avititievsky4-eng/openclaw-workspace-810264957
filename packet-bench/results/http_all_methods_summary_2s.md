# HTTP all-methods summary (2s, workers=4, port=18080)

| Method | requests_ok | GET_seen | 200_seen | GET ratio | Notes |
|---|---:|---:|---:|---:|---|
| netsniff-http | 2,097 | 2,096 | 2,096 | 99.95% |  |
| tshark-http | 2,244 | 2,241 | 2,241 | 99.87% |  |
| dpkt-http | 2,050 | 2,020 | 2,018 | 98.54% |  |
| tcpdump-http | 1,801 | 1,774 | 1,774 | 98.50% |  |
| rawsocket-http-tpacketv3 | 1,742 | 1,709 | 0 | 98.11% |  |
| suricata-http | 2,094 | 1,997 | 1,996 | 95.37% |  |
| scapy-http | 2,070 | 1,082 | 2,364 | 52.27% |  |
| libpcap-http | 1,553 | 537 | 3 | 34.58% |  |
| pypcap-http | 1,648 | 555 | 546 | 33.68% |  |
| rawsocket-http | 1,653 | 374 | 487 | 22.63% |  |
| ebpf-http-session | 2,115 | 0 | 0 | 0.00% |  |
| zeek-http | 2,074 | 0 | 0 | 0.00% | zeek binary not found |
