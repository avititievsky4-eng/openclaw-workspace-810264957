# HTTP all-methods latest run (20s, workers=1)

| Method | requests_ok | GET_seen | 200_seen | GET ratio | Notes |
|---|---:|---:|---:|---:|---|
| pypcap-http | 840 | 840 | 840 | 100.00% |  |
| rawsocket-http | 735 | 735 | 1,470 | 100.00% |  |
| rawsocket-http-tpacketv3 | 861 | 861 | 0 | 100.00% |  |
| scapy-http | 945 | 945 | 1,890 | 100.00% |  |
| tshark-http | 882 | 882 | 882 | 100.00% |  |
| netsniff-http | 882 | 881 | 881 | 99.89% |  |
| tcpdump-http | 861 | 860 | 859 | 99.88% |  |
| dpkt-http | 903 | 898 | 898 | 99.45% |  |
| libpcap-http | 840 | 803 | 42 | 95.60% |  |
| suricata-http | 903 | 814 | 814 | 90.14% |  |
| ebpf-http-session | 903 | 0 | 0 | 0.00% |  |
| zeek-http | 903 | 0 | 0 | 0.00% | zeek binary not found |
