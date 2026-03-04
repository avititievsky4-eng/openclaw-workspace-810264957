# HTTP all-methods latest run (20s, workers=1)

| Method | requests_ok | GET_seen | 200_seen | GET ratio | Notes |
|---|---:|---:|---:|---:|---|
| pypcap-http | 840 | 840 | 840 | 100.00% |  |\n| rawsocket-http | 735 | 735 | 1,470 | 100.00% |  |\n| rawsocket-http-tpacketv3 | 861 | 861 | 0 | 100.00% |  |\n| scapy-http | 945 | 945 | 1,890 | 100.00% |  |\n| tshark-http | 882 | 882 | 882 | 100.00% |  |\n| netsniff-http | 882 | 881 | 881 | 99.89% |  |\n| tcpdump-http | 861 | 860 | 859 | 99.88% |  |\n| dpkt-http | 903 | 898 | 898 | 99.45% |  |\n| libpcap-http | 840 | 803 | 42 | 95.60% |  |\n| suricata-http | 903 | 814 | 814 | 90.14% |  |\n| ebpf-http-session | 903 | 0 | 0 | 0.00% |  |\n| zeek-http | 903 | 0 | 0 | 0.00% | zeek binary not found |\n