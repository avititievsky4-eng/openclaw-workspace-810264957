# HTTP session checks (fixed run: duration=20s, workers=1)

Criteria: `min2_asset_ok` per detected session.

| Method | pass@100 | sessions_detected | Notes |
|---|---:|---:|---|
| dpkt-http | 44/45 | 45 |  |\n| ebpf-http-session | 45/45 | 45 |  |\n| libpcap-http | 44/44 | 44 |  |\n| netsniff-http | 45/45 | 45 |  |\n| pypcap-http | 44/44 | 44 |  |\n| rawsocket-http | 39/39 | 39 |  |\n| rawsocket-http-tpacketv3 | 45/45 | 45 |  |\n| scapy-http | 46/46 | 46 |  |\n| suricata-http | 40/40 | 40 |  |\n| tcpdump-http | 44/44 | 44 |  |\n| tshark-http | 45/45 | 45 |  |\n| zeek-http | 0/0 | 0 | zeek binary not found |\n