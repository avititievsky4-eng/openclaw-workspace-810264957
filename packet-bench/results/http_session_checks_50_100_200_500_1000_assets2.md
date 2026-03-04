# HTTP session checks (assets=2, latest 20s run)

Criteria: pass if `min2_asset_ok=true`.

| Method | 50 | 100 | 200 | 500 | 1000 | sessions_detected | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| dpkt-http | 0/50 | 0/100 | 0/200 | 0/426 | 0/426 | 426 |  |\n| ebpf-http-session | 0/50 | 0/100 | 0/200 | 0/423 | 0/423 | 423 |  |\n| libpcap-http | 0/50 | 0/100 | 0/200 | 0/398 | 0/398 | 398 |  |\n| netsniff-http | 0/50 | 0/100 | 0/200 | 0/419 | 0/419 | 419 |  |\n| pypcap-http | 0/50 | 0/100 | 0/200 | 0/401 | 0/401 | 401 |  |\n| rawsocket-http | 0/50 | 0/100 | 0/200 | 0/368 | 0/368 | 368 |  |\n| rawsocket-http-tpacketv3 | 0/50 | 0/100 | 0/200 | 0/419 | 0/419 | 419 |  |\n| scapy-http | 0/50 | 0/100 | 0/200 | 0/446 | 0/446 | 446 |  |\n| suricata-http | 0/50 | 0/100 | 0/200 | 0/386 | 0/386 | 386 |  |\n| tcpdump-http | 0/50 | 0/100 | 0/200 | 0/426 | 0/426 | 426 |  |\n| tshark-http | 0/50 | 0/100 | 0/200 | 0/430 | 0/430 | 430 |  |\n| zeek-http | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 | zeek binary not found |\n