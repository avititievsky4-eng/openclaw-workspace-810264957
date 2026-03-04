# HTTP session checks (assets=2, latest 20s run, zeek removed)

Criteria: pass if session has at least 2 detected asset requests.

| Method | 50 | 100 | 200 | 500 | 1000 | sessions_detected | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| dpkt-http | 50/50 | 100/100 | 200/200 | 425/426 | 425/426 | 426 |  |
| ebpf-http-session | 50/50 | 100/100 | 200/200 | 423/423 | 423/423 | 423 |  |
| libpcap-http | 50/50 | 100/100 | 200/200 | 398/398 | 398/398 | 398 |  |
| netsniff-http | 50/50 | 100/100 | 200/200 | 419/419 | 419/419 | 419 |  |
| pypcap-http | 50/50 | 100/100 | 200/200 | 401/401 | 401/401 | 401 |  |
| rawsocket-http | 50/50 | 100/100 | 200/200 | 368/368 | 368/368 | 368 |  |
| rawsocket-http-tpacketv3 | 50/50 | 100/100 | 200/200 | 419/419 | 419/419 | 419 |  |
| scapy-http | 50/50 | 100/100 | 200/200 | 446/446 | 446/446 | 446 |  |
| suricata-http | 50/50 | 100/100 | 200/200 | 386/386 | 386/386 | 386 |  |
| tcpdump-http | 50/50 | 100/100 | 200/200 | 426/426 | 426/426 | 426 |  |
| tshark-http | 50/50 | 100/100 | 200/200 | 430/430 | 430/430 | 430 |  |
