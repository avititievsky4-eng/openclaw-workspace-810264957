# HTTP session checks latest (20s, workers=1)

Criteria: pass if `min2_asset_ok=true`.

| Method | 50 | 100 | 200 | 500 | 1000 | sessions_detected | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| dpkt-http | 42/43 | 42/43 | 42/43 | 42/43 | 42/43 | 43 |  |
| ebpf-http-session | 43/43 | 43/43 | 43/43 | 43/43 | 43/43 | 43 |  |
| libpcap-http | 33/40 | 33/40 | 33/40 | 33/40 | 33/40 | 40 |  |
| netsniff-http | 42/42 | 42/42 | 42/42 | 42/42 | 42/42 | 42 |  |
| pypcap-http | 40/40 | 40/40 | 40/40 | 40/40 | 40/40 | 40 |  |
| rawsocket-http | 35/35 | 35/35 | 35/35 | 35/35 | 35/35 | 35 |  |
| rawsocket-http-tpacketv3 | 41/41 | 41/41 | 41/41 | 41/41 | 41/41 | 41 |  |
| scapy-http | 45/45 | 45/45 | 45/45 | 45/45 | 45/45 | 45 |  |
| suricata-http | 38/39 | 38/39 | 38/39 | 38/39 | 38/39 | 39 |  |
| tcpdump-http | 41/41 | 41/41 | 41/41 | 41/41 | 41/41 | 41 |  |
| tshark-http | 42/42 | 42/42 | 42/42 | 42/42 | 42/42 | 42 |  |
| zeek-http | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 | zeek binary not found |
