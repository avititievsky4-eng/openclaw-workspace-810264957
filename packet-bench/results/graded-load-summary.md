# Graded HTTP load benchmark (with pypcap)

Loads:
- Very low: 2s, workers=2
- Low: 4s, workers=4
- Medium: 6s, workers=8
- High: 10s, workers=16

## GET ratio by method

| Method | 2s/2w | 4s/4w | 6s/8w | 10s/16w |
|---|---:|---:|---:|---:|
| tcpdump-http | 99.90% | 99.97% | 100.00% | 100.00% |
| rawsocket-http-tpacketv3 | 98.35% | 99.74% | 100.00% | 100.00% |
| scapy-http | 50.54% | 51.34% | 51.07% | 50.26% |
| pypcap-http | 49.21% | 32.85% | 33.71% | 33.37% |
| libpcap-http | 49.56% | 32.56% | 31.97% | 31.16% |
| rawsocket-http | 40.64% | 25.57% | 27.04% | 27.30% |

## eBPF session metric (not L7 GET parsing)

| Method | 2s/2w | 4s/4w | 6s/8w | 10s/16w |
|---|---:|---:|---:|---:|
| ebpf-http-session | 200.00% | 199.98% | 200.00% | 199.99% |
