# Packet Bench (HTTP + SCTP)

This repo contains benchmark suites for:
- **HTTP/session parsing**
- **SCTP packet capture**

## HTTP suite

Methods:
- `http_bench/benchmark_http_scapy.py`
- `http_bench/benchmark_http_libpcap.py`
- `http_bench/benchmark_http_tcpdump.py`
- `http_bench/benchmark_http_rawsocket.py`
- `http_bench/benchmark_http_rawsocket_tpacketv3.py`
- `http_bench/benchmark_http_pypcap.py`
- `http_bench/benchmark_http_ebpf.py`

Run:
```bash
cd packet-bench
./run_http_compare_all.sh 6 8
```
- arg1 = duration (seconds)
- arg2 = workers

## SCTP suite

Methods:
- `sctp_bench/benchmark_sctp_scapy.py`
- `sctp_bench/benchmark_sctp_tcpdump.py`
- `sctp_bench/benchmark_sctp_libpcap.py`
- `sctp_bench/benchmark_sctp_pypcap.py`
- `sctp_bench/benchmark_sctp_rawsocket.py`
- `sctp_bench/benchmark_sctp_ebpf.py`

Generators:
- `sctp_bench/generate_sctp_scapy.py`
- `sctp_bench/generate_sctp_tcpreplay.py`

Run (default):
```bash
cd packet-bench
./run_sctp_compare_all.sh 10 1024 16
```
- arg1 = duration (seconds)
- arg2 = payload bytes
- arg3 = generator threads
- arg4 = iface (optional, default `eth0`)
- arg5 = generator PPS (optional, default `0` = topspeed)

Example with fixed rate (the “~half Scapy” scenario):
```bash
./run_sctp_compare_all.sh 3 512 1 eth0 10000 192.168.86.47
```

## Notes
- Most methods require `sudo`.
- Loopback (`lo`) may show packet duplication for raw capture methods; normalized counters are used where relevant.
- Results are written under `packet-bench/results/`.
