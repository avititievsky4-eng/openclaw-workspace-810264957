# Packet Capture Stress Benchmark (All Methods)

Implemented methods:

- `scapy_project` (Scapy)
- `libpcap_project` (`pcapy-ng` / libpcap binding)
- `tcpdump_project` (tcpdump CLI on libpcap)
- `rawsocket_project` (Linux `AF_PACKET` raw socket)

## Files

- `scapy_project/benchmark_scapy.py`
- `libpcap_project/benchmark_libpcap.py`
- `tcpdump_project/benchmark_tcpdump.py`
- `rawsocket_project/benchmark_rawsocket.py`
- `run_compare.sh` — Scapy vs libpcap
- `run_compare_all.sh` — runs all methods and prints winner
- `results/*.json` — benchmark outputs

## Run

```bash
cd packet-bench
./run_compare_all.sh 5 64
```

Arguments:

- first arg: duration in seconds
- second arg: UDP payload size in bytes

## Latest 5s run (payload 64)

- `libpcap(pcapy-ng)`: 100.00% capture
- `raw_socket(AF_PACKET)`: 99.74% capture
- `scapy`: 1.86% capture
- `tcpdump(libpcap)`: 0.06% capture

## Notes

- Capture tests require root (scripts use sudo).
- Traffic is local only (`127.0.0.1`, UDP port `9999`) so no external network traffic is generated.
- For stronger stress, increase duration/payload (e.g. `./run_compare_all.sh 10 256`).
