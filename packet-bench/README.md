# Packet Capture Stress Benchmark (Scapy vs libpcap)

Two Python projects were created:

- `scapy_project` (uses `scapy`)
- `libpcap_project` (uses `pcapy-ng`, a libpcap binding)

## Files

- `scapy_project/benchmark_scapy.py`
- `libpcap_project/benchmark_libpcap.py`
- `run_compare.sh` — runs both and prints winner
- `results/*.json` — benchmark outputs

## Run

```bash
cd packet-bench
./run_compare.sh 5 64
```

Arguments:

- first arg: duration in seconds
- second arg: UDP payload size in bytes

## Notes

- Capture tests require root (script uses sudo).
- Traffic is local only (`127.0.0.1`, UDP port `9999`) so no external network traffic is generated.
- If you want stronger stress, increase duration and payload, e.g. `./run_compare.sh 10 256`.
