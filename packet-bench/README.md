# HTTP Benchmark Suite

This repository is now focused on **HTTP/session benchmarking only**.

## Included methods

- `http_bench/benchmark_http_scapy.py`
- `http_bench/benchmark_http_libpcap.py`
- `http_bench/benchmark_http_tcpdump.py`
- `http_bench/benchmark_http_rawsocket.py`
- `http_bench/benchmark_http_rawsocket_tpacketv3.py`
- `http_bench/benchmark_http_pypcap.py`
- `http_bench/benchmark_http_ebpf.py`

Shared helper:
- `http_bench/common_http.py`

Runner:
- `run_http_compare_all.sh`

Results summaries:
- `results/latest-http-summary.md`
- `results/graded-load-summary.md`

## Run

```bash
cd packet-bench
./run_http_compare_all.sh 6 8
```

Arguments:
- first arg: duration in seconds
- second arg: worker count

## Notes

- Requires sudo/root for packet capture methods.
- Uses local benchmark traffic on loopback (`127.0.0.1`).
