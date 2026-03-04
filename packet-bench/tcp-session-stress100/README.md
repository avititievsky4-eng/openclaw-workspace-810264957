# TCP Session Stress 100 (HTTP GET)

This folder runs a stress scenario and reports how many TCP sessions were successful per method.

## Goal
- Stress each HTTP capture method.
- Evaluate first **100 detected HTTP sessions** per method.
- A session is counted as successful when it loaded all required files for one page-load flow:
  - `1` page request (`/page?sid=...`)
  - `20` asset requests (`/asset?sid=...&i=...`)

## Run

```bash
cd packet-bench
./tcp-session-stress100/run_stress100_all_methods.sh
```

## Output
Results are written to:

- `packet-bench/results/http_tcp_sessions_stress100.md`
- `packet-bench/results/http_tcp_sessions_stress100.csv`

Columns:
- `method`
- `sessions_detected`
- `sessions_checked` (up to 100)
- `tcp_sessions_success`
- `success_rate`
- `notes`
