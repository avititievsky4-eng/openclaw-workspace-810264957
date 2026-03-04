#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--suffix', default='30s', help='JSON suffix, e.g. 30s for http_*_30s.json')
    ap.add_argument('--limit', type=int, default=100, help='How many sessions to evaluate per method')
    args = ap.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    pattern = os.path.join(root, 'results', f'http_*_{args.suffix}.json')
    files = sorted(glob.glob(pattern))
    if not files:
        raise SystemExit(f'No files matched: {pattern}')

    rows = []
    for fp in files:
        j = json.load(open(fp))
        method = j.get('tool', os.path.basename(fp))
        notes = j.get('unavailable', '')
        sess = j.get('sniff_session_files', {}) or {}
        sids = sorted([int(k) for k in sess.keys()])
        checked = sids[: args.limit]

        success = 0
        for sid in checked:
            rec = sess[str(sid)]
            if rec.get('min20_ok'):
                success += 1

        rows.append({
            'method': method,
            'sessions_detected': len(sids),
            'sessions_checked': len(checked),
            'tcp_sessions_success': success,
            'success_rate': (success / len(checked) * 100.0) if checked else 0.0,
            'notes': notes,
        })

    rows.sort(key=lambda r: r['success_rate'], reverse=True)

    out_csv = os.path.join(root, 'results', 'http_tcp_sessions_stress100.csv')
    out_md = os.path.join(root, 'results', 'http_tcp_sessions_stress100.md')

    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['method', 'sessions_detected', 'sessions_checked', 'tcp_sessions_success', 'success_rate', 'notes'],
        )
        w.writeheader()
        w.writerows(rows)

    with open(out_md, 'w') as f:
        f.write('# HTTP TCP sessions stress report (target: first 100 sessions)\n\n')
        f.write('| Method | sessions_detected | sessions_checked | tcp_sessions_success | success_rate | Notes |\n')
        f.write('|---|---:|---:|---:|---:|---|\n')
        for r in rows:
            f.write(
                f"| {r['method']} | {r['sessions_detected']} | {r['sessions_checked']} | {r['tcp_sessions_success']} | {r['success_rate']:.2f}% | {r['notes']} |\n"
            )

    print('wrote', out_csv)
    print('wrote', out_md)


if __name__ == '__main__':
    main()
