#!/usr/bin/env python3
import http.client
import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import re


IMG_COUNT = 2
IMG_DELAY_S = 0.02
IMG_BYTES = b'\x89PNG\r\n\x1a\n' + (b'X' * 8192)


class BenchHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        # Long-load model: one HTML page that references many images.
        if path == '/page':
            sid = q.get('sid', ['0'])[0]
            imgs = '\n'.join([f'<img src="/asset?sid={sid}&i={i}" />' for i in range(IMG_COUNT)])
            body = (
                '<!doctype html><html><head><title>bench</title></head>'
                f'<body><h1>session {sid}</h1>{imgs}</body></html>'
            ).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == '/asset':
            # Simulate longer waterfall loading.
            time.sleep(IMG_DELAY_S)
            body = IMG_BYTES
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Legacy endpoint kept for backward compatibility.
        if path.startswith('/bench'):
            body = b'OK'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def start_http_server(host: str, port: int):
    server = ThreadingHTTPServer((host, port), BenchHandler)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    return server


def _default_trace_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, '..', 'results', 'http_session_traces'))


# Generic helpers for session/file mapping
def build_sniff_session_map(paths):
    # Convert sniffed URI list into per-session -> loaded-files mapping.
    """Build per-session loaded file map from sniffed HTTP request paths."""
    sid_re = re.compile(r'sid=(\d+)')
    sessions = defaultdict(list)
    for p in paths or []:
        if isinstance(p, (bytes, bytearray)):
            p = p.decode('utf-8', errors='ignore')
        m = sid_re.search(str(p))
        if not m:
            continue
        sid = m.group(1)
        sessions[sid].append(str(p))

    payload = {}
    for sid, files in sessions.items():
        uniq = sorted(set(files))
        asset_count = sum(1 for f in uniq if str(f).lstrip('/').startswith('asset?'))
        payload[sid] = {
            'files': uniq,
            'loaded_count': len(uniq),
            'asset_count': asset_count,
            'min1_asset_ok': asset_count >= 1,
            'min2_asset_ok': asset_count >= 2,
            'min20_ok': asset_count >= 20,
        }
    return payload


def load_session_files_map(sessions_file: str):
    # Read generator-produced sessions JSON and normalize into map form.
    """Load per-session file map from generator sessions trace JSON."""
    try:
        with open(sessions_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return {}

    out = {}
    for s in data.get('sessions', []):
        sid = str(s.get('sid'))
        files = s.get('loaded_files', []) or []
        uniq = sorted(set(files))
        asset_count = sum(1 for f in uniq if str(f).lstrip('/').startswith('asset?'))
        out[sid] = {
            'files': uniq,
            'loaded_count': len(uniq),
            'asset_count': asset_count,
            'min1_asset_ok': asset_count >= 1,
            'min2_asset_ok': asset_count >= 2,
            'min20_ok': asset_count >= 20,
        }
    return out


# Shared long-load generator
def generate_http_load(host: str, port: int, duration: float, workers: int = 4, trace_dir: str | None = None):
    # Core long-load driver used by all HTTP benchmark implementations.
    """
    Long-load generator:
    - open /page?sid=X
    - then fetch IMG_COUNT assets from that page (/asset?...)

    Also records a queue-like trace of loaded files per session:
    - queue_file: chronological request events (JSONL)
    - sessions_file: per-session loaded file list + completion flag (JSON)

    Returns:
      {
        "requests_ok": <page+asset successful requests>,
        "sessions_ok": <full page sessions completed>,
        "queue_file": <path>,
        "sessions_file": <path>
      }
    """
    stop_at = time.perf_counter() + duration
    sid_counter = 0
    requests_ok = 0
    sessions_ok = 0
    lock = threading.Lock()

    events = []
    session_files = defaultdict(list)
    session_done = {}

    run_id = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    trace_root = trace_dir or _default_trace_dir()
    os.makedirs(trace_root, exist_ok=True)
    queue_file = os.path.join(trace_root, f'http_load_queue_{run_id}.jsonl')
    sessions_file = os.path.join(trace_root, f'http_sessions_{run_id}.json')

    def rec_event(sid: int, path: str, status: int):
        ts = time.time()
        with lock:
            events.append({'ts': ts, 'sid': sid, 'path': path, 'status': status})
            if status == 200:
                session_files[str(sid)].append(path)

    def worker():
        nonlocal sid_counter, requests_ok, sessions_ok
        while time.perf_counter() < stop_at:
            with lock:
                sid = sid_counter
                sid_counter += 1

            local_ok = 0
            full_session = False
            conn = None
            try:
                # Keep one TCP connection per session (page + all assets).
                conn = http.client.HTTPConnection(host, port, timeout=2)
                page_path = f'/page?sid={sid}'
                conn.request('GET', page_path, headers={'Connection': 'keep-alive'})
                resp = conn.getresponse()
                _ = resp.read()
                rec_event(sid, page_path, int(resp.status))
                if resp.status == 200:
                    local_ok += 1
                    full_session = True

                for i in range(IMG_COUNT):
                    asset_path = f'/asset?sid={sid}&i={i}'
                    conn.request('GET', asset_path, headers={'Connection': 'keep-alive'})
                    r2 = conn.getresponse()
                    _ = r2.read()
                    rec_event(sid, asset_path, int(r2.status))
                    if r2.status == 200:
                        local_ok += 1
                    else:
                        full_session = False

                with lock:
                    requests_ok += local_ok
                    if full_session and local_ok == (1 + IMG_COUNT):
                        sessions_ok += 1
                        session_done[str(sid)] = True
                    else:
                        session_done[str(sid)] = False
            except Exception:
                with lock:
                    requests_ok += local_ok
                    session_done[str(sid)] = False
            finally:
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Persist queue trace (chronological)
    events.sort(key=lambda e: e['ts'])
    with open(queue_file, 'w', encoding='utf-8') as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + '\n')

    sessions_payload = {
        'img_count_expected': IMG_COUNT,
        'sessions': [
            {
                'sid': sid,
                'loaded_files': files,
                'loaded_count': len(files),
                'asset_count': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')),
                'min1_asset_ok': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')) >= 1,
                'min2_asset_ok': sum(1 for f in files if str(f).lstrip('/').startswith('asset?')) >= 2,
                'expected_count': 1 + IMG_COUNT,
                'completed': bool(session_done.get(sid, False) and len(files) == (1 + IMG_COUNT)),
            }
            for sid, files in sorted(session_files.items(), key=lambda kv: int(kv[0]))
        ],
    }
    with open(sessions_file, 'w', encoding='utf-8') as f:
        json.dump(sessions_payload, f, ensure_ascii=False, indent=2)

    return {
        'requests_ok': requests_ok,
        'sessions_ok': sessions_ok,
        'queue_file': queue_file,
        'sessions_file': sessions_file,
    }
