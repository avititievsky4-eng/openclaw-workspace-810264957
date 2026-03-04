#!/usr/bin/env python3
import http.client
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


IMG_COUNT = 20
IMG_DELAY_S = 0.02
IMG_BYTES = b'\x89PNG\r\n\x1a\n' + (b'X' * 8192)


class BenchHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        # New long-load model: one HTML page that references many images.
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


def generate_http_load(host: str, port: int, duration: float, workers: int = 4):
    """
    Long-load generator:
    - open /page?sid=X
    - then fetch IMG_COUNT assets from that page (/asset?...)

    Returns:
      {
        "requests_ok": <page+asset successful requests>,
        "sessions_ok": <full page sessions completed>
      }
    """
    stop_at = time.perf_counter() + duration
    sid_counter = 0
    requests_ok = 0
    sessions_ok = 0
    lock = threading.Lock()

    def worker():
        nonlocal sid_counter, requests_ok, sessions_ok
        while time.perf_counter() < stop_at:
            with lock:
                sid = sid_counter
                sid_counter += 1

            local_ok = 0
            try:
                conn = http.client.HTTPConnection(host, port, timeout=2)
                conn.request('GET', f'/page?sid={sid}')
                resp = conn.getresponse()
                _ = resp.read()
                if resp.status == 200:
                    local_ok += 1
                conn.close()

                full_session = (resp.status == 200)
                for i in range(IMG_COUNT):
                    conn = http.client.HTTPConnection(host, port, timeout=2)
                    conn.request('GET', f'/asset?sid={sid}&i={i}')
                    r2 = conn.getresponse()
                    _ = r2.read()
                    if r2.status == 200:
                        local_ok += 1
                    else:
                        full_session = False
                    conn.close()

                with lock:
                    requests_ok += local_ok
                    if full_session and local_ok == (1 + IMG_COUNT):
                        sessions_ok += 1
            except Exception:
                with lock:
                    requests_ok += local_ok

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {'requests_ok': requests_ok, 'sessions_ok': sessions_ok}
