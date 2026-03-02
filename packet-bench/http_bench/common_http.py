#!/usr/bin/env python3
import http.client
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class BenchHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/bench'):
            body = b'OK'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
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
    stop_at = time.perf_counter() + duration
    counter = 0
    ok = 0
    lock = threading.Lock()

    def worker():
        nonlocal counter, ok
        while time.perf_counter() < stop_at:
            with lock:
                rid = counter
                counter += 1
            try:
                conn = http.client.HTTPConnection(host, port, timeout=1)
                conn.request('GET', f'/bench?id={rid}')
                resp = conn.getresponse()
                _ = resp.read()
                if resp.status == 200:
                    with lock:
                        ok += 1
                conn.close()
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return ok
