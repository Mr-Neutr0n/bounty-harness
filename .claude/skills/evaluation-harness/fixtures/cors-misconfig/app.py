#!/usr/bin/env python3
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8084


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        origin = self.headers.get("Origin", "")

        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data": "sensitive user data"}')

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")

        self.send_response(204)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "received": true}')


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"cors-misconfig fixture listening on port {PORT}")
    httpd.serve_forever()