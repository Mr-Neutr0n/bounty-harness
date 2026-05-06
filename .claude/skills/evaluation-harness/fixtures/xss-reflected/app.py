#!/usr/bin/env python3
import http.server
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        q = params.get("q", [""])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = f"<html><body>Search results for: {q}</body></html>".encode()
        self.wfile.write(body)


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"xss-reflected fixture listening on port {PORT}")
    httpd.serve_forever()