#!/usr/bin/env python3
import http.server
import sys
import urllib.parse
import urllib.request
import urllib.error

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8083


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        url = params.get("url", [""])[0]

        if not url:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Send a ?url= parameter to start SSRF fixture\n")
            return

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SSRF-Fixture/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()[:1024]
                status = resp.status
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            result = (
                f"Status: {status}\n"
                f"Body: {body.decode(errors='replace')[:500]}"
            )
            self.wfile.write(result.encode())
        except urllib.error.URLError as exc:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Fetch Error (URLError): {exc.reason}".encode())
        except Exception as exc:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Fetch Error: {exc}".encode())


if __name__ == "__main__":
    httpd = http.server.ThreadingHTTPServer(("", PORT), Handler)
    print(f"ssrf-blind fixture listening on port {PORT}")
    httpd.serve_forever()