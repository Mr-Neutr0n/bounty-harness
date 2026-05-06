#!/usr/bin/env python3
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        forwarded_host = self.headers.get("X-Forwarded-Host", "")

        self.send_response(200)
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        if forwarded_host:
            response = (
                "<html><head>"
                '<script src="//' + forwarded_host + '/tracking.js"></script>'
                '<link rel="stylesheet" href="//' + forwarded_host + '/styles.css" />'
                "</head><body>"
                "<h1>Welcome</h1>"
                "<p>Page cached and served via CDN</p>"
                "</body></html>"
            )
        else:
            response = (
                "<html><head>"
                '<script src="/static/tracking.js"></script>'
                '<link rel="stylesheet" href="/static/styles.css" />'
                "</head><body>"
                "<h1>Welcome</h1>"
                "<p>Page cached and served via CDN</p>"
                "</body></html>"
            )

        self.wfile.write(response.encode())


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"cache-poison fixture listening on port {PORT}")
    httpd.serve_forever()