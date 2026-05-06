#!/usr/bin/env python3
import http.server
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        filename = self.headers.get("X-Filename", "uploaded_file")
        filepath = os.path.join(UPLOAD_DIR, filename)

        with open(filepath, "wb") as uf:
            uf.write(body)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"File saved: {filename}".encode())

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = """<html><body>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
</body></html>"""
        self.wfile.write(html.encode())


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"upload-unrestricted fixture listening on port {PORT}")
    httpd.serve_forever()