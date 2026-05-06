#!/usr/bin/env python3
import http.server
import sqlite3
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8082

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
conn.execute("INSERT INTO users VALUES (2, 'user', 'password')")
conn.commit()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        username = params.get("username", [""])[0]

        query = f"SELECT * FROM users WHERE username = '{username}'"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        try:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            response = str(rows)
        except Exception as exc:
            response = f"Error: {exc}"

        self.wfile.write(response.encode())


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"sqli-error fixture listening on port {PORT}")
    httpd.serve_forever()