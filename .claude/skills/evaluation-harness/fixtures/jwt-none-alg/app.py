#!/usr/bin/env python3
import base64
import http.server
import json
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8086


def _b64url_decode(encoded):
    s = encoded.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Missing or malformed Authorization header"}')
            return

        token = auth[7:]
        parts = token.split(".")

        if len(parts) != 3:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid JWT format"}')
            return

        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
            alg = header.get("alg", "")

            if alg == "none":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {
                    "authenticated": True,
                    "user": payload.get("sub", "unknown"),
                    "alg": "none",
                    "role": payload.get("role", "user"),
                }
                self.wfile.write(json.dumps(resp).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unsupported algorithm -- signature verification failed"}')
        except Exception:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Token processing error"}')


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"jwt-none-alg fixture listening on port {PORT}")
    httpd.serve_forever()