#!/usr/bin/env python3
import http.server
import json
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8087

SCHEMA = {
    "__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "kind": "OBJECT",
                "name": "Query",
                "fields": [
                    {"name": "user", "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}], "type": {"kind": "OBJECT", "name": "User"}},
                    {"name": "allUsers", "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}},
                    {"name": "secretData", "type": {"kind": "OBJECT", "name": "Secret"}},
                ],
            },
            {
                "kind": "OBJECT",
                "name": "User",
                "fields": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                    {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "passwordHash", "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "ssn", "type": {"kind": "SCALAR", "name": "String"}},
                ],
            },
            {
                "kind": "OBJECT",
                "name": "Secret",
                "fields": [
                    {"name": "apiKey", "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "internalEndpoint", "type": {"kind": "SCALAR", "name": "String"}},
                ],
            },
            {
                "kind": "OBJECT",
                "name": "Mutation",
                "fields": [
                    {"name": "deleteUser", "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}], "type": {"kind": "SCALAR", "name": "Boolean"}},
                ],
            },
        ],
    }
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()

        try:
            query_data = json.loads(body)
            query = query_data.get("query", "")
        except json.JSONDecodeError:
            query = ""

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if "__schema" in query or "IntrospectionQuery" in query:
            self.wfile.write(json.dumps({"data": SCHEMA}).encode())
        else:
            self.wfile.write(
                json.dumps({
                    "data": {
                        "user": {
                            "id": "1",
                            "email": "admin@example.com",
                        }
                    }
                }).encode()
            )

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"GraphQL endpoint -- POST to /graphql\n")


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"graphql-introspection fixture listening on port {PORT}")
    httpd.serve_forever()