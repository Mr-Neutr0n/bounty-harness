# Adding a New Fixture

## Directory structure

Create a new directory under `fixtures/` with exactly 4 files:

```
fixtures/<fixture-name>/
  fixture.yaml        # Metadata and controls
  app.py              # Vulnerable-by-design HTTP server
  test_positive.sh    # Start server, exploit vuln, verify detection
  test_negative.sh    # Start server, send benign input, verify no detection
```

## Step 1: Choose a port

Check existing port assignments in `fixtures/*/fixture.yaml`. Pick the next available port (highest used + 1). Never reuse a port.

## Step 2: Write fixture.yaml

```yaml
name: "<fixture-name>"
skill_tested: "<skill-id>"           # Must match a skill from the catalog
vulnerability_class: "<class-name>"  # e.g. command-injection, ssti, lfi
severity: "medium|high|critical"
description: "One-sentence summary of what this fixture demonstrates"
requirements:
  port: <unique-port>
  timeout: 10
positive_control: "Description of exploit input and expected vulnerable behavior"
negative_control: "Description of benign input and expected safe behavior"
```

The `skill_tested` field must match one of:
`recon`, `xss`, `sqli`, `ssrf`, `rce`, `auth`, `api`, `file-upload`, `cors-csrf`, `race-condition`, `cloud`, `mobile`, `osint`, `privesc`, `nuclei-scanner`, `http-protocol`

## Step 3: Write app.py

Must be self-contained Python 3 using only stdlib (`http.server`, `socketserver`, etc.). No Flask, no FastAPI, no third-party modules.

Template:

```python
#!/usr/bin/env python3
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else <default-port>


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # vulnerable logic here
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"response")


if __name__ == "__main__":
    httpd = http.server.HTTPServer(("", PORT), Handler)
    print(f"<fixture-name> fixture listening on port {PORT}")
    httpd.serve_forever()
```

- Always accept port from `sys.argv[1]`
- Always print a startup message with the port
- Always use `__name__ == "__main__"` guard
- Kill cleanly — no infinite retries or background threads

## Step 4: Write test_positive.sh

```bash
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=<fixture-port>

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

# Send exploit input
RESPONSE=$(curl -s <exploit-request>)
# Verify vulnerability is present
if <check-response>; then
    echo "POSITIVE TEST PASSED: <message>"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "POSITIVE TEST FAILED: <reason>"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi
```

Rules:
- Always use `SCRIPT_DIR` for locating `app.py`
- Always `set -e` at the top
- Always `sleep 1` after starting server
- Always kill the server before exiting
- Exit 0 for pass, exit 1 for fail

## Step 5: Write test_negative.sh

Same structure as test_positive.sh, but send benign input and verify the vulnerability signal is NOT present.

```bash
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=<fixture-port>

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

# Send benign input
RESPONSE=$(curl -s <benign-request>)
# Verify no vulnerability signal
if <check-no-vuln>; then
    echo "NEGATIVE TEST PASSED: <message>"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "NEGATIVE TEST FAILED: <reason>"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi
```

## Step 6: Make scripts executable

```bash
chmod +x fixtures/<fixture-name>/test_positive.sh
chmod +x fixtures/<fixture-name>/test_negative.sh
```

## Step 7: Verify compilation

```bash
python3 -m py_compile fixtures/<fixture-name>/app.py
echo "fixtures/<fixture-name>/app.py compiles"
```

## Step 8: Run standalone tests

```bash
bash fixtures/<fixture-name>/test_positive.sh && echo "POSITIVE OK"
bash fixtures/<fixture-name>/test_negative.sh && echo "NEGATIVE OK"
```

## Step 9: Register in fixture_types.txt

Add the fixture name to `payloads/fixture_types.txt`:
```
echo "<fixture-name>" >> payloads/fixture_types.txt
```

## Step 10: Update fixture-catalog.md

Add an entry following the same format as existing entries:
- Name, skill tested, vulnerability
- Port, positive control, negative control
- Detection method

## Checklist before submitting

- [ ] app.py compiles with `python3 -m py_compile`
- [ ] app.py uses only stdlib (no installs needed)
- [ ] test_positive.sh passes (exit 0)
- [ ] test_negative.sh passes (exit 0)
- [ ] Port does not conflict with existing fixtures
- [ ] fixture.yaml has all required fields
- [ ] fixture_types.txt includes the new name
- [ ] fixture-catalog.md has an entry
- [ ] Scripts are `chmod +x`
- [ ] Scripts clean up the server process