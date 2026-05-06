# CORS/CSRF — Runbook 06: False Positive Filter

## Purpose
Filter out common false positives before reporting. Apply verification checklist and confidence scoring.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory

---

## F6.1 — CORS False Positive Patterns

### Pattern 1: ACAO * without credentials (public API)

```bash
# Check if ACAC is present when ACAO is *
grep 'access-control-allow-origin: \*' "$OUTDIR/cors-csrf/"*headers*.txt 2>/dev/null | while read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  has_acac=$(grep -i 'access-control-allow-credentials: true' "$file")
  if [ -z "$has_acac" ]; then
    echo "FALSE POSITIVE: $file -- wildcard ACAO without ACAC (public API, not exploitable)"
  fi
done
```

### Pattern 2: ACAO matches only same origin

```bash
TARGET_HOST=$(echo "$TARGET_URL" | awk -F/ '{print $3}')

grep -li 'access-control-allow-origin' "$OUTDIR/cors-csrf/"*headers*.txt 2>/dev/null | while read -r file; do
  acao=$(grep -i 'access-control-allow-origin' "$file")
  # If ACAO only ever equals the target origin, it's correctly implemented
  reflected=$(grep "access-control-allow-origin.*evil" "$file" 2>/dev/null)
  if [ -z "$reflected" ]; then
    echo "LIKELY SAFE: $file -- ACAO present but never reflects attacker origin"
  fi
done
```

### Pattern 3: ACAO reflected but response is public

```bash
# If endpoint returns same data without authentication, CORS reflection is low impact
CORS_ENDPOINT="$TARGET_URL/api/public"

anon_body=$(curl -s "$CORS_ENDPOINT" -o "$OUTDIR/cors-csrf/fp-anon-response.txt" 2>/dev/null)
auth_body=""
[ -f "$COOKIE_JAR" ] && auth_body=$(curl -s -b "$COOKIE_JAR" "$CORS_ENDPOINT" -o "$OUTDIR/cors-csrf/fp-auth-response.txt" 2>/dev/null)

if [ "$anon_body" = "$auth_body" ]; then
  echo "FALSE POSITIVE: Endpoint returns same data with and without auth -- public endpoint, no impact"
fi
```

### Pattern 4: Preflight blocks actual request

```bash
curl -s -X OPTIONS "$TARGET_URL/api/me" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -D - -o /dev/null 2>/dev/null | head -1
# If preflight returns 4xx, browser will block the actual request
```

---

## F6.2 — CSRF False Positive Patterns

### Pattern 1: Token present but not visible in HTML source

```bash
# CSRF token may be set via JavaScript, not in page source
curl -s "$TARGET_URL/settings" ${COOKIE_JAR:+-b "$COOKIE_JAR"} | \
  grep -oiE '(csrf|token|nonce|xsrf)' | wc -l
# If >0, token might be JS-injected -- re-check with headless browser
```

### Pattern 2: Action accepted but not actually processed

```bash
# 200 OK doesn't mean state changed -- must verify
curl -s "$TARGET_URL/settings" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$OUTDIR/cors-csrf/fp-before.txt"

curl -s -X POST "$TARGET_URL/settings" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -d "email=test@test.com" \
  -o /dev/null -w "%{http_code}"

curl -s "$TARGET_URL/settings" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$OUTDIR/cors-csrf/fp-after.txt"

diff "$OUTDIR/cors-csrf/fp-before.txt" "$OUTDIR/cors-csrf/fp-after.txt"
# If no diff, action was accepted but not persisted -- false positive
```

### Pattern 3: Anti-CSRF via custom header (X-Requested-With, Content-Type)

```bash
# Some apps validate Content-Type or X-Requested-With
curl -s -X POST "$TARGET_URL/settings" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -H "Content-Type: text/plain" \
  -d "email=test@test.com" \
  -D - -o /dev/null | head -1
# If 415 or 400, app enforces Content-Type -- may be partial protection
```

---

## F6.3 — Confidence Scoring Checklist

Answer each with YES / NO / UNCLEAR:

```bash
cat > "$EVIDENCE_DIR/confidence-checklist.txt" << 'CHECKEOF'
CORS Misconfig Confidence Checklist
====================================
[ ] Origin reflected in ACAO header? (required)
[ ] ACAC: true present? (increases severity)
[ ] Response contains authenticated/sensitive data?
[ ] Not a public API endpoint (same data w/o auth)?
[ ] Preflight does NOT block the cross-origin request?
[ ] Exploitable in a real browser (not just curl)?

CSRF Confidence Checklist
=========================
[ ] State-changing action (POST/PUT/DELETE/PATCH)?
[ ] No CSRF token in request body or headers?
[ ] Token bypass attempted (empty, removed, GET)?
[ ] Action actually persisted (verified state change)?
[ ] Cookie auth (not Bearer token)?
[ ] No SameSite: Strict/Lax protection?

Scoring:
- 5-6 YES for either = HIGH confidence
- 3-4 YES = MEDIUM confidence (needs more verification)
- 0-2 YES = LOW confidence (likely false positive)
CHECKEOF

echo "Go through the checklist above and score your finding."
echo "HIGH -> report. MEDIUM -> re-verify. LOW -> discard."
```

---

## F6.4 — Same-Site Cookie Check

```bash
# Check if cookies use SameSite (mitigates CSRF)
curl -s -D - -o /dev/null "$TARGET_URL" ${COOKIE_JAR:+-b "$COOKIE_JAR"} 2>/dev/null | \
  grep -i 'set-cookie' | grep -i 'samesite'
# If SameSite=Strict or SameSite=Lax, CSRF may be mitigated
```

---

## Next Routing

| Score | Route |
|---|---|
| HIGH confidence (5-6 checklist items) | -> 05-evidence-collection.md (package for report) |
| MEDIUM confidence (3-4 items) | -> 03-verify.md (re-verify with additional tests) |
| LOW confidence (0-2 items) | -> Discard or document as informational |
| SameSite=Strict on session cookie | -> CSRF likely mitigated; focus on CORS only |
