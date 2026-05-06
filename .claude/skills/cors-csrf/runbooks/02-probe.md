# CORS/CSRF — Runbook 02: Probe

## Purpose
Low-impact probing to confirm CORS/CSRF suspicion. Test origin reflection, credential forwarding, and CSRF token absence.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — (optional) authenticated cookie jar path

---

## W2.1 — Origin reflection fuzzing

```bash
echo "https://evil.com
https://attacker.evil.com
https://evil.target.com
https://target.com.evil.com
null
file://
https://target.com%60.evil.com
https://evil.com.target.com" > "$OUTDIR/cors-csrf/origin-payloads.txt"

while IFS= read -r endpoint; do
  while IFS= read -r origin; do
    result=$(curl -s -o /dev/null -w '%{http_code}' "$endpoint" \
      -H "Origin: $origin" 2>/dev/null)
    acao=$(curl -s -D - -o /dev/null "$endpoint" \
      -H "Origin: $origin" 2>/dev/null | grep -i 'access-control-allow-origin')
    echo "$endpoint | Origin: $origin | Status: $result | ACAO: $acao"
  done < "$OUTDIR/cors-csrf/origin-payloads.txt"
done < "$OUTDIR/cors-csrf/endpoints.txt" > "$OUTDIR/cors-csrf/origin-fuzz-results.txt"
```

## W2.2 — Test credentialed CORS (with cookies)

```bash
if [ -n "$COOKIE_JAR" ] && [ -f "$COOKIE_JAR" ]; then
  while IFS= read -r endpoint; do
    curl -s -o /dev/null -D - "$endpoint" \
      -b "$COOKIE_JAR" \
      -H "Origin: https://evil.com" \
      2>/dev/null | grep -iE '(access-control-allow-credentials|access-control-allow-origin|set-cookie)'
  done < "$OUTDIR/cors-csrf/endpoints.txt" > "$OUTDIR/cors-csrf/credentialed-cors-results.txt"
fi
```

## W2.3 — CSRF token presence check on form endpoints

```bash
while IFS= read -r line; do
  url=$(echo "$line" | awk '{print $NF}')
  body=$(curl -s "$url" 2>/dev/null)
  has_token=$(echo "$body" | grep -ciE '(csrf|_token|authenticity_token|xsrf|__RequestVerificationToken)')
  has_form=$(echo "$body" | grep -ciE '<form[^>]*method="?(POST|PUT|DELETE)')
  echo "$url | Forms: $has_form | Token indicators: $has_token"
done < "$OUTDIR/cors-csrf/form-endpoints.txt" > "$OUTDIR/cors-csrf/csrf-token-audit.txt"
```

## W2.4 — Null origin test (CORS bypass via null)

```bash
while IFS= read -r endpoint; do
  acao=$(curl -s -D - -o /dev/null "$endpoint" \
    -H "Origin: null" 2>/dev/null | grep -i 'access-control-allow-origin')
  acac=$(curl -s -D - -o /dev/null "$endpoint" \
    -H "Origin: null" 2>/dev/null | grep -i 'access-control-allow-credentials')
  echo "$endpoint | NullOrigin-ACAO: $acao | ACAC: $acac"
done < "$OUTDIR/cors-csrf/endpoints.txt" > "$OUTDIR/cors-csrf/null-origin-results.txt"
```

## W2.5 — Test subdomain Origin bypass

```bash
while IFS= read -r endpoint; do
  target_host=$(echo "$endpoint" | awk -F/ '{print $3}')
  acao=$(curl -s -D - -o /dev/null "$endpoint" \
    -H "Origin: https://evil.$target_host" 2>/dev/null | grep -i 'access-control-allow-origin')
  echo "$endpoint | evil.sub ACAO: $acao"
done < "$OUTDIR/cors-csrf/endpoints.txt" > "$OUTDIR/cors-csrf/suborigin-results.txt"
```

## W2.6 — Preflight OPTIONS analysis

```bash
curl -s -X OPTIONS "$TARGET_URL/api/me" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  -D "$OUTDIR/cors-csrf/preflight-headers.txt" \
  -o /dev/null 2>/dev/null

grep -iE 'access-control' "$OUTDIR/cors-csrf/preflight-headers.txt"
```

---

## Detection Signals

| Signal | Confidence | Next Step |
|---|---|---|
| ACAO reflects exactly the supplied Origin | HIGH | -> 03-verify.md |
| ACAO: * + ACAC: true | HIGH | -> 03-verify.md |
| ACAO: null + ACAC: true | MEDIUM | -> 03-verify.md W3.2 |
| POST forms with zero CSRF token indicators | MEDIUM | -> 03-verify.md W3.3 |
| ACAO reflects origin substring (prefix/suffix) | LOW | -> 03-verify.md W3.4 |

## False Positive Patterns

| Pattern | Meaning |
|---|---|
| ACAO: * WITHOUT ACAC: true | Public API -- no credentials, low risk |
| ACAO matches only exact TARGET_URL origin | Expected -- same-origin, no vuln |
| CSRF token present but not validated | False negative risk -- still test W3.3 |
| Vary: Origin header present | Likely properly implemented CORS |

---

## Next Routing

| Result | Route |
|---|---|
| Origin reflected (any variant) | -> 03-verify.md W3.1 |
| Null origin allowed | -> 03-verify.md W3.2 |
| Forms without CSRF tokens | -> 03-verify.md W3.3 |
| ACAO wildcard + ACAC true (browser blocks) | -> 06-false-positive-filter.md |
| All origins blocked / no reflection | -> Cease investigation |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/cors-csrf/origin-payloads.txt | Origin payload list |
| $OUTDIR/cors-csrf/origin-fuzz-results.txt | Origin fuzzing results |
| $OUTDIR/cors-csrf/credentialed-cors-results.txt | Credentialed CORS test output |
| $OUTDIR/cors-csrf/csrf-token-audit.txt | CSRF token audit per endpoint |
| $OUTDIR/cors-csrf/null-origin-results.txt | Null origin test results |
| $OUTDIR/cors-csrf/suborigin-results.txt | Subdomain origin bypass results |
| $OUTDIR/cors-csrf/preflight-headers.txt | Preflight OPTIONS response headers |
