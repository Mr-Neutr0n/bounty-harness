# Auth False Positive Filter Runbook

## Purpose
Filter out common auth false positives. Many auth "issues" appear real but are just default frameworks, intentional behaviors, or scope-excluded features.

## Variables
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/auth`

## FP-1 — JWT "none" Algorithm False Positive

### Pattern: Server accepts alg:none but validates audience/issuer
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"user","aud":"wrong"}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."
curl -sk -H "Authorization: Bearer $TOKEN" "$TARGET_URL/api/public" -o "$EVIDENCE_DIR/fp-jwt-public-check.txt"
# If only works on public endpoints -> not a vulnerability
# If works on protected endpoints -> real finding
```

### Pattern: JWT signature validation only in some microservices
```bash
ENDPOINTS="/api/user /api/admin /api/orders /api/settings /api/public"
for ep in $ENDPOINTS; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$TARGET_URL$ep")
  echo "$ep: $CODE" >> "$EVIDENCE_DIR/fp-jwt-endpoint-check.txt"
done
```

## FP-2 — Session Fixation False Positive

### Pattern: Session is rotated but still set same value in cookie jar
```bash
curl -sk -c "$EVIDENCE_DIR/fp-fix-post.txt" -d "user=test&pass=test" "$TARGET_URL/login" -o /dev/null
curl -sk -b "$EVIDENCE_DIR/fp-fix-post.txt" "$TARGET_URL/api/me" -o "$EVIDENCE_DIR/fp-fix-post-check.txt"
grep -qiE 'not authenticated|unauthorized|login' "$EVIDENCE_DIR/fp-fix-post-check.txt" && echo "OK: old session rejected — no fixation"
```

### Pattern: Pre-login cookie is just a tracking cookie, not auth session
```bash
PRE_COOKIES=$(cat "$EVIDENCE_DIR/request/02-fixation-prelogin-cookies.txt" | grep -v '^\s*$' | grep -v '^#')
POST_COOKIES=$(cat "$EVIDENCE_DIR/response/02-fixation-postlogin-cookies.txt" | grep -v '^\s*$' | grep -v '^#')
# Only auth-related cookie names matter (session, auth, token, sid, connect.sid)
```

## FP-3 — Password Reset False Positive

### Pattern: "Email sent" message shown regardless of user existence
```bash
curl -sk "$TARGET_URL/forgot" -d "email=nonexistent_xy12z@target.com" -o "$EVIDENCE_DIR/fp-reset-nonexistent.txt"
curl -sk "$TARGET_URL/forgot" -d "email=admin@target.com" -o "$EVIDENCE_DIR/fp-reset-admin.txt"
diff "$EVIDENCE_DIR/fp-reset-nonexistent.txt" "$EVIDENCE_DIR/fp-reset-admin.txt" > "$EVIDENCE_DIR/fp-reset-diff.txt"
# If identical -> no enumeration possible (by design, good security practice)
```

### Pattern: Host header injection works but reset link still uses server hostname
```bash
# Verify the actual email contains the injected host, not just HTTP response
```

## FP-4 — IDOR False Positive

### Pattern: Resource is intentionally public
```bash
curl -sk "$TARGET_URL/api/user/1" -o "$EVIDENCE_DIR/fp-idor-anon.txt"
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/user/1" -o "$EVIDENCE_DIR/fp-idor-auth.txt"
diff "$EVIDENCE_DIR/fp-idor-anon.txt" "$EVIDENCE_DIR/fp-idor-auth.txt"
# If both return same content -> resource is public by design, not IDOR
# If auth returns extra fields -> real IDOR
```

### Pattern: Sequential IDs but authorization is enforced
```bash
curl -sk -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "$TARGET_URL/api/user/99999" > "$EVIDENCE_DIR/fp-idor-99999-code.txt"
# If returns 403/404 -> auth enforced, sequential IDs not exploitable
```

## Confidence Scoring Guide

| Score | Criteria |
|---|---|
| 10/10 | Auth bypass works on multiple protected endpoints, verified with separate accounts |
| 8/10 | Works on key endpoints, reproducible, demonstrates privilege escalation |
| 5/10 | Works inconsistently, only on certain endpoints, partial data exposure |
| 2/10 | Works but only on public endpoints or test endpoints |
| 0/10 | Default framework behavior, intentional design, scope excluded |

## Verification Checklist
```
[ ] Tested with two different accounts (not just your own)
[ ] Verified protected endpoint returns 401/403 normally
[ ] Verified bypass works on multiple protected endpoints
[ ] Confirmed it's not a public endpoint by design
[ ] Tested from different browser/incognito (no cached auth)
[ ] No real users' data modified or exposed in testing
[ ] Scope allows auth testing on this target
```

## Next Routing
- Passes filters with confidence >= 8 -> `runbooks/05-evidence-collection.md`
- Passes filters with confidence 5-7 -> re-test with additional methods
- Confidence < 5 -> discard finding
