# API False Positive Filter Runbook

## Purpose
Filter out common API false positives. Many API "findings" are actually intended functionality, test endpoints, or non-exploitable behaviors.

## Variables
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/api`
- `$TARGET_URL` — API under test

## FP-1 — GraphQL Introspection "Vulnerability" False Positive

### Pattern: Introspection is intentionally enabled (e.g., public API documentation)
```bash
curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL/graphql" -d '{"query":"{__schema{types{name}}}"}' > "$EVIDENCE_DIR/fp-gql-intro-code.txt"
# If this is a public API with public docs, introspection is expected
# Only a finding if: introspection exposes internal/private schemas, production data model
```

### Filter: Check if the schema contains obviously internal types
```bash
python3 -c "
import json
d=json.load(open('$OUTDIR/gql-full-introspection.json'))
types=[t.get('name','') for t in d.get('data',{}).get('__schema',{}).get('types',[])]
internal_keywords=['internal','private','secret','admin','debug','test','backup','migration']
found=[t for t in types for kw in internal_keywords if kw in t.lower()]
print('Internal types found:', found if found else 'None')
" > "$EVIDENCE_DIR/fp-gql-internal-types.txt"
# If internal types exposed -> real finding
# If only standard public types -> low severity or not an issue
```

### Pattern: GraphQL suggestions but no actual data leak
```bash
curl -sk "$TARGET_URL/graphql" -d '{"query":"{user(id:1){email password}}"}' -o "$EVIDENCE_DIR/fp-gql-real-leak-test.txt"
grep -qiE 'email|password' "$EVIDENCE_DIR/fp-gql-real-leak-test.txt" && echo "REAL LEAK" || echo "No data leak from suggestions alone"
# Field suggestions alone are info, not critical unless they reveal sensitive field names
```

## FP-2 — Mass Assignment "Vulnerability" False Positive

### Pattern: API returns 200 but role not actually changed
```bash
curl -sk -X PATCH "$TARGET_URL/api/me" -H "Content-Type: application/json" -b "$COOKIE_JAR" -d '{"role":"admin"}' -o "$EVIDENCE_DIR/fp-mass-before.json"
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/me" -o "$EVIDENCE_DIR/fp-mass-after.json"
BEFORE=$(python3 -c "import json; print(json.load(open('$EVIDENCE_DIR/fp-mass-before.json')).get('role',''))")
AFTER=$(python3 -c "import json; print(json.load(open('$EVIDENCE_DIR/fp-mass-after.json')).get('role',''))")
[ "$BEFORE" = "$AFTER" ] && echo "OK: role returned was just echoed, not persisted" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Pattern: Field accepted and returned but has no actual effect
```bash
curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/admin/users" -o "$EVIDENCE_DIR/fp-mass-real-admin-check.txt"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$TARGET_URL/api/admin/users")
[ "$HTTP_CODE" = "403" ] && echo "OK: admin endpoints still blocked despite role:admin in response" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Pattern: Test/staging environment accepts mass assignment but production does not
```bash
echo "$TARGET_URL" | grep -qiE 'dev|staging|test|sandbox|localhost' && echo "WARNING: testing against non-production environment" >> "$EVIDENCE_DIR/fp-log.txt"
```

## FP-3 — Rate Limiting "Vulnerability" False Positive

### Pattern: Rate limiting exists but threshold is high
```bash
for i in $(seq 1 100); do curl -sk -o /dev/null -w "%{http_code}\n" "$TARGET_URL/api/search?q=test$i"; done > "$EVIDENCE_DIR/fp-rate-threshold.txt"
# Rate limit of 60/min is reasonable, not a vulnerability
# Only report if no limit at all (or absurdly high like 1000/min)
```

### Pattern: Rate limit on specific endpoints (login) is the only expected case
```bash
# Some endpoints should NOT be rate-limited (GET lists, public search)
# Missing rate limit on login/reset is real; missing on search/listing is not always an issue
```

## FP-4 — "Auth Bypass" False Positive

### Pattern: Endpoint returns 200 but with empty or public data
```bash
AUTH_SIZE=$(curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/data" | wc -c)
ANON_SIZE=$(curl -sk "$TARGET_URL/api/data" | wc -c)
[ "$AUTH_SIZE" -gt "$ANON_SIZE" ] && echo "Auth returns more data — real issue" || echo "Both return same public data — not a bypass"
```

## Confidence Scoring Guide

| Score | Criteria |
|---|---|
| 10/10 | Privilege escalated, admin endpoints accessible, real data exposed |
| 8/10 | Field accepted, role elevated in response, but admin access not proven |
| 5/10 | Schema exposed but no sensitive types, rate limit high but present |
| 2/10 | Public API with docs, intentional introspection, test environment |
| 0/10 | Default framework behavior, expected public endpoint, rate limit exists |

## Next Routing
- Passes filters with confidence >= 8 -> `runbooks/05-evidence-collection.md`
- Confidence < 5 -> discard finding
