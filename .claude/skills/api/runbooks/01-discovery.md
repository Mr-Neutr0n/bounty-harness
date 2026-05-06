# API Discovery Runbook

## Purpose
Discover API endpoints, map the API surface area, identify REST/GraphQL routes, and find documentation/configuration leaks.

## Variables
- `$TARGET_URL` — base URL (e.g., `https://target.com` or `https://api.target.com`)
- `$OUTDIR` — output directory
- `$WORDLIST_DIR` — path to wordlists dir
- `$COOKIE_JAR` — curl cookie jar

## Step 1 — REST API Endpoint Discovery

### W1A. Crawl for API paths with katana
```bash
katana -u "$TARGET_URL" -jc -kf all -d 3 -silent -field url | grep -iE '/api/|/v[0-9]/|/graphql|/rest/|/services/|/ws/' | sort -u > "$OUTDIR/api-endpoints-katana.txt"
```

### W1B. Wayback API URL discovery
```bash
gau "$TARGET_URL" | grep -iE '/api/|/v[0-9]/|/graphql|/rest/|/services/|/ws/' | sort -u > "$OUTDIR/api-endpoints-wayback.txt"
```

### W1C. API path brute-force
```bash
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST_DIR/api/api-paths.txt" -mc 200,301,302,401,403 -o "$OUTDIR/api-paths-ffuf.json" -of json
```

### W1D. Subdomain-based API discovery (api., dev-api., etc.)
```bash
subfinder -d "$TARGET_URL" -silent | grep -iE 'api|dev|staging|sandbox|internal|admin|test' | sort -u > "$OUTDIR/api-subdomains.txt"
```

## Step 2 — OpenAPI / Swagger / Postman Collection Discovery

### W2A. Discover API docs
```bash
for path in /swagger.json /swagger-ui.html /api-docs /openapi.json /swagger/v1/swagger.json /v2/api-docs /v3/api-docs /docs/api /api/swagger.json /_swagger /spec.json; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL$path")
  [ "$STATUS" != "404" ] && echo "$TARGET_URL$path -> $STATUS" >> "$OUTDIR/api-docs-found.txt"
done
```

### W2B. Fetch and parse discovered API docs
```bash
curl -sk "$TARGET_URL/swagger.json" -o "$OUTDIR/swagger.json" 2>/dev/null
curl -sk "$TARGET_URL/openapi.json" -o "$OUTDIR/openapi.json" 2>/dev/null
python3 -c "import json; d=json.load(open('$OUTDIR/swagger.json')); [print(p) for p in d.get('paths',{}).keys()]" 2>/dev/null > "$OUTDIR/swagger-endpoints.txt"
python3 -c "import json; d=json.load(open('$OUTDIR/openapi.json')); [print(p) for p in d.get('paths',{}).keys()]" 2>/dev/null > "$OUTDIR/openapi-endpoints.txt"
```

## Step 3 — GraphQL Discovery

### W3A. GraphQL endpoint discovery
```bash
for path in /graphql /gql /graphiql /graphql-explorer /query /api/graphql /v1/graphql /v2/graphql /playground; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL$path")
  [ "$STATUS" != "404" ] && echo "$TARGET_URL$path -> $STATUS" >> "$OUTDIR/graphql-found.txt"
done
```

### W3B. GraphQL introspection probe
```bash
curl -sk "$TARGET_URL/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}' -o "$OUTDIR/graphql-introspection.json"
python3 -c "import json; d=json.load(open('$OUTDIR/graphql-introspection.json')); print(json.dumps(d,indent=2))" 2>/dev/null | head -50
```

### W3C. GraphQL introspection via GET
```bash
curl -sk "$TARGET_URL/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D" -o "$OUTDIR/graphql-introspection-get.json"
```

## Step 4 — Method Fuzzing on Discovered Endpoints

### W4A. Combine all discovered endpoints
```bash
cat "$OUTDIR"/*-endpoints*.txt 2>/dev/null | sort -u > "$OUTDIR/all-api-endpoints.txt"
```

### W4B. Test HTTP methods on each endpoint
```bash
while read -r endpoint; do
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$TARGET_URL$endpoint")
    echo "$method $endpoint -> $CODE" >> "$OUTDIR/api-method-check.txt"
  done
done < "$OUTDIR/all-api-endpoints.txt"
```

## Step 5 — API Version Discovery
```bash
for v in v1 v2 v3 v4 v5 latest beta alpha; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL/api/$v/")
  echo "$v: $STATUS" >> "$OUTDIR/api-versions.txt"
done
```

## Signals
| Signal | Indicates |
|---|---|
| Swagger/OpenAPI JSON returned | Full API schema exposed — parse for all endpoints |
| GraphQL introspection enabled | Full schema queryable — enumerate types/queries/mutations |
| 405 Method Not Allowed | Endpoint exists but method not supported — try methods from Allow header |
| Internal API on public subdomain | Potential data exposure if auth is missing |
| 401/403 on API endpoint | Protected endpoint found, test auth bypass |

## Next Routing
- GraphQL introspection enabled -> `runbooks/02-probe.md` (GraphQL workflow)
- Swagger/OpenAPI discovered -> parse schema, test all endpoints for auth/mass assignment
- API endpoints discovered -> `runbooks/02-probe.md` (REST API workflow)
- No APIs found -> try subdomain enumeration or stop
