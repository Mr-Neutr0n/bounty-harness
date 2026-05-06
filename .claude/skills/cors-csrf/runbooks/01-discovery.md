# CORS/CSRF — Runbook 01: Discovery

## Purpose
Discover endpoints with potential CORS misconfigurations or CSRF token weaknesses. Identify which origins/endpoints to test.

## Variables
- `$TARGET_URL` — base URL (e.g., https://example.com)
- `$OUTDIR` — output directory for this run
- `$CONTEXT` — (optional) prior recon output (httpx json, katana crawl)

---

## W1.1 — Crawl endpoints from prior recon

```bash
katana -u "$TARGET_URL" -d 5 -jc -kf -sf -o "$OUTDIR/cors-csrf/endpoints.txt"
```

If `$CONTEXT` is a file of URLs from recon:

```bash
katana -list "$CONTEXT" -d 3 -jc -kf -sf -o "$OUTDIR/cors-csrf/endpoints.txt"
```

## W1.2 — Scan for CORS headers with nuclei

```bash
nuclei -list "$OUTDIR/cors-csrf/endpoints.txt" \
  -t ~/nuclei-templates/http/cors/ \
  -o "$OUTDIR/cors-csrf/nuclei-cors.txt" \
  -silent
```

## W1.3 — Check Access-Control headers on discovered endpoints

```bash
while IFS= read -r url; do
  echo "=== $url ==="
  curl -s -o /dev/null -D - -X OPTIONS "$url" \
    -H "Origin: https://attacker.evil.com" \
    -H "Access-Control-Request-Method: GET" 2>/dev/null \
    | grep -iE '(access-control|allow-origin|allow-credentials|allow-methods)'
  echo ""
done < "$OUTDIR/cors-csrf/endpoints.txt" > "$OUTDIR/cors-csrf/headers-raw.txt"
```

## W1.4 — Identify endpoints with forms (CSRF target surface)

```bash
cat "$OUTDIR/cors-csrf/endpoints.txt" | httpx -silent -mc 200 | \
  while IFS= read -r url; do
    curl -s "$url" | grep -iE '<form[^>]*method="?(POST|PUT|DELETE|PATCH)' && echo "  FORM: $url"
  done > "$OUTDIR/cors-csrf/form-endpoints.txt"
```

## W1.5 — Extract all JS files for CORS header audit

```bash
cat "$OUTDIR/cors-csrf/endpoints.txt" | grep -E '\.(js)(\?|$)' > "$OUTDIR/cors-csrf/js-files.txt"
```

---

## Signals — what indicates CORS/CSRF surface is present

| Signal                                                    | Means                                  |
| --------------------------------------------------------- | -------------------------------------- |
| `Access-Control-Allow-Origin: *` in curl response         | Wildcard CORS — high priority          |
| `Access-Control-Allow-Origin: https://attacker.evil.com`  | Origin reflection — likely exploitable |
| `Access-Control-Allow-Credentials: true` + reflected origin | Credentialed CORS — critical         |
| `<form method="POST">` with no CSRF token input           | Potential CSRF — further testing needed|
| `<meta name="csrf-param"` or `_csrf` hidden input         | CSRF token exists — test bypass        |

---

## Next Routing

| Finding                              | Route                                      |
| ------------------------------------ | ------------------------------------------ |
| Origin reflection detected           | → `02-probe.md` W2.1 (origin fuzzing)      |
| ACAO wildcard + credentials          | → `02-probe.md` W2.2 (credentialed CORS)   |
| POST forms without tokens            | → `02-probe.md` W2.3 (CSRF token check)    |
| No CORS headers at all               | → `02-probe.md` W2.4 (null origin test)    |
| Nuclei found high-confidence matches | → `03-verify.md`                           |

---

## Output Files

| File                                       | Contents                                     |
| ------------------------------------------ | -------------------------------------------- |
| `$OUTDIR/cors-csrf/endpoints.txt`          | All crawled endpoints                        |
| `$OUTDIR/cors-csrf/nuclei-cors.txt`        | Nuclei CORS template findings                |
| `$OUTDIR/cors-csrf/headers-raw.txt`        | Raw Access-Control headers per endpoint      |
| `$OUTDIR/cors-csrf/form-endpoints.txt`     | Endpoints containing POST/PUT/DELETE forms   |
| `$OUTDIR/cors-csrf/js-files.txt`           | JavaScript file URLs for further analysis    |