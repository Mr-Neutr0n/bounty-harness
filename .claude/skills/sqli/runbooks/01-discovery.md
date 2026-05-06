# SQL Injection — Discovery

## Purpose
Find every parameter, cookie, header, and JSON body field that could feed into a database query. Identifies numeric ID params, search terms, sort/filter parameters, and login form fields — the highest-value SQLi injection points.

## Required Variables
- `$TARGET_URL` — base target URL (e.g. `https://example.com`)
- `$OUTDIR` — output root

## Commands

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$OUTDIR/sqli"

# D1 — Arjun parameter discovery (GET + POST + JSON)
arjun -u "$TARGET_URL" -oJ "$OUTDIR/sqli/arjun_get.json"
arjun -u "$TARGET_URL/login" -m POST -oJ "$OUTDIR/sqli/arjun_post.json"
arjun -u "$TARGET_URL/api/search" -m POST --include-json -oJ "$OUTDIR/sqli/arjun_json.json"

jq -r '.results[] | "\(.url) -> \(.params[])"' "$OUTDIR/sqli"/arjun_get.json arjun_post.json arjun_json.json 2>/dev/null | sort -u > "$OUTDIR/sqli/all_params.txt"

# D2 — Harvest parameterized URLs from historical data
gau --subs "$TARGET_URL" | grep '\?' | sort -u > "$OUTDIR/sqli/gau_params.txt"
grep -oP '[?&]\K[A-Za-z0-9_-]+(?==)' "$OUTDIR/sqli/gau_params.txt" | sort -u > "$OUTDIR/sqli/param_names.txt"

# D3 — High-value SQLi targets (numeric/ID params)
grep -iE '[?&](id|uid|pid|user_id|product|category|article|post|news|page|sort|filter|order|offset|limit|type|status|action|do|mode|code|token|ref)=' "$OUTDIR/sqli/gau_params.txt" | uro > "$OUTDIR/sqli/high_value_targets.txt"

echo "High-value SQLi candidates: $(wc -l < "$OUTDIR/sqli/high_value_targets.txt")"

# D4 — katana crawl for hidden endpoints with DB-backed params
katana -u "$TARGET_URL" -jc -kf all -d 3 -c 50 -p 20 -timeout 10 -o "$OUTDIR/sqli/katana_crawl.txt"
grep '\?' "$OUTDIR/sqli/katana_crawl.txt" | uro >> "$OUTDIR/sqli/high_value_targets.txt"
sort -u "$OUTDIR/sqli/high_value_targets.txt" -o "$OUTDIR/sqli/high_value_targets.txt"

# D5 — Find form fields that map to DB columns
grep -oP 'name="[^"]+' "$OUTDIR/sqli/katana_crawl.txt" | cut -d'"' -f2 | sort -u > "$OUTDIR/sqli/form_fields.txt"

grep -iE '(username|email|password|login|signin|search|q|query|keyword|title|body|description|comment|message)' "$OUTDIR/sqli/form_fields.txt" > "$OUTDIR/sqli/db_backed_fields.txt"

# D6 — Cookie values (potential session/ID params in SQL queries)
curl -sI "$TARGET_URL" | grep -i 'set-cookie' | grep -oP '[A-Za-z0-9_-]+(?==)' > "$OUTDIR/sqli/cookie_names.txt"

# D7 — HTTP headers that may feed DB queries
curl -sI "$TARGET_URL" -H "User-Agent: sqli-probe" -H "X-Forwarded-For: 127.0.0.1" -H "Referer: https://test.com" > "$OUTDIR/sqli/header_probe.txt"
```

## Detection Signals
- `high_value_targets.txt` > 5 entries with `id=` pattern → strong SQLi surface
- `param_names.txt` includes `id`, `uid`, `sort`, `order`, `filter` → DB lookup params
- `db_backed_fields.txt` includes `username`, `email`, `password`, `search` → authentication + search SQL vectors
- Cookie values are UUIDs or numeric IDs → likely used in SQL queries for session lookup

## False Positives
- Static params like `utm_source`, `_ga` — filter: `grep -vE 'utm_|_ga|fbclid|gclid|mc_cid|mc_eid'`
- Arjun detecting reflected params that don't hit DB — needs SQL error testing to confirm
- katana crawling third-party CDN URLs — filter: `grep -i "$TARGET"`

## Next
├── If `high_value_targets.txt` > 0 → proceed to `02-probe.md` for error-based injection
├── If `db_backed_fields.txt` has login/search fields → proceed to `02-probe.md` on POST endpoints
├── If GET params found → test each with single-quote probe from `02-probe.md`
└── Always → save `high_value_targets.txt` as canonical SQLi injection surface