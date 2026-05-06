# XSS — Discovery

## Purpose
Identify every parameter, form field, HTTP header, and URL fragment that could reflect user input. Uses parameter mining, crawling, and static JS analysis to map all injection surfaces before firing a single payload.

## Required Variables
- `$TARGET_URL` — base target URL (e.g. `https://example.com`)
- `$OUTDIR` — output root for this scan session

## Commands

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$OUTDIR/xss"

# D1 — Arjun parameter discovery (GET params)
arjun -u "$TARGET_URL" -oJ "$OUTDIR/xss/arjun_get.json"
jq -r '.results[] | "\(.url) -> \(.params[])"' "$OUTDIR/xss/arjun_get.json" | sort -u > "$OUTDIR/xss/discovered_params_get.txt"

# D2 — Arjun POST parameters (including JSON body)
arjun -u "$TARGET_URL/login" -m POST -oJ "$OUTDIR/xss/arjun_post.json"
arjun -u "$TARGET_URL/api/search" -m POST --include-json -oJ "$OUTDIR/xss/arjun_json.json"

# D3 — Extract all parameterized URLs from historical crawl data
gau --subs "$TARGET_URL" | grep '\?' | sort -u > "$OUTDIR/xss/gau_params.txt"
cat "$OUTDIR/xss/gau_params.txt" | grep -oP '[?&]\K[A-Za-z0-9_-]+(?==)' | sort -u > "$OUTDIR/xss/all_param_names.txt"

# D4 — katana crawl for hidden endpoints and forms
katana -u "$TARGET_URL" -jc -kf all -d 3 -c 50 -p 20 -timeout 10 -o "$OUTDIR/xss/katana_crawl.txt"
grep -iE '(search|q=|query|comment|message|name|email|redirect|callback|return|url|id=|page)' "$OUTDIR/xss/katana_crawl.txt" > "$OUTDIR/xss/xss_candidate_endpoints.txt"

# D5 — Extract form field names (POST injection points)
grep -oP 'name="[^"]+' "$OUTDIR/xss/katana_crawl.txt" | cut -d'"' -f2 | sort -u > "$OUTDIR/xss/form_field_names.txt"

# D6 — JS analysis for DOM sources and sinks
python3 skills/xss/xss_dom_sink_scanner.py --url "$TARGET_URL" --output "$OUTDIR/xss/dom_xss_findings.json" 2>/dev/null
```

If standalone scripts are unavailable, use inline analysis:

```bash
mkdir -p "$OUTDIR/xss/js_downloads"
grep -E '\.js(\?|$)' "$OUTDIR/xss/gau_params.txt" "$OUTDIR/xss/katana_crawl.txt" 2>/dev/null | sort -u > "$OUTDIR/xss/js_urls.txt"

while read -r url; do
  fname=$(echo "$url" | md5)
  curl -sL -m 10 "$url" -o "$OUTDIR/xss/js_downloads/${fname}.js" 2>/dev/null
done < "$OUTDIR/xss/js_urls.txt"

rg -n 'location\.(href|hash|search)|document\.(URL|cookie|referrer)|window\.name|innerHTML|eval\(|postMessage' "$OUTDIR/xss/js_downloads/" > "$OUTDIR/xss/dom_sources_and_sinks.txt" 2>/dev/null
```

## Detection Signals
- `arjun_get.json` has `.results[].params` entries → GET params discovered
- `all_param_names.txt` > 10 unique entries → rich injection surface
- `dom_sources_and_sinks.txt` contains `location.hash` and `innerHTML` on same file → DOM XSS candidate
- `form_field_names.txt` includes `comment`, `message`, `name` → stored XSS surface

## False Positives
- Arjun detecting static/unchanging parameters like `_csrf`, `nonce` — filter: `grep -vE 'csrf|nonce|token'`
- JS source/sink matches inside minified libraries where taint doesn't actually flow — requires manual source-to-sink trace
- katana crawling external links (ads, CDN, analytics) — filter: `grep -i "$TARGET"`

## Next
├── If `all_param_names.txt` > 0 → proceed to `02-probe.md` for reflected XSS injection
├── If `form_field_names.txt` has input fields → proceed to `02-probe.md` for stored XSS on POST
├── If `dom_sources_and_sinks.txt` has matching sources+sinks → route to DOM XSS workflow
└── Always → save param list as canonical injection surface map