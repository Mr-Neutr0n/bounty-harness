# SSRF — Discovery

## Purpose
Identify every parameter, endpoint, and API that accepts a URL, hostname, or IP address as user input. Covers URL importers, webhooks, file fetchers, image proxies, redirect params, PDF generators, and JS URL-accepting functions.

## Required Variables
- `$TARGET_URL` — base target URL (e.g. `https://example.com`)
- `$OUTDIR` — output root

## Commands

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$OUTDIR/ssrf"

# D1 — Grep all harvested URLs for URL-accepting parameter names
gau --subs "$TARGET_URL" | rg -i '(url|uri|link|path|src|dest|redirect|next|file|document|crawl|fetch|proxy|callback|webhook|endpoint|host|domain|site|resource|api_url|image_url|upload_url|import_url|feed_url|download_url|media_url|avatar_url|thumbnail_url|preview_url)=' | sort -u > "$OUTDIR/ssrf/candidate_params_raw.txt"

# D2 — Filter to only entries that contain full http/https URLs (confirmed URL-accepting)
rg '=https?://' "$OUTDIR/ssrf/candidate_params_raw.txt" > "$OUTDIR/ssrf/ssrf_confirmed_urls.txt"
echo "Confirmed URL-accepting params: $(wc -l < "$OUTDIR/ssrf/ssrf_confirmed_urls.txt")"

# D3 — Extract unique param names that accept URLs
grep -oP '[?&]\K[A-Za-z_-]+(?==https?://)' "$OUTDIR/ssrf/ssrf_confirmed_urls.txt" | sort -u > "$OUTDIR/ssrf/ssrf_param_names.txt"

# D4 — JS analysis for URL-accepting functions
mkdir -p "$OUTDIR/ssrf/js_downloads"
grep -E '\.js(\?|$)' "$OUTDIR/ssrf/candidate_params_raw.txt" 2>/dev/null | grep -v 'jquery|bootstrap' | sort -u > "$OUTDIR/ssrf/js_urls.txt"

while read -r url; do
  fname=$(echo "$url" | md5)
  curl -sL -m 10 "$url" -o "$OUTDIR/ssrf/js_downloads/${fname}.js" 2>/dev/null
done < "$OUTDIR/ssrf/js_urls.txt"

# Find URL-accepting JS patterns
rg -n '(fetch\(|axios\(|XMLHttpRequest|\.open\(|got\(|request\(|http\.request|urlopen|curl_exec|file_get_contents|copy\(|fopen\()' "$OUTDIR/ssrf/js_downloads/" > "$OUTDIR/ssrf/js_urlcallers.txt" 2>/dev/null

# D5 — katana crawl with form extraction for URL inputs
katana -u "$TARGET_URL" -jc -kf all -d 3 -c 50 -p 20 -timeout 10 -o "$OUTDIR/ssrf/katana_crawl.txt"

# Extract form fields that accept URLs
rg -oP 'name="(url|uri|link|image_url|avatar|import_url|feed_url|webhook|crawl_url|source|resource|media|document|file_url)"' "$OUTDIR/ssrf/katana_crawl.txt" | sort -u > "$OUTDIR/ssrf/ssrf_form_fields.txt"

# D6 — arjun param discovery on live endpoints
arjun -u "$TARGET_URL" -oJ "$OUTDIR/ssrf/arjun_params.json"
jq -r '.results[] | "\(.url) -> \(.params[])"' "$OUTDIR/ssrf/arjun_params.json" 2>/dev/null | rg -i 'url|uri|link|redirect|next|crawl|proxy|webhook|callback|fetch|resource' > "$OUTDIR/ssrf/arjun_ssrf_params.txt"
```

## Detection Signals
- `ssrf_confirmed_urls.txt` > 0 lines with `url=https://` → confirmed URL-accepting endpoints
- `ssrf_param_names.txt` includes `url`, `image_url`, `webhook`, `import_url` → high-value SSRF surface
- `js_urlcallers.txt` has `fetch()` or `axios()` with URL params from user input → JS-driven SSRF
- `ssrf_form_fields.txt` non-empty → form-based URL input (profile pics, import, avatars)

## False Positives
- Params like `return_url` that only accept same-origin URLs — test with OOB callback to confirm backend fetches
- JS `fetch()` calls to static CDN URLs — check if URL is constructed from user input or hardcoded
- katana crawling third-party links — filter: `grep -i "$TARGET"`
- `redirect=` params that redirect client-side (302) instead of server-side fetch — test with internal IP

## Next
├── If `ssrf_confirmed_urls.txt` > 0 → proceed to `02-probe.md` for OOB callback testing
├── If param names found but no confirmed URL values → manually construct URL values and test
├── If JS URL callers found → trace user input to fetch() for exploitable path
└── Always → save `ssrf_param_names.txt` as canonical SSRF injection surface