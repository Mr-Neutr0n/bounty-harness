# Recon — Verify

## Purpose
Crawl live hosts, discover historical URLs, extract JavaScript endpoints and secrets, and correlate all findings into a verified asset map. Confirms every recon artifact is live, reachable, and classified.

## Required Variables
- `$TARGET` — primary domain
- `$OUTDIR` — output root
- `$LIVE_HOSTS` — path to live URLs (`$OUTDIR/live-hosts/live_urls.txt`)

## Commands

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
LIVE_HOSTS="${LIVE_HOSTS:-$OUTDIR/live-hosts/live_urls.txt}"

# V1 — katana JS-aware crawl
katana -list "$LIVE_HOSTS" -silent -jc -kf all -c 50 -p 20 -timeout 10 -retries 2 -o "$OUTDIR/crawling/katana_crawl.txt"

# V2 — katana headless crawl (SPA/JS-heavy sites)
katana -list "$LIVE_HOSTS" -silent -jc -headless -kf all -c 30 -p 10 -timeout 15 -o "$OUTDIR/crawling/katana_headless.txt"

# V3 — katana form extraction
katana -list "$LIVE_HOSTS" -silent -jc -kf all -c 50 -p 20 -form-extraction -o "$OUTDIR/crawling/katana_forms.txt"

# V4 — gau historical URL dump
cat "$LIVE_HOSTS" | gau --threads 50 --blacklist png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,webm,mp3,avi --o "$OUTDIR/urls/gau_historical.txt"

# V5 — waybackurls historical
cat "$LIVE_HOSTS" | waybackurls > "$OUTDIR/urls/wayback_historical.txt"

# V6 — Merge all URLs
cat "$OUTDIR/crawling"/{katana_crawl,katana_headless}.txt "$OUTDIR/urls"/{gau_historical,wayback_historical}.txt 2>/dev/null | sort -u > "$OUTDIR/urls/all_urls.txt"

# V7 — Categorize URLs
grep -E '\.js(\?|$)' "$OUTDIR/urls/all_urls.txt" | sort -u > "$OUTDIR/urls/js_files.txt"
grep -iE '(api|v[0-9]+/|graphql|rest)' "$OUTDIR/urls/all_urls.txt" | sort -u > "$OUTDIR/urls/api_endpoints.txt"
grep '\?' "$OUTDIR/urls/all_urls.txt" | sort -u > "$OUTDIR/urls/parameterized_urls.txt"
grep -iE '(admin|dashboard|panel|manage|config|debug|phpmyadmin|phpinfo|jenkins|grafana)' "$OUTDIR/urls/all_urls.txt" | sort -u > "$OUTDIR/urls/admin_endpoints.txt"
grep -iE '(\.env$|\.git/|\.bak$|\.backup$|\.old$|\.swp$|~$|\.sql$|\.log$)' "$OUTDIR/urls/all_urls.txt" | sort -u > "$OUTDIR/urls/sensitive_files.txt"

# V8 — Extract unique parameters (injection points)
grep -oP '[?&]\K[A-Za-z0-9_-]+(?==)' "$OUTDIR/urls/parameterized_urls.txt" | sort -u > "$OUTDIR/urls/unique_params.txt"

# V9 — JS recon: download and scan for secrets/endpoints
mkdir -p "$OUTDIR/js/downloads"
while read -r url; do
  fname=$(echo "$url" | md5)
  curl -sL -m 10 "$url" -o "$OUTDIR/js/downloads/${fname}.js" 2>/dev/null
done < "$OUTDIR/urls/js_files.txt"

# V9.1 — Secret patterns in JS
rg -n --no-heading '(api[_-]?key|api[_-]?secret|api[_-]?token|access[_-]?key|access[_-]?token|secret[_-]?token|private[_-]?key|auth[_-]?token|bearer|client[_-]?secret)' "$OUTDIR/js/downloads/" > "$OUTDIR/js/secrets.txt" 2>/dev/null
rg -n --no-heading 'AKIA[0-9A-Z]{16}' "$OUTDIR/js/downloads/" > "$OUTDIR/js/secrets_aws.txt" 2>/dev/null

# V9.2 — Internal IP references
rg -n --no-heading '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b' "$OUTDIR/js/downloads/" > "$OUTDIR/js/internal_ips.txt" 2>/dev/null

# V10 — httpx screenshots of live hosts
httpx -l "$LIVE_HOSTS" -silent -screenshot -ss-path "$OUTDIR/screenshots/" -title -tech-detect -status-code -threads 25 -timeout 15 -o "$OUTDIR/screenshots/screenshots_index.csv"

# V11 — Asset inventory JSON
jq -n --arg t "$TARGET" --arg d "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg subs "$(wc -l < "$OUTDIR/subdomains/all_passive.txt" 2>/dev/null || echo 0)" \
  --arg live "$(wc -l < "$OUTDIR/live-hosts/live_urls.txt" 2>/dev/null || echo 0)" \
  --arg urls "$(wc -l < "$OUTDIR/urls/all_urls.txt" 2>/dev/null || echo 0)" \
  --arg params "$(wc -l < "$OUTDIR/urls/unique_params.txt" 2>/dev/null || echo 0)" \
  '{target:$t,scanned_at:$d,counts:{subdomains:($subs|tonumber),live_hosts:($live|tonumber),urls:($urls|tonumber),params:($params|tonumber)}}' > "$OUTDIR/reports/asset_inventory.json"
```

## Detection Signals
- `all_urls.txt` > 1000 → rich attack surface; ready for vuln-class scanning
- `secrets.txt` or `secrets_aws.txt` non-empty → **critical finding**
- `internal_ips.txt` non-empty → SSRF/recon targets mapped
- `admin_endpoints.txt` non-empty → priority targets for auth bypass/panel testing
- `sensitive_files.txt` non-empty → potential data exposure

## False Positives
- katana crawl yields CDN/cached URLs — filter with `grep -v cloudfront`
- JS secrets matching minified variable names like `api_key = null` — verify context with -C 3
- Screenshots of login pages without creds — note as "auth-required" not "dead"

## Next
├── If secrets found → escalate to `04-impact-escalation.md` evidence path
├── If admin panels discovered → route to auth skill runbooks
├── If parameterized URLs > 0 → pass to xss/sqli/ssrf runbooks for injection testing
└── Always → `asset_inventory.json` is the canonical input for all downstream skills