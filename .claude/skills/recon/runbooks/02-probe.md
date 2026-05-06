# Recon — Probe

## Purpose
Resolve DNS records, discover live hosts, fingerprint technologies, and scan open ports. Converts a list of domain names into a prioritized map of the live attack surface.

## Required Variables
- `$TARGET` — primary domain
- `$OUTDIR` — output root (same as 01-discovery)
- `$SUBS_FILE` — path to subdomain list (default: `$OUTDIR/subdomains/all_passive.txt`)

## Commands

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
SUBS_FILE="${SUBS_FILE:-$OUTDIR/subdomains/all_passive.txt}"

# P1 — DNS record resolution (A/AAAA/CNAME/MX/NS/TXT/SOA)
dnsx -l "$SUBS_FILE" -silent -a -aaaa -cname -mx -ns -txt -soa -resp -resp-only -t 200 -retry 2 -o "$OUTDIR/dns/dnsx_all_records.txt"

# P2 — Extract CNAMEs for takeover detection
grep '\[CNAME\]' "$OUTDIR/dns/dnsx_all_records.txt" | sort -u > "$OUTDIR/dns/cname.txt"
grep -iE '(amazonaws\.com|cloudfront\.net|herokuapp\.com|azurewebsites|\.s3\.|ghs\.googlehosted\.com)' "$OUTDIR/dns/cname.txt" > "$OUTDIR/dns/takeover_candidates.txt"

# P3 — Wildcard DNS detection
RANDSUBS="$(openssl rand -hex 12).$TARGET"
dig +short "$RANDSUBS" A > "$OUTDIR/dns/wildcard_test.txt"
[ -s "$OUTDIR/dns/wildcard_test.txt" ] && echo "WARNING: Wildcard DNS detected: $(cat $OUTDIR/dns/wildcard_test.txt)" || echo "No wildcard DNS."

# P4 — httpx live host probe
httpx -l "$SUBS_FILE" -silent -title -status-code -content-length -tech-detect -web-server -cdn -location -threads 75 -timeout 8 -retries 2 -fr -o "$OUTDIR/live-hosts/live.csv"

# P5 — Extract live URLs only
awk '{print $1}' "$OUTDIR/live-hosts/live.csv" | sort -u > "$OUTDIR/live-hosts/live_urls.txt"

# P6 — Flag interesting hosts
grep -iE '(dev|staging|test|qa|beta|demo|uat|sandbox|internal|admin|jenkins|git)' "$OUTDIR/live-hosts/live_urls.txt" > "$OUTDIR/live-hosts/interesting_dev.txt"
grep -iE '(login|signin|auth|signup|register|sso)' "$OUTDIR/live-hosts/live_urls.txt" > "$OUTDIR/live-hosts/auth_pages.txt"
grep -iE '(api|graphql|rest|v1|v2|v3|swagger|openapi)' "$OUTDIR/live-hosts/live_urls.txt" > "$OUTDIR/live-hosts/api_hosts.txt"

# P7 — Port scan with naabu
cat "$OUTDIR/live-hosts/live_urls.txt" | naabu -silent -top-ports 1000 -rate 500 -retries 2 -timeout 3000 -exclude-cdn -o "$OUTDIR/ports/naabu_top1000.txt"

# P8 — Technology summary
cut -d' ' -f5 "$OUTDIR/live-hosts/live.csv" 2>/dev/null | tr ',' '\n' | sort | uniq -c | sort -rn > "$OUTDIR/tech/tech_summary.txt"

# P9 — WAF detection
wafw00f -i "$OUTDIR/live-hosts/live_urls.txt" -o "$OUTDIR/tech/waf_results.txt" 2>/dev/null

# P10 — Zone transfer attempt
grep '\[NS\]' "$OUTDIR/dns/dnsx_all_records.txt" | awk '{print $1}' | sort -u > "$OUTDIR/dns/ns_hosts.txt"
while read -r ns; do dig AXFR "$TARGET" @"$ns" +time=5 +tries=1 >> "$OUTDIR/dns/zone_transfer.txt" 2>&1; done < "$OUTDIR/dns/ns_hosts.txt"
```

## Detection Signals
- `live_urls.txt` > 0 → target has live web infrastructure
- `tech_summary.txt` contains `WordPress`, `Drupal`, `Jenkins` → high-value vuln targets
- `takeover_candidates.txt` > 0 → flagged for subdomain takeover testing
- Zone transfer returns records beyond SOA → **critical finding**
- `waf_results.txt` shows Cloudflare/AWS WAF → note for bypass payloads
- Non-200 status codes in `live.csv` → check for internal/admin panels

## False Positives
- httpx `cdn=true` hosts — edge-cached; actual origin may be behind WAF
- DNS wildcard resolves random subdomains — all brute-forced subs may resolve incorrectly
- naabu detecting open 80/443 on CDN IPs — not the origin; filter via `-exclude-cdn`

## Next
├── If `takeover_candidates.txt` > 0 → escalate to `04-impact-escalation.md`
├── If zone transfer successful → escalate to `04-impact-escalation.md`
├── If live hosts > 0 → proceed to `03-verify.md` for URL discovery and crawling
├── If 0 live hosts → check DNS resolution; if no A records, target may be inactive
└── Always → save `live.csv` and `live_urls.txt` as primary live asset inventory