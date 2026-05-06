# Recon — False Positive Filter

## Purpose
Eliminate noise from recon output before it pollutes downstream pipelines. Filter out CDN aliases, wildcard DNS artifacts, known-service subdomains, parked domains, and scan-level false positives that produce false findings.

## Required Variables
- `$TARGET` — primary domain
- `$OUTDIR` — output root

## Commands

### Filter 1: Remove Wildcard DNS Noise

```bash
# If wildcard DNS is active, every dnsx brute result may be false
WILDCARD_IP=$(cat "$OUTDIR/dns/wildcard_test.txt" 2>/dev/null)
if [ -n "$WILDCARD_IP" ]; then
  echo "Wildcard IP: $WILDCARD_IP — filtering all subdomains resolving to it"
  grep -v "$WILDCARD_IP" "$OUTDIR/dns/dnsx_all_records.txt" > "$OUTDIR/dns/dnsx_filtered.txt"
  cp "$OUTDIR/dns/dnsx_filtered.txt" "$OUTDIR/dns/dnsx_all_records.txt"
fi
```

### Filter 2: Strip CDN / Third-Party Hosts

```bash
# Remove known CDN, hosting, and parked domains from the subdomain list
CDN_PATTERNS='(cloudfront\.net|fastly\.net|akamai\.net|edgekey\.net|azureedge\.net|cdn77\.|stackpathcdn\.|kxcdn\.|cachefly\.|netdna-ssl\.|amazonaws\.com)'
grep -viE "$CDN_PATTERNS" "$OUTDIR/subdomains/all_passive.txt" > "$OUTDIR/subdomains/all_passive_clean.txt"

# Remove domains that don't contain the target root
grep -i "$TARGET" "$OUTDIR/subdomains/all_passive_clean.txt" > "$OUTDIR/subdomains/all_verified.txt"
```

### Filter 3: Remove Parked / Placeholder Subdomains

```bash
# Domains that return identical "parked" content are false positives
BASELINE_SIZE=$(curl -s -o /dev/null -w '%{size_download}' "http://$TARGET" 2>/dev/null)

while read -r sub; do
  size=$(curl -s -o /dev/null -w '%{size_download}' "http://$sub" 2>/dev/null)
  title=$(curl -s "http://$sub" 2>/dev/null | grep -oP '(?<=<title>).*?(?=</title>)' | head -1)
  if [ "$size" = "$BASELINE_SIZE" ]; then
    echo "$sub" >> "$OUTDIR/live-hosts/parked_domains.txt"
  fi
done < "$OUTDIR/live-hosts/live_urls.txt"
```

### Filter 4: httpx Status Code Cleanup

```bash
# Remove 4xx/5xx from live hosts (they're down or blocked)
grep -vE '\b(40[0-9]|50[0-9])\b' "$OUTDIR/live-hosts/live.csv" > "$OUTDIR/live-hosts/live_clean.csv"
awk '{print $1}' "$OUTDIR/live-hosts/live_clean.csv" | sort -u > "$OUTDIR/live-hosts/live_urls_clean.txt"
```

### Filter 5: Deduplicate by IP

```bash
# Multiple subdomains resolving to the same IP → pick one canonical
awk '{print $2, $1}' "$OUTDIR/dns/a_records.txt" 2>/dev/null | sort -u -k1,1 | awk '!seen[$1]++{print $2}' > "$OUTDIR/subdomains/deduped_by_ip.txt"
```

### Filter 6: Domain Parking Services

```bash
# Remove known parking/nxdomain service patterns
grep -viE '(domaincontrol\.com|registrar-servers\.com|parkingcrew\.|bodis\.|sedoparking\.|afternic\.)' "$OUTDIR/subdomains/all_passive.txt" > "$OUTDIR/subdomains/all_noparking.txt"
```

## Detection Signals
- `all_verified.txt` line count < `all_passive.txt` → noise reduction successful
- `parked_domains.txt` populated → those subs were false positives
- No live hosts after 4xx/5xx filter → target may have no public web surface

## Next
├── Run filtered files through `02-probe.md` if significant noise was removed
├── If `all_verified.txt` > 0 → proceed to `03-verify.md` crawl phase
├── If 0 subdomains remain after filters → target may be misconfigured or internal-only
└── Always → diff filters and report: `echo "Removed $(($(wc -l < all_passive.txt) - $(wc -l < all_verified.txt))) noise entries"`