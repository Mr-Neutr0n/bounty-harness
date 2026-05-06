# Recon — Discovery

## Purpose
Collect every asset belonging to the target without touching target infrastructure. Subdomains, ASN ranges, IP blocks, certificate SANs, and organizational aliases -- all via passive sources.

## Required Variables
- `$TARGET` — primary domain (e.g. `example.com`)
- `$OUTDIR` — output root (`./output/$TARGET/$(date +%Y-%m-%d)`)

## Commands

### Passive Subdomain Sources

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
export OUTDIR="./output/$TARGET/$(date +%Y-%m-%d)"
mkdir -p "$OUTDIR"/{subdomains,dns,live-hosts,urls}

# W1.1 — subfinder (all passive APIs)
subfinder -d "$TARGET" -all -silent -o "$OUTDIR/subdomains/subfinder.txt" -timeout 5 -max-time 10

# W1.2 — amass passive
amass enum -passive -d "$TARGET" -o "$OUTDIR/subdomains/amass_passive.txt" -timeout 15

# W1.3 — crt.sh certificate transparency
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" -o "$OUTDIR/subdomains/crtsh_raw.json"
jq -r '.[].name_value' "$OUTDIR/subdomains/crtsh_raw.json" | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u > "$OUTDIR/subdomains/crtsh.txt"

# W1.4 — gau historical URLs (extract subdomains)
echo "$TARGET" | gau --subs --threads 50 --o "$OUTDIR/urls/gau_all.txt"
grep -oP 'https?://\K[^/?#]+' "$OUTDIR/urls/gau_all.txt" | sort -u > "$OUTDIR/subdomains/gau_subs.txt"

# W1.5 — waybackurls
echo "$TARGET" | waybackurls > "$OUTDIR/urls/wayback_all.txt"
grep -oP 'https?://\K[^/?#]+' "$OUTDIR/urls/wayback_all.txt" | sort -u > "$OUTDIR/subdomains/wayback_subs.txt"

# W1.6 — BufferOver DNS
curl -s "https://dns.bufferover.run/dns?q=.$TARGET" | jq -r '.FDNS_A[]?, .RDNS[]?' 2>/dev/null | grep "$TARGET" | sed 's/,.*//' | sort -u > "$OUTDIR/subdomains/bufferover.txt"

# W1.7 — AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" | jq -r '.passive_dns[].hostname' 2>/dev/null | grep -i "$TARGET" | sort -u > "$OUTDIR/subdomains/otx.txt"

# W1.8 — Merge all passive sources
cat "$OUTDIR/subdomains"/{subfinder,amass_passive,crtsh,gau_subs,wayback_subs,bufferover,otx}.txt 2>/dev/null | grep -i "$TARGET" | tr '[:upper:]' '[:lower:]' | grep -v '^\*\.' | sort -u > "$OUTDIR/subdomains/all_passive.txt"

# W1.9 — ASN / IP discovery
amass intel -d "$TARGET" -o "$OUTDIR/reports/amass_intel.txt" -timeout 15
whois "$TARGET" > "$OUTDIR/reports/whois.txt" 2>&1
```

## Detection Signals
- `all_passive.txt` > 0 lines → subdomains found, proceed to DNS resolution
- crt.sh returns `name_value` entries → certificate transparency actively monitored
- amass intel returns ASN blocks → target has registered IP space
- whois shows `OrgName` or `Registrant Organization` → organization ownership confirmed

## False Positives
- crt.sh wildcard entries (`*.example.com`) — strip `*.` prefix before using
- gau/waybackurls output containing CDN aliases (e.g. `*.cloudfront.net`) — filter to only `$TARGET`-containing hosts
- BufferOver returning expired/defunct subdomains — resolved later by DNS probing

## Next
├── If `all_passive.txt` has 0 entries → target may be tiny; try direct DNS (`02-probe.md`)
├── If `all_passive.txt` has 1-50 entries → small target; proceed to `02-probe.md` DNS resolution
├── If `all_passive.txt` has 50-500 entries → normal target; proceed to `02-probe.md`
├── If `all_passive.txt` has 500+ entries → large target; skip DNS brute, go to `02-probe.md` only for A/CNAME
└── Always → save `all_passive.txt` as the authoritative subdomain inventory