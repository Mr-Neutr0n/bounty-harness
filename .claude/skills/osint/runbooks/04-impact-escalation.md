# OSINT — Impact Escalation

## Purpose
Correlate discovered emails with breach databases, enumerate social media usernames, and map the full digital footprint of exposed credentials. Demonstrate the blast radius of a single leaked secret or credential.

## Required Variables
- $TARGET: domain or organization name
- $OUTDIR: output directory for escalation results

## Commands

```bash
mkdir -p $OUTDIR/escalation

rg -oI '[a-zA-Z0-9._%+-]+@'"${TARGET//./\\.}" 2>/dev/null \
  -r $OUTDIR \
  | sort -u > $OUTDIR/escalation/org_emails.txt

while read -r EMAIL; do
  SANITIZED=$(echo "$EMAIL" | tr '@.' '_')
  curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${EMAIL}?truncateResponse=false" \
    -H "hibp-api-key: ${HIBP_API_KEY}" \
    -H "User-Agent: OSINT-Scanner" \
    | jq '.' > "$OUTDIR/escalation/hibp_${SANITIZED}.json" 2>/dev/null || true
done < $OUTDIR/escalation/org_emails.txt

rg -oI '[a-zA-Z0-9._-]{3,30}' $OUTDIR/discovery/github_code_urls.txt 2>/dev/null \
  | sort -u | head -20 > $OUTDIR/escalation/username_candidates.txt

while read -r USERNAME; do
  [ ${#USERNAME} -lt 3 ] && continue
  sherlock "$USERNAME" \
    --output "$OUTDIR/escalation/sherlock_${USERNAME}" \
    --csv --timeout 10 --print-found 2>/dev/null || true
done < $OUTDIR/escalation/username_candidates.txt

curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sed 's/^\*\.//' \
  | sort -u > $OUTDIR/escalation/all_subdomains_crt.txt

waybackurls "$TARGET" 2>/dev/null \
  | grep -iE 'admin|internal|staging|dev|test|backup|db|database|api/v[0-9]|graphql' \
  | sort -u > $OUTDIR/escalation/sensitive_urls.txt

curl -s "https://dns.google/resolve?name=${TARGET}&type=MX" \
  | jq '.Answer[] | select(.type==15) | .data' \
  > $OUTDIR/escalation/mx_records.json

curl -s "https://dns.google/resolve?name=${TARGET}&type=TXT" \
  | jq -r '.Answer[] | select(.type==16) | .data' \
  > $OUTDIR/escalation/txt_records.txt

rg -rl 'spf1|DKIM|MS=' $OUTDIR/escalation/txt_records.txt 2>/dev/null \
  && echo "Email security records found — check for DMARC p=none" \
  >> $OUTDIR/escalation/email_security_findings.txt

curl -s "https://dns.google/resolve?name=${TARGET}&type=NS" \
  | jq -r '.Answer[] | select(.type==2) | .data' \
  > $OUTDIR/escalation/nameservers.txt

jq -n \
  --arg target "$TARGET" \
  --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson breach_count "$(ls $OUTDIR/escalation/hibp_*.json 2>/dev/null | wc -l | tr -d ' ')" \
  --argjson social_count "$(find $OUTDIR/escalation -name 'sherlock_*' -type d 2>/dev/null | wc -l | tr -d ' ')" \
  '{target: $target, scan_date: $date, breach_accounts: $breach_count, social_profiles_enumerated: $social_count}' \
  > $OUTDIR/escalation/summary.json
```

## Detection Signals
- HIBP breach count > 0 for `@target.com` emails — credentials already in breach dumps
- `sherlock` finds profiles on `github`, `gitlab`, `npm`, `pypi` — supply chain risk
- `waybackurls` surfaces `admin`, `internal`, `staging` endpoints — expanded attack surface
- MX records pointing to Google Workspace or Office 365 — phishing target identification
- SPF record ending in `~all` or `?all` — email spoofing possible

## Next
├── If breach data found for org emails → proceed to `05-evidence-collection.md`
├── If sensitive Wayback URLs discovered → feed back to `01-discovery.md` for deeper dorking
├── If email security misconfigs → cross-reference with `.claude/skills/auth`
└── If no escalation paths → document as low-impact; proceed to `06-false-positive-filter.md`
