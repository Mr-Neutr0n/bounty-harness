# OSINT — False Positive Filter

## Purpose
Remove placeholder, example, test, and non-functional credentials from OSINT findings. Ensure only real, actionable secrets remain. Validate domain ownership to confirm discovered resources actually belong to the target.

## Required Variables
- $TARGET: domain or organization name
- $OUTDIR: output directory for filtered results

## Commands

```bash
mkdir -p $OUTDIR/filtered

PLACEHOLDER_PATTERN='example|EXAMPLE|test|TEST|TODO|changeme|CHANGEME|placeholder|PLACEHOLDER|XXXX|xxxx|REPLACE_ME|replace_me|YOUR_API_KEY|your_api_key|your-key|dummy|fake|foobar|helloworld|abc123|123456|password1'

find $OUTDIR/probe -name 'trufflehog_*.json' -exec cat {} + 2>/dev/null \
  | jq -r 'select(.Raw != null) | "\(.Raw)\t\(.DetectorName)\t\(.Verified)"' \
  | rg -v "$PLACEHOLDER_PATTERN" \
  > $OUTDIR/filtered/trufflehog_no_placeholders.tsv

find $OUTDIR/probe -name 'gitleaks_*.json' -exec cat {} + 2>/dev/null \
  | jq -r '.[] | "\(.Match)\t\(.RuleID)\t\(.Entropy)"' \
  | rg -v "$PLACEHOLDER_PATTERN" \
  > $OUTDIR/filtered/gitleaks_no_placeholders.tsv

rg -o 'AKIA[0-9A-Z]{16}' $OUTDIR/filtered/trufflehog_no_placeholders.tsv \
  | sort -u > $OUTDIR/filtered/aws_keys_formatted.txt
rg -o 'ghp_[0-9a-zA-Z]{36}' $OUTDIR/filtered/trufflehog_no_placeholders.tsv \
  | sort -u > $OUTDIR/filtered/github_tokens_formatted.txt
rg -o 'sk_live_[0-9a-zA-Z]{24,99}' $OUTDIR/filtered/trufflehog_no_placeholders.tsv \
  | sort -u > $OUTDIR/filtered/stripe_keys_formatted.txt
rg -o 'xox[bpras]-[0-9]+-[0-9]+-[0-9a-z]+' $OUTDIR/filtered/trufflehog_no_placeholders.tsv \
  | sort -u > $OUTDIR/filtered/slack_tokens_formatted.txt
rg -o '[A-Za-z0-9+/]{40,}={0,2}' $OUTDIR/filtered/gitleaks_no_placeholders.tsv \
  | sort -u > $OUTDIR/filtered/high_entropy_formatted.txt

curl -s "https://www.google.com/search?q=${TARGET}" \
  -H "User-Agent: Mozilla/5.0" \
  | rg -o 'https?://[^"<> ]+'"${TARGET}"'[^"<> ]*' \
  | sort -u > $OUTDIR/filtered/google_owned_urls.txt

rg -o 'https?://[a-zA-Z0-9.-]*'"${TARGET//./\\.}"'[^"<> ]*' \
  $OUTDIR/discovery/cert_transparency.txt \
  | sort -u > $OUTDIR/filtered/ct_owned_domains.txt

cat $OUTDIR/escalation/all_subdomains_crt.txt 2>/dev/null \
  | while read -r SUB; do
    DIG_RESULT=$(dig +short "$SUB" A 2>/dev/null)
    [ -n "$DIG_RESULT" ] && echo "$SUB → $DIG_RESULT"
  done > $OUTDIR/filtered/resolving_subdomains.txt

python3 "$HOME/Desktop/bug bounty/.claude/skills/osint/scripts/github_secret_scanner.py" \
  --input "$OUTDIR/probe/consolidated_trufflehog.json" \
  --filter-placeholders \
  --output "$OUTDIR/filtered/verified_high_signal.json" 2>/dev/null || true

wc -l $OUTDIR/filtered/*.txt $OUTDIR/filtered/*.tsv 2>/dev/null \
  > $OUTDIR/filtered/final_counts.txt

echo "=== High-Signal Findings ===" > $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
echo "Scan: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
echo "Target: $TARGET" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
echo "" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s $OUTDIR/filtered/aws_keys_formatted.txt ] && echo "[CRITICAL] AWS Access Keys found" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s $OUTDIR/filtered/github_tokens_formatted.txt ] && echo "[CRITICAL] GitHub Personal Access Tokens found" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s $OUTDIR/filtered/stripe_keys_formatted.txt ] && echo "[CRITICAL] Stripe Live Keys found" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s $OUTDIR/filtered/slack_tokens_formatted.txt ] && echo "[HIGH] Slack Bot Tokens found" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s $OUTDIR/filtered/high_entropy_formatted.txt ] && echo "[MEDIUM] High-entropy strings require manual review" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
[ -s "$OUTDIR/escalation/hibp_*.json" ] 2>/dev/null && echo "[HIGH] Employee emails found in breach databases" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
echo "" >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
cat $OUTDIR/filtered/final_counts.txt >> $OUTDIR/filtered/ACTIONABLE_FINDINGS.txt
```

## Detection Signals
- String matches `example`, `TODO`, `changeme`, `YOUR_API_KEY` → discarded as placeholder
- String matches `AKIA[0-9A-Z]{16}` exactly → valid AWS key format, flag for manual review
- Entropy < 3.5 in Gitleaks → likely false positive, suppress
- Domain resolves via `dig` → confirms DNS ownership, resource is active
- `Verified: true` in TruffleHog → highest signal, never discard these

## Next
├── Review `ACTIONABLE_FINDINGS.txt` → triage by severity (CRITICAL > HIGH > MEDIUM)
├── Critical findings → immediate disclosure per responsible disclosure policy
├── High findings → include in final report with remediation timeline
├── Medium findings → document for internal hygiene improvements
└── Proceed to `.claude/skills/reporting` with `$OUTDIR/filtered/ACTIONABLE_FINDINGS.txt` as input
