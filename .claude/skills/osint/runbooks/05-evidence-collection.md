# OSINT — Evidence Collection

## Purpose
Capture persistent evidence of discovered exposures: screenshots, archived snapshots, downloaded files, and a structured JSON report. Preserve findings that may be remediated before review.

## Required Variables
- $TARGET: domain or organization name
- $OUTDIR: output directory for evidence

## Commands

```bash
EVIDENCE_DIR="$OUTDIR/evidence"
mkdir -p "$EVIDENCE_DIR/screenshots" "$EVIDENCE_DIR/files" "$EVIDENCE_DIR/wayback" "$EVIDENCE_DIR/reports"

waybackurls "$TARGET" 2>/dev/null | sort -u > "$EVIDENCE_DIR/wayback/all_urls.txt"

rg -i '\.env$|\.sql$|\.log$|\.bak$|\.json$|\.yml$|\.xml$|\.config$|\.pem$|\.key$|\.p12$' \
  "$EVIDENCE_DIR/wayback/all_urls.txt" \
  > "$EVIDENCE_DIR/wayback/sensitive_files.txt"

head -100 "$EVIDENCE_DIR/wayback/sensitive_files.txt" | while read -r URL; do
  SAFE_NAME=$(echo "$URL" | md5 2>/dev/null || echo "$URL" | shasum -a 256 | cut -d' ' -f1)
  curl -s -L --max-time 15 -o "$EVIDENCE_DIR/files/${SAFE_NAME}" "$URL" 2>/dev/null || true
done

cat "$EVIDENCE_DIR/wayback/all_urls.txt" \
  | rg -i 'login|signin|oauth|callback|reset_password|verify|admin|dashboard|api/v1' \
  | sort -u > "$EVIDENCE_DIR/wayback/high_value_urls.txt"

cat "$EVIDENCE_DIR/wayback/high_value_urls.txt" \
  | while read -r URL; do
    DOMAIN=$(echo "$URL" | sed 's|https\?://||' | cut -d/ -f1)
    echo "$DOMAIN"
  done | sort -u > "$EVIDENCE_DIR/reports/unique_domains.txt"

echo "=== Wayback Snapshot Archive ===" > "$EVIDENCE_DIR/reports/wayback_summary.txt"
echo "Target: $TARGET" >> "$EVIDENCE_DIR/reports/wayback_summary.txt"
echo "Scan Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVIDENCE_DIR/reports/wayback_summary.txt"
echo "Total URLs: $(wc -l < "$EVIDENCE_DIR/wayback/all_urls.txt")" >> "$EVIDENCE_DIR/reports/wayback_summary.txt"
echo "Sensitive Files: $(wc -l < "$EVIDENCE_DIR/wayback/sensitive_files.txt")" >> "$EVIDENCE_DIR/reports/wayback_summary.txt"
echo "High-Value Endpoints: $(wc -l < "$EVIDENCE_DIR/wayback/high_value_urls.txt")" >> "$EVIDENCE_DIR/reports/wayback_summary.txt"

jq -n \
  --arg target "$TARGET" \
  --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson total_urls "$(wc -l < "$EVIDENCE_DIR/wayback/all_urls.txt" | tr -d ' ')" \
  --argjson secrets_found "$(find "$OUTDIR/probe" -name '*.json' -exec jq 'length' {} + 2>/dev/null | paste -sd+ - | bc 2>/dev/null || echo 0)" \
  --argjson breached_emails "$(find "$OUTDIR/escalation" -name 'hibp_*.json' 2>/dev/null | wc -l | tr -d ' ')" \
  --argjson active_tokens "$(wc -l < "$OUTDIR/verify/github_token_results.txt" 2>/dev/null | tr -d ' ' || echo 0)" \
  '{
    target: $target,
    scan_date: $date,
    stats: {
      wayback_urls: $total_urls,
      secrets_detected: $secrets_found,
      breached_accounts: $breached_emails,
      active_tokens: $active_tokens
    },
    findings: []
  }' > "$EVIDENCE_DIR/reports/osint_final_report.json"

ls -laR "$EVIDENCE_DIR" > "$EVIDENCE_DIR/reports/evidence_manifest.txt"

echo "Evidence collection complete. Report: $EVIDENCE_DIR/reports/osint_final_report.json"
echo "Manifest: $EVIDENCE_DIR/reports/evidence_manifest.txt"
```

## Detection Signals
- Downloaded files > 0 bytes — actual content was retrieved and preserved
- `sensitive_files.txt` contains entries — exposed config/data files confirmed via Wayback
- `high_value_urls.txt` contains auth/admin endpoints — expanded attack surface documented
- `osint_final_report.json` has non-zero stats — quantifiable findings exist

## Next
├── Evidence captured → proceed to `06-false-positive-filter.md` for final cleanup
├── Then → use `.claude/skills/reporting` to generate the final deliverable
├── Zip evidence: `tar -czf $OUTDIR/osint_evidence.tar.gz -C $OUTDIR evidence/`
└── If Wayback returned zero URLs → target may have no historical snapshots; note as limitation
