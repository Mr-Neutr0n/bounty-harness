# Nuclei Scanner — Impact Escalation & Chained Exploitation

## Purpose
Escalate verified findings to prove impact. Run deeper CVE-specific scans, multi-step workflow templates, and chain nuclei with other tools (dalfox for XSS, ffuf for confirmation) to demonstrate real-world exploitability.

## Required Variables
- $TARGET_URL: target URL or file of live URLs
- $OUTDIR: output directory for scan results
- $EVIDENCE_DIR: evidence directory

## Commands

### Pre-flight

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
TEMPLATES_DIR=""
for d in "/opt/homebrew/share/nuclei-templates" "$HOME/nuclei-templates" "templates/nuclei-templates" "./nuclei-templates"; do
  if [ -d "$d" ]; then TEMPLATES_DIR="$d"; break; fi
done
mkdir -p "$OUTDIR/scans" "$EVIDENCE_DIR"
```

### Targeted CVE scan with retry on transient errors

```bash
/opt/homebrew/bin/nuclei -l "$TARGET_URL" \
  -templates "$TEMPLATES_DIR/http/cves/" \
  -severity critical \
  -retryable-http-code 429,500,502,503 \
  -bulk-size 25 \
  -rate 25 \
  -timeout 15 \
  -retries 2 \
  -silent \
  -json \
  -stats \
  -stats-interval 60 \
  -o "$OUTDIR/scans/escalation_cve_critical.jsonl"
```

### Multi-step workflow: tech detection → conditional CVE

```bash
cat > "$OUTDIR/scans/escalation_workflow.yaml" << 'WFEOF'
id: targeted-conditional-cve
info:
  name: Technology Detection → Conditional CVE Escalation
  severity: critical
  description: Detect technology stack, then run matching CVE checks

workflows:
  - template: http/technologies/tech-detect.yaml
    subtemplates:
      - tags: wordpress
        subtemplates:
          - tags: wordpress,cve,critical
      - tags: apache
        subtemplates:
          - tags: apache,cve,critical
      - tags: nginx
        subtemplates:
          - tags: nginx,cve,critical
      - tags: php
        subtemplates:
          - tags: php,cve,critical
      - tags: tomcat
        subtemplates:
          - tags: tomcat,cve,critical
      - tags: iis
        subtemplates:
          - tags: iis,cve,critical
      - tags: jenkins
        subtemplates:
          - tags: jenkins,cve,critical
      - tags: gitlab
        subtemplates:
          - tags: gitlab,cve,critical
      - tags: drupal
        subtemplates:
          - tags: drupal,cve,critical
      - tags: joomla
        subtemplates:
          - tags: joomla,cve,critical
WFEOF

/opt/homebrew/bin/nuclei -l "$TARGET_URL" \
  -w "$OUTDIR/scans/escalation_workflow.yaml" \
  -silent \
  -stats \
  -stats-interval 60 \
  -timeout 20 \
  -json \
  -o "$OUTDIR/scans/escalation_workflow_results.jsonl"
```

### All known workflow templates from nuclei-templates repo

```bash
for wf in $(find "$TEMPLATES_DIR/workflows/" -name "*.yaml" -type f 2>/dev/null); do
  wf_name=$(basename "$wf" .yaml)
  echo "Running workflow: $wf_name"
  /opt/homebrew/bin/nuclei -l "$TARGET_URL" \
    -w "$wf" \
    -silent \
    -stats \
    -timeout 20 \
    -json \
    -o "$OUTDIR/scans/escalation_workflow_${wf_name}.jsonl"
done
```

### Chained XSS confirmation: nuclei → dalfox

```bash
/opt/homebrew/bin/jq -r 'select(.info.severity=="critical" or .info.severity=="high") | select(.template-id | test("xss"; "i")) | "\(.host)\(.matched_at // "")"' \
  "$OUTDIR/scans/probe_critical_high.jsonl" 2>/dev/null | \
  sort -u > "$OUTDIR/scans/escalation_xss_urls.txt"

if [ -s "$OUTDIR/scans/escalation_xss_urls.txt" ]; then
  echo "Running dalfox on $(wc -l < "$OUTDIR/scans/escalation_xss_urls.txt") XSS candidate URLs"
  /opt/homebrew/bin/dalfox pipe --silence --skip-mining-all --no-color \
    < "$OUTDIR/scans/escalation_xss_urls.txt" \
    > "$OUTDIR/scans/escalation_dalfox_results.txt" 2>/dev/null
  echo "Dalfox findings:"
  grep -c '\[POC\]' "$OUTDIR/scans/escalation_dalfox_results.txt" 2>/dev/null
fi
```

### Chained SQLi confirmation: nuclei → sqlmap on candidate URLs

```bash
/opt/homebrew/bin/jq -r 'select(.info.severity=="critical" or .info.severity=="high") | select(.template-id | test("sqli|sql-injection"; "i")) | "\(.host)\(.matched_at // "")"' \
  "$OUTDIR/scans/probe_critical_high.jsonl" 2>/dev/null | \
  sort -u > "$OUTDIR/scans/escalation_sqli_urls.txt"

if [ -s "$OUTDIR/scans/escalation_sqli_urls.txt" ]; then
  echo "SQLi candidate URLs found: $(wc -l < "$OUTDIR/scans/escalation_sqli_urls.txt")"
  head -5 "$OUTDIR/scans/escalation_sqli_urls.txt" | while read url; do
    /opt/homebrew/bin/sqlmap -u "$url" --batch --level 1 --risk 1 --threads 3 --timeout 15 \
      --output-dir="$OUTDIR/scans/sqlmap" 2>&1 | \
      tee -a "$OUTDIR/scans/escalation_sqlmap_output.txt"
  done
fi
```

### ffuf parameter fuzzing on endpoints with findings

```bash
/opt/homebrew/bin/jq -r '.host' "$OUTDIR/scans/probe_critical_high.jsonl" 2>/dev/null | sort -u | while read host; do
  if [ -n "$host" ]; then
    /opt/homebrew/bin/ffuf -u "${host}/FUZZ" \
      -w "$OUTDIR/../../../wordlists/fuzz/params.txt" \
      -rate 20 \
      -timeout 10 \
      -mc 200,403,401 \
      -silent \
      -o "$OUTDIR/scans/escalation_ffuf_$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-40).json" 2>/dev/null
  fi
done
```

### Generate impact assessment summary

```bash
python3 -c "
import json, os, glob
summary = {'critical_cve': 0, 'workflow': 0, 'xss_dalfox': 0, 'sqli_sqlmap': 0}
for f in glob.glob(os.path.join('$OUTDIR/scans','escalation_cve_critical.jsonl')):
    summary['critical_cve'] = sum(1 for _ in open(f))
for f in glob.glob(os.path.join('$OUTDIR/scans','escalation_workflow_*.jsonl')):
    summary['workflow'] += sum(1 for _ in open(f))
dalfox_path = os.path.join('$OUTDIR/scans','escalation_dalfox_results.txt')
if os.path.exists(dalfox_path):
    summary['xss_dalfox'] = open(dalfox_path).read().count('[POC]')
print(json.dumps(summary, indent=2))
" | tee "$OUTDIR/scans/escalation_impact_summary.json"
```

## Detection Signals
- Workflow template produces results — multi-step exploit path confirmed; document full chain
- Dalfox finds PoC XSS — nuclei XSS finding escalated to proven reflected XSS
- SQLMap confirms injection — nuclei SQLi finding escalated to exploitable SQL injection
- `retryable-http-code` triggers — target is rate-limiting; reduce rate further
- ffuf discovers new parameters — surface area larger than nuclei templates covered

## Next
├── If chained exploit confirmed → go to `05-evidence-collection.md` to document PoC
├── If workflows produce new findings → re-validate with `03-verify.md`
├── If no escalation achieved → go to `06-false-positive-filter.md` to document limitations
