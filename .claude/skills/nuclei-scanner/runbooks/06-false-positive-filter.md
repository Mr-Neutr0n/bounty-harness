# Nuclei Scanner — False Positive Filtering & Deduplication

## Purpose
Deduplicate findings by matcher name and URL, filter known false positive patterns (WAF blocks, CDN errors, 404 pages), and produce a clean, submission-ready findings list with manual validation checklist.

## Required Variables
- $TARGET_URL: target URL or file of live URLs
- $OUTDIR: output directory for scan results
- $EVIDENCE_DIR: evidence directory

## Commands

### Pre-flight

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$OUTDIR/results"
echo "=== FP Filter Run $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee "$OUTDIR/results/fp_filter_log.txt"
```

### Step 1: Merge all JSONL scan outputs into one file

```bash
cat "$OUTDIR/scans/probe_critical_high.jsonl" \
    "$OUTDIR/scans/probe_medium.jsonl" \
    "$OUTDIR/scans/escalation_cve_critical.jsonl" \
    "$OUTDIR/scans/escalation_workflow_results.jsonl" \
    2>/dev/null > "$OUTDIR/results/all_raw_findings.jsonl"
echo "Raw findings: $(wc -l < "$OUTDIR/results/all_raw_findings.jsonl")"
```

### Step 2: Python deduplication — deduplicate by matcher-name + URL

```bash
python3 -c "
import json, os

infile = os.path.join('$OUTDIR', 'results', 'all_raw_findings.jsonl')
outfile = os.path.join('$OUTDIR', 'results', 'deduped_findings.jsonl')
summary_file = os.path.join('$OUTDIR', 'results', 'dedup_summary.txt')

seen = {}
deduped = []
duplicate_count = 0

with open(infile) as f:
    for line in f:
        try:
            d = json.loads(line.strip())
        except:
            continue
        host = d.get('host', '')
        matched_at = d.get('matched_at', '')
        template_id = d.get('template-id', '')
        matcher_name = d.get('matcher_name', '')
        severity = d.get('info', {}).get('severity', 'unknown')
        name = d.get('info', {}).get('name', '')

        # Composite key: host + matched_at + template_id + matcher_name
        key = f'{host}|{matched_at}|{template_id}|{matcher_name}'

        if key in seen:
            duplicate_count += 1
            continue
        seen[key] = True
        deduped.append(d)

with open(outfile, 'w') as f:
    for d in deduped:
        f.write(json.dumps(d) + '\n')

# Stats
severity_counts = {}
for d in deduped:
    sev = d.get('info', {}).get('severity', 'unknown')
    severity_counts[sev] = severity_counts.get(sev, 0) + 1

with open(summary_file, 'w') as f:
    f.write(f'Raw findings: {sum(1 for _ in open(infile))}\n')
    f.write(f'Duplicates removed: {duplicate_count}\n')
    f.write(f'After dedup: {len(deduped)}\n')
    f.write('\\nSeverity breakdown:\\n')
    for sev, count in sorted(severity_counts.items()):
        f.write(f'  {sev}: {count}\n')

print(f'Raw: {sum(1 for _ in open(infile))} | Duplicates: {duplicate_count} | Deduped: {len(deduped)}')
for sev, count in sorted(severity_counts.items()):
    print(f'  {sev}: {count}')
" 2>&1 | tee -a "$OUTDIR/results/fp_filter_log.txt"
```

### Step 3: Filter false positive patterns with ripgrep on response bodies

```bash
# Build an FP pattern file dynamically
cat > "$OUTDIR/results/fp_patterns.txt" << 'FPPATTERNS'
cloudflare
cloudfront
captcha
rate limit
429
too many
blocked
throttle
nginx 404
apache test page
under construction
coming soon
please enable javascript
cf-error
akamai
incapsula
f5 big-ip
error 404
not found
page not found
your browser is out of date
browser not supported
enable cookies
cookie required
javascript is disabled
FPPATTERNS
```

```bash
# Filter JSONL by checking if matched_at URL response body contains known FP signals
python3 -c "
import json, os, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

deduped_file = os.path.join('$OUTDIR', 'results', 'deduped_findings.jsonl')
fp_patterns_file = os.path.join('$OUTDIR', 'results', 'fp_patterns.txt')
filtered_file = os.path.join('$OUTDIR', 'results', 'filtered_findings.jsonl')
fp_file = os.path.join('$OUTDIR', 'results', 'false_positives.jsonl')

fp_patterns = [l.strip().lower() for l in open(fp_patterns_file) if l.strip() and not l.startswith('#')]

findings = []
with open(deduped_file) as f:
    for line in f:
        try: findings.append(json.loads(line.strip()))
        except: pass

def check_fp(finding, idx):
    host = finding.get('host','')
    matched = finding.get('matched_at','')
    url = f'{host}{matched}' if matched else host
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '10', '-L', url],
                          capture_output=True, text=True, timeout=15)
        body_lower = r.stdout[:4096].lower()
        for pat in fp_patterns:
            if pat in body_lower:
                return (idx, True, pat)
        return (idx, False, None)
    except:
        return (idx, False, 'curl_failed')

results_map = {}
with ThreadPoolExecutor(max_workers=15) as ex:
    futures = {ex.submit(check_fp, f, i): i for i, f in enumerate(findings)}
    for future in as_completed(futures):
        idx, is_fp, matched_pattern = future.result()
        results_map[idx] = (is_fp, matched_pattern)

filtered, fps = [], []
for i, f in enumerate(findings):
    is_fp, pat = results_map.get(i, (False, None))
    if is_fp:
        fps.append({**f, 'fp_pattern': pat})
    else:
        filtered.append(f)

with open(filtered_file, 'w') as f:
    for d in filtered: f.write(json.dumps(d) + '\n')
with open(fp_file, 'w') as f:
    for d in fps: f.write(json.dumps(d) + '\n')

print(f'Passed filter: {len(filtered)}')
print(f'Flagged as false positive: {len(fps)}')
for pat in sorted(set(f.get('fp_pattern','?') for f in fps)):
    count = sum(1 for f in fps if f.get('fp_pattern') == pat)
    print(f'  {pat}: {count}')
" 2>&1 | tee -a "$OUTDIR/results/fp_filter_log.txt"
```

### Step 4: Static FP filter on response body text (if captured in 05-evidence)

```bash
for body_file in "$EVIDENCE_DIR/responses/"finding_*_body.txt; do
  [ -f "$body_file" ] || continue
  base=$(basename "$body_file" _body.txt)
  if /opt/homebrew/bin/rg -qi 'cloudflare|captcha|404|not found|blocked|throttle|under construction' "$body_file" 2>/dev/null; then
    echo "[FP] $base matched static patterns"
  fi
done >> "$OUTDIR/results/fp_static_check.txt"
```

### Step 5: Manual validation checklist generation

```bash
cat > "$OUTDIR/results/manual_validation_checklist.md" << 'CHECKEOF'
# Nuclei Finding Manual Validation Checklist

For each finding below, verify by manually visiting the URL in a browser.

## Confirmed Findings
CHECKEOF

/opt/homebrew/bin/jq -r '"### [\(.info.severity // "?")] \(.info.name // "unnamed")",
  "- **URL**: \(.host // "")\(.matched_at // "")",
  "- **Template**: \(.[\"template-id\"] // "N/A")",
  "- **Matcher**: \(.matcher_name // "N/A")",
  "- **Verified**: [ ] Confirmed  [ ] False Positive",
  ""' "$OUTDIR/results/filtered_findings.jsonl" 2>/dev/null >> "$OUTDIR/results/manual_validation_checklist.md"

echo "Checklist created: $OUTDIR/results/manual_validation_checklist.md"
```

### Step 6: Final export — clean CSV for reporting

```bash
/opt/homebrew/bin/jq -r '[.host, (.info.severity // "unknown"), (.info.name // ""), (.matcher_name // ""), "\(.host)\(.matched_at // "")", (.["template-id"] // "")] | @csv' \
  "$OUTDIR/results/filtered_findings.jsonl" \
  > "$OUTDIR/results/final_findings.csv" 2>/dev/null

echo "=== Final Results ==="
echo "Raw: $(wc -l < "$OUTDIR/results/all_raw_findings.jsonl")"
echo "Deduped: $(wc -l < "$OUTDIR/results/deduped_findings.jsonl")"
echo "After FP filter: $(wc -l < "$OUTDIR/results/filtered_findings.jsonl")"
echo "False positives flagged: $(wc -l < "$OUTDIR/results/false_positives.jsonl")"
echo "CSV export: $OUTDIR/results/final_findings.csv ($(wc -l < "$OUTDIR/results/final_findings.csv") rows)"
```

## Detection Signals
- Deduplication removes >50% of raw findings — heavy duplicate matches; normal for broad templates
- `cf-error` / `cloudflare` FP pattern matches many findings — target is behind Cloudflare WAF; adjust templates
- `curl_failed` in all FP checks — target blocks curl User-Agent; add `-H 'User-Agent: Mozilla/5.0'` to curl commands
- Zero findings after FP filter — either 100% false positives (unlikely) or curl FP check too aggressive
- `filtered_findings.jsonl` still has >10 critical entries — escalate to manual validation immediately

## Next
├── If `final_findings.csv` has confirmed critical/high → submit findings or load `reporting` skill
├── If `false_positives.jsonl` has entries → review FP patterns, update `fp_patterns.txt` for future runs
├── If `manual_validation_checklist.md` needs review → manually verify each item in browser
├── If all findings clean and ready → scan complete; merge with other skill outputs for final report