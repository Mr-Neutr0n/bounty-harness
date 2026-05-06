# Nuclei Scanner — Automated Finding Verification

## Purpose
Validate every critical and high severity nuclei finding using curl re-tests, response comparison, and template integrity checks. Confirm which findings are real vs. false positives before escalation.

## Required Variables
- $TARGET_URL: target URL or file of live URLs
- $OUTDIR: output directory for scan results
- $EVIDENCE_DIR: evidence directory

## Commands

### Pre-flight: validate individual templates for integrity

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
TEMPLATES_DIR=""
for d in "/opt/homebrew/share/nuclei-templates" "$HOME/nuclei-templates" "templates/nuclei-templates" "./nuclei-templates"; do
  if [ -d "$d" ]; then TEMPLATES_DIR="$d"; break; fi
done
mkdir -p "$EVIDENCE_DIR"
```

```bash
for f in $(find "$TEMPLATES_DIR/http/cves/" -name "*.yaml" -type f | head -20); do
  /opt/homebrew/bin/nuclei -validate -t "$f" 2>&1
done | tee "$OUTDIR/verify_template_validation.txt"
```

### Parse nuclei JSONL output and extract unique finding URLs

```bash
python3 -c "
import json, os
scans_dir = os.path.join('$OUTDIR', 'scans')
jsonl_files = ['probe_critical_high.jsonl', 'probe_medium.jsonl']
unique = set()
for f in jsonl_files:
    path = os.path.join(scans_dir, f)
    if not os.path.exists(path):
        continue
    with open(path) as fh:
        for line in fh:
            try:
                d = json.loads(line.strip())
                host = d.get('host','')
                matched = d.get('matched_at','')
                severity = d.get('info',{}).get('severity','')
                name = d.get('info',{}).get('name','')
                if matched and host:
                    key = f'{host}{matched}'
                    if key not in unique:
                        unique.add(key)
                        print(json.dumps({
                            'url': f'{host}{matched}',
                            'host': host,
                            'severity': severity,
                            'name': name,
                            'template_id': d.get('template-id',''),
                            'matcher_name': d.get('matcher_name',''),
                            'finding_line': d.get('extracted_results',[])
                        }))
            except: pass
" > "$OUTDIR/verify_findings_flat.jsonl"
echo "Unique findings to verify: $(wc -l < "$OUTDIR/verify_findings_flat.jsonl")"
```

### Curl-based automated verification of each finding

```bash
python3 -c "
import json, subprocess, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

jsonl_path = os.path.join('$OUTDIR', 'verify_findings_flat.jsonl')
if not os.path.exists(jsonl_path):
    print('FATAL: No findings file found.')
    sys.exit(1)

findings = []
with open(jsonl_path) as f:
    for line in f:
        try: findings.append(json.loads(line.strip()))
        except: pass

def probe(finding):
    url = finding['url']
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '10', '-L', url],
            capture_output=True, text=True, timeout=15
        )
        code = r.stdout.strip()
        return {**finding, 'curl_status': code}
    except Exception as e:
        return {**finding, 'curl_status': 'error', 'curl_error': str(e)}

results = []
with ThreadPoolExecutor(max_workers=10) as ex:
    futures = {ex.submit(probe, f): f for f in findings}
    for future in as_completed(futures):
        r = future.result()
        results.append(r)
        status_icon = 'VERIFIED' if r['curl_status'] in ('200','403','401','301','302','500') else 'UNLIKELY' if r['curl_status'] == '404' else r['curl_status']
        print(f'[{status_icon}] {r[\"curl_status\"]} {r[\"url\"]} — {r[\"name\"][:60]}')

verified = [r for r in results if r['curl_status'] not in ('404','000','error')]
unverified = [r for r in results if r['curl_status'] in ('404','000','error')]
print(f'\nVerified: {len(verified)} | Unverified/Not found: {len(unverified)}')

with open(os.path.join('$EVIDENCE_DIR', 'verification_report.json'), 'w') as f:
    json.dump({'verified': verified, 'unverified': unverified, 'total': len(results)}, f, indent=2)
print(f'Report saved to $EVIDENCE_DIR/verification_report.json')
" 2>&1 | tee "$OUTDIR/verify_curl_results.txt"
```

### Deep-verify top findings: capture full response body and headers

```bash
/opt/homebrew/bin/jq -r '.url' "$OUTDIR/verify_findings_flat.jsonl" 2>/dev/null | head -10 | while read url; do
  safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-60)
  curl -sv --max-time 15 "$url" > "$EVIDENCE_DIR/verify_${safe_name}_response.txt" 2>"$EVIDENCE_DIR/verify_${safe_name}_headers.txt"
  echo "[$(date -u +%H:%M:%S)] Curled: $url"
done
```

### Cross-reference: compare curl response body with nuclei matcher words

```bash
python3 -c "
import json, os, subprocess
with open(os.path.join('$OUTDIR', 'verify_findings_flat.jsonl')) as f:
    findings = [json.loads(l) for l in f if l.strip()]
report = json.load(open(os.path.join('$EVIDENCE_DIR', 'verification_report.json')))
verified_urls = {v['url'] for v in report['verified']}

for finding in findings:
    url = finding['url']
    matcher = finding.get('matcher_name','')
    template_id = finding.get('template_id','')
    name = finding.get('name','')
    if url in verified_urls:
        print(f'[MATCH] {template_id} :: {matcher} :: {name[:80]}')
    else:
        curl_status = next((r.get('curl_status','?') for r in report['verified']+report['unverified'] if r.get('url')==url), '?')
        print(f'[NO-MATCH {curl_status}] {template_id} :: {matcher} :: {name[:80]}')
" | tee "$OUTDIR/verify_matcher_crossref.txt"
```

## Detection Signals
- curl returns `200` or `403` on finding URL — finding confirmed; escalate for impact assessment
- curl returns `404` on finding URL — likely false positive; flag for FP filter in `06-false-positive-filter.md`
- Template fails `-validate` — template is malformed; exclude from scans and report upstream
- Response body contains matcher words — template match is reproducible (confirmed)
- No matcher words in response body — template may have matched transient error page

## Next
├── If verified findings exist → go to `04-impact-escalation.md` for deeper exploitation
├── If all findings unverified (404/error) → go to `06-false-positive-filter.md` to document FP patterns
├── If template validation failures → fix or exclude templates, re-run probe