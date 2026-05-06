# Nuclei Scanner — Initial Probe with OOB Detection

## Purpose
Run the first broad scan against the target with rate limiting and interactsh for out-of-band (blind) vulnerability detection. Covers critical, high, and medium severities across the full HTTP template set.

## Required Variables
- $TARGET_URL: target URL or file of live URLs (one per line)
- $OUTDIR: output directory for scan results
- $EVIDENCE_DIR: evidence directory

## Commands

### Pre-flight: discover templates directory

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
TEMPLATES_DIR=""
for d in "/opt/homebrew/share/nuclei-templates" "$HOME/nuclei-templates" "templates/nuclei-templates" "./nuclei-templates"; do
  if [ -d "$d" ]; then TEMPLATES_DIR="$d"; break; fi
done
if [ -z "$TEMPLATES_DIR" ]; then
  echo "FATAL: No nuclei-templates directory found. Run 01-discovery.md first."
  exit 1
fi
mkdir -p "$OUTDIR"/{scans,results,evidence,diff}
```

### Start interactsh client in background for OOB callbacks

```bash
/opt/homebrew/bin/interactsh-client -json -o "$OUTDIR/scans/interactsh_poll.json" > "$OUTDIR/scans/interactsh_client.log" 2>&1 &
INTERACTSH_PID=$!
echo "$INTERACTSH_PID" > "$OUTDIR/scans/_interactsh_pid.txt"
sleep 5
```

### Extract interactsh URL from client output

```bash
cat "$OUTDIR/scans/interactsh_client.log" | /opt/homebrew/bin/jq -r 'select(.url != null) | .url' 2>/dev/null | head -1 > "$OUTDIR/scans/interactsh_url.txt"
INTERACTSH_URL=$(cat "$OUTDIR/scans/interactsh_url.txt" 2>/dev/null)
if [ -n "$INTERACTSH_URL" ]; then
  echo "Interactsh OOB server: $INTERACTSH_URL"
else
  echo "WARN: Could not extract interactsh URL — OOB templates will be skipped"
fi
```

### Critical + high severity scan (fast first pass)

```bash
if [ -n "$INTERACTSH_URL" ]; then
  /opt/homebrew/bin/nuclei -l "$TARGET_URL" \
    -templates "$TEMPLATES_DIR/http/" \
    -severity critical,high \
    -rate 50 \
    -bulk-size 50 \
    -timeout 10 \
    -retries 1 \
    -interactsh-url "${INTERACTSH_URL}" \
    -stats \
    -stats-interval 60 \
    -silent \
    -json \
    -o "$OUTDIR/scans/probe_critical_high.jsonl"
else
  /opt/homebrew/bin/nuclei -l "$TARGET_URL" \
    -templates "$TEMPLATES_DIR/http/" \
    -severity critical,high \
    -rate 50 \
    -bulk-size 50 \
    -timeout 10 \
    -retries 1 \
    -stats \
    -stats-interval 60 \
    -silent \
    -json \
    -o "$OUTDIR/scans/probe_critical_high.jsonl"
fi
```

### Medium severity scan (broader coverage)

```bash
if [ -n "$INTERACTSH_URL" ]; then
  /opt/homebrew/bin/nuclei -l "$TARGET_URL" \
    -templates "$TEMPLATES_DIR/http/" \
    -severity medium \
    -rate 75 \
    -bulk-size 75 \
    -timeout 10 \
    -retries 1 \
    -interactsh-url "${INTERACTSH_URL}" \
    -stats \
    -stats-interval 90 \
    -silent \
    -json \
    -exclude-severity critical,high \
    -o "$OUTDIR/scans/probe_medium.jsonl"
else
  /opt/homebrew/bin/nuclei -l "$TARGET_URL" \
    -templates "$TEMPLATES_DIR/http/" \
    -severity medium \
    -rate 75 \
    -bulk-size 75 \
    -timeout 10 \
    -retries 1 \
    -stats \
    -stats-interval 90 \
    -silent \
    -json \
    -exclude-severity critical,high \
    -o "$OUTDIR/scans/probe_medium.jsonl"
fi
```

### Technology detection scan (in parallel with severity scans)

```bash
/opt/homebrew/bin/nuclei -l "$TARGET_URL" \
  -templates "$TEMPLATES_DIR/http/technologies/" \
  -rate 100 \
  -bulk-size 100 \
  -timeout 10 \
  -retries 1 \
  -stats \
  -stats-interval 60 \
  -silent \
  -json \
  -o "$OUTDIR/scans/probe_tech.jsonl"
```

### Poll interactsh for hits after all scans complete

```bash
sleep 30
/opt/homebrew/bin/interactsh-client -poll-interval 15 -n 8 -json -o "$OUTDIR/scans/interactsh_hits.json" > "$OUTDIR/scans/interactsh_poll_log.txt" 2>&1

cat "$OUTDIR/scans/interactsh_hits.json" 2>/dev/null | /opt/homebrew/bin/jq -r '[.protocol, ."remote-address", ."raw-request"] | @tsv' 2>/dev/null | tee "$OUTDIR/scans/interactsh_hits.txt"

echo "Interactsh interactions captured: $(wc -l < "$OUTDIR/scans/interactsh_hits.txt" 2>/dev/null)"
```

### Summarize probe results

```bash
python3 -c "
import json, os
for fname,label in [('probe_critical_high.jsonl','critical+high'),('probe_medium.jsonl','medium'),('probe_tech.jsonl','tech')]:
    path = os.path.join('$OUTDIR/scans', fname)
    count = sum(1 for _ in open(path)) if os.path.exists(path) else 0
    print(f'{label}: {count} findings')
" | tee "$OUTDIR/scans/probe_summary.txt"
```

### Clean up interactsh client

```bash
kill "$(cat "$OUTDIR/scans/_interactsh_pid.txt" 2>/dev/null)" 2>/dev/null
rm -f "$OUTDIR/scans/_interactsh_pid.txt"
```

## Detection Signals
- `probe_critical_high.jsonl` has entries — critical vulnerabilities detected; escalate to verify immediately
- `interactsh_hits.txt` has lines — blind/out-of-band vulnerability confirmed (SSRF, blind RCE, blind XSS)
- `probe_tech.jsonl` identifies specific versions — cross-reference with known CVEs in next phase
- Scan runs too fast (<2 min for 500 hosts) — templates may be empty or path is wrong

## Next
├── If critical/high findings → go to `03-verify.md` for automated validation
├── If interactsh hits → go to `04-impact-escalation.md` for deeper OOB exploitation
├── If tech detected, no vulns → go to `04-impact-escalation.md` for targeted CVE scan
├── If zero findings across all scans → go to `04-impact-escalation.md` for custom template fuzzing
