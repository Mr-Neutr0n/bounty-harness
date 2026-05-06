# Reporting — Evidence Collection

## Purpose
Capture, sanitize, and bundle all evidence artifacts: screenshots of live findings, full HTTP request/response traces, PoC scripts, and redacted output. Package everything into a single zip archive ready for submission.

## Required Variables
- `$OUTDIR`: output directory for reports
- `$EVIDENCE_DIR`: evidence directory (typically `$OUTDIR/evidence/`)
- `$TARGET_URL`: vulnerable endpoint being captured

## Commands

```bash
mkdir -p "$EVIDENCE_DIR"

cat finding_urls.txt | while read -r url; do
  url=$(echo "$url" | xargs)
  [ -z "$url" ] && continue
  safe=$(echo "$url" | tr '/:?=&<>"' '_' | cut -c1-80)
  echo "[*] Capturing: $url"
  curl -sv --connect-timeout 10 --max-time 30 \
    -H "User-Agent: Mozilla/5.0 (Security Assessment; BugBounty)" \
    -H "Accept: text/html,application/json" \
    "$url" \
    2>"$EVIDENCE_DIR/${safe}_request.txt" \
    -o "$EVIDENCE_DIR/${safe}_response.html"
  echo "[*] Response size: $(wc -c < "$EVIDENCE_DIR/${safe}_response.html") bytes"
done

if command -v httpx >/dev/null 2>&1; then
  httpx -l finding_urls.txt -screenshot -ss-path "$EVIDENCE_DIR/screenshots/" -silent -timeout 15 \
    -H "User-Agent: Mozilla/5.0 (Security Assessment; BugBounty)" 2>&1 | tee "$EVIDENCE_DIR/httpx_screenshots.log"
fi

for f in "$EVIDENCE_DIR"/*_response.html; do
  [ -f "$f" ] || continue
  out="${f%.html}_redacted.html"
  python3 - "$f" "$out" << 'PYEOF'
import sys, re
with open(sys.argv[1],"r",errors="ignore") as fh: data = fh.read()
data = re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', '[EMAIL_REDACTED]', data)
data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', data)
data = re.sub(r'\b\d{13,19}\b', '[CC_REDACTED]', data)
data = re.sub(r'(api[_-]?key|api[_-]?secret|password|token)=\S+', r'\1=[REDACTED]', data, flags=re.I)
data = re.sub(r'Bearer\s+[\w.-]+', 'Bearer [REDACTED]', data)
data = re.sub(r'sk-[A-Za-z0-9]{20,}', '[OPENAI_KEY_REDACTED]', data)
data = re.sub(r'ghp_[A-Za-z0-9]{36}', '[GITHUB_TOKEN_REDACTED]', data)
data = re.sub(r'AIza[0-9A-Za-z\-_]{35}', '[GCP_KEY_REDACTED]', data)
with open(sys.argv[2],"w") as fh: fh.write(data)
PYEOF
  echo "[*] Redacted: $f → $out"
done

cp -f "$OUTDIR/inventory/findings_with_impact.json" "$EVIDENCE_DIR/findings_with_impact.json" 2>/dev/null
cp -f "$OUTDIR/inventory/finding_inventory.json" "$EVIDENCE_DIR/finding_inventory.json" 2>/dev/null

python3 - "$EVIDENCE_DIR" "$EVIDENCE_DIR/evidence_manifest.md" << 'PYEOF'
import sys, os, time
edir = sys.argv[1]
manifest = sys.argv[2]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
lines = [f"# Evidence Manifest — {now}", "", "| File | Size | Type |", "|------|------|------|"]
for root, dirs, files in os.walk(edir):
    for f in sorted(files):
        fp = os.path.join(root, f)
        rel = os.path.relpath(fp, edir)
        sz = os.path.getsize(fp)
        ext = os.path.splitext(f)[1]
        lines.append(f"| {rel} | {sz:,} B | {ext} |")
with open(manifest, 'w') as fh:
    fh.write("\n".join(lines))
print(f"Manifest written: {manifest}")
PYEOF

zip -r "$OUTDIR/evidence_bundle.zip" "$EVIDENCE_DIR/" -x "*.DS_Store"
echo "Bundle size: $(du -h "$OUTDIR/evidence_bundle.zip" | cut -f1)"
ls -lh "$OUTDIR/evidence_bundle.zip"
```

## Detection Signals
- `evidence_bundle.zip` exists and is non-zero size
- At least one screenshot captured per active finding
- All response files have corresponding redacted versions
- Manifest lists every file with size and type
- No secrets found in redacted output (verified by `gitleaks detect --source $EVIDENCE_DIR --no-git -v`)

## Next
├── If bundle created → `06-false-positive-filter.md`
├── If screenshots failed (httpx not available) → skip, note in manifest
└── If evidence incomplete → re-run with remaining URLs only