# Nuclei Scanner — Evidence Collection & PoC Capturing

## Purpose
Capture screenshots, response bodies, request headers, and timestamps for every confirmed finding. Produce a complete evidence package suitable for bug bounty report submission.

## Required Variables
- $TARGET_URL: target URL or file of live URLs
- $OUTDIR: output directory for scan results
- $EVIDENCE_DIR: evidence directory

## Commands

### Pre-flight: create evidence directory structure

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$EVIDENCE_DIR"/screenshots "$EVIDENCE_DIR"/responses "$EVIDENCE_DIR"/requests "$EVIDENCE_DIR"/manifests
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Evidence collection started: $TIMESTAMP" | tee "$EVIDENCE_DIR/manifests/collection_start.txt"
```

### Extract all verified finding URLs (from 03-verify.md output)

```bash
/opt/homebrew/bin/jq -r '.verified[].url // empty' "$EVIDENCE_DIR/verification_report.json" 2>/dev/null > "$OUTDIR/evidence_urls.txt"
if [ ! -s "$OUTDIR/evidence_urls.txt" ]; then
  /opt/homebrew/bin/jq -r '.url' "$OUTDIR/verify_findings_flat.jsonl" 2>/dev/null > "$OUTDIR/evidence_urls.txt"
fi
FINDING_COUNT=$(wc -l < "$OUTDIR/evidence_urls.txt" 2>/dev/null)
echo "Findings to collect evidence for: $FINDING_COUNT"
```

### httpx screenshots of all findings

```bash
/opt/homebrew/bin/httpx -l "$OUTDIR/evidence_urls.txt" \
  -screenshot \
  -screenshot-timeout 15 \
  -ss-path "$EVIDENCE_DIR/screenshots" \
  -silent \
  -timeout 15 \
  -title \
  -status-code \
  -o "$EVIDENCE_DIR/screenshots/httpx_screenshot_manifest.txt"
echo "Screenshots captured: $(ls "$EVIDENCE_DIR/screenshots/"*.png 2>/dev/null | wc -l)"
```

### Curl verbose trace: capture full request + response per finding

```bash
i=0
while IFS= read -r FINDING_URL; do
  i=$((i+1))
  SAFE_NAME="finding_$(printf '%03d' $i)_$(echo "$FINDING_URL" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)"

  # Full verbose curl with headers
  curl -sv --max-time 15 -L "$FINDING_URL" \
    > "$EVIDENCE_DIR/responses/${SAFE_NAME}_body.txt" \
    2>"$EVIDENCE_DIR/requests/${SAFE_NAME}_headers_verbose.txt"

  # Sanitized curl command for reproduction (one-liner)
  echo "curl -sv --max-time 15 -L '${FINDING_URL}' 2>&1" > "$EVIDENCE_DIR/requests/${SAFE_NAME}_poc.sh"
  chmod +x "$EVIDENCE_DIR/requests/${SAFE_NAME}_poc.sh"

  # Timestamp
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | $FINDING_URL" >> "$EVIDENCE_DIR/manifests/timestamps.txt"

  echo "[$i/$FINDING_COUNT] Evidence captured: $FINDING_URL"
done < "$OUTDIR/evidence_urls.txt"
```

### HTTP header-only capture for response analysis

```bash
i=0
while IFS= read -r FINDING_URL; do
  i=$((i+1))
  SAFE_NAME="finding_$(printf '%03d' $i)_$(echo "$FINDING_URL" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)"
  curl -sI --max-time 10 -L "$FINDING_URL" > "$EVIDENCE_DIR/requests/${SAFE_NAME}_response_headers.txt" 2>/dev/null
done < "$OUTDIR/evidence_urls.txt"
```

### Tool version manifest for reproducibility

```bash
echo "=== Tool Versions $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" > "$EVIDENCE_DIR/manifests/tool_versions.txt"

/opt/homebrew/bin/nuclei --version 2>&1 | head -1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
/opt/homebrew/bin/httpx --version 2>&1 | head -1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
/opt/homebrew/bin/interactsh-client --version 2>&1 | head -1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
curl --version 2>&1 | head -1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
/opt/homebrew/bin/jq --version 2>&1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
python3 --version 2>&1 >> "$EVIDENCE_DIR/manifests/tool_versions.txt"

TEMPLATES_DIR=""
for d in "/opt/homebrew/share/nuclei-templates" "$HOME/nuclei-templates" "templates/nuclei-templates" "./nuclei-templates"; do
  if [ -d "$d" ]; then TEMPLATES_DIR="$d"; break; fi
done
if [ -n "$TEMPLATES_DIR" ]; then
  echo "Templates commit: $(git -C "$TEMPLATES_DIR" rev-parse HEAD 2>/dev/null)" >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
  echo "Templates path: $TEMPLATES_DIR" >> "$EVIDENCE_DIR/manifests/tool_versions.txt"
fi
```

### Generate evidence manifest index

```bash
{
  echo "# Nuclei Scanner Evidence Manifest"
  echo "## Collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "## Summary"
  echo "- Total findings: $FINDING_COUNT"
  echo "- Screenshots: $(ls "$EVIDENCE_DIR/screenshots/"*.png 2>/dev/null | wc -l)"
  echo "- Response captures: $(ls "$EVIDENCE_DIR/responses/" 2>/dev/null | wc -l)"
  echo "- Request traces: $(ls "$EVIDENCE_DIR/requests/" 2>/dev/null | wc -l)"
  echo ""
  echo "## File Listing"
  echo "### Screenshots"
  ls -la "$EVIDENCE_DIR/screenshots/" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "### Responses"
  ls -la "$EVIDENCE_DIR/responses/" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "### Requests"
  ls -la "$EVIDENCE_DIR/requests/" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "## Tool Versions"
  cat "$EVIDENCE_DIR/manifests/tool_versions.txt" 2>/dev/null | sed 's/^/  /'
  echo ""
  echo "## Timestamps"
  cat "$EVIDENCE_DIR/manifests/timestamps.txt" 2>/dev/null | sed 's/^/  /'
} > "$EVIDENCE_DIR/manifests/evidence_manifest.md"

echo "Evidence manifest written: $EVIDENCE_DIR/manifests/evidence_manifest.md"
echo "Collection complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

### Quick sanity check: verify all captures are non-empty

```bash
echo "=== Evidence Integrity Check ==="
echo "Empty response bodies:"
find "$EVIDENCE_DIR/responses/" -name "*.txt" -empty 2>/dev/null | wc -l
echo "Empty request traces:"
find "$EVIDENCE_DIR/requests/" -name "*.txt" -empty 2>/dev/null | wc -l
echo "Empty screenshots:"
find "$EVIDENCE_DIR/screenshots/" -name "*.png" -size 0 2>/dev/null | wc -l
echo "Total evidence files: $(find "$EVIDENCE_DIR" -type f | wc -l)"
```

## Detection Signals
- Zero screenshots captured — httpx screenshot failed; check $EVIDENCE_DIR/screenshots path write permissions
- Empty response body on `curl -sv` — site blocks headless requests; try with User-Agent header
- `finding_*_poc.sh` files contain `curl` exit code 0 — PoC script is valid and reproducible
- Evidence manifest shows zero findings — verification report may be empty; re-run `03-verify.md`

## Next
├── If evidence complete → go to `06-false-positive-filter.md` for final dedup and sanity check
├── If missing screenshots → re-run httpx with `-debug` flag to diagnose
├── If all evidence files empty → site may be blocking automated scans, fall back to manual testing
