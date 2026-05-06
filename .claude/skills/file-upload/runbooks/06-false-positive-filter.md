# File Upload False Positive Filter Runbook

## Purpose
Filter false positives from file upload testing. Many upload "bypasses" either don't execute or only work in controlled/test scenarios.

## Variables
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/file-upload`
- `$FILE_URL` — URL where file is served

## FP-1 — Extension Bypass But No Code Execution

### Pattern: PHP file uploaded but served as text/plain or download
```bash
CONTENT_TYPE=$(curl -sk -I "$FILE_URL" 2>&1 | grep -i content-type | head -1)
echo "Content-Type: $CONTENT_TYPE"
# If Content-Type is text/plain, application/octet-stream, or has Content-Disposition:attachment
# -> PHP code NOT executed, just served as a file download
```

### Filter: Verify actual code execution
```bash
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/fp-code-exec-check.txt"
grep -q '<?php' "$EVIDENCE_DIR/fp-code-exec-check.txt" && echo "PHP SOURCE SENT TO CLIENT — no code execution" >> "$EVIDENCE_DIR/fp-log.txt"
grep -qE 'uid=|gid=|VERIFY_PHP_RCE_OK' "$EVIDENCE_DIR/fp-code-exec-check.txt" && echo "CODE EXECUTED — real finding" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Pattern: File uploaded but immediately deleted by security scanner
```bash
curl -sk "$FILE_URL" -w "%{http_code}" -o /dev/null > "$EVIDENCE_DIR/fp-file-available-check.txt"
# If 404 -> file removed, scanner caught it. Document as "self-correcting" but still a finding if extension bypass was accepted
```

### Pattern: Upload to temporary directory that gets cleaned
```bash
sleep 10
curl -sk "$FILE_URL" -w "%{http_code}" -o /dev/null >> "$EVIDENCE_DIR/fp-file-available-check-2.txt"
# If file disappears after short time -> ephemeral, lower severity but still a finding
```

## FP-2 — SVG XSS False Positive

### Pattern: SVG uploaded but sanitized (script stripped)
```bash
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/fp-svg-check.xml"
grep -q '<script\|onload' "$EVIDENCE_DIR/fp-svg-check.xml" || echo "SVG SANITIZED — script removed by server" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Pattern: SVG served from different origin (no cookie access)
```bash
FILE_DOMAIN=$(echo "$FILE_URL" | grep -oP 'https?://[^/]+')
TARGET_DOMAIN=$(echo "$TARGET_URL" | grep -oP 'https?://[^/]+')
[ "$FILE_DOMAIN" != "$TARGET_DOMAIN" ] && echo "CROSS-ORIGIN SVG — XSS cannot access main app cookies/session" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Pattern: SVG served with Content-Disposition: attachment
```bash
curl -sk -I "$FILE_URL" 2>&1 | grep -qi 'content-disposition.*attachment' && echo "SVG SENT AS DOWNLOAD — XSS not triggerable in browser" >> "$EVIDENCE_DIR/fp-log.txt"
```

## FP-3 — Content-Type Bypass False Positive

### Pattern: Server accepts content-type but still inspects file magic bytes
```bash
echo "<?php system('id');?>" | sed 's/^/GIF89a; /' > "$PAYLOAD_DIR/gif-with-php.gif"
curl -sk -F "file=@$PAYLOAD_DIR/gif-with-php.gif;type=image/gif" -b "$COOKIE_JAR" "$TARGET_URL" -o "$EVIDENCE_DIR/fp-magic-bytes-check.txt"
# If server says "invalid image" -> magic bytes checked, content-type bypass ineffective
```

## FP-4 — Path Traversal False Positive

### Pattern: Traversal "accepted" but file goes to default location, not target path
```bash
curl -sk -v -F "filename=../../../etc/hosts" -F "file=@$PAYLOAD_DIR/pt-test.txt" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/fp-traversal-check.txt" 2>&1
# If response shows file URL in normal upload directory -> traversal was silently ignored
# If response shows error about path -> traversal blocked
```

## Confidence Scoring Guide

| Score | Criteria |
|---|---|
| 10/10 | PHP code executed, commands run, system info returned |
| 8/10 | Extension bypass works, PHP source sent but not executed (web server not configured) |
| 5/10 | Extension bypass works but file deleted/cleaned up quickly |
| 3/10 | SVG uploaded but sanitized - only raw upload bypass |
| 0/10 | Upload accepted but file never accessible, content-type mismatch |

## Verification Checklist
```
[ ] Uploaded file is accessible via URL (not just accepted)
[ ] PHP code actually EXECUTES (not served as source code)
[ ] SVG XSS triggers JavaScript in target domain (not cross-origin)
[ ] File persists long enough for exploitation (not ephemeral)
[ ] Extension bypass leads to code execution (not just storage)
[ ] No cleanup script modified production files or configs
```

## Next Routing
- Passes filters with confidence >= 8 -> `runbooks/05-evidence-collection.md`
- Passes filters with confidence 3-7 -> re-evaluate with additional techniques
- Confidence < 3 -> discard finding
