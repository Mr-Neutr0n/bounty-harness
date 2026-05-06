# CORS/CSRF — Runbook 05: Evidence Collection

## Purpose
Standardized evidence packaging for CORS/CSRF findings. Capture everything needed for a complete bug bounty report.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence output directory (typically $OUTDIR/cors-csrf/evidence/)
- `$FINDING_ID` — unique finding identifier

---

## Directory Structure

```bash
mkdir -p "$EVIDENCE_DIR/$FINDING_ID"/{requests,responses,screenshots,poc}
```

---

## E5.1 — Capture CORS misconfig evidence

### Request with full headers

```bash
curl -v "$TARGET_URL/api/me" \
  -H "Origin: https://evil.com" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/$FINDING_ID/responses/cors-response-body.txt" \
  2>"$EVIDENCE_DIR/$FINDING_ID/requests/cors-request-headers.txt"
```

### Extract relevant headers only

```bash
grep -iE '(> |< )?(access-control|origin|cookie|authorization|content-type)' \
  "$EVIDENCE_DIR/$FINDING_ID/requests/cors-request-headers.txt" \
  > "$EVIDENCE_DIR/$FINDING_ID/requests/cors-key-headers.txt"
```

### Response body (first 200 lines)

```bash
head -200 "$EVIDENCE_DIR/$FINDING_ID/responses/cors-response-body.txt" \
  > "$EVIDENCE_DIR/$FINDING_ID/responses/cors-response-truncated.txt"
```

---

## E5.2 — Capture CSRF evidence

### Request/response for CSRF POST

```bash
curl -v -X POST "$TARGET_URL/settings/email" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=hacked@evil.com" \
  -o "$EVIDENCE_DIR/$FINDING_ID/responses/csrf-post-response.txt" \
  2>"$EVIDENCE_DIR/$FINDING_ID/requests/csrf-post-request.txt"
```

### Before/after state diff

```bash
diff "$EVIDENCE_DIR/pre-state.txt" "$EVIDENCE_DIR/post-state.txt" \
  > "$EVIDENCE_DIR/$FINDING_ID/poc/state-change.diff"
```

---

## E5.3 — Screenshots

```bash
# Take screenshot of CORS PoC page (if hosted)
echo "$TARGET_URL/api/me" | httpx -screenshot -silent -o "$EVIDENCE_DIR/$FINDING_ID/screenshots/"

# Screenshot of curl showing ACAO header in terminal
script -q /dev/null bash -c 'curl -s -D - -o /dev/null "$TARGET_URL/api/me" -H "Origin: https://evil.com" 2>/dev/null | grep -i access-control' \
  > "$EVIDENCE_DIR/$FINDING_ID/screenshots/acao-terminal-output.txt"
```

---

## E5.4 — Timestamp

```bash
date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt"
```

---

## E5.5 — Tool version manifest

```bash
cat > "$EVIDENCE_DIR/$FINDING_ID/tool-versions.txt" << EOF
curl: $(curl --version 2>&1 | head -1)
httpx: $(httpx -version 2>&1)
nuclei: $(nuclei -version 2>&1)
katana: $(katana -version 2>&1)
date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname: $(hostname)
OS: $(sw_vers 2>/dev/null || uname -a)
EOF
```

---

## E5.6 — Evidence manifest

```bash
cat > "$EVIDENCE_DIR/$FINDING_ID/manifest.txt" << EOF
FINDING_ID: $FINDING_ID
TARGET: $TARGET_URL
SEVERITY: (fill -- high/medium/low/info)
VULN_CLASS: (fill -- cors-misconfig / csrf / null-origin / subdomain-cors)
TIMESTAMP: $(cat "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt")

ARTIFACTS:
  requests/cors-request-headers.txt      -- Full curl -v output with Origin header
  requests/cors-key-headers.txt          -- Filtered relevant CORS headers
  requests/csrf-post-request.txt         -- Full curl -v for CSRF POST
  responses/cors-response-body.txt       -- Full response from CORS test endpoint
  responses/cors-response-truncated.txt  -- Truncated response (first 200 lines)
  responses/csrf-post-response.txt       -- Response from CSRF POST attempt
  screenshots/                           -- Screenshots directory
  poc/cors-exfil-poc.html               -- CORS exfiltration PoC HTML
  poc/csrf-poc.html                      -- CSRF auto-submit form PoC
  poc/state-change.diff                  -- Before/after state diff
  timestamp.txt                          -- Finding timestamp
  tool-versions.txt                      -- Tool version manifest

DESCRIPTION:
(fill -- describe what was found, how to reproduce, and impact)

REPRODUCTION:
1. (fill -- step by step reproduction)
2. (fill)
3. (fill)

NOTES:
(fill -- any additional context, false positive risks, caveats)
EOF

echo "Evidence manifest written to $EVIDENCE_DIR/$FINDING_ID/manifest.txt"
```

---

## E5.7 — Package for reporting

```bash
tar -czf "$EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz" \
  -C "$EVIDENCE_DIR" "$FINDING_ID"

echo "Evidence packaged: $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz"
echo "Evidence dir: $EVIDENCE_DIR/$FINDING_ID/"
```

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/$FINDING_ID/manifest.txt | Complete evidence manifest |
| $EVIDENCE_DIR/$FINDING_ID/requests/ | All request captures |
| $EVIDENCE_DIR/$FINDING_ID/responses/ | All response captures |
| $EVIDENCE_DIR/$FINDING_ID/screenshots/ | Screenshots |
| $EVIDENCE_DIR/$FINDING_ID/poc/ | PoC files |
| $EVIDENCE_DIR/$FINDING_ID/timestamp.txt | UTC timestamp |
| $EVIDENCE_DIR/$FINDING_ID/tool-versions.txt | Tool version manifest |
| $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz | Packaged evidence archive |
