# RCE False Positive Filter Runbook

## Purpose
Filter out common false positives before reporting. Avoid submitting invalid RCE reports that waste triager time.

## Variables
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/rce`
- `$TARGET_URL` — the tested URL

## FP-1 — Command Injection False Positives

### Pattern: Error message contains "uid="
If the response contains `uid=` but in an HTML-encoded or quoted context:
```bash
grep -o 'uid=[0-9]*([a-z]*)' "$EVIDENCE_DIR/response"/*.txt | head -5
```

### Filter test: Command result is static / invariant
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;echo RANDOM$(date +%s)" -o "$EVIDENCE_DIR/fp-check-random.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;echo STATIC12345" -o "$EVIDENCE_DIR/fp-check-static.txt"
# If both return the same thing -> likely static reflection, not execution
diff "$EVIDENCE_DIR/fp-check-random.txt" "$EVIDENCE_DIR/fp-check-static.txt" && echo "STATIC RESPONSE — likely false positive" >> "$EVIDENCE_DIR/fp-log.txt"
```

### Filter test: Arithmetic with different values
```bash
A=$(curl -sk "$TARGET_URL?$VULN_PARAM=$(expr 100 + 50)")
B=$(curl -sk "$TARGET_URL?$VULN_PARAM=$(expr 200 + 75)")
echo "$A" | grep -o '[0-9]\+'
echo "$B" | grep -o '[0-9]\+'
# If both show different arithmetic results -> command injection likely real
# If both show same number -> false positive
```

### Filter test: Command result appears in HTML comment or JS string
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;id" | grep -C3 'uid='
# If surrounded by <!-- --> or inside quotes/delimiters, check if it's server template syntax
```

## FP-2 — SSTI False Positives

### Pattern: `{{7*7}}` renders as literal text in response
```bash
curl -sk "$TARGET_URL?$VULN_PARAM={{7*7}}" -o "$EVIDENCE_DIR/fp-ssti-check.txt"
# Real SSTI: response contains "49"
# False positive: response contains literal "{{7*7}}" (no evaluation)
```

### Pattern: 49 appears but is not from SSTI evaluation
```bash
curl -sk "$TARGET_URL?$VULN_PARAM={{0*0}}" -o "$EVIDENCE_DIR/fp-ssti-zero.txt"
curl -sk "$TARGET_URL?$VULN_PARAM={{1*1}}" -o "$EVIDENCE_DIR/fp-ssti-one.txt"
# If both return 0 and 1 respectively -> SSTI confirmed
# If both return same value -> likely not SSTI, just coincidental 49 in response
```

### Pattern: Jinja2 config object renders but is not accessible
```bash
curl -sk "$TARGET_URL?$VULN_PARAM={{config}}" -o "$EVIDENCE_DIR/fp-ssti-config.txt"
curl -sk "$TARGET_URL?$VULN_PARAM={{unknown_variable_xyz}}" -o "$EVIDENCE_DIR/fp-ssti-unknown.txt"
# If both produce the same empty/error response -> not real SSTI
```

## FP-3 — LFI False Positives

### Pattern: `root:x:0:0:` appears but is hardcoded in HTML
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=../../etc/passwd" -o "$EVIDENCE_DIR/fp-lfi-passwd.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=../../etc/NONEXISTENT_FILE_XYZ" -o "$EVIDENCE_DIR/fp-lfi-nonexistent.txt"
# Real LFI: /etc/passwd returns passwd content, nonexistent returns error
# False positive: both return same content (passwd string is hardcoded in error page)
```

## FP-4 — Deserialization False Positives

### Pattern: Base64-encoded string looks like serialized object
```bash
echo "rO0ABXNy" | base64 -d 2>/dev/null && echo "IS JAVA SERIALIZED" || echo "NOT JAVA SERIALIZED"
# Even if base64 decodes, verify it represents a real object graph, not random data
```

## Confidence Scoring Guide

| Score | Criteria |
|---|---|
| 10/10 | Command output changes based on input (arithmetic confirms), multiple params affected |
| 8/10 | One command works reliably but only on one separator |
| 5/10 | Inconsistent results, only works sometimes, not reproducible on retry |
| 2/10 | Single instance, coincidental match, static response regardless of input |
| 0/10 | Static HTML, no evaluation, no variation based on input |

## Verification Checklist
```
[ ] Response changes based on different arithmetic inputs
[ ] `id` returns real user info, not a hardcoded string
[ ] Different commands produce different outputs (not same template)
[ ] Exploit works on retry (not a fluke / race condition)
[ ] Exploit works from different client (not cached response)
[ ] No secrets or tokens in captured output files
```

## Next Routing
- Passes filters with confidence >= 8 -> `runbooks/05-evidence-collection.md`
- Passes filters with confidence 5-7 -> re-test with additional payloads
- Confidence < 5 -> discard finding, return to discovery
