# XSS — False Positive Filter

## Purpose
Eliminate false XSS alerts caused by sandboxed contexts, CSP blocking, browser filtering, and non-executable reflection. Prevents reporting of payloads that reflect but can't execute.

## Required Variables
- `$TARGET_URL` — target endpoint
- `$VULN_PARAM` — parameter under test
- `$OUTDIR` — output root

## Commands

### Filter 1: Textarea/Code-Block Sanitization

```bash
# Payloads reflected inside <textarea>, <code>, <pre>, or <xmp> are not exploitable
curl -s "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | \
  rg -oP '(?<=<textarea[^>]*>).*?(?=</textarea>)' > "$OUTDIR/xss/textarea_context.txt"

curl -s "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | \
  rg -oP '(?<=<code[^>]*>).*?(?=</code>)' > "$OUTDIR/xss/code_context.txt"

[ -s "$OUTDIR/xss/textarea_context.txt" ] && echo "[FP] Payload inside <textarea> — not exploitable" >> "$OUTDIR/xss/false_positives.txt"
[ -s "$OUTDIR/xss/code_context.txt" ] && echo "[FP] Payload inside <code> — not exploitable" >> "$OUTDIR/xss/false_positives.txt"
```

### Filter 2: HTML Entity Encoding

```bash
# If payload is fully HTML-entity-encoded upon reflection, it won't execute
curl -s "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | \
  grep -c '&lt;svg/onload=alert(1)&gt;' && \
  echo "[FP] Payload fully HTML-entity-encoded" >> "$OUTDIR/xss/false_positives.txt"

# Check for partial encoding (partially encoded can still work with mutations)
curl -s "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | \
  grep -c '<svg/onload=alert' && echo "[OK] No entity encoding — exploitable" || echo "[?] Check encoding level"
```

### Filter 3: CSP Blocking

```bash
CSP=$(curl -sI "$TARGET_URL" | grep -i 'content-security-policy')
echo "$CSP" > "$OUTDIR/xss/csp_check.txt"

# If CSP exists and blocks inline scripts AND no bypass is possible
if echo "$CSP" | grep -q "script-src" && echo "$CSP" | grep -qv "'unsafe-inline'"; then
  echo "[FP-POTENTIAL] CSP blocks inline execution. Test with script-src bypass." >> "$OUTDIR/xss/false_positives.txt"
fi
```

### Filter 4: XSS Auditor / Browser Filter Artifacts

```bash
# Modern Chrome/Edge don't have XSS Auditor, but some WAFs add blocking headers
curl -sI "$TARGET_URL?${VULN_PARAM}=<script>alert(1)</script>" | \
  grep -iE 'X-XSS-Protection: 1; mode=block' && \
  echo "[FP-FILTER] Browser XSS filter enabled on response" >> "$OUTDIR/xss/false_positives.txt"
```

### Filter 5: Attribute-Value Context Without Breakout

```bash
# Payload reflected inside an attribute value but no quote breakout works
# Example: <a href="&lt;img src=x onerror=alert(1)&gt;">
curl -s "$TARGET_URL?${VULN_PARAM}=test" > "$OUTDIR/xss/context_baseline.html"
# Check if value is inside quotes without ability to break out
rg -oP '(?:href|src|value|action|data-\w+)="[^"]*test[^"]*"' "$OUTDIR/xss/context_baseline.html" && \
  echo "[CTX] Value reflected inside attribute. Need '\" or \"' breakout." >> "$OUTDIR/xss/context_analysis.txt"
```

### Filter 6: JSON String Context

```bash
# Payload inside JSON string like {"q":"<svg/onload=alert(1)>"} is not HTML-rendered
curl -s "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | \
  grep -oP '(?<=")[^"]*<svg/onload=alert[^"]*(?=")' && \
  echo "[FP] Payload inside JSON string value — not rendered as HTML" >> "$OUTDIR/xss/false_positives.txt"
```

### Filter 7: Content-Type Enforcement

```bash
# If response Content-Type is application/json or text/plain, browser won't render HTML
CT=$(curl -sI "$TARGET_URL?${VULN_PARAM}=<svg/onload=alert(1)>" | grep -i 'content-type' | grep -c 'json\|plain')
[ "$CT" -gt 0 ] && echo "[FP] Response Content-Type prevents HTML rendering" >> "$OUTDIR/xss/false_positives.txt"
```

### Filter Summary

```bash
echo "===== XSS False Positive Summary =====" > "$OUTDIR/xss/fp_summary.txt"
echo "Context analysis:" >> "$OUTDIR/xss/fp_summary.txt"
cat "$OUTDIR/xss/context_analysis.txt" 2>/dev/null >> "$OUTDIR/xss/fp_summary.txt"
echo "False positives:" >> "$OUTDIR/xss/fp_summary.txt"
cat "$OUTDIR/xss/false_positives.txt" 2>/dev/null >> "$OUTDIR/xss/fp_summary.txt"
echo "Total FP candidates: $(wc -l < "$OUTDIR/xss/false_positives.txt" 2>/dev/null || echo 0)" >> "$OUTDIR/xss/fp_summary.txt"
```

## Detection Signals
- Payload inside `<textarea>`, `<code>`, `<pre>`, `<xmp>` → false positive
- Payload fully entity-encoded (`&lt;` `&gt;`) → false positive unless double-encoding works
- CSP blocks execution with no bypass → downgrade from vulnerability to defense-in-depth finding
- JSON string context with no HTML rendering → false positive

## Next
├── Any context marked `[FP]` → remove from findings list
├── CSP blocked but bypass possible → re-route to `03-verify.md` with bypass payloads
├── Context requires breakout ('" etc) → re-test with context-aware payloads from `02-probe.md`
├── Clean findings remain → proceed to `04-impact-escalation.md` for exploitation
└── Always → run `cat "$OUTDIR/xss/fp_summary.txt"` before declaring final hit list