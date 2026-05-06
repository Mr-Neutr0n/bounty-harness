# SQL Injection — False Positive Filter

## Purpose
Eliminate false SQLi signals caused by application-layer validation errors, WAF blocking patterns, HTML encoding of error messages, parameter binding artifacts, and ORM-safe contexts that appear vulnerable but are not exploitable.

## Required Variables
- `$TARGET_URL` — target endpoint
- `$OUTDIR` — output root

## Commands

### Filter 1: Application Validation Errors (Not SQL)

```bash
# Many apps return "error" for any invalid input — not necessarily SQL errors
curl -s "${TARGET_URL}'" | rg -iE 'error|exception|invalid' > "$OUTDIR/sqli/raw_error.txt"

# Filter out common non-SQL error phrases
grep -viE '(required|must be|invalid format|too long|too short|characters|special chars|not allowed|validation failed|missing field|unexpected token|bad request|input error|malformed request)' "$OUTDIR/sqli/raw_error.txt" > "$OUTDIR/sqli/sql_specific_error.txt"

[ -s "$OUTDIR/sqli/sql_specific_error.txt" ] && echo "[OK] SQL-specific error found" || echo "[FP] Generic validation error — not SQLi"
```

### Filter 2: HTML-Encoded SQL Errors

```bash
# SQL error message may be HTML-entity-encoded, making grep miss it
curl -s "${TARGET_URL}'" | grep -ci 'syntax\|sql\|mysql\|ORA-' && echo "[OK] Raw SQL error visible"
curl -s "${TARGET_URL}'" | grep -ci '&.*;' && echo "[FP-ENCODED] Error is HTML-encoded — check raw source"

# Decode entities for analysis
curl -s "${TARGET_URL}'" | python3 -c "import sys,html; print(html.unescape(sys.stdin.read()))" | rg -i 'sql|syntax|error' > "$OUTDIR/sqli/decoded_error.txt"
```

### Filter 3: WAF Blocking (False Negative / Masked)

```bash
# Some WAFs return 403 instead of letting SQL errors through
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "${TARGET_URL}'")
[ "$HTTP_CODE" = "403" ] && echo "[FP-CLOAKED] WAF blocking — true SQLi may exist but hidden" >> "$OUTDIR/sqli/fp_notes.txt"

# Check for WAF-specific block pages
curl -s "${TARGET_URL}'; SELECT 1--" | rg -iE 'cloudflare|akamai|imperva|f5|blocked|access denied|challenge|waf|firewall' && \
  echo "[FP-WAF] WAF actively blocking SQLi attempts — needs bypass testing" >> "$OUTDIR/sqli/fp_notes.txt"
```

### Filter 4: Parameterized Query / Prepared Statement Safety

```bash
# If injection produces consistent 200 but no data differential, it may be parameterized
# Test extreme injection that should break anything non-parameterized
curl -s -o /dev/null -w '%{http_code}' "${TARGET_URL}'; DROP TABLE nonexistent--" > "$OUTDIR/sqli/prepared_test.txt"

# If it returns 200 with no error, queries are likely parameterized (FP)
# If it returns 500, check if error is SQL-specific or generic
```

### Filter 5: ORM-Safe Contexts

```bash
# ORM frameworks often use parameterized queries by default
# But some methods allow SQL injection via `.raw()`, `.extra()`, `.where("name = '#{input}'")`

curl -s "${TARGET_URL}/users?order=username%20ASC--" | rg -c 'syntax.*error' && \
  echo "[SQLI-HINT] ORDER BY injection may be possible" >> "$OUTDIR/sqli/fp_notes.txt"

curl -s "${TARGET_URL}/users?order=username%20ASC" | rg -c 'no.*results\|empty\|not.*found' && \
  echo "[FP] ORDER BY parameter sanitized — returns validation not SQL error" >> "$OUTDIR/sqli/fp_notes.txt"
```

### Filter 6: Boolean Differential False Positives

```bash
# Some pages naturally return different content per request (ads, CSRF tokens, timestamps)
# Measure noise floor by comparing two identical requests
SIZE1=$(curl -s "$TARGET_URL" | wc -c)
SIZE2=$(curl -s "$TARGET_URL" | wc -c)
NOISE=$((SIZE1 - SIZE2))
[ "$NOISE" -lt 0 ] && NOISE=$((SIZE2 - SIZE1))
echo "Noise floor: $NOISE bytes"

# Only flag differentials > 2x noise floor
if [ "$NOISE" -gt 50 ]; then
  echo "[FP-RISK] High page variance — boolean blind results unreliable below ${NOISE} byte diff"
fi
```

### Filter 7: Timing False Positives

```bash
# Network latency can cause false time-based results
# Measure 5 baselines and compute average + stddev
BASELINES=()
for i in 1 2 3 4 5; do
  BASELINES+=($(curl -s -o /dev/null -w '%{time_total}' "$TARGET_URL"))
done

# Compute average
SUM=0
for t in "${BASELINES[@]}"; do SUM=$(echo "$SUM + $t" | bc); done
AVG=$(echo "scale=3; $SUM / 5" | bc)
echo "Average baseline: ${AVG}s"

# Only flag > baseline + 3s as significant
MAX_BASE=0
for t in "${BASELINES[@]}"; do
  (( $(echo "$t > $MAX_BASE" | bc -l) )) && MAX_BASE=$t
done
THRESHOLD=$(echo "$MAX_BASE + 3" | bc)
echo "Time-based threshold: ${THRESHOLD}s (max baseline: ${MAX_BASE}s + 3s buffer)"
```

### Filter 8: Consistent Error Messages (Not SQLi)

```bash
# If the same error appears regardless of injection, it's app-level not DB-level
ERROR_QUOTE=$(curl -s "${TARGET_URL}'" | grep -oP 'id="error"[^>]*>[^<]+' | head -1)
ERROR_VALID=$(curl -s "${TARGET_URL}?id=99999" | grep -oP 'id="error"[^>]*>[^<]+' | head -1)
ERROR_NULL=$(curl -s "${TARGET_URL}?id=" | grep -oP 'id="error"[^>]*>[^<]+' | head -1)

echo "Quote error:    $ERROR_QUOTE" | tee "$OUTDIR/sqli/error_comparison.txt"
echo "Valid error:    $ERROR_VALID" | tee -a "$OUTDIR/sqli/error_comparison.txt"
echo "Null error:     $ERROR_NULL" | tee -a "$OUTDIR/sqli/error_comparison.txt"

[ "$ERROR_QUOTE" = "$ERROR_VALID" ] && [ "$ERROR_VALID" = "$ERROR_NULL" ] && \
  echo "[FP] Same error for all inputs — application-level validation, not SQLi" | tee -a "$OUTDIR/sqli/fp_notes.txt"
```

### Filter Summary

```bash
echo "===== SQLi False Positive Summary =====" > "$OUTDIR/sqli/fp_summary.txt"
echo "Noise floor: ${NOISE}b" >> "$OUTDIR/sqli/fp_summary.txt"
echo "Time-based threshold: ${THRESHOLD}s" >> "$OUTDIR/sqli/fp_summary.txt"
echo "" >> "$OUTDIR/sqli/fp_summary.txt"
cat "$OUTDIR/sqli/fp_notes.txt" "$OUTDIR/sqli/error_comparison.txt" 2>/dev/null >> "$OUTDIR/sqli/fp_summary.txt"
```

## Detection Signals
- Generic validation errors → false positive (filter 1)
- HTML-encoded error messages → decode before triage (filter 2)
- WAF blocking responses → masked potential; test with WAF bypass (filter 3)
- High page variance (>50 bytes) → boolean blind unreliable (filter 6)
- Network latency >2x baseline → timing results suspect (filter 7)

## Next
├── Any filter marked `[FP]` → remove from confirmed findings
├── WAF blocking but SQLi suspected → route to WAF bypass skill/testing
├── Boolean unreliable but error messages confirm → use error-based extraction instead
├── Timing unreliable → use boolean or error-based if available
└── Always → save `fp_summary.txt` and only promote findings that pass all filters