# Race Condition — Runbook 01: Discovery

## Purpose
Discover endpoints vulnerable to race conditions: coupon redemption, balance transfer, voting, limited-use features, rate-limited endpoints, token refresh, file upload processing.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$CONTEXT` — (optional) prior recon output (httpx json, katana crawl)

---

## W1.1 — Crawl for time-sensitive endpoints

```bash
katana -u "$TARGET_URL" -d 5 -jc -kf -sf -o "$OUTDIR/race/endpoints.txt"
```

## W1.2 — Filter for state-changing endpoints (POST/PUT/PATCH/DELETE)

```bash
cat "$OUTDIR/race/endpoints.txt" | grep -iE '(POST|PUT|DELETE|PATCH)' > "$OUTDIR/race/stateful-endpoints.txt"
```

## W1.3 — Identify race-condition-prone patterns

```bash
curl -s "$TARGET_URL" | grep -oiE '(coupon|voucher|redeem|transfer|withdraw|vote|claim|apply|checkout|purchase|buy|order|balance|charge|discount|promo|gift|refund|invite|register|signup|subscribe|limit|unlock|activate)' | sort -u > "$OUTDIR/race/keywords.txt"

echo "=== Keywords suggesting race condition surface ==="
cat "$OUTDIR/race/keywords.txt"
```

## W1.4 — Extract API endpoint patterns from JS

```bash
cat "$OUTDIR/race/endpoints.txt" | grep -E '\.js(\?|$)' > "$OUTDIR/race/js-files.txt"

while IFS= read -r jsurl; do
  curl -s "$jsurl" 2>/dev/null | grep -oiE '"(/api/[^"]*(transfer|redeem|coupon|claim|vote|withdraw|balance|checkout)[^"]*)"' | tr -d '"'
done < "$OUTDIR/race/js-files.txt" | sort -u > "$OUTDIR/race/api-race-targets.txt"

echo "=== API endpoints suggesting race condition targets ==="
cat "$OUTDIR/race/api-race-targets.txt"
```

## W1.5 — Check for idempotency keys / deduplication tokens

```bash
# Look for idempotency headers in JS (indicates proper race protection)
while IFS= read -r jsurl; do
  curl -s "$jsurl" 2>/dev/null | grep -oiE '(idempotency[_-]?key|X-Idempotency|x-idempotency|dedup|duplicate|nonce)'
done < "$OUTDIR/race/js-files.txt" | sort -u > "$OUTDIR/race/idempotency-indicators.txt"

echo "=== Idempotency protection indicators found ==="
cat "$OUTDIR/race/idempotency-indicators.txt"
# If empty, race conditions are more likely
```

## W1.6 — Identify rate-limitable endpoints

```bash
cat "$OUTDIR/race/stateful-endpoints.txt" | httpx -silent -mc 429 -title -status-code > "$OUTDIR/race/rate-limited-endpoints.txt"

# Also check with rapid sequential requests
while IFS= read -r endpoint; do
  for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code} " "$endpoint" 2>/dev/null
  done
  echo " <- $endpoint"
done < "$OUTDIR/race/stateful-endpoints.txt" | head -20 > "$OUTDIR/race/rate-limit-test.txt"

echo "=== Rate limit test (10 rapid requests) ==="
cat "$OUTDIR/race/rate-limit-test.txt"
```

---

## Signals — what indicates race condition surface

| Signal | Means |
|---|---|
| coupon/redeem/transfer/withdraw/vote/claim in endpoint path | Time-sensitive operation -- high priority |
| Sequential requests return varied HTTP codes | Rate limiting exists -- bypass likely needed |
| No idempotency key in JS source | No deduplication protection -- exploitable |
| POST returns 200 without unique request ID | No tracking of individual requests |
| Order API with add/remove item | Cart manipulation race |
| File upload with processing callback | TOCTOU on file processing |

---

## Next Routing

| Finding | Route |
|---|---|
| Coupon/voucher/redeem endpoints found | -> 02-probe.md W2.1 (sequential timing baseline) |
| Balance/transfer/withdraw endpoints | -> 02-probe.md W2.2 (concurrent transfer test) |
| Rate-limited endpoints (429 detected) | -> 02-probe.md W2.3 (rate limit bypass probe) |
| File upload + processing | -> 02-probe.md W2.4 (TOCTOU probe) |
| Voting/claim/limit endpoints | -> 02-probe.md W2.1 (concurrent action test) |
| No targets found | -> Cease investigation |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/race/endpoints.txt | All crawled endpoints |
| $OUTDIR/race/stateful-endpoints.txt | POST/PUT/DELETE/PATCH endpoints |
| $OUTDIR/race/keywords.txt | Race-condition-prone keywords in page content |
| $OUTDIR/race/api-race-targets.txt | API endpoints suggesting race targets |
| $OUTDIR/race/idempotency-indicators.txt | Idempotency key patterns found |
| $OUTDIR/race/rate-limited-endpoints.txt | Endpoints returning 429 |
| $OUTDIR/race/rate-limit-test.txt | Rapid sequential request status codes |
