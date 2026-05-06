# Race Condition — Runbook 06: False Positive Filter

## Purpose
Filter out common false positives in race condition testing. Concurrent 200 responses do not always mean duplicate state changes.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory

---

## F6.1 — Verify state delta matches request count

```bash
# Critical check: did the state actually change more than once?
python3 -c "
import re

pre = open('$OUTDIR/race/evidence/pre-balance.txt').read()
post = open('$OUTDIR/race/evidence/post-balance.txt').read()

pre_nums = re.findall(r'[\d.]+', pre)
post_nums = re.findall(r'[\d.]+', post)

print(f'PRE numbers: {pre_nums}')
print(f'POST numbers: {post_nums}')

if pre_nums and post_nums:
    try:
        delta = abs(float(post_nums[0]) - float(pre_nums[0]))
        print(f'DELTA: {delta}')
        if delta < 0.5:
            print('FALSE POSITIVE: No meaningful state change')
        elif delta < 5:
            print('LOW IMPACT: Single-operation change (1x multiplier) -- not a race')
        else:
            print(f'CONFIRMED: State changed by {delta:.2f} units')
    except:
        print('Could not parse numeric delta')
"
```

## F6.2 — Check for request deduplication

```bash
# Many frameworks auto-deduplicate within a short window
# Check response for dedup indicators
python3 -c "
import urllib.request, concurrent.futures, json

url = '$TARGET_URL/api/redeem'
def send(i):
    req = urllib.request.Request(url, method='POST')
    req.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return (i, resp.status, resp.read().decode()[:300])
    except:
        return (i, 0, 'ERROR')

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    results = list(ex.map(send, range(5)))

dups = {}
for i, status, body in results:
    dup = body[:80]
    dups[dup] = dups.get(dup, 0) + 1
    print(f'Req {i}: {status} | {dup}')

most_common = max(dups.values()) if dups else 0
if most_common == 5:
    print('\\nFALSE POSITIVE: All responses identical -- likely idempotent endpoint')
elif most_common >= 3:
    print('\\nLIKELY FALSE POSITIVE: Most responses identical')
else:
    print(f'\\nResponses vary -- not immediately deduped (max identical: {most_common}/5)')
"
```

## F6.3 — Check for atomicity guarantees

```bash
# Send requests at increasing intervals to find the race window
echo "=== Race Window Detection ===" > "$OUTDIR/race/race-window.txt"

for delay in 0.05 0.1 0.2 0.5 1.0; do
  python3 -c "
import urllib.request, concurrent.futures, time

url = '$TARGET_URL/api/redeem'
time.sleep($delay)

def send(i):
    req = urllib.request.Request(url, method='POST')
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status
    except:
        return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
    results = list(ex.map(send, range(3)))
print(f'Delay=${delay}s -> {sum(1 for r in results if r == 200)}/3 success')
" 2>/dev/null
done | tee -a "$OUTDIR/race/race-window.txt"

# If success drops to 1/3 at 1s delay, race window is < 1s (still valid, just narrow)
```

## F6.4 — Confidence Scoring

```bash
cat > "$EVIDENCE_DIR/confidence-checklist.txt" << 'CHECKEOF'
Race Condition Confidence Checklist
====================================
[ ] Concurrent requests resulted in >1 success (200 OK)?
[ ] State delta exceeds single-operation effect?
[ ] No idempotency/deduplication in responses?
[ ] Responses are NOT all identical body text?
[ ] Race window is practical (<500ms)?
[ ] Impact is meaningful (not just cosmetic)?

Scoring:
- 5-6 YES = HIGH confidence — report
- 3-4 YES = MEDIUM — re-verify with more precise timing
- 0-2 YES = LOW — likely false positive, discard

False Positive Patterns (Check Each):
[ ] Application uses atomic database transactions (UPDATE with WHERE)
[ ] Application returns success but processes only one
[ ] Application uses idempotency keys (check headers)
[ ] Application serializes with database locks (slow sequential response)
[ ] Race window > 5 seconds (impractical)
[ ] Endpoint is read-only (GET) — no race on reads
CHECKEOF

echo "Complete confidence checklist at $EVIDENCE_DIR/confidence-checklist.txt"
```

---

## Next Routing

| Score | Route |
|---|---|
| HIGH (5-6) | -> 05-evidence-collection.md |
| MEDIUM (3-4) | -> 03-verify.md (refine timing / burst size) |
| LOW (0-2) | -> Discard |
| Race window < 50ms | -> Still valid if exploitable; test with lower burst |
| Idempotent endpoint | -> False positive — cease |
