# Race Condition — Runbook 02: Probe

## Purpose
Low-impact probing: establish sequential timing baselines and send small concurrent bursts to detect race windows. No aggressive exploitation.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — (optional) authenticated cookie jar

---

## W2.1 — Sequential timing baseline

```bash
TARGET_ENDPOINT="$TARGET_URL/api/redeem"

echo "=== Sequential Timing Baseline ==="
for i in $(seq 1 5); do
  start=$(python3 -c 'import time; print(int(time.time()*1000))')
  curl -s -o /dev/null -w "%{http_code}" "$TARGET_ENDPOINT" \
    ${COOKIE_JAR:+-b "$COOKIE_JAR"} 2>/dev/null
  end=$(python3 -c 'import time; print(int(time.time()*1000))')
  echo "  Request $i: $((end - start))ms"
  sleep 0.5
done
```

## W2.2 — Concurrent request probe (bash backgrounding, 5 requests)

```bash
TARGET_ENDPOINT="$TARGET_URL/api/redeem"

echo "=== Concurrent Probe ($(date -u +%T)) ===" > "$OUTDIR/race/concurrent-probe.txt"

for i in $(seq 1 5); do
  (
    echo "Request $i start: $(date -u +%T.%N)"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_ENDPOINT" \
      ${COOKIE_JAR:+-b "$COOKIE_JAR"} 2>/dev/null)
    echo "Request $i: HTTP $status at $(date -u +%T.%N)"
  ) &
done
wait

echo "=== All concurrent requests completed ==="
```

## W2.3 — Python concurrent sender (higher precision, 10 requests)

```bash
python3 -c "
import urllib.request
import concurrent.futures
import time

url = '$TARGET_URL/api/redeem'
results = []

def send_request(i):
    start = time.time()
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status
    except Exception as e:
        status = str(e)
    elapsed = time.time() - start
    return (i, status, elapsed)

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(send_request, i) for i in range(10)]
    for f in concurrent.futures.as_completed(futures):
        results.append(f.result())

results.sort()
for i, status, elapsed in results:
    print(f'Request {i}: HTTP {status} ({elapsed:.3f}s)')
" > "$OUTDIR/race/python-concurrent-probe.txt"

cat "$OUTDIR/race/python-concurrent-probe.txt"
```

## W2.4 — TOCTOU probe (file upload race)

```bash
# Upload a file and immediately read it back
echo "test content v1" > "$OUTDIR/race/toctou-test.txt"

curl -s -X POST "$TARGET_URL/api/upload" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -F "file=@$OUTDIR/race/toctou-test.txt" \
  -D "$OUTDIR/race/toctou-upload-headers.txt" \
  -o "$OUTDIR/race/toctou-upload-response.txt"

# Extract file ID/URL from response
FILE_URL=$(grep -oiE '(https?://[^"]*|/api/files/[^"]*)' "$OUTDIR/race/toctou-upload-response.txt" | head -1)

if [ -n "$FILE_URL" ]; then
  # Immediately read the file
  curl -s "$FILE_URL" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
    > "$OUTDIR/race/toctou-readback.txt"
  echo "=== Uploaded content ==="
  cat "$OUTDIR/race/toctou-readback.txt"
fi
```

---

## Detection Signals

| Signal | Confidence | Route |
|---|---|---|
| Concurrent requests all return 200 (success) | HIGH | -> 03-verify.md W3.1 |
| Some concurrent requests fail, others succeed | MEDIUM | -> 03-verify.md W3.2 (refine timing) |
| Sequential baseline shows 200-400ms processing | MEDIUM | -> 03-verify.md (race window sizing) |
| Rate limit bypassed with concurrent sends | HIGH | -> 03-verify.md W3.3 |
| TOCTOU: stale file read after immediate re-upload | HIGH | -> 03-verify.md W3.4 |
| All concurrent requests return 4xx/5xx equally | LOW | -> 06-false-positive-filter.md |

## False Positive Patterns

| Pattern | Meaning |
|---|---|
| All concurrent requests return identical 403/409 | Proper locking -- serialized access |
| Last-write-wins with single status change | May not be exploitable -- verify state change count |
| Concurrent 200 but only one state change persists | Application handles race -- not exploitable |
| Rate limit returns 429 even with concurrent sends | IP-based or global rate limit, not per-endpoint |

---

## Next Routing

| Result | Route |
|---|---|
| Multiple concurrent 200 (all "succeeded") | -> 03-verify.md W3.1 (verify state change count) |
| Mixed results (some 200, some 4xx) | -> 03-verify.md W3.2 (timing refinement) |
| Rate limit bypassed via concurrency | -> 03-verify.md W3.3 |
| All requests blocked / identical results | -> 06-false-positive-filter.md |
| No race window detected | -> Cease investigation |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/race/concurrent-probe.txt | Bash concurrent probe results |
| $OUTDIR/race/python-concurrent-probe.txt | Python ThreadPoolExecutor results |
| $OUTDIR/race/toctou-test.txt | Test file for TOCTOU probe |
| $OUTDIR/race/toctou-upload-headers.txt | Upload response headers |
| $OUTDIR/race/toctou-upload-response.txt | Upload response body |
| $OUTDIR/race/toctou-readback.txt | Immediate read-back after upload |
