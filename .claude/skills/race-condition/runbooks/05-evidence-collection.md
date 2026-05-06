# Race Condition — Runbook 05: Evidence Collection

## Purpose
Standardized evidence packaging for race condition findings.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$FINDING_ID` — unique finding identifier

---

## Directory Structure

```bash
mkdir -p "$EVIDENCE_DIR/$FINDING_ID"/{requests,responses,state-snapshots,scripts}
```

## E5.1 — Capture pre/post state snapshots

```bash
curl -s "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  > "$EVIDENCE_DIR/$FINDING_ID/state-snapshots/pre-state.txt"

curl -v "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/$FINDING_ID/state-snapshots/pre-state-detailed.txt" \
  2>"$EVIDENCE_DIR/$FINDING_ID/requests/pre-state-request.txt"

curl -v "$TARGET_URL/api/balance" ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -o "$EVIDENCE_DIR/$FINDING_ID/state-snapshots/post-state-detailed.txt" \
  2>"$EVIDENCE_DIR/$FINDING_ID/requests/post-state-request.txt"
```

## E5.2 — Capture concurrent attack script and output

```bash
cp "$OUTDIR/race/race-script.py" "$EVIDENCE_DIR/$FINDING_ID/scripts/race-attack.py" 2>/dev/null || echo "No script to copy"

cp "$OUTDIR/race/"*verify*.txt "$EVIDENCE_DIR/$FINDING_ID/scripts/" 2>/dev/null
cp "$OUTDIR/race/python-concurrent-probe.txt" "$EVIDENCE_DIR/$FINDING_ID/scripts/" 2>/dev/null
```

## E5.3 — State delta computation

```bash
python3 -c "
import os, json, re
ed = '$EVIDENCE_DIR/$FINDING_ID'
pre = open(f'{ed}/state-snapshots/pre-state.txt').read()
post = open(f'{ed}/state-snapshots/post-state.txt').read()
print('=== PRE vs POST STATE ANALYSIS ===')
print(f'PRE body: {pre[:300]}')
print(f'POST body: {post[:300]}')
pre_nums = re.findall(r'-?[\d]+\\.?[\\d]*', pre)
post_nums = re.findall(r'-?[\d]+\\.?[\\d]*', post)
print(f'\\nPRE numbers: {pre_nums}')
print(f'POST numbers: {post_nums}')
# Try to find delta
for pn, pn2 in zip(sorted(pre_nums, key=len, reverse=True)[:5], sorted(post_nums, key=len, reverse=True)[:5]):
    try:
        diff = float(pn2) - float(pn)
        print(f'Delta: {pn} -> {pn2} = {diff}')
    except:
        pass
" > "$EVIDENCE_DIR/$FINDING_ID/state-snapshots/delta-analysis.txt"
```

## E5.4 — Capture single request with full detail

```bash
curl -v -X POST "$TARGET_URL/api/redeem" \
  ${COOKIE_JAR:+-b "$COOKIE_JAR"} \
  -H "Content-Type: application/json" \
  -d '{"code":"TEST-RACE"}' \
  -o "$EVIDENCE_DIR/$FINDING_ID/responses/single-response.txt" \
  2>"$EVIDENCE_DIR/$FINDING_ID/requests/single-request.txt"
```

## E5.5 — Screenshot (of state before/after if UI accessible)

```bash
echo "$TARGET_URL/balance" | httpx -screenshot -silent \
  -o "$EVIDENCE_DIR/$FINDING_ID/screenshots/" 2>/dev/null
```

## E5.6 — Timestamp and tool versions

```bash
date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt"

cat > "$EVIDENCE_DIR/$FINDING_ID/tool-versions.txt" << EOF
curl: $(curl --version 2>&1 | head -1)
python3: $(python3 --version 2>&1)
httpx: $(httpx -version 2>&1)
katana: $(katana -version 2>&1)
date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
OS: $(sw_vers 2>/dev/null || uname -a)
EOF
```

## E5.7 — Evidence manifest

```bash
cat > "$EVIDENCE_DIR/$FINDING_ID/manifest.txt" << EOF
FINDING_ID: $FINDING_ID
TARGET: $TARGET_URL
SEVERITY: (fill -- high/medium/low)
VULN_CLASS: race-condition
SUB_TYPE: (fill -- coupon-redeem / balance-transfer / rate-limit / toctou / vote)
TIMESTAMP: $(cat "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt")

ARTIFACTS:
  requests/single-request.txt       -- curl -v of single request
  requests/pre-state-request.txt    -- curl -v of pre-state request
  requests/post-state-request.txt   -- curl -v of post-state request
  responses/single-response.txt     -- Single request response
  state-snapshots/pre-state.txt     -- State before concurrent attack
  state-snapshots/post-state.txt    -- State after concurrent attack
  state-snapshots/delta-analysis.txt -- Numerical delta analysis
  scripts/race-attack.py            -- Python concurrent attack script
  scripts/*-verify.txt              -- Verification output
  screenshots/                      -- Before/after screenshots
  timestamp.txt                     -- Finding timestamp
  tool-versions.txt                 -- Tool version manifest

REPRODUCTION:
1. Authenticate and navigate to the target endpoint
2. Send N concurrent requests as shown in scripts/race-attack.py
3. Observe state change exceeds expected single-operation change

IMPACT:
(fill -- describe financial/resource/security impact)
EOF

echo "Evidence written to $EVIDENCE_DIR/$FINDING_ID/"
```

## E5.8 — Package

```bash
tar -czf "$EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz" \
  -C "$EVIDENCE_DIR" "$FINDING_ID"
echo "Packaged: $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz"
```

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/$FINDING_ID/manifest.txt | Complete evidence manifest |
| $EVIDENCE_DIR/$FINDING_ID/requests/ | Request captures |
| $EVIDENCE_DIR/$FINDING_ID/responses/ | Response captures |
| $EVIDENCE_DIR/$FINDING_ID/state-snapshots/ | Pre/post state snapshots + delta |
| $EVIDENCE_DIR/$FINDING_ID/scripts/ | Attack scripts and verification output |
| $EVIDENCE_DIR/$FINDING_ID/timestamp.txt | UTC timestamp |
| $EVIDENCE_DIR/$FINDING_ID/tool-versions.txt | Tool version manifest |
| $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz | Packaged archive |
