# Mobile Security — Runbook 05: Evidence Collection

## Purpose
Standardized evidence packaging for mobile security findings.

## Variables
- `$APK_PATH` — path to APK/IPA
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$FINDING_ID` — unique finding identifier

---

## Directory Structure

```bash
mkdir -p "$EVIDENCE_DIR/$FINDING_ID"/{secrets,firebase,deeplinks,network,source}
```

## E5.1 — Capture discovered secrets (redacted)

```bash
# Copy secrets with sensitive portions redacted for safe inclusion
cp "$OUTDIR/mobile/secrets-strings.txt" "$EVIDENCE_DIR/$FINDING_ID/secrets/secrets-full.txt"

# Create redacted version
python3 -c "
import re

with open('$EVIDENCE_DIR/$FINDING_ID/secrets/secrets-full.txt') as f:
    lines = f.readlines()

redacted = []
for line in lines:
    line = re.sub(r'AKIA[0-9A-Z]{16}', lambda m: m.group()[:6] + '...' + m.group()[-4:], line)
    line = re.sub(r'AIza[0-9A-Za-z_-]{35}', lambda m: m.group()[:8] + '...' + m.group()[-8:], line)
    line = re.sub(r'sk_live_[0-9a-zA-Z]{24}', lambda m: m.group()[:10] + '...' + m.group()[-6:], line)
    redacted.append(line)

with open('$EVIDENCE_DIR/$FINDING_ID/secrets/secrets-redacted.txt', 'w') as f:
    f.writelines(redacted)

print(f'Redacted {len(redacted)} lines')
" 2>/dev/null
```

## E5.2 — Capture Firebase evidence

```bash
cp "$EVIDENCE_DIR/../firebase-full-dump.json" "$EVIDENCE_DIR/$FINDING_ID/firebase/full-dump.json" 2>/dev/null
cp "$EVIDENCE_DIR/../firebase-sensitive-fields.txt" "$EVIDENCE_DIR/$FINDING_ID/firebase/sensitive-fields.txt" 2>/dev/null

# Take first 2KB for sample
head -c 2048 "$EVIDENCE_DIR/$FINDING_ID/firebase/full-dump.json" 2>/dev/null \
  > "$EVIDENCE_DIR/$FINDING_ID/firebase/sample.json"
```

## E5.3 — Capture deeplink evidence

```bash
cp "$OUTDIR/mobile/deeplink-schemes.txt" "$EVIDENCE_DIR/$FINDING_ID/deeplinks/schemes.txt" 2>/dev/null
cp "$OUTDIR/mobile/deep links.txt" "$EVIDENCE_DIR/$FINDING_ID/deeplinks/raw-discovery.txt" 2>/dev/null
cp "$EVIDENCE_DIR/../deeplink-test-results.txt" "$EVIDENCE_DIR/$FINDING_ID/deeplinks/adb-test-results.txt" 2>/dev/null
```

## E5.4 — Capture network security config

```bash
cp "$OUTDIR/mobile/network-security-config.txt" "$EVIDENCE_DIR/$FINDING_ID/network/security-config.txt" 2>/dev/null
cp "$OUTDIR/mobile/cert-pinning-indicators.txt" "$EVIDENCE_DIR/$FINDING_ID/network/cert-pinning.txt" 2>/dev/null
```

## E5.5 — Capture API key validation evidence

```bash
cp "$OUTDIR/mobile/key-test-"*.json "$EVIDENCE_DIR/$FINDING_ID/source/" 2>/dev/null
cp "$EVIDENCE_DIR/../verified-keys.txt" "$EVIDENCE_DIR/$FINDING_ID/secrets/verified-keys.txt" 2>/dev/null
```

## E5.6 — Timestamp and tool versions

```bash
date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt"

cat > "$EVIDENCE_DIR/$FINDING_ID/tool-versions.txt" << EOF
apktool: $(apktool -version 2>&1 || echo "not installed")
jadx: $(jadx --version 2>&1 || echo "not installed")
strings: $(strings --version 2>&1 | head -1 || echo "built-in")
adb: $(adb version 2>&1 | head -1 || echo "not installed")
curl: $(curl --version 2>&1 | head -1)
python3: $(python3 --version 2>&1)
date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
OS: $(sw_vers 2>/dev/null || uname -a)
APK: $(md5 -q "$APK_PATH" 2>/dev/null || md5sum "$APK_PATH" 2>/dev/null)
EOF
```

## E5.7 — Evidence manifest

```bash
cat > "$EVIDENCE_DIR/$FINDING_ID/manifest.txt" << EOF
FINDING_ID: $FINDING_ID
TARGET: (fill)
APK_SHA256: $(shasum -a 256 "$APK_PATH" 2>/dev/null | awk '{print $1}')
SEVERITY: (fill -- critical/high/medium/low/info)
VULN_CLASS: (fill -- hardcoded-secrets / public-firebase / deeplink-hijack / cert-pinning-bypass)
TIMESTAMP: $(cat "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt")

ARTIFACTS:
  secrets/secrets-full.txt           -- Full extracted secrets
  secrets/secrets-redacted.txt       -- Redacted for report inclusion
  secrets/verified-keys.txt          -- Key validation results
  firebase/full-dump.json            -- Complete Firebase database
  firebase/sample.json               -- First 2KB sample
  firebase/sensitive-fields.txt      -- PII field frequency
  deeplinks/schemes.txt              -- Deeplink URI schemes
  deeplinks/adb-test-results.txt     -- ADB deeplink test results
  network/security-config.txt        -- Network security config
  network/cert-pinning.txt           -- Certificate pinning indicators
  timestamp.txt                      -- Finding timestamp
  tool-versions.txt                  -- Tool version manifest

IMPACT:
(fill -- describe what an attacker could do with these findings)

REPRODUCTION:
1. Decompile APK: apktool d app.apk
2. Extract strings: strings app.apk | grep -i secret
3. (fill -- specific steps for this finding)
EOF

echo "Evidence written to $EVIDENCE_DIR/$FINDING_ID/"
```

## E5.8 — Package

```bash
tar -czf "$EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz" \
  -C "$EVIDENCE_DIR" "$FINDING_ID" \
  --exclude="*.apk" --exclude="*.ipa" --exclude="firebase-full-dump.json"
echo "Packaged: $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz"
```

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/$FINDING_ID/manifest.txt | Complete evidence manifest |
| $EVIDENCE_DIR/$FINDING_ID/secrets/ | Secret extraction and validation |
| $EVIDENCE_DIR/$FINDING_ID/firebase/ | Firebase database evidence |
| $EVIDENCE_DIR/$FINDING_ID/deeplinks/ | Deeplink evidence |
| $EVIDENCE_DIR/$FINDING_ID/network/ | Network security evidence |
| $EVIDENCE_DIR/$FINDING_ID/timestamp.txt | UTC timestamp |
| $EVIDENCE_DIR/$FINDING_ID/tool-versions.txt | Tool version manifest |
| $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz | Packaged archive |
