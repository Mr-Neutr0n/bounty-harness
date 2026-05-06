# Mobile Security — Runbook 02: Probe

## Purpose
Low-impact probing: validate discovered secrets, test deeplinks, check Firebase databases, verify API endpoint accessibility.

## Variables
- `$APK_PATH` — path to APK/IPA
- `$OUTDIR` — output directory
- `$TARGET_URL` — base URL if known

---

## W2.1 — Validate discovered API keys (safe — read-only tests)

```bash
# Test Google Maps API key
GOOGLE_MAPS_KEY=$(grep -oiE 'AIza[0-9A-Za-z_-]{35}' "$OUTDIR/mobile/secrets-strings.txt" | head -1)
if [ -n "$GOOGLE_MAPS_KEY" ]; then
  echo "Testing Google Maps key: $GOOGLE_MAPS_KEY"
  curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=$GOOGLE_MAPS_KEY" \
    -o "$OUTDIR/mobile/key-test-google-maps.json" 2>/dev/null
  python3 -c "
import json
d = json.load(open('$OUTDIR/mobile/key-test-google-maps.json'))
print(f'Status: {d.get(\"status\",\"ERROR\")}')" 2>/dev/null
fi

# Test Firebase URL access
FIREBASE_URL=$(head -1 "$OUTDIR/mobile/firebase-urls.txt" 2>/dev/null)
if [ -n "$FIREBASE_URL" ]; then
  echo "Testing Firebase: $FIREBASE_URL"
  curl -s "$FIREBASE_URL/.json" -o "$OUTDIR/mobile/firebase-data.json" 2>/dev/null
  python3 -c "
import json
d = json.load(open('$OUTDIR/mobile/firebase-data.json'))
print(f'Keys at root level: {list(d.keys())[:10] if isinstance(d, dict) else \"not an object\"}')" 2>/dev/null
fi
```

## W2.2 — Test API endpoints from mobile app

```bash
# Take discovered API endpoints and probe them
while IFS= read -r endpoint; do
  echo "=== $endpoint ==="
  curl -s -o /dev/null -w "GET: %{http_code}" "$endpoint"
  echo ""
  curl -s -X POST -o /dev/null -w "POST: %{http_code}" "$endpoint" \
    -H "Content-Type: application/json" -d '{}'
  echo ""
  echo ""
done < "$OUTDIR/mobile/api-endpoints.txt" > "$OUTDIR/mobile/api-probe-results.txt"

head -30 "$OUTDIR/mobile/api-probe-results.txt"
```

## W2.3 — Probe deeplinks with adb

```bash
# Extract deeplink URIs from discovered schemes
grep -oiE '[a-zA-Z][a-zA-Z0-9+.-]*://' "$OUTDIR/mobile/deeplinks.txt" 2>/dev/null | sort -u > "$OUTDIR/mobile/deeplink-schemes.txt"

echo "=== Deeplink schemes ==="
cat "$OUTDIR/mobile/deeplink-schemes.txt"

# Test with adb if device connected
if adb devices 2>/dev/null | grep -q 'device$'; then
  PACKAGE_NAME=$(grep -oiE 'package="([^"]*)"' "$OUTDIR/mobile/decompiled/apktool/AndroidManifest.xml" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | head -1)

  while IFS= read -r scheme; do
    clean_scheme=$(echo "$scheme" | tr -d '://')
    echo "Testing deeplink: ${clean_scheme}://test"
    adb shell am start -W -a android.intent.action.VIEW \
      -d "${clean_scheme}://test" "$PACKAGE_NAME" 2>/dev/null
  done < "$OUTDIR/mobile/deeplink-schemes.txt"
else
  echo "No Android device connected via adb. Deeplink testing requires a device."
  echo "Extracted deeplink schemes available in $OUTDIR/mobile/deeplink-schemes.txt"
fi
```

## W2.4 — Binary / native library analysis

```bash
# Find compiled .so libraries
find "$OUTDIR/mobile/decompiled/apktool/lib/" -name "*.so" 2>/dev/null > "$OUTDIR/mobile/native-libs.txt"

if [ -s "$OUTDIR/mobile/native-libs.txt" ]; then
  echo "=== Native libraries found ==="
  cat "$OUTDIR/mobile/native-libs.txt"

  # Extract strings from native libs for additional secrets
  for lib in $(head -5 "$OUTDIR/mobile/native-libs.txt"); do
    echo "--- $(basename $lib) ---"
    strings "$lib" | grep -iE '(key|secret|token|password|encrypt|decrypt|api|url)' | head -5
  done > "$OUTDIR/mobile/native-lib-strings.txt"

  head -30 "$OUTDIR/mobile/native-lib-strings.txt"
fi
```

## W2.5 — Certificate pinning check

```bash
# Search for SSL pinning indicators
grep -rni 'pinning\|trustmanager\|certificate\|sslcontext\|okhttp' \
  "$OUTDIR/mobile/decompiled/jadx/" 2>/dev/null | head -20 > "$OUTDIR/mobile/cert-pinning-indicators.txt"

echo "=== Certificate pinning indicators ==="
cat "$OUTDIR/mobile/cert-pinning-indicators.txt"

# Check network security config
grep -A 30 '<network-security-config' \
  "$OUTDIR/mobile/decompiled/apktool/AndroidManifest.xml" 2>/dev/null || \
  find "$OUTDIR/mobile/decompiled/apktool" -name "network_security_config.xml" -exec cat {} \; 2>/dev/null \
  > "$OUTDIR/mobile/network-security-config.txt"

echo "=== Network security config ==="
cat "$OUTDIR/mobile/network-security-config.txt"
```

---

## Detection Signals

| Signal | Confidence | Route |
|---|---|---|
| Google Maps/API key returns valid data | HIGH | -> 03-verify.md |
| Firebase .json returns data (not error/null) | HIGH | -> 03-verify.md W3.3 |
| API endpoints respond 200 | MEDIUM | -> Route to api skill for deep testing |
| Deeplinks found + device available | MEDIUM | -> 03-verify.md W3.4 |
| No certificate pinning + cleartext allowed | MEDIUM | -> 03-verify.md (traffic interception) |
| Hardcoded AWS keys matching AKIA... pattern | HIGH | -> 03-verify.md W3.2 |

## False Positive Patterns

| Pattern | Meaning |
|---|---|
| API key returns "forbidden" or "restricted" | Key is restricted -- still valid finding but limited impact |
| Firebase .json returns "Permission denied" | Firebase has security rules -- not public |
| Strings contain "example" or "test" keys | Placeholder values -- not real secrets |
| URLs extracted are from SDKs (facebook, google, etc.) | Third-party SDK endpoints -- not target-owned |

---

## Next Routing

| Result | Route |
|---|---|
| Valid API keys/secrets found | -> 03-verify.md |
| Public Firebase database | -> 03-verify.md W3.3 |
| Deeplinks ready for testing | -> 03-verify.md W3.4 |
| No valid secrets, all keys restricted | -> Route API endpoints to api skill |
| Nothing exploitable found | -> Cease investigation |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/mobile/key-test-*.json | API key validation responses |
| $OUTDIR/mobile/firebase-data.json | Firebase database content |
| $OUTDIR/mobile/api-probe-results.txt | API endpoint probe results |
| $OUTDIR/mobile/deeplink-schemes.txt | Extracted deeplink URI schemes |
| $OUTDIR/mobile/native-libs.txt | Paths to .so native libraries |
| $OUTDIR/mobile/native-lib-strings.txt | Strings from native libraries |
| $OUTDIR/mobile/cert-pinning-indicators.txt | SSL pinning code indicators |
| $OUTDIR/mobile/network-security-config.txt | Android network security config |
