# Mobile Security — Runbook 01: Discovery

## Purpose
Discover mobile application assets: decompile APK/IPA, extract endpoints, find hardcoded secrets, enumerate deeplinks, and identify exposed Firebase/API configurations.

## Variables
- `$APK_PATH` — path to APK or IPA file (absolute path)
- `$OUTDIR` — output directory
- `$TARGET_URL` — (optional) base URL if known, for cross-referencing

---

## W1.1 — Decompile APK with apktool

```bash
mkdir -p "$OUTDIR/mobile/decompiled"

apktool d "$APK_PATH" -o "$OUTDIR/mobile/decompiled/apktool" -f 2>&1 | tail -5
```

## W1.2 — Extract classes.dex to Java with jadx

```bash
ls "$OUTDIR/mobile/decompiled/apktool/"*.dex 2>/dev/null && \
  jadx -d "$OUTDIR/mobile/decompiled/jadx" "$APK_PATH" 2>&1 | tail -10

# If jadx output exists, verify
[ -d "$OUTDIR/mobile/decompiled/jadx" ] && echo "jadx decompile SUCCESS" || echo "jadx not available -- skip Java extraction"
```

## W1.3 — Extract all strings from APK

```bash
strings "$APK_PATH" > "$OUTDIR/mobile/strings-all.txt" 2>/dev/null

echo "=== Total strings extracted: $(wc -l < "$OUTDIR/mobile/strings-all.txt") ==="
```

## W1.4 — Extract endpoints and URLs from APK strings

```bash
grep -oiE 'https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^"'\''[:space:]]*' \
  "$OUTDIR/mobile/strings-all.txt" | sort -u > "$OUTDIR/mobile/urls.txt"

echo "=== URLs discovered ==="
cat "$OUTDIR/mobile/urls.txt"

# Filter for API endpoints
grep -iE '/api/|/v[0-9]/|/graphql|/rest|/ws|/socket' "$OUTDIR/mobile/urls.txt" > "$OUTDIR/mobile/api-endpoints.txt"
echo "=== API endpoints: $(wc -l < "$OUTDIR/mobile/api-endpoints.txt") ==="
```

## W1.5 — Extract hardcoded secrets from APK strings

```bash
grep -iE '(api[_-]?key|api[_-]?secret|aws_access|aws_secret|AKIA[0-9A-Z]{16}|private[_-]?key|-----BEGIN|client[_-]?secret|token|password|credential|authorization|bearer|jwt|firebase|google_api|maps_key|stripe[_-]?key|twilio[_-]?s?i?d?)' \
  "$OUTDIR/mobile/strings-all.txt" | sort -u > "$OUTDIR/mobile/secrets-strings.txt"

echo "=== Potential secrets found: $(wc -l < "$OUTDIR/mobile/secrets-strings.txt") ==="
head -30 "$OUTDIR/mobile/secrets-strings.txt"
```

## W1.6 — Extract firebase configuration

```bash
grep -oiE '([a-zA-Z0-9-]+\.firebaseio\.com|[a-zA-Z0-9-]+\.firebase\.app|[a-zA-Z0-9-]+\.firebaseapp\.com)' \
  "$OUTDIR/mobile/strings-all.txt" | sort -u > "$OUTDIR/mobile/firebase-urls.txt"

# Check for Firebase database (common misconfig: public .json)
while IFS= read -r fburl; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$fburl/.json" 2>/dev/null)
  echo "$fburl/.json -> HTTP $code"
done < "$OUTDIR/mobile/firebase-urls.txt" | tee "$OUTDIR/mobile/firebase-check.txt"
```

## W1.7 — Extract deeplink intent filters from AndroidManifest

```bash
grep -A 20 '<intent-filter>' "$OUTDIR/mobile/decompiled/apktool/AndroidManifest.xml" 2>/dev/null \
  | grep -oiE 'scheme="([^"]*)".*host="([^"]*)".*(path.*="([^"]*)")?' | sort -u \
  > "$OUTDIR/mobile/deeplinks.txt"

echo "=== Deeplinks discovered ==="
cat "$OUTDIR/mobile/deeplinks.txt"
```

## W1.8 — Check IPA if applicable (iOS)

```bash
# If IPA, unzip and check Info.plist
if [[ "$APK_PATH" == *.ipa ]]; then
  mkdir -p "$OUTDIR/mobile/decompiled/ipa"
  unzip -o "$APK_PATH" -d "$OUTDIR/mobile/decompiled/ipa" 2>/dev/null
  find "$OUTDIR/mobile/decompiled/ipa" -name "Info.plist" -exec plutil -p {} \; > "$OUTDIR/mobile/ios-plist.txt" 2>/dev/null
  echo "=== iOS Info.plist ==="
  head -50 "$OUTDIR/mobile/ios-plist.txt"
fi
```

---

## Signals

| Signal | Means |
|---|---|
| Firebase URL with public .json access (HTTP 200) | Public Firebase database |
| AKIA... in strings | AWS access key exposed |
| api_key in strings | Hardcoded API key -- test for validity |
| Deeplinks with custom schemes | Deeplink hijacking surface |
| GraphQL/REST endpoints | API attack surface |
| Google Maps / Stripe / Twilio keys | Third-party service key exposure |

---

## Next Routing

| Finding | Route |
|---|---|
| URLs/endpoints discovered | -> Route to appropriate skill (api, xss, sqli, etc.) |
| Secrets found (API keys, tokens) | -> 02-probe.md W2.1 (validate secrets) |
| Firebase URL with public access | -> 03-verify.md W3.3 |
| Deeplinks discovered | -> 02-probe.md W2.3 (deeplink testing) |
| Native libraries found | -> 02-probe.md W2.4 (binary analysis) |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/mobile/decompiled/apktool/ | Apktool decompile output |
| $OUTDIR/mobile/decompiled/jadx/ | Jadx Java decompile output |
| $OUTDIR/mobile/strings-all.txt | All strings from APK binary |
| $OUTDIR/mobile/urls.txt | URLs extracted from strings |
| $OUTDIR/mobile/api-endpoints.txt | API endpoint URLs |
| $OUTDIR/mobile/secrets-strings.txt | Potential secrets from strings |
| $OUTDIR/mobile/firebase-urls.txt | Firebase project URLs |
| $OUTDIR/mobile/firebase-check.txt | Firebase public access check |
| $OUTDIR/mobile/deeplinks.txt | Deeplink intent filters |
| $OUTDIR/mobile/ios-plist.txt | (IPA only) iOS plist contents |
