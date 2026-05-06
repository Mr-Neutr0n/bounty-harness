# Mobile Security — Runbook 06: False Positive Filter

## Purpose
Filter out common false positives in mobile security testing. Not every string match is a real secret, not every Firebase URL is public.

## Variables
- `$APK_PATH` — path to APK/IPA
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory

---

## F6.1 — Filter placeholder/test API keys

```bash
python3 -c "
import re

with open('$OUTDIR/mobile/secrets-strings.txt') as f:
    lines = f.read()

# Known placeholder/fake keys
PLACEHOLDERS = [
    r'YOUR_API_KEY',
    r'YOUR_SECRET',
    r'your-api-key',
    r'your_secret',
    r'put-your-key-here',
    r'enter-your-key',
    r'sample[-_]?key',
    r'test[-_]?key',
    r'example[-_]?key',
    r'changeme',
    r'xxxxxxxx',
    r'0000000',
]

for pattern in PLACEHOLDERS:
    matches = re.findall(pattern, lines, re.IGNORECASE)
    if matches:
        print(f'PLACEHOLDER FOUND (ignore): {matches[0]}')

# Filter valid-looking keys
real_keys = re.findall(r'(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24}|SK[0-9a-fA-F]{32})', lines)
for key in set(real_keys):
    print(f'POTENTIALLY VALID KEY: {key[:15]}...')
" 2>/dev/null
```

## F6.2 — Firebase false positive check

```bash
# Check if Firebase .json returns actual data (not error/null)
FIREBASE_URL=$(head -1 "$OUTDIR/mobile/firebase-urls.txt" 2>/dev/null)

if [ -n "$FIREBASE_URL" ]; then
  response=$(curl -s "$FIREBASE_URL/.json" 2>/dev/null)

  if [ "$response" = "null" ]; then
    echo "FALSE POSITIVE: Firebase database exists but is empty or inaccessible"
  elif echo "$response" | grep -q "error"; then
    echo "FALSE POSITIVE: Firebase returned error, not accessible"
  elif echo "$response" | grep -q "Permission denied"; then
    echo "FALSE POSITIVE: Firebase has security rules enabled (401/403)"
  elif [ -n "$response" ] && [ "$response" != "null" ]; then
    size=$(echo "$response" | wc -c | tr -d ' ')
    echo "CONFIRMED: Firebase database returns data ($size bytes)"
  fi
fi
```

## F6.3 — SDK vs custom endpoint filtering

```bash
# Separate third-party SDK URLs from target-owned endpoints
python3 -c "
SDK_DOMAINS = [
    'firebaseio.com', 'firebase.com', 'googleapis.com', 'google.com',
    'facebook.com', 'graph.facebook.com', 'amazonaws.com',
    'mixpanel.com', 'segment.com', 'sentry.io', 'crashlytics.com',
    'appsflyer.com', 'adjust.com', 'braze.com', 'onesignal.com',
    'intercom.io', 'zendesk.com', 'newrelic.com', 'datadog.com',
    'amplitude.com', 'branch.io', 'clevertap.com',
]

with open('$OUTDIR/mobile/urls.txt') as f:
    urls = f.readlines()

sdk_urls = []
target_urls = []

for url in urls:
    url = url.strip()
    if not url:
        continue
    if any(d in url for d in SDK_DOMAINS):
        sdk_urls.append(url)
    else:
        target_urls.append(url)

print(f'SDK/Third-party URLs: {len(sdk_urls)}')
print(f'Potential target-owned URLs: {len(target_urls)}')
print()
print('--- Target-owned endpoints (higher priority) ---')
for u in target_urls[:10]:
    print(u)
" 2>/dev/null
```

## F6.4 — Confidence Scoring

```bash
cat > "$EVIDENCE_DIR/confidence-checklist.txt" << 'CHECKEOF'
Mobile Security Confidence Checklist
=====================================

Hardcoded Secrets:
[ ] Key is NOT a placeholder (YOUR_KEY, test, example, changeme)?
[ ] Key matches a known format (AKIA..., AIza..., sk_live_...)?
[ ] Key returns valid API response (not "restricted" or "invalid")?
[ ] Key provides access to billable/sensitive service?
[ ] Key is target-specific (not from a shared SDK)?
[ ] Key is found in app code, not just documentation strings?

Public Firebase:
[ ] .json endpoint returns structured data (not null/error)?
[ ] Data contains user information or PII?
[ ] Write access is also available (test with PUT)?
[ ] Database name clearly belongs to target?

Deeplink Hijacking:
[ ] Custom scheme is NOT a well-known SDK scheme?
[ ] Deeplink triggers authenticated action without validation?
[ ] Deeplink parameters are reflected in UI without sanitization?

Scoring:
- 5-6 YES for a category = HIGH confidence -- report
- 3-4 YES = MEDIUM -- further verification needed
- 0-2 YES = LOW -- likely false positive

Key Red Flags (immediate dismissal):
[ ] Placeholder keys (YOUR_API_KEY, xxxxxxxx, test, example)
[ ] Firebase returns null (empty database)
[ ] Firebase returns "Permission denied" (properly secured)
[ ] URLs only from well-known SDKs (no custom endpoints)
[ ] All API keys return "restricted" or "not authorized"
CHECKEOF

echo "Complete confidence checklist at $EVIDENCE_DIR/confidence-checklist.txt"
```

---

## Next Routing

| Score | Route |
|---|---|
| HIGH confidence | -> 05-evidence-collection.md |
| MEDIUM confidence | -> Re-verify with appropriate probe/verify workflows |
| LOW confidence | -> Discard |
| Only SDK endpoints, no secrets | -> Route URLs to api skill for further testing |
