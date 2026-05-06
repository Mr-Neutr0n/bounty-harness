# Mobile Security — Runbook 04: Impact Escalation

## Purpose
Escalate from detection to demonstrable impact. Show what attackers can do with exposed keys, public Firebase data, deeplink hijacking, or traffic interception.

## Variables
- `$APK_PATH` — path to APK/IPA
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory

---

## W4.1 — Demonstrate API key abuse impact

```bash
# Show what each exposed API key enables
echo "=== API Key Impact Analysis ===" > "$EVIDENCE_DIR/impact-api-keys.txt"

# Google Maps: check quota
GOOGLE_MAPS_KEY=$(grep -oiE 'AIza[0-9A-Za-z_-]{35}' "$OUTDIR/mobile/secrets-strings.txt" | head -1)
if [ -n "$GOOGLE_MAPS_KEY" ]; then
  echo "Google Maps Key: ${GOOGLE_MAPS_KEY:0:12}..."
  echo "Impact: Attacker can consume Maps API quota -> financial impact on target"
  echo "Abuse: Free directions, geocoding, places API access at target's expense"
  echo ""
fi >> "$EVIDENCE_DIR/impact-api-keys.txt"

# Check for Stripe keys
STRIPE_KEY=$(grep -oiE '(pk_live_[0-9a-zA-Z]{24}|sk_live_[0-9a-zA-Z]{24})' "$OUTDIR/mobile/secrets-strings.txt" | head -1)
if [ -n "$STRIPE_KEY" ]; then
  echo "STRIPE KEY FOUND: ${STRIPE_KEY:0:15}..."
  if [[ "$STRIPE_KEY" == sk_* ]]; then
    echo "IMPACT: Secret key! Full Stripe API access."
    echo "Attack: Refund payments, create charges, view all transactions"
  else
    echo "IMPACT: Publishable key -- limited to tokenization, but still exposed"
  fi
  echo ""
fi >> "$EVIDENCE_DIR/impact-api-keys.txt"

# Check for Twilio keys
TWILIO_KEY=$(grep -oiE '(SK[0-9a-fA-F]{32})' "$OUTDIR/mobile/secrets-strings.txt" | head -1)
if [ -n "$TWILIO_KEY" ]; then
  echo "TWILIO KEY FOUND: ${TWILIO_KEY:0:10}..."
  echo "IMPACT: SMS/voice spoofing, phone number lookup, messaging abuse"
  echo ""
fi >> "$EVIDENCE_DIR/impact-api-keys.txt"

cat "$EVIDENCE_DIR/impact-api-keys.txt"
```

## W4.2 — Demonstrate Firebase data impact

```bash
FIREBASE_URL=$(head -1 "$OUTDIR/mobile/firebase-urls.txt" 2>/dev/null)

if [ -n "$FIREBASE_URL" ] && [ -f "$EVIDENCE_DIR/firebase-full-dump.json" ]; then
  python3 -c "
import json

with open('$EVIDENCE_DIR/firebase-full-dump.json') as f:
    data = json.load(f)

if not isinstance(data, dict):
    print('No structured data in Firebase')
    exit()

# Find user records
user_indicators = ['users', 'user', 'profiles', 'customers', 'accounts']
for key in data:
    if any(ui in key.lower() for ui in user_indicators):
        records = data[key]
        if isinstance(records, dict):
            count = len(records)
            print(f'COLLECTION: {key} ({count} records)')
            # Show first record sample, redacted
            first_key = list(records.keys())[0]
            first_record = records[first_key]
            print(f'  Sample record fields: {list(first_record.keys())}')
            # Check for PII
            pii_fields = ['email', 'name', 'phone', 'address', 'password', 'ssn', 'dob', 'token']
            found_pii = [f for f in pii_fields if f in str(first_record).lower()]
            if found_pii:
                print(f'  PII EXPOSED: {found_pii}')
            print()

print(f'Total size of exposed data: {len(json.dumps(data)):,} bytes')
" | tee "$EVIDENCE_DIR/impact-firebase-analysis.txt"
fi
```

## W4.3 — Demonstrate deeplink hijacking chain

```bash
cat > "$EVIDENCE_DIR/impact-deeplink-analysis.txt" << 'DEEPLINKEOF'
Deeplink Hijacking Impact Analysis
===================================

If deeplinks can be triggered via adb, an attacker can:
1. Create a malicious webpage that triggers deeplinks
2. Phishing: redirect user to attacker-controlled content
3. Data exfiltration: deeplink with parameters leaked to attacker
4. CSRF-like attacks: trigger authenticated actions via deeplink
5. JavaScript bridge injection: if WebView + deeplink, inject JS

Deeplink schemes found: (see $OUTDIR/mobile/deeplink-schemes.txt)
DEEPLINKEOF

cat "$OUTDIR/mobile/deeplink-schemes.txt" >> "$EVIDENCE_DIR/impact-deeplink-analysis.txt" 2>/dev/null
```

## W4.4 — Demonstrate traffic interception impact (if cert pinning bypassable)

```bash
cat > "$EVIDENCE_DIR/impact-traffic-interception.txt" << 'TRAFFICEOF'
Traffic Interception Impact Analysis
=====================================

If certificate pinning is bypassable (user CA trusted):
1. Install mitmproxy CA on device
2. Set device proxy to mitmproxy (default 8080)
3. All HTTPS traffic is now visible in plaintext
4. Attackers can:
   - Steal session tokens / auth headers
   - View sensitive API responses (user data, PII)
   - Modify requests in transit (parameter tampering)
   - Capture credentials sent in requests

Steps to bypass cert pinning:
  - objection: objection -g <app> explore -s "android sslpinning disable"
  - Frida: frida -U -l frida-scripts/ssl-pinning-bypass.js -f <package>
TRAFFICEOF

echo "Traffic interception impact written"
```

## W4.5 — Impact summary

```bash
cat > "$EVIDENCE_DIR/impact-summary.txt" << 'IMPACTOF'
Mobile Security Impact Summary
===============================

HARDCODED API KEYS:
  - Financial impact (API quota abuse)
  - Service abuse (Stripe, Twilio, AWS)
  - Severity: MEDIUM-HIGH

PUBLIC FIREBASE DATABASE:
  - User data exposure (PII, credentials)
  - Data modification if writeable
  - Severity: HIGH-CRITICAL

DEEPLINK HIJACKING:
  - Phishing / content spoofing
  - Unauthorized action triggering
  - Severity: MEDIUM-HIGH

CERTIFICATE PINNING BYPASS:
  - Full traffic interception
  - Session hijacking
  - Severity: HIGH

SOURCE CODE EXPOSURE:
  - Business logic discovery
  - Hidden API endpoint discovery
  - Cryptographic key extraction
  - Severity: MEDIUM
IMPACTOF

cat "$EVIDENCE_DIR/impact-api-keys.txt" >> "$EVIDENCE_DIR/impact-summary.txt" 2>/dev/null
cat "$EVIDENCE_DIR/impact-firebase-analysis.txt" >> "$EVIDENCE_DIR/impact-summary.txt" 2>/dev/null

echo "Impact summary written to $EVIDENCE_DIR/impact-summary.txt"
```

---

## Evidence for Report

| Artifact | What to Capture |
|---|---|
| API key validation | curl response showing valid key usage |
| Firebase data sample | First 5 records showing PII fields |
| Deeplink schemes | List of all custom URI schemes |
| Network security config | XML showing cleartext/user CA settings |
| Redacted AWS/Stripe key | Partial key with X...X format |

---

## Next Routing

| Result | Route |
|---|---|
| Impact demonstrated (any category) | -> 05-evidence-collection.md |
| Firebase/API keys with user data | -> 05-evidence-collection.md (HIGH+) |
| Only informational findings | -> 05-evidence-collection.md (INFO severity) |
