# Cloud Security — Runbook 06: False Positive Filter

## Purpose
Filter out common false positives in cloud storage testing. Not every accessible bucket is a vulnerability.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$BUCKET_NAME` — bucket being assessed

---

## F6.1 — Check if bucket is intentionally public

```bash
BUCKET="$BUCKET_NAME"

# Check for CloudFront CDN origin (intentionally public assets)
curl -s -D - -o /dev/null "https://$BUCKET.s3.amazonaws.com" 2>/dev/null | grep -iE '(x-amz-meta|x-cache|cloudfront)'

# If response shows static website hosting, it may be intentional
curl -s "https://$BUCKET.s3.amazonaws.com" 2>/dev/null | head -5
# Look for Index document, Error document config in XML
```

## F6.2 — Content sensitivity analysis

```bash
# Public web assets (HTML, CSS, JS, images) with NO sensitive data = NOT a finding
python3 -c "
import xml.etree.ElementTree as ET, re

tree = ET.parse('$EVIDENCE_DIR/s3-full-listing.xml')
root = tree.getroot()
ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}

sensitive_indicators = {
    '.env': False, 'config': False, 'secret': False, '.pem': False,
    '.key': False, '.sql': False, '.dump': False, 'backup': False,
    'credential': False, 'password': False, 'private': False,
    'database': False, '.yml': False, '.yaml': False, '.json': False,
    '.log': False, 'internal': False
}

total_files = 0
sensitive_files = 0

for content in root.findall('.//s3:Contents', ns):
    key = content.find('s3:Key', ns).text.lower()
    total_files += 1
    for indicator in sensitive_indicators:
        if indicator in key:
            sensitive_files += 1
            break

print(f'Total files: {total_files}')
print(f'Potentially sensitive files: {sensitive_files}')

if total_files > 0 and sensitive_files == 0:
    print('\\nLIKELY FALSE POSITIVE: All files appear to be public web assets')
elif sensitive_files < total_files * 0.05:
    print('\\nLOW IMPACT: Only {:.0f}% of files appear sensitive'.format(sensitive_files/total_files*100))
else:
    print('\\nPOTENTIALLY VALID: {}% of files may contain sensitive data'.format(sensitive_files/total_files*100))
" 2>/dev/null
```

## F6.3 — Verify bucket ownership

```bash
# Critical: A bucket name matching target name may not belong to target
# Check if bucket content references the target domain
BUCKET="$BUCKET_NAME"

curl -s "https://$BUCKET.s3.amazonaws.com" 2>/dev/null | grep -o "$TARGET_URL" | wc -l

# If 0 references to target URL, bucket might be unrelated
python3 -c "
import urllib.request, xml.etree.ElementTree as ET
try:
    resp = urllib.request.urlopen(f'https://$BUCKET.s3.amazonaws.com')
    body = resp.read()
    count = body.count(b'$TARGET_URL')
    if count == 0:
        print('WARNING: Bucket content does not reference target domain -- may be unrelated')
    else:
        print(f'Bucket verified: $TARGET_URL referenced {count} times')
except:
    print('Could not verify bucket ownership')
"
```

## F6.4 — Confidence scoring checklist

```bash
cat > "$EVIDENCE_DIR/confidence-checklist.txt" << 'CHECKEOF'
Cloud Storage Confidence Checklist
===================================
[ ] Bucket name clearly associated with target organization?
[ ] Bucket contains application source code, configs, or secrets?
[ ] Bucket is NOT intentionally public (CDN, static site hosting)?
[ ] Sensitive data is readable (not just listable)?
[ ] Impact is meaningful (PII, credentials, DB dumps, source, etc)?
[ ] Bucket content references or belongs to the target?

Scoring:
- 5-6 YES = HIGH confidence -- report
- 3-4 YES = MEDIUM -- further investigation needed
- 0-2 YES = LOW -- likely false positive

False Positive Patterns:
[ ] Bucket contains only public-facing web assets (images, CSS, JS, HTML)
[ ] Bucket is a CDN origin with no sensitive files
[ ] Bucket name matches target but content is unrelated
[ ] Bucket intentionally serves public static website
[ ] Listing is enabled but all files are public by design

Severity Adjustments:
- Writable bucket + can serve XSS/CSRF: Upgrade to CRITICAL
- Readable bucket + secrets/DB dumps: Upgrade to CRITICAL
- Readable bucket + source code (no secrets): HIGH
- Listable but no read access: LOW/MEDIUM
- Only public web assets: INFO
CHECKEOF

echo "Complete confidence checklist at $EVIDENCE_DIR/confidence-checklist.txt"
```

---

## Next Routing

| Score | Route |
|---|---|
| HIGH confidence (5-6) | -> 05-evidence-collection.md |
| MEDIUM confidence (3-4) | -> 03-verify.md (deeper file inspection) |
| LOW confidence (0-2) | -> Discard |
| Unrelated bucket | -> Discard (not within scope) |
