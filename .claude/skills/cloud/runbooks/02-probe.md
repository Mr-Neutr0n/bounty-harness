# Cloud Security — Runbook 02: Probe

## Purpose
Low-impact probing: test discovered S3/Azure/GCP buckets for public accessibility, listable permissions, and writable status.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$BUCKET_NAME` — specific bucket name from discovery (e.g., example-assets)

---

## W2.1 — Probe S3 bucket accessibility

### Test 1: Direct HTTP access

```bash
BUCKET="$BUCKET_NAME"

echo "=== Testing bucket: $BUCKET ==="

# Try direct access
curl -s -o /dev/null -w "%{http_code}" "https://$BUCKET.s3.amazonaws.com" 2>/dev/null
echo " <- HTTP direct"

# Try with region variant
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$BUCKET.s3.$region.amazonaws.com" 2>/dev/null)
  echo "  $region: $code"
done
```

### Test 2: Check if listing is enabled

```bash
curl -s "https://$BUCKET.s3.amazonaws.com" 2>/dev/null | head -50 > "$OUTDIR/cloud/s3-listing-$BUCKET.txt"

if grep -q '<Contents>' "$OUTDIR/cloud/s3-listing-$BUCKET.txt" 2>/dev/null; then
  echo "BUCKET LISTING ENABLED: $BUCKET"
  grep -oiE '<Key>[^<]+</Key>' "$OUTDIR/cloud/s3-listing-$BUCKET.txt" | sed 's/<[^>]*>//g' > "$OUTDIR/cloud/s3-files-$BUCKET.txt"
  echo "=== Files found ==="
  head -20 "$OUTDIR/cloud/s3-files-$BUCKET.txt"
else
  echo "Bucket not listable or empty"
fi
```

### Test 3: Check write permissions (SAFE — no actual write)

```bash
# OPTIONS preflight or PUT with empty body
curl -s -X PUT "https://$BUCKET.s3.amazonaws.com/test-write-check" \
  -H "Content-Length: 0" \
  -D - -o /dev/null 2>/dev/null | head -5

# If 200 or 403 (AccessDenied), bucket exists. If 301 redirect, region mismatch.
```

## W2.2 — Probe Azure blob storage

```bash
AZURE_STORAGE="$BUCKET_NAME"  # e.g., mystorageaccount

# Test public container access
curl -s -o /dev/null -w "Container listing: %{http_code}\n" \
  "https://$AZURE_STORAGE.blob.core.windows.net/\$root?restype=container&comp=list" 2>/dev/null

# Test common container names
for container in static assets files media uploads data public cdn images; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://$AZURE_STORAGE.blob.core.windows.net/$container?restype=container&comp=list" 2>/dev/null)
  echo "$container: HTTP $code"
done
```

## W2.3 — Probe GCP storage bucket

```bash
GCP_BUCKET="$BUCKET_NAME"  # e.g., my-app-bucket

curl -s -o /dev/null -w "GCP bucket: %{http_code}\n" \
  "https://storage.googleapis.com/$GCP_BUCKET" 2>/dev/null

# Check if listing is enabled
curl -s "https://storage.googleapis.com/storage/v1/b/$GCP_BUCKET/o" 2>/dev/null | head -50 > "$OUTDIR/cloud/gcp-listing-$GCP_BUCKET.txt"

if grep -q '"name"' "$OUTDIR/cloud/gcp-listing-$GCP_BUCKET.txt" 2>/dev/null; then
  echo "GCP BUCKET LISTING ENABLED: $GCP_BUCKET"
  python3 -c "import json,sys; data=json.load(open('$OUTDIR/cloud/gcp-listing-$GCP_BUCKET.txt')); [print(i['name']) for i in data.get('items',[])]" 2>/dev/null | head -20
fi
```

## W2.4 — Probe cloud metadata endpoints (from application context)

```bash
# Test if the app can reach metadata endpoints (SSRF context)
# This probes from YOUR machine, not the server -- only useful for open buckets
curl -s --connect-timeout 3 "http://169.254.169.254/latest/meta-data/" 2>/dev/null | head -5
# This will almost certainly fail from your machine. Use ssrf skill for metadata via server.

# Instead, check for CloudFront misconfigurations
TARGET_HOST=$(echo "$TARGET_URL" | awk -F/ '{print $3}')
curl -s -D - -o /dev/null "https://$TARGET_HOST" 2>/dev/null | grep -iE '(x-amz|cloudfront|x-cache|cf-ray|x-azure-ref)'
```

## W2.5 — Batch test all bucket candidates

```bash
while IFS= read -r bucket; do
  [ -z "$bucket" ] && continue
  code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
    "https://$bucket.s3.amazonaws.com" 2>/dev/null)
  echo "$bucket -> HTTP $code"
done < "$OUTDIR/cloud/bucket-name-candidates.txt" > "$OUTDIR/cloud/bucket-probe-results.txt"

echo "=== Accessible buckets (HTTP 200/403) ==="
grep -vE 'HTTP (000|404|502)' "$OUTDIR/cloud/bucket-probe-results.txt"
```

---

## Detection Signals

| Signal | Confidence | Route |
|---|---|---|
| HTTP 200 on S3 bucket with XML listing | HIGH | -> 03-verify.md |
| HTTP 403 on S3 bucket (exists, private) | LOW | -> 03-verify.md (test specific files) |
| Azure blob listing returns 200 + XML | HIGH | -> 03-verify.md |
| GCP bucket listing returns 200 + JSON | HIGH | -> 03-verify.md |
| HTTP 404 or 502 | Nonexistent | -> Cease for this bucket |
| HTTP 301 redirect (wrong region) | LOW | -> Retry with correct region |

## False Positive Patterns

| Pattern | Meaning |
|---|---|
| HTTP 200 but no files in listing | Empty bucket -- low impact |
| HTTP 403 + no listing | Private bucket -- not exploitable |
| HTTP 200 on *.s3.amazonaws.com but redirects to login | Access denied via redirect |
| HTTP 200 with "static website hosting" page | Intended public bucket -- not a vuln unless sensitive content |

---

## Next Routing

| Result | Route |
|---|---|
| Publicly listable bucket (S3/Azure/GCP) | -> 03-verify.md W3.1 |
| Bucket accessible but not listable | -> 03-verify.md W3.2 (guess file names) |
| Bucket writeable (200 on PUT) | -> 03-verify.md W3.3 |
| No accessible buckets | -> Cease investigation |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/cloud/s3-listing-$BUCKET.txt | S3 bucket listing response |
| $OUTDIR/cloud/s3-files-$BUCKET.txt | Extracted file keys from listing |
| $OUTDIR/cloud/gcp-listing-$GCP_BUCKET.txt | GCP bucket listing response |
| $OUTDIR/cloud/bucket-probe-results.txt | Batch probe results for all candidates |
