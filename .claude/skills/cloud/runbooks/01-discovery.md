# Cloud Security — Runbook 01: Discovery

## Purpose
Discover cloud assets: S3 buckets, Azure blob storage, GCP buckets, exposed cloud metadata endpoints, and cloud service usage patterns.

## Variables
- `$TARGET_URL` — base URL (e.g., https://example.com)
- `$OUTDIR` — output directory
- `$CONTEXT` — (optional) prior recon output (subdomains, httpx json)

---

## W1.1 — Extract S3 bucket references from page source

```bash
curl -s "$TARGET_URL" | grep -oiE 'https?://[^"'\''<> ]*s3[^"'\''<> ]*' | sort -u > "$OUTDIR/cloud/s3-page-refs.txt"
curl -s "$TARGET_URL" | grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.s3[.-]?(us-|eu-|ap-|sa-|ca-|me-|af-)?[a-z-]*[0-9]*\.amazonaws\.com' | sort -u >> "$OUTDIR/cloud/s3-page-refs.txt"
```

## W1.2 — Extract S3 bucket names from JavaScript

```bash
grep -rE '\.js(\?|$)' "$OUTDIR"*.txt 2>/dev/null | head -20 | while IFS= read -r jsurl; do
  curl -s "$jsurl" 2>/dev/null | grep -oiE '"[^"]*s3[^"]*bucket[^"]*"' | tr -d '"'
done > "$OUTDIR/cloud/s3-js-refs.txt" 2>/dev/null

# Also from katana crawl if available
katana -u "$TARGET_URL" -d 3 -jc -o "$OUTDIR/cloud/katana-urls.txt" 2>/dev/null
grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.s3\.amazonaws\.com' "$OUTDIR/cloud/katana-urls.txt" 2>/dev/null | sort -u >> "$OUTDIR/cloud/s3-js-refs.txt"
```

## W1.3 — Enumerate S3 buckets with nuclei

```bash
echo "$TARGET_URL" | nuclei -t ~/nuclei-templates/http/misconfiguration/s3-bucket-takeover.yaml \
  -o "$OUTDIR/cloud/nuclei-s3.txt" -silent

# Also scan subdomains if available from $CONTEXT
if [ -f "$CONTEXT" ]; then
  nuclei -list "$CONTEXT" -t ~/nuclei-templates/http/misconfiguration/s3-bucket*.yaml \
    -o "$OUTDIR/cloud/nuclei-s3-subs.txt" -silent
fi
```

## W1.4 — Enumerate common S3 bucket name patterns

```bash
TARGET_NAME=$(echo "$TARGET_URL" | awk -F/ '{print $3}' | awk -F. '{print $1}')

# Generate common bucket name permutations
echo "$TARGET_NAME
${TARGET_NAME}-prod
${TARGET_NAME}-dev
${TARGET_NAME}-staging
${TARGET_NAME}-assets
${TARGET_NAME}-static
${TARGET_NAME}-media
${TARGET_NAME}-uploads
${TARGET_NAME}-backup
${TARGET_NAME}-backups
${TARGET_NAME}-cdn
${TARGET_NAME}-logs
${TARGET_NAME}-files
${TARGET_NAME}-data
${TARGET_NAME}-images
assets.${TARGET_NAME}
static.${TARGET_NAME}
media.${TARGET_NAME}
cdn.${TARGET_NAME}" > "$OUTDIR/cloud/bucket-name-candidates.txt"

echo "=== Bucket name candidates ==="
cat "$OUTDIR/cloud/bucket-name-candidates.txt"
```

## W1.5 — Check for Azure blob storage references

```bash
curl -s "$TARGET_URL" | grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.(blob\.core\.windows\.net|azurewebsites\.net|cloudapp\.net)' | sort -u > "$OUTDIR/cloud/azure-refs.txt"

katana -u "$TARGET_URL" -d 3 -jc -o - 2>/dev/null | grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.blob\.core\.windows\.net' | sort -u >> "$OUTDIR/cloud/azure-refs.txt"
```

## W1.6 — Check for GCP bucket references

```bash
curl -s "$TARGET_URL" | grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.storage\.googleapis\.com' | sort -u > "$OUTDIR/cloud/gcp-refs.txt"

katana -u "$TARGET_URL" -d 3 -jc -o - 2>/dev/null | grep -oiE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.storage\.googleapis\.com' | sort -u >> "$OUTDIR/cloud/gcp-refs.txt"
```

## W1.7 — Identify cloud metadata endpoints in app code

```bash
# Look for 169.254.169.254 references (AWS/cloud metadata)
curl -s "$TARGET_URL" | grep -oiE '169\.254\.169\.254|metadata\.google\.internal' > "$OUTDIR/cloud/metadata-refs.txt"

# Check JS files
grep -rE '\.js(\?|$)' "$OUTDIR"*.txt 2>/dev/null | head -10 | while IFS= read -r jsurl; do
  curl -s "$jsurl" 2>/dev/null | grep -oiE '(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)' >> "$OUTDIR/cloud/metadata-refs.txt"
done
```

---

## Signals

| Signal | Means |
|---|---|
| s3.amazonaws.com URLs in page source | S3 bucket usage identified |
| Bucket name in JS (e.g., "my-app-assets.s3...") | Bucket name discovered -- test accessibility |
| *.blob.core.windows.net references | Azure blob storage in use |
| *.storage.googleapis.com references | GCP storage in use |
| 169.254.169.254 in source code | SSRF/cloud metadata target |

---

## Next Routing

| Finding | Route |
|---|---|
| S3 bucket names/URLs discovered | -> 02-probe.md W2.1 (test bucket accessibility) |
| Azure blob URLs found | -> 02-probe.md W2.2 (test Azure blob access) |
| GCP storage URLs found | -> 02-probe.md W2.3 (test GCP bucket access) |
| Cloud metadata references found | -> Route to ssrf skill for metadata endpoint testing |
| No cloud assets found | -> Cease or broaden recon |

---

## Output Files

| File | Contents |
|---|---|
| $OUTDIR/cloud/s3-page-refs.txt | S3 URLs from page source |
| $OUTDIR/cloud/s3-js-refs.txt | S3 bucket names from JavaScript |
| $OUTDIR/cloud/katana-urls.txt | Katana crawl output |
| $OUTDIR/cloud/nuclei-s3.txt | Nuclei S3 findings |
| $OUTDIR/cloud/bucket-name-candidates.txt | Generated bucket name permutations |
| $OUTDIR/cloud/azure-refs.txt | Azure blob storage references |
| $OUTDIR/cloud/gcp-refs.txt | GCP storage references |
| $OUTDIR/cloud/metadata-refs.txt | Cloud metadata endpoint references |
