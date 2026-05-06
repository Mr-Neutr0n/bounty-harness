# Cloud Security — Runbook 05: Evidence Collection

## Purpose
Standardized evidence packaging for cloud storage findings.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence directory
- `$FINDING_ID` — unique finding identifier
- `$BUCKET_NAME` — vulnerable bucket

---

## Directory Structure

```bash
mkdir -p "$EVIDENCE_DIR/$FINDING_ID"/{listing,secrets,files,dns}
```

## E5.1 — Capture bucket listing

```bash
curl -s "https://$BUCKET_NAME.s3.amazonaws.com" \
  -o "$EVIDENCE_DIR/$FINDING_ID/listing/bucket-listing.xml" \
  -D "$EVIDENCE_DIR/$FINDING_ID/listing/listing-headers.txt"

head -c 2000 "$EVIDENCE_DIR/$FINDING_ID/listing/bucket-listing.xml" \
  > "$EVIDENCE_DIR/$FINDING_ID/listing/listing-truncated.xml"
```

## E5.2 — Capture sample sensitive file (redacted)

```bash
# If .env or config file was found
SENSITIVE_FILE=".env"  # adjust based on findings
curl -s "https://$BUCKET_NAME.s3.amazonaws.com/$SENSITIVE_FILE" \
  -o "$EVIDENCE_DIR/$FINDING_ID/files/$SENSITIVE_FILE" 2>/dev/null

head -c 1000 "$EVIDENCE_DIR/$FINDING_ID/files/$SENSITIVE_FILE" \
  > "$EVIDENCE_DIR/$FINDING_ID/files/sensitive-sample.txt" 2>/dev/null
```

## E5.3 — Secret scan evidence

```bash
python3 -c "
import urllib.request, re

bucket = '$BUCKET_NAME'
SECRETS = [
    (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key'),
    (r'(?i)(aws_secret_access_key[\s]*[=:][\s]*[\x27\x22]?[A-Za-z0-9+/=]{20,})', 'AWS Secret Key'),
    (r'(?i)(-----BEGIN RSA PRIVATE KEY-----)', 'Private Key'),
    (r'(?i)(DATABASE_URL[\s]*=[\s]*[^\s]+)', 'Database URL'),
    (r'(?i)(JWT_SECRET[\s]*=[\s]*[^\s]+)', 'JWT Secret'),
]

# Check listing for config-like files first
listing = open('$EVIDENCE_DIR/$FINDING_ID/listing/bucket-listing.xml').read()
config_files = re.findall(r'<Key>([^<]*(?:\.env|config|secret|credential|password|\.pem|\.key)[^<]*)</Key>', listing, re.I)

with open('$EVIDENCE_DIR/$FINDING_ID/secrets/findings.txt', 'w') as out:
    for cf in config_files[:10]:
        try:
            resp = urllib.request.urlopen(f'https://{bucket}.s3.amazonaws.com/{cf}')
            body = resp.read().decode('utf-8', errors='ignore')
            for pattern, name in SECRETS:
                if re.search(pattern, body):
                    out.write(f'SECRET ({name}): {cf}\n')
                    print(f'SECRET ({name}) found in {cf}')
        except:
            pass
" 2>/dev/null > "$EVIDENCE_DIR/$FINDING_ID/secrets/findings.txt"

cat "$EVIDENCE_DIR/$FINDING_ID/secrets/findings.txt"
```

## E5.4 — DNS takeover evidence

```bash
dig +short "$BUCKET_NAME.$TARGET_HOST" CNAME > "$EVIDENCE_DIR/$FINDING_ID/dns/cname.txt" 2>/dev/null
dig +short "$BUCKET_NAME.$TARGET_HOST" A >> "$EVIDENCE_DIR/$FINDING_ID/dns/a-records.txt" 2>/dev/null

cat "$EVIDENCE_DIR/$FINDING_ID/dns/cname.txt"
```

## E5.5 — Timestamp and tool versions

```bash
date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt"

cat > "$EVIDENCE_DIR/$FINDING_ID/tool-versions.txt" << EOF
curl: $(curl --version 2>&1 | head -1)
python3: $(python3 --version 2>&1)
aws: $(aws --version 2>&1 || echo "not installed")
nuclei: $(nuclei -version 2>&1)
katana: $(katana -version 2>&1)
dig: $(dig -v 2>&1 | head -1)
date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
OS: $(sw_vers 2>/dev/null || uname -a)
EOF
```

## E5.6 — Evidence manifest

```bash
cat > "$EVIDENCE_DIR/$FINDING_ID/manifest.txt" << EOF
FINDING_ID: $FINDING_ID
TARGET: $TARGET_URL
BUCKET: $BUCKET_NAME
SEVERITY: (fill -- critical/high/medium/low)
VULN_CLASS: cloud-storage-misconfig
CLOUD_PROVIDER: (fill -- AWS / Azure / GCP)
TIMESTAMP: $(cat "$EVIDENCE_DIR/$FINDING_ID/timestamp.txt")

ARTIFACTS:
  listing/bucket-listing.xml          -- Full S3/Azure/GCP bucket listing
  listing/listing-truncated.xml       -- Truncated listing (first 2KB)
  listing/listing-headers.txt         -- HTTP headers from listing request
  files/sensitive-sample.txt          -- Sample of sensitive file (redacted)
  secrets/findings.txt                -- Secret scanning results
  dns/cname.txt                       -- DNS CNAME records for takeover check
  dns/a-records.txt                   -- DNS A records
  timestamp.txt                       -- Finding timestamp
  tool-versions.txt                   -- Tool version manifest

IMPACT:
(fill -- describe what data was exposed, what secrets were found)

REPRODUCTION:
1. curl https://$BUCKET_NAME.s3.amazonaws.com shows public bucket listing
2. (fill -- specific paths to sensitive files)
3. (fill -- secrets found and their impact)
EOF

echo "Evidence written to $EVIDENCE_DIR/$FINDING_ID/"
```

## E5.7 — Package

```bash
tar -czf "$EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz" \
  -C "$EVIDENCE_DIR" "$FINDING_ID"
echo "Packaged: $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz"
```

---

## Output Files

| File | Contents |
|---|---|
| $EVIDENCE_DIR/$FINDING_ID/manifest.txt | Complete evidence manifest |
| $EVIDENCE_DIR/$FINDING_ID/listing/ | Bucket listing evidence |
| $EVIDENCE_DIR/$FINDING_ID/secrets/ | Secret scan results |
| $EVIDENCE_DIR/$FINDING_ID/files/ | Sample files |
| $EVIDENCE_DIR/$FINDING_ID/dns/ | DNS records for takeover |
| $EVIDENCE_DIR/$FINDING_ID/timestamp.txt | UTC timestamp |
| $EVIDENCE_DIR/$FINDING_ID/tool-versions.txt | Tool version manifest |
| $EVIDENCE_DIR/${FINDING_ID}-evidence.tar.gz | Packaged archive |
