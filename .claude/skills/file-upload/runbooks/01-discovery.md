# File Upload Discovery Runbook

## Purpose
Discover file upload functionality, identify upload endpoints, map supported file types, and detect file path disclosure in responses.

## Variables
- `$TARGET_URL` — base URL
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — authenticated session
- `$PAYLOAD_DIR` — `$OUTDIR/payloads`

## Step 1 — Discover Upload Endpoints

### W1A. Crawl for upload forms and endpoints
```bash
katana -u "$TARGET_URL" -jc -d 3 -silent -field url | grep -iE 'upload|attach|image|file|avatar|profile|import|bulk|doc|media|asset|logo|background' | sort -u > "$OUTDIR/upload-endpoints.txt"
```

### W1B. Wayback upload endpoint discovery
```bash
gau "$TARGET_URL" | grep -iE 'upload|attach|image|file|avatar|profile|import|bulk' | sort -u >> "$OUTDIR/upload-endpoints.txt"
```

### W1C. Common upload path brute-force
```bash
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST_DIR/web-content/upload-paths.txt" -mc 200,301,302,403 -o "$OUTDIR/upload-paths-ffuf.json"
```

## Step 2 — Test Basic Upload

### W2A. Upload a benign text file
```bash
echo "test" > "$OUTDIR/test-upload.txt"
curl -sk -v "$TARGET_URL/upload" -F "file=@$OUTDIR/test-upload.txt" -b "$COOKIE_JAR" -o "$OUTDIR/upload-basic-response.txt" 2>"$OUTDIR/upload-basic-headers.txt"
```

### W2B. Check response for file path disclosure
```bash
grep -oE '(https?://[^"'\'']*|/[a-zA-Z0-9/_.-]+\.txt)' "$OUTDIR/upload-basic-response.txt" | sort -u > "$OUTDIR/upload-file-paths.txt"
cat "$OUTDIR/upload-file-paths.txt"
```

### W2C. Check response headers for upload location
```bash
grep -iE 'location|content-location|x-upload-path' "$OUTDIR/upload-basic-headers.txt" >> "$OUTDIR/upload-file-paths.txt"
```

## Step 3 — Discover Allowed File Types

### W3A. Extension enumeration
```bash
for ext in jpg jpeg png gif bmp svg webp pdf doc docx xls xlsx csv txt xml json html css js zip tar gz php asp aspx jsp py rb pl cgi; do
  echo "benign" > "$PAYLOAD_DIR/test.$ext"
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL/upload" -F "file=@$PAYLOAD_DIR/test.$ext" -b "$COOKIE_JAR")
  echo "$ext -> $HTTP_CODE" >> "$OUTDIR/upload-extension-check.txt"
done
```

### W3B. Identify accepted and rejected extensions
```bash
grep '200\|201\|302' "$OUTDIR/upload-extension-check.txt" > "$OUTDIR/upload-accepted-extensions.txt"
grep '400\|403\|415' "$OUTDIR/upload-extension-check.txt" > "$OUTDIR/upload-rejected-extensions.txt"
echo "Accepted: $(wc -l < "$OUTDIR/upload-accepted-extensions.txt") extensions"
```

## Step 4 — Discover Server Type for Exploit Selection
```bash
curl -sk -v "$TARGET_URL" 2>&1 | grep -iE 'server:|x-powered-by:|x-aspnet' | tee "$OUTDIR/upload-server-tech.txt"
```

## Step 5 — Identify File Storage / Serving Pattern
```bash
cat "$OUTDIR/upload-file-paths.txt"
# Common patterns:
# /uploads/<filename> -> direct file access
# /uploads/<hash>/<filename> -> hashed path
# https://cdn.domain/u/<filename> -> CDN
# https://s3.amazonaws.com/bucket/<filename> -> S3
```

## Signals
| Signal | Indicates |
|---|---|
| Upload endpoint returns file path/URL | File location known — test direct access |
| Server is Apache/IIS with PHP/ASPX | Test PHP/ASPX shell upload |
| Only images allowed but SVG accepted | Test SVG XSS |
| Upload endpoint allows zip/tar | Test zip slip / path traversal |
| Cloud storage URL returned | Route to cloud skill for S3 bucket testing |
| 200 on PHP/ASPX extension | Server allows dangerous extensions — critical finding |

## Next Routing
- Upload endpoint found and testable -> `runbooks/02-probe.md`
- PHP/ASPX accepted -> immediate high-severity, go to verify
- Only image extensions accepted -> probe with extension bypass techniques
- No upload endpoints found -> expand crawl scope or stop
