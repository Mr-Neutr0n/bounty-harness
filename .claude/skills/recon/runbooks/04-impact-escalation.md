# Recon — Impact Escalation

## Purpose
Transform recon artifacts into actionable attack paths. Subdomain takeovers, credential leaks, exposed admin panels, zone transfer dumps, and unauthenticated internal services become fully weaponized findings.

## Required Variables
- `$TARGET` — primary domain
- `$OUTDIR` — output root
- `$EVIDENCE_DIR` — evidence destination (`evidence/recon_$(date +%s)`)

## Commands

### Path A: Subdomain Takeover

```bash
EVIDENCE_DIR="evidence/takeover_${TARGET}_$(date +%s)"
mkdir -p "$EVIDENCE_DIR"

while read -r line; do
  sub=$(echo "$line" | awk '{print $1}')
  echo "=== Testing takeover: $sub ==="
  dig +short "$sub" CNAME | tee -a "$EVIDENCE_DIR/dns_cname.txt"
  curl -sIL -m 10 "$sub" -o "$EVIDENCE_DIR/http_${sub//./_}.txt" -w "HTTP %{http_code}\n"
done < "$OUTDIR/dns/takeover_candidates.txt"

# Check for dangling cloud resources
grep -iE 'cloudfront\.net' "$OUTDIR/dns/takeover_candidates.txt" && \
  echo "[CRITICAL] CloudFront CNAME with possible dangling distribution"
grep -iE 'herokuapp\.com' "$OUTDIR/dns/takeover_candidates.txt" && \
  echo "[CRITICAL] Heroku CNAME — test app registration"
```

### Path B: Exposed Admin / Internal Panels

```bash
EVIDENCE_DIR="evidence/admin_panel_$(date +%s)"
mkdir -p "$EVIDENCE_DIR"

while read -r url; do
  curl -sv "$url" -o "$EVIDENCE_DIR/body_$(echo $url | md5).html" 2>"$EVIDENCE_DIR/headers_$(echo $url | md5).txt"
  echo "$url" | httpx -silent -screenshot -ss-path "$EVIDENCE_DIR/" -title -status-code
done < "$OUTDIR/urls/admin_endpoints.txt"
```

### Path C: Zone Transfer Success

```bash
EVIDENCE_DIR="evidence/axfr_$(date +%s)"
mkdir -p "$EVIDENCE_DIR"
cp "$OUTDIR/dns/zone_transfer.txt" "$EVIDENCE_DIR/"
echo "Target: $TARGET" >> "$EVIDENCE_DIR/summary.txt"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVIDENCE_DIR/summary.txt"
echo "Record count: $(grep -c 'IN\s' "$EVIDENCE_DIR/zone_transfer.txt" 2>/dev/null)" >> "$EVIDENCE_DIR/summary.txt"
```

### Path D: Credential / Secret Leaks in JS

```bash
EVIDENCE_DIR="evidence/js_leaks_$(date +%s)"
mkdir -p "$EVIDENCE_DIR"
cp "$OUTDIR/js/secrets.txt" "$OUTDIR/js/secrets_aws.txt" "$OUTDIR/js/internal_ips.txt" "$EVIDENCE_DIR/" 2>/dev/null
```

## Detection Signals
- `404` / `NXDOMAIN` on takeover candidate → dangling record confirmed
- `200` on admin endpoint without auth redirect → unauthenticated admin panel
- Zone transfer returns > SOA record → full DNS enumeration achieved
- AWS key pattern `AKIA*` in JS → IAM user access key exposed

## False Positives
- CNAME resolves successfully → not actually dangling; the service is still active
- Admin panel returns `200` but body is a login form → still requires credentials
- `AKIA` pattern matches documentation/examples in JS — verify key is real by checking length (20 chars)

## Next
├── If takeover confirmed → go to `05-evidence-collection.md`
├── If admin panel accessible → route to `auth` skill for login testing
├── If secrets found → route to `cloud` skill for IAM/key validation
└── Always → capture all evidence before moving to vuln-class skills