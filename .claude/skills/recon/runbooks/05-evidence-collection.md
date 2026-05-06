# Recon — Evidence Collection

## Purpose
Capture reproducible proof for every recon finding. Request/response pairs, DNS records, screenshots, and timestamped manifests sufficient for bug bounty submission or pentest report appendices.

## Required Variables
- `$TARGET` — primary domain
- `$FINDING_ID` — unique identifier per finding (e.g. `takeover_admin_staging`)
- `$EVIDENCE_ROOT` — base evidence directory (`evidence/$TARGET/`)

## Commands

### Standard Evidence Template

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

FINDING_ID="${FINDING_ID:-$(date +%s)_recon_finding}"
EVIDENCE_DIR="$EVIDENCE_ROOT/$FINDING_ID"
mkdir -p "$EVIDENCE_DIR"

# Timestamp
date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/timestamp.txt"

# Tool versions manifest
{
  echo "subfinder $(subfinder -version 2>&1 | head -1)"
  echo "httpx $(httpx -version 2>&1 | head -1)"
  echo "dnsx $(dnsx -version 2>&1 | head -1)"
  echo "naabu $(naabu -version 2>&1 | head -1)"
  echo "curl $(curl --version | head -1)"
} > "$EVIDENCE_DIR/tool_versions.txt"
```

### Subdomain Takeover Evidence

```bash
TAKEOVER_SUB="$1"
EVIDENCE_DIR="$EVIDENCE_ROOT/takeover_${TAKEOVER_SUB//./_}"

# DNS CNAME chain
dig +short "$TAKEOVER_SUB" CNAME > "$EVIDENCE_DIR/cname_chain.txt"
dig +short "$TAKEOVER_SUB" A > "$EVIDENCE_DIR/a_record.txt"

# HTTP response
curl -sIL -m 10 "http://$TAKEOVER_SUB" > "$EVIDENCE_DIR/http_response.txt" 2>&1

# Screenshot
echo "http://$TAKEOVER_SUB" | httpx -silent -screenshot -ss-path "$EVIDENCE_DIR/" -title -status-code

# PoC reproducer
cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
dig +short $TAKEOVER_SUB CNAME
curl -sI http://$TAKEOVER_SUB | head -20
echo "Service at $(dig +short $TAKEOVER_SUB CNAME) is dangling/claimable."
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### Exposed Admin Panel Evidence

```bash
ADMIN_URL="$1"
EVIDENCE_DIR="$EVIDENCE_ROOT/admin_$(echo $ADMIN_URL | md5)"

# Full request trace
curl -sv "$ADMIN_URL" -o "$EVIDENCE_DIR/response_body.html" 2>"$EVIDENCE_DIR/request_headers.txt"

# Screenshot
echo "$ADMIN_URL" | httpx -silent -screenshot -ss-path "$EVIDENCE_DIR/" -title -status-code

# PoC
cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
curl -sI '$ADMIN_URL'
echo "Admin panel at $ADMIN_URL returns HTTP \$(curl -s -o /dev/null -w '%{http_code}' '$ADMIN_URL') without authentication."
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### Zone Transfer Evidence

```bash
NS_SERVER="$1"
EVIDENCE_DIR="$EVIDENCE_ROOT/axfr_${NS_SERVER//./_}"

dig AXFR "$TARGET" @"$NS_SERVER" +time=10 > "$EVIDENCE_DIR/zone_transfer_full.txt"
echo "NS: $NS_SERVER | Target: $TARGET | Records: $(grep -c 'IN\s' "$EVIDENCE_DIR/zone_transfer_full.txt")" > "$EVIDENCE_DIR/summary.txt"
```

### Evidence Manifest

```bash
cat > "$EVIDENCE_ROOT/manifest.md" << MANIFEST
# Evidence Manifest — $TARGET

| Finding ID | Type | DNS | HTTP | Screenshot | PoC |
|---|---|---|---|---|---|
MANIFEST

for d in "$EVIDENCE_ROOT"/*/; do
  fid=$(basename "$d")
  dns=$( [ -f "$d/cname_chain.txt" ] && echo "yes" || echo "-" )
  http=$( [ -f "$d/http_response.txt" ] && echo "yes" || echo "-" )
  ss=$( ls "$d"/*.png 2>/dev/null | head -1 | xargs -I{} basename {} || echo "-" )
  poc=$( [ -f "$d/poc.sh" ] && echo "yes" || echo "-" )
  echo "| $fid | $(basename "$d") | $dns | $http | $ss | $poc |" >> "$EVIDENCE_ROOT/manifest.md"
done
```

## Detection Signals
- `poc.sh` at each evidence dir → reproducible one-liner
- `.png` screenshot exists → visual proof
- `cname_chain.txt` shows cloud service → takeover type classifiable
- `request_headers.txt` shows no Set-Cookie/auth redirect → confirmed unauthenticated

## Next
├── After evidence collected → ready for report generation (reporting skill)
├── After takeover PoC → attempt actual service registration as proof-of-impact
└── Always → run `ls -laR "$EVIDENCE_ROOT"` and verify all files non-empty