# Workflow: Auto-Setup

## Purpose
One-command OOB infrastructure initialization with health check.

## Execution
```bash
bin/bb-run oob-infra auto-setup
```

## What It Does
1. Checks interactsh server health (`oast.pro` or custom)
2. Starts interactsh client session
3. Saves session metadata to `$OUTDIR/oob/session.json`

## When to Use
- At the start of every engagement that involves blind vulnerability testing
- Before running `api`, `ssrf`, `sqli`, `xss` workflows that may need OOB confirmation

## Integration with Other Skills
The `oob_integration.py` helper lets any skill inject canaries:
```bash
python3 .claude/skills/oob-infra/scripts/oob_integration.py inject \
  --template 'https://{{CANARY}}/callback' \
  --purpose ssrf-test \
  --test-id api-001
```

## Next Steps
- Run `generate-canary` for specific test cases
- Use `inject-and-poll` for rapid testing
