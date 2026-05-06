# Browser Capture Runbook

Captures authenticated browser sessions using personas with full safety enforcement.

## Prerequisites

- Persona skill initialized (`bin/bb-run persona init-personas`)
- At least one persona with imported credentials (`bin/bb-run persona import-cookie`)
- Persona sessions validated (`bin/bb-run persona validate-sessions`)
- Playwright installed (`pip install playwright && playwright install chromium`)
- `SCOPE_FILE` configured for scope enforcement

## Workflow

```bash
bin/bb-run persona browser-capture
```

### Required Environment Variables

| Variable | Purpose |
|---|---|
| `PERSONA_NAME` | Persona ID (e.g., `attacker`, `victim`) |
| `CAPTURE_URL` | Target URL to capture |
| `OUTDIR` | Output directory for all engagement artifacts |

### Optional

| Flag | Purpose |
|---|---|
| `--capture-screenshot` | Save annotated screenshot (visual plane) |
| `--save-har` | Record and save HAR traffic file |

## What Gets Captured

### Visual Plane
- `screenshot.png` — page screenshot (if `--capture-screenshot`)
- `page_state.json` — URL, title, HTTP status code

### Structured Plane
- `interactables.json` — all forms, links, buttons, and inputs with identifiers

### Action Plane
- No auto-actions taken. Every interactable is described but never engaged.

## Artifact Redaction

All captured artifacts are automatically redacted:
- `Authorization`, `Cookie`, `X-API-Key`, and similar auth headers replaced with `[REDACTED]`
- URL query parameters matching (`token`, `api_key`, `secret`, etc.) redacted
- Cookie values stripped from HAR entries
- Raw response content sanitized

## Safety Gates (automatic)

1. Persona must exist in `personas.json` with `credentials_imported: true`
2. URL must match scope patterns from `SCOPE_FILE`
3. Forbidden paths rejected automatically:
   - `/login`, `/signin`, `/signup`, `/register`
   - `/checkout`, `/payment`, `/card`, `/billing`
   - `/reset-password`, `/forgot-password`
   - `/verify-email`, `/confirm-payment`
4. No auto-submit, no auto-click, no auto-scroll
5. Single tab, no parallel browsing
6. Browser session closed after capture

## Output Structure

```
$OUTDIR/browser/
├── capture_result.json      # Full capture metadata
├── model_summary.json       # Three-plane model summary
├── page_state.json          # URL, title, status (visual plane)
├── interactables.json       # Forms, links, buttons, inputs (structured plane)
├── traffic.har              # HAR traffic (if --save-har)
└── screenshot.png           # Page screenshot (if --capture-screenshot)
```

## Integration Points

| Consumer Skill | What It Uses |
|---|---|
| `traffic-corpus` | Imports HAR via `--source browser $OUTDIR/browser/` |
| `cross-account` | Uses captured routes via `--source browser-capture $OUTDIR/browser/` |
| `agent-safety` | Scans interactables via `--check-browser-output $OUTDIR/browser/` |

## Manual Capture

```bash
python3 .claude/skills/persona/scripts/browser_capture.py \
  --persona attacker \
  --url https://target.com/dashboard \
  --output $OUTDIR/browser/ \
  --capture-screenshot \
  --save-har
```

## Rate Limits

- Max 1 request per second enforced by the script
- No parallel browsing — single tab only
- Browser session closes immediately after capture completes

## Troubleshooting

| Issue | Resolution |
|---|---|
| Playwright not found | `pip install playwright && playwright install chromium` |
| persona not configured | Run `init-personas` then `import-cookie` |
| Out of scope | Check `SCOPE_FILE` content and `CAPTURE_URL` |
| Forbidden path | Use a URL that is not login/register/payment/password-reset |