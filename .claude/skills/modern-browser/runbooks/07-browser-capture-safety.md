# Browser Capture Safety

Guidance on safe browser capture practices for vulnerability testing.

## Core Principle

Browser capture is a **read-only observation** of a single authenticated page. It never:
- Submits forms automatically
- Clicks links or buttons
- Scrolls or interacts with the page
- Navigates away from the specified URL
- Captures login flows, payment pages, or password reset flows

## Pre-Capture Checklist

Before running any browser capture:

1. **Verify Scope**: Confirm the target URL is within the program's authorized scope
2. **Persona Auth Valid**: Run `validate-sessions` to confirm the persona's tokens/cookies are active
3. **No Forbidden Pages**: The script automatically rejects login, signup, payment, billing, and password-reset URLs
4. **Single Tab**: Only one page is opened per capture session
5. **Rate Limit**: Enforced at 1 request per second internally

## During Capture

- The browser launches in headless mode (no visible window)
- Persona cookies and auth headers are injected before navigation
- The page loads but **no JavaScript interactions are triggered beyond what the page does on load**
- Interactables are extracted via `document.querySelectorAll` — no events fired
- Screenshot captures the visible viewport only (no scrolling)

## Post-Capture Safety

### Automatic Redaction

Every artifact written to disk has auth data stripped:

| Artifact | What Gets Redacted |
|---|---|
| `traffic.har` | All `Authorization`, `Cookie`, `X-API-Key`, bearer headers replaced with `[REDACTED]` |
| `traffic.har` | All cookie values in request/response entries redacted |
| `traffic.har` | URL query params (`token`, `api_key`, `secret`, etc.) redacted |
| `page_state.json` | URL saved with query params stripped of sensitive values |
| `interactables.json` | No auth headers included — only DOM element metadata |

### Agent-Safety Scan (Recommended)

After capture, run the agent-safety skill to scan for prompt injection risks:

```bash
bin/bb-run agent-safety check-browser-capture
```

Or manually:

```bash
python3 .claude/skills/agent-safety/scripts/safety_checker.py \
  --action check-browser-output \
  --input $OUTDIR/browser/ \
  --output $OUTDIR/browser/safety_scan.json
```

## What NOT to Capture

- **Login forms**: URLs containing `/login`, `/signin`, `/sign_in`
- **Registration pages**: `/register`, `/signup`, `/sign_up`
- **Payment flows**: `/checkout`, `/payment`, `/card`, `/billing`, `/purchase`, `/wallet`
- **Password reset**: `/reset-password`, `/forgot-password`
- **Email verification**: `/verify-email`
- **Any page that processes real credentials or payment data**

## Evidence Handling

Captured screenshots and interactables may contain sensitive UI elements from authenticated pages. Before sharing:
1. Review screenshots for PII or internal data
2. Redact any internal identifiers visible in interactables JSON
3. Run `safety_checker.py --check-browser-output` to flag risks

## Cross-Account Testing Safety

When using browser-captured traffic as input for cross-account replay:
1. Ensure both personas have active sessions
2. The authz replayer replays routes with persona B's credentials against persona A's resources
3. No auto-approval — findings require manual verification before reporting

## Emergency Stop

The capture script respects these boundaries:
- If Playwright is not installed, it prints install instructions and exits
- If the persona has no credentials, it exits
- If the URL is out of scope, it exits
- If the URL is a forbidden path, it exits
- If navigation fails (timeout, DNS, TLS), it records the error and exits

No capture ever proceeds past a safety gate violation.