# 03-validate: Validate Sessions

## Overview

Test every imported persona credential against the target application to
determine session health. Produces a `validation.json` report classifying each
persona as `active`, `expired`, or `missing`.

## Prerequisites

- At least one persona credential imported via `import-cookie`.
- Target application is reachable from the testing host.
- `validate-sessions` workflow configured in `skill.yaml`.

## Steps

1. (Recommended) Re-validate context is loaded:
   ```
   source .bb/context.env
   ```

2. Run the session validation workflow:
   ```
   bin/bb-run persona validate-sessions
   ```

3. The workflow sends an authenticated probe request for each persona and records
   the HTTP status code and body fingerprint.

4. Inspect results:
   ```
   python3 -m json.tool $OUTDIR/personas/validation.json
   ```

## Verification

- `validation.json` exists and has one entry per imported persona.
- Each entry contains `persona_id`, `auth_state`, `status_code`, and `probe_url`.
- Auth state classifications:
  - **Active** — received a 2xx response (session valid).
  - **Expired** — received a 401 or 403 (session invalid).
  - **Missing** — no credential found; import needed.
  - **Error** — network failure or unexpected 5xx.

  ```
  python3 -c "
  import json
  data = json.load(open('$OUTDIR/personas/validation.json'))
  for p in data:
      print(f\"{p['persona_id']:15s} -> {p['auth_state']:10s} ({p['status_code']})\")
  "
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| All personas `Error` | Target unreachable or rate-limited | Check connectivity; use `--rate-limit` flag |
| `Active` but expected `Expired` | Application accepts expired cookies | Re-import a fresh cookie and re-validate |
| Persona missing from report | Credential file malformed or empty | Re-run `import-cookie` for that persona |
| Same status for all personas | Probe endpoint not auth-gated | Use a different probe URL from `skill.yaml` |