# 04-evidence: Prepare Evidence Safely

## Overview

Export persona headers for evidence collection while stripping secrets from all
output artifacts. The redaction step runs first to guarantee no credential leaks
into evidence packages, Burp logs, or report screenshots.

## Prerequisites

- Persona credentials imported and session validation completed.
- `redact-secrets` and `export-headers` workflows defined in `skill.yaml`.
- Evidence directory `$EVIDENCE_DIR` configured in context.

## Steps

1. **Redact secrets first.** This is mandatory before any export:
   ```
   bin/bb-run persona redact-secrets
   ```
   This produces `$OUTDIR/personas/redacted_manifest.json` with every credential
   value replaced by `[REDACTED]` markers. The originals remain in `creds/` but
   are excluded from all downstream exports.

2. **Export sanitized headers:**
   ```
   bin/bb-run persona export-headers
   ```
   This writes per-persona header files to `$OUTDIR/personas/headers/`. Each file
   contains the full request header set with secrets already stripped.

3. **Validate redaction coverage:**
   ```
   python3 -c "
   import json
   manifest = json.load(open('$OUTDIR/personas/redacted_manifest.json'))
   for p in manifest:
       assert '[REDACTED]' in str(p.get('credential','')), f\"{p['id']} not redacted\"
   print(f'{len(manifest)} personas redacted')
   "
   ```

4. Copy the redacted headers into the evidence bundle:
   ```
   cp -r $OUTDIR/personas/headers/* $EVIDENCE_DIR/
   ```

## Verification

- `redacted_manifest.json` exists and every credential field contains `[REDACTED]`.
- `headers/` directory has one header file per imported persona.
- No raw cookie, token, or API key appears in any file under `headers/`:
  ```
  grep -rl 'session=\|Bearer \|Api-Key' $OUTDIR/personas/headers/  # should return nothing
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `grep` finds secrets in headers | Redaction step skipped | Run `redact-secrets` before `export-headers` |
| Some personas missing from headers | Credential import failed earlier | Re-run `import-cookie` then `redact-secrets` |
| `redacted_manifest.json` empty | No credentials imported | Import at least one persona first |
| Headers file empty | Persona creds expired during export | Re-validate sessions and re-export |