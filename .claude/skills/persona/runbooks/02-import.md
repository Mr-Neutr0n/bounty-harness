# 02-import: Import Credentials

## Overview

Bind real-world authentication material to a persona role so authenticated
workflows execute with the correct session context. Supports cookies, tokens,
and header-based auth via the `PERSONA_SOURCE` parameter.

## Prerequisites

- Persona manifest initialized (`personas.json` exists with 11 roles).
- `creds/` directory exists under `$OUTDIR/personas/`.
- You have a valid session cookie or token for the target application.

## Steps

1. Choose a persona role from the manifest. Example — pick the `attacker` persona:
   ```
   cat $OUTDIR/personas/personas.json | python3 -c "import json,sys; [print(p['id'], p['role']) for p in json.load(sys.stdin)]"
   ```

2. Extract the cookie value from browser DevTools:
   - Open DevTools → Application → Storage → Cookies.
   - Copy the **full cookie string** (e.g., `session=abc123; csrf=xyz789`).

3. Run the import workflow:
   ```
   bin/bb-run persona import-cookie \
     PERSONA_ID=attacker \
     PERSONA_SOURCE=cookie \
     PERSONA_VALUE="session=abc123; csrf=xyz789"
   ```

   For token-based auth, use:
   ```
   PERSONA_SOURCE=token \
   PERSONA_VALUE="Bearer eyJhbG..."
   ```

   For custom headers:
   ```
   PERSONA_SOURCE=header \
   PERSONA_VALUE="X-Api-Key: sk-live-..."
   ```

4. The workflow writes the credential file to `$OUTDIR/personas/creds/<PERSONA_ID>.json`.

## Verification

- A credential file exists for the persona:
  ```
  ls -la $OUTDIR/personas/creds/attacker.json
  ```
- File contents contain the credential value and metadata (source type, import timestamp):
  ```
  python3 -c "import json; print(json.load(open('$OUTDIR/personas/creds/attacker.json')).keys())"
  ```
- The credential does **not** appear in plaintext in any log or stdout.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `PERSONA_ID not found` | Persona ID doesn't match manifest | Run `init-personas` first or check spelling |
| File not written | Permission issue on `creds/` | `chmod 755 $OUTDIR/personas/creds` |
| Import succeeds but auth fails | Cookie expired or truncated | Re-extract full cookie string from DevTools |
| `PERSONA_SOURCE` rejected | Unrecognized source type | Valid values: `cookie`, `token`, `header` |