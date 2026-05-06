# 01-init: Initialize Persona Manifest

## Overview

Bootstrap the persona system by generating the canonical `personas.json` manifest
and creating the credential storage directory. This is a one-time setup per target.

## Prerequisites

- `bin/bb-init` must have been run for the current target.
- `TARGET` and `OUTDIR` must be set in `.bb/context.env`.
- The persona skill must be present at `.claude/skills/persona/`.

## Steps

1. Load context if not already active:
   ```
   source .bb/context.env
   ```

2. Run the persona initialization workflow:
   ```
   bin/bb-run persona init-personas
   ```

3. The workflow generates two artifacts:
   - `$OUTDIR/personas/personas.json` — canonical manifest of 11 persona roles.
   - `$OUTDIR/personas/creds/` — empty directory for credential storage.

4. Inspect the manifest to confirm role coverage:
   ```
   python3 -c "import json; roles = json.load(open('$OUTDIR/personas/personas.json')); print(f'Loaded {len(roles)} roles')"
   ```

## Verification

- `personas.json` exists and contains exactly **11** persona roles.
- Each role entry has `id`, `role`, `description`, and `priority` fields.
- The `creds/` directory exists and is empty.

  ```
  ls -la $OUTDIR/personas/personas.json
  ls -la $OUTDIR/personas/creds/
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `bb-run` unknown workflow | Skill not loaded or wrong directory | Verify `.claude/skills/persona/skill.yaml` exists |
| `personas.json` empty or missing | Workflow exited early | Run `bb-run` with `--verbose` and check stderr |
| Less than 11 roles | Template schema missing entries | Re-pull the skill package or diff against `skill.yaml` |
| `OUTDIR` unset | Context not sourced | Run `source .bb/context.env` first |