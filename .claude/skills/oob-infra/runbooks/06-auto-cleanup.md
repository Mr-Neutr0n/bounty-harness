# Workflow: Auto-Cleanup

## Purpose
Cleanly shut down OOB client and export all evidence before ending the session.

## Execution
```bash
bin/bb-run oob-infra auto-cleanup
```

## What It Does
1. Stops the interactsh client session
2. Runs final poll for any lingering interactions
3. Exports all correlated evidence to `$OUTDIR/oob/evidence/`

## When to Use
- At the end of every engagement
- Before switching to a different target
- When you need to free up the interactsh session

## Evidence Output
- `correlation.jsonl` — All matched interactions with canary metadata
- Individual correlation directories with full interaction data

## Next Steps
- Review `$OUTDIR/oob/evidence/` for confirmed findings
- Feed confirmed OOB callbacks into `impact-verifier`
- Include evidence in final report via `reporting` skill
