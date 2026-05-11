# Workflow: Track and Diff Scope

## Purpose
Version control your scope file and detect changes between engagements or program updates.

## Execution
```bash
# Save current scope snapshot
bin/bb-run scope-manager track-scope

# Check for changes since last snapshot
bin/bb-run scope-manager check-changes
```

## What It Does
1. `track-scope`: Records scope file content + SHA-256 hash to `.bb/scope_history.jsonl`
2. `check-changes`: Compares latest snapshot with previous, shows additions/removals

## Why This Matters
Bug bounty programs frequently update scope:
- New subdomains added
- APIs opened or closed
- Out-of-scope items clarified
- Rate limits changed

Tracking prevents you from testing old OOS items or missing newly in-scope assets.

## Output Example
```json
{
  "added": {
    "in_scope": ["new-api.example.com"],
    "wildcards": ["*.cdn.example.com"]
  },
  "removed": {
    "in_scope": ["legacy.example.com"]
  },
  "has_changes": true
}
```

## Next Steps
- Run `check-changes` at the start of each testing session
- If changes detected, re-run `recon passive-subdomains` for new assets
