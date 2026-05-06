# Scan Sources Runbook

## Purpose
Check all configured public sources for new content since the last scan.

## Prerequisites
- Python 3 with PyYAML installed
- `git` CLI for GitHub repo checks
- `gh` CLI for GitHub release checks (authenticated)
- `curl` for HTTP source checks

## Command

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
python3 .claude/skills/auto-research/scripts/source_scanner.py \
  --sources .claude/skills/auto-research/sources.yaml \
  --cache-dir .claude/skills/auto-research/cache/ \
  --output .claude/skills/auto-research/cache/scan_result.json
```

## What It Does
1. Reads `sources.yaml` to get the list of configured sources
2. Loads `cache/source_state.json` to get last-seen state for each source
3. For each source, fetches the current state identifier (commit SHA, release tag, or Last-Modified header)
4. Compares current state to cached state
5. Writes results to `scan_result.json`

## Output: scan_result.json
```json
{
  "scan_time": "ISO-8601 timestamp",
  "total_sources": 11,
  "changed": [
    {"id": "source-id", "reason": "state_changed|first_check", "current_state": "..."},
    ...
  ],
  "unchanged": 5,
  "errors": [],
  "changed_count": 6
}
```

## Triage
- **changed > 0**: Proceed to extraction step
- **changed == 0**: Nothing new. Wait until next scheduled check.
- **errors > 0**: Investigate connectivity or auth issues.

## Schedule
- Daily: cisa-kev
- Weekly: nuclei-templates, portswigger-research
- Monthly: all others