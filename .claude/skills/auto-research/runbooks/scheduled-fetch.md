# Scheduled Fetch Runbook

## Purpose
Run automated, hands-off pipeline checks on schedule.

## Prerequisites
- Python 3 environment with PyYAML
- `git`, `gh`, `curl` available on PATH
- Cache directory initialized (auto-created if missing)

## Daily Check (CISA KEV + urgent sources)

```bash
#!/bin/bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

SKILL_DIR=".claude/skills/auto-research"
CACHE_DIR="$SKILL_DIR/cache"
DAILY_SOURCES="$CACHE_DIR/daily_sources.yaml"

python3 -c "
import yaml, json
with open('$SKILL_DIR/sources.yaml') as f:
    config = yaml.safe_load(f)
feeds = config['feeds']
daily = [f for f in feeds if f.get('check_frequency') == 'daily']
with open('$DAILY_SOURCES', 'w') as f:
    yaml.dump({'feeds': daily}, f)
print(f'Daily sources: {len(daily)}')
"

python3 "$SKILL_DIR/scripts/source_scanner.py" \
  --sources "$DAILY_SOURCES" \
  --cache-dir "$CACHE_DIR" \
  --output "$CACHE_DIR/daily_scan.json"

echo "Daily scan complete. See $CACHE_DIR/daily_scan.json"
```

## Weekly Check (Nuclei templates + PortSwigger research)

```bash
#!/bin/bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

SKILL_DIR=".claude/skills/auto-research"
CACHE_DIR="$SKILL_DIR/cache"
WEEKLY_SOURCES="$CACHE_DIR/weekly_sources.yaml"

python3 -c "
import yaml, json
with open('$SKILL_DIR/sources.yaml') as f:
    config = yaml.safe_load(f)
feeds = config['feeds']
weekly = [f for f in feeds if f.get('check_frequency') == 'weekly']
with open('$WEEKLY_SOURCES', 'w') as f:
    yaml.dump({'feeds': weekly}, f)
print(f'Weekly sources: {len(weekly)}')
"

python3 "$SKILL_DIR/scripts/source_scanner.py" \
  --sources "$WEEKLY_SOURCES" \
  --cache-dir "$CACHE_DIR" \
  --output "$CACHE_DIR/weekly_scan.json"

echo "Weekly scan complete. See $CACHE_DIR/weekly_scan.json"
```

## Monthly Check (Full pipeline)

```bash
#!/bin/bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

SKILL_DIR=".claude/skills/auto-research"
CACHE_DIR="$SKILL_DIR/cache"
TECHNIQUES_DIR="path/to/technique-kb"

python3 "$SKILL_DIR/scripts/batch_importer.py" \
  --sources "$SKILL_DIR/sources.yaml" \
  --cache-dir "$CACHE_DIR" \
  --techniques-dir "$TECHNIQUES_DIR" \
  --rules "$SKILL_DIR/ingest_rules.yaml" \
  --output "$CACHE_DIR/monthly_batch.json"

echo "Monthly batch complete. See $CACHE_DIR/monthly_batch.json"
```

## Crontab Example

```cron
# Daily: CISA KEV check at 08:00 UTC
0 8 * * * /path/to/bug-bounty/.claude/skills/auto-research/cron/daily.sh >> /path/to/logs/auto-research-daily.log 2>&1

# Weekly: Nuclei + PortSwigger at 09:00 UTC Monday
0 9 * * 1 /path/to/bug-bounty/.claude/skills/auto-research/cron/weekly.sh >> /path/to/logs/auto-research-weekly.log 2>&1

# Monthly: Full pipeline at 10:00 UTC on the 1st
0 10 1 * * /path/to/bug-bounty/.claude/skills/auto-research/cron/monthly.sh >> /path/to/logs/auto-research-monthly.log 2>&1
```

## Triage After Scheduled Run

1. Check the output JSON for error entries
2. If sources changed, review extracted candidates
3. Create a GitHub issue or TODO for any new technique that passed review
4. Update the cache retention — remove entries older than 90 days