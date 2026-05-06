# Check Coverage — Runbook

## Purpose

Run a quick coverage health check. Answers: "what's our current state?"

## Prerequisites

- Python 3 with PyYAML (`pip3 install pyyaml`)
- `coverage_matrix.yaml` exists at `.claude/skills/coverage/coverage_matrix.yaml`

## Steps

### 1. Run the calculator

```bash
python3 .claude/skills/coverage/scripts/coverage_calculator.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/stats.json
```

### 2. Read top-level stats

```bash
cat output/coverage/stats.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d['summary']
print(f'Total items: {s[\"total_items\"]}')
print(f'Covered: {s[\"covered\"]} ({s[\"overall_covered_percentage\"]}%)')
print(f'Partial: {s[\"partial\"]}')
print(f'Missing: {s[\"missing\"]}')
print(f'Manual: {s[\"manual\"]}')
print(f'Any Coverage: {s[\"overall_any_coverage_percentage\"]}%')
"
```

### 3. Per-standard drill-down

```bash
cat output/coverage/stats.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for std in d['standards']:
    s=std['stats']
    print(f'{std[\"standard\"]:20s} {s[\"covered_percentage\"]:5.1f}% covered  ({s[\"total\"]:3d} items)')
"
```

### 4. Quick triage

If `overall_covered_percentage < 30%` → run `find-gaps` next.
If `overall_any_coverage_percentage > 75%` → good breadth; prioritize deepening partial items.
If any standard has a `covered` count of 0 → critical infrastructure gap.

## Output

A quick terminal dashboard showing coverage health at a glance.