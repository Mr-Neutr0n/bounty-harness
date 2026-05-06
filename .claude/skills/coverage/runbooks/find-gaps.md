# Find Gaps — Runbook

## Purpose

Identify the highest-priority items that have zero coverage. Answers: "what should we build next?"

## Prerequisites

- Python 3 with PyYAML
- `coverage_matrix.yaml` exists

## Steps

### 1. Run gap finder (JSON mode for programmatic use)

```bash
python3 .claude/skills/coverage/scripts/gap_finder.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/gaps.json \
  --format json
```

### 2. Read gap summary

```bash
cat output/coverage/gaps.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
gaps=d['high_priority_gaps']
print(f'High-priority gaps: {len(gaps)}')
for g in gaps[:10]:
    print(f'  [{g[\"priority_gap\"].upper():>8s}] {g[\"id\"]:20s} {g[\"name\"]}')
"
```

### 3. Read suggested next skills

```bash
cat output/coverage/gaps.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d['suggested_skills'][:5]:
    print(f'{s[\"category\"]:30s} -> {s[\"suggested_skill\"]:30s} ({s[\"gap_count\"]} gaps) [{s[\"priority\"]}]')
"
```

### 4. Generate markdown for human-readable output

```bash
python3 .claude/skills/coverage/scripts/gap_finder.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/gaps.md \
  --format markdown
```

### 5. Triage recommendations

Look at the `suggested_skills` array. Each entry has:
- `category` — what area to cover
- `suggested_skill` — proposed skill name
- `gap_count` — how many gaps this would close
- `gaps` — individual WSTG/ASVS items

**Decision rule**: Build the skill with the most gaps first, unless a `critical` priority gap exists in another category — then build that one first.

## Output

- `output/coverage/gaps.json` — machine-readable gap analysis
- `output/coverage/gaps.md` — human-readable gap report