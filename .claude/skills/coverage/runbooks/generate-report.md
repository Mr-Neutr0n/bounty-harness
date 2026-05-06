# Generate Report — Runbook

## Purpose

Produce a comprehensive markdown coverage report suitable for sharing, tracking trends, or pasting into planning discussions.

## Prerequisites

- Python 3 with PyYAML
- `coverage_matrix.yaml` exists and is current

## Steps

### 1. Generate the report

```bash
python3 .claude/skills/coverage/scripts/coverage_report.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/coverage_report.md \
  --format markdown
```

### 2. Generate JSON version (for dashboards/automation)

```bash
python3 .claude/skills/coverage/scripts/coverage_report.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/coverage_report.json \
  --format json
```

### 3. Review key sections of the report

The report contains these sections:

1. **Overall Dashboard** — total items, covered %, any-coverage %, status bar
2. **Per-Standard Breakdown** — table of WSTG/ASVS/API Top 10/VRT with counts per status
3. **Top 10 Priority Gaps** — the highest-urgency missing items
4. **Recommendations** — suggested skill builds ranked by impact
5. **Low Hanging Fruit** — partial items with high-priority gaps

### 4. Trend tracking

To track coverage over time, save dated snapshots:

```bash
DATE=$(date -u +%Y-%m-%d)
mkdir -p output/coverage/trends/
python3 .claude/skills/coverage/scripts/coverage_calculator.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/trends/stats_${DATE}.json
```

Compare with previous snapshots to show improvement.

### 5. Share or export

The markdown report is self-contained. It can be:
- Viewed directly in any markdown renderer
- Converted to PDF via `.claude/skills/make-pdf/SKILL.md`
- Copied into planning docs or GitHub issues
- Used as an evidence artifact in the coverage skill itself

## Output

- `output/coverage/coverage_report.md` — comprehensive markdown report
- `output/coverage/coverage_report.json` — structured JSON export