# Update Matrix — Runbook

## Purpose

Keep `coverage_matrix.yaml` current when new skills or scripts are added to the toolkit.

## When to Update

Run this every time you:
- Create a new skill
- Add a new workflow to an existing skill
- Add a new Python script to any skill
- Close a previously-missing gap
- Change tooling that affects coverage

## Steps

### 1. Identify what changed

Ask: "What standard items does the new code cover?"

Find the relevant items in `coverage_matrix.yaml` by searching:

```bash
grep -n "WSTG-" .claude/skills/coverage/coverage_matrix.yaml
```

Or search for the section you want:

```bash
grep -n "section_name:" .claude/skills/coverage/coverage_matrix.yaml
```

### 2. Update the covered_by entry

For each relevant item, add a new `covered_by` entry:

```yaml
covered_by:
  - skill: "your-skill"
    workflow: "your-workflow"
    scripts: [".claude/skills/your-skill/scripts/your_script.py"]
    status: "covered"
    notes: "What this covers and how"
```

### 3. Upgrade status

If a partial item now has a dedicated workflow with a working script:
- Change `status: "covered"`
- Keep old `partial` entries for historical reference

If a missing item now has any automation:
- Set `status` to `"covered"` if full coverage, `"partial"` if partial

### 4. Update priority_gap

If the new coverage addresses a `high` priority gap, consider updating `priority_gap` to `"medium"` or `"low"`.

### 5. Update metadata

At the top of the matrix:

```yaml
version: "1.1"        # Increment minor for substantive changes
last_updated: "2026-05-XX"  # Current date
toolkit_skills: 20     # If a new skill was added, increment
```

For minor corrections (typos, notes clarity), only update `last_updated`.

### 6. Update statistics

After editing, re-run the calculator to verify:

```bash
python3 .claude/skills/coverage/scripts/coverage_calculator.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/stats_updated.json
```

Compare with previous stats:

```bash
# Before (from earlier run)
python3 -c "import json; d=json.load(open('output/coverage/stats.json')); print(f'Before: {d[\"summary\"][\"overall_covered_percentage\"]}% covered')"
# After
python3 -c "import json; d=json.load(open('output/coverage/stats_updated.json')); print(f'After:  {d[\"summary\"][\"overall_covered_percentage\"]}% covered')"
```

### 7. Update generated stats in matrix

After computing new stats, update the `generated_stats` section at the bottom of `coverage_matrix.yaml` to reflect current numbers.

### 8. Regenerate the report

```bash
python3 .claude/skills/coverage/scripts/coverage_report.py \
  --matrix .claude/skills/coverage/coverage_matrix.yaml \
  --output output/coverage/coverage_report.md
```

## Checklist

- [ ] Searched matrix for relevant WSTG/ASVS items
- [ ] Added `covered_by` entry with skill, workflow, script path, status, notes
- [ ] Updated statuses (partial→covered, missing→partial, etc.)
- [ ] Updated priority_gap if gap is now addressed
- [ ] Updated version and last_updated metadata
- [ ] Re-ran calculator and verified stats improved
- [ ] Updated generated_stats in matrix YAML
- [ ] Regenerated markdown report

## YAML Status Reference

| Status | Meaning |
|---|---|
| `covered` | Dedicated script exists and is tested |
| `partial` | Some coverage via general or indirect methods |
| `manual` | Requires human judgment; not automatable |
| `missing` | No coverage — this is a gap |
| `not_applicable` | Not in scope for black-box bug bounty |