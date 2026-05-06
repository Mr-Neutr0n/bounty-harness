# Runbook: Plan vs Results

## Purpose
Compare expected outcomes from a plan against actual execution results.
Produce a coverage delta, identify false positive/negative patterns, and feed
back into the coverage matrix for future plan generation.

## Prerequisites
- Plan JSON (`plan.json`)
- Results JSON directory (per-workflow result files from execution)
- Coverage matrix JSON (will be updated)

## Steps

### 1. Collate results
```bash
python3 -c "
import json, sys
plan = json.load(open('plan.json'))
results_path = sys.argv[1] if len(sys.argv) > 1 else 'results/'
print(f'Plan items: {len(plan[\"plan_items\"])}')
"
```

### 2. Compute coverage delta

For each plan item, compare:
| Planned | Actual | Outcome |
|---------|--------|---------|
| Not executed | | `skipped` |
| Executed, positive signal expected | Positive signal found | `confirmed` |
| Executed, positive signal expected | Negative/neutral result | `false_positive_plan` |
| Executed, negative signal expected | Negative result confirmed | `clean` (true negative) |
| Executed, negative signal expected | Positive signal found | `finding` (true positive, unplanned) |

### 3. Update coverage matrix

```python
# Pseudologic for updating coverage matrix
covered = []
partial = []
missing = []

for item in executed_plan_items:
    if item.outcome == "confirmed":
        covered.append(item.technique_id)
    elif item.outcome == "clean":
        partial.append(item.technique_id)
    else:
        missing.append(item.technique_id)

# Add any unplanned findings as new entries
for finding in unplanned_findings:
    covered.append(finding.technique_id)
```

```bash
python3 -c "
import json
# Update coverage matrix from execution results
matrix = {'covered': [], 'partial': [], 'missing': [], 'updated_at': ''}
# ... load existing, merge with results, save
with open('coverage.json', 'w') as f:
    json.dump(matrix, f, indent=2)
print('Coverage matrix updated')
"
```

### 4. Generate comparison report

Key metrics:
- **Execution rate:** items executed / items planned
- **Confirmation rate:** confirmed findings / executed items
- **False positive rate (plan):** false_positive_plan / executed items
- **Unplanned findings:** discoveries not in the plan
- **Coverage improvement:** (coverage_after - coverage_before) from plan vs actual

### 5. Triage Questions

| Observation | Implication |
|-------------|-------------|
| High unplanned findings | Domain model is incomplete or technique catalog has gaps |
| High false positive rate (plan) | Over-scoring; adjust ranking weights or signal quality scores |
| Low execution rate for auth items | Auth configuration needs improvement |
| Many skipped items | Plan was too aggressive; tighten preconditions |

## Output

### Updated coverage matrix
Saved to the standard coverage location (typically `output/TARGET/coverage.json`):
```json
{
  "covered": ["technique-id-1", "technique-id-2"],
  "partial": ["technique-id-3"],
  "missing": ["technique-id-4"],
  "updated_at": "ISO 8601"
}
```

### Plan-vs-results report
A markdown report saved alongside the plan for historical tracking:
```markdown
# Plan vs Results: TARGET — DATE

| Technique | Priority | Expected | Actual | Notes |
|-----------|----------|----------|--------|-------|
| xss-001 | critical | positive | confirmed | Reflected in search param |
| sqli-001 | high | positive | clean | Parameterized queries detected |
```

## Next Step
After updating the coverage matrix, the next `generate_plan.py` run will use updated coverage data for more accurate priorities.