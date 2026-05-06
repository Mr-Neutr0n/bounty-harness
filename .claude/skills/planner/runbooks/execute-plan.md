# Runbook: Execute Plan

## Purpose
Execute workflows from the prioritized plan, collect evidence, and record results.

## Prerequisites
- Reviewed and validated plan JSON (`plan.json`)
- All required tools available and in PATH
- Auth credentials configured for auth-required workflows
- Evidence directory structure created

## Execution Protocol

### Per-Workflow Execution

For each plan item, in priority order:

1. **Safety gate check**
   - Verify scope before running
   - If `INTRUSIVE` or `DESTRUCTIVE`, confirm explicit approval
   - `RATE-LIMITED` items: ensure rate limiting is configured
   - `CONFIRM-REQ` items: review expected signals before running

2. **Tool check**
   ```bash
   for tool in <tools_from_plan>; do
     command -v "$tool" >/dev/null && echo "ok  $tool" || echo "MISSING $tool"
   done
   ```

3. **Execute the workflow**
   - Follow the workflow command from the referenced skill's `skill.yaml`
   - Substitute `TARGET`, `OUTDIR`, and other variables from the plan context
   - Record execution timestamp

4. **Collect evidence**
   - Save raw request/response
   - Take screenshots where applicable
   - Record tool versions used
   - Save finding to evidence directory

5. **Record results**
   - Mark item as `executed`, `found`, `not_found`, `error`, or `skipped`
   - Note any false positives detected
   - Log any unexpected behavior

### Execution Order

```
Phase 1: CRITICAL, safe, non-intrusive, no auth
Phase 2: CRITICAL with auth
Phase 3: HIGH, safe, non-intrusive, no auth
Phase 4: HIGH with auth
Phase 5: MEDIUM as time permits
Phase 6: LOW only if they fill critical coverage gaps
```

### Recording Results

Create a results JSON per executed plan item:
```json
{
  "plan_item_id": "technique-id",
  "executed_at": "ISO 8601",
  "status": "found|not_found|error|skipped",
  "evidence_paths": ["/path/to/evidence/"],
  "notes": "free-text observations"
}
```

## Pausing and Resuming

To pause execution:
- Record the last completed plan item index
- Save all evidence and results collected so far
- Note any items skipped and why

To resume:
- Start from the next unexecuted item in priority order
- Re-verify tool availability and auth

## After Execution

Run `plan-vs-results.md` to compare expected vs actual findings and update the coverage matrix.

## Commands Reference

### Execute a single workflow from the plan
```bash
# Extract a specific plan item
python3 -c "
import json
with open('plan.json') as f:
    plan = json.load(f)
item = next(i for i in plan['plan_items'] if i['technique_id'] == 'TECHNIQUE_ID')
print(json.dumps(item, indent=2))
"
```

### Verify tools for a specific plan item
```bash
# Extract tools list and check availability
python3 -c "
import json, shutil
with open('plan.json') as f:
    plan = json.load(f)
items = [i for i in plan['plan_items'] if i['priority'] in ('critical', 'high')]
for item in items:
    tools = item.get('preconditions', {}).get('tools', [])
    for tool in tools:
        found = shutil.which(tool.split()[0])
        print(f\"{'ok' if found else 'MISSING'} {tool}\")
"
```