# Workflow: Correlate with Technique-KB

## Purpose
Map discovered CVEs and vulnerabilities to actionable test techniques from the technique knowledge base.

## Prerequisites
- Intelligence report generated (`$OUTDIR/vuln-intel/intel_report.json`)
- Technique-kb directory exists (default: `.claude/skills/technique-kb/`)

## Execution
```bash
bin/bb-run vuln-intel correlate-techniques
```

## What It Does
1. Reads the intel report
2. Loads all technique-kb YAML entries
3. Matches CVE descriptions against technique tags and names
4. Outputs correlation mapping with confidence scores

## Output Example
```json
{
  "correlation_count": 5,
  "correlations": [
    {
      "cve_id": "CVE-2024-1234",
      "technique": "JWT Algorithm Confusion",
      "technique_id": "AUTH-003",
      "confidence": "medium"
    }
  ]
}
```

## Next Steps
- Use correlations to build targeted test plans
- Run `planner generate-plan-safe` with technique priorities
