# Workflow: Generate Intelligence Report

## Purpose
Produce a comprehensive intelligence report combining all sources: CVEs, advisories, disclosed reports, PoCs, and security news.

## Prerequisites
- `$TARGET` and optionally `$PROGRAM` set in context
- Internet connectivity

## Execution
```bash
bin/bb-run vuln-intel generate-report
```

## What It Does
1. Runs `search-cves` for CVE intelligence
2. Runs `search-reports` for disclosed bounty reports
3. Runs `search-news` for security news
4. Searches GitHub for PoCs for top CVEs
5. Aggregates everything into a single JSON report

## Output Structure
```json
{
  "summary": {
    "cve_count": 12,
    "advisory_count": 3,
    "h1_report_count": 5,
    "poc_count": 8,
    "news_count": 4
  },
  "cves": [...],
  "advisories": [...],
  "disclosed_reports": [...],
  "pocs": [...],
  "news": [...]
}
```

## Next Steps
- Run `correlate-techniques` to map to test techniques
- Feed report into `planner generate-plan-safe` for prioritized testing
