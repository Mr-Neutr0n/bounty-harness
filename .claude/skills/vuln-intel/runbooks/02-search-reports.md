# Workflow: Search Disclosed Reports

## Purpose
Find publicly disclosed bug bounty reports for your target program on HackerOne and Bugcrowd.

## Prerequisites
- Program name set in `$PROGRAM` context variable
- Internet connectivity

## Execution
```bash
bin/bb-run vuln-intel search-reports
```

## What It Does
1. Searches DuckDuckGo for disclosed reports on specified platforms
2. Extracts report IDs, titles, and URLs
3. Outputs structured JSON to `$OUTDIR/vuln-intel/reports.json`

## Interpreting Results
- **Recent reports** → Active attack surface, known vulnerability classes
- **Old reports** → Historical context, may indicate recurring issues
- **Report titles** → Reveal endpoint names, parameter names, feature areas

## Next Steps
- Read full reports to understand methodology
- Check if reported vulnerabilities are fully patched
- Run `generate-report` for comprehensive view
