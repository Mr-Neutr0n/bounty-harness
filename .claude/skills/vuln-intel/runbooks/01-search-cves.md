# Workflow: Search CVEs

## Purpose
Search the National Vulnerability Database (NVD) for CVEs related to your target within a configurable lookback period.

## Prerequisites
- Target domain or product name set in context
- Internet connectivity (NVD API is queried)

## Execution
```bash
bin/bb-run vuln-intel search-cves
```

## What It Does
1. Queries NVD API for CVEs matching target keyword
2. Filters by publication date (default: last 60 days)
3. Filters by minimum CVSS score (default: 0.0 = all)
4. Extracts CVE ID, description, CVSS score, severity, references
5. Outputs structured JSON to `$OUTDIR/vuln-intel/cves.json`

## Interpreting Results
- **High/Critical CVEs** → Immediate test priority
- **Medium CVEs** → Check if target uses affected component/version
- **Low/Info CVEs** → Background context, may indicate tech stack

## Next Steps
- Run `search-pocs` to find exploit code
- Run `correlate-techniques` to map to testable techniques
