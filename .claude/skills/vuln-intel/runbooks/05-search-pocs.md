# Workflow: Search Proof-of-Concepts

## Purpose
Find GitHub repositories containing exploit code or proof-of-concept scripts for a specific CVE.

## Execution
```bash
bin/bb-run vuln-intel search-pocs
# Or directly:
python3 .claude/skills/vuln-intel/scripts/vuln_intel.py search-pocs --cve CVE-2024-1234
```

## What It Does
1. Queries GitHub Search API for repositories matching the CVE
2. Filters for repos with "poc", "exploit", or "proof-of-concept" in name/description
3. Returns repo metadata: stars, language, last updated

## Interpreting Results
- **High stars + recent update** → Likely working PoC
- **Specific language** → Match your testing environment
- **Fork count** → Community validation

## Safety Note
Always review PoC code before running. Never execute untrusted scripts on production systems.

## Next Steps
- Clone and review promising PoCs in isolated environment
- Adapt PoC to target's specific configuration
- Run `correlate-techniques` to map to testable techniques
