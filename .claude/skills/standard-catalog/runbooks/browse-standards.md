# Browse Standards

Use the standard catalog to explore and map testing standards to your target.

## Browse by Standard

```bash
cd .claude/skills/standard-catalog

# List all catalogs
ls catalogs/

# View a specific catalog in YAML
cat catalogs/wstg_latest.yaml

# Open source URL for WSTG
open "https://owasp.org/www-project-web-security-testing-guide/latest/"
```

## Search Across Standards

```bash
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "injection"
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "authentication" --json | jq .
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "XSS" --file wstg_latest.yaml
```

## Quick Lookups

```bash
# Find what WSTG tests cover a particular area
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "SSRF"

# Cross-reference ASVS chapter sections
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "V6" --file asvs_5.0.yaml

# Find CWE by name
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "injection" --file cwe_top50.yaml
```

## Export for Reporting

```bash
python3 scripts/export_references.py --catalogs-dir catalogs/ --output /tmp/references.json --pretty
cat /tmp/references.json | jq '.summary'
```