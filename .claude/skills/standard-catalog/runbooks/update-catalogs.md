# Update Catalogs

How to keep the standard catalogs up to date when new versions are released.

## When to Update

- **OWASP WSTG**: Check every 6 months for new version. Source: `https://owasp.org/www-project-web-security-testing-guide/`
- **OWASP ASVS**: When new major version is tagged. Source: `https://github.com/OWASP/ASVS/releases`
- **OWASP API Top 10**: When new edition is published. Source: `https://owasp.org/API-Security/`
- **Bugcrowd VRT**: When new version announced. Source: `https://bugcrowd.com/vulnerability-rating-taxonomy`
- **CWE Top 25**: Published annually. Source: `https://cwe.mitre.org/top25/`
- **CISA KEV**: Updated continuously. Source: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- **PortSwigger Topics**: Check quarterly for new labs. Source: `https://portswigger.net/web-security/all-topics`
- **OWASP MASVS**: When new version released. Source: `https://mas.owasp.org/MASVS/`

## Update Procedure

1. Clone/check for new versions of each source
2. Extract IDs, names, and structure
3. Update the corresponding YAML file in `catalogs/`
4. Run validation:
   ```bash
   python3 scripts/validate_catalog.py --catalogs-dir catalogs/
   ```
5. Check for breaking changes:
   ```bash
   python3 scripts/export_references.py --catalogs-dir catalogs/ --output /tmp/new.json --pretty
   diff <(python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "" --json) <(git show HEAD:catalogs/...)
   ```
6. Commit with message: `catalogs: update {standard} to version {version}`

## YAML Format Rules

- All entries MUST have `id` and `name` fields
- Use dot-notation for hierarchical IDs (e.g., `V1.1`, `WSTG-INFO-01`)
- Source URL must be current and verifiable
- Version must match the upstream project's version tag