# Reference Cheatsheet

Quick-lookup table for all standards in the catalog.

## Standards Inventory

| Standard              | File                       | Version  | Source                                         |
| --------------------- | -------------------------- | -------- | ---------------------------------------------- |
| OWASP WSTG            | wstg_latest.yaml           | latest   | owasp.org/www-project-web-security-testing-guide |
| OWASP ASVS            | asvs_5.0.yaml              | 5.0.0    | github.com/OWASP/ASVS                          |
| OWASP API Top 10      | api_top10_2023.yaml        | 2023     | owasp.org/API-Security                         |
| Bugcrowd VRT          | bugcrowd_vrt_1.18.yaml     | 1.18     | bugcrowd.com/vulnerability-rating-taxonomy      |
| CWE Top 25            | cwe_top50.yaml             | 2024     | cwe.mitre.org/top25                            |
| CISA KEV              | cisa_kev_vendors.yaml      | -        | cisa.gov/known-exploited-vulnerabilities-catalog |
| PortSwigger Academy   | portswigger_topics.yaml    | -        | portswigger.net/web-security/all-topics         |
| OWASP MASVS           | masvs_categories.yaml      | 2.0.0    | mas.owasp.org/MASVS                            |

## Severity Mapping

See `payloads/severity_mapping.txt` for Bugcrowd VRT severity to CVSS mapping.

## Common WSTG IDs to CWE

| WSTG Test      | CWE          |
| -------------- | ------------ |
| INPV-01, INPV-02, CLNT-01, CLNT-03 | CWE-79 (XSS) |
| INPV-05        | CWE-89 (SQLi) |
| INPV-12        | CWE-78 (Cmd Inj) |
| INPV-18        | CWE-1336 (SSTI) |
| INPV-19        | CWE-918 (SSRF) |
| ATHZ-01        | CWE-22 (Path Trav) |
| ATHZ-04        | CWE-639 (IDOR) |
| SESS-05        | CWE-352 (CSRF) |
| BUSL-10        | CWE-770 (Rate Limit) |

## Common ASVS Cross-Reference

| ASVS    | Bugcrowd VRT                               | Skill Mapping  |
| ------- | ------------------------------------------ | -------------- |
| V1      | injection.*                                | sqli, rce      |
| V3      | cross_site_scripting_xss.*, cors_misconfig | xss, cors-csrf |
| V4      | ssrf, api issues                           | ssrf, api      |
| V5      | file upload issues                         | file-upload    |
| V6      | broken_authentication_and_session_management.* | auth       |
| V7      | session management                         | auth           |
| V8      | broken_access_control.*                    | auth, api      |

## Using with Skills

```bash
# Before running XSS tests, check what standards apply:
python3 scripts/search_standards.py --catalogs-dir .claude/skills/standard-catalog/catalogs/ --query "cross-site"

# Before reporting, export references for appendices:
python3 scripts/export_references.py --catalogs-dir .claude/skills/standard-catalog/catalogs/ --output output/references.json --pretty
```