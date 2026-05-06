# Map Vulnerability to Standard

For every vulnerability found, map it to the relevant external standards for the coverage ledger.

## Mapping Table

| Vulnerability Class    | WSTG Tests                   | ASVS Chapter | API Top 10   | CWE IDs        | Bugcrowd VRT                        |
| ---------------------- | ---------------------------- | ------------ | ------------ | -------------- | ---------------------------------- |
| Reflected XSS          | WSTG-INPV-01                 | V3           | -            | CWE-79         | cross_site_scripting_xss.reflected_xss |
| Stored XSS             | WSTG-INPV-02                 | V3           | -            | CWE-79         | cross_site_scripting_xss.stored_xss    |
| SQL Injection          | WSTG-INPV-05                 | V1           | -            | CWE-89         | injection.sql_injection               |
| Command Injection      | WSTG-INPV-12                 | V1           | -            | CWE-78         | injection.command_injection           |
| SSRF                   | WSTG-INPV-19                 | V4           | API7:2023    | CWE-918        | server_security_misconfiguration.server_side_request_forgery_ssrf |
| IDOR                   | WSTG-ATHZ-04                 | V8           | API1:2023    | CWE-639        | broken_access_control.insecure_direct_object_references_idor |
| Path Traversal         | WSTG-ATHZ-01                 | V8           | -            | CWE-22         | broken_access_control.path_traversal   |
| CSRF                   | WSTG-SESS-05                 | V3           | -            | CWE-352        | cross_site_request_forgery_csrf        |
| Auth Bypass            | WSTG-ATHN-04                 | V6           | API2:2023    | CWE-287        | broken_authentication_and_session_management.authentication_bypass |
| File Upload RCE        | WSTG-BUSL-08, WSTG-BUSL-09   | V5           | -            | CWE-434        | -                                    |
| CORS Misconfig         | WSTG-CLNT-07                 | V3           | -            | CWE-942        | broken_access_control.cors_misconfiguration |
| JWT Weakness           | WSTG-SESS-10                 | V7           | API2:2023    | CWE-347        | broken_authentication_and_session_management.jwt_misconfiguration |
| Rate Limit Missing     | WSTG-BUSL-10                 | V2           | API4:2023    | CWE-770        | denial_of_service.resource_exhaustion  |
| Mass Assignment        | WSTG-INPV-20                 | V4           | API3:2023    | CWE-915        | -                                    |
| SSTI                   | WSTG-INPV-18                 | V1           | -            | CWE-1336       | injection.ssti_injection              |
| Prototype Pollution    | WSTG-INPV-21                 | V3           | -            | CWE-1321       | -                                    |
| Open Redirect          | WSTG-CLNT-04                 | V3           | -            | CWE-601        | unvalidated_redirects_and_forwards.open_redirect |
| Clickjacking           | WSTG-CLNT-09                 | V3           | -            | CWE-1021       | cross_site_scripting_xss               |
| HTTP Smuggling         | WSTG-INPV-15                 | V2           | -            | CWE-444        | -                                    |
| XXE                    | WSTG-INPV-07                 | V4           | -            | CWE-611        | injection.xml_external_entity_xxe     |
| Insecure Deserialization | WSTG-INPV-11               | V1           | -            | CWE-502        | insecure_deserialization              |
| Sensitive Data Exposure | WSTG-INFO-05, WSTG-CONFIG-03 | V12          | -            | CWE-200        | sensitive_data_exposure               |
| Weak TLS               | WSTG-CRYP-01                 | V9           | -            | CWE-295        | server_security_misconfiguration.poor_tls_configuration |
| LLM Prompt Injection   | -                            | V14          | -            | CWE-94         | -                                    |

## Mapping Script

```bash
cd .claude/skills/standard-catalog

# Search for all standards covering a specific vulnerability
python3 scripts/search_standards.py --catalogs-dir catalogs/ --query "XSS"

# Cross-reference WSTG to CWE
python3 scripts/export_references.py --catalogs-dir catalogs/ --output /tmp/xref.json --pretty
cat /tmp/xref.json | jq '.crosswalk | to_entries[] | select(.key | startswith("WSTG-INPV"))'
```

## Adding to Coverage Ledger

When you complete a test, record the standard ID in your coverage ledger:
```yaml
- test: "WSTG-INPV-05"
  standard: "OWASP WSTG Latest"
  status: "completed"
  result: "no vulns found"
  date: "2025-01-15"
```