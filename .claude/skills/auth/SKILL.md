# Auth

## Overview
Authentication and authorization testing — JWT attacks, OAuth 2.0, SAML, session management, 2FA bypass, password reset, IDOR, privilege escalation

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `auth`
- Severity range: `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `python3`, `jwt_tool`, `openssl`, `jq`, `hashcat`
- Expected input files: `auth_pages.txt`, `all_urls.txt`, `js_files.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `jwt-analysis` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `jwt-analysis` | Decode a supplied JWT and optionally generate safe attack variants. | `.claude/skills/auth/scripts/jwt_analyzer.py` | `$OUTDIR/auth/jwt/findings.jsonl` | `$OUTDIR/auth/jwt/evidence/` |
| `jwt-attack-matrix` | Test JWT none, HS/RS confusion, and replay against an optional target URL. | `.claude/skills/auth/scripts/jwt_attack_matrix.py` | `$OUTDIR/auth/jwt/attack_findings.jsonl` | `$OUTDIR/auth/jwt/evidence/` |
| `oauth-redirects` | Test OAuth authorization redirect URI bypass variants. | `.claude/skills/auth/scripts/oauth_redirect_matrix.py` | `$OUTDIR/auth/oauth/findings.jsonl` | `$OUTDIR/auth/oauth/evidence/` |
| `mfa-flow` | Probe MFA-protected access, OTP reuse, and resend rate limiting. | `.claude/skills/auth/scripts/mfa_flow_tester.py` | `$OUTDIR/auth/mfa/findings.jsonl` | `$OUTDIR/auth/mfa/evidence/` |
| `auth-race` | Send concurrent requests to a selected auth-sensitive endpoint. | `.claude/skills/auth/scripts/auth_race_tester.py` | `$OUTDIR/auth/race/results.json` | `$OUTDIR/auth/race/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `jwt_forge`: Forged JWT token + successful access response
- `oauth_bypass`: Redirect URI bypass request/response with stolen code
- `idor_data`: Response body showing another user's private data

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-ATHN-01`, `WSTG-ATHN-02`, `WSTG-ATHN-03`, `WSTG-ATHN-04`, `WSTG-ATHN-05`, `WSTG-ATHN-06`, `WSTG-ATHN-07`, `WSTG-ATHN-08`, `WSTG-ATHN-09`, `WSTG-ATHN-10`, `WSTG-ATHZ-01`, `WSTG-ATHZ-02`, `WSTG-ATHZ-03`, `WSTG-ATHZ-04`
- OWASP API Top 10: `API1:2023`, `API2:2023`, `API3:2023`, `API5:2023`
