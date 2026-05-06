# Http Protocol

## Overview
HTTP protocol-layer attacks — request smuggling (HTTP/1+2), cache poisoning, cache deception, URL parser differentials, email parser bypasses, TLS 0-RTT replay

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `http-protocol`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `curl`, `python3`, `nc`, `openssl`, `jq`
- Expected input files: `live_urls.txt`, `tech_fingerprint.json`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `http1-smuggling` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `http1-smuggling` | Test CL.TE, TE.CL, and TE.TE HTTP/1.1 request smuggling using Python socket-based probes with obfuscated Transfer-Encoding variants | `.claude/skills/http-protocol/scripts/http_smuggling_probe.py` | `$OUTDIR/http-protocol/smuggling/http1_findings.jsonl` | `$OUTDIR/http-protocol/smuggling/evidence/` |
| `http2-smuggling` | Test H2.CL and H2.TE downgrade smuggling where HTTP/2 frontend connects to HTTP/1.1 backend via Content-Length or Transfer-Encoding injection | `.claude/skills/http-protocol/scripts/http_smuggling_probe.py` | `$OUTDIR/http-protocol/smuggling/http2_findings.jsonl` | `$OUTDIR/http-protocol/smuggling/evidence/` |
| `cache-poisoning` | Test web cache poisoning via unkeyed header injection (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL), fat GET body poisoning, and parameter cloaking | `.claude/skills/http-protocol/scripts/cache_poison_probe.py` | `$OUTDIR/http-protocol/cache/poison_findings.jsonl` | `$OUTDIR/http-protocol/cache/evidence/` |
| `cache-deception` | Test web cache deception attacks where sensitive pages get cached as static files via path confusion (account.css, profile.js, .css/.js extensions on dynamic paths) | `.claude/skills/http-protocol/scripts/cache_deception_probe.py` | `$OUTDIR/http-protocol/cache/deception_findings.jsonl` | `$OUTDIR/http-protocol/cache/evidence/` |
| `url-parser-differential` | Test URL parser differentials — backslash vs forward slash normalization, URL encoding confusion, double encoding, Unicode UTF-8 overlong bypasses, null-byte truncation, path parameter separation | `.claude/skills/http-protocol/scripts/url_parser_differential.py` | `$OUTDIR/http-protocol/url-parser/differential_findings.jsonl` | `$OUTDIR/http-protocol/url-parser/evidence/` |
| `email-parser-bypass` | Test email parser bypasses — encoded @ signs, quoted local-parts, comments in emails, multiple @ signs, backslash escapes, Unicode confusables, display name injection, based on PortSwigger "Splitting the email atom" research | `.claude/skills/http-protocol/scripts/email_parser_bypass.py` | `$OUTDIR/http-protocol/email-parser/bypass_findings.jsonl` | `$OUTDIR/http-protocol/email-parser/evidence/` |
| `early-data-probe` | TLS 1.3 0-RTT early data replay testing — checks if server accepts early data, replays POST requests creating duplicate side effects, detects Early-Data header for GET replay feasibility | `.claude/skills/http-protocol/scripts/early_data_probe.py` | `$OUTDIR/http-protocol/tls/early_data_findings.jsonl` | `$OUTDIR/http-protocol/tls/evidence/` |
| `verify` | Verify protocol findings with raw socket captures and secondary confirmation probes | No script reference in `skill.yaml` command. | `$OUTDIR/http-protocol/verified/manifest.txt` | `$OUTDIR/http-protocol/verified/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `smuggling_curl`: curl -v raw smuggling request/response pair
- `cache_header_dump`: curl -sD headers.txt showing cache hit with poisoned value
- `deception_body`: Full response body showing PII/CSRF tokens in cached static file
- `url_diff_response`: Side-by-side curl of normal vs encoded path responses
- `email_injection_log`: curl log showing crafted email accepted at registration
- `early_data_capture`: openssl s_client early-data send + replay confirmation

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-CONF-01`, `WSTG-ATHZ-01`
- OWASP API Top 10: `API7:2019`, `API8:2019`
