# Recon

## Overview
Full-stack reconnaissance for bug bounty targets — subdomains, DNS, ports, tech, crawling, URLs, JS, and asset inventory

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `recon`
- Severity range: `info`, `low`, `medium`
- Required tools: `subfinder`, `amass`, `httpx`, `katana`, `gau`, `waybackurls`, `dnsx`, `naabu`, `nmap`, `wafw00f`, `openssl`, `jq`, `curl`, `python3`
- Expected input files: `all_unique.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `passive-subdomains` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `passive-subdomains` | Enumerate passive subdomains for a target domain. | `.claude/skills/recon/scripts/subdomain_enum.py` | `$OUTDIR/recon/subdomains/subs.txt`<br>`$OUTDIR/recon/subdomains/findings.jsonl` | `$OUTDIR/recon/subdomains/evidence/` |
| `live-discovery` | Probe enumerated subdomains for live HTTP services. | `.claude/skills/recon/scripts/live_discovery.py` | `$OUTDIR/recon/live/live_hosts.txt`<br>`$OUTDIR/recon/live/live_full.csv`<br>`$OUTDIR/recon/live/findings.jsonl` | `$OUTDIR/recon/live/evidence/` |
| `js-recon` | Extract JavaScript URLs, download bundles, and scan for endpoints or secrets. | `.claude/skills/recon/scripts/js_recon.py` | `$OUTDIR/recon/js/js_files.txt`<br>`$OUTDIR/recon/js/js_secrets.txt`<br>`$OUTDIR/recon/js/js_endpoints.txt`<br>`$OUTDIR/recon/js/findings.jsonl` | `$OUTDIR/recon/js/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `takeover_candidate`: DNS CNAME chain + HTTP probe + screenshot
- `open_admin_panel`: Full curl with headers + screenshot + timestamp
- `zone_transfer`: Full AXFR dump with NS server info and timestamp

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INFO-01`, `WSTG-INFO-02`, `WSTG-INFO-03`, `WSTG-INFO-04`, `WSTG-INFO-05`, `WSTG-INFO-06`, `WSTG-INFO-07`, `WSTG-INFO-08`, `WSTG-INFO-09`, `WSTG-INFO-10`
