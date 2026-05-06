# Osint

## Overview
Open Source Intelligence — GitHub dorking, Google dorks, Shodan/Censys, email discovery, WHOIS history, certificate transparency, leaked credentials

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `osint`
- Severity range: `info`, `low`, `medium`
- Required tools: `curl`, `trufflehog`, `gitleaks`, `semgrep`, `python3`, `jq`, `git`, `openssl`, `dnsx`
- Expected input files: `all_unique.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `github-secrets` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `github-secrets` | Search a GitHub organization or user for exposed secrets. | `.claude/skills/osint/scripts/github_secret_scanner.py` | `$OUTDIR/osint/github/findings.jsonl` | `$OUTDIR/osint/github/evidence/` |
| `google-dorks` | Generate and run Google dork queries for a target domain or keyword. | `.claude/skills/osint/scripts/google_dork_runner.py` | `$OUTDIR/osint/google/findings.jsonl` | `$OUTDIR/osint/google/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `github_secret`: GitHub commit URL + line number with exposed secret
- `google_dork`: Google dork URL + screenshot of exposed file
- `email_breach`: HIBP/Holehe output showing password exposed in breach

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INFO-01`, `WSTG-INFO-02`, `WSTG-INFO-10`
