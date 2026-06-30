# Privesc

## Overview
Privilege escalation enumeration and exploitation — Linux SUID, sudo, capabilities, cron, Docker/K8s escape

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `privesc`
- Severity range: `high`, `critical`
- Required tools: `curl`, `python3`, `find`, `netstat`, `docker`, `kubectl`
- Expected input files: None listed in `skill.yaml`.
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `linux-quick-enum` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `linux-quick-enum` | Quick Linux privilege escalation enumeration | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/id.txt`<br>`$OUTDIR/privesc/sudo.txt`<br>`$OUTDIR/privesc/suid.txt`<br>`$OUTDIR/privesc/caps.txt`<br>`...` | `$OUTDIR/privesc/evidence/` |
| `auto-enum` | Run automated enumeration tool (linPEAS) | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/linpeas_output.txt` | `$OUTDIR/privesc/evidence/` |
| `suid-exploit` | Check SUID binaries against GTFOBins for exploitation | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/suid_analysis.txt` | `$OUTDIR/privesc/evidence/` |
| `sudo-exploit` | Check sudo permissions against GTFOBins | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/sudo_analysis.txt` | `$OUTDIR/privesc/evidence/` |
| `capability-abuse` | Analyze Linux capabilities for exploitation paths | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/dangerous_caps.txt` | `$OUTDIR/privesc/evidence/` |
| `cron-abuse` | Check for writable cron jobs and PATH abuse | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/cron_analysis.txt` | `$OUTDIR/privesc/evidence/` |
| `docker-escape` | Check if running in container and enumerate escape vectors | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/docker_escape.txt` | `$OUTDIR/privesc/evidence/` |
| `credential-hunt` | Search for credentials in config files and history | No script reference in `skill.yaml` command. | `$OUTDIR/privesc/credentials.txt`<br>`$OUTDIR/privesc/history.txt` | `$OUTDIR/privesc/evidence/` |
| `evidence` | Package privesc findings | No script reference in `skill.yaml` command. | `$EVIDENCE_DIR/privesc/` | `$EVIDENCE_DIR/privesc/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Credential-hunting workflows may surface live passwords, tokens, session secrets, and authorization material from host config and history; redact and sanitize these values before they leave the host. Keep raw credential output local-only, never committed to git, and ensure evidence directories are covered by gitignore so secrets are never committed.
- Evidence templates from `skill.yaml`:
- `suid`: Output of find / -perm -4000 with GTFOBins cross-reference
- `sudo_escape`: sudo -l output with GTFOBins cross-reference

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-ATHZ-01`, `WSTG-ATHZ-02`, `WSTG-ATHZ-03`, `WSTG-ATHZ-04`
