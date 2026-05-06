# Ssrf

## Overview
Server-Side Request Forgery — internal probing, cloud metadata attacks, URL parser bypasses, protocol smuggling

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `ssrf`
- Severity range: `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `arjun`, `katana`, `nuclei`, `python3`, `interactsh-client`, `jq`
- Expected input files: `parameterized_urls.txt`, `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `ssrf-probe` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `ssrf-probe` | Identify and test URL-like parameters for SSRF with internal, metadata, OAST, and bypass checks. | `.claude/skills/ssrf/scripts/ssrf_probe.py` | `$OUTDIR/ssrf/probe/findings.jsonl` | `$OUTDIR/ssrf/probe/evidence/` |
| `cloud-metadata` | Probe cloud metadata endpoints through known URL-like parameters. | `.claude/skills/ssrf/scripts/cloud_metadata_hunter.py` | `$OUTDIR/ssrf/metadata/findings.jsonl` | `$OUTDIR/ssrf/metadata/evidence/` |
| `parser-bypass` | Generate and test URL parser differential payloads against the configured URL. | `.claude/skills/ssrf/scripts/url_parser_differential.py` | `$OUTDIR/ssrf/bypass/results.json` | `$OUTDIR/ssrf/bypass/evidence/` |
| `single-param-detector` | Run the legacy single-parameter SSRF detector when a specific parameter is known. | `.claude/skills/ssrf/scripts/ssrf_detector.py` | `$OUTDIR/ssrf/single/results.json` | `$OUTDIR/ssrf/single/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `ssrf_metadata`: AWS/GCP/Azure credential response from metadata endpoint
- `ssrf_internal`: Redis INFO/Memcached stats/ES cluster health output
- `ssrf_oob`: Interactsh log entry showing HTTP/DNS callback from target

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INPV-19`
