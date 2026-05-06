# Mobile

## Overview
Mobile application security — APK/IPA static analysis, Firebase misconfig, WebView vulnerabilities, certificate pinning bypass, deeplinks, Frida hooks

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `mobile`
- Severity range: `medium`, `high`, `critical`
- Required tools: `adb`, `apktool`, `jadx`, `frida`, `objection`, `mitmproxy`, `curl`, `python3`, `openssl`, `jq`
- Expected input files: `none`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `apk-analysis` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `apk-analysis` | Run static APK analysis against an operator-provided APK path. | `.claude/skills/mobile/scripts/apk_analyzer.py` | `$OUTDIR/mobile/static/apk_analysis.json`<br>`$OUTDIR/mobile/static/findings.jsonl` | `$OUTDIR/mobile/static/evidence/` |
| `frida-ssl-bypass` | Launch the existing Frida SSL bypass script for a supplied mobile package. | `.claude/skills/mobile/scripts/frida_ssl_bypass.js` | `$OUTDIR/mobile/pinning/` | `$OUTDIR/mobile/pinning/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `firebase_misconfig`: curl response showing Firebase DB accessible without auth
- `traffic_capture`: mitmproxy flow showing cleartext API request with sensitive data
- `deeplink_poc`: adb am start command demonstrating deeplink injection

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-MOBL-01`, `WSTG-MOBL-02`, `WSTG-MOBL-03`, `WSTG-MOBL-04`, `WSTG-MOBL-05`, `WSTG-MOBL-06`, `WSTG-MOBL-07`, `WSTG-MOBL-08`
