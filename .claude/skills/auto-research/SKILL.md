# Auto Research

## Overview
Imports and normalizes public security knowledge into the technique knowledge base. Watches public sources (OWASP WSTG, ASVS, nuclei-templates, CISA KEV, PayloadsAllTheThings, HackTricks, SecLists, PortSwigger Research, Bugcrowd VRT, and more), extracts candidate improvements, normalizes them into Technique KB schema, and proposes skill updates. Nothing goes live without validation. Everything is attributed.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `auto-research`
- Severity range: `info`
- Required tools: `python3`, `jq`
- Expected input files: none
- Scope check: not applicable — imports public data into local KB.

## Workflow Selection
- Start with `scan` to check all sources for changes since last scan.
- Run `batch` for the full pipeline: scan -> extract -> deduplicate -> review.
- Run `review` to score and filter extraction candidates.
- Runbooks: use `runbooks/`.
- If a workflow has no script reference, treat it as a manual or tool-native workflow.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `scan` | Scan all sources for new content since last check. | `.claude/skills/auto-research/scripts/source_scanner.py` | `.claude/skills/auto-research/cache/scan_result.json` | `$OUTDIR/auto-research/evidence/` |
| `batch` | Run full import pipeline scan extract deduplicate review. | `.claude/skills/auto-research/scripts/batch_importer.py` | `.claude/skills/auto-research/cache/pipeline_log.json` | `$OUTDIR/auto-research/evidence/` |
| `review` | Review pipeline output candidates. | `.claude/skills/auto-research/scripts/candidate_reviewer.py` | `.claude/skills/auto-research/cache/batch_review.json` | `$OUTDIR/auto-research/evidence/` |

## Evidence Required
- Not applicable — this skill produces candidate data, not vulnerability findings.
- Attribution is embedded in each candidate record (source_id, source_type, extracted_at, content_hash).
- All candidates are traceable to their origin source for provenance.

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: https://github.com/OWASP/wstg
- OWASP ASVS: https://github.com/OWASP/ASVS
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://github.com/HackTricks-wiki/hacktricks
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- PortSwigger Research: https://portswigger.net/research