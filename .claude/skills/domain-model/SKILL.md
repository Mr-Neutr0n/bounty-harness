# Domain Model

## Overview
Application-agnostic domain archetype classification for bug bounty targets. Infers what the target application actually does based on recon data — classifying into archetypes (media platform, billing SaaS, marketplace, etc.) and mapping detected infrastructure to attack surfaces. This replaces "spray XSS/SQLi/SSRF everywhere" with archetype-driven, surface-prioritized testing.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `domain-model`
- Severity range: `info`, `low`, `medium`
- Required tools: `python3`, `pyyaml`
- Required prior skills: `recon` (needs `subdomains/subs.txt`, `live/live_full.csv`, `js/js_endpoints.txt`)
- Scope check: no intrusive operations in this skill — classification only.
- Redaction: classification, surface map, and domain profile artifacts are local-only and must be sanitized to redact target hostnames and identifiers before sharing; they are never committed and should stay covered by `.gitignore`.

## Workflow Selection
- Run `classify` first to determine archetypes from recon data.
- Run `map-surfaces` second to map detected infrastructure to attack surfaces.
- Run `profile` third to generate the full domain profile report for dispatch decisions.
- Each workflow depends on the output of the previous.

## Available Workflows

| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `classify` | Classify target into domain archetypes from recon data | `.claude/skills/domain-model/scripts/archetype_classifier.py` | `$OUTDIR/domain-model/archetypes.json` | None (classification only) |
| `map-surfaces` | Map detected infrastructure to attack surface taxonomy | `.claude/skills/domain-model/scripts/surface_mapper.py` | `$OUTDIR/domain-model/surfaces.json` | None (mapping only) |
| `profile` | Generate full domain profile report with prioritized testing order | `.claude/skills/domain-model/scripts/domain_report.py` | `$OUTDIR/domain-model/domain-profile.md` | None (reporting only) |

## Evidence Required
- This skill does not collect evidence directly. It produces classification artifacts.
- Archetype JSON: target, archetype list with confidence scores, supporting evidence strings.
- Surface JSON: target, detected surface list with confidence, auth requirements, intrusive levels.
- Domain profile: full markdown report with prioritized testing order and recommended skill loading sequence.

## References
- Source of truth: `skill.yaml`
- Archetype definitions: `domain.yaml`
- Surface definitions: `surfaces.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INFO-01`, `WSTG-INFO-02`, `WSTG-INFO-03`, `WSTG-INFO-05`, `WSTG-INFO-06`