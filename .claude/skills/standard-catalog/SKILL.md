# Standard Catalog

## Overview
Canonical standards reference for the bug bounty toolkit. Every bug bounty test maps to an external standard (OWASP WSTG, ASVS, API Top 10, Bugcrowd VRT, CWE, PortSwigger Academy, CISA KEV, OWASP MASVS). This catalog is the single source of truth for WHAT those standards contain, enabling the coverage ledger to track WHAT we test against whom.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `standard-catalog`
- Severity range: `info`
- Required tools: `python3`
- Expected input files: none
- Scope check: not applicable — read-only reference data.

## Workflow Selection
- Start with `validate` to ensure catalog integrity.
- Run `search` by keyword to find standards items.
- Run `export` to generate a combined JSON for use in reports.
- Runbooks: use `runbooks/`.
- If a workflow has no script reference, treat it as a manual or tool-native workflow.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `validate` | Validate all catalog YAML files for structure integrity. | `.claude/skills/standard-catalog/scripts/validate_catalog.py` | `$OUTDIR/standard-catalog/validation.json` | `$OUTDIR/standard-catalog/evidence/` |
| `search` | Search across all catalogs by keyword. | `.claude/skills/standard-catalog/scripts/search_standards.py` | `$OUTDIR/standard-catalog/search_results.json` | `$OUTDIR/standard-catalog/evidence/` |
| `export` | Export a combined reference JSON with all standard IDs. | `.claude/skills/standard-catalog/scripts/export_references.py` | `$OUTDIR/standard-catalog/references.json` | `$OUTDIR/standard-catalog/evidence/` |

## Evidence Required
- Not applicable — this skill produces reference data, not vulnerability findings.
- All catalogs include source URLs and version information for provenance.

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: WSTG-INFO-01 through WSTG-INFO-10
- Covered standards: WSTG Latest, ASVS 5.0, API Top 10 2023, Bugcrowd VRT 1.18, CWE Top 50, CISA KEV, PortSwigger Academy, OWASP MASVS