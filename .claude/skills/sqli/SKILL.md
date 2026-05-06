# Sqli

## Overview
SQL Injection detection and exploitation — error-based, UNION, Boolean blind, time-based, OOB, stacked queries, NoSQL

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `sqli`
- Severity range: `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `arjun`, `dalfox`, `sqlmap`, `python3`, `jq`, `katana`, `gau`
- Expected input files: `parameterized_urls.txt`, `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `sql-injection` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `sql-injection` | Detect SQL injection in parameterized URLs using error, boolean, and timing checks. | `.claude/skills/sqli/scripts/sqli_detector.py` | `$OUTDIR/sqli/sql/findings.jsonl` | `$OUTDIR/sqli/sql/evidence/` |
| `nosql-injection` | Detect MongoDB-style NoSQL injection operators in parameterized URLs. | `.claude/skills/sqli/scripts/nosql_injector.py` | `$OUTDIR/sqli/nosql/findings.jsonl` | `$OUTDIR/sqli/nosql/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `sqli_error`: Error message with database fingerprint
- `sqlmap_log`: Full sqlmap output showing DB names, tables, columns
- `nosql_bypass`: Response showing authentication bypass via $ne operator

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INPV-05`
- OWASP API Top 10: `API8:2019`
