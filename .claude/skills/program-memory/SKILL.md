# Program Memory

## Overview
Persist target-specific knowledge across engagements. Track accepted/rejected findings, false-positive patterns, rate limits, auth behavior, object ID formats, WAF quirks, and technology profiles. Feed learning back into planner rankings.

## Quick Reference
- **Skill**: program-memory
- **Version**: 1.0.0
- **Bounded Context**: ProgramMemoryContext
- **Required tools**: `python3`, `jq`
- **Risk tier**: passive

## Workflow Selection
- New program: `init-memory` to create the memory store.
- After each run: `import-run` to ingest findings and facts.
- Before planning: `export-planner-hints` for ranking signals.
- Review: `record-fact` or `record-false-positive` for manual notes.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `init-memory` | Create program memory store for the current program. |
| `import-run` | Ingest findings, facts, and patterns from current run. |
| `record-fact` | Add a manual fact about the program. |
| `record-false-positive` | Record a confirmed false-positive pattern. |
| `record-finding` | Record a submitted/finalized finding. |
| `summarize-memory` | Produce human-readable memory summary. |
| `export-planner-hints` | Export planner-weighting hints from accumulated memory. |

## Redaction and Storage Policy
Program memory is **local-only**: the SQLite store (`.bb/memory.sqlite`) and all summaries live under `.bb/` / `$OUTDIR` and are **never committed** (keep them in `.gitignore`). Before any fact is persisted, secrets, tokens, cookies, and auth headers must be redacted; the `export-safe` workflow enforces this redaction so only report-safe, sanitized facts ever leave the store.

## Evidence Required
- Program facts with source attribution and confidence.
- False-positive patterns with example request/response pairs.
- Finding history with Bugcrowd/HackerOne verdicts.

## References
- Bugcrowd VRT 1.18
- OWASP WSTG-INFO-01 (Reconnaissance)
- OWASP ASVS V1 (Architecture)