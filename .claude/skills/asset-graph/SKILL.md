# Asset Graph

## Overview
Persistent target understanding across runs. Connect recon output, traffic corpus, objects, personas, and findings into a SQLite asset graph with delta comparison, hotlist ranking, and planner integration.

## Quick Reference
- **Skill**: asset-graph
- **Version**: 1.0.0
- **Bounded Context**: AssetGraphContext
- **Required tools**: `python3`, `jq`
- **Risk tier**: passive

## Workflow Selection
- First run: `init-graph`, then `ingest-recon`, then `ingest-corpus`, then `ingest-personas`.
- Subsequent runs: `diff-runs` to see what changed, then re-ingest only new data.
- Planning prep: `build-hotlist` then `export-planner-hints`.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `init-graph` | Create SQLite database and schema for the engagement. |
| `ingest-recon` | Load recon output (hosts, URLs, JS files) into the graph. |
| `ingest-corpus` | Load normalized traffic corpus routes and objects. |
| `ingest-personas` | Load persona definitions and auth states. |
| `ingest-findings` | Load confirmed findings and false positives. |
| `build-hotlist` | Score and rank assets by value and untested surface. |
| `diff-runs` | Compare current run against previous runs. |
| `query` | Run arbitrary SQL queries against the graph. |

## Evidence Required
- SQLite database under `$OUTDIR/asset-graph/`.
- Hotlist JSON with ranked assets and scores.
- Delta report highlighting new hosts, routes, objects.

## References
- OWASP WSTG-INFO-01 (Conduct Search Engine Discovery Reconnaissance)
- OWASP WSTG-INFO-02 (Fingerprint Web Server)
- OWASP ASVS V1 (Architecture, Design, and Threat Modeling)