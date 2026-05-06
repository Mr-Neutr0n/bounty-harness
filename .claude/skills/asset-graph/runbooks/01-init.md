# 01-init: Initialize Graph

## Overview

Create the SQLite-backed asset graph database and generate an initial summary.
This is the foundation that all downstream graph operations build on.

## Prerequisites

- `OUTDIR` set from `.bb/context.env`.
- Recon data available (subdomains, live hosts) from the recon skill pipeline.
- `sqlite3` available on PATH.

## Steps

1. Ensure recon baseline exists:
   ```
   ls $OUTDIR/recon/live-hosts.jsonl 2>/dev/null || echo "Run recon live-discovery first"
   ```

2. Initialize the graph:
   ```
   bin/bb-run asset-graph init-graph
   ```

3. The workflow:
   - Creates `$OUTDIR/asset-graph/asset_graph.sqlite` with the full schema.
   - Bootstraps tables: `assets`, `routes`, `personas`, `relationships`, `hotlist_cache`.
   - Generates `graph_summary.md` describing the schema and entity counts.

## Verification

- SQLite database file exists and is non-trivial:
  ```
  ls -lh $OUTDIR/asset-graph/asset_graph.sqlite
  ```
- Database has expected tables:
  ```
  sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite ".tables"
  ```
- Summary markdown file is generated:
  ```
  head -20 $OUTDIR/asset-graph/graph_summary.md
  ```
- Initial entity counts are zero (no data ingested yet):
  ```
  sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "SELECT 'hosts', COUNT(*) FROM assets UNION ALL SELECT 'routes', COUNT(*) FROM routes UNION ALL SELECT 'personas', COUNT(*) FROM personas;"
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `sqlite3` not found | SQLite not installed | `brew install sqlite` |
| Database not created | Permission issue on `OUTDIR` | `chmod 755 $OUTDIR/asset-graph/` |
| Schema load failure | Corrupt `schema.sql` in skill package | Re-pull skill: `git pull` from skill repo |
| `OUTDIR` empty | Context not sourced | `source .bb/context.env` first |