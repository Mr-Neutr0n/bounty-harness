# 02-ingest: Ingest Data

## Overview

Populate the asset graph with data from the three upstream pipelines: recon
(hosts/subdomains), traffic corpus (routes/endpoints), and persona (role
credentials). Run the three ingestion workflows sequentially to build the
complete graph.

## Prerequisites

- Asset graph initialized via `init-graph`.
- Recon, traffic corpus, and persona pipelines all have output data available.

## Steps

1. **Ingest recon data (hosts and subdomains):**
   ```
   bin/bb-run asset-graph ingest-recon
   ```
   Reads recon outputs and populates the `assets` table with host entries and
   their metadata (IP, status code, title, technologies).

2. **Ingest traffic corpus data (routes and objects):**
   ```
   bin/bb-run asset-graph ingest-corpus
   ```
   Reads `routes.jsonl` and `objects.jsonl` from the traffic corpus pipeline.
   Creates `routes` entries linked to host assets and `objects` entries with
   foreign keys to their source routes.

3. **Ingest persona data (roles and credential state):**
   ```
   bin/bb-run asset-graph ingest-personas
   ```
   Reads `personas.json` and `validation.json`. Creates persona nodes in the
   graph with their current auth state.

4. Check overall graph health:
   ```
   sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "
     SELECT 'Hosts', COUNT(*) FROM assets
     UNION ALL SELECT 'Routes', COUNT(*) FROM routes
     UNION ALL SELECT 'Personas', COUNT(*) FROM personas
     UNION ALL SELECT 'Objects', COUNT(*) FROM objects
     UNION ALL SELECT 'Relationships', COUNT(*) FROM relationships;
   "
   ```

## Verification

- Each ingestion step completes with a count summary printed to stdout.
- Host count > 0 (if recon ran):
  ```
  sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "SELECT COUNT(*) FROM assets WHERE type='host';"
  ```
- Route count matches traffic corpus:
  ```
  echo "Graph routes: $(sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "SELECT COUNT(*) FROM routes;")"
  echo "Corpus routes: $(wc -l < $OUTDIR/traffic-corpus/routes.jsonl)"
  ```
- Persona count matches imported personas:
  ```
  sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "SELECT COUNT(*) FROM personas;"
  ```
- Relationships exist linking routes to hosts and objects to routes.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| 0 hosts ingested | Recon pipeline not run or stale | Run `bb-run recon live-discovery` first |
| 0 routes ingested | Traffic corpus not imported/normalized | Run `import-traffic` then `normalize-corpus` |
| 0 personas ingested | Persona init not run or no imports | Run `init-personas` then `import-cookie` |
| Duplicate hosts on re-ingest | Ingester not using upsert | Run `init-graph` to reset the DB before re-ingest |
| Foreign key constraint errors | Data from one pipeline references missing assets | Ensure ingestion order: recon → corpus → personas |