# 03-hotlist: Build Hotlist

## Overview

Rank every asset in the graph by risk and value. The hotlist scorer considers
route sensitivity, persona access level, object exposure, and graph centrality
to produce a prioritized list of assets for targeted testing.

## Prerequisites

- All three ingestion workflows completed (recon, corpus, personas).
- Graph relationships populated (asset→route, route→object, persona→route links).

## Steps

1. Verify the graph is fully populated:
   ```
   sqlite3 $OUTDIR/asset-graph/asset_graph.sqlite "
     SELECT 'Assets', COUNT(*) FROM assets
     UNION ALL SELECT 'Routes', COUNT(*) FROM routes
     UNION ALL SELECT 'Personas', COUNT(*) FROM personas
     UNION ALL SELECT 'Relationships', COUNT(*) FROM relationships;
   "
   ```
   All counts should be > 0.

2. Build the hotlist:
   ```
   bin/bb-run asset-graph build-hotlist
   ```

3. The scorer assigns points based on multiple signals:
   - **Route sensitivity** — auth-gated routes score higher.
   - **Persona exposure** — routes accessible by low-privilege personas that
     return high-value data score higher (privilege escalation targets).
   - **Object density** — routes exposing UUIDs, Stripe IDs, or PII score higher.
   - **Graph centrality** — pivot assets that connect many subgraphs score higher.
   - **Technology risk** — assets running known-vulnerable software version ranges.

## Verification

- `hotlist.json` exists:
  ```
  ls -la $OUTDIR/asset-graph/hotlist.json
  ```
- Assets are sorted by descending score:
  ```
  python3 -c "
  import json
  hotlist = json.load(open('$OUTDIR/asset-graph/hotlist.json'))
  print(f'Total assets ranked: {len(hotlist)}')
  for a in hotlist[:5]:
      print(f\"  {a['score']:5.1f}  {a['host']:30s}  {a.get('route',''):40s}\")
  "
  ```
- Each entry contains `host`, `route` (if applicable), `score`, `signals`, and
  `recommended_skills`.
- Top entries have clear rationale in the `signals` array.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| All scores are 0 | Graph is empty or no relationships | Re-run all ingestion steps |
| Top entry looks wrong | Scoring signal weights need tuning | Adjust `HOTLIST_WEIGHTS` in `skill.yaml` |
| `hotlist.json` missing | Workflow failed silently | Run `bb-run` with `--verbose` |
| Hotlist too large (all routes scored) | No filtering applied | Set `HOTLIST_MIN_SCORE` to threshold (default: 1.0) |
| No `recommended_skills` in output | Skill mapping config missing | Verify `technique-kb` data is available for cross-reference |