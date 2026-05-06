# 04-diff: Diff Runs

## Overview

Compare two asset graph snapshots to surface what changed between runs.
Identifies new assets, removed assets, changed routes, persona state
transitions, and hotlist rank movements.

## Prerequisites

- At least two completed runs with full graph data (two separate `OUTDIR`s
  or two timestamped snapshots).
- `diff-runs` workflow defined in `skill.yaml`.
- Both runs must have been through the full pipeline (init → ingest → hotlist).

## Steps

1. Identify the two run directories to compare:
   ```
   ls -d $TARGET/recon_*  # or wherever OUTDIR trees are stored
   ```

2. Run the diff workflow:
   ```
   bin/bb-run asset-graph diff-runs \
     BASELINE_DIR=$TARGET/recon_2026-05-05/asset-graph/ \
     CURRENT_DIR=$TARGET/recon_2026-05-06/asset-graph/
   ```

   If you have snapshots inside a single graph DB (versioned data), use:
   ```
   bin/bb-run asset-graph diff-runs \
     BASELINE_SNAPSHOT=v1 \
     CURRENT_SNAPSHOT=v2
   ```

3. The diff produces `delta.json` with these change categories:
   - `new_assets` — hosts or routes present in current but not baseline.
   - `removed_assets` — hosts or routes in baseline but not current.
   - `changed_routes` — routes with modified status codes or response fingerprints.
   - `persona_changes` — auth state transitions (active → expired, etc.).
   - `rank_changes` — hotlist position movements of ±10 or more spots.

## Verification

- `delta.json` exists:
  ```
  ls -la $OUTDIR/asset-graph/delta.json
  ```
- Summary of changes:
  ```
  python3 -c "
  import json
  d = json.load(open('$OUTDIR/asset-graph/delta.json'))
  for cat in ['new_assets','removed_assets','changed_routes','persona_changes','rank_changes']:
      print(f'{cat:25s}: {len(d.get(cat,[]))} changes')
  "
  ```
- New assets have URL and discovery source:
  ```
  python3 -c "import json; [print(a['url']) for a in json.load(open('$OUTDIR/asset-graph/delta.json'))['new_assets'][:5]]"
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `BASELINE_DIR not found` | Wrong path or run directory renamed | Use `find . -name asset_graph.sqlite` to locate DBs |
| All assets show as `new` | Baseline DB is empty | Verify baseline run completed ingestion |
| No `rank_changes` in delta | Hotlist not built on both runs | Run `build-hotlist` on each run first |
| `delta.json` empty | Both runs are identical | Expected if no scope changes between runs |
| Diff slow on large graphs | Full table scan without indexing | Add indexes to `assets.created_at` and `routes.last_seen` |