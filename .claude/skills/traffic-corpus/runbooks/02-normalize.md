# 02-normalize: Normalize Corpus

## Overview

Reduce raw traffic samples to canonical route signatures. The normalizer strips
dynamic path segments (IDs, slugs, timestamps), collapses query parameter
variants, and deduplicates routes into `routes.jsonl`.

## Prerequisites

- `samples.jsonl` populated from `import-traffic`.
- Python 3.9+ available (used by the normalizer script).

## Steps

1. Verify the input corpus has data:
   ```
   wc -l $OUTDIR/traffic-corpus/samples.jsonl
   ```

2. Run the normalization workflow:
   ```
   bin/bb-run traffic-corpus normalize-corpus
   ```

3. The normalizer performs these transformations on every request:
   - Replaces path segments matching UUID, numeric, or hash patterns with `{param}`.
   - Normalizes query strings — removes unique tracking params, sorts remaining keys.
   - Strips protocol and port from host to produce canonical host:route pairs.
   - Groups identical signatures and records a hit count.

## Verification

- `routes.jsonl` exists and contains fewer lines than `samples.jsonl`:
  ```
  echo "Routes: $(wc -l < $OUTDIR/traffic-corpus/routes.jsonl)"
  echo "Samples: $(wc -l < $OUTDIR/traffic-corpus/samples.jsonl)"
  ```
- Each route entry has `host`, `method`, `path_template`, `hit_count`, and `content_types`:
  ```
  head -1 $OUTDIR/traffic-corpus/routes.jsonl | python3 -m json.tool
  ```
- No duplicate `host + method + path_template` combinations exist:
  ```
  python3 -c "
  import json
  seen = set()
  for line in open('$OUTDIR/traffic-corpus/routes.jsonl'):
      r = json.loads(line)
      key = (r['host'], r['method'], r['path_template'])
      assert key not in seen, f'Duplicate: {key}'
      seen.add(key)
  print(f'{len(seen)} unique routes, no duplicates')
  "
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `routes.jsonl` identical count to samples | No dynamic segments detected | Check normalizer regex patterns in script |
| Some IDs not replaced | Pattern not in normalizer config | Add custom patterns via `NORMALIZE_PATTERNS` env var |
| Normalization hangs | Very large corpus, slow regex | Use `--workers 4` for parallel processing |
| Routes missing content types | Response body was empty or binary | Expected; skip with `--require-body` if needed |