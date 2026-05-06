# 04-graphql: Extract GraphQL

## Overview

Identify and extract GraphQL operations from the normalized corpus. Parses query
bodies for operation types (queries, mutations, subscriptions), extracts field
signatures, and writes structured operation records to `graphql_ops.jsonl`.

## Prerequisites

- `normalize-corpus` must have completed (routes are normalized).
- Traffic corpus must contain requests hitting GraphQL endpoints.
- The GraphQL endpoint is typically `/graphql`, `/v1/graphql`, or `/api/graphql`.

## Steps

1. Confirm GraphQL traffic exists in the corpus:
   ```
   grep -l 'graphql' $OUTDIR/traffic-corpus/samples.jsonl | head -1
   ```
   Or search for the query/mutation keyword in request bodies:
   ```
   python3 -c "
   import json
   count = 0
   for line in open('$OUTDIR/traffic-corpus/samples.jsonl'):
       s = json.loads(line)
       body = s.get('request_body','')
       if 'query' in body or 'mutation' in body:
           count += 1
   print(f'{count} GraphQL-like requests found')
   "
   ```

2. Run the GraphQL extraction workflow:
   ```
   bin/bb-run traffic-corpus extract-graphql
   ```

3. The extractor parses each candidate request body to identify:
   - **Operation type** — `query`, `mutation`, or `subscription`.
   - **Operation name** — the named operation if present.
   - **Top-level fields** — root field selections.
   - **Variables** — input variable names and types.
   - **Source route** — the normalized route path and host.

## Verification

- `graphql_ops.jsonl` exists:
  ```
  ls -la $OUTDIR/traffic-corpus/graphql_ops.jsonl
  ```
- Operation breakdown:
  ```
  python3 -c "
  import json
  from collections import Counter
  ops = Counter()
  for line in open('$OUTDIR/traffic-corpus/graphql_ops.jsonl'):
      ops[json.loads(line)['operation_type']] += 1
  for op, c in ops.most_common():
      print(f'{op:15s} {c:5d}')
  "
  ```
- Each entry has `operation_type`, `operation_name`, `top_level_fields`, `variables`, and `source_route`.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| No GraphQL ops found | Traffic doesn't hit GraphQL endpoints | Capture traffic while using the app's GraphQL features |
| All ops classified as `query` | Mutations use `query` keyword (common anti-pattern) | Expected; check operation names for intent |
| Malformed query parsing | Batching or persisted queries used | Set `GRAPHQL_MODE=batch` or `GRAPHQL_MODE=persisted` |
| Variables missing | Variables sent separately (APQ) | Enable `--parse-extensions` to pull from extensions block |
| Subscriptions not detected | Subscriptions use WebSocket transport | Subscriptions require WS capture; not supported in HAR alone |