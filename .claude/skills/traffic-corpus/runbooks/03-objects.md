# 03-objects: Extract Objects

## Overview

Scan response bodies from the traffic corpus to extract structured object
identifiers — UUIDs, numeric IDs, Stripe IDs, email addresses, and other
application-specific identifiers. Results are written to `objects.jsonl`
keyed by object type, value, and source route.

## Prerequisites

- `samples.jsonl` and `routes.jsonl` from import and normalization.
- Response bodies must be present in the samples (not headers-only).

## Steps

1. Confirm samples include response bodies:
   ```
   python3 -c "
   import json
   total = with_body = 0
   for line in open('$OUTDIR/traffic-corpus/samples.jsonl'):
       total += 1
       s = json.loads(line)
       if s.get('response_body') and len(s['response_body']) > 10:
           with_body += 1
   print(f'{with_body}/{total} samples have response bodies')
   "
   ```

2. Run the object extraction workflow:
   ```
   bin/bb-run traffic-corpus extract-objects
   ```

3. The extractor scans response bodies for these object types by default:
   - `uuid` — standard UUID v1/v4 patterns.
   - `numeric_id` — integers in JSON id fields (`{"id": 12345}`).
   - `stripe_id` — Stripe prefixed IDs (`sk_live_`, `pi_`, `ch_`, `cus_`).
   - `email` — RFC 5322 email addresses.
   - `path_id` — URL path segments that look like identifiers.

## Verification

- `objects.jsonl` exists:
  ```
  ls -la $OUTDIR/traffic-corpus/objects.jsonl
  ```
- Count objects by type:
  ```
  python3 -c "
  import json
  from collections import Counter
  types = Counter()
  for line in open('$OUTDIR/traffic-corpus/objects.jsonl'):
      types[json.loads(line)['object_type']] += 1
  for t, c in types.most_common():
      print(f'{t:20s} {c:5d}')
  "
  ```
- Each entry has `object_type`, `object_value`, `source_route`, and `source_host`.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Zero objects extracted | Response bodies absent from samples | Re-import traffic with full bodies enabled |
| Only UUIDs, no numeric IDs | JSON response parsing issue | Check that `Content-Type` is `application/json` |
| Stripe IDs not found | No Stripe IDs in scope | Expected for non-payment targets |
| Many false positives | Weak regex for custom object types | Tune `OBJECT_PATTERNS` in skill config |