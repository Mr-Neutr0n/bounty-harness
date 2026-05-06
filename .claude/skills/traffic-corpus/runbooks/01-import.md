# 01-import: Import Traffic

## Overview

Ingest raw HTTP traffic from HAR files, Burp Suite exports, or proxy logs into
the traffic corpus pipeline. All source files are staged in a `raw/` directory
before batch import into a structured `samples.jsonl` file.

## Prerequisites

- `OUTDIR` set from `.bb/context.env`.
- Source traffic files available as `.har` (HTTP Archive) or `.xml` (Burp format).
- The `import-traffic` workflow defined in `skill.yaml`.

## Steps

1. Create the staging directory if it doesn't exist:
   ```
   mkdir -p $OUTDIR/traffic-corpus/raw/
   ```

2. Place traffic files in the staging area:
   ```
   cp ~/Downloads/session-export.har $OUTDIR/traffic-corpus/raw/
   cp ~/Downloads/target-burp.xml $OUTDIR/traffic-corpus/raw/
   ```

   You can stage multiple files. The importer processes all compatible files
   found in the `raw/` directory.

3. Run the import workflow:
   ```
   bin/bb-run traffic-corpus import-traffic
   ```

4. The workflow reads each source file, decodes requests/responses, and appends
   normalized entries to `samples.jsonl`.

## Verification

- `samples.jsonl` exists and is non-empty:
  ```
  wc -l $OUTDIR/traffic-corpus/samples.jsonl
  ```
- Each line is valid JSON with `method`, `url`, `host`, `path`, `status_code`,
  and `source_file` fields:
  ```
  head -1 $OUTDIR/traffic-corpus/samples.jsonl | python3 -m json.tool | head -10
  ```
- Total entry count matches expectations from source files:
  ```
  python3 -c "print(sum(1 for _ in open('$OUTDIR/traffic-corpus/samples.jsonl')))"
  ```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `samples.jsonl` empty after import | No compatible files in `raw/` | Verify files are `.har` or `.xml` and readable |
| Import fails with parse error | Corrupt or truncated HAR file | Re-export from browser/Burp |
| Duplicate entries | Same files imported twice | Clear `raw/` after successful import or use `--dedup` |
| High memory usage on large HAR | Single HAR exceeds available RAM | Split HAR into chunks or use `--stream` flag |
| `OUTDIR` not set | Context not loaded | `source .bb/context.env` first |