# Import Candidate Runbook

## Purpose
Extract, deduplicate, review, and import a single candidate from a source.

## Prerequisites
- Content file downloaded from the source (clone repo, curl URL, etc.)
- Python 3 with PyYAML
- Existing technique KB directory for deduplication

## Step 1: Extract Candidates

```bash
python3 .claude/skills/auto-research/scripts/knowledge_extractor.py \
  --content-file path/to/downloaded/content.txt \
  --source-id "source-id-from-sources.yaml" \
  --rules .claude/skills/auto-research/ingest_rules.yaml \
  --output-dir .claude/skills/auto-research/cache/
```

## Step 2: Deduplicate Against Existing KB

```bash
python3 .claude/skills/auto-research/scripts/deduplicator.py \
  --candidates cache/candidates_sourceid_timestamp.json \
  --techniques-dir path/to/technique-kb/ \
  --rules .claude/skills/auto-research/ingest_rules.yaml \
  --output cache/dedup_result.json
```

## Step 3: Review and Score

```bash
python3 .claude/skills/auto-research/scripts/candidate_reviewer.py \
  --candidates cache/dedup_result.json \
  --rules .claude/skills/auto-research/ingest_rules.yaml \
  --output cache/reviewed_candidates.json
```

## Step 4: Manual Review
Review the scored candidates:
```bash
cat cache/reviewed_candidates.json | python3 -m json.tool | less
```

## Step 5: Import
After manual confirmation, import candidates that passed the threshold into the technique KB.
Create technique files in the appropriate directory following the KB schema.

## Triage
- **0 candidates extracted**: Source may not contain extractable content
- **0 new after dedup**: All content already known
- **0 passing review**: Candidates below quality threshold — investigate scoring