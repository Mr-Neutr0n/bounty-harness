# Review Pipeline Runbook

## Purpose
Review the output of a batch pipeline run and make import decisions.

## Step 1: Load Pipeline Log

```bash
cat .claude/skills/auto-research/cache/pipeline_log.json | python3 -m json.tool
```

## Step 2: Review Scored Candidates

```bash
cat .claude/skills/auto-research/cache/batch_review_*.json | python3 -m json.tool | less
```

## Step 3: Check per Candidate
For each passing candidate, verify:
- **Attribution**: Source is cited correctly
- **Accuracy**: Technique description matches the source
- **Overlap**: Does this genuinely add new knowledge?
- **Actionable**: Are there commands or payloads to use?
- **Schema fit**: Does it match the technique KB schema?

## Step 4: Approve or Reject
Create a review decisions file:
```json
{
  "reviewed_at": "<timestamp>",
  "decisions": {
    "candidate_hash_or_index": {
      "action": "approve|reject|needs_review",
      "notes": "<reason>",
      "suggested_skill_update": "<skill name or null>"
    }
  }
}
```

## Step 5: Create Technique Files
For approved candidates, create technique files in the KB:
```bash
# Example: creating a new technique file
cat > path/to/technique-kb/new-technique.yaml << 'TECHNIQUE'
name: "New Technique Name"
source: "auto-research"
source_id: "nuclei-templates"
description: >
  Extracted description from the source.
category: "web_exploitation"
tags: ["cve-2024-xxxx", "rce"]
extracted_at: "ISO-8601"
TECHNIQUE
```

## Step 6: Propose Skill Updates
If any candidate suggests updating an existing skill:
1. Identify the target skill file
2. Draft the proposed change
3. Include the candidate as evidence
4. Submit for manual review before applying