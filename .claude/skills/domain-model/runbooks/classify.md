# Classify Runbook — Archetype Classification

## Purpose
Classify a target domain into one or more application archetypes using signals extracted from completed recon data.

## Prerequisites
- Recon workflow `passive-subdomains` must have completed (subs.txt exists).
- Recon workflow `live-discovery` must have completed (live_full.csv exists).
- Recon workflow `js-recon` must have completed (js_endpoints.txt, js_files.txt exist).

## Execution

```bash
mkdir -p $OUTDIR/domain-model && \
python3 .claude/skills/domain-model/scripts/archetype_classifier.py \
  --target $TARGET \
  --context $OUTDIR/recon \
  --output $OUTDIR/domain-model/archetypes.json
```

## Expected Output
- `$OUTDIR/domain-model/archetypes.json` — JSON file with target, archetype list, confidence scores, and evidence.

## Sample Output Format
```json
{
  "target": "vimeo.com",
  "archetypes": [
    {
      "id": "media-platform",
      "confidence": 0.95,
      "evidence": [
        "player.* subdomain",
        "Player embed detected in JS",
        "upload subdomain"
      ]
    }
  ]
}
```

## Triage Rules
- Confidence >= 0.7: strong match. Prioritize surfaces listed in primary_surfaces.
- Confidence 0.3-0.69: moderate match. Include secondary archetype surfaces.
- Confidence < 0.3: weak match. Use as supplemental context only.
- Multiple archetypes: sort by severity_weight for triage priority.
- No archetypes found: target may be a simple static site or insufficient recon data.

## Next Step
After classify completes, run `map-surfaces` workflow.