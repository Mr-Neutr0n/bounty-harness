# How to Add a New Technique

## Step 1: Choose category and ID

Pick the right category directory under `techniques/`. If no directory exists, create one
and add an entry in the `category` enum of `technique_schema.yaml`.

The ID must follow the pattern: `category-short-description`, lowercase with hyphens
(e.g. `xss-reflected-post`, `sqli-stacked-queries`).

## Step 2: Create the YAML file

Copy the structure from an existing technique in the same category. Fill every required
field. The schema has these required top-level keys:

```yaml
id: <unique-id>
name: <Human-readable name>
category: <one of the enum values>
description: <full explanation, multiline with > or |>
severity: <critical|high|medium|low|info>
standards:
  wstg: []
  asvs: []
  api_top10: []
  vrt: []
  cwe: []
applies_to:
  archetypes: []
  surfaces: []
requires:
  auth: <none|single_account|two_accounts|admin|session_cookie|api_key>
  inputs: []
  tools: []
signals:
  positive: []
  negative: []
safety:
  intrusive: <true|false>
  data_modifying: <true|false>
  rate_limited: <true|false>
  requires_approval: <true|false>
evidence:
  required: []
```

Optional keys: `references`, `workflow_mapping`, `payload_families`, `tags`.

## Step 3: Fill with real data

Each field must be factually correct. Standards references must match real OWASP/ASVS/CWE
identifiers. Signals must be specific and actionable. Evidence requirements should list
actual artifacts the bug bounty agent can capture.

## Step 4: Validate

```bash
python3 .claude/skills/technique-kb/scripts/technique_validator.py \
  --techniques-dir .claude/skills/technique-kb/techniques \
  --schema .claude/skills/technique-kb/technique_schema.yaml
```

Fix any validation errors. The validator checks required fields, types, enums, and structure.

## Step 5: Update workflow_mapping

If this technique maps to a skill workflow, set `workflow_mapping.skill` to the skill
directory name and `workflow_mapping.workflow` to the workflow identifier.

If no mapping exists yet, leave it blank or remove the key.

## Step 6: Test searchability

```bash
python3 .claude/skills/technique-kb/scripts/technique_search.py \
  --techniques-dir .claude/skills/technique-kb/techniques \
  --query "category:YOUR_CATEGORY"
```

Confirm the new technique appears in results.
