# Planner

## Overview
Domain-driven ranked test plan generator. Consumes the Domain Model (archetypes + surfaces), the Asset Graph (recon data), the Technique KB catalog, and the Coverage Ledger. Outputs a prioritized list of workflows to execute — ranked by business impact, surface prevalence, vulnerability severity, signal quality, coverage gaps, and tool availability.

This replaces "did we run everything?" with "here is a measurable plan covering X% of relevant surfaces."

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `planner`
- Severity range: `info`
- Required tools: `python3`, `jq`, `yq`
- Expected input files: Domain profile JSON (from `domain-model/`), Technique YAML catalog (from `technique-kb/`), optional coverage matrix YAML or JSON
- Scope check: The planner itself does not execute intrusive tests — it plans them. Ensure scope authorization exists before executing any plan items.

## When to Use
Trigger phrases:
- "create a test plan", "generate a plan", "ranked plan", "what should I test", "prioritize my testing", "plan my engagement", "coverage-based plan"
- "plan", "planning", "test strategy", "engagement plan", "plan vs results"

**Prerequisite:** The planner requires a domain profile. If the target has no prior recon, run the `recon` skill first, then the `domain-model` skill to generate a domain profile, then use the planner.

## Decision Tree

```
User provides target + wants a plan
          │
          ├── Domain profile exists? ── No ──> Run recon → domain-model → retry
          │
          ├── Technique catalog populated? ── No ──> Warn user, plan will be empty
          │
          ├── Coverage matrix available? ── No ──> Plan treats all techniques as gaps
          │
          └── Generate plan ──> Review ──> Execute ──> Plan vs Results
```

## Workflow Selection
- Start with `generate-plan` for the full plan.
- Use `generate-plan-safe` if you only want safe, non-destructive items.
- Follow with `visualize-plan` and `validate-plan` to review before execution.
- After execution, use the `plan-vs-results` runbook to feed findings back into the coverage matrix.

## Available Workflows

| Workflow | Purpose | Script paths | Primary outputs |
|---|---|---|---|
| `generate-plan` | Generate full ranked test plan from domain profile + techniques + coverage | `.claude/skills/planner/scripts/generate_plan.py` | Plan JSON file |
| `generate-plan-safe` | Generate plan excluding intrusive and destructive techniques | `.claude/skills/planner/scripts/generate_plan.py` | Plan JSON file |
| `visualize-plan` | Convert plan JSON to readable markdown or HTML | `.claude/skills/planner/scripts/plan_visualizer.py` | Markdown or HTML file |
| `validate-plan` | Validate plan JSON against plan_schema.yaml for structural correctness | `.claude/skills/planner/scripts/plan_validator.py` | Validation report (stdout) |

## Runbooks

| Runbook | Purpose | Path |
|---|---|---|
| Generate Plan | Step-by-step plan generation | `.claude/skills/planner/runbooks/generate-plan.md` |
| Review Plan | Review plan for safety, scope, completeness | `.claude/skills/planner/runbooks/review-plan.md` |
| Execute Plan | Execute plan items, collect evidence, record results | `.claude/skills/planner/runbooks/execute-plan.md` |
| Plan vs Results | Compare plan to actual results, update coverage matrix | `.claude/skills/planner/runbooks/plan-vs-results.md` |

## Scoring Model

Each technique is scored on 6 dimensions and weighted to produce a final score [0,1]:

| Dimension | Weight | What it measures |
|---|---|---|
| Business Impact | 0.30 | Archetype severity weight × technique severity mapping |
| Surface Prevalence | 0.20 | Match between technique surfaces and target's detected surfaces |
| Vulnerability Severity | 0.20 | Direct mapping from technique severity field |
| Detection Signal Quality | 0.15 | Number and specificity of positive/negative expected signals |
| Coverage Gap Urgency | 0.10 | Whether the technique fills a prior gap (1.0 = not covered, 0.0 = covered) |
| Tool Availability | 0.05 | Fraction of required tools found in PATH |

Priority tiers: **critical** (≥0.80), **high** (≥0.60), **medium** (≥0.35), **low** (<0.35)

## Technique YAML Format (expected in technique-kb/techniques/)

```yaml
id: "xss-reflected-get"
name: "Human-readable technique name"
category: "xss"
severity: "critical|high|medium|low|info"
description: "What this technique detects"
standards:
  wstg: ["WSTG-INPV-01"]
  asvs: []
  api_top10: []
  vrt: []
  cwe: ["CWE-79"]
applies_to:
  archetypes: ["all"]
  surfaces: ["all-parameterized-endpoints"]
requires:
  auth: "none"
  inputs: ["parameterized URLs"]
  tools: ["curl", "dalfox"]
signals:
  positive:
    - "Payload echoed in response without sanitization"
  negative:
    - "Content-Type prevents script execution"
safety:
  intrusive: false
  data_modifying: false
  rate_limited: false
  requires_approval: false
evidence:
  required:
    - "raw_request"
    - "raw_response"
    - "screenshot"
workflow_mapping:
  skill: "xss"
  workflow: "reflected-param-test"
```

## Evidence Required
The planner itself does not produce evidence — it produces a plan. Each plan item specifies what evidence to collect during execution:
- `raw_request` — full HTTP request with headers
- `raw_response` — full HTTP response with headers and body
- `screenshot` — visual evidence of the finding
- `poc_script` — reproducible proof of concept
- `tool_output` — raw tool output logs
- `timestamp` — ISO 8601 execution time

## Output Files
| File | Contents |
|---|---|
| `plan.json` | Full ranked plan in plan_schema format |
| `plan.md` / `plan.html` | Human-readable visualizations |
| `coverage.json` | Updated coverage matrix (after plan-vs-results) |

## References
- Source of truth: `skill.yaml`
- Scoring rules: `ranking_rules.yaml`
- Plan schema: `plan_schema.yaml`
- Runbooks: `runbooks/`
