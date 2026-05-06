# Contributing

## Quick Start

```bash
make test      # YAML parse + Python compile checks
make validate  # Run skill quality validator
make secrets   # GitLeaks secret scan
make audit     # Workflow + security audit
```

All PRs must pass `make test`, `make validate`, `make secrets`, and
`make audit` before merge.

## Adding a New Skill

Create a directory under `.claude/skills/<skill>/` with the following structure:

```
.claude/skills/<skill>/
  SKILL.md        # Human-facing router with Overview, Quick Reference, Workflow
                  # Selection, Available Workflows, Evidence Required, References
  skill.yaml      # Machine-executable workflow registry (consumed by bin/bb-run)
  scripts/        # At least 3 scripts (Python or shell)
  runbooks/       # At least 4 runbook markdown files
  payloads/       # At least 2 payload text files
```

Each Python script under `scripts/` must support `--help` and return useful
output within 8 seconds.

See `.claude/skills/recon/` for a well-structured example.

## Adding a Tool to the Registry

1. Create a YAML file under `tools/registry/<tool>.yaml` with install method,
   version check, capabilities, and risk tier.
2. Update `tools/capabilities.yaml` if the tool provides a new capability.
3. Run `bin/bb-tools verify` to confirm the entry is well-formed.
4. Run `bin/bb-tools doctor --skill <relevant-skill>` to verify integration.

## PR Requirements

- [ ] `make test` passes (all skill.yaml parse, all Python compile)
- [ ] `make validate` passes (all skills at or above 85/100 quality threshold)
- [ ] `make secrets` passes (`gitleaks detect --source . --no-git -v`)
- [ ] `make audit` passes (workflow + security audit)
- [ ] No placeholders (`TODO`, `TBD`, `YOUR_`, `<script>`) in SKILL.md files
- [ ] No destructive patterns (`rm -rf`, `DROP TABLE`, fork bombs) in committed files
- [ ] No secrets, credentials, or tokens in committed files
- [ ] Workflow commands reference scripts that exist on disk

## Skill Quality Standards

`tools/validate_skills.py` checks every skill for:

| Category | Minimum |
|---|---|
| Required files | `SKILL.md`, `skill.yaml` |
| Script count | 3+ under `scripts/` |
| Runbook count | 4+ under `runbooks/` |
| Payload count | 2+ under `payloads/` |
| SKILL.md sections | Overview, Quick Reference, Workflow Selection, Available Workflows, Evidence Required, References |
| Script health | `--help` executes and returns usage text |
| Script references | All doc and workflow refs point to existing files |
| Placeholders | No `TODO`, `TBD`, or `YOUR_` tags |

## Code Style

- Python scripts: standard library first, then third-party deps.
- Shell scripts: POSIX-compatible where possible; bash when arrays or
  advanced features are needed.
- YAML: 2-space indent, no tabs.
- Avoid comments — code should be self-documenting.
- Follow existing patterns in neighboring scripts.
- Workflow commands in `skill.yaml` should use `bin/bb-run` conventions.

## Proposing New Vulnerability Workflows

1. Identify the technique gap — check `technique-kb` to confirm it is not
   already covered.
2. Open an issue describing the technique, preconditions, signals, and
   suggested evidence collection.
3. After discussion, create a skill skeleton with `SKILL.md`, `skill.yaml`,
   and stubs for scripts, runbooks, and payloads.
4. Implement the workflows and submit a PR matching the requirements above.