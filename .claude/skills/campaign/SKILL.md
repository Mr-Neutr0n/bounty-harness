# Campaign — Autonomous End-to-End Bug Bounty Run

## Overview
The `campaign` skill turns a single target into a full, hands-off engagement. From one URL it runs context init, recon, domain modeling, technique matching, planning, then executes every applicable skill workflow in priority order (filtered by a safety ceiling), and finishes with reporting and readiness checks. The run is bounded by a wall-clock time budget, is resumable, and never aborts the whole campaign because one workflow failed.

This is the entry point for "here's a URL — go find everything you can." The deterministic engine is `scripts/campaign_runner.py` (invoked by `bin/bb-hunt` or `bin/bb-run campaign hunt`). The judgement parts — understanding the target, triage, and impact verification — are driven by the agent following the loop below.

## Quick Reference
| Goal | Command |
|---|---|
| Hunt a brand-new URL (cold start, does its own init) | `bin/bb-hunt <url> --time-budget 2h` |
| Hunt with intrusive blackbox testing (requires authorization) | `bin/bb-hunt <url> --scope-file <auth> --max-tier intrusive --time-budget 3h` |
| Hunt using an already-initialized context | `bin/bb-run campaign hunt` |
| Check progress | `bin/bb-run campaign status` |
| Resume an interrupted run | `bin/bb-hunt <url> --no-init --resume <campaign-id>` |
| Preview the full plan without executing | `bin/bb-hunt <url> --dry-run` |

Safety ceiling defaults to `intrusive` but is **auto-capped to `active-safe` unless a non-empty `--scope-file` is supplied** — intrusive blackbox testing only runs against targets you have authorization for. Credentials, cookies, tokens, and target responses are kept local-only, are never committed (the `.bb/` and `output/` trees are gitignored), and must be redacted/sanitized before any report leaves the machine.

## Workflow Selection
- New target, no prior recon, "find all vulns", "run for a while", a bare URL → start here with `bin/bb-hunt`.
- Authorization confirmed / scope file in hand and you want active+intrusive blackbox coverage → `--scope-file <auth> --max-tier intrusive`.
- Context already initialized for the target → `bin/bb-run campaign hunt` (or `hunt-intrusive`).
- A previous campaign was interrupted → `resume` with its campaign id.
- You only want recon/triage, not full execution → run the individual `recon`, `domain-model`, `planner` skills instead.

## Agent Loop (how the agent drives a campaign)
1. **Authorization.** Confirm the user is authorized to test the target. If they have a scope/authorization file, pass it with `--scope-file` to unlock intrusive testing; without it the run stays at `active-safe`.
2. **Understand the target (web search).** Before or alongside launch, use web search and the `vuln-intel` and `osint` skills to learn what the target is: the company, its tech stack and frameworks, login/SSO providers, known CVEs for detected technologies, and any public bug bounty program scope and exclusions. Feed this into scope and into which skills to prioritize.
3. **Launch.** Run `bin/bb-hunt <url>` with the agreed `--max-tier` and `--time-budget`. The engine handles init → recon → domain model → plan → priority-ordered execution → reporting on its own.
4. **Monitor.** Poll `bin/bb-run campaign status` (or read `.bb/campaigns/<id>/status.json` and `campaign.log`). The run continues past individual workflow failures.
5. **Triage.** As findings land under `$OUTDIR`, do not treat scanner output as a finding. For each candidate, run the matching vulnerability skill's verify workflow and the `impact-verifier` skill to rule out false positives and classify impact.
6. **Report.** For confirmed, impact-verified findings, use the `reporting` skill (including `platform-export`) to produce platform-ready writeups with full evidence.

## Available Workflows
- `hunt` — full autonomous campaign using the already-initialized context (active-safe ceiling by default).
- `hunt-intrusive` — full campaign at the intrusive ceiling; requires `SCOPE_FILE` authorization.
- `status` — print the latest or named campaign status.
- `resume` — resume an interrupted campaign by id, skipping completed workflows.

The engine's safety ceiling, time budget, skill subset, and rate limit are all configurable; see `python3 scripts/campaign_runner.py hunt --help`.

## Evidence Required
- Campaign state lives under `.bb/campaigns/<campaign-id>/`: `campaign.log` (timestamped, redacted run log), `results.jsonl` (per-workflow exit codes and timing), and `status.json` (live phase and counts).
- Per-workflow findings and evidence land under `$OUTDIR` as defined by each individual skill.
- Keep all of the above local-only; redact or sanitize any auth headers, cookies, bearer tokens, and PII before a report leaves the machine. Nothing in `.bb/` or `output/` is committed.
- A finding is only reportable after the `impact-verifier` gate confirms impact and rules out false positives.

## References
- Engine: `scripts/campaign_runner.py` (`hunt`, `status`; `--help` for all flags)
- CLI wrapper: `bin/bb-hunt`
- Backbone skills: `recon`, `domain-model`, `technique-kb`, `planner`
- Triage/report: `impact-verifier`, `reporting`, `vuln-intel`, `osint`
- Source of truth for workflows: `skill.yaml`
