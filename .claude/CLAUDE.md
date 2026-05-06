# Bug Bounty Agent Toolkit

## Architecture

```text
Fat Skills = scripts, payloads, wordlists, runbooks, evidence rules, standards mappings, and runnable commands live in .claude/skills/.
Thin Harness = context initialization, context validation, and selected workflow execution only.
Agent Role = dispatch, triage, report. Do not invent flags or ad-hoc pipelines when a skill workflow exists.
```

The harness is deliberately small:

| File | Job |
|---|---|
| `bin/bb-init` | Creates `.bb/context.env` and `.bb/context.json`. |
| `bin/bb-validate` | Checks context and scope file presence. |
| `bin/bb-run` | Runs one command from `.claude/skills/<skill>/skill.yaml`. |
| `bin/bb-tools` | Install, update, verify, and lock external tools. |
| `tools/validate_skills.py` | Scores skill package quality. |

Do not move bug bounty logic into the harness. Add or change workflows inside the relevant skill package.

## Tool Registry

External tools are managed through a registry so agents never invent install commands.

| File | Purpose |
|---|---|
| `tools/registry/*.yaml` | Canonical tool definitions with install method, version/health check, capabilities, risk tier |
| `tools/capabilities.yaml` | Maps capability names (e.g., `subdomain_enum`, `crawl`) to tools |
| `tools/safety_profiles.yaml` | Safety tiers: passive, active-safe, intrusive, destructive-manual |
| `bin/bb-tools` | Thin harness command: install, doctor, lock, verify |

Commands:
- `bin/bb-tools list` — all tools in registry
- `bin/bb-tools list --installed` — only installed
- `bin/bb-tools list --missing` — required by skills but missing
- `bin/bb-tools doctor` — health check all tools
- `bin/bb-tools doctor --skill <skill>` — health check for one skill
- `bin/bb-tools install --profile projectdiscovery` — install PD suite
- `bin/bb-tools install --profile recon` — install recon tools
- `bin/bb-tools install <tool>` — install single tool
- `bin/bb-tools lock` — write `.bb/tool-lock.json`
- `bin/bb-tools verify` — verify lock against installed versions

`bb-validate` checks that the tool registry is populated and warns about missing tools.
`bb-run` warns when a selected workflow needs a tool that is not on PATH.

## Environment

```bash
export PATH="/opt/homebrew/bin:$HOME/.pdtm/go/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
```

All workflows assume this PATH. Prefer Homebrew tool builds when both Homebrew and Go/Python installs exist.

## RunContext

`bin/bb-init` writes the canonical context to `.bb/context.env` and `.bb/context.json`.

Common variables:

| Variable | Meaning |
|---|---|
| `TARGET` | Primary target domain. |
| `PROGRAM` | Bug bounty program name. |
| `TARGET_HOST` | Hostname version of target. |
| `TARGET_URL` | Scheme and host URL. |
| `OUTDIR` | Output directory for the current run. |
| `EVIDENCE_DIR` | Default evidence directory. |
| `SCOPE_FILE` | Local authorization or scope file. |
| `AUTH_HEADER` | Optional auth header for authenticated workflows. |
| `COOKIE_JAR` | Optional cookie jar path. |
| `RATE_LIMIT` | Default rate limit. |
| `CONCURRENCY` | Default concurrency. |
| `USER_AGENT` | Security research user agent. |

Workflow-specific variables are allowed, but `skill.yaml` should provide safe defaults where practical. Examples: `QUERY`, `PLAN`, `PLAN_OUTPUT`, `DOMAIN_PROFILE`, `COVERAGE_MATRIX`, `ARCHETYPES_FILE`, `SURFACES_FILE`.

## Default Workflow

For a new target with no prior recon:

```text
1. bin/bb-init <target> --program <program> --scope-file <scope>
2. bin/bb-validate
3. bin/bb-run recon passive-subdomains
4. bin/bb-run recon live-discovery
5. bin/bb-run recon js-recon
6. bin/bb-run domain-model classify
7. bin/bb-run domain-model map-surfaces
8. bin/bb-run domain-model profile
9. bin/bb-run technique-kb match
10. bin/bb-run planner generate-plan-safe
11. bin/bb-run planner visualize-plan
12. Run selected vulnerability skills from the plan.
13. bin/bb-run reporting <workflow> when evidence is ready.
```

For a target with prior recon, load the most specific skill directly and use the workflows in that skill's `skill.yaml`.

## Skill Loading

Every skill lives at `.claude/skills/<skill>/`.

| File or directory | Purpose |
|---|---|
| `SKILL.md` | Human-facing router, workflow selection, evidence notes, references. |
| `skill.yaml` | Machine-executable workflow registry consumed by `bin/bb-run`. |
| `scripts/` | Prebuilt command implementations. |
| `runbooks/` | Manual triage and execution guidance. |
| `payloads/` | Static payloads, test cases, or fixtures. |

Always prefer `bin/bb-run <skill> <workflow>` after context is initialized. If you must run a command manually, copy it from `skill.yaml` or a runbook and preserve the same output paths.

## Skill Catalog

| # | Skill | Purpose |
|---|---|---|
| 1 | `recon` | Subdomains, live hosts, crawling, JavaScript recon, asset inventory. |
| 2 | `xss` | Reflected, stored, DOM, blind XSS, CSP and context checks. |
| 3 | `sqli` | Error, blind, time-based, union, and NoSQL injection probes. |
| 4 | `ssrf` | Direct, blind, parser-bypass, and cloud metadata SSRF testing. |
| 5 | `rce` | Command injection, SSTI, LFI/RFI, and execution checks. |
| 6 | `auth` | JWT, OAuth, session, MFA, password reset, and auth race testing. |
| 7 | `api` | REST, GraphQL, BOLA/IDOR, mass assignment, and rate-limit testing. |
| 8 | `file-upload` | Extension bypass, content-type bypass, polyglots, SVG and upload checks. |
| 9 | `cors-csrf` | CORS misconfigurations, CSRF, SameSite, and origin behavior. |
| 10 | `race-condition` | Concurrent requests, TOCTOU, redeem/retry, and timing-window testing. |
| 11 | `cloud` | S3, bucket exposure, cloud asset, IAM, and metadata-adjacent checks. |
| 12 | `mobile` | APK analysis, deeplinks, and cert-pinning helper workflows. |
| 13 | `osint` | Email, username, GitHub, Google dork, and public-source discovery. |
| 14 | `privesc` | Linux, Docker, SUID, capabilities, cron, and container escape enumeration. |
| 15 | `nuclei-scanner` | Scope-aware nuclei template execution and result validation. |
| 16 | `reporting` | Evidence manifests, CVSS, single finding reports, and batch report export. |
| 17 | `ai-llm` | Prompt injection, tool abuse, data exfiltration, and LLM trust-boundary testing. |
| 18 | `modern-browser` | WebGPU, WASM, XS-Leaks, browser isolation, and client-side protocol edge cases. |
| 19 | `http-protocol` | Request smuggling, cache poisoning, parser differentials, and HTTP edge cases. |
| 20 | `domain-model` | Target archetype classification and attack surface mapping. |
| 21 | `standard-catalog` | Canonical standards references for WSTG, ASVS, API Top 10, VRT, CWE, MASVS, KEV, and PortSwigger topics. |
| 22 | `coverage` | Coverage ledger and gap reporting across security standards. |
| 23 | `technique-kb` | Structured technique catalog with preconditions, signals, evidence, safety, and workflow mappings. |
| 24 | `planner` | Domain-driven ranked test plan generator and visualizer. |
| 25 | `auto-research` | Public security knowledge import, normalization, deduplication, and candidate review. |
| 26 | `evaluation-harness` | Vulnerable-by-design fixtures and precision/recall/F1 skill evaluation. |
| 27 | `skill-scientist` | Hypothesize, design, run, review, and propose skill improvements. |
| 28 | `persona` | Attacker/victim/admin persona management, credential storage, session validation. |
| 29 | `traffic-corpus` | HAR/Burp/mitmproxy traffic import, route normalization, object extraction. |
| 30 | `asset-graph` | SQLite-based persistent asset graph with delta, hotlist, and planner integration. |
| 31 | `cross-account` | Cross-persona request replay for BOLA/IDOR/tenant isolation testing. |
| 32 | `business-logic` | Workflow state machine testing for skip, repeat, reorder, race, and invariants. |
| 33 | `oob-infra` | Interactsh-based OOB callback infrastructure for blind vulnerability detection. |
| 34 | `impact-verifier` | Candidate-to-bounty-grade verification gate with impact classification. |
| 35 | `agent-safety` | AI agent guardrails against prompt injection in target content. |
| 36 | `program-memory` | Per-program knowledge persistence across engagements. |

## Dispatch Rules

| User intent | First skill |
|---|---|
| New target, scan domain, enumerate, map attack surface | `recon` then `domain-model` then `planner` |
| XSS, cross-site scripting, JavaScript injection, CSP bypass | `xss` |
| SQL injection, NoSQL injection, database error, blind SQL | `sqli` |
| SSRF, metadata endpoint, internal URL fetch, webhook URL fetch | `ssrf` |
| RCE, command injection, SSTI, LFI, deserialization | `rce` |
| Login, JWT, OAuth, session, MFA, password reset | `auth` |
| REST, GraphQL, BOLA, IDOR, mass assignment, rate limit | `api` |
| File upload, SVG, polyglot, content type, extension bypass | `file-upload` |
| CORS, CSRF, SameSite, origin reflection | `cors-csrf` |
| Race condition, concurrent requests, TOCTOU | `race-condition` |
| S3, bucket, IAM, cloud asset, metadata | `cloud` |
| APK, IPA, Android, iOS, deeplink, Frida | `mobile` |
| OSINT, email, username, GitHub dork, Google dork | `osint` |
| Privilege escalation, SUID, capabilities, Docker escape | `privesc` |
| Nuclei, CVE scan, template scan, automated vulnerability scan | `nuclei-scanner` |
| Report, writeup, PoC, evidence export | `reporting` |
| LLM, prompt injection, tool abuse, AI agent security | `ai-llm` |
| WebGPU, WASM, XS-Leaks, browser isolation | `modern-browser` |
| HTTP smuggling, cache poisoning, parser differential | `http-protocol` |
| Standards lookup or mapping | `standard-catalog` |
| Coverage gaps or quality dashboard | `coverage` |
| Technique lookup, matching, or precondition analysis | `technique-kb` |
| Ranked plan from recon data | `planner` |
| Import new public research | `auto-research` |
| Measure skill precision/recall/F1 | `evaluation-harness` |
| Propose new skill experiments | `skill-scientist` |

| Authenticated testing, multi-account, session management | `persona` then `cross-account` |
| Import traffic, build replay corpus | `traffic-corpus` |
| Asset relationship graph, hotlists, delta analysis | `asset-graph` |
| IDOR, BOLA, tenant isolation, cross-account diffs | `cross-account` |
| Workflow abuse, state transitions, business invariants | `business-logic` |
| Blind vulns, OOB callbacks, interactsh management | `oob-infra` |
| Verify finding impact before reporting | `impact-verifier` |
| Protect AI agent from prompt injection | `agent-safety` |
| Program knowledge, false-positive history | `program-memory` |

If multiple skills matchIf multiple skills match, pick the most specific vulnerability class after recon. If no skill matches but a domain is provided, start with `recon`. If scope is unclear, ask for authorization before intrusive testing.

## Evidence Standard

For every confirmed finding, collect:

| Artifact | Saved as |
|---|---|
| Full request with headers | `evidence/<finding>/request.txt` |
| Full response headers and body | `evidence/<finding>/response.txt` |
| Screenshot or visual proof | `evidence/<finding>/screenshot.png` |
| Reproduction command or script | `evidence/<finding>/poc.sh` |
| Timestamp | included in manifest or filenames |
| Tool versions | evidence manifest |

Do not report scanner output as a finding until impact is verified and false-positive signals are ruled out.

## Safety Rules

- Check authorization and scope before intrusive, authenticated, destructive, or high-volume workflows.
- Use rate limits from context or the workflow.
- Do not test explicit out-of-scope hosts.
- Do not exploit data-modifying paths without approval.
- Do not store secrets in logs or commits.
- Run `gitleaks detect --source . --no-git -v` before committing generated evidence that could contain tokens.

## Validation

```bash
make test
python3 tools/validate_skills.py
```

Expected healthy state: all skills pass the validator and Python scripts compile.
