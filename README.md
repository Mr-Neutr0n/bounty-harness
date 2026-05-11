# bb_agent_toolkit

`bb_agent_toolkit` is a practical bug bounty agent toolkit built around a thin harness and fat skill packages.

The harness stays small: it initializes target context, validates scope, manages external tools, and runs selected workflows. The security knowledge lives in reusable skills: recon, API testing, auth testing, business logic, AI/LLM security, evidence handling, reporting, and more.

Use this only for systems you are authorized to test.

## What It Includes

- 36 skill packages for common bug bounty workflows
- Domain-driven planning from recon data to ranked test plans
- Scope-aware execution through `bin/bb-run <skill> <workflow>`
- Tool registry for installing and checking external security tools
- Runbooks, payloads, scripts, and evidence guidance per skill
- Support for authenticated testing, cross-account replay, business logic testing, OOB callbacks, and impact verification

## Project Model

The toolkit follows a simple split:

| Layer | Role |
|---|---|
| Thin harness | Context setup, validation, tool checks, workflow dispatch |
| Fat skills | Scripts, payloads, runbooks, workflow definitions, evidence rules |
| RunContext | Current target, program, scope file, output paths, auth inputs |
| Tool registry | Canonical list of external tools and install/check commands |

If a workflow needs to change, update the relevant skill package. The harness should stay boring.

## Quick Start

```bash
git clone https://github.com/Mr-Neutr0n/bb_agent_toolkit.git
cd bb_agent_toolkit

export PATH="/opt/homebrew/bin:$HOME/.pdtm/go/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

bin/bb-init example.com --program example --scope-file ./engagements/example/scope.md
bin/bb-validate
bin/bb-run recon passive-subdomains
bin/bb-run recon live-discovery
bin/bb-run domain-model classify
bin/bb-run planner generate-plan-safe
```

`engagements/`, `.bb/`, and `output/` are intentionally ignored by git. Keep target scopes, notes, credentials, evidence, and generated results there or outside the repository.

## Common Commands

```bash
bin/bb-tools list
bin/bb-tools doctor
bin/bb-tools install --profile recon

bin/bb-run recon passive-subdomains
bin/bb-run api graphql-map
bin/bb-run cross-account build-matrix
bin/bb-run impact-verifier readiness-report
```

## Skill Catalog

| # | Skill | Purpose |
|---|---|---|
| 1 | `recon` | Subdomains, live hosts, crawling, JavaScript recon, asset inventory |
| 2 | `xss` | Reflected, stored, DOM, blind XSS, CSP and context checks |
| 3 | `sqli` | Error, blind, time-based, union, and NoSQL injection probes |
| 4 | `ssrf` | Direct, blind, parser-bypass, and cloud metadata SSRF testing |
| 5 | `rce` | Command injection, SSTI, LFI/RFI, and execution checks |
| 6 | `auth` | JWT, OAuth, session, MFA, password reset, and auth race testing |
| 7 | `api` | REST, GraphQL, BOLA/IDOR, mass assignment, and rate-limit testing |
| 8 | `file-upload` | Extension bypass, content-type bypass, polyglots, SVG and upload checks |
| 9 | `cors-csrf` | CORS misconfigurations, CSRF, SameSite, and origin behavior |
| 10 | `race-condition` | Concurrent requests, TOCTOU, redeem/retry, and timing-window testing |
| 11 | `cloud` | S3, bucket exposure, cloud asset, IAM, and metadata-adjacent checks |
| 12 | `mobile` | APK analysis, deeplinks, and cert-pinning helper workflows |
| 13 | `osint` | Email, username, GitHub, Google dork, and public-source discovery |
| 14 | `privesc` | Linux, Docker, SUID, capabilities, cron, and container escape enumeration |
| 15 | `nuclei-scanner` | Scope-aware nuclei template execution and result validation |
| 16 | `reporting` | Evidence manifests, CVSS, single finding reports, batch report export |
| 17 | `ai-llm` | Prompt injection, tool abuse, data exfiltration, LLM trust-boundary testing |
| 18 | `modern-browser` | WebGPU, WASM, XS-Leaks, browser isolation, client-side protocol edge cases |
| 19 | `http-protocol` | Request smuggling, cache poisoning, parser differentials, HTTP edge cases |
| 20 | `domain-model` | Target archetype classification and attack surface mapping |
| 21 | `standard-catalog` | Standards references: WSTG, ASVS, API Top 10, VRT, CWE, MASVS, KEV |
| 22 | `coverage` | Coverage ledger and gap reporting across security standards |
| 23 | `technique-kb` | Structured technique catalog with preconditions, signals, evidence, safety |
| 24 | `planner` | Domain-driven ranked test plan generator and visualizer |
| 25 | `auto-research` | Public security knowledge import, normalization, deduplication, candidate review |
| 26 | `evaluation-harness` | Vulnerable-by-design fixtures and precision/recall/F1 skill evaluation |
| 27 | `skill-scientist` | Hypothesize, design, run, review, and propose skill improvements |
| 28 | `persona` | Attacker/victim/admin persona management, credential storage, session validation |
| 29 | `traffic-corpus` | HAR/Burp/mitmproxy traffic import, route normalization, object extraction |
| 30 | `asset-graph` | SQLite-based persistent asset graph with delta, hotlist, planner integration |
| 31 | `cross-account` | Cross-persona request replay for BOLA/IDOR/tenant isolation testing |
| 32 | `business-logic` | Workflow state machine testing for skip, repeat, reorder, race, invariants |
| 33 | `oob-infra` | Interactsh-based OOB callback infrastructure for blind vulnerability detection |
| 34 | `impact-verifier` | Candidate-to-bounty-grade verification gate with impact classification |
| 35 | `agent-safety` | AI agent guardrails against prompt injection in target content |
| 36 | `program-memory` | Per-program knowledge persistence across engagements |
| 37 | `vuln-intel` | CVE tracking, disclosed report hunting, PoC discovery |
| 38 | `scope-manager` | Scope definition, validation, versioning, guardrails |

## Validation

Run these before submitting changes:

```bash
make test
python3 tools/validate_skills.py
```

The validator checks skill metadata, workflow definitions, script availability, Python syntax, `--help` behavior, runbooks, and payload coverage.

## Safety

- Test only targets where you have authorization.
- Respect program scope and rate limits.
- Do not run intrusive or destructive workflows without explicit approval.
- Do not commit target evidence, cookies, tokens, HAR files, or generated output.
- Verify impact before reporting a scanner result as a finding.

## License

MIT License. See `LICENSE`.
