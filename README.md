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

## Skill Areas

- Recon and asset inventory
- Domain modeling and attack-surface planning
- Web vulnerabilities: XSS, SQLi, SSRF, RCE, upload, CORS/CSRF, race conditions
- API and GraphQL testing
- Auth, session, OAuth, MFA, and cross-account authorization testing
- Business logic and workflow abuse testing
- Cloud, mobile, browser, and HTTP protocol checks
- AI/LLM, RAG, MCP, and agent safety testing
- OOB callback infrastructure and impact verification
- Reporting, coverage tracking, and program memory

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
- Do not vendor large third-party scanner template repositories; install them locally instead.
- Verify impact before reporting a scanner result as a finding.

## License

MIT License. See `LICENSE`.
