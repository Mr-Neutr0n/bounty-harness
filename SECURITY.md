# Security Policy

## Scope

This security policy applies to **bugs in the bb_agent_toolkit software itself** — the
harness, tools, skill packages, and supporting scripts in this repository.

**Target applications, bug bounty programs, and remote systems are not in scope**
for this policy. Do not use this channel to report vulnerabilities you find in
third-party hosts or services. Report those to the relevant program directly.

## Reporting a Vulnerability

If you discover a security issue in the bb_agent_toolkit codebase:

1. **Do not open a public issue.** Instead, email
   `security@example.com` (replace with your actual security contact).

2. Include:
   - A clear description of the issue
   - Steps to reproduce
   - Affected versions (commit hash or release tag)
   - Any suggested mitigations

3. You will receive an acknowledgment within **3 business days**.

## Response Timeline

| Phase | Commitment |
|---|---|
| Acknowledgment | Within 3 business days |
| Triage and initial assessment | Within 5 business days |
| Fix and public disclosure | Within 90 days |

We keep reporters informed of progress and coordinate disclosure timing.

## Safe Harbor

We will not pursue legal action against researchers who:

- Act in good faith to identify vulnerabilities in this codebase
- Follow responsible disclosure practices
- Avoid data destruction, denial of service, or privacy violations
- Do not access or modify data belonging to other users

## Out of Scope

- Vulnerabilities in third-party dependencies (report upstream)
- Bugs in example or test-only code that do not represent real workflows
- Theoretical issues with no practical exploit path
- Social engineering of project maintainers