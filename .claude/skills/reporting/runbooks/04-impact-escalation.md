# Reporting — Impact & Escalation

## Purpose
Produce business impact statements, remediation guidance, and severity mappings for each finding. Translate raw technical findings into language meaningful to triage teams: what can the attacker achieve, what data is at risk, and what is the remediation priority.

## Required Variables
- `$OUTDIR`: output directory for reports
- `$FINDING_TITLE`: title of the finding
- `$CVSS_SCORE`: CVSS score
- `$SEVERITY`: severity label

## Commands

```bash
python3 - "$OUTDIR/inventory/findings_scored.json" "$OUTDIR/inventory/findings_with_impact.json" << 'PYEOF'
import sys, json

VRT_MAP = {
    "sqli": "server_security_injection.sql_injection",
    "rce":  "server_security_injection.command_injection",
    "xss":  "server_security_injection.stored_xss",
    "ssrf": "server_security_misconfiguration.ssrf",
    "idor": "broken_access_control.idor_insecure_direct_object_reference",
    "idor-bola": "broken_access_control.idor_insecure_direct_object_reference",
    "auth-bypass": "broken_authentication_and_session_management.authentication_bypass",
    "file-upload": "server_security_misconfiguration.arbitrary_file_upload",
    "xxe":  "server_security_injection.xxe_external_entity_injection",
    "csrf": "broken_authentication_and_session_management.csrf",
    "cors": "server_security_misconfiguration.cors_misconfiguration",
    "open-redirect": "unvalidated_redirects_and_forwards.open_redirect",
    "info-disclosure": "server_security_misconfiguration.information_disclosure",
}

IMPACT_TEMPLATES = {
    "sqli": "An attacker can extract, modify, or delete data from the backend database, including user credentials, PII, and application secrets. Full database compromise is possible.",
    "rce": "An attacker can execute arbitrary operating system commands on the server. This enables full server compromise, lateral movement, and data exfiltration.",
    "xss": "An attacker can execute arbitrary JavaScript in a victim's browser, enabling session hijacking, credential theft, keylogging, and DOM manipulation.",
    "ssrf": "An attacker can force the server to make requests to internal services, including cloud metadata endpoints, internal APIs, and administrative interfaces.",
    "idor": "An attacker can access or modify resources belonging to other users by manipulating object references, leading to unauthorized data access and privilege escalation.",
    "auth-bypass": "An attacker can bypass authentication controls entirely, gaining unauthorized access to the application with full user privileges.",
    "file-upload": "An attacker can upload malicious files (webshells, malware) to the server, leading to remote code execution and persistent access.",
}

REMEDIATION_TEMPLATES = {
    "sqli": "Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL strings. Implement an ORM or query builder with built-in escaping.",
    "rce": "Avoid passing user input to system shells or command interpreters. Use language-native APIs instead of shell commands. Sanitize and whitelist input if system calls are unavoidable.",
    "xss": "Apply context-aware output encoding (HTML entity, JavaScript, CSS, URL). Implement a strict Content-Security-Policy header. Use framework auto-escaping (React, Vue, Angular).",
    "ssrf": "Implement a strict URL allowlist for outbound requests. Block requests to RFC 1918, link-local, and loopback addresses at the network layer. Disable unnecessary URL schemes (file://, gopher://, dict://).",
    "idor": "Use indirect object references (UUIDs or opaque tokens) instead of sequential IDs. Enforce server-side authorization checks for every resource access. Never trust client-supplied identifiers.",
}

def classify(template_str):
    t = template_str.lower()
    for key in IMPACT_TEMPLATES:
        if key in t:
            return key
    return None

with open(sys.argv[1]) as fh:
    findings = json.load(fh)

for f in findings:
    cls = classify(f.get("template", ""))
    if cls:
        f["vrt_category"] = VRT_MAP.get(cls, "unclassified")
        f["business_impact"] = IMPACT_TEMPLATES[cls]
        f["remediation"] = REMEDIATION_TEMPLATES[cls]
    else:
        f["vrt_category"] = "unclassified"
        f["business_impact"] = "The vulnerability may expose sensitive data or allow unauthorized actions. A detailed impact assessment requires further analysis."
        f["remediation"] = "Apply defense-in-depth controls: input validation, output encoding, least-privilege access, and regular security testing."

with open(sys.argv[2], 'w') as fh:
    json.dump(findings, fh, indent=2)
print(f"Added impact/remediation to {len(findings)} findings. Output: {sys.argv[2]}")
PYEOF

jq -r '.[]|"\(.severity) | CVSS \(.cvss_v31) | VRT: \(.vrt_category)\n  → \(.business_impact)"' "$OUTDIR/inventory/findings_with_impact.json" > "$OUTDIR/inventory/impact_summary.txt"
cat "$OUTDIR/inventory/impact_summary.txt"
```

## CVSS ↔ HackerOne VRT ↔ Qualitative Mapping

| CVSS v3.1 | Qualitative | HackerOne VRT Priority | Bounty Multiplier |
|-----------|-------------|------------------------|-------------------|
| 9.0–10.0  | Critical    | P1 — Critical          | 1.0x              |
| 7.0–8.9   | High        | P2 — High              | 0.7x              |
| 4.0–6.9   | Medium      | P3 — Medium            | 0.4x              |
| 0.1–3.9   | Low         | P4 — Low               | 0.1x              |
| 0.0       | Informational | P5 — None            | 0.0x              |

## Detection Signals
- All findings have a business impact statement (not empty)
- Remediation is concrete and actionable (not generic)
- VRT mapping is present for every finding
- Severity mapping matches CVSS qualitative ranges

## Next
├── If impact + remediation complete → `05-evidence-collection.md`
├── If custom impact needed for unique vuln class → write manually, merge in
└── If VRT category unknown → flag for triage team