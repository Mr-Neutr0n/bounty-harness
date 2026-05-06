#!/usr/bin/env python3
"""Markdown report generator — produces a professional vulnerability report from finding data.

Usage:
    report_generator.py --finding-json finding.json --context output/reports
    report_generator.py --finding-json finding.json --context output/reports --vuln-type sqli
    report_generator.py --finding-dir evidence/finding_001 --context output/reports --vuln-type xss
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_date() -> str:
    return datetime.now(timezone.utc).strftime("%B %d, %Y")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def severity_badge(severity: str) -> str:
    colors = {
        "critical": "#8B0000",
        "high": "#CC0000",
        "medium": "#CC7000",
        "low": "#0066CC",
        "none": "#999999",
        "info": "#999999",
    }
    sev_lower = severity.lower()
    color = colors.get(sev_lower, "#999999")
    return f'<span style="background-color:{color};color:white;padding:4px 8px;border-radius:4px;font-weight:bold">{severity.upper()}</span>'


REMEDIATION_TEMPLATES: dict[str, str] = {
    "sqli": """## Remediation

1. **Use parameterized queries (prepared statements)** for all database interactions.
2. Never concatenate user input into SQL query strings.
3. Use an ORM with built-in protections (e.g., SQLAlchemy, Django ORM, Hibernate).
4. Apply input validation and allowlisting on all user-supplied data.
5. Implement proper error handling that never exposes SQL errors to clients.
6. Use the principle of least privilege for database accounts.

### Example (Python):
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```""",

    "xss": """## Remediation

1. **Contextually encode output** before rendering in HTML (HTML entity encoding, JS encoding, URL encoding).
2. Use Content-Security-Policy (CSP) headers to restrict script execution sources.
3. Set the `HttpOnly` flag on session cookies.
4. Implement `X-XSS-Protection: 1; mode=block` header.
5. Use modern frameworks that auto-escape by default (React, Vue, Angular).
6. Validate and sanitize all user input on both client and server sides.

### Example (HTTP header):
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```""",

    "ssrf": """## Remediation

1. **Allowlist** permitted destination hosts/IPs.
2. Deny connections to internal/private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254).
3. Disable HTTP redirect following, or validate redirect targets before following.
4. Use a dedicated proxy/firewall for outbound requests from the application.
5. Resolve hostnames to IPs and validate them against the allowlist.
6. Restrict supported URL schemes to http/https only.

### Example (Go net.Dialer control):
```go
dialer.Control = func(network, address string, c syscall.RawConn) error {
    host, _, _ := net.SplitHostPort(address)
    ip := net.ParseIP(host)
    if ip.IsPrivate() { return fmt.Errorf("private IP blocked") }
    return nil
}
```""",

    "idor": """## Remediation

1. Use indirect object references (UUIDs, random tokens) instead of sequential IDs.
2. **Verify ownership** of every object on every request — never trust client-supplied IDs alone.
3. Implement proper authorization checks in middleware, not per-endpoint.
4. Use access control lists (ACLs) with role-based access control (RBAC).
5. Log and alert on unauthorized access attempts to detect abuse.

### Example (ownership check):
```python
obj = get_object(request.id)
if obj.owner_id != request.user.id:
    raise PermissionDenied
```""",

    "auth_bypass": """## Remediation

1. Enforce authentication uniformly via middleware — never per-endpoint.
2. Validate session tokens/JWTs on **every** request, not just at login.
3. Set short token expiry with secure refresh mechanisms.
4. Use TLS for all authentication-related traffic.
5. Implement account lockout and rate limiting on login attempts.
6. Require MFA for sensitive operations.

### Example (JWT validation middleware):
```python
@app.before_request
def check_auth():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.current_user = payload
    except jwt.InvalidTokenError:
        abort(401)
```""",

    "rce": """## Remediation

1. **Never pass user input to system shells** (`os.system`, `subprocess.call(shell=True)`, `eval`, `exec`).
2. Use built-in language APIs instead of shell commands (e.g., `subprocess.run` with `shell=False` and argument list).
3. If shell commands are unavoidable, use strict input allowlisting.
4. Disable dangerous PHP functions (`exec`, `system`, `passthru`, `shell_exec`, `popen`).
5. Use application sandboxing and OS-level protections (seccomp, AppArmor, SELinux).
6. Keep all libraries and frameworks updated.

### Example (safe subprocess):
```python
subprocess.run(['ls', user_provided_path], shell=False, check=True)
```""",

    "file_upload": """## Remediation

1. **Allowlist** file extensions — never use denylists.
2. Validate file content-type via magic bytes, not file extension or MIME type.
3. Store uploaded files outside the web root.
4. Use random filenames — never preserve user-supplied names.
5. Scan uploads with antivirus/antimalware tools.
6. Set proper permissions on upload directories (no execute).
7. Limit file size and enforce rate limiting.

### Example (extension allowlist):
```python
ALLOWED = {'.jpg', '.png', '.pdf', '.docx'}
ext = os.path.splitext(file.name)[1].lower()
if ext not in ALLOWED:
    raise InvalidUploadError
```""",

    "default": """## Remediation

1. Apply the **principle of least privilege**.
2. Implement proper input validation and output encoding.
3. Use defense in depth — layer multiple security controls.
4. Conduct regular security testing and code reviews.
5. Keep all dependencies and frameworks updated.
6. Follow secure coding guidelines (OWASP, CWE top 25).
7. Implement proper logging and monitoring to detect abuse.

### References:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)""",
}

REFERENCES: dict[str, str] = {
    "sqli": "[OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)",
    "xss": "[OWASP XSS](https://owasp.org/www-community/attacks/xss/) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [WSTG-INPV-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)",
    "ssrf": "[OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | [WSTG-INPV-19](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)",
    "idor": "[OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | [CWE-639](https://cwe.mitre.org/data/definitions/639.html)",
    "auth_bypass": "[OWASP Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [WSTG-ATHN](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)",
    "rce": "[OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | [WSTG-INPV-12](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)",
    "file_upload": "[OWASP File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | [WSTG-BUSL-08](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types)",
    "default": "[OWASP Top 10](https://owasp.org/www-project-top-ten/) | [CWE Top 25](https://cwe.mitre.org/top25/)",
}


def load_finding(finding_json: Optional[str], finding_dir: Optional[str]) -> dict:
    finding: dict = {}
    if finding_json:
        with open(finding_json, encoding="utf-8") as f:
            if finding_json.endswith(".jsonl"):
                for line in f:
                    finding = json.loads(line.strip())
            else:
                finding = json.load(f)
    elif finding_dir:
        jl = Path(finding_dir) / "findings.jsonl"
        if jl.exists():
            with open(jl, encoding="utf-8") as f:
                for line in f:
                    finding = json.loads(line.strip())
        js = Path(finding_dir) / "finding.json"
        if js.exists() and not finding:
            finding = json.loads(js.read_text(encoding="utf-8"))
        manifest = Path(finding_dir) / "manifest.json"
        if manifest.exists() and not finding:
            finding = json.loads(manifest.read_text(encoding="utf-8"))
    else:
        log("No finding source provided")
        sys.exit(1)
    return finding


def collect_evidence(finding_dir: Optional[str]) -> str:
    if not finding_dir:
        return ""
    evidence_dir = Path(finding_dir) / "evidence"
    if not evidence_dir.exists():
        return ""

    lines: list[str] = []
    lines.append("## Evidence\n")
    for f in sorted(evidence_dir.iterdir()):
        if f.is_file():
            rel = f.name
            lines.append(f"- **[{rel}](evidence/{rel})**  ")
            if f.suffix in (".png", ".jpg", ".jpeg"):
                lines.append(f"  ![Screenshot](evidence/{rel})  ")
    return "\n".join(lines) if lines else ""


def build_report(finding: dict, vuln_type: str, ctx: Path, evidence_md: str = "") -> str:
    title = finding.get("title", finding.get("name", "Unnamed Finding"))
    severity = finding.get("severity", "medium").lower()
    score = finding.get("cvss", finding.get("base_score", finding.get("score", "N/A")))
    description = finding.get("description", finding.get("summary", ""))
    steps = finding.get("steps_to_reproduce", finding.get("steps", finding.get("reproduction", "")))
    impact = finding.get("impact", finding.get("business_impact", ""))
    url = finding.get("url", finding.get("endpoint", finding.get("target", "")))
    method = finding.get("method", finding.get("http_method", "GET"))

    if isinstance(steps, list):
        steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    else:
        steps_str = str(steps) if steps else "_No reproduction steps provided_"

    if isinstance(description, list):
        desc_str = "\n".join(f"- {d}" for d in description)
    else:
        desc_str = str(description) if description else "_No description provided_"

    if isinstance(impact, list):
        imp_str = "\n".join(f"- {i}" for i in impact)
    else:
        imp_str = str(impact) if impact else "_Impact not specified_"

    remediation = REMEDIATION_TEMPLATES.get(vuln_type, REMEDIATION_TEMPLATES["default"])
    references = REFERENCES.get(vuln_type, REFERENCES["default"])

    md = f"""# {title}

**Severity:** {severity_badge(severity)}
**CVSS Score:** `{score}`
**Date:** {now_date()}
**Vulnerability Type:** `{vuln_type.upper() if vuln_type != "default" else "GENERAL"}`
{f"**Affected URL:** `{url}`" if url else ""}
{f"**HTTP Method:** `{method}`" if method else ""}

---

## Description

{desc_str}

---

## Steps to Reproduce

{steps_str}

---

## Impact

{imp_str}

---

{evidence_md}

{remediation}

---

## References

{references}

---

> Generated by bug-bounty-agent on {now_date()}
"""
    return md


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Markdown vulnerability report generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  report.md    Complete markdown vulnerability report

Supported --vuln-type values:
  sqli, xss, ssrf, idor, auth_bypass, rce, file_upload, default
""",
    )
    p.add_argument("--finding-json", "-j", default=None, help="Path to finding JSON or JSONL file")
    p.add_argument("--finding-dir", "-d", default=None, help="Path to finding directory with evidence/")
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--vuln-type", "-t", default="default", choices=list(REMEDIATION_TEMPLATES.keys()), help="Vulnerability type for remediation & references")
    p.add_argument("--dry-run", action="store_true", help="Validate inputs without writing report")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    if not args.finding_json and not args.finding_dir:
        log("ERROR: --finding-json/-j or --finding-dir/-d is required")
        sys.exit(1)

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)

    log(f"Loading finding data...")
    finding = load_finding(args.finding_json, args.finding_dir)

    if args.dry_run:
        print(json.dumps({"dry_run": True, "finding_keys": list(finding.keys()), "vuln_type": args.vuln_type}))
        return

    evidence_md = collect_evidence(args.finding_dir)

    report = build_report(finding, args.vuln_type, ctx, evidence_md)

    out_path = ctx / "report.md"
    out_path.write_text(report, encoding="utf-8")
    log(f"Report written → {out_path}")

    print(json.dumps({"report": str(out_path), "severity": finding.get("severity", "unknown"), "vuln_type": args.vuln_type, "size_bytes": len(report)}))


if __name__ == "__main__":
    main()