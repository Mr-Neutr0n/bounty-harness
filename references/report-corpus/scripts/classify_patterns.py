#!/usr/bin/env python3
"""
classify_patterns.py — Group normalized reports by bug_type + primitive,
extract common attack patterns, map to skill workflows.

Input:  normalized/*.jsonl (from normalize_reports.py)
Output: patterns/{bug_type}.jsonl with FindingPattern entries + coverage stats
"""

import argparse
import json
import sys
import os
import pathlib
import hashlib
from collections import defaultdict, Counter
from datetime import datetime


MIN_PATTERN_REPORTS = 3


SKILL_WORKFLOW_MAP: dict[str, list[str]] = {
    "xss": ["W1-reflected-param", "W2-stored-test", "W3-dom-scan", "W4-blind-xss", "W5-csp-bypass"],
    "sqli": ["W1-error-detection", "W2-blind-test", "W3-time-based", "W4-union-inject", "W5-boolean-blind"],
    "ssrf": ["W1-basic-probe", "W2-cloud-metadata", "W3-internal-scan", "W4-blind-ssrf", "W5-protocol-bypass"],
    "rce": ["W1-command-injection", "W2-ssti-probe", "W3-deserialization", "W4-lfi-rfi", "W5-eval-injection"],
    "idor": ["W1-bola-detection", "W2-id-enumeration", "W3-sequential-access", "W4-uuid-predictability"],
    "csrf": ["W1-token-validation", "W2-same-site-bypass", "W3-sensitive-action", "W4-json-csrf"],
    "xxe": ["W1-basic-entity", "W2-blind-xxe", "W3-ssrf-exfil", "W4-parameter-entities"],
    "race-condition": ["W1-send-concurrent", "W2-timing-window", "W3-turbo-style", "W4-token-reuse"],
    "ssti": ["W1-polyglot-probe", "W2-engine-fingerprint", "W3-os-execution", "W4-sandbox-escape"],
    "auth": ["W1-auth-flow-map", "W2-jwt-analysis", "W3-session-mgmt", "W4-oauth-misconfig", "W5-mfa-bypass"],
    "api": ["W1-endpoint-discovery", "W2-mass-assignment", "W3-rate-limit", "W4-graphql-introspection", "W5-sensitive-exposure"],
    "file-upload": ["W1-extension-fuzz", "W2-content-type-bypass", "W3-svg-xss", "W4-polyglot-payload", "W5-path-traversal-upload"],
    "cors-csrf": ["W1-cors-misconfig", "W2-null-origin", "W3-credentials-steal", "W4-preflight-bypass"],
    "mobile": ["W1-apk-decompile", "W2-deeplink-analysis", "W3-cert-pinning", "W4-api-intercept"],
    "cloud": ["W1-bucket-enum", "W2-metadata-probe", "W3-iam-fuzz", "W4-open-storage"],
}


ENTRYPOINT_PATTERNS: dict[str, dict] = {
    "email-change": {"primitive": "token misrouting", "impact": "account takeover"},
    "password-reset": {"primitive": "token leakage", "impact": "account takeover"},
    "oauth-callback": {"primitive": "redirect chain", "impact": "token theft"},
    "file-upload-endpoint": {"primitive": "extension bypass", "impact": "remote code execution"},
    "search-param": {"primitive": "reflected input", "impact": "javascript execution"},
    "api-endpoint": {"primitive": "missing authorization", "impact": "data exposure"},
    "graphql-mutation": {"primitive": "mass assignment", "impact": "privilege escalation"},
    "webhook-receiver": {"primitive": "request smuggling", "impact": "internal access"},
    "cache-key": {"primitive": "poisoned header", "impact": "stored XSS / deface"},
    "race-window": {"primitive": "concurrent requests", "impact": "duplicate action"},
}


def extract_primitive_from_desc(description: str, title: str) -> str:
    text = (description + " " + title).lower()
    primitives = [
        ("token misrouting", "token"), ("token leakage", "token"), ("token reuse", "token"),
        ("reflected input", "reflected"), ("stored input", "stored"),
        ("missing authorization", "authorization"), ("missing access control", "access control"),
        ("concurrent requests", "race"), ("race window", "race"), ("race condition", "race"),
        ("mass assignment", "mass"),
        ("command injection", "command"), ("code injection", "injection"),
        ("ssti", "template"), ("template injection", "template"),
        ("xxe", "xxe entity"), ("xml external entity", "xee"),
        ("extension bypass", "upload"), ("content-type bypass", "upload"),
        ("cors misconfiguration", "cors"), ("null origin", "cors"),
        ("request smuggling", "smuggling"), ("cache poisoning", "cache"),
        ("cache deception", "cache"), ("host header injection", "host header"),
        ("path traversal", "traversal"), ("directory traversal", "traversal"),
        ("local file inclusion", "lfi"), ("server side request forgery", "ssrf"),
        ("open redirect", "redirect"), ("clickjacking", "clickjacking"),
        ("subdomain takeover", "subdomain"), ("s3 bucket open", "s3"),
        ("oauth redirect", "oauth"), ("jwt none algorithm", "jwt"),
        ("2fa bypass", "2fa"), ("mfa bypass", "mfa"),
        ("session fixation", "session"), ("session hijacking", "session"),
        ("business logic", "logic"), ("logic flaw", "logic"),
    ]
    for primitive, keyword in primitives:
        if keyword in text:
            return primitive
    return "unspecified"


def extract_entrypoint_from_desc(description: str, title: str) -> str:
    text = (description + " " + title).lower()
    entrypoints = [
        "email-change", "password-reset", "oauth-callback", "file-upload", "file-upload-endpoint",
        "search-param", "search", "api-endpoint", "graphql-mutation", "graphql",
        "webhook-receiver", "webhook", "cache-key", "race-window",
        "login", "register", "checkout", "payment", "account-settings",
        "profile", "invite", "share", "export", "import",
        "admin-panel", "dashboard", "comment", "review",
        "subscription", "notification",
    ]
    for ep in entrypoints:
        if ep in text:
            return ep
    return "unknown"


def extract_tech_from_desc(description: str) -> list[str]:
    text = description.lower()
    all_tech = [
        "Ruby on Rails", "Django", "Flask", "Express", "Spring", "Laravel",
        "React", "Vue.js", "Angular", "Next.js", "Nuxt",
        "PostgreSQL", "MySQL", "MongoDB", "Redis", "Elasticsearch",
        "AWS", "GCP", "Azure", "Cloudflare", "Fastly",
        "Kubernetes", "Docker", "Terraform", "Ansible",
        "Jenkins", "GitLab CI", "GitHub Actions", "CircleCI",
        "Nginx", "Apache", "HAProxy", "Traefik",
        "GraphQL", "REST", "gRPC", "WebSocket",
        "SAML", "OAuth2", "OpenID Connect", "LDAP",
        "JWT", "Devise", "Passport", "Auth0", "Okta",
    ]
    found = [t for t in all_tech if t.lower() in text]
    return found[:5]


def compute_finding_pattern(group_key: str, reports: list[dict]) -> dict:
    bug_type = reports[0].get("bug_type", "unknown")
    primitives = Counter(
        r.get("primitive", "unspecified") for r in reports
    )
    dominant_primitive = primitives.most_common(1)[0][0] if primitives else "unspecified"
    impacts = Counter(r.get("impact", "unknown") for r in reports)
    dominant_impact = impacts.most_common(1)[0][0] if impacts else "unknown"

    entrypoints = Counter(
        r.get("entrypoint", "unknown") for r in reports
    )
    dominant_entrypoint = entrypoints.most_common(1)[0][0] if entrypoints else "unknown"

    sample_titles = [r.get("title", "") for r in reports[:5]]

    skill_mapping = reports[0].get("skill_mapping", [])
    workflow_ideas = []
    for skill in skill_mapping:
        if skill in SKILL_WORKFLOW_MAP:
            workflow_ideas.extend(SKILL_WORKFLOW_MAP[skill])

    pattern = {
        "pattern_id": hashlib.sha256(group_key.encode()).hexdigest()[:12],
        "pattern_name": f"{dominant_primitive.replace(' ', '-')}-via-{dominant_entrypoint}",
        "bug_type": bug_type,
        "primitive": dominant_primitive,
        "entrypoint": dominant_entrypoint,
        "impact": dominant_impact,
        "report_count": len(reports),
        "sample_reports": sample_titles,
        "detection_approach": f"Probe {dominant_entrypoint} for {dominant_primitive} behavior",
        "skill_mapping": skill_mapping,
        "workflow_ideas": list(dict.fromkeys(workflow_ideas))[:10],
        "confidence": "high" if len(reports) >= 10 else "medium",
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    return pattern


def main():
    parser = argparse.ArgumentParser(
        description="Classify finding patterns from normalized reports"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Directory containing normalized/*.jsonl files",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory to write pattern files (patterns/)",
    )
    args = parser.parse_args()

    input_dir = pathlib.Path(args.input)
    output_dir = pathlib.Path(args.output) / "patterns"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_dir.is_dir():
        print(f"Error: input directory '{input_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    jsonl_files = sorted(input_dir.glob("*.jsonl"))
    if not jsonl_files:
        print(f"Error: No .jsonl files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(jsonl_files)} JSONL input files", file=sys.stderr)

    all_reports: list[dict] = []

    for jf in jsonl_files:
        with open(jf, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    report = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"  Warning: skipping malformed JSON in {jf.name}: {e}", file=sys.stderr)
                    continue
                if not report.get("primitive") or not report.get("entrypoint"):
                    report["primitive"] = extract_primitive_from_desc(
                        report.get("description", ""), report.get("title", "")
                    )
                    report["entrypoint"] = extract_entrypoint_from_desc(
                        report.get("description", ""), report.get("title", "")
                    )
                if not report.get("target_tech"):
                    report["target_tech"] = extract_tech_from_desc(
                        report.get("description", "")
                    )
                all_reports.append(report)

    print(f"Total reports loaded: {len(all_reports)}", file=sys.stderr)

    groups: dict[str, list[dict]] = defaultdict(list)
    for r in all_reports:
        bt = r.get("bug_type", "unknown")
        primitive = r.get("primitive", "unspecified")
        group_key = f"{bt}|{primitive}"
        groups[group_key].append(r)

    all_patterns: dict[str, list[dict]] = defaultdict(list)
    pattern_count = 0

    for group_key, reports in sorted(groups.items()):
        if len(reports) < MIN_PATTERN_REPORTS:
            continue
        pattern = compute_finding_pattern(group_key, reports)
        bug_type = pattern["bug_type"]
        all_patterns[bug_type].append(pattern)
        pattern_count += 1
        print(f"  Pattern: {pattern['pattern_name']:50s} ({len(reports):3d} reports)", file=sys.stderr)

    for bug_type, patterns in sorted(all_patterns.items()):
        out_path = output_dir / f"{bug_type}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for pat in patterns:
                f.write(json.dumps(pat, ensure_ascii=False) + "\n")
        print(f"  Wrote {len(patterns)} patterns -> {out_path.name}", file=sys.stderr)

    coverage = {}
    for bug_type, patterns in sorted(all_patterns.items()):
        coverage[bug_type] = {
            "pattern_count": len(patterns),
            "workflows_covered": list(set(
                wf for p in patterns for wf in p.get("workflow_ideas", [])
            )),
            "primitives": list(set(p["primitive"] for p in patterns)),
        }

    stats = {
        "total_patterns": pattern_count,
        "bug_type_coverage": coverage,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }

    stats_path = output_dir / "_coverage.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"\nCoverage stats written to {stats_path}", file=sys.stderr)
    print(f"Total patterns: {pattern_count} across {len(all_patterns)} bug types", file=sys.stderr)

    for bt, info in sorted(coverage.items()):
        print(f"  {bt:25s}: {info['pattern_count']:3d} patterns, {len(info['primitives']):2d} primitives", file=sys.stderr)


if __name__ == "__main__":
    main()