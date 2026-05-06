#!/usr/bin/env python3
"""Coverage Report Generator — produces a comprehensive markdown coverage report.

Generates:
  - Summary dashboard with overall coverage %
  - Per-standard breakdown with counts and percentages
  - Top 10 gaps by priority
  - Recommendations for next skill builds

Usage:
  python3 coverage_report.py --matrix coverage_matrix.yaml --output report.md
  python3 coverage_report.py --matrix coverage_matrix.yaml --output - --format json
  python3 coverage_report.py --help
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

STATUS_ORDER = ["covered", "partial", "missing", "manual", "not_applicable"]
STATUS_EMOJI = {
    "covered": "G",
    "partial": "Y",
    "missing": "R",
    "manual": "W",
    "not_applicable": "X",
}
STATUS_LABEL = {
    "covered": "Covered",
    "partial": "Partial",
    "missing": "Missing",
    "manual": "Manual Only",
    "not_applicable": "N/A",
}


def load_yaml(matrix_path: str) -> dict:
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip3 install pyyaml", file=sys.stderr)
        sys.exit(1)

    with open(matrix_path, "r") as f:
        data = yaml.safe_load(f)
    return data


def get_best_status(item: dict) -> str:
    covered_by = item.get("covered_by", [])
    if not covered_by:
        return "missing"
    return min(
        (e.get("status", "missing") for e in covered_by),
        key=lambda s: STATUS_ORDER.index(s),
        default="missing",
    )


def compute_standard_stats(items: list[dict]) -> dict:
    total = len(items)
    counts = {s: 0 for s in STATUS_ORDER}
    for item in items:
        status = get_best_status(item)
        counts[status] += 1

    covered = counts.get("covered", 0)
    partial = counts.get("partial", 0)
    any_cov = covered + partial
    return {
        "total": total,
        "counts": counts,
        "covered_pct": round(covered / total * 100, 1) if total else 0.0,
        "any_coverage_pct": round(any_cov / total * 100, 1) if total else 0.0,
    }


def status_bar(counts: dict, total: int, width: int = 20) -> str:
    segments = []
    for status, label in [("covered", "C"), ("partial", "P"), ("missing", "M"), ("manual", "H"), ("not_applicable", "N")]:
        n = counts.get(status, 0)
        if n > 0:
            bar_len = max(1, round(n / total * width))
            segments.append((bar_len, label))
    result = ""
    for length, label in segments:
        result += label * length
    return result[:width].ljust(width)


def per_status_rows(counts: dict, total: int) -> str:
    lines = []
    for status in STATUS_ORDER:
        n = counts.get(status, 0)
        pct = f"{round(n / total * 100, 1)}%" if total else "0.0%"
        lines.append(f"| {STATUS_LABEL[status]} | {n} | {pct} |")
    return "\n".join(lines)


def format_markdown(data: dict) -> str:
    lines: list[str] = []
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("# Bug Bounty Toolkit — Coverage Report")
    lines.append("")
    lines.append(f"> Generated: {generated}  ")
    lines.append(f"> Matrix version: {data.get('version', 'unknown')}  ")
    lines.append(f"> Toolkit version: {data.get('toolkit_version', 'unknown')}  ")
    lines.append(f"> Skills: {data.get('toolkit_skills', '?')}  ")
    lines.append("")

    all_items: list[dict] = []
    standards_data: list[dict] = []

    for std in data.get("standards", []):
        std_items: list[dict] = []
        for section in std.get("sections", []):
            std_items.extend(section.get("items", []))
        stats = compute_standard_stats(std_items)
        all_items.extend(std_items)
        standards_data.append({
            "standard": std.get("standard"),
            "version": std.get("version"),
            "stats": stats,
        })

    global_counts = {s: 0 for s in STATUS_ORDER}
    for item in all_items:
        global_counts[get_best_status(item)] += 1
    total_items = len(all_items)
    overall_covered = global_counts.get("covered", 0)
    overall_any = overall_covered + global_counts.get("partial", 0)
    overall_pct = round(overall_covered / total_items * 100, 1) if total_items else 0.0
    overall_any_pct = round(overall_any / total_items * 100, 1) if total_items else 0.0

    lines.append("## Overall Dashboard")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total items tracked | {total_items} |")
    lines.append(f"| Fully covered | {overall_covered} ({overall_pct}%) |")
    lines.append(f"| Partially covered | {global_counts.get('partial', 0)} |")
    lines.append(f"| Missing | {global_counts.get('missing', 0)} |")
    lines.append(f"| Manual only | {global_counts.get('manual', 0)} |")
    lines.append(f"| Not applicable | {global_counts.get('not_applicable', 0)} |")
    lines.append(f"| **Any coverage** | **{overall_any} ({overall_any_pct}%)** |")
    lines.append("")

    lines.append(f"`{status_bar(global_counts, total_items, 40)}`")
    lines.append("")
    lines.append(f"C=Covered P=Partial M=Missing H=Manual N=N/A")
    lines.append("")

    lines.append("## Per-Standard Breakdown")
    lines.append("")
    lines.append("| Standard | Version | Total | Covered | Partial | Missing | Manual | N/A | Covered % | Any Cov % |")
    lines.append("|----------|---------|-------|---------|---------|---------|--------|-----|-----------|-----------|")
    for sd in standards_data:
        s = sd["stats"]
        c = s["counts"]
        lines.append(
            f"| {sd['standard']} | {sd['version']} | {s['total']} | "
            f"{c.get('covered', 0)} | {c.get('partial', 0)} | "
            f"{c.get('missing', 0)} | {c.get('manual', 0)} | "
            f"{c.get('not_applicable', 0)} | "
            f"{s['covered_pct']}% | {s['any_coverage_pct']}% |"
        )
    lines.append("")

    lines.append("## Top 10 Priority Gaps")
    lines.append("")
    gaps = find_gaps(all_items)
    lines.append("| # | Priority | ID | Name | Standard |")
    lines.append("|---|----------|----|------|----------|")
    for i, gap in enumerate(gaps[:10], 1):
        lines.append(f"| {i} | **{gap['priority_gap'].upper()}** | {gap['id']} | {gap['name']} | {gap['standard']} |")
    lines.append("")

    if len(gaps) > 10:
        lines.append("<details>")
        lines.append("<summary>View all gaps ({len(gaps)} total)</summary>")
        lines.append("")
        lines.append("| # | Priority | ID | Name | Standard |")
        lines.append("|---|----------|----|------|----------|")
        for i, gap in enumerate(gaps, 1):
            lines.append(f"| {i} | {gap['priority_gap']} | {gap['id']} | {gap['name']} | {gap['standard']} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("### Highest Impact Skill Builds")
    lines.append("")
    lines.append("| # | Category | Gap Count | Suggested Skill Name | Priority |")
    lines.append("|---|----------|-----------|----------------------|----------|")
    recs = get_recommendations(all_items)
    for i, rec in enumerate(recs[:10], 1):
        lines.append(f"| {i} | {rec['category']} | {rec['gap_count']} | `{rec['skill']}` | {rec['priority']} |")
    lines.append("")

    lines.append("### Low Hanging Fruit")
    lines.append("")
    lines.append("Items marked `partial` with scripts that could achieve `covered` with dedicated workflows:")
    lines.append("")
    for item in sorted(all_items, key=lambda x: get_best_status(x)):
        if get_best_status(item) == "partial" and item.get("priority_gap", "low") in ("high",):
            lines.append(f"- **{item.get('id')}**: {item.get('name')} — {item.get('notes', 'No notes')}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Report generated by coverage_report.py — use `python3 .claude/skills/coverage/scripts/coverage_calculator.py` for raw JSON stats.*")
    lines.append("")

    return "\n".join(lines)


def find_gaps(all_items: list[dict]) -> list[dict]:
    gaps = []
    for item in all_items:
        status = get_best_status(item)
        priority = item.get("priority_gap", "low")
        if status == "missing" and priority in ("critical", "high"):
            gaps.append({
                "id": item.get("id"),
                "name": item.get("name"),
                "standard": item.get("_standard", "WSTG"),
                "priority_gap": priority,
            })
    gaps.sort(key=lambda g: ({"critical": 0, "high": 1}[g["priority_gap"]]))
    return gaps


def get_recommendations(all_items: list[dict]) -> list[dict]:
    category_map: dict[str, dict] = {}

    keyword_to_category = {
        ("open redirect", "redirect"): ("Open Redirects", "skill-open-redirect"),
        ("session", "cookie", "logout", "timeout", "fixation"): ("Session & Cookie Security", "skill-session-cookies"),
        ("tls", "ssl", "cipher", "hsts", "certificate"): ("TLS & Transport Security", "skill-tls-security"),
        ("workflow", "work flow", "business logic"): ("Business Logic & Workflows", "skill-business-logic"),
        ("function level", "access control", "function-level"): ("Function-Level Auth", "skill-function-level-auth"),
        ("backup", "extension", "unreferenced"): ("Sensitive File Discovery", "skill-sensitive-files"),
        ("host header", "header injection"): ("Host Header Injection", "skill-host-header"),
        ("error", "stack trace", "exception"): ("Error Handling", "skill-error-handling"),
        ("username", "registration", "account enum", "account provision"): ("Identity & Registration", "skill-identity"),
        ("password", "reset", "recovery", "lockout", "brute force"): ("Password & Recovery", "skill-password-reset"),
        ("websocket"): ("WebSocket Security", "skill-websocket"),
        ("clickjacking", "frame option", "x-frame"): ("Clickjacking", "skill-clickjacking"),
        ("browser storage", "localstorage", "sessionstorage"): ("Browser Storage", "skill-browser-storage"),
        ("dependency", "cve", "library", "package"): ("Dependency Scanning", "skill-dependency-scan"),
        ("sensitive data", "pii", "data leak", "data exposure"): ("Data Exposure Detection", "skill-data-exposure"),
        ("mass assignment", "property level"): ("Mass Assignment", "skill-mass-assignment"),
        ("deserialization", "serialization"): ("Deserialization Attacks", "skill-deserialization"),
        ("subdomain takeover", "cname", "dangling"): ("Subdomain Takeover", "skill-subdomain-takeover"),
    }

    for item in all_items:
        status = get_best_status(item)
        if status != "missing":
            continue
        name_lower = item.get("name", "").lower()
        priority = item.get("priority_gap", "low")
        for keywords, (category, skill) in keyword_to_category.items():
            if any(kw in name_lower for kw in keywords):
                if category not in category_map:
                    category_map[category] = {"category": category, "skill": skill, "gap_count": 0, "priority": "low"}
                category_map[category]["gap_count"] += 1
                if priority == "critical" or (priority == "high" and category_map[category]["priority"] != "critical"):
                    category_map[category]["priority"] = priority
                break

    return sorted(category_map.values(), key=lambda r: ({"critical": 0, "high": 1}.get(r["priority"], 2), -r["gap_count"]))


def format_json(data: dict) -> str:
    all_items: list[dict] = []
    for std in data.get("standards", []):
        for section in std.get("sections", []):
            for item in section.get("items", []):
                item_copy = dict(item)
                item_copy["_standard"] = std.get("standard")
                item_copy["_status"] = get_best_status(item)
                all_items.append(item_copy)

    global_counts = {s: 0 for s in STATUS_ORDER}
    for item in all_items:
        global_counts[item["_status"]] += 1

    output = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "total_items": len(all_items),
            "counts": global_counts,
            "overall_covered_pct": round(global_counts["covered"] / len(all_items) * 100, 1) if all_items else 0.0,
        },
        "gaps": find_gaps(all_items),
        "recommendations": get_recommendations(all_items),
    }
    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a comprehensive coverage report from coverage_matrix.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --matrix coverage_matrix.yaml --output coverage_report.md
  %(prog)s --matrix coverage_matrix.yaml --output coverage_report.json --format json
  %(prog)s --matrix coverage_matrix.yaml --output -
        """,
    )
    parser.add_argument("--matrix", required=True, help="Path to coverage_matrix.yaml")
    parser.add_argument("--output", required=True, help="Path for output (use '-' for stdout)")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    args = parser.parse_args()

    if not Path(args.matrix).exists():
        print(f"ERROR: matrix file not found: {args.matrix}", file=sys.stderr)
        sys.exit(1)

    data = load_yaml(args.matrix)

    if args.format == "json":
        output_text = format_json(data)
    else:
        output_text = format_markdown(data)

    if args.output == "-":
        print(output_text)
    else:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            f.write(output_text)
            f.write("\n")
        print(f"Coverage report written to {args.output}")


if __name__ == "__main__":
    main()