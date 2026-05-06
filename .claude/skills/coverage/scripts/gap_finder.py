#!/usr/bin/env python3
"""Gap Finder — identifies highest-priority missing coverage from coverage_matrix.yaml.

Identifies:
  - Missing coverage for high-severity standards items
  - Standards items with priority_gap "high" or "critical" that are "missing"
  - Suggests which skills to create next

Usage:
  python3 gap_finder.py --matrix coverage_matrix.yaml --output gaps.json
  python3 gap_finder.py --matrix coverage_matrix.yaml --output - --format markdown
  python3 gap_finder.py --help
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

STATUS_ORDER = ["covered", "partial", "missing", "manual", "not_applicable"]


def load_yaml(matrix_path: str) -> dict:
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip3 install pyyaml", file=sys.stderr)
        sys.exit(1)

    with open(matrix_path, "r") as f:
        data = yaml.safe_load(f)
    return data


def flatten_items(data: dict) -> list[dict]:
    items: list[dict] = []
    for standard in data.get("standards", []):
        for section in standard.get("sections", []):
            for item in section.get("items", []):
                item_copy = dict(item)
                item_copy["_standard"] = standard.get("standard", "unknown")
                item_copy["_section"] = section.get("section_name", section.get("section", "unknown"))
                items.append(item_copy)
    return items


def get_best_status(item: dict) -> str:
    covered_by = item.get("covered_by", [])
    if not covered_by:
        return "missing"
    return min(
        (e.get("status", "missing") for e in covered_by),
        key=lambda s: STATUS_ORDER.index(s),
        default="missing",
    )


def find_gaps(items: list[dict]) -> list[dict]:
    gaps: list[dict] = []

    for item in items:
        status = get_best_status(item)
        priority = item.get("priority_gap", "low")

        if status == "missing" and priority in ("critical", "high"):
            gaps.append({
                "id": item.get("id", "unknown"),
                "name": item.get("name", "Unknown"),
                "standard": item.get("_standard", "unknown"),
                "section": item.get("_section", "unknown"),
                "status": status,
                "priority_gap": priority,
                "notes": item.get("notes", ""),
            })

    gaps.sort(key=lambda g: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[g["priority_gap"]], g["standard"], g["id"]))

    return gaps


def suggest_skills(gaps: list[dict]) -> list[dict]:
    suggestions_map: dict[str, dict] = {}

    category_keywords = {
        "Redirect": {"url redirect", "open redirect", "redirect uri"},
        "Cookies and Session": {"cookie", "session", "logout", "timeout", "fixation"},
        "TLS and Crypto": {"tls", "ssl", "encryption", "certificate", "cipher", "crypto", "hsts"},
        "Business Logic": {"business logic", "workflow", "work flow", "process timing"},
        "Authorization": {"authorization", "function level", "access control", "idor"},
        "File and Backup": {"backup", "extension", "unreferenced", "file permission"},
        "Host Header": {"host header", "header injection", "forwarded"},
        "Error Handling": {"error handling", "error message", "stack trace"},
        "Username and Registration": {"username", "registration", "account enumeration", "account provision"},
        "Password and Reset": {"password", "reset", "recovery", "lockout", "brute force"},
        "WebSocket": {"websocket", "ws:"},
        "Browser Features": {"clickjacking", "iframe", "frame option", "localstorage", "sessionstorage"},
        "Dependencies": {"dependency", "cve", "library", "package", "framework"},
        "Data Exposure": {"sensitive data", "pii", "data leak", "information disclosure", "data exposure"},
        "Mass Assignment": {"mass assignment", "property level"},
        "Deserialization": {"deserialization", "serialization"},
        "Subdomain Takeover": {"subdomain takeover", "cname", "dangling"},
    }

    for gap in gaps:
        name_lower = gap["name"].lower()
        matched = False
        for category, keywords in category_keywords.items():
            if any(kw in name_lower for kw in keywords):
                if category not in suggestions_map:
                    suggestions_map[category] = {
                        "category": category,
                        "gaps": [],
                        "suggested_skill": f"skill-{category.lower().replace(' ', '-').replace('(', '').replace(')', '')}",
                        "priority": gap["priority_gap"],
                    }
                suggestions_map[category]["gaps"].append(gap)
                matched = True
                break

        if not matched:
            if "other" not in suggestions_map:
                suggestions_map["other"] = {
                    "category": "Other / Uncategorized",
                    "gaps": [],
                    "suggested_skill": "skill-miscellaneous",
                    "priority": "medium",
                }
            suggestions_map["other"]["gaps"].append(gap)

    suggestions = sorted(
        suggestions_map.values(),
        key=lambda s: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s["priority"], 2),
            -len(s["gaps"]),
        ),
    )

    for s in suggestions:
        s["gap_count"] = len(s["gaps"])
        s["gaps"] = [{"id": g["id"], "name": g["name"], "standard": g["standard"], "priority": g["priority_gap"]} for g in s["gaps"]]

    return suggestions


def format_markdown(gaps: list[dict], suggestions: list[dict]) -> str:
    lines: list[str] = []

    lines.append("# Coverage Gap Analysis")
    lines.append("")
    lines.append(f"> Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append(f"## Summary")
    lines.append("")
    lines.append(f"- **Total High-Priority Gaps Found:** {len(gaps)}")
    lines.append(f"- **Suggested New Skills:** {len(suggestions)}")
    lines.append("")

    lines.append("## Top 10 Highest-Priority Gaps")
    lines.append("")
    lines.append("| # | Priority | ID | Name | Standard |")
    lines.append("|---|----------|----|------|----------|")
    for i, gap in enumerate(gaps[:10], 1):
        lines.append(f"| {i} | {gap['priority_gap']} | {gap['id']} | {gap['name']} | {gap['standard']} |")
    lines.append("")

    lines.append("## Suggested Next Skills to Build")
    lines.append("")
    for i, suggestion in enumerate(suggestions, 1):
        lines.append(f"### {i}. {suggestion['category']} ({suggestion['gap_count']} gaps)")
        lines.append(f"- **Suggested skill name:** `{suggestion['suggested_skill']}`")
        lines.append(f"- **Priority:** {suggestion['priority']}")
        lines.append(f"- **Gaps to address:**")
        for g in suggestion["gaps"]:
            lines.append(f"  - {g['id']}: {g['name']} [{g['standard']}]")
        lines.append("")

    if len(gaps) > 10:
        lines.append("## All Priority Gaps (Critical + High)")
        lines.append("")
        lines.append("| # | Priority | ID | Name | Standard | Section |")
        lines.append("|---|----------|----|------|----------|---------|")
        for i, gap in enumerate(gaps, 1):
            lines.append(f"| {i} | {gap['priority_gap']} | {gap['id']} | {gap['name']} | {gap['standard']} | {gap['section']} |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Identify high-priority coverage gaps from coverage_matrix.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --matrix coverage_matrix.yaml --output gaps.json
  %(prog)s --matrix coverage_matrix.yaml --output - --format markdown
        """,
    )
    parser.add_argument("--matrix", required=True, help="Path to coverage_matrix.yaml")
    parser.add_argument("--output", required=True, help="Path for output (use '-' for stdout)")
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format (default: json)",
    )
    args = parser.parse_args()

    if not Path(args.matrix).exists():
        print(f"ERROR: matrix file not found: {args.matrix}", file=sys.stderr)
        sys.exit(1)

    data = load_yaml(args.matrix)
    items = flatten_items(data)
    gaps = find_gaps(items)
    suggestions = suggest_skills(gaps)

    if args.format == "markdown":
        output_text = format_markdown(gaps, suggestions)
        if args.output == "-":
            print(output_text)
        else:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w") as f:
                f.write(output_text)
                f.write("\n")
            print(f"Gap report written to {args.output}")
    else:
        output = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_gaps": len(gaps),
            "high_priority_gaps": gaps,
            "suggested_skills": suggestions,
        }
        if args.output == "-":
            json.dump(output, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
                f.write("\n")
            print(f"Gap analysis written to {args.output}")


if __name__ == "__main__":
    main()