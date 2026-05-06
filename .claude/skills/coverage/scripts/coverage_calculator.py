#!/usr/bin/env python3
"""Coverage Calculator — reads coverage_matrix.yaml and computes coverage statistics.

Calculates:
  - Total items per standard
  - Items covered vs partial vs missing vs manual vs not_applicable
  - Percentage complete per standard
  - Overall coverage score
  - Outputs JSON with stats

Usage:
  python3 coverage_calculator.py --matrix coverage_matrix.yaml --output stats.json
  python3 coverage_calculator.py --help
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


def count_items(items: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in STATUS_ORDER}
    for item in items:
        covered_by = item.get("covered_by", [])
        if not covered_by:
            counts["missing"] += 1
            continue

        best_status = "missing"
        for entry in covered_by:
            status = entry.get("status", "missing")
            if STATUS_ORDER.index(status) < STATUS_ORDER.index(best_status):
                best_status = status

        counts[best_status] = counts.get(best_status, 0) + 1

    return counts


def compute_standard_section(items: list[dict]) -> dict:
    total = len(items)
    counts = count_items(items)
    covered = counts.get("covered", 0)
    partial = counts.get("partial", 0)
    any_coverage = covered + partial
    covered_pct = round(covered / total * 100, 1) if total > 0 else 0.0
    any_pct = round(any_coverage / total * 100, 1) if total > 0 else 0.0

    return {
        "total": total,
        "counts": counts,
        "covered_percentage": covered_pct,
        "any_coverage_percentage": any_pct,
    }


def compute_standard(standard: dict) -> dict:
    sections_raw = standard.get("sections", [])
    all_items: list[dict] = []
    sections_detail: list[dict] = []

    for section in sections_raw:
        items = section.get("items", [])
        all_items.extend(items)
        sec_stats = compute_standard_section(items)
        sections_detail.append({
            "section": section.get("section", "unknown"),
            "section_name": section.get("section_name", "Unknown"),
            "stats": sec_stats,
        })

    total_stats = compute_standard_section(all_items)

    return {
        "standard": standard.get("standard", "unknown"),
        "version": standard.get("version", "unknown"),
        "total_items": len(all_items),
        "stats": total_stats,
        "sections": sections_detail,
    }


def find_high_priority_gaps(all_items: list[dict]) -> list[dict]:
    gaps = []
    for item in all_items:
        covered_by = item.get("covered_by", [])
        if not covered_by:
            status = "missing"
        else:
            status = min(
                (e.get("status", "missing") for e in covered_by),
                key=lambda s: STATUS_ORDER.index(s),
                default="missing",
            )
        priority = item.get("priority_gap", "low")
        if status in ("missing",) and priority in ("high", "critical"):
            gaps.append({
                "id": item.get("id", "unknown"),
                "name": item.get("name", "Unknown"),
                "status": status,
                "priority_gap": priority,
                "current_coverage": None,
            })
    return gaps


def generate_recommendations(standards_data: list[dict]) -> list[dict]:
    recommendations = []

    for std in standards_data:
        all_items: list[dict] = []
        sections = std.get("sections", [])
        for section in sections:
            all_items.extend(section.get("items", []))

        gaps = find_high_priority_gaps(all_items)
        if gaps:
            recommendations.append({
                "standard": std["standard"],
                "high_priority_gaps": len(gaps),
                "top_gaps": gaps[:5],
            })

    return recommendations


def main():
    parser = argparse.ArgumentParser(
        description="Compute coverage statistics from coverage_matrix.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --matrix coverage_matrix.yaml --output coverage_stats.json
  %(prog)s --matrix coverage_matrix.yaml --output - > /dev/null && echo "OK"
        """,
    )
    parser.add_argument(
        "--matrix",
        required=True,
        help="Path to coverage_matrix.yaml",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path for output JSON (use '-' for stdout)",
    )
    args = parser.parse_args()

    if not Path(args.matrix).exists():
        print(f"ERROR: matrix file not found: {args.matrix}", file=sys.stderr)
        sys.exit(1)

    data = load_yaml(args.matrix)

    if "standards" not in data:
        print("ERROR: 'standards' key not found in matrix YAML", file=sys.stderr)
        sys.exit(1)

    standards_output = []
    all_items_global: list[dict] = []

    for standard in data["standards"]:
        result = compute_standard(standard)
        standards_output.append(result)
        sections = standard.get("sections", [])
        for section in sections:
            all_items_global.extend(section.get("items", []))

    total_items = len(all_items_global)
    total_counts = count_items(all_items_global)
    covered = total_counts.get("covered", 0)
    partial_count = total_counts.get("partial", 0)
    overall_covered_pct = round(covered / total_items * 100, 1) if total_items > 0 else 0.0
    overall_any_pct = round((covered + partial_count) / total_items * 100, 1) if total_items > 0 else 0.0

    recommendations = generate_recommendations(standards_output)

    output = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "matrix_version": data.get("version", "unknown"),
        "toolkit_version": data.get("toolkit_version", "unknown"),
        "summary": {
            "total_items": total_items,
            "covered": covered,
            "partial": partial_count,
            "missing": total_counts.get("missing", 0),
            "manual": total_counts.get("manual", 0),
            "not_applicable": total_counts.get("not_applicable", 0),
            "overall_covered_percentage": overall_covered_pct,
            "overall_any_coverage_percentage": overall_any_pct,
        },
        "standards": standards_output,
        "high_priority_gaps": find_high_priority_gaps(all_items_global),
        "recommendations": recommendations,
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
        print(f"Coverage stats written to {args.output}")


if __name__ == "__main__":
    main()