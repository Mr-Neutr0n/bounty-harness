#!/usr/bin/env python3
"""Generate hypotheses from a coverage matrix.

Reads coverage_matrix.yaml. Finds all items with status=missing and
priority_gap=high or critical. Outputs hypotheses.json.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


def parse_yaml_simple(path):
    """Parse a simple YAML file into structured data.
    Handles the nested list-of-dicts pattern used in coverage_matrix.yaml.
    """
    with open(path, "r") as f:
        content = f.read()

    entries = []
    current_skill = None
    current_entry = {}

    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- skill:"):
            if current_entry:
                entries.append(current_entry)
                current_entry = {}
            current_skill = stripped.split("skill:")[1].strip().strip('"').strip("'")
            current_entry["skill"] = current_skill
            continue

        if current_skill is None:
            continue

        for key in ["standard", "technique", "status", "priority_gap", "name"]:
            if stripped.startswith(f"{key}:"):
                val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                current_entry[key] = val
                break

    if current_entry:
        entries.append(current_entry)

    return entries


def generate_hypotheses(entries):
    """Filter entries for missing high/critical gaps and produce hypothesis objects."""
    hypotheses = []

    for entry in entries:
        status = entry.get("status", "").strip().lower()
        priority = entry.get("priority_gap", "").strip().lower()

        if status != "missing":
            continue
        if priority not in ("high", "critical"):
            continue

        gap_id = entry.get("standard", "UNKNOWN-STANDARD")
        standard = entry.get("standard", "")
        name = entry.get("name", "")
        technique = entry.get("technique", "")
        skill = entry.get("skill", "")

        hypothesis_text = _build_hypothesis_text(standard, name, technique)
        technique_needed = _derive_technique_needed(standard, name, technique)
        difficulty = _estimate_difficulty(technique, priority)
        requires = _derive_requires(technique, skill)

        hypotheses.append({
            "gap_id": gap_id,
            "standard": standard,
            "name": name,
            "hypothesis_text": hypothesis_text,
            "technique_needed": technique_needed,
            "skill_impacted": skill,
            "difficulty": difficulty,
            "requires": requires,
        })

    return hypotheses


def _build_hypothesis_text(standard, name, technique):
    parts = []
    if standard:
        parts.append(standard)
    if name:
        parts.append(f"({name})")
    if technique:
        parts.append(f"via {technique}")
    return "Add detection for " + " ".join(parts)


def _derive_technique_needed(standard, name, technique):
    if technique:
        return technique
    if name:
        return name
    if standard:
        return f"{standard} probe"
    return "basic detection"


def _estimate_difficulty(technique, priority):
    if priority == "critical":
        return "hard" if "blind" in technique.lower() or "race" in technique.lower() else "medium"
    return "medium" if "injection" in technique.lower() or "bypass" in technique.lower() else "easy"


def _derive_requires(technique, skill):
    reqs = []
    technique_lower = technique.lower()
    if "http" in technique_lower or "curl" in technique_lower:
        reqs.append("curl")
    if "inject" in technique_lower:
        reqs.append("python3:payload-generation")
    if "fuzz" in technique_lower:
        reqs.append("ffuf")
    if "scan" in technique_lower or "template" in technique_lower:
        reqs.append("nuclei")
    if "js" in technique_lower or "javascript" in technique_lower:
        reqs.append("playwright")
    if "dns" in technique_lower:
        reqs.append("dnsx")
    if "tls" in technique_lower or "ssl" in technique_lower or "cert" in technique_lower:
        reqs.append("openssl")
    reqs.append(f"skill:{skill}")
    return reqs


def main():
    parser = argparse.ArgumentParser(
        description="Generate hypotheses from a coverage matrix."
    )
    parser.add_argument(
        "--coverage-matrix",
        required=True,
        help="Path to coverage_matrix.yaml file.",
    )
    parser.add_argument(
        "--context",
        default=".",
        help="Output directory context for artifacts.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.coverage_matrix):
        print(json.dumps({"error": f"Coverage matrix not found: {args.coverage_matrix}"}), file=sys.stderr)
        sys.exit(1)

    entries = parse_yaml_simple(args.coverage_matrix)
    hypotheses = generate_hypotheses(entries)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_matrix": args.coverage_matrix,
        "total_entries_scanned": len(entries),
        "hypotheses_count": len(hypotheses),
        "hypotheses": hypotheses,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()