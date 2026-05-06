#!/usr/bin/env python3
"""Generate promotion proposals for experiments that passed review.

Reads review_report.json. For each entry with passed=true, creates a
promotion proposal describing which skill files to modify and what changes
are needed. Does NOT modify any actual skill files.
Outputs promotion_report.json.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def generate_proposal(review_entry, design, hypothesis):
    """Generate a promotion proposal for a single passed experiment."""
    hypothesis_id = review_entry["hypothesis_id"]
    target_skill = hypothesis.get("skill_impacted", "unknown")
    standard = hypothesis.get("standard", "")
    name = hypothesis.get("name", "")
    technique = hypothesis.get("technique_needed", "")

    suggested_files = _derive_suggested_files(target_skill)
    diff_description = _describe_diff(standard, name, technique, target_skill)
    standards_added = [standard] if standard else []
    impact_estimate = _estimate_impact(hypothesis)

    return {
        "hypothesis_id": hypothesis_id,
        "target_skill": target_skill,
        "suggested_files": suggested_files,
        "diff_description": diff_description,
        "standards_added": standards_added,
        "impact_estimate": impact_estimate,
    }


def _derive_suggested_files(target_skill):
    base_path = f".claude/skills/{target_skill}"
    return [
        f"{base_path}/SKILL.md",
        f"{base_path}/skill.yaml",
    ]


def _describe_diff(standard, name, technique, target_skill):
    label = name if name else standard
    parts = [
        f"Add '{label}' detection workflow to {target_skill} skill.",
        f"Insert a new workflow entry in {target_skill}/skill.yaml with positive/negative fixture references.",
        f"If technique requires a script, add to {target_skill}/scripts/ for {technique} probing.",
        f"Update {target_skill}/SKILL.md workflow table with new detection capability.",
    ]
    return " ".join(parts)


def _estimate_impact(hypothesis):
    difficulty = hypothesis.get("difficulty", "medium")

    coverages = {
        "easy": "Expected to increase precision by 5-10% for targeted vulnerability class",
        "medium": "Expected to increase recall by 10-15% for targeted vulnerability class",
        "hard": "Expected to close a critical gap with 15-25% coverage improvement",
    }

    return coverages.get(difficulty, coverages["medium"])


def main():
    parser = argparse.ArgumentParser(
        description="Generate promotion proposals from a review report."
    )
    parser.add_argument(
        "--review-report",
        required=True,
        help="Path to review_report.json file.",
    )
    parser.add_argument(
        "--context",
        default=".",
        help="Output directory context for artifacts.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.review_report):
        print(json.dumps({"error": f"Review report not found: {args.review_report}"}), file=sys.stderr)
        sys.exit(1)

    with open(args.review_report, "r") as f:
        report = json.load(f)

    reviews = report.get("reviews", [])

    designs = {}
    hypotheses = {}
    if "source_manifest" in report:
        manifest_path = report.get("source_manifest", "")
        if os.path.isfile(manifest_path):
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
            for e in manifest.get("experiments", []):
                designs[e["hypothesis_id"]] = e

        hypotheses_path = manifest.get("source_hypotheses", "") if manifest else ""
        if hypotheses_path and os.path.isfile(hypotheses_path):
            with open(hypotheses_path, "r") as f:
                hyp_data = json.load(f)
            for h in hyp_data.get("hypotheses", []):
                hypotheses[h["gap_id"]] = h

    proposals = []
    for review in reviews:
        if not review.get("passed", False):
            continue
        design = designs.get(review["hypothesis_id"], {})
        hypothesis = hypotheses.get(review["hypothesis_id"], {})
        proposals.append(generate_proposal(review, design, hypothesis))

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": args.review_report,
        "total_proposals": len(proposals),
        "proposals": proposals,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()