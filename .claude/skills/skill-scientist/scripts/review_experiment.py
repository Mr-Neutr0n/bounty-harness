#!/usr/bin/env python3
"""Review experiment results and score them.

Reads results_manifest.json. Scores each experiment on 4 dimensions:
accuracy (0-10), false_positive_control (0-10), evidence_completeness (0-5),
reproducibility (0-5). Total 0-30, normalized to 0-10. Threshold 7.
Outputs review_report.json.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

PASS_THRESHOLD = 7.0


def score_dimension_accuracy(result):
    """Score based on positive/negative control outcomes."""
    p = 5 if result.get("positive_passed", False) else 0
    n = 5 if result.get("negative_passed", False) else 0
    return p + n


def score_false_positive_control(result):
    """Score based on negative control and error count."""
    base = 10
    if not result.get("negative_passed", False):
        base -= 5
    errors = result.get("errors", [])
    base -= min(len(errors), 5)
    return max(0, base)


def score_evidence_completeness(result):
    """Score based on whether output was captured for both controls."""
    base = 5
    if not result.get("positive_output"):
        base -= 2
    if not result.get("negative_output"):
        base -= 2
    return max(0, base)


def score_reproducibility(result):
    """Placeholder reproducibility score. Full implementation requires 3-run data."""
    return 5


def review_result(result):
    """Score a single experiment result."""
    accuracy = score_dimension_accuracy(result)
    fp_control = score_false_positive_control(result)
    evidence = score_evidence_completeness(result)
    reproducibility = score_reproducibility(result)

    total = accuracy + fp_control + evidence + reproducibility
    normalized = round((total / 30.0) * 10.0, 2)
    passed = normalized >= PASS_THRESHOLD

    return {
        "hypothesis_id": result["hypothesis_id"],
        "scores": {
            "accuracy": accuracy,
            "false_positive_control": fp_control,
            "evidence_completeness": evidence,
            "reproducibility": reproducibility,
        },
        "total_score": total,
        "normalized_score": normalized,
        "passed": passed,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Review experiment results and produce scored report."
    )
    parser.add_argument(
        "--results-manifest",
        required=True,
        help="Path to results_manifest.json file.",
    )
    parser.add_argument(
        "--context",
        default=".",
        help="Output directory context for artifacts.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.results_manifest):
        print(json.dumps({"error": f"Results manifest not found: {args.results_manifest}"}), file=sys.stderr)
        sys.exit(1)

    with open(args.results_manifest, "r") as f:
        manifest = json.load(f)

    results = manifest.get("results", [])
    reviews = [review_result(r) for r in results]
    passed_count = sum(1 for r in reviews if r["passed"])
    failed_count = len(reviews) - passed_count

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_manifest": args.results_manifest,
        "pass_threshold": PASS_THRESHOLD,
        "total_experiments": len(reviews),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "reviews": reviews,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()