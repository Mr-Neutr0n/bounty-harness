#!/usr/bin/env python3
"""Design controlled experiments for each hypothesis.

Reads hypotheses.json. For each hypothesis, designs an experiment with
positive and negative controls, success criteria, and required evidence.
Outputs design_manifest.json.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def design_experiment(hypothesis):
    """Produce an experiment design object from a single hypothesis."""
    hypothesis_id = hypothesis["gap_id"]
    name = hypothesis.get("name", "")
    standard = hypothesis.get("standard", "")
    technique = hypothesis.get("technique_needed", "")

    fixture_name = _derive_fixture_name(hypothesis_id, standard)
    positive_desc = _describe_positive_control(standard, name, technique)
    negative_desc = _describe_negative_control(standard, technique)
    success_criteria = _derive_success_criteria(standard, name)
    evidence_required = _derive_evidence_required(technique)

    return {
        "hypothesis_id": hypothesis_id,
        "fixture_name": fixture_name,
        "positive_control_desc": positive_desc,
        "negative_control_desc": negative_desc,
        "success_criteria": success_criteria,
        "evidence_required": evidence_required,
    }


def _derive_fixture_name(hypothesis_id, standard):
    clean_id = hypothesis_id.lower().replace(" ", "-").replace(":", "-").replace("_", "-")
    clean_id = "".join(c for c in clean_id if c.isalnum() or c == "-")
    return f"fixture-{clean_id}"


def _describe_positive_control(standard, name, technique):
    if name:
        return f"Positive control: A target that exhibits {name} ({standard}) should be detected by the {technique} probe"
    return f"Positive control: A target exhibiting {standard} should be detected by the {technique} probe"


def _describe_negative_control(standard, technique):
    return f"Negative control: A target that does NOT exhibit {standard} should NOT trigger the {technique} probe"


def _derive_success_criteria(standard, name):
    label = name if name else standard
    return [
        f"{label} is correctly identified in positive fixture",
        f"{label} absence is correctly confirmed in negative fixture",
        "No false positives triggered on unrelated fixtures",
        "Detection is reproducible across 3 consecutive runs",
    ]


def _derive_evidence_required(technique):
    evidence = [
        "stdout capture of probe execution",
        "exit code for positive test",
        "exit code for negative test",
    ]
    technique_lower = technique.lower()
    if "http" in technique_lower:
        evidence.append("curl -v request/response output")
    if "nuclei" in technique_lower:
        evidence.append("nuclei matched template name and matcher status")
    if "fuzz" in technique_lower:
        evidence.append("ffuf result with matched status code and line count")
    if "js" in technique_lower or "javascript" in technique_lower:
        evidence.append("playwright console output or screenshot")
    return evidence


def main():
    parser = argparse.ArgumentParser(
        description="Design experiments from a hypotheses file."
    )
    parser.add_argument(
        "--hypotheses-file",
        required=True,
        help="Path to hypotheses.json file.",
    )
    parser.add_argument(
        "--context",
        default=".",
        help="Output directory context for artifacts.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.hypotheses_file):
        print(json.dumps({"error": f"Hypotheses file not found: {args.hypotheses_file}"}), file=sys.stderr)
        sys.exit(1)

    with open(args.hypotheses_file, "r") as f:
        hypotheses_data = json.load(f)

    hypotheses = hypotheses_data.get("hypotheses", [])

    designs = [design_experiment(h) for h in hypotheses]

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_hypotheses": args.hypotheses_file,
        "experiment_count": len(designs),
        "experiments": designs,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()