#!/usr/bin/env python3
"""Run experiments against evaluation-harness fixtures.

Reads design_manifest.json. For each experiment design, checks if fixture
exists at .claude/skills/evaluation-harness/fixtures/{fixture_name}/.
Runs positive.sh and negative.sh if present. Captures output and exit codes.
Outputs results_manifest.json.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

EVALUATION_BASE = ".claude/skills/evaluation-harness/fixtures"


def run_fixture_script(fixture_dir, script_name):
    """Run a test script and return (exit_code, stdout, stderr)."""
    script_path = os.path.join(fixture_dir, script_name)
    if not os.path.isfile(script_path):
        return None, None, None

    try:
        result = subprocess.run(
            ["bash", script_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as exc:
        return -2, "", str(exc)


def run_experiment(design):
    """Execute a single experiment design against its fixtures."""
    hypothesis_id = design["hypothesis_id"]
    fixture_name = design["fixture_name"]
    fixture_dir = os.path.join(EVALUATION_BASE, fixture_name)

    result = {
        "hypothesis_id": hypothesis_id,
        "fixture_name": fixture_name,
        "fixture_exists": False,
        "positive_passed": False,
        "negative_passed": False,
        "positive_output": "",
        "negative_output": "",
        "errors": [],
    }

    if not os.path.isdir(fixture_dir):
        result["errors"].append(f"Fixture directory not found: {fixture_dir}")
        return result

    result["fixture_exists"] = True

    positive_script = os.path.join(fixture_dir, "test_positive.sh")
    negative_script = os.path.join(fixture_dir, "test_negative.sh")

    if not os.path.isfile(positive_script):
        result["errors"].append(f"test_positive.sh missing in {fixture_dir}")
    else:
        exit_code, stdout, stderr = run_fixture_script(fixture_dir, "test_positive.sh")
        if exit_code is None:
            result["errors"].append("test_positive.sh failed to execute")
        else:
            result["positive_passed"] = (exit_code == 0)
            result["positive_output"] = stdout or ""
            if exit_code != 0:
                result["errors"].append(f"test_positive.sh exit={exit_code} stderr={stderr}")

    if not os.path.isfile(negative_script):
        result["errors"].append(f"test_negative.sh missing in {fixture_dir}")
    else:
        exit_code, stdout, stderr = run_fixture_script(fixture_dir, "test_negative.sh")
        if exit_code is None:
            result["errors"].append("test_negative.sh failed to execute")
        else:
            result["negative_passed"] = (exit_code != 0)
            result["negative_output"] = stdout or ""
            if exit_code == 0:
                result["errors"].append(f"test_negative.sh incorrectly passed (exit=0)")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run experiments from a design manifest."
    )
    parser.add_argument(
        "--design-manifest",
        required=True,
        help="Path to design_manifest.json file.",
    )
    parser.add_argument(
        "--context",
        default=".",
        help="Output directory context for artifacts.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.design_manifest):
        print(json.dumps({"error": f"Design manifest not found: {args.design_manifest}"}), file=sys.stderr)
        sys.exit(1)

    with open(args.design_manifest, "r") as f:
        manifest = json.load(f)

    experiments = manifest.get("experiments", [])
    results = [run_experiment(e) for e in experiments]

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_manifest": args.design_manifest,
        "total_experiments": len(results),
        "fixtures_found": sum(1 for r in results if r["fixture_exists"]),
        "results": results,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()