#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
import yaml


def main():
    parser = argparse.ArgumentParser(description="Run skill tests against lab fixtures")
    parser.add_argument("--skills-dir", required=True, help="Directory containing skill definitions")
    parser.add_argument("--fixtures-dir", required=True, help="Directory containing lab fixtures")
    parser.add_argument("--context", required=True, help="Output context directory for results")
    args = parser.parse_args()

    fixtures_dir = os.path.abspath(args.fixtures_dir)
    context_dir = os.path.abspath(args.context)
    os.makedirs(context_dir, exist_ok=True)

    results = []
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    fixture_names = sorted([d for d in os.listdir(fixtures_dir) if os.path.isdir(os.path.join(fixtures_dir, d))])

    for fixture_name in fixture_names:
        fixture_path = os.path.join(fixtures_dir, fixture_name)
        fixture_yaml_path = os.path.join(fixture_path, "fixture.yaml")

        if not os.path.exists(fixture_yaml_path):
            continue

        with open(fixture_yaml_path) as f:
            fixture_meta = yaml.safe_load(f)

        skill = fixture_meta.get("skill_tested", "unknown")
        positive_sh = os.path.join(fixture_path, "test_positive.sh")
        negative_sh = os.path.join(fixture_path, "test_negative.sh")

        result_entry = {
            "fixture_name": fixture_name,
            "skill": skill,
            "vulnerability_class": fixture_meta.get("vulnerability_class", ""),
            "severity": fixture_meta.get("severity", ""),
            "timestamp": timestamp,
            "positive_pass": False,
            "positive_output": "",
            "positive_error": "",
            "positive_runtime": 0,
            "negative_pass": False,
            "negative_output": "",
            "negative_error": "",
            "negative_runtime": 0,
            "fixture_errors": [],
        }

        if os.path.exists(positive_sh) and os.access(positive_sh, os.X_OK):
            start = time.time()
            try:
                proc = subprocess.run(
                    [positive_sh],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=os.path.dirname(fixtures_dir),
                )
                result_entry["positive_output"] = proc.stdout.strip()
                result_entry["positive_error"] = proc.stderr.strip()
                result_entry["positive_pass"] = proc.returncode == 0
                result_entry["positive_runtime"] = round(time.time() - start, 3)
            except subprocess.TimeoutExpired:
                result_entry["positive_error"] = "Positive test timed out after 30 seconds"
                result_entry["positive_runtime"] = round(time.time() - start, 3)
                result_entry["fixture_errors"].append("positive test timed out")
            except FileNotFoundError:
                result_entry["positive_error"] = "bash not found or test_positive.sh not accessible"
                result_entry["positive_runtime"] = 0
                result_entry["fixture_errors"].append("positive test — bash not reachable")
            except Exception as exc:
                result_entry["positive_error"] = f"Unexpected error: {exc}"
                result_entry["positive_runtime"] = round(time.time() - start, 3)
                result_entry["fixture_errors"].append(f"positive test unexpected error: {exc}")
        else:
            result_entry["positive_error"] = "test_positive.sh not found or not executable"
            result_entry["fixture_errors"].append("test_positive.sh missing or not executable")

        if os.path.exists(negative_sh) and os.access(negative_sh, os.X_OK):
            start = time.time()
            try:
                proc = subprocess.run(
                    [negative_sh],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=os.path.dirname(fixtures_dir),
                )
                result_entry["negative_output"] = proc.stdout.strip()
                result_entry["negative_error"] = proc.stderr.strip()
                result_entry["negative_pass"] = proc.returncode == 0
                result_entry["negative_runtime"] = round(time.time() - start, 3)
            except subprocess.TimeoutExpired:
                result_entry["negative_error"] = "Negative test timed out after 30 seconds"
                result_entry["negative_runtime"] = round(time.time() - start, 3)
                result_entry["fixture_errors"].append("negative test timed out")
            except FileNotFoundError:
                result_entry["negative_error"] = "bash not found or test_negative.sh not accessible"
                result_entry["negative_runtime"] = 0
                result_entry["fixture_errors"].append("negative test — bash not reachable")
            except Exception as exc:
                result_entry["negative_error"] = f"Unexpected error: {exc}"
                result_entry["negative_runtime"] = round(time.time() - start, 3)
                result_entry["fixture_errors"].append(f"negative test unexpected error: {exc}")
        else:
            result_entry["negative_error"] = "test_negative.sh not found or not executable"
            result_entry["fixture_errors"].append("test_negative.sh missing or not executable")

        results.append(result_entry)

    total = len(results)
    passed_pos = sum(1 for r in results if r["positive_pass"])
    passed_neg = sum(1 for r in results if r["negative_pass"])

    manifest = {
        "results": results,
        "timestamp": timestamp,
        "total_fixtures": total,
        "positive_passed": passed_pos,
        "negative_passed": passed_neg,
    }

    manifest_path = os.path.join(context_dir, "results_manifest.json")
    with open(manifest_path, "w") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"[evaluation-harness] Results written → {manifest_path}")
    print(f"[evaluation-harness] Positive: {passed_pos}/{total}   Negative: {passed_neg}/{total}")


if __name__ == "__main__":
    main()