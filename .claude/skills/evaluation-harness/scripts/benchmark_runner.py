#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import time


def main():
    parser = argparse.ArgumentParser(description="Compare current evaluation to a saved baseline")
    parser.add_argument("--eval-matrix", required=True, help="Path to eval_matrix.json")
    parser.add_argument("--context", required=True, help="Directory storing baseline and benchmark outputs")
    args = parser.parse_args()

    with open(args.eval_matrix) as f:
        current = json.load(f)

    context_dir = os.path.abspath(args.context)
    os.makedirs(context_dir, exist_ok=True)

    baseline_path = os.path.join(context_dir, "baseline.json")
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    current_skills = current.get("skills", {})

    baseline = None
    baseline_exists = os.path.exists(baseline_path)
    if baseline_exists:
        with open(baseline_path) as bf:
            baseline = json.load(bf)

    comparisons = []
    regressions = []
    improvements = []

    for skill_name, curr in sorted(current_skills.items()):
        comp = {
            "skill": skill_name,
            "current": {
                "precision": curr["precision"],
                "recall": curr["recall"],
                "f1": curr["f1"],
                "fpr": curr["false_positive_rate"],
                "health_score": curr["health_score"],
                "fixtures": curr["fixtures_tested"],
            },
            "baseline": {},
            "deltas": {},
            "regressions": [],
            "improvements": [],
        }

        if baseline and skill_name in baseline.get("skills", {}):
            bl = baseline["skills"][skill_name]
            comp["baseline"] = {
                "precision": bl.get("precision", 0),
                "recall": bl.get("recall", 0),
                "f1": bl.get("f1", 0),
                "fpr": bl.get("false_positive_rate", 0),
                "health_score": bl.get("health_score", 0),
                "fixtures": bl.get("fixtures_tested", 0),
            }

            delta_precision = round(curr["precision"] - bl["precision"], 4)
            delta_recall = round(curr["recall"] - bl["recall"], 4)
            delta_f1 = round(curr["f1"] - bl["f1"], 4)
            delta_fpr = round(curr["false_positive_rate"] - bl["false_positive_rate"], 4)
            delta_health = round(curr["health_score"] - bl["health_score"], 2)

            comp["deltas"] = {
                "precision": delta_precision,
                "recall": delta_recall,
                "f1": delta_f1,
                "fpr": delta_fpr,
                "health_score": delta_health,
            }

            if delta_f1 < -0.05:
                desc = (
                    f"{skill_name}: F1 dropped "
                    f"from {bl['f1']} to {curr['f1']} ({delta_f1:+.4f})"
                )
                regressions.append(desc)
                comp["regressions"].append(f"F1 regression: {delta_f1:+.4f}")

            if delta_health < -0.5:
                desc = f"{skill_name}: Health score dropped by {delta_health:+.2f}"
                regressions.append(desc)
                comp["regressions"].append(f"Health regression: {delta_health:+.2f}")

            if delta_f1 > 0.05:
                desc = (
                    f"{skill_name}: F1 improved "
                    f"from {bl['f1']} to {curr['f1']} (+{delta_f1:+.4f})"
                )
                improvements.append(desc)
                comp["improvements"].append(f"F1 improvement: +{delta_f1:+.4f}")

            if delta_health > 0.5:
                desc = f"{skill_name}: Health score improved by +{delta_health:+.2f}"
                improvements.append(desc)
                comp["improvements"].append(f"Health improvement: +{delta_health:+.2f}")

        comparisons.append(comp)

    shutil.copy2(args.eval_matrix, baseline_path)

    benchmark = {
        "timestamp": timestamp,
        "baseline_available": baseline_exists,
        "first_run": not baseline_exists,
        "comparisons": comparisons,
        "regressions": regressions,
        "improvements": improvements,
    }

    benchmark_path = os.path.join(context_dir, "benchmark.json")
    with open(benchmark_path, "w") as bj:
        json.dump(benchmark, bj, indent=2)

    report_lines = [
        "# Benchmark Report",
        "",
        f"Generated: {timestamp}",
        f"Baseline available: {'yes' if baseline_exists else 'no (first run — baseline saved)'}",
        "",
    ]

    if not baseline_exists:
        report_lines.append(
            "This is the first benchmark run. A baseline has been established. "
            "Run the benchmark again after making skill improvements to see comparison results."
        )
        report_lines.append("")
    else:
        if regressions:
            report_lines.append("## Regressions")
            for r in regressions:
                report_lines.append(f"- {r}")
            report_lines.append("")

        if improvements:
            report_lines.append("## Improvements")
            for imp in improvements:
                report_lines.append(f"- {imp}")
            report_lines.append("")

        if not regressions and not improvements:
            report_lines.append("No significant changes detected (all deltas within 5% threshold).")
            report_lines.append("")

        report_lines.append("## Skill Comparison")
        report_lines.append("| Skill | Prev F1 | Curr F1 | Delta F1 | Prev Health | Curr Health |")
        report_lines.append("| --- | --- | --- | --- | --- | --- |")
        for comp in comparisons:
            if comp["baseline"]:
                row = (
                    f"| {comp['skill']} | {comp['baseline'].get('f1', 0)} | "
                    f"{comp['current']['f1']} | {comp['deltas'].get('f1', 0)} | "
                    f"{comp['baseline'].get('health_score', 0)} | {comp['current']['health_score']} |"
                )
            else:
                row = (
                    f"| {comp['skill']} | N/A | {comp['current']['f1']} | "
                    f"N/A | N/A | {comp['current']['health_score']} |"
                )
            report_lines.append(row)
        report_lines.append("")

    report_path = os.path.join(context_dir, "benchmark_report.md")
    with open(report_path, "w") as rf:
        rf.write("\n".join(report_lines) + "\n")

    print(f"[evaluation-harness] Benchmark written → {benchmark_path}")
    print(f"[evaluation-harness] Report written → {report_path}")


if __name__ == "__main__":
    main()