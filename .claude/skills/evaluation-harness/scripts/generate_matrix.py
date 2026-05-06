#!/usr/bin/env python3
import argparse
import json
import os
import time


def _safe_div(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator


def main():
    parser = argparse.ArgumentParser(description="Generate evaluation matrix from test results")
    parser.add_argument("--results-manifest", required=True, help="Path to results_manifest.json")
    parser.add_argument("--context", required=True, help="Output directory for matrix and dashboard")
    args = parser.parse_args()

    with open(args.results_manifest) as f:
        manifest = json.load(f)

    results = manifest.get("results", [])
    context_dir = os.path.abspath(args.context)
    os.makedirs(context_dir, exist_ok=True)

    skill_metrics = {}

    for record in results:
        skill = record["skill"]
        if skill not in skill_metrics:
            skill_metrics[skill] = {
                "skill": skill,
                "fixtures_tested": 0,
                "true_positives": 0,
                "true_negatives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "fixture_details": [],
            }

        sm = skill_metrics[skill]
        sm["fixtures_tested"] += 1
        sm["fixture_details"].append({
            "name": record["fixture_name"],
            "positive_pass": record["positive_pass"],
            "negative_pass": record["negative_pass"],
        })

        if record["positive_pass"]:
            sm["true_positives"] += 1
        else:
            sm["false_negatives"] += 1

        if record["negative_pass"]:
            sm["true_negatives"] += 1
        else:
            sm["false_positives"] += 1

    for skill, sm in skill_metrics.items():
        tp = sm["true_positives"]
        fp = sm["false_positives"]
        fn = sm["false_negatives"]
        tn = sm["true_negatives"]

        sm["precision"] = round(_safe_div(tp, tp + fp), 4)
        sm["recall"] = round(_safe_div(tp, tp + fn), 4)
        if sm["precision"] + sm["recall"] > 0:
            sm["f1"] = round(2 * sm["precision"] * sm["recall"] / (sm["precision"] + sm["recall"]), 4)
        else:
            sm["f1"] = 0.0
        sm["false_positive_rate"] = round(_safe_div(fp, fp + tn), 4)
        sm["accuracy"] = round(_safe_div(tp + tn, tp + fp + fn + tn), 4)
        sm["health_score"] = round(sm["f1"] * 10, 1)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    eval_matrix = {
        "generated": timestamp,
        "total_skills": len(skill_metrics),
        "total_fixtures": len(results),
        "skills": {sk: sm for sk, sm in skill_metrics.items()},
    }

    matrix_path = os.path.join(context_dir, "eval_matrix.json")
    with open(matrix_path, "w") as mf:
        json.dump(eval_matrix, mf, indent=2)

    dashboard_lines = [
        "# Evaluation Dashboard",
        "",
        f"Generated: {timestamp}",
        "",
        "| Skill | Fixtures | TP | TN | FP | FN | Precision | Recall | F1 | FPR | Health |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for skill_name in sorted(skill_metrics.keys()):
        sm = skill_metrics[skill_name]
        hs = sm["health_score"]
        if hs >= 8.0:
            health_symbol = "\U0001f7e2"
        elif hs >= 5.0:
            health_symbol = "\U0001f7e1"
        else:
            health_symbol = "\U0001f534"

        row = (
            f"| {sm['skill']} | {sm['fixtures_tested']} | {sm['true_positives']} | "
            f"{sm['true_negatives']} | {sm['false_positives']} | {sm['false_negatives']} | "
            f"{sm['precision']} | {sm['recall']} | {sm['f1']} | {sm['false_positive_rate']} | "
            f"{hs} {health_symbol} |"
        )
        dashboard_lines.append(row)

    dashboard_lines.extend([
        "",
        "## Health Score Legend",
        "- \U0001f7e2 8.0-10.0: Production ready",
        "- \U0001f7e1 5.0-7.9: Needs improvement",
        "- \U0001f534 0.0-4.9: Critical issues",
    ])

    dashboard_path = os.path.join(context_dir, "eval_dashboard.md")
    with open(dashboard_path, "w") as df:
        df.write("\n".join(dashboard_lines) + "\n")

    print(f"[evaluation-harness] Matrix written → {matrix_path}")
    print(f"[evaluation-harness] Dashboard written → {dashboard_path}")


if __name__ == "__main__":
    main()