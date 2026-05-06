#!/usr/bin/env python3
"""
Plan Validator

Validates a planner JSON output against plan_schema.yaml.
Checks structural completeness, required fields, value ranges,
metadata sanity, and summary consistency.
"""

import argparse
import json
import os
import sys
import math
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = SKILL_DIR / "plan_schema.yaml"

REQUIRED_META_FIELDS = ["target", "program", "generated_at", "standards_coverage_pct",
                         "total_techniques_available", "techniques_matched", "techniques_filtered"]

REQUIRED_ITEM_FIELDS = [
    "priority", "score", "technique_id", "technique_name", "category", "severity",
    "skill", "workflow", "rationale", "preconditions", "safety",
    "expected_signals", "evidence_requirements", "standards_checked", "coverage_gap",
    "score_breakdown", "surface_matches",
]

REQUIRED_SAFETY_FIELDS = ["intrusive", "data_modifying", "rate_limited", "requires_confirmation"]

REQUIRED_SCORE_BREAKDOWN_FIELDS = [
    "business_impact", "surface_prevalence", "vulnerability_severity",
    "detection_signal_quality", "coverage_gap_urgency", "tool_availability",
]

VALID_PRIORITIES = {"critical", "high", "medium", "low"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

WEIGHTS = {
    "business_impact": 0.30,
    "surface_prevalence": 0.20,
    "vulnerability_severity": 0.20,
    "detection_signal_quality": 0.15,
    "coverage_gap_urgency": 0.10,
    "tool_availability": 0.05,
}


def _load_schema(path: str) -> dict[str, Any]:
    if yaml is None:
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "PyYAML"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import yaml as _yaml_module
        globals()["yaml"] = _yaml_module

    with open(path, "r") as fh:
        return yaml.safe_load(fh)


def validate(plan: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    meta = plan.get("metadata")
    if not isinstance(meta, dict):
        errors.append("metadata: missing or not an object")
    else:
        for field in REQUIRED_META_FIELDS:
            if field not in meta:
                errors.append(f"metadata.{field}: missing required field")

        ts = meta.get("generated_at", "")
        if ts and not isinstance(ts, str):
            errors.append("metadata.generated_at: must be string")
        if isinstance(ts, str) and len(ts) < 10:
            errors.append("metadata.generated_at: malformed timestamp")

        coverage_pct = meta.get("standards_coverage_pct", 0)
        if isinstance(coverage_pct, (int, float)):
            if coverage_pct < 0 or coverage_pct > 100:
                errors.append("metadata.standards_coverage_pct: out of range [0,100]")

    domain = plan.get("domain_profile")
    if not isinstance(domain, dict):
        errors.append("domain_profile: missing or not an object")

    items = plan.get("plan_items")
    if not isinstance(items, list):
        errors.append("plan_items: missing or not a list")
    else:
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append(f"plan_items[{i}]: not an object")
                continue

            for field in REQUIRED_ITEM_FIELDS:
                if field not in item:
                    errors.append(f"plan_items[{i}].{field}: missing required field")

            priority = item.get("priority", "")
            if priority not in VALID_PRIORITIES:
                errors.append(f"plan_items[{i}].priority: invalid value '{priority}'")

            severity = item.get("severity", "").lower()
            if severity not in VALID_SEVERITIES:
                errors.append(f"plan_items[{i}].severity: invalid value '{severity}'")

            score = item.get("score")
            if isinstance(score, (int, float)):
                if score < 0 or score > 1:
                    errors.append(f"plan_items[{i}].score: out of range [0,1]")
            else:
                errors.append(f"plan_items[{i}].score: must be a number")

            breakdown = item.get("score_breakdown")
            if isinstance(breakdown, dict):
                for field in REQUIRED_SCORE_BREAKDOWN_FIELDS:
                    if field not in breakdown:
                        errors.append(f"plan_items[{i}].score_breakdown.{field}: missing")
                    else:
                        val = breakdown[field]
                        if isinstance(val, (int, float)):
                            if val < 0 or val > 1:
                                errors.append(
                                    f"plan_items[{i}].score_breakdown.{field}: "
                                    f"out of range [0,1]"
                                )

                computed = sum(
                    WEIGHTS[k] * breakdown.get(k, 0)
                    for k in WEIGHTS
                )
                if abs(computed - score) > 0.02:
                    errors.append(
                        f"plan_items[{i}].score: computed={computed:.4f} "
                        f"!= declared={score:.4f} (diff={abs(computed-score):.4f})"
                    )
            else:
                errors.append(f"plan_items[{i}].score_breakdown: missing or not an object")

            safety = item.get("safety")
            if isinstance(safety, dict):
                for field in REQUIRED_SAFETY_FIELDS:
                    if field not in safety:
                        errors.append(f"plan_items[{i}].safety.{field}: missing")
                    elif not isinstance(safety[field], bool):
                        errors.append(
                            f"plan_items[{i}].safety.{field}: must be boolean"
                        )
            else:
                errors.append(f"plan_items[{i}].safety: missing or not an object")

            preconditions = item.get("preconditions")
            if isinstance(preconditions, dict):
                tools = preconditions.get("tools")
                if not isinstance(tools, list):
                    errors.append(f"plan_items[{i}].preconditions.tools: must be a list")
            else:
                errors.append(f"plan_items[{i}].preconditions: missing or not an object")

            signals = item.get("expected_signals")
            if isinstance(signals, dict):
                pos = signals.get("positive")
                neg = signals.get("negative")
                if not isinstance(pos, list) and pos is not None:
                    errors.append(
                        f"plan_items[{i}].expected_signals.positive: must be a list"
                    )
                if not isinstance(neg, list) and neg is not None:
                    errors.append(
                        f"plan_items[{i}].expected_signals.negative: must be a list"
                    )
            else:
                errors.append(f"plan_items[{i}].expected_signals: missing or not an object")

            evidence = item.get("evidence_requirements")
            if not isinstance(evidence, list):
                errors.append(
                    f"plan_items[{i}].evidence_requirements: must be a list"
                )

            standards = item.get("standards_checked")
            if not isinstance(standards, list):
                errors.append(
                    f"plan_items[{i}].standards_checked: must be a list"
                )

            coverage_gap = item.get("coverage_gap")
            if not isinstance(coverage_gap, bool):
                errors.append(
                    f"plan_items[{i}].coverage_gap: must be boolean"
                )

    summary = plan.get("summary")
    if isinstance(summary, dict):
        expected_total = summary.get("total_plan_items", 0)
        actual_total = len(items) if isinstance(items, list) else 0
        if expected_total != actual_total:
            errors.append(
                f"summary.total_plan_items: {expected_total} != actual {actual_total}"
            )

        by_priority = summary.get("by_priority", {})
        if isinstance(by_priority, dict):
            counted: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        p = item.get("priority", "low")
                        if p in counted:
                            counted[p] += 1
            for p in ["critical", "high", "medium", "low"]:
                if by_priority.get(p, 0) != counted.get(p, 0):
                    errors.append(
                        f"summary.by_priority.{p}: {by_priority.get(p, 0)} "
                        f"!= counted {counted.get(p, 0)}"
                    )

        auth_count = summary.get("auth_required_count", 0)
        actual_auth = 0
        if isinstance(items, list):
            actual_auth = sum(
                1 for item in items
                if isinstance(item, dict)
                and item.get("preconditions", {}).get("auth_required", "none") not in ("none", "")
            )
        if auth_count != actual_auth:
            errors.append(
                f"summary.auth_required_count: {auth_count} != actual {actual_auth}"
            )

        intrusive_count = summary.get("intrusive_count", 0)
        actual_intrusive = 0
        if isinstance(items, list):
            actual_intrusive = sum(
                1 for item in items
                if isinstance(item, dict) and item.get("safety", {}).get("intrusive", False)
            )
        if intrusive_count != actual_intrusive:
            errors.append(
                f"summary.intrusive_count: {intrusive_count} != actual {actual_intrusive}"
            )

        safe_count = summary.get("safe_to_run_immediately", 0)
        actual_safe = 0
        if isinstance(items, list):
            actual_safe = sum(
                1 for item in items
                if isinstance(item, dict)
                and not item.get("safety", {}).get("intrusive", False)
                and not item.get("safety", {}).get("data_modifying", False)
            )
        if safe_count != actual_safe:
            errors.append(
                f"summary.safe_to_run_immediately: {safe_count} != actual {actual_safe}"
            )
    else:
        errors.append("summary: missing or not an object")

    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan Validator — validate plan JSON against schema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 plan_validator.py --plan plan.json
  python3 plan_validator.py --plan plan.json --schema /path/to/plan_schema.yaml
        """,
    )
    parser.add_argument("--plan", required=True, help="Path to plan JSON file")
    parser.add_argument("--schema", default=None,
                        help="Path to plan_schema.yaml (default: skill's plan_schema.yaml)")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.plan):
        print(f"error: plan file not found: {args.plan}", file=sys.stderr)
        sys.exit(1)

    schema_path = args.schema or str(DEFAULT_SCHEMA)
    if not os.path.isfile(schema_path):
        print(f"error: schema file not found: {schema_path}", file=sys.stderr)
        sys.exit(1)

    schema = _load_schema(schema_path)

    with open(args.plan, "r") as fh:
        try:
            plan = json.load(fh)
        except json.JSONDecodeError as exc:
            print(f"error: invalid JSON in plan file: {exc}", file=sys.stderr)
            sys.exit(1)

    errors = validate(plan, schema)

    if errors:
        print(f"\N{cross mark} Validation FAILED — {len(errors)} issues found:\n")
        for e in errors:
            print(f"  - {e}")
        print()
        sys.exit(1)
    else:
        meta = plan.get("metadata", {})
        items = plan.get("plan_items", [])
        summary = plan.get("summary", {})

        print(f"\N{check mark} Validation PASSED")
        print(f"  Target: {meta.get('target', '?')}")
        print(f"  Program: {meta.get('program', '?')}")
        print(f"  Plan items: {len(items)}")
        print(f"  Coverage: {summary.get('coverage_before', 0)}% -> "
              f"{summary.get('coverage_after', 0)}%")


if __name__ == "__main__":
    main()