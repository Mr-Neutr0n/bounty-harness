#!/usr/bin/env python3
"""
Playbook Validator

Validates playbook YAML files against playbook_schema.yaml.
Checks schema compliance, dependency cycles, skill/workflow existence,
safety tier consistency, output path validity, and resume policy correctness.

Returns:
  0 = all valid
  1 = validation errors
  2 = schema or file errors (missing files, invalid YAML)
"""

import argparse
import json
import os
import sys
from collections import deque
from pathlib import Path
from typing import Any


SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = SKILL_DIR / "playbook_schema.yaml"
PLAYBOOKS_DIR = SKILL_DIR / "playbooks"
SKILLS_DIR = Path(__file__).resolve().parent.parent.parent  # .claude/skills/


def _load_yaml(path: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "PyYAML"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import yaml

    with open(path, "r") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"top-level must be a mapping, got {type(data).__name__}")
    return data


def load_schema(path: str) -> dict[str, Any]:
    return _load_yaml(path)


def load_playbook(path: str) -> dict[str, Any]:
    return _load_yaml(path)


def discover_playbooks(playbooks_dir: str) -> list[str]:
    pd = Path(playbooks_dir)
    if not pd.is_dir():
        return []
    return sorted(str(p) for p in pd.glob("*.yaml"))


def load_skill_registry() -> dict[str, set[str]]:
    """Build {skill_name: {workflow_name, ...}} from all skill.yaml files."""
    registry: dict[str, set[str]] = {}
    if not SKILLS_DIR.is_dir():
        return registry

    for skill_yaml_path in sorted(SKILLS_DIR.glob("*/skill.yaml")):
        try:
            data = _load_yaml(str(skill_yaml_path))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        if not name:
            continue
        workflows = data.get("workflows", {})
        if isinstance(workflows, dict):
            registry[str(name)] = set(workflows.keys())

    return registry


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_schema_compliance(playbook: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    required = schema.get("required_fields", [])
    for field in required:
        if field not in playbook:
            errors.append(f"top-level.{field}: missing required field")

    phases = playbook.get("phases")
    if not isinstance(phases, list):
        errors.append("phases: must be a list")
        return errors

    if len(phases) == 0:
        errors.append("phases: must contain at least one phase")
        return errors

    phase_req = schema.get("phase_fields", {}).get("required", [])
    phase_opt = schema.get("phase_fields", {}).get("optional", [])
    valid_tiers = schema.get("safety_tiers", [])
    valid_policies = schema.get("resume_policies", [])
    valid_stop = schema.get("stop_on_conditions", [])

    step_req = schema.get("step_fields", {}).get("required", [])

    phase_ids_seen: set[str] = set()

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            errors.append(f"phases[{i}]: not a mapping")
            continue

        for field in phase_req:
            if field not in phase:
                errors.append(f"phases[{i}].{field}: missing required field")

        pid = phase.get("id", "")
        if not isinstance(pid, str) or not pid:
            errors.append(f"phases[{i}].id: missing or empty")
        elif pid in phase_ids_seen:
            errors.append(f"phases[{i}].id: duplicate phase id '{pid}'")
        else:
            phase_ids_seen.add(pid)

        safety = phase.get("safety_tier", "")
        if safety and safety not in valid_tiers:
            errors.append(f"phases[{i}].safety_tier: invalid '{safety}' (valid: {valid_tiers})")

        rp = phase.get("resume_policy")
        if rp is not None and rp not in valid_policies:
            errors.append(f"phases[{i}].resume_policy: invalid '{rp}' (valid: {valid_policies})")

        steps = phase.get("steps")
        if not isinstance(steps, list):
            errors.append(f"phases[{i}].steps: must be a list")
            continue
        if len(steps) == 0:
            errors.append(f"phases[{i}].steps: must contain at least one step")
            continue

        step_ids_seen: set[str] = set()
        for j, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"phases[{i}].steps[{j}]: not a mapping")
                continue

            for field in step_req:
                if field not in step:
                    errors.append(f"phases[{i}].steps[{j}].{field}: missing required field")

            sid = step.get("id", "")
            if not isinstance(sid, str) or not sid:
                errors.append(f"phases[{i}].steps[{j}].id: missing or empty")
            elif sid in step_ids_seen:
                errors.append(f"phases[{i}].steps[{j}].id: duplicate step id '{sid}'")
            else:
                step_ids_seen.add(sid)

            skill = step.get("skill", "")
            workflow = step.get("workflow", "")
            if not isinstance(skill, str) or not skill:
                errors.append(f"phases[{i}].steps[{j}].skill: missing or empty")
            if not isinstance(workflow, str) or not workflow:
                errors.append(f"phases[{i}].steps[{j}].workflow: missing or empty")

            stop = step.get("stop_on")
            if stop is not None and stop not in valid_stop:
                errors.append(f"phases[{i}].steps[{j}].stop_on: invalid '{stop}' (valid: {valid_stop})")

    return errors


def detect_dependency_cycles(playbook: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        return errors

    phase_ids = {}
    adj: dict[str, set[str]] = {}

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        pid = phase.get("id", "")
        if not pid:
            continue
        phase_ids[pid] = i

    for phase in phases:
        if not isinstance(phase, dict):
            continue
        pid = phase.get("id", "")
        if not pid:
            continue
        deps = phase.get("depends_on", [])
        if not isinstance(deps, list):
            deps = []
        adj[pid] = set()
        for dep in deps:
            dep_str = str(dep)
            if dep_str not in phase_ids:
                errors.append(f"phase '{pid}'.depends_on: references unknown phase '{dep_str}'")
            else:
                adj[pid].add(dep_str)

    if errors:
        return errors

    color: dict[str, int] = {pid: 0 for pid in phase_ids}

    def dfs(node: str, stack: list[str]) -> list[str] | None:
        color[node] = 1
        for neighbor in adj.get(node, set()):
            if color[neighbor] == 0:
                result = dfs(neighbor, stack + [neighbor])
                if result:
                    return result
            elif color[neighbor] == 1:
                cycle_start = stack.index(neighbor) if neighbor in stack else 0
                return stack[cycle_start:] + [neighbor]
        color[node] = 2
        return None

    for pid in phase_ids:
        if color[pid] == 0:
            cycle = dfs(pid, [pid])
            if cycle:
                errors.append(f"dependency cycle detected: {' -> '.join(cycle)}")
                break

    return errors


def validate_skill_workflow_existence(playbook: dict[str, Any],
                                       registry: dict[str, set[str]]) -> list[str]:
    errors: list[str] = []
    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        return errors

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue
        for j, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            skill = str(step.get("skill", ""))
            workflow = str(step.get("workflow", ""))
            if not skill or not workflow:
                continue

            known_workflows = registry.get(skill)
            if known_workflows is None:
                errors.append(
                    f"phases[{i}].steps[{j}] '{step.get('id','?')}': "
                    f"skill '{skill}' not found in registry"
                )
            elif workflow not in known_workflows:
                errors.append(
                    f"phases[{i}].steps[{j}] '{step.get('id','?')}': "
                    f"workflow '{workflow}' not found in skill '{skill}' "
                    f"(available: {sorted(known_workflows)})"
                )

    return errors


def validate_safety_tier_monotonicity(playbook: dict[str, Any],
                                       schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    ordering = schema.get("safety_tier_order", {})
    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        return errors

    prev_tier_level = -1
    prev_phase_id = ""
    had_approval = False

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        pid = phase.get("id", f"#{i}")
        tier = phase.get("safety_tier", "")
        current_level = ordering.get(tier, -1)

        if current_level < 0:
            continue

        if current_level < prev_tier_level and not had_approval:
            errors.append(
                f"phase '{pid}' safety tier '{tier}' is lower than previous "
                f"phase '{prev_phase_id}' tier "
                f"({phases[i-1].get('safety_tier','?') if i > 0 else '?'}) "
                f"without an approval gate"
            )

        if prev_tier_level >= 2 and current_level >= 2:
            had_approval = had_approval or bool(phase.get("approval_required"))

        prev_tier_level = current_level
        prev_phase_id = pid
        had_approval = bool(phase.get("approval_required"))

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        pid = phase.get("id", f"#{i}")
        tier = phase.get("safety_tier", "")
        if tier == "destructive-manual":
            if not phase.get("approval_required"):
                errors.append(
                    f"phase '{pid}': destructive-manual tier requires approval_required=true"
                )

    return errors


def validate_output_paths(playbook: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        return errors

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        steps = phase.get("steps", [])
        if not isinstance(steps, list):
            continue
        for j, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            outputs = step.get("outputs")
            if outputs is None:
                continue
            if not isinstance(outputs, list):
                errors.append(
                    f"phases[{i}].steps[{j}] '{step.get('id','?')}': "
                    f"outputs must be a list"
                )
                continue
            for k, out_path in enumerate(outputs):
                if not isinstance(out_path, str):
                    errors.append(
                        f"phases[{i}].steps[{j}] '{step.get('id','?')}': "
                        f"outputs[{k}] must be a string"
                    )

    return errors


def validate_playbook(playbook: dict[str, Any], schema: dict[str, Any],
                       registry: dict[str, set[str]]) -> list[str]:
    all_errors: list[str] = []

    all_errors.extend(validate_schema_compliance(playbook, schema))
    all_errors.extend(detect_dependency_cycles(playbook))
    all_errors.extend(validate_skill_workflow_existence(playbook, registry))
    all_errors.extend(validate_safety_tier_monotonicity(playbook, schema))
    all_errors.extend(validate_output_paths(playbook))

    return all_errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def format_json_output(results: list[dict[str, Any]]) -> str:
    return json.dumps(results, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Playbook Validator — validate playbook YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 playbook_validator.py playbooks/new-target-passive.yaml
  python3 playbook_validator.py --all
  python3 playbook_validator.py --all --json
  python3 playbook_validator.py playbooks/api-authz-safe.yaml --json
  python3 playbook_validator.py --all --schema /path/to/playbook_schema.yaml
        """,
    )
    parser.add_argument(
        "playbook",
        nargs="?",
        help="Path to a single playbook YAML file (omit if using --all)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all playbooks in the playbooks/ directory",
    )
    parser.add_argument(
        "--schema",
        default=None,
        help="Path to playbook_schema.yaml (default: skill's playbook_schema.yaml)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON (machine-readable)",
    )
    parser.add_argument(
        "--playbooks-dir",
        default=None,
        help="Path to playbooks directory (default: skill's playbooks/)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    schema_path = args.schema or str(DEFAULT_SCHEMA)
    if not os.path.isfile(schema_path):
        msg = f"error: schema file not found: {schema_path}"
        if args.json_output:
            print(json.dumps({"error": msg}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(2)

    try:
        schema = load_schema(schema_path)
    except Exception as exc:
        msg = f"error: cannot load schema: {exc}"
        if args.json_output:
            print(json.dumps({"error": msg}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(2)

    registry = load_skill_registry()
    if not registry:
        if not args.json_output:
            print("warn: skill registry is empty — skill/workflow existence checks "
                  "will report all as missing", file=sys.stderr)

    playbooks_dir = args.playbooks_dir or str(PLAYBOOKS_DIR)

    if args.all:
        playbook_files = discover_playbooks(playbooks_dir)
        if not playbook_files:
            msg = f"error: no playbook YAML files found in {playbooks_dir}"
            if args.json_output:
                print(json.dumps({"error": msg}))
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)
    elif args.playbook:
        if not os.path.isfile(args.playbook):
            msg = f"error: playbook file not found: {args.playbook}"
            if args.json_output:
                print(json.dumps({"error": msg}))
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)
        playbook_files = [args.playbook]
    else:
        parser.print_help()
        sys.exit(2)

    all_results: list[dict[str, Any]] = []
    overall_exit = 0

    for pb_path in playbook_files:
        try:
            playbook = load_playbook(pb_path)
        except Exception as exc:
            result = {
                "playbook": pb_path,
                "valid": False,
                "errors": [f"cannot parse YAML: {exc}"],
            }
            all_results.append(result)
            overall_exit = max(overall_exit, 2)
            continue

        errors = validate_playbook(playbook, schema, registry)

        result = {
            "playbook": pb_path,
            "playbook_id": playbook.get("id", "?"),
            "playbook_name": playbook.get("name", "?"),
            "valid": len(errors) == 0,
            "error_count": len(errors),
            "errors": errors,
        }
        all_results.append(result)

        if errors and overall_exit < 1:
            overall_exit = 1

    if args.json_output:
        print(format_json_output(all_results))
    else:
        for result in all_results:
            pb_display = result.get("playbook_id", os.path.basename(result["playbook"]))
            if result["valid"]:
                print(f"  PASS  {pb_display}  ({result['playbook_name']})")
            else:
                print(f"  FAIL  {pb_display}  ({result['playbook_name']}) "
                      f"[{result['error_count']} issues]")
                for err in result["errors"]:
                    print(f"         - {err}")

        total = len(all_results)
        passed = sum(1 for r in all_results if r["valid"])
        print()
        print(f"{passed}/{total} playbooks passed")

    sys.exit(overall_exit)


if __name__ == "__main__":
    main()