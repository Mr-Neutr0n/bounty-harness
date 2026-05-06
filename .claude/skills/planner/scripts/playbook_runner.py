#!/usr/bin/env python3
"""
Playbook Runner

Safely executes playbook phases with guardrails. Reads a playbook YAML,
validates it, shows the execution plan, and asks before running.

Safety guarantees:
- Never auto-runs destructive-manual phases
- Stops at intrusive phases without --approve-intrusive
- Shows execution plan before running
- Respects resume_policy for output skipping
- Creates trace records for every step
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = SKILL_DIR / "playbook_schema.yaml"
PLAYBOOKS_DIR = SKILL_DIR / "playbooks"
TRACE_DIR = Path(".bb/traces") if Path(".bb/traces").is_dir() else Path(".bb")
TRACE_FILE = TRACE_DIR / "playbook_runs.jsonl"


def _load_yaml(path: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "PyYAML"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import yaml

    with open(path, "r") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"top-level must be a mapping")
    return data


def load_playbook(path: str) -> dict[str, Any]:
    return _load_yaml(path)


def load_schema(path: str) -> dict[str, Any]:
    return _load_yaml(path)


def load_context() -> dict[str, str]:
    """Load environment variables from .bb/context.env if it exists."""
    ctx: dict[str, str] = {}
    env_file = Path(".bb/context.env")
    if env_file.is_file():
        with open(env_file, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    val = val.strip().strip('"').strip("'")
                    ctx[key.strip()] = os.path.expandvars(val)
    return ctx


def resolve_inputs(inputs: dict[str, str] | None, context: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    if not inputs:
        return resolved
    for key, value in inputs.items():
        v = str(value)
        for env_key, env_val in context.items():
            v = v.replace(f"${env_key}", env_val)
        v = os.path.expandvars(v)
        resolved[key] = v
    return resolved


def all_outputs_exist(outputs: list[str] | None) -> bool:
    if not outputs:
        return False
    return all(os.path.exists(p) for p in outputs)


def run_playbook_validator(playbook_path: str, schema_path: str) -> tuple[bool, list[str]]:
    validator_path = SKILL_DIR / "scripts" / "playbook_validator.py"
    cmd = [
        sys.executable,
        str(validator_path),
        playbook_path,
        "--schema", schema_path,
        "--json",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return False, [result.stderr.strip() or "validation failed"]

        data = json.loads(result.stdout)
        results_list = data if isinstance(data, list) else [data]
        for r in results_list:
            if not r.get("valid", False):
                return False, r.get("errors", ["unknown validation error"])
        return True, []
    except subprocess.TimeoutExpired:
        return False, ["validator timed out"]
    except json.JSONDecodeError:
        return False, [f"validator output not parseable: {result.stdout[:200] if result else ''}"]
    except FileNotFoundError:
        return False, [f"validator script not found: {validator_path}"]
    except Exception as exc:
        return False, [str(exc)]


def write_trace(trace: dict[str, Any]) -> None:
    try:
        TRACE_DIR.mkdir(parents=True, exist_ok=True)
        with open(TRACE_FILE, "a") as fh:
            fh.write(json.dumps(trace) + "\n")
    except Exception:
        pass


def execute_step(step: dict[str, Any], context: dict[str, str],
                  step_ctx: dict[str, str], dry_run: bool) -> tuple[int, str]:
    """Execute a single step via bin/bb-run or directly."""
    skill = step.get("skill", "")
    workflow = step.get("workflow", "")
    step_id = step.get("id", "?")

    bb_run = Path("bin/bb-run")
    if bb_run.exists() and os.access(bb_run, os.X_OK):
        cmd_str = f"{bb_run} {skill} {workflow}"
    else:
        cmd_str = f"echo '[bb-run] would run: {skill} {workflow}'"

    combined_env = {**os.environ, **context, **step_ctx}

    trace = {
        "step_id": step_id,
        "skill": skill,
        "workflow": workflow,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run": dry_run,
    }

    if dry_run:
        print(f"      [DRY-RUN] {cmd_str}")
        trace["exit_code"] = 0
        trace["status"] = "dry_run_skipped"
        write_trace(trace)
        return 0, ""

    print(f"      Running: {skill}/{workflow} ...")
    try:
        proc = subprocess.run(
            cmd_str,
            shell=True,
            env=combined_env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        trace["exit_code"] = -1
        trace["status"] = "timeout"
        write_trace(trace)
        return -1, "timeout after 600s"
    except Exception as exc:
        trace["exit_code"] = -1
        trace["status"] = "error"
        trace["error"] = str(exc)
        write_trace(trace)
        return -1, str(exc)

    trace["exit_code"] = proc.returncode
    trace["status"] = "success" if proc.returncode == 0 else "failure"
    trace["stderr_tail"] = (proc.stderr or "")[-500:]
    write_trace(trace)

    if proc.stdout:
        for line in proc.stdout.strip().splitlines():
            print(f"        {line}")
    if proc.returncode != 0 and proc.stderr:
        print(f"        stderr: {proc.stderr[-300:]}", file=sys.stderr)

    return proc.returncode, proc.stderr


def execute_phase(phase: dict[str, Any], context: dict[str, str],
                   dry_run: bool, auto_safe: bool,
                   approve_intrusive: bool) -> bool:
    pid = phase.get("id", "?")
    pname = phase.get("name", pid)
    safety = phase.get("safety_tier", "unknown")
    resume_policy = phase.get("resume_policy", "always-run")

    print(f"\n  Phase: {pname} [{safety}]")

    if safety == "destructive-manual":
        print(f"    BLOCKED: destructive-manual phases are never auto-executed")
        return False

    if safety == "intrusive" and not approve_intrusive:
        print(f"    BLOCKED: intrusive phase requires --approve-intrusive")
        return False

    if safety == "intrusive" and approve_intrusive:
        print(f"    APPROVED: intrusive phase — user approved via --approve-intrusive")

    if not auto_safe and safety not in ("passive", "active-safe"):
        print(f"    BLOCKED: non-safe phase requires --auto-safe or --approve-intrusive")
        return False

    steps = phase.get("steps", [])
    if not isinstance(steps, list):
        return True

    for step in steps:
        if not isinstance(step, dict):
            continue

        sid = step.get("id", "?")
        inputs = step.get("inputs", {})
        outputs = step.get("outputs", [])
        stop_on = step.get("stop_on")

        step_context = resolve_inputs(inputs, context)

        if resume_policy == "skip-if-output-exists" and all_outputs_exist(outputs):
            print(f"    Skip: [{sid}] outputs already exist (resume_policy={resume_policy})")
            continue

        exit_code, stderr = execute_step(step, context, step_context, dry_run)

        if exit_code != 0 and stop_on == "error":
            print(f"    STOP: step '{sid}' failed and stop_on=error")
            return False

        if stop_on == "no_findings" and exit_code == 0 and not stderr:
            pass

    return True


def print_execution_plan(playbook: dict[str, Any]) -> None:
    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        return

    print(f"Playbook: {playbook.get('name', '?')} ({playbook.get('id', '?')})")
    print(f"Description: {playbook.get('description', '?')}")
    print(f"\nPhases ({len(phases)}):")
    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue
        pid = phase.get("id", "?")
        pname = phase.get("name", pid)
        safety = phase.get("safety_tier", "?")
        approval = " [APPROVAL REQUIRED]" if phase.get("approval_required") else ""
        dep = phase.get("depends_on", [])
        dep_str = f" (depends: {', '.join(dep)})" if dep else ""

        print(f"  {i+1}. [{safety}]{approval} {pname}{dep_str}")
        steps = phase.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    sid = step.get("id", "?")
                    sk = step.get("skill", "?")
                    wf = step.get("workflow", "?")
                    print(f"       - {sid}: {sk}/{wf}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Playbook Runner — safe multi-phase test flow execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 playbook_runner.py playbooks/new-target-passive.yaml --dry-run
  python3 playbook_runner.py playbooks/new-target-passive.yaml --auto-safe
  python3 playbook_runner.py playbooks/cors-csrf-safe.yaml --auto-safe
  python3 playbook_runner.py playbooks/api-authz-safe.yaml --approve-intrusive
        """,
    )
    parser.add_argument(
        "playbook",
        help="Path to a playbook YAML file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without executing anything",
    )
    parser.add_argument(
        "--auto-safe",
        action="store_true",
        help="Auto-run passive and active-safe phases without prompting",
    )
    parser.add_argument(
        "--approve-intrusive",
        action="store_true",
        help="Allow execution of intrusive phases (destructive-manual is still blocked)",
    )
    parser.add_argument(
        "--schema",
        default=None,
        help="Path to playbook_schema.yaml (default: skill's playbook_schema.yaml)",
    )
    parser.add_argument(
        "--context-env",
        default=".bb/context.env",
        help="Path to context env file",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip pre-execution validation",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.playbook):
        print(f"error: playbook not found: {args.playbook}", file=sys.stderr)
        sys.exit(1)

    try:
        playbook = load_playbook(args.playbook)
    except Exception as exc:
        print(f"error: cannot load playbook: {exc}", file=sys.stderr)
        sys.exit(1)

    schema_path = args.schema or str(DEFAULT_SCHEMA)
    context = load_context()

    print()
    print("=" * 60)
    print_execution_plan(playbook)
    print("=" * 60)

    if not args.no_validate:
        print("\nValidating playbook ...")
        valid, errors = run_playbook_validator(args.playbook, schema_path)
        if not valid:
            print(f"  Validation FAILED:")
            for e in errors:
                print(f"    - {e}")
            print("\nAborting. Fix validation errors or use --no-validate to skip.")
            sys.exit(1)
        print("  Validation PASSED")

    if args.dry_run:
        print("\n--- DRY RUN (no commands will execute) ---")

    phases = playbook.get("phases", [])
    if not isinstance(phases, list):
        print("error: playbook has no phases", file=sys.stderr)
        sys.exit(1)

    run_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not args.dry_run and not args.auto_safe:
        print()
        response = input("Proceed with execution? [y/N] ").strip().lower()
        if response not in ("y", "yes"):
            print("Aborted by user.")
            sys.exit(0)

    for phase in phases:
        ok = execute_phase(
            phase,
            context,
            dry_run=args.dry_run,
            auto_safe=args.auto_safe,
            approve_intrusive=args.approve_intrusive,
        )
        if not ok:
            print(f"\nPlaybook halted at phase '{phase.get('id','?')}'")
            break

    print()
    print(f"Playbook run complete at {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")


if __name__ == "__main__":
    main()