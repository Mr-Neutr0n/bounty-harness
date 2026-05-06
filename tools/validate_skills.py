#!/usr/bin/env python3
"""Skill Quality Validator — checks every skill meets the Definition of Best."""
import os, sys, subprocess, json, yaml, re
from pathlib import Path

SKILLS_DIR = Path(".claude/skills")
CONTEXT_FILE = Path(".bb/context.json")
REQUIRED_FILES = ["SKILL.md", "skill.yaml"]
MIN_SCRIPTS = 3
MIN_RUNBOOKS = 4
MIN_PAYLOADS = 2
PLACEHOLDER_PATTERNS = ["YOUR_", "TODO", "TBD", "<script>", "placeholder"]
DESTRUCTIVE_PATTERNS = ["rm -rf", "DROP TABLE", ":(){ :|:& };:", "> /dev/sda"]
PASS_THRESHOLD = 85
SCRIPT_REF_RE = re.compile(r"\.claude/skills/[^\s\"'`]+")
SKILL_MD_SCRIPT_REF_RE = re.compile(r"scripts/[A-Za-z0-9_.\-/]+")
SCRIPT_HELP_TIMEOUT = 8
REQUIRED_SKILL_MD_SECTIONS = [
    "## Overview",
    "## Quick Reference",
    "## Workflow Selection",
    "## Available Workflows",
    "## Evidence Required",
    "## References",
]

def check_skill(skill_path):
    name = skill_path.name
    report = {"name": name, "checks": [], "score": 100, "deductions": []}

    # Check required files exist
    for req in REQUIRED_FILES:
        if (skill_path / req).exists():
            report["checks"].append(f"PASS: {req} exists")
        else:
            report["checks"].append(f"FAIL: {req} missing")
            report["deductions"].append(f"Missing {req}")

    # Check scripts directory
    scripts_dir = skill_path / "scripts"
    if scripts_dir.exists():
        py_scripts = list(scripts_dir.glob("*.py")) + list(scripts_dir.glob("*.sh"))
        if len(py_scripts) >= MIN_SCRIPTS:
            report["checks"].append(f"PASS: {len(py_scripts)} scripts (min {MIN_SCRIPTS})")
        else:
            report["checks"].append(f"FAIL: only {len(py_scripts)} scripts (need {MIN_SCRIPTS})")
            report["deductions"].append(f"Script count {len(py_scripts)} < {MIN_SCRIPTS}")

        for script in sorted(scripts_dir.glob("*.py")):
            try:
                result = subprocess.run(
                    [sys.executable, str(script), "--help"],
                    cwd=Path.cwd(),
                    capture_output=True,
                    text=True,
                    timeout=SCRIPT_HELP_TIMEOUT,
                )
                help_text = (result.stdout + result.stderr).lower()
                if result.returncode != 0 or "usage:" not in help_text:
                    report["checks"].append(f"FAIL: {script.name} --help failed")
                    report["deductions"].append(f"Broken --help for {script.name}")
            except Exception as e:
                report["checks"].append(f"FAIL: {script.name} --help exception: {e}")
                report["deductions"].append(f"Broken --help for {script.name}")
    else:
        report["checks"].append("FAIL: scripts/ directory missing")
        report["deductions"].append("Missing scripts/")

    # Check runbooks
    runbooks_dir = skill_path / "runbooks"
    if runbooks_dir.exists():
        rb_count = len(list(runbooks_dir.glob("*.md")))
        if rb_count >= MIN_RUNBOOKS:
            report["checks"].append(f"PASS: {rb_count} runbooks (min {MIN_RUNBOOKS})")
        else:
            report["checks"].append(f"FAIL: only {rb_count} runbooks (need {MIN_RUNBOOKS})")
            report["deductions"].append(f"Runbook count {rb_count} < {MIN_RUNBOOKS}")

    # Check payloads
    payloads_dir = skill_path / "payloads"
    if payloads_dir.exists():
        pl_count = len(list(payloads_dir.glob("*.txt")))
        if pl_count >= MIN_PAYLOADS:
            report["checks"].append(f"PASS: {pl_count} payload files (min {MIN_PAYLOADS})")
        else:
            report["checks"].append(f"FAIL: only {pl_count} payload files (need {MIN_PAYLOADS})")
            report["deductions"].append(f"Payload count {pl_count} < {MIN_PAYLOADS}")

    # Check SKILL.md for placeholders
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        content = skill_md.read_text()
        for section in REQUIRED_SKILL_MD_SECTIONS:
            if section not in content:
                report["checks"].append(f"FAIL: SKILL.md missing section {section}")
                report["deductions"].append(f"Missing SKILL.md section {section}")

        for pat in PLACEHOLDER_PATTERNS:
            if pat in content:
                count = content.count(pat)
                report["checks"].append(f"WARN: '{pat}' found {count} times in SKILL.md")
                report["deductions"].append(f"Placeholder '{pat}' ({count}x)")

        missing_doc_refs = []
        for ref in SKILL_MD_SCRIPT_REF_RE.findall(content):
            ref = ref.rstrip(");,")
            if ref.endswith((".py", ".sh", ".js")) and not (skill_path / ref).exists():
                missing_doc_refs.append(ref)
        if missing_doc_refs:
            for ref in missing_doc_refs[:10]:
                report["checks"].append(f"FAIL: SKILL.md references missing script {ref}")
            if len(missing_doc_refs) > 10:
                report["checks"].append(f"FAIL: {len(missing_doc_refs) - 10} additional missing SKILL.md script references")
            for ref in missing_doc_refs:
                report["deductions"].append(f"Missing SKILL.md script ref: {ref}")
        else:
            report["checks"].append("PASS: SKILL.md script refs exist")

    # Check skill.yaml format
    skill_yaml = skill_path / "skill.yaml"
    if skill_yaml.exists():
        try:
            with open(skill_yaml) as f:
                data = yaml.safe_load(f)
            wf_count = len(data.get("workflows", {}))
            report["checks"].append(f"PASS: skill.yaml has {wf_count} workflows")

            missing_refs = []
            for wf_name, workflow in (data.get("workflows", {}) or {}).items():
                command = str((workflow or {}).get("command", ""))
                for ref in SCRIPT_REF_RE.findall(command):
                    ref = ref.rstrip(");,")
                    if ref.endswith((".py", ".sh", ".js")) and not Path(ref).exists():
                        missing_refs.append((wf_name, ref))

            if missing_refs:
                for wf_name, ref in missing_refs[:10]:
                    report["checks"].append(f"FAIL: {wf_name} references missing script {ref}")
                if len(missing_refs) > 10:
                    report["checks"].append(f"FAIL: {len(missing_refs) - 10} additional missing script references")
                for wf_name, ref in missing_refs:
                    report["deductions"].append(f"Missing workflow script ref: {wf_name} -> {ref}")
            else:
                report["checks"].append("PASS: workflow script refs exist")
        except Exception as e:
            report["checks"].append(f"FAIL: skill.yaml parse error: {e}")
            report["deductions"].append(f"skill.yaml invalid")

    # Calculate score
    report["score"] = max(0, 100 - (len(report["deductions"]) * 5))
    return report

def main():
    results = []
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if skill_dir.is_dir() and not skill_dir.name.startswith("."):
            r = check_skill(skill_dir)
            results.append(r)

    results.sort(key=lambda x: x["score"])

    print("\n=== Skill Quality Report ===\n")
    total = 0
    for r in results:
        status = "PASS" if r["score"] >= PASS_THRESHOLD else "FAIL"
        icon = "✓" if r["score"] >= PASS_THRESHOLD else "✗"
        print(f"{icon} {r['name']:30s} {r['score']:3d}/100 [{status}]")
        if r["deductions"]:
            for d in r["deductions"]:
                print(f"   ↳ {d}")
        total += r["score"]

    avg = total // len(results) if results else 0
    print(f"\n{'─'*50}")
    print(f"Average: {avg}/100")
    print(f"Threshold: {PASS_THRESHOLD}/100")

    all_pass = all(r["score"] >= PASS_THRESHOLD for r in results)
    print(f"Overall: {'ALL PASS' if all_pass else 'SOME FAIL'}")

    # Write report
    report_path = Path("output/quality_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    json_results = [{"name": r["name"], "score": r["score"], "checks": r["checks"],
                      "deductions": r["deductions"]} for r in results]
    report_path.write_text(json.dumps(json_results, indent=2))
    print(f"\nReport saved to {report_path}")

    sys.exit(0 if all_pass else 1)

if __name__ == "__main__":
    main()
