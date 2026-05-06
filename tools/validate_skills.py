#!/usr/bin/env python3
"""Skill Audit Framework — validates, audits, and quality-scores bug bounty skills.

Subcommands:
  (default)         Run quality check on all skills (backward compatible)
  --json            Output machine-readable JSON report
  audit-skill <sk>  Deep audit of a single skill
  audit-workflows   Validate all workflow commands and linkages
  audit-security    Check safety tiers, secrets, risky commands, credentials
  audit-release     Full release gate — runs all audits + stale doc checks
"""

import os, sys, subprocess, json, yaml, re
from datetime import datetime, timezone
from pathlib import Path

SKILLS_DIR = Path(".claude/skills")
CONTEXT_FILE = Path(".bb/context.json")
TOOLS_REGISTRY_DIR = Path("tools/registry")
SAFETY_TIERS = {"passive", "active-safe", "intrusive", "destructive-manual"}
TOOLKIT_VERSION = "3.0.0"
REQUIRED_FILES = ["SKILL.md", "skill.yaml"]
MIN_SCRIPTS = 3
MIN_RUNBOOKS = 4
MIN_PAYLOADS = 2
PLACEHOLDER_PATTERNS = ["YOUR_", "TODO", "TBD", "<script>", "placeholder"]
DESTRUCTIVE_PATTERNS = ["rm -rf", "DROP TABLE", ":(){ :|:& };:", "> /dev/sda"]
PASS_THRESHOLD = 70
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
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?:sk_live_[A-Za-z0-9]{24}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:xox[baprs]-[A-Za-z0-9-]+)|"
    r"(?:ya29\.[A-Za-z0-9_-]+)|"
    r"(?:eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*))"
)
OUTPUT_SAFE_PREFIXES = [r"\$OUTDIR", r"\$EVIDENCE_DIR", r"\.bb/"]

WEIGHTS = {
    "metadata_schema": 15,
    "workflows": 20,
    "scripts": 15,
    "safety_model": 15,
    "evidence_model": 10,
    "tool_registry": 10,
    "runbooks_payloads": 10,
    "standards_techniques": 5,
}


def _load_schema(path):
    with open(path) as f:
        return json.load(f)


def _validate_against_schema(instance, schema, path=""):
    errors = []
    if not isinstance(instance, dict):
        return [f"{path}: expected object, got {type(instance).__name__}"]
    if "required" in schema:
        for req in schema["required"]:
            if req not in instance:
                errors.append(f"{path}: missing required field '{req}'")
    if "properties" in schema:
        for prop, prop_schema in schema["properties"].items():
            if prop in instance:
                val = instance[prop]
                prop_path = f"{path}.{prop}"
                if prop_schema.get("type") == "string" and not isinstance(val, str):
                    errors.append(f"{prop_path}: expected string, got {type(val).__name__}")
                elif prop_schema.get("type") == "integer" and not isinstance(val, int):
                    errors.append(f"{prop_path}: expected integer, got {type(val).__name__}")
                elif prop_schema.get("type") == "boolean" and not isinstance(val, bool):
                    errors.append(f"{prop_path}: expected boolean, got {type(val).__name__}")
                elif prop_schema.get("type") == "array" and not isinstance(val, list):
                    errors.append(f"{prop_path}: expected array, got {type(val).__name__}")
                elif prop_schema.get("type") == "object" and not isinstance(val, dict):
                    errors.append(f"{prop_path}: expected object, got {type(val).__name__}")
                if "enum" in prop_schema and val not in prop_schema["enum"]:
                    errors.append(f"{prop_path}: '{val}' not in allowed values: {prop_schema['enum']}")
                if "pattern" in prop_schema and isinstance(val, str):
                    if not re.match(prop_schema["pattern"], val):
                        errors.append(f"{prop_path}: '{val}' does not match pattern {prop_schema['pattern']}")
                if "minLength" in prop_schema and isinstance(val, str):
                    if len(val) < prop_schema["minLength"]:
                        errors.append(f"{prop_path}: string too short ({len(val)} < {prop_schema['minLength']})")
                if "minProperties" in prop_schema and isinstance(val, dict):
                    if len(val) < prop_schema["minProperties"]:
                        errors.append(f"{prop_path}: expected at least {prop_schema['minProperties']} properties")
                if "minItems" in prop_schema and isinstance(val, list):
                    if len(val) < prop_schema["minItems"]:
                        errors.append(f"{prop_path}: expected at least {prop_schema['minItems']} items")
                if prop_schema.get("type") == "object" and "additionalProperties" in prop_schema and isinstance(val, dict):
                    ap_schema = prop_schema["additionalProperties"]
                    if isinstance(ap_schema, dict):
                        ap_type = ap_schema.get("type")
                        for k, v in val.items():
                            ap_path = f"{prop_path}.{k}"
                            if ap_type == "string" and not isinstance(v, str):
                                errors.append(f"{ap_path}: expected string, got {type(v).__name__}")
                            elif ap_type == "integer" and not isinstance(v, int):
                                errors.append(f"{ap_path}: expected integer, got {type(v).__name__}")
                            elif ap_type == "boolean" and not isinstance(v, bool):
                                errors.append(f"{ap_path}: expected boolean, got {type(v).__name__}")
                            elif ap_type == "array" and not isinstance(v, list):
                                errors.append(f"{ap_path}: expected array, got {type(v).__name__}")
                            elif ap_type == "object":
                                inner_errors = _validate_against_schema(v, ap_schema, ap_path)
                                errors.extend(inner_errors)
    if "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
        known_props = set(schema.get("properties", {}).keys())
        ap_schema = schema["additionalProperties"]
        ap_type = ap_schema.get("type")
        for k, v in instance.items():
            if k not in known_props:
                ap_path = f"{path}.{k}"
                if ap_type == "string" and not isinstance(v, str):
                    errors.append(f"{ap_path}: expected string, got {type(v).__name__}")
                elif ap_type == "integer" and not isinstance(v, int):
                    errors.append(f"{ap_path}: expected integer, got {type(v).__name__}")
                elif ap_type == "boolean" and not isinstance(v, bool):
                    errors.append(f"{ap_path}: expected boolean, got {type(v).__name__}")
                elif ap_type == "array" and not isinstance(v, list):
                    errors.append(f"{ap_path}: expected array, got {type(v).__name__}")
                elif ap_type == "object":
                    inner_errors = _validate_against_schema(v, ap_schema, ap_path)
                    errors.extend(inner_errors)
    return errors


def _load_tool_registry():
    known = set()
    if not TOOLS_REGISTRY_DIR.exists():
        return known
    for reg_file in TOOLS_REGISTRY_DIR.glob("*.yaml"):
        try:
            with open(reg_file) as f:
                data = yaml.safe_load(f)
            tools = data.get("registry", {}).get("tools", [])
            for t in tools:
                known.add(t.get("name", ""))
        except Exception:
            pass
    return known


def _load_technique_skills():
    techniques_dir = SKILLS_DIR / "technique-kb" / "techniques"
    skill_set = set()
    if not techniques_dir.exists():
        return skill_set
    for tf in techniques_dir.rglob("*.yaml"):
        try:
            with open(tf) as f:
                data = yaml.safe_load(f)
            wm = data.get("workflow_mapping", {})
            if isinstance(wm, dict) and wm.get("skill"):
                skill_set.add(wm["skill"])
            rs = data.get("related_skills", [])
            if isinstance(rs, list):
                for s in rs:
                    skill_set.add(s)
        except Exception:
            pass
    return skill_set


def _is_output_safe(output_path):
    if isinstance(output_path, dict):
        path = output_path.get("path", "")
    else:
        path = str(output_path)
    for prefix in OUTPUT_SAFE_PREFIXES:
        if re.search(prefix, path):
            return True
    return path.startswith("$OUTDIR") or path.startswith("$EVIDENCE_DIR") or path.startswith(".bb/")


def _check_has_secret_handling(command, skill_md_content):
    command_lower = command.lower() if command else ""
    md_lower = skill_md_content.lower() if skill_md_content else ""
    indicators = ["auth", "cookie", "session", "har", "bearer", "token"]
    redaction = ["redact", "sanitize", "local-only", "never committed", "gitignore", ".env"]
    for ind in indicators:
        if ind in command_lower or ind in md_lower:
            for red in redaction:
                if red in md_lower:
                    return True
            return False
    return True


def check_skill(skill_path, schemas=None, tool_registry=None, technique_skills=None):
    name = skill_path.name
    report = {
        "name": name,
        "checks": [],
        "deductions": [],
        "score": 100,
        "issues": [],
        "subscores": {
            "metadata_schema": 0,
            "workflows": 0,
            "scripts": 0,
            "safety_model": 0,
            "evidence_model": 0,
            "tool_registry": 0,
            "runbooks_payloads": 0,
            "standards_techniques": 0,
        },
    }

    if tool_registry is None:
        tool_registry = _load_tool_registry()
    if technique_skills is None:
        technique_skills = _load_technique_skills()

    meta_max = WEIGHTS["metadata_schema"]
    wf_max = WEIGHTS["workflows"]
    scripts_max = WEIGHTS["scripts"]
    safety_max = WEIGHTS["safety_model"]
    evidence_max = WEIGHTS["evidence_model"]
    toolreg_max = WEIGHTS["tool_registry"]
    rbp_max = WEIGHTS["runbooks_payloads"]
    st_max = WEIGHTS["standards_techniques"]

    meta_score = meta_max
    wf_score = wf_max
    scripts_score = scripts_max
    safety_score = safety_max
    evidence_score = evidence_max
    toolreg_score = toolreg_max
    rbp_score = rbp_max
    st_score = st_max

    def add_check(text):
        report["checks"].append(text)

    def add_issue(severity, itype, message, filepath=None, line=None):
        report["issues"].append({
            "skill": name,
            "severity": severity,
            "type": itype,
            "message": message,
            "file": filepath,
            "line": line,
        })

    def deduct(amount, subscore_key=None):
        nonlocal meta_score, wf_score, scripts_score, safety_score, evidence_score, toolreg_score, rbp_score, st_score
        score_vars = {
            "metadata_schema": lambda: (meta_score, "meta_score"),
            "workflows": lambda: (wf_score, "wf_score"),
            "scripts": lambda: (scripts_score, "scripts_score"),
            "safety_model": lambda: (safety_score, "safety_score"),
            "evidence_model": lambda: (evidence_score, "evidence_score"),
            "tool_registry": lambda: (toolreg_score, "toolreg_score"),
            "runbooks_payloads": lambda: (rbp_score, "rbp_score"),
            "standards_techniques": lambda: (st_score, "st_score"),
        }
        report["score"] = max(0, report["score"] - amount)
        if subscore_key and subscore_key in score_vars:
            pass

    def deduct_ss(subscore_key, amount):
        nonlocal meta_score, wf_score, scripts_score, safety_score, evidence_score, toolreg_score, rbp_score, st_score
        ss_map = {
            "metadata_schema": "meta_score",
            "workflows": "wf_score",
            "scripts": "scripts_score",
            "safety_model": "safety_score",
            "evidence_model": "evidence_score",
            "tool_registry": "tool_registry",
            "runbooks_payloads": "rbp_score",
            "standards_techniques": "st_score",
        }
        if subscore_key == "metadata_schema":
            meta_score = max(0, meta_score - amount)
        elif subscore_key == "workflows":
            wf_score = max(0, wf_score - amount)
        elif subscore_key == "scripts":
            scripts_score = max(0, scripts_score - amount)
        elif subscore_key == "safety_model":
            safety_score = max(0, safety_score - amount)
        elif subscore_key == "evidence_model":
            evidence_score = max(0, evidence_score - amount)
        elif subscore_key == "tool_registry":
            toolreg_score = max(0, toolreg_score - amount)
        elif subscore_key == "runbooks_payloads":
            rbp_score = max(0, rbp_score - amount)
        elif subscore_key == "standards_techniques":
            st_score = max(0, st_score - amount)
        report["score"] = max(0, report["score"] - amount)

    report["deductions"] = []

    skill_md = skill_path / "SKILL.md"
    skill_yaml = skill_path / "skill.yaml"
    skill_md_content = ""
    yaml_data = None

    # --- METADATA AND SCHEMA SECTION ---
    for req in REQUIRED_FILES:
        if (skill_path / req).exists():
            add_check(f"PASS: {req} exists")
        else:
            add_check(f"FAIL: {req} missing")
            report["deductions"].append(f"Missing {req}")
            deduct_ss("metadata_schema", 5)
            add_issue("error", "missing_file", f"Missing required file: {req}", str(skill_path / req))

    if skill_md.exists():
        skill_md_content = skill_md.read_text()
        for section in REQUIRED_SKILL_MD_SECTIONS:
            if section in skill_md_content:
                add_check(f"PASS: SKILL.md has section {section}")
            else:
                add_check(f"FAIL: SKILL.md missing section {section}")
                report["deductions"].append(f"Missing SKILL.md section {section}")
                deduct_ss("metadata_schema", 2)
                add_issue("error", "missing_section", f"SKILL.md missing section: {section}", str(skill_md))

    if skill_yaml.exists():
        try:
            with open(skill_yaml) as f:
                yaml_data = yaml.safe_load(f)
        except Exception as e:
            add_check(f"FAIL: skill.yaml parse error: {e}")
            report["deductions"].append("skill.yaml invalid")
            deduct_ss("metadata_schema", 15)
            add_issue("error", "yaml_parse_error", f"skill.yaml parse error: {e}", str(skill_yaml))

        if yaml_data:
            if schemas and "skill" in schemas:
                schema_errors = _validate_against_schema(yaml_data, schemas["skill"])
                if schema_errors:
                    for se in schema_errors[:5]:
                        add_check(f"FAIL: schema: {se}")
                        report["deductions"].append(f"Schema validation: {se}")
                        deduct_ss("metadata_schema", 3)
                        add_issue("error", "schema_validation", se, str(skill_yaml))
                else:
                    add_check("PASS: skill.yaml passes JSON schema validation")

            wf_count = len(yaml_data.get("workflows", {}))
            add_check(f"PASS: skill.yaml has {wf_count} workflows")
    else:
        yaml_data = None

    # --- TOOL REGISTRY LINKAGE ---
    if yaml_data and yaml_data.get("tools_required"):
        for tool_name in yaml_data["tools_required"]:
            if tool_name in tool_registry:
                add_check(f"PASS: tool '{tool_name}' in registry")
            else:
                add_check(f"FAIL: tool '{tool_name}' not in tool registry")
                report["deductions"].append(f"Tool '{tool_name}' missing from registry")
                deduct_ss("tool_registry", 2)
                add_issue("error", "missing_tool_registry", f"Tool '{tool_name}' not found in tools/registry/", str(skill_yaml))
    else:
        add_check("PASS: no tools_required declared (or no skill.yaml)")
        toolreg_score = min(toolreg_max, toolreg_score)

    # --- SCRIPTS SECTION ---
    scripts_dir = skill_path / "scripts"
    if scripts_dir.exists():
        py_scripts = list(scripts_dir.glob("*.py")) + list(scripts_dir.glob("*.sh"))
        if len(py_scripts) >= MIN_SCRIPTS:
            add_check(f"PASS: {len(py_scripts)} scripts (min {MIN_SCRIPTS})")
        else:
            add_check(f"FAIL: only {len(py_scripts)} scripts (need {MIN_SCRIPTS})")
            report["deductions"].append(f"Script count {len(py_scripts)} < {MIN_SCRIPTS}")
            deduct_ss("scripts", 5)
            add_issue("error", "insufficient_scripts", f"Only {len(py_scripts)} scripts, need {MIN_SCRIPTS}", str(scripts_dir))

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
                    add_check(f"FAIL: {script.name} --help failed")
                    report["deductions"].append(f"Broken --help for {script.name}")
                    deduct_ss("scripts", 2)
                    add_issue("warning", "script_help_failure", f"{script.name} --help failed", str(script))
            except Exception as e:
                add_check(f"FAIL: {script.name} --help exception: {e}")
                report["deductions"].append(f"Broken --help for {script.name}")
                deduct_ss("scripts", 2)
                add_issue("warning", "script_help_exception", f"{script.name} --help exception: {e}", str(script))
    else:
        add_check("FAIL: scripts/ directory missing")
        report["deductions"].append("Missing scripts/")
        deduct_ss("scripts", 15)
        add_issue("error", "missing_dir", "scripts/ directory missing", str(scripts_dir))

    # --- RUNBOOKS AND PAYLOADS SECTION ---
    runbooks_dir = skill_path / "runbooks"
    if runbooks_dir.exists():
        rb_count = len(list(runbooks_dir.glob("*.md")))
        if rb_count >= MIN_RUNBOOKS:
            add_check(f"PASS: {rb_count} runbooks (min {MIN_RUNBOOKS})")
        else:
            add_check(f"FAIL: only {rb_count} runbooks (need {MIN_RUNBOOKS})")
            report["deductions"].append(f"Runbook count {rb_count} < {MIN_RUNBOOKS}")
            deduct_ss("runbooks_payloads", 3)
            add_issue("warning", "insufficient_runbooks", f"Only {rb_count} runbooks, need {MIN_RUNBOOKS}", str(runbooks_dir))
    else:
        add_check("FAIL: runbooks/ directory missing")
        report["deductions"].append("Missing runbooks/")
        deduct_ss("runbooks_payloads", 5)
        add_issue("error", "missing_dir", "runbooks/ directory missing", str(runbooks_dir))

    payloads_dir = skill_path / "payloads"
    if payloads_dir.exists():
        pl_count = len(list(payloads_dir.glob("*.txt")))
        if pl_count >= MIN_PAYLOADS:
            add_check(f"PASS: {pl_count} payload files (min {MIN_PAYLOADS})")
        else:
            add_check(f"FAIL: only {pl_count} payload files (need {MIN_PAYLOADS})")
            report["deductions"].append(f"Payload count {pl_count} < {MIN_PAYLOADS}")
            deduct_ss("runbooks_payloads", 2)
            add_issue("warning", "insufficient_payloads", f"Only {pl_count} payloads, need {MIN_PAYLOADS}", str(payloads_dir))
    else:
        add_check("FAIL: payloads/ directory missing")
        report["deductions"].append("Missing payloads/")
        deduct_ss("runbooks_payloads", 5)
        add_issue("error", "missing_dir", "payloads/ directory missing", str(payloads_dir))

    # --- WORKFLOWS SECTION ---
    if yaml_data:
        missing_refs = []
        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            command = str((workflow or {}).get("command", ""))
            for ref in SCRIPT_REF_RE.findall(command):
                ref = ref.rstrip(");,")
                if ref.endswith((".py", ".sh", ".js")) and not Path(ref).exists():
                    missing_refs.append((wf_name, ref))
        if missing_refs:
            for wf_name, ref in missing_refs[:10]:
                add_check(f"FAIL: {wf_name} references missing script {ref}")
            if len(missing_refs) > 10:
                add_check(f"FAIL: {len(missing_refs) - 10} additional missing script references")
            for wf_name, ref in missing_refs:
                report["deductions"].append(f"Missing workflow script ref: {wf_name} -> {ref}")
                deduct_ss("workflows", 3)
                add_issue("error", "missing_script_ref", f"Workflow '{wf_name}' references missing script: {ref}", str(skill_yaml))
        else:
            add_check("PASS: workflow script refs exist")

        # Check "next" links
        workflow_names = set(yaml_data.get("workflows", {}).keys())
        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            nxt = workflow.get("next", {})
            if nxt:
                if nxt.get("if_findings") and nxt["if_findings"] not in workflow_names:
                    add_check(f"FAIL: {wf_name} next.if_findings='{nxt['if_findings']}' not a valid workflow")
                    report["deductions"].append(f"Broken next link: {wf_name} -> {nxt['if_findings']}")
                    deduct_ss("workflows", 2)
                    add_issue("error", "broken_next_link", f"Workflow '{wf_name}' links to unknown workflow '{nxt['if_findings']}'", str(skill_yaml))
                if nxt.get("if_no_findings") and nxt["if_no_findings"] not in workflow_names:
                    add_check(f"FAIL: {wf_name} next.if_no_findings='{nxt['if_no_findings']}' not a valid workflow")
                    report["deductions"].append(f"Broken next link: {wf_name} -> {nxt['if_no_findings']}")
                    deduct_ss("workflows", 2)
                    add_issue("error", "broken_next_link", f"Workflow '{wf_name}' links to unknown workflow '{nxt['if_no_findings']}'", str(skill_yaml))

        # Check output path contract
        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            outputs = workflow.get("outputs", [])
            for out in outputs:
                if not _is_output_safe(out):
                    add_check(f"FAIL: {wf_name} output '{out}' outside $OUTDIR/$EVIDENCE_DIR/.bb/")
                    report["deductions"].append(f"Output outside safe dir: {wf_name} -> {out}")
                    deduct_ss("workflows", 2)
                    add_issue("warning", "output_path_unsafe", f"Workflow '{wf_name}' output path '{out}' is outside safe directories", str(skill_yaml))

            ed = workflow.get("evidence_dir", "")
            if ed and not _is_output_safe(ed):
                add_check(f"FAIL: {wf_name} evidence_dir '{ed}' outside safe directories")
                report["deductions"].append(f"Evidence dir outside safe dir: {wf_name} -> {ed}")
                deduct_ss("evidence_model", 2)
                add_issue("warning", "evidence_dir_unsafe", f"Workflow '{wf_name}' evidence_dir is outside safe directories", str(skill_yaml))

    # --- SAFETY MODEL SECTION ---
    safety_tiers_found = []
    if yaml_data:
        skill_safety = yaml_data.get("safety_tier", "")
        if skill_safety and skill_safety in SAFETY_TIERS:
            add_check(f"PASS: skill-level safety_tier '{skill_safety}' declared")
            safety_tiers_found.append(skill_safety)
        elif skill_safety:
            add_check(f"FAIL: skill-level safety_tier '{skill_safety}' invalid")
            report["deductions"].append(f"Invalid skill safety_tier: {skill_safety}")
            deduct_ss("safety_model", 5)
            add_issue("error", "invalid_safety_tier", f"Invalid skill-level safety_tier: {skill_safety}", str(skill_yaml))
        else:
            add_check("FAIL: no skill-level safety_tier declared")
            report["deductions"].append("Missing skill-level safety_tier")
            deduct_ss("safety_model", 5)
            add_issue("error", "missing_safety_tier", "No skill-level safety_tier declared", str(skill_yaml))

        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            wf_safety = workflow.get("safety_tier", "")
            if wf_safety:
                if wf_safety in SAFETY_TIERS:
                    add_check(f"PASS: {wf_name} safety_tier '{wf_safety}'")
                    safety_tiers_found.append(wf_safety)
                else:
                    add_check(f"FAIL: {wf_name} safety_tier '{wf_safety}' invalid")
                    report["deductions"].append(f"Invalid workflow safety_tier: {wf_name} -> {wf_safety}")
                    deduct_ss("safety_model", 3)
                    add_issue("error", "invalid_workflow_safety_tier", f"Workflow '{wf_name}' has invalid safety_tier '{wf_safety}'", str(skill_yaml))

        if not safety_tiers_found:
            add_check("FAIL: no safety tiers declared at any level")
            report["deductions"].append("No safety tiers declared")
            deduct_ss("safety_model", 5)
            add_issue("error", "no_safety_tiers", "No safety tiers declared at skill or workflow level", str(skill_yaml))

    # --- EVIDENCE MODEL ---
    if yaml_data:
        has_evidence_templates = bool(yaml_data.get("evidence_templates", {}))
        if has_evidence_templates:
            add_check("PASS: evidence_templates declared")
        else:
            add_check("FAIL: no evidence_templates declared")
            report["deductions"].append("Missing evidence_templates")
            deduct_ss("evidence_model", 5)
            add_issue("warning", "missing_evidence_templates", "No evidence_templates declared in skill.yaml", str(skill_yaml))

        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            if not workflow.get("evidence_dir"):
                add_check(f"FAIL: {wf_name} missing evidence_dir")
                report["deductions"].append(f"Missing evidence_dir for {wf_name}")
                deduct_ss("evidence_model", 2)
                add_issue("warning", "missing_evidence_dir", f"Workflow '{wf_name}' missing evidence_dir", str(skill_yaml))

    # --- SECRET HANDLING CHECK ---
    if yaml_data:
        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            command = str(workflow.get("command", ""))
            inputs = workflow.get("inputs", [])
            input_str = " ".join(inputs) if inputs else ""
            if not _check_has_secret_handling(command + " " + input_str, skill_md_content):
                add_check(f"FAIL: {wf_name} uses auth/session but has no redaction policy")
                report["deductions"].append(f"Auth workflow missing redaction: {wf_name}")
                deduct_ss("safety_model", 3)
                add_issue("warning", "missing_redaction_policy", f"Workflow '{wf_name}' handles auth/session data but lacks redaction policy", str(skill_yaml))

    # --- STANDARDS AND TECHNIQUE LINKAGE ---
    if yaml_data:
        has_standards = bool(yaml_data.get("owasp_wstg", []) or yaml_data.get("owasp_api_top10", []))
        if has_standards:
            add_check("PASS: skill maps to OWASP standards")
        else:
            add_check("FAIL: no OWASP standard mappings")
            report["deductions"].append("Missing OWASP standard mappings")
            deduct_ss("standards_techniques", 2)
            add_issue("warning", "missing_standards", "No OWASP WSTG or API Top 10 mappings", str(skill_yaml))

        if name in technique_skills:
            add_check("PASS: skill is referenced in technique-kb")
        else:
            add_check("FAIL: skill not referenced in technique-kb")
            report["deductions"].append("Missing technique-kb reference")
            deduct_ss("standards_techniques", 3)
            add_issue("warning", "missing_technique_kb_ref", f"Skill '{name}' not referenced in technique-kb entries", str(skill_yaml))

    # --- PLACEHOLDER CHECK IN SKILL.MD ---
    if skill_md.exists():
        for pat in PLACEHOLDER_PATTERNS:
            if pat in skill_md_content:
                count = skill_md_content.count(pat)
                add_check(f"WARN: '{pat}' found {count} times in SKILL.md")
                report["deductions"].append(f"Placeholder '{pat}' ({count}x)")
                deduct_ss("metadata_schema", 1)
                add_issue("warning", "placeholder_pattern", f"'{pat}' found {count}x in SKILL.md", str(skill_md))

        missing_doc_refs = []
        for ref in SKILL_MD_SCRIPT_REF_RE.findall(skill_md_content):
            ref = ref.rstrip(");,")
            if ref.endswith((".py", ".sh", ".js")) and not (skill_path / ref).exists():
                missing_doc_refs.append(ref)
        if missing_doc_refs:
            for ref in missing_doc_refs[:10]:
                add_check(f"FAIL: SKILL.md references missing script {ref}")
            if len(missing_doc_refs) > 10:
                add_check(f"FAIL: {len(missing_doc_refs) - 10} additional missing SKILL.md script references")
            for ref in missing_doc_refs:
                report["deductions"].append(f"Missing SKILL.md script ref: {ref}")
                deduct_ss("metadata_schema", 1)
        else:
            add_check("PASS: SKILL.md script refs exist")

    # --- SECRET PLACEHOLDER CHECK ---
    if skill_md_content:
        matches = SECRET_PLACEHOLDER_RE.findall(skill_md_content)
        if matches:
            add_check(f"FAIL: {len(matches)} potential secret patterns found in SKILL.md")
            for match in matches[:5]:
                masked = match[:4] + "..." + match[-4:] if len(match) > 10 else "***"
                report["deductions"].append(f"Secret pattern in SKILL.md: {masked}")
                deduct_ss("safety_model", 2)
                add_issue("error", "secret_in_docs", f"Potential secret pattern found in SKILL.md: {masked}", str(skill_md))
        else:
            add_check("PASS: no secret patterns detected in SKILL.md")

    # --- DANGEROUS COMMAND CHECK ---
    if yaml_data:
        for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
            command = str(workflow.get("command", ""))
            for pat in DESTRUCTIVE_PATTERNS:
                if pat in command:
                    add_check(f"FAIL: {wf_name} contains destructive pattern '{pat}'")
                    report["deductions"].append(f"Destructive command in {wf_name}: {pat}")
                    deduct_ss("safety_model", 5)
                    add_issue("error", "destructive_command", f"Workflow '{wf_name}' contains destructive pattern: {pat}", str(skill_yaml))

    # --- RUNBOOK LINKAGE PER WORKFLOW ---
    if runbooks_dir.exists() and yaml_data:
        runbook_names = {f.stem for f in runbooks_dir.glob("*.md")}
        for wf_name in yaml_data.get("workflows", {}):
            if wf_name in runbook_names:
                add_check(f"PASS: {wf_name} has matching runbook")
            else:
                add_check(f"FAIL: {wf_name} has no matching runbook '{wf_name}.md'")
                report["deductions"].append(f"Missing runbook for workflow: {wf_name}")
                deduct_ss("runbooks_payloads", 1)
                add_issue("warning", "missing_workflow_runbook", f"Workflow '{wf_name}' has no matching runbook", str(runbooks_dir))
        add_check("PASS: all workflow runbook links verified")

    # --- FINALIZE SUBSORES ---
    report["subscores"] = {
        "metadata_schema": meta_score,
        "workflows": wf_score,
        "scripts": scripts_score,
        "safety_model": safety_score,
        "evidence_model": evidence_score,
        "tool_registry": toolreg_score,
        "runbooks_payloads": rbp_score,
        "standards_techniques": st_score,
    }

    total_sub = sum(report["subscores"].values())
    if total_sub > 0:
        report["score"] = total_sub

    return report


def _get_all_skills():
    return sorted(
        [d for d in SKILLS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")],
        key=lambda x: x.name,
    )


def _build_json_report(results, all_issues):
    avg = sum(r["score"] for r in results) // len(results) if results else 0
    all_pass = all(r["score"] >= PASS_THRESHOLD for r in results)
    error_count = sum(1 for i in all_issues if i["severity"] == "error")
    warning_count = sum(1 for i in all_issues if i["severity"] == "warning")
    if error_count > 0:
        exit_code = 1
    elif warning_count > 50:
        exit_code = 2
    else:
        exit_code = 0

    return {
        "toolkit_version": TOOLKIT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "skills": [
            {
                "name": r["name"],
                "score": r["score"],
                "checks": r["checks"],
                "deductions": r["deductions"],
                "subscores": r.get("subscores", {}),
            }
            for r in results
        ],
        "overall": {
            "average_score": avg,
            "threshold": PASS_THRESHOLD,
            "all_pass": all_pass,
            "exit_code": exit_code,
        },
        "issues": all_issues,
    }


def cmd_default(json_output=False, schemas=None):
    results = []
    all_issues = []
    tool_registry = _load_tool_registry()
    technique_skills = _load_technique_skills()
    for skill_dir in _get_all_skills():
        r = check_skill(skill_dir, schemas=schemas, tool_registry=tool_registry, technique_skills=technique_skills)
        results.append(r)
        all_issues.extend(r.get("issues", []))

    results.sort(key=lambda x: x["score"])

    if json_output:
        report = _build_json_report(results, all_issues)
        print(json.dumps(report, indent=2))
        return report["overall"]["exit_code"]

    print("\n=== Skill Quality Report ===")
    print(f"Toolkit Version: {TOOLKIT_VERSION}")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
    total = 0
    for r in results:
        status = "PASS" if r["score"] >= PASS_THRESHOLD else "FAIL"
        icon = "✓" if r["score"] >= PASS_THRESHOLD else "✗"
        print(f"{icon} {r['name']:30s} {r['score']:3d}/100 [{status}]")
        if r["subscores"]:
            ss = r["subscores"]
            print(f"   subscores: meta={ss['metadata_schema']} wf={ss['workflows']} "
                  f"scr={ss['scripts']} safety={ss['safety_model']} ev={ss['evidence_model']} "
                  f"tools={ss['tool_registry']} rb/pld={ss['runbooks_payloads']} std={ss['standards_techniques']}")
        if r["deductions"]:
            for d in r["deductions"]:
                print(f"   ↳ {d}")
        total += r["score"]

    avg = total // len(results) if results else 0
    print(f"\n{'─' * 50}")
    print(f"Average: {avg}/100")
    print(f"Threshold: {PASS_THRESHOLD}/100")

    all_pass = all(r["score"] >= PASS_THRESHOLD for r in results)
    print(f"Overall: {'ALL PASS' if all_pass else 'SOME FAIL'}")

    report_path = Path("output/quality_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    json_results = [
        {"name": r["name"], "score": r["score"], "checks": r["checks"], "deductions": r["deductions"]}
        for r in results
    ]
    report_path.write_text(json.dumps(json_results, indent=2))
    print(f"\nReport saved to {report_path}")

    return 0


def cmd_audit_skill(skill_name, json_output=False, schemas=None):
    skill_dir = SKILLS_DIR / skill_name
    if not skill_dir.exists() or not skill_dir.is_dir():
        print(f"ERROR: Skill '{skill_name}' not found at {skill_dir}", file=sys.stderr)
        return 1

    tool_registry = _load_tool_registry()
    technique_skills = _load_technique_skills()
    r = check_skill(skill_dir, schemas=schemas, tool_registry=tool_registry, technique_skills=technique_skills)

    if json_output:
        report = _build_json_report([r], r.get("issues", []))
        print(json.dumps(report, indent=2))
        return report["overall"]["exit_code"]

    print(f"\n=== Deep Audit: {skill_name} ===\n")
    print(f"Score: {r['score']}/100")
    print(f"\nSubscores:")
    for k, v in r.get("subscores", {}).items():
        bar = "█" * (v // 2)
        print(f"  {k:25s} [{bar:10s}] {v}")
    print(f"\nChecks ({len(r['checks'])}):")
    for c in r["checks"]:
        print(f"  {c}")
    if r["deductions"]:
        print(f"\nDeductions ({len(r['deductions'])}):")
        for d in r["deductions"]:
            print(f"  ↳ {d}")
    if r.get("issues"):
        print(f"\nIssues ({len(r['issues'])}):")
        for iss in r["issues"]:
            print(f"  [{iss['severity'].upper()}] {iss['type']}: {iss['message']}")

    report_wrapper = _build_json_report([r], r.get("issues", []))
    exit_code = report_wrapper["overall"]["exit_code"]
    return exit_code if not json_output else (print(json.dumps(report_wrapper, indent=2)) or exit_code)


def cmd_audit_workflows(json_output=False, schemas=None):
    results = []
    all_issues = []
    broken_links = []
    missing_scripts = []
    unsafe_outputs = []
    tool_registry = _load_tool_registry()
    technique_skills = _load_technique_skills()

    for skill_dir in _get_all_skills():
        r = check_skill(skill_dir, schemas=schemas, tool_registry=tool_registry, technique_skills=technique_skills)
        results.append(r)
        all_issues.extend(r.get("issues", []))

        skill_yaml = skill_dir / "skill.yaml"
        if not skill_yaml.exists():
            continue
        try:
            with open(skill_yaml) as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        workflow_names = set(data.get("workflows", {}).keys())
        for wf_name, workflow in (data.get("workflows", {}) or {}).items():
            command = str(workflow.get("command", ""))
            # Check script references
            for ref in SCRIPT_REF_RE.findall(command):
                ref = ref.rstrip(");,")
                if ref.endswith((".py", ".sh", ".js")) and not Path(ref).exists():
                    missing_scripts.append(f"{skill_dir.name}/{wf_name} -> {ref}")
            # Check next links
            nxt = workflow.get("next", {})
            if nxt:
                if nxt.get("if_findings") and nxt["if_findings"] not in workflow_names:
                    broken_links.append(f"{skill_dir.name}/{wf_name} -> {nxt['if_findings']}")
                if nxt.get("if_no_findings") and nxt["if_no_findings"] not in workflow_names:
                    broken_links.append(f"{skill_dir.name}/{wf_name} -> {nxt['if_no_findings']}")
            # Check output paths
            for out in workflow.get("outputs", []):
                if not _is_output_safe(out):
                    unsafe_outputs.append(f"{skill_dir.name}/{wf_name} -> {out}")

    if json_output:
        report = _build_json_report(results, all_issues)
        report["workflow_audit"] = {
            "broken_links": broken_links,
            "missing_scripts": missing_scripts,
            "unsafe_outputs": unsafe_outputs,
        }
        print(json.dumps(report, indent=2))
        return report["overall"]["exit_code"]

    print("\n=== Workflow Cross-Skill Audit ===\n")
    print(f"Skills audited: {len(results)}")
    print(f"Broken 'next' links: {len(broken_links)}")
    print(f"Missing script references: {len(missing_scripts)}")
    print(f"Unsafe output paths: {len(unsafe_outputs)}")
    print()

    if broken_links:
        print("Broken 'next' links:")
        for bl in broken_links:
            print(f"  ↳ {bl}")
    if missing_scripts:
        print("\nMissing script references:")
        for ms in missing_scripts[:20]:
            print(f"  ↳ {ms}")
        if len(missing_scripts) > 20:
            print(f"  ... and {len(missing_scripts) - 20} more")
    if unsafe_outputs:
        print("\nUnsafe output paths:")
        for uo in unsafe_outputs[:20]:
            print(f"  ↳ {uo}")
        if len(unsafe_outputs) > 20:
            print(f"  ... and {len(unsafe_outputs) - 20} more")

    if not broken_links and not missing_scripts and not unsafe_outputs:
        print("No issues found in workflow linkages.")

    has_errors = bool(broken_links or missing_scripts)
    warning_count = sum(1 for i in all_issues if i["severity"] == "warning")
    if has_errors:
        return 1
    elif warning_count > 5:
        return 2
    return 0


def cmd_audit_security(json_output=False, schemas=None):
    tool_registry = _load_tool_registry()
    technique_skills = _load_technique_skills()
    findings = []
    all_issues = []

    for skill_dir in _get_all_skills():
        skill_yaml = skill_dir / "skill.yaml"
        skill_md = skill_dir / "SKILL.md"
        skill_md_content = ""
        if skill_md.exists():
            skill_md_content = skill_md.read_text()

        yaml_data = None
        if skill_yaml.exists():
            try:
                with open(skill_yaml) as f:
                    yaml_data = yaml.safe_load(f)
            except Exception:
                pass

        name = skill_dir.name

        # Check secret patterns in docs
        if skill_md_content:
            for match in SECRET_PLACEHOLDER_RE.findall(skill_md_content):
                masked = match[:4] + "..." + match[-4:] if len(match) > 10 else "***"
                findings.append({
                    "skill": name,
                    "type": "secret_in_docs",
                    "severity": "error",
                    "detail": f"Secret pattern found: {masked}",
                })
                all_issues.append({
                    "skill": name,
                    "severity": "error",
                    "type": "secret_in_docs",
                    "message": f"Secret pattern in SKILL.md: {masked}",
                    "file": str(skill_md),
                    "line": None,
                })

        # Check destructive commands
        if yaml_data:
            for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
                command = str(workflow.get("command", ""))
                for pat in DESTRUCTIVE_PATTERNS:
                    if pat in command:
                        findings.append({
                            "skill": name,
                            "type": "destructive_command",
                            "severity": "error",
                            "detail": f"Workflow '{wf_name}' contains '{pat}'",
                        })
                        all_issues.append({
                            "skill": name,
                            "severity": "error",
                            "type": "destructive_command",
                            "message": f"Workflow '{wf_name}' contains destructive pattern: {pat}",
                            "file": str(skill_yaml),
                            "line": None,
                        })

            # Check safety tiers
            skill_safety = yaml_data.get("safety_tier", "")
            if skill_safety and skill_safety not in SAFETY_TIERS:
                findings.append({
                    "skill": name,
                    "type": "invalid_safety_tier",
                    "severity": "error",
                    "detail": f"Invalid skill safety_tier: {skill_safety}",
                })
            for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
                wf_safety = workflow.get("safety_tier", "")
                if wf_safety and wf_safety not in SAFETY_TIERS:
                    findings.append({
                        "skill": name,
                        "type": "invalid_workflow_safety_tier",
                        "severity": "error",
                        "detail": f"Workflow '{wf_name}' invalid tier: {wf_safety}",
                    })

            # Check secret handling
            for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
                command = str(workflow.get("command", ""))
                inputs = workflow.get("inputs", [])
                input_str = " ".join(inputs) if inputs else ""
                if not _check_has_secret_handling(command + " " + input_str, skill_md_content):
                    findings.append({
                        "skill": name,
                        "type": "missing_redaction",
                        "severity": "warning",
                        "detail": f"Workflow '{wf_name}' handles auth but lacks redaction policy",
                    })

        # Check payload files for secrets
        payloads_dir = skill_dir / "payloads"
        if payloads_dir.exists():
            for pf in payloads_dir.glob("*.txt"):
                try:
                    content = pf.read_text()
                    for match in SECRET_PLACEHOLDER_RE.findall(content):
                        masked = match[:4] + "..." + match[-4:] if len(match) > 10 else "***"
                        findings.append({
                            "skill": name,
                            "type": "secret_in_payload",
                            "severity": "error",
                            "detail": f"Secret pattern in {pf.name}: {masked}",
                        })
                except Exception:
                    pass

    results_for_report = []
    for skill_dir in _get_all_skills():
        r = check_skill(skill_dir, schemas=schemas, tool_registry=tool_registry, technique_skills=technique_skills)
        results_for_report.append(r)

    if json_output:
        report = _build_json_report(results_for_report, all_issues)
        report["security_audit"] = findings
        print(json.dumps(report, indent=2))
        return report["overall"]["exit_code"]

    print("\n=== Security Audit ===\n")
    print(f"Skills checked: {len(results_for_report)}")
    print(f"Issues found: {len(findings)}")

    severities = {"error": 0, "warning": 0}
    for f in findings:
        severities[f["severity"]] += 1
    print(f"  Errors: {severities['error']}")
    print(f"  Warnings: {severities['warning']}")
    print()

    if findings:
        for f in findings:
            label = "✗" if f["severity"] == "error" else "⚠"
            print(f"  {label} [{f['severity'].upper()}] {f['skill']}: {f['type']} — {f['detail']}")
    else:
        print("  No security issues found.")

    warning_count = sum(1 for f in findings if f["severity"] == "warning")
    total_severity = sum(1 for f in findings if f["severity"] == "error")
    if total_severity > 0:
        return 1
    elif warning_count > 5:
        return 2
    return 0


def cmd_audit_release(json_output=False, schemas=None):
    print("=== Release Gate Audit ===\n", file=sys.stderr)

    tool_registry = _load_tool_registry()
    technique_skills = _load_technique_skills()
    exit_code = 0

    # 1. Run all skills through quality check
    results = []
    all_issues = []
    for skill_dir in _get_all_skills():
        r = check_skill(skill_dir, schemas=schemas, tool_registry=tool_registry, technique_skills=technique_skills)
        results.append(r)
        all_issues.extend(r.get("issues", []))

    print("[1/5] Quality check complete", file=sys.stderr)

    # 2. Workflow audit
    broken_links = 0
    missing_scripts_count = 0
    for skill_dir in _get_all_skills():
        skill_yaml = skill_dir / "skill.yaml"
        if not skill_yaml.exists():
            continue
        try:
            with open(skill_yaml) as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        workflow_names = set(data.get("workflows", {}).keys())
        for wf_name, workflow in (data.get("workflows", {}) or {}).items():
            command = str(workflow.get("command", ""))
            for ref in SCRIPT_REF_RE.findall(command):
                ref = ref.rstrip(");,")
                if ref.endswith((".py", ".sh", ".js")) and not Path(ref).exists():
                    missing_scripts_count += 1
            nxt = workflow.get("next", {})
            if nxt:
                if nxt.get("if_findings") and nxt["if_findings"] not in workflow_names:
                    broken_links += 1
                if nxt.get("if_no_findings") and nxt["if_no_findings"] not in workflow_names:
                    broken_links += 1

    print("[2/5] Workflow audit complete", file=sys.stderr)

    # 3. Security audit
    security_errors = 0
    for skill_dir in _get_all_skills():
        skill_md = skill_dir / "SKILL.md"
        skill_yaml = skill_dir / "skill.yaml"
        skill_md_content = ""
        if skill_md.exists():
            skill_md_content = skill_md.read_text()

        if skill_md_content and SECRET_PLACEHOLDER_RE.search(skill_md_content):
            security_errors += 1

        yaml_data = None
        if skill_yaml.exists():
            try:
                with open(skill_yaml) as f:
                    yaml_data = yaml.safe_load(f)
            except Exception:
                pass

        if yaml_data:
            for wf_name, workflow in (yaml_data.get("workflows", {}) or {}).items():
                command = str(workflow.get("command", ""))
                for pat in DESTRUCTIVE_PATTERNS:
                    if pat in command:
                        security_errors += 1

    print("[3/5] Security audit complete", file=sys.stderr)

    # 4. Schema validation
    schema_errors = 0
    for skill_dir in _get_all_skills():
        skill_yaml = skill_dir / "skill.yaml"
        if not skill_yaml.exists():
            continue
        try:
            with open(skill_yaml) as f:
                yaml_data = yaml.safe_load(f)
            if schemas and "skill" in schemas:
                schema_errors += len(_validate_against_schema(yaml_data, schemas["skill"]))
        except Exception:
            schema_errors += 1

    print("[4/5] Schema validation complete", file=sys.stderr)

    # 5. Stale docs check
    actual_skill_count = len(_get_all_skills())
    stale_doc_issues = []

    claude_md = Path(".claude/CLAUDE.md")
    if claude_md.exists():
        claude_content = claude_md.read_text()
        catalog_match = re.search(r'## Skill Catalog\n\n((?:\|.*\n)+)', claude_content)
        if catalog_match:
            claude_skills = re.findall(r"^\|\s*\d+\s*\|", catalog_match.group(1), re.MULTILINE)
        else:
            claude_skills = re.findall(r"^\|\s*\d+\s*\|", claude_content, re.MULTILINE)
        claude_count = len(claude_skills)
        if claude_count != actual_skill_count:
            stale_doc_issues.append(
                f"CLAUDE.md lists {claude_count} skills but {actual_skill_count} exist"
            )

    readme = Path("README.md")
    if readme.exists():
        readme_content = readme.read_text()
        catalog_match = re.search(r'## Skill Catalog\n\n((?:\|.*\n)+)', readme_content)
        if catalog_match:
            readme_skills = re.findall(r"^\|\s*\d+\s*\|", catalog_match.group(1), re.MULTILINE)
        else:
            readme_skills = re.findall(r"^\|\s*\d+\s*\|", readme_content, re.MULTILINE)
        readme_count = len(readme_skills)
        if readme_count != actual_skill_count:
            stale_doc_issues.append(
                f"README.md lists {readme_count} skills but {actual_skill_count} exist"
            )

    print("[5/5] Stale docs check complete", file=sys.stderr)

    # Compute exit code — hard errors only for release gate
    all_pass = all(r["score"] >= PASS_THRESHOLD for r in results)
    has_errors = broken_links > 0 or missing_scripts_count > 0 or security_errors > 0 or schema_errors > 0 or len(stale_doc_issues) > 0

    exit_code = 1 if has_errors else 0

    if json_output:
        report = _build_json_report(results, all_issues)
        report["release_audit"] = {
            "quality_pass": all_pass,
            "broken_next_links": broken_links,
            "missing_script_refs": missing_scripts_count,
            "security_errors": security_errors,
            "schema_errors": schema_errors,
            "actual_skill_count": actual_skill_count,
            "stale_doc_issues": stale_doc_issues,
            "exit_code": exit_code,
        }
        print(json.dumps(report, indent=2))
        return exit_code

    print("\n=== Release Gate Summary ===")
    print(f"Skills: {actual_skill_count}")
    print(f"Quality: {'ALL PASS' if all_pass else 'SOME FAIL'}")
    print(f"Broken next links: {broken_links}")
    print(f"Missing script refs: {missing_scripts_count}")
    print(f"Security errors: {security_errors}")
    print(f"Schema errors: {schema_errors}")

    avg = sum(r["score"] for r in results) // len(results) if results else 0
    print(f"Average score: {avg}/100")
    print(f"Exit code: {exit_code}")

    if stale_doc_issues:
        print(f"\nStale docs ({len(stale_doc_issues)}):")
        for si in stale_doc_issues:
            print(f"  ↳ {si}")

    if exit_code == 0:
        print("\n✓ RELEASE GATE: PASSED")
    elif exit_code == 2:
        print("\n⚠ RELEASE GATE: WARNINGS EXCEEDED")
    else:
        print("\n✗ RELEASE GATE: FAILED")

    return exit_code


def main():
    args = sys.argv[1:]
    json_output = False
    schemas = {}

    # Load schemas if available
    schema_dir = Path("tools/schemas")
    skill_schema_path = schema_dir / "skill.schema.json"
    technique_schema_path = schema_dir / "technique.schema.json"
    if skill_schema_path.exists():
        try:
            schemas["skill"] = _load_schema(skill_schema_path)
        except Exception:
            pass
    if technique_schema_path.exists():
        try:
            schemas["technique"] = _load_schema(technique_schema_path)
        except Exception:
            pass

    # Parse --json flag from anywhere in args
    filtered_args = []
    for a in args:
        if a == "--json":
            json_output = True
        else:
            filtered_args.append(a)

    if not filtered_args:
        exit_code = cmd_default(json_output=json_output, schemas=schemas)
        sys.exit(exit_code)

    subcommand = filtered_args[0]
    sub_args = filtered_args[1:]

    if subcommand == "audit-skill":
        if not sub_args:
            print("ERROR: audit-skill requires a skill name", file=sys.stderr)
            sys.exit(1)
        exit_code = cmd_audit_skill(sub_args[0], json_output=json_output, schemas=schemas)
        sys.exit(exit_code)
    elif subcommand == "audit-workflows":
        exit_code = cmd_audit_workflows(json_output=json_output, schemas=schemas)
        sys.exit(exit_code)
    elif subcommand == "audit-security":
        exit_code = cmd_audit_security(json_output=json_output, schemas=schemas)
        sys.exit(exit_code)
    elif subcommand == "audit-release":
        exit_code = cmd_audit_release(json_output=json_output, schemas=schemas)
        sys.exit(exit_code)
    else:
        print(f"ERROR: Unknown subcommand '{subcommand}'", file=sys.stderr)
        print("Available: audit-skill, audit-workflows, audit-security, audit-release", file=sys.stderr)
        print("Flags: --json (for JSON output)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()