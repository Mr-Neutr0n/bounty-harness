#!/usr/bin/env python3
"""
BB Toolkit Adapter Renderer

Renders provider-specific agent instructions from the canonical CLAUDE.md
and .claude/skills/*/SKILL.md skill catalog.

Usage:
    python3 tools/adapters/render_adapter.py preview --target claude-code
    python3 tools/adapters/render_adapter.py apply --target claude-code
    python3 tools/adapters/render_adapter.py list-targets
    python3 tools/adapters/render_adapter.py validate
    python3 tools/adapters/render_adapter.py uninstall --target claude-code
"""

import argparse
import hashlib
import os
import re
import shutil
import sys
import difflib
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    sys.exit("Error: pyyaml is required. Install with: pip install pyyaml")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
CANONICAL_MD = REPO_ROOT / "CLAUDE.md"
ADAPTERS_DIR = REPO_ROOT / "tools" / "adapters"
MANIFEST_PATH = ADAPTERS_DIR / "manifest.yaml"
TEMPLATES_DIR = ADAPTERS_DIR / "templates"
STATE_PATH = ADAPTERS_DIR / "state.yaml"

OWNER_MARKER_START = "<!-- BB-ADAPTER-GENERATED [{}] -->"
OWNER_MARKER_END = "<!-- /BB-ADAPTER-GENERATED [{}] -->"
MARKER_START_RE = re.compile(r"<!-- BB-ADAPTER-GENERATED \[(.+?)\] -->")
MARKER_END_RE = re.compile(r"<!-- /BB-ADAPTER-GENERATED \[(.+?)\] -->")

SAFE_DIRS = {".claude", "tools", "docs", "bin", ".github", ".cursor", ".codex"}
SENSITIVE_PREFIXES = {".bb/", "output/", "engagements/", "evidence/"}
FORBIDDEN_VARS = {
    "AUTH_HEADER", "AUTH_TOKEN", "API_KEY", "COOKIE_JAR", "PASSWORD",
    "SECRET", "CREDENTIAL", "TOKEN", "PRIVATE_KEY", "ACCESS_KEY",
}


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        die(f"Manifest not found: {MANIFEST_PATH}")
    try:
        with open(MANIFEST_PATH, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        die(f"Failed to parse manifest: {e}")
    return data


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            with open(STATE_PATH, "r") as f:
                return yaml.safe_load(f) or {"version": "1.0", "tracked_files": {}}
        except Exception:
            pass
    return {"version": "1.0", "tracked_files": {}}


def save_state(state: dict):
    with open(STATE_PATH, "w") as f:
        yaml.safe_dump(state, f, default_flow_style=False, sort_keys=False)


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def parse_claude_md_sections() -> Dict[str, str]:
    with open(CANONICAL_MD, "r") as f:
        content = f.read()
    lines = content.splitlines(keepends=True)

    sections: Dict[str, str] = {}
    heading_re = re.compile(r"^##\s+(.+)$")

    headings = []
    for i, line in enumerate(lines):
        m = heading_re.match(line.strip())
        if m:
            headings.append((i, m.group(1).lower().replace(" ", "_")))

    header_lines = lines[: headings[0][0]] if headings else []

    sections["header"] = "".join(header_lines).rstrip()

    for idx, (start, name) in enumerate(headings):
        if idx + 1 < len(headings):
            end = headings[idx + 1][0]
        else:
            end = len(lines)
        sections[name] = "".join(lines[start:end]).rstrip()

    return sections


def discover_skills() -> List[Dict[str, str]]:
    skills = []
    if not SKILLS_DIR.exists():
        return skills

    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue

        name = skill_dir.name
        purpose = ""
        skill_ref = name

        try:
            with open(skill_md, "r") as f:
                content = f.read()
            lines = content.splitlines()

            if lines and lines[0].startswith("# "):
                name = lines[0][2:].strip()

            in_overview = False
            for line in lines:
                if line.strip() == "## Overview":
                    in_overview = True
                    continue
                if in_overview:
                    if line.strip().startswith("#") or line.strip().startswith("---"):
                        break
                    stripped = line.strip()
                    if stripped:
                        purpose = stripped
                        break

            in_quick_ref = False
            for line in lines:
                if line.strip() == "## Quick Reference":
                    in_quick_ref = True
                    continue
                if in_quick_ref:
                    if line.strip().startswith("#"):
                        break
                    m = re.match(r"- Skill:\s*`(.+?)`", line.strip())
                    if m:
                        skill_ref = m.group(1)
                        break

        except Exception:
            pass

        skills.append({
            "name": name,
            "ref": skill_ref or skill_dir.name,
            "purpose": purpose,
        })

    return skills


def build_skill_catalog_table(skills: List[Dict[str, str]]) -> str:
    lines = [
        "| # | Skill | Purpose |",
        "|---|---|---|",
    ]
    for i, s in enumerate(skills, 1):
        lines.append(f"| {i} | `{s['ref']}` | {s['purpose']} |")
    return "\n".join(lines)


def extract_section_block(content: str, heading_name: str) -> str:
    heading_marker = f"## {heading_name}"
    index = content.find(heading_marker)
    if index == -1:
        return ""

    after = content[index + len(heading_marker):]

    next_re = re.compile(r"\n##\s")
    m = next_re.search(after)
    if m:
        after = after[: m.start()]

    return heading_marker + after


def extract_env_block(sections: Dict[str, str]) -> str:
    env_section = sections.get("environment", "")
    if "```bash" in env_section:
        start = env_section.index("```bash") + len("```bash")
        end = env_section.index("```", start)
        return "```bash\n" + env_section[start:end].strip() + "\n```"
    return env_section


def _strip_heading(content: str) -> str:
    lines = content.splitlines()
    if lines and lines[0].startswith("## "):
        return "\n".join(lines[1:]).strip()
    return content


def resolve_template_variables(sections: Dict[str, str], skills: List[Dict[str, str]]) -> Dict[str, str]:
    header = sections.get("header", "")
    catalog = build_skill_catalog_table(skills)
    dispatch_full = _strip_heading(sections.get("dispatch_rules", ""))
    safety_section = sections.get("safety_rules", "")

    safety_body = ""
    s_idx = safety_section.find("\n")
    if s_idx != -1:
        safety_body = safety_section[s_idx:].strip()

    env = extract_env_block(sections)

    return {
        "HEADER": header,
        "SKILL_CATALOG": catalog,
        "DISPATCH_RULES": dispatch_full,
        "SAFETY_RULES": safety_body,
        "ENVIRONMENT": env,
    }


def safety_check_variables(variables: Dict[str, str]):
    for key in variables:
        lower_key = key.lower()
        for forbidden in FORBIDDEN_VARS:
            if forbidden.lower() in lower_key:
                die(f"Safety violation: variable '{key}' resembles a credential/secret name. Remove from templates and variables.")
    for key, val in variables.items():
        if key.startswith("_"):
            continue
        val_lower = val.lower()
        for secret_pattern in ("auth_header=", "authorization:", "bearer ", "x-api-key:", "cookie:", "set-cookie:", "password="):
            if secret_pattern in val_lower:
                print(f"WARNING: variable '{key}' may contain inline credentials. Redacting value for safety.")
                variables[key] = "[REDACTED]"
                break


def render_template(template_path: Path, variables: Dict[str, str]) -> str:
    with open(template_path, "r") as f:
        tmpl = f.read()
    return Template(tmpl).safe_substitute(**variables)


def wrap_owned(content: str, section_id: str) -> str:
    return f"{OWNER_MARKER_START.format(section_id)}\n{content}\n{OWNER_MARKER_END.format(section_id)}"


def compute_section_hash(content: str, section_id: str) -> str:
    pattern = re.compile(
        re.escape(OWNER_MARKER_START.format(section_id)) + r"\n(.*?)\n" +
        re.escape(OWNER_MARKER_END.format(section_id)),
        re.DOTALL,
    )
    m = pattern.search(content)
    if m:
        return compute_hash(m.group(1))
    return ""


def strip_adapter_markers(content: str) -> str:
    content = MARKER_START_RE.sub("", content)
    content = MARKER_END_RE.sub("", content)
    return content


def extract_adapter_sections(content: str) -> Dict[str, str]:
    sections = {}
    for m in MARKER_START_RE.finditer(content):
        section_id = m.group(1)
        start_pos = m.start()
        end_m = re.search(
            re.escape(OWNER_MARKER_END.format(section_id)),
            content[start_pos:],
        )
        if end_m:
            end_pos = start_pos + end_m.end()
            inner = content[start_pos + len(m.group(0)) + 1: end_pos - len(OWNER_MARKER_END.format(section_id)) - 1]
            sections[section_id] = inner
    return sections


def generate_output(target_info: dict, variables: Dict[str, str]) -> Dict[str, str]:
    outputs = {}
    for file_spec in target_info["files"]:
        tmpl_path = TEMPLATES_DIR / file_spec["template"]
        if not tmpl_path.exists():
            die(f"Template not found: {tmpl_path}")

        rendered = render_template(tmpl_path, variables)

        if "sections" in file_spec:
            for sec in file_spec["sections"]:
                marker = OWNER_MARKER_START.format(sec)
                if marker not in rendered:
                    rendered = wrap_owned(rendered, sec)
        else:
            rendered = wrap_owned(rendered, "all")

        outputs[file_spec["name"]] = rendered

    return outputs


def _preview_diff(target: str, target_info: dict, outputs: Dict[str, str], state: dict):
    print(f"\n{'=' * 70}")
    print(f"  PREVIEW: {target}")
    print(f"{'=' * 70}")

    for filename, new_content in outputs.items():
        out_dir = REPO_ROOT / target_info["output_dir"]
        out_path = out_dir / filename
        display_path = target_info.get("output_dir", ".") + "/" + filename

        if out_path.exists():
            with open(out_path, "r") as f:
                old_content = f.read()
        else:
            old_content = ""

        if old_content == new_content:
            print(f"\n  {display_path}: no changes")
            continue

        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"{display_path} (current)",
            tofile=f"{display_path} (generated)",
            lineterm="",
        )
        diff_output = "\n".join(diff)
        if diff_output.strip():
            print(f"\n  {display_path}:")
            for dline in diff_output.splitlines():
                prefix = dline[:1] if dline else " "
                if prefix == "+":
                    print(f"    {dline}")
                elif prefix == "-":
                    print(f"    {dline}")
                elif prefix == "@":
                    print(f"    {dline}")
                else:
                    print(f"    {dline}")
        else:
            print(f"\n  {display_path}: no changes")

    print(f"\n{'=' * 70}")
    print("  Run with --target <target> apply to write these changes.")
    print(f"{'=' * 70}\n")


def _apply_target(target: str, target_info: dict, outputs: Dict[str, str], state: dict):
    out_dir = REPO_ROOT / target_info["output_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    tracked = state.setdefault("tracked_files", {})

    for filename, new_content in outputs.items():
        out_path = out_dir / filename

        if out_path.exists():
            backup_path = Path(str(out_path) + ".bak")
            shutil.copy2(out_path, backup_path)
            print(f"  backed up: {backup_path}")

        with open(out_path, "w") as f:
            f.write(new_content)

        generated_sections = extract_adapter_sections(new_content)

        section_entries = []
        for section_id in generated_sections:
            section_entries.append({
                "section": section_id,
                "hash": compute_hash(generated_sections[section_id]),
            })

        rel_path = str(out_path.relative_to(REPO_ROOT))
        tracked[rel_path] = {
            "owner": "bb-adapter",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "sections": section_entries,
        }

        print(f"  wrote: {rel_path}")

    save_state(state)


def cmd_preview(args):
    manifest = load_manifest()
    if args.target not in manifest["targets"]:
        die(f"Unknown target: '{args.target}'. Use list-targets to see available targets.")

    validate_manifest(manifest)
    target_info = manifest["targets"][args.target]
    sections = parse_claude_md_sections()
    skills = discover_skills()
    variables = resolve_template_variables(sections, skills)
    safety_check_variables(variables)
    outputs = generate_output(target_info, variables)
    state = load_state()
    _preview_diff(args.target, target_info, outputs, state)


def cmd_apply(args):
    manifest = load_manifest()
    if args.target not in manifest["targets"]:
        die(f"Unknown target: '{args.target}'. Use list-targets to see available targets.")

    validate_manifest(manifest)
    target_info = manifest["targets"][args.target]
    sections = parse_claude_md_sections()
    skills = discover_skills()
    variables = resolve_template_variables(sections, skills)
    safety_check_variables(variables)
    outputs = generate_output(target_info, variables)
    state = load_state()

    print(f"\nApplying adapter: {args.target}")
    _apply_target(args.target, target_info, outputs, state)
    print(f"Done. Files tracked in {STATE_PATH}\n")


def cmd_list_targets(args):  # noqa: ARG001
    manifest = load_manifest()
    print("\nAvailable adapter targets:\n")
    for name, info in manifest["targets"].items():
        files = ", ".join(f.get("name", "") for f in info.get("files", []))
        print(f"  {name:<20} -> {info.get('output_dir', '.')}  ({files})")
    print()


def validate_manifest(manifest: dict, verbose: bool = True):
    errors = []
    if "version" not in manifest:
        errors.append("Missing 'version' field")
    if "targets" not in manifest or not isinstance(manifest["targets"], dict):
        errors.append("Missing or invalid 'targets' section")
    else:
        for tname, tinfo in manifest["targets"].items():
            if not isinstance(tinfo, dict):
                errors.append(f"Target '{tname}' is not a valid object")
                continue
            if "output_dir" not in tinfo:
                errors.append(f"Target '{tname}' missing 'output_dir'")
            if "files" not in tinfo:
                errors.append(f"Target '{tname}' missing 'files'")
            else:
                for fspec in tinfo.get("files", []):
                    if "name" not in fspec:
                        errors.append(f"Target '{tname}': file entry missing 'name'")
                    if "template" not in fspec:
                        errors.append(f"Target '{tname}': file entry missing 'template'")
                    else:
                        tmpl_path = TEMPLATES_DIR / fspec["template"]
                        if not tmpl_path.exists():
                            errors.append(f"Target '{tname}': template not found: {fspec['template']}")

    if errors:
        if verbose:
            for e in errors:
                print(f"  - {e}")
        die("Manifest validation failed.", code=2)

    if verbose:
        print("Manifest is valid.")


def cmd_validate(args):  # noqa: ARG001
    manifest = load_manifest()
    validate_manifest(manifest, verbose=True)
    print(f"Skills dir: {SKILLS_DIR} (exists: {SKILLS_DIR.exists()})")
    print(f"Canonical: {CANONICAL_MD} (exists: {CANONICAL_MD.exists()})")

    skills = discover_skills()
    print(f"Discovered {len(skills)} skills:")
    for s in skills:
        print(f"  - {s['ref']}: {s['purpose']}")

    state = load_state()
    tracked = state.get("tracked_files", {})
    if tracked:
        print(f"\nTracked files: {len(tracked)}")
        for path, info in tracked.items():
            print(f"  {path} (target={info.get('target')}, generated={info.get('generated_at')})")
    else:
        print("\nNo tracked files.")


def cmd_uninstall(args):
    state = load_state()
    tracked = state.get("tracked_files", {})

    to_remove = {}
    for path, info in tracked.items():
        if args.target and info.get("target") != args.target:
            continue
        to_remove[path] = info

    if not to_remove:
        print(f"No tracked files found{' for target ' + args.target if args.target else ''}.")
        return

    print(f"\nFiles to uninstall ({len(to_remove)}):\n")
    for path, info in to_remove.items():
        full_path = REPO_ROOT / path
        backup = Path(str(full_path) + ".bak")
        print(f"  {path}")
        print(f"    target={info.get('target')}, generated={info.get('generated_at')}")
        if backup.exists():
            print(f"    backup exists: {backup}")
        print()

    if args.force or input("Proceed with uninstall? [y/N] ").strip().lower() == "y":
        for path in to_remove:
            full_path = REPO_ROOT / path
            if full_path.exists():
                backup_path = Path(str(full_path) + ".bak")
                if not backup_path.exists():
                    shutil.copy2(full_path, backup_path)
                full_path.unlink()
                print(f"  removed: {path}")

        remaining = {k: v for k, v in tracked.items() if k not in to_remove}
        state["tracked_files"] = remaining
        save_state(state)
        print("Uninstall complete.")
    else:
        print("Uninstall cancelled.")


def main():
    parser = argparse.ArgumentParser(
        description="BB Toolkit Adapter Renderer — port skill catalog to other agent platforms.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tools/adapters/render_adapter.py preview --target claude-code
  python3 tools/adapters/render_adapter.py apply --target opencode
  python3 tools/adapters/render_adapter.py list-targets
  python3 tools/adapters/render_adapter.py validate
  python3 tools/adapters/render_adapter.py uninstall --target cursor --force
        """,
    )
    sub = parser.add_subparsers(dest="command", help="Subcommand")

    p_preview = sub.add_parser("preview", help="Preview changes without writing")
    p_preview.add_argument("--target", required=True, help="Target platform name")

    p_apply = sub.add_parser("apply", help="Apply and write rendered files")
    p_apply.add_argument("--target", required=True, help="Target platform name")

    sub.add_parser("list-targets", help="Show available adapter targets")

    sub.add_parser("validate", help="Check manifest and discover skills")

    p_uninstall = sub.add_parser("uninstall", help="Remove adapter-generated files")
    p_uninstall.add_argument("--target", help="Limit uninstall to specific target")
    p_uninstall.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    args = parser.parse_args()

    if args.command == "preview":
        cmd_preview(args)
    elif args.command == "apply":
        cmd_apply(args)
    elif args.command == "list-targets":
        cmd_list_targets(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()