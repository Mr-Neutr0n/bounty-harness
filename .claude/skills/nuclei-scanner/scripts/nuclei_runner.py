#!/usr/bin/env python3
"""Nuclei Runner — executes nuclei templates with severity profiles, tag filtering, and rate limiting."""

import argparse
import json
import os
import subprocess
import sys
import shutil
import tempfile
import hashlib
from datetime import datetime, timezone


SEVERITY_PROFILES = {
    "quick": {"severity": "critical,high", "label": "Quick (critical,high)"},
    "standard": {"severity": "medium,high,critical", "label": "Standard (medium+)"},
    "full": {"severity": None, "label": "Full (all severities)"},
}


def build_parser():
    p = argparse.ArgumentParser(description="Execute nuclei templates with configurable profiles")
    p.add_argument("--targets-file", required=True, help="File with target URLs/hosts (one per line)")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for findings.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--profile", default="quick", choices=["quick", "standard", "full"], help="Severity profile")
    p.add_argument("--severity", default=None, help="Override severity filter (e.g. critical,high)")
    p.add_argument("--tags", default=None, help="Nuclei tag filter (e.g. xss,cve,tech)")
    p.add_argument("--exclude-tags", default=None, help="Nuclei tags to exclude")
    p.add_argument("--templates", default=None, nargs="*", help="Specific template paths or template directory")
    p.add_argument("--rate-limit", type=int, default=150, help="Requests per second")
    p.add_argument("--concurrency", type=int, default=25, help="Template concurrency")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    p.add_argument("--interactsh", action="store_true", help="Enable Interactsh for OOB detection")
    p.add_argument("--interactsh-url", default=None, help="Custom Interactsh server URL")
    p.add_argument("--deduplicate", action="store_true", default=True, help="Deduplicate results by URL+template")
    p.add_argument("--no-deduplicate", action="store_false", dest="deduplicate")
    p.add_argument("--nuclei-path", default="nuclei", help="Path to nuclei binary")
    p.add_argument("--stats-interval", type=int, default=0, help="Stats reporting interval in seconds (0=disable)")
    p.add_argument("--resume", default=None, help="Path to resume file (.cfr)")
    return p


def find_nuclei(nuclei_path):
    resolved = shutil.which(nuclei_path)
    if resolved:
        return resolved
    if nuclei_path == "nuclei":
        for candidate in ["/opt/homebrew/bin/nuclei", "/usr/local/bin/nuclei", os.path.expanduser("~/go/bin/nuclei")]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def get_nuclei_version(nuclei_bin):
    try:
        result = subprocess.run([nuclei_bin, "-version"], capture_output=True, text=True, timeout=10)
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return "unknown"


def build_nuclei_command(nuclei_bin, args):
    cmd = [nuclei_bin, "-l", args.targets_file, "-jsonl", "-silent", "-no-mhe"]

    severity = args.severity
    if not severity and args.profile in SEVERITY_PROFILES:
        severity = SEVERITY_PROFILES[args.profile]["severity"]
    if severity:
        cmd.extend(["-s", severity])

    if args.tags:
        cmd.extend(["-tags", args.tags])
    if args.exclude_tags:
        cmd.extend(["-etags", args.exclude_tags])

    cmd.extend(["-rl", str(args.rate_limit)])
    cmd.extend(["-c", str(args.concurrency)])
    cmd.extend(["-timeout", str(args.timeout)])

    if args.interactsh:
        cmd.append("-interactsh")
    if args.interactsh_url:
        cmd.extend(["-iserver", args.interactsh_url])

    if args.stats_interval > 0:
        cmd.extend(["-stats", "-stats-interval", str(args.stats_interval)])

    if args.resume:
        cmd.extend(["-resume", args.resume])

    if args.templates:
        for t in args.templates:
            cmd.extend(["-t", t])

    return cmd


def run_nuclei(cmd, timeout_sec=None):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env={**os.environ, "NO_COLOR": "1"},
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "nuclei timed out", -1
    except FileNotFoundError:
        return "", "nuclei binary not found", -2


def parse_nuclei_jsonl(stdout):
    results = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(obj)
        except json.JSONDecodeError:
            continue
    return results


def deduplicate_results(results):
    seen = set()
    deduped = []
    for r in results:
        key = (r.get("host", ""), r.get("matched-at", ""), r.get("template-id", ""), r.get("matcher-name", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


def compute_risk_from_severity(severity):
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "unknown"}
    return mapping.get(str(severity).lower(), "unknown")


def enrich_results(raw_results, context_label, profile_label):
    enriched = []
    for r in raw_results:
        timestamp = r.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        severity = r.get("info", {}).get("severity", "unknown") if isinstance(r.get("info"), dict) else r.get("severity", "unknown")
        entry = {
            "tool": "nuclei_runner",
            "context": context_label,
            "profile": profile_label,
            "template_id": r.get("template-id", r.get("templateID", "")),
            "template_name": r.get("info", {}).get("name", "") if isinstance(r.get("info"), dict) else r.get("name", ""),
            "host": r.get("host", ""),
            "matched_at": r.get("matched-at", r.get("matched", "")),
            "severity": severity,
            "risk_level": compute_risk_from_severity(severity),
            "type": r.get("type", ""),
            "tags": r.get("info", {}).get("tags", []) if isinstance(r.get("info"), dict) else r.get("tags", []),
            "description": r.get("info", {}).get("description", "") if isinstance(r.get("info"), dict) else r.get("description", ""),
            "curl_command": r.get("curl-command", r.get("curl_command", "")),
            "extracted_results": r.get("extracted-results", r.get("extracted_results", [])),
            "ip": r.get("ip", ""),
            "timestamp": timestamp,
            "request": r.get("request", ""),
            "response": r.get("response", ""),
            "raw": r,
        }
        enriched.append(entry)
    return enriched


def main():
    parser = build_parser()
    args = parser.parse_args()

    profile_label = SEVERITY_PROFILES[args.profile]["label"]

    if not os.path.isfile(args.targets_file):
        print(f"Error: targets-file not found: {args.targets_file}", file=sys.stderr)
        sys.exit(1)

    nuclei_bin = find_nuclei(args.nuclei_path)

    if args.dry_run:
        cmd = build_nuclei_command(args.nuclei_path, args)
        finding = {
            "tool": "nuclei_runner",
            "context": args.context,
            "profile": profile_label,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dry_run": True,
            "nuclei_binary": nuclei_bin if nuclei_bin else "NOT FOUND",
            "command": " ".join(cmd),
            "targets_file": args.targets_file,
            "target_count": sum(1 for _ in open(args.targets_file)),
            "risk_notes": f"DRY RUN — would execute nuclei with profile '{args.profile}'",
        }
        line = json.dumps(finding, default=str)
        if args.output:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "a") as f:
                f.write(line + "\n")
        else:
            print(line)
        return

    if not nuclei_bin:
        finding = {
            "tool": "nuclei_runner",
            "context": args.context,
            "profile": profile_label,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "risk_level": "unknown",
            "risk_notes": "nuclei binary not found — install via: brew install nuclei",
            "errors": ["nuclei not installed or not on PATH"],
            "results": [],
        }
        line = json.dumps(finding, default=str)
        if args.output:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "a") as f:
                f.write(line + "\n")
        else:
            print(line)
        print("ERROR: nuclei binary not found", file=sys.stderr)
        sys.exit(1)

    version = get_nuclei_version(nuclei_bin)
    print(f"Using nuclei: {nuclei_bin} ({version})", file=sys.stderr)
    print(f"Profile: {profile_label} | Targets: {args.targets_file}", file=sys.stderr)

    cmd = build_nuclei_command(nuclei_bin, args)
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)

    stdout, stderr, rc = run_nuclei(cmd)
    if rc == -2:
        print("ERROR: nuclei binary not found", file=sys.stderr)
        sys.exit(1)

    if stderr:
        for line in stderr.strip().split("\n"):
            if line.strip():
                print(f"[nuclei] {line}", file=sys.stderr)

    raw_results = parse_nuclei_jsonl(stdout)
    print(f"Raw findings: {len(raw_results)}", file=sys.stderr)

    if args.deduplicate and raw_results:
        before = len(raw_results)
        raw_results = deduplicate_results(raw_results)
        print(f"After dedup: {len(raw_results)} (removed {before - len(raw_results)} duplicates)", file=sys.stderr)

    results = enrich_results(raw_results, args.context, profile_label)

    out_fh = sys.stdout
    close_out = False
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        out_fh = open(args.output, "a")
        close_out = True

    try:
        for r in results:
            out_fh.write(json.dumps(r, default=str) + "\n")
        out_fh.flush()
    finally:
        if close_out:
            out_fh.close()

    severity_counts = {}
    for r in results:
        sev = r.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"Done. Results by severity: {severity_counts}", file=sys.stderr)
    if rc != 0 and rc != -1:
        print(f"WARNING: nuclei exited with code {rc}", file=sys.stderr)


if __name__ == "__main__":
    main()