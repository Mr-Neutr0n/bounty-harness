#!/usr/bin/env python3
"""
batch_importer.py — Orchestrates the full import pipeline.

Pipeline stages:
  1. SCAN    — source_scanner.py: check sources for new content
  2. EXTRACT — knowledge_extractor.py: extract candidates from changed sources
  3. DEDUP   — deduplicator.py: remove duplicates against existing KB
  4. REVIEW  — candidate_reviewer.py: score and filter candidates

Each stage calls the corresponding script with the right arguments.
If a stage produces no output, the pipeline stops early with a message.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

SCANNER = os.path.join(SCRIPTS_DIR, "source_scanner.py")
EXTRACTOR = os.path.join(SCRIPTS_DIR, "knowledge_extractor.py")
DEDUP = os.path.join(SCRIPTS_DIR, "deduplicator.py")
REVIEWER = os.path.join(SCRIPTS_DIR, "candidate_reviewer.py")


def run_stage(name, args_list, description):
    print(f"\n{'=' * 60}")
    print(f"STAGE: {name}")
    print(f"{'=' * 60}")
    print(f"  {description}")
    print(f"  Command: python3 {' '.join(args_list)}")

    result = subprocess.run(
        ["python3"] + args_list,
        capture_output=True,
        text=True,
        timeout=300
    )

    print(result.stdout)

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        print(f"STAGE FAILED: {name} (exit code {result.returncode})", file=sys.stderr)
        return False, None

    return True, result.stdout


def scan_stage(sources_path, cache_dir, output):
    print("Stage 1: SCAN — checking sources for new content")
    scan_output = os.path.join(cache_dir, "scan_result.json")

    ok, _ = run_stage(
        "SCAN",
        [
            SCANNER,
            "--sources", sources_path,
            "--cache-dir", cache_dir,
            "--output", scan_output
        ],
        "Checking all sources for changes since last scan"
    )

    if not ok:
        return False, None

    with open(scan_output, "r") as f:
        scan_data = json.load(f)

    changed = scan_data.get("changed", [])
    print(f"\n  Sources changed: {len(changed)}")

    for c in changed:
        print(f"    [{c.get('priority', '?')}] {c['id']}: {c.get('reason', '?')}")

    if not changed:
        print("  No sources changed. Pipeline complete.")
        return True, None

    return True, scan_data


def extract_stage(source_id, source_data, sources_path, cache_dir, rules_path):
    print(f"\n  --- Extracting candidates from: {source_id} ---")

    source_type = source_data.get("type", "unknown")
    url = source_data.get("url", "")

    if source_type in ("json_url", "web_page"):
        print(f"    NOTE: Content download for '{source_id}' ({source_type}) must be done manually.")
        print(f"    URL: {url}")
        print(f"    After downloading, run: python3 {EXTRACTOR} --content-file <downloaded_file> --source-id {source_id} --rules {rules_path} --output-dir {cache_dir}")
        return True, None

    print(f"    Skipping automatic download for '{source_id}' ({source_type}).")
    print(f"    Clone/mirror the repo first, then pass content with --content-file.")
    return True, None


def dedup_stage(candidates_file, techniques_dir, rules_path, output_file):
    ok, _ = run_stage(
        "DEDUP",
        [
            DEDUP,
            "--candidates", candidates_file,
            "--techniques-dir", techniques_dir,
            "--rules", rules_path,
            "--output", output_file
        ],
        f"Deduplicating {candidates_file} against {techniques_dir}"
    )

    if not ok:
        return False, None

    with open(output_file, "r") as f:
        data = json.load(f)

    new_count = data.get("new_candidates", 0)
    dup_count = data.get("duplicates_removed", 0)

    print(f"\n  New candidates after dedup: {new_count}")
    print(f"  Duplicates removed: {dup_count}")

    return True, data


def review_stage(candidates_file, rules_path, output_file):
    ok, _ = run_stage(
        "REVIEW",
        [
            REVIEWER,
            "--candidates", candidates_file,
            "--rules", rules_path,
            "--output", output_file
        ],
        f"Reviewing and scoring {candidates_file}"
    )

    if not ok:
        return False, None

    with open(output_file, "r") as f:
        data = json.load(f)

    passed = data.get("passed", 0)
    rejected = data.get("rejected", 0)

    print(f"\n  Passed review: {passed}")
    print(f"  Rejected: {rejected}")

    return True, data


def run_pipeline(sources_path, cache_dir, techniques_dir, rules_path, output_dir):
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    pipeline_log = {
        "pipeline_start": datetime.now(timezone.utc).isoformat(),
        "sources": sources_path,
        "cache_dir": cache_dir,
        "techniques_dir": techniques_dir,
        "stages": {}
    }

    ok, scan_data = scan_stage(sources_path, cache_dir, output_dir)
    pipeline_log["stages"]["scan"] = {
        "success": ok,
        "changed_count": len(scan_data.get("changed", [])) if scan_data else 0
    }

    if not ok:
        pipeline_log["pipeline_status"] = "failed_at_scan"
        return False, pipeline_log

    if scan_data is None:
        pipeline_log["pipeline_status"] = "no_changes"
        return True, pipeline_log

    changed_sources = scan_data.get("changed", [])

    all_candidates = []
    extract_results = []

    for changed_item in changed_sources:
        source_id = changed_item["id"]
        source_meta = {"type": changed_item.get("type", "unknown"), "url": ""}

        ok, result_data = extract_stage(
            source_id, source_meta, sources_path, cache_dir, rules_path
        )

        extract_results.append({
            "source_id": source_id,
            "success": ok,
            "candidates_found": 0
        })

    pipeline_log["stages"]["extract"] = {
        "success": True,
        "sources_processed": len(changed_sources),
        "total_candidates": len(all_candidates)
    }

    if not all_candidates:
        print("\nNo candidates were extracted from changed sources.")
        print("This may be because sources require manual content download.")
        print("See scan_result.json for the list of changed sources.")
        pipeline_log["pipeline_status"] = "no_candidates_extracted"
        return True, pipeline_log

    all_candidates_file = os.path.join(cache_dir, f"all_candidates_{timestamp}.json")
    with open(all_candidates_file, "w") as f:
        json.dump(all_candidates, f, indent=2, default=str)

    dedup_output = os.path.join(cache_dir, f"dedup_result_{timestamp}.json")
    ok, dedup_data = dedup_stage(all_candidates_file, techniques_dir, rules_path, dedup_output)
    pipeline_log["stages"]["dedup"] = {
        "success": ok,
        "new_candidates": dedup_data.get("new_candidates", 0) if dedup_data else 0,
        "duplicates_removed": dedup_data.get("duplicates_removed", 0) if dedup_data else 0
    }

    if not ok or (dedup_data and dedup_data.get("new_candidates", 0) == 0):
        pipeline_log["pipeline_status"] = "nothing_new"
        return True, pipeline_log

    review_output = os.path.join(output_dir, f"batch_review_{timestamp}.json")
    ok, review_data = review_stage(dedup_output, rules_path, review_output)
    pipeline_log["stages"]["review"] = {
        "success": ok,
        "passed": review_data.get("passed", 0) if review_data else 0,
        "rejected": review_data.get("rejected", 0) if review_data else 0
    }

    if not ok:
        pipeline_log["pipeline_status"] = "failed_at_review"
        return False, pipeline_log

    pipeline_log["pipeline_status"] = "complete"
    pipeline_log["pipeline_end"] = datetime.now(timezone.utc).isoformat()
    pipeline_log["output_file"] = review_output

    return True, pipeline_log


def main():
    parser = argparse.ArgumentParser(
        description="Orchestrate full auto-research import pipeline: scan -> extract -> dedup -> review"
    )
    parser.add_argument(
        "--sources",
        required=True,
        help="Path to sources.yaml"
    )
    parser.add_argument(
        "--cache-dir",
        required=True,
        help="Directory for cache and intermediate files"
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Directory of existing technique files for deduplication"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to ingest_rules.yaml"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path for final pipeline result JSON (default: cache-dir/batch_result.json)"
    )
    args = parser.parse_args()

    for path, name in [
        (args.sources, "sources"),
        (args.rules, "rules")
    ]:
        if not os.path.exists(path):
            print(f"ERROR: {name} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    output_dir = args.output if args.output else args.cache_dir
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    success, log = run_pipeline(
        args.sources,
        args.cache_dir,
        args.techniques_dir,
        args.rules,
        output_dir
    )

    log_file = os.path.join(args.cache_dir, "pipeline_log.json")
    with open(log_file, "w") as f:
        json.dump(log, f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f"PIPELINE COMPLETE")
    print(f"  Status: {log.get('pipeline_status', 'unknown')}")
    print(f"  Log: {log_file}")
    print(f"{'=' * 60}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())