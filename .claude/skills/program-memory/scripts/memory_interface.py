#!/usr/bin/env python3
"""
Program memory interface — summary-first, detail-on-demand layer.
Provides redacted overview, search, and fact retrieval for program memory.
Imports from memory_store.py for core persistence; this module adds the
agent-facing interfaces that auto-redact by default.

Usage:
  python3 memory_interface.py summary --program example_program --memory-dir .bb/memory/
  python3 memory_interface.py search --program example_program --query "IDOR" --memory-dir .bb/memory/
  python3 memory_interface.py get-fact --fact-id fact_123 --memory-dir .bb/memory/
"""

import argparse, json, os, re, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SENSITIVE_FIELDS = {"email", "token", "api_key", "password", "secret", "cookie", "bearer"}
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')


def _get_memory_path(memory_dir, program):
    return Path(memory_dir) / program / "program_memory.json"


def _get_fp_path(memory_dir, program):
    return Path(memory_dir) / program / "false_positives.jsonl"


def _get_findings_path(memory_dir, program):
    return Path(memory_dir) / program / "findings_history.jsonl"


def _redact_value(value, include_sensitive=False):
    if include_sensitive:
        return value
    if not isinstance(value, str):
        return value
    text = EMAIL_RE.sub("MASKED", value)
    for field in SENSITIVE_FIELDS:
        pattern = re.compile(r'(' + re.escape(field) + r')[=:]\s*[^\s,;]+', re.I)
        text = pattern.sub(r'\1=REDACTED', text)
    return text


def _load_memory(memory_dir, program):
    path = _get_memory_path(memory_dir, program)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def memory_summary(memory_dir, program, include_sensitive, output_json):
    memory = _load_memory(memory_dir, program)
    if memory is None:
        result = {"status": "not_found", "program": program, "error": f"no memory found at {memory_dir}"}
        if output_json:
            print(json.dumps(result))
        return result

    facts = memory.get("facts", [])
    stats = memory.get("stats", {})

    category_counts = defaultdict(int)
    for fact in facts:
        category_counts[fact.get("category", "unknown")] += 1

    fp_count = 0
    fp_path = _get_fp_path(memory_dir, program)
    if fp_path.exists():
        fp_count = len([l for l in fp_path.read_text().splitlines() if l.strip()])

    fh_count = 0
    fh_path = _get_findings_path(memory_dir, program)
    if fh_path.exists():
        fh_count = len([l for l in fh_path.read_text().splitlines() if l.strip()])

    last_run = memory.get("last_run", "never")
    last_run_dir = memory.get("last_run_dir", "")

    result = {
        "status": "ok",
        "program": program,
        "total_facts": len(facts),
        "category_distribution": dict(category_counts),
        "false_positive_patterns": fp_count,
        "total_findings_history": fh_count,
        "stats": {
            "total_runs": stats.get("total_runs", 0),
            "total_findings": stats.get("total_findings", 0),
            "accepted": stats.get("accepted", 0),
            "rejected": stats.get("rejected", 0),
        },
        "last_run": last_run,
        "last_run_dir": _redact_value(last_run_dir, include_sensitive) if last_run_dir else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Program Memory: {program} ===")
        print(f"  Facts:               {result['total_facts']}")
        print(f"  Categories:          {dict(category_counts)}")
        print(f"  FP patterns:         {fp_count}")
        print(f"  Findings history:    {fh_count}")
        print(f"  Total runs:          {stats.get('total_runs',0)}")
        print(f"  Total findings:      {stats.get('total_findings',0)}")
        print(f"  Accepted:            {stats.get('accepted',0)}")
        print(f"  Rejected:            {stats.get('rejected',0)}")
        print(f"  Last run:            {last_run}")
    return result


def memory_search(memory_dir, program, query, include_sensitive, output_json):
    memory = _load_memory(memory_dir, program)
    if memory is None:
        result = {"status": "not_found", "program": program}
        if output_json:
            print(json.dumps(result))
        return result

    facts = memory.get("facts", [])
    query_lower = query.lower()
    results = []
    for i, fact in enumerate(facts):
        cat = fact.get("category","").lower()
        value = fact.get("value","").lower()
        conf = fact.get("confidence","").lower()
        if query_lower in cat or query_lower in value or query_lower in conf:
            r = dict(fact)
            r["fact_id"] = f"fact_{i:03d}"
            if not include_sensitive:
                r["value"] = _redact_value(r.get("value",""))
            results.append(r)

    fp_path = _get_fp_path(memory_dir, program)
    if fp_path.exists():
        for i, line in enumerate(fp_path.read_text().splitlines()):
            if not line.strip(): continue
            fp = json.loads(line)
            pat = fp.get("pattern","").lower()
            desc = fp.get("description","").lower()
            if query_lower in pat or query_lower in desc:
                results.append({"fact_id": f"fp_{i:03d}", "category": "false_positive",
                               "value": fp.get("pattern",""), "confidence": fp.get("description",""),
                               "recorded_at": fp.get("recorded_at",""), "source": "fp_db"})

    result = {"status": "ok", "program": program, "query": query, "results": results, "count": len(results)}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Search '{query}' in {program} ({len(results)} results) ===")
        for r in results:
            print(f"  {r['fact_id']} [{r.get('category','?')}] (conf: {r.get('confidence','?')})")
            print(f"    {r.get('value','')[:200]}")
    return result


def memory_get_fact(memory_dir, fact_id, include_sensitive, output_json):
    memory = _load_memory(memory_dir, ".")
    if memory is None:
        result = {"status": "not_found", "fact_id": fact_id}
        if output_json:
            print(json.dumps(result))
        return result

    prefix, idx_str = fact_id.split("_", 1)
    idx = int(idx_str) if idx_str.isdigit() else None

    if prefix == "fact" and idx is not None:
        facts = memory.get("facts", [])
        if idx < len(facts):
            fact = dict(facts[idx])
            fact["fact_id"] = fact_id
            if not include_sensitive:
                fact["value"] = _redact_value(fact.get("value",""))
            result = {"status": "ok", "fact_id": fact_id, "fact": fact}
            if output_json:
                print(json.dumps(result))
            else:
                print(f"=== Fact: {fact_id} ===")
                print(json.dumps(fact, indent=2))
            return result

    result = {"status": "not_found", "fact_id": fact_id, "error": "fact not found"}
    if output_json:
        print(json.dumps(result))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Program memory interface — summary-first, detail-on-demand layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 memory_interface.py summary --program example --memory-dir .bb/memory/
  python3 memory_interface.py search --program example --query "IDOR" --memory-dir .bb/memory/
  python3 memory_interface.py get-fact --fact-id fact_0 --memory-dir .bb/memory/
  python3 memory_interface.py get-fact --fact-id fact_0 --memory-dir .bb/memory/ --json
        """,
    )
    parser.add_argument("--action", required=True, choices=["summary","search","get-fact"])
    parser.add_argument("--memory-dir", required=True, help="Base memory directory")
    parser.add_argument("--program", help="Program name")
    parser.add_argument("--query", help="Search query for facts")
    parser.add_argument("--fact-id", help="Fact ID to retrieve")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON format")
    parser.add_argument("--include-sensitive", action="store_true", help="Include sensitive data in output")

    args = parser.parse_args()

    if args.action == "summary":
        if not args.program:
            print(json.dumps({"error": "--program is required for summary"}), file=sys.stderr)
            sys.exit(1)
        memory_summary(args.memory_dir, args.program, args.include_sensitive, args.output_json)
    elif args.action == "search":
        if not args.program:
            print(json.dumps({"error": "--program is required for search"}), file=sys.stderr)
            sys.exit(1)
        if not args.query:
            print(json.dumps({"error": "--query is required for search"}), file=sys.stderr)
            sys.exit(1)
        memory_search(args.memory_dir, args.program, args.query, args.include_sensitive, args.output_json)
    elif args.action == "get-fact":
        if not args.fact_id:
            print(json.dumps({"error": "--fact-id is required for get-fact"}), file=sys.stderr)
            sys.exit(1)
        programs_dir = Path(args.memory_dir)
        found_program = None
        for subdir in sorted(programs_dir.iterdir()) if programs_dir.is_dir() else []:
            if subdir.is_dir():
                mem = _load_memory(str(programs_dir), subdir.name)
                if mem:
                    prefix, idx_str = args.fact_id.split("_", 1)
                    idx = int(idx_str) if idx_str.isdigit() else None
                    if prefix == "fact" and idx is not None and idx < len(mem.get("facts", [])):
                        found_program = subdir.name
                        break
        if found_program:
            memory_get_fact(args.memory_dir, args.fact_id, args.include_sensitive, args.output_json)
        else:
            result = {"status": "not_found", "fact_id": args.fact_id}
            if args.output_json:
                print(json.dumps(result))


if __name__ == "__main__":
    main()