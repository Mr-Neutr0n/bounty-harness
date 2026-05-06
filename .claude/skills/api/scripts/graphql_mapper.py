#!/usr/bin/env python3
"""GraphQL Mapper -- introspect, map schema, detect dangerous fields, test limits."""
import argparse, json, os, sys, time, urllib.parse, urllib.request, urllib.error, ssl

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields { name description args { name type { name kind ofType { name kind ofType { name kind } } } } type { name kind ofType { name kind ofType { name kind } } } }
      inputFields { name description type { name kind ofType { name kind } } defaultValue }
      enumValues { name description }
      interfaces { name }
      possibleTypes { name }
    }
    directives { name description args { name type { name kind ofType { name kind } } } locations }
  }
}
""".strip()

DEPTH_TEST_QUERY = """
query RecurseTest {
  __typename
  ...Recurse
}
fragment Recurse on Query {
  __typename
  ...Recurse
}
"""

ALIAS_BATCH_QUERY = """
query AliasBatch {
  a01: __typename
  a02: __typename
  a03: __typename
  a04: __typename
  a05: __typename
  a06: __typename
  a07: __typename
  a08: __typename
  a09: __typename
  a10: __typename
  a11: __typename
  a12: __typename
  a13: __typename
  a14: __typename
  a15: __typename
  a16: __typename
  a17: __typename
  a18: __typename
  a19: __typename
  a20: __typename
}
"""

DANGEROUS_PATTERNS = ["password", "secret", "token", "key", "credential", "admin",
                       "private", "ssn", "pin", "hash", "credit", "card", "cvv",
                       "internal", "debug", "privilege", "role", "permission"]

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def gql_request(url, query, cookies=None, headers=None, proxy=None, timeout=15):
    ssl_ctx = build_ctx()
    data = json.dumps({"query": query}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req.add_header("Cookie", cookie_str)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    opener = urllib.request.build_opener(*handlers)
    resp = opener.open(req, timeout=timeout)
    return json.loads(resp.read().decode())

def introspect_schema(url, cookies, headers, proxy, timeout, dry_run):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "introspection",
        "url": url,
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["introspection_enabled"] = None
        entry["evidence"] = "dry-run: no request sent"
        return entry, None

    try:
        result = gql_request(url, INTROSPECTION_QUERY, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
        if "data" in result and result["data"] and "__schema" in result["data"]:
            schema = result["data"]["__schema"]
            entry["status"] = "completed"
            entry["introspection_enabled"] = True
            entry["type_count"] = len(schema.get("types", []))
            entry["evidence"] = f"Introspection enabled; {len(schema.get('types', []))} types discovered"
            return entry, schema
        else:
            entry["status"] = "completed"
            entry["introspection_enabled"] = False
            entry["evidence"] = f"Introspection disabled or denied: {json.dumps(result.get('errors', result))[:300]}"
            return entry, None
    except Exception as e:
        entry["status"] = "error"
        entry["introspection_enabled"] = None
        entry["evidence"] = f"Error: {e}"
        return entry, None

def analyze_schema(schema, timestamp):
    findings = []
    types_list = schema.get("types", [])
    all_fields = []
    query_type_name = schema.get("queryType", {}).get("name")
    mutation_type_name = schema.get("mutationType", {}).get("name")
    subscription_type_name = schema.get("subscriptionType", {}).get("name")

    queries = []
    mutations = []
    subscriptions = []

    for t in types_list:
        kind = t.get("kind")
        name = t.get("name")
        if name == query_type_name and kind == "OBJECT" and t.get("fields"):
            queries = [f.get("name") for f in t["fields"]]
        if name == mutation_type_name and kind == "OBJECT" and t.get("fields"):
            mutations = [f.get("name") for f in t["fields"]]
        if name == subscription_type_name and kind == "OBJECT" and t.get("fields"):
            subscriptions = [f.get("name") for f in t["fields"]]

        if t.get("fields"):
            for field in t["fields"]:
                field_name = field.get("name", "")
                field_type = field.get("type", {})
                all_fields.append({
                    "type_name": name,
                    "field_name": field_name,
                    "type_kind": field_type.get("kind"),
                    "type_name_ref": field_type.get("name"),
                    "args": [a.get("name") for a in (field.get("args") or [])],
                })
                for pattern in DANGEROUS_PATTERNS:
                    if pattern in field_name.lower():
                        findings.append({
                            "timestamp": timestamp,
                            "test": "dangerous_field",
                            "field_name": field_name,
                            "type_name": name,
                            "pattern_matched": pattern,
                            "risk": "HIGH" if pattern in ("password", "token", "secret", "key", "credential") else "MEDIUM",
                            "evidence": f"Field '{field_name}' in type '{name}' matches dangerous pattern '{pattern}'",
                        })
                        break

    summary = {
        "query_type": query_type_name,
        "mutation_type": mutation_type_name,
        "subscription_type": subscription_type_name,
        "total_types": len(types_list),
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "subscription_count": len(subscriptions),
        "queries": queries,
        "mutations": mutations,
        "subscriptions": subscriptions,
        "dangerous_field_count": len(findings),
    }

    return summary, findings, all_fields

def test_depth_limit(url, cookies, headers, proxy, timeout, dry_run):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "depth_limit",
        "url": url,
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["depth_limit_enforced"] = None
        entry["evidence"] = "dry-run: no request sent"
        return entry

    try:
        result = gql_request(url, DEPTH_TEST_QUERY, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
        if "errors" in result:
            errors = result["errors"]
            entry["status"] = "completed"
            entry["depth_limit_enforced"] = True
            entry["evidence"] = f"Depth limit enforced: {errors[0].get('message', str(errors))[:200]}"
        else:
            entry["status"] = "completed"
            entry["depth_limit_enforced"] = False
            entry["evidence"] = "No depth limit detected -- recursive fragment accepted"
    except Exception as e:
        entry["status"] = "error"
        entry["depth_limit_enforced"] = None
        entry["evidence"] = str(e)
    return entry

def test_alias_batching(url, cookies, headers, proxy, timeout, dry_run):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "alias_batching",
        "url": url,
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["alias_limit_enforced"] = None
        entry["evidence"] = "dry-run: no request sent"
        return entry

    try:
        result = gql_request(url, ALIAS_BATCH_QUERY, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
        if "errors" in result:
            entry["status"] = "completed"
            entry["alias_limit_enforced"] = True
            entry["evidence"] = f"Alias/rate limit enforced: {result['errors'][0].get('message', '')[:200]}"
        else:
            entry["status"] = "completed"
            entry["alias_limit_enforced"] = False
            entry["evidence"] = "Alias batching accepted -- potential rate-limit bypass vector"
    except Exception as e:
        entry["status"] = "error"
        entry["alias_limit_enforced"] = None
        entry["evidence"] = str(e)
    return entry

def main():
    parser = argparse.ArgumentParser(description="GraphQL Mapper -- schema introspection and analysis")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("--cookie", default="", help="Session cookies (key=value; key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Extra headers (Name:Value), repeatable")
    parser.add_argument("--proxy", default="", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--schema-output", default="graphql_schema.json", help="Schema JSON output file")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without sending requests")
    parser.add_argument("--output", default="graphql_findings.jsonl", help="JSONL findings output file")
    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    print(f"[*] GraphQL Mapper", file=sys.stderr)
    print(f"[*] Endpoint: {args.url}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)
    print(f"[*] Schema: {args.schema_output}", file=sys.stderr)

    all_findings = []

    print(f"\n[*] [1/4] Introspecting schema...", file=sys.stderr)
    intro_entry, schema = introspect_schema(args.url, cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.append(intro_entry)
    if intro_entry.get("introspection_enabled"):
        print(f"    Introspection ENABLED ({intro_entry.get('type_count', 0)} types)", file=sys.stderr)
    else:
        print(f"    Introspection disabled or denied", file=sys.stderr)

    if schema:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        print(f"[*] [2/4] Analyzing schema for dangerous fields...", file=sys.stderr)
        summary, danger_findings, all_fields = analyze_schema(schema, timestamp)
        all_findings.extend(danger_findings)

        print(f"    Query type: {summary['query_type']}", file=sys.stderr)
        print(f"    Mutation type: {summary['mutation_type']}", file=sys.stderr)
        print(f"    Subscription type: {summary['subscription_type']}", file=sys.stderr)
        print(f"    Queries: {summary['query_count']}", file=sys.stderr)
        print(f"    Mutations: {summary['mutation_count']}", file=sys.stderr)
        print(f"    Subscriptions: {summary['subscription_count']}", file=sys.stderr)
        print(f"    Dangerous fields: {summary['dangerous_field_count']}", file=sys.stderr)

        schema_export = {
            "endpoint": args.url,
            "introspected_at": timestamp,
            "summary": summary,
            "types": [{k: v for k, v in t.items() if k != "fields"} for t in schema.get("types", [])],
        }
        with open(args.schema_output, "w") as sf:
            json.dump(schema_export, sf, indent=2)
        print(f"    Schema saved to {args.schema_output}", file=sys.stderr)

    print(f"[*] [3/4] Testing depth limit...", file=sys.stderr)
    depth_entry = test_depth_limit(args.url, cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.append(depth_entry)
    print(f"    Depth limit: {'ENFORCED' if depth_entry.get('depth_limit_enforced') else 'NOT ENFORCED'}", file=sys.stderr)

    print(f"[*] [4/4] Testing alias batching...", file=sys.stderr)
    alias_entry = test_alias_batching(args.url, cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.append(alias_entry)
    print(f"    Alias limit: {'ENFORCED' if alias_entry.get('alias_limit_enforced') else 'NOT ENFORCED'}", file=sys.stderr)

    with open(args.output, "w") as outfile:
        for e in all_findings:
            outfile.write(json.dumps(e) + "\n")

    issues = sum(1 for f in all_findings
                 if f.get("introspection_enabled") == True
                 or f.get("test") == "dangerous_field"
                 or f.get("depth_limit_enforced") == False
                 or f.get("alias_limit_enforced") == False)

    print(f"\n[*] {issues} potential issues found", file=sys.stderr)
    print(f"[*] Findings written to {args.output}", file=sys.stderr)

    sys.exit(1 if issues > 0 else 0)

if __name__ == "__main__":
    main()