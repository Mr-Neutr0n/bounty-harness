#!/usr/bin/env python3
import argparse
import json
import sys
import re
import urllib.parse
import requests

CSP_DIRECTIVE_INFO = {
    "default-src": {
        "severity": "critical",
        "description": "Fallback for all fetch directives",
        "dangerous_values": ["*", "'none'", "data:", "blob:", "https:", "http:"],
        "bypasses": ["If '*' is present, any resource can be loaded from anywhere."],
    },
    "script-src": {
        "severity": "critical",
        "description": "Controls which scripts can execute",
        "dangerous_values": ["*", "'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "https:", "http:"],
        "bypasses": [
            "'unsafe-inline' allows inline scripts and event handlers — trivial XSS",
            "'unsafe-eval' allows eval(), setTimeout(string), Function() constructor",
            "Wildcard '*' or missing nonce/hash + domain allow-listing = JSONP bypass possible",
            "'strict-dynamic' without nonces/hashes on ancestor scripts propagates trust",
        ],
    },
    "style-src": {
        "severity": "medium",
        "description": "Controls CSS sources",
        "dangerous_values": ["*", "'unsafe-inline'", "data:", "https:", "http:"],
        "bypasses": ["'unsafe-inline' allows CSS injection for data exfiltration via @import or background-url"],
    },
    "img-src": {
        "severity": "low",
        "description": "Controls image sources",
        "dangerous_values": ["*", "data:", "https:", "http:"],
        "bypasses": ["Wildcard allows loading images from attacker-controlled servers (exfiltration via img tag)"],
    },
    "connect-src": {
        "severity": "medium",
        "description": "Controls XMLHttpRequest, fetch(), WebSocket, EventSource",
        "dangerous_values": ["*", "https:", "http:", "wss:", "ws:"],
        "bypasses": ["Wildcard allows CORS requests to arbitrary origins — data exfiltration channel"],
    },
    "frame-src": {
        "severity": "medium",
        "description": "Controls framing / iframe sources",
        "dangerous_values": ["*", "https:", "http:"],
        "bypasses": ["Wildcard enables clickjacking if frame-ancestors is not set"],
    },
    "frame-ancestors": {
        "severity": "critical",
        "description": "Controls who can embed the page in iframe",
        "dangerous_values": ["*", "'none'"],
        "bypasses": ["Missing or '*' allows universal clickjacking. Use X-Frame-Options as fallback check."],
    },
    "form-action": {
        "severity": "high",
        "description": "Controls where forms can submit",
        "dangerous_values": ["*", "https:", "http:"],
        "bypasses": ["Wildcard allows form submissions to attacker-controlled endpoints for credential theft"],
    },
    "base-uri": {
        "severity": "medium",
        "description": "Controls base element href for relative URL resolution",
        "dangerous_values": ["*", "'none'", "https:", "http:"],
        "bypasses": ["Missing allows base tag injection to hijack relative script/src URLs"],
    },
    "object-src": {
        "severity": "low",
        "description": "Controls plugin sources (Flash, Java, etc.)",
        "dangerous_values": ["*", "'none'", "https:", "http:"],
        "bypasses": ["Allowing plugins enables legacy plugin-based attacks"],
    },
    "media-src": {
        "severity": "low",
        "description": "Controls audio/video sources",
        "dangerous_values": ["*", "data:", "https:", "http:"],
        "bypasses": [],
    },
    "font-src": {
        "severity": "low",
        "description": "Controls font sources",
        "dangerous_values": ["*", "data:", "https:", "http:"],
        "bypasses": [],
    },
    "manifest-src": {
        "severity": "low",
        "description": "Controls web app manifest sources",
        "dangerous_values": ["*", "data:", "https:", "http:"],
        "bypasses": [],
    },
    "worker-src": {
        "severity": "medium",
        "description": "Controls worker script sources",
        "dangerous_values": ["*", "data:", "blob:", "https:", "http:"],
        "bypasses": ["Wildcard allows service worker registration from attacker origins for persistent XSS"],
    },
    "child-src": {
        "severity": "medium",
        "description": "Controls child browsing contexts (workers, frames) — deprecated, prefer frame-src + worker-src",
        "dangerous_values": ["*", "https:", "http:"],
        "bypasses": [],
    },
    "prefetch-src": {
        "severity": "low",
        "description": "Controls prefetch/prerender sources",
        "dangerous_values": ["*", "https:", "http:"],
        "bypasses": [],
    },
    "require-trusted-types-for": {
        "severity": "high",
        "description": "Requires Trusted Types for DOM XSS sinks",
        "dangerous_values": [],
        "bypasses": ["Missing means no Trusted Types enforcement — all DOM XSS sinks unprotected"],
    },
    "trusted-types": {
        "severity": "high",
        "description": "Whitelist of allowed Trusted Types policies",
        "dangerous_values": ["*", "'allow-duplicates'"],
        "bypasses": ["'allow-duplicates' weakens the policy by allowing policy name reuse"],
    },
    "sandbox": {
        "severity": "high",
        "description": "Sandbox restrictions for the resource",
        "dangerous_values": [],
        "bypasses": ["Missing means no sandbox restrictions applied"],
    },
    "upgrade-insecure-requests": {
        "severity": "low",
        "description": "Upgrades HTTP requests to HTTPS",
        "dangerous_values": [],
        "bypasses": [],
    },
    "block-all-mixed-content": {
        "severity": "low",
        "description": "Blocks mixed content (deprecated)",
        "dangerous_values": [],
        "bypasses": [],
    },
    "report-uri": {
        "severity": "info",
        "description": "Deprecated reporting endpoint",
        "dangerous_values": [],
        "bypasses": [],
    },
    "report-to": {
        "severity": "info",
        "description": "Reporting API endpoint group",
        "dangerous_values": [],
        "bypasses": [],
    },
}

KNOWN_BYPASS_TECHNIQUES = {
    "jsonp_bypass": "If script-src allows a domain with JSONP endpoints, inject <script src=\"https://allowed.example/jsonp?callback=alert(1)\">",
    "path_bypass": "If script-src allows a domain, check for open redirects or user-uploaded content paths on that domain",
    "cdn_bypass": "If script-src allows a CDN (cdnjs, unpkg, etc.), check for AngularJS or outdated library versions with known CSP bypass gadgets",
    "nonce_retrieval": "If nonces are static or predictable, extract via injected CSS attribute selector + background-url exfiltration",
    "base_uri_hijack": "If base-uri is missing, inject <base href=\"https://attacker.com/\"> to hijack relative script sources",
    "strict_dynamic_propagation": "If 'strict-dynamic' is set, check if any allowed script uses document.createElement('script') unsafely",
    "dangling_markup": "If no effective script-src and page reflects input before CSP nonce, use dangling markup to steal nonce",
    "policy_injection": "Check if user input is reflected in CSP header value (e.g., via report-uri parameter)",
    "meta_csp_override": "Check if the page uses <meta http-equiv=\"Content-Security-Policy\"> which can be weaker than header CSP",
    "ip_origin_exfiltration": "Use DNS prefetch or WebSocket to exfiltrate data to allowed origins by IP",
    "missing_default_src": "If default-src is missing and specific directives have gaps, resources fall through the gap",
    "unsafe_hashes": "If 'unsafe-hashes' is present in script-src, inline event handlers with matching hash can execute",
    "service_worker_bypass": "If worker-src is '*' or missing, register a malicious service worker for persistent compromise",
    "csp_report_only": "Check for Content-Security-Policy-Report-Only header — violations are reported but NOT blocked",
}

SEVERITY_SCORES = {
    "critical": 1,
    "high": 5,
    "medium": 15,
    "low": 20,
    "info": 0,
}


def fetch_csp_data(url, context):
    proxy = context.get("proxy")
    timeout = context.get("timeout", 15)
    user_agent = context.get("user_agent", "BugBountyAgent/2.0")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": user_agent}
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return None, str(e), None
    csp_header = resp.headers.get("Content-Security-Policy")
    csp_ro = resp.headers.get("Content-Security-Policy-Report-Only")
    xfo = resp.headers.get("X-Frame-Options")
    return csp_header, csp_ro, xfo


def parse_csp(csp_string):
    if not csp_string:
        return []
    directives = []
    tokens = [t.strip() for t in csp_string.split(";") if t.strip()]
    for token in tokens:
        parts = token.split()
        if not parts:
            continue
        name = parts[0].lower()
        values = parts[1:]
        directives.append({"name": name, "values": values})
    return directives


def compute_directive_score(directive_info, values):
    if not values:
        for dv in directive_info.get("dangerous_values", []):
            if dv == "'none'":
                base = 10
                ded_missing = True
                if directive_info.get("severity") == "critical":
                    base = 5
                return {"score": base, "risk": "none_source", "issues": []}
        return {"score": 0, "risk": "none", "issues": []}
    score = 10
    issues = []
    has_wildcard = "*" in values or any(v.startswith("https:") or v.startswith("http:") or v.startswith("ws:") for v in values) if "*" not in values else False
    has_scheme_allow = any(v == "https:" or v == "http:" or v == "ws:" or v == "wss:" for v in values)
    has_wildcard_star = "*" in values
    has_unsafe_inline = "'unsafe-inline'" in values
    has_unsafe_eval = "'unsafe-eval'" in values
    has_data_blob = "data:" in values or "blob:" in values
    severity = directive_info.get("severity", "medium")
    if has_wildcard_star:
        base_score = SEVERITY_SCORES.get(severity, 15)
        score = max(0, 10 - base_score // 2)
        issues.append({
            "type": "wildcard_source",
            "severity": "high",
            "detail": f"Wildcard '*' in {directive_info.get('description', 'directive')} — allows resources from any origin",
        })
    if has_unsafe_inline:
        score = max(0, score - 4)
        issues.append({
            "type": "unsafe_inline",
            "severity": "critical",
            "detail": f"'unsafe-inline' in {directive_info.get('description', 'directive')} — allows inline scripts/styles",
        })
    if has_unsafe_eval:
        score = max(0, score - 3)
        issues.append({
            "type": "unsafe_eval",
            "severity": "high",
            "detail": f"'unsafe-eval' in {directive_info.get('description', 'directive')} — allows eval() and similar",
        })
    if has_scheme_allow and not has_wildcard_star:
        score = max(0, score - 2)
        issues.append({
            "type": "scheme_source",
            "severity": "medium",
            "detail": f"Scheme source (https:/http:/ws:) in {directive_info.get('description', 'directive')} — allows any domain over that scheme",
        })
    if has_data_blob:
        score = max(0, score - 1)
        issues.append({
            "type": "data_blob_source",
            "severity": "low",
            "detail": f"data:/blob: source in {directive_info.get('description', 'directive')} — allows inline data/blobs",
        })
    bypasses = []
    if has_unsafe_inline or has_wildcard_star:
        bypasses.extend(directive_info.get("bypasses", []))
    else:
        for dv in directive_info.get("dangerous_values", []):
            if dv in values:
                idx = directive_info["dangerous_values"].index(dv)
                if idx < len(directive_info.get("bypasses", [])):
                    bypasses.append(directive_info["bypasses"][idx])
    return {
        "score": min(10, max(0, score)),
        "risk": "high" if score <= 3 else "medium" if score <= 6 else "low",
        "issues": issues,
        "bypasses": bypasses,
    }


def compute_overall_score(directive_scores):
    critical_found = False
    total = 0
    count = 0
    for ds in directive_scores:
        total += ds["score"]
        count += 1
    if count == 0:
        return 0
    avg = total / count
    return round(max(0, min(10, avg)), 1)


def generate_bypass_suggestions(parsed_directives, directive_scores, csp_string):
    suggestions = []
    has_script_src = any(d["name"] == "script-src" for d in parsed_directives)
    has_default_src = any(d["name"] == "default-src" for d in parsed_directives)
    found_weak = False
    for ds in directive_scores:
        if ds["score"] <= 5 and ds.get("bypasses"):
            for bp in ds["bypasses"]:
                if bp not in suggestions:
                    suggestions.append({"directive_specific": bp, "category": "directive_bypass"})
            found_weak = True
    if has_script_src:
        for d in parsed_directives:
            if d["name"] == "script-src":
                if "'unsafe-inline'" in d["values"]:
                    suggestions.append({
                        "category": "directive_bypass",
                        "directive_specific": "'unsafe-inline' in script-src — every reflected input can execute inline script. Trivial XSS.",
                    })
                if "'unsafe-eval'" in d["values"]:
                    suggestions.append({
                        "category": "directive_bypass",
                        "directive_specific": "'unsafe-eval' in script-src — allows eval(), setTimeout(string), Function() — inject eval(payload)",
                    })
    if not has_default_src:
        suggestions.append({
            "category": "missing_default_src",
            "directive_specific": "No default-src set. Resources not covered by specific directives fall through completely open.",
        })
    for tech_name, description in KNOWN_BYPASS_TECHNIQUES.items():
        if tech_name in suggestions:
            continue
        suggestions.append({"category": "technique", "technique": tech_name, "description": description})
    return suggestions


def main():
    parser = argparse.ArgumentParser(
        description="CSP Analyzer — fetch, parse, and score Content-Security-Policy headers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
References: CSP Level 3 (W3C), OWASP CSP Cheat Sheet, PortSwigger CSP Bypass Research

Examples:
  %(prog)s --url https://example.com
  %(prog)s --url https://example.com --context .bb/context.json
  %(prog)s --url https://example.com --dry-run
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--url", required=True, help="Target URL to fetch CSP header from")
    parser.add_argument("--dry-run", action="store_true", help="Print analysis plan without executing")
    args = parser.parse_args()

    ctx = {}
    if args.context and __import__("os").path.exists(args.context):
        try:
            with open(args.context, "r") as f:
                ctx = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[warn] Failed to load context: {e}", file=sys.stderr)

    if args.dry_run:
        print(f"[dry-run] Would fetch CSP from {args.url}, parse directives, compute scores, and suggest bypasses.", file=sys.stderr)
        return

    csp_header, csp_report_only, xfo_header = fetch_csp_data(args.url, ctx)

    result = {
        "url": args.url,
        "csp_header": csp_header,
        "csp_report_only": csp_report_only,
        "x_frame_options": xfo_header,
        "has_csp": bool(csp_header),
        "has_csp_report_only": bool(csp_report_only),
        "fetch_error": None,
    }

    if csp_report_only and not csp_header:
        result["warning"] = "Only Content-Security-Policy-Report-Only found — violations are NOT blocked. Check for CSP bypass via report-only mode."
        result["report_only_risk"] = "CSP is in monitoring mode — all resources execute freely, only reporting violations."

    parsed = parse_csp(csp_header)
    result["directives"] = parsed

    directive_scores = []
    all_scored = []
    for d in parsed:
        di = CSP_DIRECTIVE_INFO.get(d["name"], {
            "severity": "medium",
            "description": f"Custom directive: {d['name']}",
            "dangerous_values": ["*"],
            "bypasses": [],
        })
        score_result = compute_directive_score(di, d["values"])
        entry = {
            "name": d["name"],
            "values": d["values"],
            "description": di.get("description", ""),
            "severity": di.get("severity", "medium"),
            "score": score_result["score"],
            "risk": score_result["risk"],
            "issues": score_result.get("issues", []),
            "bypasses": score_result.get("bypasses", []),
        }
        all_scored.append(entry)
        directive_scores.append(entry)

    result["directive_analysis"] = all_scored
    result["overall_score"] = compute_overall_score([ds for ds in all_scored])

    bypass_suggestions = generate_bypass_suggestions(parsed, all_scored, csp_header or "")
    result["bypass_suggestions"] = bypass_suggestions
    result["bypass_suggestion_count"] = len(bypass_suggestions)

    weak_directives = [ds for ds in all_scored if ds["score"] <= 5]
    result["weak_directives"] = [{"name": wd["name"], "score": wd["score"], "risk": wd["risk"]} for wd in weak_directives]
    result["weak_directive_count"] = len(weak_directives)

    if not csp_header:
        result["no_csp_risk"] = "No CSP header set — no restrictions on script execution or resource loading. XSS is unbounded."

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()