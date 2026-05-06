#!/usr/bin/env python3
"""Safe browser capture script — capture authenticated page state via Playwright.

Three-Plane Browser Output Model:
  1. Visual plane:   screenshot, page title, URL, status code
  2. Structured plane: interactables JSON (forms, links, buttons, inputs with IDs)
  3. Action plane:   NO auto-actions. All actions must be explicit and approved.

Safety gates:
  - Persona must exist and have valid auth
  - URL must be in scope (requires SCOPE_FILE)
  - Never capture login flows or payment pages by default
  - Never auto-submit forms, auto-click, auto-scroll
  - Redact all auth headers, cookies, bearer tokens from saved artifacts
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

FORBIDDEN_PATH_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"/login",
        r"/signin",
        r"/sign_in",
        r"/register",
        r"/signup",
        r"/sign_up",
        r"/checkout",
        r"/payment",
        r"/card",
        r"/billing",
        r"/reset[_-]?password",
        r"/forgot[_-]?password",
        r"/verify[_-]?email",
        r"/confirm[_-]?payment",
        r"/activate[_-]?subscription",
        r"/purchase",
        r"/wallet",
        r"/add[_-]?card",
    ]
]

AUTH_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-id",
    "bearer",
    "proxy-authorization",
    "www-authenticate",
}

SENSITIVE_URL_PARAMS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "session",
    "sid",
    "auth",
    "code",
    "state",
    "nonce",
    "signature",
    "sig",
}


def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)


def load_persona_creds(persona_dir, persona_id):
    personas_file = Path(persona_dir) / "personas.json"
    if not personas_file.exists():
        print(
            json.dumps(
                {
                    "error": f"personas.json not found at {personas_file}, run persona init first"
                }
            )
        )
        sys.exit(1)
    personas = json.loads(personas_file.read_text())
    if persona_id not in personas.get("personas", {}):
        print(
            json.dumps(
                {
                    "error": f"unknown persona '{persona_id}', available: {list(personas.get('personas', {}).keys())}"
                }
            )
        )
        sys.exit(1)
    pdata = personas["personas"][persona_id]
    if not pdata.get("credentials_imported"):
        print(
            json.dumps(
                {"error": f"persona '{persona_id}' has no credentials imported"}
            )
        )
        sys.exit(1)
    creds_dir = Path(persona_dir) / "creds"
    cred_files = sorted(creds_dir.glob(f"{persona_id}_*.json"))
    if not cred_files:
        print(
            json.dumps(
                {"error": f"no credential files found for persona '{persona_id}'"}
            )
        )
        sys.exit(1)
    cred = json.loads(cred_files[-1].read_text())
    return personas, cred


def check_scope(url, scope_file):
    if not scope_file or not Path(scope_file).exists():
        print(
            json.dumps(
                {
                    "status": "scope_warning",
                    "message": "SCOPE_FILE not found or not configured, skipping scope check",
                }
            )
        )
        return True
    scope_text = Path(scope_file).read_text()
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain_patterns = []
    for line in scope_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*."):
            domain_patterns.append(
                re.compile(
                    r"(^|\.)" + re.escape(line[2:]) + r"$",
                    re.I,
                )
            )
        elif line.startswith("."):
            domain_patterns.append(
                re.compile(r"(^|\.)" + re.escape(line[1:]) + r"$", re.I)
            )
        else:
            domain_patterns.append(
                re.compile(r"^" + re.escape(line) + r"$", re.I)
            )
        full_url_pattern = re.compile(
            re.escape(line).replace(r"\*", ".*"), re.I
        )
    for pat in domain_patterns:
        if pat.search(hostname):
            return True
    print(
        json.dumps(
            {
                "status": "out_of_scope",
                "message": f"URL '{url}' is not in scope according to {scope_file}",
            }
        )
    )
    return False


def is_forbidden_path(url):
    from urllib.parse import urlparse

    path = urlparse(url).path or "/"
    for pat in FORBIDDEN_PATH_PATTERNS:
        if pat.search(path):
            return True
    return False


def redact_url(url):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    if parsed.query:
        qs_pairs = []
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k.lower() in SENSITIVE_URL_PARAMS:
                    qs_pairs.append(f"{k}=[REDACTED]")
                else:
                    qs_pairs.append(pair)
            else:
                qs_pairs.append(pair)
        query = "&".join(qs_pairs)
    else:
        query = ""
    redacted = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment,
        )
    )
    return redacted


def redact_har_entry(entry):
    req = entry.get("request", {})
    headers = req.get("headers", [])
    for h in headers:
        if h.get("name", "").lower() in AUTH_HEADER_NAMES:
            h["value"] = "[REDACTED]"
    if "cookies" in req:
        for c in req["cookies"]:
            c["value"] = "[REDACTED]"
    resp = entry.get("response", {})
    resp_headers = resp.get("headers", [])
    for h in resp_headers:
        if h.get("name", "").lower() in AUTH_HEADER_NAMES:
            h["value"] = "[REDACTED]"
    if "cookies" in resp:
        for c in resp["cookies"]:
            c["value"] = "[REDACTED]"
    url = entry.get("request", {}).get("url", "")
    if url:
        entry["request"]["url"] = redact_url(url)
    return entry


def redact_har(har_data):
    entries = har_data.get("log", {}).get("entries", [])
    for entry in entries:
        redact_har_entry(entry)
    return har_data


def extract_interactables(page):
    result = {
        "forms": [],
        "links": [],
        "buttons": [],
        "inputs": [],
        "extracted_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        forms = page.evaluate(
            """() => {
            const results = [];
            document.querySelectorAll('form').forEach((f, i) => {
                const inputs = [];
                f.querySelectorAll('input, select, textarea').forEach(el => {
                    inputs.push({
                        tag: el.tagName.toLowerCase(),
                        name: el.getAttribute('name') || '',
                        type: el.getAttribute('type') || 'text',
                        id: el.id || '',
                        placeholder: el.getAttribute('placeholder') || '',
                        required: el.hasAttribute('required')
                    });
                });
                results.push({
                    index: i,
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    id: f.id || '',
                    input_count: inputs.length,
                    inputs: inputs
                });
            });
            return results;
        }"""
        )
        result["forms"] = forms or []
    except Exception as e:
        result["forms_error"] = str(e)[:200]

    try:
        links = page.evaluate(
            """() => {
            return Array.from(document.querySelectorAll('a[href]')).map((a, i) => ({
                index: i,
                href: a.getAttribute('href'),
                text: (a.textContent || '').trim().substring(0, 200),
                id: a.id || '',
                rel: a.getAttribute('rel') || '',
                target: a.getAttribute('target') || ''
            }));
        }"""
        )
        result["links"] = links or []
    except Exception as e:
        result["links_error"] = str(e)[:200]

    try:
        buttons = page.evaluate(
            """() => {
            return Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]')).map((el, i) => ({
                index: i,
                tag: el.tagName.toLowerCase(),
                text: (el.textContent || el.getAttribute('value') || '').trim().substring(0, 200),
                id: el.id || '',
                name: el.getAttribute('name') || '',
                type: el.getAttribute('type') || '',
                disabled: el.hasAttribute('disabled')
            }));
        }"""
        )
        result["buttons"] = buttons or []
    except Exception as e:
        result["buttons_error"] = str(e)[:200]

    try:
        inputs = page.evaluate(
            """() => {
            return Array.from(document.querySelectorAll('input:not([type="submit"]):not([type="button"]), select, textarea')).map((el, i) => ({
                index: i,
                tag: el.tagName.toLowerCase(),
                name: el.getAttribute('name') || '',
                type: el.getAttribute('type') || 'text',
                id: el.id || '',
                placeholder: el.getAttribute('placeholder') || '',
                required: el.hasAttribute('required'),
                readonly: el.hasAttribute('readonly'),
                disabled: el.hasAttribute('disabled')
            }));
        }"""
        )
        result["inputs"] = inputs or []
    except Exception as e:
        result["inputs_error"] = str(e)[:200]

    return result


def capture_page(
    persona_id, persona_creds, url, output_dir, capture_screenshot, save_har
):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    cookies_payload = persona_creds.get("cookies", "")
    bearer_token = persona_creds.get("bearer_token", "")
    api_key = persona_creds.get("api_key", "")

    result = {
        "status": "unknown",
        "persona": persona_id,
        "url": url,
        "redacted_url": redact_url(url),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(out),
    }

    with sync_playwright() as pw:
        context_kwargs = {"user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
        if save_har:
            har_path = str(out / "traffic.har")
            context_kwargs["record_har_path"] = har_path

        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(**context_kwargs)

        if cookies_payload:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            domain = parsed.hostname or "localhost"
            secure = parsed.scheme == "https"
            for cookie_str in cookies_payload.split("; "):
                if "=" in cookie_str:
                    cname, cval = cookie_str.split("=", 1)
                    context.add_cookies(
                        [
                            {
                                "name": cname.strip(),
                                "value": cval.strip(),
                                "domain": domain,
                                "path": "/",
                                "secure": secure,
                                "httpOnly": False,
                            }
                        ]
                    )

        extra_headers = {}
        if bearer_token:
            extra_headers["Authorization"] = f"Bearer {bearer_token}"
        elif api_key:
            extra_headers["X-API-Key"] = api_key
        extra_headers["X-Persona-Id"] = persona_id

        page = context.new_page()
        page.set_extra_http_headers(extra_headers)

        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(1000)
        except Exception as e:
            result["status"] = "navigation_error"
            result["error"] = str(e)[:500]
            context.close()
            browser.close()
            (out / "capture_result.json").write_text(json.dumps(result, indent=2))
            print(
                json.dumps(
                    {
                        "status": "error",
                        "phase": "navigation",
                        "error": str(e)[:200],
                    }
                )
            )
            return

        http_status = response.status if response else 0
        page_title = page.title()
        page_url = page.url

        result["status"] = "captured"
        result["http_status"] = http_status
        result["page_title"] = page_title
        result["final_url"] = redact_url(page_url)

        interactables = extract_interactables(page)
        interactables_path = out / "interactables.json"
        interactables_path.write_text(json.dumps(interactables, indent=2))
        result["interactables_file"] = str(interactables_path)

        if capture_screenshot:
            screenshot_path = out / "screenshot.png"
            try:
                page.screenshot(path=str(screenshot_path), full_page=False)
                result["screenshot_file"] = str(screenshot_path)
            except Exception as e:
                result["screenshot_error"] = str(e)[:200]

        page_state = {
            "persona": persona_id,
            "url": redact_url(url),
            "final_url": redact_url(page_url),
            "title": page_title,
            "http_status": http_status,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        (out / "page_state.json").write_text(json.dumps(page_state, indent=2))
        result["page_state_file"] = str(out / "page_state.json")

        context.close()
        browser.close()

    if save_har and Path(har_path).exists():
        try:
            har_data = json.loads(Path(har_path).read_text())
            redacted_har = redact_har(har_data)
            Path(har_path).write_text(json.dumps(redacted_har, indent=2))
            result["har_file"] = har_path
        except Exception as e:
            result["har_redaction_error"] = str(e)[:200]

    (out / "capture_result.json").write_text(json.dumps(result, indent=2))

    model_summary = {
        "visual_plane": {
            "screenshot_captured": capture_screenshot,
            "page_title": page_title,
            "url": redact_url(page_url),
            "status_code": http_status,
        },
        "structured_plane": {
            "interactables_file": str(interactables_path),
            "forms_count": len(interactables.get("forms", [])),
            "links_count": len(interactables.get("links", [])),
            "buttons_count": len(interactables.get("buttons", [])),
            "inputs_count": len(interactables.get("inputs", [])),
        },
        "action_plane": {
            "auto_actions_taken": 0,
            "auto_submits": 0,
            "auto_clicks": 0,
            "auto_scrolls": 0,
            "note": "All actions must be explicit and approved",
        },
    }
    (out / "model_summary.json").write_text(json.dumps(model_summary, indent=2))

    print(json.dumps({"status": "success", "output_dir": str(out), "http_status": http_status, "title": page_title}))
    return result


def main():
    if not HAS_PLAYWRIGHT:
        print(
            json.dumps(
                {
                    "error": "Playwright is not installed. Install with: pip install playwright && playwright install chromium",
                    "help": "pip install playwright && playwright install chromium",
                }
            )
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Safe browser capture — capture authenticated page state via Playwright"
    )
    parser.add_argument(
        "--context",
        default=".bb/context.json",
        help="Context JSON file (default: .bb/context.json)",
    )
    parser.add_argument(
        "--persona",
        required=True,
        help="Persona ID to use for authentication",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="URL to capture",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for captured artifacts",
    )
    parser.add_argument(
        "--capture-screenshot",
        action="store_true",
        help="Save screenshot of the page",
    )
    parser.add_argument(
        "--save-har",
        action="store_true",
        help="Save HAR traffic recording",
    )
    parser.add_argument(
        "--persona-dir",
        help="Persona directory (default: inferred from context OUTDIR/persona or .bb/persona)",
    )
    args = parser.parse_args()

    ctx = load_context(args.context)

    if args.persona_dir:
        persona_dir = args.persona_dir
    else:
        outdir = ctx.get("outdir", ".bb")
        persona_dir = os.path.join(outdir, "persona")
        if not Path(persona_dir).exists():
            persona_dir = ".bb/persona"

    if not Path(persona_dir).exists():
        print(
            json.dumps(
                {
                    "error": f"Persona directory '{persona_dir}' not found. Run persona init first.",
                }
            )
        )
        sys.exit(1)

    personas, cred = load_persona_creds(persona_dir, args.persona)

    if is_forbidden_path(args.url):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "reason": "URL matches a forbidden path pattern (login, payment, etc.). Browser capture does not target these pages.",
                    "url": args.url,
                }
            )
        )
        sys.exit(1)

    scope_file = ctx.get("scope_file", os.environ.get("SCOPE_FILE", ""))
    if scope_file and Path(scope_file).exists():
        if not check_scope(args.url, scope_file):
            sys.exit(1)

    capture_page(
        persona_id=args.persona,
        persona_creds=cred,
        url=args.url,
        output_dir=args.output,
        capture_screenshot=args.capture_screenshot,
        save_har=args.save_har,
    )


if __name__ == "__main__":
    main()