#!/usr/bin/env python3
"""
postMessage Auditor — uses Playwright to audit postMessage communication.

Audits:
  - Missing origin validation (event.origin not checked)
  - Weak regex origin checks
  - All registered listeners and their source mapping files
  - Senders (postMessage calls) with their target origin
  - Message payload structures

Outputs findings.jsonl
"""

import argparse
import json
import sys
import os
import time
import re
import urllib.parse
from typing import Optional


FINDING_TEMPLATES = {
    "no_origin_check": {
        "severity": "HIGH",
        "description": "postMessage listener does not validate event.origin — accepts messages from any origin",
    },
    "wildcard_target_origin": {
        "severity": "MEDIUM",
        "description": "postMessage sent with targetOrigin='*' — message may be intercepted by any origin",
    },
    "weak_regex_origin": {
        "severity": "MEDIUM",
        "description": "postMessage origin check uses weak regex that may be bypassed",
    },
    "no_listener_found": {
        "severity": "INFO",
        "description": "No postMessage listeners detected on the page",
    },
    "sensitive_data_in_message": {
        "severity": "HIGH",
        "description": "postMessage payload contains potentially sensitive data",
    },
}

WEAK_ORIGIN_PATTERNS = [
    (r"event\.origin\s*==\s*['\"]https?://[^'\"]*['\"]", "exact_match_weak", "Exact match — subdomain bypass possible"),
    (r"event\.origin\s*\.\s*endsWith", "ends_with", "endsWith check is trivially bypassable (evil-target.com)"),
    (r"event\.origin\s*\.\s*includes\s*", "includes_origin", "includes check on origin is bypassable"),
    (r"event\.origin\s*\.\s*startsWith", "starts_with", "startsWith check is bypassable (target.com.evil.com)"),
    (r"event\.origin\s*\.\s*indexOf", "index_of", "indexOf check is bypassable"),
    (r"new\s+URL\(.*\)\.hostname", "url_parse_hostname", "URL hostname check — ensure no subdomain bypass"),
]


def _inject_audit_script() -> str:
    return """
    (function() {
      window.__postmessage_audit = {
        listeners: [],
        senders: [],
        messages: [],
        startTime: Date.now(),
      };

      const _origAddEventListener = EventTarget.prototype.addEventListener;
      EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'message' && typeof listener === 'function') {
          const listenerStr = listener.toString();
          const stack = new Error().stack || '';
          window.__postmessage_audit.listeners.push({
            type: 'message',
            listenerSource: listenerStr.substring(0, 2000),
            registrationStack: stack.substring(0, 2000),
            registeredAt: Date.now(),
            pageUrl: window.location.href,
          });
        }
        return _origAddEventListener.call(this, type, listener, options);
      };

      const _origPostMessage = window.postMessage.bind(window);
      window.postMessage = function(message, targetOrigin, transfer) {
        window.__postmessage_audit.senders.push({
          message: typeof message === 'object' ? JSON.stringify(message).substring(0, 2000) : String(message).substring(0, 2000),
          targetOrigin: targetOrigin,
          pageUrl: window.location.href,
          timestamp: Date.now(),
        });
        return _origPostMessage(message, targetOrigin, transfer);
      };

      window.addEventListener('message', function(event) {
        window.__postmessage_audit.messages.push({
          origin: event.origin,
          source: event.source ? (event.source === window ? 'same-window' : 'cross-origin-window') : 'unknown',
          data: typeof event.data === 'object' ? JSON.stringify(event.data).substring(0, 2000) : String(event.data).substring(0, 2000),
          hasOriginValidation: true,
          timestamp: Date.now(),
        });
      }, true);

      var _origOnMessage = Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
      var _origOnMessageSetter = _origOnMessage ? _origOnMessage.set : null;
      if (_origOnMessageSetter) {
        Object.defineProperty(window, 'onmessage', {
          set: function(handler) {
            if (typeof handler === 'function') {
              window.__postmessage_audit.listeners.push({
                type: 'message',
                listenerSource: handler.toString().substring(0, 2000),
                registrationStack: new Error().stack ? new Error().stack.substring(0, 2000) : '',
                registeredAt: Date.now(),
                pageUrl: window.location.href,
                via: 'onmessage',
              });
            }
            _origOnMessageSetter.call(window, handler);
          },
          get: function() { return _origOnMessage ? _origOnMessage.get.call(window) : null; },
          configurable: true,
        });
      }

      console.log('[postMessage Auditor] Monitoring activated — ' + window.location.href);
    })();
    """


def _extract_origin_checks(listener_source: str) -> dict:
    checks = {}
    has_origin_check = False
    weak_check = False

    origin_patterns = [
        (r"event\.origin", "references_origin"),
        (r"e\.origin", "references_origin_short"),
        (r"messageEvent\.origin", "references_full_name"),
        (r"if\s*\(.*origin", "has_origin_conditional"),
    ]

    for pat, name in origin_patterns:
        if re.search(pat, listener_source, re.IGNORECASE):
            has_origin_check = True
            checks[name] = True

    for pat, vuln_type, desc in WEAK_ORIGIN_PATTERNS:
        if re.search(pat, listener_source, re.IGNORECASE):
            weak_check = True
            checks[vuln_type] = True
            checks[f"{vuln_type}_desc"] = desc

    if re.search(r"event\.origin\s*!==?\s*", listener_source) or re.search(r"event\.origin\s*===?\s*", listener_source):
        checks["origin_strict_check"] = True
    elif not has_origin_check:
        checks["no_origin_check"] = True

    return {
        "has_origin_check": has_origin_check,
        "weak_origin_check": weak_check,
        "details": checks,
    }


def _parse_audit_results(audit_data: dict) -> list:
    findings = []

    listeners = audit_data.get("listeners", [])
    senders = audit_data.get("senders", [])
    messages = audit_data.get("messages", [])

    if not listeners:
        findings.append({
            "type": "no_listener_found",
            "severity": "INFO",
            "description": FINDING_TEMPLATES["no_listener_found"]["description"],
            "details": "No addEventListener('message', ...) or window.onmessage registered",
        })

    for lidx, listener in enumerate(listeners):
        source = listener.get("listenerSource", "")
        origin_analysis = _extract_origin_checks(source)

        finding = {
            "listener_index": lidx,
            "registration_method": listener.get("via", "addEventListener"),
            "has_origin_check": origin_analysis["has_origin_check"],
            "weak_origin_check": origin_analysis["weak_origin_check"],
            "origin_check_details": origin_analysis["details"],
            "listener_source_preview": source[:500],
            "registration_stack": listener.get("registrationStack", "")[:500],
            "page_url": listener.get("pageUrl", ""),
            "registered_at_epoch": listener.get("registeredAt", 0),
        }

        if not origin_analysis["has_origin_check"]:
            finding.update({
                "vulnerable": True,
                "vuln_type": "missing_origin_validation",
                "severity": "HIGH",
                "exploit_scenario": "Any origin can send postMessage to this listener — no origin validation",
            })
        elif origin_analysis["weak_origin_check"]:
            finding.update({
                "vulnerable": True,
                "vuln_type": "weak_origin_validation",
                "severity": "MEDIUM",
                "exploit_scenario": "Origin check is present but uses weak comparison that may be bypassed",
            })
        else:
            finding.update({
                "vulnerable": False,
                "vuln_type": "",
                "severity": "INFO",
                "exploit_scenario": "Origin appears to be checked with strict comparison",
            })

        findings.append(finding)

    for sidx, sender in enumerate(senders):
        target_origin = sender.get("targetOrigin", "")
        if target_origin == "*":
            findings.append({
                "sender_index": sidx,
                "vulnerable": True,
                "vuln_type": "wildcard_target_origin",
                "severity": "MEDIUM",
                "target_origin": "*",
                "message_preview": sender.get("message", "")[:500],
                "page_url": sender.get("pageUrl", ""),
                "exploit_scenario": "postMessage with targetOrigin='*' — any origin can receive this message",
            })

    return findings


def run_audit(url: str, context: Optional[str], timeout: int, dry_run: bool) -> list:
    if dry_run:
        return [{
            "vulnerable": False,
            "type": "dry_run",
            "severity": "INFO",
            "description": f"Would audit postMessage on {url}",
            "context": context,
            "dry_run": True,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.stderr.write("[!] Playwright not installed. Install with: pip install playwright && playwright install chromium\n")
        return [{
            "vulnerable": False,
            "type": "error",
            "severity": "ERROR",
            "description": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]

    findings = []
    audit_data = {}

    with sync_playwright() as p:
        sys.stderr.write("[*] Launching headless Chromium...\n")
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        try:
            sys.stderr.write(f"[*] Navigating to {url}\n")
            page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")

            sys.stderr.write("[*] Injecting postMessage audit script...\n")
            page.evaluate(_inject_audit_script())

            sys.stderr.write("[*] Waiting for messages to propagate (2s)...\n")
            time.sleep(2)

            page.evaluate("""
                window.postMessage({ __audit_test: true, timestamp: Date.now() }, '*');
            """)
            time.sleep(1)

            audit_data = page.evaluate("() => window.__postmessage_audit || {}")
            sys.stderr.write(f"[*] Captured {len(audit_data.get('listeners', []))} listener(s), "
                             f"{len(audit_data.get('senders', []))} sender(s)\n")

            all_scripts = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => ({ src: s.src, type: s.type, async: s.async, defer: s.defer }));
            }""")

            all_inline_scripts = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script:not([src])'))
                    .map(s => s.textContent.substring(0, 2000));
            }""")

            found_in_scripts = []
            for isrc in all_inline_scripts:
                if "postMessage" in isrc or "addEventListener" in isrc:
                    found_in_scripts.append({"type": "inline", "content_preview": isrc[:500]})

            final_audit = {
                "url": url,
                "listeners": audit_data.get("listeners", []),
                "senders": audit_data.get("senders", []),
                "messages": audit_data.get("messages", []),
                "external_scripts": all_scripts,
                "related_inline_scripts": found_in_scripts,
            }

        except Exception as e:
            sys.stderr.write(f"[!] Browser error: {e}\n")
            final_audit = {
                "url": url,
                "error": str(e),
                "listeners": [],
                "senders": [],
                "messages": [],
            }
        finally:
            browser.close()

    findings = _parse_audit_results(final_audit)

    for f in findings:
        f["target_url"] = url
        f["context"] = context
        f["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if not findings:
        findings.append({
            "vulnerable": False,
            "type": "no_action",
            "severity": "INFO",
            "description": "No postMessage senders or listeners detected on the page",
            "target_url": url,
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="postMessage Auditor — audit postMessage communication on a page using Playwright",
    )
    parser.add_argument("--url", required=True, help="URL of the page to audit")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--timeout", type=int, default=30, help="Page navigation timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be tested without launching browser")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] postMessage Auditor\n")
    sys.stderr.write(f"[*] URL: {args.url}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    findings = run_audit(args.url, args.context, args.timeout, args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    sys.stderr.write(f"\n[*] Findings written to {outfile}\n")

    vuln_count = sum(1 for f in findings if f.get("vulnerable"))
    sys.stderr.write(f"[*] Summary: {vuln_count}/{len(findings)} findings flagged as vulnerable\n")

    for f in findings:
        if f.get("vulnerable"):
            sys.stderr.write(f"  [{f['severity']}] {f.get('vuln_type', 'unknown')}: {f.get('exploit_scenario', '')}\n")

    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()