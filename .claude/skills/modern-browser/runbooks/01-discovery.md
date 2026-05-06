# Modern Browser — Discovery

## Purpose
Launch Chromium via Playwright, navigate to the target, capture page structure (title, links, forms, inputs, JS files, cookies, localStorage, sessionStorage) and an initial full-page screenshot.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 01.1 — Install Chromium browser binary
```bash
python3 -m playwright install chromium
```

### 01.2 — Launch browser, navigate, capture full discovery data
```bash
mkdir -p $OUTDIR/discovery $EVIDENCE_DIR

python3 << 'PYEOF'
import asyncio, json, os
from datetime import datetime, timezone
from playwright.async_api import async_playwright

TARGET = os.environ["TARGET_URL"]
OUTDIR = os.environ["OUTDIR"]
EVDIR  = os.environ["EVIDENCE_DIR"]

async def run():
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto(TARGET, wait_until="networkidle", timeout=30000)
        title = await page.title()
        links = await page.eval_on_selector_all("a[href]", "els => els.map(e => ({text: e.textContent.trim().slice(0,120), href: e.href}))")
        forms = await page.eval_on_selector_all("form", """els => els.map(f => ({
            action: f.action, method: f.method, id: f.id,
            inputs: [...f.querySelectorAll('input,textarea,select')].map(i => ({name:i.name, type:i.type||i.tagName, id:i.id}))
        }))""")
        inputs = await page.eval_on_selector_all("input:not(form input), textarea:not(form textarea)", "els => els.map(e => ({name:e.name, type:e.type, id:e.id}))")
        js_files = await page.eval_on_selector_all("script[src]", "els => els.map(s => s.src)")
        cookies = await context.cookies()
        ls_data = await page.evaluate("() => JSON.stringify(localStorage)")
        ss_data = await page.evaluate("() => JSON.stringify(sessionStorage)")
        await page.screenshot(path=f"{EVDIR}/discovery_{ts}.png", full_page=True)

        report = {
            "url": TARGET, "title": title, "timestamp": ts,
            "link_count": len(links), "links": links,
            "form_count": len(forms), "forms": forms,
            "standalone_input_count": len(inputs), "standalone_inputs": inputs,
            "js_file_count": len(js_files), "js_files": js_files,
            "cookies": cookies,
            "localStorage": json.loads(ls_data) if ls_data else {},
            "sessionStorage": json.loads(ss_data) if ss_data else {},
        }
        with open(f"{OUTDIR}/discovery/page_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        await browser.close()

asyncio.run(run())
PYEOF
```

## Detection Signals
- `form_count > 0` → interactive attack surface available
- `js_file_count > 5` → rich JS footprint worth auditing
- `cookies` missing `HttpOnly` or `Secure` → session hijack risk
- `localStorage` or `sessionStorage` contain `token`, `jwt`, `apiKey` → sensitive data exposure
- `link_count` > 200 → large crawl surface

## Next
├── If forms detected → run `02-probe.md` for interaction fuzzing
├── If localStorage/sessionStorage populated → note for `04-impact-escalation.md`
├── If no JS or empty page → target may be SSR-only or blocked; try with `headless=False`