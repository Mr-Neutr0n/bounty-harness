# Modern Browser — Evidence Collection

## Purpose
Capture annotated screenshots, HAR-format network logs, console output, network response bodies, DOM snapshots as HTML, and timestamped finding manifests for report generation.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 05.1 — Full-page screenshot, HAR capture, console log, DOM snapshot
```bash
mkdir -p $OUTDIR/evidence $EVIDENCE_DIR/har $EVIDENCE_DIR/console $EVIDENCE_DIR/screenshots

python3 << 'PYEOF'
import asyncio, json, os, re
from datetime import datetime, timezone
from playwright.async_api import async_playwright

TARGET = os.environ["TARGET_URL"]
OUTDIR = os.environ["OUTDIR"]
EVDIR  = os.environ["EVIDENCE_DIR"]

async def run():
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    har_entries = []
    console_lines = []
    network_bodies = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(record_har_path=f"{EVDIR}/har/traffic_{ts}.har")
        page = await context.new_page()

        page.on("console", lambda msg: console_lines.append(f"[{msg.type}] {msg.text}"))

        page.on("response", lambda resp: asyncio.ensure_future(
            (lambda r: network_bodies.append({
                "url": r.url, "status": r.status,
                "content_type": r.headers.get("content-type","")[:100],
                "body_len": len(r.body())
            }))(resp)
        ) if resp.status < 400 and "json" in (resp.headers.get("content-type","") or "") and len(resp.body()) < 50000 else None))

        await page.goto(TARGET, wait_until="networkidle", timeout=30000)

        await page.screenshot(path=f"{EVDIR}/screenshots/fullpage_{ts}.png", full_page=True)
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.screenshot(path=f"{EVDIR}/screenshots/mobile_{ts}.png", full_page=True)
        await page.set_viewport_size({"width": 1280, "height": 720})

        js_context = await page.evaluate("""() => {
            return JSON.stringify({
                url: location.href, origin: location.origin, referrer: document.referrer,
                userAgent: navigator.userAgent, platform: navigator.platform,
                screenW: screen.width, screenH: screen.height,
                innerW: window.innerWidth, innerH: window.innerHeight,
                hasOpener: window.opener !== null,
                cookieEnabled: navigator.cookieEnabled,
            });
        }""")

        dom_html = await page.content()
        with open(f"{EVDIR}/dom_snapshot_{ts}.html", "w") as f:
            f.write(dom_html)

        with open(f"{EVDIR}/console/console_{ts}.log", "w") as f:
            for line in console_lines:
                f.write(line + "\n")

        await page.screenshot(path=f"{EVDIR}/screenshots/viewport_{ts}.png", full_page=False)

        close_result = await context.close()

    with open(f"{OUTDIR}/evidence/manifest_{ts}.json", "w") as f:
        manifest = {
            "target": TARGET, "timestamp": ts,
            "artifacts": {
                "har": f"{EVDIR}/har/traffic_{ts}.har",
                "fullpage_screenshot": f"{EVDIR}/screenshots/fullpage_{ts}.png",
                "mobile_screenshot": f"{EVDIR}/screenshots/mobile_{ts}.png",
                "viewport_screenshot": f"{EVDIR}/screenshots/viewport_{ts}.png",
                "dom_snapshot": f"{EVDIR}/dom_snapshot_{ts}.html",
                "console_log": f"{EVDIR}/console/console_{ts}.log",
            },
            "js_context": json.loads(js_context) if js_context else {},
            "network_bodies_captured": len(network_bodies),
            "console_line_count": len(console_lines),
            "network_bodies": network_bodies[:50],
        }
        json.dump(manifest, f, indent=2)
        print(json.dumps(manifest, indent=2))

    print(f"\n[DONE] Evidence manifest: {OUTDIR}/evidence/manifest_{ts}.json")

asyncio.run(run())
PYEOF
```

### 05.2 — Verify artifacts on disk
```bash
echo "=== Collected Evidence ==="
ls -lh $EVIDENCE_DIR/screenshots/
ls -lh $EVIDENCE_DIR/har/
ls -lh $EVIDENCE_DIR/console/
echo ""
echo "Manifest:"
cat $OUTDIR/evidence/manifest_*.json 2>/dev/null | python3 -m json.tool | head -30
```

## Detection Signals
- HAR file > 100KB → substantial traffic captured, rich for analysis
- `console_line_count > 20` → active logging, may expose debug info or secrets
- `dom_snapshot_*.html` contains inline credentials or debug endpoints → information disclosure
- Screenshot shows authenticated dashboard → session was active during capture
- `network_bodies` contain JSON with `token`, `secret`, or `password` fields → leaked credentials

## Next
├── Evidence collected → proceed to `06-false-positive-filter.md` to validate findings
├── If HAR file empty or 404 on TARGET → check connectivity, verify $TARGET_URL is reachable
├── If authenticated screenshots needed → import cookies via `setup-browser-cookies` skill first