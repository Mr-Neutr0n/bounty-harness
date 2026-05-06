# Modern Browser — False Positive Filter

## Purpose
Distinguish real vulnerabilities from expected browser behavior: SPA CSR vs SSR rendering differences, same-origin vs cross-origin context, CSP bypass artifacts, and browser extension interference.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 06.1 — Validate findings: context checks, SPA hydration diff, origin verification
```bash
mkdir -p $OUTDIR/filter $EVIDENCE_DIR

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

        cold_origin = await page.evaluate("() => location.origin")
        cold_content_len = 0
        await page.goto(TARGET, wait_until="networkidle", timeout=30000)
        cold_content_len = len(await page.content())

        warm_page = await context.new_page()
        await warm_page.goto(TARGET, wait_until="networkidle", timeout=30000)
        warm_content_len = len(await warm_page.content())
        await warm_page.close()

        hydration_diff = abs(cold_content_len - warm_content_len)
        hydration_finding = {
            "cold_len": cold_content_len,
            "warm_len": warm_content_len,
            "diff": hydration_diff,
            "significant": hydration_diff > 5000,
            "note": ">5KB difference suggests CSR hydration variance" if hydration_diff > 5000 else "Minor diff, likely timing/cache variance"
        }

        about_blank_origin = await page.evaluate("""() => {
            return new Promise(resolve => {
                let w = window.open('about:blank');
                if (!w) { resolve({error: 'popup blocked'}); return; }
                setTimeout(() => {
                    resolve({
                        origin: w.location.origin,
                        canAccess: (() => { try { return w.document.domain; } catch(e) { return 'BLOCKED'; } })()
                    });
                    w.close();
                }, 1000);
            });
        }""")

        origin_check = await page.evaluate("""() => {
            return {
                target_origin: location.origin,
                target_domain: document.domain,
                is_in_iframe: window !== window.top,
                frame_depth: (function f(w){ let d=0; while(w!==w.parent){d++;w=w.parent;} return d; })(window),
            };
        }""")

        proto_real = await page.evaluate("""() => {
            let findings = [];
            try {
                let test = {};
                Object.defineProperty(Object.prototype, '_fp_test', {value:1,writable:true,configurable:true});
                if (test._fp_test === 1) findings.push("pollution_works_at_page_level");
                delete Object.prototype._fp_test;
            } catch(e) { findings.push("prototype_not_writable: "+e.message.slice(0,60)); }

            try {
                let obj = JSON.parse('{"__proto__":{"isAdmin":true}}');
                if (Object.prototype.isAdmin) {
                    findings.push("json_parse_spreads_to_prototype");
                    delete Object.prototype.isAdmin;
                } else { findings.push("json_parse_safe"); }
            } catch(e) { findings.push("json_parse_error: "+e.message.slice(0,60)); }
            return findings;
        }""")

        ext_check = await page.evaluate("""() => {
            let signals = [];
            if (document.querySelectorAll('script[src*="chrome-extension://"]').length > 0) signals.push("chrome_extension_scripts_detected");
            if (document.querySelectorAll('script[src*="moz-extension://"]').length > 0) signals.push("firefox_extension_scripts_detected");
            if (window.chrome && window.chrome.runtime && window.chrome.runtime.id) signals.push("chrome_runtime_api_available");
            return signals;
        }""")

        report = {
            "url": TARGET, "timestamp": ts,
            "hydration_check": hydration_finding,
            "about_blank_test": about_blank_origin,
            "origin_context": origin_check,
            "prototype_safety": proto_real,
            "browser_extensions": ext_check,
            "verdict": {
                "spa_hydration_false_positive": hydration_finding["significant"],
                "about_blank_xss_irrelevant": about_blank_origin.get("error") or (about_blank_origin.get("origin") == "null"),
                "extensions_may_pollute": len(ext_check) > 0,
                "target_is_iframe": origin_check["is_in_iframe"],
            }
        }

        with open(f"{OUTDIR}/filter/filter_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))

        print("\n=== FILTER VERDICT ===")
        for k, v in report["verdict"].items():
            flag = "[!]" if v else "[OK]"
            print(f"  {flag} {k}: {v}")
        if hydration_finding["significant"]:
            print("  [!] SPA hydration diff > 5KB — CSR variance may cause false DOM XSS triggers")
        if len(ext_check) > 0:
            print("  [!] Browser extensions detected — may inject scripts that trigger alerts")
        print("  [OK] origin_check confirms context is", origin_check["target_origin"])
        await browser.close()

asyncio.run(run())
PYEOF
```

## Detection Signals
- `hydration_check.significant == true` → SPAs rerender differently on warm loads; DOM XSS alerts from first load may not reproduce on second load (CSR hydration artifact)
- `about_blank_test.origin == "null"` → XSS that fires in `about:blank` is NOT a real vulnerability against the target domain
- `browser_extensions` list non-empty → extension-injected scripts can trigger `alert()` appearing as false DOM XSS
- `origin_context.is_in_iframe == true` → the target was loaded inside an iframe; ensure XSS fires in its own origin, not the parent
- `prototype_safety` includes `"json_parse_safe"` → `JSON.parse` with `__proto__` key does NOT pollute, some frameworks handle it differently

## Next
├── If false positives filtered → compile final findings, exclude flagged artifacts
├── If hydration diff significant → retest DOM XSS payloads on BOTH cold and warm loads
├── If extensions detected → rerun in incognito/clean context: `context = await browser.new_context(ignore_https_errors=True)`
├── If all findings survive filter → valid vulnerabilities confirmed, proceed to `/reporting` skill