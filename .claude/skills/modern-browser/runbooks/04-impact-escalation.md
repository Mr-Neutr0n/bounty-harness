# Modern Browser — Impact Escalation

## Purpose
Advanced browser exploitation: prototype pollution detection, DOM clobbering, postMessage exploitation via wildcard origins, CSRF token extraction, JWT/auth token extraction from JS context, Service Worker registration abuse.

## Required Variables
- $TARGET_URL: target web application URL
- $OUTDIR: output directory
- $EVIDENCE_DIR: evidence directory

## Commands

### 04.1 — Prototype pollution, DOM clobbering, postMessage exploit, token extraction
```bash
mkdir -p $OUTDIR/impact $EVIDENCE_DIR

python3 << 'PYEOF'
import asyncio, json, os, re
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

        proto_result = await page.evaluate("""() => {
            let findings = [];
            try {
                Object.prototype.polluted = true;
                let leaked = {};
                leaked['__polluted_test__'] = true;
                if ({}.polluted === true) {
                    findings.push({type: 'prototype_pollution', detail: 'Object.prototype directly writable and leaks to new objects'});
                }
                delete Object.prototype.polluted;
            } catch(e) { findings.push({type: 'prototype_pollution', detail: 'Object.prototype frozen or error: '+e.message.slice(0,80)}); }

            try {
                let form = document.createElement('form');
                form.innerHTML = '<input name=id value=1><img name=nextId>';
                document.body.appendChild(form);
                if (form.nextId) { findings.push({type: 'dom_clobbering', detail: 'forms.images can clobber form.nextId'}); }
                let anchor = document.createElement('a');
                anchor.id = 'testclobber';
                document.body.appendChild(anchor);
                if (window.testclobber) { findings.push({type: 'dom_clobbering', detail: 'named element clobbers window property'}); }
                anchor.remove();
                form.remove();
            } catch(e) {}
            return findings;
        }""")

        pm_exploit = await page.evaluate("""() => {
            return new Promise((resolve) => {
                let results = [];
                let w = window.open('');
                if (!w) { resolve([{type: 'postmessage', detail: 'popup blocked by browser'}]);
                }
                let handler = (e) => {
                    results.push({origin: e.origin, data_len: String(e.data).length, trusted: e.isTrusted});
                    if (results.length >= 3 || Date.now() - start > 5000) {
                        window.removeEventListener('message', handler);
                        resolve(results);
                    }
                };
                window.addEventListener('message', handler);
                let start = Date.now();
                setTimeout(() => resolve(results), 5000);
                try {
                    let ifr = document.createElement('iframe');
                    ifr.src = TARGET;
                    ifr.style.display = 'none';
                    ifr.onload = () => { ifr.contentWindow.postMessage('test_probe', '*'); };
                    document.body.appendChild(ifr);
                } catch(e) {}
            });
        }""")

        csrf_tokens = await page.evaluate("""() => {
            let tokens = [];
            document.querySelectorAll('input[type=hidden]').forEach(el => {
                let name = (el.name||'').toLowerCase();
                if (/(csrf|xsrf|_token|nonce|authenticity)/i.test(name)) {
                    tokens.push({name: el.name, value_len: el.value.length, value_preview: el.value.slice(0,20)});
                }
            });
            let meta = document.querySelector('meta[name=csrf-token], meta[name=csrf-param], meta[name=_csrf]');
            if (meta) tokens.push({name: 'meta:'+meta.getAttribute('name'), value_preview: (meta.getAttribute('content')||'').slice(0,20)});
            return tokens;
        }""")

        auth_tokens = await page.evaluate("""() => {
            let tokens = [];
            const patterns = [/jwt|token|access_token|id_token|apikey|auth/i];
            for (let i = 0; i < localStorage.length; i++) {
                let key = localStorage.key(i);
                if (patterns.some(p => p.test(key))) {
                    tokens.push({source: 'localStorage', key: key, value_len: localStorage.getItem(key).length});
                }
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                let key = sessionStorage.key(i);
                if (patterns.some(p => p.test(key))) {
                    tokens.push({source: 'sessionStorage', key: key, value_len: sessionStorage.getItem(key).length});
                }
            }
            if (document.cookie) {
                document.cookie.split(';').forEach(c => {
                    let [k] = c.trim().split('=');
                    if (patterns.some(p => p.test(k))) tokens.push({source: 'cookie', key: k.trim()});
                });
            }
            return tokens;
        }""")

        sw_result = await page.evaluate("""() => {
            return 'serviceWorker' in navigator ? {supported: true, controller: !!navigator.serviceWorker.controller} : {supported: false};
        }""")

        report = {
            "url": TARGET, "timestamp": ts,
            "prototype_pollution": proto_result,
            "dom_clobbering": [p for p in proto_result if p.get("type")=="dom_clobbering"],
            "postmessage_exploit": pm_exploit,
            "csrf_tokens_found": len(csrf_tokens), "csrf_tokens": csrf_tokens,
            "auth_tokens_exposed": len(auth_tokens), "auth_tokens": auth_tokens,
            "service_worker": sw_result,
        }
        with open(f"{OUTDIR}/impact/escalation_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        await browser.close()

asyncio.run(run())
PYEOF
```

## Detection Signals
- `prototype_pollution[*].detail` includes "directly writable" → full prototype pollution, critical if merges user input
- `dom_clobbering` entries → can bypass type checks, poison config variables (`forms.token`, `window.config`)
- `postmessage_exploit[*].origin` is target domain → self-XSS escalation via iframe postMessage
- `csrf_tokens_found == 0` on authenticated form → CSRF missing, high impact
- `auth_tokens[*].source == "localStorage"` → token persists across sessions, accessible to XSS
- `service_worker.controller == true` → already registered SW, potential persistent exploitation

## Next
├── If prototype pollution writable → try injecting into known merge functions (lodash, jQuery.extend)
├── If auth tokens exposed in localStorage → full account takeover with XSS → document in `05-evidence-collection.md`
├── If CSRF tokens missing on state-changing forms → build CSRF PoC
├── If no escalation path found → run `06-false-positive-filter.md`