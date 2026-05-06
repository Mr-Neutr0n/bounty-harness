# Hypothesis Templates

Common coverage gap patterns and their corresponding hypothesis formulations.

## Gap Pattern Taxonomy

| Gap Category | Typical Pattern | Example Gap | Suggested Hypothesis |
| --- | --- | --- | --- |
| **Missing HTTP header check** | Security-critical headers not tested | `Strict-Transport-Security` header absence | Add HSTS header presence test with max-age validation |
| **Missing cookie attribute** | Cookie flags not validated | `HttpOnly`, `Secure`, `SameSite` missing | Add session cookie attribute testing to detect missing security flags |
| **Missing input validation** | User-supplied input not sanitized in a context | Open redirect via `redirect_uri` param | Add open redirect probe to detect user-supplied redirect URLs in auth flows |
| **Missing auth check** | Authorization bypass not tested | IDOR on user-owned resources | Add IDOR detection by iterating resource IDs across sessions |
| **Missing rate limit** | No brute-force protection check | Login endpoint without lockout | Add rate-limit probe with concurrent login attempts over 10s window |
| **Missing CORS config** | CORS headers not validated | Wildcard `Access-Control-Allow-Origin` with credentials | Add CORS misconfiguration test: origin reflection + credential mode |
| **Missing CSP directive** | CSP header gaps | `script-src 'unsafe-inline'` allowed | Add CSP bypass detection for missing nonce/hash requirements |
| **Missing TLS check** | TLS version/cipher not tested | TLS 1.0/1.1 still accepted | Add TLS minimum version enforcement test (require >=1.2) |
| **Missing error handling** | Verbose error disclosure | Stack traces in 500 responses | Add error message leak detection with debug-mode patterns |
| **Missing file upload** | Upload sanitization not tested | SVG upload executes JS | Add SVG+JS payload upload to detect missing Content-Disposition or sandbox |
| **Missing GraphQL** | GraphQL introspection not tested | Introspection enabled in production | Add GraphQL introspection probe and field-suggestion leak test |
| **Missing JWT** | JWT validation gaps | `alg=none` accepted | Add JWT algorithm confusion test (none, HS256 vs RS256) |
| **Missing SSRF** | Internal service probing | Metadata endpoint not blocked | Add AWS/GCP metadata endpoint probe with IP format bypasses |
| **Missing SQLi** | Blind SQL injection not tested | Time-based blind via `sleep()` | Add time-based blind SQLi probe with multi-second delay calibration |
| **Missing XSS** | DOM XSS via `postMessage` | Unvalidated `postMessage` origin | Add DOM XSS probe for missing origin checks on message event listeners |

## Hypothesis Formulation Rules

1. **Specificity**: Name the exact standard/technique being added
2. **Measurability**: Include what constitutes a positive detection signal
3. **Scope**: Reference the skill that will receive the improvement
4. **Priority**: Tag as high or critical based on severity of undetected vulnerability

### Template String

```
{STANDARD}: Add {TECHNIQUE} detection to test for {VULNERABILITY_CLASS} in {CONTEXT}
```

### Examples

```
WSTG-CRYP-03: Add HSTS header validation to test for missing Strict-Transport-Security with includeSubDomains
WSTG-SESS-02: Add cookie attribute testing to detect missing HttpOnly/Secure/SameSite flags on session tokens
WSTG-AUTHN-05: Add credential brute-force detection with rate-limit probing on login endpoints
WSTG-ATHZ-04: Add IDOR detection by cross-referencing resource ownership across authenticated sessions
```

## Gap-to-Hypothesis Mapping

| Gap ID Pattern | Skill Impacted | Difficulty | Typical Requires |
| --- | --- | --- | --- |
| `WSTG-CRYP-*` | `recon` or `http-protocol` | easy | `curl`, `openssl` |
| `WSTG-SESS-*` | `auth` | easy | `curl` |
| `WSTG-AUTHN-*` | `auth` | medium | `curl`, `ffuf` |
| `WSTG-ATHZ-*` | `auth` or `api` | hard | `python3:session-management`, `curl` |
| `WSTG-INPV-*` | `xss` | medium | `dalfox`, `python3:payload-generation` |
| `WSTG-CONF-*` | `recon` or `cors-csrf` | easy | `curl`, `httpx` |
| `ASVS-V4-*` | varies | medium | `curl`, `python3:analysis` |
| `CWE-*` | varies | hard | varies |