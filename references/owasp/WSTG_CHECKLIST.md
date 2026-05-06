# OWASP Web Security Testing Guide (WSTG v4.2) — Condensed Checklist

Check off each test as you complete it. Each ID maps directly to the OWASP WSTG v4.2 documentation.

---

## INFO — Information Gathering

- [ ] **WSTG-INFO-01** — Conduct Search Engine Discovery Reconnaissance
  - [ ] Google dorks (site:TARGET, inurl:TARGET, intitle:TARGET)
  - [ ] GitHub dorks (org:TARGET, TOKEN, password, secret)
  - [ ] Shodan search (org:TARGET, hostname:TARGET)
- [ ] **WSTG-INFO-02** — Fingerprint Web Server
  - [ ] Server header (curl -sI TARGET | grep -i server)
  - [ ] Cookie names (ASPSESSIONID, JSESSIONID, PHPSESSID, CFID)
  - [ ] File extensions (.php, .aspx, .jsp, .py, .rb)
  - [ ] Wappalyzer / WhatWeb / httpx -tech-detect
- [ ] **WSTG-INFO-03** — Review Webserver Metafiles
  - [ ] /robots.txt — disallowed paths may expose admin panels
  - [ ] /sitemap.xml — full site structure
  - [ ] /security.txt — RFC 9116 security contact
  - [ ] /humans.txt — may leak dev team names
- [ ] **WSTG-INFO-04** — Enumerate Applications on Webserver
  - [ ] Virtual host enumeration (ffuf -w vhosts.txt -u TARGET -H 'Host: FUZZ.TARGET')
  - [ ] Reverse proxy / load balancer detection
  - [ ] CDN origin IP discovery (dnsx -a, historical DNS)
- [ ] **WSTG-INFO-05** — Review Webpage Content for Information Leakage
  - [ ] HTML comments (<!-- dev note -->, <!-- TODO -->, <!-- password -->)
  - [ ] JavaScript comments (// API key: xxx, // TODO: remove before prod)
  - [ ] Hidden form fields (<input type="hidden" name="role" value="admin">)
  - [ ] Client-side source maps (.js.map files)
- [ ] **WSTG-INFO-06** — Identify Application Entry Points
  - [ ] All forms, login pages, registration pages
  - [ ] All API endpoints (gau + httpx, katana crawl)
  - [ ] File upload endpoints
  - [ ] WebSocket endpoints
  - [ ] GraphQL endpoints
- [ ] **WSTG-INFO-07** — Map Execution Paths Through Application
  - [ ] Crawl the entire site (katana -js-crawl)
  - [ ] Spider all links and forms
  - [ ] Map multi-step flows (checkout, registration, password reset)
- [ ] **WSTG-INFO-08** — Fingerprint Web Application Framework
  - [ ] Framework-specific paths (/wp-admin, /rails/info, /django/admin)
  - [ ] Framework-specific headers (X-Powered-By, X-Generator, X-Drupal-Cache)
  - [ ] Framework-specific cookies (laravel_session, CakeCookie)
- [ ] **WSTG-INFO-09** — Fingerprint Web Application
  - [ ] Version-specific URLs (/version.txt, /CHANGELOG.md, /README.md)
  - [ ] Default favicon hashes (nuclei -t http/technologies)
  - [ ] Error page stack traces (framework + version)
- [ ] **WSTG-INFO-10** — Map Application Architecture
  - [ ] Identify frontend/backend separation
  - [ ] Identify third-party services (payment gateway, CDN, analytics)
  - [ ] Identify microservice boundaries (different subdomains, different APIs)

---

## CONFIG — Configuration and Deployment Management Testing

- [ ] **WSTG-CONF-01** — Test Network Infrastructure Configuration
  - [ ] Check for internal IP leaks in headers (X-Forwarded-For, X-Real-IP)
  - [ ] Check DNS zone transfer (dig axfr TARGET @ns1.TARGET)
  - [ ] Check for exposed admin interfaces on non-standard ports
- [ ] **WSTG-CONF-02** — Test Application Platform Configuration
  - [ ] Default credentials for framework/CMS
  - [ ] Sample applications still installed (/examples, /test, /demo)
  - [ ] Debug mode enabled (Django DEBUG=True, Rails raise exceptions)
- [ ] **WSTG-CONF-03** — Test File Extensions Handling
  - [ ] .php → .php5, .phtml, .pht, .shtml, .phar, .phps
  - [ ] .asp → .aspx, .asmx, .ashx, .asa, .cer
  - [ ] .jsp → .jspx, .jspf, .jsv
  - [ ] Extension stripping via null byte (%00, %2500)
  - [ ] Double extensions (file.php.jpg, file.jpg.php)
- [ ] **WSTG-CONF-04** — Review Backup and Unreferenced Files
  - [ ] .bak, .backup, .old, .orig, .save, .swp, ~ files
  - [ ] .git/ exposed (/.git/HEAD, /.git/config)
  - [ ] .svn/ exposed (/.svn/entries)
  - [ ] .DS_Store exposed
  - [ ] Backup archives (.tar.gz, .zip, .sql, .7z)
- [ ] **WSTG-CONF-05** — Enumerate Infrastructure and Admin Interfaces
  - [ ] /admin, /administrator, /manager, /console
  - [ ] /phpmyadmin, /phpPgAdmin, /mysql, /db
  - [ ] /jenkins, /grafana, /kibana, /prometheus (no auth)
  - [ ] /actuator (Spring Boot Actuator endpoints)
  - [ ] /swagger-ui.html, /api-docs, /graphql
- [ ] **WSTG-CONF-06** — Test HTTP Methods
  - [ ] OPTIONS method — what methods are allowed?
  - [ ] TRACE method (XST — Cross-Site Tracing)
  - [ ] PUT method (arbitrary file upload)
  - [ ] DELETE method (arbitrary resource deletion)
  - [ ] PATCH method (partial resource modification)
  - [ ] Method override headers (X-HTTP-Method-Override)
- [ ] **WSTG-CONF-07** — Test HTTP Strict Transport Security (HSTS)
  - [ ] Strict-Transport-Security header present?
  - [ ] max-age value (should be >= 31536000 for preload)
  - [ ] includeSubDomains directive present?
  - [ ] preload directive present?
  - [ ] HTTP → HTTPS redirect working?
- [ ] **WSTG-CONF-08** — Test RIA Cross Domain Policy
  - [ ] /crossdomain.xml (Flash cross-domain policy — deprecated but still present)
  - [ ] /clientaccesspolicy.xml (Silverlight)
  - [ ] Wildcard in crossdomain.xml (allow-access-from domain="*")
- [ ] **WSTG-CONF-09** — Test File Permissions
  - [ ] Can you access /etc/passwd, /etc/shadow?
  - [ ] Can you access .env, .htaccess, web.config?
- [ ] **WSTG-CONF-10** — Test for Subdomain Takeover
  - [ ] DNS records pointing to third-party services (AWS, Azure, GitHub, Heroku)
  - [ ] CNAME records for unclaimed resources
  - [ ] NS records for unregistered name servers
- [ ] **WSTG-CONF-11** — Test Cloud Storage (S3, GCS, Azure Blob)
  - [ ] Open/public S3 buckets (bucketname.s3.amazonaws.com)
  - [ ] GCS bucket enumerations
  - [ ] Azure blob storage (blob.core.windows.net)

---

## IDNT — Identity Management Testing

- [ ] **WSTG-IDNT-01** — Test Role Definitions
  - [ ] Map all roles (user, admin, moderator, superadmin, editor, viewer)
  - [ ] Check for privilege separation issues
  - [ ] Try to escalate from one role to another
- [ ] **WSTG-IDNT-02** — Test User Registration Process
  - [ ] Can you register with an existing username (duplicate account)?
  - [ ] Can you register with admin / administrator / root as username?
  - [ ] Can you register with no password / weak password?
  - [ ] Is email verification required? Can you skip it?
  - [ ] Can you register with + aliases (user+admin@TARGET)?
- [ ] **WSTG-IDNT-03** — Test Account Provisioning Process
  - [ ] Can you self-assign roles during registration?
  - [ ] Can you modify role via parameter manipulation (role=admin)?
  - [ ] Can you create accounts with admin privileges?
- [ ] **WSTG-IDNT-04** — Testing for Account Enumeration
  - [ ] Login error messages: "User not found" vs "Wrong password"
  - [ ] Registration: "Email already registered"
  - [ ] Password reset: "No account with that email" vs "Reset email sent"
  - [ ] Timing differences between valid and invalid usernames
- [ ] **WSTG-IDNT-05** — Testing for Weak Username Policy
  - [ ] Can usernames be enumerated from profile URLs (/user/1, /user/2)?
  - [ ] Are sequential user IDs exposed?

---

## ATHN — Authentication Testing

- [ ] **WSTG-ATHN-01** — Testing for Credentials Transported over Unencrypted Channel
  - [ ] Login form submits over HTTP?
  - [ ] POST to HTTPS from HTTP page (mixed content)?
- [ ] **WSTG-ATHN-02** — Testing for Default Credentials
  - [ ] admin:admin, admin:password, root:root, user:user, guest:guest
  - [ ] Framework default creds (tomcat:tomcat, jboss:jboss, jenkins:jenkins)
- [ ] **WSTG-ATHN-03** — Testing for Weak Lock Out Mechanism
  - [ ] Can you brute-force with no lockout?
  - [ ] Does lockout reset after timeout?
  - [ ] Can you bypass lockout via race condition?
  - [ ] Can you bypass lockout via IP rotation (X-Forwarded-For)?
- [ ] **WSTG-ATHN-04** — Testing for Bypassing Authentication Schema
  - [ ] Direct page access without login (/admin, /dashboard)
  - [ ] Parameter manipulation (authenticated=true, login=true)
  - [ ] SQL injection in login form
  - [ ] Session fixation (accept user-provided session ID)
- [ ] **WSTG-ATHN-05** — Testing for Vulnerable Remember Password
  - [ ] "Remember me" cookie — is it guessable?
  - [ ] Is "Remember me" token stored as plaintext?
- [ ] **WSTG-ATHN-06** — Testing for Browser Cache Weaknesses
  - [ ] Is sensitive data cached? (Cache-Control: no-store missing)
  - [ ] Back button after logout shows previous page?
- [ ] **WSTG-ATHN-07** — Testing for Weak Password Policy
  - [ ] Can you set a 1-character password?
  - [ ] Can you set password same as username?
  - [ ] Is password change old password required?
- [ ] **WSTG-ATHN-08** — Testing for Weak Security Question/Answer
  - [ ] Are security questions guessable (mother's maiden name, pet name)?
  - [ ] Can you bypass security questions?
- [ ] **WSTG-ATHN-09** — Testing for Weak Password Reset Functionality
  - [ ] Can you reset password with just email (no additional verification)?
  - [ ] Is reset token predictable (timestamp, base64 email, sequential)?
  - [ ] Is reset token leaked via Referer header?
  - [ ] Can you use the same reset token multiple times?
  - [ ] Can you reset another user's password via IDOR?
- [ ] **WSTG-ATHN-10** — Testing for Weak Alternative Authentication Channels
  - [ ] OAuth redirect_uri validation
  - [ ] OpenID Connect misconfiguration
  - [ ] SAML assertion signing bypass
  - [ ] Social login account linking without verification

---

## AUTH — Authorization Testing

- [ ] **WSTG-AUTH-01** — Testing Directory Traversal / File Include
  - [ ] Path traversal: ../../etc/passwd, ..%2f..%2f..%2fetc%2fpasswd
  - [ ] PHP wrappers: php://filter, php://input, expect://
  - [ ] Null byte injection: ../../etc/passwd%00
  - [ ] Double encoding: ..%252f..%252f..%252f
- [ ] **WSTG-AUTH-02** — Testing for Bypassing Authorization Schema
  - [ ] Direct object reference (user ID in URL: /profile?id=2)
  - [ ] Parameter manipulation (admin=false → admin=true)
  - [ ] Cookie manipulation (role=user → role=admin)
  - [ ] HTTP header manipulation (X-Role: admin)
- [ ] **WSTG-AUTH-03** — Testing for Privilege Escalation
  - [ ] Horizontal: can user A access user B's data?
  - [ ] Vertical: can user access admin functions?
  - [ ] Can you access admin API endpoints as user?
- [ ] **WSTG-AUTH-04** — Testing for Insecure Direct Object References (IDOR)
  - [ ] Sequential IDs in URLs (/user/1, /user/2, /order/100, /order/101)
  - [ ] UUID/GUID — are they guessable from other endpoints?
  - [ ] File IDs — can you access other users' uploaded files?
  - [ ] API endpoints — can you change owner_id parameter?
- [ ] **WSTG-AUTH-05** — Testing for OAuth Weaknesses
  - [ ] redirect_uri open redirect
  - [ ] Missing state parameter (CSRF)
  - [ ] Missing PKCE for native/mobile apps
  - [ ] Authorization code reuse
  - [ ] Client secret exposed in frontend/mobile

---

## SESS — Session Management Testing

- [ ] **WSTG-SESS-01** — Testing for Session Management Schema
  - [ ] Session cookie attributes: HttpOnly, Secure, SameSite, Path, Domain
  - [ ] Session ID entropy — is it random or predictable?
  - [ ] Session ID length — short IDs are brute-forceable
- [ ] **WSTG-SESS-02** — Testing for Cookie Attributes
  - [ ] Secure flag — missing on HTTPS? Cookie sent over HTTP?
  - [ ] HttpOnly flag — missing? Cookie accessible via JavaScript (XSS!)
  - [ ] SameSite flag — missing? Vulnerable to CSRF
  - [ ] Domain attribute — too broad? (.TARGET → subdomains can read)
  - [ ] Path attribute — can sibling paths read?
  - [ ] Cookie prefixes: __Secure- and __Host- used?
- [ ] **WSTG-SESS-03** — Testing for Session Fixation
  - [ ] Can you provide a session ID before login? Does server accept it?
  - [ ] Does server rotate session ID after login? (MUST rotate)
  - [ ] Does server rotate session ID after logout? (MUST rotate)
  - [ ] Does server rotate session ID after privilege change?
- [ ] **WSTG-SESS-04** — Testing for Exposed Session Variables
  - [ ] Session data leaked in URL query string (PHPSESSID=xxx in URL)
  - [ ] Session data leaked in Referer header
  - [ ] Session data in HTML source (hidden fields, JS variables, comments)
- [ ] **WSTG-SESS-05** — Testing for CSRF (Cross-Site Request Forgery)
  - [ ] CSRF token missing on state-changing endpoints
  - [ ] CSRF token not validated (remove token, empty token, different token)
  - [ ] CSRF token not bound to session (use another user's token)
  - [ ] CSRF token predictable (timestamp, sequential, base64 username)
  - [ ] CSRF token leaked via Referer header
  - [ ] SameSite cookie attribute missing
- [ ] **WSTG-SESS-06** — Testing for Logout Functionality
  - [ ] After logout, can you use the back button to access authenticated pages?
  - [ ] After logout, can you reuse the session cookie?
- [ ] **WSTG-SESS-07** — Testing Session Timeout
  - [ ] How long is the session valid? (Should be 15-30 min idle, 4-8h absolute)
  - [ ] Can you extend session indefinitely via activity?
- [ ] **WSTG-SESS-08** — Testing for Session Puzzling
  - [ ] Can you reuse a session variable in a different context?
  - [ ] Can you bypass auth by setting specific session variables?

---

## INPV — Input Validation Testing

- [ ] **WSTG-INPV-01** — Testing for Reflected XSS
  - [ ] Inject into every query parameter
  - [ ] Inject into POST body parameters
  - [ ] Inject into HTTP headers (User-Agent, Referer, Cookie)
  - [ ] Inject into URL path
  - [ ] Test with different contexts (HTML, JS, attribute, URL, CSS)
- [ ] **WSTG-INPV-02** — Testing for Stored XSS
  - [ ] Inject into every input field that stores data (comments, profiles, messages)
  - [ ] Check if output is encoded on display
  - [ ] Check admin panels (admin sees different rendering)
  - [ ] Check PDF/image generators (SVG XSS)
- [ ] **WSTG-INPV-03** — Testing for HTTP Verb Tampering
  - [ ] GET instead of POST for state-changing actions
  - [ ] HEAD for bypassing CSRF token validation
  - [ ] PUT for file upload / resource creation
  - [ ] PATCH for partial modifications
  - [ ] DELETE for resource deletion
- [ ] **WSTG-INPV-04** — Testing for HTTP Parameter Pollution
  - [ ] Duplicate parameters: param=value1&param=value2
  - [ ] Which value does the server use (first, last, both)?
  - [ ] HPP in auth endpoints (bypass validation, inject values)
- [ ] **WSTG-INPV-05** — Testing for SQL Injection
  - [ ] Error-based: inject single quote, double quote, backtick
  - [ ] Boolean-based blind: AND 1=1 vs AND 1=2
  - [ ] Time-based blind: SLEEP(5), BENCHMARK(5000000,MD5(1))
  - [ ] UNION-based: ORDER BY to find columns, UNION SELECT to extract
  - [ ] Out-of-band: xp_dirtree, UTL_HTTP, load_file
  - [ ] Second-order SQLi (stored then executed later)
- [ ] **WSTG-INPV-06** — Testing for LDAP Injection
- [ ] **WSTG-INPV-07** — Testing for ORM Injection
- [ ] **WSTG-INPV-08** — Testing for XML Injection
  - [ ] XXE: <!ENTITY xxe SYSTEM "file:///etc/passwd">
  - [ ] XML Entity Expansion (Billion Laughs)
  - [ ] XPath injection
- [ ] **WSTG-INPV-09** — Testing for SSI Injection
  - [ ] <!--#exec cmd="id" -->
  - [ ] <!--#include virtual="/etc/passwd" -->
- [ ] **WSTG-INPV-10** — Testing for XPath Injection
- [ ] **WSTG-INPV-11** — Testing for IMAP/SMTP Injection
- [ ] **WSTG-INPV-12** — Testing for Code Injection
  - [ ] Command injection: ; whoami, | id, & uname, `id`, $(id), \n whoami
  - [ ] Eval / system / exec in reflected parameters
- [ ] **WSTG-INPV-13** — Testing for Command Injection (focused)
- [ ] **WSTG-INPV-14** — Testing for Buffer Overflow
- [ ] **WSTG-INPV-15** — Testing for Incubated Vulnerability (stored attack chain)
- [ ] **WSTG-INPV-16** — Testing for HTTP Splitting / Smuggling
  - [ ] CRLF injection in headers: %0d%0a
  - [ ] CL.TE smuggling: Content-Length mismatch with Transfer-Encoding
  - [ ] TE.CL smuggling
  - [ ] H2.CL smuggling

---

## ERRH — Error Handling

- [ ] **WSTG-ERRH-01** — Testing for Improper Error Handling
  - [ ] Stack traces exposed (file paths, framework version, DB queries)
  - [ ] Verbose SQL errors (table names, column names, DB type)
  - [ ] Verbose API error messages (internal logic exposed)
  - [ ] Debug mode enabled in production
  - [ ] Custom error pages or raw server errors?
- [ ] **WSTG-ERRH-02** — Testing for Stack Traces
  - [ ] Trigger 500 errors — what information leaks?
  - [ ] Force type errors (string where int expected)
  - [ ] Force out-of-bounds (negative IDs, oversized values)
  - [ ] Force missing auth (access protected endpoint without token)
  - [ ] Force malformed requests (bad JSON, bad XML, invalid encoding)

---

## CRYP — Weak Cryptography

- [ ] **WSTG-CRYP-01** — Testing for Weak Transport Layer Security (TLS)
  - [ ] SSLv2, SSLv3, TLS 1.0, TLS 1.1 supported?
  - [ ] Weak ciphers: NULL, EXPORT, DES, RC4, anon, 3DES, CBC
  - [ ] Certificate validity (expired, self-signed, wrong hostname)
  - [ ] Certificate chain issues (missing intermediates, untrusted root)
  - [ ] HSTS missing or misconfigured
- [ ] **WSTG-CRYP-02** — Testing for Padding Oracle (padding oracle attacks on CBC)
- [ ] **WSTG-CRYP-03** — Testing for Sensitive Information Sent via Unencrypted Channels
  - [ ] Mixed content (HTTP resources on HTTPS page)
  - [ ] Login/Credentials over HTTP
  - [ ] API calls over HTTP (even if page is HTTPS)
  - [ ] WebSocket ws:// instead of wss://
- [ ] **WSTG-CRYP-04** — Testing for Weak Encryption
  - [ ] Base64 used as encryption? (easily decoded)
  - [ ] MD5/SHA1 for password hashing? (fast, crackable)
  - [ ] Weak key generation (predictable, short, hardcoded)
  - [ ] Hardcoded encryption keys in client-side JS
  - [ ] ECB mode (reveals patterns — check with pixelated image ciphertext)

---

## BUSL — Business Logic Testing

- [ ] **WSTG-BUSL-01** — Testing for Business Logic Data Validation
  - [ ] Negative values in quantity/amount fields
  - [ ] Zero values bypassing minimum limits
  - [ ] Extremely large values (overflow, DoS)
  - [ ] String values in numeric fields
  - [ ] Unicode/encoding tricks in business logic fields
- [ ] **WSTG-BUSL-02** — Testing for Ability to Forge Requests
  - [ ] Can you modify prices in hidden fields or cookies?
  - [ ] Can you change order totals client-side?
  - [ ] Can you apply multiple coupons?
  - [ ] Can you reuse one-time codes?
- [ ] **WSTG-BUSL-03** — Testing for Integrity Checks
  - [ ] Are transaction amounts verified server-side?
  - [ ] Is the shopping cart total recalculated server-side on checkout?
  - [ ] Are voucher/coupon validations done server-side?
- [ ] **WSTG-BUSL-04** — Testing for Process Timing
  - [ ] Race conditions in checkout / coupon application
  - [ ] Race conditions in inventory / limited stock
  - [ ] Race conditions in referral / points / reward systems
  - [ ] TOCTOU (Time of Check, Time of Use) vulnerabilities
- [ ] **WSTG-BUSL-05** — Testing for Number of Times a Function Can Be Used Limits
  - [ ] Can you vote multiple times?
  - [ ] Can you claim a reward multiple times?
  - [ ] Can you bypass one-time-use restrictions?
  - [ ] Can you bypass rate limits via race conditions?
- [ ] **WSTG-BUSL-06** — Testing for the Circumvention of Workflows
  - [ ] Can you skip steps in a multi-step process?
  - [ ] Can you access the success/confirmation page directly?
  - [ ] Can you bypass payment steps?
  - [ ] Can you bypass email verification?
- [ ] **WSTG-BUSL-07** — Testing Defenses Against Application Misuse
  - [ ] Can you bypass captcha?
  - [ ] Can you bypass anti-automation controls?
- [ ] **WSTG-BUSL-08** — Testing for Upload of Unexpected File Types
  - [ ] Can you upload .php instead of .jpg?
  - [ ] Can you upload .svg with XSS payload?
  - [ ] Can you upload .html with iframe?
  - [ ] Can you bypass content-type validation?
  - [ ] Can you bypass extension blacklist?
  - [ ] Can you upload polyglot files?
- [ ] **WSTG-BUSL-09** — Testing for Upload of Malicious Files
  - [ ] Can you upload a web shell?
  - [ ] Can you upload and execute a script?
  - [ ] Can you overwrite existing sensitive files?
  - [ ] Can you upload large files (DoS)?

---

## CLNT — Client-Side Testing

- [ ] **WSTG-CLNT-01** — Testing for DOM-Based XSS
  - [ ] Sources: document.URL, document.location, location.hash, location.search, document.referrer, window.name, postMessage
  - [ ] Sinks: innerHTML, document.write, eval, setTimeout, setInterval, location.href, document.createElement
  - [ ] Check URL fragments (#) for DOM XSS
  - [ ] Check postMessage handlers
  - [ ] Check localStorage/sessionStorage usage
- [ ] **WSTG-CLNT-02** — Testing for JavaScript Execution
  - [ ] Can you inject JavaScript via URL parameters?
  - [ ] Check eval() usage with user-controlled input
  - [ ] Check Function() constructor usage
  - [ ] Check setTimeout/setInterval with string args
- [ ] **WSTG-CLNT-03** — Testing for HTML Injection
  - [ ] Can you inject arbitrary HTML tags?
  - [ ] Can you inject iframes?
  - [ ] Can you inject forms (credential harvesting)?
  - [ ] Can you inject meta refresh (redirect)?
- [ ] **WSTG-CLNT-04** — Testing for Client-Side URL Redirect
  - [ ] Open redirect via JavaScript redirect
  - [ ] window.location manipulation
  - [ ] Meta refresh injection
- [ ] **WSTG-CLNT-05** — Testing for CSS Injection
  - [ ] Can you inject style attributes or style tags?
  - [ ] CSS attribute selectors for data exfiltration
- [ ] **WSTG-CLNT-06** — Testing for Client-Side Resource Manipulation
  - [ ] Can you manipulate client-side routing?
  - [ ] Can you change API endpoint URLs?
- [ ] **WSTG-CLNT-07** — Testing Cross-Origin Resource Sharing (CORS)
  - [ ] ACAO reflects Origin? (critical with credentials)
  - [ ] ACAO wildcard (*) with credentials? (blocked by browser, but check)
  - [ ] Null origin allowed? (sandboxed iframe)
  - [ ] Subdomain bypass in Origin validation
  - [ ] Preflight response (ACAM, ACAH)
- [ ] **WSTG-CLNT-08** — Testing for Cross-Site Flashing
- [ ] **WSTG-CLNT-09** — Testing for Clickjacking
  - [ ] X-Frame-Options: DENY / SAMEORIGIN present?
  - [ ] CSP frame-ancestors directive present?
  - [ ] Can the page be framed? Test: iframe the login page
- [ ] **WSTG-CLNT-10** — Testing WebSockets
  - [ ] WebSocket missing Origin check (Cross-Site WebSocket Hijacking)
  - [ ] WebSocket data is reflected? (XSS via WebSocket)
  - [ ] WebSocket SQLi / Command Injection
  - [ ] WebSocket authentication? (session cookie sent on upgrade?)
- [ ] **WSTG-CLNT-11** — Testing Web Messaging (postMessage)
  - [ ] No origin check in postMessage handler
  - [ ] Wildcard origin: event.origin !== "*" (check for wildcard bypass)
  - [ ] indexOf instead of strict comparison
  - [ ] postMessage data used in sink (DOM XSS)
- [ ] **WSTG-CLNT-12** — Testing for Local Storage / Session Storage
  - [ ] JWT/session tokens in localStorage? (XSS → token theft)
  - [ ] Sensitive data in localStorage? (clear text, no encryption)
  - [ ] localStorage accessible to subdomains?
- [ ] **WSTG-CLNT-13** — Testing for Cross-Site Script Inclusion (XSSI)
  - [ ] Dynamic JavaScript with sensitive data? (JSONP, API response as JS)
  - [ ] Can you include scripts cross-origin?
  - [ ] Override Array/Object constructors to leak data

---

## API — API Testing

- [ ] **WSTG-APIT-01** — Testing for GraphQL Introspection
  - [ ] GraphQL introspection enabled? POST {"query":"{__schema{types{name}}}"}
  - [ ] GraphQL field suggestions leaking schema?
  - [ ] GraphQL batching attacks?
- [ ] **WSTG-APIT-02** — Testing for REST API
  - [ ] Mass assignment vulnerability (extra fields accepted)
  - [ ] IDOR in API endpoints
  - [ ] Missing rate limiting
  - [ ] Missing authentication on internal APIs
  - [ ] API versioning exposing old vulnerable endpoints (/v1, /v2, /legacy)
- [ ] **WSTG-APIT-03** — Testing for SOAP APIs
- [ ] **WSTG-APIT-04** — Testing for Excessive Data Exposure (API returns more than UI shows)

---

## Quick Reference: Tools per Category

| Category | Primary Tools |
|----------|---------------|
| INFO | subfinder, amass, dnsx, httpx, katana, gau, waybackurls |
| CONFIG | nmap, naabu, ffuf, nuclei, curl, openssl |
| ATHN | ffuf, Burp, custom scripts, hashcat (cracking) |
| AUTH | custom curl, ffuf (IDOR fuzzing), Burp |
| SESS | curl (cookie analysis), Burp Sequencer |
| INPV | sqlmap, dalfox, ffuf, nuclei, custom payloads |
| CRYP | openssl, nmap (ssl-enum-ciphers), testssl.sh |
| BUSL | Custom curl/Python race condition scripts, manual logic testing |
| CLNT | Browser devtools, dalfox (DOM XSS), custom HTML PoCs |

---

## Scoring (for reporting)

| Severity | CVSS | Example |
|----------|------|---------|
| Critical | 9.0-10.0 | RCE, SQLi with full DB access, auth bypass to admin |
| High | 7.0-8.9 | Stored XSS, SSRF to internal, IDOR to sensitive data |
| Medium | 4.0-6.9 | Reflected XSS, CSRF on critical actions, verbose errors |
| Low | 0.1-3.9 | Missing security headers, clickjacking, weak ciphers |
| Info | 0.0 | Informational findings, best practices