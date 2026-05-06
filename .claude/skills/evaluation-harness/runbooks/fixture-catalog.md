# Fixture Catalog

## xss-reflected
- **Skill tested**: `xss`
- **Vulnerability**: Reflected XSS — GET parameter reflected in HTML body without encoding
- **Port**: 8081
- **Positive control**: `GET /search?q=<script>alert(1)</script>` — script tag appears raw in HTML
- **Negative control**: `GET /search?q=hello` — plain text reflected, no script injection possible
- **Detection method**: Check response body for unescaped HTML/Javascript payloads

## sqli-error
- **Skill tested**: `sqli`
- **Vulnerability**: Error-based SQL injection — user input concatenated into SQL query, errors exposed
- **Port**: 8082
- **Positive control**: `GET /search?username=admin' OR '1'='1` — returns extra rows from users table
- **Negative control**: `GET /search?username=admin` — returns only the admin row, no SQL error
- **Detection method**: Inject SQL syntax, check for error messages or unexpected row counts

## ssrf-blind
- **Skill tested**: `ssrf`
- **Vulnerability**: Blind SSRF — endpoint fetches user-supplied URL, no restriction on internal hosts
- **Port**: 8083
- **Positive control**: `GET /fetch?url=http://127.0.0.1:8083/` — fetch succeeds against loopback
- **Negative control**: `GET /fetch?url=http://non-existent-domain.test` — returns DNS resolution error
- **Detection method**: Supply internal/loopback URLs, check if server fetches them

## cors-misconfig
- **Skill tested**: `cors-csrf`
- **Vulnerability**: CORS misconfiguration — Origin header echoed back dynamically with credentials
- **Port**: 8084
- **Positive control**: Request with `Origin: http://evil.com` — response includes `Access-Control-Allow-Origin: http://evil.com` and `Access-Control-Allow-Credentials: true`
- **Negative control**: Request without Origin header — no permissive CORS headers returned
- **Detection method**: Send varying Origin headers, inspect response for reflected ACAO with credentials

## upload-unrestricted
- **Skill tested**: `file-upload`
- **Vulnerability**: Unrestricted file upload — no extension filtering, content-type validation, or size limits
- **Port**: 8085
- **Positive control**: POST with `X-Filename: shell.php` — file saved to uploads/ with .php extension
- **Negative control**: POST with `X-Filename: document.txt` — text file saved normally (benign upload)
- **Detection method**: Upload files with dangerous extensions, verify they persist in writable directory

## jwt-none-alg
- **Skill tested**: `auth`
- **Vulnerability**: JWT algorithm confusion — server accepts tokens with `alg: none`, bypassing signature validation
- **Port**: 8086
- **Positive control**: Bearer token with `{"alg":"none"}` header — authenticated as admin
- **Negative control**: No Authorization header — returns 401 (benign rejection)
- **Detection method**: Craft JWT with `alg: none`, check if server accepts without signature

## graphql-introspection
- **Skill tested**: `api`
- **Vulnerability**: GraphQL introspection enabled — full schema exposed including sensitive field names
- **Port**: 8087
- **Positive control**: POST introspection query `{ __schema { types { name fields { name } } } }` — returns full schema with passwordHash, ssn fields
- **Negative control**: POST normal query `{ user(id: 1) { id email } }` — returns only requested fields
- **Detection method**: Send introspection query, check response for schema structure

## cache-poison
- **Skill tested**: `http-protocol`
- **Vulnerability**: Web cache poisoning — X-Forwarded-Host header reflected in cacheable response
- **Port**: 8088
- **Positive control**: GET with `X-Forwarded-Host: evil.com` — response includes `evil.com/tracking.js` in script src with `Cache-Control: public, max-age=3600`
- **Negative control**: GET without unkeyed headers — response uses `/static/tracking.js` (relative URL)
- **Detection method**: Send unkeyed headers (X-Forwarded-Host, X-Original-URL), check if response caches poisoned content