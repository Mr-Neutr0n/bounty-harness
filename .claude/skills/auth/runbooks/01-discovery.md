# Auth Discovery Runbook

## Purpose
Discover authentication vulnerabilities by mapping auth flows and identifying weak points: login, registration, password reset, session management, MFA, JWT, OAuth.

## Variables
- `$TARGET_URL` — base URL (e.g., `https://target.com`)
- `$OUTDIR` — output directory
- `$COOKIE_JAR` — curl cookie jar file (`$OUTDIR/cookies.txt`)

## Step 1 — Auth Flow Mapping

### W1A. Crawl for auth-related endpoints
```bash
katana -u "$TARGET_URL" -jc -d 3 -silent -field url | grep -iE 'login|signin|register|signup|reset|forgot|recover|password|oauth|auth|verify|logout|session|mfa|2fa|otp' | sort -u > "$OUTDIR/auth-endpoints.txt"
```

### W1B. Wayback auth endpoint discovery
```bash
gau "$TARGET_URL" | grep -iE 'login|signin|register|signup|reset|forgot|password|oauth|auth|verify|logout|session|mfa|2fa|otp' | sort -u >> "$OUTDIR/auth-endpoints.txt"
```

### W1C. Common auth path brute-force
```bash
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST_DIR/web-content/auth-paths.txt" -mc 200,301,302,403 -o "$OUTDIR/auth-paths.json"
```

## Step 2 — JWT Discovery

### W2A. Search for JWTs in all accessible endpoints
```bash
while read -r url; do
  curl -sk -v "$url" 2>&1 | grep -iE 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' >> "$OUTDIR/jwt-tokens.txt"
done < "$OUTDIR/auth-endpoints.txt"
```

### W2B. Search source JavaScript for JWT references
```bash
katana -u "$TARGET_URL" -jc -d 2 -silent -field url | grep '\.js$' | sort -u > "$OUTDIR/js-files.txt"
while read -r jsfile; do
  curl -sk "$jsfile" | grep -oE 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' >> "$OUTDIR/jwt-from-js.txt"
done < "$OUTDIR/js-files.txt"
```

### W2C. Decode discovered JWTs
```bash
sort -u "$OUTDIR/jwt-tokens.txt" "$OUTDIR/jwt-from-js.txt" > "$OUTDIR/jwt-all.txt"
while read -r token; do
  echo "=== JWT: $token ==="
  echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null
  echo ""
done < "$OUTDIR/jwt-all.txt" > "$OUTDIR/jwt-decoded.txt"
```

## Step 3 — Session Cookie Analysis

### W3A. Capture cookies from various endpoints
```bash
rm -f "$COOKIE_JAR"
curl -sk -c "$COOKIE_JAR" -o /dev/null "$TARGET_URL"
curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null "$TARGET_URL/login"
cat "$COOKIE_JAR" | awk '{print $NF" = "$7}' > "$OUTDIR/session-cookies.txt"
```

### W3B. Check cookie attributes from headers
```bash
curl -sk -v "$TARGET_URL" 2>&1 | grep -i 'set-cookie' > "$OUTDIR/cookie-headers.txt"
grep -i 'httponly\|secure\|samesite\|path\|domain\|expires\|max-age' "$OUTDIR/cookie-headers.txt" > "$OUTDIR/cookie-flags.txt"
```

## Step 4 — Password Reset Flow Mapping

### W4A. Discover password reset flow
```bash
grep -iE 'forgot|reset|recover' "$OUTDIR/auth-endpoints.txt" > "$OUTDIR/pwreset-endpoints.txt"
```

### W4B. Trigger password reset and capture flow
```bash
cat "$OUTDIR/pwreset-endpoints.txt"
```

## Step 5 — OAuth / SSO Discovery

### W5A. Find OAuth SSO references
```bash
grep -iE 'oauth|sso|saml|openid|connect' "$OUTDIR/auth-endpoints.txt" > "$OUTDIR/oauth-endpoints.txt"
```

### W5B. Check for third-party auth providers in HTML
```bash
curl -sk "$TARGET_URL" | grep -iE 'google.*login|facebook.*login|github.*login|apple.*login|microsoft.*login|sso' > "$OUTDIR/sso-providers.txt"
```

## Step 6 — IDOR Candidate Discovery

### W6A. Find endpoints with numeric/sequential IDs
```bash
gau "$TARGET_URL" | grep -oP '/\w+/\d+' | sort -u > "$OUTDIR/idor-candidates.txt"
katana -u "$TARGET_URL" -d 2 -silent | grep -oP '/\w+/\d+' | sort -u >> "$OUTDIR/idor-candidates.txt"
```

## Signals
| Signal | Indicates |
|---|---|
| JWT token found in request/response | JWT-based auth — test token manipulation |
| Set-Cookie without HttpOnly or Secure | Potential session hijacking via XSS or MITM |
| Password reset endpoint with token in URL | Potential reset token leakage via Referer |
| Numeric IDs in URLs for user/order/profile | IDOR candidate |
| OAuth endpoints found | Test OAuth misconfigurations |

## Next Routing
- JWT tokens found -> `runbooks/02-probe.md` (JWT workflow)
- Password reset flow found -> `runbooks/02-probe.md` (reset workflow)
- IDOR candidates found -> `runbooks/02-probe.md` (IDOR workflow)
- Session issues found -> `runbooks/02-probe.md` (session workflow)
- No auth endpoints found -> expand scope or stop
