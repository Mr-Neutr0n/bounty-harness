# Surface Checklist Runbook — Per-Surface Testing Guide

## Purpose
Provides a checklist of what to test for each attack surface type. Use after the domain profile report is generated to ensure comprehensive surface coverage.

## Surface Checklists

### upload-pipeline
- [ ] Identify file upload endpoints and accepted MIME types.
- [ ] Test extension bypass: double extensions, null byte, case sensitivity.
- [ ] Test content-type spoofing.
- [ ] Test SVG XSS upload for profile images.
- [ ] Test polyglot files (e.g. GIFAR, PDF+XSS).
- [ ] Check if upload triggers server-side processing (SSRF via file fetch).
- [ ] Test large file upload for DoS potential.
- [ ] Test concurrent upload race conditions.
- [ ] Check signed upload URL generation for parameter injection.

### player-embed
- [ ] Enumerate URL parameters accepted by player/embed endpoints.
- [ ] Test for reflected XSS in player parameters.
- [ ] Test for open redirect via source/media URL parameter.
- [ ] Test SSRF if player fetches remote media URLs.
- [ ] Check CORS headers on player endpoints for cross-origin abuse.
- [ ] Test token/signature parameters for replay or bypass.

### api-object-crud
- [ ] Enumerate all API routes with object IDs in paths.
- [ ] Test IDOR by swapping object IDs between users.
- [ ] Test BOLA/IDOR across workspaces, teams, or projects.
- [ ] Check mass assignment by adding unexpected fields in PUT/PATCH.
- [ ] Test for excessive data exposure via ?include=, ?expand=, or GraphQL fields.
- [ ] Test parameter pollution (duplicate params with different values).
- [ ] Check rate limiting on CRUD endpoints.
- [ ] Test HTTP method override via X-HTTP-Method-Override.

### graphql
- [ ] Run introspection query to extract full schema.
- [ ] Test depth attacks (deeply nested queries).
- [ ] Test alias-based batching for rate limit bypass.
- [ ] Test directive overloading (@skip, @include).
- [ ] Check field suggestions in error messages for information disclosure.
- [ ] Test persisted queries bypass.
- [ ] Test subscription endpoints for unauthorized streaming access.
- [ ] Check batching and query merging for auth bypass.

### websocket
- [ ] Identify WebSocket connection endpoints.
- [ ] Test connection without authentication token.
- [ ] Test cross-origin WebSocket connection (CORS WS).
- [ ] Test message injection in chat or event channels.
- [ ] Test channel enumeration for unauthorized subscription.
- [ ] Check Origin header validation on WebSocket handshake.
- [ ] Test message payload for XSS if rendered in UI.
- [ ] Test connection limits and reconnection behavior.

### oauth-flow
- [ ] Test redirect_uri open redirect and path traversal.
- [ ] Test state parameter CSRF bypass.
- [ ] Test response_type and response_mode manipulation.
- [ ] Test code replay for token generation.
- [ ] Test PKCE bypass by omitting code_challenge or code_verifier.
- [ ] Check scope escalation by adding extra scopes.
- [ ] Test client_id confusion (using another app's client_id).
- [ ] Test implicit flow token leakage via referrer or history.

### checkout-payment
- [ ] Test price/amount manipulation in request body.
- [ ] Test currency parameter injection.
- [ ] Test coupon/discount code abuse (multiple uses, negative values).
- [ ] Test race condition on checkout for double-spend.
- [ ] Check if order confirmation is idempotent (resend creates duplicate).
- [ ] Test payment method enumeration across users.
- [ ] Check for test/staging payment gateway endpoints in production.

### webhook
- [ ] Test unauthenticated webhook POST.
- [ ] Test webhook signature bypass (missing, wrong, or replay).
- [ ] Test SSRF via webhook URL configuration.
- [ ] Test payload injection in webhook body.
- [ ] Check webhook event type spoofing.
- [ ] Test webhook replay to trigger duplicate events.
- [ ] Check webhook URL validation for bypass.

### file-download
- [ ] Test path traversal in download URL parameter.
- [ ] Test IDOR on file ID parameter.
- [ ] Test forced browsing of download directory.
- [ ] Check Content-Disposition header manipulation.
- [ ] Test signed URL parameter extraction and reuse.
- [ ] Test download URL with SSRF-capable parameter.

### cdn-cache
- [ ] Test cache poisoning via unkeyed headers.
- [ ] Test cache deception (authenticated pages cached as public).
- [ ] Test Host header injection for cache key manipulation.
- [ ] Check for X-Forwarded-Host poisoning.
- [ ] Test fat GET (body in GET request) for cache confusion.
- [ ] Discover origin server IP via cache miss or DNS.
- [ ] Check for CloudFront/S3 origin misconfiguration.

### auth-flow
- [ ] Test user enumeration via login response timing or messages.
- [ ] Test password reset token brute force or prediction.
- [ ] Test email verification bypass.
- [ ] Test MFA bypass via response manipulation or direct API access.
- [ ] Test session fixation on login.
- [ ] Test password reset poisoning via Host header.
- [ ] Check lockout policy for bypass (alternate endpoints, IP rotation).
- [ ] Test remember-me token generation and reuse.

### admin-panel
- [ ] Enumerate admin panel subdomains and paths.
- [ ] Test default credentials on admin panels.
- [ ] Check for unauthenticated access to admin endpoints.
- [ ] Test privilege escalation from regular user to admin.
- [ ] Check exposed configuration or logs in admin panel.
- [ ] Test internal admin API endpoints for auth bypass.

### llm-endpoint
- [ ] Test prompt injection via user input that reaches model.
- [ ] Test system prompt extraction via prompt leaking techniques.
- [ ] Test tool-use abuse (calling unauthorized tools or functions).
- [ ] Test RAG data exfiltration via model extraction queries.
- [ ] Test token limit bypass via large or repetitive input.
- [ ] Test model switching to less-restricted models.
- [ ] Check streaming SSE endpoint for information in metadata.

### mobile-deep-link
- [ ] Identify all custom URL schemes in the application.
- [ ] Test deep link parameter injection.
- [ ] Test deeplink-based XSS if URL is rendered in webview.
- [ ] Test OAuth token theft via deeplink redirect.
- [ ] Check if deeplink can trigger sensitive actions without auth.
- [ ] Test universal link / app link interception.

### subdomain-takeover
- [ ] Check all CNAME records for dangling DNS.
- [ ] Probe each CNAME target for service "not found" response.
- [ ] Check for unclaimed GitHub Pages, Heroku apps, S3 buckets.
- [ ] Check CloudFront distributions without valid origin.
- [ ] Verify Azure CDN or Storage endpoints are claimed.
- [ ] Test Shopify/Shopify Plus CNAME for unclaimed stores.

### email-handling
- [ ] Check email verification token strength and expiry.
- [ ] Test email injection in recipient field.
- [ ] Test email parsing for SSRF (HTML email rendering fetches remote images).
- [ ] Test unsubscribe link for IDOR or auth bypass.
- [ ] Check bounce handling for email address enumeration.
- [ ] Test inbound email processing for command injection in subject/body.
- [ ] Verify DKIM/SPF/DMARC configuration for spoofing protection.