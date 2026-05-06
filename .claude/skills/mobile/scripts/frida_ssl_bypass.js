/**
 * Universal SSL Pinning Bypass for Frida
 *
 * Hooks certificate validation routines on both Android (TrustManager)
 * and iOS (NSURLSession) platforms to accept all certificates,
 * bypassing SSL pinning in mobile applications.
 *
 * === Android Usage ===
 *   frida -U -l frida_ssl_bypass.js -f com.target.app --no-pause
 *
 *   frida -U -l frida_ssl_bypass.js com.target.app
 *
 *   frida -U -l frida_ssl_bypass.js -n "Target App Name"
 *
 * === iOS Usage ===
 *   frida -U -l frida_ssl_bypass.js -f com.target.app --no-pause
 *
 *   frida -U -l frida_ssl_bypass.js "Target App"
 *
 * === Requirements ===
 *   - Frida server running on device (root/jailbreak)
 *   - For iOS: trusted developer profile or jailbreak
 *   - frida-tools: pip3 install frida-tools
 */

var TrustManagerImpl = null;

setTimeout(function() {
    Java.perform(function() {
        // ── Android: Hooks ───────────────────────────────────────

        try {
            var array_list = Java.use("java.util.ArrayList");
            var x509_cert = Java.use("java.security.cert.X509Certificate");
            var certFactory = Java.use("java.security.cert.CertificateFactory");

            // Hook TrustManager.checkServerTrusted(X509Certificate[], String)
            var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

            // ── Generic TrustManager intercept ──
            var NativeCrypto = Java.use('com.android.org.conscrypt.NativeCrypto');
            NativeCrypto.SSL_do_handshake_bio.overload(
                'com.android.org.conscrypt.NativeCrypto$SSLHandshakeCallbacks',
                'int',
                'byte[]',
                'int',
                'byte[]',
                'com.android.org.conscrypt.ClientSessionContext',
                'com.android.org.conscrypt.NativeRef'
            ).implementation = function() {
                return this.SSL_do_handshake_bio.apply(this, arguments);
            };

            // ── TrustManagerImpl — checkTrustedRecursive ──
            try {
                TrustManagerImpl.checkTrustedRecursive.implementation = function(
                    certs, ocspData, tlsSctData, host, clientAlias, untrustedChain,
                    trustAnchorChain, used, trustedChain, errState
                ) {
                    console.log("[+] SSL Bypass: checkTrustedRecursive → " + host);
                    return;
                };
                console.log("[✓] Patched: TrustManagerImpl.checkTrustedRecursive");
            } catch(e) {
                console.log("[!] TrustManagerImpl.checkTrustedRecursive not found: " + e);
            }

            // ── TrustManagerImpl — verifyChain ──
            try {
                TrustManagerImpl.verifyChain.implementation = function(
                    untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
                ) {
                    console.log("[+] SSL Bypass: verifyChain → " + host);
                    return untrustedChain;
                };
                console.log("[✓] Patched: TrustManagerImpl.verifyChain");
            } catch(e) {
                console.log("[!] TrustManagerImpl.verifyChain not found: " + e);
            }

            // ── OkHttp CertificatePinner (if present) ──
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, certs) {
                    console.log("[+] OkHttp3 check bypassed: " + host);
                    return;
                };
                console.log("[✓] Patched: OkHttp3 CertificatePinner");
            } catch(e) {
                console.log("[!] OkHttp3 not found — skipped.");
            }

            // ── OkHttp4 CertificatePinner ──
            try {
                var CertificatePinner4 = Java.use("okhttp3.internal.tls.CertificateChainCleaner");
                console.log("[✓] Found OkHttp4 CertificateChainCleaner (no explicit patch needed)");
            } catch(e) {
                // silent — not present
            }

            // ── Android WebView — onReceivedSslError ──
            try {
                var WebViewClient = Java.use("android.webkit.WebViewClient");
                WebViewClient.onReceivedSslError.overload(
                    'android.webkit.WebView',
                    'android.webkit.SslErrorHandler',
                    'android.net.http.SslError'
                ).implementation = function(webview, handler, error) {
                    console.log("[+] WebView SSL error bypassed");
                    handler.proceed();
                };
                console.log("[✓] Patched: WebViewClient.onReceivedSslError");
            } catch(e) {
                console.log("[!] WebView SSL handler not found: " + e);
            }

        } catch(e) {
            console.log("[!] Android hooks failed: " + e);
        }

    });

    // ── iOS: Hooks ──────────────────────────────────────────────
    if (ObjC.available) {
        try {
            var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
            if (SecTrustEvaluate) {
                Interceptor.attach(SecTrustEvaluate, {
                    onEnter: function(args) {
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                        console.log("[+] SecTrustEvaluate → accepted (ret=0)");
                    }
                });
                console.log("[✓] Patched: Security!SecTrustEvaluate");
            }

            var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
            if (SecTrustEvaluateWithError) {
                Interceptor.attach(SecTrustEvaluateWithError, {
                    onEnter: function(args) {
                    },
                    onLeave: function(retval) {
                        retval.replace(1);
                        console.log("[+] SecTrustEvaluateWithError → accepted");
                    }
                });
                console.log("[✓] Patched: Security!SecTrustEvaluateWithError");
            }

            // ── NSURLSession delegate hooks ──
            var AuthChallengeHandler = ObjC.classes.NSURLSession;
            if (AuthChallengeHandler) {
                console.log("[✓] NSURLSession available — TrustKit/standard pinning bypassed via SecTrustEvaluate hook");
            }

        } catch(e) {
            console.log("[!] iOS hooks failed: " + e);
        }
    }

    console.log("[✓] SSL Pinning Bypass activated — all certificates accepted.");

}, 0);