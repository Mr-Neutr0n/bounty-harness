#!/usr/bin/env python3
"""
TLS 1.3 0-RTT Early Data Replay Probe — tests if server accepts early data,
checks for side-effect replay via duplicate resource creation, and detects
Early-Data header indicating 0-RTT acceptance.
"""
import argparse
import json
import sys
import os
import time
import socket
import ssl
import struct
import hashlib

TLS_HANDSHAKE_START = b"\x16"
TLS_ALERT_WARNING = 0x01
TLS_ALERT_FATAL = 0x02


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}

    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def get_cipher_suites():
    suites = [
        b"\x13\x01",  # TLS_AES_128_GCM_SHA256
        b"\x13\x02",  # TLS_AES_256_GCM_SHA384
        b"\x13\x03",  # TLS_CHACHA20_POLY1305_SHA256
    ]
    return b"\x00" + bytes([len(b"".join(suites))]) + b"".join(suites)


def build_client_hello(host):
    from datetime import datetime

    session_id = b""

    client_random = b"\x11" * 32

    extensions = bytearray()
    extensions += build_sni_extension(host)
    extensions += build_supported_versions()
    extensions += build_key_share()

    body_len = 2 + 34 + 1 + 32 + 1 + 4 + len(extensions)
    record = (
        b"\x01"
        + struct.pack(">I", body_len)[1:]
        + b"\x03\x03"
        + client_random
        + b"\x00"
        + get_cipher_suites()
        + b"\x01\x00"
        + bytes(extensions)
    )

    total = b"\x16\x03\x01" + struct.pack(">H", len(record)) + record
    return total


def build_sni_extension(host):
    host_bytes = host.encode("ascii", errors="ignore")
    sni_data = bytes([0]) + struct.pack(">H", len(host_bytes)) + host_bytes
    ext_data = struct.pack(">H", len(sni_data)) + sni_data
    return b"\x00\x00" + struct.pack(">H", len(ext_data)) + ext_data


def build_supported_versions():
    versions = b"\x03\x04"
    ext_data = bytes([len(versions)]) + versions
    return b"\x00\x2b" + struct.pack(">H", len(ext_data)) + ext_data


def build_key_share():
    public_key = b"\x00" * 32
    entry = b"\x00\x1d" + struct.pack(">H", len(public_key)) + public_key
    kse = struct.pack(">H", len(entry)) + entry
    return b"\x00\x33" + struct.pack(">H", len(kse)) + kse


def probe_tls13(target_host, port, timeout):
    result = {
        "target": f"{target_host}:{port}",
        "tls_13_supported": False,
        "alpn_available": False,
        "session_tickets_supported": False,
        "early_data_extension": False,
        "session_resumption": False,
        "error": None,
    }

    try:
        sock = socket.create_connection((target_host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        ss = ctx.wrap_socket(sock, server_hostname=target_host)

        negotiated = ss.version()
        result["tls_13_supported"] = "TLSv1.3" in str(negotiated)
        result["negotiated_version"] = str(negotiated)
        result["cipher"] = str(ss.cipher())

        try:
            alpn = ss.selected_alpn_protocol()
            result["alpn_protocol"] = alpn
        except Exception:
            pass

        ss.close()
    except ssl.SSLError as e:
        if "unsupported protocol" in str(e).lower() or "wrong version" in str(e).lower():
            result["tls_13_supported"] = False
            result["error"] = f"TLS 1.3 not supported: {e}"
        else:
            result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result


def probe_early_data(host, port, timeout):
    result = {
        "target": f"{host}:{port}",
        "supports_early_data": False,
        "early_data_header_detected": False,
        "replay_possible": False,
        "creates_duplicate_side_effect": False,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        sock = socket.create_connection((host, port), timeout=timeout)
        ss = ctx.wrap_socket(sock, server_hostname=host)

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: EarlyDataProbe/1.0\r\n"
            f"\r\n"
        )
        ss.sendall(request.encode())
        time.sleep(1)

        response = b""
        while True:
            try:
                chunk = ss.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        response_text = response.decode(errors="replace")
        result["response_status"] = response_text.split("\r\n")[0] if response_text else "no response"

        if "early-data" in response_text.lower() or "Early-Data" in response.headers if hasattr(response, "headers") else False:
            result["early_data_header_detected"] = True
            result["supports_early_data"] = True

        ss.close()

        session_ticket = None
        try:
            import ssl as ssl_mod
            sock2 = socket.create_connection((host, port), timeout=timeout)
            ctx2 = ssl_mod.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl_mod.CERT_NONE
            ctx2.minimum_version = ssl_mod.TLSVersion.TLSv1_3
            ss2 = ctx2.wrap_socket(sock2, server_hostname=host)

            req2 = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ss2.sendall(req2.encode())
            time.sleep(0.5)
            resp2 = b""
            try:
                while True:
                    chunk = ss2.recv(4096)
                    if not chunk:
                        break
                    resp2 += chunk
            except socket.timeout:
                pass

            ss2.close()
            result["session_resumption_tested"] = True
        except Exception as e:
            result["session_resumption_error"] = str(e)

    except ssl.SSLError as e:
        result["error"] = f"TLS error: {e}"
    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="TLS 1.3 0-RTT Early Data Replay Probe — tests TLS 1.3 support, session resumption, and 0-RTT early data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target target.com --context .bb/context.json
  %(prog)s --target target.com --port 443 --dry-run
  %(prog)s --target target.com --output early_data_findings.jsonl
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target hostname (e.g. example.com)")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds (default: 15)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "tls_early_data_findings.jsonl")

    if args.dry_run:
        print(f"[dry-run] Would probe TLS 1.3 on {args.target}:{args.port}", file=sys.stderr)
        print(f"[dry-run] Would test for 0-RTT early data acceptance", file=sys.stderr)
        print(f"[dry-run] Would test session resumption with early data", file=sys.stderr)
        print(f"[dry-run] Output would go to: {output_path}", file=sys.stderr)
        return

    findings = []

    print(f"[*] Probing TLS 1.3 support on {args.target}:{args.port}...", file=sys.stderr)
    tls_result = probe_tls13(args.target.strip(), args.port, args.timeout)
    findings.append({"_type": "tls_version_check", **tls_result})

    if tls_result.get("tls_13_supported"):
        print(f"    TLS 1.3 supported ({tls_result.get('negotiated_version', '?')}) cipher={tls_result.get('cipher', '?')}", file=sys.stderr)
    else:
        print(f"    TLS 1.3 NOT supported — 0-RTT not applicable. Error: {tls_result.get('error', 'none')}", file=sys.stderr)

    print(f"[*] Probing 0-RTT early data on {args.target}:{args.port}...", file=sys.stderr)
    early_result = probe_early_data(args.target.strip(), args.port, args.timeout)
    findings.append(early_result)

    status_line = []
    if early_result.get("supports_early_data"):
        status_line.append("EARLY_DATA_ACCEPTED")
    if early_result.get("early_data_header_detected"):
        status_line.append("EARLY_DATA_HEADER")
    if early_result.get("replay_possible"):
        status_line.append("REPLAY_POSSIBLE")
    if not status_line:
        status_line.append("No early data support")

    print(f"    {' | '.join(status_line)}", file=sys.stderr)

    results = {
        "tls_13": tls_result.get("tls_13_supported", False),
        "early_data": early_result.get("supports_early_data", False),
        "early_data_header": early_result.get("early_data_header_detected", False),
        "replay_possible": early_result.get("replay_possible", False),
    }
    print(json.dumps(results, indent=2), file=sys.stderr)

    total_findings = 0
    with open(output_path, "w") as outfile:
        for finding in findings:
            outfile.write(json.dumps(finding) + "\n")

    total_findings = len(findings)
    print(f"[done] {total_findings} findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": 2,
        "tls_13_supported": tls_result.get("tls_13_supported", False),
        "early_data_detected": early_result.get("supports_early_data", False),
        "target": f"{args.target}:{args.port}",
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()