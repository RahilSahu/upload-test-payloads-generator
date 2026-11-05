#!/usr/bin/env python3
"""File-upload security test payload generator.

Generates a folder of benign file-upload test files plus a manifest
describing each one, the upload-handling weakness it tests, and what a
secure upload handler should do with it.

Every file is a harmless marker. Script files only echo or print a
fixed UPLOAD_TEST_MARKER string. There are no shells, no command
execution, no request handling and nothing that reads input. If a test
file ever "runs" on a server, the only thing it can do is print the
marker, which is exactly the signal a tester needs.

Zero dependencies: Python 3.9+ standard library only.
For authorised security testing only.
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import zipfile
from pathlib import Path

MARKER = "UPLOAD_TEST_MARKER"

# The standard EICAR anti-malware test string. This is not malware: it
# is the industry-standard harmless string that antivirus products are
# expected to flag, used worldwide to test that AV is working.
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

LONG_NAME = "long_filename_test_" + ("a" * 150) + ".txt"
UNICODE_NAME = "unicode_täst_üñïçødé_test.txt"
ZIP_SLIP_ENTRY = "../../zip_slip_test.txt"

MANIFEST_NAME = "manifest.csv"
MANIFEST_FIELDS = ["filename", "technique", "expected_secure_behavior"]


def _files(size_mb: float) -> list[tuple[str, bytes, str, str]]:
    """Return (filename, content, technique, expected behaviour) rows."""
    php_echo = (
        '<?php echo "UPLOAD_TEST_MARKER - double extension test file. '
        'If this text was rendered by a PHP interpreter, the upload '
        'handler executed a file it should never have executed."; ?>\n'
    ).encode("utf-8")

    plain_marker = (
        "UPLOAD_TEST_MARKER - plain text content in a file whose name "
        "or extension claims something else. Content is harmless text.\n"
    ).encode("utf-8")

    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">\n'
        '  <text x="10" y="30" font-size="14">UPLOAD_TEST_MARKER</text>\n'
        '  <script>alert("UPLOAD_TEST_MARKER - SVG script test");</script>\n'
        "</svg>\n"
    ).encode("utf-8")

    html = (
        "<!DOCTYPE html>\n<html><head><title>Upload test</title></head>\n"
        "<body><p>UPLOAD_TEST_MARKER - HTML upload test file.</p>\n"
        '<script>alert("UPLOAD_TEST_MARKER - HTML script test");</script>\n'
        "</body></html>\n"
    ).encode("utf-8")

    gif_polyglot = (
        b"GIF89a"
        + b"\nUPLOAD_TEST_MARKER - GIF header polyglot test file. "
          b"The header is a GIF magic value, the rest is plain text.\n"
    )

    fake_image = (
        "UPLOAD_TEST_MARKER - this file has a .jpg extension but is "
        "plain text. Its magic bytes do not match any image format.\n"
    ).encode("utf-8")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            ZIP_SLIP_ENTRY,
            "UPLOAD_TEST_MARKER - zip slip test entry. A secure "
            "extractor must never write this file outside the target "
            "directory.\n",
        )
        zf.writestr(
            "normal_file.txt",
            "UPLOAD_TEST_MARKER - normal file inside the test zip.\n",
        )
    zip_bytes = zip_buffer.getvalue()

    large_size = int(size_mb * 1024 * 1024)
    large_bytes = b"\x00" * large_size

    return [
        (
            "eicar_test.txt",
            EICAR.encode("ascii"),
            "Antivirus test string (EICAR)",
            "Antivirus on the upload path must flag and reject or quarantine this file.",
        ),
        (
            "invoice.pdf.php",
            php_echo,
            "Double extension, script after a document extension",
            "Reject, or store with a safe generated name and never execute. Final extension checks alone are not enough.",
        ),
        (
            "shell_test.php.jpg",
            plain_marker,
            "Script extension hidden before an image extension",
            "Reject files with a script extension anywhere in the name, and serve uploads as static files only.",
        ),
        (
            "script_test.svg",
            svg,
            "SVG with an embedded script element",
            "Sanitise SVG on upload, or serve it with a content type and disposition that prevent script execution in your origin.",
        ),
        (
            "script_test.html",
            html,
            "HTML file with a script element",
            "Reject HTML uploads from untrusted users, or serve them from a separate domain with Content-Disposition attachment.",
        ),
        (
            "gif_polyglot_test.gif",
            gif_polyglot,
            "GIF magic header followed by text (polyglot)",
            "Validate full file structure, not just magic bytes, and never let an upload be interpreted as more than one type.",
        ),
        (
            "fake_image.jpg",
            fake_image,
            "Plain text with an image extension (magic byte mismatch)",
            "Reject. Sniffed content type must match the claimed type, and image uploads should be re-encoded before storage.",
        ),
        (
            "zip_slip_test.zip",
            zip_bytes,
            "Zip archive with a path traversal entry (zip slip)",
            "Extraction must resolve every entry path inside the target directory and reject entries containing traversal.",
        ),
        (
            LONG_NAME,
            plain_marker,
            "Very long filename (over 150 characters)",
            "Accept safely with truncation, or reject with a clean error. It must not crash the handler or break the filesystem.",
        ),
        (
            UNICODE_NAME,
            plain_marker,
            "Unicode characters in the filename",
            "Normalise or safely encode the stored name. It must not break paths, URLs or later downloads.",
        ),
        (
            "large_test_file.bin",
            large_bytes,
            "Large file upload (size limit test)",
            "Enforce the documented size limit and reject oversized files with a clean error, without storing partial files.",
        ),
    ]


def generate_payloads(output_dir: str | Path, size_mb: float = 5.0) -> list[str]:
    """Generate all test files and the manifest into output_dir.

    Returns the list of generated file names (not including the
    manifest itself). size_mb controls the large test file and can be
    a fraction, which the tests use to keep runs fast.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = _files(size_mb)
    names: list[str] = []
    for name, content, _technique, _expected in rows:
        (out / name).write_bytes(content)
        names.append(name)

    with open(out / MANIFEST_NAME, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        for name, _content, technique, expected in rows:
            writer.writerow(
                {
                    "filename": name,
                    "technique": technique,
                    "expected_secure_behavior": expected,
                }
            )
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate benign file-upload security test files and a "
            "manifest describing what each one tests."
        )
    )
    parser.add_argument("-o", "--output-dir", default="upload_test_files",
                        help="Directory to generate the files into")
    parser.add_argument("--size-mb", type=float, default=5.0,
                        help="Size of the large test file in MB (default: 5)")
    args = parser.parse_args(argv)

    if args.size_mb < 0:
        print("Error: --size-mb cannot be negative", file=sys.stderr)
        return 2

    names = generate_payloads(args.output_dir, size_mb=args.size_mb)
    print(f"Generated {len(names)} test files plus {MANIFEST_NAME} in {args.output_dir}:")
    for name in names:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
