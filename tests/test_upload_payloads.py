import csv
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from upload_payloads import EICAR, ZIP_SLIP_ENTRY, generate_payloads

BANNED_SUBSTRINGS = [
    "system(",
    "exec(",
    "eval(",
    "$_GET",
    "$_POST",
    "cmd.exe",
    "/bin/sh",
]

EXPECTED_FILES = {
    "eicar_test.txt",
    "invoice.pdf.php",
    "shell_test.php.jpg",
    "script_test.svg",
    "script_test.html",
    "gif_polyglot_test.gif",
    "fake_image.jpg",
    "zip_slip_test.zip",
    "large_test_file.bin",
}


class GeneratePayloadsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        # Small large-file override so the test run stays fast.
        self.names = generate_payloads(self.out, size_mb=0.01)

    def tearDown(self):
        self.tmp.cleanup()

    def test_expected_files_exist(self):
        for name in EXPECTED_FILES:
            self.assertTrue((self.out / name).is_file(), f"missing {name}")
        # Plus the long-name and unicode-name files.
        self.assertEqual(len(self.names), 11)
        self.assertTrue(any(len(n) > 150 for n in self.names))
        self.assertTrue(any("ü" in n or "ä" in n for n in self.names))

    def test_manifest_exists_and_lists_every_file(self):
        manifest = self.out / "manifest.csv"
        self.assertTrue(manifest.is_file())
        with open(manifest, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        listed = {row["filename"] for row in rows}
        self.assertEqual(listed, set(self.names))
        for row in rows:
            self.assertTrue(row["technique"])
            self.assertTrue(row["expected_secure_behavior"])

    def test_eicar_string_is_exact(self):
        content = (self.out / "eicar_test.txt").read_bytes()
        self.assertEqual(content, EICAR.encode("ascii"))
        self.assertEqual(
            content.decode("ascii"),
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        self.assertEqual(len(content), 68)

    def test_zip_contains_traversal_entry(self):
        with zipfile.ZipFile(self.out / "zip_slip_test.zip") as zf:
            self.assertIn(ZIP_SLIP_ENTRY, zf.namelist())
            self.assertIn("../../zip_slip_test.txt", zf.namelist())

    def test_gif_starts_with_gif89a(self):
        content = (self.out / "gif_polyglot_test.gif").read_bytes()
        self.assertTrue(content.startswith(b"GIF89a"))

    def test_fake_image_is_not_an_image(self):
        content = (self.out / "fake_image.jpg").read_bytes()
        self.assertFalse(content.startswith(b"\xff\xd8"))  # JPEG magic
        self.assertFalse(content.startswith(b"\x89PNG"))  # PNG magic
        self.assertIn(b"UPLOAD_TEST_MARKER", content)

    def test_no_dangerous_content_anywhere(self):
        for path in self.out.iterdir():
            if not path.is_file():
                continue
            raw = path.read_bytes()
            if path.suffix == ".zip":
                with zipfile.ZipFile(path) as zf:
                    for entry in zf.namelist():
                        raw += zf.read(entry)
            text = raw.decode("utf-8", errors="ignore")
            for banned in BANNED_SUBSTRINGS:
                self.assertNotIn(
                    banned, text,
                    f"{banned!r} found in generated file {path.name}",
                )

    def test_script_files_only_echo_the_marker(self):
        php = (self.out / "invoice.pdf.php").read_text(encoding="utf-8")
        self.assertIn("echo", php)
        self.assertIn("UPLOAD_TEST_MARKER", php)


if __name__ == "__main__":
    unittest.main()
