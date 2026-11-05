# File Upload Test Payloads Generator

A small, zero-dependency Python tool that generates a folder of benign
file-upload security test files, plus a `manifest.csv` describing each
file, the upload-handling weakness it tests, and what a secure upload
handler should do with it.

File upload is one of the easiest places for an application to get
owned: a weak handler can be turned into remote code execution, stored
XSS, path traversal or a full disk. This kit gives you a standard set
of test files to check a handler before an attacker does.

## Safety first: everything here is a harmless marker

- Script files only echo or print a fixed `UPLOAD_TEST_MARKER` string.
  There are no shells, no command execution, no eval, and nothing that
  reads request input.
- The EICAR file is the industry-standard antivirus test string. It is
  not malware; antivirus products are expected to flag it, and it is
  how you prove your AV scanning on the upload path actually works.
- The zip slip entry is a path inside an archive. It only matters if
  something extracts it unsafely, which is the bug being tested.

If a test file ever executes on your server, the worst it can do is
print the marker. That print is the signal: it proves the upload
handler let a file be executed, and that is the finding.

## Files generated

| File | What it tests |
| --- | --- |
| `eicar_test.txt` | Antivirus scanning on the upload path |
| `invoice.pdf.php` | Double extension, document then script |
| `shell_test.php.jpg` | Script extension hidden before an image extension |
| `script_test.svg` | SVG with an embedded script element |
| `script_test.html` | HTML upload leading to stored script execution |
| `gif_polyglot_test.gif` | GIF magic header with text body (polyglot) |
| `fake_image.jpg` | Plain text with an image extension (magic mismatch) |
| `zip_slip_test.zip` | Archive entry with `../../` path traversal |
| Long filename file (170+ characters) | Filename length handling |
| Unicode filename file | Filename normalisation and encoding |
| `large_test_file.bin` | Size limit enforcement (5 MB by default) |

The `manifest.csv` in the output folder has the full list, the
technique behind each file, and the expected behaviour of a secure
handler, which makes it easy to attach to an assessment report.

## Usage

```bash
python3 upload_payloads.py -o upload_test_files
python3 upload_payloads.py -o upload_test_files --size-mb 20
```

Options:

- `-o, --output-dir`: where to generate the files
- `--size-mb`: size of the large test file in MB, default 5

Then upload the files to the upload form you are testing, one at a
time, and compare what the application does with the
`expected_secure_behavior` column in the manifest.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests generate the full set into a temporary directory and check
that the manifest lists every file, the EICAR string is byte-exact,
the zip really contains the traversal entry, the GIF file starts with
GIF89a, and that no generated file contains dangerous constructs such
as system or eval calls, request superglobals, or shell paths.

## Responsible use

For authorised security testing only. Only upload these files to
applications you own or are explicitly authorised to test. The files
are benign markers by design, but uploading test payloads to someone
else's system without permission is still unauthorised testing.

## License

MIT, see LICENSE.
