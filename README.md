# dmgx — macOS DMG Source Inspector & Extractor

`dmgx` is a terminal-only Python tool for inspecting macOS `.dmg` disk images, preserving application bundles, extracting recoverable content from Electron ASAR archives and supported embedded archives, and producing local source-code and static-analysis reports.

It is designed to make an initial inspection as simple as:

```bash
dmgx "/path/to/Application.dmg"
```

> **Important limitation:** `dmgx` can only recover files and text that are present in the packaged application or its resources. It cannot reconstruct original Swift, Objective-C, C/C++, or other source files from compiled native binaries. JavaScript may be bundled, generated, or minified. Formatting bundled code does not restore the original project source.

## Features

- **Terminal-only workflow:** no GUI, dashboard, or graphical file browser.
- **Read-only DMG mounting:** uses macOS `hdiutil` and detaches mounted volumes at the end unless `--keep-mounted` is supplied.
- **Application discovery:** finds `.app` bundles, reads `Info.plist` metadata, detects Electron indicators, and records native executable information where available.
- **Electron ASAR extraction:** preserves the original `.asar` file and extracts its contents to a separate directory using a bounds-checked ASAR reader built into the script.
- **Embedded archives:** safely extracts supported ZIP, TAR, and GZIP archives, including common compressed TAR variants.
- **Source export:** creates `source-code.txt`, a consolidated text export of recoverable source-like and configuration files. `analysis/source-export.json` records included and skipped files.
- **Static analysis:** records URL/endpoints, route references, environment-variable names, IPC channel names, package/dependency information, source-map references, and file classifications where detected.
- **Native binary inspection:** reports available architecture, linked-library, symbol, and debug-information details using macOS command-line tools when present.
- **Reports:** creates both JSON and Markdown reports.
- **Optional formatting:** formats copies of supported files into `formatted/`; files under `original/` and `extracted/` are not modified by formatting.
- **Safety limits:** configurable file-count, per-file, total-size, scan-size, and source-export-size limits; path-traversal checks; guarded symlink handling; duplicate archive paths are not silently overwritten.
- **No telemetry:** files and findings remain local. The tool does not execute the application or extracted scripts.
- **Offline self-tests:** `--self-test` runs the built-in test suite without mounting a real disk image.

## Requirements

- macOS for actual DMG mounting and extraction.
- Python 3.11 or newer.
- `hdiutil`, which is included with macOS.

Other macOS utilities are used when available, including `ditto`, `file`, `codesign`, `plutil`, `otool`, `lipo`, `nm`, and `dwarfdump`. Missing optional utilities can reduce the amount of metadata collected, but they are not Python package dependencies.

No third-party Python packages are required.

### Optional formatters

`--format` always handles JSON formatting internally. For additional formatting, install optional tools:

- [Prettier](https://prettier.io/) for supported JavaScript, TypeScript, CSS, HTML, YAML, and Markdown files.
- [Black](https://black.readthedocs.io/) for Python files.

If an optional formatter is missing or cannot process a file, `dmgx` records that result; it does not change the preserved original file.

## Installation

### Requirements

- macOS
- Python 3.11 or newer
- Apple's `hdiutil` utility, included with macOS

No third-party Python packages are required.

### Install from GitHub

Clone the repository and enter its directory:

```bash
git clone https://github.com/grendizerh/dmgx.git
cd dmgx
```

Make the script executable and run the built-in tests:

```bash
chmod +x dmgx.py
./dmgx.py --version
./dmgx.py --self-test
```

Install the executable in `~/bin`:

```bash
mkdir -p "$HOME/bin"
install -m 755 ./dmgx.py "$HOME/bin/dmgx"
```

Ensure `~/bin` is on your Zsh PATH:

```bash
grep -qxF 'export PATH="$HOME/bin:$PATH"' "$HOME/.zshrc" \
  || printf '\nexport PATH="$HOME/bin:$PATH"\n' >> "$HOME/.zshrc"

source "$HOME/.zshrc"
```

Verify the installation:

```bash
dmgx --version
dmgx --help
dmgx --self-test
```

### Update an existing installation

Pull the latest changes and reinstall:

```bash
cd "$HOME/dmgx"
git pull --ff-only
./dmgx.py --self-test
install -m 755 ./dmgx.py "$HOME/bin/dmgx"
dmgx --version
```


## Quick start

### 1. Preview a DMG

```bash
dmgx "$HOME/Downloads/Application.dmg" --dry-run
```

A dry run mounts the image read-only and scans its mounted contents to report the planned work. It does not create the extraction output or extract files. It can therefore still fail if macOS cannot mount the image.

### 2. Extract and analyze

```bash
dmgx "$HOME/Downloads/Application.dmg"
```

The default output directory is created beside the DMG and named `<DMG-name>-extracted`.

### 3. Choose an output location

```bash
dmgx "$HOME/Downloads/My Application.dmg" \
  --output "$HOME/Desktop/My Application-extracted"
```

Paths containing spaces should be enclosed in quotes.

### 4. Read the consolidated source export

After extraction, open the generated source export with a pager:

```bash
less "$HOME/Downloads/Application-extracted/source-code.txt"
```

Search in `less` by typing `/` followed by a search term, and press `q` to exit.

To print the full source export to standard output after extraction:

```bash
dmgx "$HOME/Downloads/Application.dmg" --show-source
```

`--show-source` can generate a very large amount of terminal output. Use `less` on `source-code.txt` for normal inspection. `--show-source` cannot be combined with `--dry-run`.

## Command-line options

```text
dmgx [OPTIONS] DMG

dmgx --help
dmgx --version
dmgx --self-test
```

| Option | Description |
| --- | --- |
| `--output DIR`, `-o DIR` | Output directory. Defaults to `<DMG-name>-extracted` beside the input image. |
| `--dry-run` | Mount read-only and preview the work without creating extraction output. |
| `--format` | Write formatted copies of supported source files to `formatted/`. Never formats files in `original/` or `extracted/` in place. |
| `--analyze` | Explicitly request static analysis; analysis is also part of the standard pipeline. |
| `--report` | Explicitly request `report.json` and `report.md`; reports are also generated by default. |
| `--show-source` | Print the entire `source-code.txt` export to stdout after extraction. |
| `--keep-mounted` | Leave read-only mounted volume(s) attached after the run. |
| `--verbose` | Show additional diagnostic details and log them to `logs/extraction.log`. |
| `--quiet` | Suppress progress output while keeping errors visible. |
| `--yes` | Accept safe defaults in automation; does **not** bypass overwrite protection. |
| `--force` | Replace an existing output path. This is destructive; use it only when intended. |
| `--max-files N` | Maximum number of regular files scanned/extracted (default: 200,000). |
| `--max-file-size BYTES` | Maximum size of an individual file (default: 1 GiB). |
| `--max-total-size BYTES` | Maximum total bytes copied/extracted (default: 20 GiB). |
| `--max-scan-size BYTES` | Maximum amount read from one text file for analysis/formatting (default: 32 MiB). |
| `--max-source-export-size BYTES` | Maximum source/text contents in `source-code.txt` (default: 512 MiB). Files are skipped whole when they would exceed the limit; source files are not silently truncated. |
| `--self-test` | Run the offline built-in test suite; no DMG or macOS required. |

Existing output is not replaced unless `--force` is explicitly provided. `--yes` does not override this guard. If an extraction stops part-way through, inspect the output and logs before deciding whether to rerun with a new output directory or use `--force`.

## Output layout

```text
Application-extracted/
├── original/
│   └── Application.app/          # Preserved application bundle and original archives
├── extracted/
│   ├── asar/                     # Extracted ASAR payloads
│   └── archives/                 # Supported embedded archives
├── formatted/                    # Optional transformed copies
├── analysis/
│   ├── endpoints.json            # Endpoint and URL findings
│   ├── dependencies.json         # Detected package/dependency data
│   ├── file-index.json           # File classifications and metadata
│   ├── findings.json             # Combined static-analysis findings
│   └── source-export.json        # Detailed source-export inclusion/skip list
├── logs/
│   └── extraction.log
├── source-code.txt               # Combined recoverable text/source export
├── report.json                   # Machine-readable run report
└── report.md                     # Human-readable run report
```

The exact set of files depends on the contents of the input DMG and which supported formats are present. Reports describe findings actually collected; no example counts or endpoints are hardcoded.

## Source recovery and interpretation

`source-code.txt` contains complete text files discovered in the preserved application and extracted payloads, subject to the export size limit. It includes a file header before each file so content can be traced back to its path. The detailed index at `analysis/source-export.json` lists which files were included and which were skipped.

Keep these distinctions in mind:

- **Original source:** A packaged application may not include the original source tree at all.
- **Bundled/minified JavaScript:** Extractable and searchable, but not necessarily the same as the developer's original source.
- **Source maps:** May point to original source files. Maps containing embedded `sourcesContent` can contain additional source text.
- **Native binaries:** Architecture, linked libraries, symbols, and debug metadata may be inspectable, but these are not original source code.
- **Binary resources:** Images, fonts, compiled assets, and other non-text files stay in the extracted file structure; they are not pasted into `source-code.txt`.

## Security and privacy notes

Treat disk images and their contents as untrusted input. `dmgx` mounts the input read-only, does not execute applications or scripts, checks archive paths, skips unsafe symlinks, enforces extraction limits, and does not upload telemetry or extracted content.

Static analysis is heuristic: it can miss findings or produce false positives. Credential-redaction patterns are not a guarantee that all secrets will be detected.

**Review before sharing:** `source-code.txt` intentionally preserves source contents and may contain API keys, tokens, private endpoints, personal data, or other sensitive strings. Analysis reports apply common credential-redaction patterns, but they should also be reviewed before publication. Do not commit extracted proprietary application content or confidential findings to a public repository unless you are authorized to publish them.

Use `dmgx` only on software and disk images you own or are authorized to inspect. This project is an extraction and static-inspection tool, not a decompiler that can restore arbitrary source code from compiled binaries.

## Testing

Run the built-in offline tests:

```bash
dmgx --self-test
```

The suite exercises ASAR parsing, archive path traversal defenses, duplicate archive entries, safe path handling, URL-analysis edge cases, source-export limits, and a synthetic end-to-end pipeline fixture. The fixture does **not** mount a real macOS DMG; native mounting and inspection should also be tested on a Mac with a known test image before relying on the tool in production.

## Exit status

| Exit code | Meaning |
| ---: | --- |
| `0` | Success. |
| `2` | Invalid input/arguments, or a protected/occupied output path. |
| `3` | macOS or required platform utility unavailable. |
| `4` | Mounting, archive-processing, or resource-limit failure. |
| `5` | Unexpected failure or failing built-in test suite. |
| `130` | Interrupted by Ctrl+C. |

## Contributing

Bug reports and pull requests are welcome. For reproducible bug reports, include the `dmgx` version, macOS version, Python version, the command used, and the relevant sanitized error output. Do not attach proprietary DMGs or publish extracted application source without permission.


## License

`dmgx` is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.
