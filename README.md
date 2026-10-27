# dmgx — macOS DMG Source Inspector & Extractor

`dmgx` is a terminal-only Python tool for inspecting macOS `.dmg` disk images, preserving application bundles, extracting recoverable content from Electron ASAR archives and supported embedded archives, and generating source-code and static-analysis reports.

The goal is to make an initial inspection as simple as:

```bash
dmgx "$HOME/Downloads/Application.dmg"
```

> **Important limitation:** `dmgx` can only recover files and text that are present in the packaged application or its resources. It cannot reconstruct original Swift, Objective-C, C/C++, or other source files from compiled native binaries. Electron applications may contain bundled, generated, or minified JavaScript rather than the original project. Formatting bundled code can improve readability, but it does not restore the original source tree.

## Features

- **Terminal-only workflow.** No GUI, dashboard, menu-bar application, or graphical file browser.
- **Read-only DMG mounting.** Uses macOS `hdiutil`; volumes are detached at the end unless `--keep-mounted` is supplied.
- **Application discovery.** Finds `.app` bundles, reads application metadata, detects Electron indicators, and collects native executable metadata when available.
- **Electron ASAR extraction.** Preserves original application files and ASAR archives, then extracts ASAR payloads into a separate directory using a bounds-checked ASAR reader built into the script.
- **Embedded archive extraction.** Supports ZIP, TAR, GZIP, and common compressed TAR variants, with path-safety checks.
- **Consolidated source export.** Writes recoverable text/source-like files to `source-code.txt`. The accompanying `analysis/source-export.json` lists included and skipped files.
- **Static analysis.** Looks for URLs and endpoints, API route references, environment-variable names, IPC channel names, package/dependency data, source-map references, and file classifications.
- **Native binary inspection.** Collects available architecture, linked-library, symbol, and debug-information details using macOS utilities when available.
- **Reports.** Produces machine-readable `report.json` and readable `report.md`, plus detailed JSON files under `analysis/`.
- **Optional formatting.** Writes formatted copies of supported files to `formatted/`; preserved originals and extracted payloads are not formatted in place.
- **Resource limits.** Configurable file-count, per-file, total-size, scan-size, and source-export-size limits.
- **Local-only processing.** No telemetry or upload of extracted files. The application and extracted scripts are not executed.
- **Built-in tests.** `--self-test` runs the offline test suite without mounting a real DMG.

## Requirements

- macOS for actual disk-image mounting and extraction.
- Python 3.11 or newer.
- `hdiutil`, included with macOS.

Other Apple command-line utilities are used when available, including `ditto`, `file`, `codesign`, `plutil`, `otool`, `lipo`, `nm`, and `dwarfdump`. Missing optional utilities may reduce collected metadata, but they are not Python package dependencies.

**No third-party Python packages are required.**

### Optional source formatters

`--format` handles JSON formatting internally. Additional formatters can be installed for supported file types:

- [Prettier](https://prettier.io/) for supported JavaScript, TypeScript, CSS, HTML, YAML, and Markdown files.
- [Black](https://black.readthedocs.io/) for Python files.

If an optional formatter is not installed or cannot process a file, `dmgx` records the result. Formatting never overwrites preserved originals.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/grendizerh/dmgx.git
cd dmgx
```

The repository contains the standalone `dmgx.py` script. You do not need to download a separate script or install Python packages.

### 2. Verify Python and run the built-in tests

```bash
python3 --version
chmod +x dmgx.py
./dmgx.py --version
./dmgx.py --self-test
```

Use Python 3.11 or newer. The self-test command should finish with `OK` before you rely on the installation.

### 3. Install the `dmgx` command

The following installs the script to `~/bin/dmgx`:

```bash
mkdir -p "$HOME/bin"
install -m 755 ./dmgx.py "$HOME/bin/dmgx"
```

If `~/bin` is not already on your Zsh `PATH`, add it and reload the shell configuration:

```bash
grep -qxF 'export PATH="$HOME/bin:$PATH"' "$HOME/.zshrc" \
  || printf '\nexport PATH="$HOME/bin:$PATH"\n' >> "$HOME/.zshrc"
source "$HOME/.zshrc"
```

Verify the installed command:

```bash
command -v dmgx
dmgx --version
dmgx --help
dmgx --self-test
```

`command -v dmgx` should point to the executable you installed, usually `$HOME/bin/dmgx`.

### Updating an existing checkout

From the repository directory, fetch the latest fast-forward update, run the tests, and reinstall:

```bash
cd "$HOME/dmgx"
git pull --ff-only
./dmgx.py --self-test
install -m 755 ./dmgx.py "$HOME/bin/dmgx"
dmgx --version
```

If your repository is in another directory, replace `$HOME/dmgx` with that path. If `git pull --ff-only` fails because your local branch has diverged, resolve the Git history first instead of forcing a reset.

## Quick start

### 1. Preview the DMG

```bash
dmgx "$HOME/Downloads/Application.dmg" --dry-run
```

A dry run mounts the image read-only and scans mounted contents to preview the planned work. It does not create the extraction output or extract files, but it still needs macOS to mount the image and can fail if mounting fails.

### 2. Extract and analyze

```bash
dmgx "$HOME/Downloads/Application.dmg"
```

By default, the output directory is created beside the DMG and named `<DMG-name>-extracted`.

### 3. Choose the output directory

```bash
dmgx "$HOME/Downloads/My Application.dmg" \
  --output "$HOME/Desktop/My Application-extracted"
```

Quote paths that contain spaces.

### 4. Read the source-code export

After extraction, open the consolidated export using a pager:

```bash
less "$HOME/Downloads/Application-extracted/source-code.txt"
```

In `less`, type `/` followed by a search term to search, and press `q` to quit.

To print the export to standard output after extraction:

```bash
dmgx "$HOME/Downloads/Application.dmg" --show-source
```

`--show-source` may print a very large amount of text. Using `less` on `source-code.txt` is generally more convenient. `--show-source` cannot be combined with `--dry-run`.

## Command-line reference

```text
dmgx [OPTIONS] DMG

dmgx --help
dmgx --version
dmgx --self-test
```

| Option | Description |
| --- | --- |
| `--output DIR`, `-o DIR` | Output directory. Defaults to `<DMG-name>-extracted` beside the input DMG. |
| `--dry-run` | Mount read-only and preview planned work without creating extraction output. |
| `--format` | Write formatted copies of supported source files to `formatted/`. Originals and extracted files are not modified in place. |
| `--analyze` | Explicitly request static analysis; analysis is also part of the normal pipeline. |
| `--report` | Explicitly request `report.json` and `report.md`; reports are generated by default. |
| `--show-source` | Print the full `source-code.txt` export to stdout after extraction. Can produce extensive output. |
| `--keep-mounted` | Leave read-only mounted volume(s) attached after the run. |
| `--verbose` | Show additional diagnostic details and write them to `logs/extraction.log`. |
| `--quiet` | Suppress progress output while keeping errors visible. |
| `--yes` | Accept safe defaults in automation. Does **not** bypass overwrite protection. |
| `--force` | Replace an existing output path. This is destructive; use only when intended. |
| `--max-files N` | Maximum regular-file count scanned/extracted. Default: `200000`. |
| `--max-file-size BYTES` | Maximum individual file size. Default: `1073741824` bytes (1 GiB). |
| `--max-total-size BYTES` | Maximum total bytes copied/extracted. Default: `21474836480` bytes (20 GiB). |
| `--max-scan-size BYTES` | Maximum bytes read from one text file for analysis/formatting. Default: `33554432` bytes (32 MiB). |
| `--max-source-export-size BYTES` | Maximum total source/text content in `source-code.txt`. Default: `536870912` bytes (512 MiB). Files are skipped whole if they exceed the remaining budget. |
| `--self-test` | Run built-in offline tests; no DMG or macOS mounting is required. |

Existing output is not replaced unless `--force` is explicitly provided. `--yes` does not override that protection. If a run stops part-way through, inspect the output and logs before rerunning; using a new output directory is often safer than overwriting the previous one.

## Output layout

A typical output directory looks like this (the exact contents depend on the image):

```text
Application-extracted/
├── original/
│   └── Application.app/          # Preserved app bundle and original archives
├── extracted/
│   ├── asar/                     # Extracted ASAR payloads
│   └── archives/                 # Supported embedded archives
├── formatted/                    # Optional transformed copies
├── analysis/
│   ├── endpoints.json            # URL and endpoint findings
│   ├── dependencies.json          # Detected package/dependency data
│   ├── file-index.json            # File classifications and metadata
│   ├── findings.json              # Combined static-analysis findings
│   └── source-export.json         # Source-export inclusion/skip details
├── logs/
│   └── extraction.log
├── source-code.txt                # Consolidated recoverable text/source export
├── report.json                    # Machine-readable run report
└── report.md                      # Human-readable run report
```

Reports are generated from the image's actual contents and findings. Example counts shown in documentation are illustrative only; `dmgx` does not hardcode application counts, endpoint counts, or file counts.

## Understanding source recovery

`source-code.txt` combines complete readable text files detected in the preserved application and extracted payloads, subject to `--max-source-export-size`. It places a path header before each file so that content can be traced back to its location. `analysis/source-export.json` lists files included and files skipped.

Keep the following distinctions in mind:

- **Original source:** A packaged application may not include the original source tree.
- **Bundled or minified JavaScript:** It can be extracted and searched, but may not match the developer's original source files, names, comments, module boundaries, or build structure.
- **Source maps:** They may point to original source files. Maps with embedded `sourcesContent` may contain additional recoverable text; a map can also contain mapping metadata only.
- **Native binaries:** Architecture, linked libraries, symbols, and debug information may be inspectable, but they are not original source code. `dmgx` does not decompile native executables into original source.
- **Binary resources:** Images, fonts, compiled assets, and other binary files remain in the extracted file structure; they are not concatenated into `source-code.txt`.

Formatting makes supported text files easier to read; it does not reverse compilation or recover source that was never shipped.

## Security and privacy

Treat DMGs and their contents as untrusted input.

- DMGs are mounted read-only.
- Extracted applications and scripts are never executed.
- Archive paths are checked to defend against path traversal; unsafe symlinks are skipped.
- Duplicate archive paths are not silently overwritten.
- File-count and size limits help bound processing.
- No telemetry or extracted contents are uploaded by `dmgx`.

Static analysis is heuristic. It can miss findings or produce false positives; a detected URL does not prove that an endpoint is live, reachable, or used at runtime. Credential-redaction patterns are not guaranteed to identify every secret.

> **Review before sharing:** `source-code.txt` intentionally preserves source contents and may include credentials, tokens, private endpoints, personal data, or other sensitive information. Analysis reports apply common credential-redaction patterns, but should also be reviewed before publication. Do not commit proprietary application files or confidential findings to a public repository unless you are authorized to publish them.

Use `dmgx` only on software and disk images you own or are authorized to inspect.

## Testing and verification

Run the built-in test suite:

```bash
dmgx --self-test
```

The offline suite covers ASAR parsing, malformed archives, archive path traversal, duplicate archive entries, safe path handling, URL-analysis edge cases, source-export limits, and a synthetic end-to-end pipeline fixture.

**The synthetic fixture does not mount a real macOS DMG.** Before relying on the tool for production work, also test it on a Mac with a known, authorized test image. Successful unit tests do not prove that every DMG format, mount state, or application bundle will work.

## Exit codes

| Exit code | Meaning |
| ---: | --- |
| `0` | Success. |
| `2` | Invalid input/arguments, or a protected/occupied output path. |
| `3` | macOS or a required platform utility is unavailable. |
| `4` | Mounting, archive-processing, or resource-limit failure. |
| `5` | Unexpected failure or failing built-in test suite. |
| `130` | Interrupted with Ctrl+C. |

## Troubleshooting

### `dmgx: command not found`

Check whether `$HOME/bin` is on your `PATH` and whether the installed file exists:

```bash
ls -l "$HOME/bin/dmgx"
echo "$PATH"
command -v dmgx
```

If necessary, reload Zsh with `source "$HOME/.zshrc"` or run the script directly from the repository as `./dmgx.py`.

### `hdiutil: attach failed - Resource busy`

Check whether the image is already mounted:

```bash
hdiutil info
```

If the exact DMG is listed, identify its device and detach it normally when it is safe to do so. Do not force-detach a volume that is in use. A dry run still needs to mount the image.

### The output directory already exists

Choose a new `--output` path or, only if you intend to replace that output, use `--force`. `--yes` does not imply `--force`.

### Static analysis reports an error

Try the latest repository version and preserve the error output. If reporting a bug, include the `dmgx` version, macOS version, Python version, command used, and sanitized diagnostics. Do not attach proprietary DMGs or publish extracted source without permission.

## Contributing

Bug reports and pull requests are welcome. Please include reproducible steps and sanitized diagnostic output. Add tests for security-sensitive behavior and avoid submitting proprietary application contents, credentials, or private findings.

## License

`dmgx` is distributed under the MIT License. See [`LICENSE`](LICENSE) for the full license text.
