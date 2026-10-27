#!/usr/bin/env python3
"""dmgx: terminal-only macOS DMG inspector and recoverable-source extractor.

Python 3.11+. No third-party Python packages are required.
ASAR archives are parsed with a bounds-checked reader compatible with @electron/asar.
This tool never executes code found in disk images or archives.
"""
from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VERSION = "1.0.0"
APP_NAME = "dmgx"
DEFAULT_MAX_FILES = 200_000
DEFAULT_MAX_FILE_SIZE = 1 * 1024**3
DEFAULT_MAX_TOTAL_SIZE = 20 * 1024**3
DEFAULT_MAX_SCAN_SIZE = 32 * 1024**2
SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".sass",
    ".less", ".html", ".htm", ".xhtml", ".json", ".jsonc", ".map", ".py", ".pyi",
    ".rb", ".go", ".rs", ".swift", ".m", ".mm", ".h", ".hh", ".hpp", ".c", ".cc",
    ".cpp", ".java", ".kt", ".kts", ".php", ".sh", ".bash", ".zsh", ".fish", ".sql",
    ".vue", ".svelte", ".graphql", ".gql", ".xml", ".plist", ".yaml", ".yml", ".toml",
    ".ini", ".conf", ".properties", ".env", ".md", ".txt", ".gradle", ".proto", ".ex",
    ".exs", ".erl", ".hrl", ".clj", ".cljs", ".scala", ".dart", ".lua", ".r", ".jl",
    ".wasm", ".config", ".lock"
}
CONFIG_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "tsconfig.json", "webpack.config.js", "vite.config.js", "vite.config.ts", "rollup.config.js",
    "electron-builder.yml", "electron-builder.yaml", "electron-builder.json", "forge.config.js",
    "babel.config.js", ".babelrc", ".npmrc", ".env", ".env.example", "config.json",
    "settings.json", "defaults.json", "manifest.json", "info.plist"
}
TEXT_EXTS = SOURCE_EXTS | {".log", ".csv", ".svg", ".strings", ".stringsdict", ".xcconfig"}
ASSET_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".pdf", ".mp3", ".wav",
    ".mp4", ".mov", ".webm", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".pak", ".dat",
    ".bin", ".car", ".nib", ".storyboardc", ".model", ".metallib", ".strings"
}
ARCHIVE_EXTS = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".txz", ".tbz", ".tbz2"}
SKIP_DIR_NAMES = {".Trashes", ".Spotlight-V100", ".fseventsd", ".TemporaryItems", ".DocumentRevisions-V100"}
SENSITIVE_QUERY_KEYS = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|authorization|auth|credential|signature|session|private[_-]?key|client[_-]?secret)")
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret)\s*[:=]\s*(['\"]?)[^\s'\";,]{6,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]
URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\]+")
ROUTE_RE = re.compile(r"(?i)[\"'`]((?:/api(?:/v\d+)?|/v\d+|/graphql|/rest|/rpc|/oauth|/auth|/webhooks?)(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}-]*)*)[\"'`]")
ENV_RE = re.compile(r"\b(?:Deno\.env\.get|os\.environ(?:\.get)?|getenv)\s*\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]")
ENV_BRACKET_RE = re.compile(r"\b(?:process\.env|import\.meta\.env)\s*\[\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]\s*\]")
ENV_DOT_RE = re.compile(r"\b(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)")
ENV_LINE_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{1,})\s*=")
IPC_RE = re.compile(r"\b(?:ipcMain|ipcRenderer|webContents)\s*\.\s*(?:handleOnce|handle|invoke|sendSync|send|on|once)\s*\(\s*['\"`]([^'\"`\r\n]{1,160})['\"`]")
SOURCE_MAP_RE = re.compile(r"(?i)sourceMappingURL\s*=\s*([^\s*]+)")

class DmgxError(Exception):
    """Expected failure with a process exit status."""
    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code

@dataclass
class Limits:
    max_files: int = DEFAULT_MAX_FILES
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    max_scan_size: int = DEFAULT_MAX_SCAN_SIZE

@dataclass
class Budget:
    limits: Limits
    files: int = 0
    bytes_written: int = 0
    def add(self, size: int, label: str, *, count: bool = True) -> None:
        if size < 0:
            raise DmgxError(f"Invalid negative size while processing {label}")
        if size > self.limits.max_file_size:
            raise DmgxError(f"File exceeds --max-file-size ({self.limits.max_file_size} bytes): {label}", 4)
        if count and self.files + 1 > self.limits.max_files:
            raise DmgxError(f"File-count limit exceeded (--max-files {self.limits.max_files})", 4)
        if self.bytes_written + size > self.limits.max_total_size:
            raise DmgxError(f"Total output limit exceeded (--max-total-size {self.limits.max_total_size} bytes)", 4)
        if count:
            self.files += 1
        self.bytes_written += size

@dataclass
class Mount:
    mount_point: Path
    device: str | None = None

@dataclass
class RunContext:
    input_path: Path
    output_path: Path
    args: argparse.Namespace
    limits: Limits
    logger: logging.Logger
    start_time: float = field(default_factory=time.monotonic)
    mounts: list[Mount] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    applications: list[dict[str, Any]] = field(default_factory=list)
    archives: list[dict[str, Any]] = field(default_factory=list)
    bundle_items: list[dict[str, Any]] = field(default_factory=list)
    analysis: dict[str, Any] = field(default_factory=dict)
    image_metadata: dict[str, Any] = field(default_factory=dict)
    output_budget: Budget | None = None


def redact_text(text: str) -> str:
    """Redact common credential-shaped strings without retaining their values."""
    out = text
    for pattern in SECRET_PATTERNS:
        if pattern is SECRET_PATTERNS[0]:
            out = pattern.sub(lambda m: m.group(1) + "<REDACTED>", out)
        elif pattern is SECRET_PATTERNS[1]:
            out = pattern.sub(lambda m: m.group(1) + "=<REDACTED>", out)
        else:
            out = pattern.sub("<REDACTED_JWT>", out)
    return out


def sanitize_url(raw: str) -> str:
    raw = raw.rstrip(".,;:!?)]]}")
    try:
        p = urlsplit(raw)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        if p.username or p.password:
            host = "<REDACTED>@" + host
        query = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            query.append((k, "<REDACTED>" if SENSITIVE_QUERY_KEYS.search(k) else v))
        return urlunsplit((p.scheme.lower(), host, p.path, urlencode(query), ""))
    except Exception:
        return redact_text(raw)


def setup_logger(output: Path | None, verbose: bool, quiet: bool) -> logging.Logger:
    logger = logging.getLogger("dmgx")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else (logging.ERROR if quiet else logging.WARNING))
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console)
    if output and output.exists() and output.is_dir():
        logs = output / "logs"
        try:
            logs.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(logs / "extraction.log", encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(fh)
        except OSError:
            pass
    return logger


def log_warning(ctx: RunContext, message: str) -> None:
    safe = redact_text(message)
    ctx.warnings.append(safe)
    ctx.logger.warning(safe)


def log_error(ctx: RunContext, message: str) -> None:
    safe = redact_text(message)
    ctx.errors.append(safe)
    ctx.logger.error(safe)


def progress(index: int, total: int, message: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[{index}/{total}] {message}", file=sys.stderr, flush=True)


def run_command(command: Sequence[str], *, timeout: int = 90, check: bool = False,
                input_text: str | None = None, logger: logging.Logger | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke a native utility without a shell; never run extracted application code."""
    try:
        cp = subprocess.run(
            list(command), text=True, input=input_text, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except FileNotFoundError as exc:
        raise DmgxError(f"Required command not found: {command[0]}. Install it or add it to PATH.", 3) from exc
    except subprocess.TimeoutExpired as exc:
        raise DmgxError(f"Command timed out after {timeout}s: {Path(command[0]).name}", 4) from exc
    if logger:
        logger.debug("Command %s returned %s", Path(command[0]).name, cp.returncode)
    if check and cp.returncode != 0:
        detail = redact_text((cp.stderr or cp.stdout or "").strip())[-1200:]
        raise DmgxError(f"Command failed ({cp.returncode}): {Path(command[0]).name}" + (f": {detail}" if detail else ""), 4)
    return cp


def validate_input_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    try:
        path = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise DmgxError(f"Input file does not exist: {value}", 2) from exc
    except OSError as exc:
        raise DmgxError(f"Cannot resolve input path {value!s}: {exc}", 2) from exc
    if not path.is_file():
        raise DmgxError(f"Input is not a regular file: {path}", 2)
    if path.suffix.lower() != ".dmg":
        raise DmgxError(f"Input must have a .dmg extension: {path}", 2)
    if path.stat().st_size <= 0:
        raise DmgxError(f"Input DMG is empty: {path}", 2)
    return path


def default_output_path(input_path: Path) -> Path:
    return input_path.with_name(input_path.stem + "-extracted")


def resolve_output_path(raw: str | None, input_path: Path) -> Path:
    path = Path(raw).expanduser() if raw else default_output_path(input_path)
    if raw is not None and (not path.name or path.name in {".", ".."}):
        raise DmgxError("Output must name a dedicated directory; --output . and parent directories are refused.", 2)
    if not path.is_absolute():
        path = Path.cwd() / path
    # Resolve the parent so non-existing final components are kept lexical and predictable.
    parent = path.parent.resolve(strict=False)
    result = parent / path.name
    home = Path.home().resolve()
    cwd = Path.cwd().resolve()
    if result == Path(result.anchor) or result == home or result.parent == Path(result.anchor):
        raise DmgxError(f"Unsafe output path refused: {result}", 2)
    # Never allow --force to target the working directory or any directory containing it/home/input.
    for protected in (cwd, home, input_path):
        try:
            if os.path.commonpath([str(result), str(protected)]) == str(result):
                raise DmgxError(f"Output directory must not contain a protected path ({protected}).", 2)
        except ValueError:
            pass
    return result


def prepare_output(output: Path, force: bool) -> None:
    if output.is_symlink():
        if not force:
            raise DmgxError(f"Output path already exists (use --force to replace it): {output}", 2)
        output.unlink()
    elif output.exists():
        if not force:
            raise DmgxError(f"Output path already exists (use --force to replace it): {output}", 2)
        if output.is_dir():
            if output.resolve() == Path.home().resolve() or output.resolve() == Path(output.anchor):
                raise DmgxError(f"Refusing to remove a protected directory: {output}", 2)
            shutil.rmtree(output)
        else:
            output.unlink()
    output.mkdir(parents=True, exist_ok=False)


def _mount_info_from_plist(data: bytes) -> list[Mount]:
    try:
        obj = plistlib.loads(data)
    except Exception as exc:
        raise DmgxError(f"Could not parse hdiutil mount metadata: {exc}", 4) from exc
    result: list[Mount] = []
    for entity in obj.get("system-entities", []):
        mp = entity.get("mount-point")
        if mp:
            result.append(Mount(Path(mp), entity.get("dev-entry")))
    return result


def validate_image_and_read_metadata(ctx: RunContext) -> None:
    if sys.platform != "darwin":
        raise DmgxError("DMG extraction requires macOS (hdiutil is unavailable on this platform). You can run --self-test here.", 3)
    if not shutil.which("hdiutil"):
        raise DmgxError("Missing required macOS utility: hdiutil", 3)
    info = run_command(["hdiutil", "imageinfo", "-plist", str(ctx.input_path)], timeout=60, logger=ctx.logger)
    if info.returncode != 0:
        # Some macOS releases accept imageinfo without -plist only.
        info = run_command(["hdiutil", "imageinfo", str(ctx.input_path)], timeout=60, logger=ctx.logger)
        if info.returncode != 0:
            detail = redact_text((info.stderr or info.stdout or "invalid disk image").strip())[-1000:]
            raise DmgxError(f"hdiutil could not validate the disk image: {detail}", 2)
        ctx.image_metadata = {"raw_imageinfo": redact_text(info.stdout.strip())[:12000]}
    else:
        try:
            parsed = plistlib.loads(info.stdout.encode("utf-8", "surrogateescape")) if isinstance(info.stdout, str) else plistlib.loads(info.stdout)
            ctx.image_metadata = parsed if isinstance(parsed, dict) else {"metadata": parsed}
        except Exception:
            ctx.image_metadata = {"raw_imageinfo": redact_text(info.stdout.strip())[:12000]}
    file_tool = shutil.which("file")
    if file_tool:
        fp = run_command([file_tool, "-b", str(ctx.input_path)], timeout=20, logger=ctx.logger)
        ctx.image_metadata["file_identification"] = redact_text(fp.stdout.strip())[:1000]
    # hdiutil verify may report failure for images without a supported checksum; it is advisory.
    verify = run_command(["hdiutil", "verify", str(ctx.input_path)], timeout=180, logger=ctx.logger)
    ctx.image_metadata["checksum_verification"] = "passed" if verify.returncode == 0 else "unavailable_or_failed"
    if verify.returncode != 0:
        log_warning(ctx, "hdiutil verify did not confirm a checksum; continuing to inspect the image structure.")


def mount_image(ctx: RunContext) -> list[Mount]:
    cp = run_command([
        "hdiutil", "attach", "-readonly", "-nobrowse", "-owners", "off", "-plist", str(ctx.input_path)
    ], timeout=180, logger=ctx.logger)
    if cp.returncode != 0:
        detail = redact_text((cp.stderr or cp.stdout or "mount failed").strip())[-1200:]
        raise DmgxError(f"Could not mount DMG read-only: {detail}", 4)
    mounts = _mount_info_from_plist(cp.stdout.encode("utf-8", "surrogateescape"))
    mounts = [m for m in mounts if m.mount_point.exists() and m.mount_point.is_dir()]
    if not mounts:
        raise DmgxError("hdiutil attached the image but reported no mounted volumes.", 4)
    ctx.mounts.extend(mounts)
    return mounts


def unmount_all(ctx: RunContext) -> None:
    if getattr(ctx.args, "keep_mounted", False):
        return
    for mount in reversed(ctx.mounts):
        try:
            cp = run_command(["hdiutil", "detach", str(mount.mount_point)], timeout=60, logger=ctx.logger)
            if cp.returncode != 0:
                # A device path can succeed when a mount path does not.
                if mount.device:
                    cp = run_command(["hdiutil", "detach", mount.device], timeout=60, logger=ctx.logger)
            if cp.returncode != 0:
                detail = redact_text((cp.stderr or cp.stdout or "").strip())[-400:]
                log_error(ctx, f"Could not unmount {mount.mount_point}: {detail}")
        except DmgxError as exc:
            log_error(ctx, f"Could not unmount {mount.mount_point}: {exc}")
    ctx.mounts.clear()


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath([str(path.resolve(strict=False)), str(parent.resolve(strict=False))]) == str(parent.resolve(strict=False))
    except (ValueError, OSError, RuntimeError):
        return False


def safe_relative_path(value: str | PurePosixPath) -> Path:
    raw = str(value)
    if not raw or "\x00" in raw or "\\" in raw:
        raise DmgxError(f"Unsafe archive path rejected: {raw!r}", 4)
    p = PurePosixPath(raw)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        raise DmgxError(f"Unsafe archive path rejected: {raw!r}", 4)
    if p.parts and re.match(r"^[A-Za-z]:", p.parts[0]):
        raise DmgxError(f"Unsafe archive path rejected: {raw!r}", 4)
    return Path(*p.parts)


def safe_symlink_target(link_path: Path, target: str, root: Path) -> bool:
    if not target or os.path.isabs(target):
        return False
    resolved = (link_path.parent / target).resolve(strict=False)
    return path_is_within(resolved, root)


def scan_tree_limits(root: Path, limits: Limits) -> dict[str, int]:
    count = 0
    total_size = 0
    visited: set[tuple[int, int]] = set()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur = Path(current)
        kept_dirs = []
        for d in dirs:
            if d in SKIP_DIR_NAMES:
                continue
            p = cur / d
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            inode = (st.st_dev, st.st_ino)
            if inode in visited:
                continue
            visited.add(inode)
            kept_dirs.append(d)
        dirs[:] = kept_dirs
        for name in files:
            p = cur / name
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            count += 1
            total_size += st.st_size
            if count > limits.max_files:
                raise DmgxError(f"Input volume contains more than --max-files ({limits.max_files}) regular files.", 4)
            if st.st_size > limits.max_file_size:
                raise DmgxError(f"Input file exceeds --max-file-size ({limits.max_file_size} bytes): {p}", 4)
            if total_size > limits.max_total_size:
                raise DmgxError(f"Input volume exceeds --max-total-size ({limits.max_total_size} bytes).", 4)
    return {"files": count, "bytes": total_size}


def _copy_file_safe(src: Path, dst: Path, source_root: Path, budget: Budget, warnings: list[str]) -> bool:
    try:
        st = src.lstat()
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(src)
            except OSError as exc:
                warnings.append(f"Could not read symlink {src}: {exc}")
                return False
            if not safe_symlink_target(src, target, source_root):
                warnings.append(f"Skipped symlink that resolves outside the image: {src}")
                return False
            budget.add(0, str(src))
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, dst)
            return True
        if stat.S_ISDIR(st.st_mode):
            raise ValueError("directory passed to file copier")
        if not stat.S_ISREG(st.st_mode):
            warnings.append(f"Skipped non-regular filesystem entry: {src}")
            return False
        budget.add(st.st_size, str(src))
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Open the source only if it is still a regular file; mounted DMGs are read-only.
        with src.open("rb") as fin, dst.open("xb") as fout:
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
        try:
            shutil.copystat(src, dst, follow_symlinks=False)
        except OSError:
            pass
        return True
    except FileExistsError:
        warnings.append(f"Duplicate output path skipped rather than overwritten: {dst}")
        return False
    except DmgxError:
        raise
    except (OSError, ValueError) as exc:
        warnings.append(f"Could not copy {src}: {exc}")
        return False


def copy_tree_safe(src_root: Path, dst_root: Path, budget: Budget, warnings: list[str], *, exclude_names: set[str] | None = None) -> int:
    """Copy a tree without following symlinks; unsafe symlinks are skipped."""
    exclude_names = exclude_names or set()
    copied = 0
    dst_root.mkdir(parents=True, exist_ok=True)
    for current, dirs, files in os.walk(src_root, topdown=True, followlinks=False):
        current_path = Path(current)
        rel_dir = current_path.relative_to(src_root)
        dst_dir = dst_root / rel_dir
        dst_dir.mkdir(parents=True, exist_ok=True)
        new_dirs: list[str] = []
        for name in sorted(dirs):
            if name in exclude_names or name in SKIP_DIR_NAMES:
                continue
            source_dir = current_path / name
            target_dir = dst_dir / name
            try:
                st = source_dir.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                if _copy_file_safe(source_dir, target_dir, src_root, budget, warnings):
                    copied += 1
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            target_dir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copystat(source_dir, target_dir, follow_symlinks=False)
            except OSError:
                pass
            new_dirs.append(name)
        dirs[:] = new_dirs
        for name in sorted(files):
            if name in exclude_names:
                continue
            src = current_path / name
            dst = dst_dir / name
            if _copy_file_safe(src, dst, src_root, budget, warnings):
                copied += 1
    return copied


def tree_symlinks_safe(root: Path, volume_root: Path) -> bool:
    """Return False if ditto would encounter an absolute or out-of-volume symlink."""
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for name in list(dirs) + list(files):
            link = base / name
            try:
                if link.is_symlink() and not safe_symlink_target(link, os.readlink(link), volume_root):
                    return False
            except (OSError, RuntimeError):
                return False
        dirs[:] = [d for d in dirs if not (base / d).is_symlink()]
    return True


def reserve_tree_budget(root: Path, budget: Budget) -> int:
    """Reserve output limits before asking ditto to copy a directory tree."""
    reserved_files = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        names = list(files) + [d for d in dirs if (base / d).is_symlink()]
        dirs[:] = [d for d in dirs if not (base / d).is_symlink()]
        for name in names:
            item = base / name
            try:
                st = item.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                budget.add(0, str(item))
                reserved_files += 1
            elif stat.S_ISREG(st.st_mode):
                budget.add(st.st_size, str(item))
                reserved_files += 1
    return reserved_files


def copy_directory_prefer_ditto(source: Path, dest: Path, volume_root: Path, budget: Budget,
                                warnings: list[str], logger: logging.Logger) -> int:
    """Use Apple's metadata-preserving ditto if safe; otherwise use the guarded copier."""
    ditto = shutil.which("ditto")
    if ditto and tree_symlinks_safe(source, volume_root):
        files_before, bytes_before = budget.files, budget.bytes_written
        try:
            expected_count = reserve_tree_budget(source, budget)
            dest.parent.mkdir(parents=True, exist_ok=True)
            cp = run_command([ditto, "--rsrc", "--extattr", str(source), str(dest)], timeout=300, logger=logger)
            if cp.returncode == 0 and dest.is_dir():
                return expected_count
            detail = redact_text((cp.stderr or cp.stdout or "ditto failed").strip())[-500:]
            warnings.append(f"ditto could not copy {source.name}; falling back to guarded Python copy: {detail}")
        except DmgxError as exc:
            warnings.append(f"ditto copy preflight failed for {source.name}; falling back to guarded Python copy: {exc}")
        except OSError as exc:
            warnings.append(f"ditto failed for {source.name}; falling back to guarded Python copy: {exc}")
        if dest.is_symlink():
            dest.unlink(missing_ok=True)
        elif dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        budget.files, budget.bytes_written = files_before, bytes_before
    return copy_tree_safe(source, dest, budget, warnings)


def validate_plist(path: Path, logger: logging.Logger) -> str:
    plutil = shutil.which("plutil")
    if not plutil:
        return "not checked (plutil unavailable; Python plistlib used)"
    cp = run_command([plutil, "-lint", str(path)], timeout=20, logger=logger)
    return "passed" if cp.returncode == 0 else "failed"


def inspect_codesign(app_path: Path, logger: logging.Logger) -> dict[str, Any]:
    codesign = shutil.which("codesign")
    if not codesign:
        return {"available": False, "signature_present": None, "verification": "not checked"}
    details = run_command([codesign, "-dv", "--verbose=2", str(app_path)], timeout=45, logger=logger)
    combined = (details.stdout or "") + "\n" + (details.stderr or "")
    result: dict[str, Any] = {
        "available": True,
        "signature_present": details.returncode == 0 and "code object is not signed" not in combined.lower(),
        "verification": "not checked",
    }
    for key in ("Identifier", "TeamIdentifier", "Authority", "Format", "CodeDirectory"):
        matches = re.findall(rf"(?m)^{re.escape(key)}=(.+)$", combined)
        if matches:
            result[key.lower()] = matches[0].strip()[:500]
    verify = run_command([codesign, "--verify", "--deep", "--strict", str(app_path)], timeout=90, logger=logger)
    result["verification"] = "passed" if verify.returncode == 0 else "failed_or_unsigned"
    return result


def parse_info_plist(app_path: Path) -> dict[str, Any]:
    info_path = app_path / "Contents" / "Info.plist"
    if not info_path.is_file():
        return {}
    try:
        with info_path.open("rb") as fh:
            data = plistlib.load(fh)
        if isinstance(data, dict):
            allowed = ["CFBundleName", "CFBundleDisplayName", "CFBundleIdentifier", "CFBundleExecutable",
                       "CFBundleShortVersionString", "CFBundleVersion", "LSMinimumSystemVersion", "LSArchitecturePriority"]
            return {key: data[key] for key in allowed if key in data and isinstance(data[key], (str, int, float, list))}
    except Exception:
        return {"info_plist_parse_error": True}
    return {}


def discover_applications(mounts: Sequence[Mount]) -> list[dict[str, Any]]:
    apps: list[dict[str, Any]] = []
    for mount in mounts:
        root = mount.mount_point
        for current, dirs, _files in os.walk(root, topdown=True, followlinks=False):
            base = Path(current)
            # Do not follow symlinked directories, installer packages, or already-found app bundles.
            keep: list[str] = []
            for name in sorted(dirs):
                p = base / name
                try:
                    if p.is_symlink():
                        continue
                except OSError:
                    continue
                if name in SKIP_DIR_NAMES:
                    continue
                if name.lower().endswith(".app"):
                    try:
                        st = p.lstat()
                        if stat.S_ISDIR(st.st_mode):
                            apps.append({"source": p, "mount": mount, "relative": p.relative_to(root), "info": parse_info_plist(p)})
                    except OSError:
                        pass
                    continue
                if name.lower().endswith((".pkg", ".framework", ".xcframework", ".dsym")):
                    # These are separately copied as bundles; do not duplicate traversal inside them.
                    continue
                keep.append(name)
            dirs[:] = keep
    # Deduplicate by absolute path defensively.
    unique: dict[str, dict[str, Any]] = {str(item["source"]): item for item in apps}
    return sorted(unique.values(), key=lambda item: str(item["source"]).casefold())


def discover_copy_roots(mount: Mount, all_mounts: Sequence[Mount]) -> list[Path]:
    """Select roots to preserve: complete mounted volume contents, excluding OS noise."""
    root = mount.mount_point
    return [p for p in sorted(root.iterdir(), key=lambda p: p.name.casefold()) if p.name not in SKIP_DIR_NAMES]


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{value} B"


def magic_kind(head: bytes) -> str | None:
    if head.startswith((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")):
        return "Mach-O native binary"
    if head.startswith(b"\x7fELF"):
        return "ELF native binary"
    if head.startswith(b"MZ"):
        return "PE/COFF executable"
    if head.startswith(b"\x00asm"):
        return "WebAssembly module"
    if head.startswith(b"%PDF-"):
        return "PDF document"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "GIF image"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if head.startswith(b"xar!"):
        return "XAR installer archive"
    if head.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if head.startswith(b"bplist00"):
        return "Binary property list"
    return None


def classify_file(path: Path, rel: str, head: bytes, size: int, sample_text: str | None = None) -> tuple[str, dict[str, Any]]:
    lower = path.name.lower()
    ext = path.suffix.lower()
    parts = {p.lower() for p in Path(rel).parts}
    magic = magic_kind(head)
    details: dict[str, Any] = {"magic": magic}
    if ".dsym" in parts or ext in {".dwarf", ".pdb", ".sym", ".debug"}:
        return "debug symbols", details
    if ext == ".pkg" or magic == "XAR installer archive":
        return "installer package", details
    if ext == ".dmg":
        return "disk image", details
    if ext == ".map":
        return "source map", details
    if magic and "native binary" in magic or magic == "PE/COFF executable":
        if "frameworks" in parts or ".framework" in rel.lower():
            return "framework binary", details
        return "native executable", details
    if ext in {".dylib", ".so", ".node", ".bundle", ".kext"}:
        if "frameworks" in parts or ".framework" in rel.lower():
            return "framework binary", details
        return "native executable", details
    if any(p in {"node_modules", "vendor", "third_party", "third-party", "vendors"} for p in parts):
        return "third-party dependency", details
    if lower in CONFIG_NAMES or ext in {".plist", ".ini", ".toml", ".yaml", ".yml", ".conf", ".config"} or lower.startswith(".env"):
        return "configuration file", details
    if ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        text = sample_text if sample_text is not None else ""
        lines = text.splitlines()
        longest = max((len(line) for line in lines[:5000]), default=0)
        if size > 100_000 or longest > 1000 or (len(lines) < 4 and len(text) > 2000):
            details.update({"bundled_or_minified_heuristic": True, "sample_longest_line": longest})
            return "bundled or minified source", details
        return "original-looking source (heuristic)", details
    if ext in SOURCE_EXTS:
        return "source or text", details
    if magic in {"PNG image", "GIF image", "PDF document"} or ext in ASSET_EXTS:
        return "static asset", details
    if magic in {"ZIP archive"} or ext in ARCHIVE_EXTS or lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return "archive", details
    if not magic and head and b"\x00" not in head and is_probably_text(head):
        return "text file (unknown extension)", details
    return "unknown format", details


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return sum(1 for b in data if b in (9, 10, 13) or 32 <= b < 127) / max(1, len(data)) > 0.85


def safe_read_sample(path: Path, limit: int) -> tuple[bytes, str | None, bool]:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
        truncated = len(data) > limit
        if truncated:
            data = data[:limit]
        text = None
        if b"\x00" not in data:
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                pass
        return data[:4096], text, truncated
    except OSError:
        return b"", None, False


def iter_files_no_symlinks(root: Path) -> Iterator[Path]:
    for current, dirs, files in os.walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = [d for d in dirs if not (base / d).is_symlink() and d not in SKIP_DIR_NAMES]
        for name in files:
            path = base / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            yield path


def safe_extract_zip(archive: Path, dest: Path, budget: Budget, warnings: list[str]) -> list[str]:
    written: list[str] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                try:
                    rel = safe_relative_path(info.filename.rstrip("/"))
                except DmgxError as exc:
                    warnings.append(f"Unsafe ZIP member skipped in {archive.name}: {exc}")
                    continue
                if not info.filename or info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    warnings.append(f"ZIP symbolic link skipped: {info.filename}")
                    continue
                if info.file_size > budget.limits.max_file_size:
                    warnings.append(f"ZIP member exceeds per-file limit and was skipped: {info.filename}")
                    continue
                target = dest / rel
                if not path_is_within(target, dest):
                    warnings.append(f"ZIP member escaped output path and was skipped: {info.filename}")
                    continue
                if target.exists() or target.is_symlink():
                    warnings.append(f"Duplicate ZIP output path skipped rather than overwritten: {info.filename}")
                    continue
                reserved = False
                try:
                    budget.add(info.file_size, f"{archive.name}:{info.filename}")
                    reserved = True
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, target.open("xb") as out:
                        shutil.copyfileobj(src, out, 1024 * 1024)
                    written.append(rel.as_posix())
                except (OSError, RuntimeError, zipfile.BadZipFile, DmgxError) as exc:
                    if reserved and isinstance(exc, FileExistsError):
                        budget.files -= 1
                        budget.bytes_written -= info.file_size
                    warnings.append(f"Could not extract ZIP member {info.filename}: {exc}")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        warnings.append(f"Corrupt or unreadable ZIP archive {archive}: {exc}")
    return written


def safe_extract_tar(archive: Path, dest: Path, budget: Budget, warnings: list[str]) -> list[str]:
    written: list[str] = []
    try:
        with tarfile.open(archive, mode="r:*") as tf:
            for member in tf:
                if not member.isfile():
                    if member.issym() or member.islnk():
                        warnings.append(f"TAR link skipped: {member.name}")
                    continue
                try:
                    rel = safe_relative_path(member.name)
                except DmgxError as exc:
                    warnings.append(f"Unsafe TAR member skipped in {archive.name}: {exc}")
                    continue
                if member.size > budget.limits.max_file_size:
                    warnings.append(f"TAR member exceeds per-file limit and was skipped: {member.name}")
                    continue
                target = dest / rel
                if not path_is_within(target, dest):
                    warnings.append(f"TAR member escaped output path and was skipped: {member.name}")
                    continue
                if target.exists() or target.is_symlink():
                    warnings.append(f"Duplicate TAR output path skipped rather than overwritten: {member.name}")
                    continue
                stream = tf.extractfile(member)
                if stream is None:
                    continue
                reserved = False
                try:
                    budget.add(member.size, f"{archive.name}:{member.name}")
                    reserved = True
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with stream, target.open("xb") as out:
                        shutil.copyfileobj(stream, out, 1024 * 1024)
                    written.append(rel.as_posix())
                except (OSError, DmgxError) as exc:
                    if reserved and isinstance(exc, FileExistsError):
                        budget.files -= 1
                        budget.bytes_written -= member.size
                    warnings.append(f"Could not extract TAR member {member.name}: {exc}")
    except (OSError, tarfile.TarError) as exc:
        warnings.append(f"Corrupt or unreadable TAR archive {archive}: {exc}")
    return written


def safe_extract_gzip(archive: Path, dest: Path, budget: Budget, warnings: list[str]) -> list[str]:
    target_name = archive.name[:-3] if archive.name.lower().endswith(".gz") else archive.name + ".out"
    if target_name.lower().endswith(".tar"):
        return safe_extract_tar(archive, dest, budget, warnings)
    try:
        target = dest / safe_relative_path(target_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Stream decompression while enforcing both per-file and total limits.
        with gzip.open(archive, "rb") as fin:
            tmp = target.with_name(target.name + ".dmgx-tmp")
            size = 0
            try:
                with tmp.open("xb") as fout:
                    while True:
                        chunk = fin.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > budget.limits.max_file_size:
                            raise DmgxError(f"GZIP output exceeds per-file limit: {archive.name}", 4)
                        fout.write(chunk)
                budget.add(size, str(archive))
                os.replace(tmp, target)
                return [target.relative_to(dest).as_posix()]
            except Exception:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
    except (OSError, EOFError, gzip.BadGzipFile, DmgxError) as exc:
        warnings.append(f"Corrupt or unreadable GZIP archive {archive}: {exc}")
        return []


def _json_no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_asar_header(archive: Path) -> tuple[dict[str, Any], int, int]:
    """Read ASAR's two Pickle records; return (header, data_start, archive_size)."""
    try:
        archive_size = archive.stat().st_size
        with archive.open("rb") as fh:
            size_pickle = fh.read(8)
            if len(size_pickle) != 8:
                raise ValueError("truncated ASAR header-size Pickle")
            pickle_payload_size = struct.unpack_from("<I", size_pickle, 0)[0]
            header_pickle_size = struct.unpack_from("<I", size_pickle, 4)[0]
            if pickle_payload_size != 4:
                raise ValueError("invalid ASAR header-size Pickle")
            if header_pickle_size < 8 or header_pickle_size > archive_size - 8:
                raise ValueError("ASAR header size exceeds archive bounds")
            header_pickle = fh.read(header_pickle_size)
            if len(header_pickle) != header_pickle_size:
                raise ValueError("truncated ASAR header JSON Pickle")
            # Each Pickle starts with its payload length, followed by the String length.
            header_payload_size = struct.unpack_from("<I", header_pickle, 0)[0]
            json_size = struct.unpack_from("<I", header_pickle, 4)[0]
            if header_payload_size != header_pickle_size - 4:
                raise ValueError("invalid ASAR header Pickle payload length")
            if json_size < 2 or json_size > header_pickle_size - 8:
                raise ValueError("invalid ASAR JSON size")
            raw_json = header_pickle[8:8 + json_size]
            header = json.loads(raw_json.decode("utf-8"), object_pairs_hook=_json_no_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, struct.error, ValueError) as exc:
        raise DmgxError(f"Invalid or corrupt ASAR archive {archive.name}: {exc}", 4) from exc
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise DmgxError(f"Invalid ASAR root header in {archive.name}: expected a files object", 4)
    return header, 8 + header_pickle_size, archive_size


def _walk_asar_entries(directory: dict[str, Any], prefix: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    files = directory.get("files")
    if not isinstance(files, dict):
        raise DmgxError(f"Invalid ASAR directory entry at {prefix or '/'}", 4)
    for name, entry in files.items():
        if not isinstance(name, str) or "/" in name or "\\" in name or name in {"", ".", ".."} or "\x00" in name:
            raise DmgxError(f"Unsafe ASAR entry name rejected: {name!r}", 4)
        if not isinstance(entry, dict):
            raise DmgxError(f"Invalid ASAR entry at {prefix}/{name}", 4)
        rel = f"{prefix}/{name}" if prefix else name
        if "files" in entry:
            yield from _walk_asar_entries(entry, rel)
        else:
            yield rel, entry


def _read_unpacked_file(unpacked_root: Path, rel: Path, output_root: Path) -> tuple[Path | None, str | None]:
    source = unpacked_root / rel
    if not path_is_within(source, unpacked_root):
        return None, "unpacked path escapes its root"
    # Any symlink in path components is rejected; ASAR files should be regular files here.
    check = unpacked_root
    for part in rel.parts:
        check = check / part
        try:
            if check.is_symlink():
                return None, "unpacked symlink skipped"
        except OSError:
            return None, "could not inspect unpacked entry"
    try:
        if not source.is_file():
            return None, "unpacked file is missing"
    except OSError:
        return None, "could not inspect unpacked file"
    return source, None


def extract_asar_python(archive: Path, dest: Path, budget: Budget, warnings: list[str]) -> dict[str, Any]:
    header, data_start, archive_size = read_asar_header(archive)
    dest.mkdir(parents=True, exist_ok=True)
    entries = list(_walk_asar_entries(header))
    seen: set[str] = set()
    extracted = 0
    skipped_links = 0
    total_size = 0
    unpacked_root = Path(str(archive) + ".unpacked")
    with archive.open("rb") as source:
        for rel_text, entry in entries:
            try:
                rel = safe_relative_path(rel_text)
            except DmgxError as exc:
                warnings.append(str(exc))
                continue
            normal = rel.as_posix()
            if normal in seen:
                warnings.append(f"Duplicate ASAR output path skipped: {normal}")
                continue
            seen.add(normal)
            target = dest / rel
            if not path_is_within(target, dest):
                warnings.append(f"ASAR path escapes output directory and was skipped: {normal}")
                continue
            if target.exists() or target.is_symlink():
                warnings.append(f"ASAR output path collides with an existing entry; skipped: {normal}")
                continue
            if "link" in entry:
                # Skip archive symlinks rather than create potentially escaping links.
                skipped_links += 1
                warnings.append(f"ASAR symlink entry skipped for safety: {normal}")
                continue
            is_unpacked = entry.get("unpacked") is True
            try:
                if is_unpacked:
                    size = entry.get("size")
                    if not isinstance(size, int) or size < 0:
                        raise ValueError("invalid unpacked file size")
                    file_source, reason = _read_unpacked_file(unpacked_root, rel, dest)
                    if file_source is None:
                        warnings.append(f"ASAR unpacked entry skipped ({normal}): {reason}")
                        continue
                    actual_size = file_source.stat().st_size
                    if actual_size != size:
                        warnings.append(f"ASAR unpacked size mismatch for {normal}; using actual file size")
                    size = actual_size
                    budget.add(size, f"{archive.name}:{normal}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with file_source.open("rb") as src, target.open("xb") as out:
                        shutil.copyfileobj(src, out, 1024 * 1024)
                else:
                    offset_raw = entry.get("offset")
                    size = entry.get("size")
                    if not isinstance(offset_raw, str) or not offset_raw.isdigit() or not isinstance(size, int) or size < 0:
                        raise ValueError("invalid file offset or size")
                    offset = int(offset_raw)
                    start = data_start + offset
                    if start < data_start or start + size > archive_size:
                        raise ValueError("file payload exceeds archive bounds")
                    budget.add(size, f"{archive.name}:{normal}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as out:
                        source.seek(start)
                        remaining = size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ValueError("truncated file payload")
                            out.write(chunk)
                            remaining -= len(chunk)
                if entry.get("executable") is True:
                    try:
                        target.chmod(target.stat().st_mode | stat.S_IXUSR)
                    except OSError:
                        pass
                extracted += 1
                total_size += size
            except FileExistsError:
                warnings.append(f"ASAR output already exists; skipped: {normal}")
            except DmgxError:
                raise
            except (OSError, ValueError, TypeError) as exc:
                warnings.append(f"Failed to extract ASAR entry {normal}: {exc}")
    return {"archive": str(archive), "output": str(dest), "entries": len(entries), "files_extracted": extracted,
            "bytes_extracted": total_size, "symlinks_skipped": skipped_links, "parser": "built-in bounded ASAR reader"}


def detect_electron(app_path: Path, info: dict[str, Any]) -> tuple[bool, list[str]]:
    resources = app_path / "Contents" / "Resources"
    frameworks = app_path / "Contents" / "Frameworks"
    indicators: list[str] = []
    if (resources / "app.asar").is_file():
        indicators.append("Contents/Resources/app.asar")
    if (resources / "app").is_dir():
        indicators.append("Contents/Resources/app/")
    if (resources / "app.asar.unpacked").is_dir():
        indicators.append("Contents/Resources/app.asar.unpacked/")
    if resources.is_dir() and any(resources.glob("*.pak")):
        indicators.append("Contents/Resources/*.pak")
    if frameworks.is_dir() and any("electron" in p.name.lower() for p in frameworks.iterdir()):
        indicators.append("Contents/Frameworks Electron component")
    strings = " ".join(str(info.get(k, "")) for k in ("CFBundleIdentifier", "CFBundleName", "CFBundleExecutable"))
    if "electron" in strings.lower():
        indicators.append("Electron identifier or executable metadata")
    return bool(indicators), indicators


def inspect_native_executable(path: Path, logger: logging.Logger) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(path), "file_type": None, "architectures": [], "linked_libraries": [],
                              "global_symbols_count": None, "debug_symbols": False}
    file_cmd = shutil.which("file")
    if file_cmd:
        cp = run_command([file_cmd, "-b", str(path)], timeout=20, logger=logger)
        if cp.returncode == 0:
            result["file_type"] = cp.stdout.strip()[:1000]
    lipo = shutil.which("lipo")
    if lipo:
        cp = run_command([lipo, "-archs", str(path)], timeout=20, logger=logger)
        if cp.returncode == 0:
            result["architectures"] = cp.stdout.strip().split()
    if not result["architectures"] and result["file_type"]:
        for arch in ("arm64", "x86_64", "i386", "armv7", "ppc64", "ppc"):
            if arch in result["file_type"]:
                result["architectures"].append(arch)
    otool = shutil.which("otool")
    if otool:
        cp = run_command([otool, "-L", str(path)], timeout=30, logger=logger)
        if cp.returncode == 0:
            result["linked_libraries"] = [line.strip().split(" (compatibility version")[0] for line in cp.stdout.splitlines()[1:] if line.strip()][:500]
    nm = shutil.which("nm")
    if nm:
        cp = run_command([nm, "-gU", str(path)], timeout=30, logger=logger)
        if cp.returncode == 0:
            result["global_symbols_count"] = sum(1 for line in cp.stdout.splitlines() if line.strip())
    otool = shutil.which("otool")
    if otool:
        load_commands = run_command([otool, "-l", str(path)], timeout=30, logger=logger)
        if load_commands.returncode == 0:
            result["debug_symbols"] = "__DWARF" in load_commands.stdout or "__debug_info" in load_commands.stdout
    dwarf = shutil.which("dwarfdump")
    if dwarf:
        cp = run_command([dwarf, "--uuid", str(path)], timeout=20, logger=logger)
        result["debug_uuid_available"] = cp.returncode == 0 and bool(cp.stdout.strip())
    return result


def application_metadata(app_path: Path, rel_output_path: str, logger: logging.Logger) -> dict[str, Any]:
    info = parse_info_plist(app_path)
    info_plist_path = app_path / "Contents" / "Info.plist"
    plist_status = validate_plist(info_plist_path, logger) if info_plist_path.is_file() else "missing"
    codesign_status = inspect_codesign(app_path, logger)
    executable_name = info.get("CFBundleExecutable")
    executable = app_path / "Contents" / "MacOS" / str(executable_name) if executable_name else None
    native = inspect_native_executable(executable, logger) if executable and executable.is_file() and not executable.is_symlink() else None
    electron, indicators = detect_electron(app_path, info)
    frameworks: list[str] = []
    fwdir = app_path / "Contents" / "Frameworks"
    if fwdir.is_dir():
        try:
            frameworks = sorted(p.name for p in fwdir.iterdir())[:500]
        except OSError:
            pass
    return {
        "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or app_path.stem,
        "path": rel_output_path,
        "bundle_identifier": info.get("CFBundleIdentifier"),
        "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"),
        "bundle_metadata": info,
        "info_plist_validation": plist_status,
        "code_signature": codesign_status,
        "electron": electron,
        "electron_indicators": indicators,
        "frameworks": frameworks,
        "native_executable": native,
        "architecture": (native or {}).get("architectures", []),
        "source_recovery": "not assessed yet",
    }


def extract_embedded_archives(original: Path, extracted_root: Path, ctx: RunContext) -> None:
    assert ctx.output_budget is not None
    asar_files = [p for p in iter_files_no_symlinks(original) if p.suffix.lower() == ".asar"]
    for index, archive in enumerate(asar_files, 1):
        relative = archive.relative_to(original)
        target = extracted_root / "asar" / Path(str(relative) + ".contents")
        try:
            info = extract_asar_python(archive, target, ctx.output_budget, ctx.warnings)
            info["archive_relative_path"] = relative.as_posix()
            ctx.archives.append(info)
            ctx.logger.info("Extracted ASAR %s (%d files)", relative, info["files_extracted"])
        except DmgxError as exc:
            log_warning(ctx, str(exc))
            ctx.archives.append({"archive_relative_path": relative.as_posix(), "error": str(exc), "files_extracted": 0})
    # Extract one safe layer of ZIP/TAR/GZIP archives from the image and ASAR payloads.
    # Do not scan extracted archive outputs again, which would create unbounded recursion.
    archive_candidates: list[tuple[Path, str, Path]] = []
    for archive in iter_files_no_symlinks(original):
        if archive.suffix.lower() in ARCHIVE_EXTS or archive.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            archive_candidates.append((archive, "original", archive.relative_to(original)))
    asar_root = extracted_root / "asar"
    if asar_root.exists():
        for archive in iter_files_no_symlinks(asar_root):
            if archive.suffix.lower() in ARCHIVE_EXTS or archive.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                archive_candidates.append((archive, "from-asar", archive.relative_to(asar_root)))
    for archive, origin, rel in archive_candidates:
        suffix = archive.name.lower()
        if not (suffix.endswith(".zip") or suffix.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz", ".tbz2", ".txz", ".gz"))):
            continue
        target = extracted_root / "archives" / origin / Path(str(rel) + ".contents")
        try:
            if suffix.endswith(".zip"):
                files = safe_extract_zip(archive, target, ctx.output_budget, ctx.warnings)
            elif suffix.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz", ".tbz2", ".txz")):
                files = safe_extract_tar(archive, target, ctx.output_budget, ctx.warnings)
            else:
                files = safe_extract_gzip(archive, target, ctx.output_budget, ctx.warnings)
            ctx.archives.append({"archive_relative_path": f"{origin}/{rel.as_posix()}", "type": "zip/tar/gzip", "output": str(target.relative_to(ctx.output_path)),
                                 "files_extracted": len(files), "member_paths": files[:10000]})
        except Exception as exc:
            log_warning(ctx, f"Could not extract embedded archive {origin}/{rel}: {exc}")
            ctx.archives.append({"archive_relative_path": f"{origin}/{rel.as_posix()}", "error": redact_text(str(exc)), "files_extracted": 0})


def read_text_for_analysis(path: Path, max_bytes: int) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        if b"\x00" in raw[:4096]:
            return None, truncated
        try:
            return raw.decode("utf-8", errors="replace"), truncated
        except Exception:
            return None, truncated
    except OSError:
        return None, False


def analyze_files(ctx: RunContext, scan_roots: Sequence[tuple[Path, str]]) -> dict[str, Any]:
    file_index: list[dict[str, Any]] = []
    endpoints: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    routes: dict[tuple[str, str, int], dict[str, Any]] = {}
    env_names: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    ipc_channels: dict[tuple[str, str, int], dict[str, Any]] = {}
    source_map_refs: list[dict[str, Any]] = []
    source_maps_embedded: list[dict[str, Any]] = []
    build_configs: list[dict[str, Any]] = []
    credential_findings: list[dict[str, Any]] = []
    dependencies: dict[tuple[str, str, str], dict[str, Any]] = {}
    total_files = 0
    total_scan_bytes = 0
    truncated_files: list[str] = []
    package_json_paths: list[Path] = []
    source_extensions_seen: set[str] = set()
    package_relpaths: dict[str, str] = {}

    for root, prefix in scan_roots:
        if not root.exists():
            continue
        for path in iter_files_no_symlinks(root):
            total_files += 1
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            relpath = (Path(prefix) / path.relative_to(root)).as_posix()
            ext = path.suffix.lower()
            likely_text = ext in TEXT_EXTS or path.name.lower() in CONFIG_NAMES or path.name.lower().startswith(".env")
            if likely_text:
                head, sample, _was_truncated = safe_read_sample(path, min(ctx.limits.max_scan_size, 1024 * 1024))
            else:
                try:
                    with path.open("rb") as fh:
                        head = fh.read(4096)
                except OSError:
                    head = b""
                sample = None
            category, details = classify_file(path, relpath, head, size, sample)
            entry = {"path": relpath, "size_bytes": size, "category": category, "extension": path.suffix.lower(), **details}
            file_index.append(entry)
            if path.suffix.lower() in SOURCE_EXTS:
                source_extensions_seen.add(path.suffix.lower())
            if path.name.lower() == "package.json":
                package_json_paths.append(path)
                package_relpaths[str(path.resolve(strict=False))] = relpath
            if path.name.lower() in CONFIG_NAMES or any(x in path.name.lower() for x in ("webpack.config", "vite.config", "rollup.config", "electron-builder", "babel.config")):
                build_configs.append({"file": relpath, "kind": "recognized build/configuration file"})
            if path.suffix.lower() == ".map":
                source_map_refs.append({"file": relpath, "kind": "source map file"})
            if sample is None or category in {"native executable", "framework binary", "debug symbols", "static asset", "archive", "unknown format"}:
                continue
            text, truncated = read_text_for_analysis(path, ctx.limits.max_scan_size)
            if truncated:
                truncated_files.append(relpath)
            if text is None:
                continue
            total_scan_bytes += len(text.encode("utf-8", errors="ignore"))
            lines = text.splitlines()
            # Endpoint and route discovery uses real source text; values are sanitized before output.
            for line_no, line in enumerate(lines, 1):
                for match in URL_RE.finditer(line):
                    raw_url = match.group(0).rstrip(".,;:!?)]]}")
                    parsed_url = urlsplit(raw_url)
                    known_schema = ((parsed_url.hostname or "").lower() in {"www.apple.com", "www.w3.org", "schemas.microsoft.com", "www.w3.org"}
                                    and any(part in parsed_url.path.lower() for part in ("/dtds/", "/xml/", "/2000/", "/1999/", "/schema")))
                    if known_schema:
                        continue
                    sanitized = sanitize_url(raw_url)
                    scheme = urlsplit(sanitized).scheme.lower()
                    evidence_type = "WebSocket URL" if scheme in {"ws", "wss"} else "HTTP(S) URL"
                    key = (sanitized, relpath, line_no)
                    endpoints[key] = {"url": sanitized, "scheme": scheme, "file": relpath, "line": line_no,
                                      "evidence": f"{evidence_type} string literal; credentials redacted"}
                for match in ROUTE_RE.finditer(line):
                    route = redact_text(match.group(1))
                    routes[(route, relpath, line_no)] = {"route": route, "file": relpath, "line": line_no,
                                                          "evidence": "API-style route string"}
                for env_pattern in (ENV_RE, ENV_BRACKET_RE, ENV_DOT_RE):
                    for match in env_pattern.finditer(line):
                        env = match.group(1)
                        env_names[(env, relpath, line_no)] = {"name": env, "file": relpath, "line": line_no,
                                                             "evidence": "environment-variable access reference"}
                for match in IPC_RE.finditer(line):
                    channel = redact_text(match.group(1))
                    ipc_channels[(channel, relpath, line_no)] = {"channel": channel, "file": relpath, "line": line_no,
                                                                 "evidence": "Electron-style IPC channel reference"}
                for match in SOURCE_MAP_RE.finditer(line):
                    source_map_refs.append({"file": relpath, "line": line_no, "reference": redact_text(match.group(1)),
                                            "kind": "sourceMappingURL comment/reference"})
                for pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        credential_findings.append({"file": relpath, "line": line_no,
                                                    "evidence": "Possible credential/token-shaped string; value redacted"})
            if path.suffix.lower() in {".env", ".example", ".development", ".production"} or path.name.lower().startswith(".env"):
                for line_no, line in enumerate(lines, 1):
                    m = ENV_LINE_RE.match(line)
                    if m:
                        env_names[(m.group(1), relpath, line_no)] = {"name": m.group(1), "file": relpath, "line": line_no,
                                                                     "evidence": "environment-file variable name; value not reported"}
            if path.suffix.lower() == ".map":
                try:
                    data = json.loads(text)
                    sources_content = data.get("sourcesContent") if isinstance(data, dict) else None
                    if isinstance(sources_content, list):
                        source_maps_embedded.append({"file": relpath, "sources_content_entries": len(sources_content),
                                                     "nonempty_sources_content": sum(1 for item in sources_content if isinstance(item, str) and item)})
                except (json.JSONDecodeError, TypeError):
                    pass

    # package.json dependency extraction, keeping names/versions but no arbitrary configuration values.
    for package_path in package_json_paths:
        text, truncated = read_text_for_analysis(package_path, min(ctx.limits.max_scan_size, 16 * 1024 * 1024))
        if truncated or text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        relpath = package_relpaths.get(str(package_path.resolve(strict=False)), str(package_path))
        pkg_name = str(data.get("name", ""))[:300]
        pkg_version = str(data.get("version", ""))[:100]
        if pkg_name:
            dependencies[(pkg_name, pkg_version, relpath)] = {"name": pkg_name, "version": pkg_version, "package_file": relpath, "kind": "package metadata"}
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(group, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    if isinstance(name, str) and isinstance(version, (str, int, float)):
                        key = (name[:300], str(version)[:100], relpath)
                        dependencies[key] = {"name": name[:300], "version": str(version)[:100], "package_file": relpath, "kind": group}

    index_file = ctx.output_path / "analysis" / "file-index.json"
    endpoints_file = ctx.output_path / "analysis" / "endpoints.json"
    dependencies_file = ctx.output_path / "analysis" / "dependencies.json"
    findings_file = ctx.output_path / "analysis" / "findings.json"
    analysis_dir = ctx.output_path / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps({"files_indexed": len(file_index), "files": file_index}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    endpoint_list = sorted(endpoints.values(), key=lambda x: (x["file"], x["line"], x["url"]))
    deps_list = sorted(dependencies.values(), key=lambda x: (x["package_file"], x["name"], x["version"]))
    endpoints_file.write_text(json.dumps({"endpoints": endpoint_list, "count": len(endpoint_list)}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    dependencies_file.write_text(json.dumps({"dependencies": deps_list, "count": len(deps_list)}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    findings = {
        "api_routes": sorted(routes.values(), key=lambda x: (x["file"], x["line"])),
        "environment_variables": sorted(env_names.values(), key=lambda x: (x["file"], x["line"], x["name"])),
        "ipc_channels": sorted(ipc_channels.values(), key=lambda x: (x["file"], x["line"])),
        "source_map_references": source_map_refs,
        "source_maps_with_embedded_sources_content": source_maps_embedded,
        "build_configuration_files": build_configs,
        "credential_like_strings_redacted": credential_findings,
        "analysis_limits": {"max_scan_size_per_file": ctx.limits.max_scan_size, "truncated_files": truncated_files,
                            "files_indexed": len(file_index), "bytes_scanned_from_text": total_scan_bytes},
    }
    findings_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Heuristic source recovery assessment, never equating beautification with original-source recovery.
    code_count = sum(1 for f in file_index if f["category"] in {"original-looking source (heuristic)", "bundled or minified source", "source or text"})
    embedded = sum(int(item.get("nonempty_sources_content", 0)) for item in source_maps_embedded)
    source_maps_present = any(f["category"] == "source map" for f in file_index) or bool(source_map_refs)
    if embedded > 0:
        recovery = "partial; source maps contain embedded sourcesContent"
    elif code_count > 0:
        recovery = "partial; text/source-like files found, original project sources not verified"
    else:
        recovery = "limited; no obvious source-like files recovered"
    result = {
        "files_indexed": len(file_index),
        "file_categories": _category_counts(file_index),
        "endpoints": endpoint_list,
        "api_routes": list(findings["api_routes"]),
        "environment_variables": list(findings["environment_variables"]),
        "ipc_channels": list(findings["ipc_channels"]),
        "dependencies": deps_list,
        "source_maps_found": source_maps_present,
        "source_maps_with_embedded_sources_content": source_maps_embedded,
        "source_map_references": source_map_refs,
        "build_configuration_files": build_configs,
        "credential_like_strings_redacted": credential_findings,
        "original_source_recovery": recovery,
        "truncated_files": truncated_files,
        "output_files": {"file_index": "analysis/file-index.json", "endpoints": "analysis/endpoints.json",
                         "dependencies": "analysis/dependencies.json", "findings": "analysis/findings.json"}
    }
    for app in ctx.applications:
        app["source_recovery"] = recovery
    return result


def _category_counts(file_index: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in file_index:
        key = str(item["category"])
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def inspect_native_inventory(ctx: RunContext, scan_roots: Sequence[tuple[Path, str]], limit: int = 500) -> dict[str, Any]:
    """Inspect Mach-O files across preserved and extracted trees, with a finite command cap."""
    inspected: list[dict[str, Any]] = []
    candidates: list[tuple[Path, str]] = []
    for root, prefix in scan_roots:
        if not root.exists():
            continue
        for path in iter_files_no_symlinks(root):
            try:
                with path.open("rb") as fh:
                    head = fh.read(16)
            except OSError:
                continue
            if magic_kind(head) == "Mach-O native binary":
                rel = (Path(prefix) / path.relative_to(root)).as_posix()
                candidates.append((path, rel))
    for path, rel in candidates[:limit]:
        try:
            detail = inspect_native_executable(path, ctx.logger)
            detail["path"] = rel
            inspected.append(detail)
        except DmgxError as exc:
            log_warning(ctx, f"Native binary inspection failed for {rel}: {exc}")
    skipped = max(0, len(candidates) - len(inspected))
    return {"native_mach_o_files_found": len(candidates), "native_mach_o_files_inspected": len(inspected),
            "inspection_limit": limit, "additional_files_not_inspected": skipped, "binaries": inspected}


def format_sources(scan_roots: Sequence[tuple[Path, str]], formatted_root: Path, ctx: RunContext) -> dict[str, Any]:
    results = {"formatted": 0, "skipped": 0, "errors": []}
    prettier = shutil.which("prettier")
    black = shutil.which("black")
    parsers = {".js": "babel", ".mjs": "babel", ".cjs": "babel", ".jsx": "babel", ".ts": "typescript",
               ".tsx": "typescript", ".css": "css", ".scss": "scss", ".less": "less", ".html": "html",
               ".htm": "html", ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".md": "markdown"}
    for source_root, prefix in scan_roots:
        if not source_root.exists():
            continue
        for source in iter_files_no_symlinks(source_root):
            ext = source.suffix.lower()
            rel = Path(prefix) / source.relative_to(source_root)
            if ext not in parsers and ext != ".py":
                continue
            try:
                st = source.stat()
                if st.st_size > ctx.limits.max_scan_size:
                    results["skipped"] += 1
                    results["errors"].append({"file": rel.as_posix(), "reason": "larger than formatting scan limit"})
                    continue
                target = formatted_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if ctx.output_budget is not None:
                    ctx.output_budget.add(st.st_size, str(source))
                shutil.copy2(source, target)
                if ext == ".json":
                    try:
                        data = json.loads(target.read_text(encoding="utf-8"))
                        target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                        results["formatted"] += 1
                    except Exception as exc:
                        results["skipped"] += 1
                        results["errors"].append({"file": rel.as_posix(), "reason": f"invalid JSON: {exc}"})
                elif ext == ".py" and black:
                    cp = run_command([black, "--quiet", "--safe", "--no-cache", "--config", os.devnull, str(target)], timeout=60, logger=ctx.logger)
                    if cp.returncode == 0:
                        results["formatted"] += 1
                    else:
                        results["skipped"] += 1
                        results["errors"].append({"file": rel.as_posix(), "reason": "black could not format this copy"})
                elif ext in parsers and prettier:
                    cp = run_command([prettier, "--write", "--no-config", "--no-editorconfig", "--parser", parsers[ext], str(target)], timeout=60, logger=ctx.logger)
                    if cp.returncode == 0:
                        results["formatted"] += 1
                    else:
                        results["skipped"] += 1
                        results["errors"].append({"file": rel.as_posix(), "reason": "prettier could not format this copy"})
                else:
                    results["skipped"] += 1
                    results["errors"].append({"file": rel.as_posix(), "reason": "formatter unavailable; preserved an unchanged copy"})
            except (OSError, DmgxError) as exc:
                results["skipped"] += 1
                results["errors"].append({"file": rel.as_posix(), "reason": redact_text(str(exc))})
    return results

def write_reports(ctx: RunContext, started_wall: str | None, elapsed: float, counts: dict[str, Any]) -> None:
    report = {
        "tool": {"name": APP_NAME, "version": VERSION},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "input": str(ctx.input_path),
        "output": str(ctx.output_path),
        "image_metadata": ctx.image_metadata,
        "mounts": [{"mount_point": str(m.mount_point), "device": m.device} for m in ctx.mounts] if ctx.args.keep_mounted else [],
        "applications": ctx.applications,
        "items_preserved": ctx.bundle_items,
        "archives": ctx.archives,
        "analysis": ctx.analysis,
        "counts": counts,
        "limits": {"max_files": ctx.limits.max_files, "max_file_size_bytes": ctx.limits.max_file_size,
                   "max_total_size_bytes": ctx.limits.max_total_size, "max_scan_size_bytes": ctx.limits.max_scan_size},
        "warnings": ctx.warnings,
        "errors": ctx.errors,
        "elapsed_seconds": round(elapsed, 3),
        "source_recovery_note": "Source recovery is necessarily partial when an app only contains compiled binaries or bundled/minified code. Formatting changes readability, not source provenance."
    }
    (ctx.output_path / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    lines = [
        f"# dmgx report — {ctx.input_path.name}", "", f"- **Tool version:** {VERSION}",
        f"- **Input:** `{ctx.input_path}`", f"- **Output:** `{ctx.output_path}`",
        f"- **Elapsed:** {elapsed:.2f} seconds", f"- **Files indexed:** {counts.get('files_indexed', 0)}",
        f"- **Applications found:** {len(ctx.applications)}", f"- **Electron applications:** {sum(1 for a in ctx.applications if a.get('electron'))}",
        f"- **ASAR archives:** {sum(1 for a in ctx.archives if str(a.get('archive_relative_path', '')).lower().endswith('.asar'))}",
        f"- **Source maps found:** {str(bool(ctx.analysis.get('source_maps_found', False))).lower()}",
        f"- **Potential HTTP/WebSocket endpoints:** {len(ctx.analysis.get('endpoints', []))}", "", "## Applications", ""
    ]
    if not ctx.applications:
        lines.append("No `.app` bundle was discovered on the mounted image.")
    else:
        for app in ctx.applications:
            lines.extend([
                f"### {app.get('name', 'Unknown application')}", "",
                f"- **Path:** `{app.get('path')}`",
                f"- **Bundle identifier:** `{app.get('bundle_identifier') or 'not found'}`",
                f"- **Version:** `{app.get('version') or 'not found'}`",
                f"- **Electron:** {'yes' if app.get('electron') else 'not detected'}",
                f"- **Architecture:** `{', '.join(app.get('architecture') or []) or 'not detected'}`",
                f"- **Source recovery assessment:** {app.get('source_recovery', 'not assessed')}",
                f"- **Info.plist validation:** {app.get('info_plist_validation', 'not checked')}",
                f"- **Code signature verification:** {(app.get('code_signature') or {}).get('verification', 'not checked')}", ""
            ])
            native = app.get("native_executable")
            if native:
                lines.extend(["**Native executable inspection**", "", f"- File type: `{native.get('file_type') or 'not identified'}`",
                              f"- Linked libraries: {len(native.get('linked_libraries', []))}",
                              f"- Global symbols listed: `{native.get('global_symbols_count')}`",
                              f"- Debug UUID information available: `{bool(native.get('debug_symbols'))}`", ""])
    lines.extend(["## Analysis summary", ""])
    categories = ctx.analysis.get("file_categories", {})
    if categories:
        lines.extend(["| Classification | Files |", "|---|---:|"])
        for category, amount in categories.items():
            safe_category = str(category).replace("|", "\\|")
            lines.append(f"| {safe_category} | {amount} |")
        lines.append("")
    lines.extend([f"- **Dependencies recorded:** {len(ctx.analysis.get('dependencies', []))}",
                  f"- **API route references:** {len(ctx.analysis.get('api_routes', []))}",
                  f"- **Environment variable names:** {len(ctx.analysis.get('environment_variables', []))}",
                  f"- **IPC channel references:** {len(ctx.analysis.get('ipc_channels', []))}",
                  f"- **Credential-like patterns redacted:** {len(ctx.analysis.get('credential_like_strings_redacted', []))}",
                  f"- **Mach-O binaries inspected:** {(ctx.analysis.get('native_binaries') or {}).get('native_mach_o_files_inspected', 0)}", "",
                  "Detailed findings are stored under `analysis/` as JSON. Values resembling credentials or tokens are redacted by default.", "",
                  "## Caveats", "",
                  "- Static analysis reports strings and references found in files; it does not establish that an endpoint is live, reachable, or used at runtime.",
                  "- Decompiled or disassembled native code is not original source code. This tool does not decompile native executables.",
                  "- Minified JavaScript can be formatted for readability, but formatting does not recover original names, comments, modules, or source structure.",
                  "- A source map may only contain mapping metadata; `sourcesContent` is checked separately.", ""])
    if ctx.warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {w}" for w in ctx.warnings[:500])
        lines.append("")
    if ctx.errors:
        lines.extend(["## Errors", ""])
        lines.extend(f"- {e}" for e in ctx.errors[:500])
        lines.append("")
    (ctx.output_path / "report.md").write_text("\n".join(lines), encoding="utf-8")


def collect_output_counts(output: Path) -> dict[str, Any]:
    count = 0
    byte_count = 0
    for root_name in ("original", "extracted", "formatted"):
        root = output / root_name
        if not root.exists():
            continue
        for path in iter_files_no_symlinks(root):
            count += 1
            try:
                byte_count += path.stat().st_size
            except OSError:
                pass
    asar_count = 0
    for p in iter_files_no_symlinks(output / "original") if (output / "original").exists() else []:
        if p.suffix.lower() == ".asar":
            asar_count += 1
    return {"files_extracted": count, "bytes_output": byte_count, "asar_archives": asar_count}


def describe_dry_run(ctx: RunContext) -> int:
    validate_image_and_read_metadata(ctx)
    mounts = mount_image(ctx)
    try:
        scan_stats = {"files": 0, "bytes": 0}
        for mount in mounts:
            stats = scan_tree_limits(mount.mount_point, ctx.limits)
            scan_stats["files"] += stats["files"]
            scan_stats["bytes"] += stats["bytes"]
        apps = discover_applications(mounts)
        print("dmgx dry run — no files will be extracted")
        print(f"Input: {ctx.input_path}")
        print(f"Output planned: {ctx.output_path}")
        print(f"Mounted volumes: {len(mounts)}")
        for mount in mounts:
            print(f"  - {mount.mount_point}")
        print(f"Files on mounted volumes: {scan_stats['files']}")
        print(f"Input content size: {format_bytes(scan_stats['bytes'])}")
        print(f"Applications discovered: {len(apps)}")
        for app in apps:
            info = app["info"]
            print(f"  - {info.get('CFBundleDisplayName') or info.get('CFBundleName') or app['source'].stem}: {app['relative']}")
            is_electron, indicators = detect_electron(app["source"], info)
            print(f"    Electron: {'yes' if is_electron else 'not detected'}" + (f" ({', '.join(indicators)})" if indicators else ""))
        print("Planned: preserve mounted volume contents, extract supported ASAR/ZIP/TAR/GZIP archives, index files, analyze strings, and write JSON/Markdown reports.")
        if ctx.output_path.exists() and not ctx.args.force:
            print("Note: output already exists; actual execution will require --force to replace it.")
        return 0
    finally:
        unmount_all(ctx)


def execute_pipeline(ctx: RunContext) -> int:
    wall_start = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    progress(1, 8, "Validating disk image and reading metadata...", ctx.args.quiet)
    validate_image_and_read_metadata(ctx)
    progress(2, 8, "Mounting image read-only...", ctx.args.quiet)
    mounts = mount_image(ctx)
    # Preflight the whole read-only volume before allocating output.
    input_stats = {"files": 0, "bytes": 0}
    for mount in mounts:
        stats = scan_tree_limits(mount.mount_point, ctx.limits)
        input_stats["files"] += stats["files"]
        input_stats["bytes"] += stats["bytes"]
        if input_stats["files"] > ctx.limits.max_files:
            raise DmgxError(f"Mounted volumes collectively exceed --max-files ({ctx.limits.max_files}).", 4)
        if input_stats["bytes"] > ctx.limits.max_total_size:
            raise DmgxError(f"Mounted volumes collectively exceed --max-total-size ({ctx.limits.max_total_size} bytes).", 4)
    apps = discover_applications(mounts)
    progress(3, 8, "Discovering application bundles and relevant resources...", ctx.args.quiet)
    prepare_output(ctx.output_path, ctx.args.force)
    (ctx.output_path / "original").mkdir(parents=True)
    (ctx.output_path / "extracted").mkdir(parents=True)
    (ctx.output_path / "formatted").mkdir(parents=True)
    (ctx.output_path / "analysis").mkdir(parents=True)
    (ctx.output_path / "logs").mkdir(parents=True)
    # Add file logger now that the output exists.
    try:
        fh = logging.FileHandler(ctx.output_path / "logs" / "extraction.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        ctx.logger.addHandler(fh)
    except OSError as exc:
        log_warning(ctx, f"Could not initialize extraction log file: {exc}")
    budget = Budget(ctx.limits)
    ctx.output_budget = budget
    original = ctx.output_path / "original"
    progress(4, 8, "Preserving application contents and relevant resources...", ctx.args.quiet)
    volume_names = [m.mount_point.name or f"volume-{i+1}" for i, m in enumerate(mounts)]
    multiple_mounts = len(mounts) > 1
    for idx, mount in enumerate(mounts):
        volume_root = original / (re.sub(r"[^A-Za-z0-9._-]+", "_", volume_names[idx]) or f"volume-{idx+1}") if multiple_mounts else original
        copied = 0
        for source in discover_copy_roots(mount, mounts):
            destination = volume_root / source.name
            if source.is_symlink():
                # Preserve only in-volume symbolic links; an absolute alias such as /Applications is skipped.
                if _copy_file_safe(source, destination, mount.mount_point, budget, ctx.warnings):
                    copied += 1
                continue
            if source.is_dir():
                copied += copy_directory_prefer_ditto(source, destination, mount.mount_point, budget, ctx.warnings, ctx.logger)
                try:
                    shutil.copystat(source, destination, follow_symlinks=False)
                except OSError:
                    pass
            elif source.is_file():
                if _copy_file_safe(source, destination, mount.mount_point, budget, ctx.warnings):
                    copied += 1
        ctx.bundle_items.append({"volume": volume_names[idx], "copied_files": copied, "destination": str(volume_root.relative_to(ctx.output_path))})
    # Build app records based on copied originals, not the mounted source paths.
    progress(5, 8, "Detecting Electron applications and native architectures...", ctx.args.quiet)
    for app in apps:
        mount_index = mounts.index(app["mount"])
        prefix = Path(re.sub(r"[^A-Za-z0-9._-]+", "_", volume_names[mount_index]) or f"volume-{mount_index+1}") if multiple_mounts else Path()
        copied_app = original / prefix / app["relative"]
        rel_path = copied_app.relative_to(ctx.output_path).as_posix()
        # Use the original metadata from the read-only mounted image, but inspect the copied executable.
        metadata = application_metadata(copied_app, rel_path, ctx.logger)
        metadata["electron"] = detect_electron(copied_app, metadata.get("bundle_metadata", {}))[0]
        metadata["electron_indicators"] = detect_electron(copied_app, metadata.get("bundle_metadata", {}))[1]
        ctx.applications.append(metadata)
    progress(6, 8, "Extracting ASAR and supported embedded archives...", ctx.args.quiet)
    extract_embedded_archives(original, ctx.output_path / "extracted", ctx)
    scan_roots = [(original, "original"), (ctx.output_path / "extracted", "extracted")]
    progress(7, 8, "Analyzing endpoints, dependencies, source maps, IPC, and configuration...", ctx.args.quiet)
    ctx.analysis = analyze_files(ctx, scan_roots)
    ctx.analysis["native_binaries"] = inspect_native_inventory(ctx, scan_roots)
    if ctx.args.format:
        formatted = format_sources(scan_roots, ctx.output_path / "formatted", ctx)
        ctx.analysis["formatting"] = formatted
        for warning in formatted.get("errors", [])[:500]:
            if warning.get("reason", "").startswith("formatter unavailable"):
                # Only warn once per unavailable formatter type in terminal/logs.
                pass
    counts = collect_output_counts(ctx.output_path)
    counts.update({
        "applications_found": len(ctx.applications),
        "electron_applications": sum(1 for app in ctx.applications if app.get("electron")),
        "source_maps": ctx.analysis.get("file_categories", {}).get("source map", 0),
        "installer_packages": ctx.analysis.get("file_categories", {}).get("installer package", 0),
        "potential_endpoints": len(ctx.analysis.get("endpoints", [])),
        "input_files": input_stats["files"], "input_bytes": input_stats["bytes"],
        "budget_files_written": budget.files, "budget_bytes_written": budget.bytes_written,
    })
    progress(8, 8, "Writing JSON and Markdown reports...", ctx.args.quiet)
    elapsed = time.monotonic() - ctx.start_time
    write_reports(ctx, wall_start, elapsed, counts)
    if not ctx.args.quiet:
        print("\ndmgx — Extraction complete")
        print(f"Applications found: {len(ctx.applications)}")
        print(f"Electron applications: {sum(1 for app in ctx.applications if app.get('electron'))}")
        print(f"Files extracted/indexed: {counts.get('files_extracted', 0)} / {counts.get('files_indexed', 0)}")
        print(f"ASAR archives: {counts.get('asar_archives', 0)}")
        print(f"Source maps: {counts.get('source_maps', 0)}")
        print(f"Potential API endpoints: {counts.get('potential_endpoints', 0)}")
        print(f"Elapsed: {elapsed:.2f}s")
        print(f"Output: {ctx.output_path}")
        print(f"Report: {ctx.output_path / 'report.md'}")
        if ctx.args.keep_mounted and ctx.mounts:
            for mount in ctx.mounts:
                print(f"Still mounted: {mount.mount_point}")
    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dmgx",
        description="Extract and statically inspect recoverable files from macOS DMG images. Extracted code is never executed.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("dmg", nargs="?", help="Path to a .dmg disk image")
    parser.add_argument("--output", "-o", help="Output directory (default: <DMG-name>-extracted beside the input)")
    parser.add_argument("--format", action="store_true", help="Format supported source-file copies into formatted/ (never changes originals)")
    parser.add_argument("--analyze", action="store_true", help="Run static analysis (also part of the normal pipeline)")
    parser.add_argument("--report", action="store_true", help="Write report.json and report.md (also part of the normal pipeline)")
    parser.add_argument("--keep-mounted", action="store_true", help="Leave the read-only mounted DMG volume(s) mounted")
    parser.add_argument("--verbose", action="store_true", help="Write diagnostic details to stderr and extraction.log")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output; errors remain visible")
    parser.add_argument("--yes", action="store_true", help="Accept safe defaults for automation; never overrides --force")
    parser.add_argument("--dry-run", action="store_true", help="Mount read-only and preview work without creating output files")
    parser.add_argument("--force", action="store_true", help="Replace an existing output path (explicitly destructive)")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum regular-file count scanned/extracted")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE, help="Maximum size of any individual file in bytes")
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_SIZE, help="Maximum total bytes copied/extracted in bytes")
    parser.add_argument("--max-scan-size", type=int, default=DEFAULT_MAX_SCAN_SIZE, help="Maximum bytes read from any text file for analysis/formatting")
    parser.add_argument("--self-test", action="store_true", help="Run the built-in offline test suite (no DMG or macOS required)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


class DmgxTests(unittest.TestCase):
    """Offline tests for security-sensitive helpers. No real DMG mount is attempted."""
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="dmgx-test-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_validate_rejects_wrong_extension_and_empty(self) -> None:
        wrong = self.root / "not-a-dmg.txt"
        wrong.write_text("x")
        with self.assertRaises(DmgxError):
            validate_input_path(wrong)
        empty = self.root / "empty.dmg"
        empty.touch()
        with self.assertRaises(DmgxError):
            validate_input_path(empty)

    def test_spaces_and_nested_paths_copy(self) -> None:
        source = self.root / "mount" / "My App.app" / "Contents" / "Resources"
        source.mkdir(parents=True)
        (source / "app.js").write_text("const ok = true;\n")
        dest = self.root / "out" / "original"
        warnings: list[str] = []
        budget = Budget(Limits())
        copy_tree_safe(self.root / "mount", dest, budget, warnings)
        self.assertEqual((dest / "My App.app" / "Contents" / "Resources" / "app.js").read_text(), "const ok = true;\n")

    def test_safe_relative_path_rejects_traversal(self) -> None:
        for name in ("../escape", "/absolute", "a/../../b", "C:/escape", r"a\\b"):
            with self.subTest(name=name), self.assertRaises(DmgxError):
                safe_relative_path(name)

    def test_symlink_escape_is_skipped(self) -> None:
        source = self.root / "src"
        source.mkdir()
        outside = self.root / "secret.txt"
        outside.write_text("private")
        try:
            (source / "escape").symlink_to(outside)
        except OSError:
            self.skipTest("symlinks unavailable")
        dest = self.root / "dst"
        warnings: list[str] = []
        copy_tree_safe(source, dest, Budget(Limits()), warnings)
        self.assertFalse((dest / "escape").exists())
        self.assertTrue(any("outside" in w for w in warnings))

    def test_duplicate_json_keys_rejected_in_asar(self) -> None:
        archive = self.root / "duplicate.asar"
        json_data = b'{"files":{"x":{"offset":"0","size":0},"x":{"offset":"0","size":0}}}'
        # Minimal Pickle wrapping: header JSON string followed by 4-byte padding.
        payload = struct.pack("<I", len(json_data)) + json_data
        payload += b"\x00" * ((4 - (len(payload) % 4)) % 4)
        header_pickle = struct.pack("<I", len(payload)) + payload
        size_pickle = struct.pack("<II", 4, len(header_pickle))
        archive.write_bytes(size_pickle + header_pickle)
        with self.assertRaises(DmgxError):
            read_asar_header(archive)

    def test_corrupt_asar_rejected(self) -> None:
        archive = self.root / "bad.asar"
        archive.write_bytes(b"not an asar")
        with self.assertRaises(DmgxError):
            read_asar_header(archive)

    def test_valid_asar_extracted(self) -> None:
        archive = self.root / "app.asar"
        payload_files = {"package.json": b'{"name":"fixture","version":"1.2.3"}', "src/main.js": b"const endpoint = 'https://example.test/api';\n"}
        json_tree: dict[str, Any] = {"files": {}}
        blob = bytearray()
        for path, content in payload_files.items():
            parts = path.split("/")
            node = json_tree
            for part in parts[:-1]:
                node = node["files"].setdefault(part, {"files": {}})
            node["files"][parts[-1]] = {"offset": str(len(blob)), "size": len(content)}
            blob.extend(content)
        raw_json = json.dumps(json_tree, separators=(",", ":")).encode()
        string_payload = struct.pack("<I", len(raw_json)) + raw_json
        string_payload += b"\x00" * ((4 - (len(string_payload) % 4)) % 4)
        header_pickle = struct.pack("<I", len(string_payload)) + string_payload
        size_pickle = struct.pack("<II", 4, len(header_pickle))
        archive.write_bytes(size_pickle + header_pickle + blob)
        out = self.root / "out"
        warnings: list[str] = []
        info = extract_asar_python(archive, out, Budget(Limits()), warnings)
        self.assertEqual(info["files_extracted"], 2)
        self.assertEqual((out / "src" / "main.js").read_bytes(), payload_files["src/main.js"])

    def test_asar_traversal_rejected(self) -> None:
        archive = self.root / "traversal.asar"
        json_tree = {"files": {"..": {"files": {"escape.txt": {"offset": "0", "size": 0}}}}}
        raw_json = json.dumps(json_tree).encode()
        string_payload = struct.pack("<I", len(raw_json)) + raw_json
        string_payload += b"\x00" * ((4 - (len(string_payload) % 4)) % 4)
        header_pickle = struct.pack("<I", len(string_payload)) + string_payload
        archive.write_bytes(struct.pack("<II", 4, len(header_pickle)) + header_pickle)
        with self.assertRaises(DmgxError):
            extract_asar_python(archive, self.root / "out", Budget(Limits()), [])

    def test_zip_traversal_rejected(self) -> None:
        archive = self.root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../escape.txt", "escape")
            zf.writestr("nested/ok.txt", "ok")
        dest = self.root / "unzip"
        warnings: list[str] = []
        found = safe_extract_zip(archive, dest, Budget(Limits()), warnings)
        self.assertIn("nested/ok.txt", found)
        self.assertFalse((self.root / "escape.txt").exists())
        self.assertTrue(any("Unsafe ZIP" in w for w in warnings))

    def test_zip_duplicate_names_are_not_overwritten(self) -> None:
        archive = self.root / "duplicate.zip"
        with self.assertWarns(UserWarning):
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("same.txt", "first")
                zf.writestr("same.txt", "second")
        dest = self.root / "duplicate-out"
        warnings: list[str] = []
        budget = Budget(Limits())
        found = safe_extract_zip(archive, dest, budget, warnings)
        self.assertEqual(found, ["same.txt"])
        self.assertEqual((dest / "same.txt").read_text(), "first")
        self.assertTrue(any("Duplicate ZIP output path" in item for item in warnings))
        self.assertEqual(budget.files, 1)
        self.assertEqual(budget.bytes_written, len("first"))

    def test_url_redaction(self) -> None:
        value = sanitize_url("https://user:pass@example.com/api?token=secret&region=us#frag")
        self.assertNotIn("secret", value)
        self.assertNotIn("pass", value)
        self.assertIn("<REDACTED>", value)
        self.assertIn("region=us", value)

    def test_analyzer_reports_real_path_and_line(self) -> None:
        output = self.root / "output"
        orig = output / "original" / "Demo.app" / "Contents" / "Resources"
        orig.mkdir(parents=True)
        (orig / "main.js").write_text("// first\nconst url = 'https://api.example.test/v1?api_key=supersecretvalue';\nprocess.env.API_TOKEN;\n")
        (orig / "package.json").write_text('{"name":"demo","version":"1.0.0","dependencies":{"chalk":"^5.0.0"}}')
        output.mkdir(exist_ok=True)
        logger = setup_logger(None, False, True)
        ctx = RunContext(self.root / "fake.dmg", output, argparse.Namespace(), Limits(), logger)
        ctx.output_budget = Budget(ctx.limits)
        result = analyze_files(ctx, [(output / "original", "original")])
        self.assertTrue(result["endpoints"])
        self.assertEqual(result["endpoints"][0]["line"], 2)
        self.assertNotIn("supersecretvalue", json.dumps(result))
        self.assertTrue((output / "analysis" / "file-index.json").is_file())
        self.assertTrue(any(item["name"] == "API_TOKEN" for item in result["environment_variables"]))

    def test_output_path_guards(self) -> None:
        dmg = self.root / "image.dmg"
        dmg.write_bytes(b"not really a dmg")
        with self.assertRaises(DmgxError):
            resolve_output_path(".", dmg)
        with self.assertRaises(DmgxError):
            resolve_output_path(str(self.root), dmg)

    def test_pipeline_end_to_end_with_fixture_volume(self) -> None:
        from unittest import mock
        volume = self.root / "mounted volume"
        app = volume / "Demo App.app"
        resources = app / "Contents" / "Resources"
        macos = app / "Contents" / "MacOS"
        resources.mkdir(parents=True)
        macos.mkdir(parents=True)
        with (app / "Contents" / "Info.plist").open("wb") as fh:
            plistlib.dump({"CFBundleName": "Demo App", "CFBundleIdentifier": "test.demo", "CFBundleExecutable": "Demo",
                           "CFBundleShortVersionString": "1.0"}, fh)
        (macos / "Demo").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
        payload_files = {
            "package.json": b'{"name":"demo-app","version":"1.0.0","main":"main.js","dependencies":{"chalk":"^5.0.0"}}',
            "main.js": b"const endpoint = 'https://api.example.test/v1';\nprocess.env.API_TOKEN;\n",
        }
        tree: dict[str, Any] = {"files": {}}
        blob = bytearray()
        for filename, content in payload_files.items():
            node = tree
            for part in filename.split("/")[:-1]:
                node = node["files"].setdefault(part, {"files": {}})
            node["files"][filename.split("/")[-1]] = {"offset": str(len(blob)), "size": len(content)}
            blob.extend(content)
        raw_json = json.dumps(tree, separators=(",", ":")).encode()
        string_payload = struct.pack("<I", len(raw_json)) + raw_json
        string_payload += b"\x00" * ((4 - (len(string_payload) % 4)) % 4)
        header_pickle = struct.pack("<I", len(string_payload)) + string_payload
        (resources / "app.asar").write_bytes(struct.pack("<II", 4, len(header_pickle)) + header_pickle + blob)
        input_dmg = self.root / "Demo Image.dmg"
        input_dmg.write_bytes(b"fake test input")
        output = self.root / "Demo Output"
        args = argparse.Namespace(quiet=True, force=False, keep_mounted=False, format=False, verbose=False)
        ctx = RunContext(input_dmg, output, args, Limits(), setup_logger(None, False, True))
        fixture_mount = Mount(volume, "/dev/disk99s1")
        def fake_validate(context: RunContext) -> None:
            context.image_metadata = {"fixture": "synthetic volume; no hdiutil was invoked"}
        def fake_mount(context: RunContext) -> list[Mount]:
            context.mounts.append(fixture_mount)
            return [fixture_mount]
        with mock.patch.object(sys.modules[__name__], "validate_image_and_read_metadata", side_effect=fake_validate), \
             mock.patch.object(sys.modules[__name__], "mount_image", side_effect=fake_mount):
            status = execute_pipeline(ctx)
        self.assertEqual(status, 0)
        self.assertTrue((output / "original" / "Demo App.app" / "Contents" / "Resources" / "app.asar").is_file())
        self.assertTrue((output / "extracted" / "asar" / "Demo App.app" / "Contents" / "Resources" / "app.asar.contents" / "main.js").is_file())
        self.assertTrue((output / "report.json").is_file())
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["applications"][0]["name"], "Demo App")
        self.assertTrue(report["applications"][0]["electron"])
        self.assertEqual(len(report["analysis"]["endpoints"]), 1)
        self.assertTrue(any(item["name"] == "API_TOKEN" for item in report["analysis"]["environment_variables"]))

    def test_cleanup_on_cancellation(self) -> None:
        from unittest import mock
        dmg = self.root / "cancel-test.dmg"
        dmg.write_bytes(b"synthetic DMG input")
        mount_point = self.root / "cancel-mounted-volume"
        mount_point.mkdir()
        commands: list[list[str]] = []

        def cancel_pipeline(ctx: RunContext) -> int:
            ctx.mounts.append(Mount(mount_point, "/dev/disk-cancel"))
            raise KeyboardInterrupt

        def fake_command(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            commands.append(list(command))
            return subprocess.CompletedProcess(list(command), 0, "", "")

        with mock.patch.object(sys.modules[__name__], "execute_pipeline", side_effect=cancel_pipeline), \
             mock.patch.object(sys.modules[__name__], "run_command", side_effect=fake_command):
            status = main([str(dmg), "--quiet"])
        self.assertEqual(status, 130)
        self.assertTrue(any(command[:2] == ["hdiutil", "detach"] for command in commands))


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DmgxTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 5


def main(argv: Sequence[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_tests()
    if not args.dmg:
        parser.error("the following argument is required: dmg")
    if args.max_files < 1 or args.max_file_size < 1 or args.max_total_size < 1 or args.max_scan_size < 1:
        parser.error("all --max-* limits must be positive integers")
    try:
        input_path = validate_input_path(args.dmg)
        output_path = resolve_output_path(args.output, input_path)
        if args.dry_run and output_path.exists() and not args.force:
            # Dry-run remains read-only and reports the conflict instead of touching the directory.
            pass
        limits = Limits(args.max_files, args.max_file_size, args.max_total_size, args.max_scan_size)
        logger = setup_logger(output_path if output_path.exists() else None, args.verbose, args.quiet)
        ctx = RunContext(input_path, output_path, args, limits, logger)
        if args.dry_run:
            return describe_dry_run(ctx)
        try:
            return execute_pipeline(ctx)
        except KeyboardInterrupt:
            log_warning(ctx, "Interrupted by user; attempting to unmount read-only volumes and clean up.")
            if ctx.output_path.exists():
                try:
                    (ctx.output_path / "logs").mkdir(parents=True, exist_ok=True)
                    write_reports(ctx, None, time.monotonic() - ctx.start_time, {"interrupted": True})
                except Exception:
                    pass
            return 130
        finally:
            unmount_all(ctx)
    except DmgxError as exc:
        print(f"dmgx: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        else:
            print(f"dmgx: unexpected error: {redact_text(str(exc))}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())

