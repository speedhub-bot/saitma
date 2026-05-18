"""
Cookie extraction engine.

Houses the SmartCookieExtractor (reused exactly from the original
``log to cookie.py``) plus an async wrapper that runs extraction
off the event-loop via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Callable, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union,
)

from loguru import logger

import config
from services import log_parser

MAX_TEXT_SCAN_BYTES = 64 * 1024 * 1024
PROCESS_TAIL_BYTES = 8192
ARCHIVE_PROCESS_IDLE_SECONDS = 900.0

# Output mode tokens for ``run_extraction_async``. Kept up top so the
# zip-streaming fast path (defined before _run_extraction) can use the
# defaults too.
COOKIE_MODE = "cookies"
ULP_MODE = "ulp"
COMBO_TARGETED_MODE = "combo_targeted"
COMBO_FULL_MODE = "combo_full"
CC_MODE = "cc"
ALL_CREDENTIAL_MODES: "FrozenSet[str]" = frozenset(
    {ULP_MODE, COMBO_TARGETED_MODE, COMBO_FULL_MODE}
)
ALL_NON_COOKIE_MODES: "FrozenSet[str]" = frozenset(
    {ULP_MODE, COMBO_TARGETED_MODE, COMBO_FULL_MODE, CC_MODE}
)
DEFAULT_OUTPUT_MODES: "FrozenSet[str]" = frozenset({COOKIE_MODE})


# ════════════════════════════════════════════════════════════
#  SmartCookieExtractor  — REUSED EXACTLY AS-IS
# ════════════════════════════════════════════════════════════

def _coerce_domains(domain: Union[str, Iterable[str]]) -> List[str]:
    """Normalise *domain* into a deduplicated list of lowercase domains.

    Accepts a single string or any iterable of strings. Empty / blank
    entries and leading dots are stripped. Order is preserved.
    """
    if isinstance(domain, str):
        candidates = [domain]
    else:
        candidates = list(domain)
    cleaned: List[str] = []
    seen = set()
    for d in candidates:
        if not isinstance(d, str):
            continue
        norm = d.strip().lower().lstrip(".")
        if norm and norm not in seen:
            seen.add(norm)
            cleaned.append(norm)
    return cleaned


class SmartCookieExtractor:
    """Efficiently extracts cookies from Netscape cookie format files.

    Supports filtering against a single target domain or multiple target
    domains in a single pass. When multiple domains are provided each cookie
    dict is tagged with a ``target_domain`` key naming whichever configured
    domain it matched, so callers can route per-domain without rerunning
    the parse.
    """

    def __init__(
        self,
        domain: Union[str, Iterable[str]],
        patterns: Optional[List[str]] = None,
    ):
        """Initialise extractor.

        Args:
            domain: A single domain string (e.g. ``"spotify.com"``) or an
                iterable of domain strings to filter against.
            patterns: Optional regex patterns for additional filtering.
        """
        domains = _coerce_domains(domain)
        if not domains:
            raise ValueError("SmartCookieExtractor requires at least one domain")
        self.domains: List[str] = domains
        # Back-compat: single ``self.domain`` attr keeps pointing at the
        # primary (first) target so older callers keep working.
        self.domain: str = domains[0]
        self.patterns = patterns or []
        self.domain_pattern = re.compile(
            rf"({re.escape(self.domain)})", re.IGNORECASE,
        )

    def extract_from_file(self, filepath: str) -> List[Dict[str, str]]:
        """
        Extract cookies from Netscape format cookie file

        Args:
            filepath: Path to cookie file

        Returns:
            List of cookie dictionaries
        """
        fp = Path(filepath)
        if not fp.exists():
            raise FileNotFoundError(f"File not found: {fp}")
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            return self.extract_from_lines(f)

    def extract_from_lines(self, lines: Iterable[str]) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cookie = self.parse_cookie_line(line)
            if cookie is None:
                continue
            target = self.match_domain(cookie["domain"])
            if target is not None:
                cookie["target_domain"] = target
                results.append(cookie)
        return results

    def extract_from_text(self, text: str) -> List[Dict[str, str]]:
        """Extract cookies from a raw Netscape-format cookies string.

        Lets streaming code paths (e.g. in-memory decompressed zip
        entries) reuse the same parser without writing to disk.
        """
        return self.extract_from_lines(text.splitlines())

    def parse_cookie_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Parse a Netscape cookie format line
        Format: domain flag path secure expiration name value

        Args:
            line: Cookie line to parse

        Returns:
            Dictionary with cookie data or None if invalid
        """
        parts = line.split("\t")

        if len(parts) < 7:
            return None

        try:
            return {
                "domain": parts[0].strip(),
                "flag": parts[1].strip(),
                "path": parts[2].strip(),
                "secure": parts[3].strip(),
                "expiration": parts[4].strip(),
                "name": parts[5].strip(),
                "value": parts[6].strip(),
            }
        except Exception:
            return None

    def match_domain(self, cookie_domain: str) -> Optional[str]:
        """Return the configured target domain that matches *cookie_domain*.

        Match rules (per configured target):
          * exact match, or
          * cookie domain is a subdomain of the target, or
          * target is a subdomain of the cookie domain (legacy permissive
            behaviour preserved from the original single-domain extractor).

        Returns ``None`` when no configured target matches.
        """
        cookie_domain = cookie_domain.lower().lstrip(".")
        for target in self.domains:
            if (
                cookie_domain == target
                or cookie_domain.endswith("." + target)
                or target.endswith("." + cookie_domain)
            ):
                return target
        return None

    def _matches_domain(self, cookie_domain: str) -> bool:
        """Back-compat alias used by older single-domain callers."""
        return self.match_domain(cookie_domain) is not None

    def extract_from_directory(
        self,
        directory: str,
        output_dir: Optional[str] = None,
        realtime_save: bool = False,
    ) -> Dict[str, List[Dict[str, str]]]:
        """
        Recursively extract cookies from all cookie files in directory

        Args:
            directory: Path to directory containing cookie files
            output_dir: Base output directory for real-time saving
            realtime_save: If True, save cookies in real-time to separate files

        Returns:
            Dictionary mapping file paths to cookie lists
        """
        results: Dict[str, List[Dict[str, str]]] = {}
        dir_path = Path(directory)

        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        # Setup output directory structure if real-time saving
        domain_output_dir: Optional[Path] = None
        if realtime_save and output_dir:
            domain_output_dir = Path(output_dir) / self.domain
            domain_output_dir.mkdir(parents=True, exist_ok=True)

        # Find all .txt files in Cookies subdirectories
        cookie_files: List[Path] = []
        try:
            cookie_files = list(dir_path.rglob("Cookies/*.txt"))
        except Exception:
            try:
                for item in dir_path.iterdir():
                    if item.is_dir():
                        cookies_dir = item / "Cookies"
                        if cookies_dir.exists():
                            cookie_files.extend(cookies_dir.glob("*.txt"))
            except Exception:
                pass

        file_counter = 1
        for i, filepath in enumerate(cookie_files, 1):
            try:
                cookies = self.extract_from_file(str(filepath))
                if cookies:
                    results[str(filepath)] = cookies

                    if realtime_save and domain_output_dir:
                        output_filename = f"akaza_{self.domain}_{file_counter}.txt"
                        output_path = domain_output_dir / output_filename

                        with open(output_path, "w", encoding="utf-8") as f:
                            for cookie in cookies:
                                f.write(
                                    f"{cookie['domain']}\t{cookie['flag']}\t{cookie['path']}\t"
                                    f"{cookie['secure']}\t{cookie['expiration']}\t"
                                    f"{cookie['name']}\t{cookie['value']}\n"
                                )

                        file_counter += 1
            except Exception:
                pass

        return results


# ════════════════════════════════════════════════════════════
#  Async wrapper & archive handling
# ════════════════════════════════════════════════════════════

@dataclass
class ExtractionProgress:
    """Mutable progress state shared between the worker thread and the bot."""
    phase: str = "idle"          # downloading / extracting / scanning / done / failed
    files_total: int = 0
    files_scanned: int = 0
    cookies_found: int = 0
    credentials_found: int = 0   # ULP / combo password rows produced
    download_current: int = 0
    download_total: int = 0
    download_start: float = 0.0     # monotonic timestamp when download began
    extract_total: int = 0          # total members in the archive (when known)
    extract_current: int = 0        # members already written to disk
    extract_start: float = 0.0      # monotonic timestamp when extraction began
    current_file: str = ""          # name of the file currently being processed
    cancelled: bool = False
    # Set by the downloader when it is editing the user-facing status
    # message itself (every ~2 MB). The dashboard updater checks this
    # flag and stays silent during the downloading phase to avoid two
    # writers fighting over the same message.
    live_download_msg: bool = False
    # Live password-guess feedback. ``current_password_attempt`` is the
    # candidate currently being tested by the auto-guesser; the prompt
    # renders it so the user can see what the bot has already tried.
    # ``password_attempts`` keeps the most recent failed candidates.
    current_password_attempt: str = ""
    password_attempts: List[str] = field(default_factory=list)


@dataclass
class ExtractionResult:
    """Final outcome of an extraction job."""
    success: bool
    output_files: List[str] = field(default_factory=list)
    cookies_found: int = 0
    files_scanned: int = 0
    error: str = ""
    duration_seconds: float = 0.0
    partial: bool = False           # True when results came from a cancelled job
    # Per-target-domain cookie counts. Only populated when the extractor
    # was configured for one or more domains; keys are the cleaned target
    # domain strings.
    per_domain_counts: Dict[str, int] = field(default_factory=dict)
    # Credential-mode counters (ULP / combo). Zero when those modes
    # weren't requested.
    credentials_found: int = 0
    # Per-output-mode counts so the user-facing summary can show
    # ``2,431 ULP / 187 claude.ai combos``.
    credential_counts: Dict[str, int] = field(default_factory=dict)
    # True when ``error`` came from a known content/environment issue
    # (corrupt archive, non-UTF8 filename, disk full, wrong password, …)
    # rather than a code bug. Callers use this to decide whether to
    # spam the admin with a critical-error alert.
    recoverable: bool = False


def _friendly_extraction_error(exc: BaseException) -> Tuple[str, bool]:
    """Translate raw exceptions into user-facing messages.

    Returns ``(message, recoverable)``. ``recoverable=True`` means the
    failure is a known content/environment issue (bad archive, non-UTF8
    filenames, disk full, wrong password, …) — *not* a code bug, so the
    admin doesn't need to be paged.
    """
    if isinstance(exc, UnicodeDecodeError):
        return (
            "Archive contained non-UTF8 filenames or text. Most files were "
            "still processed; some entries with garbled names were skipped.",
            True,
        )
    if isinstance(exc, FileNotFoundError):
        return (f"Required file missing: {exc}", True)
    if isinstance(exc, PermissionError):
        return (
            "Permission denied while reading or writing extraction files.",
            True,
        )
    if isinstance(exc, OSError):
        # Disk full, ENOSPC, broken pipe, etc. — environment, not code.
        errno_str = f" (errno {exc.errno})" if getattr(exc, "errno", None) else ""
        return (f"OS error during extraction{errno_str}: {exc}", True)
    msg = str(exc) or exc.__class__.__name__
    low = msg.lower()
    recoverable_markers = (
        "wrong password",
        "bad password",
        "is not encrypted",
        "no files to extract",
        "extraction failed",
        "unrar exited with code",
        "7z exited with code",
        "rar: ",
        "7z: ",
        "patoolib: ",
        "encrypted entries",
        "crc",
        "checksum",
        "unsupported archive",
        "not a zip",
        "not a rar",
        "corrupt",
    )
    if any(marker in low for marker in recoverable_markers):
        return (msg, True)
    return (msg, False)


def _terminate_process(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is not None:
            return
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def _kill_process(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is not None:
            return
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _tail_append(lines: List[str], line: str, limit: int = PROCESS_TAIL_BYTES) -> None:
    lines.append(line)
    total = 0
    keep: List[str] = []
    for item in reversed(lines):
        total += len(item.encode("utf-8", "ignore"))
        if total > limit and keep:
            break
        keep.append(item)
    keep.reverse()
    if len(keep) != len(lines):
        lines[:] = keep


def _safe_zip_extract(
    zf: zipfile.ZipFile,
    dest: str,
    progress: Optional["ExtractionProgress"] = None,
) -> None:
    """Extract zip with path traversal protection and per-member progress."""
    dest_real = os.path.realpath(dest)
    members = zf.namelist()
    for member in members:
        target = os.path.realpath(os.path.join(dest, member))
        if not target.startswith(dest_real + os.sep) and target != dest_real:
            raise ValueError(f"Path traversal detected in zip: {member}")
    if progress is not None:
        progress.extract_total = len(members)
        progress.extract_current = 0
    for name in members:
        if progress is not None and progress.cancelled:
            return
        if progress is not None:
            progress.current_file = os.path.basename(name) or name
        zf.extract(name, dest)
        if progress is not None:
            progress.extract_current += 1


def _safe_tar_extract(
    tf: tarfile.TarFile,
    dest: str,
    progress: Optional["ExtractionProgress"] = None,
) -> None:
    """Extract tar with path traversal/symlink protection and per-member progress."""
    dest_real = os.path.realpath(dest)
    safe_members = []
    for member in tf.getmembers():
        if member.issym() or member.islnk():
            logger.warning("Skipping symlink/hardlink in tar: {}", member.name)
            continue
        target = os.path.realpath(os.path.join(dest, member.name))
        if not target.startswith(dest_real + os.sep) and target != dest_real:
            raise ValueError(f"Path traversal detected in tar: {member.name}")
        safe_members.append(member)
    if progress is not None:
        progress.extract_total = len(safe_members)
        progress.extract_current = 0
    for member in safe_members:
        if progress is not None and progress.cancelled:
            return
        if progress is not None:
            progress.current_file = os.path.basename(member.name) or member.name
        tf.extract(member, dest)
        if progress is not None:
            progress.extract_current += 1



def _probe_encrypted_entries(archive_path: str) -> List[str]:
    """Return a list of password-protected entry names inside *archive_path*.

    Returns an empty list if the archive has no encrypted entries, or if
    we can't tell (missing tools, unknown format). Never raises.

    Detection order:
      * For ``.rar``: prefer ``unrar lt -p-`` and look for ``Flags: enc``.
      * Fallback / other formats: ``7z l -slt`` and look for
        ``Encrypted = +``.
    """
    import shutil as _shutil

    lower = archive_path.lower()
    encrypted: List[str] = []

    if lower.endswith(".rar"):
        unrar = _shutil.which("unrar")
        if unrar:
            try:
                proc = subprocess.run(
                    [unrar, "lt", "-p-", archive_path],
                    capture_output=True, text=True, errors="replace",
                    timeout=60,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                # ``lt`` (technical listing) emits blocks like:
                #     Name: foo.txt
                #     ...
                #     Flags: encrypted
                # We parse blocks split on "Name:" lines.
                blocks = re.split(r"(?m)^Name:\s+", proc.stdout)
                for blk in blocks[1:]:
                    first_nl = blk.find("\n")
                    name = blk[:first_nl].strip() if first_nl >= 0 else blk.strip()
                    if re.search(r"(?mi)^\s*Flags:.*encrypted", blk):
                        encrypted.append(name)
                if encrypted:
                    return encrypted
            except Exception as exc:
                logger.debug("unrar probe failed ({}); falling back", exc)

    sz = _shutil.which("7z")
    if sz:
        try:
            proc = subprocess.run(
                [sz, "l", "-slt", archive_path],
                capture_output=True, text=True, errors="replace",
                timeout=60,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            cur_name: Optional[str] = None
            for line in proc.stdout.splitlines():
                if line.startswith("Path = "):
                    cur_name = line[len("Path = "):].strip()
                elif line.startswith("Encrypted = +") and cur_name:
                    encrypted.append(cur_name)
        except Exception as exc:
            logger.debug("7z probe failed ({})", exc)

    return encrypted


_COMMON_PASSWORDS: List[str] = [
    # Default lazy passwords — ordered by prevalence in stealer-log dumps.
    "1234", "0000", "pass", "password", "123456", "12345",
    "admin", "root", "logs", "log", "rar", "zip", "test",
    "cookies", "archive", "akaza", "free", "vip",
]


def _password_candidates(archive_path: str) -> List[str]:
    """Build the list of passwords to try for *archive_path*.

    Combines:
      * ``_COMMON_PASSWORDS`` (default stealer-dump passwords).
      * Tokens derived from the filename: the full basename (with and
        without extension), and splits on common separators.
      * Any ``@TAG`` substrings in the filename (channel handles like
        ``@HARMONYLOGS`` — dump authors frequently use these as passwords).
    """
    base = os.path.basename(archive_path)
    stem = base
    # Strip up to two extensions so ``foo.tar.gz`` becomes ``foo``.
    for _ in range(2):
        if "." in stem:
            stem = stem.rsplit(".", 1)[0]

    seen: "set[str]" = set()
    out: List[str] = []

    def _push(val: str) -> None:
        val = val.strip()
        if not val:
            return
        if val in seen:
            return
        seen.add(val)
        out.append(val)

    for pwd in _COMMON_PASSWORDS:
        _push(pwd)

    _push(stem)
    _push(stem.lower())
    _push(stem.upper())

    # Channel-handle style: ``@Something`` tokens.
    for m in re.findall(r"@[A-Za-z0-9_]+", base):
        _push(m)            # with @
        _push(m.lstrip("@"))

    # Split on common separators.
    for tok in re.split(r"[\s._\-#@()\[\]{}]+", stem):
        _push(tok)
        _push(tok.lower())

    return out


# Max wall-clock time we let a single password test run. Big archives
# (hundreds of MB) can take well over a minute on cheap CPU before 7z /
# unrar finishes integrity-testing every encrypted entry, so 30 s used
# to false-fail correct passwords on large stealer dumps.
PASSWORD_TEST_TIMEOUT = 300


def _try_archive_password(archive_path: str, password: str) -> bool:
    """Return True if *password* successfully decrypts *archive_path*.

    Uses ``unrar t -p<pwd>`` for RAR (exit 0 = ok, 11 = wrong pwd) and
    ``7z t -p<pwd>`` for the rest. ``7z`` exit 1 is "warning" (e.g.
    extra-data warnings on otherwise-valid archives) and we treat it as
    a pass; only exit 2 / non-zero with stderr-flagged "Wrong password"
    is treated as a hard fail.

    Pipes ``-y`` / stdin=DEVNULL so the tool never hangs prompting and
    allows ``PASSWORD_TEST_TIMEOUT`` seconds before giving up.
    """
    import shutil as _shutil

    lower = archive_path.lower()

    if lower.endswith(".rar"):
        unrar = _shutil.which("unrar")
        if unrar:
            try:
                proc = subprocess.run(
                    [unrar, "t", f"-p{password}", "-y", "-inul", archive_path],
                    capture_output=True, timeout=PASSWORD_TEST_TIMEOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                # unrar: 0 = success, 11 = wrong password, anything else
                # is a tool-side issue (corrupt archive, missing file,
                # etc.) — we surface those in the log so debugging a
                # "wrong password" report is straightforward.
                if proc.returncode == 0:
                    return True
                if proc.returncode != 11:
                    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
                    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
                    logger.debug(
                        "unrar test rc={} stderr={!r} stdout={!r}",
                        proc.returncode, err[:200], out[:200],
                    )
                return False
            except subprocess.TimeoutExpired:
                logger.warning(
                    "unrar password test timed out after {}s on {}",
                    PASSWORD_TEST_TIMEOUT, os.path.basename(archive_path),
                )
                return False
            except Exception:
                logger.exception("unrar password test crashed")
                return False

    sz = _shutil.which("7z")
    if sz:
        try:
            proc = subprocess.run(
                [sz, "t", f"-p{password}", archive_path],
                capture_output=True, timeout=PASSWORD_TEST_TIMEOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            # 7z: 0 = ok, 1 = warning (still OK), 2 = fatal (incl. wrong
            # password). We accept 0 + 1 as success and look at stderr
            # for the "Wrong password" / "Data Error" markers when in
            # doubt.
            if proc.returncode in (0, 1):
                return True
            err = (proc.stderr or b"").decode("utf-8", "replace")
            out = (proc.stdout or b"").decode("utf-8", "replace")
            if "Wrong password" in out or "Wrong password" in err:
                return False
            logger.debug(
                "7z test rc={} stderr={!r} stdout={!r}",
                proc.returncode, err.strip()[:200], out.strip()[:200],
            )
            return False
        except subprocess.TimeoutExpired:
            logger.warning(
                "7z password test timed out after {}s on {}",
                PASSWORD_TEST_TIMEOUT, os.path.basename(archive_path),
            )
            return False
        except Exception:
            logger.exception("7z password test crashed")
            return False

    return False


def guess_archive_password(
    archive_path: str,
    progress: Optional["ExtractionProgress"] = None,
) -> Optional[str]:
    """Try the password candidate list against *archive_path*.

    Returns the first password that successfully tests, or ``None`` if
    none of the candidates worked. Runs sequentially — candidate list
    is short enough (~30 entries) that parallelism isn't worth the
    extra fork overhead.

    When *progress* is supplied we publish the password currently being
    tested via ``progress.current_password_attempt`` and append every
    attempted candidate (capped at the most recent 10) to
    ``progress.password_attempts`` so the prompt can render a live list.
    """
    candidates = _password_candidates(archive_path)
    logger.info(
        "Trying {} candidate passwords for {}",
        len(candidates), os.path.basename(archive_path),
    )
    for pwd in candidates:
        if progress is not None:
            if progress.cancelled:
                progress.current_password_attempt = ""
                return None
            progress.current_password_attempt = pwd
        logger.debug("password test: trying {!r}", pwd)
        if _try_archive_password(archive_path, pwd):
            if progress is not None:
                progress.current_password_attempt = ""
            logger.info(
                "Password auto-guess hit for {}: {!r}",
                os.path.basename(archive_path), pwd,
            )
            return pwd
        if progress is not None:
            attempts = progress.password_attempts
            attempts.append(pwd)
            # Keep the visible history short — Telegram's max message
            # length is small relative to a 30-entry candidate list.
            if len(attempts) > 10:
                del attempts[: len(attempts) - 10]
    if progress is not None:
        progress.current_password_attempt = ""
    logger.info(
        "Password auto-guess exhausted for {} ({} candidates tried)",
        os.path.basename(archive_path), len(candidates),
    )
    return None


def _is_split_archive(path: str) -> bool:
    """Detect split/multipart archive naming patterns."""
    base = os.path.basename(path).lower()
    if re.search(r"\.part-?\d+\.zip$", base):
        return True
    if re.search(r"\.part-?\d+\.rar$", base):
        return True
    if re.search(r"\.part-?\d+\.7z$", base):
        return True
    if re.search(r"\.zip\.\d+$", base):
        return True
    if re.search(r"\.7z\.\d+$", base):
        return True
    return False


# Magic-byte signatures used to detect the *actual* archive format,
# regardless of the filename extension the user sent.
_MAGIC_SIGNATURES: List[tuple[bytes, str]] = [
    (b"PK\x03\x04", "zip"),         # standard zip
    (b"PK\x05\x06", "zip"),         # empty zip (EOCD only)
    (b"PK\x07\x08", "zip"),         # spanned zip data descriptor
    (b"Rar!\x1a\x07\x00", "rar"),   # RAR 1.5+
    (b"Rar!\x1a\x07\x01\x00", "rar"),  # RAR 5.0
    (b"7z\xbc\xaf\x27\x1c", "7z"),  # 7z
    (b"\x1f\x8b", "gz"),            # gzip / .tar.gz
    (b"BZh", "bz2"),                # bzip2 / .tar.bz2
    (b"\xfd7zXZ\x00", "xz"),        # xz / .tar.xz
]


def _sniff_archive_type(path: str) -> Optional[str]:
    """Return a normalised archive-type tag based on file magic bytes.

    Returns one of: "zip", "rar", "7z", "gz", "bz2", "xz", or None
    if the file is empty / unreadable / unrecognised.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if not head:
        return None
    for sig, kind in _MAGIC_SIGNATURES:
        if head.startswith(sig):
            return kind
    return None


class _DirCountPoller:
    """Background polling thread that updates progress by counting files in *dest*.

    Acts as a robust fallback when the underlying extraction tool's own
    progress output can't be parsed (e.g. patoolib, or 7z when it streams
    progress on a different fd than we expect). Only ever moves the counter
    forward, never backward.
    """

    def __init__(
        self,
        dest: str,
        progress: Optional["ExtractionProgress"],
        interval: float = 1.5,
    ) -> None:
        self._dest = dest
        self._progress = progress
        self._interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "_DirCountPoller":
        if self._progress is not None:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            progress = self._progress
            if progress is None:
                return
            try:
                count = 0
                for _root, _dirs, files in os.walk(self._dest):
                    count += len(files)
                if count > progress.extract_current:
                    progress.extract_current = count
            except Exception:
                pass


def _validate_extracted_paths(dest: str) -> None:
    """Post-extraction check: ensure no file escaped the destination directory."""
    dest_real = os.path.realpath(dest)
    for root, dirs, files in os.walk(dest):
        for name in files + dirs:
            full = os.path.realpath(os.path.join(root, name))
            if not full.startswith(dest_real + os.sep) and full != dest_real:
                raise ValueError(f"Path traversal detected after extraction: {name}")


def _extract_with_7z(
    archive_path: str,
    dest: str,
    progress: Optional["ExtractionProgress"] = None,
    password: Optional[str] = None,
) -> None:
    """Extract using 7z command-line tool with live per-file progress.

    7z's ``-bsp2`` option streams progress lines to stderr. We parse them
    so the bot can show ``extract_current / extract_total`` while the
    process runs. A ``_DirCountPoller`` also runs alongside as a fallback
    so the counter advances even if 7z's output format changes.
    """
    import shutil as _shutil

    sz = _shutil.which("7z")
    if not sz:
        raise RuntimeError(
            "7z not found. Install with: apt-get install -y p7zip-full"
        )

    # First, count entries so we can show a real progress bar.
    # stdin=DEVNULL + start_new_session=True for the listing step too:
    # archives with encrypted headers (``-mhe=on``) require the password
    # to even read the file list, and 7z would otherwise hang prompting
    # before extraction even begins.
    list_cmd = [sz, "l", "-slt", archive_path]
    if password:
        list_cmd.append(f"-p{password}")
    if progress is not None:
        try:
            count_proc = subprocess.run(
                list_cmd,
                capture_output=True, text=True, errors="replace",
                timeout=60,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            if count_proc.returncode == 0:
                # "Path =" lines, minus the archive header line.
                paths = [
                    ln for ln in count_proc.stdout.splitlines()
                    if ln.startswith("Path = ")
                ]
                progress.extract_total = max(len(paths) - 1, 0)
                progress.extract_current = 0
        except Exception as exc:
            logger.debug("7z list failed ({}); progress count unavailable", exc)

    # Stream extraction with line-buffered stderr so we can update progress.
    # 7z output-control flags:
    #   -bb1   log level 1 (one line per extracted entry: "- relative/path")
    #   -bso2  output stream    -> stderr (fd 2)
    #   -bse2  error messages   -> stderr (fd 2)
    #   -bsp2  progress info    -> stderr (fd 2)
    # We capture stderr below and parse per-file progress lines from it.
    # A directory-count poller runs alongside as a robust fallback so the
    # dashboard advances even if 7z's progress output format changes.
    # stdin=DEVNULL + start_new_session=True together neutralise every way
    # 7z could otherwise hang on a password prompt:
    #   * stdin=DEVNULL gives 7z immediate EOF when it tries to read input.
    #   * start_new_session=True puts 7z in its own process group with no
    #     controlling terminal, so even if it tries to open /dev/tty
    #     directly to bypass stdin (some builds do that), the open fails.
    # Combined effect: 7z fails any password-protected entry with a
    # non-zero exit code rather than blocking forever.
    extract_cmd = [
        sz, "x", archive_path, f"-o{dest}", "-y",
        "-bb1", "-bso2", "-bse2", "-bsp2",
    ]
    if password:
        extract_cmd.append(f"-p{password}")
    proc = subprocess.Popen(
        extract_cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    stderr_chunks: List[str] = []
    file_lines_seen = 0
    # Watchdog: if neither the line parser nor the directory poller
    # advance progress for this many seconds, assume the underlying tool
    # is wedged and kill it. Picked generously so big-file decompression
    # still finishes naturally.
    WATCHDOG_IDLE_SECONDS = ARCHIVE_PROCESS_IDLE_SECONDS
    last_progress_count = 0
    last_progress_time = time.monotonic()
    stop_watchdog = threading.Event()

    def _watchdog() -> None:
        nonlocal last_progress_count, last_progress_time
        while not stop_watchdog.wait(5.0):
            if proc.poll() is not None:
                return
            current = (
                progress.extract_current
                if progress is not None
                else file_lines_seen
            )
            if current > last_progress_count:
                last_progress_count = current
                last_progress_time = time.monotonic()
                continue
            if time.monotonic() - last_progress_time > WATCHDOG_IDLE_SECONDS:
                logger.error(
                    "7z made no progress for {}s (stuck at {} entries); "
                    "terminating.",
                    int(WATCHDOG_IDLE_SECONDS), current,
                )
                _kill_process(proc)
                return

    watchdog_thread = threading.Thread(target=_watchdog, daemon=True)
    watchdog_thread.start()

    try:
        assert proc.stderr is not None
        with _DirCountPoller(dest, progress):
            for line in proc.stderr:
                _tail_append(stderr_chunks, line)
                # 7z streams progress with embedded backspaces and CRs to
                # repaint a TTY counter; strip those before parsing so the
                # regex can find the "- relative/path" suffix.
                cleaned = line.replace("\x08", "").replace("\r", "").strip()
                if not cleaned:
                    continue
                if progress is not None:
                    # Per-file lines (with -bb1) look like:
                    #   "- relative/path/inside/archive"
                    # Combined with progress (-bsp2) they may look like:
                    #   "  3% 12      - relative/path"
                    m = re.search(r"-\s+([^\s].*)$", cleaned)
                    if m:
                        name = m.group(1).strip()
                        progress.current_file = os.path.basename(name) or name
                        file_lines_seen += 1
                        if file_lines_seen > progress.extract_current:
                            progress.extract_current = file_lines_seen
                if progress is not None and progress.cancelled:
                    _terminate_process(proc)
                    break
            proc.wait(timeout=60)
    except Exception:
        _kill_process(proc)
        raise
    finally:
        stop_watchdog.set()
        watchdog_thread.join(timeout=2.0)

    if progress is not None and progress.cancelled:
        # Caller will short-circuit; don't raise.
        return

    # Ground-truth the file count — see identical logic in
    # _extract_with_unrar for the reasoning.
    actual_count = 0
    for _r, _d, files in os.walk(dest):
        actual_count += len(files)
    if progress is not None:
        progress.extract_current = max(progress.extract_current, actual_count)

    if proc.returncode != 0:
        # If at least some files made it out, treat this as a partial success
        # rather than aborting the whole job. Common cause: a single
        # password-protected entry inside an otherwise-fine archive (e.g. a
        # bundled "KeyGen.rar" inside a log dump). We still want the cookies
        # from the 95% that extracted cleanly.
        if actual_count > 0:
            logger.warning(
                "7z exited with code {} after extracting {} files; "
                "treating as partial success. Last error output: {}",
                proc.returncode,
                actual_count,
                "".join(stderr_chunks[-5:]).strip()[:200],
            )
        else:
            raise RuntimeError(
                f"7z extraction failed: {''.join(stderr_chunks).strip()[:2000]}"
            )
    _validate_extracted_paths(dest)


def _extract_with_unrar(
    archive_path: str,
    dest: str,
    progress: Optional["ExtractionProgress"] = None,
    password: Optional[str] = None,
) -> None:
    """Extract a .rar archive with the proprietary ``unrar`` binary.

    unrar is RARLab's reference implementation and is the only free tool
    that correctly handles RAR5 format plus per-entry password protection.
    We pass ``-p-`` to make it skip password-protected entries silently
    instead of prompting, and ``-o+`` to overwrite any conflicts.

    A ``_DirCountPoller`` advances the dashboard (unrar doesn't stream
    per-file progress in a structured format), and the same watchdog
    pattern as 7z guards against hangs.
    """
    import shutil as _shutil

    unrar = _shutil.which("unrar")
    if not unrar:
        raise RuntimeError("unrar not found")

    # ``-p<password>`` unlocks encrypted entries without prompting.
    # ``-p-`` keeps the old skip-encrypted behaviour when no password
    # was provided.
    pw_flag = f"-p{password}" if password else "-p-"

    # Count entries first for the progress bar.
    if progress is not None:
        try:
            count_proc = subprocess.run(
                [unrar, "lb", pw_flag, archive_path],
                capture_output=True, text=True, errors="replace",
                timeout=60,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            if count_proc.returncode == 0:
                lines = [
                    ln for ln in count_proc.stdout.splitlines() if ln.strip()
                ]
                progress.extract_total = len(lines)
                progress.extract_current = 0
        except Exception as exc:
            logger.debug(
                "unrar list failed ({}); progress count unavailable", exc
            )

    # ``x``    extract with full paths
    # ``-p-``  never ask for password; skip encrypted entries with error
    # ``-o+``  overwrite existing files without prompting
    # ``-y``   yes to all queries
    # ``-idq`` quiet mode (reduce noise)
    proc = subprocess.Popen(
        [unrar, "x", pw_flag, "-o+", "-y", archive_path, dest + os.sep],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    output_chunks: List[str] = []
    WATCHDOG_IDLE_SECONDS = ARCHIVE_PROCESS_IDLE_SECONDS
    last_progress_count = 0
    last_progress_time = time.monotonic()
    stop_watchdog = threading.Event()

    def _watchdog() -> None:
        nonlocal last_progress_count, last_progress_time
        while not stop_watchdog.wait(5.0):
            if proc.poll() is not None:
                return
            current = progress.extract_current if progress is not None else 0
            if current > last_progress_count:
                last_progress_count = current
                last_progress_time = time.monotonic()
                continue
            if time.monotonic() - last_progress_time > WATCHDOG_IDLE_SECONDS:
                logger.error(
                    "unrar made no progress for {}s (stuck at {} entries); "
                    "terminating.",
                    int(WATCHDOG_IDLE_SECONDS), current,
                )
                _kill_process(proc)
                return

    watchdog_thread = threading.Thread(target=_watchdog, daemon=True)
    watchdog_thread.start()

    try:
        assert proc.stdout is not None
        with _DirCountPoller(dest, progress):
            for line in proc.stdout:
                _tail_append(output_chunks, line)
                cleaned = line.strip()
                if not cleaned:
                    continue
                # unrar emits lines like "Extracting  dir/file.txt"
                m = re.match(r"Extracting\s+(.+?)(?:\s+OK\s*)?$", cleaned)
                if m and progress is not None:
                    name = m.group(1).strip()
                    progress.current_file = os.path.basename(name) or name
                if progress is not None and progress.cancelled:
                    _terminate_process(proc)
                    break
            proc.wait(timeout=60)
    except Exception:
        _kill_process(proc)
        raise
    finally:
        stop_watchdog.set()
        watchdog_thread.join(timeout=2.0)

    if progress is not None and progress.cancelled:
        return

    # Ground-truth the extracted file count by walking the destination
    # directory. _DirCountPoller may have missed the final state, and
    # progress.extract_current can lag behind reality right after the
    # process exits. This gives us an authoritative number to decide
    # whether we got partial success.
    actual_count = 0
    for _r, _d, files in os.walk(dest):
        actual_count += len(files)
    if progress is not None:
        progress.extract_current = max(progress.extract_current, actual_count)

    # unrar exit codes:
    #   0    success
    #   1    non-fatal warning (still success for us)
    #   3    corrupt header / CRC (can be partial)
    #   10   nothing to extract (hard failure if count==0, partial otherwise)
    #   11   wrong password — an archive-wide or per-entry password issue;
    #        with -p- any encrypted entry triggers this. If other entries
    #        extracted cleanly this is a partial success.
    # Anything else we treat as a hard failure iff nothing was extracted.
    if proc.returncode not in (0, 1):
        if actual_count > 0:
            logger.warning(
                "unrar exited with code {} after extracting {} files; "
                "treating as partial success (archive likely has "
                "password-protected entries). Last output: {}",
                proc.returncode,
                actual_count,
                "".join(output_chunks[-5:]).strip()[:200],
            )
        else:
            raise RuntimeError(
                f"unrar extraction failed (exit {proc.returncode}): "
                f"{''.join(output_chunks).strip()[:2000]}"
            )
    _validate_extracted_paths(dest)


def _extract_archive(
    archive_path: str,
    dest: str,
    progress: Optional["ExtractionProgress"] = None,
    password: Optional[str] = None,
) -> None:
    """Extract an archive into *dest* using the best available tool.

    Strategy:
    1. Split/multipart archives → 7z directly.
    2. Detect the *actual* archive format from magic bytes (so a file
       mis-named with the wrong extension still works).
    3. Try the cheapest pure-Python handler first (zipfile / tarfile),
       fall through to patoolib for .rar, and finally fall back to 7z
       for anything that didn't extract cleanly.
    Path-traversal protection (ValueError) is never swallowed.
    """
    if not os.path.exists(archive_path):
        raise RuntimeError(f"Archive not found: {archive_path}")
    if os.path.getsize(archive_path) == 0:
        raise RuntimeError(
            "Uploaded file is empty (0 bytes). "
            "Please re-upload a valid archive."
        )

    # Split archives — go straight to 7z
    if _is_split_archive(archive_path):
        logger.info("Split archive detected, using 7z: {}", archive_path)
        _extract_with_7z(archive_path, dest, progress, password=password)
        return

    # Determine the real archive format from the file's magic bytes; if
    # that's inconclusive, fall back to the filename extension. This
    # prevents e.g. a 7z file mis-named as .zip from killing the job
    # with "File is not a zip file".
    sniffed = _sniff_archive_type(archive_path)
    lower = archive_path.lower()
    if sniffed is None:
        if lower.endswith(".zip"):
            sniffed = "zip"
        elif lower.endswith((".tar.gz", ".tgz")):
            sniffed = "gz"
        elif lower.endswith(".tar.bz2"):
            sniffed = "bz2"
        elif lower.endswith(".rar"):
            sniffed = "rar"
        elif lower.endswith(".7z"):
            sniffed = "7z"

    if sniffed != _ext_kind(lower):
        logger.info(
            "Archive content ({}) differs from extension ({}); routing by content",
            sniffed, _ext_kind(lower),
        )

    # Pure-Python zip. Skip it when a password is provided; stdlib
    # ``zipfile`` only supports the weak ZipCrypto password format, and
    # falling straight to 7z gives us AES-protected zip support for free.
    if sniffed == "zip" and not password:
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                _safe_zip_extract(zf, dest, progress)
            return
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("zipfile failed ({}), falling back to 7z", exc)
            _extract_with_7z(archive_path, dest, progress, password=password)
            return
    if sniffed == "zip":  # password provided — go straight to 7z
        _extract_with_7z(archive_path, dest, progress, password=password)
        return

    # Pure-Python tarball (gzip / bzip2 / xz / plain tar)
    if sniffed in ("gz", "bz2", "xz"):
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                _safe_tar_extract(tf, dest, progress)
            return
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("tarfile failed ({}), falling back to 7z", exc)
            _extract_with_7z(archive_path, dest, progress, password=password)
            return

    # .rar / .7z / unknown.
    #
    # For ``.rar``, prefer the proprietary ``unrar`` binary when installed:
    # it's the RARLab reference implementation, is the only free tool that
    # handles RAR5 correctly, and has a native ``-p-`` flag that skips
    # password-protected entries non-interactively. This matters because
    # p7zip 16.02 (the Debian 12 default) has no RAR5 support and hangs
    # on per-entry encryption even with stdin=DEVNULL / setsid.
    #
    # Fall through to ``_extract_with_7z`` if unrar isn't available or
    # failed. Both paths are hardened against stdin prompts and have a
    # watchdog. patoolib is kept as an absolute last resort for exotic
    # formats (e.g. ACE, ARJ) that neither 7z nor unrar handle.
    import shutil as _shutil

    has_tool = (
        _shutil.which("unrar") or _shutil.which("7z") or _shutil.which("unar")
    )
    if not has_tool:
        raise RuntimeError(
            "No extraction tool found for this archive format. "
            "Install p7zip-full + unrar on the server: "
            "apt-get install -y p7zip-full unrar"
        )

    unrar_path = _shutil.which("unrar")
    sevenz_path = _shutil.which("7z")
    logger.info(
        "Extracting {} (sniffed={}); available tools: unrar={}, 7z={}",
        archive_path, sniffed, unrar_path, sevenz_path,
    )

    errors: List[str] = []

    # Try unrar first for .rar files (best RAR5 + encrypted-entry support).
    if sniffed == "rar" and unrar_path:
        logger.info("Trying unrar first for {}", archive_path)
        try:
            _extract_with_unrar(archive_path, dest, progress, password=password)
            logger.info("unrar extraction succeeded for {}", archive_path)
            return
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("unrar extraction failed ({}), falling back to 7z", exc)
            errors.append(f"unrar: {exc}")

    # Try 7z next.
    if sevenz_path:
        logger.info("Trying 7z for {}", archive_path)
        try:
            _extract_with_7z(archive_path, dest, progress, password=password)
            logger.info("7z extraction succeeded for {}", archive_path)
            return
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("7z extraction failed ({}), trying patoolib", exc)
            errors.append(f"7z: {exc}")

    # Last resort: patoolib.
    logger.info("Trying patoolib as final fallback for {}", archive_path)
    try:
        import patoolib
        with _DirCountPoller(dest, progress):
            patoolib.extract_archive(archive_path, outdir=dest, interactive=False)
        _validate_extracted_paths(dest)
        logger.info("patoolib extraction succeeded for {}", archive_path)
        return
    except ValueError:
        raise
    except Exception as exc:
        errors.append(f"patoolib: {exc}")

    # Everything failed. Surface every tool's error — truncate each
    # tool's message so the combined string stays within Telegram's
    # 4096-char message limit.
    combined = "; ".join(
        f"[{e[:700]}{'...' if len(e) > 700 else ''}]" for e in errors
    )
    raise RuntimeError(
        f"All extraction tools failed on this archive. Errors: {combined}"
    )


def _ext_kind(lower_path: str) -> Optional[str]:
    """Return the archive-kind tag implied by a (lowercased) filename."""
    if lower_path.endswith(".zip"):
        return "zip"
    if lower_path.endswith((".tar.gz", ".tgz")):
        return "gz"
    if lower_path.endswith(".tar.bz2"):
        return "bz2"
    if lower_path.endswith(".rar"):
        return "rar"
    if lower_path.endswith(".7z"):
        return "7z"
    return None


def _write_one_zip(
    files: List[str],
    output_dir: str,
    domain: str,
    part_idx: int,
) -> str:
    safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
    if part_idx == 1:
        zip_path = os.path.join(output_dir, f"{safe_domain}_cookies.zip")
    else:
        zip_path = os.path.join(output_dir, f"{safe_domain}_cookies_part{part_idx}.zip")
    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as zf:
        for src in files:
            zf.write(src, arcname=os.path.basename(src))
    return zip_path


def _bundle_one_domain(
    per_source_dir: str,
    output_dir: str,
    domain: str,
) -> List[str]:
    """Bundle every per-source ``.txt`` in *per_source_dir* into one or
    more chunked ``{domain}_cookies[_partN].zip`` files in *output_dir*.

    Returns the list of zip files created (possibly empty)."""
    entries: List[tuple[str, int]] = []
    for name in sorted(os.listdir(per_source_dir)):
        path = os.path.join(per_source_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            sz = os.path.getsize(path)
        except OSError:
            continue
        if sz > 0:
            entries.append((path, sz))

    if not entries:
        return []

    limit = max(int(getattr(config, "OUTPUT_CHUNK_SIZE_BYTES", 45 * 1024 * 1024)), 1024)
    zip_paths: List[str] = []
    part_idx = 1
    batch: List[str] = []
    batch_size = 0
    for path, sz in entries:
        if batch and batch_size + sz > limit:
            zip_paths.append(_write_one_zip(batch, output_dir, domain, part_idx))
            part_idx += 1
            batch = []
            batch_size = 0
        batch.append(path)
        batch_size += sz
    if batch:
        zip_paths.append(_write_one_zip(batch, output_dir, domain, part_idx))
    return zip_paths


def _bundle_all_zips(
    per_source_dir: str,
    output_dir: str,
    domain: Union[str, Iterable[str]],
) -> List[str]:
    """Bundle per-source ``.txt`` files into one zip per target domain.

    *per_source_dir* may either be:

    * a flat directory of ``.txt`` files (legacy single-domain layout) —
      in which case all files are bundled into ``{domain}_cookies.zip``; or
    * a directory containing one subdirectory per target domain (each
      holding that domain's per-source ``.txt`` files) — in which case
      one zip is produced per domain.

    Returns the flat list of zip files created across every domain.
    """
    domains = _coerce_domains(domain)

    # Detect layout: if any of the configured domains has a subdirectory
    # under per_source_dir we treat this as the multi-domain layout. We
    # also fall back to the legacy flat layout when only one domain is
    # configured *and* there's no matching subdirectory — to keep older
    # callers and tests behaving identically.
    multi_layout = any(
        os.path.isdir(os.path.join(per_source_dir, d)) for d in domains
    )
    if not multi_layout:
        # Legacy layout — flat dir, single domain.
        return _bundle_one_domain(per_source_dir, output_dir, domains[0])

    zip_paths: List[str] = []
    for d in domains:
        sub = os.path.join(per_source_dir, d)
        if not os.path.isdir(sub):
            continue
        zip_paths.extend(_bundle_one_domain(sub, output_dir, d))
    return zip_paths


def _run_extraction_zip_stream(
    archive_path: str,
    domain: Union[str, Iterable[str]],
    progress: ExtractionProgress,
    output_dir: str,
    start: float,
    output_modes: FrozenSet[str] = DEFAULT_OUTPUT_MODES,
) -> ExtractionResult:
    """Fast path for plain zip archives: walk members in place, scan
    each one in memory, write per-source .txt files (one folder per
    target domain) + bundle into one zip per domain.

    When *output_modes* includes any credential mode (ULP / combo) we
    also stream-parse every password file in the same loop and emit
    the matching output files alongside the cookie zips.

    Saves the disk-space + wall-clock cost of first unpacking the whole
    archive to a temp dir, matching u.txt's ``extractZipStreaming`` idea.
    """
    logger.info(
        "Zip-streaming {} (no disk extraction), modes={}",
        archive_path, sorted(output_modes),
    )
    progress.phase = "extracting"
    progress.extract_start = time.monotonic()
    progress.current_file = ""

    domains = _coerce_domains(domain)
    want_cookies = COOKIE_MODE in output_modes
    want_creds = bool(output_modes & ALL_CREDENTIAL_MODES)
    want_cc = CC_MODE in output_modes

    per_source_dir = tempfile.mkdtemp(
        dir=str(config.TEMP_DIR), prefix="cookie_out_",
    )
    # One subdirectory per target domain so _bundle_all_zips can produce
    # one zip per domain.
    safe_targets: Dict[str, str] = {}
    file_counters: Dict[str, int] = {}
    for d in domains:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", d)
        safe_targets[d] = safe
        file_counters[d] = 1
        os.makedirs(os.path.join(per_source_dir, d), exist_ok=True)

    cookie_parser = SmartCookieExtractor(domains)
    per_domain_counts: Dict[str, int] = {d: 0 for d in domains}
    creds: List[log_parser.Credential] = []
    creds_seen: Set = set()
    cc_by_num: Dict[str, "log_parser.CreditCard"] = {}

    try:
        try:
            zf = zipfile.ZipFile(archive_path, "r")
        except zipfile.BadZipFile as exc:
            raise RuntimeError(f"Not a valid zip: {exc}") from exc

        with zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            progress.extract_total = len(members)
            progress.files_total = len(members)

            # Switch to scanning phase straight away — we're doing
            # extract+scan together, so there's no separate "extract
            # to disk" step for the dashboard to render.
            progress.phase = "scanning"

            for member in members:
                if progress.cancelled:
                    break
                progress.current_file = (
                    os.path.basename(member.filename) or member.filename
                )
                progress.extract_current += 1

                if member.file_size and member.file_size > MAX_TEXT_SCAN_BYTES:
                    progress.files_scanned += 1
                    continue

                is_pwd = want_creds and log_parser.is_password_file(member.filename)
                # CC scanning runs on both dedicated CC files and on
                # password dumps — many stealers inline CC data right
                # next to the passwords block. The parser is uniformly
                # strict now (full NUMBER|MM|YY|CVV required, brand &
                # exp validation), so we don't need a per-file toggle.
                is_cc_candidate = want_cc and (
                    log_parser.is_cc_file(member.filename)
                    or log_parser.is_password_file(member.filename)
                )

                # Read once, parse for cookies + credentials + CCs as
                # requested. Tabbed cookie files have no ``@`` lines so
                # the ULP parser will skip them naturally.
                try:
                    with zf.open(member, "r") as fh:
                        raw_bytes = fh.read()
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    progress.files_scanned += 1
                    continue
                text = raw_bytes.decode("utf-8", errors="ignore")

                cookies: List[Dict[str, str]] = []
                if want_cookies:
                    try:
                        cookies = cookie_parser.extract_from_lines(
                            iter(text.splitlines())
                        )
                    except Exception:
                        cookies = []

                if is_pwd:
                    for c in log_parser.parse_any(text):
                        key = (c.url, c.user, c.password)
                        if key in creds_seen:
                            continue
                        creds_seen.add(key)
                        creds.append(c)

                if is_cc_candidate:
                    for card in log_parser.parse_credit_cards(text):
                        existing = cc_by_num.get(card.number)
                        if existing is None:
                            cc_by_num[card.number] = card
                            continue
                        # Prefer the record with more fields filled in.
                        def _ccscore(c: "log_parser.CreditCard") -> int:
                            return (
                                int(bool(c.mm))
                                + int(bool(c.yy))
                                + int(bool(c.cvv))
                            )
                        if _ccscore(card) > _ccscore(existing):
                            cc_by_num[card.number] = card

                if cookies:
                    # Group hits from this source file by target domain so
                    # each target gets its own per-source ``akaza_*.txt``.
                    by_target: Dict[str, List[Dict[str, str]]] = {}
                    for c in cookies:
                        t = c.get("target_domain", domains[0])
                        by_target.setdefault(t, []).append(c)
                    for t, group in by_target.items():
                        safe = safe_targets.get(
                            t, re.sub(r"[^A-Za-z0-9._-]", "_", t),
                        )
                        idx = file_counters.get(t, 1)
                        out_name = f"akaza_{safe}_{idx}.txt"
                        sub_dir = os.path.join(per_source_dir, t)
                        os.makedirs(sub_dir, exist_ok=True)
                        out_path = os.path.join(sub_dir, out_name)
                        try:
                            with open(out_path, "w", encoding="utf-8") as fh2:
                                for c in group:
                                    fh2.write(
                                        f"{c['domain']}\t{c['flag']}\t{c['path']}\t"
                                        f"{c['secure']}\t{c['expiration']}\t"
                                        f"{c['name']}\t{c['value']}\n"
                                    )
                                    progress.cookies_found += 1
                                    per_domain_counts[t] = (
                                        per_domain_counts.get(t, 0) + 1
                                    )
                            file_counters[t] = idx + 1
                        except OSError:
                            logger.exception(
                                "Failed to write per-source file {}", out_path,
                            )

                progress.files_scanned += 1

        progress.phase = "packaging"
        progress.current_file = ""
        output_files: List[str] = []
        if want_cookies:
            output_files.extend(
                _bundle_all_zips(per_source_dir, output_dir, domains)
            )

        # Emit credential output files (ULP / combo) into output_dir
        # alongside the cookie zips. These ride on the same job's
        # delivery path so the user gets everything in one drop.
        cred_counts: Dict[str, int] = {}
        if want_creds:
            output_files.extend(
                _emit_credential_outputs(
                    creds, domains, output_modes, output_dir, progress,
                )
            )
            cred_counts = _credential_counts(creds, domains, output_modes)

        if want_cc and cc_by_num:
            cards = list(cc_by_num.values())
            output_files.extend(
                _emit_cc_outputs(cards, domains, output_dir, progress)
            )
            cred_counts[CC_MODE] = len(cards)

        output_files = [
            p for p in output_files
            if os.path.exists(p) and os.path.getsize(p) > 0
        ]
        duration = time.monotonic() - start

        if progress.cancelled:
            progress.phase = "cancelled"
            return ExtractionResult(
                success=bool(output_files),
                output_files=output_files,
                cookies_found=progress.cookies_found,
                files_scanned=progress.files_scanned,
                duration_seconds=duration,
                partial=True,
                error="" if output_files else "Cancelled by user (no results yet)",
                per_domain_counts=per_domain_counts,
                credentials_found=progress.credentials_found,
                credential_counts=cred_counts,
            )

        progress.phase = "done"
        return ExtractionResult(
            success=True,
            output_files=output_files,
            cookies_found=progress.cookies_found,
            files_scanned=progress.files_scanned,
            duration_seconds=duration,
            per_domain_counts=per_domain_counts,
            credentials_found=progress.credentials_found,
            credential_counts=cred_counts,
        )

    finally:
        shutil.rmtree(per_source_dir, ignore_errors=True)


# ── Credential output (ULP / combo) ─────────────────────────


def _safe_domain_label(domains: Iterable[str]) -> str:
    """Filesystem-safe slug for the first domain (or ``multi`` for many)."""
    domain_list = [d for d in domains if d]
    if not domain_list:
        return "logs"
    if len(domain_list) == 1:
        return re.sub(r"[^A-Za-z0-9._-]", "_", domain_list[0])
    return "multi"


def _collect_credentials_from_zip(
    zf: "zipfile.ZipFile",
    progress: ExtractionProgress,
) -> List[log_parser.Credential]:
    """Stream-scan a zip's password files in memory, no disk extraction.

    Used by the streaming fast-path so credential modes don't force
    a full disk extraction.
    """
    creds: List[log_parser.Credential] = []
    seen: Set = set()
    try:
        members = list(zf.infolist())
    except (UnicodeDecodeError, zipfile.BadZipFile, OSError) as exc:
        logger.warning(
            "zip infolist failed ({}); credentials skipped", exc,
        )
        return creds
    for member in members:
        if progress.cancelled:
            break
        try:
            if member.is_dir():
                continue
            if not log_parser.is_password_file(member.filename):
                continue
            if member.file_size and member.file_size > MAX_TEXT_SCAN_BYTES:
                continue
        except (UnicodeDecodeError, AttributeError):
            continue
        try:
            with zf.open(member, "r") as fh:
                raw = fh.read()
        except (RuntimeError, zipfile.BadZipFile, OSError, UnicodeDecodeError):
            continue
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for c in log_parser.parse_any(text):
            key = (c.url, c.user, c.password)
            if key in seen:
                continue
            seen.add(key)
            creds.append(c)
    return creds


def _collect_credentials_from_dir(
    root: str,
    progress: ExtractionProgress,
) -> List[log_parser.Credential]:
    """Walk *root* and collect deduped credentials from every password file."""
    creds: List[log_parser.Credential] = []
    seen: Set = set()
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if progress.cancelled:
                return creds
            fpath = os.path.join(dirpath, fname)
            if not log_parser.is_password_file(fpath):
                continue
            try:
                if os.path.getsize(fpath) > MAX_TEXT_SCAN_BYTES:
                    continue
                with open(fpath, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue
            for c in log_parser.parse_any(text):
                key = (c.url, c.user, c.password)
                if key in seen:
                    continue
                seen.add(key)
                creds.append(c)
    return creds


def _emit_credential_outputs(
    creds: List[log_parser.Credential],
    domains: List[str],
    output_modes: FrozenSet[str],
    output_dir: str,
    progress: ExtractionProgress,
) -> List[str]:
    """Write requested credential output files into *output_dir*.

    Returns the list of files created (skipping empty ones). Bumps
    ``progress.credentials_found`` to the total rows produced across
    all enabled modes (deduped within each mode but not across modes —
    a single ``user:pass`` may show up in both ULP and combo files).
    """
    out_files: List[str] = []
    if not creds:
        return out_files

    slug = _safe_domain_label(domains)

    if ULP_MODE in output_modes:
        body = log_parser.format_ulp(creds)
        if body.strip():
            path = os.path.join(output_dir, f"{slug}_ulp.txt")
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                lines = body.count("\n")
                progress.credentials_found += lines
                out_files.append(path)
            except OSError:
                logger.exception("Failed to write ULP output {}", path)

    if COMBO_TARGETED_MODE in output_modes and domains:
        body = log_parser.format_combo_targeted(creds, domains)
        if body.strip():
            target_slug = re.sub(
                r"[^A-Za-z0-9._-]", "_",
                domains[0] if len(domains) == 1 else "targets",
            )
            path = os.path.join(
                output_dir, f"{slug}_combo_targeted_{target_slug}.txt",
            )
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                lines = body.count("\n")
                progress.credentials_found += lines
                out_files.append(path)
            except OSError:
                logger.exception("Failed to write combo-targeted output {}", path)

    if COMBO_FULL_MODE in output_modes:
        body = log_parser.format_combo_full(creds)
        if body.strip():
            path = os.path.join(output_dir, f"{slug}_combo_full.txt")
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                # Section headers + blank lines aren't credentials; count
                # only ``user:pass`` rows by re-running the formatter
                # against the deduped cred set.
                progress.credentials_found += len(set(c.combo_line for c in creds))
                out_files.append(path)
            except OSError:
                logger.exception("Failed to write combo-full output {}", path)

    return out_files


def _credential_counts(
    creds: List[log_parser.Credential],
    domains: List[str],
    output_modes: FrozenSet[str],
) -> Dict[str, int]:
    """Per-mode line-count summary used for the user-facing result text."""
    counts: Dict[str, int] = {}
    if not creds:
        return counts
    if ULP_MODE in output_modes:
        counts[ULP_MODE] = len({c.ulp_line for c in creds})
    if COMBO_TARGETED_MODE in output_modes and domains:
        body = log_parser.format_combo_targeted(creds, domains)
        counts[COMBO_TARGETED_MODE] = body.count("\n") if body.strip() else 0
    if COMBO_FULL_MODE in output_modes:
        counts[COMBO_FULL_MODE] = len({c.combo_line for c in creds})
    return counts


def _emit_cc_outputs(
    cards: List["log_parser.CreditCard"],
    domains: List[str],
    output_dir: str,
    progress: ExtractionProgress,
) -> List[str]:
    """Write the Luhn-validated CC file (``NUMBER|MM|YY|CVV`` per line).

    Bumps ``progress.credentials_found`` by the number of cards written
    so the live dashboard reflects CC results too.
    """
    out_files: List[str] = []
    if not cards:
        return out_files
    body = log_parser.format_cc(cards)
    if not body.strip():
        return out_files
    slug = _safe_domain_label(domains)
    path = os.path.join(output_dir, f"{slug}_cc.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        progress.credentials_found += len(cards)
        out_files.append(path)
    except OSError:
        logger.exception("Failed to write CC output {}", path)
    return out_files


def _collect_cc_from_dir(
    root: str,
    progress: ExtractionProgress,
) -> List["log_parser.CreditCard"]:
    """Walk *root* and collect deduped Luhn-valid CCs.

    Scans password files + dedicated CC files (CreditCards.txt etc.).
    """
    by_num: Dict[str, "log_parser.CreditCard"] = {}
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if progress.cancelled:
                return list(by_num.values())
            fpath = os.path.join(dirpath, fname)
            if not (
                log_parser.is_cc_file(fpath)
                or log_parser.is_password_file(fpath)
            ):
                continue
            try:
                if os.path.getsize(fpath) > MAX_TEXT_SCAN_BYTES:
                    continue
                with open(fpath, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue
            for card in log_parser.parse_credit_cards(text):
                existing = by_num.get(card.number)
                if existing is None:
                    by_num[card.number] = card
                    continue

                def _ccscore(c: "log_parser.CreditCard") -> int:
                    return (
                        int(bool(c.mm))
                        + int(bool(c.yy))
                        + int(bool(c.cvv))
                    )
                if _ccscore(card) > _ccscore(existing):
                    by_num[card.number] = card
    return list(by_num.values())


def _run_extraction(
    archive_path: str,
    domain: Union[str, Iterable[str]],
    progress: ExtractionProgress,
    password: Optional[str] = None,
    output_modes: FrozenSet[str] = DEFAULT_OUTPUT_MODES,
) -> ExtractionResult:
    """Blocking extraction — meant to run inside ``asyncio.to_thread``.

    Accepts either a single domain string or an iterable of domains. When
    multiple domains are configured the archive is scanned once and each
    target gets its own ``{domain}_cookies[_partN].zip`` output bundle.
    """
    import time

    start = time.monotonic()
    domains = _coerce_domains(domain)
    temp_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR))
    output_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR))

    # Initialise these at function scope so the catch-all ``except``
    # below can still salvage anything that was already produced when
    # a later phase blows up.
    output_files: List[str] = []
    per_domain_counts: Dict[str, int] = {d: 0 for d in domains}
    cred_counts: Dict[str, int] = {}

    try:
        # Fast path: plain (non-encrypted) zip → stream-decompress each
        # entry in memory and scan as we go, avoiding a full disk
        # extraction. Mirrors u.txt's extractZipStreaming pattern.
        if (
            password is None
            and _sniff_archive_type(archive_path) == "zip"
            and not _probe_encrypted_entries(archive_path)
        ):
            return _run_extraction_zip_stream(
                archive_path, domains, progress, output_dir, start,
                output_modes=output_modes,
            )

        # Phase 1: extract archive
        progress.phase = "extracting"
        progress.extract_start = time.monotonic()
        progress.current_file = ""
        logger.info(
            "Extracting archive {} into {} for domains={}",
            archive_path, temp_dir, domains,
        )
        _extract_archive(archive_path, temp_dir, progress, password=password)

        if progress.cancelled:
            # Nothing useful to send if the user cancelled mid-extraction.
            return ExtractionResult(
                success=False,
                error="Cancelled by user before any files were scanned",
                duration_seconds=time.monotonic() - start,
                partial=True,
            )

        # Phase 2: scan files. Mirrors the reference layout from
        # ``log to cookie.py``: one .txt per source file that yielded
        # matching cookies, named ``akaza_{domain}_{counter}.txt`` and
        # then bundled into one zip per target domain.
        progress.phase = "scanning"
        want_cookies = COOKIE_MODE in output_modes
        extractor = SmartCookieExtractor(domains) if want_cookies else None

        all_files: List[str] = []
        for root, _dirs, files in os.walk(temp_dir):
            for fname in files:
                all_files.append(os.path.join(root, fname))
        progress.files_total = len(all_files)

        per_source_dir = tempfile.mkdtemp(
            dir=str(config.TEMP_DIR), prefix="cookie_out_"
        )
        safe_targets: Dict[str, str] = {
            d: re.sub(r"[^A-Za-z0-9._-]", "_", d) for d in domains
        }
        file_counters: Dict[str, int] = {d: 1 for d in domains}
        for d in domains:
            os.makedirs(os.path.join(per_source_dir, d), exist_ok=True)

        for fpath in all_files:
            if progress.cancelled:
                break
            progress.current_file = os.path.basename(fpath)
            try:
                if os.path.getsize(fpath) > MAX_TEXT_SCAN_BYTES:
                    progress.files_scanned += 1
                    continue
            except OSError:
                progress.files_scanned += 1
                continue
            if not want_cookies:
                # Skip cookie scanning entirely. Credentials are
                # collected in the dedicated dir-walk below.
                progress.files_scanned += 1
                continue
            try:
                cookies = extractor.extract_from_file(fpath)
            except Exception:
                cookies = []
            if cookies:
                # Group by target domain so each gets its own per-source
                # ``akaza_*.txt`` file.
                by_target: Dict[str, List[Dict[str, str]]] = {}
                for c in cookies:
                    t = c.get("target_domain", domains[0])
                    by_target.setdefault(t, []).append(c)
                for t, group in by_target.items():
                    safe = safe_targets.get(
                        t, re.sub(r"[^A-Za-z0-9._-]", "_", t),
                    )
                    idx = file_counters.get(t, 1)
                    out_name = f"akaza_{safe}_{idx}.txt"
                    sub_dir = os.path.join(per_source_dir, t)
                    os.makedirs(sub_dir, exist_ok=True)
                    out_path = os.path.join(sub_dir, out_name)
                    try:
                        with open(out_path, "w", encoding="utf-8") as fh:
                            for c in group:
                                fh.write(
                                    f"{c['domain']}\t{c['flag']}\t{c['path']}\t"
                                    f"{c['secure']}\t{c['expiration']}\t"
                                    f"{c['name']}\t{c['value']}\n"
                                )
                                progress.cookies_found += 1
                                per_domain_counts[t] = (
                                    per_domain_counts.get(t, 0) + 1
                                )
                        file_counters[t] = idx + 1
                    except OSError:
                        logger.exception(
                            "Failed to write per-source file {}", out_path,
                        )
            progress.files_scanned += 1

        # Phase 3: bundle per-source .txt files into one zip per domain.
        progress.phase = "packaging"
        progress.current_file = ""
        if COOKIE_MODE in output_modes:
            output_files.extend(
                _bundle_all_zips(per_source_dir, output_dir, domains)
            )

        # The per-source temp dir is no longer needed once zipped.
        shutil.rmtree(per_source_dir, ignore_errors=True)

        # Optional phase 4: scan the same extracted tree for password
        # files and emit ULP / combo outputs.
        if output_modes & ALL_CREDENTIAL_MODES:
            creds = _collect_credentials_from_dir(temp_dir, progress)
            output_files.extend(
                _emit_credential_outputs(
                    creds, domains, output_modes, output_dir, progress,
                )
            )
            cred_counts = _credential_counts(creds, domains, output_modes)

        if CC_MODE in output_modes:
            cards = _collect_cc_from_dir(temp_dir, progress)
            output_files.extend(
                _emit_cc_outputs(cards, domains, output_dir, progress)
            )
            cred_counts[CC_MODE] = len(cards)

        # Drop empty output files (shouldn't happen, but belt-and-braces).
        output_files = [
            p for p in output_files
            if os.path.exists(p) and os.path.getsize(p) > 0
        ]

        duration = time.monotonic() - start

        if progress.cancelled:
            progress.phase = "cancelled"
            return ExtractionResult(
                success=bool(output_files),
                output_files=output_files,
                cookies_found=progress.cookies_found,
                files_scanned=progress.files_scanned,
                duration_seconds=duration,
                partial=True,
                error="" if output_files else "Cancelled by user (no results yet)",
                per_domain_counts=per_domain_counts,
                credentials_found=progress.credentials_found,
                credential_counts=cred_counts,
            )

        progress.phase = "done"
        return ExtractionResult(
            success=True,
            output_files=output_files,
            cookies_found=progress.cookies_found,
            files_scanned=progress.files_scanned,
            duration_seconds=duration,
            per_domain_counts=per_domain_counts,
            credentials_found=progress.credentials_found,
            credential_counts=cred_counts,
        )

    except Exception as exc:
        logger.exception("Extraction failed")
        progress.phase = "failed"
        friendly, recoverable = _friendly_extraction_error(exc)
        # Salvage anything we produced before the failure so the user
        # still gets partial output instead of a bare error message.
        salvaged = [
            p for p in output_files
            if os.path.exists(p) and os.path.getsize(p) > 0
        ]
        return ExtractionResult(
            success=bool(salvaged),
            output_files=salvaged,
            cookies_found=progress.cookies_found,
            files_scanned=progress.files_scanned,
            duration_seconds=time.monotonic() - start,
            partial=bool(salvaged),
            error=friendly,
            per_domain_counts=per_domain_counts,
            credentials_found=progress.credentials_found,
            credential_counts=cred_counts,
            recoverable=recoverable,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        # output_dir is cleaned up by the caller after sending files


async def run_extraction_async(
    archive_path: str,
    domain: Union[str, Iterable[str]],
    progress: ExtractionProgress,
    password: Optional[str] = None,
    output_modes: Optional[Iterable[str]] = None,
) -> ExtractionResult:
    """Non-blocking facade — offloads heavy work to a thread.

    *domain* may be either a single domain string or an iterable of
    domain strings; in the multi-domain case each target gets its own
    output zip.

    *output_modes* selects which outputs to produce. Defaults to
    ``{COOKIE_MODE}`` (legacy behavior). Pass a set that includes any
    of ``ULP_MODE``, ``COMBO_TARGETED_MODE``, ``COMBO_FULL_MODE`` to
    also emit credential files. Cookies and credentials can be mixed
    in one job; the same archive is scanned once for both.
    """
    modes = frozenset(output_modes) if output_modes else DEFAULT_OUTPUT_MODES
    return await asyncio.to_thread(
        _run_extraction, archive_path, domain, progress, password, modes,
    )


async def probe_encrypted_entries_async(archive_path: str) -> List[str]:
    """Async wrapper around ``_probe_encrypted_entries``."""
    return await asyncio.to_thread(_probe_encrypted_entries, archive_path)


async def guess_archive_password_async(
    archive_path: str,
    progress: Optional["ExtractionProgress"] = None,
) -> Optional[str]:
    """Async wrapper around :func:`guess_archive_password`."""
    return await asyncio.to_thread(
        guess_archive_password, archive_path, progress,
    )


async def try_archive_password_async(archive_path: str, password: str) -> bool:
    """Async wrapper around :func:`_try_archive_password`.

    Used by the chat handler when the user types a password manually —
    we test that single candidate immediately rather than walking the
    full common-password list, so feedback is fast.
    """
    return await asyncio.to_thread(_try_archive_password, archive_path, password)
