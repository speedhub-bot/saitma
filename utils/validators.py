"""
Input validation utilities.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple, Union

# ── Supported archive containers ─────────────────────────────
# The extraction pipeline routes by *magic bytes* (see
# services.extractor._sniff_archive_type) so the MIME-type column is
# advisory only — the upload validator below matches on extension.
SUPPORTED_ARCHIVE_EXTENSIONS: Dict[str, List[str]] = {
    # ZIP family
    ".zip":      ["application/zip", "application/x-zip-compressed"],
    ".zipx":     ["application/zip"],
    ".jar":      ["application/java-archive"],
    ".war":      ["application/java-archive"],
    ".ear":      ["application/java-archive"],
    ".apk":      ["application/vnd.android.package-archive"],
    ".ipa":      ["application/octet-stream"],
    ".xpi":      ["application/x-xpinstall"],
    # RAR
    ".rar":      ["application/x-rar-compressed", "application/vnd.rar"],
    # 7z
    ".7z":       ["application/x-7z-compressed"],
    # TAR (uncompressed + every popular compressor)
    ".tar":      ["application/x-tar"],
    ".tar.gz":   ["application/gzip", "application/x-gzip", "application/x-tar"],
    ".tgz":      ["application/gzip"],
    ".tar.bz2":  ["application/x-bzip2"],
    ".tbz":      ["application/x-bzip2"],
    ".tbz2":     ["application/x-bzip2"],
    ".tar.xz":   ["application/x-xz"],
    ".txz":      ["application/x-xz"],
    ".tar.zst":  ["application/zstd"],
    ".tzst":     ["application/zstd"],
    ".tar.lz":   ["application/x-lzip"],
    ".tlz":      ["application/x-lzip"],
    ".tar.lzma": ["application/x-lzma"],
    ".tar.lz4":  ["application/x-lz4"],
    # Single-file compression
    ".gz":       ["application/gzip"],
    ".bz2":      ["application/x-bzip2"],
    ".xz":       ["application/x-xz"],
    ".lz":       ["application/x-lzip"],
    ".lzma":     ["application/x-lzma"],
    ".lz4":      ["application/x-lz4"],
    ".zst":      ["application/zstd"],
    ".zstd":     ["application/zstd"],
    ".z":        ["application/x-compress"],
    # Other archive containers
    ".cab":      ["application/vnd.ms-cab-compressed"],
    ".iso":      ["application/x-iso9660-image"],
    ".arj":      ["application/x-arj"],
    ".ace":      ["application/x-ace-compressed"],
    ".cpio":     ["application/x-cpio"],
    ".ar":       ["application/x-archive"],
    ".deb":      ["application/vnd.debian.binary-package"],
    ".rpm":      ["application/x-rpm"],
    ".dmg":      ["application/x-apple-diskimage"],
}

# ── Plain text / log files ───────────────────────────────────
# When the user uploads one of these directly (instead of an archive)
# the extraction pipeline treats it as a single-file "archive" and
# scans it in place. The same patterns are detected inside extracted
# archives as well.
SUPPORTED_TEXT_EXTENSIONS: Dict[str, List[str]] = {
    ".txt":        ["text/plain"],
    ".log":        ["text/plain"],
    ".logs":       ["text/plain"],
    ".csv":        ["text/csv"],
    ".tsv":        ["text/tab-separated-values"],
    ".json":       ["application/json"],
    ".jsonl":      ["application/x-ndjson"],
    ".ndjson":     ["application/x-ndjson"],
    ".xml":        ["application/xml", "text/xml"],
    ".html":       ["text/html"],
    ".htm":        ["text/html"],
    ".yaml":       ["application/x-yaml"],
    ".yml":        ["application/x-yaml"],
    ".ini":        ["text/plain"],
    ".conf":       ["text/plain"],
    ".cfg":        ["text/plain"],
    ".toml":       ["application/toml"],
    ".md":         ["text/markdown"],
    ".markdown":   ["text/markdown"],
    ".nfo":        ["text/plain"],
    ".lst":        ["text/plain"],
    ".list":       ["text/plain"],
    ".dat":        ["application/octet-stream"],
    ".out":        ["text/plain"],
    ".dump":       ["text/plain"],
    ".properties": ["text/plain"],
}

# Combined view — what the upload validator accepts.
SUPPORTED_EXTENSIONS: Dict[str, List[str]] = {
    **SUPPORTED_ARCHIVE_EXTENSIONS,
    **SUPPORTED_TEXT_EXTENSIONS,
}

# Split-archive part suffixes: ``foo.7z.001`` / ``foo.zip.002`` /
# ``foo.r01`` / ``foo.z01`` / ``foo.part1.rar``. The extraction
# pipeline reassembles parts when it sees the first volume.
_SPLIT_PART_RE = re.compile(
    r"\.(?:\d{3,4}|r\d{2}|z\d{2}|part\d{1,3}\.(?:rar|zip|7z))$",
    re.IGNORECASE,
)


def is_plain_text_input(file_name: str | None) -> bool:
    """Return True iff *file_name* is one of the plain-text/log shapes
    the bot accepts as a "single-file archive" (no extraction needed).
    """
    if not file_name:
        return False
    lower = file_name.lower()
    return any(lower.endswith(ext) for ext in SUPPORTED_TEXT_EXTENSIONS)


def is_split_archive_part(file_name: str | None) -> bool:
    """Return True iff *file_name* looks like a multi-volume archive part."""
    if not file_name:
        return False
    return bool(_SPLIT_PART_RE.search(file_name.lower()))


_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Splits user input into individual domain tokens. We accept commas,
# semicolons, pipes, and any whitespace (incl. newlines) as separators.
_DOMAIN_SPLIT_RE = re.compile(r"[,\s;|]+")


def validate_domain(raw: str) -> Tuple[bool, str]:
    """
    Validate and normalise a domain string.

    Returns:
        (is_valid, cleaned_domain_or_error)
    """
    domain = raw.strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    if not domain or "." not in domain:
        return False, "Domain must contain at least one dot (e.g. spotify.com)"
    if not _DOMAIN_RE.match(domain):
        return False, f"Invalid domain format: {domain}"
    return True, domain


def validate_domains(
    raw: str,
    max_count: int = 10,
) -> Tuple[bool, Union[List[str], str]]:
    """
    Validate and normalise a list of domains supplied as a single string.

    Accepts any combination of commas, semicolons, pipes, spaces and
    newlines as separators. Each token is run through :func:`validate_domain`,
    duplicates are removed (preserving the user's original ordering), and the
    final list is capped at *max_count* entries.

    Returns:
        (True,  list_of_cleaned_domains)  on success
        (False, error_message)            on the first validation failure
    """
    if not raw or not raw.strip():
        return False, "Please send at least one domain (e.g. spotify.com)"

    tokens = [t for t in _DOMAIN_SPLIT_RE.split(raw.strip()) if t]
    if not tokens:
        return False, "Please send at least one domain (e.g. spotify.com)"

    if len(tokens) > max_count:
        return False, (
            f"Too many domains ({len(tokens)}). "
            f"Maximum allowed per extraction: {max_count}."
        )

    cleaned: List[str] = []
    seen: set[str] = set()
    for tok in tokens:
        ok, value = validate_domain(tok)
        if not ok:
            return False, value
        if value not in seen:
            seen.add(value)
            cleaned.append(value)

    return True, cleaned


# Match longest extensions first so ``foo.tar.gz`` resolves to
# ``.tar.gz`` rather than the shorter ``.gz``.
_SORTED_EXTENSIONS: List[str] = sorted(
    SUPPORTED_EXTENSIONS, key=len, reverse=True,
)


def validate_archive(
    file_name: str | None,
    mime_type: str | None,
) -> Tuple[bool, str]:
    """
    Check whether a file looks like a supported archive, plain log, or
    multi-volume archive part.

    Returns:
        (is_valid, cleaned_extension_or_error)
    """
    if not file_name:
        return False, "No filename provided"
    lower = file_name.lower()
    for ext in _SORTED_EXTENSIONS:
        if lower.endswith(ext):
            return True, ext
    if is_split_archive_part(lower):
        return True, ".split"
    return False, (
        "Unsupported file type. Upload an archive "
        "(.zip .rar .7z .tar.gz .tar.xz .zst .cab .iso .deb .rpm ...), "
        "a plain log (.txt .log .csv .json .xml .html ...), "
        "or a multi-volume part (.001 .002 .r01 .partN.rar)."
    )
