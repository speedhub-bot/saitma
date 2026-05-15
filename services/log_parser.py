"""
Stealer-log credential parser.

Parses password files dumped by infostealer malware families (RedLine,
Vidar, Raccoon, Lumma, StealC, Meta, Risepro, Atomic, etc.) into
``Credential`` tuples and renders them as ULP or combo output.

Output modes:
  * ``ulp``             — ``url:user:pass`` one line per credential.
  * ``combo_targeted``  — ``user:pass``, filtered to user-provided domains.
  * ``combo_full``      — grouped by domain, alphabetical, ``user:pass`` per line.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse


# Files that typically contain credentials inside a stealer log.
# Matched case-insensitively against the *basename*. We also key off
# parent folder names because some families put credentials in
# ``Browsers/`` / ``Soft/`` / ``Logins/``.
_PASSWORD_FILE_NAMES: Tuple[str, ...] = (
    "passwords.txt",
    "password.txt",
    "all passwords.txt",
    "allpasswords.txt",
    "all_passwords.txt",
    "passwords - copy.txt",
    "logins.txt",
    "credentials.txt",
    "_allpasswords_list.txt",
    "passwordlist.txt",
    "password_list.txt",
    "pwds.txt",
    "browser_passwords.txt",
    "browsers_passwords.txt",
    "google_chrome_default.txt",
    "edge_default.txt",
    "firefox.txt",
    "ie_passwords.txt",
)

_PASSWORD_NAME_RE = re.compile(
    r"(passwords?|logins?|credentials?|pwds?)\b",
    re.IGNORECASE,
)


def is_password_file(path: str) -> bool:
    """Return True if *path*'s basename looks like a stealer-log password dump."""
    base = os.path.basename(path).lower()
    if base in _PASSWORD_FILE_NAMES:
        return True
    if not base.endswith((".txt", ".log")):
        return False
    return bool(_PASSWORD_NAME_RE.search(base))


# ── Credential dataclass ────────────────────────────────────

@dataclass(frozen=True)
class Credential:
    """One ``(url, user, password)`` triple parsed from a stealer log."""
    url: str
    user: str
    password: str

    @property
    def domain(self) -> str:
        """Effective registrable host for grouping/filtering."""
        return _extract_host(self.url)

    @property
    def ulp_line(self) -> str:
        """`url:user:pass` formatted line."""
        return f"{self.url}:{self.user}:{self.password}"

    @property
    def combo_line(self) -> str:
        """`user:pass` formatted line."""
        return f"{self.user}:{self.password}"


# ── Host extraction ─────────────────────────────────────────

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _extract_host(url: str) -> str:
    """Return the lowercase host portion of *url*, sans port and leading ``www.``.

    Tolerates URLs without a scheme (very common in stealer dumps,
    e.g. ``example.com/login`` or ``android://...``).
    """
    if not url:
        return ""
    url = url.strip()
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _normalize_target(domain: str) -> str:
    """Normalize a user-supplied target domain for matching."""
    domain = (domain or "").strip().lower().lstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _matches_target(host: str, targets: Sequence[str]) -> bool:
    """Return True if *host* matches any of *targets* (exact or subdomain)."""
    if not host:
        return False
    for t in targets:
        if not t:
            continue
        if host == t or host.endswith("." + t):
            return True
    return False


# ── Parsing ─────────────────────────────────────────────────

# Stealer logs use many field labels. We normalize them to the canonical
# trio: url / user / pass. Each pattern matches a single line:
#   "<label>: <value>"
# with whitespace and a colon (or equals) separator.
_FIELD_RE = re.compile(
    r"""
    ^                                    # start of line
    \s*                                  # leading whitespace
    (?P<key>
        url | host | hostname | site | website | link | application |
        soft | software |                # some logs use 'SOFT:' as URL
        user(?:name)? | login | email | account |
        pass(?:word)? | pwd
    )
    \s* [:=] \s*                         # separator
    (?P<val>.*?)                         # captured value (non-greedy)
    \s* $                                # trailing whitespace
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Map a normalized label to its slot in the (url, user, pass) tuple.
_FIELD_BUCKET: Dict[str, str] = {
    "url": "url", "host": "url", "hostname": "url", "site": "url",
    "website": "url", "link": "url", "application": "url",
    "soft": "url", "software": "url",
    "user": "user", "username": "user", "login": "user",
    "email": "user", "account": "user",
    "pass": "pass", "password": "pass", "pwd": "pass",
}

# Lines we should treat as record separators (in addition to blank lines).
_SEPARATOR_RE = re.compile(
    r"^\s*(?:=+|-+|\*+|#+|_+|~+|=====+|\+\+\++)\s*$"
)


def parse_passwords(text: str) -> List[Credential]:
    """Parse *text* (one stealer-log password file) into ``Credential`` rows.

    Robust to:
      * ``URL: ... / Username: ... / Password: ...`` (RedLine/Vidar)
      * ``SOFT: ... / HOST: ... / LOGIN: ... / PASSWORD: ...`` (Raccoon-style)
      * ``URL = ... / USER = ... / PASS = ...`` (equals separator)
      * Records separated by blank lines, by horizontal rules, or by
        the next ``URL:`` line.

    Skips entries with no password (impossible to use) and dedupes
    by ``(url, user, pass)``.
    """
    creds: List[Credential] = []
    seen: Set[Tuple[str, str, str]] = set()
    cur: Dict[str, str] = {}

    def flush() -> None:
        u = cur.get("url", "").strip()
        usr = cur.get("user", "").strip()
        pwd = cur.get("pass", "").strip()
        cur.clear()
        # Need at least user OR url, plus a non-empty password.
        if not pwd:
            return
        if not usr and not u:
            return
        key = (u, usr, pwd)
        if key in seen:
            return
        seen.add(key)
        creds.append(Credential(url=u, user=usr, password=pwd))

    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            flush()
            continue
        if _SEPARATOR_RE.match(line):
            flush()
            continue
        m = _FIELD_RE.match(line)
        if not m:
            continue
        key = m.group("key").lower()
        bucket = _FIELD_BUCKET.get(key)
        if bucket is None:
            continue
        val = m.group("val")
        # Starting a fresh record: if we already have a complete record
        # in flight (url + user + pass slot all filled), flush before
        # overwriting.
        if bucket == "url" and "url" in cur:
            flush()
        if bucket == "user" and "user" in cur and "pass" in cur:
            flush()
        cur[bucket] = val

    flush()
    return creds


# ── Flexible single-line ULP parser ─────────────────────────

# Matches the typical "URL:USER:PASS" or "URL USER PASS" shape that
# stealer-log aggregators (and some browser dumps) emit. We split on
# whitespace, ``:``, ``|``, ``;`` or ``,`` and look for the column that
# contains an ``@`` (likely email/user). Everything before that column
# becomes the URL, everything after becomes the password. Mirrors the
# ``parse_ulp_file`` flow in the user's reference ``ulp_bot.py``.
_DELIM_RE = re.compile(r"[\s|;,]+")  # do NOT split on ':' — many URLs contain ':'

# What we accept as an "email-like" user column. Has to look like a
# real email (something@something.something or something@something)
# to avoid false positives from prose lines that happen to contain ``@``.
_EMAIL_LIKE_RE = re.compile(
    r"^[^@\s:]{1,128}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$"
)

# Bare URL (with optional port) at the START of a line, no scheme.
# Stealer dumps frequently strip the scheme: ``claude.ai:user:pass``.
_BARE_HOST_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)"
    r"(?::\d{1,5})?"
    r"(/[^\s]*)?"
    r"$"
)


def _split_ulp_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Return ``(url, user, pass)`` from a single ULP-shaped line, or None.

    Handles, in order of preference:
      * ``https?://URL:USER:PASS`` (canonical ULP — passwords may
        themselves contain ``:``)
      * ``URL EMAIL PASS`` with whitespace / pipe / semicolon delim
      * ``android://bundle.id:USER:PASS`` (mobile stealer dumps)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Cookies use tabs — don't try to interpret those as ULP.
    if "\t" in line:
        return None

    # Canonical ``scheme://URL:USER:PASS``. URL may itself contain ``:``
    # (port number). Walk colon positions and prefer the one whose
    # immediate next field is an email-like user, falling back to "any
    # plausible user/pass split" if no email shows up.
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)(.+)$", line)
    if m:
        scheme, rest = m.group(1), m.group(2)
        best: Optional[Tuple[str, str, str]] = None
        for sep in re.finditer(r":", rest):
            tail = rest[sep.end():]
            up_idx = tail.find(":")
            if up_idx <= 0:
                continue
            user = tail[:up_idx].strip()
            pwd = tail[up_idx + 1:].strip()
            if not user or not pwd or len(pwd) < 2:
                continue
            if pwd.startswith(("http://", "https://", "android://", "ftp://")):
                continue
            url = scheme + rest[:sep.start()]
            cand = (url.strip(), user, pwd)
            # Strong match: user looks like a real email → take it now.
            if _EMAIL_LIKE_RE.match(user):
                return cand
            # Otherwise remember the first plausible split and keep
            # scanning in case an email-shaped user shows up later.
            if best is None:
                best = cand
        if best is not None:
            return best
        # Scheme matched but no ``:user:pass`` tail. Fall through to the
        # generic delimiter branch (handles ``https://x EMAIL PASS``).

    # Generic delimited shape (no scheme): split on whitespace / pipe /
    # comma / semicolon, then locate an email-like column. Used for
    # ``URL EMAIL PASS`` and ``URL | EMAIL | PASS`` variants.
    parts = [p for p in _DELIM_RE.split(line) if p]
    if len(parts) >= 3:
        email_idx = -1
        for i, p in enumerate(parts):
            if _EMAIL_LIKE_RE.match(p):
                email_idx = i
                break
        if 0 < email_idx < len(parts) - 1:
            url = " ".join(parts[:email_idx]).rstrip(":")
            user = parts[email_idx]
            pwd = " ".join(parts[email_idx + 1:])
            if url and user and pwd and len(pwd) >= 2:
                return (url, user, pwd)

    # Bare-host single-line ``host[:port][/path]:USER:PASS`` (no scheme).
    # Only accept if the first colon is followed by a valid user + at
    # least one more colon (the user/pass separator).
    first_colon = line.find(":")
    if first_colon > 0:
        host_part = line[:first_colon]
        tail = line[first_colon + 1:]
        if _BARE_HOST_RE.match(host_part):
            up_idx = tail.find(":")
            if up_idx > 0:
                user = tail[:up_idx].strip()
                pwd = tail[up_idx + 1:].strip()
                if user and pwd and len(pwd) >= 2:
                    return ("http://" + host_part, user, pwd)

    return None


def parse_ulp_lines(text: str) -> List[Credential]:
    """Parse text that's already in single-line ULP shape.

    Use this for aggregator dumps (``Combo.txt``, ``All_ULP.txt``,
    pre-flattened breach lists). For raw stealer logs use
    :func:`parse_passwords` instead — the multi-line state machine
    handles ``URL: / Username: / Password:`` blocks.
    """
    out: List[Credential] = []
    seen: Set[Tuple[str, str, str]] = set()
    for raw in text.splitlines():
        triple = _split_ulp_line(raw)
        if not triple:
            continue
        url, user, pwd = triple
        if not pwd or len(pwd) < 2:
            continue
        key = (url, user, pwd)
        if key in seen:
            continue
        seen.add(key)
        out.append(Credential(url=url, user=user, password=pwd))
    return out


def parse_any(text: str) -> List[Credential]:
    """Try both the labeled and ULP-line parsers; merge + dedupe.

    Files in the wild often mix both shapes (a header block at top,
    raw ULP lines below). Running both pickups everything.
    """
    labeled = parse_passwords(text)
    ulp = parse_ulp_lines(text)
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Credential] = []
    for c in labeled + ulp:
        key = (c.url, c.user, c.password)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# ── Output formatters ───────────────────────────────────────

def format_ulp(creds: Iterable[Credential]) -> str:
    """`url:user:pass` lines, deduped, one per credential."""
    seen: Set[str] = set()
    out: List[str] = []
    for c in creds:
        line = c.ulp_line
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def format_combo_targeted(
    creds: Iterable[Credential],
    targets: Sequence[str],
) -> str:
    """`user:pass` lines for credentials whose host matches *targets*.

    Each target may be a bare domain (``claude.ai``) or with subdomain
    (``api.claude.ai``); matching is exact-or-suffix.
    """
    norm = [_normalize_target(t) for t in targets if t]
    norm = [t for t in norm if t]
    seen: Set[str] = set()
    out: List[str] = []
    for c in creds:
        if not _matches_target(c.domain, norm):
            continue
        line = c.combo_line
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def format_combo_full(creds: Iterable[Credential]) -> str:
    """Group credentials by host, alphabetical, ``[host]`` header per group.

    Output shape::

        [claude.ai]
        user1:pass1
        user2:pass2

        [netflix.com]
        someone@x.com:hunter2

    Credentials with no host (URL was unparseable) land under
    ``[unknown]`` at the end.
    """
    groups: Dict[str, List[str]] = {}
    per_group_seen: Dict[str, Set[str]] = {}
    for c in creds:
        host = c.domain or "unknown"
        line = c.combo_line
        seen = per_group_seen.setdefault(host, set())
        if line in seen:
            continue
        seen.add(line)
        groups.setdefault(host, []).append(line)

    if not groups:
        return ""

    # Alphabetical, with "unknown" pinned to the end.
    keys = sorted(k for k in groups if k != "unknown")
    if "unknown" in groups:
        keys.append("unknown")

    chunks: List[str] = []
    for k in keys:
        chunks.append(f"[{k}]")
        chunks.extend(groups[k])
        chunks.append("")  # blank line between groups
    return "\n".join(chunks).rstrip() + "\n"


# ── Convenience: scan a directory tree ──────────────────────

def collect_credentials_from_dir(
    root: str,
    max_bytes_per_file: Optional[int] = None,
) -> List[Credential]:
    """Walk *root*, parse every password-looking file, return all creds.

    Used as a fallback when the streaming-zip path isn't available
    (encrypted archives that had to be expanded to disk first).
    """
    out: List[Credential] = []
    seen: Set[Tuple[str, str, str]] = set()
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            if not is_password_file(fpath):
                continue
            try:
                if max_bytes_per_file is not None:
                    if os.path.getsize(fpath) > max_bytes_per_file:
                        continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for c in parse_any(text):
                key = (c.url, c.user, c.password)
                if key in seen:
                    continue
                seen.add(key)
                out.append(c)
    return out
