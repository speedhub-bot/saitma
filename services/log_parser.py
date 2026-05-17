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
from datetime import datetime, timezone
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


# ── Credit card extraction (Luhn-validated) ─────────────────

# We accept 13-19 digit sequences. The Luhn check then drops anything
# that isn't a real card number. The two regexes are run in order:
#   * ``_CC_RUN_RE``    — any 13-19 digit run (allowing spaces/dashes
#                          as visual separators); MOST stealer logs
#                          dump CCs like ``4111 1111 1111 1111`` or
#                          ``4111-1111-1111-1111``.
#   * ``_CC_FIELD_RE``  — labeled blocks (``Number: …``, ``Card #: …``).
#                          Used to pair a CC with its exp date / CVV
#                          when they sit on adjacent lines.
_CC_RUN_RE = re.compile(
    r"(?<![0-9])"
    r"(\d(?:[ \-]?\d){12,18})"
    r"(?![0-9])"
)

# Expiry-date patterns we'll try in order. Each MUST capture two
# named groups, ``mm`` and ``yy``. Year may be 2 or 4 digits.
_CC_EXP_PATTERNS: Tuple[re.Pattern, ...] = (
    # MM/YY or MM/YYYY or MM-YY or MM-YYYY, optional spaces.
    re.compile(
        r"(?<![0-9])(?P<mm>0[1-9]|1[0-2])\s*[/\-\.]\s*"
        r"(?P<yy>20\d{2}|\d{2})(?![0-9])"
    ),
    # MM YY (whitespace-only separator) — only after a clear "exp"
    # context, to avoid grabbing random adjacent numbers. Guarded
    # at the caller by `_find_exp_near`.
    re.compile(
        r"(?<![0-9])(?P<mm>0[1-9]|1[0-2])\s+(?P<yy>20\d{2}|\d{2})(?![0-9])"
    ),
)

# CVV / CVV2 / CVC / Security code (3 or 4 digits).
_CC_CVV_RE = re.compile(
    r"(?i)(?:cvv2?|cvc2?|c\.?v\.?v|security\s*code|cv?n)\s*[:=#]?\s*"
    r"(?<![0-9])(?P<cvv>\d{3,4})(?![0-9])"
)

# Labeled blocks (``Number:``, ``Card Number:``, ``CC:``, etc.).
# When we find one we'll look ahead for an Exp / CVV line in the
# same record (delimited by a blank line or the next label).
_CC_NUMBER_LABEL_RE = re.compile(
    r"(?im)^\s*"
    r"(?:card(?:\s*(?:number|num|no|#))?|cc(?:\s*num(?:ber)?)?|"
    r"number|num|pan)"
    r"\s*[:=#]\s*"
    r"(?P<num>[\d \-]{13,32})"
    r"\s*$"
)

# Expiry / CVV labels we look for in the labeled block. We grab the
# whole field including any leading punctuation so the exp regex
# above can pick out mm / yy.
_CC_EXP_LABEL_RE = re.compile(
    r"(?im)^\s*(?:exp(?:iry|ire|iration)?|expiry\s*date|valid|expdate)"
    r"\s*[:=#]\s*(?P<v>.+?)\s*$"
)
_CC_CVV_LABEL_RE = re.compile(
    r"(?im)^\s*(?:cvv2?|cvc2?|c\.?v\.?v|cvn|security\s*code|"
    r"card\s*verification)"
    r"\s*[:=#]\s*(?P<v>\d{3,4})\s*$"
)


@dataclass(frozen=True)
class CreditCard:
    """One credit-card record parsed from a stealer log."""
    number: str   # digits only, no spaces/dashes
    mm: str       # zero-padded 2-char month, or "" if unknown
    yy: str       # 2-char year (last 2 digits), or "" if unknown
    cvv: str      # 3-4 digits, or "" if unknown

    @property
    def out_line(self) -> str:
        """``NUMBER|MM|YY|CVV`` formatted pipe line."""
        return f"{self.number}|{self.mm}|{self.yy}|{self.cvv}"


def _luhn_ok(digits: str) -> bool:
    """Return True iff *digits* (a stripped CC string) passes Luhn."""
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    if not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        n = ord(ch) - 48
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _is_known_iin(digits: str) -> bool:
    """Quick sanity check that *digits* starts with a known card-brand IIN.

    Used as a second filter after Luhn — most random 16-digit numbers
    that pass Luhn don't start with a real BIN range. Covers Visa,
    Mastercard (incl. 2-series), Amex, Discover, Diners, JCB, UnionPay.
    """
    n = digits
    L = len(digits)
    # Visa: starts with 4, 13/16/19 long.
    if n[0] == "4" and L in (13, 16, 19):
        return True
    # Mastercard: 51-55, 16 long; 2221-2720, 16 long.
    if L == 16:
        if n.startswith(("51", "52", "53", "54", "55")):
            return True
        if n.startswith("2") and 2221 <= int(n[:4]) <= 2720:
            return True
    # Amex: 34 or 37, 15 long.
    if L == 15 and n.startswith(("34", "37")):
        return True
    # Discover: 6011, 644-649, 65, 16 or 19 long.
    if L in (16, 19):
        if n.startswith("6011") or n.startswith("65"):
            return True
        if n.startswith("64") and n[2] in "456789":
            return True
    # Diners Club: 300-305, 36, 38, 39, 14 long (16/19 modern).
    if L in (14, 16, 19):
        if n.startswith("36") or n.startswith("38") or n.startswith("39"):
            return True
        if n.startswith("30") and n[2] in "012345":
            return True
    # JCB: 3528-3589, 16-19 long.
    if 16 <= L <= 19 and n.startswith("35"):
        if 3528 <= int(n[:4]) <= 3589:
            return True
    # UnionPay: 62, 16-19 long.
    if 16 <= L <= 19 and n.startswith("62"):
        return True
    return False


# ── Junk / sanity filters ───────────────────────────────────
#
# Even after Luhn + IIN, a non-trivial number of false-positive CC
# numbers slip through because:
#   * test/dev card numbers ("4242 4242 4242 4242") are placeholders;
#   * repeated-digit and counting sequences happen to pass Luhn at
#     some lengths;
#   * timestamps and order-IDs occasionally satisfy Luhn (the
#     16-digit space has a 10% Luhn hit rate by definition).
#
# These helpers reject the obvious cases.

# Visa, Mastercard, and Stripe-published test card prefixes. These are
# the ones every payments doc embeds; they pollute every CC export.
_TEST_CARD_NUMBERS: Set[str] = {
    # Visa
    "4111111111111111", "4012888888881881", "4222222222222",
    "4000000000000002", "4000000000000010", "4000000000000028",
    "4000000000000036", "4000000000000044", "4000000000000051",
    "4000000000000069", "4000000000000077", "4000000000000085",
    "4000000000000093", "4000000000000119", "4000000000000127",
    "4000000000000135", "4000000000000143", "4000000000000150",
    "4000000000000168", "4000000000000176", "4000000000000184",
    "4000000000000192", "4000000000000259", "4000000000000341",
    "4242424242424242", "4012000033330026",
    # Mastercard
    "5555555555554444", "5105105105105100", "5200828282828210",
    "2223003122003222", "2223000048400011",
    # Amex
    "378282246310005", "371449635398431",
    # Discover
    "6011111111111117", "6011000990139424",
    # Diners / JCB / UnionPay
    "30569309025904", "38520000023237", "3530111333300000",
    "3566002020360505", "6200000000000005",
}


def _is_junk_digits(digits: str) -> bool:
    """Reject obvious non-card patterns that nonetheless pass Luhn.

    Catches:
      * known published test/dev card numbers (Stripe / Adyen / etc.);
      * sequences of a single repeated digit (``4444444444444444``);
      * strictly increasing/decreasing single-step runs
        (``1234567890123452``);
      * runs with fewer than 4 unique digits (almost certainly an
        ID or marker, not a real PAN).
    """
    if not digits:
        return True
    if digits in _TEST_CARD_NUMBERS:
        return True
    # All-same-digit (``4444...``).
    if len(set(digits)) == 1:
        return True
    # Strictly ascending / descending runs.
    diffs = {int(digits[i + 1]) - int(digits[i]) for i in range(len(digits) - 1)}
    if diffs in ({1}, {-1}):
        return True
    # Very low entropy: fewer than 4 distinct digits across 13-19 chars
    # is overwhelmingly an ID / phone number / serial.
    if len(set(digits)) < 4:
        return True
    return False


def _exp_looks_plausible(mm: str, yy: str) -> bool:
    """Return True iff a parsed ``(mm, yy)`` expiry looks like a real card.

    * Month must be 01-12.
    * Year must be within ``current_year - 1 .. current_year + 15``
      (we tolerate one year of staleness so freshly-expired cards
      still appear; future cards are capped at ~15y).

    A blank expiry is treated as "no info, can't reject on this basis".
    """
    if not mm or not yy:
        return True
    if not (mm.isdigit() and yy.isdigit()):
        return False
    m = int(mm)
    if m < 1 or m > 12:
        return False
    y = int(yy)
    if 0 <= y <= 99:
        full = 2000 + y
    else:
        full = y
    current_year = datetime.now(timezone.utc).year
    return (current_year - 1) <= full <= (current_year + 15)


_CVV_NUMERIC_RE = re.compile(r"^\d{3,4}$")


def _cvv_looks_plausible(cvv: str) -> bool:
    """Reject obviously-junk CVVs (000, 0000) — keep everything else."""
    if not cvv:
        return True
    if not _CVV_NUMERIC_RE.match(cvv):
        return False
    if cvv == "0" * len(cvv):
        return False
    return True


# Words that, if found within ~400 chars of a digit-run, strongly
# suggest the run is intended to be a credit card. Used as an extra
# disambiguator in strict mode so order-IDs/timestamps stop sneaking
# through.
_CC_KEYWORD_RE = re.compile(
    r"(?i)\b(?:"
    r"card(?:\s*(?:number|num|no|holder))?"
    r"|credit|debit"
    r"|visa|master\s*card|mastercard|amex|american\s*express"
    r"|discover|diners|jcb|union\s*pay"
    r"|maestro|rupay"
    r"|pan|cardholder"
    r"|exp(?:iry|ire|iration)?|expdate|valid\s*thru"
    r"|cvv2?|cvc2?|cvn|security\s*code"
    r"|fullz|billing|payment"
    r")\b"
)


def _has_cc_keyword_near(text: str, start: int, end: int) -> bool:
    """Return True iff a CC-related keyword appears in a tight window
    around ``[start, end]`` (see :data:`_KEYWORD_WINDOW`).

    The window is intentionally small (~80 chars, ~1-2 lines) so a
    completely unrelated mention of ``card`` or ``cvv`` 5+ lines away
    doesn't validate an otherwise-random digit run.
    """
    lo = max(0, start - _KEYWORD_WINDOW)
    hi = min(len(text), end + _KEYWORD_WINDOW)
    return bool(_CC_KEYWORD_RE.search(text, lo, hi))


def _normalize_year(yy: str) -> str:
    """Return 2-digit year. ``2025`` → ``25``, ``25`` → ``25``."""
    yy = yy.strip()
    if len(yy) == 4 and yy.isdigit():
        return yy[2:]
    if len(yy) == 2 and yy.isdigit():
        return yy
    return ""


_EXP_WINDOW = 120
_CVV_WINDOW = 120
_KEYWORD_WINDOW = 80


def _find_exp_near(text: str, start: int, end: int) -> Tuple[str, str]:
    """Return ``(mm, yy)`` for the closest expiry-date match around
    ``[start, end]`` in *text*. Empty strings when none.

    Searches a small window AFTER the CC (most common: ``CARD\\nEXP\\nCVV``)
    then a small window BEFORE. The window is intentionally narrow so
    an expiry that belongs to a *different* card a few lines away
    doesn't get mis-attributed.
    """
    after = text[end:end + _EXP_WINDOW]
    for pat in _CC_EXP_PATTERNS:
        m = pat.search(after)
        if m:
            return m.group("mm"), _normalize_year(m.group("yy"))
    before = text[max(0, start - _EXP_WINDOW):start]
    for pat in _CC_EXP_PATTERNS:
        m = pat.search(before)
        if m:
            return m.group("mm"), _normalize_year(m.group("yy"))
    return "", ""


def _find_cvv_near(text: str, start: int, end: int) -> str:
    """Return CVV digits near the CC, empty if none in the window."""
    after = text[end:end + _CVV_WINDOW]
    m = _CC_CVV_RE.search(after)
    if m:
        return m.group("cvv")
    before = text[max(0, start - _CVV_WINDOW):start]
    m = _CC_CVV_RE.search(before)
    if m:
        return m.group("cvv")
    return ""


def _card_score(c: "CreditCard") -> int:
    return int(bool(c.mm)) + int(bool(c.yy)) + int(bool(c.cvv))


# Already-flattened combo shape produced by stealer aggregators:
#   ``NUMBER|MM|YY|CVV``  (also accepts ``,`` / ``;`` / `\t` / `:` as
#   field separators). The number itself may contain spaces or
#   dashes as visual separators (``4111 1111 1111 1111``).
_CC_COMBO_RE = re.compile(
    r"(?<![0-9])"
    r"(?P<num>\d(?:[ \-]?\d){12,18})"
    r"\s*[|,:;\t]\s*"
    r"(?P<mm>0?[1-9]|1[0-2])"
    r"\s*[|,:;\t /\-]\s*"
    r"(?P<yy>20\d{2}|\d{2})"
    r"\s*[|,:;\t /\-]\s*"
    r"(?P<cvv>\d{3,4})"
    r"(?![0-9])"
)


def parse_credit_cards(
    text: str,
    *,
    strict: bool = True,
) -> List[CreditCard]:
    """Extract all Luhn-valid credit cards (with nearby MM/YY/CVV) from *text*.

    Strategy:
      1. Run the pipe-combo regex first — stealer aggregators dump
         cards in ``NUMBER|MM|YY|CVV`` shape and grabbing the whole
         tuple in one pass is more accurate than searching a window.
      2. Then find every 13-19 digit run elsewhere in the text.
         Strip separators, run Luhn + IIN sanity check, search a
         +/-200-char window for exp / CVV labels.
      3. Dedupe by CC number — keep the most-complete record per
         number (more filled fields wins).

    Every candidate (in both passes) must clear:
      * :func:`_luhn_ok` — Luhn check, 13-19 digits;
      * :func:`_is_known_iin` — starts with a real card-brand IIN;
      * :func:`_is_junk_digits` — not a test card, not a repeated /
        counting / low-entropy sequence;
      * :func:`_exp_looks_plausible` — month 01-12 and year within
        ``current_year - 1 .. current_year + 15`` (only when an
        expiry is attached);
      * :func:`_cvv_looks_plausible` — drops all-zero CVVs.

    When ``strict`` is True (the default), a 13-19 digit run found
    OUTSIDE the pipe-combo form must have BOTH:
      * a CC-related keyword (``card``, ``cvv``, ``exp``, ``visa``,
        ``fullz``, ...) within ±:data:`_KEYWORD_WINDOW` chars, AND
      * at least one of MM/YY/CVV resolvable from the ±:data:`_EXP_WINDOW`
        / ±:data:`_CVV_WINDOW`-char windows.
    This kills the long tail of false positives where timestamps /
    order-IDs happen to pass Luhn (e.g. ``2303200123032001``).
    Pipe-combo matches are exempt because the shape itself proves
    intent.
    """
    by_num: Dict[str, CreditCard] = {}

    def _store(card: CreditCard) -> None:
        existing = by_num.get(card.number)
        if existing is None or _card_score(card) > _card_score(existing):
            by_num[card.number] = card

    # Pass 1: NUMBER|MM|YY|CVV style combo lines. Always trusted —
    # the combo shape itself proves the number is a CC, not a
    # timestamp/ID.
    for m in _CC_COMBO_RE.finditer(text):
        digits = re.sub(r"[ \-]", "", m.group("num"))
        if not _luhn_ok(digits):
            continue
        if not _is_known_iin(digits):
            continue
        if _is_junk_digits(digits):
            continue
        mm = m.group("mm").zfill(2)
        yy = _normalize_year(m.group("yy"))
        cvv = m.group("cvv")
        if not _exp_looks_plausible(mm, yy):
            continue
        if not _cvv_looks_plausible(cvv):
            continue
        _store(CreditCard(number=digits, mm=mm, yy=yy, cvv=cvv))

    # Pass 2: any 13-19 digit run, with metadata pulled from a
    # surrounding window. Catches "labeled" shapes (Number: ... /
    # Exp: ... / CVV: ...) and CCs sprinkled in passwords files.
    for m in _CC_RUN_RE.finditer(text):
        raw = m.group(1)
        digits = re.sub(r"[ \-]", "", raw)
        if not _luhn_ok(digits):
            continue
        if not _is_known_iin(digits):
            continue
        if _is_junk_digits(digits):
            continue
        if digits in by_num and _card_score(by_num[digits]) == 3:
            continue  # already have a fully-fleshed-out record
        mm, yy = _find_exp_near(text, m.start(), m.end())
        cvv = _find_cvv_near(text, m.start(), m.end())
        if not _exp_looks_plausible(mm, yy):
            # Expiry is right there next to the number but obviously
            # wrong — almost certainly noise.
            continue
        if not _cvv_looks_plausible(cvv):
            continue
        if strict:
            if not (mm or yy or cvv):
                continue
            if not _has_cc_keyword_near(text, m.start(), m.end()):
                continue
        _store(CreditCard(number=digits, mm=mm, yy=yy, cvv=cvv))

    return list(by_num.values())


def format_cc(cards: Iterable[CreditCard]) -> str:
    """``NUMBER|MM|YY|CVV`` lines, sorted by number (stable, deduped)."""
    seen: Set[str] = set()
    out: List[str] = []
    for c in sorted(cards, key=lambda x: x.number):
        line = c.out_line
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


# Files that typically contain CCs inside a stealer log.
_CC_FILE_NAMES: Tuple[str, ...] = (
    "creditcards.txt", "credit_cards.txt", "credit cards.txt",
    "cards.txt", "cc.txt", "ccs.txt", "ccfullz.txt", "fullz.txt",
    "card.txt", "cards_list.txt", "cclist.txt", "bank.txt",
    "billing.txt", "payment.txt", "payments.txt", "paymentcards.txt",
)

_CC_NAME_RE = re.compile(
    r"\b(credit[\s_-]*cards?|cards?|cc|fullz|billing|payments?)\b",
    re.IGNORECASE,
)


def is_cc_file(path: str) -> bool:
    """Return True if *path*'s basename looks like a CC dump file."""
    base = os.path.basename(path).lower()
    if base in _CC_FILE_NAMES:
        return True
    if not base.endswith((".txt", ".log")):
        return False
    return bool(_CC_NAME_RE.search(base))


def collect_cc_from_dir(
    root: str,
    max_bytes_per_file: Optional[int] = None,
    scan_all_text: bool = True,
) -> List[CreditCard]:
    """Walk *root*, parse every CC-looking file, return all valid cards.

    When ``scan_all_text`` is True (default), ALSO scans any other
    ``.txt`` file that looks generic (Passwords.txt, browser dumps,
    etc.) — stealer dumps often inline CC data alongside passwords.
    """
    by_num: Dict[str, CreditCard] = {}
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            lower = fname.lower()
            is_cc = is_cc_file(fpath)
            is_generic_txt = (
                scan_all_text
                and lower.endswith((".txt", ".log"))
                and not is_cc
                # skip enormous logs (browser history, etc.)
            )
            if not (is_cc or is_generic_txt):
                continue
            try:
                if max_bytes_per_file is not None:
                    if os.path.getsize(fpath) > max_bytes_per_file:
                        continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for card in parse_credit_cards(text):
                existing = by_num.get(card.number)
                if existing is None:
                    by_num[card.number] = card
                    continue

                def _score(c: CreditCard) -> int:
                    return (
                        int(bool(c.mm))
                        + int(bool(c.yy))
                        + int(bool(c.cvv))
                    )
                if _score(card) > _score(existing):
                    by_num[card.number] = card
    return list(by_num.values())
