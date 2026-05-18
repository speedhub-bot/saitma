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

import datetime
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


# ── Credit card extraction (strict Luhn + brand + exp + CVV) ─────
#
# Output contract: every emitted card has a FULL ``NUMBER|MM|YY|CVV``
# tuple. No empty fields. We never guess — if any of MM/YY/CVV is
# missing or fails validation, the candidate is dropped.
#
# Pipeline per file:
#   1. Tuple-combo regex (``NUMBER<sep>MM<sep>YY<sep>CVV``)
#      Catches the dominant stealer-aggregator dump shape and is the
#      most reliable signal — the tuple itself proves the number is
#      a CC, not a timestamp.
#   2. Labeled-block parser. Lines like ``Card Number: 4111...`` followed
#      within a few lines by ``Exp: 12/27`` / ``CVV: 123``.
#   3. Inline-run scanner with TIGHT window (60 chars) + explicit
#      ``exp``/``cvv`` context tokens required. Used only as the last
#      resort, because random 16-digit runs that happen to pass Luhn
#      (timestamps, order IDs, UUIDs) are noisy.
#
# Every candidate is then run through:
#   - Luhn checksum
#   - Brand classifier (Visa/MC/Amex/Discover/Diners/JCB/UnionPay/Maestro)
#   - Brand-specific length check
#   - Brand-specific CVV length check (Amex=4, others=3)
#   - Exp-date sanity (MM 01-12, year within ``[now-2, now+15]``)
#   - Junk-shape rejection (all-same digit, sequential runs)

# A loose "find a digit run" regex used by the structured passes.
# Visual separators (space, dash, dot) are allowed inside the run;
# the boundaries reject longer digit neighbours so we don't grab
# the middle of a 20+ digit blob.
_CC_RUN_RE = re.compile(
    r"(?<![0-9])"
    r"(?P<num>\d(?:[ \-.]?\d){12,18})"
    r"(?![0-9])"
)

# Compact MM/YY (or MM/YYYY) exp regex. Used both standalone and as
# the value-parser for labeled ``Exp:`` lines.
_CC_EXP_INLINE_RE = re.compile(
    r"(?<![0-9])"
    r"(?P<mm>0[1-9]|1[0-2])"
    r"\s*[/\-.]\s*"
    r"(?P<yy>20\d{2}|\d{2})"
    r"(?![0-9])"
)

# CVV / CVV2 / CVC / Security code — requires an explicit label
# so a random 3-digit number near the card isn't picked up.
_CC_CVV_LABELED_RE = re.compile(
    r"(?i)(?:cvv2?|cvc2?|c\.?v\.?v\.?|cvn|security\s*code)"
    r"\s*[:=#]?\s*"
    r"(?<![0-9])(?P<cvv>\d{3,4})(?![0-9])"
)

# Labeled card-number line (start of a multi-line CC block).
_CC_NUMBER_LABEL_RE = re.compile(
    r"(?im)^[\t ]*"
    r"(?:card(?:[\t ]*(?:number|num|no|#))?|cc(?:[\t ]*num(?:ber)?)?|"
    r"number|num|pan|cardnum|cardnumber|card\#)"
    r"[\t ]*[:=#][\t ]*"
    r"(?P<num>[\d \-.]{13,32})"
    r"[\t ]*$"
)

# Same record's exp / cvv labels. Value parser is _CC_EXP_INLINE_RE
# / int-cast respectively.
_CC_EXP_LABEL_RE = re.compile(
    r"(?im)^[\t ]*"
    r"(?:exp(?:iry|ires?|iration)?|expiry[\t ]*date|expdate|"
    r"valid(?:[\t ]*thru)?|good[\t ]*thru)"
    r"[\t ]*[:=#][\t ]*"
    r"(?P<v>.+?)[\t ]*$"
)
_CC_CVV_LABEL_RE = re.compile(
    r"(?im)^[\t ]*"
    r"(?:cvv2?|cvc2?|c\.?v\.?v\.?|cvn|security[\t ]*code|"
    r"card[\t ]*verification(?:[\t ]*value)?)"
    r"[\t ]*[:=#][\t ]*"
    r"(?P<v>\d{3,4})[\t ]*$"
)

# Flattened combo line: NUMBER<sep>MM<sep>YY<sep>CVV. Separators may
# differ between fields (common: pipe, colon, comma, semicolon, tab).
# Year may be 2 or 4 digits; the number tolerates inner space/dash
# visual separators. Anchored to a non-digit on each side.
_CC_COMBO_RE = re.compile(
    r"(?<![0-9])"
    r"(?P<num>\d(?:[ \-.]?\d){12,18})"
    r"[\t ]*[|,:;/][\t ]*"
    r"(?P<mm>0?[1-9]|1[0-2])"
    r"[\t ]*[|,:;/\-][\t ]*"
    r"(?P<yy>20\d{2}|\d{2})"
    r"[\t ]*[|,:;/\-][\t ]*"
    r"(?P<cvv>\d{3,4})"
    r"(?![0-9])"
)


@dataclass(frozen=True)
class CreditCard:
    """One fully-validated credit-card record."""
    number: str   # digits only, no spaces/dashes
    mm: str       # zero-padded 2-char month
    yy: str       # 2-char year (last 2 digits)
    cvv: str      # 3-4 digits (4 for Amex, 3 for everything else)

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


# Brand classifier. Returns the brand name (used to pick the right
# CVV length) or ``None`` if the prefix doesn't match any known
# scheme. Length is checked here too — most brands have specific
# allowed PAN lengths.
def _brand_of(digits: str) -> Optional[str]:
    """Return brand name for *digits*, or None if it isn't a known card."""
    n = digits
    L = len(digits)

    # Amex: 34 or 37, exactly 15 digits.
    if L == 15 and (n.startswith("34") or n.startswith("37")):
        return "amex"

    # Diners Club: 36 / 38 / 39 → 14-19; 300-305 → 14-19.
    if 14 <= L <= 19:
        if n.startswith(("36", "38", "39")):
            return "diners"
        if n.startswith("30") and n[2] in "012345":
            return "diners"

    # Visa: starts with 4, 13 / 16 / 19 long.
    if n[0] == "4" and L in (13, 16, 19):
        return "visa"

    # Mastercard: 51-55 (16) or 2221-2720 (16).
    if L == 16:
        if n[0] == "5" and n[1] in "12345":
            return "mastercard"
        if n.startswith("2") and 2221 <= int(n[:4]) <= 2720:
            return "mastercard"

    # Discover: 6011, 65, 644-649 → 16/19.
    if L in (16, 19):
        if n.startswith("6011"):
            return "discover"
        if n.startswith("65"):
            return "discover"
        if n.startswith("64") and n[2] in "456789":
            return "discover"

    # JCB: 3528-3589, 16-19 long.
    if 16 <= L <= 19 and n.startswith("35"):
        if 3528 <= int(n[:4]) <= 3589:
            return "jcb"

    # UnionPay: 62, 16-19 long.
    if 16 <= L <= 19 and n.startswith("62"):
        return "unionpay"

    # Maestro: 5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763
    # → 12-19 long.
    if 12 <= L <= 19:
        if n.startswith(("5018", "5020", "5038", "5893",
                         "6304", "6759", "6761", "6762", "6763")):
            return "maestro"

    return None


def _cvv_len_for_brand(brand: str) -> int:
    """Return the expected CVV/CVC length for the given brand."""
    return 4 if brand == "amex" else 3


# ---- Junk-shape filters --------------------------------------------------

_SEQUENTIAL_DIGITS = "0123456789"


def _is_junk_shape(digits: str) -> bool:
    """Reject obviously-non-card digit runs.

    Conservative — only drops patterns that are almost certainly NOT
    real cards. We err on the side of keeping more real cards rather
    than catching every fake test value.

      * all-same digit         (``0000000000000000``)
      * fully sequential       (``1234567890123452``)
      * obvious timestamp      (``YYYYMMDDhhmmssxx`` style — 14-16
                                digits where the first 4 are a year
                                in ``[1990, 2100]`` AND the next 4
                                form a valid date)
    """
    if len(set(digits)) == 1:
        return True
    # Sequential run check (forwards or reversed).
    if digits in _SEQUENTIAL_DIGITS * 2:
        return True
    rev = digits[::-1]
    if rev in _SEQUENTIAL_DIGITS * 2:
        return True
    # Looks like a YYYYMMDD... timestamp.
    if len(digits) >= 8:
        head4 = digits[:4]
        if head4.isdigit():
            yr = int(head4)
            mo = int(digits[4:6]) if digits[4:6].isdigit() else 0
            dy = int(digits[6:8]) if digits[6:8].isdigit() else 0
            if 1990 <= yr <= 2100 and 1 <= mo <= 12 and 1 <= dy <= 31:
                return True
    return False


# ---- Exp-date validation -------------------------------------------------

_MIN_EXP_YEAR_OFFSET = -2   # accept cards expired up to 2 years ago
_MAX_EXP_YEAR_OFFSET = 15   # ...and up to 15 years in the future


def _normalize_year(yy: str) -> str:
    """Return 2-digit year. ``2025`` → ``25``, ``25`` → ``25``."""
    yy = yy.strip()
    if len(yy) == 4 and yy.isdigit():
        return yy[2:]
    if len(yy) == 2 and yy.isdigit():
        return yy
    return ""


def _exp_is_valid(mm: str, yy: str) -> bool:
    """Return True iff (mm, yy) is a plausible CC expiry date."""
    if len(mm) != 2 or len(yy) != 2:
        return False
    if not mm.isdigit() or not yy.isdigit():
        return False
    month = int(mm)
    if month < 1 or month > 12:
        return False
    now = datetime.datetime.utcnow()
    year_full = 2000 + int(yy)
    return (now.year + _MIN_EXP_YEAR_OFFSET) <= year_full <= (
        now.year + _MAX_EXP_YEAR_OFFSET
    )


# ---- Validation entry point ---------------------------------------------

def _validate(
    digits: str,
    mm: str,
    yy: str,
    cvv: str,
) -> Optional["CreditCard"]:
    """Run the full validation pipeline. Returns a CreditCard or None."""
    if not digits.isdigit():
        return None
    if not _luhn_ok(digits):
        return None
    if _is_junk_shape(digits):
        return None
    brand = _brand_of(digits)
    if brand is None:
        return None
    if not _exp_is_valid(mm, yy):
        return None
    if not cvv.isdigit():
        return None
    if len(cvv) != _cvv_len_for_brand(brand):
        return None
    return CreditCard(number=digits, mm=mm, yy=yy, cvv=cvv)


# ---- Pass 1: tuple combo line --------------------------------------------

def _parse_tuple_combo(text: str, store: "Dict[str, CreditCard]") -> None:
    for m in _CC_COMBO_RE.finditer(text):
        digits = re.sub(r"[ \-.]", "", m.group("num"))
        mm = m.group("mm").zfill(2)
        yy = _normalize_year(m.group("yy"))
        cvv = m.group("cvv")
        card = _validate(digits, mm, yy, cvv)
        if card is not None:
            store[card.number] = card


# ---- Pass 2: labeled multi-line block ------------------------------------

def _parse_labeled_blocks(text: str, store: "Dict[str, CreditCard]") -> None:
    """Find ``Card Number: …`` lines and look ahead/back for matching
    ``Exp: …`` and ``CVV: …`` labels within the SAME record (the next
    ~12 lines, stopping at a blank-line / new ``Number:`` boundary).
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        nm = _CC_NUMBER_LABEL_RE.match(line)
        if not nm:
            continue
        digits = re.sub(r"[ \-.]", "", nm.group("num"))
        if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
            continue
        # Already have a fully-validated record for this PAN — skip.
        if digits in store:
            continue

        mm = ""
        yy = ""
        cvv = ""
        # Look at the next 12 lines (or until we hit a fresh
        # ``Number:`` label, signalling a new record).
        for j in range(i + 1, min(len(lines), i + 13)):
            other = lines[j]
            if _CC_NUMBER_LABEL_RE.match(other):
                break
            if not mm:
                em = _CC_EXP_LABEL_RE.match(other)
                if em:
                    ev = em.group("v").strip()
                    inline = _CC_EXP_INLINE_RE.search(ev)
                    if inline:
                        mm = inline.group("mm")
                        yy = _normalize_year(inline.group("yy"))
            if not cvv:
                cm = _CC_CVV_LABEL_RE.match(other)
                if cm:
                    cvv = cm.group("v")
        # Also scan a few lines BEFORE in case the order is
        # exp/cvv first, number after.
        for j in range(max(0, i - 5), i):
            other = lines[j]
            if _CC_NUMBER_LABEL_RE.match(other):
                continue
            if not mm:
                em = _CC_EXP_LABEL_RE.match(other)
                if em:
                    inline = _CC_EXP_INLINE_RE.search(em.group("v").strip())
                    if inline:
                        mm = inline.group("mm")
                        yy = _normalize_year(inline.group("yy"))
            if not cvv:
                cm = _CC_CVV_LABEL_RE.match(other)
                if cm:
                    cvv = cm.group("v")

        card = _validate(digits, mm, yy, cvv)
        if card is not None:
            store[card.number] = card


# ---- Pass 3: inline run + tight context window ---------------------------

# Search window (chars) around an inline CC run when looking for an
# accompanying exp/cvv pair. Tighter than v1 (was 200) to reject
# coincidentally-close timestamps / order IDs.
_INLINE_CTX_WINDOW = 60


def _parse_inline_runs(text: str, store: "Dict[str, CreditCard]") -> None:
    for m in _CC_RUN_RE.finditer(text):
        raw = m.group("num")
        digits = re.sub(r"[ \-.]", "", raw)
        # Skip cheaply before doing heavy work.
        if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
            continue
        if digits in store:
            continue  # already covered by a higher-confidence pass
        if not _luhn_ok(digits):
            continue
        brand = _brand_of(digits)
        if brand is None:
            continue
        if _is_junk_shape(digits):
            continue

        start, end = m.start(), m.end()
        ctx_before = text[max(0, start - _INLINE_CTX_WINDOW):start]
        ctx_after = text[end:end + _INLINE_CTX_WINDOW]

        # Look for an explicit exp date in either window.
        mm = ""
        yy = ""
        for chunk in (ctx_after, ctx_before):
            em = _CC_EXP_INLINE_RE.search(chunk)
            if em:
                mm = em.group("mm")
                yy = _normalize_year(em.group("yy"))
                break
        if not mm or not yy:
            continue

        # CVV must be LABELED (otherwise we'd grab any nearby 3-digit
        # number) and live in the same window.
        cvv = ""
        for chunk in (ctx_after, ctx_before):
            cm = _CC_CVV_LABELED_RE.search(chunk)
            if cm:
                cvv = cm.group("cvv")
                break
        if not cvv:
            continue

        card = _validate(digits, mm, yy, cvv)
        if card is not None:
            store[card.number] = card


def parse_credit_cards(
    text: str,
    *,
    strict: bool = False,
) -> List[CreditCard]:
    """Extract fully-validated credit cards from *text*.

    Every emitted card has all four ``NUMBER|MM|YY|CVV`` fields
    populated AND passes:
      * Luhn checksum
      * Brand classifier (Visa/MC/Amex/Discover/Diners/JCB/UnionPay/Maestro)
      * Brand-specific length (Amex=15, Visa=13/16/19, etc.)
      * Brand-specific CVV length (Amex=4, others=3)
      * Expiry-date plausibility (MM 01-12, year in [now-2, now+15])
      * Junk-shape rejection (all-same digit, sequential runs,
        ``YYYYMMDD…`` timestamps)

    Three passes are run in order; each later pass skips numbers
    already captured by an earlier (higher-confidence) pass:

      1. ``NUMBER<sep>MM<sep>YY<sep>CVV`` flattened combo lines.
      2. Labeled multi-line blocks (``Card Number:`` / ``Exp:`` /
         ``CVV:`` within the same record).
      3. Inline 13-19 digit run with an explicit exp date AND a
         labeled CVV in a tight surrounding window.

    The ``strict`` parameter is kept for backward compatibility but
    is effectively a no-op now — the new pipeline is uniformly
    strict. Every output card is guaranteed to be a full, valid
    record regardless of which file it came from.
    """
    del strict  # parameter is now a no-op; see docstring
    store: Dict[str, CreditCard] = {}
    _parse_tuple_combo(text, store)
    _parse_labeled_blocks(text, store)
    _parse_inline_runs(text, store)
    return list(store.values())


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
