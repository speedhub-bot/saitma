"""
Gofile.io adapter.

Public API flow (current as of 2025):

  1. ``POST https://api.gofile.io/accounts`` -> creates a guest account,
     returns ``token``.
  2. ``GET https://api.gofile.io/contents/{contentId}?wt={websiteToken}
     [&password={sha256_hex}]`` with ``Authorization: Bearer {token}``.
     Returns a JSON tree of children. The download URL of each file
     child is ``children[<id>].link``.

The ``websiteToken`` (``wt``) is an obfuscated short string baked into
gofile's frontend bundle. It rotates every few months — we try a known
recent value first and fall back to scraping the share page for any
hard-coded ``wt`` literal.

If a file is locked to *premium* accounts you'll see
``error-notPremium`` — in that case we use ``GOFILE_PREMIUM_TOKEN`` (env
var) as the Authorization header if it's set.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

from . import ResolvedURL


HOSTS = ("gofile.io",)


# Known recent ``wt`` values. Try in order; first one that returns
# anything other than ``error-wt`` wins. Append new ones at the front
# when gofile rotates.
_KNOWN_WT: tuple[str, ...] = (
    "4fd6sg89d7s6",
)

_API_BASE = "https://api.gofile.io"


def _content_id(url: str) -> Optional[str]:
    """Extract the content id from ``https://gofile.io/d/<id>``."""
    path = urlparse(url).path
    m = re.match(r"^/d/([A-Za-z0-9]+)/?$", path)
    if m:
        return m.group(1)
    # ``/c/<id>`` shows up on some embeds.
    m = re.match(r"^/c/([A-Za-z0-9]+)/?$", path)
    return m.group(1) if m else None


async def _guest_token(session) -> str:
    async with session.post(f"{_API_BASE}/accounts") as r:
        j = await r.json()
    if j.get("status") != "ok":
        raise RuntimeError(f"gofile: account create failed: {j!r}")
    return j["data"]["token"]


async def _scrape_wt(session, url: str) -> Optional[str]:
    """Best-effort scrape of a hard-coded ``wt`` literal from the page."""
    try:
        async with session.get(url) as r:
            html = await r.text()
    except Exception:
        return None
    # Look for ``wt:"..."`` or ``wt = "..."`` first (un-obfuscated builds).
    m = re.search(r'wt\s*[:=]\s*"([A-Za-z0-9]{6,32})"', html)
    if m:
        return m.group(1)
    return None


def _sha256_hex(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


async def _api_contents(
    session, content_id: str, wt: str, token: str,
    password_hex: Optional[str],
) -> dict:
    url = f"{_API_BASE}/contents/{content_id}?wt={wt}"
    if password_hex is not None:
        url += f"&password={password_hex}"
    async with session.get(
        url, headers={"Authorization": f"Bearer {token}"}
    ) as r:
        return await r.json()


async def resolve(session: Any, url: str, password: Optional[str] = None):
    cid = _content_id(url)
    if not cid:
        raise RuntimeError(f"gofile: unrecognised URL shape: {url}")

    # Prefer a premium account token from env (set by operator) so
    # premium-locked files work without manual intervention.
    premium_token = os.getenv("GOFILE_PREMIUM_TOKEN", "").strip()
    token = premium_token or await _guest_token(session)

    pwd_hex = _sha256_hex(password) if password else None

    last: dict = {}
    wt_candidates = list(_KNOWN_WT)
    scraped = await _scrape_wt(session, url)
    if scraped and scraped not in wt_candidates:
        wt_candidates.insert(0, scraped)

    for wt in wt_candidates:
        last = await _api_contents(session, cid, wt, token, pwd_hex)
        status = last.get("status", "")
        if status == "ok" or status.startswith("error-password"):
            break

    status = last.get("status", "")
    if status == "error-notPremium":
        raise RuntimeError(
            "gofile: this file is restricted to premium accounts. "
            "Set GOFILE_PREMIUM_TOKEN in the bot environment to a "
            "premium account token, or re-upload to a different host."
        )
    if status == "error-passwordRequired":
        raise RuntimeError(
            "gofile: this file is password-protected. Send the password "
            "with the URL (the bot will prompt you)."
        )
    if status == "error-password":
        raise RuntimeError("gofile: wrong password.")
    if status != "ok":
        raise RuntimeError(f"gofile: API error: {status or last!r}")

    data = last.get("data") or {}
    children = data.get("children") or {}
    if not children:
        raise RuntimeError("gofile: share has no downloadable children")

    # Public shares are usually single-file. When there are multiple
    # files, pick the largest one — that's almost always the actual log
    # archive the user is trying to download.
    files = [c for c in children.values() if c.get("type") == "file"]
    if not files:
        raise RuntimeError("gofile: no file entries in share (folder share?)")
    files.sort(key=lambda c: c.get("size") or 0, reverse=True)
    target = files[0]

    direct = target.get("link")
    if not direct:
        raise RuntimeError("gofile: file entry has no direct link")

    # gofile's CDN requires the ``accountToken`` cookie. Without it the
    # CDN returns 401.
    return ResolvedURL(
        url=direct,
        file_name=target.get("name"),
        cookies={"accountToken": token},
        headers={"Origin": "https://gofile.io", "Referer": "https://gofile.io/"},
    )
