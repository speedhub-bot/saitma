"""
Bunkr (bunkr.cr / bunkr.is / bunkr.ru / bunkr.ws / bunkr.la / etc.) adapter.

Bunkr rotates TLDs frequently. Share pages render a ``<source src="...">``
inside a ``<video>`` for media, and a ``<a id="download">`` for archives.
The CDN host is ``<subdomain>.bunkr.cr`` directly. Some recent skins
also expose ``window.serverUrl`` in inline JS.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = (
    "bunkr.cr",
    "bunkr.is",
    "bunkr.ru",
    "bunkr.ws",
    "bunkr.la",
    "bunkr.si",
    "bunkr.sk",
    "bunkr.ax",
    "bunkr.fi",
    "bunkrr.su",
)


_DL_RE = re.compile(
    r'<a[^>]+(?:id=["\']download(?:[A-Za-z_-]*)?["\']|class=["\'][^"\']*download[^"\']*["\'])[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SRC_RE = re.compile(
    r'<source[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_API_RE = re.compile(
    r'fetch\(["\']([^"\']*api/_001[^"\']*)["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()

    m = _DL_RE.search(html) or _SRC_RE.search(html)
    if m:
        direct = m.group(1)
        if direct.startswith("//"):
            direct = "https:" + direct
        return ResolvedURL(url=direct, referer=url)

    # Newer Bunkr skins gate the CDN URL behind ``api/_001`` — they
    # return JSON ``{"url": "..."}``. We try that as a fallback.
    api_m = _API_RE.search(html)
    if api_m:
        api_url = api_m.group(1)
        if api_url.startswith("/"):
            api_url = "https://" + url.split("//", 1)[1].split("/", 1)[0] + api_url
        async with session.get(api_url, headers={"Referer": url}) as r:
            j = await r.json(content_type=None)
        direct = j.get("url") if isinstance(j, dict) else None
        if direct:
            return ResolvedURL(url=direct, referer=url)

    raise RuntimeError(
        "bunkr: could not find direct download URL — the page layout "
        "may have changed (Bunkr rotates skins / TLDs often)."
    )
