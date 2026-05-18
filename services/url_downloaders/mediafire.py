"""
Mediafire adapter.

Two URL shapes are common:
  * ``https://www.mediafire.com/file/<id>/<name>/file``
  * ``https://www.mediafire.com/?<id>``

The share page contains a ``<a id="downloadButton" href="...">`` whose
href is the direct CDN URL. Some pages instead embed a
``window.location.href = "..."`` redirect in inline JS — we cover both.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("mediafire.com",)


# href-attr can appear either before *or* after id="downloadButton" — we
# match both orders. The fallback CDN_RE catches the URL via the
# `https://download<NNN>.mediafire.com/...` pattern anywhere in the page,
# which is the safest signal that survives most layout refactors.
_HREF_BEFORE_RE = re.compile(
    r'<a[^>]+href=["\'](https?://download\d+\.mediafire\.com/[^"\']+)["\']'
    r'[^>]+id=["\']downloadButton["\']',
    re.IGNORECASE,
)
_HREF_AFTER_RE = re.compile(
    r'<a[^>]+id=["\']downloadButton["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_CDN_RE = re.compile(
    r'https?://download\d+\.mediafire\.com/[A-Za-z0-9_./%+~?&=:!-]+',
    re.IGNORECASE,
)
_JS_RE = re.compile(
    r'window\.location\.href\s*=\s*["\']([^"\']+\.\w{2,4})["\']',
    re.IGNORECASE,
)


_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
}


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url, headers=_DEFAULT_HEADERS) as r:
        html = await r.text()

    m = (
        _HREF_BEFORE_RE.search(html)
        or _HREF_AFTER_RE.search(html)
        or _JS_RE.search(html)
    )
    if m:
        direct = m.group(1)
    else:
        # Last resort: pull the first download<N>.mediafire.com URL we
        # see anywhere in the page. Works even when the surrounding
        # markup changes.
        m2 = _CDN_RE.search(html)
        if not m2:
            raise RuntimeError(
                "mediafire: could not find direct download URL on the share "
                "page. The page layout may have changed, or this is a folder "
                "share."
            )
        direct = m2.group(0)

    # File name from URL tail — strip URL-encoding so we get a sane name.
    from urllib.parse import unquote
    file_name = direct.rsplit("/", 1)[-1] if "/" in direct else None
    if file_name:
        file_name = unquote(file_name)
    return ResolvedURL(
        url=direct,
        file_name=file_name,
        referer=url,
    )
