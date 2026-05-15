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


_HREF_RE = re.compile(
    r'<a[^>]+id=["\']downloadButton["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_JS_RE = re.compile(
    r'window\.location\.href\s*=\s*["\']([^"\']+\.\w{2,4})["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()

    m = _HREF_RE.search(html) or _JS_RE.search(html)
    if not m:
        raise RuntimeError(
            "mediafire: could not find direct download URL on the share page. "
            "The page layout may have changed, or this is a folder share."
        )
    direct = m.group(1)
    # File name from URL tail.
    file_name = direct.rsplit("/", 1)[-1] if "/" in direct else None
    return ResolvedURL(
        url=direct,
        file_name=file_name,
        referer=url,
    )
