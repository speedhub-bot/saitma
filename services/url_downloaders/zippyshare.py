"""
Zippyshare-clone adapter (zippyshare.day, zippyshareclone, etc.).

The original zippyshare.com is dead. Several mirrors are still up and
follow the same JS-puzzle pattern: the share page contains a small
inline script computing the final URL via arithmetic, plus a server
hostname extracted from the response URL.

This adapter handles the most common modern variants by simply
scanning the page for an ``href="/d/<token>/<num>/<name>"`` followed
by reconstructing it against the page's hostname. It does NOT attempt
to evaluate the JS puzzle — if the simple href isn't present, we give
up with a clear error.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urljoin

from . import ResolvedURL


HOSTS = ("zippyshare.day",)


_DL_RE = re.compile(
    r'<a[^>]+(?:id=["\']dlbutton["\']|class=["\'][^"\']*download[^"\']*["\'])[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_RE = re.compile(
    r'document\.getElementById\(["\']dlbutton["\']\)\.href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()
        page_url = str(r.url)

    m = _DL_RE.search(html) or _JS_RE.search(html)
    if not m:
        raise RuntimeError(
            "zippyshare: could not find a static download href on the page "
            "(this mirror likely uses JS arithmetic — unsupported)."
        )
    direct = urljoin(page_url, m.group(1))
    return ResolvedURL(url=direct, referer=page_url)
