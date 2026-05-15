"""
qiwi.gg adapter.

Share page has a ``<a download>`` element whose href is the direct
CDN URL on ``cdn.qiwi.gg`` or a numbered subdomain.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("qiwi.gg",)


_DL_RE = re.compile(
    r'<a[^>]+download[^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SRC_RE = re.compile(
    r'<source[^>]+src=["\'](https?://[^"\']+)["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()
    m = _DL_RE.search(html) or _SRC_RE.search(html)
    if not m:
        raise RuntimeError(
            "qiwi.gg: could not find direct download URL."
        )
    return ResolvedURL(url=m.group(1), referer=url)
