"""
dropmefiles.com adapter.

The share page contains a JSON-LD block with ``contentUrl`` pointing
straight at the CDN. Failing that, we fall back to scanning the page
for any ``https://dropmefiles.com/<id>/<name>`` link with an extension.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("dropmefiles.com",)


_JSONLD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.+?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_FALLBACK_RE = re.compile(
    r'href=["\'](https?://dropmefiles\.com/[A-Za-z0-9_\-/]+\.[A-Za-z0-9]{2,5})["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()

    for m in _JSONLD_RE.finditer(html):
        blob = m.group(1).strip()
        try:
            obj = json.loads(blob)
        except Exception:
            continue
        if isinstance(obj, list):
            obj = obj[0] if obj else {}
        direct = obj.get("contentUrl") if isinstance(obj, dict) else None
        if direct:
            return ResolvedURL(
                url=direct,
                file_name=obj.get("name"),
                referer=url,
            )

    fb = _FALLBACK_RE.search(html)
    if fb:
        return ResolvedURL(url=fb.group(1), referer=url)

    raise RuntimeError(
        "dropmefiles: could not find direct download URL on the share page."
    )
