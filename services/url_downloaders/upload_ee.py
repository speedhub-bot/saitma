"""
upload.ee adapter.

Share URLs look like ``https://upload.ee/files/<id>/<name>.html``. The
share page renders a ``<a class="thinbut">`` whose href points to the
direct file. We also accept the embedded ``downloadUrl`` JS variable
some skin variants use.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("upload.ee",)


_THINBUT_RE = re.compile(
    r'<a[^>]+(?:class=["\']thinbut["\']|id=["\']d_l["\'])[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_DLVAR_RE = re.compile(
    r'(?:var|let|const)\s+download_url\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()

    m = _THINBUT_RE.search(html) or _DLVAR_RE.search(html)
    if not m:
        raise RuntimeError(
            "upload.ee: could not find direct download URL on the share page."
        )
    direct = m.group(1)
    if direct.startswith("//"):
        direct = "https:" + direct
    elif direct.startswith("/"):
        direct = "https://upload.ee" + direct
    return ResolvedURL(
        url=direct,
        file_name=direct.rsplit("/", 1)[-1] or None,
        referer=url,
    )
