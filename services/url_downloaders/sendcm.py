"""
send.cm adapter.

send.cm follows the XFileSharing 2-step download flow:
  1. GET the share page; it contains an HTML form with ``op``, ``id``,
     ``hash`` fields.
  2. POST those fields back; response contains a direct download URL
     inside another form or a ``<a class="btn-primary">``.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("send.cm",)


_FORM_FIELD_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_DL_BTN_RE = re.compile(
    r'<a[^>]+(?:class=["\'][^"\']*btn-primary[^"\']*["\']|id=["\']download["\'])[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()
        page_url = str(r.url)

    fields = dict(_FORM_FIELD_RE.findall(html))
    if "op" in fields and "id" in fields:
        # Submit the form back to the same URL.
        async with session.post(
            page_url, data=fields, headers={"Referer": page_url}
        ) as r:
            html = await r.text()

    m = _DL_BTN_RE.search(html)
    if not m:
        raise RuntimeError(
            "send.cm: could not extract direct download URL after form POST."
        )
    return ResolvedURL(url=m.group(1), referer=page_url)
