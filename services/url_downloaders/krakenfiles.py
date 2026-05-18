"""
Krakenfiles adapter.

Share page contains a form whose ``action`` is the API endpoint and
whose ``token`` hidden input is the per-request CSRF token. POSTing
``token=<token>`` returns JSON ``{"url": "<direct CDN URL>"}``.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import ResolvedURL


HOSTS = ("krakenfiles.com",)


_TOKEN_RE = re.compile(
    r'<input[^>]+name=["\']token["\'][^>]+value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_FORM_RE = re.compile(
    r'<form[^>]+(?:id=["\']dl-form["\']|action=["\'](/download/[^"\']+))',
    re.IGNORECASE,
)


async def resolve(session: Any, url: str, password: Optional[str] = None):
    async with session.get(url) as r:
        html = await r.text()
        page_url = str(r.url)

    tok_m = _TOKEN_RE.search(html)
    form_m = _FORM_RE.search(html)
    if not tok_m or not form_m:
        raise RuntimeError(
            "krakenfiles: could not extract CSRF token + form action."
        )
    token = tok_m.group(1)
    action = form_m.group(1)
    if action.startswith("/"):
        action = "https://krakenfiles.com" + action

    async with session.post(
        action,
        data={"token": token},
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Referer": page_url,
        },
    ) as r:
        j = await r.json(content_type=None)

    direct = j.get("url") if isinstance(j, dict) else None
    if not direct:
        raise RuntimeError(f"krakenfiles: API did not return a URL: {j!r}")
    return ResolvedURL(url=direct, referer=page_url)
