"""
Pixeldrain adapter.

Pixeldrain serves direct downloads at ``/api/file/<id>?download``. The
share UI URL is ``https://pixeldrain.com/u/<id>`` (file) or
``/l/<id>`` (list). For lists we pick the largest file.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

from . import ResolvedURL


HOSTS = ("pixeldrain.com",)

_API_BASE = "https://pixeldrain.com/api"


async def resolve(session: Any, url: str, password: Optional[str] = None):
    parsed = urlparse(url)
    path = parsed.path
    m = re.match(r"^/u/([A-Za-z0-9]+)/?$", path)
    if m:
        file_id = m.group(1)
        return await _resolve_file(session, file_id)
    m = re.match(r"^/l/([A-Za-z0-9]+)/?$", path)
    if m:
        return await _resolve_list(session, m.group(1))
    raise RuntimeError(f"pixeldrain: unrecognised URL shape: {url}")


async def _resolve_file(session, file_id: str) -> ResolvedURL:
    info_url = f"{_API_BASE}/file/{file_id}/info"
    async with session.get(info_url) as r:
        info = await r.json()
    if not info.get("success", True) and info.get("message"):
        raise RuntimeError(f"pixeldrain: {info['message']}")
    name = info.get("name") if isinstance(info, dict) else None
    return ResolvedURL(
        url=f"{_API_BASE}/file/{file_id}?download",
        file_name=name,
    )


async def _resolve_list(session, list_id: str) -> ResolvedURL:
    info_url = f"{_API_BASE}/list/{list_id}"
    async with session.get(info_url) as r:
        info = await r.json()
    files = info.get("files") or []
    if not files:
        raise RuntimeError("pixeldrain: list has no files")
    files.sort(key=lambda f: f.get("size") or 0, reverse=True)
    fid = files[0]["id"]
    return ResolvedURL(
        url=f"{_API_BASE}/file/{fid}?download",
        file_name=files[0].get("name"),
    )
