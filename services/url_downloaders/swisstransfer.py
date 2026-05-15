"""
SwissTransfer (swisstransfer.com) adapter.

Public API:
  * ``GET https://www.swisstransfer.com/api/links/<linkId>``
    returns transfer metadata including ``container.files`` and the
    download host. Each file's direct URL is::

        https://<downloadHost>/api/download/<linkId>/<UUID>

If the transfer is password-protected, the bot must pass
``X-Password: <base64 sha256>`` headers — handled inline.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Optional
from urllib.parse import urlparse

from . import ResolvedURL


HOSTS = ("swisstransfer.com",)


def _link_id(url: str) -> Optional[str]:
    path = urlparse(url).path
    m = re.match(r"^/d/([A-Za-z0-9-]+)/?$", path)
    return m.group(1) if m else None


def _password_header(password: str) -> str:
    return base64.b64encode(
        hashlib.sha256(password.encode("utf-8")).digest()
    ).decode("ascii")


async def resolve(session: Any, url: str, password: Optional[str] = None):
    link_id = _link_id(url)
    if not link_id:
        raise RuntimeError(f"swisstransfer: unrecognised URL: {url}")

    api = f"https://www.swisstransfer.com/api/links/{link_id}"
    headers: dict[str, str] = {}
    if password:
        headers["X-Password"] = _password_header(password)

    async with session.get(api, headers=headers) as r:
        j = await r.json(content_type=None)

    if not isinstance(j, dict) or "data" not in j:
        raise RuntimeError(f"swisstransfer: unexpected API response: {j!r}")
    data = j["data"]
    container = data.get("container") or {}
    files = container.get("files") or []
    if not files:
        raise RuntimeError("swisstransfer: transfer has no files")
    files.sort(key=lambda f: f.get("fileSizeInBytes") or 0, reverse=True)
    target = files[0]

    dl_host = data.get("downloadHost") or "dl.swisstransfer.com"
    direct = f"https://{dl_host}/api/download/{link_id}/{target['UUID']}"
    return ResolvedURL(
        url=direct,
        file_name=target.get("fileName"),
        headers=headers,
    )
