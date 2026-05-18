"""
Direct-download host adapters.

Many "direct download" links (gofile, mediafire, mega.nz, upload.ee,
pixeldrain, etc.) don't actually serve the file at the URL the user
pastes — they serve an HTML landing page that contains the real CDN
URL behind it. Each adapter in this package knows how to resolve one
host into either:

  * a plain :class:`ResolvedURL` that the existing aiohttp downloader
    in :mod:`services.downloader` can stream normally, or
  * a :class:`StreamingDownload` that hands back its own async chunk
    iterator (used by hosts whose protocol isn't plain HTTPS — mega.nz).

Add a new host by writing a module with ``HOSTS`` (tuple of bare
host strings) and ``async def resolve(session, url, password)``
returning one of the two result types. Register it in
:data:`_ADAPTERS` below.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple


@dataclass
class ResolvedURL:
    """Plain HTTPS URL the main downloader can stream directly."""
    url: str
    file_name: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    # Some hosts need a referer set per-request for the CDN to accept
    # the GET. Mediafire/pixeldrain occasionally do this.
    referer: Optional[str] = None


@dataclass
class StreamingDownload:
    """Host-managed download — yields ``(chunk_bytes, total_or_None)``.

    Used by hosts whose download protocol isn't plain HTTPS (mega.nz
    end-to-end-encrypted chunks, for example). The factory is an async
    callable that opens the stream when the worker is ready to write.
    """
    factory: Callable[[], Awaitable[AsyncIterator[Tuple[bytes, Optional[int]]]]]
    file_name: str
    total_size: Optional[int] = None


# A host adapter is an async callable. We use a module-by-host registry
# rather than subclassing because each host is fundamentally a
# stateless URL-rewrite.
HostResolver = Callable[
    [Any, str, Optional[str]],  # (aiohttp.ClientSession, url, password)
    Awaitable[Any],              # ResolvedURL or StreamingDownload
]


def _host_of(url: str) -> str:
    """Lowercase host portion of *url* (strips ``www.`` and any port)."""
    try:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").lower()
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


# Each adapter exports HOSTS + resolve(). We import lazily inside
# :func:`get_adapter` to avoid paying for unused HTTP scrapers (and to
# keep optional deps like ``mega.py`` truly optional).
_ADAPTER_MODULES: Tuple[str, ...] = (
    "gofile",
    "mediafire",
    "mega_nz",
    "pixeldrain",
    "upload_ee",
    "krakenfiles",
    "bunkr",
    "dropmefiles",
    "qiwigg",
    "sendcm",
    "swisstransfer",
    "zippyshare",
)


_HOST_MAP: Dict[str, HostResolver] = {}
_LOADED: bool = False


def _load_adapters() -> None:
    global _LOADED
    if _LOADED:
        return
    import importlib
    for mod_name in _ADAPTER_MODULES:
        try:
            mod = importlib.import_module(f"services.url_downloaders.{mod_name}")
        except Exception:  # noqa: BLE001 — one broken adapter shouldn't kill all
            continue
        hosts = getattr(mod, "HOSTS", ())
        resolver = getattr(mod, "resolve", None)
        if not resolver or not hosts:
            continue
        for host in hosts:
            _HOST_MAP[host.lower()] = resolver
    _LOADED = True


def supported_hosts() -> List[str]:
    """Return the alphabetical list of host strings we know how to resolve."""
    _load_adapters()
    return sorted(_HOST_MAP)


def get_adapter(url: str) -> Optional[HostResolver]:
    """Return the adapter for *url*'s host, or ``None`` for plain HTTP."""
    _load_adapters()
    host = _host_of(url)
    if not host:
        return None
    # Exact match first, then suffix match (handles e.g. ``cdn.bunkr.cr``
    # mapping to the ``bunkr`` adapter via its ``bunkr.cr`` host entry).
    if host in _HOST_MAP:
        return _HOST_MAP[host]
    for known, fn in _HOST_MAP.items():
        if host.endswith("." + known):
            return fn
    return None


async def resolve(
    session: Any,
    url: str,
    password: Optional[str] = None,
):
    """Dispatch *url* to the right adapter; ``None`` if unhandled.

    Returns either ``ResolvedURL`` (the caller streams it normally) or
    ``StreamingDownload`` (the caller invokes the factory).
    """
    adapter = get_adapter(url)
    if adapter is None:
        return None
    return await adapter(session, url, password)
