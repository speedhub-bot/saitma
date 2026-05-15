"""
mega.nz adapter — streams a public share via mega's CloudRAID API.

Implements the *unencrypted-on-disk* part of mega's share protocol:

  1. Parse the share URL: ``https://mega.nz/file/<fileId>#<key>`` or the
     newer ``https://mega.nz/folder/<id>#<key>`` (folder shares not
     supported by this adapter — too much state).
  2. POST to ``https://g.api.mega.co.nz/cs?id=<seq>`` with ``[{"a":"g",
     "g":1, "p":<fileId>}]`` to ask for the CDN URL.
  3. Decrypt the file attributes (name + size) with the file key.
  4. The CDN URL serves raw AES-CTR-encrypted chunks; we decrypt each
     chunk on the fly as we stream it.

This implementation is intentionally minimal — public single-file
shares only, no resume, no MAC verification (the user's downstream
extractor will catch corruption via archive integrity). We depend
only on the stdlib + ``Crypto.Cipher.AES`` (pycryptodome) which is
already pulled in transitively by ``tgcrypto``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
import struct
from typing import Any, AsyncIterator, Optional, Tuple
from urllib.parse import urlparse

from . import StreamingDownload


HOSTS = ("mega.nz", "mega.co.nz")


_API = "https://g.api.mega.co.nz/cs"


def _b64_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(_b64_pad(s))


def _str_to_a32(s: bytes) -> list[int]:
    if len(s) % 4:
        s = s + b"\x00" * (-len(s) % 4)
    return list(struct.unpack(f">{len(s)//4}I", s))


def _a32_to_str(a: list[int]) -> bytes:
    return struct.pack(f">{len(a)}I", *a)


def _parse_share_url(url: str) -> Tuple[str, list[int]]:
    """Extract (file_id, key_a32) from a mega share URL."""
    parsed = urlparse(url)
    fragment = parsed.fragment
    path = parsed.path

    # Newer format: /file/<id>#<key>
    m = re.match(r"^/file/([A-Za-z0-9_-]+)$", path)
    if m and fragment:
        file_id = m.group(1)
        key = fragment
    else:
        # Legacy: /#!<id>!<key>
        m = re.match(r"^([A-Za-z0-9_-]+)!([A-Za-z0-9_-]+)$", fragment.lstrip("!"))
        if not m:
            raise RuntimeError(
                "mega.nz: this adapter supports only single-file share URLs "
                "of the form https://mega.nz/file/<id>#<key>."
            )
        file_id, key = m.group(1), m.group(2)

    key_bytes = _b64url_decode(key)
    if len(key_bytes) != 32:
        raise RuntimeError("mega.nz: malformed key (expected 32 bytes)")
    return file_id, _str_to_a32(key_bytes)


def _decrypt_attr(attr_b64: str, key_a32: list[int]) -> dict:
    """Decrypt mega's CBC-encrypted file attributes blob."""
    from Crypto.Cipher import AES  # pycryptodome
    enc = _b64url_decode(attr_b64)
    aes = AES.new(_a32_to_str(key_a32), AES.MODE_CBC, b"\x00" * 16)
    plain = aes.decrypt(enc)
    plain = plain.rstrip(b"\x00")
    if not plain.startswith(b"MEGA"):
        raise RuntimeError("mega.nz: failed to decrypt file attributes")
    try:
        return json.loads(plain[4:].decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"mega.nz: attribute JSON decode failed: {exc}")


async def resolve(session: Any, url: str, password: Optional[str] = None):
    file_id, key_a32 = _parse_share_url(url)

    # The "file key" mega sends is 32 bytes: split into a XOR-folded
    # 16-byte AES key + a 16-byte (iv + meta-mac) pair.
    k = [
        key_a32[0] ^ key_a32[4],
        key_a32[1] ^ key_a32[5],
        key_a32[2] ^ key_a32[6],
        key_a32[3] ^ key_a32[7],
    ]
    iv = key_a32[4:6] + [0, 0]  # CTR nonce: high 64 bits, low 64 = counter

    seq = random.randint(0, 0xFFFFFFFF)
    api_url = f"{_API}?id={seq}"
    body = [{"a": "g", "g": 1, "p": file_id}]
    async with session.post(api_url, json=body) as r:
        try:
            j = await r.json(content_type=None)
        except Exception:
            txt = await r.text()
            raise RuntimeError(f"mega.nz: API returned non-JSON: {txt[:200]!r}")

    if isinstance(j, int):
        raise RuntimeError(f"mega.nz: API error code {j}")
    if not (isinstance(j, list) and j and isinstance(j[0], dict)):
        raise RuntimeError(f"mega.nz: unexpected API response: {j!r}")

    info = j[0]
    if "g" not in info or "at" not in info or "s" not in info:
        raise RuntimeError(f"mega.nz: API response missing fields: {info!r}")

    cdn_url = info["g"]
    size = int(info["s"])
    attrs = _decrypt_attr(info["at"], k)
    name = attrs.get("n", "mega_download.bin")

    aes_key = _a32_to_str(k)
    iv_bytes = _a32_to_str(iv)

    async def _factory() -> AsyncIterator[Tuple[bytes, Optional[int]]]:
        # Re-use the caller's session for the CDN GET so cookies/timeout
        # propagate. ``timeout=None`` because some files are multi-GB.
        async with session.get(cdn_url) as cdn:
            # AES-CTR over the raw stream. We feed chunks straight in,
            # decrypt in 16 KB blocks, and re-yield.
            from Crypto.Cipher import AES
            ctr = AES.new(aes_key, AES.MODE_CTR,
                          nonce=iv_bytes[:8],
                          initial_value=int.from_bytes(iv_bytes[8:16], "big"))
            async for raw in cdn.content.iter_chunked(256 * 1024):
                if not raw:
                    continue
                yield ctr.decrypt(raw), size

    return StreamingDownload(factory=_factory, file_name=name, total_size=size)


# Convenience: avoid an import-time failure when pycryptodome isn't
# installed; the adapter still resolves URLs but raises a clear error
# when the user actually tries to download.
def __getattr__(name: str):  # pragma: no cover
    if name == "_check_crypto":
        try:
            import Crypto.Cipher.AES  # noqa: F401
            return lambda: True
        except ImportError as exc:
            raise RuntimeError(
                "mega.nz downloads need pycryptodome — "
                "add `pycryptodome>=3.20` to requirements.txt."
            ) from exc
    raise AttributeError(name)
