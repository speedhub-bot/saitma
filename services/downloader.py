"""
Large-file downloader using Pyrogram MTProto client.

Pyrogram connects via MTProto directly (not the HTTP Bot API),
so it can download files of any size using just the bot token —
no user session string required.

All files are downloaded via Pyrogram MTProto for maximum speed.
MTProto is significantly faster than the Bot API HTTP endpoint
because it uses persistent encrypted TCP connections with parallel
chunk transfers.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import urllib.parse
from typing import Optional

from loguru import logger
from pyrogram import Client, raw
from pyrogram.file_id import FileId, FileType
from pyrogram.session import Auth, Session
from pyrogram.types import Message as PyroMessage
from telegram import Document, Message

import config
from services.extractor import ExtractionProgress

RESUME_RETRY_DELAY_SECONDS = 2.0

# Lazy-initialised Pyrogram client
_pyro_client: Client | None = None
_pyro_started: bool = False

# Minimum gap between dashboard log lines (separate from the in-chat
# 2 MB-boundary edits, which are throttled independently).
MIN_EDIT_INTERVAL = 1.0

# How often we edit the user-facing status message during a download.
# Pyrogram fires `_progress_cb` on every chunk (~512 KB) which is far
# more often than Telegram's per-chat edit budget, so we throttle by
# bytes (every ~2 MB) AND by wall-clock seconds (>= 1.5 s apart) to
# stay well within rate limits while still feeling responsive.
LIVE_MSG_EDIT_BYTES = 2 * 1024 * 1024
LIVE_MSG_EDIT_INTERVAL = 1.5

# Pyrogram's stock download_media is *strictly sequential* — it walks
# 1 MB chunks one at a time on a single MTProto session, so even on a
# fast link single-file throughput tops out around 3-5 MB/s. The bulk
# of the speed gain comes from the parallel chunk downloader below;
# this knob only controls how many *separate* downloads can run
# concurrently when the legacy fallback path is used.
MAX_CONCURRENT_TRANSMISSIONS = int(
    os.getenv("PYROGRAM_MAX_TRANSMISSIONS", "16")
)

# Worker thread pool inside Pyrogram (chunk decryption + write back).
# 32 keeps tgcrypto saturated on the multi-session parallel path.
PYROGRAM_WORKERS = int(os.getenv("PYROGRAM_WORKERS", "16"))

# ── Parallel chunk download tuning ────────────────────────────────
#
# Single-file throughput is bottlenecked by Pyrogram's *sequential*
# 1 MB GetFile loop. We reach for 25 MB/s+ by opening multiple media
# sessions to the file's DC and pulling many chunk windows in flight
# at the same time, then writing each chunk straight to its file
# offset with ``os.pwrite``.
#
#   total_in_flight = PARALLEL_SESSIONS * PARALLEL_PER_SESSION
#
# 4 × 4 = 16 in-flight 1 MB chunks is a good default — enough to
# saturate a gigabit pipe without tripping per-bot rate limits. Tune
# higher only if you have very large files and a fat downstream link.
PARALLEL_SESSIONS = int(os.getenv("PYROGRAM_PARALLEL_SESSIONS", "4"))
PARALLEL_PER_SESSION = int(os.getenv("PYROGRAM_PARALLEL_PER_SESSION", "4"))

# MTProto's hard upper bound for a single ``upload.GetFile`` request.
CHUNK_SIZE = 1024 * 1024

# How long Pyrogram silently absorbs a FloodWait before raising it. 60s
# means most rate-limit hiccups recover transparently without the
# extraction job failing.
PYROGRAM_SLEEP_THRESHOLD = int(os.getenv("PYROGRAM_SLEEP_THRESHOLD", "60"))


def _check_tgcrypto_loaded() -> None:
    """Log whether TgCrypto (pyrogram's fast C MTProto crypto backend)
    is actually available. Missing TgCrypto silently falls back to the
    pure-Python implementation, which is typically **5-10x slower**.
    """
    try:
        import tgcrypto  # noqa: F401
        logger.info("tgcrypto loaded — MTProto crypto uses C backend")
    except ImportError:
        logger.warning(
            "tgcrypto NOT found; downloads will use the slow pure-Python "
            "crypto fallback. Install with: pip install tgcrypto"
        )


async def _get_pyrogram() -> Client:
    """Return a started Pyrogram bot client (singleton).

    Configured for high-throughput downloads:
      * ``workers``                       — internal thread pool for
                                            chunk decrypt + disk write.
      * ``max_concurrent_transmissions``  — parallel chunk fetches per
                                            download.
      * ``sleep_threshold``               — silently absorb FloodWait
                                            replies up to this many sec.
    """
    global _pyro_client, _pyro_started
    if _pyro_client is None:
        _pyro_client = Client(
            name="cookie_downloader",
            api_id=config.API_ID,
            api_hash=config.API_HASH,
            bot_token=config.BOT_TOKEN,
            in_memory=True,
            no_updates=True,
            workers=PYROGRAM_WORKERS,
            max_concurrent_transmissions=MAX_CONCURRENT_TRANSMISSIONS,
            sleep_threshold=PYROGRAM_SLEEP_THRESHOLD,
        )
    if not _pyro_started:
        _check_tgcrypto_loaded()
        await _pyro_client.start()
        _pyro_started = True
        logger.info(
            "Pyrogram download client started "
            "(workers={}, concurrent_transmissions={}, sleep_threshold={}s)",
            PYROGRAM_WORKERS,
            MAX_CONCURRENT_TRANSMISSIONS,
            PYROGRAM_SLEEP_THRESHOLD,
        )
    return _pyro_client


async def disconnect_pyrogram() -> None:
    """Gracefully disconnect the Pyrogram client."""
    global _pyro_started
    if _pyro_client is not None and _pyro_started:
        await _pyro_client.stop()
        _pyro_started = False
        logger.info("Pyrogram download client stopped")


async def _open_media_session(client: Client, dc_id: int) -> Session:
    """Open one media session against ``dc_id``.

    For files hosted on a different DC than the bot's home DC we
    export/import auth so the new session is allowed to issue
    ``upload.GetFile``. For same-DC files we reuse the existing auth_key.
    """
    home_dc = await client.storage.dc_id()
    test_mode = await client.storage.test_mode()
    if dc_id == home_dc:
        auth_key = await client.storage.auth_key()
    else:
        auth_key = await Auth(client, dc_id, test_mode).create()
    session = Session(client, dc_id, auth_key, test_mode, is_media=True)
    await session.start()
    if dc_id != home_dc:
        exported = await client.invoke(
            raw.functions.auth.ExportAuthorization(dc_id=dc_id)
        )
        await session.invoke(
            raw.functions.auth.ImportAuthorization(
                id=exported.id, bytes=exported.bytes,
            )
        )
    return session


async def _parallel_download(
    client: Client,
    pyro_msg: PyroMessage,
    out_path: str,
    file_size: int,
    progress_cb,
    cancel_cb,
) -> str:
    """Download a Telegram document in parallel by partitioning the file
    into 1 MB chunks and pulling many in flight at once across multiple
    media sessions.

    Returns the output path, or raises on unrecoverable failure. The
    caller should fall back to ``client.download_media`` on
    ``NotImplementedError`` (e.g. CDN redirects, photo thumbs).
    """
    try:
        from pyrogram.errors import FloodWait
    except ImportError:
        FloodWait = None  # type: ignore[assignment]

    media = pyro_msg.document or pyro_msg.video or pyro_msg.audio
    if media is None:
        raise NotImplementedError("message has no document-style media")
    file_id_obj = FileId.decode(media.file_id)
    if file_id_obj.file_type not in (
        FileType.DOCUMENT, FileType.VIDEO, FileType.AUDIO,
        FileType.ANIMATION, FileType.VOICE, FileType.VIDEO_NOTE,
    ):
        raise NotImplementedError(
            f"unsupported file type for parallel path: {file_id_obj.file_type}"
        )

    location = raw.types.InputDocumentFileLocation(
        id=file_id_obj.media_id,
        access_hash=file_id_obj.access_hash,
        file_reference=file_id_obj.file_reference,
        thumb_size=file_id_obj.thumbnail_size or "",
    )
    dc_id = file_id_obj.dc_id
    total_chunks = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)

    # Pre-allocate the output file so we can `pwrite` chunks at any
    # offset without races.
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as fh:
        if file_size > 0:
            fh.truncate(file_size)
    fd = os.open(out_path, os.O_WRONLY)

    sessions: list[Session] = []
    cdn_redirected = False
    downloaded_bytes = 0
    next_chunk_idx = 0
    idx_lock = asyncio.Lock()
    write_lock = asyncio.Lock()

    async def take_next_idx() -> int | None:
        nonlocal next_chunk_idx
        async with idx_lock:
            if next_chunk_idx >= total_chunks:
                return None
            idx = next_chunk_idx
            next_chunk_idx += 1
            return idx

    async def fetch_chunk(session: Session, offset: int) -> bytes:
        # Retry the chunk on transient FloodWait — anything else
        # bubbles up and aborts the whole download.
        attempts = 0
        while True:
            attempts += 1
            try:
                r = await session.invoke(
                    raw.functions.upload.GetFile(
                        location=location,
                        offset=offset,
                        limit=CHUNK_SIZE,
                    ),
                    sleep_threshold=PYROGRAM_SLEEP_THRESHOLD,
                )
            except Exception as exc:  # noqa: BLE001
                if FloodWait is not None and isinstance(exc, FloodWait):
                    if attempts >= 5:
                        raise
                    wait = float(getattr(exc, "value", getattr(exc, "x", 5)))
                    logger.warning(
                        "FloodWait on chunk @ offset {}: sleeping {}s",
                        offset, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise
            if isinstance(r, raw.types.upload.FileCdnRedirect):
                # Telegram CDN responses need encrypted-chunk handling
                # we don't replicate here. Bail and let the caller fall
                # back to the legacy single-session path.
                nonlocal cdn_redirected
                cdn_redirected = True
                raise NotImplementedError("CDN redirect")
            if not isinstance(r, raw.types.upload.File):
                raise RuntimeError(f"unexpected GetFile response: {type(r).__name__}")
            return r.bytes

    async def worker(session: Session) -> None:
        nonlocal downloaded_bytes
        while True:
            if cancel_cb is not None and cancel_cb():
                return
            idx = await take_next_idx()
            if idx is None:
                return
            offset = idx * CHUNK_SIZE
            chunk = await fetch_chunk(session, offset)
            if not chunk:
                continue
            # ``os.pwrite`` is atomic per-call and lets workers write
            # different offsets without serialising. Wrap in a write
            # lock anyway to be safe across platforms.
            async with write_lock:
                os.pwrite(fd, chunk, offset)
                downloaded_bytes += len(chunk)
                if progress_cb is not None:
                    try:
                        progress_cb(downloaded_bytes, file_size)
                    except Exception:  # noqa: BLE001
                        # Progress callback failures must never abort
                        # the actual download.
                        pass

    try:
        # Spin up parallel sessions. Each session can have multiple
        # in-flight invocations because pyrogram routes responses by
        # message id, so two workers per session multiplies throughput
        # without opening more TCP connections than necessary.
        for _ in range(max(1, PARALLEL_SESSIONS)):
            sessions.append(await _open_media_session(client, dc_id))
        tasks: list[asyncio.Task] = []
        for s in sessions:
            for _ in range(max(1, PARALLEL_PER_SESSION)):
                tasks.append(asyncio.create_task(worker(s)))
        try:
            await asyncio.gather(*tasks)
        except Exception:
            for t in tasks:
                t.cancel()
            raise
    finally:
        os.close(fd)
        for s in sessions:
            try:
                await s.stop()
            except Exception:  # noqa: BLE001
                pass

    if cdn_redirected:
        raise NotImplementedError("CDN redirect")

    if file_size and os.path.getsize(out_path) != file_size:
        raise RuntimeError(
            f"Incomplete download: got {os.path.getsize(out_path):,} "
            f"of {file_size:,} bytes"
        )

    return out_path


def _format_live_progress(current: int, total: int, start_ts: float) -> str:
    """Render the user-facing live download text (the format requested
    by the bot owner — speed in MB/s, percent, MB-of-MB)."""
    elapsed = max(time.monotonic() - start_ts, 0.001)
    speed_mbps = (current / elapsed) / (1024 * 1024)
    percent = (current / total * 100) if total > 0 else 0.0
    downloaded_mb = current / (1024 * 1024)
    total_mb = total / (1024 * 1024) if total > 0 else 0.0
    return (
        "\u2b07\ufe0f <b>Downloading\u2026</b>\n"
        f"Progress: {percent:.1f}%\n"
        f"\U0001f4e6 {downloaded_mb:.1f} MB / {total_mb:.1f} MB\n"
        f"\u26a1 Speed: {speed_mbps:.1f} MB/s"
    )


async def _edit_live_progress(
    status_msg,
    current: int,
    total: int,
    start_ts: float,
    cancel_kb,
) -> None:
    """Edit *status_msg* with the live download text, swallowing the
    inevitable ``MessageNotModified`` / network errors."""
    if status_msg is None:
        return
    text = _format_live_progress(current, total, start_ts)
    try:
        await status_msg.edit_text(
            text, parse_mode="HTML", reply_markup=cancel_kb,
        )
    except Exception:
        # Telegram rejects edits that produce identical text, plus we
        # can race with the dashboard updater. Both are harmless.
        pass


def ensure_enough_disk_space(dest_path: str, required_bytes: int) -> None:
    if required_bytes <= 0:
        return
    usage = os.statvfs(dest_path)
    free_bytes = usage.f_bavail * usage.f_frsize
    if free_bytes < required_bytes:
        raise RuntimeError(
            "Not enough disk space for this archive. "
            f"Need about {required_bytes / (1024 ** 3):.1f} GB free; "
            f"only {free_bytes / (1024 ** 3):.1f} GB is available."
        )


async def download_file(
    message: Message,
    dest_path: str,
    progress: ExtractionProgress,
    max_retries: int = 3,
    status_msg=None,
    cancel_kb=None,
) -> str:
    """
    Download the document attached to *message* into *dest_path*.

    Uses pyrogram's MTProto transport with up to ``MAX_CONCURRENT_TRANSMISSIONS``
    parallel chunk fetches and the tgcrypto C backend (if installed) for
    AES-IGE. Also:
      * Retries once on ``FloodWait`` after sleeping the server-requested
        delay, up to *max_retries* total attempts.
      * Tracks and logs **instantaneous**, **peak** and **average** MB/s.
      * Updates the ExtractionProgress so the Telegram live dashboard
        always reflects true bytes-in-flight.

    Returns:
        Absolute path to the downloaded file.
    """
    doc: Document | None = message.document
    if doc is None:
        raise ValueError("Message has no document attached")

    file_size = doc.file_size or 0
    file_name = doc.file_name or "archive"
    out_path = os.path.join(dest_path, file_name)

    progress.phase = "downloading"
    progress.download_total = file_size
    progress.download_current = 0
    progress.download_start = time.monotonic()
    progress.live_download_msg = status_msg is not None

    os.makedirs(dest_path, exist_ok=True)
    required_bytes = int(
        file_size * config.EXTRACTION_DISK_MULTIPLIER
        + config.MIN_FREE_DISK_BYTES
    )
    ensure_enough_disk_space(dest_path, required_bytes)

    logger.info(
        "Downloading {} ({:.1f} MB) via Pyrogram MTProto "
        "(parallel_sessions={}, per_session={}, sleep_threshold={}s)",
        file_name, file_size / 1e6,
        PARALLEL_SESSIONS, PARALLEL_PER_SESSION,
        PYROGRAM_SLEEP_THRESHOLD,
    )
    client = await _get_pyrogram()

    # Resolve the message in Pyrogram context
    pyro_msg = await client.get_messages(message.chat_id, message.message_id)
    if not isinstance(pyro_msg, PyroMessage) or not pyro_msg.document:
        raise RuntimeError("Could not resolve file message via Pyrogram")

    # Import lazily: pyrogram exceptions module location varies between
    # 2.x minor versions. We degrade gracefully if the exact exception
    # class isn't found.
    try:
        from pyrogram.errors import FloodWait
    except ImportError:
        FloodWait = None  # type: ignore[assignment]

    main_loop = asyncio.get_running_loop()

    attempt = 0
    while True:
        attempt += 1
        if attempt > 1 and os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
            progress.download_current = 0
        start_ts = time.monotonic()
        last_log = start_ts
        last_bytes = 0
        peak_mbps = 0.0
        # Bytes-thresholded throttle for the in-chat live edit. We refuse
        # to fire another edit until at least LIVE_MSG_EDIT_BYTES have
        # been transferred AND LIVE_MSG_EDIT_INTERVAL seconds have
        # elapsed since the last one.
        last_edit_bytes = 0
        last_edit_ts = 0.0
        edit_inflight = False

        def _progress_cb(current: int, total: int) -> None:
            nonlocal last_log, last_bytes, peak_mbps
            nonlocal last_edit_bytes, last_edit_ts, edit_inflight
            progress.download_current = current
            progress.download_total = total
            now = time.monotonic()
            if now - last_log >= MIN_EDIT_INTERVAL:
                dt = max(now - last_log, 0.001)
                # Instantaneous speed over the last second or so — the
                # real "are we still moving" signal during flaky links.
                inst_mbps = (current - last_bytes) / dt / 1e6
                # Average since the download began — the one most users
                # think of as "how fast was this download".
                avg_elapsed = max(now - start_ts, 0.001)
                avg_mbps = current / avg_elapsed / 1e6
                if inst_mbps > peak_mbps:
                    peak_mbps = inst_mbps
                last_log = now
                last_bytes = current
                logger.info(
                    "Download {}/{:,}B  {:.1f}% | "
                    "inst={:.1f}MB/s avg={:.1f}MB/s peak={:.1f}MB/s",
                    f"{current:,}", total,
                    (current / total * 100) if total else 0,
                    inst_mbps, avg_mbps, peak_mbps,
                )

            # In-chat live edit: every 2 MB and at most once / 1.5 s.
            # We schedule the coroutine on the bot's loop because this
            # callback runs inside Pyrogram's executor.
            if (
                status_msg is not None
                and not edit_inflight
                and (current - last_edit_bytes) >= LIVE_MSG_EDIT_BYTES
                and (now - last_edit_ts) >= LIVE_MSG_EDIT_INTERVAL
            ):
                last_edit_bytes = current
                last_edit_ts = now
                edit_inflight = True

                def _done(_task):
                    nonlocal edit_inflight
                    edit_inflight = False

                try:
                    coro = _edit_live_progress(
                        status_msg, current, total, start_ts, cancel_kb,
                    )
                    # Pyrogram fires this callback inside the bot's
                    # event loop. ``call_soon_threadsafe`` is the safe
                    # cross-thread variant if Pyrogram ever moves to an
                    # executor — it works either way.
                    if main_loop.is_running():
                        try:
                            asyncio.get_running_loop()
                            task = asyncio.ensure_future(coro)
                        except RuntimeError:
                            task = asyncio.run_coroutine_threadsafe(
                                coro, main_loop,
                            )
                    else:
                        task = asyncio.run_coroutine_threadsafe(
                            coro, main_loop,
                        )
                    task.add_done_callback(_done)
                except Exception:
                    edit_inflight = False

        def _cancel_cb() -> bool:
            return bool(progress.cancelled)

        try:
            try:
                # Fast path: multi-session parallel chunk download.
                # ~16 chunks in flight at once on a fresh link reaches
                # 25 MB/s+ on most ISPs — about 5-8x stock pyrogram.
                path = await _parallel_download(
                    client,
                    pyro_msg,
                    out_path,
                    file_size,
                    _progress_cb,
                    _cancel_cb,
                )
            except NotImplementedError as exc:
                # Falls back for CDN redirects, photos, or any media
                # the parallel path doesn't decode (it then handles
                # the encrypted-CDN dance + hash verification itself).
                logger.info(
                    "Parallel path bailed ({}); falling back to "
                    "pyrogram.download_media",
                    exc,
                )
                path = await client.download_media(
                    message=pyro_msg,
                    file_name=out_path,
                    progress=_progress_cb,
                )
            break
        except Exception as exc:
            # FloodWait: server asked us to back off — sleep and retry.
            if FloodWait is not None and isinstance(exc, FloodWait):
                wait = getattr(exc, "value", getattr(exc, "x", 5))
                if attempt >= max_retries:
                    raise
                logger.warning(
                    "FloodWait hit on attempt {}/{}; sleeping {}s",
                    attempt, max_retries, wait,
                )
                await asyncio.sleep(float(wait))
                continue
            if attempt < max_retries and not progress.cancelled:
                logger.warning(
                    "Download attempt {}/{} failed ({}); retrying from byte 0",
                    attempt, max_retries, exc,
                )
                await asyncio.sleep(RESUME_RETRY_DELAY_SECONDS)
                continue
            raise

    if path is None:
        raise RuntimeError("Pyrogram returned no file")

    elapsed = time.monotonic() - start_ts
    speed_mbps = (file_size / max(elapsed, 0.001)) / 1e6
    progress.download_current = progress.download_total
    progress.live_download_msg = False
    logger.info(
        "Download complete: {} ({:.1f} MB in {:.1f}s, avg {:.1f} MB/s, "
        "peak {:.1f} MB/s)",
        path, file_size / 1e6, elapsed, speed_mbps, peak_mbps,
    )
    return str(path)


# ─── Direct URL downloader (HTTP/HTTPS) ──────────────────────────────

_URL_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "keep-alive",
}


def _filename_from_headers(url: str, content_disposition: str) -> str:
    """Extract filename from Content-Disposition or URL path."""
    m = re.search(
        r"filename\*?=(?:UTF-8''|[\"']?)([^\"';\r\n]+)",
        content_disposition,
        re.IGNORECASE,
    )
    if m:
        name = m.group(1).strip().strip('"').strip("'")
        try:
            name = urllib.parse.unquote(name)
        except Exception:
            pass
        if name:
            return name
    path = urllib.parse.urlparse(url).path
    tail = path.rsplit("/", 1)[-1]
    return tail or "archive"


def _force_archive_extension(file_name: str) -> str:
    """Append ``.zip`` when *file_name* has no extension at all.

    Keeps the rest of the extractor pipeline's extension-sniffing
    happy. The magic-byte sniffer in extractor.py is the final word on
    format — this is just a hint.
    """
    if not file_name:
        return "archive.zip"
    if any(file_name.lower().endswith(ext) for ext in (
        ".zip", ".rar", ".7z", ".tar.gz", ".tgz", ".tar",
    )):
        return file_name
    if "." not in file_name:
        return file_name + ".zip"
    return file_name


async def download_from_url(
    url: str,
    dest_path: str,
    progress: ExtractionProgress,
    file_name_hint: str = "",
    chunk_size: int = 512 * 1024,
    timeout: float = 60.0,
    status_msg=None,
    cancel_kb=None,
    host_password: "Optional[str]" = None,
) -> str:
    """Stream-download *url* into *dest_path* using aiohttp.

    For known "indirect" hosts (gofile, mediafire, mega.nz, pixeldrain,
    upload.ee, krakenfiles, bunkr, swisstransfer, dropmefiles, qiwi.gg,
    send.cm, zippyshare-clones) the URL is first resolved to a direct
    CDN link via the matching adapter in
    :mod:`services.url_downloaders`. *host_password* is forwarded to
    the adapter (used by gofile / swisstransfer share-level passwords).

    The Content-Disposition header is honoured for the final filename.
    Updates ``progress.download_current`` / ``download_total`` so the
    live dashboard can render the same way as a Pyrogram download.
    When *status_msg* is supplied, the message is edited every ~2 MB
    with the live download dashboard (speed in MB/s, percent, total).
    """
    # Import aiohttp lazily — it isn't used on every code path and
    # Railway may not have it pre-installed on older images.
    try:
        import aiohttp
    except ImportError as exc:
        raise RuntimeError(
            "aiohttp is required for URL downloads but isn't installed. "
            "`pip install aiohttp` and retry."
        ) from exc

    from services import url_downloaders as _hosts

    progress.phase = "downloading"
    progress.download_current = 0
    progress.download_total = 0
    progress.download_start = time.monotonic()
    progress.live_download_msg = status_msg is not None

    os.makedirs(dest_path, exist_ok=True)

    timeout_cfg = aiohttp.ClientTimeout(sock_connect=timeout, sock_read=None)
    async with aiohttp.ClientSession(
        timeout=timeout_cfg, headers=_URL_HEADERS,
    ) as session:
        # Step 1: try a host adapter for known indirect hosts.
        resolved = await _hosts.resolve(session, url, host_password)

        if isinstance(resolved, _hosts.StreamingDownload):
            # Host-managed download (e.g. mega.nz needs on-the-fly
            # decryption). The adapter hands us an async iterator that
            # yields ``(chunk_bytes, total_or_None)``.
            file_name = _force_archive_extension(
                file_name_hint or resolved.file_name or "download.bin"
            )
            total = resolved.total_size or 0
            progress.download_total = total
            if total:
                required_bytes = int(
                    total * config.EXTRACTION_DISK_MULTIPLIER
                    + config.MIN_FREE_DISK_BYTES
                )
                ensure_enough_disk_space(dest_path, required_bytes)

            out_path = os.path.join(dest_path, file_name)
            start_ts = time.monotonic()
            last_log = start_ts
            last_edit_bytes = 0
            last_edit_ts = 0.0
            downloaded = 0
            stream = await resolved.factory()
            with open(out_path, "wb") as fh:
                async for chunk, maybe_total in stream:
                    if progress.cancelled:
                        raise RuntimeError("Download cancelled by user")
                    if maybe_total and not progress.download_total:
                        progress.download_total = maybe_total
                        total = maybe_total
                    fh.write(chunk)
                    downloaded += len(chunk)
                    progress.download_current = downloaded
                    now = time.monotonic()
                    if now - last_log >= MIN_EDIT_INTERVAL:
                        elapsed = max(now - start_ts, 0.001)
                        speed = downloaded / elapsed / 1e6
                        logger.debug(
                            "Host-stream download {}/{} ({:.1f} MB/s)",
                            downloaded, total or "?", speed,
                        )
                        last_log = now
                    if (
                        status_msg is not None
                        and (downloaded - last_edit_bytes) >= LIVE_MSG_EDIT_BYTES
                        and (now - last_edit_ts) >= LIVE_MSG_EDIT_INTERVAL
                    ):
                        last_edit_bytes = downloaded
                        last_edit_ts = now
                        await _edit_live_progress(
                            status_msg, downloaded,
                            total or downloaded, start_ts, cancel_kb,
                        )
            elapsed = time.monotonic() - start_ts
            progress.download_total = downloaded
            progress.download_current = downloaded
            progress.live_download_msg = False
            logger.info(
                "Host-stream download complete: {} ({:.1f} MB in {:.1f}s)",
                out_path, downloaded / 1e6, elapsed,
            )
            return out_path

        # If we got a ResolvedURL, swap the URL and merge headers /
        # cookies / referer before opening the real GET.
        get_headers: dict[str, str] = {}
        get_cookies: dict[str, str] = {}
        forced_name: "Optional[str]" = None
        if isinstance(resolved, _hosts.ResolvedURL):
            url = resolved.url
            forced_name = resolved.file_name
            if resolved.headers:
                get_headers.update(resolved.headers)
            if resolved.referer:
                get_headers.setdefault("Referer", resolved.referer)
            if resolved.cookies:
                get_cookies.update(resolved.cookies)

        async with session.get(
            url,
            allow_redirects=True,
            headers=get_headers or None,
            cookies=get_cookies or None,
        ) as resp:
            if resp.status >= 400:
                raise RuntimeError(
                    f"HTTP {resp.status} — server rejected the request. "
                    "Use a direct download link (.zip / .rar)."
                )
            total = int(resp.headers.get("Content-Length", 0) or 0)
            progress.download_total = total
            required_bytes = int(
                total * config.EXTRACTION_DISK_MULTIPLIER
                + config.MIN_FREE_DISK_BYTES
            )
            ensure_enough_disk_space(dest_path, required_bytes)
            cd = resp.headers.get("Content-Disposition", "") or ""
            file_name = (
                file_name_hint
                or forced_name
                or _filename_from_headers(url, cd)
            )
            file_name = _force_archive_extension(file_name)

            out_path = os.path.join(dest_path, file_name)
            start_ts = time.monotonic()
            last_log = start_ts
            last_edit_bytes = 0
            last_edit_ts = 0.0
            downloaded = 0
            with open(out_path, "wb") as fh:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    if progress.cancelled:
                        try:
                            resp.close()
                        except Exception:
                            pass
                        raise RuntimeError(
                            "Download cancelled by user"
                        )
                    fh.write(chunk)
                    downloaded += len(chunk)
                    progress.download_current = downloaded
                    now = time.monotonic()
                    if now - last_log >= MIN_EDIT_INTERVAL:
                        elapsed = max(now - start_ts, 0.001)
                        speed = downloaded / elapsed / 1e6
                        logger.debug(
                            "URL download {}/{} ({:.1f} MB/s)",
                            downloaded, total or "?", speed,
                        )
                        last_log = now
                    # Live in-chat progress edits — every ~2 MB and at
                    # most once per 1.5 s, matching the Pyrogram path.
                    if (
                        status_msg is not None
                        and (downloaded - last_edit_bytes) >= LIVE_MSG_EDIT_BYTES
                        and (now - last_edit_ts) >= LIVE_MSG_EDIT_INTERVAL
                    ):
                        last_edit_bytes = downloaded
                        last_edit_ts = now
                        await _edit_live_progress(
                            status_msg,
                            downloaded,
                            total or downloaded,
                            start_ts,
                            cancel_kb,
                        )

    elapsed = time.monotonic() - start_ts
    mb = downloaded / 1e6
    speed = mb / max(elapsed, 0.001)
    progress.download_total = downloaded
    progress.download_current = downloaded
    progress.live_download_msg = False
    logger.info(
        "URL download complete: {} ({:.1f} MB in {:.1f}s, {:.1f} MB/s)",
        out_path, mb, elapsed, speed,
    )
    return out_path
