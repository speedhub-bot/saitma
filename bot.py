"""
Cookie Extractor Bot — main entry point.

Wires together the Telegram Application, database, job queue,
scheduled tasks, and all handler modules.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger
from telegram.ext import Application

import config
from db import database as db
from handlers import admin as admin_handlers
from handlers import extract as extract_handlers
from handlers import user as user_handlers
from services.downloader import disconnect_pyrogram
from services.queue import JobQueue

# ── Logging ─────────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stderr,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
           "<cyan>{module}</cyan>:<cyan>{function}</cyan> | <level>{message}</level>",
)
logger.add(
    config.LOG_FILE,
    level="DEBUG",
    rotation="10 MB",
    retention=5,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function} | {message}",
)

# ── Global objects ──────────────────────────────────────────
job_queue = JobQueue(max_workers=config.MAX_CONCURRENT_JOBS)
scheduler = AsyncIOScheduler(timezone="UTC")


# ── Scheduled tasks ─────────────────────────────────────────
async def _reset_quotas() -> None:
    logger.info("Resetting daily quotas")
    await db.reset_all_quotas()


async def _check_expired_vip() -> None:
    expired = await db.expire_vip_users()
    for uid in expired:
        logger.info("VIP expired for user {}", uid)
        try:
            from telegram import Bot

            bot = Bot(token=config.BOT_TOKEN)
            async with bot:
                await bot.send_message(
                    uid,
                    "\u23f0 Your VIP has expired.\n"
                    "Tap below to request renewal.",
                    reply_markup=None,
                )
        except Exception:
            logger.warning("Could not notify {} about VIP expiry", uid)


async def _cleanup_temp() -> None:
    temp = str(config.TEMP_DIR)
    if not os.path.isdir(temp):
        return
    rescan_root = Path(temp) / "rescan"
    now = time.time()
    cutoff = config.TEMP_FILE_MAX_AGE_HOURS * 3600
    cleaned = 0
    for entry in os.scandir(temp):
        try:
            if Path(entry.path) == rescan_root:
                continue
            age = now - entry.stat().st_mtime
            if age > cutoff:
                if entry.is_dir():
                    shutil.rmtree(entry.path, ignore_errors=True)
                else:
                    os.remove(entry.path)
                cleaned += 1
        except OSError:
            pass
    if cleaned:
        logger.info("Cleaned {} old temp entries", cleaned)


async def _daily_stats_report() -> None:
    """Send daily stats summary to admin."""
    try:
        stats = await db.global_stats()
        from utils.formatting import bytes_human, number_human

        text = (
            f"\U0001f4ca Daily Stats Report\n"
            f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
            f"New users today: {stats['new_users_today']}\n"
            f"Extractions today: {stats['extractions_today']}\n"
            f"Cookies today: {number_human(stats['cookies_today'])}\n"
            f"Data today: {bytes_human(stats['bytes_today'])}\n"
            f"Total users: {stats['total_users']:,}"
        )
        from telegram import Bot

        bot = Bot(token=config.BOT_TOKEN)
        async with bot:
            await bot.send_message(config.ADMIN_ID, text)
    except Exception:
        logger.exception("Failed to send daily stats")


def _setup_scheduler() -> None:
    scheduler.add_job(_reset_quotas, "cron", hour=0, minute=0, id="reset_quotas")
    scheduler.add_job(_check_expired_vip, "interval", hours=1, id="check_vip")
    scheduler.add_job(_cleanup_temp, "interval", hours=1, id="cleanup_temp")
    scheduler.add_job(_daily_stats_report, "cron", hour=23, minute=55, id="daily_report")


# ── Error handler ───────────────────────────────────────────
async def error_handler(update, context) -> None:
    """Global error handler — log + notify admin on critical errors."""
    logger.error("Unhandled exception: {}", context.error, exc_info=context.error)
    if update and hasattr(update, "effective_user") and update.effective_user:
        uid = update.effective_user.id
        try:
            await context.bot.send_message(
                uid,
                "\u26a0\ufe0f An unexpected error occurred. Please try again.",
            )
        except Exception:
            pass

        # Notify admin
        try:
            await context.bot.send_message(
                config.ADMIN_ID,
                f"\U0001f6a8 Critical Error\n"
                f"User: {uid}\n"
                f"Error: {str(context.error)[:500]}",
            )
        except Exception:
            pass


# ── Anti-abuse middleware ───────────────────────────────────
_msg_timestamps: dict[int, list[float]] = {}


async def anti_spam_middleware(update, context) -> None:
    """Rate-limit messages per user."""
    user = update.effective_user if update else None
    if user is None or user.id == config.ADMIN_ID:
        return

    now = time.monotonic()
    uid = user.id
    timestamps = _msg_timestamps.setdefault(uid, [])
    timestamps.append(now)

    # Prune old entries
    cutoff = now - config.SPAM_WINDOW_SECONDS
    _msg_timestamps[uid] = [t for t in timestamps if t > cutoff]

    if len(_msg_timestamps[uid]) > config.SPAM_MSG_LIMIT:
        # Muted
        logger.warning("Spam detected from user {}", uid)
        if update.message:
            await update.message.reply_text(
                "\u26a0\ufe0f Slow down! You're sending messages too fast.\n"
                f"Muted for {config.SPAM_MUTE_SECONDS // 60} minutes."
            )
        raise Exception("spam_muted")


# ── Main ────────────────────────────────────────────────────
def main() -> None:
    """Build and run the bot."""
    if not config.BOT_TOKEN:
        logger.critical("BOT_TOKEN not set")
        sys.exit(1)

    # Ensure temp dir exists
    config.TEMP_DIR.mkdir(parents=True, exist_ok=True)

    # Check for system tools needed by archive extraction
    import shutil as _shutil

    if not (_shutil.which("unrar") or _shutil.which("7z") or _shutil.which("unar")):
        logger.warning(
            "No RAR/7z extractor found! Install with: sudo apt-get install -y unrar p7zip-full"
        )

    logger.info("Starting Cookie Extractor Bot...")

    app = (
        Application.builder()
        .token(config.BOT_TOKEN)
        .concurrent_updates(True)
        .build()
    )

    # Register handlers (order matters — conversations first)
    user_handlers.register(app)
    extract_handlers.register(app, job_queue)
    admin_handlers.register(app, job_queue)

    # Global error handler
    app.add_error_handler(error_handler)

    # Post-init: start queue + scheduler + register slash-command menu
    async def post_init(application) -> None:
        await db.get_db()
        await job_queue.start()
        _setup_scheduler()
        scheduler.start()
        try:
            from telegram import BotCommand

            await application.bot.set_my_commands([
                BotCommand("start", "Open the main menu"),
                BotCommand("cookies", "Extract cookies for a domain"),
                BotCommand("ulp", "Extract url:user:pass from logs"),
                BotCommand("combo", "Combo (targeted) - user:pass for a domain"),
                BotCommand("combo_full", "Combo (full) - user:pass grouped by host"),
                BotCommand("cc", "Extract Luhn-valid credit cards"),
                BotCommand("extract", "Mix modes (pick multiple)"),
                BotCommand("mystats", "Show your usage stats"),
                BotCommand("help", "How to use the bot"),
                BotCommand("about", "About this bot / credits"),
                BotCommand("cancel", "Cancel the current conversation"),
            ])
        except Exception:
            logger.exception("Failed to register slash-command menu")
        logger.info("Bot initialised — DB ready, queue started, scheduler running")

    async def post_shutdown(application) -> None:
        await job_queue.stop()
        scheduler.shutdown(wait=False)
        await disconnect_pyrogram()
        await db.close_db()
        logger.info("Shutdown complete")

    app.post_init = post_init
    app.post_shutdown = post_shutdown

    # Atexit cleanup for crash scenarios
    def _atexit_cleanup() -> None:
        temp = str(config.TEMP_DIR)
        if os.path.isdir(temp):
            for entry in os.scandir(temp):
                if entry.name == "rescan":
                    continue
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry.path, ignore_errors=True)
                    else:
                        os.remove(entry.path)
                except OSError:
                    pass

    atexit.register(_atexit_cleanup)

    logger.info("Polling for updates...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
