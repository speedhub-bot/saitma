"""
``/dt`` — direct Discord token validity checker.

Lets a user paste one or more Discord tokens (inline, in a reply, or in
a ``.txt`` upload) and immediately see which ones still hit Discord's
``/users/@me`` successfully. Reuses the validation logic from
:mod:`services.loot` so a token reported VALID here will behave the
same way it would inside a ``/loot`` archive scan.

Usage:

* ``/dt <token>``                       — validate a single token now
* ``/dt <token1> <token2> ...``         — validate several tokens
* ``/dt``                               — prompt for a message / .txt
* While in the prompt state, send a text message with one token per
  line, or upload a ``.txt`` file containing the tokens.

Heavy archive parsing is still ``/loot``'s job; ``/dt`` is the
lightweight "is this token alive?" path.
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from typing import List

import aiohttp
from loguru import logger
from telegram import Update
from telegram.ext import (
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

import config
from db import database as db
from services.loot import (
    DiscordToken,
    _DISCORD_TOKEN_RE,
    _validate_discord_token,
)

# ── Conversation state ────────────────────────────────────────────
DT_WAITING = 0

# Anti-abuse: hard cap how many tokens we validate per command. Each
# request hits Discord, so we keep this small to stay polite and to
# protect the bot from a flood of tokens in a single message.
_DT_MAX_TOKENS = 50

# Discord API is rate-limited per-IP; keep concurrency low.
_DT_CONCURRENCY = 4

# Telegram messages cap at 4096 chars — keep room for the trailing
# summary line.
_DT_MAX_REPLY = 3800


def _parse_tokens(text: str) -> List[str]:
    """Pull every Discord-shaped token out of *text* (one per line or
    space-separated). Returns a deduplicated, order-preserving list."""
    if not text:
        return []
    found: List[str] = []
    seen: set[str] = set()
    for m in _DISCORD_TOKEN_RE.finditer(text.encode("utf-8", errors="ignore")):
        try:
            tok = m.group(0).decode("ascii", errors="ignore")
        except UnicodeDecodeError:
            continue
        if not tok or tok in seen:
            continue
        seen.add(tok)
        found.append(tok)
    return found


def _format_result(tk: DiscordToken) -> str:
    """One-line summary of a validated token (kept under Telegram's
    per-message limit when joined with newlines)."""
    head = tk.redacted or tk.token[:10] + "…"
    if tk.valid is True:
        bits = [f"\u2705 VALID   {head}"]
        if tk.username:
            who = tk.global_name or tk.username
            bits.append(f"user={who} (@{tk.username})")
        if tk.user_id:
            bits.append(f"id={tk.user_id}")
        if tk.email:
            bits.append(f"email={tk.email}")
        if tk.phone:
            bits.append(f"phone={tk.phone}")
        if tk.mfa_enabled is True:
            bits.append("mfa=on")
        if tk.verified is True:
            bits.append("verified")
        if tk.nitro and tk.nitro != "none":
            bits.append(f"nitro={tk.nitro}")
        return "  ".join(bits)
    if tk.valid is False:
        err = tk.error or "revoked"
        return f"\u274c DEAD    {head}  ({err})"
    err = tk.error or "no response"
    return f"\u2754 UNKNOWN {head}  ({err})"


async def _validate_many(tokens: List[str]) -> List[DiscordToken]:
    """Validate *tokens* in parallel (respecting ``_DT_CONCURRENCY``).

    Returns one :class:`DiscordToken` per input token, in the original
    order, with the validation fields filled in.
    """
    results = [DiscordToken(token=t, source_file="/dt") for t in tokens]
    if not results:
        return results

    sem = asyncio.Semaphore(_DT_CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=25)
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    async def _run(tk: DiscordToken) -> None:
        async with sem:
            await _validate_discord_token(session, tk)

    async with aiohttp.ClientSession(
        timeout=timeout, headers={"User-Agent": ua},
    ) as session:
        await asyncio.gather(
            *(_run(tk) for tk in results), return_exceptions=True,
        )
    return results


async def _gate(update: Update) -> bool:
    """Shared ban/maintenance gate used by every entry point."""
    user = update.effective_user
    if user is None:
        return False
    row = await db.ensure_user(user.id, user.username, user.first_name)
    if row["is_banned"]:
        reason = row["ban_reason"] or "No reason provided"
        await update.message.reply_text(  # type: ignore[union-attr]
            f"\U0001f6ab You are banned.\nReason: {reason}"
        )
        return False
    if (
        await db.get_setting("maintenance") == "1"
        and user.id != config.ADMIN_ID
    ):
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f527 Bot is under maintenance. Please check back later."
        )
        return False
    return True


def _summary(results: List[DiscordToken], *, truncated: int = 0) -> str:
    """Footer with VALID / DEAD / UNKNOWN counts."""
    valid = sum(1 for t in results if t.valid is True)
    dead = sum(1 for t in results if t.valid is False)
    unknown = sum(1 for t in results if t.valid is None)
    summary = (
        f"\u2728 Done: {valid} valid, {dead} dead, {unknown} unknown "
        f"(checked {len(results)})"
    )
    if truncated:
        summary += f"\n\u26a0\ufe0f Truncated — extra {truncated} token(s) skipped."
    return summary


async def _reply_with_results(
    update: Update,
    results: List[DiscordToken],
    *,
    truncated: int = 0,
) -> None:
    """Send the per-token result lines back to the user, falling back
    to a .txt attachment when the message would overflow Telegram's
    4 KB cap."""
    lines = [_format_result(tk) for tk in results]
    summary = _summary(results, truncated=truncated)

    body = "\n".join(lines)
    if len(body) + len(summary) + 2 <= _DT_MAX_REPLY:
        await update.message.reply_text(  # type: ignore[union-attr]
            body + "\n\n" + summary,
            disable_web_page_preview=True,
        )
        return

    # Too long — ship as a file so nothing gets truncated.
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    )
    try:
        fh.write(body + "\n\n" + summary + "\n")
        fh.flush()
        fh.close()
        with open(fh.name, "rb") as readback:
            await update.message.reply_document(  # type: ignore[union-attr]
                document=readback,
                filename="discord_token_results.txt",
                caption=summary,
            )
    finally:
        try:
            os.unlink(fh.name)
        except OSError:
            pass


# ── Entry points ─────────────────────────────────────────────────


async def dt_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Handle ``/dt`` with or without inline arguments."""
    if not await _gate(update):
        return ConversationHandler.END

    raw = " ".join(context.args or [])
    tokens = _parse_tokens(raw)
    if not tokens:
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f3ae Discord token check\n\n"
            "Send me one or more Discord tokens (one per line) or "
            "upload a .txt file containing tokens.\n\n"
            f"Limit: {_DT_MAX_TOKENS} tokens per request.\n"
            "Send /cancel to abort."
        )
        return DT_WAITING

    truncated = max(0, len(tokens) - _DT_MAX_TOKENS)
    tokens = tokens[:_DT_MAX_TOKENS]

    progress = await update.message.reply_text(  # type: ignore[union-attr]
        f"\u23f3 Checking {len(tokens)} token(s)\u2026",
    )
    try:
        results = await _validate_many(tokens)
    except Exception as exc:
        logger.exception("/dt inline validation crashed")
        await progress.edit_text(f"\u274c Validation failed: {exc}")
        return ConversationHandler.END

    try:
        await progress.delete()
    except Exception:
        pass
    await _reply_with_results(update, results, truncated=truncated)
    return ConversationHandler.END


async def dt_message_received(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Follow-up text message — parse and validate the tokens in it."""
    text = update.message.text or ""  # type: ignore[union-attr]
    tokens = _parse_tokens(text)
    if not tokens:
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f6a8 No Discord-shaped tokens found in that message.\n"
            "Paste tokens one per line, or send /cancel to abort.",
        )
        return DT_WAITING

    truncated = max(0, len(tokens) - _DT_MAX_TOKENS)
    tokens = tokens[:_DT_MAX_TOKENS]

    progress = await update.message.reply_text(  # type: ignore[union-attr]
        f"\u23f3 Checking {len(tokens)} token(s)\u2026",
    )
    try:
        results = await _validate_many(tokens)
    except Exception as exc:
        logger.exception("/dt validation crashed")
        await progress.edit_text(f"\u274c Validation failed: {exc}")
        return ConversationHandler.END

    try:
        await progress.delete()
    except Exception:
        pass
    await _reply_with_results(update, results, truncated=truncated)
    return ConversationHandler.END


async def dt_document_received(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Follow-up .txt upload — pull tokens out of the file body."""
    doc = update.message.document  # type: ignore[union-attr]
    if doc is None:
        return DT_WAITING

    # 1 MB plain-text cap. A file bigger than that almost certainly is
    # not a hand-curated token list; route those through /loot.
    if doc.file_size and doc.file_size > 1024 * 1024:
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f6a8 File too large for /dt (>1 MB). Use /loot for "
            "archive-scale token recovery.",
        )
        return ConversationHandler.END

    tmp_path = ""
    try:
        tg_file = await doc.get_file()
        fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="dt_")
        os.close(fd)
        await tg_file.download_to_drive(tmp_path)
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except Exception as exc:
        logger.exception("/dt file download failed")
        await update.message.reply_text(  # type: ignore[union-attr]
            f"\u274c Could not read the uploaded file: {exc}",
        )
        return ConversationHandler.END
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    tokens = _parse_tokens(text)
    if not tokens:
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f6a8 No Discord-shaped tokens found in that file.",
        )
        return ConversationHandler.END

    truncated = max(0, len(tokens) - _DT_MAX_TOKENS)
    tokens = tokens[:_DT_MAX_TOKENS]

    progress = await update.message.reply_text(  # type: ignore[union-attr]
        f"\u23f3 Checking {len(tokens)} token(s) from file\u2026",
    )
    try:
        results = await _validate_many(tokens)
    except Exception as exc:
        logger.exception("/dt file validation crashed")
        await progress.edit_text(f"\u274c Validation failed: {exc}")
        return ConversationHandler.END

    try:
        await progress.delete()
    except Exception:
        pass
    await _reply_with_results(update, results, truncated=truncated)
    return ConversationHandler.END


async def dt_cancel(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Exit the /dt conversation."""
    await update.message.reply_text(  # type: ignore[union-attr]
        "\u274c Cancelled.",
    )
    return ConversationHandler.END


# ── Registration ────────────────────────────────────────────────


def register(app) -> None:
    """Attach the /dt conversation to *app*."""
    conv = ConversationHandler(
        entry_points=[
            CommandHandler("dt", dt_command),
            CommandHandler("checktoken", dt_command),
        ],
        states={
            DT_WAITING: [
                MessageHandler(filters.Document.ALL, dt_document_received),
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND, dt_message_received,
                ),
                CommandHandler("cancel", dt_cancel),
            ],
        },
        fallbacks=[CommandHandler("cancel", dt_cancel)],
        per_message=False,
    )
    app.add_handler(conv)
