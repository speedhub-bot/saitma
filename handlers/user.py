"""
User-facing handlers: /start, /mystats, /help, VIP request, settings.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
from utils.formatting import bytes_human, number_human, seconds_human, time_until

# ── Conversation state for VIP request ──────────────────────
VIP_REASON = 0


# Brand strings
BOT_TITLE = "\U0001f36a Cookie Extractor Bot"
BOT_TAGLINE = "Fast, GB-scale cookie extraction from logs"
BOT_CREDIT = "\U0001f338 Made with care \u2014 credits to @akaza_isnt"


# ── Keyboards ─────────────────────────────────────────────
def _main_menu_kb(user_id: int | None = None) -> InlineKeyboardMarkup:
    rows = [
        # Row 1 — cookies + ULP
        [
            InlineKeyboardButton(
                "\U0001f36a Cookies", callback_data="extract_mode_cookies",
            ),
            InlineKeyboardButton(
                "\U0001f511 ULP", callback_data="extract_mode_ulp",
            ),
        ],
        # Row 2 — combo targeted + full
        [
            InlineKeyboardButton(
                "\U0001f3af Combo (Targeted)",
                callback_data="extract_mode_combo_targeted",
            ),
            InlineKeyboardButton(
                "\U0001f4e6 Combo (Full)",
                callback_data="extract_mode_combo_full",
            ),
        ],
        # Row 3 — CC + multi-mode
        [
            InlineKeyboardButton(
                "\U0001f4b3 CC (Luhn)", callback_data="extract_mode_cc",
            ),
            InlineKeyboardButton(
                "\U0001f9e9 Mix Modes", callback_data="extract",
            ),
        ],
        [
            InlineKeyboardButton("\U0001f4ca My Stats", callback_data="mystats"),
            InlineKeyboardButton("\u2699\ufe0f Settings", callback_data="settings"),
        ],
        [
            InlineKeyboardButton("\U0001f451 Get VIP", callback_data="getvip"),
            InlineKeyboardButton("\u2753 Help", callback_data="help"),
        ],
        [InlineKeyboardButton("\u2139\ufe0f About / Credits", callback_data="about")],
    ]
    if user_id is not None and user_id == config.ADMIN_ID:
        rows.append([InlineKeyboardButton("\U0001f6e0 Admin Panel", callback_data="adm_panel")])
    return InlineKeyboardMarkup(rows)


def _back_home_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("\U0001f9e9 Extract", callback_data="extract"),
            InlineKeyboardButton("\U0001f3e0 Home", callback_data="home"),
        ],
    ])


def _help_kb(page: int = 1) -> InlineKeyboardMarkup:
    buttons: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 1:
        nav.append(InlineKeyboardButton("\u25c0 Prev", callback_data=f"help_page_{page - 1}"))
    if page < 3:
        nav.append(InlineKeyboardButton("Next \u25b6", callback_data=f"help_page_{page + 1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton("\U0001f3e0 Home", callback_data="home")])
    return buttons  # type: ignore[return-value]


# ── /start ──────────────────────────────────────────────────
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Entry point — main menu."""
    user = update.effective_user
    if user is None:
        return
    row = await db.ensure_user(user.id, user.username, user.first_name)

    if row["is_banned"]:
        reason = row["ban_reason"] or "No reason provided"
        await update.message.reply_text(  # type: ignore[union-attr]
            f"\U0001f6ab You are banned.\nReason: {reason}"
        )
        return

    # Check maintenance mode
    if await db.get_setting("maintenance") == "1" and user.id != config.ADMIN_ID:
        await update.message.reply_text(  # type: ignore[union-attr]
            "\U0001f527 Bot is under maintenance.\nPlease check back later."
        )
        return

    remaining = await db.get_remaining_quota(user.id)
    used = row["daily_used_bytes"] or 0
    vip = await db.is_vip(user.id)

    quota_line = f"\U0001f4e6 Daily quota: {bytes_human(used)} / {'Unlimited' if vip else bytes_human(config.FREE_DAILY_LIMIT_BYTES)} used"
    vip_line = ""
    if vip and row["vip_expires_at"]:
        vip_line = f"\n\U0001f451 VIP until: {row['vip_expires_at'][:10]}"
    elif vip:
        vip_line = "\n\U0001f451 VIP (forever)"

    text = _welcome_text(user.first_name or "friend", quota_line, vip_line)
    await update.message.reply_text(  # type: ignore[union-attr]
        text,
        reply_markup=_main_menu_kb(user.id),
        parse_mode="HTML",
    )


# ── Home callback ───────────────────────────────────────────
async def home_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    user = update.effective_user
    if user is None:
        return
    row = await db.ensure_user(user.id, user.username, user.first_name)

    remaining = await db.get_remaining_quota(user.id)
    used = row["daily_used_bytes"] or 0
    vip = await db.is_vip(user.id)
    quota_line = f"\U0001f4e6 Daily quota: {bytes_human(used)} / {'Unlimited' if vip else bytes_human(config.FREE_DAILY_LIMIT_BYTES)} used"
    vip_line = ""
    if vip and row["vip_expires_at"]:
        vip_line = f"\n\U0001f451 VIP until: {row['vip_expires_at'][:10]}"
    elif vip:
        vip_line = "\n\U0001f451 VIP (forever)"

    text = _welcome_text(user.first_name or "friend", quota_line, vip_line)
    await query.edit_message_text(
        text,
        reply_markup=_main_menu_kb(user.id),
        parse_mode="HTML",
    )


def _welcome_text(name: str, quota_line: str, vip_line: str) -> str:
    """Render the main /start + home greeting."""
    return (
        f"{BOT_TITLE}\n"
        f"{BOT_TAGLINE}\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        f"\U0001f44b Hey {name}!\n\n"
        "Pick what you want to extract:\n"
        "  \U0001f36a <b>Cookies</b> — Netscape cookies per domain\n"
        "  \U0001f511 <b>ULP</b> — every url:user:pass in the logs\n"
        "  \U0001f3af <b>Combo (Targeted)</b> — user:pass for a domain\n"
        "  \U0001f4e6 <b>Combo (Full)</b> — user:pass grouped by host\n"
        "  \U0001f4b3 <b>CC (Luhn)</b> — credit cards from the logs\n"
        "  \U0001f9e9 <b>Mix Modes</b> — pick any combination in one job\n\n"
        f"{quota_line}{vip_line}\n\n"
        f"{BOT_CREDIT}"
    )


# ── /about ──────────────────────────────────────────────────
ABOUT_TEXT = (
    "\u2139\ufe0f About / Credits\n"
    "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
    f"{BOT_TITLE}\n"
    f"{BOT_TAGLINE}\n\n"
    "\u2699\ufe0f Features\n"
    "\u2022 Live extraction dashboard \u2014 cookies counter, files "
    "scanned, ETA, current file\n"
    "\u2022 Cancel a job and still get the cookies found so far\n"
    "\u2022 GB-scale support: zip / rar / 7z / tar.gz, up to 10 GB for VIP\n"
    "\u2022 Magic-byte content detection \u2014 ext mismatches don\u2019t crash the job\n"
    "\u2022 Parallel MTProto download (16 concurrent chunks)\n"
    "\u2022 Priority queue, daily quotas, anti-spam, admin panel\n\n"
    f"{BOT_CREDIT}\n"
    "\U0001f4ac Issues / suggestions: contact @akaza_isnt"
)


async def about_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    await query.edit_message_text(ABOUT_TEXT, reply_markup=_back_home_kb())


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None:
        return
    await update.message.reply_text(ABOUT_TEXT, reply_markup=_back_home_kb())


# ── /mystats ────────────────────────────────────────────────
async def mystats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user is None:
        return
    await _show_stats(update, user.id)


async def mystats_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    user = update.effective_user
    if user is None:
        return
    await _show_stats(update, user.id, edit=True)


async def _show_stats(update: Update, user_id: int, edit: bool = False) -> None:
    row = await db.get_user(user_id)
    if row is None:
        return
    vip = await db.is_vip(user_id)
    remaining = await db.get_remaining_quota(user_id)
    used = row["daily_used_bytes"] or 0
    reset_in = time_until(row["daily_reset_at"]) if row["daily_reset_at"] else "Soon"

    status = "VIP"
    if vip and row["vip_expires_at"]:
        status += f" (expires {row['vip_expires_at'][:10]})"
    elif vip:
        status += " (forever)"
    elif row["is_banned"]:
        status = "Banned"
    else:
        status = "Free"

    text = (
        f"\U0001f4ca Your Statistics\n"
        f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        f"\U0001f464 Name: {row['first_name'] or 'N/A'}\n"
        f"\U0001f194 ID: {user_id}\n"
        f"\U0001f451 Status: {status}\n\n"
        f"\U0001f4e6 Today's Usage: {bytes_human(used)} / {'Unlimited' if vip else bytes_human(config.FREE_DAILY_LIMIT_BYTES)}\n"
        f"\U0001f504 Quota resets in: {reset_in}\n\n"
        f"\U0001f4c8 All Time Stats:\n"
        f"\u2022 Total extractions: {row['total_extractions']:,}\n"
        f"\u2022 Total cookies found: {number_human(row['total_cookies_found'])}\n"
        f"\u2022 Total data processed: {bytes_human(row['total_bytes_processed'])}\n"
        f"\u2022 Member since: {(row['joined_at'] or '')[:10]}"
    )
    kb = _back_home_kb()
    if edit:
        await update.callback_query.edit_message_text(text, reply_markup=kb)  # type: ignore[union-attr]
    else:
        await update.message.reply_text(text, reply_markup=kb)  # type: ignore[union-attr]


# ── /help ───────────────────────────────────────────────────
HELP_PAGES = {
    1: (
        "\u2753 Help — Page 1/3\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
        "\U0001f36a What does this bot do?\n"
        "It scans your log archives and extracts whatever you ask for. "
        "Pick one output mode from the main menu, or tap \U0001f9e9 "
        "<b>Mix Modes</b> to combine several in a single scan.\n\n"
        "Output modes:\n"
        "\u2022 \U0001f36a <b>Cookies</b> \u2014 Netscape <code>.txt</code> per target domain\n"
        "\u2022 \U0001f511 <b>ULP</b> \u2014 every <code>url:user:pass</code>, deduped\n"
        "\u2022 \U0001f3af <b>Combo (Targeted)</b> \u2014 <code>user:pass</code> for a domain\n"
        "\u2022 \U0001f4e6 <b>Combo (Full)</b> \u2014 <code>user:pass</code> grouped by host\n"
        "\u2022 \U0001f4b3 <b>CC (Luhn)</b> \u2014 Luhn-valid credit cards\n\n"
        "Supported archive formats: .zip .rar .7z .tar.gz / .tar.bz2"
    ),
    2: (
        "\u2753 Help — Page 2/3\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
        "How to use:\n"
        "1\ufe0f\u20e3 Tap a mode button on the main menu (or /cookies, /ulp, "
        "/combo, /combo_full, /cc)\n"
        "2\ufe0f\u20e3 Enter target domain(s) \u2014 or tap <b>Skip</b> for "
        "ULP / Combo Full / CC to scan the whole archive\n"
        "3\ufe0f\u20e3 Upload your archive file \u2014 OR paste a direct URL "
        "(mediafire, gofile, mega.nz, pixeldrain, krakenfiles, bunkr, \u2026)\n"
        "4\ufe0f\u20e3 Wait for processing on the live dashboard\n"
        "5\ufe0f\u20e3 Receive your results as text files"
    ),
    3: (
        "\u2753 Help — Page 3/3\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
        "\U0001f451 VIP Benefits:\n"
        "\u2022 Unlimited daily quota\n"
        "\u2022 Priority queue (skip ahead)\n"
        "\u2022 Files up to 10 GB\n"
        "\u2022 Faster processing\n"
        "\u2022 Extended job history (90 days)\n\n"
        "Free tier limits:\n"
        "\u2022 2 GB daily quota\n"
        "\u2022 Max 2 GB per file\n"
        "\u2022 Standard queue\n\n"
        "\U0001f4a1 Tip: cancel a running job and the bot still sends "
        "the cookies it has already found.\n\n"
        + BOT_CREDIT
    ),
}


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(  # type: ignore[union-attr]
        HELP_PAGES[1],
        reply_markup=InlineKeyboardMarkup(_help_kb(1)),
        parse_mode="HTML",
    )


async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()

    data = query.data or "help_page_1"
    if data == "help":
        page = 1
    else:
        try:
            page = int(data.split("_")[-1])
        except (ValueError, IndexError):
            page = 1
    page = max(1, min(page, 3))
    await query.edit_message_text(
        HELP_PAGES[page],
        reply_markup=InlineKeyboardMarkup(_help_kb(page)),
        parse_mode="HTML",
    )


# ── VIP request ─────────────────────────────────────────────
async def getvip_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Show VIP benefits and ask for reason."""
    query = update.callback_query
    if query is None:
        return ConversationHandler.END
    await query.answer()

    text = (
        "\U0001f451 VIP Membership Benefits\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        "\u2705 Unlimited daily quota\n"
        "\u2705 Priority queue (skip ahead)\n"
        "\u2705 Process files up to 10 GB\n"
        "\u2705 Faster processing (dedicated workers)\n"
        "\u2705 Results split into larger chunks\n"
        "\u2705 Extended job history (90 days)\n\n"
        "\U0001f4cb Free tier limits:\n"
        "\u274c 2 GB daily quota\n"
        "\u274c Standard queue\n"
        "\u274c Max 2 GB per file\n\n"
        "To request VIP, tell us why you need it:"
    )
    await query.edit_message_text(
        text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("\u274c Cancel", callback_data="home")]
        ]),
    )
    return VIP_REASON


async def vip_reason_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """User sent their VIP reason — forward to admin."""
    user = update.effective_user
    if user is None or update.message is None:
        return ConversationHandler.END

    reason = update.message.text or "No reason"
    await db.create_vip_request(user.id, user.username, user.first_name, reason)

    # Notify admin
    admin_text = (
        f"\U0001f451 New VIP Request\n"
        f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        f"\U0001f464 {user.first_name} (@{user.username})\n"
        f"\U0001f194 {user.id}\n"
        f"\U0001f4ac Reason: {reason}"
    )
    admin_kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("\u2705 7 days", callback_data=f"vip_approve_{user.id}_7"),
            InlineKeyboardButton("\u2705 30 days", callback_data=f"vip_approve_{user.id}_30"),
        ],
        [
            InlineKeyboardButton("\u2705 Forever", callback_data=f"vip_approve_{user.id}_0"),
            InlineKeyboardButton("\u23f1 Custom", callback_data=f"vip_custom_{user.id}"),
        ],
        [InlineKeyboardButton("\u274c Reject", callback_data=f"vip_reject_{user.id}")],
    ])
    try:
        await context.bot.send_message(config.ADMIN_ID, admin_text, reply_markup=admin_kb)
    except Exception:
        logger.exception("Failed to notify admin about VIP request")

    await update.message.reply_text(
        "\u2705 VIP request sent! Admin will review shortly.",
        reply_markup=_back_home_kb(),
    )
    return ConversationHandler.END


async def vip_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer()
        await home_callback(update, context)
    return ConversationHandler.END


# ── Settings callback (user-facing) ─────────────────────────
async def settings_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    text = (
        "\u2699\ufe0f Settings\n"
        "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        "Currently there are no user-configurable settings.\n"
        "Contact admin for custom quota limits."
    )
    await query.edit_message_text(text, reply_markup=_back_home_kb())


# ── Register all handlers ──────────────────────────────────
def register(app) -> None:
    """Attach user handlers to the Application."""

    # VIP conversation (must be added before generic callback)
    vip_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(getvip_callback, pattern="^getvip$")],
        states={
            VIP_REASON: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, vip_reason_received),
                CallbackQueryHandler(vip_cancel, pattern="^home$"),
            ]
        },
        fallbacks=[CallbackQueryHandler(vip_cancel, pattern="^home$")],
        per_message=False,
    )
    app.add_handler(vip_conv)

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("mystats", mystats_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about_command))
    app.add_handler(CommandHandler("credits", about_command))

    app.add_handler(CallbackQueryHandler(home_callback, pattern="^home$"))
    app.add_handler(CallbackQueryHandler(mystats_callback, pattern="^mystats$"))
    app.add_handler(CallbackQueryHandler(help_callback, pattern=r"^help(_page_\d+)?$"))
    app.add_handler(CallbackQueryHandler(settings_callback, pattern="^settings$"))
    app.add_handler(CallbackQueryHandler(about_callback, pattern="^about$"))
