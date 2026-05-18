"""
Extraction conversation handler — the core user workflow.

States:
  DOMAIN  -> user types a domain
  FILE    -> user uploads an archive
  (processing + results happen automatically)
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from loguru import logger
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationHandlerStop,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

import config
from db import database as db
from services.downloader import download_file, download_from_url, send_result_file
from services.extractor import (
    ALL_CREDENTIAL_MODES,
    CC_MODE,
    COMBO_FULL_MODE,
    COMBO_TARGETED_MODE,
    COOKIE_MODE,
    ULP_MODE,
    ExtractionProgress,
    guess_archive_password_async,
    probe_encrypted_entries_async,
    run_extraction_async,
    try_archive_password_async,
)
from services.loot_extractor import (
    LootExtractionConfig,
    run_loot_extraction_async,
)
from services.queue import JobQueue, QueueItem, priority_for
from utils.formatting import bytes_human, progress_bar, seconds_human, time_until
from utils.validators import validate_archive, validate_domains

# Conversation states
DOMAIN, MODE, FILE = range(3)

# Available output modes, in keyboard order. Each entry is
# ``(mode_id, short label, emoji)``.
LOOT_MODE = "loot"

_MODE_BUTTONS = [
    (COOKIE_MODE, "Cookies", "\U0001f36a"),
    (ULP_MODE, "ULP url:user:pass", "\U0001f4dd"),
    (COMBO_TARGETED_MODE, "Combo (targeted)", "\U0001f3af"),
    (COMBO_FULL_MODE, "Combo (full)", "\U0001f4e6"),
    (CC_MODE, "CC (Luhn)", "\U0001f4b3"),
    (LOOT_MODE, "Loot (tdata/Discord/Steam)", "\U0001f4e6"),
]

# Single-mode shortcut buttons on the main menu — each callback_data
# pre-selects exactly one output mode and skips the mode-picker step.
_SINGLE_MODE_MAP: Dict[str, str] = {
    "extract_mode_cookies": COOKIE_MODE,
    "extract_mode_ulp": ULP_MODE,
    "extract_mode_combo_targeted": COMBO_TARGETED_MODE,
    "extract_mode_combo_full": COMBO_FULL_MODE,
    "extract_mode_cc": CC_MODE,
}

# Convenience slash commands mapped to single-mode presets.
_SLASH_CMD_MODE_MAP: Dict[str, str] = {
    "/cookies": COOKIE_MODE,
    "/ulp": ULP_MODE,
    "/combo": COMBO_TARGETED_MODE,
    "/combo_full": COMBO_FULL_MODE,
    "/cc": CC_MODE,
}

# Modes that don't depend on the target domain — the user can skip the
# domain prompt and we'll fall back to a generic ``logs`` placeholder
# for output-file naming.
_DOMAIN_INDEPENDENT_MODES = frozenset({ULP_MODE, COMBO_FULL_MODE, CC_MODE, LOOT_MODE})

# Placeholder domain used when a user picks a domain-independent mode
# and taps "Skip" instead of typing a target.
_DEFAULT_PLACEHOLDER_DOMAIN = "logs"

# Match all single-mode callback_data values in one regex for the
# ConversationHandler entry point.
_SINGLE_MODE_CB_PATTERN = (
    r"^(?:" + "|".join(re.escape(k) for k in _SINGLE_MODE_MAP) + r")$"
)

# Module-level job queue (initialised in register())
_job_queue: JobQueue | None = None

# Active progress trackers: job_id -> ExtractionProgress
_active_progress: Dict[int, ExtractionProgress] = {}

# Pending password requests: user_id -> Future that the user's next plain
# text message (or /skip command) resolves. Value is the password string,
# or None if the user chose /skip (extract only unencrypted entries).
_pending_passwords: Dict[int, "asyncio.Future[Optional[str]]"] = {}

# How long to wait for the user to reply with a password before we
# give up and cancel the job. Per-attempt — every wrong guess restarts
# the timer so the user gets a fresh chance to retry.
PASSWORD_PROMPT_TIMEOUT = 60.0  # 60 seconds, per-attempt

# How many wrong-password retries we allow before we stop asking and
# cancel the job. The 60-second-per-attempt timer also still applies.
PASSWORD_MAX_ATTEMPTS = 5

# Sentinel returned by :func:`_maybe_prompt_for_password` to signal
# "cancel the whole extraction job" — distinct from ``None`` (which
# means "skip encrypted, extract the rest").
class _PasswordCancel:
    __slots__ = ()
    def __repr__(self) -> str:  # pragma: no cover
        return "<PasswordCancel>"


PASSWORD_CANCEL = _PasswordCancel()


# ── Rescan window ──────────────────────────────────────────
@dataclass
class RescanEntry:
    """A still-on-disk archive the user can re-search within the window."""
    user_id: int
    archive_path: str
    file_name: str
    file_size: int
    password: Optional[str]
    expires_at: float                       # monotonic clock
    cleanup_task: "asyncio.Task[None]" = field(repr=False)
    # Output modes the user picked on the original extraction. Reused
    # for rescans so the second pass produces the same kind of output
    # files as the first. None means "cookies only" (legacy default).
    output_modes: Optional["frozenset[str]"] = None


# user_id -> RescanEntry. At most one open rescan window per user.
_rescan_store: Dict[int, RescanEntry] = {}


def _rescan_dir() -> str:
    """Long-lived rescan directory under TEMP_DIR (created on demand)."""
    p = os.path.join(str(config.TEMP_DIR), "rescan")
    os.makedirs(p, exist_ok=True)
    return p


async def _delete_rescan_after(user_id: int, delay: float) -> None:
    """Sleep *delay* seconds then drop the user's rescan archive."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        return
    entry = _rescan_store.pop(user_id, None)
    if entry is None:
        return
    try:
        if os.path.exists(entry.archive_path):
            os.remove(entry.archive_path)
    except OSError:
        logger.exception(
            "Rescan cleanup failed for {}", entry.archive_path,
        )
    logger.info(
        "Rescan window closed for user {} ({})",
        user_id, entry.file_name,
    )


def _register_rescan(
    user_id: int,
    archive_path: str,
    file_name: str,
    file_size: int,
    window_seconds: float,
    password: Optional[str] = None,
    output_modes: Optional["frozenset[str]"] = None,
) -> RescanEntry:
    """Register *archive_path* as a fresh rescan entry for *user_id*.

    Cancels any previously-open rescan window for this user and removes
    its archive, then schedules a new cleanup task to fire in
    *window_seconds*. The caller is responsible for placing
    *archive_path* somewhere persistent (typically under
    :func:`_rescan_dir`) before calling this.
    """
    prev = _rescan_store.pop(user_id, None)
    if prev is not None:
        prev.cleanup_task.cancel()
        if prev.archive_path != archive_path:
            try:
                if os.path.exists(prev.archive_path):
                    os.remove(prev.archive_path)
            except OSError:
                pass
    expires_at = time.monotonic() + window_seconds
    task = asyncio.create_task(_delete_rescan_after(user_id, window_seconds))
    entry = RescanEntry(
        user_id=user_id,
        archive_path=archive_path,
        file_name=file_name,
        file_size=file_size,
        password=password,
        expires_at=expires_at,
        cleanup_task=task,
        output_modes=output_modes,
    )
    _rescan_store[user_id] = entry
    return entry


def _peek_rescan(user_id: int) -> Optional[RescanEntry]:
    """Return the user's open rescan entry or ``None`` if missing/expired.

    Cleans up the store as a side-effect when the window has expired or
    the on-disk archive has already vanished.
    """
    entry = _rescan_store.get(user_id)
    if entry is None:
        return None
    if (
        entry.expires_at < time.monotonic()
        or not os.path.exists(entry.archive_path)
    ):
        prev = _rescan_store.pop(user_id, None)
        if prev is not None:
            prev.cleanup_task.cancel()
        return None
    return entry


def _domain_prompt_kb(
    allow_skip: bool = False,
) -> InlineKeyboardMarkup:
    """Domain-prompt keyboard with an optional "Skip" button.

    Used when the picked mode (ULP / Combo Full / CC) doesn't need a
    target domain — lets the user tap once to bypass the prompt.
    """
    rows: list[list[InlineKeyboardButton]] = []
    if allow_skip:
        rows.append([
            InlineKeyboardButton(
                "\u23ed\ufe0f Skip (no filter)",
                callback_data="extract_skip_domain",
            ),
        ])
    rows.append([
        InlineKeyboardButton("\u274c Cancel", callback_data="extract_cancel"),
    ])
    return InlineKeyboardMarkup(rows)


def _cancel_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("\u274c Cancel", callback_data="extract_cancel")]
    ])


def _cancel_job_kb(job_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("\U0001f6d1 Cancel Job", callback_data=f"cancel_job_{job_id}")]
    ])


# ── Entry: ask for domain ──────────────────────────────────
async def extract_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Called via /extract command or a main-menu Extract button.

    The main menu now exposes one button per output mode plus a
    multi-select "Mix Modes" entry. When the callback_data matches one
    of the single-mode shortcuts (``extract_mode_*``) we remember that
    as a preset so the rest of the flow skips the mode-picker step.
    """
    user = update.effective_user
    if user is None:
        return ConversationHandler.END

    # Detect single-mode shortcut. Multi-select entry uses ``extract``
    # which leaves the preset empty and triggers the legacy picker. The
    # same mode-specific entry points are also exposed as slash commands
    # (``/cookies``, ``/ulp``, ``/combo``, ``/combo_full``, ``/cc``).
    cb_data = (
        update.callback_query.data if update.callback_query is not None else None
    ) or ""
    preset_mode = _SINGLE_MODE_MAP.get(cb_data)
    if preset_mode is None and update.message and update.message.text:
        head = update.message.text.strip().split()[0].lower()
        head = head.split("@", 1)[0]  # strip /cmd@botname suffix
        preset_mode = _SLASH_CMD_MODE_MAP.get(head)
    if preset_mode:
        context.user_data["extract_preset_mode"] = preset_mode  # type: ignore[index]
    else:
        context.user_data.pop("extract_preset_mode", None)  # type: ignore[union-attr]

    row = await db.ensure_user(user.id, user.username, user.first_name)
    if row["is_banned"]:
        text = f"\U0001f6ab You are banned.\nReason: {row['ban_reason'] or 'N/A'}"
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(text)
        else:
            await update.message.reply_text(text)  # type: ignore[union-attr]
        return ConversationHandler.END

    # Maintenance check
    if await db.get_setting("maintenance") == "1" and user.id != config.ADMIN_ID:
        text = "\U0001f527 Bot is under maintenance. Please check back later."
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(text)
        else:
            await update.message.reply_text(text)  # type: ignore[union-attr]
        return ConversationHandler.END

    is_admin = user.id == config.ADMIN_ID

    # Rate limit check (admin bypasses)
    count = await db.count_user_extractions_last_hour(user.id)
    if count >= config.MAX_EXTRACTIONS_PER_HOUR and not is_admin:
        text = (
            f"\u26a0\ufe0f Rate limit reached ({config.MAX_EXTRACTIONS_PER_HOUR}/hour).\n"
            "Please wait before starting another extraction."
        )
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(text)
        else:
            await update.message.reply_text(text)  # type: ignore[union-attr]
        return ConversationHandler.END

    # Mix mode (no preset_mode): skip the domain prompt entirely and go
    # straight to the format picker. After the user finishes picking
    # modes we only re-prompt for a domain if at least one of the
    # selected modes actually needs one (cookies / combo-targeted).
    # Domain-independent modes (loot/CC/ULP/combo-full) never bother
    # the user with a domain prompt.
    if not preset_mode:
        context.user_data["extract_domains"] = [_DEFAULT_PLACEHOLDER_DOMAIN]  # type: ignore[index]
        context.user_data["extract_domain"] = _DEFAULT_PLACEHOLDER_DOMAIN  # type: ignore[index]
        context.user_data["extract_modes"] = set()  # type: ignore[index]
        context.user_data.pop("extract_modes_locked", None)  # type: ignore[union-attr]
        picker_text = _mode_picker_text([_DEFAULT_PLACEHOLDER_DOMAIN])
        kb = _mode_picker_kb(set(), [_DEFAULT_PLACEHOLDER_DOMAIN])
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text(
                picker_text, reply_markup=kb, parse_mode="HTML",
            )
        else:
            await update.message.reply_text(  # type: ignore[union-attr]
                picker_text, reply_markup=kb, parse_mode="HTML",
            )
        return MODE

    # Mode-specific intro + optional Skip button for domain-independent
    # modes (ULP, Combo Full, CC — they scan the whole archive).
    if preset_mode == COOKIE_MODE:
        intro = (
            "\U0001f36a <b>Cookies extraction</b>\n"
            "Enter one or more domains to extract cookies for."
        )
    elif preset_mode == COMBO_TARGETED_MODE:
        intro = (
            "\U0001f3af <b>Combo (targeted)</b>\n"
            "Enter the target domain(s) — I'll return "
            "<code>user:pass</code> for those domains only."
        )
    elif preset_mode == ULP_MODE:
        intro = (
            "\U0001f511 <b>ULP extraction</b>\n"
            "Tap <b>Skip</b> for every <code>url:user:pass</code> in the "
            "logs, or enter domain(s) to filter only those hosts."
        )
    elif preset_mode == COMBO_FULL_MODE:
        intro = (
            "\U0001f4e6 <b>Combo (full)</b>\n"
            "Tap <b>Skip</b> to get <code>user:pass</code> grouped by "
            "host for every domain in the logs."
        )
    elif preset_mode == CC_MODE:
        intro = (
            "\U0001f4b3 <b>CC (Luhn)</b>\n"
            "Tap <b>Skip</b> to extract every Luhn-valid card from the "
            "logs. Entering domains is optional and only affects the "
            "output filename."
        )
    else:
        intro = (
            "\U0001f9e9 <b>Mix Modes</b>\n"
            "Enter one or more domains — you'll pick output formats "
            "next."
        )
    text = (
        f"{intro}\n"
        f"Up to {config.MAX_DOMAINS_PER_EXTRACT} domains, separated by "
        f"commas, spaces or new lines.\n\n"
        "Examples:\n"
        "  spotify.com\n"
        "  spotify.com, netflix.com, crunchyroll.com"
    )
    allow_skip = preset_mode in _DOMAIN_INDEPENDENT_MODES
    kb = _domain_prompt_kb(allow_skip=allow_skip)
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(
            text, reply_markup=kb, parse_mode="HTML",
        )
    else:
        await update.message.reply_text(  # type: ignore[union-attr]
            text, reply_markup=kb, parse_mode="HTML",
        )
    return DOMAIN


# ── State: DOMAIN ──────────────────────────────────────────
async def domain_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Validate one or more domains and move to FILE state."""
    user = update.effective_user
    if user is None or update.message is None:
        return ConversationHandler.END

    raw = (update.message.text or "").strip()
    valid, result = validate_domains(raw, max_count=config.MAX_DOMAINS_PER_EXTRACT)
    if not valid:
        # ``result`` is the error string in the failure branch.
        await update.message.reply_text(
            f"\u274c {result}", reply_markup=_cancel_kb(),
        )
        return DOMAIN

    domains: list[str] = result  # type: ignore[assignment]

    # Check blacklist for each domain.
    for d in domains:
        if await db.is_domain_blacklisted(d):
            await update.message.reply_text(
                f"\u274c Domain is blacklisted: {d}",
                reply_markup=_cancel_kb(),
            )
            return DOMAIN

    context.user_data["extract_domains"] = domains  # type: ignore[index]
    # Back-compat: keep the legacy single-domain key populated with the
    # first/primary domain so any code that still reads it keeps working
    # (e.g. older logging hooks).
    context.user_data["extract_domain"] = domains[0]  # type: ignore[index]

    # Rescan flow: skip the FILE state entirely and reuse the cached
    # archive that's still under the rescan store.
    if context.user_data.get("extract_rescan"):  # type: ignore[union-attr]
        context.user_data.pop("extract_rescan", None)  # type: ignore[union-attr]
        entry = _peek_rescan(user.id)
        if entry is None:
            await update.message.reply_text(
                "\u23f0 Rescan window closed before you replied.\n"
                "Use /extract to upload a new archive.",
            )
            return ConversationHandler.END
        await _kickoff_rescan_job(update, context, entry, domains)
        return ConversationHandler.END

    # Single-mode shortcut: user came in via one of the main-menu mode
    # buttons. Pre-set the selected modes and jump straight to FILE.
    preset_mode: Optional[str] = context.user_data.get(  # type: ignore[union-attr]
        "extract_preset_mode",
    )
    if preset_mode:
        context.user_data["extract_modes"] = {preset_mode}  # type: ignore[index]
        prompt = await _build_file_prompt(user.id, domains, {preset_mode})
        await update.message.reply_text(
            prompt, reply_markup=_cancel_kb(),
        )
        return FILE

    # Mix-mode "back-fill" path: the user already picked their output
    # formats and we redirected them here because they picked a
    # domain-dependent one. Re-use the locked-in modes and go straight
    # to FILE without re-showing the picker.
    if context.user_data.get("extract_modes_locked"):  # type: ignore[union-attr]
        context.user_data.pop("extract_modes_locked", None)  # type: ignore[union-attr]
        modes = context.user_data.get(  # type: ignore[union-attr]
            "extract_modes",
        ) or {COOKIE_MODE}
        prompt = await _build_file_prompt(user.id, domains, modes)
        await update.message.reply_text(
            prompt, reply_markup=_cancel_kb(),
        )
        return FILE

    # Legacy mix-entry that still landed on DOMAIN first (e.g. older
    # callback wiring): initialise the picker and move on.
    context.user_data["extract_modes"] = {COOKIE_MODE}  # type: ignore[index]
    await update.message.reply_text(
        _mode_picker_text(domains),
        reply_markup=_mode_picker_kb(context.user_data["extract_modes"], domains),  # type: ignore[union-attr]
        parse_mode="HTML",
    )
    return MODE


async def domain_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """User tapped 'Skip' on the domain prompt (domain-independent mode).

    Only valid when the conversation was started via one of the single-
    mode shortcuts that don't need a target domain (ULP, Combo Full, CC).
    Falls back to a placeholder domain used only for the output filename.
    """
    q = update.callback_query
    user = update.effective_user
    if q is None or user is None:
        return DOMAIN
    await q.answer()

    preset_mode: Optional[str] = context.user_data.get(  # type: ignore[union-attr]
        "extract_preset_mode",
    )
    if preset_mode not in _DOMAIN_INDEPENDENT_MODES:
        try:
            await q.answer(
                "This mode needs a target domain.", show_alert=True,
            )
        except Exception:
            pass
        return DOMAIN

    domains = [_DEFAULT_PLACEHOLDER_DOMAIN]
    context.user_data["extract_domains"] = domains  # type: ignore[index]
    context.user_data["extract_domain"] = domains[0]  # type: ignore[index]
    context.user_data["extract_modes"] = {preset_mode}  # type: ignore[index]

    prompt = await _build_file_prompt(user.id, domains, {preset_mode})
    try:
        await q.edit_message_text(prompt, reply_markup=_cancel_kb())
    except Exception:
        if update.effective_chat is not None:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=prompt,
                reply_markup=_cancel_kb(),
            )
    return FILE


async def _build_file_prompt(
    user_id: int, domains: List[str], modes: "set[str]",
) -> str:
    """Render the 'now send your archive' message for any flow."""
    is_admin = user_id == config.ADMIN_ID
    remaining = await db.get_remaining_quota(user_id)
    vip = await db.is_vip(user_id)
    if is_admin or vip:
        limit_text = "Unlimited"
    else:
        limit_text = bytes_human(remaining)
    if is_admin:
        max_file = "Unlimited"
    elif vip:
        max_file = "10 GB"
    else:
        max_file = "2 GB"

    if domains and domains[0] == _DEFAULT_PLACEHOLDER_DOMAIN:
        domain_line = "\U0001f310 Scope: full archive (no domain filter)"
    elif len(domains) == 1:
        domain_line = f"\U0001f310 Domain: {domains[0]}"
    else:
        domain_line = (
            f"\U0001f310 Domains ({len(domains)}): "
            + ", ".join(domains)
        )

    mode_label = ", ".join(
        f"{emoji} {label}"
        for mid, label, emoji in _MODE_BUTTONS
        if mid in modes
    )

    return (
        f"{domain_line}\n"
        f"\u2699\ufe0f Output: {mode_label}\n"
        f"\U0001f4c1 Now send your archive file \u2014 OR paste a direct "
        f"download URL (mega.nz, mediafire, gofile, upload.ee, "
        f"pixeldrain, krakenfiles, bunkr, dropmefiles, qiwi.gg, "
        f"send.cm, swisstransfer, zippyshare).\n"
        f"Supported uploads:\n"
        f"\u2022 Archives: .zip .rar .7z .tar.gz .tar.bz2 .tar.xz .tar.zst "
        f".zst .cab .iso .arj .deb .rpm .dmg \u2026\n"
        f"\u2022 Plain logs: .txt .log .csv .json .xml .html .yaml \u2026\n"
        f"\u2022 Split parts: .001 .002 \u2026 .r01 .z01 .part1.rar\n"
        f"Your limit: {limit_text} remaining today\n"
        f"Max file size: {max_file}"
    )


# ── State: MODE ────────────────────────────────────────────
def _mode_picker_text(domains: List[str]) -> str:
    if not domains or domains[0] == _DEFAULT_PLACEHOLDER_DOMAIN:
        target_line = (
            "\U0001f310 Target: <i>no domain yet \u2014 only asked if "
            "you pick Cookies or Combo (targeted)</i>"
        )
    else:
        domain_label = (
            domains[0] if len(domains) == 1
            else f"{len(domains)} domains"
        )
        target_line = f"\U0001f310 Target: <code>{domain_label}</code>"
    return (
        f"\u2699\ufe0f <b>Output format</b>\n"
        f"{target_line}\n\n"
        f"Pick one or more formats. Toggle each on/off, then tap "
        f"<b>Done</b>. You can mix cookies with credential exports — "
        f"the archive is only scanned once.\n\n"
        f"\u2022 <b>Cookies</b> \u2014 Netscape <code>.txt</code> per "
        f"target domain (needs domain)\n"
        f"\u2022 <b>ULP</b> \u2014 every <code>url:user:pass</code> in "
        f"the logs, deduped\n"
        f"\u2022 <b>Combo (targeted)</b> \u2014 <code>user:pass</code> "
        f"for the target domain(s) only (needs domain)\n"
        f"\u2022 <b>Combo (full)</b> \u2014 <code>user:pass</code> "
        f"grouped by host, every domain in the logs\n"
        f"\u2022 <b>CC</b> \u2014 Luhn-valid card dumps\n"
        f"\u2022 <b>Loot</b> \u2014 tdata (Telegram sessions), Discord "
        f"tokens, Steam accounts"
    )


def _mode_picker_kb(
    selected: "set[str]",
    domains: List[str],
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for mode_id, label, emoji in _MODE_BUTTONS:
        mark = "\u2705" if mode_id in selected else "\u2b1c"
        rows.append([
            InlineKeyboardButton(
                f"{mark} {emoji} {label}",
                callback_data=f"mode_toggle:{mode_id}",
            ),
        ])
    rows.append([
        InlineKeyboardButton(
            "\u2705 Done \u2192 send archive", callback_data="mode_done",
        ),
    ])
    rows.append([
        InlineKeyboardButton("\u274c Cancel", callback_data="extract_cancel"),
    ])
    return InlineKeyboardMarkup(rows)


async def mode_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Flip one output-mode checkbox on or off."""
    q = update.callback_query
    if q is None or q.data is None:
        return MODE
    await q.answer()
    mode_id = q.data.split(":", 1)[1] if ":" in q.data else ""
    if mode_id not in {m for m, _, _ in _MODE_BUTTONS}:
        return MODE
    selected: set = context.user_data.get("extract_modes") or {COOKIE_MODE}  # type: ignore[union-attr,assignment]
    if mode_id in selected:
        selected.discard(mode_id)
    else:
        selected.add(mode_id)
    context.user_data["extract_modes"] = selected  # type: ignore[index]
    domains: list[str] = context.user_data.get("extract_domains", [])  # type: ignore[union-attr]
    try:
        await q.edit_message_reply_markup(
            reply_markup=_mode_picker_kb(selected, domains),
        )
    except Exception:
        pass
    return MODE


async def mode_done(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """User finished picking output modes — move on to the FILE state.

    If at least one domain-dependent mode was selected (cookies or
    combo-targeted) and the user hasn't provided a real domain yet,
    bounce back to the DOMAIN state. Everything else (loot, CC, ULP,
    combo-full) proceeds straight to FILE.
    """
    q = update.callback_query
    user = update.effective_user
    if q is None or user is None:
        return MODE
    await q.answer()

    selected: set = context.user_data.get("extract_modes") or set()  # type: ignore[union-attr,assignment]
    if not selected:
        try:
            await q.answer(
                "Pick at least one format first.", show_alert=True,
            )
        except Exception:
            pass
        return MODE

    domains: list[str] = context.user_data.get("extract_domains", [])  # type: ignore[union-attr]
    has_real_domain = bool(
        domains and domains[0] != _DEFAULT_PLACEHOLDER_DOMAIN,
    )
    needs_domain = bool(selected & {COOKIE_MODE, COMBO_TARGETED_MODE})
    if needs_domain and not has_real_domain:
        # Stash the picked modes so domain_received can pick up where
        # we left off without re-showing the picker.
        context.user_data["extract_modes_locked"] = True  # type: ignore[index]
        labels = ", ".join(
            label
            for mid, label, _emoji in _MODE_BUTTONS
            if mid in selected
        )
        text = (
            "\U0001f310 <b>Target domain needed</b>\n"
            f"You picked: <b>{labels}</b>\n"
            "Enter one or more domains (comma/space separated) to filter "
            f"cookies / targeted combos.\n"
            f"Up to {config.MAX_DOMAINS_PER_EXTRACT} domains."
        )
        try:
            await q.edit_message_text(
                text, reply_markup=_cancel_kb(), parse_mode="HTML",
            )
        except Exception:
            if update.effective_chat is not None:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=text,
                    reply_markup=_cancel_kb(),
                    parse_mode="HTML",
                )
        return DOMAIN

    # Domain-independent selection → drop the placeholder so output
    # files aren't named "logs_*".
    if not has_real_domain:
        context.user_data["extract_domains"] = []  # type: ignore[index]
        context.user_data.pop("extract_domain", None)  # type: ignore[union-attr]
        domains = []

    text = await _build_file_prompt(user.id, domains, selected)
    try:
        await q.edit_message_text(text, reply_markup=_cancel_kb())
    except Exception:
        # Fallback to a new message if the inline edit failed (rare).
        if update.effective_chat is not None:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=text,
                reply_markup=_cancel_kb(),
            )
    return FILE


# ── Rescan entry / job kickoff ─────────────────────────────
async def rescan_entry(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Conversation entry triggered by the 'Search more domains' button."""
    user = update.effective_user
    q = update.callback_query
    if user is None or q is None:
        return ConversationHandler.END

    await q.answer()
    entry = _peek_rescan(user.id)
    if entry is None:
        try:
            await q.edit_message_text(
                "\u23f0 Rescan window closed \u2014 the archive was already "
                "deleted.\nUse /extract to upload a new archive.",
            )
        except Exception:
            pass
        return ConversationHandler.END

    remaining = max(0, int(entry.expires_at - time.monotonic()))
    mins, secs = divmod(remaining, 60)
    text = (
        f"\U0001f501 Rescan: <code>{entry.file_name}</code>\n"
        f"\u23f3 {mins}m {secs}s left before this archive is deleted.\n\n"
        f"Enter one or more domains to search in the same archive.\n"
        f"Up to {config.MAX_DOMAINS_PER_EXTRACT} domains, separated by "
        f"commas, spaces or new lines."
    )
    try:
        await q.edit_message_text(
            text, parse_mode="HTML", reply_markup=_cancel_kb(),
        )
    except Exception:
        pass

    context.user_data["extract_rescan"] = True  # type: ignore[index]
    return DOMAIN


async def _kickoff_rescan_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    entry: RescanEntry,
    domains: list[str],
) -> None:
    """Enqueue a rescan job that reuses *entry*'s cached archive."""
    user = update.effective_user
    assert user is not None and update.message is not None

    is_admin = user.id == config.ADMIN_ID
    vip = await db.is_vip(user.id)
    domain_label = ", ".join(domains)

    # Rescans don't consume daily quota — the archive bytes were
    # already counted against the user when they originally uploaded
    # it. They still go through the priority queue.
    job_id = await db.create_job(
        user.id, domain_label, entry.file_name, entry.file_size,
    )

    progress_msg = await update.message.reply_text(
        "\u23f3 Queued for rescan...",
        reply_markup=_cancel_job_kb(job_id),
    )

    progress = ExtractionProgress()
    _active_progress[job_id] = progress

    # Rescan reuses whatever output modes the user picked on the
    # ORIGINAL extraction. Falls back to cookies-only for older rescan
    # entries that pre-date this field.
    modes = frozenset(
        getattr(entry, "output_modes", None) or {COOKIE_MODE},
    )

    async def _worker() -> None:
        await _process_job(
            update, context, job_id, user.id, domains,
            ("rescan", entry.archive_path, entry.file_name),
            progress_msg, progress,
            output_modes=modes,
        )

    item = QueueItem(
        priority=priority_for(is_admin, vip),
        job_id=job_id,
        user_id=user.id,
        is_vip=vip,
        coro_factory=_worker,
    )
    assert _job_queue is not None
    pos = await _job_queue.enqueue(item)
    if pos > 0:
        await progress_msg.edit_text(
            f"\u23f3 You are #{pos + 1} in queue (rescan).\n"
            f"Estimated wait: ~{pos * 4} minutes",
            reply_markup=_cancel_job_kb(job_id),
        )


# ── State: FILE ────────────────────────────────────────────
async def file_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Validate file, check quota, enqueue job."""
    user = update.effective_user
    if user is None or update.message is None:
        return ConversationHandler.END

    doc = update.message.document
    if doc is None:
        await update.message.reply_text(
            "\u274c Please send an archive file.", reply_markup=_cancel_kb()
        )
        return FILE

    # Validate file type
    valid, ext_or_err = validate_archive(doc.file_name, doc.mime_type)
    if not valid:
        await update.message.reply_text(f"\u274c {ext_or_err}", reply_markup=_cancel_kb())
        return FILE

    file_size = doc.file_size or 0
    is_admin = user.id == config.ADMIN_ID
    vip = await db.is_vip(user.id)

    # Max file size check (admin bypasses)
    if not is_admin:
        max_bytes = config.VIP_MAX_FILE_BYTES if vip else config.FREE_MAX_FILE_BYTES
        if file_size > max_bytes:
            await update.message.reply_text(
                f"\u274c File too large ({bytes_human(file_size)}).\n"
                f"Max: {bytes_human(max_bytes)}\n\n"
                "\U0001f451 Get VIP for higher limits!",
                reply_markup=_cancel_kb(),
            )
            return FILE

    # Quota check (admin bypasses)
    if not is_admin:
        remaining = await db.get_remaining_quota(user.id)
        if remaining != -1 and file_size > remaining:
            await update.message.reply_text(
                f"\u274c Daily quota exceeded!\n"
                f"Used: {bytes_human(config.FREE_DAILY_LIMIT_BYTES - remaining)} / "
                f"{bytes_human(config.FREE_DAILY_LIMIT_BYTES)}\n"
                f"Resets in: {time_until((await db.get_user(user.id))['daily_reset_at'])}\n\n"  # type: ignore[index]
                "\U0001f451 Get VIP for unlimited access!",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("\U0001f451 Get VIP", callback_data="getvip")],
                    [InlineKeyboardButton("\u274c Cancel", callback_data="extract_cancel")],
                ]),
            )
            return ConversationHandler.END

    domains: list[str] = context.user_data.get(  # type: ignore[union-attr]
        "extract_domains",
        [context.user_data.get("extract_domain", "unknown")],  # type: ignore[union-attr]
    )
    if not domains:
        domains = ["unknown"]
    # Comma-joined string is what we persist in the DB ``jobs.domain`` column
    # and what we display back to the user in legacy summaries.
    domain_label = ", ".join(domains)

    # Consume quota (no-op for admin)
    if not is_admin:
        await db.consume_quota(user.id, file_size)

    # Create DB job
    job_id = await db.create_job(
        user.id, domain_label, doc.file_name or "archive", file_size,
    )

    # Send initial progress message
    progress_msg = await update.message.reply_text(
        "\u23f3 Queued for processing...",
        reply_markup=_cancel_job_kb(job_id),
    )

    # Build the async worker
    progress = ExtractionProgress()
    _active_progress[job_id] = progress

    source_ref = update.message  # Telegram document source

    modes = frozenset(
        context.user_data.get("extract_modes") or {COOKIE_MODE},  # type: ignore[union-attr]
    )

    async def _worker() -> None:
        await _process_job(
            update, context, job_id, user.id, domains,
            source_ref, progress_msg, progress,
            output_modes=modes,
        )

    # Enqueue with three-tier priority (admin > VIP > free).
    is_vip_flag = await db.is_vip(user.id)
    item = QueueItem(
        priority=priority_for(is_admin, is_vip_flag),
        job_id=job_id,
        user_id=user.id,
        is_vip=is_vip_flag,
        coro_factory=_worker,
    )
    assert _job_queue is not None
    pos = await _job_queue.enqueue(item)

    if pos > 0:
        await progress_msg.edit_text(
            f"\u23f3 You are #{pos + 1} in queue.\n"
            f"Estimated wait: ~{pos * 4} minutes",
            reply_markup=_cancel_job_kb(job_id),
        )

    return ConversationHandler.END


_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)


async def url_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Accept a direct download URL in the FILE state as an alternative
    to uploading a document. The URL is downloaded by the queue worker;
    we just enqueue the job here.
    """
    user = update.effective_user
    if user is None or update.message is None:
        return FILE

    raw = (update.message.text or "").strip()
    if not _URL_RE.match(raw):
        await update.message.reply_text(
            "\u274c That doesn't look like a direct URL.\n"
            "Send an archive (.zip / .rar / .7z / .tar.* / \u2026) or a "
            "plain log (.txt / .log / .csv / \u2026) URL.",
            reply_markup=_cancel_kb(),
        )
        return FILE

    # Basic extension sanity check (HEAD probe is done by the worker).
    # The validator already knows the full whitelist (archives, plain
    # logs, multi-volume parts) so just defer to it.
    lower = raw.split("?", 1)[0].lower()
    ok, _ = validate_archive(lower, None)
    if not ok:
        # Not fatal — CDN redirects often have no extension. Just warn.
        logger.info("URL has no recognised extension, trusting server: {}", raw)

    is_admin = user.id == config.ADMIN_ID
    vip = await db.is_vip(user.id)
    domains: list[str] = context.user_data.get(  # type: ignore[union-attr]
        "extract_domains",
        [context.user_data.get("extract_domain", "unknown")],  # type: ignore[union-attr]
    )
    if not domains:
        domains = ["unknown"]
    domain_label = ", ".join(domains)

    # Assume unknown size for URLs; the worker will enforce caps against
    # the real content-length it sees during download.
    file_name = raw.split("?")[0].rstrip("/").split("/")[-1] or "archive"
    job_id = await db.create_job(user.id, domain_label, file_name, 0)

    progress_msg = await update.message.reply_text(
        "\u23f3 Queued for download...",
        reply_markup=_cancel_job_kb(job_id),
    )

    progress = ExtractionProgress()
    _active_progress[job_id] = progress

    modes = frozenset(
        context.user_data.get("extract_modes") or {COOKIE_MODE},  # type: ignore[union-attr]
    )

    async def _worker() -> None:
        await _process_job(
            update, context, job_id, user.id, domains,
            ("url", raw, file_name), progress_msg, progress,
            output_modes=modes,
        )

    item = QueueItem(
        priority=priority_for(is_admin, vip),
        job_id=job_id,
        user_id=user.id,
        is_vip=vip,
        coro_factory=_worker,
    )
    assert _job_queue is not None
    pos = await _job_queue.enqueue(item)
    if pos > 0:
        await progress_msg.edit_text(
            f"\u23f3 You are #{pos + 1} in queue.\n"
            f"Estimated wait: ~{pos * 4} minutes",
            reply_markup=_cancel_job_kb(job_id),
        )

    return ConversationHandler.END


async def _process_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    job_id: int,
    user_id: int,
    domains: list[str],
    original_msg,
    progress_msg,
    progress: ExtractionProgress,
    output_modes: frozenset = frozenset({COOKIE_MODE}),
) -> None:
    """Download, extract, send results — runs inside the queue worker."""
    start_ts = time.monotonic()
    temp_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR))
    result = None  # set before try so finally can reference it safely
    domain_label = ", ".join(domains) if domains else "unknown"

    try:
        await db.update_job(job_id, status="processing", started_at=db._now())

        # Start progress updater
        updater_task = asyncio.create_task(
            _progress_updater(progress_msg, job_id, progress)
        )

        # Decide where the archive comes from. Three source kinds:
        #   1. Telegram document upload  (original_msg is the Message)
        #   2. Direct download URL       (tuple: ("url", url, name))
        #   3. Rescan of a cached archive (tuple: ("rescan", path, name))
        #
        # Case 3 skips both the download and the password prompt —
        # the archive is already on disk under the rescan store and
        # the original-extraction's password (if any) is cached on the
        # rescan entry.
        is_rescan = (
            isinstance(original_msg, tuple)
            and original_msg
            and original_msg[0] == "rescan"
        )
        if is_rescan:
            _, existing_path, _ = original_msg
            archive_path = existing_path
            cached_entry = _rescan_store.get(user_id)
            password = cached_entry.password if cached_entry else None
        elif (
            isinstance(original_msg, tuple)
            and original_msg
            and original_msg[0] == "url"
        ):
            _, url_value, name_hint = original_msg
            archive_path = await download_from_url(
                url_value,
                temp_dir,
                progress,
                file_name_hint=name_hint,
                status_msg=progress_msg,
                cancel_kb=_cancel_job_kb(job_id),
            )
            password = await _maybe_prompt_for_password(
                context, user_id, archive_path, progress_msg, job_id,
                progress,
            )
        else:
            archive_path = await download_file(
                original_msg,
                temp_dir,
                progress,
                status_msg=progress_msg,
                cancel_kb=_cancel_job_kb(job_id),
            )
            password = await _maybe_prompt_for_password(
                context, user_id, archive_path, progress_msg, job_id,
                progress,
            )

        # Password-cancel sentinel: caller asked us to abort the whole
        # job because the user didn't reply to the password prompt
        # within the timeout (or burned all retries).
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

        # Extract — pass the user-selected output modes so the same
        # archive can produce cookies + ULP + combo files in one pass.
        result = await run_extraction_async(
            archive_path, domains, progress, password=password,
            output_modes=output_modes,
        )

        if not updater_task.done():
            updater_task.cancel()
            try:
                await updater_task
            except asyncio.CancelledError:
                pass

        # Hard failure (no partial output to ship).
        if not result.success and not result.output_files:
            duration = time.monotonic() - start_ts
            await db.update_job(
                job_id,
                status="cancelled" if result.partial else "failed",
                error_message=result.error,
                completed_at=db._now(),
                duration_seconds=duration,
            )
            await progress_msg.edit_text(
                ("\u26a0\ufe0f Cancelled: " if result.partial else "\u274c Extraction failed: ")
                + (result.error or "unknown error"),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("\U0001f50d Try Again", callback_data="extract"),
                     InlineKeyboardButton("\U0001f3e0 Home", callback_data="home")],
                ]),
            )
            # Only ping the admin for code-bug-shaped failures. Bad
            # archives, non-UTF8 filenames, disk-full, wrong passwords, …
            # all set ``recoverable=True`` and don't need a critical alert.
            if not result.partial and not getattr(result, "recoverable", False):
                _notify_admin_error(context, user_id, "extraction", result.error)
            return

        # Update DB — success path (or cancelled with partial output)
        duration = time.monotonic() - start_ts
        await db.update_job(
            job_id,
            status="cancelled" if result.partial else "done",
            cookies_found=result.cookies_found,
            files_scanned=result.files_scanned,
            completed_at=db._now(),
            duration_seconds=duration,
            error_message="Cancelled \u2014 partial results" if result.partial else None,
        )
        await db.increment_user_stats(
            user_id, result.cookies_found,
            (await db.get_job(job_id))["file_size_bytes"],  # type: ignore[index]
        )

        # Send result files (Bot API for <50 MB, Pyrogram for bigger)
        result_caption = (
            "\u26a0\ufe0f Partial results (job cancelled)"
            if result.partial else None
        )
        for fpath in result.output_files:
            await send_result_file(
                context, user_id, fpath,
                caption=result_caption,
                status_msg=progress_msg,
            )

        # ── Loot add-on: if LOOT_MODE was selected in the mix picker,
        # run the loot extractor on the same archive and send its
        # results alongside the normal cookie/credential output.
        # Important: when the user *also* picked ULP / combo / CC
        # modes those credentials are already covered by the main
        # extractor — so the loot pipeline only scans the
        # tdata / Discord / Steam buckets. Otherwise the user would
        # get duplicated (and possibly differently formatted) password
        # dumps inside loot_results.zip.
        if LOOT_MODE in output_modes and archive_path and os.path.exists(archive_path):
            try:
                from services.loot_extractor import (
                    LOOT_DISCORD,
                    LOOT_PASSWORDS,
                    LOOT_STEAM,
                    LOOT_TDATA,
                )

                loot_buckets: frozenset[str] = frozenset(
                    {LOOT_TDATA, LOOT_DISCORD, LOOT_STEAM},
                )
                # Honour an explicit override from /loot (if a user
                # somehow lands here with one) but default to the
                # no-passwords set above for the mix flow.
                pre_buckets = context.user_data.get(  # type: ignore[union-attr]
                    "loot_buckets"
                ) if hasattr(context, "user_data") else None
                if pre_buckets:
                    loot_buckets = frozenset(pre_buckets)
                else:
                    # If user explicitly asked for ULP/combo password
                    # dumps from the main extractor, drop them from the
                    # loot zip to avoid duplicates.
                    if output_modes & ALL_CREDENTIAL_MODES:
                        loot_buckets = loot_buckets - {LOOT_PASSWORDS}

                loot_settings = LootExtractionConfig(
                    target_domains=list(domains) if domains else [],
                    validate=config.LOOT_VALIDATE,
                    buckets=loot_buckets,
                )
                loot_er, loot_lr = await run_loot_extraction_async(
                    archive_path, progress, loot_settings,
                    password=password,
                )
                for fpath in (loot_er.output_files or []):
                    await send_result_file(
                        context, user_id, fpath,
                        caption="\U0001f4e6 Loot results (from mix mode)",
                        status_msg=progress_msg,
                    )
            except Exception:
                logger.exception("Loot add-on failed for job {}", job_id)

        job_row = await db.get_job(job_id)
        file_size = job_row["file_size_bytes"] if job_row else 0  # type: ignore[index]

        # Stash this archive in the rescan store so the user can search
        # additional domains in the same archive without re-uploading.
        # Only do this for clean (non-partial) successes — partial /
        # cancelled jobs probably failed for a reason and the archive
        # may be corrupt.
        rescan_armed = False
        rescan_minutes = max(1, config.RESCAN_WINDOW_SECONDS // 60)
        try:
            if result.success and not result.partial and archive_path:
                if is_rescan:
                    # Already in the rescan dir — just refresh the timer.
                    if os.path.exists(archive_path):
                        cached_entry = _rescan_store.get(user_id)
                        cached_pw = cached_entry.password if cached_entry else None
                        cached_name = (
                            cached_entry.file_name if cached_entry
                            else os.path.basename(archive_path)
                        )
                        cached_size = (
                            cached_entry.file_size if cached_entry
                            else os.path.getsize(archive_path)
                        )
                        if cached_size <= config.RESCAN_MAX_ARCHIVE_BYTES:
                            _register_rescan(
                                user_id,
                                archive_path,
                                cached_name,
                                cached_size,
                                float(config.RESCAN_WINDOW_SECONDS),
                                password=cached_pw,
                                output_modes=output_modes,
                            )
                            rescan_armed = True
                elif os.path.exists(archive_path):
                    target_dir = _rescan_dir()
                    target_name = (
                        f"{user_id}_{job_id}_{os.path.basename(archive_path)}"
                    )
                    archive_size = os.path.getsize(archive_path)
                    if archive_size <= config.RESCAN_MAX_ARCHIVE_BYTES:
                        target_path = os.path.join(target_dir, target_name)
                        shutil.move(archive_path, target_path)
                        _register_rescan(
                            user_id,
                            target_path,
                            os.path.basename(archive_path),
                            os.path.getsize(target_path),
                            float(config.RESCAN_WINDOW_SECONDS),
                            password=password,
                            output_modes=output_modes,
                        )
                        rescan_armed = True
                    else:
                        logger.info(
                            "Skipping rescan cache for {} ({} bytes > {} bytes)",
                            archive_path, archive_size, config.RESCAN_MAX_ARCHIVE_BYTES,
                        )
        except Exception:
            logger.exception(
                "Failed to register rescan window for user {}", user_id,
            )
            rescan_armed = False

        # Summary
        header = (
            "\u26a0\ufe0f Cancelled \u2014 partial results delivered"
            if result.partial else "\u2705 Extraction Complete!"
        )
        if len(domains) == 1:
            domain_lines = f"\U0001f310 Domain: {domains[0]}\n"
        else:
            domain_lines = (
                f"\U0001f310 Domains ({len(domains)}): "
                f"{', '.join(domains)}\n"
            )
            counts = result.per_domain_counts or {}
            for d in domains:
                domain_lines += f"   \u2022 {d}: {counts.get(d, 0):,}\n"
        summary = (
            f"{header}\n\n"
            f"{domain_lines}"
        )
        if COOKIE_MODE in output_modes:
            summary += (
                f"\U0001f36a Cookies found: {result.cookies_found:,}\n"
            )
        # Per-credential-mode totals (only show what was requested).
        cred_counts = getattr(result, "credential_counts", {}) or {}
        if ULP_MODE in output_modes:
            summary += (
                f"\U0001f4dd ULP lines: {cred_counts.get(ULP_MODE, 0):,}\n"
            )
        if COMBO_TARGETED_MODE in output_modes:
            summary += (
                f"\U0001f3af Combo (targeted): "
                f"{cred_counts.get(COMBO_TARGETED_MODE, 0):,}\n"
            )
        if COMBO_FULL_MODE in output_modes:
            summary += (
                f"\U0001f4e6 Combo (full): "
                f"{cred_counts.get(COMBO_FULL_MODE, 0):,}\n"
            )
        if CC_MODE in output_modes:
            summary += (
                f"\U0001f4b3 CC (Luhn-valid): "
                f"{cred_counts.get(CC_MODE, 0):,}\n"
            )
        summary += (
            f"\U0001f4c1 Files scanned: {result.files_scanned:,}\n"
            f"\U0001f4e6 Archive size: {bytes_human(file_size)}\n"
            f"\u23f1 Time taken: {seconds_human(duration)}\n"
            f"\U0001f4c4 Output files: {len(result.output_files)}\n"
        )
        if rescan_armed:
            summary += (
                f"\n\u23f0 Heads up: this archive will be auto-deleted from "
                f"disk in {rescan_minutes} minute(s).\n"
                f"Missed a domain? Tap \U0001f501 below within "
                f"{rescan_minutes} minute(s) to search more domains in the "
                f"SAME archive without re-uploading.\n"
            )
        summary += "\n\U0001f338 Credits: @akaza_isnt"

        keyboard: list[list[InlineKeyboardButton]] = []
        if rescan_armed:
            keyboard.append([
                InlineKeyboardButton(
                    f"\U0001f501 Search more domains ({rescan_minutes} min)",
                    callback_data="rescan_more",
                ),
            ])
        keyboard.append([
            InlineKeyboardButton(
                "\U0001f50d Extract Again", callback_data="extract",
            ),
            InlineKeyboardButton(
                "\U0001f4ca My Stats", callback_data="mystats",
            ),
        ])
        keyboard.append([
            InlineKeyboardButton("\U0001f3e0 Home", callback_data="home"),
        ])
        await progress_msg.edit_text(
            summary,
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    except Exception as exc:
        logger.exception("Job {} failed unexpectedly", job_id)
        await db.update_job(
            job_id, status="failed", error_message=str(exc),
            completed_at=db._now(),
            duration_seconds=time.monotonic() - start_ts,
        )
        try:
            await progress_msg.edit_text(f"\u274c Error: {exc}")
        except Exception:
            pass
        _notify_admin_error(context, user_id, "job processing", str(exc))
    finally:
        _active_progress.pop(job_id, None)
        shutil.rmtree(temp_dir, ignore_errors=True)
        # Clean output dir created by the extractor
        if result and result.output_files:
            for fpath in result.output_files:
                parent = os.path.dirname(fpath)
                if parent and os.path.isdir(parent):
                    shutil.rmtree(parent, ignore_errors=True)
                    break  # all chunks share the same output dir


def _password_prompt_kb(job_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton(
            "\u23ed Skip encrypted", callback_data=f"skip_pw_{job_id}"
        ),
        InlineKeyboardButton(
            "\u274c Cancel Job", callback_data=f"cancel_job_{job_id}"
        ),
    ]])


def _escape_pw(value: str) -> str:
    """HTML-escape a password fragment for safe rendering inside <code>."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_password_prompt(
    encrypted: List[str],
    attempt: int,
    last_failed: Optional[str],
    timeout_secs: int,
    current_guess: str = "",
    tried_guesses: Optional[List[str]] = None,
) -> str:
    """Format the in-chat password prompt text.

    The first-attempt prompt leads with a one-line **"file is encrypted,
    please send the password"** call to action so it's obvious to the
    user what to do; the auto-guess status is mentioned underneath.
    Retries lead with the failed password instead.

    When *current_guess* / *tried_guesses* are populated, the prompt
    also lists the password the bot is currently testing in the
    background plus the last few candidates it has already ruled out,
    so the user can see exactly what's been tried.
    """
    sample = ", ".join(encrypted[:3])
    if len(encrypted) > 3:
        sample += f", +{len(encrypted) - 3} more"

    if attempt == 1:
        header = (
            "\U0001f510 <b>File is encrypted with a password.</b>\n"
            "Please send the password as a chat message."
        )
        body = (
            f"\u2139\ufe0f {len(encrypted)} locked file(s) inside: "
            f"<code>{sample}</code>\n"
            "Meanwhile I'm also trying common passwords in the "
            "background — whichever finishes first wins."
        )
    else:
        last_safe = _escape_pw(last_failed or "")
        header = (
            f"\u274c Password <code>{last_safe}</code> didn't work."
        )
        body = (
            f"Send another password "
            f"(attempt {attempt}/{PASSWORD_MAX_ATTEMPTS}), or tap Skip "
            "to extract only the unencrypted files."
        )

    parts = [header, "", body]
    # Live auto-guess feedback so the user can see which passwords have
    # already been ruled out without re-typing them.
    tried = [t for t in (tried_guesses or []) if t]
    if current_guess or tried:
        parts.append("")
        if current_guess:
            parts.append(
                "\U0001f50d Currently testing: "
                f"<code>{_escape_pw(current_guess)}</code>"
            )
        if tried:
            shown = tried[-6:]
            joined = ", ".join(f"<code>{_escape_pw(t)}</code>" for t in shown)
            parts.append(f"Already tried: {joined}")
    parts.append("")
    parts.append(f"\u23f1 Auto-cancel in <b>{timeout_secs} s</b> if no reply.")
    return "\n".join(parts)


async def _wait_for_password_or_guess(
    user_id: int,
    guess_task: "asyncio.Task[Optional[str]]",
    timeout: float,
) -> "tuple[str, Optional[str]]":
    """Race three signals over a *timeout*-second window:

    - The catch-all chat handler resolves the user's pending future
      with their typed password (or ``None`` for ``/skip``).
    - The background ``guess_task`` finishes with an auto-detected
      password (or ``None`` if the candidate list exhausted).
    - The wall-clock timeout elapses.

    Returns one of:

    - ``("guess", password)``  — auto-guess hit; use it.
    - ``("user", password)``   — user typed *password*.
    - ``("user", None)``       — user pressed Skip / typed ``/skip``.
    - ``("timeout", None)``    — no reply within *timeout* seconds.
    """
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[Optional[str]] = loop.create_future()
    prev = _pending_passwords.get(user_id)
    if prev is not None and not prev.done():
        prev.cancel()
    _pending_passwords[user_id] = fut

    try:
        # Fast-path: auto-guess might already be done from a previous
        # iteration. If it returned a hit, take it immediately.
        if guess_task.done():
            try:
                hit = guess_task.result()
            except Exception:
                hit = None
            if hit is not None:
                fut.cancel()
                return ("guess", hit)

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout", None)
            wait_targets: "set[asyncio.Future]" = {fut}
            if not guess_task.done():
                wait_targets.add(guess_task)
            done, _pending = await asyncio.wait(
                wait_targets,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                return ("timeout", None)

            if guess_task in done:
                try:
                    hit = guess_task.result()
                except Exception:
                    hit = None
                if hit is not None:
                    if not fut.done():
                        fut.cancel()
                    return ("guess", hit)
                # Auto-guess exhausted with None — keep waiting for
                # the user's typed password until the deadline.

            if fut in done:
                try:
                    user_pw = fut.result()
                except (asyncio.CancelledError, Exception):
                    return ("timeout", None)
                return ("user", user_pw)
    finally:
        # Always drop our slot so a stray future doesn't trap a later
        # password reply for a different job.
        if _pending_passwords.get(user_id) is fut:
            _pending_passwords.pop(user_id, None)


async def _maybe_prompt_for_password(
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    archive_path: str,
    progress_msg,
    job_id: int,
    progress: Optional[ExtractionProgress] = None,
):
    """Probe *archive_path* for encrypted entries. If any exist:

    - Kicks off the common-password auto-guess in the background.
    - Immediately prompts the user to type the archive password,
      with a visible 60-second auto-cancel timer.
    - If the user replies, we test their password right away (we don't
      keep walking the common-password list — fast feedback wins).
    - If their password fails, we re-prompt and the 60-second timer
      restarts (up to ``PASSWORD_MAX_ATTEMPTS`` retries).
    - If the auto-guess hits before the user types anything, we use it.
    - If the user doesn't reply within 60 s, the job is cancelled.

    Returns one of:

    - ``str``                  — password to use for extraction.
    - ``None``                 — extract only the unencrypted entries
                                 (user pressed Skip).
    - ``PASSWORD_CANCEL``      — timed out; caller should abort the job.
    """
    # Flip into the awaiting_password phase BEFORE we do anything else
    # so the dashboard updater stops rewriting the chat message every
    # 2 s — otherwise it keeps repainting the "Downloading 100% complete"
    # template on top of our password prompt and the user never gets a
    # chance to read it. We restore the previous phase in `finally` if
    # the archive turns out not to be encrypted.
    prev_phase: Optional[str] = None
    if progress is not None:
        prev_phase = progress.phase
        progress.phase = "awaiting_password"

    try:
        encrypted = await probe_encrypted_entries_async(archive_path)
    except Exception:
        logger.exception("Password probe failed on {}", archive_path)
        if progress is not None and prev_phase is not None:
            progress.phase = prev_phase
        return None

    if not encrypted:
        if progress is not None and prev_phase is not None:
            progress.phase = prev_phase
        return None

    # Reset live-attempt fields before kicking off the auto-guess so
    # the prompt starts empty and only fills with what *this* job has
    # attempted.
    if progress is not None:
        progress.current_password_attempt = ""
        progress.password_attempts.clear()

    # Background auto-guess. Runs concurrently with the user prompt;
    # we cancel it as soon as we have a winning password from either
    # source. Hands ``progress`` to the guesser so it can stream the
    # password it's currently testing back to the chat prompt.
    guess_task: "asyncio.Task[Optional[str]]" = asyncio.create_task(
        guess_archive_password_async(archive_path, progress),
        name=f"guess_pw_{job_id}",
    )

    def _snapshot_attempts() -> tuple[str, List[str]]:
        if progress is None:
            return "", []
        return (
            progress.current_password_attempt,
            list(progress.password_attempts),
        )

    try:
        last_failed: Optional[str] = None
        for attempt in range(1, PASSWORD_MAX_ATTEMPTS + 1):
            timeout_secs = int(PASSWORD_PROMPT_TIMEOUT)
            current_guess, tried_guesses = _snapshot_attempts()
            prompt_text = _build_password_prompt(
                encrypted, attempt, last_failed, timeout_secs,
                current_guess=current_guess,
                tried_guesses=tried_guesses,
            )
            last_prompt_text = prompt_text
            try:
                await progress_msg.edit_text(
                    prompt_text,
                    parse_mode="HTML",
                    reply_markup=_password_prompt_kb(job_id),
                )
            except Exception:
                logger.exception(
                    "Failed to edit progress msg for password prompt",
                )

            # Race the user/guess wait against a periodic prompt
            # refresh so the "currently testing"/"already tried" lines
            # update live without spamming Telegram with edits.
            wait_task = asyncio.create_task(
                _wait_for_password_or_guess(
                    user_id, guess_task, PASSWORD_PROMPT_TIMEOUT,
                ),
                name=f"pw_wait_{job_id}_{attempt}",
            )
            try:
                while True:
                    refresh_done, _pending = await asyncio.wait(
                        {wait_task}, timeout=2.0,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if wait_task in refresh_done:
                        break
                    new_guess, new_tried = _snapshot_attempts()
                    new_prompt = _build_password_prompt(
                        encrypted, attempt, last_failed, timeout_secs,
                        current_guess=new_guess,
                        tried_guesses=new_tried,
                    )
                    if new_prompt != last_prompt_text:
                        last_prompt_text = new_prompt
                        try:
                            await progress_msg.edit_text(
                                new_prompt,
                                parse_mode="HTML",
                                reply_markup=_password_prompt_kb(job_id),
                            )
                        except Exception:
                            # Telegram rejects identical-text edits and
                            # other transient errors are harmless here.
                            pass
                kind, value = wait_task.result()
            except asyncio.CancelledError:
                wait_task.cancel()
                raise

            if kind == "timeout":
                logger.info(
                    "Password prompt timed out for user {} job {} after "
                    "attempt {}; cancelling job.",
                    user_id, job_id, attempt,
                )
                try:
                    await progress_msg.edit_text(
                        "\u23f1 No password received within "
                        f"{int(PASSWORD_PROMPT_TIMEOUT)}s \u2014 "
                        "cancelling job.",
                        reply_markup=None,
                    )
                except Exception:
                    pass
                return PASSWORD_CANCEL

            if kind == "guess":
                logger.info(
                    "Auto-guess hit for user {} job {}: using detected pw",
                    user_id, job_id,
                )
                try:
                    await progress_msg.edit_text(
                        "\U0001f513 Password auto-detected \u2014 "
                        "extracting\u2026",
                        reply_markup=_cancel_job_kb(job_id),
                    )
                except Exception:
                    pass
                return value  # the password string

            # kind == "user"
            user_pw = value
            if user_pw is None:
                # Skip pressed.
                try:
                    await progress_msg.edit_text(
                        "\u23ed Skipping encrypted entries \u2014 "
                        "extracting the rest\u2026",
                        reply_markup=_cancel_job_kb(job_id),
                    )
                except Exception:
                    pass
                return None

            # Test the user's password immediately. We do NOT keep
            # walking the common-password list at this point — the
            # user's input is more reliable than guessing.
            try:
                await progress_msg.edit_text(
                    "\U0001f50d Testing your password\u2026",
                    reply_markup=_cancel_job_kb(job_id),
                )
            except Exception:
                pass
            try:
                ok = await try_archive_password_async(archive_path, user_pw)
            except Exception:
                logger.exception(
                    "Manual password test crashed on {}", archive_path,
                )
                ok = False
            if ok:
                try:
                    await progress_msg.edit_text(
                        "\U0001f511 Password accepted \u2014 extracting\u2026",
                        reply_markup=_cancel_job_kb(job_id),
                    )
                except Exception:
                    pass
                return user_pw

            # Wrong password — loop and re-prompt with fresh 60s timer.
            last_failed = user_pw

        # Out of retries.
        logger.info(
            "Password retries exhausted for user {} job {}; cancelling.",
            user_id, job_id,
        )
        try:
            await progress_msg.edit_text(
                f"\u274c Password failed {PASSWORD_MAX_ATTEMPTS} times "
                "\u2014 cancelling job.",
                reply_markup=None,
            )
        except Exception:
            pass
        return PASSWORD_CANCEL
    finally:
        if not guess_task.done():
            guess_task.cancel()
        # Hand control back to the dashboard updater. We restore the
        # phase the caller had us in (typically "downloading", since
        # the prompt fires right after the download finishes); the
        # extractor will overwrite this to "extracting" the moment it
        # starts.
        if progress is not None and prev_phase is not None:
            progress.phase = prev_phase


async def password_reply(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fill a pending password request with the user's next text message."""
    user = update.effective_user
    if user is None or update.message is None:
        return
    fut = _pending_passwords.get(user.id)
    if fut is None or fut.done():
        return
    text = (update.message.text or "").strip()
    if not text:
        return
    # ``/skip`` as a plain word doubles as a shortcut to the skip flow.
    if text.lower() in ("/skip", "skip"):
        fut.set_result(None)
    else:
        fut.set_result(text)
    # Try to delete the message so the password doesn't linger in chat.
    try:
        await update.message.delete()
    except Exception:
        pass
    # Stop other handlers (e.g. an active /extract conversation state)
    # from also consuming the same message.
    raise ApplicationHandlerStop


async def skip_password_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Handle the inline 'Skip encrypted' button."""
    query = update.callback_query
    if query is None or update.effective_user is None:
        return
    await query.answer()
    fut = _pending_passwords.get(update.effective_user.id)
    if fut is not None and not fut.done():
        fut.set_result(None)


async def skip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /skip command as an alternative to the inline button."""
    if update.effective_user is None:
        return
    fut = _pending_passwords.get(update.effective_user.id)
    if fut is not None and not fut.done():
        fut.set_result(None)


def _format_loot_dashboard(progress: ExtractionProgress) -> str:
    """Compact per-bucket breakdown shown inside the live dashboard.

    Reads the optional ``loot_*`` fields on the progress object. Returns
    an empty string when no loot scan is in progress so the cookie /
    credential dashboards stay unchanged for users who don't use loot.
    """
    counts = getattr(progress, "loot_counts", {}) or {}
    valid_counts = getattr(progress, "loot_valid_counts", {}) or {}
    active = getattr(progress, "loot_bucket", "") or ""
    if not counts and not active:
        return ""
    bucket_emoji = {
        "tdata": "\U0001f4f1",
        "discord": "\U0001f3ae",
        "steam": "\U0001f3ae",
        "passwords": "\U0001f511",
    }
    lines: List[str] = ["\U0001f4e6 Loot scanners"]
    for name in ("tdata", "discord", "steam", "passwords"):
        if name not in counts and name != active:
            continue
        emoji = bucket_emoji.get(name, "\u2022")
        if name in counts:
            n = counts[name]
            extra = ""
            if name == "discord" and "discord" in valid_counts:
                extra = f" ({valid_counts['discord']} live)"
            elif name == "steam" and "steam" in valid_counts:
                extra = f" ({valid_counts['steam']} live)"
            done_mark = "\u2705"
            lines.append(
                f"   {emoji} {name:<10s} {done_mark} {n:,}{extra}"
            )
        else:
            lines.append(f"   {emoji} {name:<10s} \u23f3 running\u2026")
    val_total = getattr(progress, "loot_validate_total", 0) or 0
    val_done = getattr(progress, "loot_validate_done", 0) or 0
    if val_total:
        lines.append(
            f"   \U0001f6e1 Validating {val_done}/{val_total}"
        )
    return "\n".join(lines)


async def _progress_updater(msg, job_id: int, progress: ExtractionProgress) -> None:
    """Edit the progress message every few seconds with a live dashboard."""
    start = time.monotonic()
    last_text = ""
    while True:
        await asyncio.sleep(config.PROGRESS_UPDATE_INTERVAL)
        elapsed = time.monotonic() - start
        try:
            # While the extract handler is showing the password prompt
            # (and waiting up to 60 s for the user to reply), the
            # dashboard would otherwise repaint over the prompt every
            # 2 s and the user would never see what they're meant to
            # type. Stay completely silent during this phase.
            if progress.phase == "awaiting_password":
                continue
            # When the downloader is editing the live message itself
            # every ~2 MB, the dashboard would just race with it and
            # overwrite the user's preferred per-2MB format. Stay quiet.
            if progress.phase == "downloading" and progress.live_download_msg:
                continue
            if progress.phase == "downloading":
                pct = (
                    progress.download_current / max(progress.download_total, 1) * 100
                )
                dl_elapsed = (
                    time.monotonic() - progress.download_start
                    if progress.download_start else elapsed
                )
                speed = progress.download_current / max(dl_elapsed, 0.001)
                remaining_bytes = max(
                    progress.download_total - progress.download_current, 0
                )
                eta = remaining_bytes / max(speed, 1)
                text = (
                    f"\u2699\ufe0f Live Dashboard\n"
                    f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
                    f"\U0001f4e5 Downloading\n"
                    f"   {progress_bar(progress.download_current, progress.download_total)} {pct:.0f}%\n"
                    f"   {bytes_human(progress.download_current)} / "
                    f"{bytes_human(progress.download_total)}\n"
                    f"\U0001f4c8 Speed: {bytes_human(int(speed))}/s\n"
                    f"\u23f1 ETA: {seconds_human(eta)}   Elapsed: {seconds_human(elapsed)}"
                )
            elif progress.phase == "extracting":
                cur_file = progress.current_file or "…"
                if len(cur_file) > 40:
                    cur_file = cur_file[:37] + "…"
                if progress.extract_total > 0:
                    pct = (
                        progress.extract_current
                        / max(progress.extract_total, 1) * 100
                    )
                    bar = (
                        f"   {progress_bar(progress.extract_current, progress.extract_total)} "
                        f"{pct:.0f}% "
                        f"({progress.extract_current:,}/{progress.extract_total:,})\n"
                    )
                else:
                    bar = f"   Files extracted: {progress.extract_current:,}\n"
                text = (
                    f"\u2699\ufe0f Live Dashboard\n"
                    f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
                    f"\U0001f4e5 Download:  Done \u2705\n"
                    f"\U0001f4c2 Extracting\n"
                    f"{bar}"
                    f"   Now: {cur_file}\n"
                    f"\u23f1 Elapsed: {seconds_human(elapsed)}"
                )
            elif progress.phase == "scanning":
                cur_file = progress.current_file or "…"
                if len(cur_file) > 40:
                    cur_file = cur_file[:37] + "…"
                pct = (
                    progress.files_scanned
                    / max(progress.files_total, 1) * 100
                )
                rate = progress.files_scanned / max(elapsed, 0.001)
                eta = (
                    (progress.files_total - progress.files_scanned)
                    / max(rate, 0.001)
                    if progress.files_total else 0
                )
                loot_dash = _format_loot_dashboard(progress)
                text = (
                    f"\u2699\ufe0f Live Dashboard\n"
                    f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
                    f"\U0001f4e5 Download:  Done \u2705\n"
                    f"\U0001f4c2 Extract:   Done \u2705\n"
                    f"\U0001f50d Scanning\n"
                    f"   {progress_bar(progress.files_scanned, progress.files_total)} "
                    f"{pct:.0f}% ({progress.files_scanned:,}/{progress.files_total:,})\n"
                    f"   Now: {cur_file}\n"
                    f"\U0001f36a Cookies found so far: "
                    f"{progress.cookies_found:,}\n"
                    f"\U0001f4dd Credentials so far: "
                    f"{progress.credentials_found:,}\n"
                    f"\u26a1 Rate: {rate:.1f} files/s   ETA: {seconds_human(eta)}\n"
                    f"\u23f1 Elapsed: {seconds_human(elapsed)}"
                )
                if loot_dash:
                    text += "\n" + loot_dash
            elif progress.phase == "validating":
                val_total = progress.loot_validate_total or 0
                val_done = progress.loot_validate_done or 0
                pct = (val_done / max(val_total, 1)) * 100 if val_total else 0
                loot_dash = _format_loot_dashboard(progress)
                text = (
                    f"\u2699\ufe0f Live Dashboard\n"
                    f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
                    f"\U0001f4e5 Download:  Done \u2705\n"
                    f"\U0001f4c2 Extract:   Done \u2705\n"
                    f"\U0001f50d Scan:      Done \u2705\n"
                    f"\U0001f6e1 Validating tokens / accounts\n"
                    f"   {progress_bar(val_done, val_total)} {pct:.0f}% "
                    f"({val_done:,}/{val_total:,})\n"
                    f"\u23f1 Elapsed: {seconds_human(elapsed)}"
                )
                if loot_dash:
                    text += "\n" + loot_dash
            elif progress.phase == "packaging":
                loot_dash = _format_loot_dashboard(progress)
                text = (
                    f"\u2699\ufe0f Live Dashboard\n"
                    f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
                    f"\U0001f4e5 Download:  Done \u2705\n"
                    f"\U0001f4c2 Extract:   Done \u2705\n"
                    f"\U0001f50d Scan:      Done \u2705\n"
                    f"\U0001f4e6 Packaging results into .zip\u2026\n"
                    f"\U0001f36a Cookies found: {progress.cookies_found:,}\n"
                    f"\U0001f4dd Credentials found: "
                    f"{progress.credentials_found:,}\n"
                    f"\u23f1 Elapsed: {seconds_human(elapsed)}"
                )
                if loot_dash:
                    text += "\n" + loot_dash
            else:
                continue

            if text == last_text:
                continue
            last_text = text
            await msg.edit_text(
                text,
                reply_markup=_cancel_job_kb(job_id),
            )
        except Exception:
            # Telegram throws "Message is not modified" if the text/buttons
            # haven't changed since the last edit — silently ignore so the
            # updater keeps running.
            pass


def _notify_admin_error(context, user_id: int, action: str, error: str) -> None:
    """Best-effort critical error notification to admin."""
    text = (
        f"\U0001f6a8 Critical Error\n"
        f"User: {user_id}\n"
        f"Action: {action}\n"
        f"Error: {error[:500]}"
    )
    asyncio.create_task(context.bot.send_message(config.ADMIN_ID, text))


# ── Cancel handlers ────────────────────────────────────────
async def cancel_extract(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer()
        await query.edit_message_text("\u274c Extraction cancelled.")
    return ConversationHandler.END


async def cancel_job_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cancel a running/queued job."""
    query = update.callback_query
    if query is None:
        return
    await query.answer()

    data = query.data or ""
    try:
        job_id = int(data.split("_")[-1])
    except (ValueError, IndexError):
        return

    prog = _active_progress.get(job_id)
    if prog:
        prog.cancelled = True

    if _job_queue and _job_queue.cancel(job_id):
        await db.update_job(job_id, status="cancelled", completed_at=db._now())
        await query.edit_message_text("\u274c Cancelling job...")
        return

    if prog:
        await db.update_job(job_id, status="cancelled", completed_at=db._now())
        await query.edit_message_text("\u274c Cancelling job...")
        return

    await query.edit_message_text("\u274c Job not found or already completed.")


# ── Register ───────────────────────────────────────────────
def register(app, job_queue: JobQueue) -> None:
    """Attach extraction handlers to the Application."""
    global _job_queue
    _job_queue = job_queue

    conv = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(extract_entry, pattern="^extract$"),
            CommandHandler("extract", extract_entry),
            # Single-mode shortcut buttons on the main menu \u2014 each
            # bypasses the mode-picker by pre-selecting one output mode.
            CallbackQueryHandler(
                extract_entry, pattern=_SINGLE_MODE_CB_PATTERN,
            ),
            # Convenience slash commands for the same five modes so the
            # user can type ``/cookies``, ``/ulp``, ``/cc``, etc. instead
            # of going through the menu.
            CommandHandler("cookies", extract_entry),
            CommandHandler("ulp", extract_entry),
            CommandHandler("combo", extract_entry),
            CommandHandler("combo_full", extract_entry),
            CommandHandler("cc", extract_entry),
            # 'Search more domains' button after a successful extraction.
            CallbackQueryHandler(rescan_entry, pattern="^rescan_more$"),
        ],
        states={
            DOMAIN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, domain_received),
                CallbackQueryHandler(
                    domain_skip, pattern="^extract_skip_domain$",
                ),
                CallbackQueryHandler(cancel_extract, pattern="^extract_cancel$"),
            ],
            MODE: [
                CallbackQueryHandler(mode_toggle, pattern=r"^mode_toggle:"),
                CallbackQueryHandler(mode_done, pattern=r"^mode_done$"),
                CallbackQueryHandler(cancel_extract, pattern="^extract_cancel$"),
            ],
            FILE: [
                MessageHandler(filters.Document.ALL, file_received),
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND & filters.Regex(
                        r"^\s*https?://\S+\s*$"
                    ),
                    url_received,
                ),
                CallbackQueryHandler(cancel_extract, pattern="^extract_cancel$"),
            ],
        },
        fallbacks=[
            CallbackQueryHandler(cancel_extract, pattern="^extract_cancel$"),
            CommandHandler("cancel", cancel_extract),
        ],
        per_message=False,
    )
    app.add_handler(conv)

    # Job cancel callback (works outside conversation)
    app.add_handler(CallbackQueryHandler(cancel_job_callback, pattern=r"^cancel_job_\d+$"))

    # Archive-password prompt handlers. Registered in a negative group so
    # they run ahead of the generic conversation handlers and catch the
    # user's reply even though the /extract conversation has already ended
    # (the password wait happens inside the queue worker).
    app.add_handler(CommandHandler("skip", skip_command), group=-1)
    app.add_handler(
        CallbackQueryHandler(skip_password_callback, pattern=r"^skip_pw_\d+$"),
        group=-1,
    )
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND, password_reply,
        ),
        group=-1,
    )
