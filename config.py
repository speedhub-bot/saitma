"""
Centralised configuration — every tuneable comes from environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int(key: str, default: int) -> int:
    return int(os.getenv(key, str(default)))


def _float(key: str, default: float) -> float:
    return float(os.getenv(key, str(default)))


def _str(key: str, default: str) -> str:
    return os.getenv(key, default)


# ── Telegram ────────────────────────────────────────────────
BOT_TOKEN: str = _str("BOT_TOKEN", "8482556356:AAGAjk6BRNm_HTfU6HKvJxLpPRkSHEA8htQ")
# Default to Telegram Desktop's public api_id/api_hash, which often
# routes through faster MTProto endpoints than fresh test credentials.
# Override via env if you have your own production credentials.
API_ID: int = _int("API_ID", 2040)
API_HASH: str = _str("API_HASH", "b18441a1ff607e10a989891a5462e627")
ADMIN_ID: int = _int("ADMIN_ID", 5944410248)
# SESSION_STRING is no longer needed — Pyrogram downloads via bot token directly

# ── Processing ──────────────────────────────────────────────
# Hard cap on concurrent extraction jobs across the whole bot. The
# queue uses a three-tier priority system (admin > VIP > free) so heavy
# load doesn't starve admins/VIPs.
MAX_CONCURRENT_JOBS: int = _int("MAX_CONCURRENT_JOBS", 2)
FREE_DAILY_LIMIT_GB: int = _int("FREE_DAILY_LIMIT_GB", 2)
FREE_DAILY_LIMIT_BYTES: int = FREE_DAILY_LIMIT_GB * 1024 ** 3
FREE_MAX_FILE_BYTES: int = 2 * 1024 ** 3          # 2 GB
VIP_MAX_FILE_BYTES: int = 10 * 1024 ** 3           # 10 GB
MIN_FREE_DISK_BYTES: int = _int("MIN_FREE_DISK_GB", 1) * 1024 ** 3
EXTRACTION_DISK_MULTIPLIER: float = _float("EXTRACTION_DISK_MULTIPLIER", 2.0)

# ── Paths ───────────────────────────────────────────────────
DATABASE_PATH: str = _str("DATABASE_PATH", "bot.db")
LOG_FILE: str = _str("LOG_FILE", "bot.log")
TEMP_DIR: Path = Path(_str("TEMP_DIR", "/tmp/cookiebot"))

# ── Extraction ──────────────────────────────────────────────
MAX_DOMAINS_PER_EXTRACT: int = _int("MAX_DOMAINS_PER_EXTRACT", 10)

# ── Rescan window ───────────────────────────────────────────
# After a successful extraction the source archive is kept on disk for
# this many seconds so the user can search additional domains in the
# same archive without re-uploading. After the window expires the
# archive is auto-deleted. Default: 2 minutes.
RESCAN_WINDOW_SECONDS: int = _int("RESCAN_WINDOW_SECONDS", 120)
RESCAN_MAX_ARCHIVE_BYTES: int = _int("RESCAN_MAX_ARCHIVE_GB", 2) * 1024 ** 3

# ── Rate-limits / anti-abuse ────────────────────────────────
MAX_EXTRACTIONS_PER_HOUR: int = 3
SPAM_MSG_LIMIT: int = 10          # messages within window
SPAM_WINDOW_SECONDS: int = 30
SPAM_MUTE_SECONDS: int = 300      # 5 min
QUOTA_ABUSE_WARNS: int = 3        # auto-ban threshold

# ── Output ──────────────────────────────────────────────────
OUTPUT_CHUNK_SIZE_BYTES: int = 45 * 1024 * 1024    # 45 MB per result file
PROGRESS_UPDATE_INTERVAL: float = 2.0              # seconds (live dashboard refresh)
QUEUE_UPDATE_INTERVAL: float = 30.0                # seconds

# ── Cleanup ─────────────────────────────────────────────────
TEMP_FILE_MAX_AGE_HOURS: int = 1

# ── Loot (/loot command) ────────────────────────────────────
# When True the /loot scanner additionally hits the Discord and Steam
# APIs to validate each recovered token / account and only reports
# live ones as "VALID". Turning this off makes the scan fully offline
# and noticeably faster, at the cost of also emitting dead tokens.
LOOT_VALIDATE: bool = _str("LOOT_VALIDATE", "true").lower() in (
    "1", "true", "yes", "on",
)
# Concurrency used for the validation HTTP requests. Discord and Steam
# both rate-limit by IP — keep this small to stay polite.
LOOT_VALIDATE_CONCURRENCY: int = _int("LOOT_VALIDATE_CONCURRENCY", 8)
