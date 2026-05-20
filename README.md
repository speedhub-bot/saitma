# Cookie Extractor Bot

Production-grade Telegram bot for extracting cookies from Netscape-format archive files with full admin panel, VIP system, queue management, and GB-scale file processing.

## Features

- **Cookie Extraction** — Extracts domain-specific cookies from a wide range of inputs:
  - **Archives** — `.zip`, `.zipx`, `.jar`, `.war`, `.ear`, `.apk`, `.ipa`, `.xpi`, `.rar`, `.7z`, `.tar`, `.tar.gz` (`.tgz`), `.tar.bz2` (`.tbz`/`.tbz2`), `.tar.xz` (`.txz`), `.tar.zst` (`.tzst`), `.tar.lz` (`.tlz`), `.tar.lzma`, `.tar.lz4`, plus single-stream `.gz`, `.bz2`, `.xz`, `.zst`/`.zstd`, `.lz`, `.lzma`, `.lz4`, `.z`, and container formats `.cab`, `.iso`, `.arj`, `.ace`, `.cpio`, `.ar`, `.deb`, `.rpm`, `.dmg`.
  - **Plain logs** — `.txt`, `.log`, `.logs`, `.csv`, `.tsv`, `.json`, `.jsonl`/`.ndjson`, `.xml`, `.html`/`.htm`, `.yaml`/`.yml`, `.toml`, `.ini`/`.conf`/`.cfg`, `.md`/`.markdown`, `.nfo`, `.lst`/`.list`, `.dat`, `.out`, `.dump`, `.properties` — scanned directly, no archive needed.
  - **Split / multi-volume archives** — `.001`, `.002`, ... `.r01`, `.z01`, `.partN.rar` reassembled automatically.
  Routing is by **content (magic bytes)**, not extension, so a `.zip`-named 7z file still extracts cleanly.
- **Strict credit-card validation** — Cards must pass Luhn + a known IIN/BIN range (Visa, Mastercard incl. 2-series, Amex, Discover, Diners, JCB, UnionPay), are screened against published test-card numbers (Stripe / Adyen / etc.), rejected for low-entropy / repeated-digit / counting sequences, and (in strict mode) require a CC-related keyword + at least one of MM/YY/CVV in a ±400-char window. Expiry months/years are sanity-checked against the current year.
- **Multi-domain Extraction** — Submit several domains at once (e.g. `spotify.com, netflix.com, crunchyroll.com`) and the bot scans the archive once, producing a separate result file per domain. Configurable via `MAX_DOMAINS_PER_EXTRACT` (default `10`).
- **Live Dashboard** — Per-phase progress: download speed/ETA, extraction file counter (`current/total`), scanning files-per-second, **live cookies-found counter**, and the file currently being processed. Refreshes every 2 s.
- **Cancel-with-partial-results** — Hit cancel on a running job and the bot still ships whatever cookies it has already found, captioned as partial results.
- **Large File Support** — All files downloaded via Pyrogram MTProto with **16 parallel chunk transfers** (up to 10 GB for VIP), disk-space preflight checks, resumable job cancellation, and streaming extraction/scanning paths to avoid RAM spikes. Configurable via `PYROGRAM_MAX_TRANSMISSIONS`.
- **Queue System** — Async priority queue with VIP skip-ahead and configurable concurrency
- **Quota System** — Per-user daily byte limits with midnight UTC reset
- **VIP Membership** — Unlimited quota, priority queue, larger file limits
- **Admin Panel** — Full control: user management, stats, broadcasts, settings, logs
- **Anti-Abuse** — Rate limiting, spam detection, domain blacklisting, auto-ban
- **Slash-command Menu** — `/start`, `/extract`, `/mystats`, `/help`, `/about`, `/cancel` registered with Telegram so they appear in the in-app command picker.
- **Scheduled Tasks** — APScheduler for VIP expiry, quota reset, temp cleanup, daily reports

Credits: bot is maintained by [@akaza_isnt](https://t.me/akaza_isnt).

## Project Structure

```
bot.py                     # Main entry point
config.py                  # All settings from environment variables
requirements.txt           # Dependencies
.env.example               # Environment variable template
handlers/
  user.py                  # /start, /mystats, /help, VIP request, settings
  extract.py               # Extraction conversation handler
  admin.py                 # Full admin panel with all commands
services/
  extractor.py             # SmartCookieExtractor + async wrapper
  downloader.py            # Pyrogram MTProto large file downloader
  queue.py                 # Async job queue with VIP priority
db/
  database.py              # All async database operations
  models.py                # SQL schema definitions
utils/
  formatting.py            # Human-readable bytes, time, progress bars
  validators.py            # Domain and file type validation
```

## Setup

### 1. Clone and install

```bash
git clone https://github.com/speedhub-bot/Log.git
cd Log
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

Required variables:
- `BOT_TOKEN` — From [@BotFather](https://t.me/BotFather)
- `API_ID` / `API_HASH` — From [my.telegram.org](https://my.telegram.org)
- `ADMIN_ID` — Your Telegram numeric user ID

Large-file tuning:
- `MAX_CONCURRENT_JOBS` defaults to `2` so multiple 3–10 GB jobs do not exhaust disk/RAM.
- `MIN_FREE_DISK_GB` keeps emergency free space available before accepting a large job.
- `EXTRACTION_DISK_MULTIPLIER` estimates download + extraction temp-space needs.
- `RESCAN_MAX_ARCHIVE_GB` limits the quick-rescan cache so huge archives are deleted after results are sent.

No session string needed — Pyrogram uses the bot token to download files of any size via MTProto.

### 3. Run

```bash
python bot.py
```

## Commands

### User Commands
| Command | Description |
|---------|-------------|
| `/start` | Show main menu |
| `/extract` | Start cookie extraction |
| `/loot` | Recover tdata + Discord + Steam + ULP/combos from a log archive |
| `/dt` | Discord token validity check (paste tokens or upload a `.txt`) |
| `/mystats` | View your statistics |
| `/help` | Usage guide (paginated) |

#### `/dt` — Discord token validity check

`/dt` is the lightweight "is this token alive?" path. It does **not**
require an archive — paste tokens directly or upload a small `.txt`:

```
/dt <token>                 # validate one token inline
/dt <tok1> <tok2> ...       # validate several at once
/dt                         # prompt for a paste / file
```

After `/dt` with no args, reply with tokens one per line, or upload a
`.txt` file containing tokens. Up to **50 tokens** per request; each
token is checked against Discord's `/users/@me`. Live tokens come back
with username, user-id, email/phone (when set), MFA flag and Nitro
tier. Dead tokens are reported with the HTTP reason; transient
network / rate-limit failures are tagged `UNKNOWN` so you can re-run.

### Admin Commands
| Command | Description |
|---------|-------------|
| `/admin` | Admin panel (inline keyboard) |
| `/debug` | System diagnostics |
| `/ban <user_id> <reason>` | Ban a user |
| `/unban <user_id>` | Unban a user |
| `/vip <user_id> <days>` | Grant VIP (0 = forever) |
| `/revokevip <user_id>` | Remove VIP |
| `/setlimit <user_id> <gb>` | Custom daily limit |
| `/msg <user_id> <message>` | Message a user |
| `/addquota <user_id> <gb>` | Add extra quota |

## Deployment

### Railway

1. Push to GitHub
2. Connect repo in [Railway](https://railway.app)
3. Set environment variables in Railway dashboard
4. Deploy — the `bot.py` entry point runs automatically

### Linux Server

```bash
# Install system dependencies for archive extraction
sudo apt install unrar p7zip-full

# Run with systemd or screen/tmux
python bot.py
```

### System Requirements

- Python 3.10+
- `unrar` and `7za` (for `.rar` / `.7z` support)
- Sufficient disk space for temp extraction (depends on archive sizes)
