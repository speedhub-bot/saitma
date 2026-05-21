"""Unit tests for the ``/dt`` Discord-token-check handler.

These cover the pure-Python helpers (token parsing, formatting, summary)
without spinning up Telegram or talking to Discord. The validator call
itself is exercised separately in ``tests/test_loot.py`` via the
shared :mod:`services.loot` validator.
"""

from __future__ import annotations

import os
import sys
import unittest

# Make the project root importable when this file is run via
# ``python -m unittest`` from any cwd.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# /dt's handler module imports ``config``, which reads BOT_TOKEN/etc
# from the environment. Provide harmless defaults so the import works
# in test environments that don't have a real .env.
os.environ.setdefault("BOT_TOKEN", "test")
os.environ.setdefault("API_ID", "1")
os.environ.setdefault("API_HASH", "test")
os.environ.setdefault("ADMIN_ID", "1")

from handlers.discord_check import (  # noqa: E402 — see env setup above
    _format_result,
    _parse_tokens,
    _summary,
)
from services.loot import DiscordToken  # noqa: E402


# Two well-formed Discord tokens for use in parse / format tests.
# They are syntactically valid (snowflake-decodable user-id prefix +
# correctly-sized base64 segments) but obviously not live.
_CLASSIC_TOKEN = (
    "MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf."
    "gHiJkL_mNoPqRsTuVwXyZ012345678"
)
_MFA_TOKEN = (
    "mfa." + "A" * 90
)


class ParseTokensTests(unittest.TestCase):
    def test_extracts_classic_and_mfa(self) -> None:
        text = (
            "here are my tokens:\n"
            f"{_CLASSIC_TOKEN}\n"
            f"some junk in between\n"
            f"{_MFA_TOKEN}\n"
        )
        self.assertEqual(_parse_tokens(text), [_CLASSIC_TOKEN, _MFA_TOKEN])

    def test_deduplicates_while_preserving_order(self) -> None:
        text = f"{_CLASSIC_TOKEN}\n{_MFA_TOKEN}\n{_CLASSIC_TOKEN}\n"
        self.assertEqual(_parse_tokens(text), [_CLASSIC_TOKEN, _MFA_TOKEN])

    def test_empty_input(self) -> None:
        self.assertEqual(_parse_tokens(""), [])
        self.assertEqual(_parse_tokens("nothing token-shaped here"), [])

    def test_space_separated_inline_args(self) -> None:
        text = f"{_CLASSIC_TOKEN} {_MFA_TOKEN}"
        self.assertEqual(_parse_tokens(text), [_CLASSIC_TOKEN, _MFA_TOKEN])


class FormatResultTests(unittest.TestCase):
    def test_valid_token_renders_metadata(self) -> None:
        tk = DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")
        tk.valid = True
        tk.username = "alice"
        tk.global_name = "Alice Wonderland"
        tk.user_id = "1234567890"
        tk.email = "a@example.com"
        tk.mfa_enabled = True
        tk.verified = True
        tk.nitro = "nitro"
        line = _format_result(tk)
        self.assertIn("VALID", line)
        self.assertIn("Alice Wonderland", line)
        self.assertIn("@alice", line)
        self.assertIn("id=1234567890", line)
        self.assertIn("email=a@example.com", line)
        self.assertIn("mfa=on", line)
        self.assertIn("verified", line)
        self.assertIn("nitro=nitro", line)
        # The redacted form must be used, not the raw token.
        self.assertNotIn(_CLASSIC_TOKEN, line)

    def test_dead_token_shows_error(self) -> None:
        tk = DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")
        tk.valid = False
        tk.error = "401 unauthorised"
        line = _format_result(tk)
        self.assertIn("DEAD", line)
        self.assertIn("401 unauthorised", line)
        self.assertNotIn(_CLASSIC_TOKEN, line)

    def test_unknown_token_shows_error(self) -> None:
        tk = DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")
        # valid stays None — that's the "unknown" sentinel.
        tk.error = "timeout"
        line = _format_result(tk)
        self.assertIn("UNKNOWN", line)
        self.assertIn("timeout", line)


class SummaryTests(unittest.TestCase):
    def test_counts_each_state(self) -> None:
        a = DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")
        a.valid = True
        b = DiscordToken(token=_MFA_TOKEN, source_file="/dt")
        b.valid = False
        c = DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")
        # c.valid stays None ⇒ "unknown"
        text = _summary([a, b, c])
        self.assertIn("1 valid", text)
        self.assertIn("1 dead", text)
        self.assertIn("1 unknown", text)
        self.assertIn("checked 3", text)
        self.assertNotIn("Truncated", text)

    def test_truncation_footer(self) -> None:
        tokens = [DiscordToken(token=_CLASSIC_TOKEN, source_file="/dt")]
        text = _summary(tokens, truncated=7)
        self.assertIn("Truncated", text)
        self.assertIn("7", text)


if __name__ == "__main__":
    unittest.main()
