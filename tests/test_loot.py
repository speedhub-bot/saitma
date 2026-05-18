"""Unit tests for the loot scanner (``services.loot``).

These tests don't touch the network — only the offline scanners and
output builders. Run with::

    python -m unittest tests/test_loot.py
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from services import loot


class TdataScannerTests(unittest.TestCase):
    """Telegram Desktop ``tdata`` detection + structure validation."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="loot_tdata_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _make_tdata(self, *, with_magic: bool, with_maps: bool) -> str:
        """Build the on-disk layout Telegram Desktop ships:

            tdata/Telegram/
              key_datas               (TDF$ magic + encrypted blob)
              D877F783D5D3EF8C/       (data folder)
                maps                  (optional)
              D877F783D5D3EF8Cs       (sibling keyfile, with 's' suffix)
        """
        tdata = os.path.join(self.root, "tdata", "Telegram")
        os.makedirs(tdata, exist_ok=True)
        keyfile = "D877F783D5D3EF8C"
        with open(os.path.join(tdata, "key_datas"), "wb") as fh:
            fh.write(b"TDF$" if with_magic else b"XXXX")
            fh.write(b"\x00" * 384)
        # data folder
        os.makedirs(os.path.join(tdata, keyfile), exist_ok=True)
        # sibling keyfile (s-suffix)
        with open(os.path.join(tdata, keyfile + "s"), "wb") as fh:
            fh.write(b"\x00" * 256)
        if with_maps:
            with open(
                os.path.join(tdata, keyfile, "maps"), "wb",
            ) as fh:
                fh.write(b"\x00" * 64)
        return tdata

    def test_valid_layout_is_recognised(self) -> None:
        self._make_tdata(with_magic=True, with_maps=True)
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.tdata), 1)
        acc = result.tdata[0]
        self.assertTrue(acc.valid)
        self.assertTrue(acc.has_tdf_magic)
        self.assertTrue(acc.has_maps)
        self.assertEqual(acc.keyfile, "D877F783D5D3EF8C")

    def test_missing_tdf_magic_is_rejected(self) -> None:
        self._make_tdata(with_magic=False, with_maps=True)
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.tdata), 1)
        self.assertFalse(result.tdata[0].valid)
        self.assertIn("TDF$", result.tdata[0].reason)

    def test_missing_maps_is_rejected(self) -> None:
        self._make_tdata(with_magic=True, with_maps=False)
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.tdata), 1)
        self.assertFalse(result.tdata[0].valid)
        self.assertIn("maps", result.tdata[0].reason)

    def test_account_info_sibling_is_parsed(self) -> None:
        self._make_tdata(with_magic=True, with_maps=True)
        info = os.path.join(self.root, "account_info.txt")
        with open(info, "w", encoding="utf-8") as fh:
            fh.write(
                "=== ACCOUNT INFO ===\n"
                "Phone: +123456789\n"
                "User ID: 1000\n"
                "DC: 2\n"
                "Premium: YES\n"
            )
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.tdata), 1)
        acc = result.tdata[0]
        self.assertEqual(acc.info.get("phone"), "+123456789")
        self.assertEqual(acc.info.get("user_id"), "1000")
        self.assertEqual(acc.info.get("dc"), "2")


class DiscordTokenScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="loot_disc_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_plaintext_dump_is_detected(self) -> None:
        path = os.path.join(self.root, "Discord", "tokens.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                "MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf."
                "gHiJkL_mNoPqRsTuVwXyZ012345678\n"
                "mfa.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
                "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
                "AbCdEfGhIjKlMnO\n"
                "not_a_token\n"
            )
        result = loot.scan_directory_for_loot(self.root)
        tokens = sorted(t.token for t in result.discord)
        self.assertEqual(len(tokens), 2)
        self.assertTrue(any(t.startswith("MTIz") for t in tokens))
        self.assertTrue(any(t.startswith("mfa.") for t in tokens))

    def test_binary_ldb_is_scanned(self) -> None:
        path = os.path.join(self.root, "Discord", "000003.ldb")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        token = (
            "MTAxMjM0NTY3ODkwMTIzNDU2.AbCdEf."
            "gHiJkLmNoPqRsTuVwXyZ_0123456"
        )
        with open(path, "wb") as fh:
            fh.write(b"junk\x00\x01")
            fh.write(token.encode())
            fh.write(b"\x00more junk")
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.discord), 1)
        self.assertEqual(result.discord[0].token, token)

    def test_redaction_keeps_token_value(self) -> None:
        tok = loot.DiscordToken(
            token=(
                "MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf."
                "gHiJkL_mNoPqRsTuVwXyZ012345678"
            ),
            source_file="x",
        )
        # Redacted form must not leak the secret middle.
        self.assertNotIn("AbCdEf", tok.redacted)
        self.assertIn("...", tok.redacted)


class SteamScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="loot_steam_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_loginusers_with_multiple_accounts(self) -> None:
        path = os.path.join(self.root, "Steam", "config", "loginusers.vdf")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                '"users"\n{\n'
                '\t"76561198000000001"\n\t{\n'
                '\t\t"AccountName"\t\t"alice"\n'
                '\t\t"PersonaName"\t\t"Alice"\n'
                '\t\t"RememberPassword"\t"1"\n'
                '\t\t"MostRecent"\t\t"1"\n'
                '\t\t"Timestamp"\t\t"1700000000"\n'
                '\t}\n'
                '\t"76561198000000002"\n\t{\n'
                '\t\t"AccountName"\t\t"bob"\n'
                '\t\t"PersonaName"\t\t"Bob"\n'
                '\t\t"RememberPassword"\t"0"\n'
                '\t}\n'
                '}\n'
            )
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.steam), 2)
        names = {a.account_name for a in result.steam}
        self.assertEqual(names, {"alice", "bob"})
        alice = next(a for a in result.steam if a.account_name == "alice")
        self.assertTrue(alice.remember_password)
        self.assertEqual(alice.timestamp, 1700000000)
        self.assertEqual(
            alice.profile_url,
            "https://steamcommunity.com/profiles/76561198000000001",
        )

    def test_sentry_attaches_to_account(self) -> None:
        cfg = os.path.join(self.root, "Steam", "config")
        os.makedirs(cfg, exist_ok=True)
        with open(os.path.join(cfg, "loginusers.vdf"), "w") as fh:
            fh.write(
                '"users"\n{\n'
                '\t"76561198000000001"\n\t{\n'
                '\t\t"AccountName"\t"alice"\n'
                '\t}\n}\n'
            )
        # Sentry sits next to loginusers.vdf in real installs.
        with open(os.path.join(cfg, "ssfn7188123456789"), "wb") as fh:
            fh.write(b"fake")
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.steam), 1)
        self.assertEqual(len(result.steam[0].ssfn_files), 1)

    def test_mafile_is_parsed(self) -> None:
        path = os.path.join(self.root, "alice.maFile")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                '{"account_name": "alice", '
                '"shared_secret": "AAAA1234==", '
                '"Session": {"SteamID": 76561198000000099}}'
            )
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.steam), 1)
        acc = result.steam[0]
        self.assertEqual(acc.account_name, "alice")
        self.assertEqual(acc.steam_id, "76561198000000099")
        self.assertEqual(acc.mafile_shared_secret, "AAAA1234==")


class CredentialScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="loot_pwd_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        path = os.path.join(self.root, "Chrome", "Passwords.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                "=== Chrome ===\n"
                "URL: https://claude.ai/login\n"
                "Username: alice@example.com\n"
                "Password: claude_pass_123\n"
                "\n"
                "URL: https://spotify.com/account\n"
                "Login: alice_sp\n"
                "Password: spotify_pass\n"
                "\n"
                "URL: https://claude.ai/api\n"
                "User: bob\n"
                "Password: bob_claude_pw\n"
            )

    def test_parses_blocks_with_synonyms(self) -> None:
        result = loot.scan_directory_for_loot(self.root)
        self.assertEqual(len(result.credentials), 3)
        domains = sorted({c.domain for c in result.credentials})
        self.assertEqual(domains, ["claude.ai", "spotify.com"])

    def test_ulp_and_combo_output(self) -> None:
        result = loot.scan_directory_for_loot(self.root)
        ulp = loot.build_ulp_text(result.credentials)
        self.assertIn("https://claude.ai/login:alice@example.com:claude_pass_123",
                      ulp)
        combo_all = loot.build_combo_text(result.credentials)
        self.assertIn("alice@example.com:claude_pass_123", combo_all)
        structured = loot.build_structured_combo_text(result.credentials)
        self.assertIn("=== claude.ai ===", structured)
        self.assertIn("=== spotify.com ===", structured)

    def test_targeted_filter(self) -> None:
        result = loot.scan_directory_for_loot(self.root)
        targeted = loot.filter_credentials(result.credentials, ["claude.ai"])
        self.assertEqual(len(targeted), 2)
        self.assertTrue(all(c.domain == "claude.ai" for c in targeted))


if __name__ == "__main__":
    unittest.main()
