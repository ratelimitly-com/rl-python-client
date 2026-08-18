"""Unit tests for RateLimitly Bech32 auth key parser."""

import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.auth import parse_auth_key

VECTORS_PATH = Path(__file__).parent / "fixtures/api_key_v1_test_vectors.json"


class TestAuthKeyParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        cls.aes_key = next(
            vector["bech32"]
            for vector in cls.vectors["valid_credentials"]
            if vector["auth_method"] == "aes"
        )

    def test_normative_api_key_v1_vectors(self):
        for vector in self.vectors["valid_credentials"]:
            if vector["auth_method"] == "none":
                continue
            with self.subTest(vector=vector["name"]):
                info = parse_auth_key(vector["bech32"])
                self.assertEqual(info.auth_type, vector["auth_method"])
                self.assertEqual(info.format_version, self.vectors["format_version"])
                self.assertEqual(info.key_id, int(vector["key_id"]))
                self.assertEqual(info.secret.hex(), vector["secret_hex"])
                for field, expected in vector["quotas"].items():
                    self.assertEqual(getattr(info, field), expected)
                self.assertEqual(
                    info.default_dns_srv,
                    f"c-{info.key_id}.p0.ratelimitly.com",
                )

        for vector in self.vectors["invalid_credentials"]:
            with self.subTest(vector=vector["name"]):
                with self.assertRaises(ValueError):
                    parse_auth_key(vector["bech32"])

    def test_uppercase_key_is_accepted(self):
        info = parse_auth_key(self.aes_key.upper())
        self.assertGreater(info.key_id, 0)

    def test_bad_checksum_is_rejected(self):
        replacement = "q" if self.aes_key[-1] != "q" else "p"
        with self.assertRaises(ValueError):
            parse_auth_key(self.aes_key[:-1] + replacement)

    def test_invalid_key_prefix(self):
        with self.assertRaises(ValueError):
            parse_auth_key("invalid-prefix-key")

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            parse_auth_key(12345)


if __name__ == "__main__":
    unittest.main()
