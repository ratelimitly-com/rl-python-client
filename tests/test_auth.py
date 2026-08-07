"""Unit tests for RateLimitly Bech32 auth key parser."""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.auth import parse_auth_key, AuthKeyInfo

SYNTHETIC_KEY = "rl-aes1qyqqqqqqqqqqq6uxkfel7d8uuxwkhqzwladr74684kjw4g30r4yuq8jjmkmcwk6tqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqq0n6jux"


class TestAuthKeyParser(unittest.TestCase):
    def test_parse_auth_key(self):
        info = parse_auth_key(SYNTHETIC_KEY)
        self.assertIsInstance(info, AuthKeyInfo)
        self.assertEqual(info.auth_type, "aes")
        self.assertIsInstance(info.key_id, int)
        self.assertEqual(len(info.secret), 32)
        self.assertEqual(info.default_dns_srv, f"c-{info.key_id}.p0.ratelimitly.com")

    def test_invalid_key_prefix(self):
        with self.assertRaises(ValueError):
            parse_auth_key("invalid-prefix-key")

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            parse_auth_key(12345)


if __name__ == "__main__":
    unittest.main()
