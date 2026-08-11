"""Unit tests for RateLimitly Bech32 auth key parser."""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.auth import parse_auth_key, AuthKeyInfo

SYNTHETIC_KEY = "rl-aes1qyqqqqqqqqqqq6uxkfel7d8uuxwkhqzwladr74684kjw4g30r4yuq8jjmkmcwk6tqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqq0n6jux"
COOKIE_KEY = "rl-cookie1qgqqqqqqqqqqqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqqfn54mv"
AES_KEY = "rl-aes1qvqqqqqqqqqqqqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqqqqzqqqqsqqqqqsqqqyqqqqqqkqzqqqhmzd8l"


class TestAuthKeyParser(unittest.TestCase):
    def test_parse_auth_key(self):
        info = parse_auth_key(AES_KEY)
        self.assertIsInstance(info, AuthKeyInfo)
        self.assertEqual(info.auth_type, "aes")
        self.assertEqual(info.key_id, 3)
        self.assertEqual(info.secret, b"\x03" * 32)
        self.assertEqual(info.rate_buckets_max, 65536)
        self.assertEqual(info.latency_services_max, 1024)
        self.assertEqual(info.metrics_labels_max, 4096)
        self.assertEqual(info.latency_buffer_size_max, 64)
        self.assertEqual(info.dedup_ttl_ms_max, 300)
        self.assertEqual(info.default_dns_srv, f"c-{info.key_id}.p0.ratelimitly.com")

    def test_parse_cookie_auth_key(self):
        info = parse_auth_key(COOKIE_KEY)
        self.assertEqual(info.auth_type, "cookie")
        self.assertEqual(info.key_id, 2)
        self.assertEqual(info.secret, b"\x02" * 32)

    def test_uppercase_key_is_accepted(self):
        info = parse_auth_key(AES_KEY.upper())
        self.assertEqual(info.key_id, 3)

    def test_bad_checksum_is_rejected(self):
        replacement = "q" if AES_KEY[-1] != "q" else "p"
        with self.assertRaises(ValueError):
            parse_auth_key(AES_KEY[:-1] + replacement)

    def test_invalid_key_prefix(self):
        with self.assertRaises(ValueError):
            parse_auth_key("invalid-prefix-key")

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            parse_auth_key(12345)


if __name__ == "__main__":
    unittest.main()
