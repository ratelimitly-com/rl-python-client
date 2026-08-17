"""Server identity extraction and DNS-cache behavior."""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import FixedSchedule, RateLimitlyClient, RequestPolicy, RCLIENT_OK
from ratelimitly.discovery import ServerEndpoint, server_id_from_target


COOKIE_KEY = "rl-cookie1qypqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgtruhcgpj8ys"


class TestDiscovery(unittest.TestCase):
    def test_server_id_is_derived_from_srv_target(self):
        self.assertEqual(
            server_id_from_target("s-414078221156387.c-2.p0.ratelimitly.com."),
            414078221156387,
        )
        self.assertIsNone(server_id_from_target("server.example.com"))
        self.assertIsNone(server_id_from_target("s-not-a-number.example.com"))
        self.assertIsNone(server_id_from_target(f"s-{2**64}.example.com"))

    def test_endpoint_cache_obeys_srv_ttl(self):
        now = [1_000]
        calls = []
        endpoint = ServerEndpoint(
            socket.AF_INET,
            ("127.0.0.1", 8080),
            10,
            "s-10.example.com",
            ttl_ms=100,
        )

        def resolver(_name):
            calls.append(now[0])
            return [endpoint]

        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=RequestPolicy(20, 0, FixedSchedule(1), 0, False),
            resolver=resolver,
            clock_ms=lambda: now[0],
        )
        self.assertEqual(client._ensure_endpoints()[0], RCLIENT_OK)
        now[0] += 99
        self.assertEqual(client._ensure_endpoints()[0], RCLIENT_OK)
        now[0] += 1
        self.assertEqual(client._ensure_endpoints()[0], RCLIENT_OK)
        self.assertEqual(calls, [1_000, 1_100])
        client.close()


if __name__ == "__main__":
    unittest.main()
