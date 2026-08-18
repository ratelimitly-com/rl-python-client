"""Server identity extraction and DNS-cache behavior."""

import os
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import FixedSchedule, RateLimitlyClient, RequestPolicy, RCLIENT_OK
from ratelimitly.discovery import (
    ServerEndpoint,
    discover_server_endpoints,
    server_id_from_target,
)


COOKIE_KEY = "rl-cookie1qypqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgtruhcgpj8ys"


class TestDiscovery(unittest.TestCase):
    @patch.dict(os.environ, {"RCLIENT_DNS_SERVER": "127.0.0.1:53535"})
    @patch("socket.getaddrinfo")
    @patch("ratelimitly.discovery._dns_resolver")
    def test_dns_server_override_configures_dnspython_resolver(
        self, dns_resolver, getaddrinfo
    ):
        class Answers(list):
            pass

        answers = Answers([
            SimpleNamespace(target="s-10.localhost.", port=38080),
        ])
        answers.rrset = SimpleNamespace(ttl=60)
        resolver = Mock()
        resolver.resolve.return_value = answers
        dns_resolver.Resolver.return_value = resolver
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 38080))
        ]

        endpoints = discover_server_endpoints("rl.glar.com")

        dns_resolver.Resolver.assert_called_once_with(configure=False)
        self.assertEqual(resolver.nameservers, ["127.0.0.1"])
        self.assertEqual(resolver.port, 53535)
        resolver.resolve.assert_called_once_with("_ratelimitly._udp.rl.glar.com", "SRV")
        self.assertEqual(endpoints[0].server_id, 10)

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
