"""Server identity extraction and DNS-cache behavior."""

import os
import socket
import struct
import threading
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
    _query_addresses_native,
    _encode_dns_name,
)


COOKIE_KEY = "rl-cookie1qgpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgrrulcz2hmcw"


class TestDiscovery(unittest.TestCase):
    def test_native_override_resolves_srv_and_both_address_families_over_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
            dns.bind(("127.0.0.1", 0)); dns.settimeout(2)
            errors, queries = [], []
            def serve():
                try:
                    for _ in range(3):
                        packet, peer = dns.recvfrom(2048)
                        kind = struct.unpack_from("!H", packet, len(packet) - 4)[0]
                        queries.append(kind)
                        if kind == 33:
                            data = struct.pack("!HHH", 10, 50, 38080) + _encode_dns_name("s-10.owned.test")
                        else:
                            data = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, "127.0.0.1" if kind == 1 else "::1")
                        header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                        rr = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(data)) + data
                        dns.sendto(header + packet[12:] + rr, peer)
                except BaseException as error: errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            with patch.dict(os.environ, {"RCLIENT_DNS_SERVER": f"127.0.0.1:{dns.getsockname()[1]}"}), patch("ratelimitly.discovery._dns_resolver", None):
                endpoints = discover_server_endpoints("owned.test")
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(queries, [33, 1, 28])
            self.assertEqual([e.family for e in endpoints], [socket.AF_INET, socket.AF_INET6])
            self.assertEqual([e.server_id for e in endpoints], [10, 10])

    @patch.dict(os.environ, {"RCLIENT_DNS_SERVER": "127.0.0.1:53535"})
    @patch("socket.getaddrinfo")
    @patch("ratelimitly.discovery._query_addresses_native")
    @patch("ratelimitly.discovery._dns_resolver")
    def test_dns_server_override_configures_dnspython_resolver(
        self, dns_resolver, query_addresses, getaddrinfo
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
        query_addresses.return_value = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 38080))
        ]

        endpoints = discover_server_endpoints("rl.glar.com")

        dns_resolver.Resolver.assert_called_once_with(configure=False)
        self.assertEqual(resolver.nameservers, ["127.0.0.1"])
        self.assertEqual(resolver.port, 53535)
        resolver.resolve.assert_called_once_with("_ratelimitly._udp.rl.glar.com", "SRV")
        self.assertEqual(endpoints[0].server_id, 10)
        query_addresses.assert_called_once_with("s-10.localhost", 38080, "127.0.0.1", 53535)
        getaddrinfo.assert_not_called()

    @patch("ratelimitly.discovery._query_records_native")
    def test_target_lookups_use_same_override_for_both_families(self, query):
        query.side_effect = [[("127.0.0.1", socket.AF_INET, 30)], [("::1", socket.AF_INET6, 30)]]
        addresses = _query_addresses_native("s-10.owned.test", 38080, "127.0.0.1", 53535)
        self.assertEqual([a[0] for a in addresses], [socket.AF_INET, socket.AF_INET6])
        self.assertEqual([a[4] for a in addresses], [("127.0.0.1", 38080), ("::1", 38080, 0, 0)])
        self.assertEqual([c.args for c in query.call_args_list], [
            ("s-10.owned.test", "127.0.0.1", 53535, 1),
            ("s-10.owned.test", "127.0.0.1", 53535, 28),
        ])

    @patch("ratelimitly.discovery._query_records_native")
    def test_one_failed_family_does_not_hide_the_other(self, query):
        query.side_effect = [LookupError("no A answer"), [("::1", socket.AF_INET6, 30)]]
        self.assertEqual(_query_addresses_native("s-10.owned.test", 38080, "127.0.0.1", 53535)[0][0], socket.AF_INET6)

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
