"""Physical UDP traffic, independent of logical admission outcomes."""
import dataclasses
import socket
import threading
import unittest
from unittest.mock import patch

from test_client import COOKIE_KEY, policy, response_packet, udp_server
from ratelimitly import AsyncRateLimitlyClient, RateLimitlyClient, ResourceRequest, ServiceLatencyReport, RCLIENT_OK
from ratelimitly.traffic import _TrafficCounters, MAX_COUNTER
from ratelimitly import r_client_derive_bucket_id, r_client_derive_latency_tracker_id


class TrafficTests(unittest.TestCase):
    def test_snapshot_is_immutable_and_survives_close(self):
        client = RateLimitlyClient(COOKIE_KEY)
        before = client.traffic_stats()
        self.assertEqual(before.sent.ip_bytes, 0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            before.sent.ip_bytes = 1
        client.close()
        self.assertEqual(client.traffic_stats(), before)
        adapter = AsyncRateLimitlyClient(COOKIE_KEY)
        self.assertEqual(adapter.traffic_stats(), before)
        adapter.close()

    def test_replay_report_and_invalid_receive_are_physical_traffic(self):
        server, endpoint = udp_server(10)
        resource = ResourceRequest(r_client_derive_bucket_id("traffic", 1000, 100), 1000, 100, 1)
        sent, received, errors = [], [], []
        def serve():
            try:
                first, address = server.recvfrom(2048)
                sent.append(first)  # deliberately drop first request
                second, address = server.recvfrom(2048)
                sent.append(second)
                self.assertEqual(first, second)
                reply = response_packet(second[12:28], 10, resource=resource)
                for packet in [b"invalid", reply]:
                    server.sendto(packet, address)
                    received.append(packet)
                report, _ = server.recvfrom(2048)
                sent.append(report)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with RateLimitlyClient(COOKIE_KEY, resolver=lambda _: [endpoint], policy=policy(replay_count=1)) as client:
                status, result = client.check_rate_limit([resource])
                self.assertEqual(status, RCLIENT_OK)
                self.assertTrue(result.success)
                tracker = r_client_derive_latency_tracker_id("traffic", 1000, 10, 5)
                self.assertEqual(client.report_latency([ServiceLatencyReport(tracker, 10, 1000, 10, 5)]), RCLIENT_OK)
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(errors, errors)
                stats = client.traffic_stats()
            self.assertEqual(stats.sent.datagrams, 3)
            self.assertEqual(stats.sent.payload_bytes, sum(map(len, sent)))
            self.assertEqual(stats.sent.ip_bytes, sum(len(p) + 28 for p in sent))
            self.assertEqual(stats.received.datagrams, 2)
            self.assertEqual(stats.received.ip_bytes, sum(len(p) + 28 for p in received))
            self.assertEqual(stats.send_failures, 0)
            self.assertFalse(stats.incomplete)
        finally:
            server.close()
            thread.join(2)

    def test_failed_send_is_not_sent_traffic(self):
        server, endpoint = udp_server(10)
        try:
            with RateLimitlyClient(COOKIE_KEY, resolver=lambda _: [endpoint], policy=policy()) as client:
                with patch.object(client, "_socket_for_family", side_effect=OSError("send failed")):
                    client.check_rate_limit([ResourceRequest(r_client_derive_bucket_id("traffic", 1000, 100), 1000, 100, 1)])
                self.assertEqual(client.traffic_stats().send_failures, 1)
                self.assertEqual(client.traffic_stats().sent.datagrams, 0)
        finally:
            server.close()

    def test_ip_families_and_saturation(self):
        counters = _TrafficCounters()
        for family, address, overhead in [(socket.AF_INET, "127.0.0.1", 28), (socket.AF_INET6, "::1", 48), (socket.AF_INET6, "::ffff:127.0.0.1", 28)]:
            counters.record("sent", 100, family, address)
        stats = counters.snapshot()
        self.assertEqual(stats.sent.ip_bytes, 300 + 28 + 48 + 28)
        counters.record("sent", MAX_COUNTER, socket.AF_INET, "127.0.0.1")
        self.assertEqual(counters.snapshot().sent.ip_bytes, MAX_COUNTER)
        self.assertTrue(counters.snapshot().incomplete)
        self.assertEqual(stats.sent.datagrams, 3)  # earlier snapshot is detached
