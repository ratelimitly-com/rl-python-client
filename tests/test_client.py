"""Deterministic local-UDP tests for the C-compatible client state machine."""

import asyncio
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import (
    AsyncRateLimitlyClient,
    FixedSchedule,
    LatencyGuard,
    RateLimitlyClient,
    RequestPolicy,
    ResourceRequest,
    ServiceLatencyReport,
    RCLIENT_ERR_CONFIG,
    RCLIENT_ERR_PROTOCOL,
    RCLIENT_ERR_TIMEOUT,
    RCLIENT_OK,
)
from ratelimitly.auth import parse_auth_key
from ratelimitly.discovery import ServerEndpoint
from ratelimitly.protocol import (
    R_PDU_LATENCY_REPORT,
    R_PDU_RATE_RESPONSE,
    build_authenticated_packet,
    build_pdu,
)


COOKIE_KEY = "rl-cookie1qypqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgtruhcgpj8ys"
COOKIE_KEY_WITH_1024_MS_RATE_WINDOW = "rl-cookie1qypqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgtrujsv8vz5n"
AUTH = parse_auth_key(COOKIE_KEY)


def policy(unit_ms=50, replay_count=0, final_receive_units=0, completion_delivery=True):
    return RequestPolicy(
        unit_ms=unit_ms,
        replay_count=replay_count,
        replay_gap=FixedSchedule(1),
        final_receive_units=final_receive_units,
        completion_delivery=completion_delivery,
    )


def udp_server(server_id):
    current = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current.bind(("127.0.0.1", 0))
    current.settimeout(1.0)
    endpoint = ServerEndpoint(
        socket.AF_INET,
        current.getsockname(),
        server_id,
        f"s-{server_id}.example.test",
    )
    return current, endpoint


def response_packet(
    request_id,
    server_id,
    *,
    guard=None,
    current_latency=0,
    resource=None,
    deficit=0,
    steering_feedback=True,
):
    guards = [] if guard is None else [guard]
    resources = [] if resource is None else [resource]
    body = bytearray(len(guards).to_bytes(2, "little") + len(resources).to_bytes(2, "little"))
    if guard is not None:
        body.extend(guard.latency_tracker_id)
        for value in (
            guard.ttl_ms,
            guard.max_samples,
            guard.buffer_size,
            guard.min_sample_threshold,
            guard.threshold_ms,
            current_latency,
        ):
            body.extend(value.to_bytes(4, "little"))
    if resource is not None:
        body.extend(resource.bucket_id)
        body.extend(resource.window_size_ms.to_bytes(4, "little"))
        body.extend((77).to_bytes(4, "little"))
        body.extend(deficit.to_bytes(2, "little"))
        body.extend(b"\x00\x00")
    return build_authenticated_packet(
        build_pdu(R_PDU_RATE_RESPONSE, body),
        AUTH,
        request_id=request_id,
        timestamp_ms=1234,
        tenant_id=server_id,
        steering_feedback=steering_feedback,
    )


def responder(
    current,
    server_id,
    build_response,
    *,
    drop_count=0,
    delay=0.0,
    received=None,
    source_addresses=None,
):
    def run():
        try:
            for _ in range(drop_count):
                packet, address = current.recvfrom(2048)
                if received is not None:
                    received.append(packet)
            packet, address = current.recvfrom(2048)
            if received is not None:
                received.append(packet)
            if source_addresses is not None:
                source_addresses.append(address)
            if delay:
                time.sleep(delay)
            current.sendto(build_response(packet[12:28], server_id), address)
        except OSError:
            return

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


class TestClient(unittest.TestCase):
    def test_empty_request_succeeds_locally_without_dns(self):
        calls = []
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(),
            resolver=lambda name: calls.append(name) or [],
        )
        status, result = client.check_rate_limit()
        self.assertEqual(status, RCLIENT_OK)
        self.assertTrue(result.success)
        self.assertEqual(result.server_id, 0)
        self.assertEqual(result.guards, ())
        self.assertEqual(result.resources, ())
        self.assertEqual(calls, [])
        client.close()

    def test_guard_only_request_is_sent_and_parsed(self):
        server, endpoint = udp_server(10)
        guard = LatencyGuard(b"g" * 16, 50, 1000, 10, 32, 2)
        received = []
        thread = responder(
            server,
            10,
            lambda request_id, server_id: response_packet(
                request_id, server_id, guard=guard, current_latency=25
            ),
            received=received,
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(),
            resolver=lambda _name: [endpoint],
        )
        status, result = client.check_rate_limit(guards=[guard])
        self.assertEqual(status, RCLIENT_OK)
        self.assertTrue(result.success)
        self.assertEqual(len(result.guards), 1)
        self.assertEqual(result.resources, ())
        thread.join(1.0)
        self.assertEqual(received[0][84:88].hex(), "01000000")
        request_id = received[0][12:28]
        self.assertEqual(request_id[6] & 0xF0, 0x40)
        self.assertEqual(request_id[8] & 0xC0, 0x80)
        self.assertEqual(int.from_bytes(received[0][80:84], "little"), 50)
        client.close()
        server.close()

    def test_oldest_known_server_wins_during_first_round(self):
        older, older_endpoint = udp_server(100)
        younger, younger_endpoint = udp_server(200)
        resource = ResourceRequest(b"b" * 16, 1000, 100, 1)
        older_thread = responder(
            older,
            100,
            lambda request_id, server_id: response_packet(
                request_id, server_id, resource=resource
            ),
            delay=0.02,
        )
        younger_thread = responder(
            younger,
            200,
            lambda request_id, server_id: response_packet(
                request_id, server_id, resource=resource
            ),
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(unit_ms=100),
            resolver=lambda _name: [older_endpoint, younger_endpoint],
        )
        status, result = client.check_rate_limit([resource])
        self.assertEqual(status, RCLIENT_OK)
        self.assertEqual(result.server_id, 100)
        older_thread.join(1.0)
        younger_thread.join(1.0)
        client.close()
        older.close()
        younger.close()

    def test_first_round_timeout_returns_oldest_arrived_response(self):
        older, older_endpoint = udp_server(100)
        younger, younger_endpoint = udp_server(200)
        resource = ResourceRequest(b"b" * 16, 1000, 100, 1)
        younger_thread = responder(
            younger,
            200,
            lambda request_id, server_id: response_packet(
                request_id, server_id, resource=resource
            ),
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(unit_ms=30, final_receive_units=1),
            resolver=lambda _name: [older_endpoint, younger_endpoint],
        )
        started = time.monotonic()
        status, result = client.check_rate_limit([resource])
        elapsed = time.monotonic() - started
        self.assertEqual(status, RCLIENT_OK)
        self.assertEqual(result.server_id, 200)
        self.assertGreaterEqual(elapsed, 0.02)
        self.assertLess(elapsed, 0.2)
        younger_thread.join(1.0)
        first_delivery, _ = older.recvfrom(2048)
        completion_delivery, _ = older.recvfrom(2048)
        self.assertEqual(first_delivery[12:28], completion_delivery[12:28])
        client.close()
        older.close()
        younger.close()

    def test_replay_round_returns_first_valid_response(self):
        server, endpoint = udp_server(10)
        resource = ResourceRequest(b"b" * 16, 1000, 100, 1)
        thread = responder(
            server,
            10,
            lambda request_id, server_id: response_packet(
                request_id, server_id, resource=resource
            ),
            drop_count=1,
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(unit_ms=20, replay_count=1, final_receive_units=1),
            resolver=lambda _name: [endpoint],
        )
        started = time.monotonic()
        status, result = client.check_rate_limit([resource])
        elapsed = time.monotonic() - started
        self.assertEqual(status, RCLIENT_OK)
        self.assertEqual(result.server_id, 10)
        self.assertGreaterEqual(elapsed, 0.015)
        self.assertLess(elapsed, 0.1)
        thread.join(1.0)
        client.close()
        server.close()

    def test_delayed_replay_response_can_arrive_during_final_receive(self):
        server, endpoint = udp_server(10)
        resource = ResourceRequest(b"b" * 16, 1000, 100, 1)
        thread = responder(
            server,
            10,
            lambda request_id, server_id: response_packet(
                request_id, server_id, resource=resource
            ),
            drop_count=1,
            delay=0.025,
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(unit_ms=20, replay_count=1, final_receive_units=1),
            resolver=lambda _name: [endpoint],
        )
        started = time.monotonic()
        status, result = client.check_rate_limit([resource])
        elapsed = time.monotonic() - started
        self.assertEqual(status, RCLIENT_OK)
        self.assertEqual(result.server_id, 10)
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertLess(elapsed, 0.1)
        thread.join(1.0)
        client.close()
        server.close()

    def test_keep_port_false_rebinds_persistent_socket(self):
        server, endpoint = udp_server(10)
        resource = ResourceRequest(b"b" * 16, 1000, 100, 1)
        first_sources = []
        thread = responder(
            server,
            10,
            lambda request_id, server_id: response_packet(
                request_id,
                server_id,
                resource=resource,
                steering_feedback=False,
            ),
            source_addresses=first_sources,
        )
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(),
            resolver=lambda _name: [endpoint],
        )
        status, result = client.check_rate_limit([resource])
        self.assertEqual(status, RCLIENT_OK)
        self.assertFalse(result.steering_feedback)
        self.assertIn(socket.AF_INET, client._sockets)
        replacement_port = client._sockets[socket.AF_INET].getsockname()[1]
        self.assertNotEqual(replacement_port, first_sources[0][1])

        second_sources = []
        second_thread = responder(
            server,
            10,
            lambda request_id, server_id: response_packet(
                request_id,
                server_id,
                resource=resource,
                steering_feedback=True,
            ),
            source_addresses=second_sources,
        )
        status, result = client.check_rate_limit([resource])
        self.assertEqual(status, RCLIENT_OK)
        self.assertTrue(result.steering_feedback)
        self.assertEqual(second_sources[0][1], replacement_port)
        thread.join(1.0)
        second_thread.join(1.0)
        client.close()
        server.close()

    def test_no_response_uses_rounds_and_final_receive_before_timeout(self):
        server, endpoint = udp_server(10)
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(unit_ms=10, replay_count=1, final_receive_units=1),
            resolver=lambda _name: [endpoint],
        )
        started = time.monotonic()
        status, result = client.check_rate_limit(
            [ResourceRequest(b"b" * 16, 1000, 100, 1)]
        )
        elapsed = time.monotonic() - started
        self.assertEqual(status, RCLIENT_ERR_TIMEOUT)
        self.assertIsNone(result)
        self.assertGreaterEqual(elapsed, 0.02)
        self.assertLess(elapsed, 0.2)
        client.close()
        server.close()

    def test_latency_report_is_sent_and_empty_report_is_config_error(self):
        server, endpoint = udp_server(10)
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(),
            resolver=lambda _name: [endpoint],
        )
        report = ServiceLatencyReport(b"s" * 16, 25, 1000, 10, 32, 2)
        self.assertEqual(client.report_latency([report]), RCLIENT_OK)
        packet, _address = server.recvfrom(2048)
        pdu = packet[76:]
        self.assertEqual(int.from_bytes(pdu[:2], "little"), R_PDU_LATENCY_REPORT)
        self.assertEqual(client.report_latency([]), RCLIENT_ERR_CONFIG)
        client.close()
        server.close()

    def test_oversized_guard_is_rejected_before_dns(self):
        calls = []
        client = RateLimitlyClient(
            COOKIE_KEY,
            policy=policy(),
            resolver=lambda name: calls.append(name) or [],
        )
        guard = LatencyGuard(b"g" * 16, 50, 1000, 10, 65, 2)
        status, result = client.check_rate_limit(guards=[guard])
        self.assertEqual(status, RCLIENT_ERR_PROTOCOL)
        self.assertIsNone(result)
        self.assertEqual(calls, [])
        client.close()

    def test_oversized_resource_window_is_rejected_before_dns(self):
        calls = []
        client = RateLimitlyClient(
            COOKIE_KEY_WITH_1024_MS_RATE_WINDOW,
            policy=policy(),
            resolver=lambda name: calls.append(name) or [],
        )
        resource = ResourceRequest(b"b" * 16, 1025, 100, 1)
        status, result = client.check_rate_limit([resource])
        self.assertEqual(status, RCLIENT_ERR_PROTOCOL)
        self.assertIsNone(result)
        self.assertEqual(calls, [])
        client.close()

    def test_async_empty_request_uses_same_contract(self):
        async def run():
            client = AsyncRateLimitlyClient(
                COOKIE_KEY,
                policy=policy(),
                resolver=lambda _name: [],
            )
            try:
                return await client.check_rate_limit()
            finally:
                client.close()

        status, result = asyncio.run(run())
        self.assertEqual(status, RCLIENT_OK)
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
