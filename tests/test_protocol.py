"""Known-answer and layout tests for the coordinated wire-v2 contract."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.auth import parse_auth_key
from ratelimitly.protocol import (
    R_PDU_LATENCY_REPORT,
    R_PDU_RATE_RESPONSE,
    build_authenticated_packet,
    build_latency_report_body,
    build_pdu,
    build_rate_request_body,
    build_rate_request_pdu,
    parse_rate_response_packet,
    r_client_derive_bucket_id,
    r_client_derive_latency_tracker_id,
)
from ratelimitly.types import LatencyGuard, ResourceRequest, ServiceLatencyReport


COOKIE_KEY = "rl-cookie1qgpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqfgrrulcz2hmcw"
AES_KEY = "rl-aes1qgpsqqqqqqqqqqqrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqdgrrulcv9v93m"


class TestCanonicalIdentifiers(unittest.TestCase):
    def test_bucket_known_answer_from_c_client(self):
        self.assertEqual(
            r_client_derive_bucket_id("checkout", 1000, 100).hex(),
            "67f3b7c9ab155308089e20ca8d943909",
        )
        self.assertEqual(
            r_client_derive_bucket_id("a", 10, 1).hex(),
            "5b0b0d61aa7c806a0ff9e5973bf3cacb",
        )
        self.assertEqual(
            r_client_derive_bucket_id(
                b"binary\x00bucket", 31_536_000_000, 0xFFFFFFFF
            ).hex(),
            "552c6b8185f1d61ebc3ccc65f446ec88",
        )

    def test_invalid_bucket_windows_are_rejected(self):
        for bad_window in (0, 5, 9, 15, 1_005, 31_536_000_010):
            with self.subTest(window_size_ms=bad_window):
                with self.assertRaises(ValueError):
                    r_client_derive_bucket_id("checkout", bad_window, 100)

    def test_tracker_known_answer_from_c_client(self):
        self.assertEqual(
            r_client_derive_latency_tracker_id(
                "inventory-backend", 10000, 100, 5
            ).hex(),
            "6a17d07a424568304e50d28540f76e67",
        )

        self.assertEqual(
            r_client_derive_latency_tracker_id("café", 60000, 200, 3).hex(),
            "0f04bcd0fa9d655ca40dd204f50196f7",
        )

    def test_exact_binary_tracker_name_from_c_client(self):
        self.assertEqual(
            r_client_derive_latency_tracker_id(
                b"binary\x00tracker",
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
            ).hex(),
            "2944d00ab0f1829a4d598d47f32fb0fa",
        )

        self.assertEqual(
            r_client_derive_latency_tracker_id("a", 1, 1, 1).hex(),
            "86b64d987043e6695b477b44b0cf5bdb",
        )


class TestWireProtocol(unittest.TestCase):
    def test_rate_request_body_exact_layout(self):
        guard = LatencyGuard(b"\x01" * 16, 50, 1000, 10, 2)
        resource = ResourceRequest(b"\x02" * 16, 60000, 100, 3)
        body = build_rate_request_body([resource], [guard], "api")
        self.assertEqual(
            body.hex(),
            "01000100"
            + "01" * 16
            + "e80300000a000000020000003200000000000000"
            + "02" * 16
            + "701700006400000003000000"
            + "4d4c0c000300617069000000",
        )

    def test_guard_only_and_empty_rate_bodies_are_valid(self):
        guard = LatencyGuard(b"g" * 16, 50, 1000, 10, 2)
        self.assertEqual(build_rate_request_body([], []).hex(), "00000000")
        self.assertEqual(build_rate_request_body([], [guard])[:4].hex(), "01000000")

    def test_rate_request_pdu_carries_dedup_ttl(self):
        pdu = build_rate_request_pdu(60, b"\x00\x00\x00\x00")
        self.assertEqual(pdu.hex(), "54320c003c00000000000000")

    def test_latency_report_body_and_pdu_match_c_layout(self):
        report = ServiceLatencyReport(b"svc" + b"\x00" * 13, 25, 1000, 10, 1)
        body = build_latency_report_body([report])
        self.assertEqual(
            body.hex(),
            "01000000"
            "73766300000000000000000000000000"
            "e80300000a0000000100000019000000",
        )
        pdu = build_pdu(R_PDU_LATENCY_REPORT, body)
        self.assertEqual(len(pdu), 44)
        self.assertEqual(pdu[:8].hex(), "4c522c0000000000")

    def test_cookie_packet_and_response_parser(self):
        auth = parse_auth_key(COOKIE_KEY)
        request_id = bytes(range(16))
        response_body = (
            b"\x01\x00\x01\x00"
            + b"g" * 16
            + (1000).to_bytes(4, "little")
            + (10).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (50).to_bytes(4, "little")
            + (25).to_bytes(4, "little")
            + b"b" * 16
            + (6000).to_bytes(4, "little")
            + (77).to_bytes(4, "little")
            + (0).to_bytes(2, "little")
            + b"\x00\x00"
        )
        response_pdu = build_pdu(R_PDU_RATE_RESPONSE, response_body)
        packet = build_authenticated_packet(
            response_pdu,
            auth,
            request_id=request_id,
            timestamp_ms=1234,
            tenant_id=7,
            steering_feedback=True,
        )

        self.assertEqual(packet[:4].hex(), "524c2800")
        self.assertEqual(packet[4:12], (7).to_bytes(8, "little"))
        self.assertEqual(packet[12:28], request_id)
        self.assertEqual(packet[40:44].hex(), "43412400")
        self.assertEqual(packet[44:76], b"\x02" * 32)

        parsed_request_id, result = parse_rate_response_packet(packet, auth)
        self.assertEqual(parsed_request_id, request_id)
        self.assertEqual(result.server_id, 7)
        self.assertTrue(result.steering_feedback)
        self.assertTrue(result.success)
        self.assertEqual(result.guards[0].current_latency_ms, 25)
        self.assertEqual(result.resources[0].actual_rate, 77)
        self.assertEqual(result.resources[0].tokens_deficit, 0)

    def test_aes_packet_authenticates_tenant_header_auth_header_and_nonce(self):
        auth = parse_auth_key(AES_KEY)
        request_id = bytes(range(16))
        response_pdu = build_pdu(R_PDU_RATE_RESPONSE, b"\x00\x00\x00\x00")
        packet = build_authenticated_packet(
            response_pdu,
            auth,
            request_id=request_id,
            timestamp_ms=1234,
            tenant_id=7,
            steering_feedback=True,
            nonce=b"\x11" * 12,
        )
        parsed_request_id, result = parse_rate_response_packet(packet, auth)
        self.assertEqual(parsed_request_id, request_id)
        self.assertEqual(result.server_id, 7)
        self.assertTrue(result.success)

        tampered = bytearray(packet)
        tampered[4] ^= 1
        with self.assertRaises(ValueError):
            parse_rate_response_packet(bytes(tampered), auth)

    def test_legacy_rr_response_pdu_is_rejected(self):
        auth = parse_auth_key(COOKIE_KEY)
        legacy_pdu = build_pdu(0x5252, b"\x00\x00\x00\x00")
        packet = build_authenticated_packet(
            legacy_pdu,
            auth,
            request_id=bytes(range(16)),
            timestamp_ms=1234,
            tenant_id=7,
        )
        with self.assertRaises(ValueError):
            parse_rate_response_packet(packet, auth)


if __name__ == "__main__":
    unittest.main()
