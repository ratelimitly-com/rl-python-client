"""Unit tests for binary datagram packing, unpacking, and identifier derivation."""

import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import (
    RCLIENT_OK,
    compute_identity_hash,
    r_client_derive_bucket_id,
    r_client_derive_latency_tracker_id,
)
from ratelimitly.protocol import (
    pack_evaluation_request,
    parse_evaluation_response,
)


class TestProtocol(unittest.TestCase):
    def test_compute_identity_hash(self):
        h1 = compute_identity_hash("bucket=v1|scope=api|ip=127.0.0.1")
        self.assertEqual(len(h1), 16)

    def test_derive_bucket_id(self):
        b_id = r_client_derive_bucket_id("api_calls", 60000, 1000)
        self.assertEqual(len(b_id), 16)

    def test_derive_latency_tracker_id(self):
        t_id = r_client_derive_latency_tracker_id("auth_service")
        self.assertEqual(len(t_id), 16)

    def test_pack_and_parse_datagram(self):
        req_id = 123456789
        bucket_hash = b"\x01" * 16
        secret = b"\x02" * 32
        count = 1

        packet = pack_evaluation_request(req_id, bucket_hash, count, secret)
        self.assertEqual(len(packet), 60)

        mock_resp = struct.pack("!QBI I", req_id, 0, 99, 1000)
        status, res = parse_evaluation_response(mock_resp, req_id)
        self.assertEqual(status, RCLIENT_OK)
        self.assertTrue(res.success)
        self.assertEqual(res.remaining_quota, 99)
        self.assertEqual(res.reset_ttl_ms, 1000)


if __name__ == "__main__":
    unittest.main()
