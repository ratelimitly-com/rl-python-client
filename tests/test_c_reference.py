"""Optional differential gate against a built rl-c-client v0.6.0 library."""

import ctypes
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.protocol import build_latency_report_body, build_rate_request_body
from ratelimitly.protocol import r_client_derive_bucket_id, r_client_derive_latency_tracker_id
from ratelimitly.types import LatencyGuard, ResourceRequest, ServiceLatencyReport


def random_bytes(generator, length):
    return bytes(generator.getrandbits(8) for _ in range(length))


class CResource(ctypes.Structure):
    _fields_ = [
        ("bucket_id", ctypes.c_ubyte * 16),
        ("window_size_ms", ctypes.c_uint32),
        ("rate_limit", ctypes.c_uint32),
        ("tokens_requested", ctypes.c_uint16),
    ]


class CGuard(ctypes.Structure):
    _fields_ = [
        ("latency_tracker_id", ctypes.c_ubyte * 16),
        ("threshold_ms", ctypes.c_uint32),
        ("ttl_ms", ctypes.c_uint32),
        ("max_samples", ctypes.c_uint32),
        ("buffer_size", ctypes.c_uint32),
        ("min_sample_threshold", ctypes.c_uint32),
    ]


class CReport(ctypes.Structure):
    _fields_ = [
        ("latency_tracker_id", ctypes.c_ubyte * 16),
        ("observed_latency", ctypes.c_uint32),
        ("ttl_ms", ctypes.c_uint32),
        ("max_samples", ctypes.c_uint32),
        ("buffer_size", ctypes.c_uint32),
        ("min_sample_threshold", ctypes.c_uint32),
    ]


class TestCReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library_path = os.environ.get("RL_C_CLIENT_LIBRARY")
        if not library_path:
            raise unittest.SkipTest("RL_C_CLIENT_LIBRARY is not configured")
        cls.library = ctypes.CDLL(library_path)
        byte_pointer = ctypes.POINTER(ctypes.c_ubyte)
        cls.library.r_client_derive_bucket_id.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_uint32,
            byte_pointer,
        ]
        cls.library.r_client_derive_latency_tracker_id.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            byte_pointer,
        ]
        cls.library.r_build_rate_request_body.argtypes = [
            ctypes.POINTER(CResource),
            ctypes.c_size_t,
            ctypes.POINTER(CGuard),
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        cls.library.r_build_latency_report_body.argtypes = [
            ctypes.POINTER(CReport),
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]

    def test_randomized_identifier_derivation_matches_c(self):
        generator = random.Random(0xC0FFEE)
        output = (ctypes.c_ubyte * 16)()
        for _ in range(200):
            name = random_bytes(generator, generator.randrange(0, 65))
            storage = ctypes.create_string_buffer(name) if name else None
            window_size_ms = generator.randrange(0, 2**32)
            rate_limit = generator.randrange(0, 2**32)
            self.assertEqual(
                self.library.r_client_derive_bucket_id(
                    storage, len(name), window_size_ms, rate_limit, output
                ),
                0,
            )
            self.assertEqual(
                bytes(output),
                r_client_derive_bucket_id(name, window_size_ms, rate_limit),
            )

            fields = [generator.randrange(0, 2**32) for _ in range(4)]
            self.assertEqual(
                self.library.r_client_derive_latency_tracker_id(
                    storage, len(name), *fields, output
                ),
                0,
            )
            self.assertEqual(
                bytes(output),
                r_client_derive_latency_tracker_id(name, *fields),
            )

    def test_randomized_request_and_report_bodies_match_c(self):
        generator = random.Random(0x51AFE)
        output = (ctypes.c_ubyte * 1200)()
        output_length = ctypes.c_size_t()

        for case in range(100):
            resources = []
            c_resources = []
            for _ in range(generator.randrange(0, 4)):
                values = (
                    random_bytes(generator, 16),
                    generator.randrange(0, 2**32),
                    generator.randrange(0, 2**32),
                    generator.randrange(0, 2**16),
                )
                resources.append(ResourceRequest(*values))
                c_value = CResource()
                c_value.bucket_id[:] = values[0]
                c_value.window_size_ms = values[1]
                c_value.rate_limit = values[2]
                c_value.tokens_requested = values[3]
                c_resources.append(c_value)

            guards = []
            c_guards = []
            for _ in range(generator.randrange(0, 4)):
                tracker_id = random_bytes(generator, 16)
                threshold = generator.randrange(0, 2**32)
                fields = [generator.randrange(0, 2**32) for _ in range(4)]
                guards.append(LatencyGuard(tracker_id, threshold, *fields))
                c_value = CGuard()
                c_value.latency_tracker_id[:] = tracker_id
                c_value.threshold_ms = threshold
                (
                    c_value.ttl_ms,
                    c_value.max_samples,
                    c_value.buffer_size,
                    c_value.min_sample_threshold,
                ) = fields
                c_guards.append(c_value)

            label = f"label-{case}" if case % 3 == 0 else None
            label_bytes = label.encode("utf-8") if label else None
            resource_array = (
                (CResource * len(c_resources))(*c_resources) if c_resources else None
            )
            guard_array = (CGuard * len(c_guards))(*c_guards) if c_guards else None
            self.assertEqual(
                self.library.r_build_rate_request_body(
                    resource_array,
                    len(c_resources),
                    guard_array,
                    len(c_guards),
                    label_bytes,
                    len(label_bytes or b""),
                    output,
                    len(output),
                    ctypes.byref(output_length),
                ),
                0,
            )
            self.assertEqual(
                bytes(output[: output_length.value]),
                build_rate_request_body(resources, guards, label),
            )

        for _ in range(100):
            reports = []
            c_reports = []
            for _ in range(generator.randrange(1, 5)):
                tracker_id = random_bytes(generator, 16)
                observed = generator.randrange(0, 2**32)
                fields = [generator.randrange(0, 2**32) for _ in range(4)]
                reports.append(ServiceLatencyReport(tracker_id, observed, *fields))
                c_value = CReport()
                c_value.latency_tracker_id[:] = tracker_id
                c_value.observed_latency = observed
                (
                    c_value.ttl_ms,
                    c_value.max_samples,
                    c_value.buffer_size,
                    c_value.min_sample_threshold,
                ) = fields
                c_reports.append(c_value)

            report_array = (CReport * len(c_reports))(*c_reports)
            self.assertEqual(
                self.library.r_build_latency_report_body(
                    report_array,
                    len(c_reports),
                    output,
                    len(output),
                    ctypes.byref(output_length),
                ),
                0,
            )
            self.assertEqual(
                bytes(output[: output_length.value]),
                build_latency_report_body(reports),
            )


if __name__ == "__main__":
    unittest.main()
