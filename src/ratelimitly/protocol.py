"""RateLimitly wire protocol and canonical content-defined identifiers."""

import hashlib
import hmac
import os
import struct
from typing import Optional, Sequence, Tuple, Union

from .auth import AuthKeyInfo
from .types import (
    GuardResult,
    LatencyGuard,
    RateLimitResult,
    ResourceRequest,
    ResourceResult,
    ServiceLatencyReport,
)


R_TENANT_TLV_LEN = 40
R_PDU_HEADER_LEN = 8
R_MAX_PACKET_SIZE = 1200
R_GUARD_BLOCK_WIRE_LEN = 40
R_RESOURCE_BLOCK_WIRE_LEN = 28
R_SERVICE_LATENCY_BLOCK_WIRE_LEN = 36

R_TLV_TENANT = 0x4C52
R_TLV_AUTH_COOKIE = 0x4143
R_TLV_AUTH_AES = 0x4541
R_TLV_METRICS_LABEL = 0x4C4D

R_PDU_RATE_REQUEST = 0x5452
R_PDU_RATE_RESPONSE = 0x5252
R_PDU_LATENCY_REPORT = 0x524C

IdentifierName = Union[str, bytes, bytearray, memoryview]
WireText = Union[str, bytes, bytearray, memoryview]


def _identifier_name_bytes(name: IdentifierName) -> bytes:
    if isinstance(name, str):
        return name.encode("utf-8")
    if isinstance(name, (bytes, bytearray, memoryview)):
        return bytes(name)
    raise TypeError("identifier name must be str or bytes-like")


def _wire_text_bytes(value: WireText, field_name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{field_name} must be str or bytes-like")


def _integer(value: int, field_name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{field_name} must be in range 0..{maximum}")
    return value


def _uint16(value: int, field_name: str) -> int:
    return _integer(value, field_name, 0xFFFF)


def _uint32(value: int, field_name: str) -> int:
    return _integer(value, field_name, 0xFFFFFFFF)


def _uint64(value: int, field_name: str) -> int:
    return _integer(value, field_name, 0xFFFFFFFFFFFFFFFF)


def _id16(value: bytes, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{field_name} must be bytes-like")
    exact = bytes(value)
    if len(exact) != 16:
        raise ValueError(f"{field_name} must contain exactly 16 bytes")
    return exact


def _derive_content_id(
    domain: bytes,
    name: IdentifierName,
    fields: Tuple[int, ...],
) -> bytes:
    """Mirror rl-c-client's r_hash_content_id_blake2s_128 exactly."""
    name_bytes = _identifier_name_bytes(name)
    if len(name_bytes) > 0xFFFFFFFF:
        raise ValueError("identifier name is too long")

    # C passes sizeof(domain_array), intentionally including the final NUL.
    preimage = bytearray(domain)
    preimage.append(0)
    preimage.extend(struct.pack("<I", len(name_bytes)))
    preimage.extend(name_bytes)
    for index, value in enumerate(fields):
        preimage.extend(struct.pack("<I", _uint32(value, f"field[{index}]")))

    # BLAKE2 digest length is a parameter, so digest_size=16 is different.
    return hashlib.blake2s(preimage).digest()[:16]


def r_client_derive_bucket_id(
    bucket_name: IdentifierName,
    window_size_ms: int,
    rate_limit: int,
) -> bytes:
    """Derive the canonical C-compatible 16-byte rate-bucket ID."""
    return _derive_content_id(
        b"ratelimitly.resource.v1",
        bucket_name,
        (window_size_ms, rate_limit),
    )


def r_client_derive_latency_tracker_id(
    latency_tracker_name: IdentifierName,
    ttl_ms: int,
    max_samples: int,
    buffer_size: int,
    min_sample_threshold: int,
) -> bytes:
    """Derive the canonical C-compatible 16-byte latency-tracker ID."""
    return _derive_content_id(
        b"ratelimitly.latency-tracker.v1",
        latency_tracker_name,
        (ttl_ms, max_samples, buffer_size, min_sample_threshold),
    )


def build_metrics_label_tlv(metrics_label: WireText) -> bytes:
    label = _wire_text_bytes(metrics_label, "metrics_label")
    if len(label) > 0xFFFF:
        raise ValueError("metrics_label is too long")
    body_length = 2 + len(label)
    padding = (-body_length) % 4
    tlv_size = 4 + body_length + padding
    if tlv_size > 0xFFFF:
        raise ValueError("metrics-label TLV is too large")
    return (
        struct.pack("<HHH", R_TLV_METRICS_LABEL, tlv_size, len(label))
        + label
        + bytes(padding)
    )


def build_rate_request_body(
    resources: Sequence[ResourceRequest],
    guards: Sequence[LatencyGuard],
    metrics_label: Optional[WireText] = None,
) -> bytes:
    if len(resources) > 0xFFFF or len(guards) > 0xFFFF:
        raise ValueError("request entry count exceeds uint16")

    body = bytearray(struct.pack("<HH", len(guards), len(resources)))
    for index, guard in enumerate(guards):
        body.extend(
            struct.pack(
                "<16sIIIIII",
                _id16(guard.latency_tracker_id, f"guards[{index}].latency_tracker_id"),
                _uint32(guard.ttl_ms, f"guards[{index}].ttl_ms"),
                _uint32(guard.max_samples, f"guards[{index}].max_samples"),
                _uint32(guard.buffer_size, f"guards[{index}].buffer_size"),
                _uint32(guard.min_sample_threshold, f"guards[{index}].min_sample_threshold"),
                _uint32(guard.threshold_ms, f"guards[{index}].threshold_ms"),
                0,
            )
        )

    for index, resource in enumerate(resources):
        body.extend(
            struct.pack(
                "<16sIIHH",
                _id16(resource.bucket_id, f"resources[{index}].bucket_id"),
                _uint32(resource.window_size_ms, f"resources[{index}].window_size_ms"),
                _uint32(resource.rate_limit, f"resources[{index}].rate_limit"),
                _uint16(resource.tokens_requested, f"resources[{index}].tokens_requested"),
                0,
            )
        )

    if metrics_label is not None:
        label = _wire_text_bytes(metrics_label, "metrics_label")
        if label:
            body.extend(build_metrics_label_tlv(label))

    if len(body) > R_MAX_PACKET_SIZE:
        raise ValueError("rate-request body exceeds the client packet limit")
    return bytes(body)


def build_latency_report_body(reports: Sequence[ServiceLatencyReport]) -> bytes:
    if len(reports) > 0xFFFF:
        raise ValueError("latency report count exceeds uint16")
    body = bytearray(struct.pack("<HH", len(reports), 0))
    for index, report in enumerate(reports):
        body.extend(
            struct.pack(
                "<16sIIIII",
                _id16(report.latency_tracker_id, f"reports[{index}].latency_tracker_id"),
                _uint32(report.ttl_ms, f"reports[{index}].ttl_ms"),
                _uint32(report.max_samples, f"reports[{index}].max_samples"),
                _uint32(report.buffer_size, f"reports[{index}].buffer_size"),
                _uint32(report.min_sample_threshold, f"reports[{index}].min_sample_threshold"),
                _uint32(report.observed_latency_ms, f"reports[{index}].observed_latency_ms"),
            )
        )
    if len(body) > R_MAX_PACKET_SIZE:
        raise ValueError("latency-report body exceeds the client packet limit")
    return bytes(body)


def build_pdu(pdu_type: int, body: bytes) -> bytes:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    exact_body = bytes(body)
    pdu_size = R_PDU_HEADER_LEN + len(exact_body)
    if pdu_size > 0xFFFF or pdu_size > R_MAX_PACKET_SIZE:
        raise ValueError("PDU exceeds the client packet limit")
    return struct.pack("<HHHH", _uint16(pdu_type, "pdu_type"), pdu_size, 0, 0) + exact_body


def build_rate_request_pdu(dedup_ttl_ms: int, body: bytes) -> bytes:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    exact_body = bytes(body)
    pdu_size = R_PDU_HEADER_LEN + len(exact_body)
    if pdu_size > 0xFFFF or pdu_size > R_MAX_PACKET_SIZE:
        raise ValueError("rate-request PDU exceeds the client packet limit")
    return struct.pack(
        "<HHI", R_PDU_RATE_REQUEST, pdu_size, _uint32(dedup_ttl_ms, "dedup_ttl_ms")
    ) + exact_body


def build_authenticated_packet(
    pdu: bytes,
    auth: AuthKeyInfo,
    request_id: bytes,
    timestamp_ms: int,
    tenant_id: Optional[int] = None,
    steering_feedback: bool = False,
    nonce: Optional[bytes] = None,
) -> bytes:
    exact_pdu = bytes(pdu)
    exact_request_id = _id16(request_id, "request_id")
    key_id = auth.key_id if tenant_id is None else _uint64(tenant_id, "tenant_id")
    tenant_header = struct.pack(
        "<HHQ16sQBBBB",
        R_TLV_TENANT,
        R_TENANT_TLV_LEN,
        key_id,
        exact_request_id,
        _uint64(timestamp_ms, "timestamp_ms"),
        1 if steering_feedback else 0,
        0,
        0,
        0,
    )

    if auth.auth_type == "cookie":
        packet = (
            tenant_header
            + struct.pack("<HH", R_TLV_AUTH_COOKIE, 36)
            + auth.secret
            + exact_pdu
        )
    elif auth.auth_type == "aes":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        exact_nonce = os.urandom(12) if nonce is None else bytes(nonce)
        if len(exact_nonce) != 12:
            raise ValueError("nonce must contain exactly 12 bytes")
        auth_header = struct.pack("<HH", R_TLV_AUTH_AES, 32)
        aad = tenant_header + auth_header + exact_nonce
        ciphertext_and_tag = AESGCM(auth.secret).encrypt(exact_nonce, exact_pdu, aad)
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        packet = tenant_header + auth_header + exact_nonce + tag + ciphertext
    else:
        raise ValueError("unsupported authentication type")

    if len(packet) > R_MAX_PACKET_SIZE:
        raise ValueError("authenticated packet exceeds the client packet limit")
    return packet


def _extract_authenticated_pdu(
    packet: bytes,
    auth: AuthKeyInfo,
) -> Tuple[bytes, int, bytes, bool]:
    if len(packet) < R_TENANT_TLV_LEN + 4:
        raise ValueError("truncated packet")
    (
        tlv_type,
        tenant_size,
        server_id,
        request_id,
        _timestamp,
        steering,
        _management,
        _p0,
        _p1,
    ) = struct.unpack("<HHQ16sQBBBB", packet[:R_TENANT_TLV_LEN])
    if (
        tlv_type != R_TLV_TENANT
        or tenant_size < R_TENANT_TLV_LEN
        or tenant_size > len(packet)
    ):
        raise ValueError("invalid tenant TLV")

    auth_type, auth_size = struct.unpack_from("<HH", packet, tenant_size)
    auth_body_start = tenant_size + 4
    pdu_start = tenant_size + auth_size
    if auth_size < 4 or pdu_start > len(packet):
        raise ValueError("invalid authentication TLV")

    if auth.auth_type == "cookie":
        if auth_type != R_TLV_AUTH_COOKIE or auth_size != 36:
            raise ValueError("unexpected cookie authentication TLV")
        cookie = packet[auth_body_start:pdu_start]
        if len(cookie) != 32 or not hmac.compare_digest(cookie, auth.secret):
            raise ValueError("invalid response cookie")
        pdu = packet[pdu_start:]
    elif auth.auth_type == "aes":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if auth_type != R_TLV_AUTH_AES or auth_size != 32:
            raise ValueError("unexpected AES authentication TLV")
        nonce = packet[auth_body_start:auth_body_start + 12]
        tag = packet[auth_body_start + 12:pdu_start]
        ciphertext = packet[pdu_start:]
        if len(nonce) != 12 or len(tag) != 16 or not ciphertext:
            raise ValueError("invalid AES authentication body")
        aad = packet[:auth_body_start] + nonce
        try:
            pdu = AESGCM(auth.secret).decrypt(nonce, ciphertext + tag, aad)
        except Exception as error:
            raise ValueError("AES response authentication failed") from error
    else:
        raise ValueError("unsupported authentication type")

    return request_id, server_id, pdu, bool(steering)


def parse_rate_response_packet(packet: bytes, auth: AuthKeyInfo) -> Tuple[bytes, RateLimitResult]:
    request_id, server_id, pdu, steering = _extract_authenticated_pdu(bytes(packet), auth)
    if len(pdu) < R_PDU_HEADER_LEN:
        raise ValueError("truncated response PDU")
    pdu_type, pdu_size = struct.unpack_from("<HH", pdu)
    if pdu_type != R_PDU_RATE_RESPONSE or pdu_size < R_PDU_HEADER_LEN or pdu_size > len(pdu):
        raise ValueError("invalid rate-response PDU")
    body = pdu[R_PDU_HEADER_LEN:pdu_size]
    if len(body) < 4:
        raise ValueError("truncated rate-response body")

    guard_count, resource_count = struct.unpack_from("<HH", body)
    expected = (
        4
        + guard_count * R_GUARD_BLOCK_WIRE_LEN
        + resource_count * R_RESOURCE_BLOCK_WIRE_LEN
    )
    if len(body) < expected:
        raise ValueError("truncated rate-response entries")

    offset = 4
    guards = []
    success = True
    for _ in range(guard_count):
        (
            tracker_id,
            _ttl,
            _max_samples,
            _buffer_size,
            _minimum,
            threshold,
            current,
        ) = struct.unpack_from("<16sIIIIII", body, offset)
        passed = current < threshold
        guards.append(GuardResult(tracker_id, threshold, current, passed))
        success = success and passed
        offset += R_GUARD_BLOCK_WIRE_LEN

    resources = []
    for _ in range(resource_count):
        bucket_id, _window, actual_rate, deficit, _padding = struct.unpack_from(
            "<16sIIHH", body, offset
        )
        resources.append(ResourceResult(bucket_id, deficit, actual_rate))
        success = success and deficit == 0
        offset += R_RESOURCE_BLOCK_WIRE_LEN

    return request_id, RateLimitResult(
        success=success,
        server_id=server_id,
        steering_feedback=steering,
        guards=tuple(guards),
        resources=tuple(resources),
    )
