"""Low-level binary wire protocol packing, unpacking, and identifier derivation."""

import struct
import hashlib
from typing import Tuple, Optional
from .types import (
    ResourceRequest,
    LatencyGuard,
    ServiceLatencyReport,
    RateLimitResult,
    RCLIENT_OK,
    RCLIENT_ERR_PROTOCOL,
)


def compute_identity_hash(identity_str: str) -> bytes:
    """Computes a 16-byte BLAKE2s digest for bucket or service identifiers."""
    return hashlib.blake2s(identity_str.encode("utf-8"), digest_size=16).digest()


def r_client_derive_bucket_id(
    bucket_name: str,
    window_size_ms: int,
    rate_limit: int
) -> bytes:
    """
    Derives a canonical 16-byte bucket ID.
    """
    payload = f"{bucket_name}:{window_size_ms}:{rate_limit}".encode("utf-8")
    return hashlib.blake2s(payload, digest_size=16).digest()


def r_client_derive_latency_tracker_id(
    service_name: str,
    ttl_ms: int = 300000,
    max_samples: int = 64,
    buffer_size: int = 8,
    min_sample_threshold: int = 1
) -> bytes:
    """
    Derives a canonical 16-byte latency tracker ID.
    """
    payload = f"{service_name}:{ttl_ms}:{max_samples}:{buffer_size}:{min_sample_threshold}".encode("utf-8")
    return hashlib.blake2s(payload, digest_size=16).digest()


def pack_evaluation_request(
    request_id: int,
    bucket_hash: bytes,
    count: int,
    auth_secret: bytes
) -> bytes:
    """Packs RateLimitly binary UDP evaluation request datagram."""
    if len(bucket_hash) != 16:
        raise ValueError("bucket_hash must be 16 bytes")
    if len(auth_secret) != 32:
        raise ValueError("auth_secret must be 32 bytes")

    header = struct.pack("!Q16sI", request_id, bucket_hash, count)
    return header + auth_secret


def parse_evaluation_response(data: bytes, request_id: int) -> Tuple[int, Optional[RateLimitResult]]:
    """
    Parses a RateLimitly binary UDP evaluation response.
    Returns (status, RateLimitResult).
    """
    if len(data) < 17:
        return RCLIENT_ERR_PROTOCOL, None

    resp_req_id, verdict_byte, remaining, reset_ttl = struct.unpack("!QBI I", data[:17])
    if resp_req_id != request_id:
        return RCLIENT_ERR_PROTOCOL, None

    # Extracted server_id from header or response payload
    server_id = resp_req_id
    success = (verdict_byte == 0)

    result = RateLimitResult(
        success=success,
        server_id=server_id,
        remaining_quota=remaining,
        reset_ttl_ms=reset_ttl
    )
    return RCLIENT_OK, result
