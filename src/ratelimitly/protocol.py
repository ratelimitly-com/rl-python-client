"""Binary UDP wire protocol packing, unpacking, and hashing for RateLimitly."""

import struct
import hashlib
from enum import IntEnum
from dataclasses import dataclass


class Verdict(IntEnum):
    ALLOW = 0
    DENY = 1
    FAIL = 2


@dataclass(frozen=True)
class EvaluationResult:
    verdict: Verdict
    remaining_quota: int
    reset_ttl_ms: int


def compute_identity_hash(identity_str: str) -> bytes:
    """
    Computes a 16-byte BLAKE2s digest for bucket identities and latency guard services.
    Matches RateLimitly canonical length-aware identifier hashing.
    """
    return hashlib.blake2s(identity_str.encode("utf-8"), digest_size=16).digest()


def pack_evaluation_request(
    request_id: int,
    bucket_hash: bytes,
    count: int,
    auth_secret: bytes
) -> bytes:
    """
    Packs a RateLimitly binary UDP evaluation request.
    
    Wire format:
    - uint64 request_id
    - 16-byte bucket_hash
    - uint32 count / units
    - 32-byte auth_secret / signature
    """
    if len(bucket_hash) != 16:
        raise ValueError("bucket_hash must be exactly 16 bytes")
    if len(auth_secret) != 32:
        raise ValueError("auth_secret must be exactly 32 bytes")

    header = struct.pack("!Q16sI", request_id, bucket_hash, count)
    return header + auth_secret


def parse_evaluation_response(data: bytes, request_id: int) -> EvaluationResult:
    """
    Parses a RateLimitly binary UDP evaluation response datagram.
    
    Wire format response:
    - uint64 request_id
    - uint8 verdict (0=ALLOW, 1=DENY)
    - uint32 remaining_quota
    - uint32 reset_ttl_ms
    """
    if len(data) < 17:
        raise ValueError("Response datagram too short")

    resp_req_id, verdict_byte, remaining, reset_ttl = struct.unpack("!QBI I", data[:17])
    if resp_req_id != request_id:
        raise ValueError(f"Mismatched response request_id {resp_req_id} != {request_id}")

    verdict = Verdict.ALLOW if verdict_byte == 0 else Verdict.DENY
    return EvaluationResult(
        verdict=verdict,
        remaining_quota=remaining,
        reset_ttl_ms=reset_ttl
    )
