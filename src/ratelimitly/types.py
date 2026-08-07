"""Low-level data structures and error codes matching rl-c-client."""

from dataclasses import dataclass
from typing import Optional, List

# Low-level r_client_error_t error codes (matching C-client r_client.h)
RCLIENT_OK = 0
RCLIENT_ERR_IO = -1
RCLIENT_ERR_TIMEOUT = -2
RCLIENT_ERR_PROTOCOL = -3
RCLIENT_ERR_AUTH = -4
RCLIENT_ERR_DNS = -5
RCLIENT_ERR_CONFIG = -6
RCLIENT_ERR_NOMEM = -7


@dataclass(frozen=True)
class ResourceRequest:
    """Represents a rate limit bucket request."""
    bucket_id: bytes  # 16-byte BLAKE2s bucket digest
    window_size_ms: int = 60000
    rate_limit: int = 1000
    tokens_requested: int = 1


@dataclass(frozen=True)
class LatencyGuard:
    """Represents a latency guard threshold check."""
    latency_tracker_id: bytes  # 16-byte BLAKE2s tracker digest
    threshold_ms: int
    ttl_ms: int = 300000
    max_samples: int = 64
    buffer_size: int = 8
    min_sample_threshold: int = 1


@dataclass(frozen=True)
class ServiceLatencyReport:
    """Represents a latency sample report for a service."""
    latency_tracker_id: bytes  # 16-byte BLAKE2s tracker digest
    observed_latency_ms: int
    ttl_ms: int = 300000
    max_samples: int = 64
    buffer_size: int = 8
    min_sample_threshold: int = 1


@dataclass(frozen=True)
class RateLimitResult:
    """Evaluation result returned when status == RCLIENT_OK."""
    success: bool  # True if all resource deficits are 0 and all latency guards passed
    server_id: int  # 64-bit ID of responding server
    remaining_quota: int
    reset_ttl_ms: int
