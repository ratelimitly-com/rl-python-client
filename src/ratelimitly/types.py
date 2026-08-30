"""Public request, response, and status types aligned with rl-c-client."""

from dataclasses import dataclass
from typing import Tuple


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
    """One requested consumption from a content-defined rate bucket."""

    bucket_id: bytes
    window_size_ms: int
    rate_limit: int
    tokens_requested: int


@dataclass(frozen=True)
class LatencyGuard:
    """One admission condition evaluated against a latency tracker."""

    latency_tracker_id: bytes
    threshold_ms: int
    ttl_ms: int
    max_samples: int
    min_sample_threshold: int


@dataclass(frozen=True)
class ServiceLatencyReport:
    """One observed latency contributed to a latency tracker."""

    latency_tracker_id: bytes
    observed_latency_ms: int
    ttl_ms: int
    max_samples: int
    min_sample_threshold: int


@dataclass(frozen=True)
class GuardResult:
    latency_tracker_id: bytes
    threshold_ms: int
    current_latency_ms: int
    passed: bool


@dataclass(frozen=True)
class ResourceResult:
    bucket_id: bytes
    tokens_deficit: int
    actual_rate: int


@dataclass(frozen=True)
class RateLimitResult:
    """A parsed server response; success combines every returned entry."""

    success: bool
    server_id: int
    steering_feedback: bool
    guards: Tuple[GuardResult, ...]
    resources: Tuple[ResourceResult, ...]
