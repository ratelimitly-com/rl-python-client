"""RateLimitly low-level Python client library."""

from .auth import parse_auth_key, AuthKeyInfo
from .policy import (
    RequestPolicy,
    Schedule,
    FixedSchedule,
    LinearSchedule,
    ExponentialSchedule,
    standard_policy,
    single_round_policy,
    custom_policy,
)
from .types import (
    ResourceRequest,
    LatencyGuard,
    ServiceLatencyReport,
    RateLimitResult,
    RCLIENT_OK,
    RCLIENT_ERR_IO,
    RCLIENT_ERR_TIMEOUT,
    RCLIENT_ERR_PROTOCOL,
    RCLIENT_ERR_AUTH,
    RCLIENT_ERR_DNS,
    RCLIENT_ERR_CONFIG,
    RCLIENT_ERR_NOMEM,
)
from .protocol import (
    compute_identity_hash,
    r_client_derive_bucket_id,
    r_client_derive_latency_tracker_id,
)
from .client import RateLimitlyClient, AsyncRateLimitlyClient

__version__ = "0.1.0"

__all__ = [
    "RateLimitlyClient",
    "AsyncRateLimitlyClient",
    "ResourceRequest",
    "LatencyGuard",
    "ServiceLatencyReport",
    "RateLimitResult",
    "RCLIENT_OK",
    "RCLIENT_ERR_IO",
    "RCLIENT_ERR_TIMEOUT",
    "RCLIENT_ERR_PROTOCOL",
    "RCLIENT_ERR_AUTH",
    "RCLIENT_ERR_DNS",
    "RCLIENT_ERR_CONFIG",
    "RCLIENT_ERR_NOMEM",
    "RequestPolicy",
    "Schedule",
    "FixedSchedule",
    "LinearSchedule",
    "ExponentialSchedule",
    "standard_policy",
    "single_round_policy",
    "custom_policy",
    "parse_auth_key",
    "AuthKeyInfo",
    "compute_identity_hash",
    "r_client_derive_bucket_id",
    "r_client_derive_latency_tracker_id",
]
