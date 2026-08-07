"""RateLimitly official Python client library."""

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
from .protocol import Verdict, EvaluationResult, compute_identity_hash
from .client import RateLimitlyClient, AsyncRateLimitlyClient

__version__ = "0.1.0"

__all__ = [
    "RateLimitlyClient",
    "AsyncRateLimitlyClient",
    "Verdict",
    "EvaluationResult",
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
]
