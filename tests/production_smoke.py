#!/usr/bin/env python3
"""Live production protocol smoke test, ported from rl-c-client's P0 probe.

This is a protocol smoke test, not a load test. It sends a small, bounded
number of requests to production and proves two pieces of server state:

  1. A distinctive latency sample can be read back from the same tracker.
  2. A one-token rate bucket admits once and then rejects the next request.

CI supplies a per-run namespace so the test never relies on state left by
another job. The authentication key is read from the environment and is
deliberately never copied into diagnostics.

This module is intentionally NOT named ``test_*.py``: ``python -m unittest
discover -s tests`` must never reach production. CI invokes it directly, and so
can a developer:

    RATELIMITLY_AUTH_KEY=<key> RATELIMITLY_P0_TEST_NAMESPACE=local-1 \
        python tests/production_smoke.py
"""

import os
import re
import sys
import time
from typing import Optional, Sequence, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly import (
    AuthKeyInfo,
    FixedSchedule,
    GuardResult,
    LatencyGuard,
    RateLimitlyClient,
    RateLimitResult,
    RequestPolicy,
    ResourceRequest,
    ResourceResult,
    ServiceLatencyReport,
    RCLIENT_OK,
    RCLIENT_ERR_IO,
    RCLIENT_ERR_TIMEOUT,
    RCLIENT_ERR_PROTOCOL,
    RCLIENT_ERR_AUTH,
    RCLIENT_ERR_DNS,
    RCLIENT_ERR_CONFIG,
    RCLIENT_ERR_NOMEM,
    parse_auth_key,
    r_client_derive_bucket_id,
    r_client_derive_latency_tracker_id,
)

NAMESPACE_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,48}\Z")

# Mirrors rl-c-client's tests/production_p0_profile.sh, which exports
# RATELIMITLY_REQUEST_UNIT_MS=25 and RATELIMITLY_REQUEST_REPLAY_COUNT=3. This
# client takes the same values as an explicit RequestPolicy: four replay rounds
# of one unit plus one final receive unit, a 125 ms decision horizon. The
# library default (20 ms, one replay) is a 60 ms horizon, too tight for a live
# wide-area exchange.
PROFILE_UNIT_MS = 25
PROFILE_REPLAY_COUNT = 3
PROFILE_REPLAY_GAP_UNITS = 1
PROFILE_FINAL_RECEIVE_UNITS = 1

RATE_WINDOW_SIZE_MS = 60000
LATENCY_BUCKET_RATE_LIMIT = 1000
LATENCY_THRESHOLD_MS = 1000
LATENCY_TTL_MS = 10000
LATENCY_MAX_SAMPLES = 1
LATENCY_MIN_SAMPLE_THRESHOLD = 1
REPORTED_LATENCY_MS = 37
LATENCY_POLL_ATTEMPTS = 20
LATENCY_POLL_DELAY_SECONDS = 0.15

LATENCY_METRICS_LABEL = "production-smoke-latency-probe"
RATE_METRICS_LABEL = "production-smoke-rate-probe"

# Production discovery must be derived exclusively from the credential.
# RATELIMITLY_TENANT, RATELIMITLY_EXAMPLE_SERVER_HOST and
# RATELIMITLY_EXAMPLE_SERVER_PORT are the rl-c-client overrides;
# RCLIENT_DNS_SERVER is this client's own resolver override, read by
# ratelimitly.discovery. Any of them would silently retarget the run.
DISCOVERY_OVERRIDES = (
    "RATELIMITLY_TENANT",
    "RATELIMITLY_EXAMPLE_SERVER_HOST",
    "RATELIMITLY_EXAMPLE_SERVER_PORT",
    "RCLIENT_DNS_SERVER",
)

STATUS_NAMES = {
    RCLIENT_OK: "RCLIENT_OK",
    RCLIENT_ERR_IO: "RCLIENT_ERR_IO",
    RCLIENT_ERR_TIMEOUT: "RCLIENT_ERR_TIMEOUT",
    RCLIENT_ERR_PROTOCOL: "RCLIENT_ERR_PROTOCOL",
    RCLIENT_ERR_AUTH: "RCLIENT_ERR_AUTH",
    RCLIENT_ERR_DNS: "RCLIENT_ERR_DNS",
    RCLIENT_ERR_CONFIG: "RCLIENT_ERR_CONFIG",
    RCLIENT_ERR_NOMEM: "RCLIENT_ERR_NOMEM",
}


class SmokeFailure(Exception):
    """A live-production assertion that did not hold."""


def status_name(status: int) -> str:
    return STATUS_NAMES.get(status, f"unknown status {status}")


def scoped_name(test_namespace: str, suffix: str) -> str:
    """Name every object per run so concurrent CI runs cannot collide."""
    return f"p0-{test_namespace}-{suffix}"


def require_environment() -> Tuple[str, str]:
    """Return the credential and namespace, refusing every discovery override."""
    auth_key = os.environ.get("RATELIMITLY_AUTH_KEY", "")
    if not auth_key:
        raise SmokeFailure("RATELIMITLY_AUTH_KEY is required")

    test_namespace = os.environ.get("RATELIMITLY_P0_TEST_NAMESPACE", "")
    if not test_namespace:
        raise SmokeFailure("RATELIMITLY_P0_TEST_NAMESPACE is required")
    if not NAMESPACE_PATTERN.match(test_namespace):
        raise SmokeFailure(
            "RATELIMITLY_P0_TEST_NAMESPACE must be 1..48 characters of [A-Za-z0-9_-]"
        )

    for name in DISCOVERY_OVERRIDES:
        if os.environ.get(name):
            raise SmokeFailure(
                f"{name} must not override key-derived production discovery"
            )
        # Remove even empty values so nothing downstream can observe them.
        os.environ.pop(name, None)

    return auth_key, test_namespace


def read_credential(auth_key: str) -> AuthKeyInfo:
    try:
        return parse_auth_key(auth_key)
    except (TypeError, ValueError) as error:
        # The credential itself is never interpolated into the message.
        raise SmokeFailure(
            "RATELIMITLY_AUTH_KEY is not a valid credential "
            f"({type(error).__name__})"
        ) from error


def production_policy(auth_info: AuthKeyInfo) -> Tuple[RequestPolicy, int]:
    policy = RequestPolicy(
        unit_ms=PROFILE_UNIT_MS,
        replay_count=PROFILE_REPLAY_COUNT,
        replay_gap=FixedSchedule(PROFILE_REPLAY_GAP_UNITS),
        final_receive_units=PROFILE_FINAL_RECEIVE_UNITS,
        completion_delivery=True,
    )
    try:
        horizon_ms = policy.calculate_horizon_ms(auth_info.dedup_ttl_ms_max)
    except ValueError as error:
        raise SmokeFailure(
            f"request profile rejected by the credential: {error} "
            f"(dedup_ttl_ms_max={auth_info.dedup_ttl_ms_max})"
        ) from error
    return policy, horizon_ms


def submit(
    client: RateLimitlyClient,
    resources: Sequence[ResourceRequest],
    guards: Sequence[LatencyGuard],
    metrics_label: str,
    phase: str,
) -> RateLimitResult:
    """Run one complete logical request and require a selected server decision."""
    status, result = client.check_rate_limit(resources, guards, metrics_label)
    if status != RCLIENT_OK or result is None:
        raise SmokeFailure(f"{phase}: check_rate_limit returned {status_name(status)}")
    return result


def find_resource(
    result: RateLimitResult, bucket_id: bytes
) -> Optional[ResourceResult]:
    """Match by ID: a response may reorder or omit entries."""
    for entry in result.resources:
        if entry.bucket_id == bucket_id:
            return entry
    return None


def find_guard(
    result: RateLimitResult, latency_tracker_id: bytes
) -> Optional[GuardResult]:
    for entry in result.guards:
        if entry.latency_tracker_id == latency_tracker_id:
            return entry
    return None


def prove_latency_tracker(client: RateLimitlyClient, test_namespace: str) -> int:
    """Report a distinctive sample and read it back from the same tracker."""
    bucket_id = r_client_derive_bucket_id(
        scoped_name(test_namespace, "latency-bucket"),
        RATE_WINDOW_SIZE_MS,
        LATENCY_BUCKET_RATE_LIMIT,
    )
    tracker_id = r_client_derive_latency_tracker_id(
        scoped_name(test_namespace, "latency-service"),
        LATENCY_TTL_MS,
        LATENCY_MAX_SAMPLES,
        LATENCY_MIN_SAMPLE_THRESHOLD,
    )
    resource = ResourceRequest(
        bucket_id, RATE_WINDOW_SIZE_MS, LATENCY_BUCKET_RATE_LIMIT, 1
    )
    guard = LatencyGuard(
        tracker_id,
        LATENCY_THRESHOLD_MS,
        LATENCY_TTL_MS,
        LATENCY_MAX_SAMPLES,
        LATENCY_MIN_SAMPLE_THRESHOLD,
    )

    phase = "fresh latency admission"
    result = submit(client, (resource,), (guard,), LATENCY_METRICS_LABEL, phase)
    consumed = find_resource(result, bucket_id)
    observed = find_guard(result, tracker_id)
    if consumed is None or observed is None:
        # A response with no entries would make result.success vacuously true.
        raise SmokeFailure(
            f"{phase}: server-{result.server_id} response omitted the bucket "
            f"or tracker entry (guards={len(result.guards)}, "
            f"resources={len(result.resources)})"
        )
    if consumed.tokens_deficit != 0 or not observed.passed:
        raise SmokeFailure(
            f"{phase} was denied by server-{result.server_id} "
            f"(deficit={consumed.tokens_deficit}, "
            f"current_latency_ms={observed.current_latency_ms}, "
            f"threshold_ms={observed.threshold_ms})"
        )

    report = ServiceLatencyReport(
        tracker_id,
        REPORTED_LATENCY_MS,
        LATENCY_TTL_MS,
        LATENCY_MAX_SAMPLES,
        LATENCY_MIN_SAMPLE_THRESHOLD,
    )
    status = client.report_latency((report,))
    if status != RCLIENT_OK:
        raise SmokeFailure(f"latency report failed: {status_name(status)}")

    # This budget counts complete logical requests, never poll wakeups. One
    # logical request leaves the host as up to two servers x two address
    # families x replay_count copies, and the server dedup cache answers every
    # copy, so most replies in flight are stale duplicates of an earlier
    # request. Counting wakeups here -- or inside the client -- would let those
    # duplicates exhaust the patience of the request that follows them
    # (rl-c-client#63). The client is safe by construction: every deadline in
    # ratelimitly.client._receive_until is wall-clock, a reply whose request_id
    # does not match is discarded and the loop simply re-selects.
    phase = "latency read-back"
    last: Optional[GuardResult] = None
    for attempt in range(LATENCY_POLL_ATTEMPTS):
        result = submit(client, (resource,), (guard,), LATENCY_METRICS_LABEL, phase)
        observed = find_guard(result, tracker_id)
        if observed is None:
            raise SmokeFailure(
                f"{phase}: server-{result.server_id} response carried no guard "
                "for the tracker"
            )
        if observed.passed and observed.current_latency_ms == REPORTED_LATENCY_MS:
            return attempt + 1
        last = observed
        if attempt + 1 < LATENCY_POLL_ATTEMPTS:
            time.sleep(LATENCY_POLL_DELAY_SECONDS)

    raise SmokeFailure(
        f"{phase} expected={REPORTED_LATENCY_MS} "
        f"current={last.current_latency_ms} passed={last.passed} "
        f"after {LATENCY_POLL_ATTEMPTS} requests"
    )


def prove_rate_limiter(client: RateLimitlyClient, test_namespace: str) -> int:
    """Admit once against a one-token bucket, then require a rate denial."""
    bucket_id = r_client_derive_bucket_id(
        scoped_name(test_namespace, "rate-bucket"), RATE_WINDOW_SIZE_MS, 1
    )
    resource = ResourceRequest(bucket_id, RATE_WINDOW_SIZE_MS, 1, 1)

    phase = "first rate admission"
    first = submit(client, (resource,), (), RATE_METRICS_LABEL, phase)
    granted = find_resource(first, bucket_id)
    if granted is None:
        raise SmokeFailure(
            f"{phase}: server-{first.server_id} response omitted the bucket entry"
        )
    if not first.success or granted.tokens_deficit != 0:
        raise SmokeFailure(
            f"{phase} was denied by server-{first.server_id} "
            f"(deficit={granted.tokens_deficit}, actual_rate={granted.actual_rate})"
        )

    phase = "second rate admission"
    second = submit(client, (resource,), (), RATE_METRICS_LABEL, phase)
    denied = find_resource(second, bucket_id)
    if denied is None:
        raise SmokeFailure(
            f"{phase}: server-{second.server_id} response omitted the bucket entry"
        )
    # No guard was submitted, so a conforming response carries none and the
    # denial can only be the one-token bucket. rl-c-client instead ships a
    # deliberately inactive tracker, because its admission API always carries
    # one; this client keeps guards and resources independent.
    if second.success or denied.tokens_deficit == 0 or second.guards:
        raise SmokeFailure(
            f"{phase} was not a pure rate denial "
            f"(success={second.success}, deficit={denied.tokens_deficit}, "
            f"guards={len(second.guards)}, "
            f"first_server={first.server_id}, second_server={second.server_id})"
        )
    return denied.tokens_deficit


def main() -> int:
    try:
        auth_key, test_namespace = require_environment()
        auth_info = read_credential(auth_key)
        policy, horizon_ms = production_policy(auth_info)
    except SmokeFailure as failure:
        print(f"production_smoke: {failure}", file=sys.stderr)
        return 1

    client = RateLimitlyClient(auth_key, policy=policy)
    try:
        attempts = prove_latency_tracker(client, test_namespace)
        deficit = prove_rate_limiter(client, test_namespace)
    except SmokeFailure as failure:
        print(f"production_smoke: {failure}", file=sys.stderr)
        return 1
    finally:
        client.close()

    print(
        f"production_smoke: PASS (latency read-back {REPORTED_LATENCY_MS} ms "
        f"after {attempts} request(s), one-token bucket denied with deficit "
        f"{deficit}, {horizon_ms} ms decision horizon)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
