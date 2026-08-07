# RateLimitly Python Client Configuration Guide

This guide details configuration options, client initialization parameters, and high-availability (HA) request scheduling policies in the `ratelimitly` Python library.

---

## Client Options

Both `RateLimitlyClient` (synchronous) and `AsyncRateLimitlyClient` (asynchronous) accept the following parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `auth_key` | `str` | *Required* | Bech32 authentication key string (`rl-aes1...` or `rl-cookie1...`). |
| `dns_srv` | `Optional[str]` | `None` | DNS SRV domain name used for server discovery. If omitted, defaults to `c-${key_id}.p0.ratelimitly.com`. |
| `policy` | `Optional[RequestPolicy]` | `standard_policy()` | High-availability request scheduling policy. |
| `fail_open` | `bool` | `True` | Failure handling strategy. If `True`, evaluates to `Verdict.ALLOW` during outages. |

---

## High-Availability (HA) Request Policies

RateLimitly uses UDP datagram scheduling to provide low-latency rate limit decisions. Policies control transmission rounds, timeout bounds, and retry schedules.

### 1. `standard_policy(unit_ms=20)`

- **Description**: Default 3-round transmission policy balancing fast local response with multi-server consensus.
- **Unit Duration**: `20ms` (default)
- **Decision Horizon**: `60ms` total (3 × `unit_ms`)

```python
from ratelimitly import RateLimitlyClient, standard_policy

client = RateLimitlyClient(
    auth_key="rl-aes1...",
    policy=standard_policy(unit_ms=20)
)
```

### 2. `single_round_policy(unit_ms=20)`

- **Description**: Single-transmission policy optimized for minimal network overhead and strict low latency.
- **Decision Horizon**: `unit_ms` (20ms default)

```python
from ratelimitly import single_round_policy

client = RateLimitlyClient(
    auth_key="rl-aes1...",
    policy=single_round_policy(unit_ms=10)
)
```

### 3. `custom_policy(...)`

For advanced workloads requiring custom backoffs or multi-replay schedules:

```python
from ratelimitly import custom_policy, LinearSchedule, ExponentialSchedule

# Linear backoff schedule
linear_pol = custom_policy(
    unit_ms=15,
    replays=3,
    replay_gap=LinearSchedule(initial_units=1, step_units=1, maximum_units=4),
    final_wait_units=2
)

# Exponential backoff schedule
exp_pol = custom_policy(
    unit_ms=10,
    replays=4,
    replay_gap=ExponentialSchedule(initial_units=1, factor=2, maximum_units=8),
    final_wait_units=1
)
```

---

## Failure Handling Strategies (`fail_open`)

When all RateLimitly servers are unreachable or fail to respond within the policy horizon:

- **`fail_open=True` (Default)**: Returns `Verdict.ALLOW`. Guarantees application availability during rate limiter or network disruptions.
- **`fail_open=False`**: Returns `Verdict.FAIL`. Enforces strict fail-closed security for critical operations.

```python
# Strict fail-close configuration
client = RateLimitlyClient(
    auth_key="rl-aes1...",
    fail_open=False
)
```
