# Configuration and request policy

## Client configuration

```python
client = RateLimitlyClient(
    auth_key="rl-aes1...",  # Required Bech32 credential.
    dns_srv=None,           # Derive the tenant domain from the credential.
    policy=None,            # Use the C-compatible default policy.
)
```

The credential contains format version 1, the API-key ID, a 32-byte cookie or
AES-256-GCM key, and six quotas packed into one 32-bit word. The client verifies
the Bech32 checksum, exact 45-byte payload, version, and quota codes before
accepting it. Legacy unversioned keys and unknown versions are rejected. See
the normative [wire-protocol credential format](https://github.com/ratelimitly-com/rl/blob/main/docs/spec/wire_protocol.md#api-key-quota-word-format-version-1).

When `dns_srv` is omitted, discovery queries:

```text
_ratelimitly._udp.c-<key-id>.p0.ratelimitly.com
```

Only SRV targets of the form `s-<server-id>...` become r-server endpoints. A failed refresh does not invent a default port or server; cached endpoints remain usable, otherwise the operation returns `RCLIENT_ERR_DNS`.

## One parametrized HA policy

Python uses the same single policy model as `rl-c-client`:

```python
RequestPolicy(
    unit_ms: int,
    replay_count: int,
    replay_gap: Schedule,
    final_receive_units: int = 1,
    completion_delivery: bool = True,
)
```

There are no separate “standard,” “single round,” or compatibility policy modes. Those behaviors are parameter choices.

For round `k`, `replay_gap.get_gap(k)` gives the round duration `B(k)` in units. The initial transmission is round zero and each replay adds one round. The final interval is receive-only.

```text
dedup_ttl_ms = unit_ms × (
    B(0) + B(1) + ... + B(replay_count) + final_receive_units
)
```

The computed value is both the request’s deduplication TTL and its maximum decision horizon. It must fit `uint32` and must not exceed the credential’s `dedup_ttl_ms_max`.

## Default

```python
from ratelimitly import default_request_policy

policy = default_request_policy()
```

This produces:

| Parameter | Value |
| --- | ---: |
| `unit_ms` | 20 |
| `replay_count` | 1 |
| schedule | fixed, one unit |
| `final_receive_units` | 1 |
| `completion_delivery` | true |
| deduplication TTL / horizon | 60 ms |

The default sequence is:

1. Send the logical request to every discovered r-server.
2. During the first 20 ms, return immediately if the oldest known r-server responds. Otherwise retain the oldest response received and return it at the round deadline.
3. If no response arrived, resend to servers that have not responded. During this replay round, the first valid response completes the request.
4. If the replay round is also silent, receive without sending for one final 20 ms; the first valid response completes the request.
5. If still silent, return `RCLIENT_ERR_TIMEOUT`.

When a result is selected before the deduplication deadline and `completion_delivery` is enabled, the client best-effort resends the same logical request to missing servers. This helps replicas converge for grants and denials; deduplication prevents a server that already handled the request from consuming it twice.

## Custom fixed, linear, and exponential schedules

```python
from ratelimitly import (
    ExponentialSchedule,
    FixedSchedule,
    LinearSchedule,
    RequestPolicy,
)

fixed = RequestPolicy(
    unit_ms=20,
    replay_count=0,
    replay_gap=FixedSchedule(1),
    final_receive_units=0,
    completion_delivery=False,
)

linear = RequestPolicy(
    unit_ms=10,
    replay_count=3,
    replay_gap=LinearSchedule(
        initial_units=1,
        step_units=1,
        maximum_units=4,
    ),
    final_receive_units=1,
)

exponential = RequestPolicy(
    unit_ms=5,
    replay_count=3,
    replay_gap=ExponentialSchedule(
        initial_units=1,
        factor=2,
        maximum_units=8,
    ),
    final_receive_units=1,
)
```

Validate a policy against a particular credential before using it:

```python
ttl_ms = policy.calculate_horizon_ms(auth_info.dedup_ttl_ms_max)
```

The client performs this validation during construction and again before encoding a request.

## Failure handling belongs to the application

`RCLIENT_ERR_TIMEOUT`, `RCLIENT_ERR_DNS`, and `RCLIENT_ERR_IO` mean that no RateLimitly decision is available. The library does not turn such failures into a grant or denial. Framework integrations and applications must explicitly choose their own fail-open, fail-closed, or fallback behavior.
