# Python API reference

## Client lifecycle

```python
RateLimitlyClient(
    auth_key: str,
    dns_srv: str | None = None,
    policy: RequestPolicy | None = None,
)
```

The credential is decoded and its format version, API-key ID, authentication
mode, secret, and six quotas are validated at construction. `AuthKeyInfo`
exposes `format_version`, the five existing quota fields, and
`rate_window_size_ms_max`. When `dns_srv` is omitted, the client derives
`c-<key-id>.p0.ratelimitly.com`.

The client caches DNS results and UDP sockets across calls. It is intentionally lock-free like `rl-c-client`; serialize all operations on one instance. Use one instance per worker when requests can execute concurrently.

```python
client.close()
```

`close()` releases sockets and cached discovery state. `RateLimitlyClient` supports `with`; `AsyncRateLimitlyClient` supports `async with`.

## Resource requests

```python
status, result = client.check_rate_limit(
    resources: Sequence[ResourceRequest] | None = None,
    guards: Sequence[LatencyGuard] | None = None,
    metrics_label: str | None = None,
)
```

Resource and guard counts are independent:

| Resources | Guards | Behavior |
| --- | --- | --- |
| zero | zero | Local successful no-op; no DNS lookup or packet. |
| one or more | zero | Rate-bucket consumption request. |
| zero | one or more | Guard-only server request. |
| one or more | one or more | Atomic combined decision. |

`status == RCLIENT_OK` and a non-null result means a valid server decision was selected. `result.success` is true only when every returned guard passed and every resource deficit is zero.

```python
@dataclass(frozen=True)
class ResourceRequest:
    bucket_id: bytes          # Exactly 16 bytes.
    window_size_ms: int       # uint32.
    rate_limit: int           # uint32.
    tokens_requested: int     # uint16.

@dataclass(frozen=True)
class LatencyGuard:
    latency_tracker_id: bytes # Exactly 16 bytes.
    threshold_ms: int         # uint32; passes when current latency is smaller.
    ttl_ms: int               # uint32.
    max_samples: int          # uint32.
    buffer_size: int          # uint32; bounded by the credential.
    min_sample_threshold: int # uint32.
```

An oversized guard buffer or resource window returns `RCLIENT_ERR_PROTOCOL`
before DNS lookup, serialization, or transmission. Resource windows are
validated against the credential's `rate_window_size_ms_max`; the complete
logical request fails when any one resource exceeds the limit.

## Results

```python
@dataclass(frozen=True)
class RateLimitResult:
    success: bool
    server_id: int
    steering_feedback: bool
    guards: tuple[GuardResult, ...]
    resources: tuple[ResourceResult, ...]

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
```

Match result entries by ID rather than array position: a server response can contain a different count or order from the submitted request.

`steering_feedback=True` is the wire “keep port” indication. `False` asks the client to rebind its UDP source port; the Python client closes its persistent sockets after completing that logical request so subsequent sends use newly created sockets.

## Latency reports

```python
status = client.report_latency(reports: Sequence[ServiceLatencyReport])
```

```python
@dataclass(frozen=True)
class ServiceLatencyReport:
    latency_tracker_id: bytes
    observed_latency_ms: int
    ttl_ms: int
    max_samples: int
    buffer_size: int
    min_sample_threshold: int
```

A non-empty batch is encoded into one datagram and sent to every discovered r-server. It expects no response. Reports whose `buffer_size` exceeds the credential quota are filtered, matching the C client; if none remain, the call succeeds without sending. An empty input is a configuration error.

Guards and reports are independent. When they refer to the same tracker, repeat the same tracker ID and all four tracker-definition fields. `threshold_ms` belongs only to the guard.

## Canonical content-defined identifiers

Both helpers accept `str` or bytes-like names. A `str` is encoded as UTF-8; bytes-like input is hashed exactly and may include embedded NULs.

```python
r_client_derive_bucket_id(
    bucket_name,
    window_size_ms: int,
    rate_limit: int,
) -> bytes

r_client_derive_latency_tracker_id(
    latency_tracker_name,
    ttl_ms: int,
    max_samples: int,
    buffer_size: int,
    min_sample_threshold: int,
) -> bytes
```

The common formula is:

```text
preimage = domain_with_final_NUL
         || uint32_le(name_length)
         || exact_name_bytes
         || uint32_le(field_1) || ... || uint32_le(field_n)

id = first_16_bytes(BLAKE2s-256(preimage))
```

Domains and fields:

| Kind | Domain, including final NUL | Ordered fields |
| --- | --- | --- |
| Rate bucket | `ratelimitly.resource.v1\0` | `window_size_ms`, `rate_limit` |
| Latency tracker | `ratelimitly.latency-tracker.v1\0` | `ttl_ms`, `max_samples`, `buffer_size`, `min_sample_threshold` |

The final NUL is part of the contract because the C implementation hashes `sizeof(domain_array)`. BLAKE2s-256 is computed first and then truncated. `BLAKE2s(digest_size=16)` is a different function and is not conformant.

Known-answer vectors copied from `rl-c-client` v0.6.0 (`a9cfc87`):

| Input | ID, hexadecimal |
| --- | --- |
| bucket `checkout`, window `1000`, rate `100` | `f5cf3ad8b8406854b596ba3614f16eff` |
| tracker `inventory-backend`, TTL `10000`, max `100`, buffer `32`, minimum `5` | `0320bf15b884bda367a17e5ffb650441` |
| tracker bytes `binary\0tracker`, every field `UINT32_MAX` | `0696ca52a5bfc5e9c46ba90f3110b728` |

Every client language, server-side diagnostic tool, and configuration generator must reproduce these values.

## Status codes

| Constant | Value | Meaning |
| --- | ---: | --- |
| `RCLIENT_OK` | 0 | Local success or a parsed server decision. |
| `RCLIENT_ERR_IO` | -1 | UDP I/O failed. |
| `RCLIENT_ERR_TIMEOUT` | -2 | Policy horizon ended without a valid response. |
| `RCLIENT_ERR_PROTOCOL` | -3 | Request, response, quota, or packet contract failed. |
| `RCLIENT_ERR_AUTH` | -4 | Authentication operation failed. |
| `RCLIENT_ERR_DNS` | -5 | No usable SRV endpoints were available. |
| `RCLIENT_ERR_CONFIG` | -6 | Client or call configuration is invalid. |
| `RCLIENT_ERR_NOMEM` | -7 | Reserved for parity with the C status family. |

Python construction and identifier helpers raise `TypeError` or `ValueError` for invalid direct arguments. Operational methods return status codes.
