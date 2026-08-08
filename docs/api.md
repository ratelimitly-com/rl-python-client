# RateLimitly Low-Level Python API Reference

Low-level Python API reference matching `rl-c-client` concepts and data structures.

---

## Error Codes (`r_client_error_t`)

| Error Code Constant | Integer Value | Description |
|---|---|---|
| `RCLIENT_OK` | `0` | Success. |
| `RCLIENT_ERR_IO` | `-1` | Socket / Network I/O failure. |
| `RCLIENT_ERR_TIMEOUT` | `-2` | Timeout waiting for server response. |
| `RCLIENT_ERR_PROTOCOL` | `-3` | Malformed packet or protocol violation. |
| `RCLIENT_ERR_AUTH` | `-4` | Authentication / Bech32 parsing error. |
| `RCLIENT_ERR_DNS` | `-5` | DNS SRV resolution failure. |
| `RCLIENT_ERR_CONFIG` | `-6` | Invalid configuration parameters. |
| `RCLIENT_ERR_NOMEM` | `-7` | Memory allocation failure. |

---

## Classes & Data Structures

### `RateLimitlyClient` / `AsyncRateLimitlyClient`

```python
class RateLimitlyClient:
    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None
    ) -> None: ...

    def check_rate_limit(
        self,
        resources: List[ResourceRequest],
        guards: Optional[List[LatencyGuard]] = None,
        metrics_label: Optional[str] = None
    ) -> Tuple[int, Optional[RateLimitResult]]: ...

    def report_latency(self, reports: List[ServiceLatencyReport]) -> int: ...
    def close(self) -> None: ...
```

---

### `ResourceRequest`

```python
@dataclass(frozen=True)
class ResourceRequest:
    bucket_id: bytes          # 16-byte BLAKE2s bucket digest
    window_size_ms: int = 60000
    rate_limit: int = 1000
    tokens_requested: int = 1
```

---

### `LatencyGuard`

```python
@dataclass(frozen=True)
class LatencyGuard:
    latency_tracker_id: bytes  # 16-byte BLAKE2s tracker digest
    threshold_ms: int          # Max latency threshold (ms) before load shedding
    ttl_ms: int = 300000       # Time-to-live for latency tracker (ms)
    max_samples: int = 64
    buffer_size: int = 8
    min_sample_threshold: int = 1
```

---

### `ServiceLatencyReport`

```python
@dataclass(frozen=True)
class ServiceLatencyReport:
    latency_tracker_id: bytes  # 16-byte BLAKE2s tracker digest
    observed_latency_ms: int   # Downstream service latency sample in milliseconds
    ttl_ms: int = 300000
    max_samples: int = 64
    buffer_size: int = 8
    min_sample_threshold: int = 1
```

---

### `RateLimitResult`

```python
@dataclass(frozen=True)
class RateLimitResult:
    success: bool            # True if granted (all deficits 0 & latency guards passed)
    server_id: int          # 64-bit ID of responding server
    remaining_quota: int     # Remaining quota tokens
    reset_ttl_ms: int        # Milliseconds until quota resets
```

---

## Identifier Derivation Helpers

```python
def r_client_derive_bucket_id(
    bucket_name: str,
    window_size_ms: int,
    rate_limit: int
) -> bytes: ...

def r_client_derive_latency_tracker_id(
    service_name: str,
    ttl_ms: int = 300000,
    max_samples: int = 64,
    buffer_size: int = 8,
    min_sample_threshold: int = 1
) -> bytes: ...
```
