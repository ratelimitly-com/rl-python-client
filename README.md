# `ratelimitly` (RateLimitly Low-Level Python Client)

Official low-level Python client library for **RateLimitly** rate limiting, latency tracking, and adaptive load shedding.

1-to-1 mirror of **`rl-c-client`** specification, error codes, Bech32 credential parsing, BLAKE2s identifier derivation, and binary UDP wire protocol.

---

## Features

- **Direct Low-Level C-Client Mirror**: Returns raw status codes (`RCLIENT_OK`, `RCLIENT_ERR_TIMEOUT`, `RCLIENT_ERR_DNS`, etc.) without high-level opinionated fallbacks.
- **Latency Guards & Load Shedding**: Evaluates latency guards (`LatencyGuard`) alongside resource requests to automatically shed traffic during downstream service degradation.
- **Background Latency Reporting**: Reports service response times (`ServiceLatencyReport` via `report_latency()`) to feed RateLimitly's server-side latency trackers.
- **Bech32 Credential Parser**: Parses `rl-aes1...` and `rl-cookie1...` API keys into key ID, auth mode, and secret bytes.
- **Identifier Derivation**: `r_client_derive_bucket_id()` and `r_client_derive_latency_tracker_id()` matching C client BLAKE2s hashing.
- **HA Request Policies**: Full support for `standard` (3-round), `single_round` (1-round), and `custom` schedules (`FixedSchedule`, `LinearSchedule`, `ExponentialSchedule`).
- **Sync & Async Interfaces**: Provides both `RateLimitlyClient` and `AsyncRateLimitlyClient` (`asyncio`).

---

## Installation

```bash
pip install ratelimitly
```

---

## Quickstart Examples

### 1. Basic Rate Limit Check (Synchronous)

```python
from ratelimitly import (
    RateLimitlyClient,
    ResourceRequest,
    RCLIENT_OK,
    r_client_derive_bucket_id,
)

# Initialize low-level client
client = RateLimitlyClient(auth_key="rl-aes1...")

# Derive 16-byte bucket ID
bucket_id = r_client_derive_bucket_id(
    bucket_name="api_v1_checkout",
    window_size_ms=60000,
    rate_limit=1000
)

# Create resource request
req = ResourceRequest(bucket_id=bucket_id, tokens_requested=1)

# Check rate limit
status, result = client.check_rate_limit([req])

if status == RCLIENT_OK and result:
    if result.success:
        print(f"Request allowed by server {result.server_id}! Quota remaining: {result.remaining_quota}")
    else:
        print("Rate limit exceeded (429)")
else:
    # Handle low-level error (RCLIENT_ERR_TIMEOUT, RCLIENT_ERR_DNS, RCLIENT_ERR_IO)
    print(f"RateLimitly server check failed with status: {status}")
```

### 2. Latency Guards (Adaptive Load Shedding)

RateLimitly allows checking latency guards alongside rate limits. If a downstream service's latency exceeds the guard threshold, RateLimitly automatically sheds load:

```python
from ratelimitly import (
    RateLimitlyClient,
    ResourceRequest,
    LatencyGuard,
    RCLIENT_OK,
    r_client_derive_bucket_id,
    r_client_derive_latency_tracker_id,
)

client = RateLimitlyClient(auth_key="rl-aes1...")

# 1. Bucket ID for rate limiting
bucket_id = r_client_derive_bucket_id("api_checkout", 60000, 1000)
resource_req = ResourceRequest(bucket_id=bucket_id)

# 2. Latency Guard for microservice load shedding (threshold: 200ms)
tracker_id = r_client_derive_latency_tracker_id("payment_database_service")
guard = LatencyGuard(
    latency_tracker_id=tracker_id,
    threshold_ms=200,      # Max tolerable latency
    ttl_ms=300000,
    max_samples=64,
    buffer_size=8,
    min_sample_threshold=1
)

# Check both rate limits and latency guards in a single datagram
status, result = client.check_rate_limit([resource_req], guards=[guard])

if status == RCLIENT_OK and result and result.success:
    print("Allowed: rate limits and latency guards passed!")
```

### 3. Reporting Latency Metrics

To keep RateLimitly's server-side latency trackers updated with real downstream performance:

```python
from ratelimitly import (
    RateLimitlyClient,
    ServiceLatencyReport,
    RCLIENT_OK,
    r_client_derive_latency_tracker_id,
)

client = RateLimitlyClient(auth_key="rl-aes1...")

tracker_id = r_client_derive_latency_tracker_id("payment_database_service")

# Report observed 85ms latency
report = ServiceLatencyReport(
    latency_tracker_id=tracker_id,
    observed_latency_ms=85
)

status = client.report_latency([report])
if status == RCLIENT_OK:
    print("Latency metric successfully reported!")
```

---

## Documentation

- [Configuration Guide](docs/configuration.md): Options, client setup, and HA request policies.
- [API Reference](docs/api.md): Complete module, class, latency tracking, and method reference.
- [Architecture & Wire Protocol](docs/architecture.md): Bech32 credential structure, error codes, and binary wire format.

For web documentation and support, visit [ratelimitly.com](https://ratelimitly.com).

---

## License

MIT
