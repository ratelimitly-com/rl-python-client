# `ratelimitly` (RateLimitly Low-Level Python Client)

Official low-level Python client library for **RateLimitly** rate limiting.

1-to-1 mirror of **`rl-c-client`** specification, error codes, Bech32 credential parsing, BLAKE2s identifier derivation, and binary UDP wire protocol.

---

## Features

- **Direct Low-Level C-Client Mirror**: Returns raw status codes (`RCLIENT_OK`, `RCLIENT_ERR_TIMEOUT`, `RCLIENT_ERR_DNS`, etc.) without high-level opinionated fallbacks.
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

## Quickstart Example

### Synchronous Usage

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

### Asynchronous Usage (`asyncio`)

```python
import asyncio
from ratelimitly import AsyncRateLimitlyClient, ResourceRequest, RCLIENT_OK, r_client_derive_bucket_id

async def main():
    client = AsyncRateLimitlyClient(auth_key="rl-aes1...")
    bucket_id = r_client_derive_bucket_id("api_user_scope", 60000, 100)
    req = ResourceRequest(bucket_id=bucket_id)

    status, result = await client.check_rate_limit([req])
    if status == RCLIENT_OK and result and result.success:
        print("Allowed!")

asyncio.run(main())
```

---

## Documentation

- [API Reference](docs/api.md): Complete module, class, and low-level method reference.
- [Architecture & Wire Protocol](docs/architecture.md): Bech32 credential structure, error codes, and binary wire format.

For web documentation and support, visit [ratelimitly.com](https://ratelimitly.com).

---

## License

MIT
