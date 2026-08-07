# `ratelimitly` (RateLimitly Python Client)

Official Python client library for **RateLimitly** high-performance rate limiting.

Implements the RateLimitly protocol specification, Bech32 credential parsing, binary UDP wire format, and high-availability request policies.

---

## Features

- **Bech32 Credential Parser**: Parses `rl-aes1...` and `rl-cookie1...` API keys to derive key ID, auth mode, and secret signatures.
- **Default Tenant SRV Auto-Construction**: Automatically resolves `_ratelimitly._udp.c-${api-key-id}.p0.ratelimitly.com` unless overridden.
- **Simplified HA Request Policies**: Full support for `standard` (3-round), `single_round` (1-round), and `custom` schedules (`fixed`, `linear`, `exponential`).
- **Sync & Async Interfaces**: Provides both `RateLimitlyClient` and `AsyncRateLimitlyClient` (`asyncio`).
- **BLAKE2s Identity Hashing**: Canonical 16-byte length-aware hashing matching RateLimitly identity specifications.

---

## Installation

```bash
pip install ratelimitly
```

---

## Quickstart Examples

### Synchronous Usage

```python
from ratelimitly import RateLimitlyClient, Verdict, standard_policy

# Initialize client
client = RateLimitlyClient(
    auth_key="rl-aes1...",
    policy=standard_policy(unit_ms=20),
    fail_open=True
)

# Evaluate rate limit bucket
verdict = client.eval("bucket=v1|scope=api|ip=192.168.1.1", count=1)

if verdict == Verdict.ALLOW:
    print("Request allowed!")
else:
    print("Rate limit exceeded!")
```

### Asynchronous Usage (`asyncio`)

```python
import asyncio
from ratelimitly import AsyncRateLimitlyClient, Verdict

async def main():
    client = AsyncRateLimitlyClient(
        auth_key="rl-aes1...",
        fail_open=True
    )
    
    verdict = await client.eval("bucket=v1|scope=api|user=42")
    if verdict == Verdict.ALLOW:
        print("Allowed!")

asyncio.run(main())
```

---

## Documentation

- [Configuration Guide](docs/configuration.md): Options, client setup, and HA request policies.
- [API Reference](docs/api.md): Complete module, class, and method reference.
- [Architecture & Wire Protocol](docs/architecture.md): Bech32 credential structure, UDP binary wire format, and discovery.

For web documentation and support, visit [ratelimitly.com](https://ratelimitly.com).

---

## License

MIT
