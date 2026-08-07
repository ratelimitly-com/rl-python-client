# RateLimitly Python API Reference

Complete Python API reference for the `ratelimitly` package.

---

## Top-Level Module Export (`ratelimitly`)

```python
from ratelimitly import (
    RateLimitlyClient,
    AsyncRateLimitlyClient,
    Verdict,
    EvaluationResult,
    RequestPolicy,
    Schedule,
    FixedSchedule,
    LinearSchedule,
    ExponentialSchedule,
    standard_policy,
    single_round_policy,
    custom_policy,
    parse_auth_key,
    AuthKeyInfo,
    compute_identity_hash
)
```

---

## Classes

### `RateLimitlyClient`

Synchronous rate limiting client using socket UDP transport.

```python
class RateLimitlyClient:
    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None,
        fail_open: bool = True
    ) -> None: ...

    def eval(self, bucket_identity: str, count: int = 1) -> Verdict: ...
    def close(self) -> None: ...
```

#### `eval(bucket_identity: str, count: int = 1) -> Verdict`
Evaluates a rate limit bucket identity template. Returns `Verdict.ALLOW` or `Verdict.DENY`.

---

### `AsyncRateLimitlyClient`

Asynchronous rate limiting client using `asyncio` UDP transport.

```python
class AsyncRateLimitlyClient:
    def __init__(
        self,
        auth_key: str,
        dns_srv: Optional[str] = None,
        policy: Optional[RequestPolicy] = None,
        fail_open: bool = True
    ) -> None: ...

    async def eval(self, bucket_identity: str, count: int = 1) -> Verdict: ...
```

---

## Enums & Data Structures

### `Verdict`
- `Verdict.ALLOW = 0`: Request is permitted under the rate limit quota.
- `Verdict.DENY = 1`: Quota exceeded; request must be rejected (429 Too Many Requests).
- `Verdict.FAIL = 2`: Failure encountered (only returned when `fail_open=False`).

---

### `AuthKeyInfo`
Parsed credential details extracted from Bech32 auth keys:
- `auth_type`: `"aes"` or `"cookie"`
- `key_id`: `int` (uint64 tenant key identifier)
- `secret`: `bytes` (32-byte secret key payload)
- `default_dns_srv`: `str` (`"c-${key_id}.p0.ratelimitly.com"`)

---

## Helper Functions

### `parse_auth_key(key_str: str) -> AuthKeyInfo`
Parses Bech32 string (`rl-aes1...` or `rl-cookie1...`). Raises `ValueError` for invalid signatures or lengths.

### `compute_identity_hash(identity_str: str) -> bytes`
Computes canonical 16-byte BLAKE2s digest for bucket templates.
