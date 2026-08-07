# RateLimitly Architecture & Wire Protocol

This document describes the binary wire protocol, authentication credential layout, and high-availability design implemented by the RateLimitly Python client.

---

## 1. Authentication Credentials (Bech32 Keys)

RateLimitly uses human-readable Bech32 string keys:
- Prefix `rl-aes1...`: AES-256 encrypted token credentials.
- Prefix `rl-cookie1...`: HMAC-based signature credentials.

### Credential Layout

Decoding the Bech32 payload produces a binary array:
1. **Key ID (Bytes 0..7)**: 64-bit big-endian unsigned integer identifying the tenant key.
2. **Secret Payload (Bytes 8..39)**: 32-byte secret key used for signing datagrams.

The tenant SRV name defaults to:
```text
_ratelimitly._udp.c-${key_id}.p0.ratelimitly.com
```

---

## 2. Binary UDP Wire Protocol

All evaluations use lightweight UDP datagrams to minimize latency and CPU overhead.

### Evaluation Request Datagram (60 Bytes)

| Field | Type | Offset | Description |
|---|---|---|---|
| `request_id` | `uint64` (big-endian) | `0..7` | Monotonically increasing request identifier. |
| `bucket_hash` | `bytes[16]` | `8..23` | 16-byte BLAKE2s digest of the resource bucket string. |
| `count` | `uint32` (big-endian) | `24..27` | Number of tokens requested (default: 1). |
| `auth_secret` | `bytes[32]` | `28..59` | 32-byte signature derived from the credential secret. |

### Evaluation Response Datagram (17 Bytes)

| Field | Type | Offset | Description |
|---|---|---|---|
| `request_id` | `uint64` (big-endian) | `0..7` | Echoed request identifier for response matching. |
| `verdict` | `uint8` | `8` | `0` = ALLOW, `1` = DENY. |
| `remaining_quota` | `uint32` (big-endian) | `9..12` | Remaining quota in current window. |
| `reset_ttl_ms` | `uint32` (big-endian) | `13..16` | Milliseconds until current quota window resets. |

---

## 3. Server Discovery & HA Failover

1. **DNS SRV Lookup**: Client queries `_ratelimitly._udp.<dns_srv>` to discover active server endpoints.
2. **Parallel/Sequential Retry Dispatch**: Datagrams are transmitted across active endpoints according to the configured `RequestPolicy`.
3. **Fail-Open Resilience**: If all network attempts time out or fail, the client returns `Verdict.ALLOW` when `fail_open=True`.
