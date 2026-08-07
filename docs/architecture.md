# RateLimitly Architecture & Wire Protocol

This document describes the binary wire protocol, Bech32 credential layout, and low-level error model matching `rl-c-client`.

---

## 1. Error Model (`r_client_error_t`)

The library functions return integer status codes directly:
- `RCLIENT_OK` (0): Request processed by server.
- `RCLIENT_ERR_TIMEOUT` (-2): Timeout bound reached without valid response.
- `RCLIENT_ERR_DNS` (-5): Failed to resolve DNS SRV domain.
- `RCLIENT_ERR_IO` (-1): Network socket error.

The client library does not contain framework-specific opinionated fallbacks; higher-level framework integration layers process the status code and implement their own fail-open or fail-closed rules.

---

## 2. Authentication Credentials (Bech32 Keys)

RateLimitly uses Bech32 keys (`rl-aes1...` / `rl-cookie1...`).
Decoding extracts:
- Key ID (uint64)
- 32-byte secret payload

Default tenant SRV domain: `_ratelimitly._udp.c-${key_id}.p0.ratelimitly.com`.

---

## 3. Wire Datagram Layouts

- **Evaluation Request**: 60 bytes (`uint64 request_id`, `16-byte bucket_id`, `uint32 count`, `32-byte auth_secret`).
- **Evaluation Response**: 17 bytes (`uint64 request_id`, `uint8 verdict`, `uint32 remaining`, `uint32 reset_ttl`).
