# Architecture, wire format, and conformance

The Python client independently implements the same wire-v2 public protocol
contract as the coordinated C client. It does not wrap or load the C library at
runtime.

## State ownership

One client instance preserves:

- the decoded credential and quotas;
- DNS SRV results;
- one nonblocking UDP socket per address family; and
- the configured request policy.

Calls on one instance must be serialized. `AsyncRateLimitlyClient` enforces serialization for awaited operations; callers must still avoid closing it concurrently with an operation.

## Discovery and server identity

The client queries `_ratelimitly._udp.<tenant-domain>`, resolves every valid SRV target to IPv4 and IPv6 UDP addresses, and extracts the server ID from the target’s `s-<server-id>` prefix. The server ID is also authenticated in each response’s tenant header.

Each logical request snapshots the current endpoint set. If all target IDs are known, responses from IDs outside that snapshot are ignored. The numerically smallest server ID is the oldest under the C client’s server-start ordering and therefore has first-round preference.

## Datagram envelope

All integers are little-endian.

```text
tenant TLV (40 bytes)
authentication TLV
PDU
```

Tenant TLV fields:

| Field | Size |
| --- | ---: |
| type `0x4c52` | 2 |
| TLV size `40` | 2 |
| tenant key ID on requests / server ID on responses | 8 |
| logical request ID | 16 |
| Unix wall timestamp in milliseconds | 8 |
| steering keep-port flag | 1 |
| tenant-management flag | 1 |
| padding | 2 |

Logical request IDs are random UUID-v4-shaped 16-byte values. Every replay and best-effort completion delivery keeps the same ID so server deduplication applies.

Cookie authentication uses a 36-byte TLV: four-byte header plus the credential’s 32-byte cookie, followed by the plaintext PDU.

AES authentication uses a 32-byte TLV: four-byte header, 12-byte nonce, and 16-byte tag, followed by AES-256-GCM ciphertext. The tenant header, authentication header, and nonce are authenticated as AAD.

## Rate request PDU

The PDU header is eight bytes: type `0x5452`, total PDU size, and `dedup_ttl_ms`. The body starts with `uint16 guard_count` and `uint16 resource_count`, followed by guard blocks, resource blocks, and an optional metrics-label TLV.

Guard blocks are 36 bytes:

```text
tracker_id[16], ttl_ms:u32, max_samples:u32,
min_sample_threshold:u32, threshold_ms:u32, current_latency:u32=0
```

Resource blocks are 28 bytes:

```text
bucket_id[16], window_size_ms:u32, rate_limit:u32,
tokens_requested:u16, padding:u16=0
```

The response reuses those block sizes. A guard passes when `current_latency < threshold_ms`; a resource passes when `tokens_deficit == 0`. The combined decision succeeds only when every entry passes.

## Latency-report PDU

The PDU type is `0x524c`. Its body starts with `uint16 report_count` and two reserved zero bytes. Each report is 32 bytes:

```text
tracker_id[16], ttl_ms:u32, max_samples:u32,
min_sample_threshold:u32, observed_latency_ms:u32
```

Reports are sent to all current r-servers and expect no response.

## Identifier conformance

Canonical IDs are not hashes of colon-delimited strings. They are domain-separated hashes of a binary preimage, as specified in [the API reference](api.md#canonical-content-defined-identifiers).

The repository locks this contract with:

- the C client’s three published known-answer vectors, including an embedded-NUL name;
- exact request-body, latency-body, PDU, cookie, and AES envelope tests;
- local UDP tests for request selection and replay behavior; and
- direct development-time differential checks against a pinned wire-v2
  `rl-c-client` commit.

During this conformance work, 200 randomized bucket inputs and 200 randomized latency-tracker inputs matched the C helper byte-for-byte. A further 100 randomized rate-request bodies and 100 randomized latency-report bodies matched the C builders byte-for-byte.

## Packet bound

As in the C client, an authenticated UDP packet must not exceed 1,200 bytes. Oversized batches, labels, or request shapes return a protocol error rather than relying on IP fragmentation.
