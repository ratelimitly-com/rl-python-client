# RateLimitly Python client

`ratelimitly` is the official Python client for [RateLimitly](https://ratelimitly.com/), a distributed admission-control service. An application asks whether it may begin work that consumes rate-limited resources. The decision can also depend on recent latency observations for services used by that work.

The library exposes two independent operations:

- A **resource request** atomically asks to consume quantities from zero or more rate buckets, subject to zero or more latency guards. A successful decision represents consumption of every requested quantity and authorizes the work to proceed.
- A **latency report** contributes measured service latencies to one or more trackers. It does not request resources or make an admission decision.

An empty resource request succeeds locally. A guard-only request is sent to RateLimitly and evaluated normally.

## Installation

```bash
pip install ratelimitly
```

## Request one token

In English, this request means: “Give me one token from the `checkout` bucket whose definition is 100 tokens per 1,000 ms.”

```python
from ratelimitly import (
    RCLIENT_OK,
    RateLimitlyClient,
    ResourceRequest,
    r_client_derive_bucket_id,
)

window_size_ms = 1_000
rate_limit = 100

resource = ResourceRequest(
    bucket_id=r_client_derive_bucket_id(
        "checkout",          # Exact application-defined bucket name.
        window_size_ms,      # Bucket window in milliseconds.
        rate_limit,          # Tokens available per window.
    ),
    window_size_ms=window_size_ms,
    rate_limit=rate_limit,
    tokens_requested=1,
)

with RateLimitlyClient("rl-aes1...") as client:
    status, result = client.check_rate_limit([resource])

if status != RCLIENT_OK:
    print(f"No decision: client status {status}")
elif result.success:
    print("Granted; perform the protected work")
else:
    print("Denied; do not perform the protected work")
```

`RCLIENT_OK` means a valid RateLimitly decision was received; it does not mean the request was granted. Check `result.success` for the admission decision.

## Report one measured latency

In English: “Add a 25 ms observation to the `inventory-backend` tracker defined by these storage settings.”

```python
from ratelimitly import (
    RateLimitlyClient,
    ServiceLatencyReport,
    r_client_derive_latency_tracker_id,
)

ttl_ms = 10_000
max_samples = 100
buffer_size = 32
min_sample_threshold = 5

tracker_id = r_client_derive_latency_tracker_id(
    "inventory-backend",    # Exact application-defined tracker name.
    ttl_ms,                  # Maximum sample lifetime.
    max_samples,             # Samples considered by the tracker.
    buffer_size,             # Requested tracker storage.
    min_sample_threshold,    # Warm-up samples before guards take effect.
)

report = ServiceLatencyReport(
    latency_tracker_id=tracker_id,
    observed_latency_ms=25,
    ttl_ms=ttl_ms,
    max_samples=max_samples,
    buffer_size=buffer_size,
    min_sample_threshold=min_sample_threshold,
)

with RateLimitlyClient("rl-aes1...") as client:
    status = client.report_latency([report])
```

Measure the service operation, not the RateLimitly request. Reports are independent of resource requests and may be sent by a different process.

## Add a latency guard

This request asks for the same token only when the tracker’s current latency is below 50 ms:

```python
from ratelimitly import LatencyGuard

guard = LatencyGuard(
    latency_tracker_id=tracker_id,       # Same tracker definition as the report.
    threshold_ms=50,                     # Admission requires current latency < 50 ms.
    ttl_ms=ttl_ms,
    max_samples=max_samples,
    buffer_size=buffer_size,
    min_sample_threshold=min_sample_threshold,
)

with RateLimitlyClient("rl-aes1...") as client:
    status, result = client.check_rate_limit(
        resources=[resource],
        guards=[guard],
    )
```

## Canonical IDs must agree across clients

Bucket IDs include the exact bucket-name bytes, `window_size_ms`, and `rate_limit`. Latency-tracker IDs include the exact tracker-name bytes, `ttl_ms`, `max_samples`, `buffer_size`, and `min_sample_threshold`; a guard threshold is deliberately not part of the tracker ID.

The Python helpers implement the same domain-separated binary preimage, little-endian integer encoding, BLAKE2s-256 digest, and 16-byte truncation as `rl-c-client` v0.6.0. Do not replace them with hashing of formatted text, and do not use `hashlib.blake2s(..., digest_size=16)`: digest length is a BLAKE2 parameter, so that produces a different ID.

See [API reference](docs/api.md#canonical-content-defined-identifiers) for the exact formula and cross-client known-answer vectors.

## High-availability policy

The default policy matches `rl-c-client`: `unit_ms=20`, one replay, a fixed one-unit round duration, one final receive-only unit, and completion delivery enabled. Its deduplication TTL and maximum decision horizon are 60 ms. The initial transmission goes to every discovered r-server, and the oldest known server’s response wins when it arrives within the first round.

See [configuration](docs/configuration.md) for the complete parametrized policy and [architecture](docs/architecture.md) for wire and selection semantics.

## API layers

`RateLimitlyClient` is blocking. `AsyncRateLimitlyClient` provides the same serialized state machine through `asyncio`. A client preserves DNS results and UDP sockets across calls; call `close()` or use the context-manager forms to release them.

The client returns the same status-code family as the C library. It does not choose an application fail-open or fail-closed policy: the caller decides what to do when no RateLimitly decision is available.

## Documentation

- [API reference](docs/api.md)
- [Configuration and request policy](docs/configuration.md)
- [Architecture, wire format, and conformance](docs/architecture.md)

## License

MIT
