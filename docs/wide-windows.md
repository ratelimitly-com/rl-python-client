# Wide rate windows (source support, unreleased)

Construct `RateLimitlyClient(key, wide_rate_requests=True)` only for explicitly
configured wide-capable servers (health bit 5). Requests with a member above
uint32 milliseconds use QW/RW; all-short requests continue to use RT/RR.
`r_client_derive_bucket_id` automatically retains v1 short IDs and uses v2 for
long windows, including mixed packets. Guards, latency reports and dedup TTLs
are not widened. No timeout fallback or PDU-changing retry is performed.

The supported cookie/AES key reader accepts formats 1 and 2. V1 cap numbers are
unchanged; v2 finite values are exact ints, unlimited is `None`, and `window_cap`
returns the canonical tagged dictionary. Unlimited is never a TTL. Request
windows remain finite, 1..31536000000 ms. No issuance/migration/release is implied.

Run `PYTHONPATH=src python3 -m pytest tests`. On this host, the preexisting
20ms AES replay test also fails on pristine main during cold crypto import;
preimport `cryptography.hazmat.primitives.ciphers.aead` before pytest to isolate
that setup cost from the test's request deadline. No product timing was changed.
