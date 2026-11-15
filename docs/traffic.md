# Physical UDP traffic

`client.traffic_stats()` (also on the async adapter) returns an immutable lifetime
snapshot: `sent` and `received` each contain `datagrams`, `payload_bytes`, and
`ip_bytes`; `send_failures` counts failed UDP sends. Snapshots remain available
after closing the client and span socket rotations.

These are physical packets, not logical requests: retries, replica fanout,
completion delivery and latency reports count. Received malformed or unmatched
datagrams count too. DNS traffic is excluded. Failed sends add no sent bytes.
`ip_bytes` estimates payload plus UDP and minimal IP headers: 28 bytes for IPv4
(including IPv4-mapped IPv6) or 48 for IPv6. It excludes Ethernet, IP options and
IPv6 extension headers; it is not a provider invoice measurement.

Counters saturate at unsigned 64-bit maximum. `incomplete` becomes true on
saturation or unavailable address-family information; do not reconcile such a
snapshot. Closing early may leave replica replies unread: server sent bytes can
legitimately exceed client received bytes.
