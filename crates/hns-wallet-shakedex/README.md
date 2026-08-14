# hns-wallet-shakedex

`hns-wallet-shakedex` contains persistence-first fixed-price seller, buyer,
funding, and recovery workflow boundaries. It also supplies a bounded,
encrypted/CAS offline Denuo V2 offer/cancellation outbox. The outbox preserves
exact canonical envelope bytes, persists one deterministic single-flight
handoff before exposing those bytes, and retains monotonic local retry state.
Schema v3 can terminally retain a bounded, canonical, endpoint-signed receipt
that a named relay accepted that exact prepared envelope. The receipt binds
the configured network, HRM root, HNSA service/delegation lineage, endpoint
key, attempt, request, and envelope bytes and self-validates after restart.

The wallet-defined receipt binds an `hns.named-service/v1` HRM resource. That
resource-profile identifier is defined by the draft, but no Denuo application
profile identifier is currently assigned, so integrators must provide a
non-zero caller-owned identifier. The receipt does not prove board inclusion
or currentness, chain/quote authority, or permission to move value. The crate
performs no network I/O and does not turn on any product release gate.

Shakedex creation, discovery, signing, broadcast, and dependent value gates
remain unavailable to products until the documented qualification is complete.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for current status.
