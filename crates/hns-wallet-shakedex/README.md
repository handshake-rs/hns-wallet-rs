# hns-wallet-shakedex

`hns-wallet-shakedex` contains persistence-first fixed-price seller, buyer,
funding, and recovery workflow boundaries. It also supplies a bounded,
encrypted/CAS offline Denuo V2 offer/cancellation outbox. The outbox preserves
exact canonical envelope bytes, persists one deterministic single-flight
handoff before exposing those bytes, and retains monotonic local retry state.
It performs no network I/O and grants no publication or acknowledgement
authority.

Shakedex creation, discovery, signing, broadcast, and dependent value gates
remain unavailable to products until the documented qualification is complete.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for current status.
