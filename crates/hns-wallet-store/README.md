# hns-wallet-store

`hns-wallet-store` provides the authenticated encrypted SQLite persistence and
shared process-local lock/key authority used by `hns-wallet-rs`.

Its entity API also provides callback-scoped coherent read snapshots, complete
bounded binary-prefix metadata projections, compare-only authenticated revision
assertions, and opaque single-use exact-prefix-set leases. Prefix metadata is
untrusted and is suitable only for fail-closed set comparison; authoritative
values must still be loaded and authenticated individually. Each lease privately
retains a fixed-size fingerprint of every matching ciphertext as well as the
metadata set, so same-metadata ciphertext replacement also invalidates it. A
snapshot can consume and refresh an existing lease before related reads.

A lease-gated batch rechecks the exact database, entity kind, prefix, bound,
metadata, and ciphertext fingerprints under one immediate write transaction
before authenticating current values or making any write. The primary lease
scopes every batch operation; an optional second lease may guard another entity
kind as a compare-only precondition. This supports an atomic board write whose
own namespace is primary while a separately captured `WalletAccount` prefix is
the second guard.

Embedding applications remain responsible for platform sandbox, filesystem,
backup, and Keystore or Keychain policy. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
security model and target-qualification status.
