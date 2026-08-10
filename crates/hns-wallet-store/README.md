# hns-wallet-store

`hns-wallet-store` provides the authenticated encrypted SQLite persistence and
shared process-local lock/key authority used by `hns-wallet-rs`.

Embedding applications remain responsible for platform sandbox, filesystem,
backup, and Keystore or Keychain policy. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
security model and target-qualification status.
