# hns-wallet-types

`hns-wallet-types` defines wallet-local identifiers, asset values, capability
names, and UI-safe summaries shared by the `hns-wallet-rs` packages.

`HnsNameReceiveTarget` remains a wire-compatible presentation DTO. The HNS
runtime constructs it from the same canonical account-zero external target as
`ReceiveTarget` and rejects any mismatch. The DTO itself grants no ownership,
signing, value, or provider authority.

This crate does not perform storage, signing, networking, or value movement.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for the security model and release status.
