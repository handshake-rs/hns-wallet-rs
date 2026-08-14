# hns-wallet-types

`hns-wallet-types` defines wallet-local identifiers, asset values, capability
names, and UI-safe summaries shared by the `hns-wallet-rs` packages.

`HnsNameReceiveTarget` is intentionally distinct from the ordinary
`ReceiveTarget`; the HNS runtime constructs it only from the dedicated name-key
branch. The DTO itself grants no ownership, signing, value, or provider
authority.

This crate does not perform storage, signing, networking, or value movement.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for the security model and release status.
