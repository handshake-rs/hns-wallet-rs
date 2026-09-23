# hns-wallet-bdk-kyoto

`hns-wallet-bdk-kyoto` is the BDK chain-source adapter paired with
`hns-wallet-bip157` in `hns-wallet-rs`. Its Rust library name remains
`bdk_kyoto`, preserving the upstream adapter API while giving crates.io
consumers an explicit dependency on the wallet’s reviewed transport rather
than a workspace-only patch.

The crate is derived from `bdk_kyoto 0.17.1` under its MIT/Apache-2.0 license.
The adapter logic is intentionally unchanged; only the package identity and
its exact BIP157 dependency are owned by the coordinated wallet release.

This package does not hold keys, choose fees, approve transactions, or define
swap policy. Those responsibilities remain in `hns-wallet-bitcoin-kyoto` and
the native wallet service.

See the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-wallet-rs/blob/v0.2.4/CHANGELOG.md)
and [Bitcoin integration notes](../../docs/BITCOIN_KYOTO.md).
