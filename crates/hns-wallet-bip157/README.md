# hns-wallet-bip157

`hns-wallet-bip157` is the reviewed BIP157/BIP158 peer transport used by
`hns-wallet-rs`. Its Rust library name remains `bip157` so the upstream API is
preserved for the paired BDK adapter.

The crate is derived from `bip157 0.6.3` from the Kyoto project under its
MIT/Apache-2.0 license. The wallet release adds the transaction-publication and
witness-block behavior required by its approved-broadcast recovery contract:

- transaction packages are retained by both txid and wtxid;
- every peer active at submission receives immutable parent-before-child
  payloads after BIP339 inventory announcement;
- completion occurs only after the target peer set has received the package;
- transaction-relay connections request normal relay state; and
- witness-block requests reject peers that do not advertise witness service.

This is infrastructure, not a standalone wallet. Consensus, key management,
fee selection, approval, and swap policy remain in the higher-level wallet
crates.

See the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-wallet-rs/blob/v0.2.4/CHANGELOG.md)
and [Bitcoin integration notes](../../docs/BITCOIN_KYOTO.md).
