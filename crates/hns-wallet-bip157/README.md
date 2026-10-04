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

Version 0.4.2 adds an optional authenticated `VerifiedSyncCache` provider.
Headers are persisted after verification, compact-filter headers after peer
quorum agreement, and raw filters in bounded batches. Restart revalidates
headers and filter commitments, replays only canonical filters, and requires
fresh compact-filter peers before declaring synchronization complete. Cached
filter matching decisions are never reused. Applications must provide an
authenticated store; the `data_dir` option alone does not persist this evidence.

See the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-wallet-rs/blob/main/CHANGELOG.md)
and [Bitcoin integration notes](../../docs/BITCOIN_KYOTO.md).
