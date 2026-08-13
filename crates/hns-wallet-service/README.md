# hns-wallet-service

`hns-wallet-service` composes the private framed service, one shared encrypted
store authority, provider policy, and selected non-value HNS reads.

The included executable remains a locked existing-database control surface; it
does not select a live backend or expose a browser transport. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
available library compositions and release gates.

For a separately trusted native browser launcher, the library exposes
`WalletService::new_persistent_native_hns_reads`. It composes the existing
permission-scoped read runtime from one locked shared store, one exact
pre-existing non-value HNS account configuration, and the authenticated
loopback-only node RPC configuration. Its provider surface is limited to
status, accounts, balance, history, receive address, and approval-scoped known
names plus the existing permission and lock controls. It never advertises
`valueMovement` or `browserIntegration`. The executable CLI is intentionally
unchanged: launcher configuration, artifact admission, browser-engine
authority, transport, approval UI, and installed-product qualification remain
downstream responsibilities.

The library-only persistent HNS read composition also offers one explicitly
trusted-native synchronization entry point for `hns-wallet-mobile`. It returns
the already-bounded core snapshot so the mobile crate can immediately build its
minimized typed result. The chain/mempool binding and raw known-name evidence
must not leave that trusted composition; provider callers continue through
permission-scoped projection. This adds no executable backend, provider
transport, signing, value, settlement, or marketplace authority.
