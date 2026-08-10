# Changelog

All notable changes to the `hns-wallet-rs` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## Unreleased

- Added an injectable `MobileHnsReadController` composition which transfers or
  opens one exact shared-store authority, performs bounded synchronized HNS
  reads, and returns a minimized serializable balance/receive/history/known-name/
  module-status snapshot. The existing lifecycle-only mobile controller API is
  preserved. Reads obtain a script-free chain epoch/tip snapshot and reject its
  bound height-zero block when it does not match the selected account network,
  before deriving or transmitting any wallet ScriptId. The concrete
  authenticated loopback node backend is re-exported for native composition;
  no production device transport, provider, value, signing, settlement,
  HNSA/HNSR, Shakedex, or marketplace gate is enabled.

## 0.1.0 - 2026-08-10

Initial release source for the independent Handshake wallet boundary:

- wallet-local identifiers, summaries, and capability-separated chain APIs;
- authenticated encrypted SQLite persistence with one shared lock and key
  authority;
- a Handshake-first account, name-state, node-RPC, and recovery boundary;
- origin-bound provider permissions, private ABI-v2 framing, trusted host state,
  and an in-process service composition;
- atomic single-account mobile create, restore, open, unlock, lock, and status
  control without a WebView or value surface;
- persistence-first Shakedex and chain-neutral market state machines whose live
  product and value gates remain disabled;
- Kyoto-only Bitcoin state and a native-ETH policy/contract verification
  boundary whose settlement permits remain unavailable; and
- deterministic, non-mainnet fixtures for downstream qualification.

The package set also carries a dependency-ordered publication allowlist,
crates.io metadata and archive validation, package-local release notes, exact
ABI schema/vector and Ethereum contract-artifact inventory checks, and an
explicitly confirmed, resumable publication procedure. A source archive or
successful test is not authorization to enable provider, value, settlement,
or marketplace product gates.

Version `0.1.0` is the initial shared release line. Before any wallet upload,
all required `hns-rs` `0.2.0` archives must exist on crates.io and identify the
exact reviewed protocol release commit. Registry and tag state are verified by
the release procedure instead of being encoded as a time-sensitive claim here.
