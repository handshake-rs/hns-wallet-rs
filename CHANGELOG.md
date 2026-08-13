# Changelog

All notable changes to the `hns-wallet-rs` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.1.0 - 2026-08-10

<!-- hns-wallet-release-state: 0.1.0 candidate -->
Unpublished initial release candidate for the independent Handshake wallet
boundary:

- wallet-local identifiers, summaries, and capability-separated chain APIs;
- authenticated encrypted SQLite persistence with one shared lock and key
  authority;
- a Handshake-first account, name-state, node-RPC, and recovery boundary;
- origin-bound provider permissions, private ABI-v2 framing, trusted host state,
  and an in-process service composition;
- a concrete fail-closed native HNS read-service constructor which binds an
  exact non-value account, authenticated loopback node RPC, and the literal
  shared store authority without enabling browser integration or value;
- atomic single-account mobile create, restore, open, unlock, lock, and status
  control without a WebView or value surface;
- an injectable `MobileHnsReadController` which transfers or opens one exact
  shared-store authority, performs bounded synchronized HNS reads, and returns a
  minimized serializable balance/receive/history/known-name/module-status
  snapshot while preserving the lifecycle-only controller API. Reads obtain a
  script-free chain epoch/tip snapshot and reject a bound wrong-network genesis
  before deriving or transmitting any wallet ScriptId. The authenticated
  loopback backend is re-exported for native composition, but no production
  device transport or product read gate is supplied here;
- persistence-first Shakedex and chain-neutral market state machines whose live
  product and value gates remain disabled, including a bounded encrypted/CAS
  offline Denuo V2 offer/cancellation outbox with exact-envelope restart
  validation and monotonic retry/acknowledgement state;
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
