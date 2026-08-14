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
- an explicit recovery-only core and profile-backed service opening path for an
  exact already-persisted HNS account/profile with historical value or
  settlement flags. The flags remain identity only; ordinary/full constructors
  still reject them, while the distinct recovery service exposes exactly six
  non-signing reads with no provider, persistent-permission, current-lock,
  Denuo, signing, workflow, lifecycle, or value capability;
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
- trusted-native exact-text HNS name import serialized with synchronized reads,
  with pre-backend canonical validation, native-bound preflight, fresh proof and
  ownership classification, atomic WalletAccount/KnownName persistence,
  monotonic wallet-bearing `HnsName` derivation rotation, non-wallet
  non-advancement, and minimized service/mobile output. Provider/browser import
  and all value gates remain unavailable;
- persistence-first Shakedex and chain-neutral market state machines whose live
  product and value gates remain disabled, including a bounded encrypted/CAS
  offline Denuo V2 offer/cancellation outbox with exact-envelope restart
  validation, persist-before-return single-flight handoff journaling, explicit
  crash-as-retry recovery, and monotonic bounded failure state, plus a bounded
  encrypted canonical V2 price-round zero-ID gossip cache with exact local-
  policy binding, optional exact predecessor-checkpoint bootstrap, a caller-
  owned trusted `accepted_at_unix` clock, durable canonical reporter-aligned
  current and retired-prefix sequence high-watermarks, and full validation of a
  linked maximum-128-round suffix. Retiring an old row preserves its reporter
  high-watermarks but removes
  its round hash and ID from duplicate detection; the cache provides no quote
  conversion and does not itself confer quote or live-chain authority. A
  separate offline board runtime now authenticates canonical Denuo V2 offers,
  requires the identical encrypted-store authority as a non-value HNS account
  read runtime, obtains runtime-owned time/network plus exact current and
  unspent Shakedex-lock evidence before each CAS admission, keeps exact retries
  revision-stable, and reacquires that live authority before returning a cached
  offer for later use. The same runtime admits signed cancellation tombstones
  through an exact persisted-listing/account-network/trusted-time fence without
  requiring a still-live lock; this negative path performs no node call, keeps
  exact restart/expiry retries revision-stable, and changes no release gate;
- deletion-protected encrypted HNSA/HNSR publisher high-water state with exact
  route-and-endpoint scope, physically independent endpoint-delegation and
  named-route dimensions, persist-before-use nonzero reservations, safe crash
  gaps, bounded CAS retry, monotonic clocks, and full-width `u64` values kept
  separate from SQLite entity revisions. The opaque reservation boundary is
  crate-internal until reviewed HNSA/HNSR signing dependencies are available;
- Kyoto-only Bitcoin state and a native-ETH policy/contract verification
  boundary whose settlement permits remain unavailable; and
- deterministic, non-mainnet fixtures for downstream qualification.

The package set also carries a dependency-ordered publication allowlist,
crates.io metadata and archive validation, package-local release notes, exact
ABI schema/vector and Ethereum contract-artifact inventory checks, and an
explicitly confirmed, resumable publication procedure. The release runner
classifies new crate names and updates to existing crates into fail-closed
605-second and 65-second crates.io cadence buckets, respectively, and rebuilds
an already-published version through Cargo's registry-backed publish dry-run
before exact resume checksum verification. A source archive or successful test
is not authorization to enable provider, value, settlement, or marketplace
product gates.

Version `0.1.0` is the initial shared release line. Historical release evidence
remains recorded: on 2026-08-14, all 17 required `hns-rs` `0.2.0` archives were
published to crates.io and verified to identify the exact protocol release
commit `b24b66c382de53330ec21dd3137e056a2bea3e2d`.

The current dependency tranche instead pins every protocol dependency to exact
unpublished `hns-rs` `0.3.0` Git revision
`88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e`. The wallet crates remain release
candidates, and irreversible wallet publication must fail closed until all 19
current upstream archives are published and each registry archive proves that
exact revision. The dependency update does not enable any provider, value,
settlement, or marketplace gate.

Exact source `bc5901f794450d29fa9f5630bab4fbf91e37bedf` passed complete locked
CI `31812028843`, including Wallet qualification and RustSec, and CodeQL
`31812028405` for Actions, JavaScript/TypeScript, Rust, and Python on
2026-08-14. This is source qualification only and does not satisfy publication,
installed-product, network, value, or release-gate requirements.
