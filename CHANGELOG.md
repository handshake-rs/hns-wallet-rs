# Changelog

All notable changes to the `hns-wallet-rs` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## Unreleased

- Accept the Android 9 app-sandbox ancestor layout where a root-owned sticky
  `/` is followed by the Android system-owned `/data` boundary. The wallet
  directory and database must still be owned by the application with exact
  `0700` and `0600` modes, respectively.

## 0.2.0 - 2026-08-30

<!-- hns-wallet-release-state: 0.2.0 release -->
Breaking clean-break migration of the wallet and atomic-swap boundary:

- replaced every Denuo registry, wire, storage-domain, controller, FFI, and
  diagnostic identifier with the single canonical Shakescape V1 boundary from
  `hns-p2p-experimental 0.4.0` and `hns-marketplace-protocol 0.4.0`;
- removed the former V2 profile and all Denuo compatibility aliases, decoding
  paths, and test fixtures; unknown registry versions now fail closed;
- retained the complete direct BTC/HNS atomic-swap state machine, recoverable
  board publication and taker/maker execution under the renamed protocol;
- updated HNS wallet synchronization, bulk-name operations, Bitcoin birthday
  handling, native mobile controllers, and minimized projections to use the
  same clean Shakescape boundary without exposing protocol branding in normal
  user-facing swap controls.

## 0.1.1 - 2026-08-23

<!-- hns-wallet-release-state: 0.1.1 release -->
Initial release source for the independent Handshake wallet boundary:

- wallet-local identifiers, summaries, and capability-separated chain APIs;
- authenticated encrypted SQLite persistence with one shared lock and key
  authority;
- a Handshake-first account, name-state, node-RPC, and recovery boundary;
- origin-bound provider permissions, private ABI-v2 framing, trusted host state,
  and an in-process service composition;
- a concrete fail-closed native HNS read-service constructor which binds an
  exact non-value account, authenticated loopback node RPC, and the literal
  shared store authority without enabling browser integration or value;
- the additive native-only `hnsWalletAuthorityContextV1` wire discriminator
  required by the Chromium host candidate, emitted only by the ordinary
  profile-backed mainnet/testnet/regtest service. It binds canonical network,
  active wallet/account, and authenticated profile/account revisions while
  treating the opaque namespace/generation as evidence to be joined under a
  separately held broker guard. This is part of the single initial release
  protocol, not a parallel product release line;
- an explicit recovery-only core and profile-backed service opening path for an
  exact already-persisted HNS account/profile with historical value or
  settlement flags. The flags remain identity only; ordinary/full constructors
  still reject them, while the distinct recovery service exposes exactly six
  non-signing reads with no provider, persistent-permission, current-lock,
  Shakescape, signing, workflow, lifecycle, or value capability;
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
- strict additive consumption of the node wallet RPC
  `name_action_context_v2` response. Wallet-owned TRANSFER and direct-FINALIZE
  preparation/reacquisition now retain exact active-owner Coin evidence rather
  than requiring a pruned owner transaction, independently revalidate the
  canonical NameState, Coin, covenant, inclusion, chain/mempool identity,
  ordered policy reasons, and wallet derivation, and force legacy version-1
  prepared sources through reapproval instead of silently upgrading their
  authority. Descriptor-linked Shakedex paths deliberately retain version 1
  until a separate pruning-safe previous-input linkage exists. This wiring
  changes neither fixed HNS value gate;
- persistence-first Shakedex and chain-neutral market state machines whose live
  product and value gates remain disabled, including a bounded encrypted/CAS
  offline Shakescape V1 offer/cancellation outbox with exact-envelope restart
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
  separate offline board runtime now authenticates canonical Shakescape V1 offers,
  requires the identical encrypted-store authority as a non-value HNS account
  read runtime, obtains runtime-owned time/network plus exact current and
  unspent Shakedex-lock evidence before each CAS admission, keeps exact retries
  revision-stable, and reacquires that live authority before returning a cached
  offer for later use. The same runtime admits signed cancellation tombstones
  through an exact persisted-listing/account-network/trusted-time fence without
  requiring a still-live lock; this negative path performs no node call, keeps
  exact restart/expiry retries revision-stable, and changes no release gate.
  Canonical board writes now emit an encrypted `HeadV2Indexed`, one
  digest-addressed row per seller/name identity, and one encrypted
  digest-addressed listing-hash index per row. Each compact authenticated head
  selector binds the row identity, physical revision/update time, row-value
  commitment, and listing hash, from which the exact listing-index ID set is
  derived. Full loads authenticate the exact bounded namespace and row/index
  bijection. Targeted normalized reads always perform O(N) complete metadata and
  selector comparison. All-hit queries authenticate O(K) index/row values for K
  requested hashes, while any missing requested index triggers the O(N) full
  semantic row/index loader before absence is returned. This authenticates both
  the exact derived index-ID set and the row semantics that a head-only negative
  could not exclude. Writes consume the board namespace lease and, for runtime
  admissions, a second ciphertext-
  fingerprinted `WalletAccount` prefix guard captured before node/clock work and
  refreshed in the same account-plus-board snapshot. Both guards are rechecked
  in the board write transaction. The public unchanged-account verifier remains
  read-only and non-atomic; writes use consume-and-revalidate plus the guard.
  The aggregate legacy-v1 board and historical pre-index `HeadV2` remain strict
  read formats and atomically migrate on their next successful mutation.
  Closed canonical V2 board reads cover singular offers, inventory, and a
  maximum-64 `GetOffers` subset. The batch path preflights its aggregate
  response, verifies every active row under one coherent HNS current-lock
  batch, fences the full requested board projection, discards temporary wire
  bytes, and exposes no transport, publication, signing, or value capability;
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

Version `0.1.1` is the current shared release line. Its complete resolved
Handshake protocol cohort is the published registry `hns-rs` `0.3.1` release
source `0e99addca59778b7b7c6fc56291333a97c4c8815`, pinned by
`release/hns-rs-core-0.3.1-crates.sha256`; the Shakescape `0.4.0` pair is
recorded in `release/hns-rs-shakescape-0.4.0-crates.sha256`. Its light-wallet cohort is the published
registry `hns-dane-engine` `0.2.2` release source
`b7fdf8826c81b77650a0f740d1f05314b74969f9`, pinned by
`release/hns-dane-engine-0.2.2-crates.sha256`. Execute mode downloads and
verifies every upstream archive, API checksum, VCS source path, revision, and
non-yanked status immediately before a wallet upload. These registry pins keep
the direct HNS value composition on reviewed released sources; they do not
introduce a mainnet-value disablement.

Exact source `bc5901f794450d29fa9f5630bab4fbf91e37bedf` passed complete locked
CI `31812028843`, including Wallet qualification and RustSec, and CodeQL
`31812028405` for Actions, JavaScript/TypeScript, Rust, and Python on
2026-08-14. This is source qualification only and does not satisfy publication,
installed-product, network, value, or release-gate requirements.

Exact historical source `3f52586c8befd85d21df5bb89a7ceb0097a0f2bb` passed complete
locked CI `31837067925`, including Wallet qualification and RustSec, and
CodeQL `31837067848` for Actions, JavaScript/TypeScript, Rust, and Python on
2026-08-14. This descendant includes the coherent current-lock batch and
closed `GetOffers` response-plan tranches. The result remains source
qualification only and does not authorize publication, transport, provider,
signing, settlement, value, or any release-gate change.
