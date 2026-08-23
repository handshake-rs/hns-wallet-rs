# Qualification matrix

Snapshot: 2026-08-14. This file records source-scoped evidence and the durable
qualification procedure, not transient workflow or registry state. Unit
coverage, source packaging, or publication never authorizes mainnet value.
Evidence is attached to exact commits and is not inherited automatically by
later source.

The complete
[`CI` run `31420628974`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420628974),
[`CodeQL` run `31420627924`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420627924),
and manually dispatched
[`14-crate release preflight` run `31424201574`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31424201574)
all succeeded for exact qualified implementation source
`2229be849557d58a8eb723bcc03349f0f2df9796` on 2026-08-10. The locked gate
includes atomic native bootstrap, synchronized mobile HNS reads, script-free
initial chain binding and wrong-network rejection, approval-v3 provider framing,
Shakedex purpose separation, encrypted BDK persistence, and deterministic
Ethereum contract checks. The isolated preflight normalized and verified all 14
publishable crates without credentials or upload authority.

Exact implementation commit `ba9f013a098679fe8e3d812a7e09020803e27d53`
also passed historical
[`CI` run `31383987461`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987461)
and
[`CodeQL` run `31383987478`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987478).
That baseline predates the final mobile script-free binding order and is retained
only as historical evidence.

Exact historical qualified implementation source
`bc5901f794450d29fa9f5630bab4fbf91e37bedf` passed complete locked
[`CI` run `31812028843`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31812028843),
including Wallet qualification and RustSec, and
[`CodeQL` run `31812028405`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31812028405)
for Actions, JavaScript/TypeScript, Rust, and Python on 2026-08-14. This records
the wallet source with its current dependency pin, HNWR-v2 name-target, and
trusted exact-name-import tranche. Later implementation or release-source
commits must receive
their own exact workflow records before upload. No source workflow result
supplies product, network, value, or release-gate authority.

The historical `hns-rs` `0.2.0` protocol source
`b24b66c382de53330ec21dd3137e056a2bea3e2d` independently passed its complete
[`hns-rs` CI run](https://github.com/handshake-rs/hns-rs/actions/runs/31398600728),
four-language
[`hns-rs` CodeQL run](https://github.com/handshake-rs/hns-rs/actions/runs/31398598588),
and
[`hns-rs` 17-package release preflight](https://github.com/handshake-rs/hns-rs/actions/runs/31399004538)
on 2026-08-10. That is historical upstream protocol-source evidence only; it
does not qualify the current `0.3.0` protocol source itself or change a wallet
product gate. The current wallet candidate pins exact `hns-rs` `0.3.0` Git
revision `88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e`; exact wallet source
`bc5901f` passed the locked CI and CodeQL evidence above, while the 19 upstream
`0.3.0` archives remain unpublished and no separately dispatched normalized
release preflight is recorded for this wallet source.

| Area | Exact source evidence | Persistence/restart and reorg | Product/network evidence | Release status |
| --- | --- | --- | --- | --- |
| Types and chain traits | complete locked workspace CI passed at `2229be8` | n/a | no product dependency | exact source recorded; API review remains |
| Encrypted store/schema v3 | exact `2229be8` CI passed, including atomic bootstrap, rollback, migrations, encrypted CRUD/CAS, and Unix filesystem regressions | source reopen/restart tests; no installed Android/iOS secure-store runtime evidence in this package boundary | downstream mobile candidate source contains Keystore/Keychain wrapping, but device filesystem/runtime qualification remains external | platform qualification pending |
| HNS wallet and names | exact historical `bc5901f` CI passed, including bootstrap, synchronized reads, script-free initial binding, purpose separation, dedicated name targets, trusted exact-text import, name workflows, and fail-closed value-evidence checks | source restart/reorg paths; no multi-process regtest | script-free wallet RPC remains compatible with node `2b267ffe`; pruning-safe wallet-owned name actions pair with selected node main `4275b4e`; current wallet v2 source has local focused and full-crate evidence but exact hosted qualification remains pending; current protocol source pins exact `hns-rs` `0.3.0` revision `88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e` | HNS funding, value, and fee source gates enabled; live product qualification pending |
| Provider core | exact `2229be8` CI passed, including account binding, scoped reads, exact Names consent, and unavailable-method ordering | grants persist; pending approval/UI authority remains process-local | no installed-browser wallet consent or backend E2E | browser and value exposure unavailable |
| Fixed-price Shakedex | exact `2229be8` CI passed, including canonical listing, FINALIZE, reservation, terminal-release, and release-gate tests | source reopen/conflict/reorg/finality tests; no multi-process regtest | no live Denuo, provider, trusted UI, or product coin selection | Shakedex and dependent HNS value source gates enabled; live product integration pending |
| Market sessions | exact `2229be8` workspace CI passed | CAS journal source; recovery evidence incomplete | no pair E2E, rendezvous, or relay transport | unavailable |
| Bitcoin Kyoto | exact `2229be8` CI passed, including encrypted BDK persistence, allocation regressions, and the ahead-tip crash edge | exact source restart resume; no multi-process rollback run | no regtest/P2P/broadcast run | send and settlement hard-disabled; normalized or chunked backend pending |
| Ethereum | exact `2229be8` CI and deterministic contract check passed | offline derivation and dormant primitives only | no embedded Helios/local-chain run; no contract audit | synchronization, history, send, signing, settlement, and mainnet unavailable |
| ABI, service, and host | exact `2229be8` CI passed, including canonical framed projections, approval-v3, session handling, and host retention | private process session/authority state; no installed restart E2E | downstream browser/future-mobile-provider adoption and rendering pending; trusted-native reads are a separate non-provider surface | private control only; browser/value unavailable |
| Mobile controller | exact historical `bc5901f` CI passed the lifecycle, synchronized-read, same-authority, fresh-read, script-free snapshot, zero-script-query wrong-network, trusted import, and failure-lock/retry regressions | atomic seed/account bootstrap and source reopen coverage; installed platform restart remains downstream | downstream Android/iOS 0.5.9 candidate source still requires exact import-binding/UI adoption; no archive-capable production device wallet-index backend, installed-device synchronization, resource benchmark, or production network qualification; the loopback adapter is not device transport | `bc5901f` supplies the library projection, including native direct-value composition; no device import UI is qualified, provider/market integration remains unimplemented, and installed-product qualification is pending |
| Browser products | separate repositories | platform integration pending | no installed/signed E2E | unavailable |

The later native-HNS-read profile/bootstrap tranche adds local source regressions
for encrypted-at-rest provisioning, closed nested schema, locked and partial
bootstrap denial, exact-account matching, concurrent CAS, timestamp rollback,
restart persistence, deletion-protected revocation tombstones,
revoke/re-provision ABA prevention, unknown-schema revocation, and public
non-Serde/non-Clone secret containment. The process-local bootstrap tests add
wrong-secret/absent/revoked/stale/value-profile failure locking, exact
unlock-load-lock-construct-internal-unlock-revalidation, closed six-request
service admission, live profile rotation/revocation invalidation, and drop-time
locking. This is not installed-browser or desktop-broker evidence. Persisted
credentials additionally reject JSON escape bytes to avoid non-zeroizing
parser scratch allocations. This does not qualify a live node credential,
exclusive cross-process lease, one-shot secret transport, or read operation,
and changes no provider, browser, value, or publication gate.

The historical-flag recovery tranche adds focused local source regressions for
mainnet/testnet value and settlement identity, ordinary/full-constructor
rejection, exact account/profile/revision matching, restart, chain/mempool and
live-revocation fences, an exact capability set without provider dispatch or
persistent permissions, and a real protected Shakedex anchor/high-water pair
whose authenticated recovery read leaves bytes and revisions unchanged while
missing/corrupt pairs fail closed. This evidence does not qualify installed
transport, provider exposure, signing, settlement, value, or any release gate.

The later operation-level read tranche adds local source regressions for the
closed `hnsReadOperationsV1` wire marker, its required `walletOperations`
dependency, the dedicated six-request host admission path, and strict
non-settlement/HNS-only response correlation. Only the full synchronized HNS
read runtime advertises the marker; the account-only runtime and checked-in
control executable do not. This is contract/source evidence, not a native
launcher, installed extension, signed artifact, live node, or availability
qualification. Closed-enum ABI-v2 consumers must adopt the marker in lockstep.

Exact local source commit `77d891cf320f83ecb580e378d1987b3048c5c9ad`
adds schema-v3 Denuo relay-acceptance persistence. Its 24 Shakedex library
tests passed again from an isolated clean checkout with the concurrent wallet
publisher files absent; focused warning-denied Clippy and rustdoc also passed.
That evidence covers canonical endpoint signatures, exact receipt replay and
conflict, schema-v1/v2 migration denial, and restart self-validation only. It
was not hosted CI or CodeQL at that intermediate commit; the code is included
in exact descendant `bc5901f`, whose qualified CI and CodeQL passed. Neither
record supplies live relay/HRM/HNSA authority, board currentness,
installed-product, or value-gate qualification.

The board-cancellation tranche adds focused local source regressions for the
signature/content-authenticated lookup phase, selected-account network/time and
full-selector revision fence, zero-backend-call admission after lock spend,
wrong registry/family/signature/network/seller/time rejection, monotonic
tombstone sequences, zero request ID at the offline board boundary, restart
watermark preservation, cross-network exact-retry rejection, and exact no-write
retry after signed expiry. This was local rather than exact-commit CI at the
intermediate tranche. The source regressions are included in exact descendant
`bc5901f`'s passed gate; live transport/product/value qualification remains
absent and no release gate changes.

The closed single-offer board-read tranche adds focused source regressions for
canonical V2 singular `GetOffer`/`Offer` correlation, mandatory nonzero request
IDs, wrong registry and every other request/response family, malformed and
trailing input, typed missing/cancelled absence without node queries, exact
read-only repeat, restart reacquisition, spent/expired/wrong-network/stale
chain and mempool evidence, and deterministic board replacement during the
current-lock query. A selected-account mutation during runtime clock
observation is also fenced after the clock returns. The opaque plan retains no
response bytes and exposes no listing, lock, transport, provider, or value
capability. These regressions are included in exact descendant `bc5901f`'s
passed CI and CodeQL; that changes no product or release gate.

The closed board-inventory tranche adds focused source regressions for exact
canonical V2 `GetOfferInventory`/`OfferInventory` correlation, mandatory
nonzero request IDs, valid empty inventory, wrong registry and every other
request/response family, malformed and trailing input, and rejection before
account clock or backend access. Read-only repeat and encrypted restart retain
the board revision; cancellation, not-yet-active, expired, and wrong-current-
network rows are omitted with zero node calls. A selected-account mutation
during trusted clock observation fails closed. The opaque plan retains current
hashes and account context privately but exposes neither hashes nor response
bytes and exposes no listing, lock, transport, provider, or value capability.
These regressions passed exact-commit CI/CodeQL at `9649098` and change no
release gate.

The HNSA/HRM network-magic correction adds a public-boundary signed-receipt
regression with an exact zero-valued configured magic and nonzero genesis. It
persists and reopens the terminal receipt, preserves exact idempotent replay,
and rejects an otherwise valid receipt whose configured magic is one without
mutating the prepared row. Zero is therefore neither a sentinel nor a
wildcard; policy fingerprints, receipt signatures, and handoff comparison
continue to bind its exact four-byte little-endian encoding. No release gate
changes. Exact descendant `2061a27e0358c7f00fcc70497ef97f9b89d569da`
passed complete locked CI `31818578772` and four-language CodeQL
`31818578297`; the correction remains source evidence only.

The closed batch-offer board-read tranche adds focused local source
regressions for canonical V2 `GetOffers`, the wallet/type-5 limit of 64 before
store/backend/clock access despite the protocol's larger request bound, typed
all-absent board identity without an invalid empty response, exact sorted
request ordering, missing/cancelled subset behavior, aggregate response-shape
preflight, and one coherent current-lock batch across three returned offers.
It also covers shared seller-script deduplication, duplicate underlying names
failing before backend/clock access, unchanged-board read behavior, exact full
requested-row and revision races, listing expiry, and unchanged false gates.
The opaque public projection contains only request ID, board revision, and
requested/returned counts. Exact source
`3f52586c8befd85d21df5bb89a7ceb0097a0f2bb` passed complete locked CI
`31837067925`, including Wallet qualification and RustSec, and four-language
CodeQL `31837067848`. This supplies no transport, provider, publication,
signing, or value qualification.

The settled normalized-board persistence and query-scale working-tree tranche
contains focused source regressions for coherent read snapshots; bounded,
sorted, never-authoritative prefix metadata; ciphertext-fingerprinted lease
refresh; exact-prefix-set insertion, revision, capacity, and same-metadata ABA
races; cross-kind guard rollback; compare-only assertions; and invalid assertion
or lease shape. Board regressions cover compact `HeadV2Indexed` selectors that
bind row identity/revision/time/value commitment/listing hash, exact derived
listing-index ID sets, all-hit targeted selection, miss-triggered full semantic
fallback, selected-row ciphertext ABA, selector permutation/remapping,
commitment and bijection checks, missing/extra/substituted/torn state, strict
nested schemas, monotonic identity lineage, unchanged-row physical revision
retention, per-record head/row bounds, a cryptographically real 32-row
roundtrip, atomic legacy-v1 migration, and strict pre-index `HeadV2` read plus
next-mutation migration. Runtime regressions cover selected-wallet account lease
capture before external work, refresh in the same account-plus-board snapshot,
the second ciphertext-fingerprinted write guard, and the read-only/non-atomic
unchanged-account diagnostic distinction.

Local final-source runs passed 38 Store library tests, 73 HNS library tests, 42
Shakedex library tests with one ignored, and 26 Denuo board-runtime integration
tests. The focused normalized-storage run passed 18 tests with the same one
ignored; it is an overlapping subset/re-run, not 18 additional independent
tests. The ignored case was then run explicitly in optimized release mode: the
4,096-row persistence qualification passed 1/1, with 47.20s build time and
15.92s test time.

These are local working-tree results, not exact-commit hosted evidence. No
exact-commit CI or CodeQL record, database or broader resource benchmark,
multi-process network test, installed-product evidence, or live transport
evidence has yet been recorded for this tranche. It changes no release gate and
must not inherit any earlier commit's evidence.

`3f52586`, `b8c430d`, `2061a27`, `9649098`, `bc5901f`, `2229be8`, and
`ba9f013` remain exact historical green CI/CodeQL baselines.
This repository records no independent security audit, database or resource
benchmark, multi-process network test, installed-device run, or installed-
browser wallet run for the package boundary. Downstream candidate source does
not enable these fixed gates.

## Qualification commands

The routine workspace gate is:

```bash
./scripts/check.sh
```

It performs release metadata and archive-inventory validation, formatting, a
locked all-target check, warning-denied Clippy, tests, warning-denied docs,
dependency/source-policy checks, deterministic Solidity artifact comparison,
and the npm high-severity audit. Its archive pass uses `cargo package
--no-verify`; it does not repeat package compilation.

The 14 real normalized `cargo publish --dry-run` checks are intentionally
separate. After routine CI succeeds for the exact candidate, manually dispatch
`.github/workflows/release-preflight.yml` with that qualified 40-character SHA
as `expected_commit`. The workflow verifies the exact checkout, has no
publication credentials, and cannot execute an upload.

## Fixed release gates

The following compile-time release gates remain `false`:

- `BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED`;
- every Ethereum synchronization, value, settlement, and mainnet gate.

The HNS value, HNS fee-quote, HNS Shakedex-funding, and three Shakedex source
gates are enabled. Their live operation remains conditional on the applicable
wallet configuration and its exact chain, mempool, ownership, fee, approval,
and persistence evidence. Product and installed-runtime qualification are
separate deliverables, not reasons to retain an intentionally disabled HNS
value path.

Changing any gate requires new exact-commit evidence for its complete adapter,
persistence, restart/reorg, negative, installed-product, resource, and review
boundary. Neither a package version increment nor successful publication is a
gate-change authorization.

## Publication prerequisites

As a historical record, all 17 required hns-rs 0.2.0 archives were published to
crates.io and provenance-verified on 2026-08-14 at exact source commit
`b24b66c382de53330ec21dd3137e056a2bea3e2d`. That superseded record does not
satisfy the current release prerequisite.

Before any wallet upload, all 19 current `hns-rs` `0.3.0` archives must be
visible on crates.io and each archive must identify exact source commit
`88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e` in `.cargo_vcs_info.json`. Those
archives are currently unpublished. The wallet execute path must verify every
archive before it constructs or uploads a wallet archive; any missing archive
or differing protocol provenance aborts execution. Actual publication remains
a separate, explicitly authorized human action. No runtime gate changes.
