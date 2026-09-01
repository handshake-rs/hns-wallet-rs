# Implementation status

Snapshot: 2026-08-23. This document describes the implemented source boundary,
fixed availability gates, and dated exact-source evidence. Registry, tag, and
current product state remain external facts. The native HNS value, fee-quote,
and Shakedex source gates are enabled; each live operation still requires its
specific configuration and authenticated runtime evidence. Bitcoin
send/settlement and Ethereum synchronization/history/send/settlement remain
disabled by their own source gates.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 14 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths; historical locked CI, CodeQL, and normalized preflight evidence remains recorded; current source uses published registry `hns-rs` `0.4.1` source `73611a0d83778e157b35f28ca2197d068e83fc61` and published registry `hns-dane-engine` `0.2.2` source `b7fdf8826c81b77650a0f740d1f05314b74969f9`, with exact archive manifests in `release/` | exact wallet CI, CodeQL, and manually dispatched normalized release preflight; authorized wallet publication, tag, and registry verification |
| Wallet types | persisted IDs unchanged; dedicated nonzero base64url service/session/handle/request/approval IDs with redacted diagnostics; decimal integer amounts, roles and capabilities; structurally distinct `ReceiveTarget` and `HnsNameReceiveTarget` DTOs, with the latter intrinsically restricted to the Handshake module and bounded display text | API stabilization review; coordinated HNS Wallet Read v2 (HNWR-v2) consumer adoption before the new name-target projection is treated as product-compatible |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records, including one deletion-protected fixed-ID native HNS read-profile namespace with closed nested schema, CAS rotation, persistent revocation tombstones, and monotonic revision/update-time fences; metadata-bound AEAD; bounded heterogeneous CAS batches; callback-scoped coherent entity snapshots; complete bounded untrusted binary-prefix metadata projections for fail-closed comparison; compare-only authenticated revision assertions; refreshable single-use exact-prefix-set leases with private ciphertext fingerprints; immediate transactions supporting one primary namespace lease plus an optional cross-kind compare-only guard; complete bounded entity and opaque-workflow reads; non-consuming authenticated approval reads; atomic unchanged-approval consume plus workflow/reservation CAS; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux-executed Unix source policy for read-only schema/metadata recognition before write migration, atomic create-new with armed identity-safe database/sidecar cleanup, effective-UID/exact-mode/single-link checks, non-writable host prefix plus an Android-only UID-1000 app-data exception, same-owner private suffix, no-symlink SQLite opens, and repeated file identity checks; cloneable non-debuggable shared lock/key authority with poison-time key clearing | installed Android/iOS filesystem/runtime qualification; host sandbox/ACL/Data Protection/backup evidence; downstream candidate Keystore/Keychain wrapping is not supplied or qualified by this crate; non-Unix secure-open policy; migration/import tooling for populated schema-v1 entity tables; DB benchmarks and audit |
| HNS | create/restore; separated keys; BLAKE2b-160 version-0 addresses; authenticated loopback `hns-node-rs` wallet RPC; synchronized coin, name, and Shakedex snapshots; encrypted restart/reorg state; direct HNS account, transfer, FINALIZE, funding, quote, signing, approval, and broadcast composition; canonical current/proof/owner/spender validation; deterministic encrypted workflows and settlement supervision. Canonical protocol logic comes from published registry `hns-rs` `0.4.1` source `73611a0d83778e157b35f28ca2197d068e83fc61`. | exact historical `bc5901f` locked CI covered dependency, name-target, import, account-read, action-context, MTP, allocation, Shakedex, and fee-policy regressions; the current source requires exact CI/CodeQL/preflight evidence; multi-process regtest, restart/reorg, mempool-conflict, adversarial, three-branch scan, resource, and installed-product qualification remain |
| Provider | exact 43-name vocabulary, all-HNS namespace enforcement, secure origin, opaque authority registry, authority-validated permission/tombstone snapshots, singleton persisted account binding, generation-CAS-bound single-approval `hns_requestAccounts` join, runtime-selection-rechecked `hns_accounts`, additive account-scoped read grants, prompt-disclosed maximum-64 exact name consent with approval-time account/scope reauthentication and unchanged-hash persistence, typed capability snapshot, ephemeral approvals/replay/rates, forbidden methods; checked-in existing-database control dispatcher exposes exactly five controls; library compositions expose the account join alone or the join plus synchronized balance/history/receive/name reads; the internal synchronized snapshot carries a dedicated name receive target, but website `hns_getReceiveAddress` continues to project only the ordinary `HnsCoin` target and no provider method exposes `nameReceiveTarget`; a concrete native-launcher constructor joins the latter to one authenticated loopback RPC backend, production clock, exact non-value account, and literal shared store authority; an encrypted profile API provisions, rotates, and revokes that exact startup configuration, while a process-local bootstrap consumes one zeroizing passphrase plus exact active fence into an already-unlocked exact-six runtime with an additive native-only wallet authority context bound to canonical network, authenticated profile revision, and exact account-row revision; neither is consumed by the executable or website provider; public HNS results omit internal snapshot/proof/resource/owner/derivation evidence | pushed-main exact-SHA qualification for the authority-context producer; private one-shot unlock brokerage, exclusive cross-process database ownership and HRM/HNSA lease/process invalidation, published engine authority adapter, real browser-native transport, exact `hnsNames` trusted-UI adoption, installed restart/regtest/adversarial qualification, and release evidence; no website/provider value capability is currently wired; native value composition remains separate |
| Shakedex | encrypted/CAS seller, buyer, recovery, and typed transaction-plan schemas; opaque canonical fixed-price protocol authority bound to exact hash/network/time/locking coin; typed canonical cancellation; protected monotonic HNS seller-key allocation with purpose-bound signing; canonical fulfillment, explicit-recipient recovery, and script-witness FINALIZE planning; HNS-runtime adapters consume non-serializable current/unspent lock or TRANSFER, active NameState, parent-MTP, maturity, and renewal evidence; durable aggregate buyer-fulfillment/seller-recovery/seller-script-FINALIZE child with exact parent action/bytes/hash, stable TRANSFER/owner/NameState/renewal identity, historical snapshot/mempool evidence, source/funding reservation, revision-bound approval, final-byte-fee/signed-byte/pre-submit-fence evidence, and runtime-owned restart/reorg/conflict/rebroadcast observations; atomic evidence-backed signed-workflow terminal reservation release with audit-only recovery-required reorg handling; source-enabled value authorization/submission with runtime evidence, approval, and persistence enforcement | exact `2229be8` workspace CI covered the canonical listing, FINALIZE, reservation, terminal-release, and fixed-gate tests; product coin selection, complete seller/buyer product and startup orchestration, live node/Shakescape/provider/trusted-UI integration, and multi-process restart/reorg/regtest qualification |
| Shakescape market | signed direct HNS/BTC offers and takes, bilateral proposal/session negotiation, durable execution state, ordered funding gates, independent chain watches, preimage recovery, and redeem/refund state transitions | The board is peer discovery only; signed bilateral terms remain the authority. Installed live-peer interoperability and release evidence remain separate. |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; encrypted account-authenticated CAS state; one shared store authority for BDK state, scan journal, mirrors, approved broadcasts, and bounded per-session HTLC watches; context-bound swap keys; direct-P2P BIP157 descriptor/HTLC scanning; reorg-aware funding/spend confirmation and monotonic preimage retention; exact fee-capped funding/redeem/refund signing; restart-safe exact-byte broadcast resumption; committed-input exclusion; enabled private value permit for the trusted mobile coordinator | normalized or authenticated chunked BDK backend beyond the current 1 MiB aggregate limit; explicit legacy BDK SQLite import tool; watch/record archival; installed live-network/resource qualification and publication evidence |
| Ethereum | separated offline accounts, typed dormant EIP-1559/HTLC and structural evidence primitives, deterministic contract, immutable false synchronization/value/settlement/mainnet gates, opaque runtime permits plus role/address/exact-fee-bound signing types, zeroizing preimages/intermediates, redacted controlled-broadcast artifact | embedded Helios proof source and privately minted evidence authority, persistence/balance/history/nonce/fee/broadcast runtime, redeem/refund verification, local-chain/restart/reorg qualification, approved address and audit |
| FFI/service/host | private ABI v2 with exact approval-schema-v3 negotiation; canonical framing; required sorted/unique canonical `hnsNames` permission disclosures validated by pinned HNS rules; exact prompt-to-pending-to-grant name binding; random host/service/wallet sessions; one typed provider binding; bounded typed frames; a closed `hnsReadOperationsV1` marker for status, exact account, and Handshake-only balance/receive/history/module-status reads with a dedicated host admission path and minimized correlated responses; additive `hnsWalletAuthorityContextV1` request/response outside that six-read enum with canonical network/magic, nonzero broker-claim echo, active wallet/account, authenticated profile/account revisions, and positive lifecycle/readiness flags; locked existing-database subprocess and generic/recovery runtimes advertise no authority marker; the ordinary profile-backed constructor revalidates profile and account evidence around each context; caller-owned clock/entropy, sequencing, response correlation, authority/approval/binding/event replay state; updated Draft 2020-12 private/public/manifest schema bundle and structural/runtime vectors | trusted signed artifact/verifier roots, launcher invocation, one-shot secret transport, exclusive database plus HRM/HNSA namespace lease/process supervision, downstream engine-authority binding integration, compatibility E2E, installed constructor integration, and exact-SHA qualification evidence; browser and FFI value projection remain unimplemented |
| Mobile controller | existing platform-neutral lifecycle API preserved with owned zeroizing 32-byte database key and recovery input, guarded exact-24-word create/restore, complete seed/account bootstrap open, one shared store authority, locked startup, private ABI-v2 negotiation, status/unlock/lock/single-account controls, and fail-closed request/session handling; separate backend/clock-injected read controller composes `HnsAccountReadRuntime` and `PersistentHnsReadRuntime` around that literal authority and returns a bounded serialized balance/ordinary-receive/name-receive/history/minimized-known-name/successful-tip-status snapshot whose outer and name-projection fields are camelCase while nested shared wallet-type fields retain snake_case; `nameReceiveTarget` uses the distinct shared DTO and the explicit `name_receive_target()` getter freshly synchronizes like every other getter; direct trusted-native `import_name_exact_text()` preflights the persisted display bound and returns the same minimized name summary, with invalid input non-poisoning and runtime faults locking; module, exact account, bounded display, and printable display are revalidated at the mobile boundary; a script-free chain snapshot and bound genesis check precede all ScriptId derivation/query, so wrong-network and read failures reject/lock before retry; the loopback backend/config are re-exported; browser/provider/market capabilities rejected; native direct-value composition is available | exact historical `bc5901f` locked CI qualifies that producer source; `hns-dane-browser-mobile` must coordinate the exact wallet revision plus Rust/JNI/C/Kotlin/Swift trusted-UI adoption before exposing import; downstream Android/iOS 0.5.9 candidate source supplies JNI/C projection, Keystore/Keychain wrapping, native recovery/read screens, and off-UI-thread execution, but this crate supplies no import bindings or deadline-enforced archive-capable/wallet-raw-tx-indexed production device backend; secret-buffer lifecycle verification; installed Android/iOS restart/network/resource qualification; native package publication and release evidence; provider remains unimplemented and native value installation qualification remains |
| Testkit | deterministic non-mainnet, hostile-input, reorg, and qualification fixtures | full multi-process network harnesses |
| Browser products | authority and adapter work lives in separate repositories; this wallet producer does not project the dedicated name receive target into website/provider JSON | `hns-dane-browser-mobile` remains pinned to the older consumer contract; coordinated HNWR-v2 adoption is required before its trusted native/mobile surfaces consume `nameReceiveTarget`, followed by installed-extension/native-host and signed-device qualification |

For board compositions, HNS captures a ciphertext-fingerprinted lease for the
complete selected-wallet `WalletAccount` prefix before backend or clock work and
refreshes it in the same snapshot as the related board read. Public
`verify_unchanged_account` remains a read-only diagnostic and is not an atomic
write precondition. Offer and cancellation mutations instead consume
`revalidate_unchanged_account` and pass the refreshed lease as the second
compare-only guard beside the primary board namespace lease in one immediate
transaction.

An explicit historical-flag recovery path is implemented in source. It opens
only an exact already-persisted HNS account/profile with at least one value or
settlement bit, treats those bits as identity rather than capability, and
returns a distinct exact-six service runtime with no provider dispatch,
persistent permissions, value, browser, current-lock/Shakescape, signing, workflow,
import/export, or lifecycle surface. Missing/non-flagged/mismatched/revoked or
stale state fails and relocks; ordinary and full constructors remain gated.
Focused source tests cover mainnet/testnet and both flags, restart and live
fences, exact capabilities, and non-mutating protected high-water reads. This
is recovery access to existing data, not production value availability.

## Pruning-safe name-action authority

The authenticated node adapter now consumes the additive
`name_action_context_v2` method introduced on selected node main
`4275b4e06a07ae3a4afe2db72bdd7c58d2fb1661`. It rejects any response that does
not use context version 2, active-owner projection version 1, the exact
`trusted_node_active_utxo_projection` source, a null transaction position, and
the expected chain epoch plus exact mempool instance/generation. Canonical
NameState bytes and every projected field are checked against the exact active
Coin, covenant, value, outpoint, inclusion, policy reasons, maturity, and
renewal evidence. The inclusion block is independently read under the same
epoch.

Wallet-owned TRANSFER and direct-FINALIZE preparation/reacquisition select this
v2 boundary and require the Coin address to match one exact persisted
`HnsName` derivation. New encrypted plans retain canonical serializable Coin
evidence. Historical v1 plans still decode, but a v2 reacquisition cannot reuse
their source or approval and moves them through explicit reapproval. The
descriptor-linked Shakedex path remains on v1 because it requires the owner
transaction's previous input; v2 intentionally does not supply or imply that
linkage. HNS value and fee source gates are enabled; their runtime checks
remain mandatory.

## HNS value runtime

`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` and
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` are `true`. A wallet-owned native
value controller activates `value_operations_enabled`; settlement remains an
explicit configuration that additionally requires its applicable Shakedex
composition. Capability discovery advertises only the capabilities enabled by
that authenticated account configuration.

Send and settlement-lock preparation now authenticate every current revision,
then atomically commit account change-index advancement, the prepared workflow,
and all input reservations in one bounded SQLite transaction. Duplicate
`(entity kind, record ID)` operations and stale revisions abort the whole batch.
The runtime cache changes only after commit, so failures neither burn addresses
nor reuse a change key nor leave an invisible losing workflow.

Ordinary send and the exposed settlement lock, HTLC redeem, and HTLC refund
paths are wired to quote the exact final signed bytes. Approval remains pending
until signing and quote validation succeed; one atomic store transaction then
consumes the unchanged approval, persists the authorized bytes and quote, and
activates reservations. Submission re-quotes only those persisted bytes and
durably records the refreshed quote plus `RequiresRebroadcast` first. A stale
or unavailable quote input gets one full reconciliation and one retry, never a
polling loop. Wallet-owned P2PKH TRANSFER and direct FINALIZE use the same
boundary and require the same fresh evidence and explicit approval.

The current dependency graph uses published registry `hns-rs` `0.4.1` source
`73611a0d83778e157b35f28ca2197d068e83fc61`, with all 19 upstream archive
checksums in `release/hns-rs-0.4.1-crates.sha256`, and published registry
`hns-dane-engine` `0.2.2` source
`b7fdf8826c81b77650a0f740d1f05314b74969f9`, with all 20 upstream archive
checksums in `release/hns-dane-engine-0.2.2-crates.sha256`. Execute mode
revalidates both cohorts before any wallet upload. Wallet authorization and
installed-product qualification remain separate from the enabled HNS source
gates.

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated and covered by the
  exact `bc5901f` source CI, but multi-process regtest, restart/reorg, malformed-
  transport, stale-cursor, and resource qualification is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- exact confirmed input height/address/covenant evidence now drives canonical
  `hns-script` sigops, policy-size, minimum-fee construction, standardness
  bounds, and independent node-quote comparison and passed the source gate;
  multi-process adapter and product qualification remain to be recorded, while
  `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` is source-enabled;
- name TRANSFER/FINALIZE source workflows consume fresh ephemeral authority and
  exact node action context, but their node/wallet restart/reorg/mempool/product
  qualification and provider/trusted-UI dispatch are not recorded;
- downstream Android/iOS candidate source contains platform key wrapping and
  native recovery/read UI, but secure-path installed-runtime qualification,
  host sandbox/ACL/data-protection/backup evidence, secure provider approval UI,
  browser/native-host integration, and non-Unix secure persistent database
  opening remain unavailable; and
- regtest, restart/reorg, installed-product, resource, and independent security
  qualification have not been recorded for this source tranche.

## Shakedex release gates

`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED` are `true`. Seller creation,
transition, buyer discovery, and buyer transition remain bound to their exact
evidence, persistence, and approval checks before mutation. This also prevents
sessions restored from legacy persisted records from bypassing the boundary.
Independently usable read/discovery boundaries now require
the exact listing hash, network, active time window, and supplied canonical
locking coin; cancellations bind to that exact listing; Shakescape registry and
message family are checked before protocol authority is returned. The boundary
does not authenticate that coin as current or unspent. A full persisted-board
load revalidates every canonical row, watermark, commitment, and listing-index
bijection after restart. Indexed targeted reads always compare the complete
row/index metadata and selector sets. All-hit queries authenticate only K
requested index/row values; any missing requested index invokes the full
semantic loader and authenticates O(N) row/index values before absence is
returned.
Typed adapters can also reconstruct canonical fulfillment, recovery, and
script-controlled FINALIZE plans. Encrypted workflow CAS retains signed
fulfillment and recovery parent plans, and the aggregate now retains a durable
script-controlled FINALIZE child. Its tagged plan fixes the exact signed parent
action/bytes/hash, TRANSFER transaction/output-zero coin, current NameState and
owner inclusion, historical snapshot/mempool binding, and renewal evidence. Their supplied Coin, parent MTP, NameState, renewal block, and funding
suffix remain structural on the low-level compatibility functions. The current-
authority adapters replace the first four with one exact HNS chain/mempool
snapshot.

A distinct aggregate child now covers buyer fulfillment, seller recovery, and
seller-script FINALIZE.
It durably binds the complete parent plan and commitment, exact source and
ordered funding coins, recipient, value, fee/maximum, finality/expiry,
prepared/signed bytes, exact approval and final-byte quote, bounded submission
fence, and chain observations. Initial persistence atomically installs a
globally keyed protected lock-source reservation plus exact account funding
reservations. Runtime time caps prepared rows at five minutes. Prepared
cancellation/expiry releases the whole set; signed states retain it through
reversible rebroadcast, mempool, confirmation, rollback, and conflict states.
Generic HNS cleanup cannot release these rows. A dedicated terminal operation
re-observes the exact transaction and all input spenders in one runtime-owned
snapshot. It atomically persists release evidence and deletes every protected
row only after the expected transaction or an authenticated competing spender
reaches the persisted finality threshold. Released reconciliation is read-only;
changed finality returns `RecoveryRequired` without row recreation or a stage
rollback.

The runtime owns time and chain evidence, recovers funding derivations only by
exact current-cache matches, and keeps lock-source and transfer-source
authority in distinct public type/API/purpose lanes. Save and authorization
reacquire the exact transfer for FINALIZE; submission reacquires it for the
quote and again immediately before the broadcast fence. Harmless fresh binding
advances are accepted only when stable transfer identity is unchanged, while
each immediate HNS operation still requires exact live current/reacquired
bindings. The runtime preserves the script-authorized first input,
signs only the ordinary suffix, and consumes approval only with the CAS that
persists verified signed bytes and their exact quote. Submission re-quotes the
persisted bytes and records `RequiresRebroadcast` plus active reservation
revisions before the node call. Same-snapshot transaction and all-input spender
evidence drives reconciliation, including rollback from a disappeared
confirmation to same-byte rebroadcast. Persisted fee evidence is revalidated
after restart without treating its old snapshot as current authority.

This source still does not select product funding coins, contact live Shakescape
peers, dispatch through a provider/trusted approval UI, integrate product
startup supervision, or constitute restart/reorg/regtest qualification. The
current HNS/FINALIZE regressions are included in the exact CI evidence recorded
in `QUALIFICATION.md`. Purpose-bound seller proof/
listing/cancellation/recovery signing remains separately constrained by
canonical terms and current-lock authority. No Shakedex or dependent HNS
Shakedex-funding/value/fee gate is enabled.

## Bitcoin value release gate

`BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` is enabled for the connected mobile
controller. Bitcoin receive, history, send, and atomic settlement are
advertised; only trusted Rust orchestration can construct the private value
permit.

The broadcast boundary requires a durable ready scan, a running Kyoto
node, configured peer quorum, owned unspent inputs, BDK-calculated exact fee,
and a canonical approval commitment over network, txid, wtxid, exact fee, fee
maximum, and exclusive expiry. Native-send signing and broadcast both require
the private permit. It journals `submission_started` before the bounded
Kyoto request and applies the rebroadcast interval before retrying an ambiguous
submission.

The pinned `bip157` 0.6.3 source ignores `data_dir`; full headers, compact-
filter headers/filters, and address-book state are re-fetched from untrusted
peers after restart. The encrypted BDK checkpoint is the durable light-wallet
anchor, so a pruned/full indexed node is not required. Safe archival at the
4,096-record lifetime caps, installed live-network evidence, trusted-time
review, and resource measurements remain separate release evidence. The
domain-separated keys and encrypted monotonic allocation source
first passed a historical 10-test targeted NVMe filter and is now included in
the exact `2229be8` workspace CI. Those historical results predate the current
connected value-runtime candidate.

## Ethereum containment gates

`ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED`,
`ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED`,
`ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED`, and
`ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED` are `false`. Capability output
advertises offline receive derivation only. Public acquisition cannot issue the
opaque permits required for native-transfer or HTLC construction, exact-fee-
bound signing, or authoritative Helios lock evidence. Helios provenance has no
public release-flag acquisition path, and verification also requires the
settlement permit. Signed bytes remain in a zeroizing, redacted opaque artifact
without a public raw accessor. Chain ID 1 is rejected regardless of the legacy
serialized policy flag.

The checked-in evidence structs and contract remain dormant structural source.
They do not implement synchronization, balance/history/nonce/fee discovery,
broadcast, persistence/recovery, redeem/refund proof verification, or rollback.
Caller-provided verification booleans cannot become a verified settlement lock.

## Evidence statement

The settled final-source working tree passed local library runs of 38 Store
tests, 73 HNS tests, and 42 Shakedex tests with the release-scale case ignored;
the Shakescape board-runtime integration suite passed 26 tests. A focused normalized-
storage run passed 18 tests with that same release-scale case ignored, so it is
a subset/re-run rather than additive evidence. The optimized 4,096-row
persistence qualification was then run explicitly and passed 1/1, with 47.20s
build time and 15.92s test time. These are local final-source results only. No
exact-commit CI or CodeQL result is yet recorded for this tranche, and those
results do not by themselves constitute a published release qualification.

Exact historical qualified implementation source
`bc5901f794450d29fa9f5630bab4fbf91e37bedf`
passed complete locked CI run `31812028843`, including Wallet qualification and
RustSec, and CodeQL run `31812028405` for Actions, JavaScript/TypeScript, Rust,
and Python on 2026-08-14. The workspace gate included trusted exact-name import,
dedicated name targets, synchronized reads, script-free initial binding and
wrong-network rejection, durable fences, restart/stale/account/lock,
prompt-bound name consent, changed scope, minimized public shape, bounds,
namespace/permission denial, FINALIZE, and unavailable value/module regressions.
Exact historical implementation source
`2229be849557d58a8eb723bcc03349f0f2df9796` passed complete CI run
`31420628974`, CodeQL run `31420627924`, and the credential-free 14-crate
normalized package preflight `31424201574` on 2026-08-10.
Exact predecessor `ba9f013a098679fe8e3d812a7e09020803e27d53` passed historical
CI `31383987461` and CodeQL `31383987478` before the final initial-binding order.

These records establish source qualification only. They do not cover multi-
process regtest/restart/reorg, installed products, real networks, benchmarks,
resource measurement, or independent audit, and they do not enable any value or
settlement constant. The canonical evidence procedure and historical ledger is
[`QUALIFICATION.md`](QUALIFICATION.md).

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
