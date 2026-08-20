# Implementation status

Snapshot: 2026-08-20. This document describes the implemented source boundary,
fixed availability gates, and dated exact-source evidence. Registry, tag, and
current product state remain external facts. HNS send and settlement, Bitcoin
send/settlement, and Ethereum synchronization/history/send/settlement are
hard-disabled on every network, and mainnet settlement remains disabled
independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 14 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths; exact historical `bc5901f` locked CI and four-language CodeQL passed, while historical exact `2229be8` CI, CodeQL, and normalized 14-crate preflight also passed; all 17 exact-`b24b66c` `hns-rs` `0.2.0` prerequisite archives were historically published and provenance-verified on 2026-08-14; current source pins exact unpublished `hns-rs` `0.3.0` Git revision `88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e` | all 19 current `hns-rs` `0.3.0` archives published and provenance-verified at the pinned revision; separately dispatched normalized release preflight for any publication candidate; authorized wallet publication, tag, and registry verification |
| Wallet types | persisted IDs unchanged; dedicated nonzero base64url service/session/handle/request/approval IDs with redacted diagnostics; decimal integer amounts, roles and capabilities; structurally distinct `ReceiveTarget` and `HnsNameReceiveTarget` DTOs, with the latter intrinsically restricted to the Handshake module and bounded display text | API stabilization review; coordinated HNS Wallet Read v2 (HNWR-v2) consumer adoption before the new name-target projection is treated as product-compatible |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records, including one deletion-protected fixed-ID native HNS read-profile namespace with closed nested schema, CAS rotation, persistent revocation tombstones, and monotonic revision/update-time fences; metadata-bound AEAD; bounded heterogeneous CAS batches; callback-scoped coherent entity snapshots; complete bounded untrusted binary-prefix metadata projections for fail-closed comparison; compare-only authenticated revision assertions; refreshable single-use exact-prefix-set leases with private ciphertext fingerprints; immediate transactions supporting one primary namespace lease plus an optional cross-kind compare-only guard; complete bounded entity and opaque-workflow reads; non-consuming authenticated approval reads; atomic unchanged-approval consume plus workflow/reservation CAS; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux-executed Unix source policy for read-only schema/metadata recognition before write migration, atomic create-new with armed identity-safe database/sidecar cleanup, effective-UID/exact-mode/single-link checks, non-writable host prefix plus an Android-only UID-1000 app-data exception, same-owner private suffix, no-symlink SQLite opens, and repeated file identity checks; cloneable non-debuggable shared lock/key authority with poison-time key clearing | installed Android/iOS filesystem/runtime qualification; host sandbox/ACL/Data Protection/backup evidence; downstream candidate Keystore/Keychain wrapping is not supplied or qualified by this crate; non-Unix secure-open policy; migration/import tooling for populated schema-v1 entity tables; DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, authenticated loopback `hns-node-rs` wallet RPC v1 adapter, separate bounded coin, `HnsName`, and 32-byte `HnsShakedex` queries under one exact chain/mempool snapshot, a product-composable synchronized non-value account-read runtime with no node I/O under shared-store closures and exact account/entity commit fences, distinct synchronized ordinary-coin and name receive projections where the latter requires the exact selected account, `HnsName` role, account derivation component, change zero, and post-scan `next_name_index` and rejects missing or ambiguous evidence, trusted-native exact-text name import with pre-I/O validation, fresh canonical ownership classification, atomic WalletAccount/KnownName CAS, wallet-bearing monotonic `HnsName` high-water/trailing-gap rotation and non-wallet non-advancement, complete wallet/account-scoped persisted entity reads and fail-closed opaque-workflow recovery, encrypted monotonic name/Shakedex scan state with a cross-process durable allocation fence, protected workflow/economic-terms-bound Shakedex key allocation atomically coupled to WalletAccount and authenticated seed rederivation, restore/history/reorg reconciliation, ordered spender evidence, exact snapshot-bound HSD median time past and optional transaction positions, immutable canonical `hns-rs` `0.3.0` NameState/resource source, exact raw/projected current/proof validation, owner txid/index/value/covenant/inclusion binding, `HnsName` ownership/incoming/outgoing classification, legacy-row revalidation, ephemeral exact-snapshot ownership authority, legacy transaction-backed v1 plus pruning-safe active-UTXO-backed v2 chain/mempool/owner/lockup/renewal action-context validation, with wallet-owned TRANSFER/direct-FINALIZE using v2 and descriptor-linked Shakedex retaining v1, non-serializable current/unspent Shakedex lock and seller-script-bound TRANSFER authorities, canonical index-zero value-preserving TRANSFER and outgoing-owner direct FINALIZE construction, deterministic encrypted name workflows, typed name/funding and protected Shakedex source/funding reservations, runtime-bound Shakedex funding-coin recovery, single-use trusted approval, ordered `HnsName`/`HnsCoin` and funding-suffix signing, purpose-bound lock-spend funding plus a separate transfer-only seller-script-FINALIZE purpose/bind/validate/authorize/final-fee boundary, purpose-bound Shakedex proof/listing/cancellation/recovery signing, runtime-owned Shakedex time and same-snapshot transaction/all-input-spender observations, canonical policy-size/minimum-fee construction and independent node-quote comparison, exact signed-byte quote/requote, durable broadcast/mempool/lock/eligibility/finalization/cancellation/conflict/reapproval reconciliation, canonical HTLC construction/spends, settlement evidence and restart supervision | exact historical `bc5901f` locked CI covered the dependency, name-target, trusted-import, account-read, script-free initial-binding, action-context, MTP, key-allocation, Shakedex funding/reconciliation, and fee-policy regressions; the v2 wallet action boundary pairs with selected node main `4275b4e`, while exact current-wallet qualification remains to be recorded; multi-process regtest, restart/reorg, mempool-conflict, adversarial, three-branch scan, and resource qualification; coordinated HNWR-v2 trusted-native consumer/UI integration; independent review; published canonical settlement profile; HNS value and fee gates remain false |
| Provider | exact 43-name vocabulary, all-HNS namespace enforcement, secure origin, opaque authority registry, authority-validated permission/tombstone snapshots, singleton persisted account binding, generation-CAS-bound single-approval `hns_requestAccounts` join, runtime-selection-rechecked `hns_accounts`, additive account-scoped read grants, prompt-disclosed maximum-64 exact name consent with approval-time account/scope reauthentication and unchanged-hash persistence, typed capability snapshot, ephemeral approvals/replay/rates, forbidden methods; checked-in existing-database control dispatcher exposes exactly five controls; library compositions expose the account join alone or the join plus synchronized balance/history/receive/name reads; the internal synchronized snapshot carries a dedicated name receive target, but website `hns_getReceiveAddress` continues to project only the ordinary `HnsCoin` target and no provider method exposes `nameReceiveTarget`; a concrete native-launcher constructor joins the latter to one authenticated loopback RPC backend, production clock, exact non-value account, and literal shared store authority; an encrypted profile API provisions, rotates, and revokes that exact startup configuration, while a process-local bootstrap consumes one zeroizing passphrase plus exact active fence into an already-unlocked exact-six runtime with an additive native-only wallet authority context bound to canonical network, authenticated profile revision, and exact account-row revision; neither is consumed by the executable or website provider; public HNS results omit internal snapshot/proof/resource/owner/derivation evidence | pushed-main exact-SHA qualification for the authority-context producer; private one-shot unlock brokerage, exclusive cross-process database ownership and HRM/HNSA lease/process invalidation, published engine authority adapter, real browser-native transport, exact `hnsNames` trusted-UI adoption, installed restart/regtest/adversarial qualification, and release evidence; no website/provider or value capability was added, and value/module methods remain unavailable |
| Shakedex | encrypted/CAS seller, buyer, recovery, and typed transaction-plan schemas; opaque canonical fixed-price protocol authority bound to exact hash/network/time/locking coin; typed canonical cancellation; protected monotonic HNS seller-key allocation with purpose-bound signing; canonical fulfillment, explicit-recipient recovery, and script-witness FINALIZE planning; HNS-runtime adapters consume non-serializable current/unspent lock or TRANSFER, active NameState, parent-MTP, maturity, and renewal evidence; durable aggregate buyer-fulfillment/seller-recovery/seller-script-FINALIZE child with exact parent action/bytes/hash, stable TRANSFER/owner/NameState/renewal identity, historical snapshot/mempool evidence, source/funding reservation, revision-bound approval, final-byte-fee/signed-byte/pre-submit-fence evidence, and runtime-owned restart/reorg/conflict/rebroadcast observations; atomic evidence-backed signed-workflow terminal reservation release with audit-only recovery-required reorg handling; all value authorization/submission entrypoints hard-disabled | exact `2229be8` workspace CI covered the canonical listing, FINALIZE, reservation, terminal-release, and fixed-gate tests; product coin selection, complete seller/buyer product and startup orchestration, live node/Denuo/provider/trusted-UI integration, and multi-process restart/reorg/regtest qualification |
| Denuo market | pinned canonical name-market and price-round envelopes; bounded replay/tombstone-safe normalized encrypted fixed-price board with `HeadV2Indexed` compact selectors binding row identity/revision/time/value commitment/listing hash, digest-addressed identity rows, encrypted digest-addressed listing-hash indexes, full-load commitments and index/row bijection, O(N) metadata/selector work for every targeted read, O(K) authenticated values only for all-hit queries, O(N) full semantic fallback for any miss, ciphertext-fingerprinted exact-namespace CAS, and atomic migration from legacy-v1 or historical pre-index `HeadV2`; an offline same-store-authority board runtime that captures the complete selected-wallet `WalletAccount` prefix before node/clock work, refreshes it in the same snapshot as the full board load, consumes it as a second guard in the board transaction, authenticates canonical V2 offers, obtains query-scoped runtime-owned network/time plus exact current and unspent HNS Shakedex-lock authority before CAS admission, leaves exact retries revision-stable, rejects stale/conflicting authority, and reacquires the lock plus an unchanged board row before later use; a closed singular `GetOffer` read accepts only canonical V2 with nonzero correlation, returns typed full-semantics-validated missing or cancelled absence without a node query, internally authenticates and discards the paired type-7 `Offer` bytes, and exposes only opaque point-in-time request/hash/revision metadata; a separate closed `GetOfferInventory` read accepts only canonical V2 with nonzero correlation, refreshes the complete selected-account prefix/current network/trusted time under the same store authority, omits cancelled/not-yet-active/expired/other-network rows with no backend call or write, internally verifies and discards the canonical ordered type-3 response including an empty inventory, and exposes only opaque point-in-time request/revision/count metadata; a closed `GetOffers` read narrows requests to 64 hashes before I/O, preserves exact sorted request identity, omits full-semantics-validated missing/cancelled rows while retaining typed all-absent revision, preflights aggregate type-5 size before node access, binds every returned active row to one coherent ordered account/chain/mempool/network/time current-lock batch, rejects duplicate names and invalid active candidates without fallback, refreshes the complete account prefix plus full requested board projection/revision, discards internally verified response bytes, and exposes only request/revision/requested/returned counts; the runtime separately admits signed negative cancellation tombstones after lock loss by binding externally expected target/content hashes to the exact persisted listing plus a purpose-minimized selected-account network/trusted-time context, refreshed ciphertext-fingerprinted account guard, full board fence, and dual-lease CAS with no backend call, while exact persisted retries remain no-write after restart/expiry; bounded encrypted/CAS offline V2 offer/cancellation outbox with exact-envelope and request/content identity, schema-v3 persist-before-return single-flight handoff, explicit outcome-unknown crash recovery, bounded retry/exhaustion, immutable schema-v1 acknowledgement compatibility, and terminal endpoint-signed `RelayAccepted` receipts that bind the exact handoff plus wallet-supplied HRM/HNSA policy and self-validate after restart; schema v2 cannot inject acknowledgement or acceptance, exact receipt replay is revision-stable, and conflicting terminal receipts fail closed; exact-policy-bound encrypted zero-ID price-round gossip cache with optional predecessor-checkpoint bootstrap, trusted local `accepted_at_unix`, durable canonical reporter-aligned sequence high-watermarks, full retained-row/link validation, and atomic retirement from a maximum-128-round suffix; retired round hashes/IDs leave duplicate detection while reporter high-watermarks remain; chain-neutral reservations/sessions; no receipt-provided current HRM/HNSA, quote, value, or live-chain authority and no gate changes | current HRM/HNSA authority adapter, authenticated live transport and relay supervision, peer policy and reporter governance, current chain-anchor authority, quote/value integration, multi-process regtest/reorg/adversarial tests, installed product integration and qualification; every Denuo and value gate remains `false` |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; strict versioned aggregate BDK-3.1.0 changeset persisted under encrypted account-authenticated CAS; one shared store/key authority for BDK state, scan journal, mirrors, and broadcast; persist-before-reconciling/ready ordering and ahead-tip crash recovery; context-bound atomic-swap allocation keys with crate-local regression vectors; encrypted CAS-backed monotonic session/role allocation and authenticated re-derivation; bounded Kyoto tip discovery and supervisor; encrypted birthday/phase/checkpoint journal; bounded transaction/output mirrors; exact fee-bound pre-broadcast journal; HTLC funding/spend/evidence units | normalized or authenticated chunked BDK backend beyond the current 1 MiB aggregate limit; explicit legacy BDK SQLite import tool; canonical complete-terms caller and settlement-supervisor integration, pinned Kyoto durable header/filter/peer API, record archival, signed-spend integration, regtest/restart/reorg/adversarial product qualification and benchmarks; exact source CI passed; value gate remains false |
| Ethereum | separated offline accounts, typed dormant EIP-1559/HTLC and structural evidence primitives, deterministic contract, immutable false synchronization/value/settlement/mainnet gates, opaque runtime permits plus role/address/exact-fee-bound signing types, zeroizing preimages/intermediates, redacted controlled-broadcast artifact | embedded Helios proof source and privately minted evidence authority, persistence/balance/history/nonce/fee/broadcast runtime, redeem/refund verification, local-chain/restart/reorg qualification, approved address and audit |
| FFI/service/host | private ABI v2 with exact approval-schema-v3 negotiation; canonical framing; required sorted/unique canonical `hnsNames` permission disclosures validated by pinned HNS rules; exact prompt-to-pending-to-grant name binding; random host/service/wallet sessions; one typed provider binding; bounded typed frames; a closed `hnsReadOperationsV1` marker for status, exact account, and Handshake-only balance/receive/history/module-status reads with a dedicated host admission path and minimized correlated responses; additive `hnsWalletAuthorityContextV1` request/response outside that six-read enum with canonical network/magic, nonzero broker-claim echo, active wallet/account, authenticated profile/account revisions, and positive lifecycle/readiness flags; locked existing-database subprocess and generic/recovery runtimes advertise no authority marker; the ordinary profile-backed constructor revalidates profile and account evidence around each context; caller-owned clock/entropy, sequencing, response correlation, authority/approval/binding/event replay state; updated Draft 2020-12 private/public/manifest schema bundle and structural/runtime vectors | trusted signed artifact/verifier roots, launcher invocation, one-shot secret transport, exclusive database plus HRM/HNSA namespace lease/process supervision, downstream engine-authority binding integration, compatibility E2E, installed constructor integration, and exact-SHA qualification evidence; value/browser gates remain false |
| Mobile controller | existing platform-neutral lifecycle API preserved with owned zeroizing 32-byte database key and recovery input, guarded exact-24-word create/restore, complete seed/account bootstrap open, one shared store authority, locked startup, private ABI-v2 negotiation, status/unlock/lock/single-account controls, and fail-closed request/session handling; separate backend/clock-injected read controller composes `HnsAccountReadRuntime` and `PersistentHnsReadRuntime` around that literal authority and returns a bounded serialized balance/ordinary-receive/name-receive/history/minimized-known-name/successful-tip-status snapshot whose outer and name-projection fields are camelCase while nested shared wallet-type fields retain snake_case; `nameReceiveTarget` uses the distinct shared DTO and the explicit `name_receive_target()` getter freshly synchronizes like every other getter; direct trusted-native `import_name_exact_text()` preflights the persisted display bound and returns the same minimized name summary, with invalid input non-poisoning and runtime faults locking; module, exact account, bounded display, and printable display are revalidated at the mobile boundary; a script-free chain snapshot and bound genesis check precede all ScriptId derivation/query, so wrong-network and read failures reject/lock before retry; the loopback backend/config are re-exported; browser/provider/value/market capabilities rejected | exact historical `bc5901f` locked CI qualifies that producer source; `hns-dane-browser-mobile` must coordinate the exact wallet revision plus Rust/JNI/C/Kotlin/Swift trusted-UI adoption before exposing import; downstream Android/iOS 0.5.9 candidate source supplies JNI/C projection, Keystore/Keychain wrapping, native recovery/read screens, and off-UI-thread execution, but this crate supplies no import bindings or deadline-enforced archive-capable/wallet-raw-tx-indexed production device backend; secret-buffer lifecycle verification; installed Android/iOS restart/network/resource qualification; native package publication and release evidence; value/provider gates remain unchanged and false |
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
persistent permissions, value, browser, current-lock/Denuo, signing, workflow,
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
linkage. All HNS value and fee release gates remain fixed `false`.

## HNS value release gate

`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` is `false`. Runtime configuration rejects
`value_operations_enabled` or `settlement_enabled`, and capability discovery
does not advertise those paths.

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
boundary and remain unreachable while both HNS release gates are false.

Historically, all 17 required `hns-rs` `0.2.0` archives were present on
crates.io and verified on 2026-08-14 to identify exact source
`b24b66c382de53330ec21dd3137e056a2bea3e2d`. That resolved only the superseded
protocol publication-order prerequisite. Current source pins exact unpublished
`hns-rs` `0.3.0` Git revision
`88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e`; all 19 current upstream archives
must be published and provenance-verified before execute mode may begin any
wallet upload. Wallet authorization, qualification, and all runtime gates remain
unchanged.

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated and covered by the
  exact `bc5901f` source CI, but multi-process regtest, restart/reorg, malformed-
  transport, stale-cursor, and resource qualification is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- exact confirmed input height/address/covenant evidence now drives canonical
  `hns-script` sigops, policy-size, minimum-fee construction, standardness
  bounds, and independent node-quote comparison and passed the source gate, but
  multi-process adapter and product qualification is not recorded, so
  `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains false;
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
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED` are `false`. Seller creation and
transition and buyer discovery and transition return an explicit unavailable
error before mutation. This also blocks sessions restored from legacy
persisted records. Independently usable read/discovery boundaries now require
the exact listing hash, network, active time window, and supplied canonical
locking coin; cancellations bind to that exact listing; Denuo registry and
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

This source still does not select product funding coins, contact live Denuo
peers, dispatch through a provider/trusted approval UI, integrate product
startup supervision, or constitute restart/reorg/regtest qualification. The
current HNS/FINALIZE regressions are included in the exact CI evidence recorded
in `QUALIFICATION.md`. Purpose-bound seller proof/
listing/cancellation/recovery signing remains separately constrained by
canonical terms and current-lock authority. No Shakedex or dependent HNS
Shakedex-funding/value/fee gate is enabled.

## Bitcoin value release gate

`BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` is `false`. Bitcoin receive address
derivation and source-level history remain discoverable, but capability output
does not advertise send or atomic settlement and the private value permit
cannot be constructed.

The dormant broadcast boundary requires a durable ready scan, a running Kyoto
node, configured peer quorum, owned unspent inputs, BDK-calculated exact fee,
and a canonical approval commitment over network, txid, wtxid, exact fee, fee
maximum, and exclusive expiry. Native-send signing and broadcast both require
the unavailable permit. It journals `submission_started` before the bounded
Kyoto request and applies the rebroadcast interval before retrying an ambiguous
submission.

The pinned `bip157` 0.6.3 source ignores `data_dir`; exact headers, compact-
filter headers/filters, and address-book state are not durably exposed. A
reviewed persistence-capable Kyoto boundary, safe archival at the 4,096-record
lifetime caps, signed HTLC spend supervision, complete allocation concurrency/
restart/corruption qualification, regtest/restart/reorg/adversarial evidence,
trusted-time policy, resource measurements, and independent review remain
blockers. The domain-separated keys and encrypted monotonic allocation source
first passed a historical 10-test targeted NVMe filter and is now included in
the exact `2229be8` workspace CI. Neither result changes the false value-release
gate.

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
the Denuo board-runtime integration suite passed 26 tests. A focused normalized-
storage run passed 18 tests with that same release-scale case ignored, so it is
a subset/re-run rather than additive evidence. The optimized 4,096-row
persistence qualification was then run explicitly and passed 1/1, with 47.20s
build time and 15.92s test time. These are local final-source results only. No
exact-commit CI or CodeQL result is yet recorded for this tranche, and no gate
changes.

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
