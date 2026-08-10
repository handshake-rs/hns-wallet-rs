# Implementation status

Snapshot: 2026-08-10. This document describes the implemented source boundary
and fixed availability gates; registry, tag, and per-commit workflow state are
external evidence. HNS send and settlement, Bitcoin send/settlement, and
Ethereum synchronization/history/send/settlement are hard-disabled on every
network, and mainnet settlement remains disabled independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 14 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths | release CI and published artifacts |
| Wallet types | persisted IDs unchanged; dedicated nonzero base64url service/session/handle/request/approval IDs with redacted diagnostics; decimal integer amounts, roles and capabilities | API stabilization review |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records; metadata-bound AEAD; bounded heterogeneous CAS batches; complete bounded binary-prefix entity and opaque-workflow reads; non-consuming authenticated approval reads; atomic unchanged-approval consume plus workflow/reservation CAS; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux-executed Unix source policy for read-only schema/metadata recognition before write migration, atomic create-new with armed identity-safe database/sidecar cleanup, effective-UID/exact-mode/single-link checks, non-writable host prefix plus an Android-only UID-1000 app-data exception, same-owner private suffix, no-symlink SQLite opens, and repeated file identity checks; cloneable non-debuggable shared lock/key authority with poison-time key clearing | Android/iOS target and runtime filesystem qualification; host sandbox/ACL/Data Protection/backup policy; Android Keystore/iOS Keychain/OS key wrapping; non-Unix secure-open policy; migration/import tooling for populated schema-v1 entity tables; DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, authenticated loopback `hns-node-rs` wallet RPC v1 adapter, separate bounded coin, `HnsName`, and 32-byte `HnsShakedex` queries under one exact chain/mempool snapshot, a product-composable synchronized non-value account-read runtime with no node I/O under shared-store closures and exact account/entity commit fences, complete wallet/account-scoped persisted entity reads and fail-closed opaque-workflow recovery, encrypted monotonic name/Shakedex scan state with a cross-process durable allocation fence, protected workflow/economic-terms-bound Shakedex key allocation atomically coupled to WalletAccount and authenticated seed rederivation, restore/history/reorg reconciliation, ordered spender evidence, exact snapshot-bound HSD median time past and optional transaction positions, immutable canonical 0.2 NameState/resource source, exact raw/projected current/proof validation, owner txid/index/value/covenant/inclusion binding, `HnsName` ownership/incoming/outgoing classification, legacy-row revalidation, ephemeral exact-snapshot ownership authority, versioned chain/mempool/owner/lockup/renewal action-context validation, non-serializable current/unspent Shakedex lock and seller-script-bound TRANSFER authorities, canonical index-zero value-preserving TRANSFER and outgoing-owner direct FINALIZE construction, deterministic encrypted name workflows, typed name/funding and protected Shakedex source/funding reservations, runtime-bound Shakedex funding-coin recovery, single-use trusted approval, ordered `HnsName`/`HnsCoin` and funding-suffix signing, purpose-bound lock-spend funding plus a separate transfer-only seller-script-FINALIZE purpose/bind/validate/authorize/final-fee boundary, purpose-bound Shakedex proof/listing/cancellation/recovery signing, runtime-owned Shakedex time and same-snapshot transaction/all-input-spender observations, canonical policy-size/minimum-fee construction and independent node-quote comparison, exact signed-byte quote/requote, durable broadcast/mempool/lock/eligibility/finalization/cancellation/conflict/reapproval reconciliation, canonical HTLC construction/spends, settlement evidence and restart supervision | historical exact `ba9f013` workspace CI covered the account-read, action-context, MTP, key-allocation, Shakedex funding/reconciliation, and fee-policy source regressions; multi-process regtest, restart/reorg, mempool-conflict, adversarial, three-branch scan, and resource qualification; trusted provider/UI integration; protocol publication and independent review; published canonical settlement profile |
| Provider | exact 43-name vocabulary, all-HNS namespace enforcement, secure origin, opaque authority registry, authority-validated permission/tombstone snapshots, singleton persisted account binding, generation-CAS-bound single-approval `hns_requestAccounts` join, runtime-selection-rechecked `hns_accounts`, additive account-scoped read grants, prompt-disclosed maximum-64 exact name consent with approval-time account/scope reauthentication and unchanged-hash persistence, typed capability snapshot, ephemeral approvals/replay/rates, forbidden methods; checked-in existing-database control dispatcher exposes exactly five controls; library compositions expose the account join alone or the join plus synchronized balance/history/receive/name reads; public HNS results omit internal snapshot/proof/resource/owner/derivation evidence | historical exact `ba9f013` workspace CI covered the FFI/host/provider/service regressions; trusted backend/product construction, published engine authority adapter, browser-native transport, exact `hnsNames` trusted-UI adoption, installed restart/regtest/adversarial qualification; value and module methods remain unavailable |
| Shakedex | encrypted/CAS seller, buyer, recovery, and typed transaction-plan schemas; opaque canonical fixed-price protocol authority bound to exact hash/network/time/locking coin; typed canonical cancellation; protected monotonic HNS seller-key allocation with purpose-bound signing; canonical fulfillment, explicit-recipient recovery, and script-witness FINALIZE planning; HNS-runtime adapters consume non-serializable current/unspent lock or TRANSFER, active NameState, parent-MTP, maturity, and renewal evidence; durable aggregate buyer-fulfillment/seller-recovery/seller-script-FINALIZE child with exact parent action/bytes/hash, stable TRANSFER/owner/NameState/renewal identity, historical snapshot/mempool evidence, source/funding reservation, revision-bound approval, final-byte-fee/signed-byte/pre-submit-fence evidence, and runtime-owned restart/reorg/conflict/rebroadcast observations; atomic evidence-backed signed-workflow terminal reservation release with audit-only recovery-required reorg handling; all value authorization/submission entrypoints hard-disabled | historical exact `ba9f013` workspace CI covered the canonical listing, FINALIZE, reservation, terminal-release, and fixed-gate tests; product coin selection, complete seller/buyer product and startup orchestration, live node/Denuo/provider/trusted-UI integration, and multi-process restart/reorg/regtest qualification |
| Denuo market | pinned canonical name-market envelopes; bounded replay/tombstone-safe encrypted fixed-price board with sequence watermarks and CAS restart validation; chain-neutral reservations/sessions | live relay/outbox supervision, peer policy, reporter governance, product integration and qualification |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; strict versioned aggregate BDK-3.1.0 changeset persisted under encrypted account-authenticated CAS; one shared store/key authority for BDK state, scan journal, mirrors, and broadcast; persist-before-reconciling/ready ordering and ahead-tip crash recovery; context-bound atomic-swap allocation keys with crate-local regression vectors; encrypted CAS-backed monotonic session/role allocation and authenticated re-derivation; bounded Kyoto tip discovery and supervisor; encrypted birthday/phase/checkpoint journal; bounded transaction/output mirrors; exact fee-bound pre-broadcast journal; HTLC funding/spend/evidence units | normalized or authenticated chunked BDK backend beyond the current 1 MiB aggregate limit; explicit legacy BDK SQLite import tool; canonical complete-terms caller and settlement-supervisor integration, pinned Kyoto durable header/filter/peer API, record archival, signed-spend integration, consolidated CI, regtest/restart/reorg/adversarial qualification and benchmarks; value gate remains false |
| Ethereum | separated offline accounts, typed dormant EIP-1559/HTLC and structural evidence primitives, deterministic contract, immutable false synchronization/value/settlement/mainnet gates, opaque runtime permits plus role/address/exact-fee-bound signing types, zeroizing preimages/intermediates, redacted controlled-broadcast artifact | embedded Helios proof source and privately minted evidence authority, persistence/balance/history/nonce/fee/broadcast runtime, redeem/refund verification, local-chain/restart/reorg qualification, approved address and audit |
| FFI/service/host | private ABI v2 with exact approval-schema-v3 negotiation; canonical framing; required sorted/unique canonical `hnsNames` permission disclosures validated by pinned HNS rules; exact prompt-to-pending-to-grant name binding; random host/service/wallet sessions; one typed provider binding; bounded typed frames; locked existing-database subprocess and library-only exact-account/synchronized-read compositions; caller-owned clock/entropy, sequencing, response correlation, authority/approval/binding/event replay state; updated Draft 2020-12 private/public/manifest schema bundle and structural/runtime vectors | exact browser/mobile approval-v3 adoption and rendering, trusted shipped backend, signed artifact/verifier trust store, launcher, downstream binding integration, compatibility E2E; value/browser gates remain false |
| Mobile controller | platform-neutral Android/iOS library composition; owned zeroizing 32-byte database key and recovery input; guarded exact-24-word create/restore, complete seed/account bootstrap open, one shared store authority, locked startup, private ABI-v2 negotiation, status/unlock/lock/single-account controls, and fail-closed request/session handling; browser/provider/value/market capabilities rejected | downstream JNI/C/Swift adoption and secret-buffer lifecycle verification; create-only Keystore/Keychain wrapping; dedicated recovery/control screens; Android and iOS installed-runtime qualification; native package adoption and release evidence |
| Testkit | deterministic non-mainnet, hostile-input, reorg, and qualification fixtures | full multi-process network harnesses |
| Browser products | authority and adapter work lives in separate repositories | installed-extension/native-host and signed-device qualification |

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

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated in source, but its
  consolidated CI, multi-process regtest, restart/reorg, malformed-transport,
  stale-cursor, and resource qualification evidence is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- exact confirmed input height/address/covenant evidence now drives canonical
  `hns-script` sigops, policy-size, minimum-fee construction, standardness
  bounds, and independent node-quote comparison, but consolidated fee-policy
  and adapter qualification is not recorded, so
  `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains false;
- name TRANSFER/FINALIZE source workflows consume fresh ephemeral authority and
  exact node action context, but their node/wallet restart/reorg/mempool/product
  qualification and provider/trusted-UI dispatch are not recorded;
- canonical `hns-swap` 0.2 source is pinned to final immutable release
  revision `b24b66c`; wallet publication requires all 17 corresponding
  crates.io archives and exact source-provenance verification;
- Android/iOS secure-path target/runtime qualification, host sandbox/ACL/data
  protection/backup policy, platform key wrapping, secure approval UI,
  browser/native-host integration, and non-Unix secure persistent database
  opening are unavailable; and
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
does not authenticate that coin as current or unspent. The persisted board
revalidates canonical bytes and monotonic seller/name watermarks after restart.
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
passed only its 10-test targeted NVMe filter; that evidence does not change the
false value-release gate.

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

Exact implementation commit `ba9f013a098679fe8e3d812a7e09020803e27d53`
passed complete CI run `31383987461` and CodeQL run `31383987478` on
2026-08-10. The workspace gate included the synchronized-read, exact binding,
durable-fence, restart/stale/account/lock, prompt-bound name-consent,
changed-scope, minimized-public-shape, bounds, namespace/permission denial,
FINALIZE, and unavailable value/module regressions described above.

That evidence belongs to the exact implementation commit. For a dated release
source, routine CI, CodeQL, and the manual normalized package preflight records
attached to the same exact release commit establish its source qualification;
this document does not encode a transient pending or pass state. Neither
predecessor success nor package preparation covers multi-process regtest/
restart/reorg, installed products, real networks, benchmarks, resource
measurement, or independent audit, and it does not enable any value or
settlement constant. The canonical evidence procedure and historical ledger is
[`QUALIFICATION.md`](QUALIFICATION.md).

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
