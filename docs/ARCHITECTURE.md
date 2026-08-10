# Architecture

`hns-wallet-rs` is an independent release boundary. It does not absorb the
Handshake protocol library, full node, DANE trust engine, or browser products.

```text
hostile website
  -> browser engine authority retained by platform adapter
  -> hns-wallet-host: owned clock/entropy, opaque handle, request correlation
  -> hns-wallet-ffi v2: length/session/restart/sequence validation
  -> hns-wallet-service: handle/revision/event/approval lifecycle
  -> hns-wallet-provider: origin permission, replay, rate, approval policy
  -> wallet application: HNS / Shakedex / market workflow
  -> capability-specific chain module
  -> verified local chain evidence
  -> encrypted workflow journal before irreversible broadcast
```

Canonical Handshake transactions, covenants, scripts, Urkel proofs, Shakedex
proofs, signed fixed-price listings/cancellations, and Denuo name-market
envelopes remain in `hns-rs`. This workspace consumes the required protocol
crates from reviewed immutable revision `29e4b47`; its exact source and lock
coherence are checked before the workspace gate. The wallet owns only the
protocol-verification boundary and encrypted replay/tombstone board state. Node
indexes and Denuo relay stores remain in `hns-node-rs`. Provider-injection authority
remains in `hns-dane-engine`. Browser JavaScript and platform UI remain in the
browser repositories. This workspace owns keys, encrypted local state, wallet
semantics, approvals, typed canonical transaction planning, and recoverable
application workflows.

## Crate boundaries

| Crate | Owns | Must not own |
| --- | --- | --- |
| `hns-wallet-types` | IDs, integer amounts, capabilities, UI-safe summaries | consensus/wire types |
| `hns-wallet-store` | schema, migrations, typed record AEAD, workflow/entity CAS and atomic batches, complete bounded binary-prefix entity and opaque-workflow reads, atomic approval-consume/workflow/reservation commits, provider permission tombstones, persisted workflow approvals/replays, one cloneable process-local lock/key authority | browser storage, ABI v2 authority handles, or remote truth |
| `hns-wallet-chain-api` | separate core, UTXO, account, and settlement capabilities | universal chain assumptions |
| `hns-wallet-hns` | exact-existing-account selector, synchronized non-value account-read runtime, HNS key roles, protected Shakedex seller-key allocation and purpose-bound signing, store-global lock-source plus account funding reservations, runtime-owned Shakedex time/chain observations, shared three-branch restoration/reconciliation, snapshot MTP, address/coin/name evidence and workflows | canonical encodings or market terms |
| `hns-wallet-provider` | hostile-input parsing, bounded opaque-handle registry, origin grants, ephemeral approvals/replay/rate | engine policy or JavaScript injection |
| `hns-wallet-shakedex` | fixed-price buyer/seller recovery state, exact listing/cancellation protocol verification, canonical fulfillment/recovery/script-FINALIZE planning, encrypted parent-plan CAS, durable buyer-fulfillment/seller-recovery/seller-script-FINALIZE value aggregate, canonical Denuo adapter, encrypted sequence/tombstone board | proof/listing/Denuo codecs, raw HNS keys, product coin selection, caller-asserted clock/chain truth, or release qualification |
| `hns-wallet-market` | reservations and evidence-driven cross-chain sessions | chain networking |
| `hns-wallet-bitcoin-kyoto` | BDK descriptor wallet, domain-separated swap keys, bounded Kyoto P2P supervisor/recovery journal, Bitcoin HTLC | alternate backends or claims of unavailable Kyoto persistence |
| `hns-wallet-ethereum` | offline native-ETH account derivation and release-gated Helios/HTLC policy | general Ethereum provider or caller-asserted proof authority |
| `hns-wallet-ffi` | strict ABI v2 framing, canonical service IDs, typed approvals/events | raw keys/native commands or engine authority objects |
| `hns-wallet-service` | random service/wallet sessions, exact sequences, private host control, permission-backed provider composition, locked existing-database control runtime, same-Arc exact-account and synchronized non-value HNS read library runtimes, atomic account grant, singleton persisted-account recheck, scoped public read projections | browser engine policy, value enablement, or product availability claims |
| `hns-wallet-host` | host-owned negotiation, identifiers/nonces, bounded request correlation, authority revisions, approval ownership, private provider bindings, and event replay cursors | platform process launch, engine policy, page injection, artifact trust, or availability claims |
| `hns-wallet-testkit` | deterministic non-mainnet fixtures | production configuration |

Every maintained repository keeps its own lockfile, tests, and release. There
are no sibling-checkout dependencies. A newly added `hns-rs` protocol crate
must be released or referenced by an immutable commit before a wallet release
can consume it.

The machine-readable contract bundle under `abi/` describes strict private
ABI-v2 JSON payloads, the private capability snapshot, public approval/event
projections, and signed-artifact manifest structure. It is an interface source,
not an executable runtime, generated platform binding, trusted signing key, or
artifact verifier. The browser and mobile repositories still own their outer
transport wrappers and independently qualified platform integration.

## Evidence authority

Peer statements, Denuo gossip, RPC status fields, and browser page messages are
hints. A safety-critical transition requires evidence from the corresponding
validated chain adapter. State machines accept explicit verified-evidence
variants and persist a compare-and-swap revision before the enclosing runtime
broadcasts an irreversible transaction.

The HNS adapter boundary requires a stable chain epoch/tip and a nonzero
node-instance nonce plus mempool generation across every bounded page of an
exact sorted wallet-address query. Each query carries canonical address version
and hash; the adapter must convert the exact version-0 `Address` to its node
`ScriptId`, never a bare hash. It also requires transaction/parent-output and
outpoint-spend evidence bound to that same snapshot. A stale cursor, restarted
mempool instance, or generation change restarts the bounded snapshot rather
than combining observations from different views.

`HnsAccountReadRuntime` is the product-composable non-value read boundary. It
uses the canonical account record, derivation, three-branch scanner, coin and
transaction reconciliation, name proof validation, checkpoint, and encrypted
persistence helpers; it is not a second wallet index or cache schema. Each
call stages one durable discovery fence and the exact account/entity corpus in
short `SharedWalletStore` closures, releases the store mutex before every node
request, and commits only if account selection, revisions, ciphertext-backed
rows, chain tip/epoch, and mempool instance/generation still match. The service
retains the resulting binding internally and projects only the account's
balance, transaction summaries, receive target, and approved known-name
summaries.

Names consent is a two-snapshot service flow, not post-approval enumeration.
Prompt preparation synchronizes once, projects a sorted maximum-64 canonical
name/hash list, and retains that exact account/list/hash set in ephemeral
`PendingState`. Approval synchronizes again and rejects changed permission,
account, or current scope before consuming the approval; the provider grant
receives only the frozen hashes. Required approval-schema-v3 `hnsNames`
prevents trusted host UIs from reducing Names consent to a generic capability
label. Browser and mobile adapters remain unavailable until they negotiate and
adopt that unpublished shape.

The earlier value-capable `HnsWalletRuntime` still owns a private
`Mutex<WalletStore>` and its legacy full reconciliation holds that mutex across
backend work. The synchronized provider read composition does not use that
path. Removing the legacy lock span remains required before any future value or
product composition may select it; the new read runtime does not change either
false HNS value gate.

HNS preparation authenticates the current account, workflow, and reservation
revisions before atomically committing change-index advancement, the prepared
workflow, and every input reservation. The cache changes only after commit.
Failures therefore cannot burn or reuse a change derivation and cannot leave a
partial losing workflow.

HNS value authorization is additionally bound to an exact final-signed
transaction fee quote. The approval is first read without mutation; signing and
quote validation complete before one store transaction consumes the unchanged
approval, saves the authorized exact bytes and quote, and activates the input
reservations. Broadcast re-quotes only those persisted bytes, saves the
refreshed quote with `RequiresRebroadcast` before submission, and allows at most
one full reconciliation and one retry for stale or unavailable quote evidence.
Confirmed wallet coins retain exact inclusion height and canonical covenant
bytes through encrypted persistence. Final transactions are checked against
the ordered reconstructed consensus coins: immutable `hns-script` 0.2 computes
sigops, policy virtual size, minimum fee, and standard weight/sigop bounds,
while exact input/output sums independently reproduce actual fee. Legacy or
mismatched evidence fails closed. This source has not passed consolidated
wallet qualification, so `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains
false; no local copy of the node formula is used.

Name evidence deliberately preserves the interval-committed Urkel proof/state/
owner view separately from the node's current state/owner view. The proof root
and height must exactly equal the bound tip. Ordinary HNS coin branches and the
domain-separated `HnsName` branch are scanned in separate bounded queries that
must share the exact chain epoch/tip and mempool instance/generation. Name-role
outputs may enter history but are excluded from ordinary balance, selection,
reservation, and spendability. The wallet independently decodes both raw
NameState views, compares every node projection, binds owner txid/index/value/
name covenant and typed TRANSFER/FINALIZE shape, and accepts current resource
bytes only from the decoded state. Current control is attributed only when the
owner address exactly matches a persisted `HnsName` program; incoming and
outgoing transfers are distinguished. Reconciliation replaces this encrypted
cache across restart/reorg, while legacy rows stay explicitly watch-only until
fresh evidence succeeds. Cache state cannot authorize an action: the runtime
must reacquire a non-serializable authority at the exact current snapshot.

The low-level Shakedex transaction adapters remain a canonical construction
boundary, not a chain adapter. Production-facing wrappers consume the HNS
runtime's non-serializable current-lock or current-TRANSFER authority instead
of separately supplied Coin/MTP/NameState facts. That authority binds canonical
owner and NameState, confirmed and mempool unspentness, exact chain/mempool
tokens, HSD-compatible parent MTP, and FINALIZE maturity/renewal evidence. The
HNS runtime also owns protected monotonic `HnsShakedex` allocation and opaque
purpose-bound signing; the Shakedex crate never owns raw keys. Allocation
requires a completed 32-byte lock scan; a durable scanning fence and one
WalletAccount/allocation transaction serialize restoration with every writer
to that wallet database. The signer recomputes the canonical proof-economic
terms commitment before proof, listing, or cancellation signing.

Buyer fulfillment, seller recovery, and seller-script FINALIZE now use one
aggregate `WorkflowKind::ShakedexValue` child rather than separate value journals. The
child embeds the complete canonical parent plan and its commitment, exact lock
or TRANSFER source and ordered funding coins, recipient/value/fee/finality/
expiry terms,
prepared and signed transaction bytes, approval identity, final fee quote,
submission attempt/fence, and latest chain observation. Its deterministic key
binds the parent workflow and action, so it cannot replace the parent row.
Every load revalidates canonical transaction structure, funding-only witness
changes, exact signed witnesses, fee algebra, and state-transition invariants.
The FINALIZE structural variant additionally fixes the exact signed
buyer-fulfillment or seller-recovery parent action/bytes/hash, TRANSFER
transaction and output-zero coin, current NameState and owner inclusion,
historical snapshot/mempool binding, and renewal evidence. These serialized
facts never reconstruct the ephemeral current-TRANSFER authority. Fresh
authority may carry advanced binding tokens only when the stable descriptor,
transaction/coin, owner inclusion, NameState, and renewal identity is exact.

The HNS side creates protected `ShakedexSource` and `ShakedexFunding` entities
for the aggregate's existing store CAS. The source entity uses a global ID
derived from the lock or TRANSFER outpoint, preventing cross-wallet/account
double reservation within one wallet store; the funding entities bind current tracked
ordinary coins in transaction order. Runtime time caps prepared rows at the
existing five-minute window. The aggregate and reservation inserts,
prepared-to-active updates, prepared cancellation/expiry deletes, and
pre-submit active-row retention each commit atomically. Generic HNS reservation
cleanup cannot mutate these protected kinds. Signed states retain them while
the chain result remains reversible. A dedicated terminal transition observes
the exact transaction and every input spender under one runtime-owned snapshot
and releases the rows only after either the expected transaction reaches the
persisted confirmation threshold with every exact input position and inclusion,
or an authenticated competing spender reaches that threshold under the same
snapshot binding. The terminal workflow evidence and deletion of every
protected row commit in one CAS transaction. Later reconciliation audits that
terminal evidence without recreating reservations or rolling the workflow back;
loss or change of terminal finality returns a recovery-required error. Product/
startup integration and executed FINALIZE qualification remain pending, and
every release gate remains `false`.

Approval bytes encode the exact prepared aggregate and CAS revision. The HNS
runtime owns time. Buyer fulfillment and seller recovery can enter only the
current-lock APIs; seller-script FINALIZE has a separate purpose and APIs that
can enter only with a freshly reacquired exact current TRANSFER. Save and
authorization reacquire that authority, while submission reacquires it for the
quote and again immediately before the broadcast fence. The runtime
requires exact live current/reacquired binding equality within each of those
immediate HNS operations; it does not compare a fresh binding to the historical
construction tokens.
It authenticates the unchanged pending approval, preserves script input zero, and
signs only the ordinary funding suffix. It returns the approval unconsumed so
one store transaction can persist the verified signed bytes and exact final-byte quote,
activate reservations, and consume that same row. Before submission, the
runtime re-quotes only the persisted bytes against fresh authority for that
source;
the wallet commits `RequiresRebroadcast`, the refreshed quote, bounded attempt
metadata, and all active reservation revisions before calling the node.

Reconciliation fetches exact transaction status and every input spender from
one runtime-owned chain snapshot. The aggregate derives mempool, confirming,
confirmed, conflicted, and same-byte rebroadcast states; disappearance after a
confirmation rolls back to `RequiresRebroadcast`, and an `Authorized` row can
recover if its exact bytes were observed outside the recorded submit path.
Persisted quote bindings are historical evidence only, and no caller-authored
clock or chain status restores authority after restart. Product coin selection,
live Denuo/provider/trusted-UI integration, and full
restart/reorg/regtest qualification remain pending. All Shakedex and dependent
HNS Shakedex-funding/value/fee release gates remain `false`, so preparation,
authorization, and submission cannot execute in a released product.

Wallet-owned name actions additionally consume the node's versioned
`name_action_context` for the exact chain epoch, tip, mempool instance and
generation. The wallet independently binds chain identity, candidate height,
canonical state, owner transaction and active-chain inclusion, fixed ordered
ineligibility reasons, owner mempool spender, transfer lockup, FINALIZE
maturity, and the HSD-selected active-chain renewal block. TRANSFER preserves
the name value at canonical input/output zero. Direct FINALIZE derives its
destination from the authenticated TRANSFER covenant and is signed by the
outgoing owner's `HnsName` key; incoming-recipient classification is not
signing authority.

Name workflow IDs deterministically bind account, action, and request nonce.
Preparation atomically saves the encrypted workflow plus separately typed name
source and ordinary fee-input reservations. Authorization consumes one exact
approval, retains final signed bytes and fee evidence before broadcast, and
reconciliation reports broadcast, mempool, transfer lock, finalize eligibility,
finalization, transfer cancellation, conflict, rebroadcast, and reapproval
states. Reservations for a broadcast name action remain attached across
confirmed states so a later reorg cannot silently free returned inputs.
Authority reacquisition permits a newer chain or mempool snapshot only when the
owner source and every transaction-defining action term remain unchanged. The
wallet reacquires again against the final fee quote's exact snapshot before it
persists or submits signed bytes; changed source or FINALIZE renewal terms move
the workflow to `ReapprovalRequired` for explicit cancellation and replacement.

The concrete synchronous HNS adapter now speaks the authenticated loopback
`hns-node-rs` wallet RPC v1 boundary, pinned to node commit `c1b633d1`. It
derives canonical ScriptIds, enforces full chain/mempool bindings, and validates
HTTP, JSON, transaction, spender, name, and HSD median-time evidence without
giving the node signing authority. The complete enclosing product runtime and qualification
evidence are still pending. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` therefore
remains false and HNS value capabilities are not advertised. See
[HNS_NODE_RPC.md](HNS_NODE_RPC.md) and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Bitcoin supervisor boundary

Bitcoin ordinary receive/change keys remain exclusively in BDK's BIP84
descriptor trees. Durable atomic-swap allocations use a distinct wallet-private
HKDF-SHA256 domain over the recovery seed and bind the wallet profile, session,
opaque frozen-terms commitment, coin type, exact network, bounded account/index,
and receiver/refund role. The swap derivation therefore never traverses or
allocates an ordinary BIP84 child, and an independently restored counter cannot
reuse a key for a different logical swap. One encrypted CAS batch advances a
monotonic high-water record and writes an immutable wallet/session/role binding;
redundant namespace-anchor and binding-claim records detect isolated missing or
relocated records. Exact retries are idempotent, role rebinding and clock
rollback fail closed, and recovery recomputes the public key before exposing
the non-serializable, zeroizing secret handle. The role-aware HTLC constructor
accepts that handle rather than a deserializable public record.

This is an allocation primitive, not a value-path integration. The settlement
layer must construct the opaque commitment from its complete canonical terms
and must never recycle a session ID. A whole encrypted-database rollback cannot
be detected solely by records inside that database; session-bound derivation
prevents cross-session key reuse, but recovery of already active swaps still
requires a current encrypted database backup. The byte-level scheme and
persistence boundary are documented in [BITCOIN_KYOTO.md](BITCOIN_KYOTO.md).
Signed-spend supervision and complete restart/reorg qualification remain
release blockers.

The Kyoto module starts from an explicit validated birthday, persists a
sequence/phase transition before sync, commits each returned update to BDK
SQLite, reconciles encrypted transaction/output mirrors in bounded chunks, and
commits ready last. Crash recovery can resume a pending reconciliation from the
durable BDK tip. A bounded set of previous hashes is checked against Kyoto's
local most-work chain to identify reorg ancestry; an unbounded/deep mismatch
requires recovery.

A signed broadcast record is content-addressed by txid and binds the wallet
network, wtxid, BDK-calculated fee, approved fee maximum, and expiry. The raw
transaction and approval are durable before submission starts. The supervisor
requires ready state, a running node and peer quorum, then records
`submission_started` before its bounded P2P request. Timeouts are retryable from
that record.

The BDK database and encrypted journal are independent durable boundaries, so
ready-last sequencing supplies logical recovery rather than pretending they are
one SQLite transaction. Pinned Kyoto does not durably expose headers, filter
headers/filters, or its address book; those missing objects prevent production
qualification. `BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` remains false.

## Ethereum containment boundary

Ethereum currently exposes only deterministic offline account/receive
derivation. Its synchronization, value-runtime, settlement-runtime, and
mainnet qualification constants are immutable and false; history shares the
synchronization gate. Capability discovery therefore advertises no online or
value path. Native-transfer and HTLC
construction/signing require opaque permits that the current source cannot
issue, and signing additionally binds the derived key role/address and an exact
approved maximum fee. The resulting bytes remain in a non-cloneable,
zeroizing, redacted controlled-broadcast artifact with no public raw accessor.
Chain ID 1 is rejected regardless of caller policy.

Serializable execution observations remain structural fixtures, not proof
authority. No release-flag-based public Helios provenance issuer exists; only a
future embedded verifier may construct the opaque evidence permit needed to
return an authoritative verified lock, and settlement permission is also
required. This prevents
ordinary JSON-RPC fields or caller-set booleans from advancing settlement while
Helios proof production, persistence, rollback recovery, deployment approval,
and qualification are absent.

## Future chains

A future UTXO module implements `ChainModule`, `UtxoChainModule`, and
`AtomicSettlement`. An account chain implements the applicable traits. The
market session is expressed only in module IDs, integer amounts, frozen terms,
hashlocks, timeout policies, and verified evidence. Adding a module does not
change provider method names or the market state machine. A pair is advertised
only after its complete success, restart, reorg, malicious-peer, and refund
qualification suite passes.
