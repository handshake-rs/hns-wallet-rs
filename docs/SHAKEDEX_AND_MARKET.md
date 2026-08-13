# Shakedex and cross-chain market

## Fixed-price Shakedex

The crate preserves the encrypted compare-and-swap seller, buyer, and recovery
schemas and their historical transition ordering for persisted-state
compatibility. A separate encrypted aggregate child workflow now coordinates
post-lock buyer fulfillment, seller recovery, and the seller-script FINALIZE
that follows either signed TRANSFER parent, but every authorization and
submission entrypoint remains release-gated. The wallet dependency boundary
consumes the canonical V2 `hns-swap` and
`hns-marketplace-protocol` source from the same immutable revision `b24b66c`.
It does not reproduce listing hashes, signatures, Shakedex scripts, presigns,
cancellations, or Denuo envelopes.

The canonical protocol-verification boundary decodes a bounded fixed-price
listing, requires its exact content hash, and calls
`FixedPriceListing::verify_for_network` with
the selected network, current time, and exact supplied locking coin. This
protocol authority has private fields and is neither cloneable nor
serializable, but it does not prove that the supplied coin is currently
unspent; the value runtime must obtain that evidence from the authenticated
HNS adapter. That adapter now returns non-serializable current-lock authority
only after binding canonical NameState and owner coin, no confirmed or mempool
spender, the exact chain/mempool snapshot, network/genesis, and the tip's
HSD-compatible median time past. A cancellation is accepted only through
`ListingCancellation::verify_for_listing`. Its signed listing target can be
re-authenticated from persisted canonical bytes after restart or a lock spend,
without pretending those bytes prove current ownership. Denuo offer and
cancellation decoders return typed protocol results rather than
unauthenticated wire objects.

The dormant value-planning boundary now has typed canonical adapters for the
three script-controlled transaction shapes needed after a name reaches its
Shakedex lock. Buyer fulfillment is reconstructed through the signed proof's
canonical fulfillment builder, with the seller input and payment kept in their
fixed positions. Seller recovery is reconstructed through the exact lock
descriptor and an explicit recovery recipient. Script-controlled FINALIZE is
constructed from a supplied TRANSFER coin and NameState and installs the
descriptor's script-only finalize witness. Fulfillment preparation rechecks
the listing at the supplied current wall time and checks the proof's encoded
time lock against the separately supplied parent MTP. FINALIZE preparation
requires a verified fulfillment or recovery parent and binds the supplied
TRANSFER coin to that parent's exact transaction ID and output zero. These
adapters accept explicit funding suffixes only as bounded transaction-building
inputs; they do not select wallet funds, reserve inputs, or sign ordinary
funding keys. The HNS runtime separately exposes only purpose-bound seller
signing. Prepared results bind ordered input coins and outpoints, exact
fees, expected recipients, and canonical bytes; signed-result verification
requires exact `SIGHASH_ALL` P2PKH funding witnesses and rechecks bounded
ordinary outputs, covenant links, and standard witness execution rather than
trusting a caller success flag.

The production-facing construction adapters no longer accept those chain facts
independently. Buyer fulfillment consumes the current-lock authority and its
snapshot-bound parent MTP; seller recovery consumes the same current lock;
script FINALIZE consumes a current unspent TRANSFER authority that binds the
exact parent bytes, active NameState, maturity, and selected renewal block.
Protected seller recovery can be authorized only from the current-lock wrapper
and requires that exact current-lock capability again at authorization. The
value runtime must reacquire it before irreversible use.
The explicit supplied-value functions remain a low-level structural boundary
for deterministic verification and do not themselves confer chain authority.

Seller keys use the independent `HnsShakedex` role and a protected encrypted
allocation namespace. One atomic CAS batch commits a namespace anchor,
account-global high-water, immutable workflow/name/canonical economic-terms
binding, binding claim, and the WalletAccount derivation projection. A durable
scan-required/scanning fence excludes allocation until the independent branch
scan commits, including across processes. Exact retries return the same key;
changed context is rejected; seed-only restoration scans the corresponding
32-byte lock programs. Secret scalars
are rederived only after the allocation topology and exact 64-byte recovery
seed commitment authenticate. The opaque signer is non-cloneable,
non-serializable, redacted, and exposes only canonical proof, listing,
cancellation, and recovery operations. Proof/listing/cancellation signing
recomputes payment, price, lock-time, and fee terms and rejects substitution;
proof and listing signing also require the current-lock authority directly.

Signed fulfillment and recovery results can be retained as encrypted buyer or
seller structural-plan state under the compare-and-swap journal. A persisted
plan binds its canonical terms and transaction bytes so a restart can reject a
changed or stale plan instead of silently rebuilding different bytes.
The script-controlled FINALIZE is now a third tagged structural-plan variant in
the encrypted value child. It embeds the exact signed buyer-fulfillment or
seller-recovery parent action, bytes and hash; exact TRANSFER transaction and
output-zero coin; current NameState and owner inclusion; chain/mempool binding;
and renewal height/hash. Those fields are immutable evidence, not restored
authority. A changed parent action, transfer, owner inclusion, state, renewal
commitment, funding purpose, or CAS identity fails closed.
The stored chain/mempool tokens describe construction history rather than a
permanent liveness condition. A freshly reacquired authority may have advanced
tokens only when the descriptor, parent bytes, TRANSFER coin, owner inclusion,
NameState, and renewal height/hash remain exact; immediate HNS runtime fences
still require their live current/reacquired tokens to match exactly.

The `ShakedexValue` aggregate is a distinct child of one canonical buyer or
seller plan. Its deterministic ID binds the parent and action, including a
separate discriminator for seller-script FINALIZE. One encrypted CAS record
retains the complete structural plan and commitment, exact lock or TRANSFER
source and ordered funding coins, recipient, value, fee and fee maximum,
confirmation policy, expiry, prepared bytes, signed bytes, final fee quote,
submission fence, and chain observations. Loading the row re-decodes and
revalidates those relationships; persisted fee-quote bindings remain
authenticated historical evidence and do not claim that a snapshot is still
current.

Preparation atomically saves that child with protected `ShakedexSource` and
`ShakedexFunding` reservations. The source reservation ID is store-global and
derived from the exact lock or TRANSFER outpoint rather than a wallet/account
namespace,
preventing the same script-controlled coin from being reserved by another
workflow or wallet view in the same `WalletStore`. Funding rows bind the exact
ordered, currently tracked ordinary HNS coins. Generic HNS cleanup and ordinary
activation/deletion paths reject
both protected kinds. Runtime time limits a prepared aggregate and its rows to
the wallet's existing five-minute prepared-artifact window. A prepared
cancellation or explicit expiry deletes the complete set in the same CAS;
product startup integration must invoke that expiry path. Signed states retain
the source and funding rows while their chain result remains reversible. A
terminal release re-observes the expected transaction and every input spender
under one runtime-owned snapshot. It deletes all protected rows atomically with
the terminal workflow only when the expected transaction has the persisted
minimum confirmations and every exact input position/inclusion matches, or an
authenticated competing spender reaches the same persisted threshold under
that snapshot. Subsequent reconciliation is audit-only: a deep reorg or changed
terminal reason returns `RecoveryRequired` and never silently recreates rows or
rolls the workflow back.

The approval commitment contains the exact prepared aggregate and its current
revision. Runtime-owned time governs preparation, approval expiry,
authorization, and submission timestamps. Buyer fulfillment and seller
recovery use only current-lock authority; seller-script FINALIZE has a distinct
reservation purpose and APIs that accept only current-TRANSFER authority. The
runtime reacquires the relevant non-serializable authority and its fresh
chain/mempool binding, checks the protected reservations and current cached
funding coins, preserves input zero and its script witness byte-for-byte, and
signs only the ordinary P2PKH suffix. A lock-purpose reservation cannot cross
into the FINALIZE path, and a FINALIZE-purpose reservation cannot cross into a
lock path. The unchanged approval is consumed only in the transaction that persists those
signed bytes and their exact final-byte fee quote while activating all
reservations. Restart validation recomputes canonical structure, funding
witnesses, input/output fee algebra, fee maximum, and the persisted quote.

Submission reacquires current lock or exact current-TRANSFER authority and
re-quotes only the persisted signed bytes. The FINALIZE path reacquires the
exact transfer again immediately before the durable broadcast fence. Before
the node call, one workflow/entity CAS records
`RequiresRebroadcast`, advances the monotonic attempt count, saves the refreshed
quote, and reauthenticates every active protected reservation. The node must
return the expected transaction ID. Reconciliation obtains transaction and
all-input spender evidence from one runtime-owned chain snapshot and derives
`Mempool`, `Confirming`, `Confirmed`, `Conflicted`, or
`RequiresRebroadcast`; a disappeared confirmation rolls back to the same-byte
rebroadcast path. Reconciliation also recovers an `Authorized` row when its
persisted bytes were broadcast outside the recorded submit path. There is no
submission polling loop and no caller-authored clock or chain status input.

The encrypted `DenuoBoardObject` namespace now has a versioned, bounded board
reducer and CAS load/save boundary. It persists canonical listing and
cancellation bytes, content hashes, network/genesis, name hash, seller key,
expiry, and per-seller/name sequence watermarks. One current record is retained
per identity; a higher sequence replaces it without consuming another slot.
Exact repeats are idempotent; sequence rollback, replay after a tombstone,
registry substitution, corrupt restart state, and board overflow fail closed.
Inventory contains only active, unexpired content hashes. Watermarks remain
durable after expiry to preserve the protocol's monotonic sequence rule. The
board therefore refuses a 4,097th distinct seller/name identity; bounded
archival/admission policy is still required before live relay enablement.
Persisted board objects are re-decoded on load, but they remain cache data:
every purchase or value action must reacquire fresh locking-coin and chain
evidence.

A separate encrypted `DenuoBoardObject` record holds a dormant, offline-only
publication outbox. It accepts only exact canonical V2 `Offer` and `Cancel`
envelopes with nonzero request IDs. Each row binds the canonical listing or
cancellation content hash and a wallet-local, domain-separated SHA-256
`envelope_id` over the exact envelope bytes. The latter is local persistence
identity, not a Denuo protocol content identifier. Exact enqueue retries are
idempotent; request-ID churn, duplicate message identity under different
envelope bytes, registry substitution, malformed bytes, and non-publication
message families fail closed.

Through the Shakedex outbox API, first admission is typed rather than
caller-asserted: an offer requires its `AuthenticatedFixedPriceListing`, while
a cancellation requires the listing-bound `VerifiedListingCancellation`.
Restart validation rechecks canonical signatures, exact encoding, identities,
and lifecycle invariants; it does not recreate the listing-bound admission
authority from arbitrary stored bytes. Raw mutable `WalletStore` access is a
trusted in-process composition boundary: AEAD detects external storage
tampering, but does not defend against an authorized writer constructing and
encrypting another record. No broader store-boundary redesign is part of this
tranche.

The outbox retains at most 1,024 entries, limits each exact envelope to 16 KiB,
and rejects an aggregate serialized form above 512 KiB. Schema v2 selects due
entries deterministically by due time, creation time, then envelope ID, and
permits at most one aggregate-wide `HandoffPrepared` row. The attempt ID binds
the exact envelope ID, original request ID, next failure ordinal, and
preparation timestamp. Its CAS state is durable before the exact-byte prepared
artifact is returned. That artifact has private fields and is neither cloneable
nor serializable. Loading re-decodes and exactly
re-encodes every envelope, recomputes both identities, and checks sorted unique
envelope IDs, request IDs, and message identities. The first durable version
of every entry must be pending; subsequent CAS saves cannot remove entries,
rewrite exact bytes, skip the prepare-before-failure phase, create multiple
prepared rows, roll back terminal state, or regress the encrypted record
timestamp. Restart reloads the identical outcome-unknown preparation but never
auto-resends it; an explicit correlated recovery call records one failure and
schedules the identical envelope and request ID. Failure 64 becomes terminal
`Exhausted`. Schema-v1 rows are validated in place and migrate on their next
mutating save. A schema-v1 `Acknowledged` row remains immutable terminal legacy
state; schema v2 has no API that can create acknowledgement or claim remote
acceptance. This boundary performs no network I/O, peer discovery, publication,
transport acknowledgement, or gate change. A future authenticated transport
adapter must preserve the exact stored bytes, supply correlated acceptance
evidence, and reacquire fresh current listing/lock/network/time authority before
sending.

Three compile-time gates are immutable and `false`:
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`. `SellerSession::new`,
`SellerSession::apply`, `BuyerSession::discover`, and `BuyerSession::apply`
check these gates before validation or mutation. Existing sessions restored
from legacy persisted records therefore cannot bypass the boundary.
Aggregate authorization and submission also require
`HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED`,
`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` and
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED`; all three remain `false`.
The Denuo gate governs live transport, relay publication, and product
discovery. Offline canonical envelope parsing and encrypted cache reduction do
not enable those runtime paths or advertise the feature. Typed transaction
planning, encrypted plan CAS, and the durable aggregate do not bypass any
release gate.

The wallet now has coherent canonical V2 source plus exact NameState/resource/
owner-output validation. Wallet-owned P2PKH TRANSFER/direct FINALIZE remains a
separate authority and is not reused by Shakedex. Canonical planning, protected
seller-key allocation, purpose-bound signing, current/unspent lock acquisition,
active-chain NameState/renewal evidence, parent-MTP authority, exact protected
reservations, final-byte approval and fee evidence, persist-before-broadcast,
and chain-state reconciliation are present in source for buyer fulfillment,
seller recovery, and seller-script FINALIZE. The fixed release gates remain
`false`. Product-owned coin selection, product/startup orchestration, live
Denuo/provider/trusted-UI integration, and complete
regtest/restart/reorg/product qualification are still required before any gate
can change. The current regressions are covered by the exact CI evidence in
`QUALIFICATION.md`; focused historical runs do not replace product or network
qualification. Reverse Dutch is deferred.

## Market intents and sessions

Market intents freeze offered/received integer amounts and a verified price-
round hash. Reservations enforce expiration, partial-fill policy, available
quantity, monotonic sequences, and double-reservation prevention. Peers cannot
advance a swap by claiming funding/redeem/refund; only verified evidence can.

The session state includes terms frozen, refunds prepared, first/second funding,
both funded, first redemption, secret observation, second redemption,
completion, refund eligibility/broadcast/refunded, and terminal failure. Timeout
plans require the first refund to exceed the second by a safety margin. The
canonical funding order is the side with the longer refund window first; the
shorter side funds only after sufficient confirmation evidence, preserving time
for secret observation and the first-chain redemption.

HNS/BTC uses SHA-256 native HTLCs on both chains. HNS/ETH uses the HNS script
and the approved native-ETH contract. Neither pair is advertised because full
HNS adapters, Bitcoin signed settlement, Helios runtime evidence, integrated
success/refund/restart/reorg tests, and real-network qualification are absent.
Ethereum synchronization, history, send, authoritative evidence, and settlement
permits are unavailable, and chain ID 1 is rejected unconditionally.

## Price rounds and Denuo

Canonical reporter observations, quorum rounds, intents, fill grants, name
offers, cancellations, and swap messages live in the
`hns-marketplace-protocol` boundary in `hns-rs`. The wallet consumes it only at
the pinned immutable revision, never through a sibling path. The fixed-price
name board now consumes its canonical Denuo envelopes; price governance,
reporter enrollment, outlier/circuit-breaker qualification, peer
cooldown/scoring, and live node/browser relay integration remain unavailable.
