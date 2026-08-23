# Shakedex and cross-chain market

## Fixed-price Shakedex

The crate preserves the encrypted compare-and-swap seller, buyer, and recovery
schemas and their historical transition ordering for persisted-state
compatibility. A separate encrypted aggregate child workflow now coordinates
post-lock buyer fulfillment, seller recovery, and the seller-script FINALIZE
that follows either signed TRANSFER parent, but every authorization and
submission entrypoint remains evidence- and approval-bound. The wallet dependency
boundary consumes canonical V2 `hns-swap` and `hns-marketplace-protocol` as exact
published registry `hns-rs` `0.3.1` source
`0e99addca59778b7b7c6fc56291333a97c4c8815`, with all upstream archive checksums
recorded in `release/hns-rs-0.3.1-crates.sha256`. The wallet does not reproduce
listing hashes, signatures, Shakedex scripts, presigns, cancellations, or Denuo
envelopes.

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

The name-market portion of the encrypted `DenuoBoardObject` namespace now writes
normalized `HeadV2Indexed` persistence. Its encrypted head carries the logical
board revision and compact row selectors. Each selector binds the identity-row
digest, physical revision and update time, row-value commitment, and listing
hash; the head also commits to the complete row-value and listing-index metadata
sets. Each seller/name identity has one strict, domain-separated digest-addressed
encrypted row containing its current canonical listing or cancellation and
durable sequence watermark. Each identity row also has one strict encrypted
index addressed by a domain-separated digest of its stored listing hash and
pointing to the identity-row digest.

A full load captures the exact bounded namespace in one coherent store snapshot,
authenticates every row and index, verifies the head commitments and exact
listing-index/row bijection, and then reconstructs and validates the logical
board. A mutation performs that full load, retains unchanged child physical
revisions through authenticated compare-only assertions, changes only affected
children, and consumes a ciphertext-fingerprinted exact namespace lease in the
immediate write transaction. A concurrent namespace insertion, deletion,
revision change, or same-metadata ciphertext replacement therefore fails closed.

Runtime offer and cancellation mutations add a second compare-only
`WalletAccount` prefix guard. The HNS runtime captures the selected wallet's
complete account prefix before node or clock work. The mutation closure consumes
and refreshes that guard in the same coherent snapshot that loads the board,
then both the board lease and account guard are checked in the board write
transaction. The public `verify_unchanged_account` helper is read-only and
non-atomic with a later write; mutation paths instead consume
`revalidate_unchanged_account` and the refreshed account lease.

A sole legacy-v1 aggregate remains readable and is atomically replaced by
indexed storage on its next successful mutation; legacy/head coexistence and
torn state are rejected. Historical normalized `HeadV2` plus row objects also
remain strictly readable. Targeted requests use the full semantic loader for
that format, and its next mutation preserves unchanged row revisions while
atomically adding listing indexes and installing `HeadV2Indexed`.

Indexed listing-hash reads always perform O(N) complete row/index metadata and
selector comparison against the authenticated head, including equality with the
exact listing-index ID set derived from selector listing hashes. If every
requested hash has an index, only O(K) encrypted index and row values are
authenticated for K hits in requested order. A head/index-only miss cannot rule
out a row whose authenticated semantics disagree with its selector, so any
missing requested index invokes the O(N) full semantic row/index loader before
returning authoritative absence. This is not an O(1) lookup. Legacy-v1 and
pre-index `HeadV2` targeted reads, plus inventory, always use a full logical-
board load.

One current record is retained per identity; a higher sequence replaces it
without consuming another slot. Exact repeats are idempotent; sequence rollback,
replay after a tombstone, registry substitution, corrupt restart state, and
board overflow fail closed. Inventory contains only active, unexpired content
hashes. Watermarks remain durable after expiry to preserve the protocol's
monotonic sequence rule. The board therefore refuses a 4,097th distinct
seller/name identity; bounded archival/admission policy is still required
before live relay enablement. Persisted board state remains cache data: every
purchase or value action must reacquire fresh locking-coin and chain evidence.

The offline `DenuoBoardRuntime` now supplies that admission/reacquisition join
without enabling live discovery. A non-value composition may use an
`HnsAccountReadRuntime`; the production value composition instead uses the
full `HnsWalletRuntime` so it does not maintain a second mutable account cache.
Both constructors require a clone of the runtime's literal same Arc-backed
`SharedWalletStore`; a separately opened connection to the same path is not the
same authority. The canonical offer envelope is first decoded as an
`AuthenticatedFixedPriceListing`, so its signature and exact content hash can
be checked before any caller-supplied chain projection is accepted. The HNS
read runtime first authenticates the complete selected-wallet account prefix and
captures its ciphertext-fingerprinted lease. It then obtains a script-free chain
binding, an exact seller-lock mempool query, canonical current NameState and
TRANSFER action context, confirmed and mempool unspentness, selected network,
and its trusted wall clock. It fences chain and mempool again, then refreshes
the account lease in the coherent mutation snapshot that fully loads the board.
Only the immediate transaction that checks both the account guard and board
namespace lease may commit the reducer. Exact retries return `Existing` at the
unchanged revision, higher sequences replace the same identity, and
equivocation/rollback fails closed.

Cancellation admission uses an intentionally narrower authority. A first
phase authenticates the canonical V2 cancellation signature plus externally
expected target and content hashes without treating it as time- or
listing-bound. The HNS runtime then observes only the exact selected account,
its network, and trusted wall time; it performs no backend query. It captures
the complete `WalletAccount` prefix lease before the clock observation, then
refreshes that guard beside the full board load. One bounded store mutation
reauthenticates the persisted target listing, verifies the cancellation's active
window and seller/network binding, advances the tombstone watermark, and saves
only while both the account guard and board namespace lease remain exact. A
spent or missing lock does not block this negative replay-prevention action.
Exact persisted retries remain no-write `Existing`
results after restart or signed expiry; changed cancellations must still be
currently valid and strictly advance the watermark.

`current_offer` deliberately repeats the current-lock query after restart or
before later use, verifies the persisted canonical listing against that exact
coin/network/time, and finally fences the unchanged board revision and row.
On indexed storage, both board projections use the targeted path above when the
hash hits; a missing index, the legacy aggregate, or historical pre-index
`HeadV2` uses the full semantic fallback.
Its non-serializable result is evidence for an enclosing, still-gated value
workflow, not permission to sign or broadcast. This join performs no Denuo
transport or relay I/O. The HRM draft supplies the current manifest root and
HNSA is an HRM `hns.named-service/v1` profile; neither an HRM/HNSA lineage nor
an endpoint-signed relay receipt substitutes for current HNS locking-coin
authority. Every canonical Denuo and Shakedex value product gate remains
`false`.

The board also accepts exactly one canonical V2 `GetOffer` envelope through a
closed read boundary. Denuo requires a nonzero correlation ID for both this
type-6 request and its singular type-7 `Offer` response; this differs from the
zero-ID cancellation/tombstone case. Inventory, batch, response-family, V1,
zero-ID, malformed, and noncanonical inputs are rejected before current-lock
lookup. Missing or cancelled rows return typed absence without querying a node;
a missing indexed hash first takes the full semantic board fallback described
above. Otherwise the runtime reacquires and fences `current_offer`, encodes the
singular response internally, authenticates its exact request ID, listing hash,
and canonical listing bytes, then discards both encoded and decoded response
objects. Runtime clock observation occurs before the final chain and mempool
fences and the same-snapshot refresh of the complete selected-account prefix,
so a clock-time account mutation or same-metadata ciphertext replacement cannot
survive into the plan. The non-cloneable, non-serializable plan exposes
only correlation ID, hash, and board revision. It carries no response bytes or
transport/value capability, and a future emitter must reacquire authority
again immediately at use time because neither the plan nor
`CurrentDenuoBoardOffer` is a lease.

The adjacent closed inventory boundary accepts only canonical V2
`GetOfferInventory` with a nonzero correlation ID; other request and response
families are rejected before account, clock, store, or backend access. Under
the literal same store authority, a generalized purpose-minimized HNS board
context captures the complete selected-wallet account prefix before the trusted
clock observation and refreshes its metadata and ciphertext fingerprints inside
the board-read snapshot. The snapshot contains only active rows whose network
exactly matches the current account and
whose signed window contains the observed time. It performs no node query and
no write. This inventory operation intentionally uses the full logical-board
load rather than the targeted listing-hash path. The corresponding canonical
`OfferInventory` response, including an allowed empty inventory, is encoded and
decoded internally to verify the exact
correlation ID and ordered hashes, then discarded. The non-cloneable,
non-serializable plan exposes only correlation ID, board revision, and count;
it exposes no hashes or response bytes and is neither publication nor a
transport lease.

The closed batch boundary accepts canonical V2 `GetOffers` with the same
mandatory nonzero correlation. Although the protocol request can carry up to
4,096 hashes, the corresponding type-5 `Offers` response and the wallet's
coherent current-lock primitive are both limited to 64; the wallet therefore
rejects a larger request before account, store, backend, or clock access.
Hashes remain in their canonical sorted, unique, nonzero request order.
Missing and cancelled rows are omitted, while an all-absent result retains the
observed board revision in a typed local plan and deliberately does not invent
the protocol-invalid empty `Offers` response. Before node access, the actual
nonempty candidate response is preflighted against the aggregate protocol
payload bound. Indexed storage always performs the O(N) metadata/selector scan;
all-hit requests authenticate O(K) values, while any missing index performs the
O(N) full semantic fallback before the subset is accepted. Every active
candidate is then reauthenticated and joined to
one ordered HNS current-lock batch sharing a single selected-account, chain,
mempool, network, and trusted-time authority. A duplicate underlying name,
expired or wrong-network listing, stale/spent lock, or other invalid active row
fails the whole plan; there is no sequential fallback. The final store snapshot
refreshes the complete selected-account prefix and fences the board revision and
exact projection of every requested row, including authoritative full-semantic
absence and cancelled entries. Canonical response bytes are encoded and decoded
internally under the exact request ID,
hash subset, ordering, and listing bytes, then discarded. The public plan
exposes only request ID, board revision, requested count, and returned count;
it provides no hashes, listings, locks, response bytes, transport, signing,
provider, publication, or value capability.

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
and rejects an aggregate serialized form above 512 KiB. Schema v3 selects due
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
state. Schema-v2 rows may retain a prepared handoff, but they cannot inject
either that legacy acknowledgement or schema-v3 `RelayAccepted` state.

Schema v3 can move one exact prepared handoff to terminal `RelayAccepted` only
with a bounded, canonically encoded, strict-DER low-S secp256k1 receipt signed
by the configured HNSA endpoint key. The receipt binds the network, exact HRM
root tuple, HNSA service/delegation/endpoint identifiers, caller-owned nonzero
Denuo application-profile ID, endpoint validity, maximum receipt lifetime,
attempt, request, content identity, and exact-envelope digest. The complete
network identity is `(u32 magic, nonzero genesis)`; magic zero is a valid
configured value, never a wildcard, and must exactly match the handoff. The
complete policy and receipt bytes are encrypted with the row and re-parsed,
exactly re-encoded, fingerprinted, lifetime-checked, and signature-verified
after every restart. An exact retry returns the existing terminal snapshot
without a revision change; a different valid receipt conflicts with the first
terminal receipt.

This is wallet-defined relay transport evidence only. It does not establish a
current HRM/HNSA authority, board inclusion or currentness, live chain or quote
authority, propagation, or permission to move value. The boundary still
performs no network I/O, peer discovery, publication, or gate change. A future
transport adapter must construct the policy from retained current HRM/HNSA
authority, preserve the exact stored bytes, and reacquire fresh current
listing/lock/network/time authority before any dependent use.

Three Shakedex source gates are enabled:
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`. `SellerSession::new`,
`SellerSession::apply`, `BuyerSession::discover`, and `BuyerSession::apply`
still validate the complete canonical, evidence, and persistence boundary
before mutation. Existing sessions restored from legacy persisted records
therefore cannot bypass the boundary.
Aggregate authorization and submission also require
`HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED`,
`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` and
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED`; all three source gates are enabled.
The Denuo gate governs live transport, relay publication, and product
discovery. Offline canonical envelope parsing and encrypted cache reduction do
not bypass required runtime evidence or advertise a browser/provider product.
Typed transaction planning, encrypted plan CAS, and the durable aggregate do
not bypass any of those checks.

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

`ShakedexValueRuntime` is now the only public orchestration surface for those
aggregate value transitions. It proves literal shared-store identity at
construction and before each operation. Database validation and CAS phases run
inside short store closures; current-lock/TRANSFER acquisition, signing,
fee-quote calls, broadcast, and chain observation run only after the closure
has released the store mutex. Thus a production service can combine provider,
board, and signing state under one decrypted-key authority without reopening
SQLite or deadlocking when the HNS runtime re-enters the store. This
composition work does not alter any release gate.

## Direct HNS/BTC offers and sessions

The cross-chain Denuo path is a direct, signed fixed-terms HNS/BTC board. A
maker chooses one indivisible pair of integer amounts; a taker selects that
specific offer. The protocol carries no price round, price reporter, source,
oracle, external feed, historical rate, partial-fill reservation, or matching
engine. A live board may group active offers by their exact BTC-per-HNS ratio,
but that is presentation only and never changes the signed settlement amounts.

An offer take binds the original offer ID to one swap-session ID and a distinct
taker settlement key. The maker proposal and the accepted session hello bind
both settlement authorities, the original terms, hashlock, descriptor
commitments, confirmation requirements, and asymmetric refund deadlines. Peers
cannot advance a swap by claiming funding, redemption, or refund; every value
transition requires independently verified local chain evidence.

The longer-deadline offered-asset lock funds first. The other side funds only
after the required confirmation evidence, preserving time for preimage
observation and first-chain redemption. HNS/BTC uses SHA-256 native HTLCs on
both chains. The Android product still requires complete wallet-controlled
fund/redeem/refund execution, direct-peer transport/UI wiring, recovery and
reorg testing, and release qualification before it can advertise settlement.
