# Persistence and restart recovery

Schema version 3 retains the schema-v1 table layout for forward migration and
adds encrypted, typed entity storage plus private provider tables. Wallet
accounts, derived addresses, HNS/Bitcoin/Ethereum state, known names, input
reservations, settlement verification records, market state, workflows,
permissions, approval requests, and replay records have bounded typed accessors.

Provider-service permissions use the encrypted permission records and monotonic
revocation tombstones. Provider authority handles, service/wallet sessions,
pending website approvals, handle replay/rate state, request-ID windows, and
event cursors are intentionally not restored. The generic pending-approval and
replay tables remain available to persisted wallet/HNS workflows, but ABI v2
does not write provider approvals or provider nonces there. This prevents stale
provider rows from becoming actionable or consuming provider capacity after a
restart.

An HNS Accounts permission generation persists the exact nonzero singleton
account ID selected for that origin and namespace. The service validates and
encodes the minimized `hns_requestAccounts` result before the scoped
permission write; after restart, `hns_accounts` re-authenticates the current runtime selection
and requires it to equal that persisted singleton. Legacy or generic records
that claim Accounts without an account binding are rejected, not migrated into
broader authority. The write must compare equal to the
generation authenticated by the approval, so a concurrent grant or revocation
makes that approval stale instead of rebinding it to newer authority. Runtime
selection and website approvals remain process-local and must be reacquired
after restart.

An account-scoped read grant extends that same record; it never replaces the
Accounts capability or singleton. A Names prompt performs a live reconciliation
and retains its exact account, sorted maximum-64 minimized disclosures, and
binary hashes only in process-local pending state. Approval re-synchronizes and
rejects a changed permission, account, or current set as stale. Only the exact
hashes shown to the user are persisted in the new permission generation;
display names and pending approvals are not restored. Nonempty scope requires
HNS namespace, Accounts, Names, and a nonempty account binding. Empty means no
disclosure. After restart, account and approved hashes are checked again and a
missing hash fails closed.

Sensitive values use XChaCha20-Poly1305 with random nonces. Associated data
binds the database ID, record domain and identifier, plus plaintext columns that
can affect a decision: entity/workflow revision and update time, workflow kind
and broadcast state, permission generation/revocation state, approval origin
token and expiry, and replay origin token/nonce/expiry. Changing one of those
columns without the key makes the record fail authentication.

Entity and workflow writes use immediate SQLite transactions and
compare-and-swap revisions. Bounded heterogeneous preparation batches
authenticate every current ciphertext and revision before writing, then commit
the wallet account, workflow, and all input-reservation saves/deletes together.
Duplicate `(entity kind, record ID)` operations and stale writers fail before a
partial batch becomes visible. Secret record IDs cannot change kinds; recovery
seed bytes are additionally immutable once inserted.

The native HNS create/restore bootstrap has a narrower atomic initializer. It
accepts exactly the 64-byte output of BIP-39 seed derivation and one exact
initial `WalletAccount`, requires both the recovery-seed and wallet-account
namespaces to be empty, and checks the target seed ID and account revision-zero
absence under one immediate transaction. Both ciphertexts are prepared before
the first insert. A malformed seed length, stale account, duplicate seed,
seed-only state, account-only state, encryption error, or injected failure
rolls the transaction back, so neither record can survive alone. Reopen
validation authenticates the selected seed, requires its plaintext length to
equal `RECOVERY_SEED_BYTES` (64), and still requires exactly one recovery-seed
row. This is intentionally distinct from the compatible legacy seed-only
`create_wallet` and `restore_wallet` APIs.

The HNS bootstrap helper generates or parses exactly 24 normalized English
BIP-39 words. New profiles retain the established random `WalletId`; restored
profiles retain the established mnemonic-derived `hns-wallet-id/v1` value. A
fresh nonzero wallet-local `AccountId` is paired with stable HD account index
zero. Network and restore birthday are explicit, while lookahead 100, two
confirmations, 546 atomic-unit dust, and disabled value/settlement gates are
fixed defaults. It constructs no backend and performs no node I/O. The phrase
remains in a zeroizing mnemonic until it is consumed into the dedicated
high-risk display wrapper.

HNS Shakedex seller keys have a dedicated deletion-protected encrypted entity
namespace. A legacy-defaulted WalletAccount gate starts as scan-required. The
runtime CAS-saves a durable scanning fence before the first 32-byte script
query and clears it only when the complete bounded scan commits; a later scan
can take over a crashed fence by advancing the account revision. New key
allocation is denied while the gate is required or scanning. One immediate
transaction then advances the WalletAccount projection and writes the
namespace anchor, account-global high-water, immutable workflow/name/canonical
economic-terms binding, and binding claim. No scalar is stored. Exact retry
returns the existing binding; changed context, a seed-commitment mismatch,
partial topology, clock rollback, or a second CAS conflict fails closed. The
next allocation takes the maximum of this durable high-water and the account's
restored on-chain Shakedex index, and reserves the configured trailing scan
gap, so concurrent writers to one wallet store cannot allocate through an
incomplete mnemonic scan and reuse a discovered lock key.

The fixed-price Denuo board is one versioned encrypted `DenuoBoardObject` with
an explicit 4,096-offer/watermark bound and a store-owned CAS revision. It
retains one canonical latest listing/cancellation record plus network/genesis,
name hash, seller key, expiry, status, and the exact highest observed sequence
for each seller/name identity. A higher valid listing replaces that identity's
older record without consuming another slot. Load re-decodes every object and
rejects unsorted, duplicate, mismatched, rolled-back, or malformed state. A
cancellation tombstone advances the watermark, so restart cannot make the
cancelled listing active or admit the same sequence under another content hash.
The signed listing target can be re-authenticated from these bytes to process a
still-active cancellation after restart without recreating locking-coin
authority. After the listing or cancellation's signed horizon expires, bounded
inventory filtering hides the object but retains its authenticated watermark,
so a later listing cannot reset or reuse the seller/name sequence. Relisting
the same identity replaces its stored object without growing the board. The
4,096-distinct-identity ceiling fails closed; durable archival and peer
admission policy remain required for a live relay. The cache does not persist
an action capability; current locking-coin/network/time authority must be
reacquired before a listing can drive value behavior.

Dormant Shakedex structural plans use the encrypted seller or buyer workflow
journal and its exact expected revision. Fulfillment plans retain the canonical
seller-controlled prefix and ordered buyer suffix; recovery plans bind the
exact lock descriptor and explicit recovery recipient. Exact retries may
revalidate the same persisted plan, while a stale revision or changed canonical
plan fails instead of replacing previously prepared bytes.

Post-lock buyer fulfillment, seller recovery, and seller-script FINALIZE now
share a separate encrypted `ShakedexValue` child workflow. Its deterministic ID
binds the parent workflow and action. One row retains the full canonical
structural plan and commitment, exact source and ordered funding-coin evidence,
recipient, value, fee and fee
maximum, finality threshold, expiry, prepared bytes, approval identity, signed
bytes, exact final-byte quote, monotonic attempt count/latest submission
timestamps, and runtime-derived chain observations. Deserialization revalidates
the structural transaction,
signed suffix, fee algebra, quote, identity, and state invariants before the row
can be resumed.

The additive tagged FINALIZE structural variant stores the exact signed
buyer-fulfillment or seller-recovery parent action, canonical bytes and hash;
the TRANSFER transaction and output-zero coin; current NameState and owner
inclusion; historical snapshot/mempool binding; and renewal height/hash. These
facts are immutable restart evidence. They do not serialize or recreate
`VerifiedCurrentShakedexTransfer`, and CAS cannot replace them with another
parent, transfer, purpose, owner, state, or renewal commitment.
On resume, fresh snapshot/mempool tokens may advance without changing this
historical record. Authority reacquisition compares the stable descriptor,
transaction/coin, owner inclusion, NameState, and renewal identity exactly;
the HNS runtime separately enforces exact live bindings within each immediate
bind/sign/submit fence.

The initial workflow CAS also writes one protected source reservation and every
protected funding reservation. The source row uses a store-global record ID
derived only from the exact lock or TRANSFER outpoint, so a second
wallet/account namespace in the same `WalletStore` cannot reserve the same
script-controlled coin.
Funding rows bind the workflow to the exact ordered ordinary HNS coins
recovered from the runtime cache. Missing,
extra, retyped, mixed-state, cross-account, or stale-revision rows fail closed.
Generic reservation cleanup cannot delete these protected kinds. Prepared
cancellation or explicit expiry atomically deletes the complete set;
runtime-owned time caps that prepared lifetime at five minutes, and product
startup must invoke the explicit expiry path. Authorization atomically changes
the complete set from expiring prepared rows to active rows.
Active rows remain attached through rebroadcast, mempool, confirmation,
confirmation rollback, and conflict while the result remains reversible. A
terminal release obtains the expected transaction and every input spender from
one runtime-owned snapshot, proves either exact-transaction finality or the
finality of an authenticated competitor at the workflow's persisted
confirmation threshold, and atomically saves the terminal evidence while deleting the complete protected
reservation set. Reconciliation never recreates those rows or reverses the
terminal stage; if a later snapshot no longer supports the persisted terminal
reason, it returns `RecoveryRequired` for explicit operator recovery.

Exact-transaction release requires matching spender evidence for every exact
input position and inclusion. A sufficiently final authenticated competitor on
any exact input may release the reservations because the persisted transaction
can no longer win. Missing exact-input evidence and immature competitors keep
the rows protected.

The approval request is a domain-separated encoding of the complete prepared
aggregate and its exact workflow revision. Runtime-owned time determines its
creation and expiry. The HNS runtime authenticates the unchanged approval.
Fulfillment and recovery reacquire the exact current/unspent lock; FINALIZE
uses a distinct reservation purpose and transfer-only public API, and
reacquires the exact current TRANSFER and chain/mempool snapshot. It matches
each canonical funding coin to one current tracked ordinary coin, preserves the
script-authorized first input byte-for-byte, and signs only suffix inputs
`1..`. After exact signed-byte fee quoting succeeds, one immediate SQLite
transaction consumes that same approval, saves the signed aggregate and quote,
and activates all reservations. A stale workflow or reservation revision,
changed/expired approval, stale runtime snapshot, signing failure, or quote
failure leaves the approval and prepared state unconsumed.

Before submission, the runtime reacquires current lock or exact
current-TRANSFER authority, re-quotes only the persisted signed bytes, and
atomically records the refreshed quote, `RequiresRebroadcast`, attempt
timestamp/count, and no-op CAS rewrites of every
active reservation. FINALIZE reacquires its exact transfer again immediately
before that durable fence. Only then may it call broadcast, and the returned
transaction ID must equal the persisted one. An ambiguous exit therefore
resumes from the same signed bytes. Reconciliation obtains the exact
transaction and all-input spender evidence under one runtime-owned
chain/mempool snapshot; it derives mempool, confirming, confirmed, conflicted,
or rebroadcast state and rolls a disappeared confirmation back to
`RequiresRebroadcast`. It can also recover directly from `Authorized` when the
persisted bytes reached the node outside the recorded submit path. It never
restores ephemeral current-lock/current-TRANSFER authority or treats persisted
snapshot bindings as current authority.

Script-controlled FINALIZE is durable in source, including atomic workflow plus
source/funding reservation persistence and the shared evidence-backed terminal
release path. Its HNS purpose-separation and FINALIZE restart/reopen/CAS/
replacement/binding-advance/reorg/finality regressions are included in the
exact CI evidence recorded in `QUALIFICATION.md`. All
Shakedex value authorization and submission entrypoints remain unreachable
while the fixed Shakedex and HNS Shakedex-funding/value/fee release gates are
`false`; live Denuo/provider/UI
integration and restart/reorg/regtest qualification are also pending.

HNS authorization can authenticate and return a pending approval without
consuming it. After exact signed-byte fee quoting succeeds, a bounded immediate
transaction re-authenticates that unchanged approval together with the current
workflow and reservation revisions, activates the reservations, saves the
authorized workflow/raw bytes/quote, and only then deletes the approval. Any
stale revision, changed approval, signing error, or quote error leaves the
approval and workflow state unconsumed.

Wallet-owned name preparation uses the same atomic boundary. The canonical
name source has a `Name` reservation carrying its exact name hash, while fee
inputs have `Ordinary` reservations; both sets must exactly match the encrypted
plan. Authorization activates the complete set before broadcast. Broadcast
name workflows retain those reservations through `TransferLocked`,
`FinalizeEligible`, `Finalized`, and confirmed transfer-cancellation tracking,
because any of those confirmations can disappear on reorg. Expiry, explicit
cancellation, or conflict releases them atomically. A formerly confirmed action
that disappears becomes `ReapprovalRequired`; replacing an explicitly
abandoned record requires a fresh request nonce and approval.

## HNS change derivations

Send preparation and settlement-lock preparation commit account change-index
advancement, the prepared workflow, and input reservations in one SQLite
transaction. The in-memory account is updated only after commit. Concurrent
losers and any precommit fee/build/sign failure leave all three records
unchanged; a committed workflow cannot reuse its change key or become invisible
behind a failed account CAS.

The send request nonce and settlement session/action derive deterministic
workflow IDs. A same-terms, nonexpired retry loads the encrypted prepared
workflow first, verifies the exact account/request/fee terms, signed artifact,
and complete reservation set, refreshes the committed account cache, and returns
the persisted artifact without deriving or reserving another change address.
Mismatched, expired, or advanced-stage retries fail closed.

## HNS name-role derivations

The `HnsName` branch has independent encrypted next-index, scan-end, and
last-used state. Legacy account records deserialize with deterministic defaults,
while legacy HNS coin address identifiers remain unchanged. Name-role address
identifiers include the role so the same branch/index cannot collide with an
ordinary receive address. A complete reconciliation persists the combined
account/address state only after the separate coin and name queries prove the
same chain epoch/tip and mempool instance/generation.
The legacy value runtime reloads the full authoritative account and its CAS
revision after taking its private store mutex, rejects derivation high-water
rollback, and holds that ordering through cache installation; a concurrently
prepared send or settlement cannot be overwritten by a stale scan clone. That
legacy reconciliation still spans backend work and is not selected by the
provider read composition.

`HnsAccountReadRuntime` instead writes an authenticated durable discovery fence
inside a short shared-store closure, copies the exact account/recovery/coin/
transaction/name corpus and revisions, releases the mutex, and only then calls
the node. Address derivation re-enters short closures that verify the same
fence and returns before the scanner performs backend work. The final commit
compares the unchanged fenced account and complete entity corpus, persists the
canonical shared scanner/reconciliation result, writes recovery checkpoints,
and clears the fence with the final account CAS. A crash or stale node leaves
the fence set; a later process re-authenticates the partial corpus and performs
a fresh complete scan before clearing it.

Name-role scan advancement is monotonic and bounded across restart and reorg.
Outputs to discovered name keys remain visible to history/reconciliation but
are excluded from ordinary balance, input selection, reservations, and
spendable UTXOs. This persistence establishes key discovery only: it neither
authorizes an action nor treats a node hint as ownership. Fresh reconciliation
independently decodes the split current/proof NameState bytes, binds exact owner
transactions and resource bytes, and persists canonical summaries plus
account-bound `HnsName` ownership or transfer direction. Legacy rows keep their
watch-only variant until replaced. Context-free imports authenticate canonical
state but mark wallet ownership explicitly unevaluated. Runtime imports recheck
the exact cache binding while holding the store lock immediately before their
CAS write, so a concurrent reconciliation cannot be overwritten with stale
evidence. Account, address, name, coin, transaction, and reservation reloads
query the complete bounded binary ID prefix for the selected wallet/account
(and the dedicated name role where applicable); a global list limit is never
applied before account filtering. Workflow IDs remain opaque, so recovery and
transaction lookup read the complete bounded kind or fail closed on overflow
before filtering decrypted account ownership. An action must reacquire
ephemeral ownership authority from the exact current snapshot; the encrypted
cache is UI/recovery state only.

Before HNS submission, the runtime loads the exact persisted signed bytes and
prior quote, re-quotes only those bytes, and atomically saves the refreshed
quote with `RequiresRebroadcast` before invoking the node. That durable state
means submission may have started even if the caller sees an error or the
process exits; recovery rebroadcasts the same persisted bytes, never caller
replacement bytes. Stale snapshot or unavailable quote input triggers at most
one complete reconciliation and one quote retry, with no polling loop.
Snapshot-only advancement does not invalidate an otherwise unchanged name
plan: the wallet revalidates the stable owner source and transaction-defining
terms, then reacquires against the final quote's chain/mempool binding. A
changed source or FINALIZE renewal commitment persists
`ReapprovalRequired`; cancellation releases its reservations, and replacement
uses a fresh nonce and approval.

TRANSFER/FINALIZE reconciliation follows the same persist-before-broadcast
rule and reconciles the exact persisted signed transaction by txid and
available raw-byte equality, together with confirmation arithmetic, competing
spenders, the transfer output's subsequent covenant, current candidate
maturity, renewal evidence, and owner mempool spender. It never restores an
ephemeral ownership or finalize authority from disk.

## Required startup sequence

The product runtime must:

1. securely open and migrate the database, remain locked, and request
   platform-backed unlock;
2. create fresh random wallet-service and wallet-session IDs with empty
   authority, approval, replay, rate, request-ID, and event registries;
3. negotiate a random host session plus exact restart generation over the
   private host/service transport; old handles and frames remain invalid;
4. finish any plaintext-migration checkpoint before exposing wallet state;
5. load persisted workflows, permission generations/tombstones, and the last
   consistent chain checkpoints;
6. resume HNS and Kyoto; keep Ethereum synchronization unavailable until its
   selected embedded adapter is implemented and qualified;
7. reconcile mempools, confirmations, replacements, and reorgs from atomic,
   validated evidence;
8. restore the bounded coin, name-role, and 32-byte Shakedex-lock scans under
   one exact chain/mempool binding; advance separated counters without rollback;
   revalidate split committed-proof/current name views; replace legacy watch-
   only rows with exact canonical summaries; and reacquire rather than restore
   any ephemeral ownership or Shakedex spend authority;
9. expire price rounds, intents, fill grants, persisted workflow approvals, and replay rows only
   after their authenticated metadata verifies;
10. restore swap sessions and independently verify every recorded funding,
   redemption, refund, Shakedex structural plan, and Shakedex value child
   workflow against newly acquired chain authority and its exact protected
   reservation set, requiring active rows for nonterminal signed workflows and
   no rows plus revalidated release evidence for terminal workflows;
11. extract an on-chain preimage only from the exact verified spend/event;
12. determine refund eligibility from validated local chain time; and
13. surface user actions without automatically moving value.

The checked-in subprocess now implements the locked existing-database control
subset of this sequence. It requires an explicit trusted-launcher
`--database` path, securely opens and migrates that database, rejects a
persistent composition whose store is already unlocked, creates fresh service
and wallet sessions, and accepts the passphrase only through the zeroizing ABI
unlock request. Provider state and runtime control share one store/key
authority. Unlock completes any authenticated plaintext-removal checkpoint
before rotating the wallet session; failure to rotate immediately re-locks the
store. Permission records and tombstone generations can then be loaded, while
authorities, approvals, replays, rate windows, request IDs, and event cursors
remain process-local. A separate library composition can validate one exact
pre-existing non-value HNS account from that same Arc-backed store during
unlock and expose only the account join in addition to the control methods. A
second library composition uses the synchronized read runtime and an explicitly
supplied backend to perform the non-value parts of steps 6 through 8 for every
account-scoped balance, history, receive-target, or name result. It does not
create an account, accept a caller-selected account, sign, broadcast, enable a
module, or move value. Every `hns_accounts` and chain read requires the
runtime-selected singleton to equal the persisted permission singleton. The
checked-in subprocess selects neither HNS composition, and steps 9 through 13
plus all value supervision remain uncomposed there.

The HNS source implements the concrete synchronous authenticated node adapter,
bounded coin/name/Shakedex-role chain/mempool snapshot reconciliation, and
prepared-transaction recovery. The learned durable chain epoch,
HSD-compatible tip median time, and process-instance/generation pair remain
exact across all three scans, gap expansion, and all point
reads in one reconciliation;
they are intentionally reacquired after process restart rather than persisted
as timeless authority. Exact final-signed fee quotes are wired and persisted
for HNS value and the release-gated Shakedex aggregate;
canonical fee-policy integration is implemented in source, but its explicit
qualification gate remains false. The complete multi-chain product supervisor
and current qualification evidence are not integrated, so HNS value operations
remain release-gated.

No Ethereum synchronization, history, or recovery checkpoint exists to resume
in this revision. Ethereum account and receive-target derivation is offline;
online evidence and value paths remain behind unavailable opaque permits.

## Bitcoin Kyoto recovery journal

The Bitcoin module uses one shared encrypted store authority with two ordered
record boundaries. A strict v1 `bitcoin_wallet_state` entity contains the
aggregate BDK-3.1.0 public descriptor/local-chain/transaction/output
changeset. It is account-ID authenticated, deletion-protected, and updated by
CAS. Separate encrypted records contain the authenticated birthday, distinct
non-genesis new-wallet recovery anchor, bounded recent checkpoints, supervisor
sequence and phase, transaction/output reconciliation mirrors, and signed
broadcast intents. These commits are ordered but are not claimed as one atomic
transaction.

Bitcoin swap keys add an encrypted entity namespace without a plaintext schema
table or seed copy. Each role allocation atomically writes an immutable
wallet/session/role binding and redundant binding claim while advancing its
network/account/role high-water record alongside a fixed namespace anchor. The
binding authenticates the scheme version, exact reference, compressed public
key, recovery-seed commitment, opaque frozen-terms commitment, and allocation
time. Existing exact bindings are idempotent; the store rejects generic single
or batch deletion of allocation rows. Recovery seeds are insert-once and may be
reinserted only with identical bytes; replacement or generic deletion is
rejected. Recovery re-derives from that encrypted seed and requires exact seed-
commitment and public-key matches before returning the zeroizing in-memory
secret handle. Counter, reference, record-kind, revision, time, or terms
mismatch fails closed.

The allocation-specific KDF additionally binds wallet ID, session ID, and terms
commitment, so a stale or copied counter cannot reuse a key for a different
logical swap. A full database snapshot rollback cannot be detected solely from
inside the rolled-back database and can still lose an active binding or choose
a different numeric reference. Session IDs must never be recycled, and a
current encrypted database backup is required to recover already active swaps;
the mnemonic alone is not an allocation journal.

A sync records `synchronizing`, applies the Kyoto update, commits the encrypted
BDK snapshot, records `reconciling`, applies encrypted mirror changes in bounded
chunks, and commits `ready` last. Consumers must ignore an incomplete mirror
unless the scan record is ready at its completed sequence. Restart from
`reconciling` compares the BDK tip to the pending checkpoint and resumes the
chunks without another network update. If the BDK commit landed but the
`reconciling` commit did not, the unequal tip forces a recovery scan. A sync
timeout discards the non-cancel-safe subscriber, shuts down the node, and
persists `recovery_required`; the poisoned supervisor cannot be reused.

The aggregate BDK snapshot has the same 1 MiB cleartext limit as every generic
encrypted entity, and its persistent script cache is disabled. Oversize state
fails closed; a normalized or authenticated chunked backend remains required
before Bitcoin value qualification. Standalone BDK SQLite databases from the
older source boundary are left untouched and are not imported. No migration
tool exists yet, so callers must retain such files and must not interpret a
missing encrypted entity as authorization to create over legacy state.

Broadcast preparation resolves every input through the same BDK wallet,
calculates the exact fee, verifies the approved maximum, and persists raw bytes
plus a network/txid/wtxid/fee/maximum/expiry commitment before Kyoto receives
them. A timeout after `submission_started` is restart-safe and retryable. This
retry observes the same rebroadcast interval as a known submission; approval
expiry is exclusive. Native-send signing and broadcast are dormant because the
Bitcoin value permit is release-gated.

Execution rejects a clock value behind the durable preparation or latest
attempt timestamp. A production release still requires a reviewed source of
trusted or monotonic time across process and device restart.

The pinned `bip157` 0.6.3 implementation ignores its configured `data_dir` and
does not expose durable headers, filter headers/filters, or peer address-book
state. Those databases cannot be truthfully restored by this source and remain
a release blocker. Canonically absent transaction/output records are retained;
safe archival is also pending, so the fixed lifetime caps fail closed.

## Migrations and backups

Opening first uses a read-only, no-follow, query-only connection to recognize
nonzero current-or-legacy wallet schema anchors and all four structurally exact
initialization metadata rows. A non-wallet SQLite database or an incomplete
schema-v1 wallet returns
`NotInitialized` before WAL configuration or migration. After the same file is
opened for writing, the immutable metadata snapshot is checked before
configuration and again after the transactional migration. A newer recognized
wallet schema fails closed. After plaintext rows are encrypted and deleted,
unlock records a checkpoint, truncates the WAL, clears the marker, and
truncates again; an interrupted checkpoint is retried on the next unlock before
state is returned.

The encrypted `ShakedexValue` payload keeps its internal schema version at v1
and adds script FINALIZE as a new tagged structural-plan variant. The new
reader still decodes and revalidates legacy v1 buyer/seller rows. An older
binary does not know the new tag and cannot decode a wallet after such a row is
written; downgrade is therefore unsupported and unqualified. This is only
forward compatibility for old rows in the new binary, not a downgrade-safety
claim.

Legacy schema-v1 provider grants and replay records have deterministic migration
paths. Legacy pending approvals are discarded because their creation time and
authority binding were not authenticated. Populated legacy funds-bearing entity
tables fail closed with `LegacyEntityMigrationRequired`; a dedicated import tool
must map them without ambiguity before unlock.

The Unix source, including Linux, Android, and iOS targets, requires a dedicated
directory owned by the process effective UID with exact mode `0700`. An
existing database must be a regular, single-link file under the same UID with
exact mode `0600`. Creation requires the path to be absent, atomically
precreates the file with create-new semantics, sets `0600` through the open
file handle, and then asks SQLite to open it without create permission. The
database and its `-wal`, `-shm`, and `-journal` names must all be absent before
creation. Ordinary creation retains an armed guard until the four
initialization metadata rows commit. `create_with_initializer` retains that
same guard through one borrowed caller-supplied initializer.
`create_with_owned_initializer` instead transfers the unlocked `WalletStore`
into a fallible product constructor, accepts the product's richer
`E: From<StoreError>` error, and retains the guard until the complete
store-owning controller or service has been returned. Both variants recheck the
created file identity before disarming. A returned constructor error therefore
drops the product-owned store and attempts cleanup of the whole new database,
including a seed/account transaction that may already have committed; under
the validated unchanged identity, no invocation-owned durable seed remains
when product construction fails before the recovery phrase is returned. On
failure the guard removes the database only if the path still names that same
regular, same-effective-UID, single-link inode, and attempts to remove only
regular, same-effective-UID, single-link sidecars that were absent at preflight.
An identity replacement or unowned artifact is preserved rather than guessed
away. A failed create never configures or migrates a pre-existing database or
sidecar. Abrupt process termination does not run the guard; startup must treat
a recognized database without the exact seed/account bootstrap pair as
incomplete and fail closed, not silently create the missing half. The mobile
opener authenticates the selected wallet's seed, requires its exact 64-byte
plaintext shape, and requires it to be the only recovery seed before accepting
the single account. Avoiding loss on termination after a complete bootstrap
commit but before phrase display requires a product-level
display/acknowledgement recovery design; RAII alone cannot prove delivery.

The selected directory and database entry may not be symlinks. System-level
ancestor aliases are canonicalized once. The prefix above the first directory
owned by the effective UID is an explicit native-host/platform trust boundary;
non-writable system-owned components in that prefix are host-trusted. Generic
Unix and iOS reject an unowned group- or world-writable prefix component unless
the sticky-directory rule protects a root- or effective-UID-owned next entry.
Only an Android build selects the additional app-data policy: a group-writable,
non-world-writable prefix directory owned by Android system UID 1000 is
accepted, relying on Android SELinux and app-data-root containment. From the
first process-owned directory through the selected `0700` directory, ownership
may not change and group/world write is rejected. A sticky writable directory
is accepted only when its next child is also owned by the effective UID, so
sticky rename protection actually applies. The database device/inode and
single-link identity are compared around both read-only recognition and
SQLite's write-capable no-follow open. Root, the same effective UID, and the
accepted host-platform prefix remain trusted; this is not a descriptor-bound
custom VFS and does not claim protection from those principals.

This policy has been executed on Linux only. Android and iOS target builds and
runtime filesystem tests remain release requirements. A mobile host must
provide the path inside its app sandbox and separately enforce sandbox
membership, ACL policy, Apple Data Protection where applicable, backup
exclusion, and Android Keystore/iOS Keychain key wrapping. UID/mode checks do
not prove those properties. Shared/external storage is not eligible. Non-Unix
persistent opening remains fail-closed. In-memory stores remain available for
bounded tests.
The shared process handle has no diagnostic representation and exposes the
store only through bounded locked closures. Detecting a poisoned shared lock
clears the record key before reporting failure. The service-specific persistent
constructor accepts only that shared handle and rejects an already-unlocked
store, preventing its initial locked provider posture from diverging from the
actual key state.

Copying a live SQLite file without its WAL is not a supported backup procedure.
The passphrase is not a substitute for platform device security. Product backup
design must document wrapped key handling, seed inclusion, retained KDF
parameters, and stale-state rollback detection.
