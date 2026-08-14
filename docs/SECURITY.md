# Security model

Status: production-hardening source implemented; executable value paths remain
release-gated. HNS send, wallet-owned name TRANSFER/FINALIZE, HNS settlement,
and Ethereum synchronization/history/send/settlement are disabled on every
network. Chain ID 1 and all other mainnet marketplace settlement are
independently disabled.

## Trust boundaries

- The website is hostile. It cannot supply an authenticated origin, select a
  browser namespace, reuse another navigation, or send native-host commands.
- The browser product retains the engine-issued, nonserializable authority. Its
  native host registers only engine-derived origin/namespace/runtime/policy/
  navigation facts over a private child pipe and issues a random opaque handle.
  The page cannot supply the handle or any authority fact as authentication.
- Service, wallet, and host sessions are random identities. Restart and
  authority revisions plus directional channel/event sequences are checked
  exactly. Wallet lock state and permission generation are service-owned.
- The reusable host state machine owns its authorization clock and operating-
  system entropy, mints all private host/request/authority identifiers and
  provider nonces, correlates a bounded pending set, and treats responses and
  events as one exact service-direction sequence. UI callers cannot choose
  authority revisions, approval ownership, provider bindings, or expiry time.
  Mandatory approval response classes, non-reusable approval IDs, negotiated
  method capabilities, and exact permission/session transitions are enforced
  again at this caller-side boundary.
- The wallet database and keys live in a native/mobile wallet process. Website
  JavaScript, extension local storage, and native-messaging frames never carry
  seed or raw private-key bytes.
- Denuo/Brontide authenticates a connection, not a listing, price, fill, chain
  state, or peer claim. Fixed-price discovery checks the exact registry/message
  family, canonical signature/content hash, monotonic seller/name sequence,
  network/genesis, active time window, and exact locking coin locally. The
  protocol verifier does not establish that caller-supplied coin as current or
  unspent; only fresh authenticated HNS adapter evidence may do so. Persisted
  cache bytes never become action authority after restart. Separately, the
  price-round cache accepts canonical zero-ID gossip under an exact local policy
  and a caller-owned trusted `accepted_at_unix` clock. An explicit predecessor
  checkpoint authenticates only that predecessor and its current link, not
  earlier ancestry. Canonical reporter-aligned sequence high-watermarks survive
  omission and pruning from the authenticated maximum-128-round suffix, while
  a pruned round hash/ID leaves duplicate detection. Full retained-row restart
  validation still supplies neither a live chain anchor nor quote/value
  authority, and it does not detect rollback of the complete authenticated
  database snapshot. The schema-v3 publication outbox can separately retain a
  canonical endpoint-signed receipt for one exact prepared envelope. Its full
  wallet-supplied HRM/HNSA policy, endpoint window, maximum lifetime, exact
  handoff identity, and signature are revalidated after restart, but the
  receipt proves only that configured endpoint accepted those bytes. It does
  not prove that the HRM/HNSA lineage is current, that a board included or
  retained the listing, that the lock remains unspent, or that any price or
  value action is authorized.
- The offline board runtime closes the cache-admission gap only when composed
  with the literal same Arc-backed store authority as a non-value HNS account
  read runtime. Each offer admission authenticates the canonical envelope and
  content hash, then queries and fences selected-account revision, network,
  trusted wall time, chain epoch/tip, mempool instance/generation, current
  NameState/action context, exact locking coin, and confirmed/mempool
  unspentness before a board CAS. Exact retries do not write. Cached active
  bytes are re-authenticated against a newly acquired lock and an unchanged
  board row before later use. Cancellation admission instead authenticates the
  exact signed target/content and fences selected-account network, trusted wall
  time, the full account selection, and board CAS without consulting a node or
  requiring the target lock to remain live. That negative tombstone only
  prevents replay/resurrection; it is not publication, chain, or value
  authority. This is still offline source composition: it supplies no live
  relay supervision, HRM/HNSA-currentness adapter, approval, signing,
  broadcast, quote, or product availability authority.
- The single-offer board-read plan accepts only canonical V2 `GetOffer` with a
  nonzero correlation ID and internally verifies the paired singular type-7
  `Offer`; missing and cancelled rows require no node query. It retains no
  response bytes and exposes no listing or current-lock handle. Its private
  point-in-time evidence is returned only after runtime clock observation and
  final chain, mempool, and exact selected-account fences. It is not a lease:
  any future live emitter must reacquire and fence current authority
  immediately before encoding or transport.
- Bitcoin production synchronization has one backend: Kyoto direct P2P with
  BIP157/158. There is no trusted indexer fallback.
- Handshake node evidence crosses one authenticated loopback HTTP/1.1 boundary.
  Loopback is not authorization: the wallet requires an exact, bounded,
  visible-ASCII Authorization value and rejects redirects, remote endpoints,
  ambiguous HTTP framing, and noncanonical RPC envelopes.
- The source models Helios-shaped evidence but has no embedded verifier that can
  produce its opaque authorization permit. Caller-serializable verification
  booleans are structural consistency inputs only. A future selected Helios
  runtime and its consensus/execution providers may still censor, omit, delay,
  correlate, or make the wallet unavailable.

## Secrets

Recovery seeds, imported private keys, HTLC preimages, wallet/workflow state,
provider permissions, and persisted workflow approvals/replay origins use
per-record XChaCha20-Poly1305 with random nonces. ABI v2 provider approvals and
handle replay windows are memory-only and disappear on service restart.
Associated data binds the database ID,
record kind and ID, and every plaintext metadata column used for authorization,
expiry, revision, revocation, or broadcast decisions. The database key is
derived with Argon2id. Secret buffers use zeroizing containers where practical.
The store rejects empty passphrases and inputs larger than 1,024 bytes at its
own API boundary; this is a resource/safety bound, not a substitute for device
key wrapping or a password-strength policy.

Native HNS bootstrap keeps its 24-word mnemonic in a zeroizing BIP-39 value and
exposes text only through the dedicated recovery-display wrapper. It generates
a nonzero random local account ID, fixes the HD account component to zero, and
constructs only a non-value, non-settlement account from an explicit network
and restore birthday. The encrypted, exactly 64-byte BIP-39 seed and initial
authenticated `WalletAccount` are inserted under one immediate transaction
with both namespaces required empty. Reopen authenticates the selected seed,
requires that exact plaintext length, and requires a singleton recovery-seed
namespace. Duplicate, malformed, or partial initialization is an error; the
initializer never fills in whichever half is missing.

The borrowed create-with-initializer boundary keeps the identity-safe new-file
cleanup guard armed through its callback. The owned form transfers
`WalletStore` into the fallible store-owning product constructor and keeps the
guard armed through service/controller negotiation; its error may be any
`E: From<StoreError>`. A returned construction failure drops the product and
removes the attributable new database before any recovery phrase is returned.
A hard process termination cannot run RAII cleanup, so a metadata-only file is
detected as incomplete rather than treated as authority to insert a seed or
account later. Termination after the atomic bootstrap commit but before phrase
display remains a product-level delivery/acknowledgement problem and is not
solved by the cleanup guard.

The persistent subprocess gives runtime control and provider persistence clones
of one non-debuggable `SharedWalletStore`; it does not open a second unlocked
permission connection or retain a second derived record key. Construction
requires that shared store to be locked. Unlock completes migration cleanup
before the service rotates its wallet session, and a session-entropy failure
synchronously clears the shared key again. Lock clears that key before the
provider session is rotated. Detection of a poisoned store mutex recovers it
only long enough to clear the key and then fails closed.

The exact-account library composition additionally proves Arc identity between
its `HnsExistingAccountSelector`, runtime, and provider store. Unlock succeeds
only if the configured non-value account already exists as an authenticated
record with a nonzero ID, the exact expected configuration, and no duplicate
HD account component. Selection uses a bounded store closure, performs no
node I/O, and never creates, updates, signs for, or broadcasts from an account. A separately
opened handle to the same database path is rejected as a different key
authority.

The synchronized read-only HNS composition proves the same Arc identity
for its selector, service/provider state, and `HnsAccountReadRuntime`. It stages
only authenticated rows inside bounded store closures; no backend method is
called until the closure and mutex guard have returned. A durable discovery
fence survives failure or process exit, and final persistence compares the
exact account revision plus coin, transaction, name, and recovery rows loaded
before node I/O. Account selection is checked again after scanning and after
commit. Stale chain epochs, changed tips, restarted mempool instance nonces,
generation changes, account changes, lock transitions, malformed evidence, or
row changes fail closed. The mobile read controller constructs this composition
internally from its lifecycle controller's literal shared authority or from one
newly opened shared authority; callers cannot inject a selector/runtime/store
join. Its combined synchronization obtains the trusted snapshot directly from
the composed service, immediately minimizes it, and never serializes the
chain/mempool binding or raw name proof/state/resource/owner/derivation
evidence. Every failed read locks before retry. The same binding never appears
in website JSON, and no mobile provider entry point exists.

The private `hnsReadOperationsV1` marker is emitted only by that full
synchronized runtime and requires the existing coarse wallet-operation
transport. A dedicated host method admits only status, one-account discovery,
and Handshake-scoped balance, receive, history, and module-status requests.
It rejects secrets, lifecycle controls, workflows, and other modules before
request-ID allocation. Responses fail closed unless locked status exactly
matches the absence of a nonzero active wallet and lists at most Handshake, the
account projection is exactly one nonzero Handshake account with a bounded
printable label and no receive display, balance uses HNS, receive echoes the
requested account and module with a bounded visible-ASCII target, every history
entry is Handshake with a unique nonzero transaction ID and no negative zero,
and module status is an error-free ready snapshot with one equal
validated/scanned/target height. Any mismatch poisons the session. The marker
grants no browser/provider authority and changes no availability or value gate.

The profile-backed native-read constructor narrows this further without adding
wire vocabulary. It accepts the literal locked shared authority, an owned
zeroizing/redacted/non-cloneable/non-serializable passphrase, and exact active
profile revision/update time. It unlocks only to authenticate and consume the
encrypted singleton, relocks before ordinary native-read construction,
performs a private internal unlock, and authenticates the same fence again
before returning. Its runtime-level request admission executes at the start of
request-specific dispatch, after framed session sequence/replay bookkeeping,
so every authority, provider, approval, ABI unlock/lock, create/restore,
workflow, and non-HNS module request is rejected;
only the six marker reads remain. The active profile fence is loaded before and
after each admitted read. A mismatch, tombstone, absence, malformed profile, or
store failure suppresses the read result and clears the key. Drop also
best-effort clears the same shared key. This is process-local containment, not
a cross-process database lease or secret-delivery mechanism; installed
products still need both and must terminate the process on lease invalidation.

The recovery-only profile constructor is a distinct closed runtime, not a mode
on the provider-capable native-read service. It accepts only exact existing
flagged account/profile identity under the same revision and live read fences;
there is no typed flagged-profile provisioning surface, and privileged generic
low-level store mutation is out-of-band state construction rather than recovery
authority. Its exact service capability
set omits `providerDispatch`, `persistentPermissions`, `valueMovement`, and
`browserIntegration`, every provider method is unsupported, and only the six
non-signing `hnsReadOperationsV1` wallet reads are admitted. Structural config
validation in this path is explicitly inert: it never authorizes current
Shakedex-lock/Denuo access, allocation, signing, import/export, workflows,
lifecycle, broadcast, settlement, or value. Ordinary/full constructors still
perform authority and release-gate validation. A synchronized recovery read is
not physically read-only: under the same revision fences it may create or
replace derived-address, coin, transaction, name, and recovery-cache rows,
update WalletAccount scan/index metadata without changing its configuration,
and write or clear the discovery fence, but it cannot create account/profile/
allocation/signer/workflow/value authority or rewrite configuration.

The injected backend is synchronous and broader than this read subset, but the
read controller exposes none of its broadcast, fee, signing, action, or value
methods. Products must enforce backend deadlines and call reads off the UI
thread. This repository includes no production Android/iOS wallet-index
backend; the authenticated loopback node RPC adapter is not device integration.
The runtime obtains its epoch/tip through a script-free chain snapshot, verifies
the selected network's exact genesis under that binding, and only then derives
or queries watch scripts. A wrong-network backend receives zero confirmed or
mempool script queries. This closes the protocol-ordering privacy gap but does
not qualify transport: the concrete adapter remains authenticated loopback-only,
and any production device/remote backend needs independently reviewed
authentication, confidentiality, deadlines, lifecycle, and installed-network
evidence. A pruned companion may omit raw confirmed transactions; fresh history
then fails unless authenticated wallet state already retained those bytes, so
production restore requires archive history or a durable wallet-relevant
raw-transaction index.

This boundary reuses the canonical HNS scanner and reconciliation helpers. The
legacy value runtime's full reconciliation still spans backend work while its
private store mutex is held, so it is not an eligible provider/product read
composition. Both value gates remain false.

This is authenticated record encryption, not whole-file encryption. Table
names, row counts, indexes, selected authenticated metadata, filenames, SQLite
journals, and access patterns may be visible. On Linux, Android, and iOS,
the source policy requires a process-effective-UID-owned `0700` directory and a
same-owner, single-link regular `0600` database. Creation fails on any existing
database or SQLite sidecar name and precreates `0600` through a file handle
before SQLite opens without create permission. An armed identity guard attempts
to clean a failed attempt only while the database still names the
invocation-created inode, and attempts to remove only preflight-absent sidecars that are regular,
same-effective-UID, and single-link. Opening an existing database first
recognizes its schema anchors and four structurally exact required metadata
rows through a read-only, query-only connection; non-wallet and incomplete
schema-v1 databases are not
switched to WAL or migrated. Selected-entry symlinks are rejected, system
ancestor aliases are canonicalized, and device/inode identity is compared
around recognition and the write-capable no-follow open.

Non-writable system-owned prefix components are host-trusted. Generic Unix and
iOS reject unowned group/world-writable prefix components unless a sticky
directory protects a root- or effective-UID-owned child. Only the Android
target admits the additional UID-1000, group-writable but non-world-writable
app-data prefix, relying on SELinux/app-data-root containment. The same-UID
suffix cannot change owner or be group/world writable, except for a sticky
directory protecting a same-owner child. This is not a custom-VFS guarantee
against root, same-UID, or the accepted host-platform prefix.

Only Linux execution is recorded. Android/iOS target and runtime qualification
remains required. Mobile hosts must prove app-sandbox membership, ACL policy,
Apple Data Protection where applicable, and backup exclusion; UID/mode checks
cannot establish them. Shared/external storage is not eligible. Non-Unix
persistent opening fails closed. A product integration must still wrap the
database key with Android Keystore/iOS Keychain/OS secure storage; that wrapping
is not implemented in this repo.

Recovery-phrase display remains a dedicated high-risk native/mobile concern and
is absent from the private service/provider ABI. Logs and ordinary `Debug`
implementations redact signing transactions, phrases, keys, and preimages.
Inbound passphrases and restore phrases use non-cloneable, redacted ABI secret
values whose owned allocations are zeroized on drop. Host-frame encoding, its
temporary JSON payload, and the checked-in service's inbound frame allocation
are also zeroized on drop; platform transports must not copy those
secret-bearing bytes into ordinary persistent buffers.
New host/service/wallet session IDs, authority handles, fingerprints, request
IDs, and approval IDs also redact `Debug` and `Display`; only their canonical
wire serializers reveal the value to the private transport.
Bitcoin swap-key handles additionally keep their secret half private,
non-serializable and non-cloneable, redact it from `Debug`, and zeroize the
32-byte scalar on drop. Their public allocation records and numeric references
contain no secret; the numeric reference alone is not a complete recovery
context.

## Money and transaction approval

Amounts are integer base units serialized to JavaScript as decimal strings.
Arithmetic is checked; prices and fees never use floating point. Value-moving
methods require a typed approval of at most 90 seconds bound to the service
session and exact authority handle/revision. Production UI must display asset,
exact amount, recipient, fee maximum, chain, finality policy, price-round
commitment, and refund timeout. Free-form approval display lines are rejected.

The library supplies the policy and state boundary; the current browser UI does
not yet provide every approval screen. No mainnet enablement may infer approval
from a unit test.

For ordinary HNS sends, the persisted workflow approval is authenticated
without consumption before signing. Only after the exact final signed bytes
receive a bound fee quote does one immediate transaction re-authenticate and
consume the unchanged approval, persist those bytes and quote, and activate the
matching reservations. Submission re-quotes the persisted bytes and records
`RequiresRebroadcast` before the node call. Canonical sigop-adjusted fee
algebra and exact input evidence are integrated in source, but their explicit
qualification gate remains false and prevents this wiring from authorizing
value.

Name actions bind the trusted approval to the exact encrypted prepared plan,
including its recipient, fee maximum, canonical source, and unsigned
transaction. The wallet deterministically signs and validates that unchanged
plan, obtains the bound final-byte fee quote, and consumes the unchanged
approval while persisting the signed bytes. It reacquires current name
authority and the versioned node action context before authorization and
initial broadcast, rejects any bound owner mempool spender, then reacquires
against the final fee quote's exact snapshot before persistence or submission.
An advanced snapshot is accepted only if the stable owner source and every
transaction-defining term remain unchanged; otherwise the workflow durably
requires fresh approval. The wallet persists rebroadcast state before the node
call.
TRANSFER preserves value and owner address while covenant-committing the
recipient. Direct FINALIZE takes its destination only from that authenticated
TRANSFER covenant and is signed by the outgoing owner's `HnsName` key;
incoming-recipient classification never authorizes signing.

Shakedex buyer fulfillment, seller recovery, and seller-script FINALIZE
approvals bind the complete prepared aggregate and its current CAS revision:
canonical parent plan, exact lock or TRANSFER source, ordered funding coins,
recipient, value, exact fee and maximum, confirmation policy, expiry, and
prepared bytes. FINALIZE also commits the exact signed parent action/bytes/hash,
TRANSFER transaction/output-zero coin, NameState, owner inclusion,
historical snapshot/mempool binding, and renewal evidence. The runtime owns the clock.
Lock spends accept only current-lock authority and their two existing purposes;
FINALIZE uses a new purpose and APIs that accept only current-TRANSFER
authority. The runtime reacquires that authority before signing and signs only
ordinary suffix inputs while preserving the script-authorized first input. It
consumes the unchanged approval only in the transaction that persists the
verified signed bytes and their exact final-byte fee quote and activates every
protected reservation.
All related Shakedex and HNS Shakedex-funding/value/fee release gates remain
`false`, so this source boundary cannot currently authorize value.

## Provider defenses

The provider core enforces secure exact origins (with loopback HTTP allowed for
development), origin-scoped persisted permissions, bounded methods/params,
ephemeral handle-bound request nonces, per-method windows, 90-second approval
expiry, and exact authority revisions. Replacement cannot change origin,
namespace, or runtime session and cannot regress runtime, policy, or navigation
generation. The service owns wallet session/lock state and reads permission
generation from the encrypted store. Permission creation begins at generation
one; every later grant or revocation advances the stored generation exactly
once. Revocation stores an authenticated tombstone so delete/regrant cannot
reset the generation. Service restart intentionally drops authorities,
approvals, replay/rate state, request IDs, and event cursors while permissions
survive.
Accounts permission is valid only with one exact HNS account ID in the same
encrypted permission generation. Generic permission requests cannot mint
Accounts authority, and legacy capability-only records fail closed. The
account result is validated and bounded before the scoped grant is persisted
against the exact generation authenticated by the approval; a generation
mismatch fails stale. Every `hns_accounts` call re-authenticates the current
runtime-selected singleton and requires exact equality with that persisted
singleton, so a restart configured for another account cannot inherit the old
grant. All HNS-prefixed methods are rejected outside the HNS namespace before
permission or approval processing. The checked-in persistent control runtime
cannot advertise the join; the explicit exact-account library composition can.
The control and account-only compositions cannot advertise or execute generic
permission creation because none of their methods consumes a non-Accounts
scope. The synchronized read composition can extend only an existing exact
Accounts grant, preserving its singleton account. Before a Names prompt, one
live sync derives at most 64 sorted, unique canonical name/SHA3-hash pairs with
the pinned `hns-covenants` authority. Pending state retains that exact account,
display list, and binary hashes. Approval rechecks permission/account and
performs a second live sync; any change rejects stale, and only the unchanged
displayed hashes enter the encrypted generation. No post-consent discovery or
expansion occurs. The 16 KiB prompt limit is an additional fail-closed bound.
Empty scope means no names, and any missing approved name fails the whole read
instead of falling back to all known names.

Public HNS reads are explicitly projected rather than serializing wallet
records. Amounts are decimal strings; account IDs and transaction/name hashes
are lowercase hexadecimal; keys are camelCase; heights and times must be
JavaScript-safe integers; lists fail rather than truncate above 128 entries.
Known-name output is limited to name, hash, proof height, coarse resource and
ownership statuses, and registered/expired flags. Raw/current proof bytes,
resource bytes, outpoints, derivations, node bindings, and internal epochs are
never disclosed. Labels and display strings must be nonempty printable ASCII
within their bounds.
Host restart/reset independently drops every service-derived handle revision,
pending request and approval, private binding, and event cursor. A response
kind mismatch, stale session, sequence gap/replay, unknown request ID, or stale
binding fails closed instead of advancing partial host state. Trusted-clock
rollback likewise poisons the private session and requires explicit restart.
Detached, stale, or expired host facts may be discarded, but their random
handles remain reserved for the lifetime of the host process.
Permission-change events clear every same-origin and same-namespace derived
binding and reset the global event-cursor domain exactly as the service does;
wallet-lock events clear provider state globally before further use.
The direct `wallet_lock` result snapshots the authenticated permission
generation before clearing the shared key, then returns that generation with
the newly rotated wallet session without attempting a post-lock database read.
It explicitly rejects seed/key extraction, raw signing, PSBT signing, generic
Ethereum transactions/calls, chain switching, and arbitrary native-host access.

The signed-artifact manifest schema is structural only. It contains no trusted
public key and cannot authorize itself. A product verifier must own its trust
roots, verify the artifact and canonical signed payload, persist a per-release-
line rollback high-water mark, and bind that evidence to process launch. No such
verifier is wired here, so a schema-valid manifest does not make the wallet
available.

## Atomic-swap limits

HTLCs can prevent unilateral theft when scripts, transactions, confirmation
depth, contract code/state/events, timeouts, and preimages are verified. They
do not prevent non-cooperation, fee spikes, chain congestion, censorship,
privacy leakage, delayed refunds, adverse price movement, or liquidity griefing.
Timeouts must be asymmetric and refunds must be constructed and validated
before funding.

HNS evidence requests bind a chain epoch, tip and mempool generation across
bounded sorted exact version-0 address pages. A nonzero node-instance nonce
prevents a generation reset after restart from reusing an old cursor. Transaction,
parent-output and outpoint-spend evidence must match that same snapshot.
The separate ordinary-coin and `HnsName` scans must share that exact chain and
mempool binding. Name-role outputs are tracked for history but excluded from
ordinary balance, selection, reservation, and spendability.
The scan reloads the authoritative encrypted account revision while holding the
store mutex and rejects derivation high-water rollback before replacing cache
state, so concurrent workflow preparation cannot be lost to stale reconciliation.
Settlement lock verification binds the exact funding outpoint, output index,
script, terms and confirmation policy, and preimage observation accepts only the
exact verified redeem witness.

Name proof evidence is bound to the exact chain epoch, tip height and tip tree
root, and the verified Urkel bytes must equal the separately returned proof
state. The interval-committed proof view is not collapsed with the current node
view. Both raw states are independently decoded under the requested name hash;
every node projection and exact owner transaction output must agree. Resource
bytes come only from decoded current state, and ownership requires an exact
persisted `HnsName` program rather than an ordinary coin address. Persisted
TRANSFER state also requires its transfer height to equal the active-chain
owner-transaction inclusion height. Context-free imports report ownership as
unevaluated rather than incorrectly asserting that a name is not wallet-owned.
Persisted ownership is display/recovery cache state, never action authority. The
non-serializable authority is freshly reacquired at one snapshot and is denied
for expired, revoked, unregistered, or pending-transfer state.
TRANSFER and FINALIZE additionally require the exact action/mempool snapshot,
network and genesis identity, current owner inclusion, candidate height,
ordered eligibility reasons, lockup, renewal window/hash, and absence of an
owner spender. Persisted action context is audit/recovery evidence only.

Shakedex fulfillment, explicit-recipient recovery, and script-controlled
FINALIZE adapters enforce canonical transaction shape. Encrypted parent-plan
CAS prevents a restart or stale writer from silently substituting different
structural bytes. Seller keys are allocated through a deletion-protected
encrypted namespace with an account-global CAS high-water, immutable workflow/
name/terms binding, seed commitment, and no persisted scalar. The recovered
signer is non-cloneable, non-serializable, redacted, and has no arbitrary-
digest method. The allocation transaction advances WalletAccount and protected
high-water together, while a durable scan-required/scanning gate prevents a
second writer to the same wallet database from allocating before mnemonic
restoration commits. The signer recomputes the canonical payment, price,
deadline, and fee commitment from every proof before signing, and proof/listing
signing accepts current-lock authority rather than a caller-supplied Coin.

The buyer-fulfillment, seller-recovery, and seller-script-FINALIZE value child
persists one inseparable funds-safety record: its structural commitment, exact
source/funding coins and reservation binding, prepared/signed bytes, approval,
quote, submission fence,
and chain observation. Its `ShakedexSource` reservation is keyed store-globally
by the lock or TRANSFER outpoint, so another wallet/account view in the same
`WalletStore` cannot reserve the same script-controlled input; account funding rows bind the
exact ordered ordinary coins. Generic cleanup cannot release either protected
kind. Prepared expiry is capped by runtime time to the five-minute prepared-
artifact window, and explicit expiry or cancellation releases the complete set
atomically. Product startup expiry integration remains required. Signed states
retain the rows while their chain outcome remains reversible. Terminal release
requires one runtime-owned snapshot containing the exact transaction and every
input spender. It accepts only the expected transaction at the persisted
confirmation threshold with every exact input position/inclusion, or an
authenticated competing spender at that threshold under the same snapshot.
The terminal evidence and deletion of the complete reservation set use one CAS
transaction.

The HNS runtime requires an exact current account/cache match and the authority
appropriate to the source: current lock with confirmed and mempool
unspentness for fulfillment/recovery, or exact current TRANSFER with canonical
parent, owner inclusion, NameState, maturity, and renewal evidence for
FINALIZE. The public types, reservation purposes, bind/validate/authorize
methods, and final-fee validators keep those lanes distinct. Prepared funding
witnesses must be empty; authorization preserves input zero byte-for-byte, signs inputs `1..`
with exact P2PKH `SIGHASH_ALL` witnesses, and revalidates the canonical signed
transaction. Persisted quote validation recomputes ordered input/output fee
algebra after restart but does not treat the quote's old snapshot as current.
Persisted construction bindings are likewise historical: harmless tip,
mempool-generation, or node-instance advances are accepted only when the exact
descriptor, transaction/coin, owner inclusion, NameState, and renewal identity
remain stable. Within an immediate bind/sign/submit operation, the HNS runtime
still requires exact live current/reacquired bindings.
Submission reacquires current lock authority or exact current-TRANSFER
authority, re-quotes the persisted bytes, and durably records
`RequiresRebroadcast` with the active reservation CAS before the node call.
FINALIZE reacquires its transfer a second time immediately before that fence.
Runtime-owned same-snapshot transaction and all-input
spender evidence drives mempool/confirmation/conflict transitions; a reorg can
move a formerly confirmed transaction back to same-byte rebroadcast. Caller-
supplied clocks, status flags, and replacement bytes do not drive these
transitions. Reconciliation of a released workflow is audit-only. If a deep
reorg invalidates or changes its persisted terminal reason, the workflow stays
terminal, reservations are not recreated, and the runtime returns
`RecoveryRequired` for explicit operator handling.

Script-controlled FINALIZE binds its TRANSFER coin to output zero of a fully
verified fulfillment or recovery parent that spends the exact lock, and that
identity is now durable in the aggregate. Persisted evidence never restores
current authority: save, signing, and submission reacquire the exact transfer.
Post-sign observation, reconciliation, rebroadcast, conflict handling, and
terminal release use only the runtime-owned generic evidence machinery. Exact-
transaction release requires matching spender evidence for every exact input
position; a sufficiently final authenticated competitor on any exact input may
release the now-unspendable competing transaction. Released rows are never
recreated, and later finality disagreement remains read-only
`RecoveryRequired`. Product coin selection, live Denuo/provider/trusted-UI
integration, and complete restart/reorg/regtest product qualification remain
pending. The focused FINALIZE tests are included in exact `2229be8` source CI.
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`,
`HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED`,
`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED`, and
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remain `false`.

Ethereum has no embedded Helios proof producer in this revision. Its exact
synchronization, value-runtime, settlement-runtime, and mainnet gates are
immutable and false; history shares the synchronization gate. Opaque permits
for transaction construction and verified locks cannot be issued. Helios
provenance has no public release-flag issuer and verified locks
also require settlement permission. Redeem preimages, signing intermediates,
and final signed bytes remain contained: preimages are non-Clone and zeroize on
drop, transient signing buffers use zeroizing owners, and the final signed
artifact is non-Clone, zeroizing, and redacted with no public raw-byte accessor.
Serializable observation fields are structural data only and cannot authorize
settlement.

Current cross-chain code is not qualified for live value. The concrete HNS node
adapter and canonical HNS name-state/resource ownership source are present, but
their exact source tests do not provide cross-process or product qualification.
A published canonical HNS settlement profile, live qualification of the
integrated HSD fee algebra and name-action context, Bitcoin supervisor network
qualification, embedded Helios proof construction/persistence, three-branch HNS
restoration and Shakedex-key product qualification, restart/reorg
demonstrations, real-chain tests, resource benchmarks, and independent review
remain blockers.

Bitcoin swap keys now have a deterministic application-private HKDF domain
which is disjoint from ordinary BIP84 receive/change derivation and binds the
wallet profile, session, opaque frozen-terms commitment, coin type, exact
network, bounded account/index, and receiver/refund script role. A copied or
stale counter therefore cannot reuse a key for a different logical swap. The
encrypted store atomically advances a never-decreasing per-role high-water
record and writes an immutable binding plus redundant anchor/claim integrity
records. Exact retries do not advance the counter; rebinding, exhaustion, clock
rollback, isolated missing/corrupt records, and repeated CAS conflict fail
closed. Recovery seeds are immutable through the store API, and recovery
compares both seed commitment and public key before exposing the zeroizing,
non-serializable handle. Raw derivation is crate-private; the role-aware HTLC
constructor requires that handle rather than a public record.

The allocator cannot prove that its caller's opaque commitment covers complete
canonical settlement terms, and it is not yet wired into the settlement
supervisor. A whole database rollback is not detectable from inside that
database; session-bound derivation prevents cross-session secret reuse, but
active-swap recovery still requires current encrypted allocation records and
non-recycled session IDs. This separation and persistence do not enable
settlement: signed-spend supervision and the complete qualification boundary
are still absent, and no Bitcoin signing or value permit is exposed by this key
slice.

Bitcoin's supervisor does not authorize from a peer status field. A completed
Kyoto wallet update is committed to the strict versioned encrypted BDK
changeset entity before encrypted transaction and output mirrors advance; the
authenticated scan record becomes ready only after all bounded reconciliation
chunks commit. The BDK entity and journal share the exact same non-debuggable
store/key authority. Exact local-chain hash-membership queries identify a
retained reorg ancestor. Missing ancestry, the BDK entity's 1 MiB capacity,
timeout of the non-cancel-safe update, or BDK/journal rollback mismatch fails
closed and requires a new supervisor/recovery scan. A standalone legacy BDK
SQLite database is never opened or silently discarded; migration tooling is
still absent.

The dormant broadcast path resolves every input as an unspent wallet output,
uses BDK's exact fee calculation, and verifies a domain-separated approval over
network, txid, wtxid, exact fee, approved maximum, and expiry. It persists
`submission_started` before a timeout-bounded P2P send and also requires ready
state, a live node, and peer quorum. Approval expiry is exclusive and an
ambiguous `submission_started` attempt must wait the rebroadcast interval
before retry. Native-send signing and broadcast require the value permit, which
remains unobtainable in this revision.

The journal rejects wall-clock rollback behind durable preparation or attempt
timestamps. This fail-closed check does not replace a reviewed trusted-time or
monotonic-clock source, which remains a Bitcoin value-release requirement.

Pinned `bip157` 0.6.3 discards `data_dir` and does not expose persistent header,
filter-header/filter, or address-book state. BDK checkpoints and wallet records
are durable, but they do not fill that light-client persistence gap. Bitcoin
send/settlement therefore remain disabled pending a reviewed Kyoto boundary,
adversarial/restart/reorg qualification, resource measurements, and audit.

## Reporting

Do not include live seeds, keys, database files, preimages, capability tokens,
or production origin receipts in a report. Provide a minimal non-secret
reproducer and exact repository revision.
