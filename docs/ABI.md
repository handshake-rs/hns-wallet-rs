# Private wallet service ABI v2

ABI v2 is a deliberate replacement for the unreleased v1 value decoder. There
is no v1 compatibility decoder and no byte-vector origin context. Existing
browser manifests that require v1 must continue to report the provider
unavailable until a coordinated released v2 artifact is installed.

Every frame is exactly one four-byte big-endian payload length followed by one
strict JSON object. Unknown fields, empty frames, trailing bytes, partial
frames, and declared payloads over 1 MiB are rejected. The length is checked
before payload allocation. Provider requests are at most 64 KiB, provider
results 256 KiB, provider events 64 KiB, and approval prompts 16 KiB.
Host-frame encoding returns a zeroizing owner because wallet-operation frames
can contain passphrases or restore phrases. Platform transports must write
directly from that owner and must not copy secret-bearing requests into
ordinary long-lived byte buffers. The checked-in stdio service likewise reads
each inbound frame into a zeroizing allocation.

The first frame is a host hello containing:

- ABI version 2;
- a random 256-bit host-session ID;
- a nonzero restart generation, monotonic within that host session; and
- the exact platform transport.

The service responds with a fresh random 256-bit service-session ID. Subsequent
frames bind both IDs, the restart generation, a monotonic directional channel
sequence, and a canonical request ID. A new service process therefore rejects
every old request even if a numeric restart generation is accidentally reused.
All service IDs use fixed-length, unpadded base64url JSON strings, reject the
all-zero sentinel and noncanonical trailing bits, and redact `Debug`/`Display`.
Persisted wallet IDs retain their existing serialization.

## Host-side state machine

`hns-wallet-host` is the trusted caller-side state boundary for this protocol.
It owns its clock and entropy sources, mints the host session, opaque authority
handles, request IDs, and provider nonces, and never accepts caller-supplied
authorization time. A test caller may inject deterministic clock and entropy
implementations, but the production constructor uses the operating system.

No request is emitted before an exact hello is accepted. Host request sequence
and service sequence are separate; responses and events share the one service
sequence because the service emits both from the same counter. Pending request
IDs are bounded and response kinds must match their originating operation.
Authority register/replace/revoke responses update only the exact pending
handle and revision. Provider results, capability snapshots, and approvals must
match the current private binding. Methods with mandatory approval cannot return
a direct provider result, and permission/session mutations must advance exactly
as their method requires. Negotiated service capabilities constrain every
advertised method. Approval decisions reuse the stored owner, revision, binding,
and expiry rather than accepting those values from the UI; accepted approval
IDs cannot be reused within the host session. Exhausting the bounded approval-ID
lifetime set requires an explicit new host session rather than silent reuse.
Only detached, stale, or host-clock-expired authority facts can be discarded
without a correlated service revoke, and discarded handles are never reissued.
Event replay cursors are scoped to authority revision, wallet session, and
permission generation. Permission-change events invalidate every same-origin,
same-namespace binding, module-change events invalidate capability snapshots,
and reset the host's global event-cursor domain to match the service sequence
reset. Wallet-lock events invalidate all provider state. A restart or any
protocol/sequence/correlation failure clears all
service-derived authority, binding, approval, and replay state.

This crate is a reusable state machine, not a Chromium launcher, mobile FFI
binding, engine-authority adapter, secure approval UI, or availability gate.

## Authority control

Authority registration is accepted only over the private host/service pipe.
The browser host issues a random opaque handle and registers engine-derived
facts: logical origin, namespace, runtime session/generation, policy and
navigation generations, decision fingerprint, and expiry. Registration itself
is affirmative; there are no authentication/injection booleans. The service
never receives an engine authority object and does not reproduce engine policy.

Register, exact-revision replace, and exact-revision revoke operations own the
handle lifecycle. Every provider result, approval prompt, and event embeds one
private ABI-v2 `binding`: handle, service-owned revision, wallet-session ID,
and authority-scoped permission generation. Generation zero means no grant or
revocation has ever existed; an absent record after revocation retains its
nonzero tombstone generation. Pages supply none of these binding values.

## Approvals and events

Approval expiry is Unix milliseconds with a maximum lifetime of 90,000 ms.
Free-form display lines are forbidden. The closed approval union covers
permissions, module enablement, send, name transfer/finalize, typed signature,
name offer/purchase, direct offer/direct-offer take, and swap redeem/refund.
Value summaries carry integer given/received asset amounts, maximum fee,
recipient, chain/finality, and, where applicable, refund time. An incomplete or
kind-mismatched summary fails closed. Recovery-phrase display is not a
provider/service operation.

Every approval-schema-v3 `Permissions` summary carried by private ABI v2 has a
required `hnsNames` list. It is empty unless Names is requested and always
empty for `hns_requestAccounts`. A Names summary contains at most 64 entries
sorted by `(name,nameHash)` with unique canonical names and hashes. Validation
uses the pinned `hns-covenants` rules and requires each lowercase hash to equal
SHA3-256(name). The 16,384-byte approval-frame limit remains authoritative and
prompts fail rather than truncate.

Events are typed frames bound to host/service/restart sessions, the exact
provider binding, a monotonic service channel sequence, and a per-authority
event sequence. Connect and permissions-changed payload generations must equal
the binding generation. Bounded collection and string limits are checked.

## Capability posture

Capabilities are a closed enum. Unsupported operations return the typed
`unsupportedCapability` failure and are never inferred from compiled source.
`hnsReadOperationsV1` is one fixed private sufficiency marker for exactly six
non-value wallet requests: status, list accounts, Handshake balance,
Handshake receive target, Handshake transaction history, and Handshake module
status. The last four reject every non-Handshake module before request-ID
allocation. The marker requires the coarse `walletOperations` transport but
does not imply provider dispatch, browser integration, value movement, or
product availability.

`hnsWalletAuthorityContextV1` is a separate additive native-only marker and
does not alter that frozen six-request enum. Its sole request is
`walletAuthority/currentHnsContext`, carrying a canonical mainnet, testnet, or
regtest name/magic plus a nonzero opaque namespace and lease generation. The
positive response binds those fields to one active nonzero wallet/account,
nonzero authenticated wallet-profile and account-row revisions, and exact
unlocked/persistent/nonrecovering/nonretiring/read-ready state. The namespace
claim remains authority owned by the native broker: the service response only
supplies evidence to compare while the consumer already holds the matching
guard. It is never a provider or website message. Negotiating this marker
requires both `walletOperations` and `hnsReadOperationsV1`.

`WalletHost::hns_read_request` is the strict caller path for that contract.
It accepts no create, restore, unlock, lock, workflow, signing, value, market,
or other-module operation. Correlated responses must remain non-settlement and
HNS-only: locked status is equivalent to the absence of a nonzero active wallet
and contains at most the Handshake module; the account list contains exactly
one nonzero Handshake account, a bounded printable nonempty label, and no
receive display; balances are HNS; receive targets match the requested account
and module and use a bounded nonempty visible-ASCII display; every history
entry belongs to Handshake with a unique nonzero transaction ID and no negative
zero amount; and module status is an error-free `ready` snapshot whose
validated, scanned, and target heights are equal. A scope or response class
mismatch poisons the private channel. The established generic
`wallet_request` path remains available for trusted mobile/control consumers;
its presence alone is not evidence that any read operation is implemented.

The authority-scoped private `providerCapabilities` request returns a typed
snapshot with exactly `providerSchemaVersion: 1`, `approvalSchemaVersion: 3`,
`walletSessionId`, `permissionGeneration`, and `methods`. Its session and
generation must equal the accompanying binding, schema versions are exact, and
method strings must belong to the exact shared 43-name wallet-types list; short
unknown strings are rejected as well as oversized ones. The advertised subset
may contain `hns_requestAccounts` only when the service runtime explicitly
supports the account selector; the service pairs it with `hns_accounts`, a
structured approval containing exactly Accounts, and an exact persisted account
binding. Generic `wallet_requestPermissions` summaries cannot contain Accounts.
Generic permission creation is advertised only when a currently supported
permission-bearing runtime method can consume the requested scope. When
provider dispatch is absent, `methods` is empty.

Names are synchronized before the prompt and the exact account, display list,
and binary hashes remain in process-local pending state. Approval synchronizes
again; an account, permission, or current-name-set change rejects stale. The
grant persists only the hashes already displayed and never discovers or
expands authority after the decision.

The website method `wallet_getCapabilities` instead returns only
`providerApiVersion: 1` and `methods`. Its outer private result binding is
retained by the native adapter and never projected to the page. A Chromium
adapter must combine the private snapshot with negotiated service availability
and project exactly `{abiVersion,available,walletSession,permissionGeneration,methods}`.
The checked-in subprocess is an existing-database control runtime. It starts
locked, shares one store/key authority with encrypted provider permissions, and
advertises wallet operations, persistent permissions, and provider dispatch.
It does not advertise `hnsReadOperationsV1`.
After ABI unlock its provider subset is exactly `wallet_getCapabilities`,
`wallet_getStatus`, `wallet_getPermissions`, `wallet_revokePermissions`, and
`wallet_lock`. Wallet creation/restoration, generic permission creation,
accounts, chain methods, value movement, and browser integration remain absent.
The presence of this private control plane does not make a browser provider
available; a released launcher, engine authority adapter, and independently
qualified product runtime are still required.

The subprocess requires exactly `--database <existing-wallet-database>` and
reads and writes v2 frames on inherited standard streams. The database path is
trusted launcher configuration, never a website request; the passphrase is
accepted only as the ABI-owned zeroizing unlock secret. A production Chromium
launcher must supply private child pipes and a separately released signed
artifact. The downstream Android/iOS 0.5.9 candidate source now drives the
trusted-native controller through separately maintained JNI/C wrappers; those
wrappers are not a mobile provider, production backend, signed release, or
installed-device qualification. Filesystem paths, process commands, raw signing,
recovery output, private keys, database keys, preimages, and arbitrary contract
calls are absent from the protocol.

The encrypted native-HNS-read profile remains a wallet library provisioning
record, not an ABI secret or browser message. The checked-in subprocess does
not load it, so provisioning it makes no operation or provider available. The
library-only profile-backed constructor consumes an owned zeroizing passphrase
and exact nonsecret profile fence without putting either on the wire. Its
returned ordinary runtime admits the six read requests plus the additive
authority-context request, and it is the only wallet composition that can
advertise the latter marker. It independently validates network/magic and
returns the profile revision and freshly authenticated selected-account row
revision; it does not authenticate the caller-supplied namespace claim. The
consumer must compare that claim under its independently held broker guard and
re-read it around dependent use. Recovery, simnet, generic runtimes, ABI
unlock/lock, provider requests, and the checked-in executable remain excluded.

Because service capabilities are a closed enum, an older ABI-v2 decoder rejects
a hello containing either HNS-specific marker. The native read service,
trusted host, and downstream extension adapter must therefore adopt the exact
additive vocabulary together. This is one first-release protocol shape, not a
parallel product release line. Older consumers of the checked-in control
executable remain unaffected because that executable emits neither marker.

## Machine-readable contracts

`../abi/contracts-v2.schema.json` is one JSON Schema Draft 2020-12 bundle with
five named roots: private wallet-service frames v2, private provider capability
snapshots v1, public approval projections v3, public provider event projections
v1, and signed artifact manifests v2. `../abi/golden-vectors-v2.json` provides
bounded valid and invalid structural fixtures covering every service request
and response class (including native wallet-authority evidence), every wallet
request/response class, all twelve approval
summaries, all thirteen public events, fresh generation zero, a retained
nonzero tombstone, private-field leaks, kind mismatches, and rollback metadata.
Runtime-invalid vectors additionally cover name ordering and SHA3 name/hash
equality, which JSON Schema cannot express.

Approval schema v3 deliberately replaces the unpublished v2 projection because
`hnsNames` is newly required. Private ABI framing and sessions remain v2: an
exact provider-capability snapshot negotiates approval schema v3 before the
host can issue any provider request, so mismatched peers fail before an
approval is decoded. Wallet FFI, service, host, private/public schemas, and
vectors use the one exact v3 shape. Browser or future mobile-provider consumers
must negotiate, adopt, and render it before provider Names becomes available;
strict v2 and v3 shapes reject one another rather than silently dropping
disclosure. The trusted-native mobile read snapshot is not a provider consumer
and grants no website authority.

The frame fixtures describe the JSON payload after the four-byte length prefix;
the prefix and encoded byte ceilings remain codec/transport invariants. JSON
Schema also cannot express equality between sibling binding/session fields,
clock-relative expiry, canonical set order, or stateful anti-rollback. Runtime
validators must continue to enforce those rules. Manifest structure and a
well-shaped signature do not establish publisher authenticity: trusted keys,
signature verification, durable rollback state, artifact hashing, and the
release gate are not implemented here, so artifact/runtime availability stays
false.

The host and contract regressions passed exact `2229be8` workspace CI;
the earlier `ba9f013` result remains a historical baseline. Exact run records
are in [`QUALIFICATION.md`](QUALIFICATION.md). Installed browser/mobile-provider
adoption and artifact-authenticity evidence belongs to downstream products and
does not change this private ABI or any fixed availability gate.
