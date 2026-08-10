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
name offer/purchase, market intent/fill, and swap redeem/refund. Value summaries
carry integer asset amounts, maximum fee, recipient, chain/finality and, where
applicable, price round and refund time. An incomplete or kind-mismatched
summary fails closed. Recovery-phrase display is not a provider/service
operation.

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
artifact. Mobile may drive the same state machine in process after generated
JNI/C bindings exist. Filesystem paths, process commands, raw signing, recovery
output, private keys, database keys, preimages, and arbitrary contract calls are
absent from the protocol.

## Machine-readable contracts

`../abi/contracts-v2.schema.json` is one JSON Schema Draft 2020-12 bundle with
five named roots: private wallet-service frames v2, private provider capability
snapshots v1, public approval projections v3, public provider event projections
v1, and signed artifact manifests v2. `../abi/golden-vectors-v2.json` provides
bounded valid and invalid structural fixtures covering every service request
and response class, every wallet request/response class, all twelve approval
summaries, all thirteen public events, fresh generation zero, a retained
nonzero tombstone, private-field leaks, kind mismatches, and rollback metadata.
Runtime-invalid vectors additionally cover name ordering and SHA3 name/hash
equality, which JSON Schema cannot express.

Approval schema v3 deliberately replaces the unpublished v2 projection because
`hnsNames` is newly required. Private ABI framing and sessions remain v2: an
exact provider-capability snapshot negotiates approval schema v3 before the
host can issue any provider request, so mismatched peers fail before an
approval is decoded. Wallet FFI, service, host, private/public schemas, and
vectors use the one exact v3 shape. Browser/mobile consumers must negotiate,
adopt, and render it before Names becomes available; strict v2 and v3 shapes
reject one another rather than silently dropping disclosure.

The frame fixtures describe the JSON payload after the four-byte length prefix;
the prefix and encoded byte ceilings remain codec/transport invariants. JSON
Schema also cannot express equality between sibling binding/session fields,
clock-relative expiry, canonical set order, or stateful anti-rollback. Runtime
validators must continue to enforce those rules. Manifest structure and a
well-shaped signature do not establish publisher authenticity: trusted keys,
signature verification, durable rollback state, artifact hashing, and the
release gate are not implemented here, so artifact/runtime availability stays
false.

The historical host and contract regression baseline passed the exact
`ba9f013` workspace CI recorded in
[`QUALIFICATION.md`](QUALIFICATION.md). Installed browser/mobile adoption and
artifact-authenticity evidence belongs to downstream products and does not
change this private ABI or any fixed availability gate.
