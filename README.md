# hns-wallet-rs

`hns-wallet-rs` is the independent Rust wallet boundary for the Handshake DANE
browser products. It owns encrypted local wallet state, a Handshake-first
wallet, the Handshake Provider API core, a release-gated fixed-price Shakedex
persistence boundary, chain-neutral market settlement, and deliberately narrow
Bitcoin and Ethereum modules.

The workspace does not combine the browser, node, or canonical protocol
repositories. It consumes one coherent published or reviewed immutable
protocol source and exposes a private,
length-prefixed wallet-service ABI, a fail-closed host-side protocol state
machine, and machine-readable contracts for separately released browser
adapters.

The checked-in service executable now requires an explicit existing wallet
database, opens it through the platform filesystem checks in a locked state,
and shares one decrypted-key authority between runtime control and encrypted
provider permissions. Linux, Android, and iOS persistent paths are eligible
in source only through a process-owned `0700` directory and a regular,
single-link `0600` database. Creation requires an absent path and atomically
precreates that file before SQLite opens it without create permission. The
selected entries may not be symlinks, and the file identity is checked around
SQLite's no-follow open. This repository's portable filesystem regressions run
on Linux; downstream mobile products own their target/runtime evidence, app
sandbox, ACL and data-protection policy, backup exclusion, and
Keystore/Keychain wrapping. The downstream Android/iOS 0.5.9 candidate source
now contains platform key wrapping, JNI/C projection, native recovery and read
screens, and off-UI-thread synchronization call sites; those separately
maintained implementations are not package or installed-device evidence for
this repository. A platform-neutral native controller creates or restores
exactly one non-value HNS account, opens only a complete seed/account bootstrap,
and exposes status, unlock, lock, and account identity through a private ABI-v2
session. A separate backend-injected native read controller reuses that exact
shared-store authority and returns one bounded serializable balance/receive/
history/known-name/module-status snapshot. That trusted-native snapshot now
contains both the ordinary HNS coin `ReceiveTarget` and a structurally distinct
`HnsNameReceiveTarget`, derived only from `HnsName`, change zero, at the exact
post-scan `next_name_index`. The mobile facade exposes the latter through a
freshly synchronized `name_receive_target()` call and the serialized
`nameReceiveTarget` field. The same trusted-native controller now accepts one
canonical HNS name through `import_name_exact_text()`. It passes UTF-8 bytes
through unchanged, rejects trimming/case/IDNA/Unicode/dot transformations
before node I/O, and atomically commits fresh canonical evidence with any
exact wallet `HnsName` derivation high-water rotation. The native persisted-name
bound is checked before evidence lookup, and the result is the same minimized
name summary rather than proof, owner, resource, or derivation material. It
does not add that target or import to website/provider JSON
or change any provider, signing, value, settlement, or marketplace capability.
It obtains the durable epoch and exact tip through a script-free chain snapshot,
binds height-zero evidence to the selected account network, and only then
derives and queries wallet ScriptIds. The mobile crate re-exports the concrete
authenticated loopback adapter for downstream native composition, but it does
not supply production device transport. Fresh history also needs archive raw
transactions unless the authenticated wallet already cached them. A
deadline-enforced, archive-capable (or durably indexed) device backend,
backend credential/index provisioning, and installed-device network/resource/
restart qualification therefore remain downstream release requirements rather
than authorities supplied by this crate. Native HNS value and Shakedex source
gates are enabled; no browser/provider value release path is implied.

ABI wallet status/unlock/lock and a narrow provider
control surface are implemented. One library composition can bind an exact
pre-existing HNS account selector to that identical shared authority and add
`hns_requestAccounts`/`hns_accounts`. A second library composition adds live,
account-scoped `hns_getBalance`, `hns_getTransactions`,
`hns_getReceiveAddress`, `hns_getNames`, and `hns_getName` reads through the
real HNS backend and encrypted wallet state. It authenticates the selected
account around each bounded reconciliation, retains one exact chain/mempool
binding internally, performs no node I/O while a `SharedWalletStore` closure is
active, and commits only across exact account/entity revision fences. The
service crate also provides one concrete native-launcher constructor which
wires that same composition to the authenticated loopback RPC backend, the
production wall clock, and the literal shared store authority. It adds no CLI
configuration, artifact trust, browser-engine authority, or availability gate.
An inert provisioning API can now persist one wallet-owned native-read profile
as an encrypted CAS record. It binds the exact sole non-value HNS account and
literal loopback endpoint to a zeroizing/redacted node Authorization value and
a bounded label. Persisted Authorization rejects JSON escape bytes so parsing
cannot create an unowned plaintext scratch copy. Provisioning and every load
require unlock, re-authenticate that sole account, and require its complete
singleton recovery-seed bootstrap.
The ordinary profile-backed read service now also implements the exact
native-only `hnsWalletAuthorityContextV1` contract already consumed by the
Chromium host candidate. It keeps that request outside the frozen six-read
enum, validates the account's canonical network/magic, and returns the active
wallet/account with authenticated profile and account-row revisions. Opaque
namespace and lease-generation fields are only echoed evidence for a native
caller that already holds the matching HRM/HNSA broker guard; they confer no
authority by themselves and never enter provider/page JSON. Generic, simnet,
recovery-only, and checked-in executable compositions do not advertise the
marker. A real exclusive namespace/database broker and supervised launch path
are still required.
Revocation replaces the secret-bearing record with a persistent tombstone, so
later re-provisioning continues the revision/update-time high-water. The
checked-in executable does not consume the profile, and rotation/revocation
does not claim to stop an
already-running process; trusted unlock transport, profile-revision admission,
exclusive database ownership, operation-level read qualification, and signed
browser artifact admission remain required before browser use. Tombstoning is
not secure erasure from SQLite WALs or backups; node-side credential rotation
remains required.
The approval-schema-v3 Names prompt carried by private ABI v2 contains the exact
sorted canonical name/lowercase-hash set it may grant. The service freezes that
bounded set before prompting, re-synchronizes at approval, rejects any account
or set change, and persists only the unchanged displayed hashes. This
approval-v3 shape is incompatible with consumers that omit or do not understand
`hnsNames`; browser adapters must negotiate, adopt, and render it exactly before
provider Names access is available. The native read controller is a distinct
trusted-app surface: exact-text import exists only as a direct Rust native API,
is serialized with synchronization, and exposes no provider authority. The
checked-in executable still has
no account-selection or backend inputs, so it remains the control-only runtime.
The native controllers are library-only compositions. Downstream mobile
candidate wrappers do not supply a production wallet-index backend or make the
browser/provider integration and value paths available here.
The separately maintained `hns-dane-browser-mobile` consumer currently pins an
older wallet source and therefore does not yet consume this producer shape. It
must coordinate an HNS Wallet Read v2 (HNWR-v2) dependency, binding,
serialization, and trusted-UI adoption before presenting `nameReceiveTarget`;
the producer source may land first, but that does not make the pinned consumer
compatible or available.

Current safety status: the production-hardening source boundary is implemented.
Native HNS send, settlement, and Shakedex paths are source-enabled but require
the exact authenticated runtime evidence and account configuration recorded in
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) and
[`docs/QUALIFICATION.md`](docs/QUALIFICATION.md). Bitcoin and Ethereum value
operations remain disabled by their own source gates. Test success is never a
mainnet authorization signal. HNS name-role keys are scanned and persisted separately,
and the protected `HnsShakedex` allocation high-water feeds an independent
32-byte lock-script restore scan. A durable scan fence and atomic account/key
CAS prevent another process from allocating through an incomplete mnemonic
scan. Canonical payment, price, deadline, and fee terms are recomputed before
the redacted purpose-bound signer can authorize a seller object. The node
snapshot now includes HSD-compatible
median time past, allowing non-serializable current/unspent Shakedex lock and
TRANSFER authorities without caller-asserted chain time. These source
boundaries do not change any release gate. The wallet now decodes canonical
NameState/resource bytes, verifies every
node projection and exact owner output, and binds current control only to a
persisted `HnsName` derivation. TRANSFER owners must also bind the canonical
transfer height to the active-chain owner-transaction inclusion height.
Persisted name status is never action authority: value workflows must reacquire
an ephemeral exact-snapshot proof. The wallet source implements release-gated,
wallet-owned P2PKH TRANSFER and old-owner direct FINALIZE workflows with
canonical index-zero construction, typed name/fee reservations, single-use
approval, ordered signing, exact final-byte fee quoting, durable rebroadcast,
maturity tracking, and reorg recovery. They remain unavailable through the
browser/provider surface because provider integration and product qualification
are incomplete; the HNS value and fee source gates themselves are enabled.

The encrypted Shakedex value aggregate also has a source-level
seller-script-FINALIZE variant. It binds an exact signed buyer-fulfillment or
seller-recovery parent, the canonical TRANSFER transaction/output-zero coin,
current NameState and owner inclusion, historical snapshot/mempool evidence,
and exact renewal evidence,
purpose-separated funding reservations, revision-bound approval, signed bytes,
final quote, pre-broadcast fence, and the existing terminal-release audit
state. Save, signing, and submission reacquire the non-serializable current
TRANSFER authority; a harmless live binding advance is accepted only when the
stable transfer/owner/state/renewal identity is unchanged, while the HNS
runtime requires exact bindings within each immediate live fence. Persisted
evidence never recreates authority. Shakedex and dependent HNS
funding/value/fee source gates are enabled. Exact qualified implementation source
`2229be849557d58a8eb723bcc03349f0f2df9796` passed its complete
[CI](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420628974),
[CodeQL](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420627924),
and
[14-crate normalized release preflight](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31424201574)
on 2026-08-10. The earlier exact implementation commit
`ba9f013a098679fe8e3d812a7e09020803e27d53` remains a historical CI/CodeQL
baseline. Exact historical qualified implementation source
`bc5901f794450d29fa9f5630bab4fbf91e37bedf` passed complete locked
[CI](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31812028843),
including Wallet qualification and RustSec, and
[CodeQL](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31812028405)
for Actions, JavaScript/TypeScript, Rust, and Python on 2026-08-14. That
evidence qualifies the wallet source with its current dependency pin,
name-target, and trusted-name-import tranche. These source results include the
synchronized account-read,
script-free initial binding, and purpose-separation regressions but are not
product, regtest, installed-device, resource, or release-gate qualification; see
[`docs/QUALIFICATION.md`](docs/QUALIFICATION.md).

Bitcoin BDK state now uses the same encrypted shared SQLite authority as the
wallet journal instead of BDK's independent rusqlite feature. Its strict
aggregate snapshot is CAS-protected and ordered before reconciliation/ready,
but is limited to 1 MiB; a normalized or authenticated chunked backend and an
explicit legacy-BDK-SQLite importer remain release blockers. The Bitcoin value
gate stays false.

## Crates

- `hns-wallet-types`: wallet-local identifiers and UI-safe summaries, including
  structurally distinct ordinary-coin and Handshake name receive targets.
- `hns-wallet-store`: SQLite migrations, authenticated encryption, and one
  cloneable process-local lock/key authority.
- `hns-wallet-chain-api`: modular chain and settlement capability traits.
- `hns-wallet-hns`: Handshake account/name workflows, exact synchronized coin
  and name receive-target derivation, and node backend.
- `hns-wallet-provider`: hostile-page request, permission, and approval core.
- `hns-wallet-shakedex`: release-gated persisted seller/buyer/recovery and
  post-TRANSFER script-FINALIZE schemas.
- `hns-wallet-market`: encrypted fixed-terms HNS/BTC direct offers,
  cancellations, durable accepted-session admission, and atomic-swap recovery.
- `hns-wallet-mobile`: platform-neutral, single-account Android/iOS lifecycle
  controller plus an injected, synchronized, minimized HNS read composition
  with distinct coin and name receive projections; no concrete device backend
  or value/provider surface, and downstream HNWR-v2 adoption remains required.
- `hns-wallet-bitcoin-kyoto`: BDK/Kyoto wallet, encrypted session-bound swap-key allocation primitive, and Bitcoin HTLC adapter.
- `hns-wallet-ethereum`: offline native-ETH account derivation plus
  release-gated Helios/HTLC policy.
- `hns-wallet-ffi`: ABI v2 framing, canonical service IDs, approval prompts, and events.
- `hns-wallet-service`: private session/authority registry plus locked,
  existing-database control, exact-account read/value, and wallet-peer
  Shakedex library compositions. Trusted-native value actions stay closed and
  process-local; website-provider projection remains limited to the ordinary
  coin receive target.
- `hns-wallet-host`: caller-side negotiation, correlation, authority, approval,
  binding, and event-replay state for trusted browser/mobile adapters.
- `hns-wallet-testkit`: deterministic, non-mainnet fixtures.

Run `scripts/check.sh` once for the complete local qualification gate.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Provider API](docs/PROVIDER_API.md)
- [Persistence and recovery](docs/PERSISTENCE_AND_RECOVERY.md)
- [Handshake node RPC adapter](docs/HNS_NODE_RPC.md)
- [Bitcoin Kyoto-only module](docs/BITCOIN_KYOTO.md)
- [Ethereum model and contract](docs/ETHEREUM.md)
- [Shakedex and market state](docs/SHAKEDEX_AND_MARKET.md)
- [Wallet service ABI v2](docs/ABI.md)
- [ABI schemas and bounded vectors](abi/)
- [Qualification matrix](docs/QUALIFICATION.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Future work and excluded features](FUTURE_WORK.md)
- [Release procedure](docs/releasing.md)
