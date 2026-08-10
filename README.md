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
Keystore/Keychain wrapping. A platform-neutral native controller now
creates or restores exactly one non-value HNS account, opens only a complete
seed/account bootstrap, and exposes status, unlock, lock, and account identity
through a private ABI-v2 session. A separate backend-injected native read
controller can now reuse that exact shared-store authority and return one
bounded serializable balance/receive/history/known-name/module-status snapshot.
It includes no concrete mobile backend. The current epoch protocol delivers
derived watch ScriptIds before the selected-network genesis check, and fresh
history needs archive raw transactions unless the authenticated wallet already
cached them. A trusted local, deadline-enforced, archive-capable (or durably
indexed) device backend, platform bindings, native product screens, and
installed-device qualification therefore remain downstream release
requirements rather than authorities supplied by this crate, and no
value/provider release gate is enabled.

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
approval-schema-v3 Names prompt carried by private ABI v2 contains the exact
sorted canonical name/lowercase-hash set it may grant. The service freezes that
bounded set before prompting, re-synchronizes at approval, rejects any account
or set change, and persists only the unchanged displayed hashes. This
approval-v3 shape is incompatible with consumers that omit or do not understand
`hnsNames`; browser adapters must negotiate, adopt, and render it exactly before
provider Names access is available. The native read controller is a distinct
trusted-app surface: it minimizes only already-persisted known names and exposes
no provider authority or name-import path. The checked-in executable still has
no account-selection or backend inputs, so it remains the control-only runtime.
The native controllers are library-only compositions; a production mobile
wallet-index backend, shipped bindings, browser integration, and every value
path remain unavailable here.

Current safety status: the production-hardening source boundary is implemented,
but executable HNS, Bitcoin, and Ethereum value operations and all mainnet
settlement remain release-gated. The HNS runtime rejects configurations that
enable send or settlement, and the Bitcoin and Ethereum modules cannot issue
their value permits, until the adapter-qualification and persistence gates
recorded in [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) and
[`docs/QUALIFICATION.md`](docs/QUALIFICATION.md) are complete. Test success is
never a mainnet authorization signal. Shakedex creation, discovery, and state
transitions are likewise fail-closed behind canonical V2, Denuo V2, and value
runtime release gates. HNS name-role keys are scanned and persisted separately,
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
product while the HNS value/fee gates are false and provider integration and
qualification are incomplete.

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
evidence never recreates authority. Every Shakedex and dependent HNS
funding/value/fee gate remains `false`. The exact implementation predecessor
`ba9f013a098679fe8e3d812a7e09020803e27d53` passed the complete CI and CodeQL
workflows on 2026-08-10. That source evidence includes the synchronized account
read and purpose-separation regressions but is not product, regtest, resource,
or release-gate qualification. Release-source evidence is commit-scoped: the
routine CI, CodeQL, and manual preflight records attached to one exact release
commit are authoritative, while this historical result is retained as a
baseline; see
[`docs/QUALIFICATION.md`](docs/QUALIFICATION.md).

Bitcoin BDK state now uses the same encrypted shared SQLite authority as the
wallet journal instead of BDK's independent rusqlite feature. Its strict
aggregate snapshot is CAS-protected and ordered before reconciliation/ready,
but is limited to 1 MiB; a normalized or authenticated chunked backend and an
explicit legacy-BDK-SQLite importer remain release blockers. The Bitcoin value
gate stays false.

## Crates

- `hns-wallet-types`: wallet-local identifiers and UI-safe summaries.
- `hns-wallet-store`: SQLite migrations, authenticated encryption, and one
  cloneable process-local lock/key authority.
- `hns-wallet-chain-api`: modular chain and settlement capability traits.
- `hns-wallet-hns`: Handshake account/name workflows and node backend.
- `hns-wallet-provider`: hostile-page request, permission, and approval core.
- `hns-wallet-shakedex`: release-gated persisted seller/buyer/recovery and
  post-TRANSFER script-FINALIZE schemas.
- `hns-wallet-market`: price-bound reservations and atomic-swap recovery.
- `hns-wallet-mobile`: platform-neutral, single-account Android/iOS lifecycle
  controller plus an injected, synchronized, minimized HNS read composition;
  no concrete device backend or value/provider surface.
- `hns-wallet-bitcoin-kyoto`: BDK/Kyoto wallet, encrypted session-bound swap-key allocation primitive, and Bitcoin HTLC adapter.
- `hns-wallet-ethereum`: offline native-ETH account derivation plus
  release-gated Helios/HTLC policy.
- `hns-wallet-ffi`: ABI v2 framing, canonical service IDs, approval prompts, and events.
- `hns-wallet-service`: private session/authority registry plus locked,
  existing-database control, exact-account, and synchronized non-value HNS read
  library compositions.
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
