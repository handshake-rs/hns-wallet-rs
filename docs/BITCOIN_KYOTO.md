# Bitcoin: Kyoto only

Bitcoin has one synchronization implementation: direct P2P with `bip157`
0.6.3 and `bdk_kyoto` 0.17.0, feeding a BIP84 `bdk_wallet` 3.1.0 wallet.
There is no Esplora, Electrum, hosted indexer, or Bitcoin Core RPC production
mode. Bitcoin Core regtest is only a deterministic qualification fixture.

## Implemented source boundary

The bounded supervisor now owns these transitions:

- a header/filter discovery client starts from an explicit trusted checkpoint
  and waits under a configured deadline for Kyoto's `FiltersSynced` event;
- a new wallet accepts only that validated current tip as its birthday and
  separately retains the non-genesis trusted discovery anchor plus bounded
  validated history as its recovery checkpoint set, so recovery neither reuses
  an orphaned tip nor silently falls back to genesis;
- restores accept a known checkpoint or genesis. A date-based restore requires
  a checkpoint which the already-synced Kyoto chain proves canonical and whose
  header timestamp precedes the source date by a bounded safety window; the
  wallet does not guess a height from wall-clock time;
- the encrypted scan record uses CAS revisions and explicit starting,
  synchronizing, reconciling, ready, and recovery-required phases;
- one filter subscriber checks both BDK descriptor scripts and every active
  native HTLC script. A matching block is downloaded once, applied to the BDK
  graph when relevant, and separately admitted to the swap watcher only when
  its merkle root and exact block hash match Kyoto's locally validated header
  chain;
- encrypted per-session HTLC watches discover exact funding outpoints and
  exact signed redeem/refund spends directly from those blocks. Funding and
  spend confirmations follow the canonical checkpoint and roll back on a
  reorganization. A revealed preimage is retained monotonically because an
  orphaned publication cannot make a disclosed secret private again;
- matched swap evidence is committed before the BDK checkpoint advances, then
  each Kyoto update is applied and committed as a strict BDK changeset
  snapshot before bounded transaction/output mirrors are reconciled in
  encrypted 512-record chunks; the ready checkpoint is committed last. This
  ordering makes a crash during a long offline catch-up rescan from the older
  wallet checkpoint instead of skipping a matched HTLC block;
- exact block-hash membership queries locate a retained common ancestor. A
  reorg deeper than the bounded 32-checkpoint recovery window fails closed and
  requires a recovery-anchor scan;
- sync, requester, discovery, fee, peer, and broadcast waits have configured
  deadlines. Timing out Kyoto's non-cancel-safe update poisons that supervisor,
  shuts its node down, records recovery-required state, and requires a fresh
  instance; and
- relevant transaction and wallet-output records have 4,096-record lifetime
  caps. Canonically absent records are retained for reorg evidence. Safe
  archival/pruning is not implemented, so reaching either cap fails closed.

The supervisor returns Kyoto log receivers to the application; a product must
drain them and must not treat informational progress or peer messages as chain
authority.

Initial tip discovery is bounded too. If its sync deadline expires, discovery
shuts down its Kyoto node and poisons itself; callers must create a new
discovery instance rather than continue using a possibly active timed-out
operation.

## Persistence ownership and pinned limitation

One protected `bitcoin_wallet_state` entity durably owns BDK's public
descriptors, revealed derivations, local-chain checkpoints, relevant
transactions, and wallet outputs. Its strict envelope is format v1, uses the
exact wallet account ID as authenticated associated data, records the exact BDK
3.1.0 serialization contract, and is updated by CAS. Private descriptor keys
are reconstructed from the protected mnemonic and are not serialized in that
record. The same
`SharedWalletStore` authority owns birthday, supervisor sequence/phase, last
consistent checkpoint, the distinct recovery checkpoint, bounded recent
checkpoints, transaction/output reconciliation records, and broadcast intents.
It also owns the bounded, account-bound HTLC watch set. Swap evidence, the BDK
snapshot, and the scan journal are deliberately ordered transactions, not one
falsely atomic transaction.

This first backend stores one aggregate changeset and therefore inherits the
encrypted entity cleartext limit of 1 MiB. BDK's persistent script cache is
disabled to avoid needless growth, but transaction and derivation history can
still reach the limit. Capacity exhaustion fails closed. A normalized or
authenticated chunked BDK backend would raise the current capacity ceiling.
Until then, exhaustion rejects the operation rather than authorizing a partial
wallet view.

The former standalone BDK SQLite backend is not imported, opened, truncated,
or deleted. There is no migration tool in this revision. An upgraded product
which has such a database must retain it and stop for an explicit future import
instead of treating `WalletNotFound` as permission to create replacement state.

`bip157` 0.6.3 accepts `data_dir`, but this pinned release discards the field in
`Node::new`; it does not persist a full header/filter database or its address
book. The wallet does not require a pruned or indexed Bitcoin node: its
encrypted BDK checkpoint and recovery journal are the durable authority, and
Kyoto re-fetches and revalidates the required headers and compact filters from
ordinary untrusted Bitcoin peers after restart. Full header/filter persistence
would improve startup cost, but is not a separate product authority or a
prerequisite for the light-wallet model.

## Broadcast boundary and release gate

A signed descriptor-wallet transaction is accepted for journaling only when
BDK can resolve every input as owned and unspent, calculate its exact fee, and
prove the fee does not exceed the approved maximum. A native HTLC spend has a
separate admission path which re-verifies the exact funding outpoint, branch,
preimage or timelock, fee, witness script, signer key, signature, and
`SIGHASH_ALL`. Both paths bind network magic, txid, wtxid, exact fee, fee
maximum, and expiry, and persist the complete raw transaction and approval
before `submission_started`.

Only a durable ready checkpoint, a running Kyoto node, and the configured peer
quorum can reach `submit_package`. Expiry is exclusive: a request at the expiry
second is rejected. Submission has a bounded timeout. A timeout leaves
`submission_started` durable for an idempotent retry after the same bounded
rebroadcast interval used by a known submission; successful return must contain
the expected wtxid before `submitted` is committed.

The broadcast journal rejects time earlier than its durable preparation or
latest-attempt timestamp. This prevents a backward wall-clock jump from
silently extending approval or retry windows, but a qualified product still
needs a reviewed trusted-time/monotonic-clock policy.

`BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` is enabled for the connected mobile
path. Capability discovery advertises send and atomic settlement, but signing
and broadcast still require the private permit obtained by that trusted Rust
controller. Platform callers receive only bounded approval projections and
process-local action tokens.

## Atomic-swap key derivation

Ordinary receive/change keys remain in BDK's BIP84 descriptor trees. Atomic-
swap keys never enter those trees and do not claim a standardized BIP-32 path.
They use HKDF-SHA256 over the wallet profile's 64-byte BIP-39 recovery seed
(the same empty BIP-39 passphrase policy used by this wallet's BIP84 setup),
with the exact ASCII salt:

```text
hns-wallet-rs/bitcoin-atomic-swap-key/v1
```

The 25-byte HKDF info is `HSWP || coin_type || network_code || account || role
|| index || counter`. Each numeric field except the final counter is a big-
endian `u32`; the counter is one byte and advances from 0 through 255 only if
the candidate is not a valid secp256k1 scalar. The first valid candidate wins.
Role 0 is the receiver/redeem branch and role 1 is the refund-owner branch.
Both account and key index are accepted only in the inclusive range
0..=100,000.

| Bitcoin network | coin type | network code |
| --- | ---: | ---: |
| mainnet | 0 | 0 |
| testnet3 | 1 | 1 |
| testnet4 | 1 | 2 |
| signet | 1 | 3 |
| regtest | 1 | 4 |

The coin-type field mirrors the ordinary wallet's main/test split, while the
separate network code prevents testnet, testnet4, signet, and regtest from
sharing swap keys. This application-private HKDF scheme is disjoint from BIP84
at the KDF boundary rather than relying on an unregistered BIP purpose number.

Crate-local context-free regression vectors below were calculated from the BIP-39 English
`abandon` eleven times followed by `about` mnemonic, its empty-passphrase
64-byte seed, and the exact salt/info encoding above. They are embedded as
source conformance assertions; no private material is recorded. These are not
outputs of the durable allocation API:

| Reference | compressed public key |
| --- | --- |
| mainnet, receiver, account 0, index 0 | `025e70317534f24fafdbcbd0f8524967de9a5c6f6dc9655872ddb6adba94174bff` |
| mainnet, refund owner, account 0, index 0 | `03a5f831491d756b0429dbe97b54280091883d16b0a9f79b74e220dfafe823f7af` |
| regtest, receiver, account 0, index 0 | `02de93cfd4281366f4308cc0ed7df6753c2bb3bd3e9ef32cc2e22c28f9745277b3` |

The in-memory handle exposes only its role-bound public half, redacts its secret
in `Debug`, cannot be serialized or cloned, and zeroizes its 32-byte secret on
drop. The serializable numeric reference is only one component of a complete
allocation; wallet, session, and terms bindings are also required for recovery.
Raw context-free derivation is crate-private. The role-aware HTLC constructor
requires the non-serializable derived handle and can place its public key only
in its declared receiver or refund position. The reference binds scheme
version 1 and rejects other versions.

The durable allocation KDF uses its own salt and the fixed-width info sequence
`HSAK || wallet_id || session_id || terms_commitment || scheme_version ||
coin_type || network_code || account || role || index || counter`. The wallet ID
is 16 bytes, session and terms commitments are 32 bytes each, the scheme version
is an unsigned big-endian `u16`, the remaining integers are unsigned big-endian
`u32`, and the rejection counter is one byte. This prevents the same seed and
numeric index in a copied or stale profile from producing the same key for a
different wallet, session, or terms commitment.

The same mnemonic used by the crate-local vectors pins the durable HSAK byte
contract to this exact allocation vector:

| wallet ID | session ID | terms commitment | reference | compressed public key |
| --- | --- | --- | --- | --- |
| `01` repeated 16 bytes | `02` repeated 32 bytes | `03` repeated 32 bytes | regtest, receiver, account 7, index 0, scheme 1 | `03c93cca65310a3c421ab09761fa9ce7ffeae7aa17f3f0974a48536c3ec1d51d9d` |

The allocation primitive requires a nonzero opaque terms commitment and
durably allocates each receiver/refund role. Its caller remains responsible for
hashing the complete canonical settlement terms and invoking allocation before
an irreversible action. The encrypted store commits a namespace anchor,
monotonic high-water counter, immutable wallet/session/role binding, and binding
claim in one CAS batch. The binding contains the scheme version, exact
reference, compressed public key, seed commitment, terms commitment, and
allocation time; it never contains seed or scalar bytes. Same-session exact-
term retries are idempotent. Rebinding, counter rollback/wrap, a backward clock,
corrupt variants, and a second CAS conflict fail closed. Recovery validates all
four records, the immutable seed commitment, and the re-derived public key
before returning the zeroizing secret handle.

Recovery-seed insertion is idempotent only for identical bytes; replacement or
generic deletion fails closed. Allocation rows are also protected from generic
single or batch deletion. These controls detect isolated mutation, not a whole
database snapshot rollback. Session IDs must never be recycled, and recovering
an already active allocation requires its current encrypted database records.

The allocator, exact signed-spend verifier, durable broadcast journal, and
canonical compact-filter HTLC watcher are wired together by the mobile
cross-chain coordinator. The signing/value permit remains private to Rust;
neither peer messages nor platform input can construct it.

## HTLC profile

The native settlement template is P2WSH:

```text
IF SHA256 <hashlock> EQUALVERIFY <receiver-key> CHECKSIG
ELSE <refund-absolute-locktime> CLTV DROP <refund-key> CHECKSIG ENDIF
```

Funding verification reconstructs the exact script, checks value, a unique
matching output, transaction bounds, and confirmation minimum. The refund
locktime is the Bitcoin consensus `nLockTime` value: a height below
500,000,000 or a Unix timestamp at/above that threshold. Redeem/refund
templates enforce the branch, hashlock, dust, fee, and exact locktime. Refund
eligibility comes from the wallet's Kyoto-validated next-block height and
median-time-past over the canonical header chain; it never estimates a height
from wall time or accepts a Shakescape peer's timing claim. Preimage observation
requires the expected outpoint and exact witness script. The local signer is
bound to its HTLC script position and signs an exact spend template; the
chain-neutral session signer can be used by both native adapters without
exporting a private scalar. The combined Kyoto subscriber watches the script
itself, so neither a Shakescape peer nor the counterparty supplies chain authority
or block locations. The mobile cross-chain coordinator binds these primitives
to the signed bilateral session, ordered funding, explicit approvals, durable
state, and independently verified spend observations.

## Qualification and benchmarks

On 2026-08-03, the targeted allocation filter passed from a disposable NVMe
checkout and NVMe target directory: `cargo test --locked -p
hns-wallet-bitcoin-kyoto swap_key_store::tests -- --test-threads=1` reported 10
passed, 0 failed, and 8 filtered out. No standalone build/check, full workspace
gate, optimized RocksDB compilation, network test, or benchmark was run in that
historical event. The allocation, encrypted BDK persistence, and ahead-tip
crash regressions are now also covered by exact `2229be8` complete workspace CI.
Those historical results predate the connected value-runtime candidate and do
not qualify the current source revision.

| Scenario | Disk | Bandwidth | Usable balance | Full scan | Peak mobile memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fresh install | not measured | not measured | not measured | not measured | not measured |
| New wallet | not measured | not measured | not measured | not measured | not measured |
| One-year restore | not measured | not measured | not measured | not measured | not measured |
| Five-year restore | not measured | not measured | not measured | not measured | not measured |
| Genesis restore | not measured | not measured | not measured | not measured | not measured |

Bitcoin send and settlement are available through the connected trusted mobile
controller. Full header/filter database persistence remains an optimization,
not a requirement for wallet-owned light-client authority. Installed-product,
resource, and live-network results must still be recorded separately from
source-level qualification.
