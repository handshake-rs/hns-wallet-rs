# Qualification

Qualify the exact source commit being delivered. A test, package archive,
registry entry, or successful workflow does not independently authorize a
wallet operation. Runtime evidence and native approval remain mandatory.

## Source checks

Use Rust 1.89.0 with the committed lockfile:

```sh
cargo +1.89.0 fmt --all --check
cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.89.0 test --workspace --all-targets --locked
./scripts/check.sh
```

The complete gate includes release metadata, argument validation, ABI
contracts and vectors, deterministic contract artifacts, and package inventory.
For publication, run the selected normalized package preflight described in
[releasing.md](releasing.md). CI, security review, and preflight must qualify
the same immutable source commit.

## Runtime qualification

| Boundary | Required checks |
| --- | --- |
| Encrypted store | Atomic bootstrap, authenticated schema and CAS, restart, rollback, lock authority, private filesystem policy, and platform key wrapping |
| HNS scan | Multi-peer header agreement, Merkle and Urkel verification, saved scan resume, watch-set expansion, reorg, stale evidence, and peer replacement |
| Names and sends | Exact selected account and network, active Coin and covenant, fees from final bytes, approval fences, persist-before-broadcast, and mempool conflicts |
| Provider | Exact origin and generation, bounded vocabulary and consent, revocation, replay, and unavailable-method rejection |
| ShakeDex and market | Signed terms and exact reservations, bilateral identity, funding and settlement evidence, cancellation, restart, refunds, and terminal-release safety |
| Bitcoin Kyoto | Compact-filter scans, encrypted BDK state, recovery-start selection, approved sends, bilateral HTLCs, reorg, and conflicting-input exclusion |
| Ethereum | Offline derivation and deterministic contract checks; synchronization, value, and settlement remain unavailable |
| ABI and hosts | Closed schemas, bounded frames, panic containment, allocator pairing, stale handles, and process lifecycle |
| Mobile | Android and iOS source gates, signed artifacts, installed-device restart and scan resume, current UI, and native review |

Do not reset a wallet or erase device diagnostics to make qualification pass.
Capture existing logs before filtering them. Verify on-device behavior against
its exact binary and source identity. Simulator and host tests do not establish
physical-device behavior or store acceptance.

## Capability gates

Inspect the immutable source gates and authenticated runtime configuration
before declaring a capability available. HNS value and fees require their
native account, current verified evidence, and approval paths. Bitcoin send
and settlement require the trusted-mobile Kyoto permit. Website-provider
wallet/value exposure is unavailable. Ethereum synchronization, history,
signing, value, settlement, and chain ID 1 remain unavailable.
