# hns-wallet-rs

`hns-wallet-rs` is the self-custodial Rust wallet boundary used by the native
ShakeScape applications. It owns encrypted wallet state, Handshake and Bitcoin
wallet workflows, name operations, direct ShakeDex offers, atomic-swap state,
and the private native ABI used by Android and Apple.

The wallet is deliberately separate from the browser and full-node
repositories. Website content cannot call native value operations or acquire
wallet keys. Platform applications supply user authorization, protected
storage, networking, background execution, and UI; this workspace supplies the
state machines and fail-closed authority checks beneath those integrations.

## Implemented capabilities

- Encrypted SQLite wallet state with one process-local lock and key authority.
- BIP39 account creation and restoration with bounded derivation state. New
  HNS payment accounts use the hsd/Bob-compatible BIP-44 path
  `m/44'/5353'/0'/change/index`; existing role-HKDF wallets retain their
  immutable legacy scheme and have an explicit legacy restore path.
- Direct Handshake header, peer, coin, transaction, name-state, and proof
  synchronization.
- HNS balance, payment receive, name receive, history, and tracked-name
  projections.
- HNS send, TRANSFER, FINALIZE, resource update, renewal, and name-market
  transaction preparation with exact approval and rebroadcast recovery.
- Automatic tracking and preparation of a required name FINALIZE after the
  transfer maturity window.
- Bitcoin BDK/Kyoto synchronization, compact-filter scanning, receive/send,
  transaction history, and durable broadcast recovery.
- Signed direct HNS/BTC and BTC/HNS offers, cancellations, takes, bilateral
  session negotiation, funding watches, redeem/refund recovery, and explicit
  reservation accounting.
- Direct ShakeScape peer/listener lifecycle and standard Handshake address
  discovery events for native mobile integration.
- A versioned private wallet-service ABI and host-side correlation state.
- A separately gated Handshake Provider API core for account and read
  permissions. Native wallet capability does not imply website-provider value
  capability.

Ethereum account derivation exists as a narrow experimental module, but
Ethereum synchronization, signing, value transfer, and settlement remain
disabled.

## Security and authority model

Persistent records are evidence, not transaction authority. Any value action
must reacquire current chain, wallet, coin, name, fee, and reservation state
immediately before approval and signing:

```text
authenticated synchronized snapshot
                │
                ▼
 exact coins, names, watches, and reservations
                │
                ▼
      bounded user review and approval
                │
                ▼
    purpose-bound signing authorization
                │
                ▼
 durable pre-broadcast record and submission
                │
                ▼
 confirmation, reorg, retry, or refund recovery
```

The implementation rejects stale account revisions, changed transaction
terms, mismatched networks, incomplete peer negotiation, expired offers,
uncorrelated session messages, duplicate reservations, and persisted evidence
that cannot be revalidated against current state.

Wallet databases must live in an application-owned protected directory. On
supported Unix hosts the service requires a regular, single-link `0600` file
inside a process-owned `0700` directory and rejects symlinks. Android and Apple
hosts additionally own sandboxing, Keystore/Keychain wrapping, data-protection
classes, backup exclusion, and lifecycle qualification.

## ShakeDex and atomic swaps

The direct market supports both directions:

- BTC offered for HNS;
- HNS offered for BTC.

Offer discovery and session messages are signed and bound to the exact
network, assets, amounts, deadlines, keys, and peer identities. A relay or
rendezvous node routes these messages but cannot sign for either wallet or
authorize settlement.

The swap lifecycle persists enough information to recover after peer loss,
screen lock, process restart, or an interrupted synchronization pass. Recovery
still depends on current verified HNS and Bitcoin evidence; a UI status or
relay acknowledgement is never treated as chain confirmation.

Wallet balances distinguish confirmed on-chain funds from amounts reserved by
active or unfunded swap commitments. Abandonment and signed cancellation
release only reservations that can be proven safe to release.

## Workspace crates

| Crate | Responsibility |
| --- | --- |
| `hns-wallet-types` | Wallet identifiers, amounts, receive targets, and UI-safe summaries |
| `hns-wallet-store` | Encrypted SQLite records, migrations, revisions, and shared lock authority |
| `hns-wallet-chain-api` | Typed chain, transaction, and settlement backend capabilities |
| `hns-wallet-hns` | Handshake accounts, synchronization, coins, names, and value actions |
| `hns-wallet-provider` | Hostile-page request, permission, and approval core |
| `hns-wallet-shakedex` | Handshake name-market seller, buyer, recovery, and FINALIZE state |
| `hns-wallet-market` | Direct HNS/BTC offers, sessions, reservations, and swap recovery |
| `hns-wallet-bitcoin-kyoto` | BDK/Kyoto wallet, compact-filter sync, Bitcoin HTLC, and broadcast recovery |
| `hns-wallet-ethereum` | Offline derivation and disabled-by-default Ethereum policy |
| `hns-wallet-ffi` | Private ABI v2 framing, schemas, prompts, results, and events |
| `hns-wallet-service` | Session/authority registry and native service compositions |
| `hns-wallet-host` | Caller correlation, lifecycle, approval, and event-replay state |
| `hns-wallet-mobile` | Platform-neutral Android/iOS wallet and direct-peer lifecycle |
| `hns-wallet-testkit` | Deterministic non-mainnet fixtures |

The dependency-ordered public list is maintained in
[`release/public-crates.txt`](release/public-crates.txt).

## Version and dependency policy

All sixteen wallet crates use one shared release version. The current source
prepares the `0.2.5` cohort for standards-compatible HNS derivation, legacy
recovery, and cross-purpose receive safety.

Protocol and light-client dependencies are exact-version, checksum-recorded
crates.io cohorts. Repository-local path patches may be used while coordinating
an adjacent release, but a wallet crate release is not permitted until its
tested protocol and engine dependencies have permanent registry artifacts with
matching source provenance. See [`docs/releasing.md`](docs/releasing.md).

## Build and qualification

The minimum supported compiler is Rust 1.89.0.

```sh
cargo +1.89.0 test --workspace --all-targets --locked
cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings
./scripts/check.sh
```

Release metadata and normalized archives are checked separately:

```sh
python3 scripts/verify-release.py --toolchain 1.89.0
./scripts/check-publish-arguments.sh
./scripts/publish.sh --archive-only
```

Passing source tests does not itself authorize a store release, mainnet value
operation, crates.io upload, or product feature gate. Android and iOS retain
their own build, installed-device, lifecycle, notification, accessibility,
and store-submission qualification.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Persistence and recovery](docs/PERSISTENCE_AND_RECOVERY.md)
- [Handshake node RPC adapter](docs/HNS_NODE_RPC.md)
- [Bitcoin Kyoto module](docs/BITCOIN_KYOTO.md)
- [ShakeDex and market state](docs/SHAKEDEX_AND_MARKET.md)
- [Provider API](docs/PROVIDER_API.md)
- [Wallet service ABI](docs/ABI.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Qualification matrix](docs/QUALIFICATION.md)
- [Release procedure](docs/releasing.md)

## License

The workspace is licensed under either Apache-2.0 or MIT, at your option. See
[`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
