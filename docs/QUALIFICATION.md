# Qualification matrix

Snapshot: 2026-08-10. This file records evidence, not intent. Unit coverage,
source packaging, or publication never authorizes mainnet value. Evidence is
attached to exact commits and is not inherited automatically by later source.

The complete CI run
[`31383987461`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987461)
and CodeQL run
[`31383987478`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987478)
both succeeded for exact implementation commit
`ba9f013a098679fe8e3d812a7e09020803e27d53` on 2026-08-10. Those runs include
the atomic native bootstrap, mobile controller, synchronized HNS reads,
approval-v3 provider framing, Shakedex purpose separation, encrypted BDK
persistence, and deterministic Ethereum contract checks present at that commit.

The release-tooling changes and final `hns-rs` release-candidate repin that
follow `ba9f013` require their own exact-commit CI and manual release preflight.
Predecessor success is implementation evidence only; it does not qualify the
current uncommitted or later release source.

| Area | Exact source evidence | Persistence/restart and reorg | Product/network evidence | Release status |
| --- | --- | --- | --- | --- |
| Types and chain traits | complete locked workspace CI passed at `ba9f013` | n/a | no product dependency | source-qualified predecessor; API review remains |
| Encrypted store/schema v3 | complete CI passed, including atomic bootstrap, rollback, migrations, encrypted CRUD/CAS, and Unix filesystem regressions | source reopen/restart tests; no Android/iOS secure-store runtime evidence | no device filesystem, Keystore, or Keychain qualification | platform qualification pending |
| HNS wallet and names | complete CI passed, including bootstrap, synchronized reads, purpose separation, name workflows, and fail-closed value gates | source restart/reorg paths; no multi-process regtest | node RPC source only; protocol repinned to immutable `hns-rs` `abf11ff` | HNS funding, value, and fee gates remain `false` |
| Provider core | complete CI passed, including account binding, scoped reads, exact Names consent, and unavailable-method ordering | grants persist; pending approval/UI authority remains process-local | no installed-browser consent or backend E2E | browser and value exposure unavailable |
| Fixed-price Shakedex | complete CI passed, including canonical listing, FINALIZE, reservation, terminal-release, and release-gate tests | source reopen/conflict/reorg/finality tests; no multi-process regtest | no live Denuo, provider, trusted UI, or product coin selection | every Shakedex and dependent HNS value gate remains `false` |
| Market sessions | complete workspace CI passed | CAS journal source; recovery evidence incomplete | no pair E2E, rendezvous, or relay transport | unavailable |
| Bitcoin Kyoto | complete CI passed, including encrypted BDK persistence and the ahead-tip crash edge | exact source restart resume; no multi-process rollback run | no regtest/P2P/broadcast run | send and settlement hard-disabled; normalized or chunked backend pending |
| Ethereum | complete CI and deterministic contract check passed | offline derivation and dormant primitives only | no embedded Helios/local-chain run; no contract audit | synchronization, history, send, signing, settlement, and mainnet unavailable |
| ABI, service, and host | complete CI passed, including canonical camel-case frames, approval-v3, session handling, and host retention | private process session/authority state; no installed restart E2E | downstream browser/mobile adoption and rendering pending | private control only; browser/value unavailable |
| Mobile controller | Android create and iOS open/restore simulations passed in workspace CI | atomic seed/account bootstrap and reopen tests; platform key stores are downstream | JNI/Swift product integration and installed-device qualification are downstream | native non-value controls only; provider/value/market unavailable |
| Browser products | separate repositories | platform integration pending | no installed/signed E2E | unavailable |

CodeQL passed at `ba9f013`, but no independent security audit, database or
resource benchmark, multi-process network test, installed-device run, or
installed-browser run is recorded for this package release candidate.

## Qualification commands

The routine workspace gate is:

```bash
./scripts/check.sh
```

It performs release metadata and archive-inventory validation, formatting, a
locked all-target check, warning-denied Clippy, tests, warning-denied docs,
dependency/source-policy checks, deterministic Solidity artifact comparison,
and the npm high-severity audit. Its archive pass uses `cargo package
--no-verify`; it does not repeat package compilation.

The 14 real normalized `cargo publish --dry-run` checks are intentionally
separate. After routine CI succeeds for the exact candidate, manually dispatch
`.github/workflows/release-preflight.yml` with that qualified 40-character SHA
as `expected_commit`. The workflow verifies the exact checkout, has no
publication credentials, and cannot execute an upload.

## Fixed release gates

The following compile-time release gates remain `false`:

- `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED`;
- `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED`;
- `HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED`;
- `SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`;
- `SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`;
- `SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`;
- `BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED`;
- every Ethereum synchronization, value, settlement, and mainnet gate.

Changing any gate requires new exact-commit evidence for its complete adapter,
persistence, restart/reorg, negative, installed-product, resource, and review
boundary. Neither a package version increment nor successful publication is a
gate-change authorization.

## Publication prerequisites

Before any wallet upload, all 17 `hns-rs` `0.2.0` archives must be visible on
crates.io and each archive must identify exact source commit
`abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2` in `.cargo_vcs_info.json`. The
wallet execute path verifies this provenance, constructs and inspects each
normalized wallet archive before upload, and requires a clean source record.
If final protocol release preparation creates a later commit, the wallet pin,
lockfile, release constants, documentation, and exact-commit CI must move to
that actual published commit before wallet execution.
Actual publication remains a separate, explicitly authorized human action.
