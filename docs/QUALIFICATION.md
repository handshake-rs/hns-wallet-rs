# Qualification matrix

Snapshot: 2026-08-10. This file records source-scoped evidence and the durable
qualification procedure, not transient workflow or registry state. Unit
coverage, source packaging, or publication never authorizes mainnet value.
Evidence is attached to exact commits and is not inherited automatically by
later source.

The complete
[`CI` run `31420628974`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420628974),
[`CodeQL` run `31420627924`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31420627924),
and manually dispatched
[`14-crate release preflight` run `31424201574`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31424201574)
all succeeded for exact qualified implementation source
`2229be849557d58a8eb723bcc03349f0f2df9796` on 2026-08-10. The locked gate
includes atomic native bootstrap, synchronized mobile HNS reads, script-free
initial chain binding and wrong-network rejection, approval-v3 provider framing,
Shakedex purpose separation, encrypted BDK persistence, and deterministic
Ethereum contract checks. The isolated preflight normalized and verified all 14
publishable crates without credentials or upload authority.

Exact implementation commit `ba9f013a098679fe8e3d812a7e09020803e27d53`
also passed historical
[`CI` run `31383987461`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987461)
and
[`CodeQL` run `31383987478`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987478).
That baseline predates the final mobile script-free binding order and is retained
only as historical evidence. The rows below describe exact implementation source
`2229be8`; later documentation or release-source commits must receive their own
exact workflow records before upload. No source workflow result supplies
product, network, value, or release-gate authority.

The final protocol source
`b24b66c382de53330ec21dd3137e056a2bea3e2d` independently passed its complete
[`hns-rs` CI run](https://github.com/handshake-rs/hns-rs/actions/runs/31398600728),
four-language
[`hns-rs` CodeQL run](https://github.com/handshake-rs/hns-rs/actions/runs/31398598588),
and
[`hns-rs` 17-package release preflight](https://github.com/handshake-rs/hns-rs/actions/runs/31399004538)
on 2026-08-10. That is upstream protocol-source evidence only; it neither
qualifies a wallet commit nor changes a wallet product gate.

| Area | Exact source evidence | Persistence/restart and reorg | Product/network evidence | Release status |
| --- | --- | --- | --- | --- |
| Types and chain traits | complete locked workspace CI passed at `2229be8` | n/a | no product dependency | exact source recorded; API review remains |
| Encrypted store/schema v3 | exact `2229be8` CI passed, including atomic bootstrap, rollback, migrations, encrypted CRUD/CAS, and Unix filesystem regressions | source reopen/restart tests; no installed Android/iOS secure-store runtime evidence in this package boundary | downstream mobile candidate source contains Keystore/Keychain wrapping, but device filesystem/runtime qualification remains external | platform qualification pending |
| HNS wallet and names | exact `2229be8` CI passed, including bootstrap, synchronized reads, script-free initial binding, purpose separation, name workflows, and fail-closed value gates | source restart/reorg paths; no multi-process regtest | wallet RPC source pairs with node `2b267ffe`; selected qualified node main `2712d1d` contains that API; protocol pinned to final immutable `hns-rs` `b24b66c` | HNS funding, value, and fee gates remain `false` |
| Provider core | exact `2229be8` CI passed, including account binding, scoped reads, exact Names consent, and unavailable-method ordering | grants persist; pending approval/UI authority remains process-local | no installed-browser wallet consent or backend E2E | browser and value exposure unavailable |
| Fixed-price Shakedex | exact `2229be8` CI passed, including canonical listing, FINALIZE, reservation, terminal-release, and release-gate tests | source reopen/conflict/reorg/finality tests; no multi-process regtest | no live Denuo, provider, trusted UI, or product coin selection | every Shakedex and dependent HNS value gate remains `false` |
| Market sessions | exact `2229be8` workspace CI passed | CAS journal source; recovery evidence incomplete | no pair E2E, rendezvous, or relay transport | unavailable |
| Bitcoin Kyoto | exact `2229be8` CI passed, including encrypted BDK persistence, allocation regressions, and the ahead-tip crash edge | exact source restart resume; no multi-process rollback run | no regtest/P2P/broadcast run | send and settlement hard-disabled; normalized or chunked backend pending |
| Ethereum | exact `2229be8` CI and deterministic contract check passed | offline derivation and dormant primitives only | no embedded Helios/local-chain run; no contract audit | synchronization, history, send, signing, settlement, and mainnet unavailable |
| ABI, service, and host | exact `2229be8` CI passed, including canonical framed projections, approval-v3, session handling, and host retention | private process session/authority state; no installed restart E2E | downstream browser/future-mobile-provider adoption and rendering pending; trusted-native reads are a separate non-provider surface | private control only; browser/value unavailable |
| Mobile controller | exact `2229be8` CI passed the lifecycle, synchronized-read, same-authority, fresh-read, script-free snapshot, zero-script-query wrong-network, and failure-lock/retry regressions | atomic seed/account bootstrap and source reopen coverage; installed platform restart remains downstream | downstream Android/iOS 0.5.9 candidate source contains JNI/C projection, Keystore/Keychain wrapping, native recovery/read screens, and off-UI-thread calls; no archive-capable production device wallet-index backend, installed-device synchronization, resource benchmark, or production network qualification; the loopback adapter is not device transport | candidate read UI can fail closed around the library projection, but product backend availability remains false; provider/value/HNSA/HNSR/settlement/market unavailable |
| Browser products | separate repositories | platform integration pending | no installed/signed E2E | unavailable |

CodeQL passed at exact `2229be8`; `ba9f013` remains the historical baseline.
This repository records no independent security audit, database or resource
benchmark, multi-process network test, installed-device run, or installed-
browser wallet run for the package boundary. Downstream candidate source does
not enable these fixed gates.

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
`b24b66c382de53330ec21dd3137e056a2bea3e2d` in `.cargo_vcs_info.json`. The
wallet execute path verifies this provenance, constructs and inspects each
normalized wallet archive before upload, and requires a clean source record.
Any differing protocol provenance aborts execution.
Actual publication remains a separate, explicitly authorized human action.
