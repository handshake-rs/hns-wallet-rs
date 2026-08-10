# Qualification matrix

Snapshot: 2026-08-10. This file records source-scoped evidence and the durable
qualification procedure, not transient workflow or registry state. Unit
coverage, source packaging, or publication never authorizes mainnet value.
Evidence is attached to exact commits and is not inherited automatically by
later source.

The complete CI run
[`31383987461`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987461)
and CodeQL run
[`31383987478`](https://github.com/handshake-rs/hns-wallet-rs/actions/runs/31383987478)
both succeeded for exact implementation commit
`ba9f013a098679fe8e3d812a7e09020803e27d53` on 2026-08-10. Those runs include
the atomic native bootstrap, mobile controller, synchronized HNS reads,
approval-v3 provider framing, Shakedex purpose separation, encrypted BDK
persistence, and deterministic Ethereum contract checks present at that commit.

The rows below retain that historical implementation baseline. For the dated
`0.1.0` release source, routine CI, CodeQL, and the manually dispatched release
preflight must all succeed for the same exact wallet commit. Their immutable
run records establish that release-source result; this document deliberately
does not encode a pending or latest-run claim.

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
| Types and chain traits | historical complete locked workspace CI passed at `ba9f013` | n/a | no product dependency | implementation baseline recorded; API review remains |
| Encrypted store/schema v3 | complete CI passed, including atomic bootstrap, rollback, migrations, encrypted CRUD/CAS, and Unix filesystem regressions | source reopen/restart tests; no Android/iOS secure-store runtime evidence | no device filesystem, Keystore, or Keychain qualification | platform qualification pending |
| HNS wallet and names | complete historical CI passed, including bootstrap, synchronized reads, purpose separation, name workflows, and fail-closed value gates | source restart/reorg paths; no multi-process regtest | node RPC source only; protocol pinned to final immutable `hns-rs` `b24b66c` | HNS funding, value, and fee gates remain `false` |
| Provider core | complete CI passed, including account binding, scoped reads, exact Names consent, and unavailable-method ordering | grants persist; pending approval/UI authority remains process-local | no installed-browser consent or backend E2E | browser and value exposure unavailable |
| Fixed-price Shakedex | complete CI passed, including canonical listing, FINALIZE, reservation, terminal-release, and release-gate tests | source reopen/conflict/reorg/finality tests; no multi-process regtest | no live Denuo, provider, trusted UI, or product coin selection | every Shakedex and dependent HNS value gate remains `false` |
| Market sessions | complete workspace CI passed | CAS journal source; recovery evidence incomplete | no pair E2E, rendezvous, or relay transport | unavailable |
| Bitcoin Kyoto | complete CI passed, including encrypted BDK persistence and the ahead-tip crash edge | exact source restart resume; no multi-process rollback run | no regtest/P2P/broadcast run | send and settlement hard-disabled; normalized or chunked backend pending |
| Ethereum | complete CI and deterministic contract check passed | offline derivation and dormant primitives only | no embedded Helios/local-chain run; no contract audit | synchronization, history, send, signing, settlement, and mainnet unavailable |
| ABI, service, and host | complete CI passed, including canonical camel-case frames, approval-v3, session handling, and host retention | private process session/authority state; no installed restart E2E | downstream browser/future-mobile-provider adoption and rendering pending; trusted-native reads are a separate non-provider surface | private control only; browser/value unavailable |
| Mobile controller | historical Android create and iOS open/restore simulations passed at `ba9f013`; the later injectable synchronized-read source has focused local mock-backend and mainnet-genesis-vs-regtest-account rejection coverage only and requires exact-commit CI | atomic seed/account bootstrap, literal same-authority lifecycle-to-read conversion, read-controller reopen, fresh-read, script-free snapshot plus zero-script-query wrong-network rejection, and failure-lock/retry source tests; platform key stores and installed restart remain downstream | no archive-capable production device wallet-index backend, JNI/C/Swift read binding, installed-device synchronization, resource benchmark, or production network qualification; the re-exported authenticated loopback adapter is not device transport | read-controller source only; downstream product availability remains false; provider/value/HNSA/HNSR/settlement/market unavailable |
| Browser products | separate repositories | platform integration pending | no installed/signed E2E | unavailable |

The historical CodeQL baseline passed at `ba9f013`. This repository records no
independent security audit, database or resource benchmark, multi-process
network test, installed-device run, or installed-browser run for the package
boundary; downstream product evidence does not enable these fixed gates.

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
