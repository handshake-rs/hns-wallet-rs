# Changelog

This crate uses the shared `hns-wallet-rs` workspace version. Complete release
notes for every public crate are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-wallet-rs/blob/v0.1.0/CHANGELOG.md).

## Unreleased

- Added a backend- and clock-injectable synchronized HNS read controller that
  preserves the existing lifecycle-only controller API and exact shared-store
  authority. Its bounded serializable snapshot exposes only balance, receive
  target, transaction history, minimized already-known names, and successful-tip
  module status, with an exact selected-network genesis check. The current
  backend protocol reveals derived watch scripts before it learns an epoch and
  verifies genesis, so only a trusted local backend is eligible. No concrete
  mobile backend, provider, value, signing,
  HNSA/HNSR, settlement, or marketplace capability is enabled.

## 0.1.0 - 2026-08-10

See the canonical workspace changelog for the complete shared release scope and
safety status. A source archive alone does not enable any wallet product,
provider, value, settlement, or marketplace release gate.
