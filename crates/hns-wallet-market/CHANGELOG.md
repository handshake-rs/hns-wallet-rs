# hns-wallet-market

## 0.5.1 - 2026-10-07

<!-- hns-wallet-release-state: 0.5.1 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Reconstruct seed-owned settlement allocations and reclaim candidates from chain-bound public terms. Retain independently verified spends separately for each chain and restore public preimages for the taker’s remaining claim.


## 0.5.0 - 2026-10-04

<!-- hns-wallet-release-state: 0.5.0 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Remove private offer identifiers and device-local profile IDs from settlement-key derivation. Reproduce signing authority, board identity and maker preimages from the same recovery seed and public context in a fresh profile. This is a breaking beta format change; no compatibility reader is added. Automatic recovery of contract terms after local database loss remains incomplete; this release does not claim seed-only contract discovery.

## 0.4.2 - 2026-10-03

<!-- hns-wallet-release-state: 0.4.2 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Persist and decode direct ShakeScape offers and coordinate authenticated cross-chain workflows.
