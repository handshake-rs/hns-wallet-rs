# hns-wallet-bip157

## 0.4.3 - 2026-10-18

<!-- hns-wallet-release-state: 0.4.3 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Bound cached compact-filter replay to wallet consumption so a slow filter
consumer cannot accumulate an unbounded in-memory queue during Bitcoin sync.
Avoid repeated full-chain progress recounts while restoring a large cache and
retire peers whose message channels close.

## 0.4.2 - 2026-10-04

<!-- hns-wallet-release-state: 0.4.2 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Persist verified block headers, quorum-admitted filter headers and bounded raw-filter batches through an authenticated cache provider. Restore partial syncs after process death, fill out-of-order filter gaps, replay matching on rescan, and require fresh compact-filter peers before reporting completion.

## 0.4.1 - 2026-10-01

<!-- hns-wallet-release-state: 0.4.1 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Reviewed BIP157/BIP158 light-client transport for hns-wallet-rs
