# hns-wallet-hns

## 0.4.2 - 2026-10-03

<!-- hns-wallet-release-state: 0.4.2 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Maintain idle peer connections, share public header transport, and resume authenticated wallet scans.

Connect the browser reserve concurrently so stalled peer handshakes do not
accumulate serial delays. Preserve healthy candidates when a concurrent wallet
refill has already connected them or filled the reserve.
