# hns-wallet-hns

## 0.4.5 - 2026-10-07

<!-- hns-wallet-release-state: 0.4.5 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Check live funding expiry at the final HTLC submission after publication parents and during restart. Abandon unexposed expired contracts without locking ordinary seed-owned funds; retain already attempted submissions and prevent late rebroadcast. Expire an interrupted recovery-publication retry before retransmitting any ancestor when the contract was never attempted and its persisted fresh funding authorization has elapsed.


## 0.4.4 - 2026-10-07

<!-- hns-wallet-release-state: 0.4.4 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Publish seed-discoverable Handshake swap terms through six ordinary wallet ancestors before HTLC funding. Verify ancestry and signatures, include all publication fees in native approval and preserve the approved package for interruption recovery.


## 0.4.3 - 2026-10-03

<!-- hns-wallet-release-state: 0.4.3 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.
Race the configured peer reserve and return as soon as the independent sync
quorum connects. Keep outstanding dials bounded and deduplicated across wallet
and browser consumers, without retaining the wallet or its private store.
Register late peers before header agreement. Retain discovered swap endpoints
for automatic reconnection while excluding live sessions from duplicate dials.

## 0.4.2 - 2026-10-03

<!-- hns-wallet-release-state: 0.4.2 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Maintain idle peer connections, share public header transport, and resume authenticated wallet scans.

Connect the browser reserve concurrently so stalled peer handshakes do not
accumulate serial delays. Preserve healthy candidates when a concurrent wallet
refill has already connected them or filled the reserve.
