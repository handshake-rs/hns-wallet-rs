# hns-wallet-bitcoin-kyoto

## 0.4.4 - 2026-10-07

<!-- hns-wallet-release-state: 0.4.4 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Check the independent live funding authorization at final HTLC submission for
both first- and second-chain funding, after publication parents and during
restart. Abandon unexposed expired contracts without locking ordinary
seed-owned funds; retain already attempted submissions and prevent late
rebroadcast. Apply that authorization to every untouched publication ancestor
as well as the final HTLC, and atomically abandon the untouched package suffix
on restart after expiry.


## 0.4.3 - 2026-10-07

<!-- hns-wallet-release-state: 0.4.3 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Publish seed-discoverable Bitcoin swap terms through three ordinary wallet ancestors before HTLC funding. Verify every ancestor signature, persist approved packages before broadcast, resume parents before children and register historical recovery watches.


## 0.4.2 - 2026-10-04

<!-- hns-wallet-release-state: 0.4.2 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Resume interrupted Bitcoin wallet recovery using atomic encrypted synchronization evidence. Bind cached data to the wallet account, network, genuine starting checkpoint and peer quorum; rerun script matching without advancing the birthday or skipping historical payments.

## 0.4.1 - 2026-10-01

<!-- hns-wallet-release-state: 0.4.1 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Kyoto-only Bitcoin descriptor wallet and native HTLC settlement adapter
