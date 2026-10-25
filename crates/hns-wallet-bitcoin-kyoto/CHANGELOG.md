# hns-wallet-bitcoin-kyoto

## 0.4.8 - 2026-10-25

<!-- hns-wallet-release-state: 0.4.8 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Expose the exact approved Bitcoin HTLC redeem transaction and its durable
broadcast or chain-observation stage, including recovery lookup by signed
witness script.

## 0.4.7 - 2026-10-24

<!-- hns-wallet-release-state: 0.4.7 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Migrate the wallet signing and protocol dependency graph to patched crypto-bigint 0.7.7, preserving existing derivation and transaction formats.

## 0.4.6 - 2026-10-15

<!-- hns-wallet-release-state: 0.4.6 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

On a recovery address-window expansion, rematch previously covered compact
filters only against newly derived wallet scripts. New blocks, reorganizations,
approved-broadcast recovery, and later sync cycles retain full matching. This
release also adds a read-only fee quote for the complete Bitcoin swap funding
package, including recovery publications and the HTLC lock.

## 0.4.5 - 2026-10-10

<!-- hns-wallet-release-state: 0.4.5 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.

Bound funded Bitcoin swap-watch replay to the verified funding lock and its
canonical checkpoint.

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
