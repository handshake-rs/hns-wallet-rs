# hns-wallet-basicswap-bridge

This opt-in binary exposes only exact native-HNS HTLC actions to a locally
launched BasicSwap process over bounded, sequential standard-input/output
frames. It uses the existing encrypted wallet and HSRD adapter; it does not
extend the browser/provider API or export HNS signing keys.

This is a nested Cargo workspace so the main wallet release remains exactly
its published crate set.

See [the protocol and recovery contract](../../docs/BASICSWAP_BRIDGE.md).
