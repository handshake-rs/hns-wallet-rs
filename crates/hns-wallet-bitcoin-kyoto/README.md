# hns-wallet-bitcoin-kyoto

`hns-wallet-bitcoin-kyoto` provides the wallet-owned Bitcoin authority used by
the HNS/BTC swap path:

- direct Bitcoin P2P header and BIP157 synchronization through Kyoto;
- BDK descriptor-wallet receive, history, coin selection, and signing;
- encrypted, compare-and-swap persisted wallet and synchronization state;
- session- and role-bound native Bitcoin HTLC keys; and
- exact HTLC funding, redeem, refund, evidence, and prepared-broadcast
  primitives.

Peers supply chain data and transactions, but no explorer, hosted API, relay,
or third-party node is a wallet authority. Denuo owns peer-to-peer offer and
swap-session exchange; Kyoto independently verifies and settles the Bitcoin
side.

The public Bitcoin value permit remains unavailable until these primitives are
connected to the durable product-level swap coordinator and qualified as one
complete flow. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
backend policy and release gates.
