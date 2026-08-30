# hns-wallet-bitcoin-kyoto

`hns-wallet-bitcoin-kyoto` provides the wallet-owned Bitcoin authority used by
the HNS/BTC swap path:

- direct Bitcoin P2P header and BIP157 synchronization through Kyoto;
- BDK descriptor-wallet receive, history, coin selection, and signing;
- encrypted, compare-and-swap persisted wallet and synchronization state;
- session- and role-bound native Bitcoin HTLC keys; and
- exact HTLC funding, redeem, refund, evidence, and prepared-broadcast
  primitives; and
- one Kyoto compact-filter stream that watches both descriptor scripts and all
  active swap HTLC scripts, persists canonical funding/spend observations, and
  learns a redeem preimage without trusting the counterparty to reveal it.

Peers supply chain data and transactions, but no explorer, hosted API, relay,
or third-party node is a wallet authority. Denuo owns peer-to-peer offer and
swap-session exchange; Kyoto independently verifies and settles the Bitcoin
side. A reorganization can roll back funding or spend confirmations, but it
cannot erase a preimage that has already become public.

The public Bitcoin value permit is issued only through the connected durable
product-level swap coordinator. Value actions require an exact process-local
approval, persist signed bytes and their fee cap before submission, recover
approved broadcasts after interruption, and exclude their committed inputs
until the canonical wallet view observes the transaction. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
backend policy and release gates.
