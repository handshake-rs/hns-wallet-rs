# hns-wallet-market

`hns-wallet-market` provides a wallet-owned, encrypted live board of signed
fixed-terms HNS/BTC offers plus durable, chain-neutral HTLC session admission.

Each offer is an indivisible maker promise to exchange one exact HNS amount for
one exact BTC amount. The board retains only the canonical signed offers and
cancellations, re-authenticates them against the wallet's local network
binding on every load, and expires or hides inactive rows. It contains no
oracle, reporter/source set, price policy, price history, remote indexer, or
third-party API.

The board can group currently live offers by their exact reduced BTC-per-HNS
ratio for a user interface. That grouping is display-only: selection, take,
proposal, hello, and HTLC funding each bind the original offer ID and both
native amounts. A level total can never authorize a different exchange rate.

A signed take binds a locally retained active offer to a unique session and a
taker settlement key. The corresponding maker proposal and accepted session
hello are stored separately. Funding, redeem, and refund status is peer
coordination metadata only; execution still requires independently verified
local chain evidence.

TCP, QUIC, WebSocket, WebRTC, HNSA/HRM rendezvous, or a native companion may
carry the canonical Denuo frames; none is pricing, market, or chain authority.
The crate supplies no discovery service or product UI. Release gates for real
value execution remain owned by the application layer.
