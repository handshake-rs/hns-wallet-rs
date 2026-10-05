# hns-wallet-market

`hns-wallet-market` provides a wallet-owned, encrypted live board of signed
fixed-terms HNS/BTC offers plus durable, chain-neutral HTLC session admission.

Each public offer is an indivisible offer-setter intent to exchange one exact
HNS amount for one exact BTC amount. It is not yet an executable maker listing.
The board retains only canonical signed offers and cancellations,
re-authenticates them against the wallet's local network binding on every
load, and expires or hides inactive rows. It contains no oracle,
reporter/source set, price policy, price history, remote indexer, or third-party
API.

The board can group currently live offers by their exact reduced BTC-per-HNS
ratio for a user interface. That grouping is display-only: selection,
acceptance, proposal, hello, and HTLC funding each bind the original offer ID
and both native amounts. A level total can never authorize a different
exchange rate. The signed offer also fixes the swap session identifier and the
offer setter's future taker settlement key; a responder cannot substitute an
unrelated session.

The wallet that responds to an offer signs the acceptance and becomes the
executable swap maker. It creates the canonical HTLC proposal, reverses the
public intent's sides, and funds the public offer's requested asset first. The
original offer setter verifies and countersigns that proposal as the swap
taker, then funds the asset it originally offered second. The responder-
maker's preimage is recovery-seed-derived and stored encrypted before the
proposal is admitted. Refund ordering follows the executable maker/taker
sides, not the order in which the public intent described them.

Before that maker may prepare first-chain funding, the mobile boundary
reconstructs both signed HTLC descriptors, proves that the advertised Bitcoin
refund key belongs to the wallet, and durably advances through refund-validated
and funding-ready checkpoints. An interrupted transition resumes from its last
checkpoint. The Bitcoin controller registers the exact compact-filter watch
before constructing funding, requires a separate approval of the actual txid
and fee, persists the signed transaction before submission, and accepts only
checkpoint-bound watch evidence—not a broadcast receipt or peer claim—as
confirmed funding.

A signed acceptance binds a locally retained active offer to its fixed session
and the responder-maker's settlement key. The responder's maker proposal and
the offer setter's countersigned session hello are stored separately. Funding,
redeem, and refund status is peer coordination metadata only; execution still
requires independently verified local chain evidence. Protocol objects, storage namespaces, and APIs distinguish acceptance from
executable maker admission.

TCP, QUIC, WebSocket, WebRTC, HNSA/HRM rendezvous, or a native companion may
carry the canonical Shakescape frames; none is pricing, market, or chain authority.
The crate supplies no discovery service or product UI. Release gates for real
value execution remain owned by the application layer.

## Recovery status of 0.5.0

Signing authority and maker preimages are reproducible from the wallet recovery
seed and authenticated public context, independently of the original profile
ID or private offer intent. This does not make a funded contract discoverable
from the seed alone: its public terms still need an automatic recovery path.
The owner authorized store delivery with this remaining limitation disclosed.
Automatic contract discovery after losing the local database is incomplete;
this release does not claim that restoring the seed alone recovers every funded
swap. No separate recovery-file workflow is required. See the
[recovery audit](../../docs/swap-seed-recovery-audit-2026-10-04.md).
