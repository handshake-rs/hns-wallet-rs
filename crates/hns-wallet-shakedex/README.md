# hns-wallet-shakedex

`hns-wallet-shakedex` contains persistence-first fixed-price seller, buyer,
funding, and recovery workflow boundaries. It also supplies a bounded,
encrypted/CAS offline Denuo V2 offer/cancellation outbox. The outbox preserves
exact canonical envelope bytes, persists one deterministic single-flight
handoff before exposing those bytes, and retains monotonic local retry state.
Schema v3 can terminally retain a bounded, canonical, endpoint-signed receipt
that a named relay accepted that exact prepared envelope. The receipt binds
the configured network, HRM root, HNSA service/delegation lineage, endpoint
key, attempt, request, and envelope bytes and self-validates after restart.

The wallet-defined receipt binds an `hns.named-service/v1` HRM resource. That
resource-profile identifier is defined by the draft, but no Denuo application
profile identifier is currently assigned, so integrators must provide a
non-zero caller-owned identifier. The receipt does not prove board inclusion
or currentness, chain/quote authority, or permission to move value. The crate
performs no network I/O and does not turn on any product release gate.

An independent offline board runtime now composes the canonical Denuo V2 offer
decoder with one exact non-value HNS account-read runtime and the literal same
`SharedWalletStore` authority. It accepts an offer into the encrypted CAS board
only after runtime-owned time/network and a fresh exact current, unspent
Shakedex lock validate the listing. Exact retries return `Existing` without a
revision bump; sequence equivocation and stale chain, mempool, account, or
store authority fail closed. Signed cancellations use a narrower negative
boundary: exact target/content authentication plus the selected account's
network, trusted clock, full account-selection fence, and board CAS, with no
node or live-lock query. This permits a tombstone after lock loss while
conferring no listing or value authority; exact persisted retries remain
revision-stable after restart and signed expiry. Loading cached bytes is still
not authority: `current_offer` rechecks the live lock and fences the unchanged
board row after the node queries. This layer performs no relay I/O and does not
use an HRM/HNSA receipt as chain authority.

One exact canonical V2 `GetOffer` can now be evaluated into a closed response
plan. The request and singular `Offer` response require the same nonzero
correlation ID; zero remains valid only for protocol families such as an
unsolicited cancellation tombstone. Missing or cancelled rows produce typed
absence without a node query. A current plan privately retains the freshly
reacquired lock and unchanged board revision, but exposes only request ID,
listing hash, and revision. Runtime clock observation precedes the final
chain, mempool, and exact selected-account fences. Internally authenticated
response bytes are discarded, and the plan is point-in-time evidence rather
than a transport lease or permission to encode, send, sign, provide, or move
value.

Shakedex creation, discovery, signing, broadcast, and dependent value gates
remain unavailable to products until the documented qualification is complete.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for current status.
