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
Network identity is the exact `(u32 magic, nonzero genesis)` pair: magic zero
is a valid configured value, never a wildcard, and must match the handoff.

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

For a board mutation, the HNS runtime captures the complete selected-wallet
`WalletAccount` prefix lease before node or clock work. The mutation closure
consumes and refreshes that ciphertext-fingerprinted lease in the same coherent
snapshot that fully loads the board, then supplies it as a second compare-only
guard beside the board namespace lease in the immediate board write
transaction. The public `verify_unchanged_account` helper is only a coherent
read diagnostic and is not an atomic precondition for a later write; write paths
use `revalidate_unchanged_account` and consume the resulting guard.

Canonical board mutations persist an encrypted `HeadV2Indexed`, one
digest-addressed row per seller/name identity, and one encrypted
digest-addressed listing-hash index per row. Each compact head row selector
binds the row identity digest, physical revision/update time, row-value
commitment, and listing hash. The public logical board revision remains separate
from each entity's physical store revision. A full load uses one coherent read
snapshot to check the exact bounded namespace, authenticate every row and index,
verify the head commitments and row/index bijection, and reject legacy/head
coexistence or torn state. A save retains unchanged child revisions through
compare-only assertions and changes only affected children.

Both older forms remain strict read formats. A sole legacy-v1 aggregate migrates
atomically to indexed storage on its next successful mutation. The historical
normalized `HeadV2` head and its rows also remain fully readable; targeted
lookups fall back to a full load, and the next successful mutation preserves
unchanged row revisions while installing `HeadV2Indexed` and its listing
indexes.

Indexed `current_offer`, `GetOffer`, and `GetOffers` lookups always compare the
complete O(N) row/index metadata sets and compact head selectors from the
coherent snapshot. The selectors derive the exact expected listing-index ID set
before lookup. If every requested hash has an index, the reader authenticates
only O(K) encrypted index and row values for K hits, and each selected row must
match the selector's identity, physical metadata, listing hash, and row-value
commitment. A head/index-only negative cannot exclude a row whose authenticated
semantics disagree with its selector, so any requested index miss falls back to
the O(N) full semantic row/index loader before returning authoritative absence.
Legacy-v1 and pre-index `HeadV2` targeted reads likewise decode the full board;
inventory remains a full logical-board read.

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

The matching closed `GetOfferInventory` boundary accepts only canonical V2
with a nonzero correlation ID. It uses the same exact store authority and a
purpose-minimized selected-account/network/trusted-time context to select only
active, in-window rows for the current network, without a node query or write.
The canonical `OfferInventory` response is verified and discarded internally;
an empty board is valid, while the public non-cloneable plan exposes only the
request ID, board revision, and listing count. It exposes neither hashes nor
bytes and must be reacquired before any future transport use.

Canonical V2 `GetOffers` also has a closed, read-only plan. The wallet narrows
the protocol's larger request inventory bound to the type-5 response and HNS
coherent-lock limit of 64 before store or runtime I/O. Missing and cancelled
rows form an ordered subset; all-absent returns typed local absence with the
observed board revision and no invalid empty response. A nonempty candidate
set is aggregate-size-preflighted before node access and verified with one
ordered account/chain/mempool/network/time current-lock batch. Duplicate
underlying names and any invalid, expired, wrong-network, stale, or spent
active candidate fail the whole plan. The exact selected account, board
revision, and every requested row are fenced after external reads. Internal
response bytes are authenticated and discarded; only request ID, board
revision, requested count, and returned count are public.

Shakedex creation, discovery, signing, broadcast, and dependent value gates
remain unavailable to products until the documented qualification is complete.
See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for current status.
