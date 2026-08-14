# hns-wallet-market

`hns-wallet-market` provides persisted, price-bound reservations and
chain-neutral atomic-settlement orchestration.

It also provides a bounded encrypted cache for exact canonical Denuo V2
zero-request-ID `PriceRound` gossip under a caller-owned network, pair,
reporter/source policy, and trusted local `accepted_at_unix` clock. An empty
cache bootstraps from either an unlinked current round or an exact predecessor
checkpoint plus its linked current round; ancestry before a non-genesis
checkpoint is not proven.

The CAS head preserves canonical reporter-aligned sequence high-watermarks and
an authenticated linked suffix capped at 128 rounds. Load revalidates every
retained row and adjacent link. Pruning preserves reporter high-watermarks, but
the removed round hash and ID leave duplicate detection. Cached metadata is not
a live-chain or price authority, provides no quote conversion, and does not
itself confer value authority. All marketplace and value release gates remain
disabled.

It does not supply discovery, rendezvous, relay transport, or a product
marketplace. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
disabled settlement gates and remaining integration work.
