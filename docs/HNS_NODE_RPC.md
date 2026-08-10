# Handshake node wallet RPC adapter

`HnsNodeRpcBackend` is the concrete synchronous wallet-side adapter for the
authenticated `hns-node-rs` wallet RPC v1 contract, including its additive
script-free chain-snapshot call. It implements `HnsBackend`; the node supplies
canonical chain evidence and broadcast admission while the wallet alone derives
keys, signs, approves, and persists workflows. The node never signs. Exact
wallet/node commit pairing remains required qualification evidence.

## Trusted configuration and transport

`HnsNodeRpcConfig` accepts only an explicit loopback `SocketAddr` with a nonzero
port. It does not accept a URL, hostname, proxy, redirect target, or remote
address. The configured Authorization value must be 1..=4,096 bytes, contain
only visible ASCII (`0x20..=0x7e`), and have no leading or trailing space. Tabs,
controls, newlines, and non-ASCII bytes are rejected. The value is held in a
zeroizing container and every `Debug` implementation redacts it.

Connect, complete-write, and complete-read deadlines are independently bounded
and default to 5, 30, and 30 seconds. Each call opens one TCP connection and
sends exactly `POST /api/v1/wallet` with JSON, a decimal `Content-Length`, the
trusted Authorization value, and `Connection: close`.

The response parser accepts HTTP/1.1 fixed-length JSON only. It rejects
redirects, interim/upgrade responses, chunking, compression, duplicate header
names, malformed or conflicting lengths, oversized headers or bodies, wrong
content type, wrong API version or request ID, unknown/duplicate JSON fields,
result/error ambiguity, noncanonical stable error mappings, premature EOF, and
bytes after the declared body. Request serialization is capped at 1 MiB. The
node's 8 MiB serialized-result ceiling is enforced independently; the bounded
HTTP body allowance includes only fixed envelope and request-ID overhead.

The node listener defaults to a smaller 64 KiB request-body limit. Deployments
that restore large complete script sets must deliberately configure a larger
listener limit, never exceeding the node's 1 MiB hard maximum. A listener limit
failure is explicit and does not cause the adapter to split a logically atomic
script-set query.

## Snapshot and evidence rules

The script-free request is exactly `{"method":"chain_snapshot"}`. Its strict
result has exactly `chain_epoch` and `tip`. The tip is the existing initialized
tip object (`hash`, `height`, `tree_root`, and `median_time_past`) or `null`
before the node has an active chain. Unknown or missing fields are protocol
errors; a valid `tip: null` maps to `StaleNodeSnapshot` and stops before any
script derivation or query. With an initialized tip, the non-value account-read
runtime obtains this binding without transmitting a ScriptId, requests
height-zero block evidence under the same binding, and compares it with the
pinned genesis for the selected account network. Only after that succeeds may
it derive ScriptIds or issue confirmed/mempool wallet queries. A mainnet
snapshot presented for a regtest account therefore results in zero script
queries.

The first and every later confirmed page must match the complete snapshot tip
and receives `expected_epoch: Some(chain_epoch)`. Every later block-hash,
mempool, transaction, spender, and name read remains bound to that epoch and
tip. Confirmed cursors are opaque bytes tied to the exact sorted ScriptId set.
Mempool pages add a nonzero process-instance nonce and generation; both remain
exact across all continuations, gap-limit expansion, transaction/parent reads,
and workflow reconciliation. Any difference discards the partial snapshot.
`get_chain_tip` remains available for legacy/value workflows that have not been
admitted to the product read composition.

This ordering removes the earlier pre-script privacy blocker. It does not widen
transport eligibility: `HnsNodeRpcConfig` remains authenticated loopback-only,
and production Android/iOS transport, lifecycle, resource, and installed-network
qualification remain external product gates.

Every current tip also carries the HSD-compatible median time past computed by
the node from that tip and up to ten ancestors inside the same immutable read.
The wallet wire field is mandatory. Legacy persisted bindings decode with zero
only for compatibility and cannot authorize Shakedex execution until a fresh
node snapshot replaces them.

The ordinary receive/change branches and the domain-separated `HnsName` branch
and `HnsShakedex` 32-byte lock branch use separate bounded script queries. Each
later query is accepted only under the exact chain and mempool bindings learned
by the coin query, so no branch reduces another's lookahead or combines
observations from different node views.

ScriptId derivation hashes the canonical address bytes
`[version, hash_length_u8, hash...]` with BLAKE2b-256, sorts the resulting IDs,
and retains a checked reverse map to wallet derivations. Response hex is
lowercase and canonical. Addresses, canonical covenant bytes, confirmed UTXO
inclusion heights, raw transactions, txids,
outpoint echoes, cursor lengths, collection bounds, fee evidence, inclusion
counts, optional transaction positions, and optional exact block/admission
times are validated before projection into wallet types.

A pruned node may legitimately return no raw transaction bytes. Fresh history
reconciliation can use that response only when the exact raw transaction is
already present in authenticated wallet state; otherwise it fails closed.
Consequently a production fresh-restore companion must retain archive history
or a durable wallet-relevant raw-transaction index. The currently available
pruned development node is not general production read-backend evidence.

`quote_transaction_fee` binds the exact final signed transaction bytes to the
current chain epoch/tip, mempool instance/generation, and requested confirmation
target. The adapter verifies canonical raw bytes, txid, transaction weight,
policy virtual bytes, sigop cost, rate source/sample bounds, actual fee,
minimum fee, shortfall, and the node's `meets_minimum` relationship before
projecting the quote into wallet state. The wallet supplies the exact ordered
input coins reconstructed from persisted inclusion/address/covenant evidence;
the adapter and final workflow validator independently recompute weight,
sigops, sigop-adjusted policy virtual size, minimum fee, and actual fee with the
pinned `hns-script` implementation. Legacy rows without that evidence and any
outpoint/covenant/name-lock mismatch are unusable as inputs.

The send and exposed settlement signing paths are wired to sign first and quote
those exact bytes. Authorization peeks at the authenticated approval without
consuming it; after signing and quote validation, one SQLite transaction
consumes the unchanged approval, persists the authorized workflow with exact
raw bytes and quote, and activates the matching input reservations. Immediately
before submission the wallet re-quotes only the persisted bytes, commits the
refreshed quote and `RequiresRebroadcast` state, and then submits those same
bytes. A stale snapshot or temporarily unavailable quote input permits exactly
one complete reconciliation and one quote retry; there is no polling loop.

The reviewed immutable `hns-script` 0.2 source now supplies transaction sigops,
sigop-adjusted policy size, minimum-fee construction, and standard weight/
sigop bounds directly to the wallet. No local formula is copied. This source
has not passed consolidated wallet qualification, so
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains `false` and the wired quote
path still cannot authorize value.

Confirmed coinbase identity is preserved exactly, but coinbase outputs are
conservatively excluded from selection. No local maturity constant is invented;
canonical node-projected maturity evidence and qualification are required
before an HNS value release can make those outputs spendable.

Ordered spend queries are chunked at the frozen 256-outpoint wire maximum; each
batch preserves and validates every requested outpoint echo and binding.
Every unique spender block and every confirmed transaction/name-owner inclusion
is cross-checked through the epoch-bound active-chain block-hash method before
the runtime accepts it.
Name responses preserve the exact canonical current/proof NameState bytes and
strict Urkel proof bytes. The adapter decodes each raw state under the requested
name hash and requires every projected name, height, owner, value, resource,
transfer, renewal, claim, and flag field to equal it. The HNS runtime separately
checks strict proof inclusion, owner txid/index, exact output value, name
covenant and typed TRANSFER/FINALIZE shape. Current resources are retained only
when byte-identical to decoded `resource_data`; malformed typed DNS data remains
lossless canonical opaque data rather than invalidating consensus state.
For a TRANSFER owner, canonical NameState transfer height must equal that owner
transaction's active-chain inclusion height. A non-TRANSFER owner is rejected
while transfer height remains nonzero; FINALIZE is not incorrectly bound to its
own inclusion height.

## Name-action context

`name_action_context` is a construction-evidence call, not a signing or
broadcast call. Its request supplies exactly one `transfer` or `finalize`
action, the name hash, the expected chain epoch, and the exact expected mempool
instance nonce and generation. The versioned response binds stable network ID
and genesis identity, consensus profile, tip, candidate inclusion height,
canonical current state, exact owner transaction/output/inclusion, lifecycle,
owner-spender txid, transfer lockup and maturity, HSD-selected renewal
height/hash/window, and a maximum-nine fixed ordered reason vector.

The adapter rejects unknown fields, lifecycle/reason vocabulary changes,
duplicates or reordered reasons, binding changes, projection differences,
incorrect owner/source covenant shape, transfer-height/inclusion mismatch,
incorrect maturity or HSD-selection arithmetic, and noncanonical chain
identity. For FINALIZE the wallet also reads the selected block hash through
the same epoch-bound active-chain method at each authority reacquisition,
including preparation, authorization, and broadcast or rebroadcast. A bound
owner mempool spender denies fresh action authority. No consensus name-policy
constant is copied into the wallet; contextual policy originates in the pinned
node consensus profile and is independently checked from returned evidence.

## Release policy

This adapter removes the missing source boundary; it does not by itself enable
value movement. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` remains `false`, runtime
configuration rejects HNS send and settlement on every network. Imported names
now retain authoritative decoded metadata and account-bound ownership status,
while the context-free library import reports ownership as explicitly
unevaluated instead of claiming `NotWalletOwned`. That persisted status cannot
authorize value. `verify_name_ownership`
reacquires a non-serializable authority from the exact live snapshot and only
for a registered, unexpired, unrevoked, non-transferring owner output matching a
persisted `HnsName` derivation. Shakedex/HTLC descriptor or preimage transport
remains unavailable as a value path. The wallet can now reacquire non-
serializable current/unspent Shakedex lock and TRANSFER authorities, including
tip MTP and FINALIZE renewal evidence. TRANSFER authority additionally binds
the preserved output-zero owner program back to the descriptor's seller script
and canonical name hash. Funding reservation, approval,
broadcast/reorg supervision, protocol qualification, product integration, and
the recorded gates remain outstanding. Ordinary HNS
send, the exposed settlement lock/redeem/refund paths, and wallet-owned P2PKH
TRANSFER/direct-FINALIZE source workflows are within the exact quote boundary.
Provider dispatch and release qualification remain incomplete.

Focused and consolidated evidence for this source is recorded only in
[QUALIFICATION.md](QUALIFICATION.md); no test result changes a value gate.
