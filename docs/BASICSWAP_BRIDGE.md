# BasicSwap native HNS wallet bridge

`integrations/basicswap-bridge` builds an opt-in local process pipe for BasicSwap's
native Handshake HTLC operations. It uses the existing `HnsWalletRuntime`,
`WalletService`, `HnsNodeRpcBackend`, and `hns-swap::HnsHtlc`. HSRD remains the
full node. BasicSwap never receives HNS signing keys or prepared signed-byte
artifacts. The ordinary `hns-wallet-service` executable and the browser/provider
ABI do not acquire these operations.

The settlement process opens **one existing encrypted HNS wallet account**. A
separate one-shot initializer can create or restore that account before the
settlement process starts. The operator must supply an owner-private HSRD
wallet-RPC Authorization file for settlement. The database path is subject to
the wallet store's normal single-process ownership and Unix file/ancestor
policy. The bridge requires an
explicit wallet unlock over its private pipe. It does not take a passphrase or
Authorization value in arguments, environment variables, or logs. The HSRD
endpoint must be loopback; the Authorization file must be a regular,
process-owned file with no group/other permission bits in a process-owned,
non-writable parent directory. Unlocking this purpose-built bridge enables the
account's HNS value and settlement capabilities through the wallet runtime;
the database must therefore be dedicated to this BasicSwap process and backed
up using the wallet's normal recovery seed procedure.

## Create or restore the account

Run the binary with `--initialize --database PATH --network
mainnet|testnet|regtest|simnet --restore-height HEIGHT`. This mode does not
connect to HSRD and exits after one framed stdin request and one framed stdout
response. The request has version 2, sequence 1, a passphrase, and a null
`recovery_phrase` to create, or a 24-word phrase to restore. The response
contains a 16-byte wallet ID and a 32-byte seed fingerprint. Only creation
returns a new 24-word recovery
phrase; the caller must present it for a private backup before allowing funds
into that account. The phrase and passphrase never appear in command-line
arguments, environment variables, or logs. The process exits immediately
after the response, so it does not retain the phrase while running trades.

The initializer uses the wallet store's guarded atomic creation path and
refuses an existing database. The Python `initialize_hns_wallet` helper in
BasicSwap implements the framing and validates the response. An interrupted
create can leave a database whose phrase was not received; do not fund such an
account. Restore from a backed-up phrase into a new, empty wallet path.
Creation assigns a random wallet ID; restoration derives a new wallet ID from
the phrase. The seed fingerprint is stable across that restore and is computed
as SHA-256 of `basicswap/hns-wallet-bridge/seed-fingerprint/v1\0` followed by
the 64-byte recovery seed. BasicSwap must store this fingerprint and compare it
with the unlocked bridge's `identity` response before resuming a trade. The
response also carries the selected network and the current wallet ID.

## Framing and session identity

The pipe uses a four-byte little-endian payload length followed by UTF-8 JSON,
with a 65,536-byte maximum. Requests are sequential, start at sequence 1, and
have the shape:

```json
{"version":2,"sequence":1,"request":{"operation":"sync"}}
```

Responses contain the same version and sequence, `ok`, and exactly one of a
result object or a stable error code. Unknown fields and wrong versions or
sequences fail closed. BasicSwap's 28-byte offer ID and a random 32-byte nonce
carried in the bid are mapped to the 32-byte wallet session ID as:

```text
SHA256("basicswap/hns-wallet-bridge/session/v2\0" || offer_id || session_nonce)
```

BasicSwap assigns the bid ID after sending the bid, so that ID cannot derive
the buyer's HNS receive key carried in the bid. BasicSwap must generate the
nonzero nonce with a cryptographically secure random source before sending and
persist it with the final bid ID. `terms` carries the offer ID, bid ID, nonce,
canonical 148-byte `hns-swap` v1 descriptor, and its domain-separated descriptor
hash. The bridge decodes and compares them before any wallet operation. The
wallet verifies the exact network, amount, hashlock, compressed keys, CLTV
refund deadline, plain covenant, and current HSRD chain evidence. The local
HNS receiver/refund key is derived by the encrypted wallet for the session and
must match the descriptor branch used by the requested action.

## Operations

| Operation | Result and authority |
| --- | --- |
| `unlock`, `lock` | Opens or closes the wallet key authority in this process. |
| `identity` | Returns the current wallet ID, stable seed fingerprint, and selected HNS network after unlock. |
| `sync` | Reconciles authenticated HSRD chain/mempool evidence with the wallet before value operations. |
| `receive` | Returns the wallet's ordinary HNS payment address and derivation index without spending authority. |
| `snapshot` | Synchronizes against HSRD and returns the authenticated HNS balance in decimal base units and current ordinary receive address. |
| `key` | Returns only a compressed wallet-owned session public key for receiver or refund. |
| `fund` | Checks the exact descriptor and wallet refund key, prepares under a maximum fee, durably records and broadcasts the HNS lock. Returns the transaction ID and output index 0. |
| `verify_lock` | Re-fetches and verifies the exact funding transaction at the required confirmation floor. |
| `redeem` | Checks the wallet receiver key, preimage hash, confirmed lock, and fee cap; signs and broadcasts the receiver branch. |
| `refund` | Checks the wallet refund key and confirmed lock; the runtime obtains the current authenticated HNS height or median time before signing the mature refund branch. |
| `observe_spend` | Fetches and executes the actual witness against the verified funding coin; a verified redeem returns the preimage for the counter-chain settlement. |
| `rebroadcast` | Retries durable signed-byte settlements already authorized for submission. |

`fund`, `redeem`, and `refund` recover a previously submitted transaction ID
from the wallet's exact persisted workflow if a process died after submission
but before BasicSwap received the response. The returned ID is local submission
state, **not chain confirmation**. BasicSwap must call `verify_lock` and
`observe_spend` for chain-state transitions and run `rebroadcast` after restart.
The wallet rejects changed terms for the same session.

## Integration boundary

This pipe is intended to be launched and called only by the local BasicSwap
process. BasicSwap must persist the offer/bid IDs, nonce, and exact descriptor
before requesting a value action, validate the peer's terms against its own bid and
contract deadlines, and resume observation after restart. The current
BasicSwap's `hns-integration` branch now routes fixed HNS/BTC offers through
dedicated bid, acceptance, and second-lock messages, its persisted settlement
record, and a restartable value worker. This bridge alone still does not make
HNS a supported asset: BasicSwap must also configure HSRD, Bitcoin Core,
SMSG v2, and the correct wallet seed fingerprint.

Run the focused bridge tests with:

```text
cd integrations/basicswap-bridge
cargo test --locked
cargo clippy --locked -- -D warnings
```

The ignored `funded_lock_uses_real_hsrd_wallet_index` test exercises a fresh
encrypted wallet against isolated HSD and HSRD regtest nodes. Start HSRD with
`--wallet-index --mining-engine --transaction-relay` and its private wallet RPC
Authorization file; transaction relay is opt in and a node without it rejects
HTLC publication. Start HSD with its wallet plugin, and supply its wallet's
regtest receive address as `BASICSWAP_HSD_MINER_ADDRESS`. Set
`BASICSWAP_HSRD_REGTEST_RPC`, `BASICSWAP_HSRD_REGTEST_AUTH_FILE`,
`BASICSWAP_HSD_CLI`, `BASICSWAP_HSW_CLI`, and
`BASICSWAP_HSD_REGTEST_PREFIX` to the corresponding local test values, then run:

```text
cargo test --locked funded_lock_uses_real_hsrd_wallet_index -- --ignored
```

The test mines to the HSD wallet, sends an ordinary transfer to the new Rust
wallet, confirms the HNS HTLC lock at the wallet's two-confirmation default,
redeems with the matching preimage, verifies the observed spend, and checks
that the spend evidence survives a bridge restart. Mining directly to the Rust
wallet's receive address would create coinbase outputs, which its ordinary
spendable balance excludes. The live test does not exercise a BTC contract or
a timeout refund.

BasicSwap's opt-in two-chain regtest now funds and redeems both directions
through its value adapter and its bid/worker route, with real HSRD, HSD, this
bridge, and Bitcoin Core. The app route reopens both app databases during a
trade, resumes an injected interruption after maker funding, and refuses maker
redemption during an invalidated Bitcoin second-lock confirmation. A second
isolated Linux regtest advances HSD, HSRD, and this bridge under a shared clock
and confirms a funded HNS timeout refund. A two-node Particl Core regtest
delivers a real HNS/BTC offer and bid to BasicSwap handlers and all three exact
trade envelopes over SMSG v2. The funded app route uses a mock SMSG transport;
one combined HNS, BTC, and Particl app test remains. Packaged binaries and a BasicSwap HNS
ordinary withdrawal and passphrase-rotation path also remain before mainnet
eligibility.
