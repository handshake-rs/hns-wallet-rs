# BasicSwap native HNS wallet bridge

`integrations/basicswap-bridge` builds an opt-in local process pipe for BasicSwap's
native Handshake HTLC operations. It uses the existing `HnsWalletRuntime`,
`WalletService`, `HnsNodeRpcBackend`, and `hns-swap::HnsHtlc`. HSRD remains the
full node. BasicSwap never receives HNS signing keys or prepared signed-byte
artifacts. The ordinary `hns-wallet-service` executable and the browser/provider
ABI do not acquire these operations.

The bridge currently opens **one existing encrypted HNS wallet account**. The
operator must provision that wallet and supply an owner-private HSRD wallet-RPC
Authorization file. The database path is subject to the wallet store's normal
single-process ownership and Unix file/ancestor policy. The bridge requires an
explicit wallet unlock over its private pipe. It does not take a passphrase or
Authorization value in arguments, environment variables, or logs. The HSRD
endpoint must be loopback; the Authorization file must be a regular,
process-owned file with no group/other permission bits in a process-owned,
non-writable parent directory. Unlocking this purpose-built bridge enables the
account's HNS value and settlement capabilities through the wallet runtime;
the database must therefore be dedicated to this BasicSwap process and backed
up using the wallet's normal recovery seed procedure.

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
process. BasicSwap must persist the offer/bid IDs, nonce, and exact descriptor before
requesting a value action, validate the peer's terms against its own bid and
contract deadlines, and resume observation after restart. The current
BasicSwap seller-first contract and messages use a different script/key shape;
that protocol routing must be implemented before HNS appears as a selectable
asset. The bridge does not by itself make a BasicSwap HNS trade possible.

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

An upstream release also needs a funded two-direction BasicSwap↔HSRD regtest
test for redeem, timeout refund, response loss, process restart, reorg, stale
index, fee rejection, and malformed witness before mainnet offer eligibility.
