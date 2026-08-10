# Handshake Provider API

The website surface is `HandshakeProvider`, not `window.ethereum`:

```ts
interface HandshakeProvider {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
}
```

Discovery uses `hns:requestProvider` and `hns:announceProvider`. A convenience
global may be announced, but consumers must not depend on one mutable global.

## Methods

General:

`wallet_getCapabilities`, `wallet_getEnabledModules`, `wallet_enableModule`,
`wallet_disableModule`, `wallet_requestPermissions`, `wallet_getPermissions`,
`wallet_revokePermissions`, `wallet_lock`, `wallet_getStatus`.

Handshake:

`hns_requestAccounts`, `hns_accounts`, `hns_getBalance`,
`hns_getTransactions`, `hns_getReceiveAddress`, `hns_send`, `hns_getNames`,
`hns_getName`, `hns_importKnownName`, `hns_transferName`, `hns_finalizeName`,
`hns_signTypedMessage`.

The method vocabulary is stable even when a capability is unavailable. The HNS
runtime now persists split proof/current canonical summaries, exact current
resource bytes, and account-bound ownership/transfer direction after fresh
reconciliation; legacy rows stay explicitly watch-only. A library-only service
composition now dispatches the non-value account, balance, transaction,
receive-target, and scoped known-name methods from fresh synchronized wallet
state. It is not selected by the checked-in executable or an installed browser
product. `hns_transferName` and
`hns_finalizeName` remain unavailable even though typed wallet-owned P2PKH
TRANSFER/direct-FINALIZE workflows now exist in the wallet source. Provider
value dispatch, trusted product approval UI, adapter qualification, and both
HNS value gates are incomplete. Persisted status, incoming-recipient
classification, or a node projection never authorize signing.

External assets:

`asset_getAccount`, `asset_getBalance`, `asset_getTransactions`,
`asset_getReceiveTarget`, `asset_send`. Every call includes exactly one enabled
`bitcoin` or `ethereum` module. These methods never accept calldata or PSBTs.
Ethereum currently exposes offline receive derivation only; provider dispatch,
balance/history, send, signing, and settlement remain unavailable.

Name market:

`nameMarket_listOffers`, `nameMarket_createFixedPriceOffer`,
`nameMarket_cancelOffer`, `nameMarket_acceptOffer`, `nameMarket_getSession`,
`nameMarket_finalizePurchase`, `nameMarket_recoverName`.

Cross-chain market:

`swap_getSupportedPairs`, `swap_getPriceRound`, `swap_listMarketIntents`,
`swap_publishMarketIntent`, `swap_cancelMarketIntent`, `swap_requestMatch`,
`swap_acceptFill`, `swap_getSession`, `swap_redeem`, `swap_refund`.

## Events

`connect`, `disconnect`, `permissionsChanged`, `modulesChanged`,
`accountsChanged`, `balancesChanged`, `transactionsChanged`, `namesChanged`,
`nameMarketChanged`, `priceRoundChanged`, `marketIntentChanged`,
`swapSessionChanged`, `walletLocked`.

Events are private service frames scoped by an opaque host-issued authority
handle and exact service-owned revision. A navigation/policy/runtime change,
permission revocation or expiry, wallet-session rotation, authority
replacement/revoke, or service restart invalidates pending approvals and event
channels. Only the explicit disconnect event may be emitted after permission is
no longer active.

The browser host retains the engine-issued authority. Only its private control
channel may register the logical origin, namespace, runtime session/generation,
policy/navigation generations, decision fingerprint, and expiry. Pages never
supply those values as authentication and never receive the opaque handle.
Wallet lock/session and permission generation are owned by the wallet service.
The reusable host state machine mints the opaque handle and per-request nonce,
tracks the exact authority revision and current private binding, and correlates
each bounded request with only its allowed response class. Approval decisions
reuse host-retained ownership and expiry, and service events share one exact
incoming channel sequence with responses. None of that private state is a
website request field. Mandatory-approval methods cannot complete on their
initial request, approval IDs cannot be reused within a host session, and
permission or wallet-lock transitions must advance the exact generation or
session dimension before a result is accepted.

Permission records and encrypted tombstone generations survive service
restart. Their persistence scope is the exact selected namespace plus logical
origin, stored under a domain-separated opaque key; the record retains both
values and must match them when loaded. The persistent runtimes and provider
core hold clones of one `SharedWalletStore`, so lock clears their one
decrypted record key rather than leaving an independently unlocked permission
connection. The service reads the current generation from that store; it never
accepts one from a request. The first grant is
generation one and every later grant/revocation is exactly the stored generation
plus one. An Accounts grant also retains a bounded exact set of approved
wallet-local account IDs. A legacy or generic grant that claims Accounts
without that set fails closed. Every approved permission change carries the
generation authenticated by its prompt into the persisted compare-and-swap;
if another grant or revocation wins first, the old approval is stale and cannot
authorize the next generation. Every other approved call rechecks the active,
unexpired permission and generation immediately before execution. Provider
approvals, handle-bound replay state, rate windows, request-ID windows, and
event cursors are deliberately process-ephemeral. Their maximum approval
lifetime is 90 seconds, and old service sessions cannot resume them.
Time-bearing provider entry points also reject a process-local wall-clock
rollback instead of extending authority.

`wallet_lock` is service-owned: it snapshots the authenticated permission
generation, the runtime locks, and then the service rotates the wallet session
and clears approvals and event cursors. Its result binds that prior generation
to the new session without reopening the locked store. Unlock, creation, or
restoration rotates the wallet session only after the runtime succeeds; if that
rotation cannot obtain fresh entropy, the service synchronously locks the
runtime again before returning failure. Send prompts are accepted only when the
method, requested module, displayed chain, amount asset, and fee asset agree
exactly.

The 43 method names remain the closed vocabulary, but presence in that
vocabulary is not availability. Wallet types own the single canonical wire-name
list used by both provider parsing and private ABI snapshot validation; even a
short, bounded unknown name is rejected. The website method `wallet_getCapabilities`
returns only `{providerApiVersion:1,methods:[...]}`. Native bootstrap separately
uses the authority-scoped private ABI capability request whose snapshot is
`{providerSchemaVersion:1,approvalSchemaVersion:3,walletSessionId,
permissionGeneration,methods}`. The native adapter retains its result binding;
it must never project that private envelope to website code. Chromium must
project exactly `{abiVersion,available,walletSession,permissionGeneration,
methods}` from private negotiation. The checked-in persistent control runtime
has provider dispatch but no browser integration. After unlock its private set
is exactly `wallet_getCapabilities`, `wallet_getStatus`,
`wallet_getPermissions`, `wallet_revokePermissions`, and `wallet_lock`;
Chromium `available` remains false until the separate browser/runtime gates
succeed.

Generation zero is valid only before the first grant or revocation;
`wallet_getPermissions` preserves a nonzero tombstone generation with an empty
capability list. Generic `wallet_requestPermissions` is advertised and executed
only when at least one currently supported permission-bearing runtime method
can consume the requested non-Accounts scope; this prevents the control-only
runtime from persisting dormant authority for a later upgrade. An unimplemented
method returns `unsupportedCapability`. The checked-in subprocess advertises
only the private control subset and does not advertise value movement or browser
integration.

Every HNS-prefixed method requires an HNS authority namespace before any
permission lookup or approval can act. An ICANN authority cannot invoke an HNS
method even when a persisted permission would otherwise cover it.

The service source now defines the atomic `hns_requestAccounts` join. The
library-only `PersistentHnsAccountRuntime` may advertise it only when its
`HnsExistingAccountSelector` and provider retain clones of the identical
Arc-backed store. Unlock authenticates one exact pre-existing non-value account;
selection never creates or updates an account and performs no node I/O. After
trusted approval, the service validates and encodes that singleton ID before
atomically persisting the same ID in the approval-bound permission generation.
Every `hns_accounts` call then re-authenticates the current selection and
requires exact equality with the persisted singleton, including after restart.
Both methods return one 32-character lowercase hexadecimal ID. Null or an empty
object are the only accepted parameters, and generic `wallet_requestPermissions`
cannot create Accounts authority. The account-only composition advertises
exactly those two methods plus the five controls above.

The library-only `PersistentHnsReadRuntime` requires an
`HnsAccountReadRuntime` backed by the identical Arc authority and extends that
surface with `hns_getBalance`, `hns_getTransactions`,
`hns_getReceiveAddress`, `hns_getNames`, and `hns_getName`. Every call performs
one bounded live reconciliation, retains its exact chain-tip/epoch and mempool
instance/generation binding inside the trusted service, rechecks the selected
account, and returns nothing if the binding, store corpus, lock state, or
selection changes. Node calls occur only after every shared-store closure has
returned.

Read capabilities are additive only after a persisted exact Accounts grant.
`wallet_requestPermissions` cannot replace or select that account. Approving
Names first performs one live synchronization and places the exact sorted
canonical name/lowercase-hash pairs in required approval-schema-v3 `hnsNames`.
Pending state freezes that account, display list, and binary hash set. Approval
performs one new synchronization and fails stale if the permission, account,
or current set differs; it persists exactly the displayed hashes and never
adds a post-decision name. Empty authorizes no names. The consent list is
limited to 64 and the unchanged 16 KiB approval-frame ceiling also fails closed
without truncation. A nonempty persisted set remains invalid without HNS
namespace, Accounts, Names, and a nonempty account binding.

Non-Names permission prompts and `hns_requestAccounts` carry `hnsNames: []`.
Browser/mobile consumers must negotiate, adopt, preserve, and render this
approval-v3 shape before the read composition is product-available.
Strict approval-v2 consumers reject the new field, while v3 consumers reject
its omission.

Balance, transaction, receive-address, and name-list calls accept only null or
an empty object. `hns_getName` accepts exactly one 64-character lowercase-hex
`nameHash`. The exact public result shapes are:

```json
{"amount":{"asset":"HNS","baseUnits":"42"}}
```

```json
{"transactions":[{"module":"handshake","txid":"<64 lowercase hex>","status":"confirmed","netAmount":{"negative":false,"magnitude":"17"},"fee":"2","blockHeight":99,"firstSeenUnix":1700000000,"confirmationCount":3}]}
```

```json
{"target":{"module":"handshake","account":"<32 lowercase hex>","display":"rs1...","derivationIndex":7}}
```

```json
{"names":[{"name":"alpha","nameHash":"<64 lowercase hex>","proofHeight":99,"resourceStatus":"canonicalDecoded","ownershipStatus":"walletOwned","registered":true,"expired":false}]}
```

`hns_getName` returns the same minimized object under `{"name":...}`. No result
contains raw proof/current state, raw resource bytes, owner outpoints,
derivations, node identity, chain epoch/tip, or mempool generation. Amounts and
signed magnitudes are decimal strings. Optional fee/height/time and
registered/expired fields are JSON null when unavailable. Heights and times
must fit JavaScript's exact integer range. Transaction and name lists are
limited to 128 and fail closed rather than truncate; the encoded provider
result retains the ABI byte bound. All labels and website display strings are
bounded printable ASCII.

The checked-in subprocess still uses `PersistentControlRuntime`, advertises no
HNS account or read method, and has no account/backend construction inputs.
HNS send, name import, transfer/finalize, signing, module control, and every
settlement method remain unsupported in the read composition. This source
boundary is not browser product availability and changes no value gate.

## Explicitly forbidden

The default website API rejects `eth_sendTransaction`, `eth_call`,
`eth_estimateGas`, `eth_sign`, `personal_sign`, `wallet_addEthereumChain`,
`wallet_switchEthereumChain`, `bitcoin_signPsbt`, `signRawTransaction`, seed or
private-key export, arbitrary filesystem/process/native-host operations, and
unknown methods. Marketplace actions are typed methods whose parameters are
reconstructed and verified by the wallet.

## Error posture

Unknown methods, forbidden methods, invalid params, oversized frames, insecure
origins, unauthorized capabilities, replays, request flooding, stale context,
stale approval, locked wallet, and unavailable module/backend are distinct
errors. Errors minimize account and policy disclosure.

The provider/ABI/service/host account-join, synchronized-runtime,
scoped-permission, and public-projection regressions are included in the exact
CI evidence recorded in `QUALIFICATION.md`. Installed-browser and product
chain-runtime qualification remain pending.
