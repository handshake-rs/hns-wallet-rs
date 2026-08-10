# hns-wallet-mobile

`hns-wallet-mobile` is the platform-neutral native control boundary intended
for the Android and iOS application shells. It owns the private wallet host and
service in-process. Creation and restoration use the typed store bootstrap;
every subsequent lifecycle control crosses the canonical wallet ABI v2 framing
and session checks.

`MobileWalletController` remains the lifecycle-only first slice: trusted native
status, unlock, lock, and single-account controls. Its existing API is
unchanged. It has no WebView/provider entry point, chain backend, value action,
marketplace transport, or release-gate authority. Android Keystore and iOS
Keychain integration remain responsibilities of the embedding applications;
raw database keys must never enter website content.

The optional `MobileHnsReadController<B, C>` is the next architecture-neutral
source tranche. A lifecycle controller can be consumed with `into_hns_reads`
so the selector, `HnsAccountReadRuntime`, `PersistentHnsReadRuntime`, service,
and provider persistence all retain clones of the literal same
`SharedWalletStore` authority. An existing wallet can instead be opened
directly with an injected `HnsBackend`. The backend is never selected from an
insecure default.

`synchronize` performs one fresh bounded reconciliation and returns a
camel-case serializable `MobileHnsReadSnapshot` containing balance, receive
target, transaction history, minimized known-name summaries, and successful-tip
module status from one hidden chain/mempool binding. The explicit `balance`,
`receive_target`, `transaction_history`, `known_names`, and `module_status`
methods each perform their own fresh synchronization. Lifecycle requests still
cross private ABI-v2 framing; the combined trusted-native synchronization calls
the composed service directly and never exposes its binding or raw name proof,
state, resource, owner, or derivation evidence. A failed read locks the wallet
before another request can proceed.

Known-name output can only revalidate and minimize names already persisted by a
separately authorized workflow. This crate does not add a mobile name-import
path. It also does not ship a production device backend: the existing
`HnsNodeRpcBackend` is an authenticated loopback node adapter, not an Android or
iOS wallet-index integration. Downstream applications must provide a bounded,
deadline-enforced backend, call synchronous reads off the UI thread, add their
JNI/C/Swift projection, and qualify the exact installed product before exposing
these reads.

The existing backend protocol first learns its durable chain epoch from a
confirmed script-set query, then immediately checks height-zero block evidence
against the selected account network. A wrong-network snapshot is rejected
before any wallet result is accepted or committed, but the backend has already
received derived watch scripts at that point. It is therefore a trusted local
component and must not be exposed as remotely user-configurable until a
pre-script network-identity protocol exists. A pruned node is also not a
general fresh-restore source: transaction history reconciliation requires raw
transaction bytes when they are not already retained in authenticated wallet
state. Production must use an archive-capable companion or a durable
wallet-relevant raw-transaction index. Missing evidence remains a fail-closed
read error.

Value movement, signing, provider/browser integration, HNSA/HNSR, settlement,
Shakedex, and every P2P marketplace gate remain unavailable.

See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for generated-binding progress, target qualification, and release status.
