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
serializable `MobileHnsReadSnapshot` containing balance, receive target,
transaction history, minimized known-name summaries, and successful-tip module
status from one hidden chain/mempool binding. Its outer snapshot fields and
mobile name projections use camelCase; nested shared wallet types (`Amount`,
`ReceiveTarget`, `TransactionSummary`, and `SyncStatus`) retain their established
snake_case field names. The explicit `balance`,
`receive_target`, `transaction_history`, `known_names`, and `module_status`
methods each perform their own fresh synchronization. Lifecycle requests still
cross private ABI-v2 framing; the combined trusted-native synchronization calls
the composed service directly and never exposes its binding or raw name proof,
state, resource, owner, or derivation evidence. A failed read locks the wallet
before another request can proceed.

Known-name output can only revalidate and minimize names already persisted by a
separately authorized workflow. This crate does not add a mobile name-import
path. It also does not ship a production device backend: the existing
`HnsNodeRpcBackend` and `HnsNodeRpcConfig` are re-exported here for downstream
composition, but remain an authenticated loopback node adapter rather than an
Android or iOS wallet-index integration. The downstream Android/iOS 0.5.9
candidate source contains JNI/C projection, native recovery/read screens,
Keystore/Keychain wrapping, and off-UI-thread call sites. Those wrappers are not
shipped by this crate and do not supply a backend. A product must still provide
or integrate a bounded, deadline-enforced backend and qualify the exact
installed network/runtime before exposing synchronized results.

Each read first obtains the durable chain epoch and initialized tip through the
script-free `chain_snapshot` backend call, validates height-zero block evidence
against the selected account network under that exact binding, and only then
derives and transmits wallet ScriptIds. The first confirmed page requires that
same tip and `Some(chain_epoch)`. A wrong-network backend therefore receives no
confirmed or mempool script query. This removes the earlier protocol-ordering
privacy blocker; it does not supply or qualify production mobile transport. A
pruned node is also not a general fresh-restore source: transaction history
reconciliation requires raw transaction bytes when they are not already
retained in authenticated wallet state. Production must use an archive-capable
companion or a durable wallet-relevant raw-transaction index. Missing evidence
remains a fail-closed read error.

Value movement, signing, provider/browser integration, HNSA/HNSR, settlement,
Shakedex, and every P2P marketplace gate remain unavailable.

See the [workspace repository](https://github.com/handshake-rs/hns-wallet-rs)
for generated-binding progress, target qualification, and release status.
