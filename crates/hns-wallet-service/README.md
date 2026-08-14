# hns-wallet-service

`hns-wallet-service` composes the private framed service, one shared encrypted
store authority, provider policy, and selected non-value HNS reads.

The included executable remains a locked existing-database control surface; it
does not select a live backend or expose a browser transport. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
available library compositions and release gates.

For a separately trusted native browser launcher, the library exposes
`WalletService::new_persistent_native_hns_reads`. It composes the existing
permission-scoped read runtime from one locked shared store, one exact
pre-existing non-value HNS account configuration, and the authenticated
loopback-only node RPC configuration. Its provider surface is limited to
status, accounts, balance, history, receive address, and approval-scoped known
names plus the existing permission and lock controls. It never advertises
`valueMovement` or `browserIntegration`. This full synchronized-read runtime
advertises the private `hnsReadOperationsV1` marker alongside the required
coarse wallet transport; the account-only and checked-in control runtimes do
not. The marker freezes status, one exact account, and Handshake-scoped
balance, receive-target, history, and module-status requests. The executable
CLI is intentionally unchanged: launcher configuration, artifact admission,
browser-engine authority, transport, approval UI, and installed-product
qualification remain downstream responsibilities.

The library also provides a wallet-owned `NativeHnsReadProfile`
provisioning boundary. One schema-v1 encrypted compare-and-swap entity stores
an exact non-value HNS account configuration, a literal loopback node socket,
a zeroizing/redacted escape-free Authorization value, and a bounded display
label. Provision,
rotation, and load additionally require the authenticated sole HNS account and
its complete singleton recovery-seed bootstrap; load is available only after
wallet unlock and re-authenticates the account every time. This is startup
configuration, not browser, provider, chain, or live-session authority. No
checked-in executable consumes it. Revocation persists a secret-free tombstone
so a later re-provision cannot reset the authenticated revision/update-time
high-water. Account/seed authentication and profile CAS share one
process-local store critical section; a separate process still requires
exclusive database ownership. Tombstoning is not secure erasure from SQLite
WALs or backups, so revocation also requires rotating the node credential.

`WalletService::new_profile_backed_native_hns_reads` is the process-local
composition for that record. It consumes the same locked `SharedWalletStore`,
a non-cloneable/non-serializable passphrase wrapper whose allocation is already
zeroizing, and an exact active revision/update-time fence. It briefly unlocks
to load and authenticate the profile, relocks before calling the ordinary
native-read constructor, performs a private internal unlock, and revalidates
the same fence before returning an already-unlocked service. That closed
variant admits only the six `hnsReadOperationsV1` wallet reads at the complete
service-request boundary; it rejects lifecycle, recovery, workflow, provider,
authority, approval, value, and other-module requests. It revalidates the
active fence before and after every admitted read, discards the result and
locks if the profile changed, and best-effort locks on drop. The passphrase and
profile are not new ABI or Serde vocabulary. No checked-in executable calls
this API. Exclusive cross-process database ownership, private one-shot secret
delivery outside argv/environment/native messages, process termination on
lease loss, artifact admission, and installed-product qualification remain
downstream responsibilities.

The library-only persistent HNS read composition also offers one explicitly
trusted-native synchronization entry point for `hns-wallet-mobile`. It returns
the already-bounded core snapshot so the mobile crate can immediately build its
minimized typed result. The chain/mempool binding and raw known-name evidence
must not leave that trusted composition; provider callers continue through
permission-scoped projection. This adds no executable backend, provider
transport, signing, value, settlement, or marketplace authority.
