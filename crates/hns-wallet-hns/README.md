# hns-wallet-hns

`hns-wallet-hns` contains the Handshake-first account, name workflow, recovery,
and node-backend boundary for `hns-wallet-rs`.

The crate also owns the encrypted publisher-counter boundary required by the
HNSA/HNSR adapter. Endpoint-delegation and named-route counters are independent,
are scoped by the exact route and compressed endpoint key, and commit a fresh
nonzero sequence before returning an opaque reservation. Abandoned reservations
remain safe gaps; restart, browser, or mobile flows must never reuse them. The
counter API stays internal until a reviewed immutable protocol dependency can
consume each reservation while signing.

The non-value `HnsAccountReadRuntime` can also perform one query-scoped
Shakedex-lock verification for an exact name and seller key. It obtains and
fences fresh chain and mempool bindings, canonical NameState/action context,
confirmed and mempool unspentness, selected account revision, selected network,
and runtime wall time without restoring the value-runtime cache. The returned
authority is ephemeral and non-serializable; this path exposes no signing,
broadcast, settlement, or gate-changing operation.

`HnsPersistedRecoveryReadOnlyRuntime` is a separate, deliberately smaller
opening path for an exact already-persisted account whose historical
configuration has `value_operations_enabled` or `settlement_enabled` set. It
validates inert structure and exact persisted identity without treating either
bit as authority. The wrapper exposes only exact selection and synchronized
read projection; the ordinary selector and full runtime continue to enforce
all production gates. It cannot create an account, profile, allocation, signer,
workflow, or value authority, change configuration, or obtain current
Shakedex-lock authority. Synchronization may create or replace derived-address,
coin, transaction, name, and recovery-cache rows, update WalletAccount
scan/index metadata without changing its configuration, and write or clear the
durable discovery fence used by the ordinary read scanner. These are bounded
authenticated read-cache rows scoped to the exact existing account.

Every synchronized account snapshot carries two structurally distinct receive
projections. `ReceiveTarget` remains the ordinary `HnsCoin` change-zero target;
`HnsNameReceiveTarget` is selected only from `HnsName`, change zero, at the
post-scan account's exact `next_name_index`. Missing, wrong-role, wrong-account,
wrong-branch, wrong-index, or ambiguous name-target evidence fails the whole
read. This read projection does not allocate a key or change any value,
settlement, provider, or browser capability.

The ordinary non-value read runtime also exposes `import_name_exact_text` for
a trusted native caller. It performs no trimming, lowercasing, IDNA, Unicode
normalization, or dot handling. Valid text is checked before backend I/O, fresh
canonical evidence is classified against the exact derived `HnsName`
change-zero branch, and WalletAccount plus KnownName commit in one revision-
checked batch. Wallet-owned and incoming/outgoing-transfer evidence advances a
monotonic derivation high-water with the complete trailing gap; watch-only and
non-wallet evidence persists without advancing. The existing full-runtime raw
`import_name(&[u8])` API is unchanged.

Fresh synchronization also consumes the node's versioned incoming-TRANSFER
projection as discovery evidence for derived `HnsName` scripts. Such evidence
may advance only the name-key high-water: the stale old-owner TRANSFER output
never enters wallet balance, transaction, coin, or current ownership state. A
wallet-script FINALIZE becomes a new or refreshed `KnownName` only after the
node's exact-tip active-owner projection matches the exact name and canonical
coin byte for byte. This remains a read-only trusted projection, not proof or
spend authority; consensus-valid zero-valued name owner outputs are handled by
the same exact-match rule.

Its value and settlement configurations remain fail-closed until the embedding
product completes the documented adapter and runtime qualification. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
current gates.
