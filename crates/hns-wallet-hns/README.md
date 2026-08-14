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

Its value and settlement configurations remain fail-closed until the embedding
product completes the documented adapter and runtime qualification. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
current gates.
