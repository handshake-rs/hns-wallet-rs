# hns-wallet-host

`hns-wallet-host` implements the fail-closed ABI-v2 caller state machine for
trusted browser and mobile adapters.

Its dedicated `hns_read_request` path requires the negotiated
`hnsReadOperationsV1` and `walletOperations` capabilities, admits only the six
fixed non-value HNS read requests, and fail-closes on cross-module,
cross-account, non-HNS-asset, or expanded-account response shapes. The generic
wallet request path remains unchanged for existing trusted control and mobile
callers.

The separate `hns_wallet_authority_context_request` path additionally requires
`hnsWalletAuthorityContextV1`, keeps the broker claim outside the six-read
enum, and accepts only an exact canonical network/magic and nonzero namespace/
lease-generation echo with positive persistent wallet/account revision and
lifecycle evidence. The accepted value is evidence only: this crate does not
create or retain the HRM/HNSA broker guard, and a product must compare the
evidence under that independently held guard before and after dependent use.

It does not provide generated platform bindings or grant authority to website
content by itself. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
adapter contract and integration status.
