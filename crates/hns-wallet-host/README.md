# hns-wallet-host

`hns-wallet-host` implements the fail-closed ABI-v2 caller state machine for
trusted browser and mobile adapters.

Its dedicated `hns_read_request` path requires the negotiated
`hnsReadOperationsV1` and `walletOperations` capabilities, admits only the six
fixed non-value HNS read requests, and fail-closes on cross-module,
cross-account, non-HNS-asset, or expanded-account response shapes. The generic
wallet request path remains unchanged for existing trusted control and mobile
callers.

It does not provide generated platform bindings or grant authority to website
content by itself. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
adapter contract and integration status.
