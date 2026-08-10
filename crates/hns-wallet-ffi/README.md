# hns-wallet-ffi

`hns-wallet-ffi` defines the bounded private ABI-v2 frames used between the
wallet service and trusted Android, iOS, or Chromium hosts.

The packaged `abi/` directory contains the canonical JSON schema and bounded
golden vectors for this version. The ABI is not a website-facing authority and
does not enable provider or value gates. See the
[workspace repository](https://github.com/handshake-rs/hns-wallet-rs) for the
integration and release status.
