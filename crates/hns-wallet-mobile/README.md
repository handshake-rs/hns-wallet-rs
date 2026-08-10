# hns-wallet-mobile

`hns-wallet-mobile` is the platform-neutral native control boundary intended
for the Android and iOS application shells. It owns the private wallet host and
service in-process. Creation and restoration use the typed store bootstrap;
every subsequent control operation crosses the canonical wallet ABI v2 framing
and session checks.

The first release slice exposes only trusted native status, unlock, lock, and
single-account controls. It has no WebView/provider entry point, chain backend,
value action, marketplace transport, or release-gate authority. Android
Keystore and iOS Keychain integration remain responsibilities of the embedding
applications; raw database keys must never enter website content.
