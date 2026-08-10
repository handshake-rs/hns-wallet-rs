#!/usr/bin/env bash
set -euo pipefail

wallet_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$wallet_root"

./scripts/check-publish-arguments.sh
./scripts/publish.sh --archive-only

if rg -n 'path\s*=\s*"\.\./' --glob Cargo.toml .; then
  echo "sibling path dependency is forbidden" >&2
  exit 1
fi

hns_revision="abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2"
hns_repository="https://github.com/handshake-rs/hns-rs.git"
hns_lock_source="git+${hns_repository}?rev=${hns_revision}#${hns_revision}"
for package in hns-covenants hns-encoding hns-marketplace-protocol hns-p2p-experimental hns-primitives hns-script hns-swap hns-transaction hns-urkel-proof; do
  if ! awk -v package="$package" -v source="$hns_lock_source" '
    BEGIN { RS = ""; found = 0 }
    index($0, "name = \"" package "\"") {
      found += 1
      if (!index($0, "source = \"" source "\"")) bad = 1
    }
    END { exit found != 1 || bad }
  ' Cargo.lock; then
    echo "$package must resolve exactly once from immutable hns-rs revision $hns_revision" >&2
    exit 1
  fi
done

for package in hns-covenants hns-marketplace-protocol hns-primitives hns-script hns-swap hns-transaction hns-urkel-proof; do
  declaration="$package = { version = \"=0.2.0\", git = \"$hns_repository\", rev = \"$hns_revision\" }"
  if ! rg --fixed-strings --line-regexp --quiet "$declaration" Cargo.toml; then
    echo "$package must use the reviewed immutable hns-rs source" >&2
    exit 1
  fi
done

if rg -n 'name = "(electrum-client|esplora-client|bitcoincore-rpc)"' Cargo.lock; then
  echo "alternate Bitcoin production backend found" >&2
  exit 1
fi

bdk_declaration='bdk_wallet = { version = "=3.1.0", features = ["keys-bip39"] }'
sqlite_declaration='rusqlite = { version = "=0.39.0", features = ["bundled", "fallible_uint"] }'
if ! rg --fixed-strings --line-regexp --quiet "$bdk_declaration" Cargo.toml; then
  echo "bdk_wallet must remain exactly pinned without its rusqlite feature" >&2
  exit 1
fi
if ! rg --fixed-strings --line-regexp --quiet "$sqlite_declaration" Cargo.toml; then
  echo "WalletStore rusqlite must remain on the sole reviewed 0.39.0 line" >&2
  exit 1
fi
for package_version in 'bdk_wallet 3.1.0' 'rusqlite 0.39.0' 'libsqlite3-sys 0.37.0'; do
  package="${package_version% *}"
  version="${package_version#* }"
  if ! awk -v package="$package" -v version="$version" '
    BEGIN { RS = ""; found = 0 }
    index($0, "name = \"" package "\"") {
      found += 1
      if (!index($0, "version = \"" version "\"")) bad = 1
    }
    END { exit found != 1 || bad }
  ' Cargo.lock; then
    echo "$package must resolve exactly once at $version" >&2
    exit 1
  fi
done
if ! awk '
  BEGIN { RS = ""; found = 0 }
  index($0, "name = \"bdk_chain\"") {
    found += 1
    if (index($0, "\n \"rusqlite\",")) bad = 1
  }
  END { exit found != 1 || bad }
' Cargo.lock; then
  echo "BDK's independent rusqlite persistence feature must remain disabled" >&2
  exit 1
fi

cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

contract_dir="$wallet_root/crates/hns-wallet-ethereum/contracts"
npm --prefix "$contract_dir" ci --ignore-scripts
npm --prefix "$contract_dir" audit --audit-level=high
npm --prefix "$contract_dir" run check

git diff --check
