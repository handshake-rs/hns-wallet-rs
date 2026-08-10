#!/usr/bin/env bash
set -euo pipefail

wallet_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$wallet_root"

if rg -n 'path\s*=\s*"\.\./' --glob Cargo.toml .; then
  echo "sibling path dependency is forbidden" >&2
  exit 1
fi

hns_revision="4331eee2265ebc43a28390517c24a958fa4b7733"
hns_repository="https://github.com/handshake-rs/hns-rs.git"
hns_lock_source="git+${hns_repository}?rev=${hns_revision}#${hns_revision}"
for package in hns-covenants hns-encoding hns-marketplace-protocol hns-primitives hns-script hns-swap hns-transaction hns-urkel-proof; do
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
