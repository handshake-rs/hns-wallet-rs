#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

public_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    release/public-crates.txt)

for package in $public_crates
do
    cp -- LICENSE-APACHE "crates/$package/LICENSE-APACHE"
    cp -- LICENSE-MIT "crates/$package/LICENSE-MIT"
    cp -- release/CRATE-CHANGELOG.md "crates/$package/CHANGELOG.md"
done

mkdir -p crates/hns-wallet-ffi/abi
cp -- abi/contracts-v2.schema.json \
    crates/hns-wallet-ffi/abi/contracts-v2.schema.json
cp -- abi/golden-vectors-v2.json \
    crates/hns-wallet-ffi/abi/golden-vectors-v2.json
