#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
publish_interval_seconds=${PUBLISH_INTERVAL_SECONDS-605}
mode=${1:---dry-run}
requested_package=${2:-}
confirmed_version=${3:-}
argument_count=$#
release_commit=$(git rev-parse HEAD)
release_tmp=
require_clean_archive_vcs=no
package_operation="publish-dry-run"
release_manifest=release/public-crates.txt
protocol_repository=https://github.com/handshake-rs/hns-rs.git
protocol_revision=b24b66c382de53330ec21dd3137e056a2bea3e2d
protocol_version=0.2.0
protocol_crates='hns-encoding hns-primitives hns-covenants hns-dns-relay-protocol hns-header-consensus hns-service-authority hns-odoh-protocol hns-p2p-experimental hns-urkel-proof hns-transaction hns-chat-protocol hns-hnsr-protocol hns-script hns-mining hns-swap hns-marketplace-protocol hns-p2p-wire'

cleanup_release_tmp() {
    if [ -n "$release_tmp" ] && [ -d "$release_tmp" ]
    then
        rm -rf -- "$release_tmp"
    fi
}

trap cleanup_release_tmp EXIT HUP INT TERM

usage() {
    echo "usage: $0 [--archive-only [PUBLIC-PACKAGE]|--dry-run [PUBLIC-PACKAGE]|--execute --confirm-publish VERSION]" >&2
}

ensure_release_tmp() {
    if [ -z "$release_tmp" ]
    then
        release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/hns-wallet-rs-release.XXXXXX")
    fi
}

public_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$release_manifest")

last_public_crate=
for package in $public_crates
do
    last_public_crate=$package
done

require_public_crate() {
    requested=$1
    for package in $public_crates
    do
        if [ "$package" = "$requested" ]
        then
            return
        fi
    done
    echo "error: $requested is not in the public package allowlist" >&2
    exit 2
}

dry_run_package() {
    package=$1
    shift
    if [ "$package_operation" = "archive-only" ]
    then
        cargo +"$rust_toolchain" package \
            --locked \
            --no-verify \
            --allow-dirty \
            -p "$package" \
            "$@"
    else
        cargo +"$rust_toolchain" publish \
            --locked \
            --dry-run \
            --allow-dirty \
            -p "$package" \
            "$@"
    fi
}

dry_run_with_local_dependencies() {
    package=$1
    case "$package" in
        hns-wallet-types)
            dry_run_package "$package"
            ;;
        hns-wallet-store|hns-wallet-chain-api)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-ffi)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-provider)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-hns)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-script.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-script.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-swap.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-swap.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-transaction.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-transaction.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-urkel-proof.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-urkel-proof.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-market)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-marketplace-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-marketplace-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-shakedex)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-marketplace-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-marketplace-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-script.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-script.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-swap.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-swap.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-transaction.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-transaction.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-bitcoin-kyoto)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-ethereum)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-host)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-service)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-script.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-script.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-swap.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-swap.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-transaction.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-transaction.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-urkel-proof.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-urkel-proof.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-provider.path="crates/hns-wallet-provider"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-testkit)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-marketplace-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-marketplace-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-script.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-script.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-swap.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-swap.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-transaction.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-transaction.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-urkel-proof.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-urkel-proof.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-bitcoin-kyoto.path="crates/hns-wallet-bitcoin-kyoto"' \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-ethereum.path="crates/hns-wallet-ethereum"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-market.path="crates/hns-wallet-market"' \
                --config 'patch.crates-io.hns-wallet-provider.path="crates/hns-wallet-provider"' \
                --config 'patch.crates-io.hns-wallet-shakedex.path="crates/hns-wallet-shakedex"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-mobile)
            dry_run_package "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-script.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-script.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-swap.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-swap.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-transaction.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-transaction.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-urkel-proof.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-urkel-proof.rev=\"$protocol_revision\"" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-host.path="crates/hns-wallet-host"' \
                --config 'patch.crates-io.hns-wallet-provider.path="crates/hns-wallet-provider"' \
                --config 'patch.crates-io.hns-wallet-service.path="crates/hns-wallet-service"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        *)
            echo "error: missing dry-run dependency mapping for $package" >&2
            exit 1
            ;;
    esac
}

package_version() {
    package=$1
    package_id=$(cargo +"$rust_toolchain" pkgid -p "$package")
    version=${package_id##*@}
    if [ "$version" = "$package_id" ]
    then
        version=${package_id##*#}
    fi
    printf '%s\n' "$version"
}

package_target_dir() {
    cargo +"$rust_toolchain" metadata \
        --locked \
        --no-deps \
        --format-version 1 |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

verify_archive_entry() {
    package=$1
    archive=$2
    archive_root=$3
    relative_path=$4
    ensure_release_tmp
    archive_listing=$(mktemp "$release_tmp/archive-listing.XXXXXX")
    if ! tar -tf "$archive" > "$archive_listing"
    then
        echo "error: unable to read normalized $package package archive" >&2
        exit 1
    fi
    if ! grep -Fqx "$archive_root/$relative_path" "$archive_listing"
    then
        echo "error: normalized $package package omits $relative_path" >&2
        exit 1
    fi
}

verify_archive_copy() {
    package=$1
    archive=$2
    archive_root=$3
    relative_path=$4
    repository_path=$5
    verify_archive_entry "$package" "$archive" "$archive_root" "$relative_path"
    archive_copy=$(mktemp "$release_tmp/archive-copy.XXXXXX")
    if ! tar -xOf "$archive" "$archive_root/$relative_path" > "$archive_copy"
    then
        echo "error: unable to extract normalized $package $relative_path" >&2
        exit 1
    fi
    if ! cmp -s "$archive_copy" "$repository_path"
    then
        echo "error: normalized $package $relative_path differs from $repository_path" >&2
        exit 1
    fi
}

verify_common_source_package() {
    package=$1
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    if [ ! -f "$archive" ]
    then
        echo "error: Cargo did not create $archive" >&2
        exit 1
    fi

    for relative_path in \
        .cargo_vcs_info.json \
        Cargo.toml \
        Cargo.toml.orig \
        CHANGELOG.md \
        LICENSE-APACHE \
        LICENSE-MIT \
        README.md
    do
        verify_archive_entry "$package" "$archive" "$archive_root" "$relative_path"
    done

    normalized_manifest=$(tar -xOf "$archive" "$archive_root/Cargo.toml")
    # Normalized manifests may retain target paths under [lib], [[test]],
    # [[example]], and [[bench]]. Dependency source selectors must not survive.
    if printf '%s\n' "$normalized_manifest" |
        awk '
            /^[[:space:]]*\[/ {
                header = $0
                gsub(/[[:space:]]/, "", header)
                in_dependency_table = \
                    header ~ /^\[(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[target\..+\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[workspace\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/
                next
            }
            in_dependency_table && \
                /(^|[[:space:]{,])(path|git|branch|tag|rev)[[:space:]]*=/ {
                found = 1
                exit
            }
            END { exit found ? 0 : 1 }
        '
    then
        echo "error: normalized $package manifest retains a dependency source selector" >&2
        exit 1
    fi

    vcs_info=$(tar -xOf "$archive" "$archive_root/.cargo_vcs_info.json")
    compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
    case "$compact_vcs_info" in
        *\"sha1\":\"$release_commit\"*) ;;
        *)
            echo "error: normalized $package package does not identify source commit $release_commit" >&2
            exit 1
            ;;
    esac
    if [ "$require_clean_archive_vcs" = "yes" ]
    then
        case "$compact_vcs_info" in
            *\"dirty\":true*)
                echo "error: normalized $package package records a dirty source tree" >&2
                exit 1
                ;;
        esac
    fi
}

verify_ffi_source_package() {
    package=hns-wallet-ffi
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    for name in contracts-v2.schema.json golden-vectors-v2.json
    do
        verify_archive_copy "$package" "$archive" "$archive_root" \
            "abi/$name" "abi/$name"
    done
}

verify_ethereum_source_package() {
    package=hns-wallet-ethereum
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    for relative_path in \
        contracts/README.md \
        contracts/compile.mjs \
        contracts/package-lock.json \
        contracts/package.json \
        contracts/src/NativeEthHtlc.sol \
        contracts/artifacts/NativeEthHtlc.json
    do
        verify_archive_copy "$package" "$archive" "$archive_root" \
            "$relative_path" "crates/$package/$relative_path"
    done
}

verify_source_package() {
    package=$1
    verify_common_source_package "$package"
    case "$package" in
        hns-wallet-ffi) verify_ffi_source_package ;;
        hns-wallet-ethereum) verify_ethereum_source_package ;;
    esac
}

create_source_package() {
    package=$1
    allow_dirty=$2

    if [ "$allow_dirty" = "yes" ]
    then
        cargo +"$rust_toolchain" package \
            --locked \
            --no-verify \
            --allow-dirty \
            -p "$package"
    else
        cargo +"$rust_toolchain" package \
            --locked \
            --no-verify \
            -p "$package"
    fi
    verify_source_package "$package"
}

verify_published_package() {
    package=$1
    version=$2
    package_target=$(package_target_dir)
    local_archive="$package_target/package/$package-$version.crate"

    if [ ! -f "$local_archive" ]
    then
        echo "error: Cargo did not create $local_archive" >&2
        exit 1
    fi
    # The execute loop creates and validates this archive exactly once before
    # deciding whether to upload or resume. Cargo publish may recreate it, so
    # recheck its inventory without repeating package construction.
    verify_source_package "$package"

    ensure_release_tmp
    published_archive="$release_tmp/$package-$version.crate"
    curl \
        --fail \
        --location \
        --silent \
        --show-error \
        --user-agent "hns-wallet-rs-release/$version (https://github.com/handshake-rs/hns-wallet-rs)" \
        --output "$published_archive" \
        "https://crates.io/api/v1/crates/$package/$version/download"

    local_checksum=$(sha256sum "$local_archive" | awk '{print $1}')
    published_checksum=$(sha256sum "$published_archive" | awk '{print $1}')
    if [ "$local_checksum" != "$published_checksum" ]
    then
        echo "error: published $package $version differs from the current source package" >&2
        echo "error: local checksum $local_checksum; published checksum $published_checksum" >&2
        exit 1
    fi

    for archive in "$local_archive" "$published_archive"
    do
        vcs_info=$(tar -xOf "$archive" "$package-$version/.cargo_vcs_info.json")
        compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
        case "$compact_vcs_info" in
            *\"sha1\":\"$release_commit\"*) ;;
            *)
                echo "error: $archive does not identify release commit $release_commit" >&2
                exit 1
                ;;
        esac
        case "$compact_vcs_info" in
            *\"dirty\":true*)
                echo "error: $archive records a dirty source tree" >&2
                exit 1
                ;;
        esac
    done
}

published_package_status() {
    package=$1
    version=$2
    curl \
        --silent \
        --show-error \
        --user-agent "hns-wallet-rs-release/$version (https://github.com/handshake-rs/hns-wallet-rs)" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/$package/$version"
}

verify_protocol_packages_published() {
    ensure_release_tmp
    for package in $protocol_crates
    do
        status=$(published_package_status "$package" "$protocol_version")
        if [ "$status" != "200" ]
        then
            echo "error: required protocol package $package $protocol_version is not published (HTTP $status)" >&2
            exit 1
        fi

        protocol_archive="$release_tmp/$package-$protocol_version.crate"
        curl \
            --fail \
            --location \
            --silent \
            --show-error \
            --user-agent "hns-wallet-rs-release/$protocol_version (https://github.com/handshake-rs/hns-wallet-rs)" \
            --output "$protocol_archive" \
            "https://crates.io/api/v1/crates/$package/$protocol_version/download"
        protocol_vcs_info="$release_tmp/$package-$protocol_version.cargo_vcs_info.json"
        if ! tar -xOf \
            "$protocol_archive" \
            "$package-$protocol_version/.cargo_vcs_info.json" \
            > "$protocol_vcs_info"
        then
            echo "error: required protocol package $package $protocol_version has no readable VCS identity" >&2
            exit 1
        fi
        protocol_vcs_sha=$(python3 -c \
            'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["git"]["sha1"])' \
            "$protocol_vcs_info")
        if [ "$protocol_vcs_sha" != "$protocol_revision" ]
        then
            echo "error: required protocol package $package $protocol_version identifies source $protocol_vcs_sha, expected $protocol_revision" >&2
            exit 1
        fi
        protocol_vcs_dirty=$(python3 -c \
            'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["git"].get("dirty", False)).lower())' \
            "$protocol_vcs_info")
        if [ "$protocol_vcs_dirty" = "true" ]
        then
            echo "error: required protocol package $package $protocol_version records a dirty source tree" >&2
            exit 1
        fi
    done
    echo "verified all 17 hns-rs $protocol_version archives at source $protocol_revision"
}

verify_new_upload() {
    package=$1
    version=$2

    if [ "$package" != "$last_public_crate" ] &&
        [ "$publish_interval_seconds" != "0" ]
    then
        echo "waiting ${publish_interval_seconds}s for crates.io propagation and cooldown"
        sleep "$publish_interval_seconds"
    fi

    status=$(published_package_status "$package" "$version")
    case "$status" in
        200)
            verify_published_package "$package" "$version"
            echo "verified newly published $package $version against source $release_commit"
            ;;
        404)
            echo "error: published $package $version is not yet visible for exact verification" >&2
            echo "error: rerun the same execute command after crates.io propagation; resume verification will not republish it" >&2
            exit 1
            ;;
        *)
            echo "error: crates.io returned HTTP $status while verifying newly published $package $version" >&2
            exit 1
            ;;
    esac
}

case "$mode" in
    --archive-only)
        if [ "$argument_count" -gt 2 ]
        then
            usage
            exit 2
        fi
        package_operation="archive-only"
        if [ -n "$requested_package" ]
        then
            require_public_crate "$requested_package"
        fi
        python3 scripts/verify-release.py --toolchain "$rust_toolchain"
        if [ -n "$requested_package" ]
        then
            dry_run_with_local_dependencies "$requested_package"
            verify_source_package "$requested_package"
        else
            for package in $public_crates
            do
                dry_run_with_local_dependencies "$package"
                verify_source_package "$package"
            done
        fi
        ;;
    --dry-run)
        if [ "$argument_count" -gt 2 ]
        then
            usage
            exit 2
        fi
        python3 scripts/verify-release.py --toolchain "$rust_toolchain"
        if [ -n "$requested_package" ]
        then
            require_public_crate "$requested_package"
            dry_run_with_local_dependencies "$requested_package"
            verify_source_package "$requested_package"
        else
            for package in $public_crates
            do
                dry_run_with_local_dependencies "$package"
                verify_source_package "$package"
            done
        fi
        ;;
    --execute)
        if [ "$argument_count" -ne 3 ] ||
            [ "$requested_package" != "--confirm-publish" ] ||
            [ -z "$confirmed_version" ]
        then
            echo "error: irreversible publication requires --confirm-publish VERSION" >&2
            exit 2
        fi
        case "$publish_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        python3 scripts/verify-release.py \
            --toolchain "$rust_toolchain" \
            --require-clean \
            --expected-version "$confirmed_version"
        require_clean_archive_vcs=yes
        verify_protocol_packages_published

        cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] &&
            [ ! -f "$cargo_home/credentials.toml" ]
        then
            echo "error: no crates.io credential found; run cargo login" >&2
            exit 1
        fi

        for package in $public_crates
        do
            version=$(package_version "$package")
            # Construct and inspect the exact normalized archive before either
            # an irreversible upload or an exact-checksum resume decision.
            create_source_package "$package" no
            status=$(published_package_status "$package" "$version")
            case "$status" in
                200)
                    verify_published_package "$package" "$version"
                    echo "skipping $package $version: already published"
                    ;;
                404)
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    verify_new_upload "$package" "$version"
                    ;;
                *)
                    echo "error: crates.io returned HTTP $status for $package $version" >&2
                    exit 1
                    ;;
            esac
        done
        ;;
    *)
        usage
        exit 2
        ;;
esac
