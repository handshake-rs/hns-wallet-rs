#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
publish_new_interval_seconds=${PUBLISH_NEW_INTERVAL_SECONDS-605}
publish_update_interval_seconds=${PUBLISH_UPDATE_INTERVAL_SECONDS-65}
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
protocol_revision=0e99addca59778b7b7c6fc56291333a97c4c8815
protocol_version=0.3.1
protocol_crates='hns-encoding hns-rollback-journal hns-hrm hns-primitives hns-covenants hns-dns-relay-protocol hns-header-consensus hns-service-authority hns-odoh-protocol hns-urkel-proof hns-transaction hns-chat-protocol hns-hnsr-protocol hns-script hns-mining hns-swap hns-p2p-wire'
protocol_checksum_manifest=release/hns-rs-core-0.3.1-crates.sha256
shakescape_protocol_revision=c8feb6f90f3e03efbb982a5e33192dda6fd2f37a
shakescape_protocol_version=0.4.0
shakescape_protocol_crates='hns-p2p-experimental hns-marketplace-protocol'
shakescape_protocol_checksum_manifest=release/hns-rs-shakescape-0.4.0-crates.sha256
engine_repository=https://github.com/handshake-rs/hns-dane-engine.git
engine_revision=b7fdf8826c81b77650a0f740d1f05314b74969f9
engine_version=0.2.2
engine_crates='hns-dns-wire hns-browser-runtime hns-icann-dane hns-namespace-resolution hns-resolution-policy hns-light-chain hns-light-wallet hns-dane hns-dnssec hns-gateway hns-cache hns-light-p2p hns-light-sync hns-transport hns-resolver hns-browser-observability hns-p2p-transport hns-dane-engine hns-dane-engine-ffi hns-loopback-proxy'
engine_checksum_manifest=release/hns-dane-engine-0.2.2-crates.sha256

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
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-provider)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-hns)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-market)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-bitcoin-kyoto.path="crates/hns-wallet-bitcoin-kyoto"' \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-shakedex)
            dry_run_package "$package" \
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
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-service)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-provider.path="crates/hns-wallet-provider"' \
                --config 'patch.crates-io.hns-wallet-shakedex.path="crates/hns-wallet-shakedex"' \
                --config 'patch.crates-io.hns-wallet-store.path="crates/hns-wallet-store"' \
                --config 'patch.crates-io.hns-wallet-types.path="crates/hns-wallet-types"'
            ;;
        hns-wallet-testkit)
            dry_run_package "$package" \
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
                --config 'patch.crates-io.hns-wallet-bitcoin-kyoto.path="crates/hns-wallet-bitcoin-kyoto"' \
                --config 'patch.crates-io.hns-wallet-chain-api.path="crates/hns-wallet-chain-api"' \
                --config 'patch.crates-io.hns-wallet-ffi.path="crates/hns-wallet-ffi"' \
                --config 'patch.crates-io.hns-wallet-hns.path="crates/hns-wallet-hns"' \
                --config 'patch.crates-io.hns-wallet-host.path="crates/hns-wallet-host"' \
                --config 'patch.crates-io.hns-wallet-market.path="crates/hns-wallet-market"' \
                --config 'patch.crates-io.hns-wallet-provider.path="crates/hns-wallet-provider"' \
                --config 'patch.crates-io.hns-wallet-shakedex.path="crates/hns-wallet-shakedex"' \
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

create_registry_source_package() {
    package=$1
    cargo +"$rust_toolchain" publish \
        --locked \
        --dry-run \
        -p "$package"
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
    # The caller constructs the correct path-specific archive first: Cargo's
    # registry-backed publish dry-run for resume, or the actual publish for a
    # new upload. Recheck its inventory without repeating construction.
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

published_crate_status() {
    package=$1
    version=$2
    curl \
        --silent \
        --show-error \
        --user-agent "hns-wallet-rs-release/$version (https://github.com/handshake-rs/hns-wallet-rs)" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/$package"
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

manifest_checksum() {
    manifest=$1
    filename=$2
    checksum=$(awk -v filename="$filename" '$2 == filename { count += 1; value = $1 } END { if (count == 1 && value ~ /^[0-9a-f]{64}$/) print value; else exit 1 }' "$manifest")
    if [ -z "$checksum" ]
    then
        echo "error: $manifest has no unique SHA-256 for $filename" >&2
        exit 1
    fi
    printf '%s\n' "$checksum"
}

verify_published_cohort() {
    cohort=$1
    repository=$2
    revision=$3
    version=$4
    crates=$5
    checksum_manifest=$6

    if [ ! -f "$checksum_manifest" ]
    then
        echo "error: $cohort checksum manifest $checksum_manifest is missing" >&2
        exit 1
    fi

    ensure_release_tmp
    for package in $crates
    do
        filename="$package-$version.crate"
        expected_checksum=$(manifest_checksum "$checksum_manifest" "$filename")
        status=$(published_package_status "$package" "$version")
        if [ "$status" != "200" ]
        then
            echo "error: required $cohort package $package $version is not published (HTTP $status)" >&2
            exit 1
        fi

        cohort_metadata="$release_tmp/$package-$version.metadata.json"
        curl \
            --fail \
            --location \
            --silent \
            --show-error \
            --user-agent "hns-wallet-rs-release/$version (https://github.com/handshake-rs/hns-wallet-rs)" \
            --output "$cohort_metadata" \
            "https://crates.io/api/v1/crates/$package/$version"
        cohort_api_checksum=$(python3 -c \
            'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"]["checksum"])' \
            "$cohort_metadata")
        cohort_yanked=$(python3 -c \
            'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["version"]["yanked"]).lower())' \
            "$cohort_metadata")
        if [ "$cohort_api_checksum" != "$expected_checksum" ]
        then
            echo "error: required $cohort package $package $version API checksum differs from $checksum_manifest" >&2
            exit 1
        fi
        if [ "$cohort_yanked" != "false" ]
        then
            echo "error: required $cohort package $package $version is yanked" >&2
            exit 1
        fi

        cohort_archive="$release_tmp/$filename"
        curl \
            --fail \
            --location \
            --silent \
            --show-error \
            --user-agent "hns-wallet-rs-release/$version (https://github.com/handshake-rs/hns-wallet-rs)" \
            --output "$cohort_archive" \
            "https://crates.io/api/v1/crates/$package/$version/download"
        observed_checksum=$(sha256sum "$cohort_archive" | awk '{print $1}')
        if [ "$observed_checksum" != "$expected_checksum" ]
        then
            echo "error: required $cohort package $package $version archive checksum differs from $checksum_manifest" >&2
            exit 1
        fi

        cohort_vcs_info="$release_tmp/$package-$version.cargo_vcs_info.json"
        if ! tar -xOf \
            "$cohort_archive" \
            "$package-$version/.cargo_vcs_info.json" \
            > "$cohort_vcs_info"
        then
            echo "error: required $cohort package $package $version has no readable VCS identity" >&2
            exit 1
        fi
        cohort_vcs_sha=$(python3 -c \
            'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["git"]["sha1"])' \
            "$cohort_vcs_info")
        cohort_vcs_dirty=$(python3 -c \
            'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["git"].get("dirty", False)).lower())' \
            "$cohort_vcs_info")
        cohort_vcs_path=$(python3 -c \
            'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("path_in_vcs", ""))' \
            "$cohort_vcs_info")
        if [ "$cohort_vcs_sha" != "$revision" ]
        then
            echo "error: required $cohort package $package $version identifies source $cohort_vcs_sha, expected $revision from $repository" >&2
            exit 1
        fi
        if [ "$cohort_vcs_dirty" = "true" ]
        then
            echo "error: required $cohort package $package $version records a dirty source tree" >&2
            exit 1
        fi
        if [ "$cohort_vcs_path" != "crates/$package" ]
        then
            echo "error: required $cohort package $package $version VCS path $cohort_vcs_path is not crates/$package" >&2
            exit 1
        fi
    done
    echo "verified published $cohort $version archives at source $revision"
}

verify_protocol_packages_published() {
    verify_published_cohort \
        hns-rs \
        "$protocol_repository" \
        "$protocol_revision" \
        "$protocol_version" \
        "$protocol_crates" \
        "$protocol_checksum_manifest"
    verify_published_cohort \
        hns-rs-shakescape \
        "$protocol_repository" \
        "$shakescape_protocol_revision" \
        "$shakescape_protocol_version" \
        "$shakescape_protocol_crates" \
        "$shakescape_protocol_checksum_manifest"
}

verify_engine_packages_published() {
    verify_published_cohort \
        hns-dane-engine \
        "$engine_repository" \
        "$engine_revision" \
        "$engine_version" \
        "$engine_crates" \
        "$engine_checksum_manifest"
}

verify_release_source_unchanged() {
    if [ "$(git rev-parse HEAD)" != "$release_commit" ] ||
        [ -n "$(git status --porcelain)" ]
    then
        echo "error: release source changed after execute preflight" >&2
        exit 1
    fi
}

verify_new_upload() {
    package=$1
    version=$2
    publish_interval_seconds=$3
    publish_kind=$4

    if [ "$package" != "$last_public_crate" ] &&
        [ "$publish_interval_seconds" != "0" ]
    then
        echo "waiting ${publish_interval_seconds}s for crates.io propagation and $publish_kind cooldown"
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
        case "$publish_new_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_NEW_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        case "$publish_update_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_UPDATE_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        python3 scripts/verify-release.py \
            --toolchain "$rust_toolchain" \
            --require-clean \
            --expected-version "$confirmed_version"
        require_clean_archive_vcs=yes
        verify_protocol_packages_published
        verify_engine_packages_published
        verify_release_source_unchanged

        cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] &&
            [ ! -f "$cargo_home/credentials.toml" ]
        then
            echo "error: no crates.io credential found; run cargo login" >&2
            exit 1
        fi

        for package in $public_crates
        do
            verify_release_source_unchanged
            version=$(package_version "$package")
            status=$(published_package_status "$package" "$version")
            case "$status" in
                200)
                    # Reproduce the uploaded Cargo.lock through Cargo's
                    # registry-backed publish path. A local workspace package
                    # omits registry source/checksum fields and is not an exact
                    # resume artifact once its dependencies are published.
                    create_registry_source_package "$package"
                    verify_published_package "$package" "$version"
                    echo "skipping $package $version: already published and verified"
                    ;;
                404)
                    crate_status=$(published_crate_status "$package" "$version")
                    case "$crate_status" in
                        200)
                            publish_interval_seconds=$publish_update_interval_seconds
                            publish_kind=existing-crate-update
                            ;;
                        404)
                            publish_interval_seconds=$publish_new_interval_seconds
                            publish_kind=new-crate-name
                            ;;
                        *)
                            echo "error: crates.io returned HTTP $crate_status while classifying $package" >&2
                            exit 1
                            ;;
                    esac
                    # Construct and inspect the normalized archive before the
                    # irreversible upload. cargo publish then replaces it with
                    # the registry-backed archive used for exact verification.
                    create_source_package "$package" no
                    verify_release_source_unchanged
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    verify_new_upload \
                        "$package" \
                        "$version" \
                        "$publish_interval_seconds" \
                        "$publish_kind"
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
