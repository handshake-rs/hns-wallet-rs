#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

python3 scripts/test-verify-release.py

if grep -Eq 'tar -(tf|xOf).*\|' scripts/publish.sh
then
    echo "error: archive verification must consume tar output before inspecting it" >&2
    exit 1
fi

assert_rejected() {
    expected=$1
    shift
    if output=$("$@" 2>&1)
    then
        echo "error: command unexpectedly succeeded: $*" >&2
        exit 1
    fi
    if ! printf '%s\n' "$output" | grep -Fq "$expected"
    then
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

assert_rejected \
    "irreversible publication requires --confirm-publish VERSION" \
    ./scripts/publish.sh --execute
assert_rejected \
    "irreversible publication requires --confirm-publish VERSION" \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION extra
assert_rejected \
    "PUBLISH_NEW_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_NEW_INTERVAL_SECONDS=invalid \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "PUBLISH_NEW_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_NEW_INTERVAL_SECONDS=-1 \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "PUBLISH_NEW_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_NEW_INTERVAL_SECONDS= \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "PUBLISH_UPDATE_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_UPDATE_INTERVAL_SECONDS=invalid \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "PUBLISH_UPDATE_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_UPDATE_INTERVAL_SECONDS=-1 \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "PUBLISH_UPDATE_INTERVAL_SECONDS must be a non-negative integer" \
    env PUBLISH_UPDATE_INTERVAL_SECONDS= \
    ./scripts/publish.sh --execute --confirm-publish CONFIRMED-VERSION
assert_rejected \
    "usage:" \
    ./scripts/publish.sh --dry-run hns-wallet-types extra
assert_rejected \
    "usage:" \
    ./scripts/publish.sh --archive-only hns-wallet-types extra
assert_rejected \
    "is not in the public package allowlist" \
    ./scripts/publish.sh --archive-only not-a-wallet-package

echo "publish argument validation passed"
