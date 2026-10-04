#!/usr/bin/env python3
"""Cheap regressions for release-state validation; does not invoke Cargo."""

from __future__ import annotations

import runpy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable


REPO = Path(__file__).resolve().parent.parent
CURRENT_RELEASE_VERSION = "0.4.3"
VALIDATOR = runpy.run_path(str(REPO / "scripts/verify-release.py"))
verify_state = VALIDATOR["changelog_release_state"]
require_execution_state = VALIDATOR["require_execution_release_state"]
release_order = VALIDATOR["release_order"]
verify_release_document = VALIDATOR["verify_release_document"]
verify_publish_script_safety = VALIDATOR["verify_publish_script_safety"]
crate_wording = VALIDATOR["CRATE_RELEASE_STATE_WORDING"]


def expect_failure(fragment: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except SystemExit as error:
        if fragment not in str(error):
            raise AssertionError(
                f"expected failure containing {fragment!r}, observed {error!s}"
            ) from error
    else:
        raise AssertionError(f"operation unexpectedly succeeded; wanted {fragment!r}")


def replace_once(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise AssertionError(f"mutation source is not unique: {before!r}")
    return source.replace(before, after, 1)


def expect_publish_script_mutation(
    failure: str, before: str, after: str, *, check_document: bool = False
) -> None:
    source = (REPO / "scripts/publish.sh").read_text(encoding="utf-8")
    mutated = replace_once(source, before, after)
    with TemporaryDirectory(prefix="hns-wallet-release-mutation-") as directory:
        repo = Path(directory)
        scripts = repo / "scripts"
        scripts.mkdir()
        (scripts / "publish.sh").write_text(mutated, encoding="utf-8")
        if check_document:
            docs = repo / "docs"
            docs.mkdir()
            (docs / "releasing.md").write_bytes(
                (REPO / "docs/releasing.md").read_bytes()
            )
            expect_failure(
                failure,
                lambda: verify_release_document(
                    repo, release_order(REPO), CURRENT_RELEASE_VERSION
                ),
            )
        else:
            expect_failure(failure, lambda: verify_publish_script_safety(repo))


version = CURRENT_RELEASE_VERSION
candidate = (f"# Package release\n\n## {version} - unreleased\n\n"
             f"<!-- hns-wallet-release-state: {version} candidate -->\n"
             f"{crate_wording['candidate']}\n")

def state(document):
    return verify_state(document, "package/CHANGELOG.md", version, crate_wording)

assert state(candidate) == "candidate"
expect_failure("execution requires canonical release-state wording",
               lambda: require_execution_state(state(candidate)))
for modified, error in (
    (candidate.replace(crate_wording['candidate'], ""), "does not use canonical wording"),
    (candidate.replace(f"<!-- hns-wallet-release-state: {version} candidate -->", ""), "exactly one canonical release-state marker"),
    (candidate.replace(f"{version} candidate", f"{version} release"), "does not use canonical wording"),
    (candidate + f"<!-- hns-wallet-release-state: {version} candidate -->\n", "exactly one canonical release-state marker"),
):
    expect_failure(error, lambda document=modified: state(document))
release = candidate.replace(f"{version} candidate", f"{version} release").replace(
    crate_wording['candidate'], crate_wording['release'])
assert state(release) == "release"
require_execution_state(state(release))

# The executable release path must preserve the registry-backed reconstruction,
# exact crate-name classification endpoint, both independent cooldown buckets,
# and a catch-all error for an indeterminate registry response.
verify_release_document(REPO, release_order(REPO), CURRENT_RELEASE_VERSION)
verify_publish_script_safety(REPO)

expect_publish_script_mutation(
    "registry-backed resume package construction omits '--dry-run'",
    """create_registry_source_package() {
    package=$1
    cargo +\"$rust_toolchain\" publish \\
        --locked \\
        --dry-run \\
        -p \"$package\"
    verify_source_package \"$package\"
}""",
    """create_registry_source_package() {
    package=$1
    cargo +\"$rust_toolchain\" publish \\
        --locked \\
        --no-verify \\
        -p \"$package\"
    verify_source_package \"$package\"
}""",
)
expect_publish_script_mutation(
    "crate-name classification must query the exact crates.io name endpoint",
    '        "https://crates.io/api/v1/crates/$package"\n',
    '        "https://crates.io/api/v1/crates/$package/$version"\n',
)
expect_publish_script_mutation(
    "crate-name classification must reject every unexpected HTTP status",
    """                        *)
                            echo \"error: crates.io returned HTTP $crate_status while classifying $package\" >&2
                            exit 1
""",
    """                        429)
                            echo \"error: crates.io returned HTTP $crate_status while classifying $package\" >&2
                            exit 1
""",
)
expect_publish_script_mutation(
    "execute path is incomplete",
    """                    create_registry_source_package \"$package\"
                    verify_published_package \"$package\" \"$version\"
""",
    """                    create_source_package \"$package\" no
                    verify_published_package \"$package\" \"$version\"
""",
)
expect_publish_script_mutation(
    "docs/releasing.md omits the new-name interval default",
    "publish_new_interval_seconds=${PUBLISH_NEW_INTERVAL_SECONDS-605}",
    "publish_new_interval_seconds=${PUBLISH_NEW_INTERVAL_SECONDS-606}",
    check_document=True,
)
expect_publish_script_mutation(
    "docs/releasing.md omits the existing-crate update interval default",
    "publish_update_interval_seconds=${PUBLISH_UPDATE_INTERVAL_SECONDS-65}",
    "publish_update_interval_seconds=${PUBLISH_UPDATE_INTERVAL_SECONDS-66}",
    check_document=True,
)

print("release validator mutation regressions passed")

accepts = VALIDATOR["internal_requirement_accepts"]
assert accepts("^0.4.1", "0.4.2")
assert accepts("^0.4.1", "0.4.1")
assert not accepts("^0.4.2", "0.4.1")
assert not accepts("^0.4.1", "0.5.0")
assert not accepts("^0.0.1", "0.0.2")
expect_publish_script_mutation(
    "execution must select exactly one public package",
    'for package in "$requested_package"',
    'for package in $public_crates',
)
