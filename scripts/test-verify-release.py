#!/usr/bin/env python3
"""Cheap regressions for release-state validation; does not invoke Cargo."""

from __future__ import annotations

import runpy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable


REPO = Path(__file__).resolve().parent.parent
CURRENT_RELEASE_VERSION = "0.2.1"
VALIDATOR = runpy.run_path(str(REPO / "scripts/verify-release.py"))
verify_state = VALIDATOR["verify_changelog_release_state"]
require_execution_state = VALIDATOR["require_execution_release_state"]
release_order = VALIDATOR["release_order"]
verify_release_document = VALIDATOR["verify_release_document"]
verify_publish_script_safety = VALIDATOR["verify_publish_script_safety"]
root_wording = VALIDATOR["ROOT_RELEASE_STATE_WORDING"]
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


root_candidate = (
    "# Synthetic root changelog\n\n## 0.1.0 - 2026-08-10\n\n"
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n"
    f"{root_wording['candidate']}\n"
)
crate_candidate = (
    "# Synthetic crate changelog\n\n## 0.1.0 - 2026-08-10\n\n"
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n"
    f"{crate_wording['candidate']} See the canonical workspace changelog.\n"
)

state = verify_state(root_candidate, crate_candidate, "0.1.0")
assert state == "candidate"
expect_failure(
    "execution requires canonical release-state wording",
    lambda: require_execution_state(state),
)

# A later version can retain an older versioned marker and wording without
# confusing validation of the selected workspace version.
root_with_history = (
    root_candidate
    + "\n## 0.0.9 - 2026-08-09\n\n"
    + "<!-- hns-wallet-release-state: 0.0.9 release -->\n"
    + f"{root_wording['release']}\n"
)
assert verify_state(root_with_history, crate_candidate, "0.1.0") == "candidate"

# Rephrasing or deleting the prose no longer bypasses execute mode: the
# authoritative candidate marker remains candidate, and malformed state blocks
# are independently rejected during every dry-run/archive/execute validation.
rephrased_root = root_candidate.replace(
    "Unpublished initial release candidate for the independent Handshake wallet\n"
    "boundary:",
    "Unpublished 0.1.0 wallet candidate:",
)
expect_failure(
    "does not use canonical wording for release state 'candidate'",
    lambda: verify_state(rephrased_root, crate_candidate, "0.1.0"),
)
deleted_root_wording = root_candidate.replace(
    "Unpublished initial release candidate for the independent Handshake wallet\n"
    "boundary:\n",
    "",
)
expect_failure(
    "does not use canonical wording for release state 'candidate'",
    lambda: verify_state(deleted_root_wording, crate_candidate, "0.1.0"),
)
deleted_root_marker = root_candidate.replace(
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n", ""
)
expect_failure(
    "exactly one canonical release-state marker",
    lambda: verify_state(deleted_root_marker, crate_candidate, "0.1.0"),
)
rephrased_crate = crate_candidate.replace(
    "This heading describes the current unpublished release candidate, not an\n"
    "existing crates.io package, Git tag, or GitHub release.",
    "This package is an unpublished 0.1.0 candidate.",
)
expect_failure(
    "does not use canonical wording for release state 'candidate'",
    lambda: verify_state(root_candidate, rephrased_crate, "0.1.0"),
)
deleted_crate_wording = crate_candidate.replace(
    "This heading describes the current unpublished release candidate, not an\n"
    "existing crates.io package, Git tag, or GitHub release. ",
    "",
)
expect_failure(
    "does not use canonical wording for release state 'candidate'",
    lambda: verify_state(root_candidate, deleted_crate_wording, "0.1.0"),
)

# Merely flipping the marker cannot retain candidate prose. Both changelog
# authorities must move together to their positive canonical release wording.
marker_only_root = root_candidate.replace(
    "hns-wallet-release-state: 0.1.0 candidate",
    "hns-wallet-release-state: 0.1.0 release",
)
expect_failure(
    "does not use canonical wording for release state 'release'",
    lambda: verify_state(marker_only_root, crate_candidate, "0.1.0"),
)

root_release = root_candidate.replace(
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n"
    f"{root_wording['candidate']}",
    "<!-- hns-wallet-release-state: 0.1.0 release -->\n"
    f"{root_wording['release']}",
)
crate_release = crate_candidate.replace(
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n"
    f"{crate_wording['candidate']}",
    "<!-- hns-wallet-release-state: 0.1.0 release -->\n"
    f"{crate_wording['release']}",
)
release_state = verify_state(root_release, crate_release, "0.1.0")
assert release_state == "release"
require_execution_state(release_state)

expect_failure(
    "different release-state markers",
    lambda: verify_state(root_release, crate_candidate, "0.1.0"),
)

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
