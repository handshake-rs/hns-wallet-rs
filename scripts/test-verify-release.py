#!/usr/bin/env python3
"""Cheap regressions for release-state validation; does not invoke Cargo."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import Callable


REPO = Path(__file__).resolve().parent.parent
VALIDATOR = runpy.run_path(str(REPO / "scripts/verify-release.py"))
verify_state = VALIDATOR["verify_changelog_release_state"]
require_execution_state = VALIDATOR["require_execution_release_state"]
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
    "Unpublished initial release candidate for the independent Handshake wallet\n"
    "boundary:",
    "<!-- hns-wallet-release-state: 0.1.0 release -->\n"
    "Initial release source for the independent Handshake wallet boundary:",
)
crate_release = crate_candidate.replace(
    "<!-- hns-wallet-release-state: 0.1.0 candidate -->\n"
    "This heading describes the current unpublished release candidate, not an\n"
    "existing crates.io package, Git tag, or GitHub release.",
    "<!-- hns-wallet-release-state: 0.1.0 release -->\n"
    "This crate changelog describes the prepared `hns-wallet-rs` release source.",
)
release_state = verify_state(root_release, crate_release, "0.1.0")
assert release_state == "release"
require_execution_state(release_state)

expect_failure(
    "different release-state markers",
    lambda: verify_state(root_release, crate_candidate, "0.1.0"),
)

print("release-state validator regressions passed")
