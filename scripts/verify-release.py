#!/usr/bin/env python3
"""Cheap, deterministic validation of the hns-wallet-rs release graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from datetime import date
from pathlib import Path


REPOSITORY = "https://github.com/handshake-rs/hns-wallet-rs"
PROTOCOL_REPOSITORY = "https://github.com/handshake-rs/hns-rs.git"
PROTOCOL_REVISION = "0e99addca59778b7b7c6fc56291333a97c4c8815"
PROTOCOL_VERSION = "=0.3.1"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PROTOCOL_CHECKSUM_MANIFEST = "release/hns-rs-core-0.3.1-crates.sha256"
SHAKESCAPE_PROTOCOL_REVISION = "c8feb6f90f3e03efbb982a5e33192dda6fd2f37a"
SHAKESCAPE_PROTOCOL_VERSION = "=0.4.0"
SHAKESCAPE_PROTOCOL_CHECKSUM_MANIFEST = (
    "release/hns-rs-shakescape-0.4.0-crates.sha256"
)
SHAKESCAPE_PROTOCOL_PACKAGES = (
    "hns-p2p-experimental",
    "hns-marketplace-protocol",
)
PROTOCOL_PUBLIC_PACKAGES = (
    "hns-encoding",
    "hns-rollback-journal",
    "hns-hrm",
    "hns-primitives",
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-header-consensus",
    "hns-service-authority",
    "hns-odoh-protocol",
    "hns-urkel-proof",
    "hns-transaction",
    "hns-chat-protocol",
    "hns-hnsr-protocol",
    "hns-script",
    "hns-mining",
    "hns-swap",
    "hns-p2p-wire",
)
PROTOCOL_PACKAGES = {
    "hns-covenants",
    "hns-header-consensus",
    "hns-marketplace-protocol",
    "hns-p2p-experimental",
    "hns-p2p-wire",
    "hns-primitives",
    "hns-script",
    "hns-swap",
    "hns-transaction",
    "hns-urkel-proof",
}
ENGINE_REPOSITORY = "https://github.com/handshake-rs/hns-dane-engine.git"
ENGINE_REVISION = "b7fdf8826c81b77650a0f740d1f05314b74969f9"
ENGINE_VERSION = "=0.2.2"
ENGINE_CHECKSUM_MANIFEST = "release/hns-dane-engine-0.2.2-crates.sha256"
ENGINE_PUBLIC_PACKAGES = (
    "hns-dns-wire",
    "hns-browser-runtime",
    "hns-icann-dane",
    "hns-namespace-resolution",
    "hns-resolution-policy",
    "hns-light-chain",
    "hns-light-wallet",
    "hns-dane",
    "hns-dnssec",
    "hns-gateway",
    "hns-cache",
    "hns-light-p2p",
    "hns-light-sync",
    "hns-transport",
    "hns-resolver",
    "hns-browser-observability",
    "hns-p2p-transport",
    "hns-dane-engine",
    "hns-dane-engine-ffi",
    "hns-loopback-proxy",
)
ENGINE_PACKAGES = {
    "hns-light-chain",
    "hns-light-p2p",
    "hns-light-sync",
    "hns-light-wallet",
}
ROOT_RELEASE_STATE_WORDING = {
    "candidate": (
        "Unpublished initial release candidate for the independent Handshake wallet\n"
        "boundary:"
    ),
    "release": "Breaking clean-break migration of the wallet and atomic-swap boundary:",
}
CRATE_RELEASE_STATE_WORDING = {
    "candidate": (
        "This heading describes the current unpublished release candidate, not an\n"
        "existing crates.io package, Git tag, or GitHub release."
    ),
    "release": (
        "This crate changelog describes the prepared `hns-wallet-rs` release source."
    ),
}


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def changelog_release_state(
    document: str, path: str, version: str, wording: dict[str, str]
) -> str:
    heading = re.search(
        rf"^## {re.escape(version)} - (?:unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        document,
        re.MULTILINE | re.IGNORECASE,
    )
    if heading is None:
        fail(f"{path} has no release section for {version}")
    next_heading = re.search(r"^## ", document[heading.end() :], re.MULTILINE)
    section_end = (
        len(document)
        if next_heading is None
        else heading.end() + next_heading.start()
    )
    section = document[heading.end() : section_end]
    marker_prefix = f"<!-- hns-wallet-release-state: {version} "
    if section.count(marker_prefix) != 1:
        fail(
            f"{path} must contain exactly one canonical release-state marker "
            f"for {version}"
        )
    marker = re.compile(
        rf"^<!-- hns-wallet-release-state: {re.escape(version)} "
        r"(candidate|release) -->$",
        re.MULTILINE,
    )
    states = marker.findall(section)
    if len(states) != 1:
        fail(f"{path} has an invalid canonical release-state marker for {version}")
    state = states[0]
    expected_block = (
        f"<!-- hns-wallet-release-state: {version} {state} -->\n{wording[state]}"
    )
    if section.count(expected_block) != 1:
        fail(f"{path} does not use canonical wording for release state {state!r}")
    other_state = "release" if state == "candidate" else "candidate"
    if wording[other_state] in section:
        fail(f"{path} contains contradictory {other_state} release-state wording")
    return state


def verify_changelog_release_state(
    root_changelog: str, crate_changelog: str, version: str
) -> str:
    root_state = changelog_release_state(
        root_changelog, "CHANGELOG.md", version, ROOT_RELEASE_STATE_WORDING
    )
    crate_state = changelog_release_state(
        crate_changelog,
        "release/CRATE-CHANGELOG.md",
        version,
        CRATE_RELEASE_STATE_WORDING,
    )
    if root_state != crate_state:
        fail("root and package changelogs have different release-state markers")
    return root_state


def require_execution_release_state(release_state: str) -> None:
    if release_state != "release":
        fail("execution requires canonical release-state wording in all changelogs")


def cargo_metadata(repo: Path, toolchain: str) -> dict:
    result = subprocess.run(
        [
            "cargo",
            f"+{toolchain}",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail("Cargo metadata failed for the release workspace")
    return json.loads(result.stdout)


def release_order(repo: Path) -> list[str]:
    path = repo / "release/public-crates.txt"
    packages = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not packages:
        fail(f"{path.relative_to(repo)} is empty")
    if len(packages) != len(set(packages)):
        fail(f"{path.relative_to(repo)} contains a duplicate package")
    for package in packages:
        if re.fullmatch(r"hns-wallet-[a-z0-9-]+", package) is None:
            fail(f"invalid public package name {package!r}")
    return packages


def verify_release_document(repo: Path, order: list[str], version: str) -> None:
    document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    if re.search(r"\bare\s+published\s+to\s+crates\.io\b", document):
        fail("docs/releasing.md must not claim that candidate crates are published")
    documented = re.findall(r"^\d+\. `([^`]+)`$", document, flags=re.MULTILINE)
    if documented != order:
        fail("docs/releasing.md does not match release/public-crates.txt")

    execute_command = f"./scripts/publish.sh --execute --confirm-publish {version}"
    if document.count(execute_command) != 2:
        fail("docs/releasing.md does not use the current version in execute examples")

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    interval_defaults = (
        (
            "publish_new_interval_seconds",
            "PUBLISH_NEW_INTERVAL_SECONDS",
            "new-name",
        ),
        (
            "publish_update_interval_seconds",
            "PUBLISH_UPDATE_INTERVAL_SECONDS",
            "existing-crate update",
        ),
    )
    for shell_name, environment_name, description in interval_defaults:
        interval_match = re.search(
            rf"^{shell_name}=\$\{{{environment_name}-(\d+)\}}$",
            publish_script,
            re.MULTILINE,
        )
        if interval_match is None:
            fail(
                f"scripts/publish.sh has no validated {description} "
                "publication interval default"
            )
        default_interval = interval_match.group(1)
        if re.search(
            rf"{re.escape(default_interval)}-second\s+{re.escape(description)}",
            document,
        ) is None:
            fail(f"docs/releasing.md omits the {description} interval default")
        if f"{environment_name}={default_interval}" not in document:
            fail(
                f"docs/releasing.md {description} cooldown example differs "
                "from the script default"
            )

    required_release_text = (
        "./scripts/publish.sh --archive-only",
        ".github/workflows/release-preflight.yml",
        PROTOCOL_REVISION,
        SHAKESCAPE_PROTOCOL_REVISION,
        ENGINE_REVISION,
        PROTOCOL_CHECKSUM_MANIFEST,
        SHAKESCAPE_PROTOCOL_CHECKSUM_MANIFEST,
        ENGINE_CHECKSUM_MANIFEST,
    )
    for required in required_release_text:
        if required not in document:
            fail(f"docs/releasing.md omits {required!r}")
    if "seventeen unchanged published `hns-rs` `0.3.1` core" not in document:
        fail("docs/releasing.md omits the current published core protocol prerequisite record")
    if "published `hns-p2p-experimental` and `hns-marketplace-protocol` `0.4.0`" not in document:
        fail("docs/releasing.md omits the current published Shakescape prerequisite record")
    if re.search(
        r"all 20\s+required\s+`hns-dane-engine` `0\.2\.2` archives were published",
        document,
        flags=re.IGNORECASE,
    ) is None:
        fail("docs/releasing.md omits the current published engine prerequisite record")

    self_expiring_claims = (
        "packages are unpublished",
        "package or tag has been published",
        "No `hns-wallet-rs`",
        "are not yet published",
    )
    for claim in self_expiring_claims:
        if claim in document:
            fail(f"docs/releasing.md contains self-expiring claim {claim!r}")


def verify_release_workflows(repo: Path) -> None:
    check_script = (repo / "scripts/check.sh").read_text(encoding="utf-8")
    archive_command = "./scripts/publish.sh --archive-only"
    if check_script.count(archive_command) != 1:
        fail("scripts/check.sh must run archive-only release verification once")
    if "./scripts/publish.sh --dry-run" in check_script:
        fail("scripts/check.sh must not run the expensive publish dry-run")

    workflow_path = repo / ".github/workflows/release-preflight.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    if not re.search(r"^on:\n  workflow_dispatch:\s*$", workflow, re.MULTILINE):
        fail("release preflight workflow must be manually dispatchable")
    for automatic_event in ("push", "pull_request", "schedule"):
        if re.search(rf"^  {automatic_event}:\s*", workflow, re.MULTILINE):
            fail(f"release preflight workflow must not run on {automatic_event}")
    if workflow.count("run: ./scripts/publish.sh --dry-run") != 1:
        fail("release preflight workflow must run one complete publish dry-run")
    if "--execute" in workflow:
        fail("release preflight workflow must never execute publication")
    required_exact_commit_fragments = (
        "expected_commit:",
        "required: true",
        "ref: ${{ inputs.expected_commit }}",
        "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
        "^[0-9a-f]{40}$",
        'test "$(git rev-parse HEAD)" = "$EXPECTED_COMMIT"',
    )
    for fragment in required_exact_commit_fragments:
        if fragment not in workflow:
            fail(f"release preflight workflow omits exact-commit guard {fragment!r}")


def verify_publish_script_safety(repo: Path) -> None:
    script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    required_fragments = (
        "--archive-only)",
        "create_source_package()",
        "create_registry_source_package()",
        "published_crate_status()",
        "verify_protocol_packages_published()",
        "verify_engine_packages_published()",
        "verify_published_cohort()",
        "protocol_checksum_manifest=release/hns-rs-core-0.3.1-crates.sha256",
        "shakescape_protocol_checksum_manifest=release/hns-rs-shakescape-0.4.0-crates.sha256",
        "engine_checksum_manifest=release/hns-dane-engine-0.2.2-crates.sha256",
        "require_clean_archive_vcs=yes",
        '*\\"dirty\\":true*',
        'cohort_vcs_info="$release_tmp/$package-$version.cargo_vcs_info.json"',
        '> "$cohort_vcs_info"',
        'json.load(open(sys.argv[1], encoding="utf-8"))["git"]["sha1"]',
        'sha256sum "$cohort_archive"',
        "verify_release_source_unchanged()",
        'crate_status=$(published_crate_status "$package" "$version")',
        "publish_interval_seconds=$publish_update_interval_seconds",
        "publish_kind=existing-crate-update",
        "publish_interval_seconds=$publish_new_interval_seconds",
        "publish_kind=new-crate-name",
        'error: crates.io returned HTTP $crate_status while classifying $package',
    )
    for fragment in required_fragments:
        if fragment not in script:
            fail(f"scripts/publish.sh omits execute safety fragment {fragment!r}")
    if (
        "cohort_vcs_sha=$(tar -xOf" in script
        or "cohort_vcs_dirty=$(tar -xOf" in script
    ):
        fail("execute-mode protocol VCS reads must materialize tar output")

    try:
        registry_builder = script.split("create_registry_source_package() {", 1)[
            1
        ].split("\n}", 1)[0]
        crate_status_function = script.split("published_crate_status() {", 1)[1].split(
            "\n}", 1
        )[0]
    except IndexError as error:
        fail(f"scripts/publish.sh registry helper is incomplete: {error}")
    for fragment in (
        'cargo +"$rust_toolchain" publish',
        "--locked",
        "--dry-run",
        '-p "$package"',
        'verify_source_package "$package"',
    ):
        if fragment not in registry_builder:
            fail(
                "registry-backed resume package construction omits "
                f"{fragment!r}"
            )
    if "--allow-dirty" in registry_builder:
        fail("registry-backed resume package construction must reject dirty source")
    if '"https://crates.io/api/v1/crates/$package"' not in crate_status_function:
        fail("crate-name classification must query the exact crates.io name endpoint")

    try:
        execute = script.split("    --execute)", 1)[1]
        protocol_position = execute.index("verify_protocol_packages_published")
        engine_position = execute.index("verify_engine_packages_published")
        source_guard_position = execute.index("verify_release_source_unchanged")
        version_status_position = execute.index(
            'status=$(published_package_status "$package" "$version")'
        )
        resume_package_position = execute.index(
            'create_registry_source_package "$package"'
        )
        resume_position = execute.index(
            'verify_published_package "$package" "$version"'
        )
        classification_position = execute.index(
            'crate_status=$(published_crate_status "$package" "$version")'
        )
        new_package_position = execute.index('create_source_package "$package" no')
        upload_position = execute.index(
            'cargo +"$rust_toolchain" publish --locked -p "$package"'
        )
    except (IndexError, ValueError) as error:
        fail(f"scripts/publish.sh execute path is incomplete: {error}")
    if not (
        protocol_position
        < engine_position
        < source_guard_position
        < version_status_position
        < resume_package_position
        < resume_position
        < classification_position
        < new_package_position
        < upload_position
    ):
        fail(
            "prerequisite cohorts and path-specific wallet archive checks must precede "
            "resume verification and execute upload"
        )
    classification = execute[classification_position:new_package_position]
    if re.search(
        r'\n\s+\*\)\n\s+echo "error: crates\.io returned HTTP '
        r'\$crate_status while classifying \$package" >&2\n\s+exit 1',
        classification,
    ) is None:
        fail("crate-name classification must reject every unexpected HTTP status")
    if "--allow-dirty" in execute:
        fail("scripts/publish.sh execute path must never allow dirty packaging")


def checksum_manifest(
    repo: Path, relative_path: str, packages: tuple[str, ...], version: str
) -> dict[str, str]:
    path = repo / relative_path
    expected_filenames = {f"{package}-{version.removeprefix('=')}.crate" for package in packages}
    observed: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-z0-9-]+-[0-9]+\.[0-9]+\.[0-9]+\.crate)", line)
        if match is None:
            fail(f"{relative_path}:{line_number} is not a canonical SHA-256 entry")
        checksum, filename = match.groups()
        if filename not in expected_filenames:
            fail(f"{relative_path}:{line_number} has unexpected archive {filename}")
        if filename in observed:
            fail(f"{relative_path} has duplicate archive {filename}")
        observed[filename] = checksum
    if set(observed) != expected_filenames:
        fail(
            f"{relative_path} does not cover its exact release cohort: "
            f"missing={sorted(expected_filenames - set(observed))}, "
            f"unexpected={sorted(set(observed) - expected_filenames)}"
        )
    return observed


def verify_protocol_source(repo: Path) -> None:
    manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    dependencies = manifest["workspace"]["dependencies"]
    if "patch" in manifest:
        fail("Cargo.toml must not override registry dependencies through [patch]")
    for package, version in (
        *((
            package,
            PROTOCOL_VERSION,
        ) for package in sorted(PROTOCOL_PACKAGES - set(SHAKESCAPE_PROTOCOL_PACKAGES))),
        *((package, SHAKESCAPE_PROTOCOL_VERSION) for package in SHAKESCAPE_PROTOCOL_PACKAGES),
        *((package, ENGINE_VERSION) for package in sorted(ENGINE_PACKAGES)),
    ):
        dependency = dependencies.get(package)
        expected = {"version": version}
        if dependency != expected:
            fail(f"workspace dependency {package} differs from registry policy {expected}")

    protocol_checksums = checksum_manifest(
        repo, PROTOCOL_CHECKSUM_MANIFEST, PROTOCOL_PUBLIC_PACKAGES, PROTOCOL_VERSION
    )
    shakescape_protocol_checksums = checksum_manifest(
        repo,
        SHAKESCAPE_PROTOCOL_CHECKSUM_MANIFEST,
        SHAKESCAPE_PROTOCOL_PACKAGES,
        SHAKESCAPE_PROTOCOL_VERSION,
    )
    engine_checksums = checksum_manifest(
        repo, ENGINE_CHECKSUM_MANIFEST, ENGINE_PUBLIC_PACKAGES, ENGINE_VERSION
    )

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    required_script_lines = {
        f"protocol_repository={PROTOCOL_REPOSITORY}",
        f"protocol_revision={PROTOCOL_REVISION}",
        f"protocol_version={PROTOCOL_VERSION.removeprefix('=')}",
        f"protocol_crates='{' '.join(PROTOCOL_PUBLIC_PACKAGES)}'",
        f"protocol_checksum_manifest={PROTOCOL_CHECKSUM_MANIFEST}",
        f"shakescape_protocol_revision={SHAKESCAPE_PROTOCOL_REVISION}",
        f"shakescape_protocol_version={SHAKESCAPE_PROTOCOL_VERSION.removeprefix('=')}",
        f"shakescape_protocol_crates='{' '.join(SHAKESCAPE_PROTOCOL_PACKAGES)}'",
        f"shakescape_protocol_checksum_manifest={SHAKESCAPE_PROTOCOL_CHECKSUM_MANIFEST}",
        f"engine_repository={ENGINE_REPOSITORY}",
        f"engine_revision={ENGINE_REVISION}",
        f"engine_version={ENGINE_VERSION.removeprefix('=')}",
        f"engine_crates='{' '.join(ENGINE_PUBLIC_PACKAGES)}'",
        f"engine_checksum_manifest={ENGINE_CHECKSUM_MANIFEST}",
    }
    script_lines = set(publish_script.splitlines())
    missing_lines = required_script_lines - script_lines
    if missing_lines:
        fail(
            "scripts/publish.sh prerequisite cohort differs from the workspace: "
            f"missing={sorted(missing_lines)}"
        )
    if re.search(r"patch\.crates-io\.hns-[^ ]+\.(?:git|rev)", publish_script):
        fail("scripts/publish.sh must not restore Git overrides for registry cohorts")

    release_document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    required_document_text = (
        PROTOCOL_REVISION,
        ENGINE_REVISION,
        PROTOCOL_CHECKSUM_MANIFEST,
        SHAKESCAPE_PROTOCOL_CHECKSUM_MANIFEST,
        ENGINE_CHECKSUM_MANIFEST,
        f"`hns-rs` `{PROTOCOL_VERSION.removeprefix('=')}`",
        f"`{SHAKESCAPE_PROTOCOL_VERSION.removeprefix('=')}`",
        f"`hns-dane-engine` `{ENGINE_VERSION.removeprefix('=')}`",
    )
    for required in required_document_text:
        if required not in release_document:
            fail(f"docs/releasing.md omits prerequisite release evidence {required!r}")

    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    observed_protocol_packages: set[str] = set()
    observed_engine_packages: set[str] = set()
    for package in lock["package"]:
        name = package["name"]
        if name in PROTOCOL_PUBLIC_PACKAGES:
            observed_protocol_packages.add(name)
            expected_version = PROTOCOL_VERSION.removeprefix("=")
            expected_checksum = protocol_checksums[f"{name}-{expected_version}.crate"]
            cohort = "protocol"
        elif name in SHAKESCAPE_PROTOCOL_PACKAGES:
            observed_protocol_packages.add(name)
            expected_version = SHAKESCAPE_PROTOCOL_VERSION.removeprefix("=")
            expected_checksum = shakescape_protocol_checksums[
                f"{name}-{expected_version}.crate"
            ]
            cohort = "Shakescape protocol"
        elif name in ENGINE_PUBLIC_PACKAGES:
            observed_engine_packages.add(name)
            expected_version = ENGINE_VERSION.removeprefix("=")
            expected_checksum = engine_checksums[f"{name}-{expected_version}.crate"]
            cohort = "engine"
        else:
            continue
        if package.get("version") != expected_version:
            fail(f"Cargo.lock has wrong {cohort} version for {name}")
        if package.get("source") != REGISTRY_SOURCE:
            fail(f"Cargo.lock has a non-registry {cohort} source for {name}")
        if package.get("checksum") != expected_checksum:
            fail(f"Cargo.lock checksum for {name} differs from its release manifest")
    if not PROTOCOL_PACKAGES.issubset(observed_protocol_packages):
        fail(
            "Cargo.lock omits direct protocol packages: "
            f"{sorted(PROTOCOL_PACKAGES - observed_protocol_packages)}"
        )
    if not ENGINE_PACKAGES.issubset(observed_engine_packages):
        fail(
            "Cargo.lock omits direct engine packages: "
            f"{sorted(ENGINE_PACKAGES - observed_engine_packages)}"
        )


def verify_release_artifacts(repo: Path) -> None:
    ffi_root = repo / "crates/hns-wallet-ffi/abi"
    for name in ("contracts-v2.schema.json", "golden-vectors-v2.json"):
        authority = repo / "abi" / name
        package_copy = ffi_root / name
        if package_copy.read_bytes() != authority.read_bytes():
            fail(f"hns-wallet-ffi packaged {name} differs from abi/{name}")
        value = json.loads(authority.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            fail(f"abi/{name} must contain one JSON object")

    contract_root = repo / "crates/hns-wallet-ethereum/contracts"
    required_contract_files = (
        "README.md",
        "compile.mjs",
        "package-lock.json",
        "package.json",
        "src/NativeEthHtlc.sol",
        "artifacts/NativeEthHtlc.json",
    )
    for relative in required_contract_files:
        path = contract_root / relative
        if not path.is_file() or not path.read_bytes():
            fail(f"Ethereum release artifact {relative} is missing or empty")

    source = (contract_root / "src/NativeEthHtlc.sol").read_bytes()
    artifact = json.loads(
        (contract_root / "artifacts/NativeEthHtlc.json").read_text(encoding="utf-8")
    )
    if artifact.get("sourceSha256") != hashlib.sha256(source).hexdigest():
        fail("Ethereum artifact sourceSha256 does not match NativeEthHtlc.sol")
    abi = artifact.get("abi")
    bytecode = artifact.get("bytecode")
    deployed = artifact.get("deployedBytecode")
    runtime_length = artifact.get("runtimeLength")
    if not isinstance(abi, list) or not abi:
        fail("Ethereum artifact ABI is missing or empty")
    for field, value in (("bytecode", bytecode), ("deployedBytecode", deployed)):
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]+", value):
            fail(f"Ethereum artifact {field} is missing or noncanonical")
    if not isinstance(runtime_length, int) or runtime_length <= 0:
        fail("Ethereum artifact runtimeLength is invalid")
    if len(deployed) != 2 + 2 * runtime_length:
        fail("Ethereum deployed bytecode length differs from runtimeLength")


def verify_workspace(
    repo: Path, metadata: dict, order: list[str]
) -> tuple[str, str, str]:
    root_manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_package = root_manifest["workspace"]["package"]
    version = workspace_package["version"]
    expected_publish = ["crates-io"]

    packages = {package["name"]: package for package in metadata["packages"]}
    missing = set(order) - packages.keys()
    if missing:
        fail(f"release allowlist names missing workspace packages: {sorted(missing)}")

    publishable = {
        package["name"]
        for package in metadata["packages"]
        if package.get("publish") != []
    }
    if publishable != set(order):
        fail(
            "publishable workspace packages differ from the release allowlist: "
            f"workspace={sorted(publishable)}, allowlist={sorted(order)}"
        )
    if set(packages) != set(order):
        fail(
            "workspace package set differs from the 14-crate release set: "
            f"workspace={sorted(packages)}, allowlist={sorted(order)}"
        )

    changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    if "packages are unpublished" in changelog:
        fail("CHANGELOG.md contains a self-expiring registry-status claim")
    if re.search(r"^## Unreleased$", changelog, re.MULTILINE):
        fail("CHANGELOG.md must use the selected shared version for unreleased notes")
    headings = re.findall(
        rf"^## {re.escape(version)} - (unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.MULTILINE,
    )
    if len(headings) != 1:
        fail(
            f"CHANGELOG.md must contain exactly one {version} unreleased or dated heading"
        )
    release_label = headings[0]
    if release_label != "unreleased":
        try:
            date.fromisoformat(release_label)
        except ValueError:
            fail(f"CHANGELOG.md has an invalid release date {release_label!r}")
    expected_heading = f"## {version} - {release_label}"

    template = (repo / "release/CRATE-CHANGELOG.md").read_bytes()
    template_text = template.decode("utf-8")
    release_state = verify_changelog_release_state(changelog, template_text, version)
    if expected_heading not in template_text:
        fail("release/CRATE-CHANGELOG.md does not match the workspace release heading")
    if "`CHANGELOG.md`" not in template_text:
        fail("release/CRATE-CHANGELOG.md must name the canonical changelog")
    if re.search(r"\[[^]]*CHANGELOG\.md[^]]*\]\(", template_text):
        fail("release/CRATE-CHANGELOG.md must not link a tag before it exists")

    positions = {package: index for index, package in enumerate(order)}
    observed_protocol_dependencies: set[str] = set()
    observed_engine_dependencies: set[str] = set()

    for name in order:
        package = packages[name]
        package_root = Path(package["manifest_path"]).resolve().parent
        expected_root = (repo / "crates" / name).resolve()
        if package_root != expected_root:
            fail(f"{name} manifest is outside crates/{name}")
        if package["version"] != version:
            fail(f"{name} version {package['version']} differs from workspace {version}")
        if package.get("publish") != expected_publish:
            fail(f"{name} must publish only to crates-io")

        required_values = {
            "description": package.get("description"),
            "license": package.get("license"),
            "repository": package.get("repository"),
            "documentation": package.get("documentation"),
            "readme": package.get("readme"),
            "rust_version": package.get("rust_version"),
        }
        missing_values = [field for field, value in required_values.items() if not value]
        if missing_values:
            fail(f"{name} is missing crates.io metadata: {', '.join(missing_values)}")
        if package["license"] != workspace_package["license"]:
            fail(f"{name} license differs from [workspace.package]")
        if package["repository"] != REPOSITORY:
            fail(f"{name} repository is not {REPOSITORY}")
        if package["documentation"] != f"https://docs.rs/{name}":
            fail(f"{name} has a noncanonical docs.rs URL")
        if package["rust_version"] != workspace_package["rust-version"]:
            fail(f"{name} rust-version differs from [workspace.package]")
        if package["edition"] != workspace_package["edition"]:
            fail(f"{name} edition differs from [workspace.package]")
        if package.get("keywords") != workspace_package["keywords"]:
            fail(f"{name} keywords differ from [workspace.package]")
        if package.get("categories") != workspace_package["categories"]:
            fail(f"{name} categories differ from [workspace.package]")

        readme = Path(package["readme"])
        if not readme.is_absolute():
            readme = package_root / readme
        if not readme.is_file() or not readme.read_text(encoding="utf-8").strip():
            fail(f"{name} readme is missing or empty")
        for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
            package_license = (package_root / license_name).read_bytes()
            workspace_license = (repo / license_name).read_bytes()
            if package_license != workspace_license:
                fail(f"{name} {license_name} differs from the workspace license")
        if (package_root / "CHANGELOG.md").read_bytes() != template:
            fail(f"{name} CHANGELOG.md differs from release/CRATE-CHANGELOG.md")

        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name in packages:
                if dependency_name not in positions:
                    fail(
                        f"public package {name} depends on non-allowlisted "
                        f"workspace package {dependency_name}"
                    )
                expected_requirement = f"^{version}"
                if dependency["req"] != expected_requirement:
                    fail(
                        f"{name} requires internal {dependency_name} at "
                        f"{dependency['req']}, expected {expected_requirement}"
                    )
                if positions[dependency_name] >= positions[name]:
                    fail(f"{dependency_name} must precede dependent package {name}")
            elif dependency_name in PROTOCOL_PACKAGES:
                observed_protocol_dependencies.add(dependency_name)
                expected_protocol_version = (
                    SHAKESCAPE_PROTOCOL_VERSION
                    if dependency_name in SHAKESCAPE_PROTOCOL_PACKAGES
                    else PROTOCOL_VERSION
                )
                if dependency["req"] != expected_protocol_version:
                    fail(
                        f"{name} requires protocol {dependency_name} at "
                        f"{dependency['req']}, expected {expected_protocol_version}"
                    )
                if dependency.get("source") != REGISTRY_SOURCE:
                    fail(f"{name} has a non-registry source for {dependency_name}")
            elif dependency_name in ENGINE_PACKAGES:
                observed_engine_dependencies.add(dependency_name)
                if dependency["req"] != ENGINE_VERSION:
                    fail(
                        f"{name} requires engine {dependency_name} at "
                        f"{dependency['req']}, expected {ENGINE_VERSION}"
                    )
                if dependency.get("source") != REGISTRY_SOURCE:
                    fail(f"{name} has a non-registry source for {dependency_name}")

    if observed_protocol_dependencies != PROTOCOL_PACKAGES:
        fail(
            "wallet packages do not exercise the complete declared protocol set: "
            f"observed={sorted(observed_protocol_dependencies)}"
        )
    if observed_engine_dependencies != ENGINE_PACKAGES:
        fail(
            "wallet packages do not exercise the complete declared engine set: "
            f"observed={sorted(observed_engine_dependencies)}"
        )

    return version, release_label, release_state


def verify_clean_source(repo: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout:
        fail("execution requires a clean worktree")
    subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", default="1.89.0")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    order = release_order(repo)
    version, release_label, release_state = verify_workspace(
        repo, cargo_metadata(repo, args.toolchain), order
    )
    verify_protocol_source(repo)
    verify_release_artifacts(repo)
    verify_release_document(repo, order, version)
    verify_release_workflows(repo)
    verify_publish_script_safety(repo)
    if args.expected_version is not None and args.expected_version != version:
        fail(
            f"confirmed version {args.expected_version} differs from workspace version {version}"
        )
    if args.require_clean:
        if release_label == "unreleased":
            fail("execution requires a dated release heading, not 'unreleased'")
        require_execution_release_state(release_state)
        verify_clean_source(repo)
    print(f"release metadata valid for {len(order)} public crates at version {version}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
