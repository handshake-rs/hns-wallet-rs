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
PROTOCOL_REVISION = "b24b66c382de53330ec21dd3137e056a2bea3e2d"
PROTOCOL_VERSION = "=0.2.0"
PROTOCOL_PUBLIC_PACKAGES = (
    "hns-encoding",
    "hns-primitives",
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-header-consensus",
    "hns-service-authority",
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-urkel-proof",
    "hns-transaction",
    "hns-chat-protocol",
    "hns-hnsr-protocol",
    "hns-script",
    "hns-mining",
    "hns-swap",
    "hns-marketplace-protocol",
    "hns-p2p-wire",
)
PROTOCOL_PACKAGES = {
    "hns-covenants",
    "hns-marketplace-protocol",
    "hns-primitives",
    "hns-script",
    "hns-swap",
    "hns-transaction",
    "hns-urkel-proof",
}


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


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
    interval_match = re.search(
        r"^publish_interval_seconds=\$\{PUBLISH_INTERVAL_SECONDS-(\d+)\}$",
        publish_script,
        re.MULTILINE,
    )
    if interval_match is None:
        fail("scripts/publish.sh has no validated publication interval default")
    default_interval = interval_match.group(1)
    if f"{default_interval}-second" not in document:
        fail("docs/releasing.md omits the publication interval default")
    if f"PUBLISH_INTERVAL_SECONDS={default_interval}" not in document:
        fail("docs/releasing.md cooldown example differs from the script default")

    required_release_text = (
        "./scripts/publish.sh --archive-only",
        ".github/workflows/release-preflight.yml",
        PROTOCOL_REVISION,
    )
    for required in required_release_text:
        if required not in document:
            fail(f"docs/releasing.md omits {required!r}")

    self_expiring_claims = (
        "packages are unpublished",
        "package or tag has been published",
        "No `hns-wallet-rs`",
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
        "verify_protocol_packages_published()",
        "require_clean_archive_vcs=yes",
        '*\\"dirty\\":true*',
        'python3 -c \'import json, sys; print(json.load(sys.stdin)["git"]["sha1"])\'',
    )
    for fragment in required_fragments:
        if fragment not in script:
            fail(f"scripts/publish.sh omits execute safety fragment {fragment!r}")

    try:
        execute = script.split("    --execute)", 1)[1]
        protocol_position = execute.index("verify_protocol_packages_published")
        package_position = execute.index('create_source_package "$package" no')
        upload_position = execute.index(
            'cargo +"$rust_toolchain" publish --locked -p "$package"'
        )
    except (IndexError, ValueError) as error:
        fail(f"scripts/publish.sh execute path is incomplete: {error}")
    if not protocol_position < package_position < upload_position:
        fail("protocol and wallet archives must be verified before execute upload")
    if "--allow-dirty" in execute:
        fail("scripts/publish.sh execute path must never allow dirty packaging")


def verify_protocol_source(repo: Path) -> None:
    manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    dependencies = manifest["workspace"]["dependencies"]
    for package in sorted(PROTOCOL_PACKAGES):
        dependency = dependencies.get(package)
        if not isinstance(dependency, dict):
            fail(f"workspace dependency {package} must use an explicit source table")
        expected = {
            "version": PROTOCOL_VERSION,
            "git": PROTOCOL_REPOSITORY,
            "rev": PROTOCOL_REVISION,
        }
        actual = {field: dependency.get(field) for field in expected}
        if actual != expected:
            fail(f"workspace dependency {package} differs from {expected}")

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    required_script_lines = {
        f"protocol_repository={PROTOCOL_REPOSITORY}",
        f"protocol_revision={PROTOCOL_REVISION}",
        f"protocol_version={PROTOCOL_VERSION.removeprefix('=')}",
        f"protocol_crates='{' '.join(PROTOCOL_PUBLIC_PACKAGES)}'",
    }
    script_lines = set(publish_script.splitlines())
    missing_lines = required_script_lines - script_lines
    if missing_lines:
        fail(
            "scripts/publish.sh protocol source differs from the workspace: "
            f"missing={sorted(missing_lines)}"
        )

    release_document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    if PROTOCOL_REVISION not in release_document:
        fail("docs/releasing.md omits the qualified protocol revision")
    if f"`hns-rs` `{PROTOCOL_VERSION.removeprefix('=')}`" not in release_document:
        fail("docs/releasing.md omits the required protocol package version")

    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    expected_lock_source = (
        f"git+{PROTOCOL_REPOSITORY}?rev={PROTOCOL_REVISION}#{PROTOCOL_REVISION}"
    )
    observed_lock_packages: set[str] = set()
    for package in lock["package"]:
        name = package["name"]
        if name not in PROTOCOL_PUBLIC_PACKAGES:
            continue
        observed_lock_packages.add(name)
        if package.get("source") != expected_lock_source:
            fail(f"Cargo.lock has an unreviewed source for protocol package {name}")
    if not PROTOCOL_PACKAGES.issubset(observed_lock_packages):
        fail(
            "Cargo.lock omits direct protocol packages: "
            f"{sorted(PROTOCOL_PACKAGES - observed_lock_packages)}"
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


def verify_workspace(repo: Path, metadata: dict, order: list[str]) -> tuple[str, str]:
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
    if expected_heading not in template_text:
        fail("release/CRATE-CHANGELOG.md does not match the workspace release heading")
    if "`CHANGELOG.md`" not in template_text:
        fail("release/CRATE-CHANGELOG.md must name the canonical changelog")
    if re.search(r"\[[^]]*CHANGELOG\.md[^]]*\]\(", template_text):
        fail("release/CRATE-CHANGELOG.md must not link a tag before it exists")

    positions = {package: index for index, package in enumerate(order)}
    expected_protocol_source = (
        f"git+{PROTOCOL_REPOSITORY}?rev={PROTOCOL_REVISION}"
    )
    observed_protocol_dependencies: set[str] = set()

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
                if dependency["req"] != PROTOCOL_VERSION:
                    fail(
                        f"{name} requires protocol {dependency_name} at "
                        f"{dependency['req']}, expected {PROTOCOL_VERSION}"
                    )
                if dependency.get("source") != expected_protocol_source:
                    fail(f"{name} has an unreviewed source for {dependency_name}")

    if observed_protocol_dependencies != PROTOCOL_PACKAGES:
        fail(
            "wallet packages do not exercise the complete declared protocol set: "
            f"observed={sorted(observed_protocol_dependencies)}"
        )

    return version, release_label


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
    version, release_label = verify_workspace(
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
        root_changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
        crate_changelog = (repo / "release/CRATE-CHANGELOG.md").read_text(
            encoding="utf-8"
        )
        if "Unpublished initial release candidate" in root_changelog:
            fail("execution requires release wording in CHANGELOG.md")
        if "current unpublished release candidate" in crate_changelog:
            fail("execution requires release wording in package changelogs")
        verify_clean_source(repo)
    print(f"release metadata valid for {len(order)} public crates at version {version}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
