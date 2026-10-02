# Releasing

Wallet crates are versioned and released independently. Publish only packages
with changes that need distribution. A compatible dependency patch does not
require a new release of its consumers. Each package declares its own version
and maintains one current release entry in its `CHANGELOG.md`.

## Public package allowlist

The release script accepts one package per execution. Use dependency order
when more than one changed package needs publication:

1. `hns-wallet-types`
2. `hns-wallet-store`
3. `hns-wallet-chain-api`
4. `hns-wallet-ffi`
5. `hns-wallet-provider`
6. `hns-wallet-hns`
7. `hns-wallet-bip157`
8. `hns-wallet-bdk-kyoto`
9. `hns-wallet-bitcoin-kyoto`
10. `hns-wallet-market`
11. `hns-wallet-shakedex`
12. `hns-wallet-ethereum`
13. `hns-wallet-host`
14. `hns-wallet-service`
15. `hns-wallet-testkit`
16. `hns-wallet-mobile`

`release/public-crates.txt` is the machine-readable authority. Internal
requirements must accept the selected dependency versions. Cargo removes
workspace paths from normalized packages; consumers use registry sources.
`scripts/sync-release-files.sh` copies licenses and ABI files and preserves
package-local release entries.

## Dependency prerequisites

The nineteen-crate `hns-rs` `0.5.0` prerequisite uses source
`60eb912d615243a6bfb9741b17f16833c5a9181a` and checksum manifest
`release/hns-rs-0.5.0-crates.sha256`.

Execution verifies all 20 required `hns-dane-engine` `0.2.2` archives against
source `b7fdf8826c81b77650a0f740d1f05314b74969f9` and
`release/hns-dane-engine-0.2.2-crates.sha256`. The four-package light-client `0.2.6` cohort uses source `90a5dfeb5b7c00e8fea010e79f82076de4263fd6`, and
`release/hns-dane-engine-mobile-wallet-0.2.6-crates.sha256`.

Immediately before uploading, verify API checksum and non-yanked status,
archive SHA-256, clean source identity, and `crates/<package>` VCS path for
these dependencies. Their checksum manifests are active build prerequisites.

## Qualification and upload

1. Increment the changed package's explicit version. Keep consumer dependency
   requirements when they already accept it. Update the wallet lockfile and
   inspect the package and dependency changes.
2. Maintain the selected package's current release entry. Development uses
   `unreleased` and the canonical `candidate` marker. Execution requires a
   valid dated heading, a `release` marker, and the canonical release wording.
   Candidate source cannot be uploaded by execution mode.
3. Run the deterministic metadata and argument checks:

   ```sh
   python3 scripts/verify-release.py --toolchain 1.89.0
   ./scripts/check-publish-arguments.sh
   ./scripts/publish.sh --archive-only
   ```

   Archive-only mode uses `cargo package --no-verify` and checks normalized
   inventory. Select a package to limit this pass to its archive.
4. Commit the reviewed source and run `./scripts/check.sh` for that exact
   commit. Execution rejects a dirty worktree. Qualify source once; repeat a
   check when a source change, failure, or unresolved concern requires it.
5. Dispatch [release-preflight.yml](../.github/workflows/release-preflight.yml)
   with its qualified 40-character `expected_commit` and selected `package`.
   The equivalent local normalized qualification is:

   ```sh
   ./scripts/publish.sh --dry-run hns-wallet-hns
   ```

   Preflight uses local workspace patches for package verification and receives
   no publication credentials. Archive checks cover README, licenses,
   release entry, manifest normalization, source selectors, and VCS identity.
   FFI schema/vector copies must match `abi/` exactly. The Ethereum package
   must contain its pinned contract source, compiler driver, npm manifests,
   and deterministic artifact.
6. Obtain explicit authorization for the selected irreversible upload and
   authenticate without storing a token in the repository:

   ```sh
   cargo login
   ```

7. Confirm the selected package version and upload only that package:

   ```sh
   ./scripts/publish.sh --execute hns-wallet-hns --confirm-publish 0.4.2
   ```

   The package name must be allowlisted and the confirmation must match its
   manifest version. A package already present in the registry is accepted
   only after its downloaded archive exactly matches the reconstructed
   registry-backed source package, checksum, and qualified commit.

The script distinguishes the registry's independent action buckets. The
new-name interval is a 605-second new-name propagation/cooldown interval;
the update interval is a 65-second existing-crate update propagation/cooldown
interval. Override a default only to match an explicit registry limit:

```sh
PUBLISH_NEW_INTERVAL_SECONDS=605 \
PUBLISH_UPDATE_INTERVAL_SECONDS=65 \
  ./scripts/publish.sh --execute hns-wallet-hns --confirm-publish 0.4.2
```

Download the uploaded archive and verify checksum, exact source commit, and
clean VCS metadata before declaring success. Use a package-specific annotated
tag such as `hns-wallet-hns-vX.Y.Z`, then confirm its registry and docs.rs
results. Publication cannot be overwritten or deleted.
