# Releasing

The `hns-wallet-rs` crates use one shared version and are configured for
dependency-ordered publication to crates.io. A dated source candidate, dry-run,
or Git commit is not proof that any package or tag exists. Crates.io releases
are permanent: an uploaded version cannot be overwritten or deleted.

## Public package allowlist

The release script publishes only these packages, in dependency order:

1. `hns-wallet-types`
2. `hns-wallet-store`
3. `hns-wallet-chain-api`
4. `hns-wallet-ffi`
5. `hns-wallet-provider`
6. `hns-wallet-hns`
7. `hns-wallet-bitcoin-kyoto`
8. `hns-wallet-market`
9. `hns-wallet-shakedex`
10. `hns-wallet-ethereum`
11. `hns-wallet-host`
12. `hns-wallet-service`
13. `hns-wallet-testkit`
14. `hns-wallet-mobile`

`release/public-crates.txt` is the machine-readable authority for this list.
The cheap release validator fails if this document, the workspace package set,
the crates.io publish allowlists, or the dependency order diverges from it.

Every internal dependency has both a workspace path and the shared crates.io
version. Cargo removes the path when it creates a normalized source package.
Every package carries a README, exact workspace license copies, and a
package-local changelog that references the canonical shared release notes.
`scripts/verify-release.py` checks those files, the shared version, required
crates.io metadata, internal version requirements, immutable protocol source,
dependency order, ABI release copies, and Ethereum contract artifact without
compiling Rust or Solidity.
Normalized archive inspection materializes complete tar listings and selected
files before comparison so a successful match cannot hide an upstream tar read
failure or emit a benign broken-pipe warning.

## 0.1.1 release source

Version `0.1.1` is the current `hns-wallet-rs` release line. The
canonical feature inventory is in `CHANGELOG.md`; source packaging, publication,
or test success does not enable provider, value, settlement, or marketplace
product gates. Registry and tag state are external facts and must be checked at
release time rather than embedded as a claim in the source snapshot.

The selected `0.1.1` heading and package-local changelogs use one
version-scoped canonical `release` declaration. It describes prepared source,
not an existing crates.io package or tag; execution requires this exact dated
state and rejects a stale, missing, malformed, mismatched, or candidate
declaration.

Root `CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.1.1 release -->
Initial release source for the independent Handshake wallet boundary:
```

`release/CRATE-CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.1.1 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.
```

Wallet source consumes the published registry `hns-rs` `0.3.1` cohort from
immutable release source `0e99addca59778b7b7c6fc56291333a97c4c8815`. All 19
required `hns-rs` `0.3.1` archives were published to crates.io and are recorded
in `release/hns-rs-0.3.1-crates.sha256`. It also consumes the published registry
`hns-dane-engine` `0.2.2` cohort from immutable release source
`b7fdf8826c81b77650a0f740d1f05314b74969f9`. All 20 required
`hns-dane-engine` `0.2.2` archives were published to crates.io and are recorded
in `release/hns-dane-engine-0.2.2-crates.sha256`.

Execution downloads and revalidates each prerequisite immediately before any
wallet upload. It checks the API checksum and non-yanked status, downloaded
archive SHA-256, clean VCS identity, and `crates/<package>` VCS path. Dry-run
preflight uses only local workspace-path patches needed before the dependency
order has reached crates.io; it never restores a Git override for an upstream
registry cohort.

The `hns-wallet-ffi` package archive must contain byte-identical copies of
`abi/contracts-v2.schema.json` and `abi/golden-vectors-v2.json`. The
`hns-wallet-ethereum` archive must contain the Solidity source, compiler
driver, pinned npm manifests, and deterministic `NativeEthHtlc` artifact. The
archive verifier rejects a missing or divergent file. These public artifacts
document and verify boundaries; they grant no runtime or deployment authority.

## Release procedure

1. Update the shared version in the root `Cargo.toml`, every internal dependency
   version in `[workspace.dependencies]`, `CHANGELOG.md`, and
   `release/CRATE-CHANGELOG.md`. Use one version-specific `unreleased` heading
   while developing; do not add a generic `## Unreleased` section outside the
   selected shared version. Before an upload, date that heading, set the root
   and package-template canonical release declarations, and synchronize the
   package copies:

   ```bash
   ./scripts/sync-release-files.sh
   ```

   The validator rejects an execution attempt whose version heading remains
   `unreleased`, whose root changelog retains a generic Unreleased section, or
   whose canonical root/template release-state marker is absent, malformed,
   mismatched, candidate, or separated from its exact wording.

2. Run the cheap metadata, argument, and archive-inventory checks while
   preparing the release source. Archive-only mode uses `cargo package
   --no-verify`; it does not compile the packages:

   ```bash
   python3 scripts/verify-release.py --toolchain 1.89.0
   ./scripts/check-publish-arguments.sh
   ./scripts/publish.sh --archive-only
   ```

3. Inspect and commit the exact release source. Execution mode refuses a dirty
   worktree.

4. Qualify that exact commit with the complete locked gate, preferably in CI
   after an authorized push. The routine gate performs one archive-only pass
   after the workspace checks; it does not repeat 14 normalized compile checks:

   ```bash
   ./scripts/check.sh
   ```

   Do not repeat an identical expensive gate locally and in CI.

5. After routine CI succeeds for the exact release source, manually dispatch
   [`.github/workflows/release-preflight.yml`](../.github/workflows/release-preflight.yml)
   and supply that qualified 40-character commit as `expected_commit`. The
   workflow checks out and verifies that exact immutable commit. This isolated
   workflow performs the 14 real normalized publish dry-runs and never receives
   credentials or executes publication. The equivalent local command is:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   This performs Cargo's real publish dry-run for every package against local
   dependency patches, then checks each `.crate` archive for the
   common README/license/changelog/manifest inventory, removal of dependency
   source selectors, and exact source-commit metadata. FFI and Ethereum receive
   the additional artifact checks described above. To inspect one package
   while preparing source, use:

   ```bash
   ./scripts/publish.sh --dry-run hns-wallet-ffi
   ```

   Partial selection is deliberately unavailable in execution mode.

6. Reconfirm that all current `hns-rs` prerequisites are published and
   provenance-verified, then stop and obtain
   explicit human authorization for the irreversible wallet upload.
   Authentication, publication, and tagging are never CI steps and are not
   implied by a successful dry-run. Authenticate without placing a token in
   the repository:

   ```bash
   cargo login
   ```

7. Check the version again and perform the explicitly confirmed upload. The
   confirmation must equal the workspace version:

   ```bash
   ./scripts/publish.sh --execute --confirm-publish 0.1.1
   ```

Execution mode first downloads all 19 required `hns-rs` and all 20 required
`hns-dane-engine` archives and rejects any package whose API record, checksum,
or `.cargo_vcs_info.json` does not identify the exact pinned release source.
For a new wallet version, it creates and runs the custom
inventory verifier over the normalized source package before any possible
upload. Execute-mode archive validation rejects a `.cargo_vcs_info.json`
record with `"dirty": true`, even if the worktree became dirty after the
initial clean-source check.

Execution is restartable, but it never skips a wallet package merely because an
API record exists. For an already-published package/version, it reconstructs
the source archive through Cargo's registry-backed publish dry-run so normalized
`Cargo.lock` registry source and checksum fields reproduce the uploaded archive.
It then downloads the crates.io archive and requires byte-for-byte SHA-256
identity plus the current release commit in both archives'
`.cargo_vcs_info.json`. A mismatch aborts the release.

Before an upload, the script checks whether the crate name already exists and
selects crates.io's independent action bucket. A new name uses a 605-second
new-name propagation/cooldown interval; a new version of an existing name uses
a 65-second existing-crate update interval. Those defaults add five seconds to
the current [crates.io default refill periods](https://github.com/rust-lang/crates.io/blob/main/src/rate_limiter.rs).
The command waits only after a successful upload and only when another crate
remains; verified resume skips and the final upload do not sleep. Override
either interval only when crates.io communicates a different non-negative
limit:

```bash
PUBLISH_NEW_INTERVAL_SECONDS=605 \
PUBLISH_UPDATE_INTERVAL_SECONDS=65 \
  ./scripts/publish.sh --execute --confirm-publish 0.1.1
```

After each applicable cooldown, the script downloads the new archive and
requires the same exact checksum and source-commit identity before attempting
the next dependent package. If propagation is incomplete, it exits safely;
rerun after the registry API exposes the package so the registry-backed resume
archive can be verified and the sequence resumed without republishing.

After publication, push an annotated `vX.Y.Z` tag and confirm every package
page and docs.rs build. Publication cannot be rolled back: yanking can
discourage new resolution, but cannot delete or replace an uploaded version.
