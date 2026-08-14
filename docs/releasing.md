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
7. `hns-wallet-market`
8. `hns-wallet-shakedex`
9. `hns-wallet-bitcoin-kyoto`
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

## 0.1.0 release source

Version `0.1.0` is the initial `hns-wallet-rs` release line. The
canonical feature inventory is in `CHANGELOG.md`; source packaging, publication,
or test success does not enable provider, value, settlement, or marketplace
product gates. Registry and tag state are external facts and must be checked at
release time rather than embedded as a claim in the source snapshot.

The selected `0.1.0` heading and package-local changelogs use one
version-scoped canonical release-state declaration. Candidate form describes an
unpublished candidate and deliberately uses a plain `CHANGELOG.md` reference
instead of a tag link. Before an authorized upload, replace the canonical
`candidate` marker and its adjacent statement in both changelog authorities
with the canonical `release` forms below, synchronize every package copy, and
let the execute-mode validator reject any stale, missing, malformed, or
mismatched declaration.

Root `CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.1.0 release -->
Initial release source for the independent Handshake wallet boundary:
```

`release/CRATE-CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.1.0 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.
```

The previous dependency baseline used immutable `hns-rs` revision
`b24b66c382de53330ec21dd3137e056a2bea3e2d`. On 2026-08-14, all 17 required
`hns-rs` `0.2.0` archives were published to crates.io and verified to identify
that exact revision in `.cargo_vcs_info.json`. That evidence is historical and
does not satisfy the current release prerequisite.

Wallet source now consumes exact immutable `hns-rs` `0.3.0` Git revision
`88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e`. Its 19 current upstream archives
are not yet published and provenance-verified. Execution must download and
revalidate every prerequisite immediately before any wallet upload; if one is
missing, dirty, or identifies any other source commit, it stops before the
irreversible sequence. Dry-run preflight preserves the exact Git-source policy
by patching protocol dependencies to that revision and wallet dependencies to
local workspace paths. Those patches are verification aids only; they are never
used during an actual upload.

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
   selected shared version. Before an upload, date that heading, move every
   included change under it, and replace the root and package-template
   canonical candidate markers/statements with the documented release forms.
   Synchronize the package copies:

   ```bash
   ./scripts/sync-release-files.sh
   ```

   The validator rejects an execution attempt whose version heading remains
   `unreleased`, whose root changelog retains a generic Unreleased section, or
   whose canonical root/template release-state marker is absent, malformed,
   mismatched, still `candidate`, or separated from its exact wording.

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
   ./scripts/publish.sh --execute --confirm-publish 0.1.0
   ```

Execution mode first downloads all 19 required protocol archives and rejects
any package whose `.cargo_vcs_info.json` does not identify the exact pinned
`hns-rs` revision. For a new wallet version, it creates and runs the custom
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
  ./scripts/publish.sh --execute --confirm-publish 0.1.0
```

After each applicable cooldown, the script downloads the new archive and
requires the same exact checksum and source-commit identity before attempting
the next dependent package. If propagation is incomplete, it exits safely;
rerun after the registry API exposes the package so the registry-backed resume
archive can be verified and the sequence resumed without republishing.

After publication, push an annotated `vX.Y.Z` tag and confirm every package
page and docs.rs build. Publication cannot be rolled back: yanking can
discourage new resolution, but cannot delete or replace an uploaded version.
