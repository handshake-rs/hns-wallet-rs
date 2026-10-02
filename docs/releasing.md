# Releasing

The `hns-wallet-rs` crates are versioned and released independently. Publish
only packages with changes that need distribution. A compatible dependency
patch does not require a new release of its consumers. The October 1 peer
quorum fix changed only `hns-wallet-hns`; publishing all 16 crates for it was
unnecessary. Existing published versions remain historical records. A dated source candidate, dry-run,
or Git commit is not proof that any package or tag exists. Crates.io releases
are permanent: an uploaded version cannot be overwritten or deleted.

## Public package allowlist

The release script accepts one of these packages per execution. When multiple
packages actually change, use this dependency order:

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

`release/public-crates.txt` is the machine-readable authority for this list.
The cheap release validator fails if this document, the workspace package set,
the crates.io publish allowlists, or the dependency order diverges from it.

Every internal dependency has both a workspace path and a compatible crates.io
version requirement. Each package declares its own version in its manifest.
Keep existing consumer requirements when they already accept the new version. Cargo removes the path when it creates a normalized source package.
Every package carries a README, exact workspace license copies, and a
package-local changelog. The root notes record historical coordinated releases;
new package notes belong only to the changed package.
`scripts/verify-release.py` checks those files, individual package versions, required
crates.io metadata, internal version requirements, immutable protocol source,
dependency order, ABI release copies, and Ethereum contract artifact without
compiling Rust or Solidity.
Normalized archive inspection materializes complete tar listings and selected
files before comparison so a successful match cannot hide an upstream tar read
failure or emit a benign broken-pipe warning.

## Historical 0.4.1 release source

Version `0.4.1` records the last coordinated `hns-wallet-rs` release source.
The current patches prepare only `hns-wallet-hns` and `hns-wallet-market`
`0.4.2`; the other fourteen package versions remain `0.4.1`. The
canonical feature inventory is in `CHANGELOG.md`; source packaging, publication,
or test success does not enable provider, value, settlement, or marketplace
product gates. Registry and tag state are external facts and must be checked at
release time rather than embedded as a claim in the source snapshot.

The selected `0.4.1` heading and package-local changelogs use one
version-scoped canonical declaration. During development it is a candidate;
publication requires the exact dated `release` declaration and rejects a stale,
missing, malformed, mismatched, or candidate declaration.

Root `CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.4.1 release -->
Canonical account-zero wallet and atomic-swap boundary:
```

`release/CRATE-CHANGELOG.md` release form:

```markdown
<!-- hns-wallet-release-state: 0.4.1 release -->
This crate changelog describes the prepared `hns-wallet-rs` release source.
```

Wallet source consumes the coherent nineteen-crate `hns-rs` `0.5.0` cohort
from immutable release source
`60eb912d615243a6bfb9741b17f16833c5a9181a`, recorded in
`release/hns-rs-0.5.0-crates.sha256`. It also consumes the published registry
`hns-dane-engine` `0.2.2` cohort from immutable release source
`b7fdf8826c81b77650a0f740d1f05314b74969f9`. All 20 required
`hns-dane-engine` `0.2.2` archives were published to crates.io and are recorded
in `release/hns-dane-engine-0.2.2-crates.sha256`. The wallet uses the compatible
light-client `0.2.6` cohort (`hns-light-chain`, `hns-light-wallet`,
`hns-light-p2p`, and `hns-light-sync`) from immutable engine source
`90a5dfeb5b7c00e8fea010e79f82076de4263fd6`, recorded in
`release/hns-dane-engine-mobile-wallet-0.2.6-crates.sha256`; the release gate
verifies both the historical engine cohort and all four exact patch archives.

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

1. Compare the intended source to its last released commit. Increment only the
   changed package's explicit `[package].version`, and add its own versioned
   changelog entry. Retain existing dependency requirements when they accept
   that version; raise a minimum only when the consumer needs a new API or fix.
   Update the lockfile and inspect the resulting package/dependency changes.
   Never increment `[workspace.package].version` to release a single fix: it
   records the historical coordinated release, not a publication instruction.
   `sync-release-files.sh` copies common licenses and ABI files without
   overwriting package changelogs.

   The selected package requires a dated heading and canonical `release`
   declaration before execution. Other packages may remain on older versions.

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
   after the workspace checks; it does not repeat 16 normalized compile checks:

   ```bash
   ./scripts/check.sh
   ```

   Do not repeat an identical expensive gate locally and in CI.

5. After routine CI succeeds for the exact release source, manually dispatch
   [`.github/workflows/release-preflight.yml`](../.github/workflows/release-preflight.yml)
   and supply that qualified 40-character commit as `expected_commit` and the
   package name as `package`. The
   workflow checks out and verifies that exact immutable commit. This isolated
   workflow performs the selected package's normalized publish dry-run and never receives
   credentials or executes publication. The equivalent local command is:

   ```bash
   ./scripts/publish.sh --dry-run hns-wallet-hns
   ```

   This performs Cargo's real publish dry-run for the selected package against local
   dependency patches, then checks each `.crate` archive for the
   common README/license/changelog/manifest inventory, removal of dependency
   source selectors, and exact source-commit metadata. FFI and Ethereum receive
   the additional artifact checks described above. To inspect one package
   while preparing source, use:

   ```bash
   ./scripts/publish.sh --dry-run hns-wallet-ffi
   ```

   Execution requires exactly one package. The old workspace-wide execute
   command is rejected before Cargo or registry access.

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
   confirmation must equal the selected package's version:

   ```bash
   ./scripts/publish.sh --execute hns-wallet-hns --confirm-publish 0.4.2
   ```

Execution mode first downloads all nineteen `hns-rs` `0.5.0` crates, all 20
historical `hns-dane-engine 0.2.2` archives, and the four-crate light-client
`0.2.6` cohort. It rejects any package whose API record, checksum,
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
  ./scripts/publish.sh --execute hns-wallet-hns --confirm-publish 0.4.2
```

After each applicable cooldown, the script downloads the new archive and
requires the same exact checksum and source-commit identity before returning success for the selected package. If propagation is incomplete, it exits safely;
rerun after the registry API exposes the package so the registry-backed resume
archive can be verified and the selected upload verified without republishing.

After publication, use a package-specific annotated tag such as
`hns-wallet-hns-vX.Y.Z` and confirm that package's registry page and docs.rs build. Publication cannot be rolled back: yanking can
discourage new resolution, but cannot delete or replace an uploaded version.
