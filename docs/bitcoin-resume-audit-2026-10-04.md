# Bitcoin partial-sync resume audit, 2026-10-04

The first Bitcoin recovery scan previously retained its header/filter graph only
in memory. Killing the app before the completed wallet update committed discarded
that transport progress; reopening kept the genuine birthday and repeated the
network work. The mobile progress display fix alone could not preserve it.

The shared transport now accepts an authenticated verification-context cache.
The Kyoto wallet adapter supplies that cache through the existing encrypted
WalletStore. Header batches persist after acceptance; filter-header responses
persist only after the configured distinct-peer agreement; raw filters persist
in batches of at most 64. Atomic store transactions commit the stream head,
batch metadata, digest and bounded payload chunks together. The cache binds the
account, network, genuine starting checkpoint, filter type and peer quorum.

Restart revalidates headers, attaches filter commitments to their own branch,
checks raw-filter hashes, and reruns matching with current wallet and HTLC
scripts. Stale-branch filters cannot select canonical wallet blocks. Rescans
reuse cached raw bytes with the enlarged script set. Fresh compact-filter peers
are required before completion. The wallet birthday and completed wallet scan
checkpoint remain truthful. Abrupt termination may repeat at most 63 uncommitted
filters; matched full blocks may be requested again before a wallet update
commits. Headers accepted before a later response error are retained too.

Validation on Rust 1.89.0:

- Kyoto wallet library: 57 tests passed, including encrypted-store close/reopen,
  multi-chunk payloads, account/network/checkpoint/quorum isolation, missing and
  rebound records, lock failure, oversized-batch atomicity, existing wallet
  recovery, gap extension, HTLC evidence and approved-broadcast recovery.
- Mobile controller library: 37 tests passed.
- Transport library: 29 passed and one pre-existing ignored fixture before the
  added reorg test; all five new cache regression tests subsequently passed.
  They cover interrupted first sync, repeated matching of an existing payment,
  continuation from the committed prefix, out-of-order holes, corrupt filters,
  wrong verification context, restart after a reorg, and a verified header prefix
  preceding a rejected header.
- Clippy passed with warnings denied for all targets of all three changed crates.
- Release metadata, argument checks and release-validator mutation tests passed.
- Cargo 1.98.1 publish dry-runs and normalized archive checks passed for all
  three changed 0.4.2 crates.

The Pixel remained on its older running build during qualification. Its existing
uncached initial sync was progressing, so installation was deferred to avoid
throwing away that run. The shared-core restart proof above does not claim a
physical cold-restart test of the new APK.

Release packaging also accounts for Cargo retaining publish artifacts beneath
`package/tmp-crate`. It sets aside prior temporary build archives and reads the freshly
created registry-backed archive; source identity, clean VCS and checksum gates
remain required for upload.
