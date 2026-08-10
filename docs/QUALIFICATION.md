# Qualification matrix

This file records evidence, not intent. Unit coverage never authorizes mainnet
value. “Implemented source” means the code boundary exists; “pending” means the
current commit has no recorded result for that gate.

| Area | Compile/unit evidence for current tranche | Persistence/restart | Reorg | Real network/product | Bench/audit | Release status |
| --- | --- | --- | --- | --- | --- | --- |
| Types/chain traits | pending consolidated gate | n/a | n/a | n/a | no external audit | qualification pending |
| Encrypted store/schema v3 | pending consolidated gate | source includes migration checkpoint, encrypted typed CRUD/CAS/batches and restart-safe workflow rows | n/a | no device secure-store test | no DB benchmark/audit | qualification pending |
| HNS wallet/names | new `production_followup_` synchronized-read tests are source-only and unexecuted; current combined `production_next_` purpose-separation PASS at exact local source `9d0cbeb8`: 1 passed, 0 failed, 26 filtered; prior focused `hns_shakedex` PASS on NVMe: 4 passed, 0 failed, 22 filtered; focused `canonical_hns_v3_name_action` PASS: 4 passed, 0 failed, 19 filtered; prior `canonical_hns_v2`: 6 passed, 0 failed, 9 filtered; prior account-scoped persistence regression: 1 passed, 0 failed, 15 filtered; consolidated evidence pending | source adds the shared-store synchronized non-value runtime with exact account/entity fences, durable interrupted-scan recovery, one internal chain/mempool binding, and no backend I/O under store closures; source also includes authenticated loopback RPC configuration, strict HTTP/JSON parsing, atomic coin/name/Shakedex-role snapshot restoration, complete bounded account-prefix entity reloads, encrypted monotonic scan state and durable cross-writer scan fence, WalletAccount-coupled protected Shakedex key allocation/rederivation, canonical current/proof summaries and exact owner inclusion, legacy-row revalidation, ephemeral ownership/finalize/Shakedex lock and exact TRANSFER authorities, snapshot-bound HSD median time past, versioned action context, exact persisted input evidence, canonical TRANSFER/FINALIZE construction, typed reservations, store-globally keyed protected Shakedex source and exact account-funding reservations, runtime-bound funding derivations, single-use approval, ordered coin/name and purpose-bound Shakedex suffix signing with distinct lock-only and transfer-only APIs, runtime-owned same-snapshot Shakedex transaction/spender observations, canonical local policy/minimum-fee checks, exact signed-byte fee-quote persistence/revalidation, and durable rebroadcast/name-action state | source includes durable read-fence recovery plus chain/mempool restart and selection/lock rejection tests (unrun), epoch-bound checkpoint rewind, ordered spender evidence, split current/proof revalidation, exact cross-scan binding rejection, authority reacquisition, persistent protected reservations across reversible Shakedex confirmations/conflicts, reapproval state, and one-reconciliation fee-quote recovery; no multi-process restart/reorg execution | concrete adapter source pinned to node RPC v1 commit `c1b633d1`; canonical protocol crates pinned coherently to immutable `hns-rs` `b33b346`; no multi-process regtest or product read/Shakedex/name-action run | no resource measurement/audit | synchronized non-value read source and wallet-owned P2PKH TRANSFER/direct-FINALIZE source implemented; HNS Shakedex-funding, value-runtime, and fee-policy qualification gates remain false; product and real-network qualification pending |
| Provider core | expanded `production_followup_` scoped-read/consent/public-projection tests are source-only and unexecuted; prior combined and account-join passes predate this source | provider state, runtime control, selector, and synchronized reads share one store authority; read grants extend one exact account; Names prompts disclose and freeze at most 64 exact names, reauthenticate the current account/set at approval, and persist only unchanged hashes; pending disclosures do not survive restart | source tests changed name/account scope plus restarted node/account/store fences but has no multi-process product run | checked-in executable remains five-control only; no installed-browser exact-consent E2E | no audit | product integration pending; value/browser unavailable |
| Fixed-price Shakedex | current combined `production_next_` FINALIZE PASS at exact local source `9d0cbeb8`: 6 passed, 0 failed, 9 filtered; prior focused `hns_shakedex` PASS on NVMe: 1 aggregate unit passed, 0 failed, 4 filtered; 1 restart integration passed, 0 failed, 0 filtered; exact-lock/Denuo/board filter PASS on NVMe: 1 passed, 0 failed, 3 filtered; prior immutable-V2 listing/gate filter: 3 passed, 0 failed; focused terminal-release `production_tranche_` PASS: 5 passed, 0 failed (4 workflow plus 1 encrypted store reopen); consolidated evidence pending | encrypted parent-plan/board CAS plus protected monotonic seller-key allocation; buyer-fulfillment/seller-recovery/seller-script-FINALIZE child binds exact structural plan, parent action/bytes/hash, stable TRANSFER/owner/NameState/renewal identity, historical snapshot/mempool evidence, source/funding evidence and reservations, approval/revision, final signed bytes/fee quote, and pre-submit fence; fresh binding advances do not restore or replace authority, and persisted evidence never restores current authority; terminal workflow evidence and complete reservation deletion use one CAS | source state machine retains protected reservations through reversible states and uses runtime-owned transaction/all-input-spender evidence for recovery, mempool, confirmation, conflict, rollback, same-byte rebroadcast, and exact terminal release; released reconciliation is read-only and reports `RecoveryRequired` if finality changes; focused binding-advance/replacement/reorg/finality unit cases pass, but there is no multi-process restart/reorg evidence | no regtest/live-Denuo/provider/UI E2E | no audit | all Shakedex and dependent HNS Shakedex-funding/value/fee gates remain false |
| Market sessions | prior unit baseline only | CAS journal source | evidence incomplete | no pair E2E | no audit | unavailable |
| Bitcoin Kyoto | encrypted-persister/order filter PASS on 2026-08-09: 3 passed, 0 failed, 19 filtered; ahead-tip crash-edge filter PASS: 1 passed, 0 failed, 21 filtered; prior allocation filter PASS on NVMe: 10 passed, 0 failed, 8 filtered; consolidated gate pending | source includes strict versioned encrypted aggregate BDK-3.1.0 CAS, exact-only stale retry, staged-change retention on failure, one shared store authority, encrypted CAS-backed monotonic session/role swap-key allocation, protected seed/allocation records, authenticated re-derivation, BDK-first sync journal, bounded reconciliation chunks, exact restart resume, and pre-broadcast intent; aggregate state fails closed at 1 MiB; allocation database reopen covered by the prior targeted filter; legacy BDK SQLite import and pinned Kyoto header/filter/peer persistence unavailable | source queries exact canonical hash membership within a bounded retained window and forces recovery when BDK is ahead of a synchronizing journal; no allocation reorg or multi-process snapshot-rollback evidence | no regtest/P2P/broadcast run | not measured/no audit | send and settlement hard-disabled; normalized/chunked BDK backend pending |
| Ethereum | containment tranche pending consolidated gate | offline derivation and dormant typed primitives only; no synchronization/history persistence | no restart/reorg evidence | deterministic contract compiled only in prior baseline; no embedded Helios/local-chain run; permits unavailable; mainnet denied | no contract audit | synchronization/history/send/signing/settlement unavailable |
| ABI/host | new `production_followup_` required/sorted/bounded/canonical name-disclosure and exact-host-retention cases are source-only and unexecuted; earlier account-join/control passes predate the new shape | source includes exact private-ABI-v2 sequencing/correlation/authority state, approval-schema-v3 negotiation/state, updated private/public schemas, structural vectors, and runtime-invalid ordering/hash vectors; strict approval-v2/v3 permission summaries reject one another | earlier restart evidence predates this change | no browser/mobile approval-v3 adoption, trusted rendering, platform E2E, verifier, launcher, or generated binding | no resource measurement/audit | product integration pending; private control dispatch only; browser/value unavailable |
| Browser products | separate repositories | platform integration pending | n/a | no installed/signed E2E | no review | unavailable |

## Single qualification command

The workspace gate is `scripts/check.sh`. It performs formatting, a locked
all-target check, warning-denied Clippy, tests, warning-denied docs,
sibling/forbidden-backend dependency checks, deterministic Solidity artifact
comparison, and an npm high-severity audit.

The Bitcoin allocation subtarget was tested once on 2026-08-03 from a
disposable NVMe checkout with an NVMe target and temporary directory:
`cargo test --locked -p hns-wallet-bitcoin-kyoto swap_key_store::tests --
--test-threads=1`. It passed 10 tests with 0 failures and 8 filtered out. No
standalone build/check, full workspace gate, optimized RocksDB compilation,
network test, or benchmark was run.

The encrypted BDK persistence tranche used the same cache-backed target policy
for two narrowly filtered commands on 2026-08-09:
`cargo test --locked -p hns-wallet-bitcoin-kyoto persistence::tests --
--test-threads=1` and
`cargo test --locked -p hns-wallet-bitcoin-kyoto
runtime::restart_tests::synchronizing_tip_ahead_requires_recovery_but_exact_reconciliation_resumes
-- --test-threads=1`. They passed 3 and 1 tests respectively with zero failures
and 19 and 21 filtered out. This covers encrypted create/load/reopen, staged
change retention after a locked-store failure, exact stale retry, divergent
writer rejection, descriptor/network immutability, source-order assertions,
unsupported BDK-version rejection, and the persist-before-journal crash edge.
It is focused source evidence only;
the full workspace, regtest/P2P, multi-process restart, resource, and audit gates
were not run.

The final canonical-name source was tested on 2026-08-03 from an isolated NVMe
clone with NVMe target and temporary directories:
`cargo test --locked --lib -p hns-wallet-hns -p hns-wallet-shakedex
canonical_hns_v2 -- --test-threads=1`. The HNS crate passed 6 tests with 0
failures and 9 filtered; Shakedex passed 3 listing/gate tests with 0 failures.
The later exact regression
`cargo test --locked --lib -p hns-wallet-hns
canonical_hns_v2_persisted_queries_are_complete_and_account_scoped --
--test-threads=1` passed 1 test with 0 failures and 15 filtered.
No standalone build/check, full workspace gate, RocksDB compilation, network
test, or benchmark was run. The next broad evidence event is one consolidated
CI invocation of `scripts/check.sh`; do not run
separate build, check, test, and pre-push copies of the same gate. Record its
commit ID, runner/platform, full result, test count, and artifact hashes here.

The later exact-UTXO/fee-policy/signing substrate added focused unit cases but,
by explicit efficiency constraint, did not execute another local build or test
session. Those cases and the consolidated gate remain pending evidence; the
prior results above do not qualify the new source.

The wallet-owned name-action tranche ran one narrowly filtered NVMe command:
`cargo test --locked --lib -p hns-wallet-hns canonical_hns_v3_name_action -- --test-threads=1`.
The final invocation passed 4 tests with 0 failures and 19 filtered. It covered
canonical TRANSFER and FINALIZE construction/signing, candidate maturity and
renewal binding, and closed node wire vocabulary. It is focused implementation
evidence only and cannot change either false HNS release gate.

The provider account-binding tranche used the same NVMe-only target and temp
policy for the narrowly filtered command:
`cargo test --locked -p hns-wallet-provider -p hns-wallet-service -p hns-wallet-ffi -p hns-wallet-host canonical_provider_account_join -- --test-threads=1`.
After the focused run exposed and this tranche corrected two pre-existing ABI
test-compilation inconsistencies plus an incomplete host capability fixture,
the final incremental invocation passed 5 tests with 0 failures and 31
filtered: FFI 1, host 1, provider 1, and service 2. No standalone build/check,
full workspace gate, RocksDB compilation, network test, or benchmark was run.
This is source-contract evidence only; concrete-runtime, restart, installed
browser, and product qualification remain pending.

The persistent control-plane tranche adds
`production_tranche_persistent_control_reopens_locked_and_preserves_only_permission_authority`.
The combined focused command below passed that one service regression with 0
failures and 7 filtered service-library tests. It covers rejection of an
already-unlocked composition, ABI unlock/lock, the exact five-method control
subset, generic-permission gating, encrypted tombstone survival across database
reopen, fresh service/wallet sessions, and loss of process-local
authority/request state. Installed-product and broader qualification remain
pending.

The next exact-account tranche adds five `production_next_` service regressions
for the seven-method advertised surface, same-Arc construction, minimized
singleton account grants, missing-record unlock relock, restart selection
mismatch, locked startup/session rotation/tombstone reopen behavior, successful
provider-lock binding, authenticated zero-account/malformed-row rejection, and
rejection of every chain-read/module/value method. A sixth provider-core
regression iterates all 12 HNS methods and requires ICANN namespace rejection
before permission or approval processing. At exact local source revision
`9d0cbeb8e59dcd74c189ec973b218a9f3afe167e`, the one combined filter passed all
five service regressions and the provider regression with zero failures (8 and
9 tests filtered respectively). This remains focused source evidence and does
not supersede the installed-product and consolidated gates above.

The synchronized non-value HNS read tranche adds two HNS runtime, one provider,
three service, one FFI, and one host `production_followup_` regressions. They cover the live exact
chain/mempool result and authenticated commit, proof that backend calls do not
run under a shared-store closure, durable interrupted-scan recovery, stale
chain and restarted mempool rejection, account/lock fences, account approval
followed by additive read permission, exact prompt-disclosed name scope,
canonical ordering/hash validation, changed-scope/account stale rejection, minimized
balance/history/receive/name shapes, stale/unapproved-name denial, printable
ASCII and JavaScript integer bounds, HNS namespace enforcement, and continued
absence of module/value methods. They have not been executed. The single
intended focused invocation is:

```text
CARGO_TARGET_DIR=/home/den/.cache/codex/hns-wallet-rs/target \
TMPDIR=/home/den/.cache/codex/hns-wallet-rs/tmp \
cargo test --locked --offline \
  -p hns-wallet-ffi -p hns-wallet-host -p hns-wallet-hns \
  -p hns-wallet-provider -p hns-wallet-service \
  production_followup_ -- --test-threads=1
```

Do not record a pass, commit identifier, or test count until that one command
finishes. It is still focused source evidence, not browser, regtest, resource,
or release qualification.

The fixed-price protocol/board tranche ran one narrowly filtered NVMe command:
`cargo test --locked --offline -p hns-wallet-shakedex
canonical_shakedex_fixed_price -- --test-threads=1`. It passed 1 test with 0
failures and 3 filtered. The case covered exact listing identity, network/time/
locking-coin cryptographic binding, canonical Denuo offer/inventory/request/
cancellation envelopes, registry substitution rejection, monotonic
seller/name replay and tombstone policy, relisting replacement, encrypted board
CAS, stale-writer rejection, and database reopen/unlock/reload. The protocol
boundary still cannot prove a supplied coin current or unspent, and there was
no live relay, node, regtest, chain reorg, standalone build/check, RocksDB,
network, benchmark, or broad test run. All Shakedex product/value gates remain
false.

The protected HNS key/restoration/current-authority tranche ran the single
filtered offline command with NVMe target and temporary directories:
`cargo test --locked --offline -p hns-wallet-hns -p hns-wallet-shakedex
hns_shakedex -- --test-threads=1`. Its first invocation stopped during
compilation because the new encrypted 33-byte public-key field needed an exact
bounded Serde adapter; after that source correction, the same command passed 3
HNS tests with 0 failures and 22 filtered. It covered the durable scan gate,
WalletAccount-coupled monotonic allocation/reopen, immutable canonical economic
terms, signer redaction, fail-closed legacy MTP, and the stable role-separation
vector. `hns-wallet-shakedex` and its restart target compiled, but the filter
selected 0 of their tests (4 unit and 1 restart case filtered). No standalone
build/check, full workspace gate, RocksDB compilation, network test, benchmark,
or broad test run occurred. All HNS Shakedex-funding/value/fee and Shakedex
value/product gates remain false.

The durable buyer-fulfillment/seller-recovery aggregate, store-global source and
exact funding reservations, runtime suffix authorization, pre-submit fence,
and chain reconciliation source used the same focused command. Its first run
exposed an out-of-window reservation fixture and duplicate transition patterns;
after those exact source corrections, the rerun passed 4 HNS unit tests, 1
Shakedex aggregate unit test, and 1 Shakedex restart integration test. No
standalone build/check or broader test ran. Consolidated CI, live-Denuo/
provider/UI integration, multi-process regtest restart/reorg/conflict execution,
and durable script-controlled FINALIZE remained pending at that evidence event;
every related release gate stayed `false`.

The subsequent seller-script-FINALIZE tranche changes that source-status line,
not its evidence status: the durable child, distinct transfer-only funding
purpose/APIs, exact parent and stable TRANSFER/owner/NameState/renewal identity,
historical construction bindings with harmless fresh-binding advance,
revision-bound approval, final quote, pre-broadcast fence, and shared terminal
release machinery are now implemented. It adds six Shakedex
`production_next_` restart/reopen/CAS/binding-advance/replacement/reorg/finality tests and one
HNS purpose-separation test. At exact local source revision
`9d0cbeb8e59dcd74c189ec973b218a9f3afe167e`, the one combined filter passed all
seven with zero failures (9 Shakedex and 26 HNS tests filtered). This is focused
unit/reopen evidence, not live integration or the full gate. Legacy
ShakedexValue schema-v1 rows remain
decodable by the new reader because FINALIZE is an additive tagged variant, but
an older binary cannot decode the new variant. Downgrade after writing it is
unsupported and unqualified.

The persistent-control and evidence-backed terminal-release source used one
combined, narrowly filtered command with the existing NVMe target:

```text
CARGO_TARGET_DIR=/home/den/.codex/targets/hns-wallet-shakedex-aug3 \
TMPDIR=/home/den/.codex/tmp/hns-wallet-shakedex-aug3 \
cargo test --locked --offline \
  -p hns-wallet-store -p hns-wallet-service -p hns-wallet-shakedex \
  production_tranche -- --test-threads=1
```

The initial invocation compiled the three targets and exposed a Linux
temporary-directory mode error in the new service fixture; the next run
reached a stale expected error code after locked-store failures were made
explicitly `WalletLocked`. After those fixture corrections, the same command
passed 6 tests with 0 failures: 1 service encrypted-reopen regression, 4
Shakedex exact-spender/final-competitor/reorg/terminal-state regressions, and 1
encrypted store atomic-delete/reopen regression. Twenty unrelated tests were
filtered across the selected targets. No standalone build/check, broad
workspace test, RocksDB compilation, network run, or benchmark was performed.

## Prior baseline evidence

The earlier 2026-08-02 baseline result was PASS: 34 Rust unit/negative tests,
formatting, locked all-target check, warning-denied Clippy and docs,
dependency-boundary checks, deterministic Solidity artifact comparison, and an
npm audit with zero vulnerabilities. It predates this tranche and is not
qualification evidence for the current commit.

Baseline contract evidence SHA-256:

- source: `537c0a4dd05f8128a6fe11046edc825f5a0a6577fc0fe0b61c7b31d5ec00caa7`;
- generated artifact: `ba3bfde0443c13bcdbe287ef292072d1a2a8645fd4efd9bdee2b9dd566f52cec`;
- npm lockfile: `43c5070e3475eb76ea9218bbafbe743307f4e9c7052153f2f53d5c4da3fde8e8`.

## External gates still required

- the current commit's single `scripts/check.sh` CI result;
- `hns-rs` conformance vectors and fuzz smoke/full campaigns;
- HNS and Bitcoin regtest success/refund/restart/reorg demonstrations;
- Shakedex buyer fulfillment, seller recovery, durable script FINALIZE,
  conflict/rebroadcast, and evidence-backed reservation-release demonstrations
  through the live Denuo/provider/trusted-UI product path;
- Kyoto invalid-PoW/filter/peer-consistency fixtures and birthday scans;
- Ethereum local-chain lock/redeem/refund/replay/receiver/refund-address,
  reentrancy/event/rollback tests;
- embedded proof-producing Helios runtime plus persistence/restart/reorg tests;
- Chromium installed-extension/native-host and signed Android/iOS tests;
- Kyoto disk/bandwidth/startup/mobile-memory benchmarks; and
- independent review of key management, provider authority, HTLC scripts,
  Solidity source/bytecode, and cross-chain timeout policy.

No automated test moves live mainnet funds.
