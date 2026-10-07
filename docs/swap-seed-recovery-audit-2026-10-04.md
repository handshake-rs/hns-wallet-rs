# Swap seed recovery audit, 2026-10-04

Market and mobile-controller 0.5.0 were published and included in the submitted
1.0.16 apps. The agent incorrectly treated the instruction to submit the apps
as acceptance of incomplete seed-only recovery. The owner did not accept that
limitation. The replacement implements chain-visible contract discovery and is being
qualified for the next release. Testkit remains unpublished. No recovery-file export,
file-confirmation step, compatibility reader or migration adapter is included.

## Defect and current change

The previous settlement-key derivation included a private offer intent and a
local wallet profile identifier. Restoring the recovery seed did not reproduce
a refund key when those records were absent. Neither input was required to
separate signing authority between swaps: the signed public session, participant
role and complete network binding already provide that separation.

The new format derives a settlement scalar from the recovery seed plus the
public session ID, role and network. The profile ID locates the seed and the
encrypted allocation in the store; it does not affect the scalar. Allocation
records still authenticate their public binding and seed commitment, reject
conflicting network bindings and protect the signing scalar from serialization.
The private offer-intent field and old local-offer field alias are removed.

Board identity now derives from the recovery seed and network, without a
profile ID. Maker preimages derive from the seed and public session/offer IDs,
without a private intent. Public identifiers remain necessary to distinguish
agreements; users must not have to save them manually. Domains and storage
versions change for the new beta format; existing derivations are not guessed
or silently treated as equivalent.

## What 0.5.0 did not establish

Reproducing a key is necessary but does not reconstruct a complete refund
contract. A funded P2WSH output commits to the witness script by its SHA-256
hash; that hash does not disclose the script's hashlock, counterparty public
key or deadline. The seed cannot invert that commitment.

The 0.5.0 direct-peer replay path also relied on local offer and acceptance
records to identify wallet ownership. Those records are absent in a fresh seed
restore. Consequently 0.5.0 did not establish automatic recovery of
funded swaps after local database loss. A counterparty's retained public terms
can help, but availability of that counterparty is not a sufficient refund
guarantee. Local persistence alone is not an independent recovery path.

The former private-intent derivation cannot be corrected retroactively for an
already funded output when its original derivation context is gone. This
candidate does not claim to recover that historical test output.

## Required to establish complete seed-only swap recovery

An automatic recovery path must rediscover the authenticated public contract
terms and public key context after restoring only the wallet seed. It must not
require a user-managed file, a developer-held secret, or cooperation from an
online counterparty to refund. If recovery information is stored on-chain, it must fit each
chain's actual script and transaction policy and be committed so that removing
or altering it cannot leave a funded output unrecoverable.

A fresh-profile test must discard all local offers, acceptances, key allocations
and execution journals, then reconstruct the exact funded output's script and
sign a valid refund using rediscovered data. Test both assets, both participant
roles, interrupted funding, and expired agreements. Reject wrong seed/network,
changed script commitments and refunds before independently verified maturity.
Qualification must cover the shared core and both native app paths. Signing and
broadcasting real test-account funds remains a separate owner action.

The 1.0.16 store submission did not complete the requested recovery work. A
replacement release must qualify chain-visible public terms, automatic discovery
after seed-only restoration, and actual refunds for both assets and both roles.
Passing key-derivation or package checks does not satisfy that requirement.

## Historical 0.5.0 validation

- The complete market library suite passed: 30 tests. The mobile controller
  library suite passed: 37 tests. These exercised the changed runtime before
  the package-only version bump.
- After the bump and the explicit direction coverage was added, all four
  direct-responder tests passed against 0.5.0. Each of the two bilateral offer
  tests now restores both seeds into fresh profiles and verifies the authorities
  in the canonical HNS and BTC contracts, including valid digest signatures.
- Fresh-profile key reconstruction, seed/session/role/network separation,
  board identity restoration and maker preimage restoration passed.
- Locked workspace Clippy for all targets passed with warnings denied. Format,
  release metadata, dependency-path checks, their regression tests, publish
  argument validation and whitespace checks passed.

| Public offer | Participant restored | Refund authority | Redeem authority |
| --- | --- | --- | --- |
| BTC for HNS | Offer setter / execution taker | BTC | HNS |
| BTC for HNS | Responder / execution maker | HNS | BTC |
| HNS for BTC | Offer setter / execution taker | HNS | BTC |
| HNS for BTC | Responder / execution maker | BTC | HNS |

These tests supply an authenticated public agreement to the fresh wallet; they
verify keys and canonical contract bindings. They do not discover that agreement
from the chains, sign a funded refund transaction, test maturity on-device, or
establish automatic end-to-end refund recovery. Those were incomplete at the 0.5.0 delivery.
No real account seed or funding transaction was used in these tests.


## Chain publication and native recovery, 2026-10-07

The replacement writes 204 bytes of complete public contract terms through
standard single-null-data transaction ancestors. Bitcoin uses three 80-byte
publication frames; Handshake uses six 40-byte frames. The final HTLC transaction
spends the last ancestor and commits to the exact publication and full network
binding. Removing a frame or changing its terms invalidates the final commitment.
Every child signature is verified against its exact parent output, and automatic
wallet discovery requires the publication anchor to match the restored seed's
ordinary internal address zero. Public swap identifiers supply the context;
no original offer, key allocation, local profile ID or counterparty response is
an input to this recovery path.

The complete package is prepared and included in the user's aggregate fee cap
before any irreversible broadcast. Only ordinary wallet outputs exist at every
interrupted publication prefix. Bitcoin persists the full approved sequence and
resumes it in parent order. Handshake retains the signed sequence with its native
approved settlement workflow and initial-input reservations. HTLC funding cannot
confirm without the committed ancestors.

A seed-only restore discovers public contract terms from wallet chain history,
recreates only seed-owned settlement allocations, and exposes the exact funded
output for reclaim. Both normal approval paths still independently require a
current verified chain view, an unspent exact contract and consensus maturity.
Reclaim eligibility shown from wall time supplies no spending authority.

Each chain retains its own independently verified spend observation. A missing
observation revokes only that chain's current settlement state while retaining the
previous evidence. An observed redeem reconstructs the public preimage. A taker
whose funded leg was redeemed can claim the first leg with its restored receiver
key; the target native runtime verifies that leg before signing and broadcast.
Maker recovery retains the timeout route rather than exposing a newly derived
secret without the original two-chain funding authorization.

The fixed internal discovery address makes restored discovery independent of a
private derivation counter. Its reuse links publication families on the public
chain, and publication ancestors add fees and transaction count. These are
explicit properties of this mechanism. Existing bounded history and watch limits
continue to fail closed instead of discarding active recovery records.

Additional validation uses synthetic funded transactions and freshly encrypted
stores. It checks exact negotiated scripts, both offer directions, both seeds,
valid Bitcoin and Handshake refund and redeem signatures, missing or altered
ancestry, unsigned children, wrong seed/network, premature refunds, aggregate
fees, interrupted prefixes and parent-first restart. The mobile controller test
reconstructs Handshake candidates from transaction history, exercises all four
participant/direction cases, blocks fresh funding from recovered records, tracks
refunds and per-chain reorganization, and resumes a taker's public-secret claim.
The final market, mobile-controller and service suites passed 30, 38 and 37
tests respectively. The final Bitcoin and Handshake publication suites each
passed two tests, including unsigned-child rejection. Release metadata, release
validator mutations, dependency checks and publish-argument checks passed.
Both Android and iOS native bridges compile against the changed source; their
native host suites passed 38 and 23 tests respectively. The replacement has not
been published or delivered until the registry and store handoff are recorded.

The old beta output with its missing private derivation context is unchanged.
This publication format establishes recovery for newly funded contracts and adds
no legacy derivation adapter. No real wallet seed or real funds were used in
these qualification transactions.

## Final-submission expiry correction

The first recovery cohort was published from `ce222cb` but the app delivery was
stopped before upload when the funding-resume audit found that an approved
publication package could reveal its final HTLC after its live funding window.
The correction is Bitcoin 0.4.4, Handshake 0.4.5 and mobile 0.5.2. Bitcoin
commits the stricter funding cutoff through its existing authenticated approval
expiry and consumes the funding guard in the same write. Handshake persists the
original funding cutoff and checkpoints whether the final contract was exposed.
Both re-read time at final submission and reject expired funding/rebroadcast.
An unexposed expired contract releases ordinary funds; an attempted contract
retains its journal because the signed bytes may already have reached a peer.
Ordinary wallet-send restart behavior remains unchanged.
