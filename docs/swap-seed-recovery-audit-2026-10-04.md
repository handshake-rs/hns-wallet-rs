# Swap seed recovery audit, 2026-10-04

The owner subsequently authorized incrementing and submitting both mobile apps
on 2026-10-04, superseding the earlier release hold. Market and mobile-controller
0.5.0 are prepared for that delivery; testkit remains an unpublished candidate.
Automatic contract discovery remains incomplete. No recovery-file export,
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

## What this does not establish

Reproducing a key is necessary but does not reconstruct a complete refund
contract. A funded P2WSH output commits to the witness script by its SHA-256
hash; that hash does not disclose the script's hashlock, counterparty public
key or deadline. The seed cannot invert that commitment.

The current direct-peer replay path also relies on local offer and acceptance
records to identify wallet ownership. Those records are absent in a fresh seed
restore. Consequently these changes do not establish automatic recovery of
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

The earlier candidate markers and store hold were superseded by the owner's
subsequent release instruction. Market and mobile-controller releases must pass
the existing build, package and registry verification gates before distribution.
These releases must not be described as complete seed-only swap recovery.

## Validation

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
establish automatic end-to-end refund recovery. Those remain incomplete recovery work.
No real account seed or funding transaction was used in these tests.
