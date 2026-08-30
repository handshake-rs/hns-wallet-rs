#![doc = "Chain-neutral, evidence-driven market and atomic-swap workflow state."]
#![forbid(unsafe_code)]

mod direct_board;
mod direct_maker;
mod session_board;
mod settlement_key;

use hns_marketplace_protocol::{AssetId, ChainId, DeadlineKind, SwapAssetSide, SwapSessionHello};
use hns_wallet_bitcoin_kyoto::{
    HtlcSpendBranch, VerifiedBitcoinHtlcSpendObservation, VerifiedBitcoinLock,
    build_denuo_bitcoin_htlc,
};
use hns_wallet_chain_api::{Preimage, VerifiedLock};
use hns_wallet_hns::VerifiedNativeHtlcSpend;
use hns_wallet_store::{SecretKind, StoreError, WalletStore};
use hns_wallet_types::{
    Amount, ModuleId, ObjectHash, SessionId, WalletAsset, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use direct_board::{
    DenuoDirectOfferAdmission, DenuoDirectOfferBoardPolicy, DenuoDirectOfferCancellationAdmission,
    DenuoDirectOfferLevel, DenuoDirectOfferRecord, DenuoDirectOfferSnapshot,
    MAX_DENUO_DIRECT_OFFERS, admit_denuo_direct_offer, admit_denuo_direct_offer_cancellation,
    denuo_direct_offer_inventory, live_denuo_direct_offer_levels, load_denuo_direct_offer,
    load_denuo_direct_offers,
};
pub use direct_maker::{
    DenuoBtcForHnsMakerProposal, DenuoBtcForHnsMakerProposalRequest, DenuoBtcForHnsOfferRequest,
    DenuoLocalDirectOffer, cancel_denuo_local_direct_offer,
    create_denuo_btc_for_hns_maker_proposal, create_denuo_btc_for_hns_offer,
    list_local_denuo_direct_offers, load_denuo_btc_for_hns_maker_preimage,
};
pub use session_board::{
    DenuoDirectSwapAdmission, DenuoDirectSwapPeerStatus, DenuoDirectSwapPolicy,
    DenuoDirectSwapRecord, DenuoDirectSwapSnapshot, DenuoDirectSwapStage, MAX_DENUO_DIRECT_SWAPS,
    admit_denuo_direct_offer_take, admit_denuo_direct_swap_hello, admit_denuo_direct_swap_proposal,
    load_denuo_direct_swap, load_denuo_direct_swaps, validate_denuo_direct_swap_peer_status,
};
pub use settlement_key::{
    CrossChainSwapKey, CrossChainSwapKeyAllocation, CrossChainSwapKeyError,
    CrossChainSwapKeyRequest, SwapParticipant, allocate_cross_chain_swap_key,
    derive_cross_chain_swap_key_from_store, load_cross_chain_swap_key_allocation,
};

pub const MAX_CONCURRENT_SWAP_SESSIONS: usize = 16;

const DENUO_EXECUTION_WORKFLOW_DOMAIN: &[u8] = b"hns-wallet-rs/denuo-execution-workflow/v1";
const DENUO_OBSERVED_PREIMAGE_DOMAIN: &[u8] = b"hns-wallet-rs/denuo-observed-preimage/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedQuote {
    /// Identifier of the signed exact terms that authorized this quote. For a
    /// direct HNS/BTC swap this is the maker's direct-offer ID.
    pub terms_id: ObjectHash,
    pub offered: Amount,
    pub received: Amount,
    pub valid_until_unix: u64,
}

impl VerifiedQuote {
    pub fn validate(&self, now_unix: u64) -> Result<(), MarketError> {
        if self.offered.asset == self.received.asset
            || self.offered.base_units.is_zero()
            || self.received.base_units.is_zero()
            || self.valid_until_unix <= now_unix
        {
            return Err(MarketError::InvalidQuote);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TimeoutPlan {
    pub first_chain_refund_at: u64,
    pub second_chain_refund_at: u64,
    pub minimum_safety_margin: u64,
}

impl TimeoutPlan {
    pub fn validate(self, now: u64) -> Result<(), MarketError> {
        if self.second_chain_refund_at <= now
            || self.first_chain_refund_at <= self.second_chain_refund_at
            || self
                .second_chain_refund_at
                .checked_add(self.minimum_safety_margin)
                .is_none_or(|minimum| self.first_chain_refund_at < minimum)
        {
            return Err(MarketError::UnsafeTimeouts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapState {
    OfferPublished,
    OfferTakeReceived,
    OfferReserved,
    TermsFrozen,
    RefundsPrepared,
    FirstFundingPending,
    FirstFunded,
    SecondFundingPending,
    BothFunded,
    FirstRedeemed,
    SecretObserved,
    SecondRedeemed,
    Completed,
    RefundEligible,
    RefundBroadcast,
    Refunded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SwapSession {
    pub id: SessionId,
    pub revision: u64,
    pub state: SwapState,
    pub first_module: ModuleId,
    pub second_module: ModuleId,
    pub offered: Amount,
    pub received: Amount,
    pub terms_id: ObjectHash,
    pub hashlock: ObjectHash,
    /// Canonical encoded, jointly signed Denuo `SwapSessionHello` for an
    /// execution opened from the Denuo board. Generic non-Denuo sessions keep
    /// this empty; a Denuo execution never relies on a board record surviving
    /// independently of its durable recovery journal.
    #[serde(default)]
    pub accepted_denuo_terms: Option<Vec<u8>>,
    pub timeouts: TimeoutPlan,
    pub first_funding: Option<ObjectHash>,
    pub second_funding: Option<ObjectHash>,
    pub first_redemption: Option<ObjectHash>,
    pub second_redemption: Option<ObjectHash>,
    pub refund: Option<ObjectHash>,
    pub last_verified_at_unix: u64,
    pub failure_reason: Option<String>,
}

impl SwapSession {
    pub fn new(
        id: SessionId,
        first_module: ModuleId,
        second_module: ModuleId,
        quote: VerifiedQuote,
        hashlock: ObjectHash,
        timeouts: TimeoutPlan,
        now_unix: u64,
    ) -> Result<Self, MarketError> {
        quote.validate(now_unix)?;
        timeouts.validate(now_unix)?;
        if first_module == second_module
            || !matches!(first_module.asset(), asset if asset == quote.offered.asset || asset == quote.received.asset)
            || !matches!(second_module.asset(), asset if asset == quote.offered.asset || asset == quote.received.asset)
        {
            return Err(MarketError::InvalidPair);
        }
        Ok(Self {
            id,
            revision: 0,
            state: SwapState::OfferPublished,
            first_module,
            second_module,
            offered: quote.offered,
            received: quote.received,
            terms_id: quote.terms_id,
            hashlock,
            accepted_denuo_terms: None,
            timeouts,
            first_funding: None,
            second_funding: None,
            first_redemption: None,
            second_redemption: None,
            refund: None,
            last_verified_at_unix: now_unix,
            failure_reason: None,
        })
    }

    pub fn apply<J: SwapJournal>(
        &mut self,
        evidence: VerifiedEvidence,
        now_unix: u64,
        journal: &mut J,
    ) -> Result<(), MarketError> {
        let mut next = self.clone();
        next.transition(evidence, now_unix)?;
        let next_revision = self.revision.checked_add(1).ok_or(MarketError::Invariant)?;
        next.revision = next_revision;
        journal.save(&next, self.revision)?;
        *self = next;
        Ok(())
    }

    pub fn observe_peer_hint(&self, _hint: PeerHint) -> Result<(), MarketError> {
        Err(MarketError::PeerHintNotEvidence)
    }

    fn transition(&mut self, evidence: VerifiedEvidence, now_unix: u64) -> Result<(), MarketError> {
        let next = match (self.state, evidence) {
            (SwapState::OfferPublished, VerifiedEvidence::OfferTakeValidated) => {
                SwapState::OfferTakeReceived
            }
            (SwapState::OfferTakeReceived, VerifiedEvidence::OfferReserved) => {
                SwapState::OfferReserved
            }
            (SwapState::OfferReserved, VerifiedEvidence::TermsApproved { terms_id })
                if terms_id == self.terms_id =>
            {
                SwapState::TermsFrozen
            }
            (SwapState::TermsFrozen, VerifiedEvidence::RefundsValidated) => {
                SwapState::RefundsPrepared
            }
            (SwapState::RefundsPrepared, VerifiedEvidence::FundingReady) => {
                SwapState::FirstFundingPending
            }
            (
                SwapState::FirstFundingPending,
                VerifiedEvidence::FirstFundingConfirmed { evidence },
            ) => {
                self.first_funding = Some(evidence);
                SwapState::FirstFunded
            }
            (SwapState::FirstFunded, VerifiedEvidence::SecondFundingReady) => {
                SwapState::SecondFundingPending
            }
            (
                SwapState::SecondFundingPending,
                VerifiedEvidence::SecondFundingConfirmed { evidence },
            ) => {
                self.second_funding = Some(evidence);
                SwapState::BothFunded
            }
            (SwapState::BothFunded, VerifiedEvidence::FirstRedemptionConfirmed { evidence }) => {
                self.first_redemption = Some(evidence);
                SwapState::FirstRedeemed
            }
            (SwapState::FirstRedeemed, VerifiedEvidence::SecretExtracted { hashlock })
                if hashlock == self.hashlock =>
            {
                SwapState::SecretObserved
            }
            (
                SwapState::SecretObserved,
                VerifiedEvidence::SecondRedemptionConfirmed { evidence },
            ) => {
                self.second_redemption = Some(evidence);
                SwapState::SecondRedeemed
            }
            (SwapState::SecondRedeemed, VerifiedEvidence::CompletionValidated) => {
                SwapState::Completed
            }
            (
                SwapState::FirstFundingPending
                | SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved,
                VerifiedEvidence::RefundEligibilityValidated,
            ) => SwapState::RefundEligible,
            (SwapState::RefundEligible, VerifiedEvidence::RefundBroadcast { evidence }) => {
                self.refund = Some(evidence);
                SwapState::RefundBroadcast
            }
            (SwapState::RefundBroadcast, VerifiedEvidence::RefundConfirmed { evidence })
                if self.refund == Some(evidence) =>
            {
                SwapState::Refunded
            }
            (state, VerifiedEvidence::TerminalFailure { reason })
                if !matches!(state, SwapState::Completed | SwapState::Refunded) =>
            {
                if reason.is_empty() || reason.len() > 256 {
                    return Err(MarketError::InvalidEvidence);
                }
                self.failure_reason = Some(reason);
                SwapState::Failed
            }
            _ => return Err(MarketError::InvalidTransition),
        };
        self.state = next;
        self.last_verified_at_unix = now_unix;
        Ok(())
    }
}

/// Return the deterministic workflow identity for the executable side of one
/// accepted Denuo session. The bilateral session ID is already a 256-bit
/// signed protocol identity; hashing it again domain-separates its local
/// durable execution record from every other workflow namespace.
pub fn denuo_execution_workflow_id(session_id: SessionId) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(DENUO_EXECUTION_WORKFLOW_DOMAIN);
    hasher.update(session_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

/// Promote one already admitted, fully countersigned Denuo HNS/BTC session
/// into the durable execution journal.  This is deliberately a local-store
/// operation: the board and the counterparty are not consulted, and no
/// transaction is funded or broadcast here.
///
/// The returned session is at `TermsFrozen`, so the next permitted action is
/// local refund preparation. A restart can call this function again: the
/// exact existing journal is returned, while any mismatch fails closed.
pub fn open_denuo_execution(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    let expected_accepted_at = record
        .hello_accepted_at_unix
        .ok_or(MarketError::CorruptDenuoDirectSwap)?;
    // Re-authenticate the retained record at its original admission moment.
    // This permits recovery after a funding deadline, but does not let this
    // constructor authorize new funding after that deadline.
    hello
        .verify_agreement(policy.network())
        .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    verify_canonical_denuo_lock_commitments(hello)?;
    if now_unix < expected_accepted_at {
        return Err(MarketError::InvalidEvidence);
    }
    let encoded_terms = hello
        .encode()
        .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    let workflow_id = denuo_execution_workflow_id(session_id);
    if let Some(existing) = store.load_workflow::<SwapSession>(workflow_id)? {
        if existing.kind != WorkflowKind::AtomicSwap
            || existing.state.id != session_id
            || existing.state.accepted_denuo_terms.as_deref() != Some(encoded_terms.as_slice())
        {
            return Err(MarketError::DenuoDirectSwapConflict);
        }
        return Ok(existing.state);
    }
    // A new execution must still be inside the signed new-funding window.
    // Existing execution journals deliberately remain recoverable afterwards.
    let mut expected = swap_session_from_accepted_hello(hello, now_unix)?;
    expected.accepted_denuo_terms = Some(encoded_terms);
    let saved_revision = store.save_workflow(
        workflow_id,
        WorkflowKind::AtomicSwap,
        0,
        &expected,
        false,
        now_unix,
    )?;
    if saved_revision != expected.revision {
        return Err(MarketError::Invariant);
    }
    Ok(expected)
}

/// A funding lock independently verified by one wallet's chain authority.
/// Constructing this value is not verification: callers must obtain the HNS
/// variant from the HNS wallet's proof-bound settlement verifier or the
/// Bitcoin variant from Kyoto's compact-filter watch/verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocallyVerifiedSwapFunding {
    Hns(VerifiedLock),
    Bitcoin(VerifiedBitcoinLock),
}

impl LocallyVerifiedSwapFunding {
    const fn module(&self) -> ModuleId {
        match self {
            Self::Hns(_) => ModuleId::Handshake,
            Self::Bitcoin(_) => ModuleId::Bitcoin,
        }
    }
}

/// A redeem or refund proved by one wallet's own chain verifier. HNS evidence
/// is obtained from the native proof-bound transaction verifier; Bitcoin
/// evidence is obtained from a compact-filter watch that is bound to the
/// wallet's current checkpoint. Denuo peer messages are never accepted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocallyVerifiedSwapSpend {
    Hns(VerifiedNativeHtlcSpend),
    Bitcoin(VerifiedBitcoinHtlcSpendObservation),
}

impl LocallyVerifiedSwapSpend {
    const fn module(&self) -> ModuleId {
        match self {
            Self::Hns(_) => ModuleId::Handshake,
            Self::Bitcoin(_) => ModuleId::Bitcoin,
        }
    }

    fn redeem_preimage(&self) -> Result<Preimage, MarketError> {
        match self {
            Self::Hns(VerifiedNativeHtlcSpend::Redeem { preimage, .. }) => Ok(preimage.clone()),
            Self::Bitcoin(VerifiedBitcoinHtlcSpendObservation {
                spend:
                    hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpend {
                        branch: HtlcSpendBranch::Redeem,
                        revealed_preimage: Some(preimage),
                        ..
                    },
                ..
            }) => Ok(Preimage::new(*preimage)),
            _ => Err(MarketError::InvalidEvidence),
        }
    }

    fn is_refund(&self) -> bool {
        matches!(
            self,
            Self::Hns(VerifiedNativeHtlcSpend::Refund { .. })
                | Self::Bitcoin(VerifiedBitcoinHtlcSpendObservation {
                    spend: hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpend {
                        branch: HtlcSpendBranch::Refund,
                        ..
                    },
                    ..
                })
        )
    }

    const fn confirmation_count(&self) -> u32 {
        match self {
            Self::Hns(VerifiedNativeHtlcSpend::Redeem {
                confirmation_count, ..
            })
            | Self::Hns(VerifiedNativeHtlcSpend::Refund {
                confirmation_count, ..
            }) => *confirmation_count,
            Self::Bitcoin(observation) => observation.confirmation_count,
        }
    }
}

/// Advance a durable Denuo execution only with locally verified funding
/// evidence. The peer's Denuo funding status is intentionally not accepted as
/// an argument here: it can inform UI/transport state, but cannot cause this
/// state transition.
pub fn apply_locally_verified_denuo_funding(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    funding: LocallyVerifiedSwapFunding,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = denuo_execution_workflow_id(session_id);
    let stored = store
        .load_workflow::<SwapSession>(workflow_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if stored.kind != WorkflowKind::AtomicSwap || stored.state.id != session_id {
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    let terms = stored
        .state
        .accepted_denuo_terms
        .as_deref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    let hello = SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    if hello.encode().ok().as_deref() != Some(terms)
        || SessionId::new(hello.swap_session_id) != session_id
        || hello.verify_agreement(policy.network()).is_err()
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    verify_local_funding_against_denuo_terms(&hello, &funding)?;
    let evidence = match stored.state.state {
        SwapState::FirstFundingPending if funding.module() == stored.state.first_module => {
            VerifiedEvidence::FirstFundingConfirmed {
                evidence: funding_evidence_id(&funding),
            }
        }
        SwapState::SecondFundingPending if funding.module() == stored.state.second_module => {
            VerifiedEvidence::SecondFundingConfirmed {
                evidence: funding_evidence_id(&funding),
            }
        }
        _ => return Err(MarketError::InvalidTransition),
    };
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(evidence, now_unix, &mut journal)?;
    Ok(session)
}

/// Advance a funded Denuo execution through both the first observed redeem
/// and its secret extraction, using only one wallet's independently verified
/// chain observation. In the agreed HTLC ordering, the second-funded chain is
/// redeemed first; that transaction reveals the preimage needed to redeem the
/// first-funded chain. The preimage is encrypted in the local wallet before
/// the durable state transition, so an interruption cannot strand recovery.
pub fn apply_locally_verified_denuo_first_redemption(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = denuo_execution_workflow_id(session_id);
    let stored = load_denuo_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if stored.state.state != SwapState::BothFunded
        || spend.module() != stored.state.second_module
        || spend.confirmation_count() == 0
    {
        return Err(MarketError::InvalidTransition);
    }
    let preimage = spend.redeem_preimage()?;
    if ObjectHash::new(Sha256::digest(preimage.expose_for_settlement()).into())
        != stored.state.hashlock
    {
        return Err(MarketError::InvalidEvidence);
    }
    store.put_secret(
        &denuo_observed_preimage_id(session_id),
        SecretKind::HtlcPreimage,
        preimage.expose_for_settlement(),
        now_unix,
    )?;
    let evidence = spend_evidence_id(&spend);
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::FirstRedemptionConfirmed { evidence },
        now_unix,
        &mut journal,
    )?;
    session.apply(
        VerifiedEvidence::SecretExtracted {
            hashlock: session.hashlock,
        },
        now_unix,
        &mut journal,
    )?;
    Ok(session)
}

/// Advance a Denuo execution after the locally verified redeem of the
/// first-funded chain. The preceding first redeem must already have persisted
/// the matching preimage, so this cannot be used to skip the recovery-safe
/// secret handoff step.
pub fn apply_locally_verified_denuo_second_redemption(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = denuo_execution_workflow_id(session_id);
    let stored = load_denuo_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if stored.state.state != SwapState::SecretObserved
        || spend.module() != stored.state.first_module
        || spend.confirmation_count() == 0
    {
        return Err(MarketError::InvalidTransition);
    }
    let preimage = spend.redeem_preimage()?;
    if ObjectHash::new(Sha256::digest(preimage.expose_for_settlement()).into())
        != stored.state.hashlock
    {
        return Err(MarketError::InvalidEvidence);
    }
    if store
        .get_secret(
            &denuo_observed_preimage_id(session_id),
            SecretKind::HtlcPreimage,
        )?
        .is_none_or(|stored| stored.as_slice() != preimage.expose_for_settlement().as_slice())
    {
        return Err(MarketError::InvalidEvidence);
    }
    let evidence = spend_evidence_id(&spend);
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::SecondRedemptionConfirmed { evidence },
        now_unix,
        &mut journal,
    )?;
    session.apply(
        VerifiedEvidence::CompletionValidated,
        now_unix,
        &mut journal,
    )?;
    Ok(session)
}

/// Mark the execution terminal only after a locally verified timeout refund.
/// Each chain verifier is responsible for consensus maturity and the exact
/// descriptor/signature branch; the coordinator records the resulting
/// confirmed observation rather than trusting a peer refund status.
pub fn apply_locally_verified_denuo_refund(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = denuo_execution_workflow_id(session_id);
    let stored = load_denuo_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if !spend.is_refund()
        || (spend.module() != stored.state.first_module
            && spend.module() != stored.state.second_module)
        || spend.confirmation_count() == 0
    {
        return Err(MarketError::InvalidEvidence);
    }
    let evidence = spend_evidence_id(&spend);
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::RefundEligibilityValidated,
        now_unix,
        &mut journal,
    )?;
    session.apply(
        VerifiedEvidence::RefundBroadcast { evidence },
        now_unix,
        &mut journal,
    )?;
    session.apply(
        VerifiedEvidence::RefundConfirmed { evidence },
        now_unix,
        &mut journal,
    )?;
    Ok(session)
}

/// Load the locally retained preimage that was authenticated by a first
/// redemption. This never returns a peer-provided value and requires the
/// encrypted wallet store to be unlocked.
pub fn load_locally_verified_denuo_preimage(
    store: &WalletStore,
    session_id: SessionId,
) -> Result<Option<Preimage>, MarketError> {
    store
        .get_secret(
            &denuo_observed_preimage_id(session_id),
            SecretKind::HtlcPreimage,
        )?
        .map(|value| {
            let bytes = <[u8; Preimage::LENGTH]>::try_from(value.as_slice())
                .map_err(|_| MarketError::InvalidEvidence)?;
            Ok(Preimage::new(bytes))
        })
        .transpose()
}

fn load_denuo_execution_for_local_evidence(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
    workflow_id: WorkflowId,
) -> Result<hns_wallet_store::StoredWorkflow<SwapSession>, MarketError> {
    let stored = store
        .load_workflow::<SwapSession>(workflow_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if stored.kind != WorkflowKind::AtomicSwap || stored.state.id != session_id {
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    let terms = stored
        .state
        .accepted_denuo_terms
        .as_deref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    let hello = SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    if hello.encode().ok().as_deref() != Some(terms)
        || SessionId::new(hello.swap_session_id) != session_id
        || hello.verify_agreement(policy.network()).is_err()
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    Ok(stored)
}

fn denuo_observed_preimage_id(session_id: SessionId) -> Vec<u8> {
    let mut id =
        Vec::with_capacity(DENUO_OBSERVED_PREIMAGE_DOMAIN.len() + session_id.as_bytes().len());
    id.extend_from_slice(DENUO_OBSERVED_PREIMAGE_DOMAIN);
    id.extend_from_slice(session_id.as_bytes());
    id
}

fn spend_evidence_id(spend: &LocallyVerifiedSwapSpend) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/verified-denuo-spend/v1");
    match spend {
        LocallyVerifiedSwapSpend::Hns(VerifiedNativeHtlcSpend::Redeem { transaction, .. }) => {
            hasher.update([0, 0]);
            hasher.update(transaction.as_bytes());
        }
        LocallyVerifiedSwapSpend::Hns(VerifiedNativeHtlcSpend::Refund { transaction, .. }) => {
            hasher.update([0, 1]);
            hasher.update(transaction.as_bytes());
        }
        LocallyVerifiedSwapSpend::Bitcoin(observation) => {
            hasher.update([1]);
            hasher.update(observation.spend.txid.as_bytes());
            hasher.update(observation.spend.wtxid);
            hasher.update(match observation.spend.branch {
                HtlcSpendBranch::Redeem => [0],
                HtlcSpendBranch::Refund => [1],
            });
        }
    }
    ObjectHash::new(hasher.finalize().into())
}

fn verify_local_funding_against_denuo_terms(
    hello: &SwapSessionHello,
    funding: &LocallyVerifiedSwapFunding,
) -> Result<(), MarketError> {
    match funding {
        LocallyVerifiedSwapFunding::Hns(lock) => {
            let side = hns_side(hello)?;
            let descriptor = canonical_hns_descriptor(hello, side)?;
            let minimum_confirmations = confirmation_minimum(hello, side);
            if lock.module != ModuleId::Handshake
                || lock.session_id != SessionId::new(hello.swap_session_id)
                || lock.amount.asset != WalletAsset::Hns
                || lock.amount.base_units.get() != u128::from(descriptor.value.get())
                || lock.hashlock.as_bytes() != &descriptor.hashlock
                || lock.absolute_timelock != u64::from(descriptor.refund_locktime)
                || lock.confirmation_count < minimum_confirmations
            {
                return Err(MarketError::InvalidEvidence);
            }
        }
        LocallyVerifiedSwapFunding::Bitcoin(lock) => {
            let side = bitcoin_side(hello)?;
            let descriptor = build_denuo_bitcoin_htlc(hello, side)
                .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
            let minimum_confirmations = confirmation_minimum(hello, side);
            if lock.value_sats != descriptor.value_sats
                || lock.confirmation_count < minimum_confirmations
                || lock.htlc != descriptor.htlc
            {
                return Err(MarketError::InvalidEvidence);
            }
        }
    }
    Ok(())
}

fn funding_evidence_id(funding: &LocallyVerifiedSwapFunding) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/verified-denuo-funding/v1");
    match funding {
        LocallyVerifiedSwapFunding::Hns(lock) => {
            hasher.update([0]);
            hasher.update(lock.funding_id.as_bytes());
            hasher.update(lock.evidence_hash.as_bytes());
        }
        LocallyVerifiedSwapFunding::Bitcoin(lock) => {
            hasher.update([1]);
            hasher.update(lock.funding_txid.as_bytes());
            hasher.update(lock.output_index.to_be_bytes());
        }
    }
    ObjectHash::new(hasher.finalize().into())
}

fn hns_side(hello: &SwapSessionHello) -> Result<SwapAssetSide, MarketError> {
    if hello.offered_asset == AssetId::HNS {
        Ok(SwapAssetSide::Offered)
    } else if hello.received_asset == AssetId::HNS {
        Ok(SwapAssetSide::Received)
    } else {
        Err(MarketError::InvalidPair)
    }
}

fn bitcoin_side(hello: &SwapSessionHello) -> Result<SwapAssetSide, MarketError> {
    if hello.offered_asset == AssetId::BTC {
        Ok(SwapAssetSide::Offered)
    } else if hello.received_asset == AssetId::BTC {
        Ok(SwapAssetSide::Received)
    } else {
        Err(MarketError::InvalidPair)
    }
}

fn canonical_hns_descriptor(
    hello: &SwapSessionHello,
    side: SwapAssetSide,
) -> Result<hns_swap::HnsHtlc, MarketError> {
    hello
        .build_hns_htlc(
            side,
            match side {
                SwapAssetSide::Offered => hello.taker_settlement_public_key,
                SwapAssetSide::Received => hello.maker_settlement_public_key,
            },
            match side {
                SwapAssetSide::Offered => hello.maker_settlement_public_key,
                SwapAssetSide::Received => hello.taker_settlement_public_key,
            },
        )
        .map(|binding| binding.descriptor)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)
}

fn confirmation_minimum(hello: &SwapSessionHello, side: SwapAssetSide) -> u32 {
    match side {
        SwapAssetSide::Offered => hello.offered_minimum_confirmations,
        SwapAssetSide::Received => hello.received_minimum_confirmations,
    }
}

/// Reconstruct both lock descriptors from the mutually signed terms.  The
/// HNS protocol owns its descriptor format; the Kyoto adapter owns the
/// Bitcoin P2WSH format and its domain-separated Denuo commitment.  Keeping
/// this check at the durable-execution boundary means a board record cannot
/// turn an opaque or substituted 32-byte lock claim into a fundable swap.
fn verify_canonical_denuo_lock_commitments(hello: &SwapSessionHello) -> Result<(), MarketError> {
    verify_canonical_denuo_lock_commitment(hello, SwapAssetSide::Offered)?;
    verify_canonical_denuo_lock_commitment(hello, SwapAssetSide::Received)
}

fn verify_canonical_denuo_lock_commitment(
    hello: &SwapSessionHello,
    side: SwapAssetSide,
) -> Result<(), MarketError> {
    let (asset, commitment) = match side {
        SwapAssetSide::Offered => (hello.offered_asset, hello.offered_lock_commitment),
        SwapAssetSide::Received => (hello.received_asset, hello.received_lock_commitment),
    };
    let computed = match asset {
        AssetId::HNS => {
            hello
                .build_hns_htlc(
                    side,
                    match side {
                        SwapAssetSide::Offered => hello.taker_settlement_public_key,
                        SwapAssetSide::Received => hello.maker_settlement_public_key,
                    },
                    match side {
                        SwapAssetSide::Offered => hello.maker_settlement_public_key,
                        SwapAssetSide::Received => hello.taker_settlement_public_key,
                    },
                )
                .map_err(|_| MarketError::InvalidDenuoDirectSwap)?
                .descriptor_hash
        }
        AssetId::BTC => build_denuo_bitcoin_htlc(hello, side)
            .map_err(|_| MarketError::InvalidDenuoDirectSwap)?
            .commitment
            .into_bytes(),
        _ => return Err(MarketError::InvalidPair),
    };
    if computed != commitment {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    Ok(())
}

fn swap_session_from_accepted_hello(
    hello: &hns_marketplace_protocol::SwapSessionHello,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    if hello.offered_asset != AssetId::HNS && hello.offered_asset != AssetId::BTC
        || hello.received_asset != AssetId::HNS && hello.received_asset != AssetId::BTC
        || hello.offered_asset == hello.received_asset
        || hello.offered_refund_deadline.kind != DeadlineKind::UnixTime
        || hello.received_refund_deadline.kind != DeadlineKind::UnixTime
    {
        return Err(MarketError::InvalidPair);
    }
    let offered = Amount::new(
        wallet_asset_for_protocol_asset(hello.offered_asset)?,
        hello.offered_amount.get(),
    );
    let received = Amount::new(
        wallet_asset_for_protocol_asset(hello.received_asset)?,
        hello.received_amount.get(),
    );
    let first_module = module_for_chain(hello.first_funding_chain)?;
    let second_module = module_for_chain(other_chain(hello.first_funding_chain)?)?;
    let (first_refund_at, second_refund_at) =
        if hello.first_funding_chain == hello.offered_asset.chain() {
            (
                hello.offered_refund_deadline.value,
                hello.received_refund_deadline.value,
            )
        } else if hello.first_funding_chain == hello.received_asset.chain() {
            (
                hello.received_refund_deadline.value,
                hello.offered_refund_deadline.value,
            )
        } else {
            return Err(MarketError::InvalidPair);
        };
    let safety_margin = first_refund_at
        .checked_sub(second_refund_at)
        .ok_or(MarketError::UnsafeTimeouts)?;
    let mut session = SwapSession::new(
        SessionId::new(hello.swap_session_id),
        first_module,
        second_module,
        VerifiedQuote {
            terms_id: ObjectHash::new(hello.direct_offer_id),
            offered,
            received,
            // The signed session itself is the source of execution terms;
            // its received refund deadline is the latest new-funding gate.
            valid_until_unix: hello.received_refund_deadline.value,
        },
        ObjectHash::new(hello.hashlock),
        TimeoutPlan {
            first_chain_refund_at: first_refund_at,
            second_chain_refund_at: second_refund_at,
            minimum_safety_margin: safety_margin,
        },
        now_unix,
    )?;
    // The Denuo board has already admitted the exact direct offer, its take,
    // and the exact double-signed terms. Persist one execution baseline instead of
    // replaying those historic state transitions after a restart.
    session.state = SwapState::TermsFrozen;
    session.revision = 1;
    Ok(session)
}

fn wallet_asset_for_protocol_asset(asset: AssetId) -> Result<WalletAsset, MarketError> {
    match asset {
        AssetId::HNS => Ok(WalletAsset::Hns),
        AssetId::BTC => Ok(WalletAsset::Btc),
        _ => Err(MarketError::InvalidPair),
    }
}

fn module_for_chain(chain: ChainId) -> Result<ModuleId, MarketError> {
    match chain {
        ChainId::HANDSHAKE => Ok(ModuleId::Handshake),
        ChainId::BITCOIN => Ok(ModuleId::Bitcoin),
        _ => Err(MarketError::InvalidPair),
    }
}

fn other_chain(chain: ChainId) -> Result<ChainId, MarketError> {
    match chain {
        ChainId::HANDSHAKE => Ok(ChainId::BITCOIN),
        ChainId::BITCOIN => Ok(ChainId::HANDSHAKE),
        _ => Err(MarketError::InvalidPair),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedEvidence {
    OfferTakeValidated,
    OfferReserved,
    TermsApproved { terms_id: ObjectHash },
    RefundsValidated,
    FundingReady,
    FirstFundingConfirmed { evidence: ObjectHash },
    SecondFundingReady,
    SecondFundingConfirmed { evidence: ObjectHash },
    FirstRedemptionConfirmed { evidence: ObjectHash },
    SecretExtracted { hashlock: ObjectHash },
    SecondRedemptionConfirmed { evidence: ObjectHash },
    CompletionValidated,
    RefundEligibilityValidated,
    RefundBroadcast { evidence: ObjectHash },
    RefundConfirmed { evidence: ObjectHash },
    TerminalFailure { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerHint {
    FundingClaimed,
    RedeemedClaimed,
    RefundedClaimed,
}

pub trait SwapJournal {
    fn save(&mut self, session: &SwapSession, expected_revision: u64) -> Result<(), MarketError>;
}

pub struct WalletStoreJournal<'a> {
    pub store: &'a mut WalletStore,
    pub workflow_id: WorkflowId,
    pub updated_at_unix: u64,
}

impl SwapJournal for WalletStoreJournal<'_> {
    fn save(&mut self, session: &SwapSession, expected_revision: u64) -> Result<(), MarketError> {
        let next = self.store.save_workflow(
            self.workflow_id,
            WorkflowKind::AtomicSwap,
            expected_revision,
            session,
            matches!(
                session.state,
                SwapState::FirstFundingPending
                    | SwapState::FirstFunded
                    | SwapState::SecondFundingPending
                    | SwapState::BothFunded
                    | SwapState::FirstRedeemed
                    | SwapState::SecretObserved
                    | SwapState::SecondRedeemed
                    | SwapState::RefundBroadcast
            ),
            self.updated_at_unix,
        )?;
        if next != session.revision {
            return Err(MarketError::Invariant);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryJournal {
    pub saved: Vec<SwapSession>,
}

impl SwapJournal for MemoryJournal {
    fn save(&mut self, session: &SwapSession, expected_revision: u64) -> Result<(), MarketError> {
        if session.revision != expected_revision + 1 {
            return Err(MarketError::StaleRevision);
        }
        self.saved.push(session.clone());
        Ok(())
    }
}

#[derive(Debug, Eq, Error, PartialEq)]
pub enum MarketError {
    #[error("invalid or stale verified quote")]
    InvalidQuote,
    #[error("invalid direct HNS/BTC offer-board policy")]
    InvalidDenuoDirectOfferPolicy,
    #[error("invalid or unexpected canonical direct HNS/BTC offer envelope")]
    InvalidDenuoDirectOffer,
    #[error("direct HNS/BTC offer conflicts with retained signed terms")]
    DenuoDirectOfferConflict,
    #[error("persisted direct HNS/BTC offer board is corrupt or noncanonical")]
    CorruptDenuoDirectOfferBoard,
    #[error("direct HNS/BTC offer board reached its bounded capacity")]
    DenuoDirectOfferCapacity,
    #[error("requested direct HNS/BTC offer is unknown")]
    UnknownDenuoDirectOffer,
    #[error("invalid direct HNS/BTC swap policy")]
    InvalidDenuoDirectSwapPolicy,
    #[error("invalid or unexpected canonical direct HNS/BTC swap message")]
    InvalidDenuoDirectSwap,
    #[error("the referenced direct HNS/BTC swap is unknown")]
    UnknownDenuoDirectSwap,
    #[error("direct HNS/BTC swap conflicts with accepted state")]
    DenuoDirectSwapConflict,
    #[error("direct HNS/BTC swap capacity reached")]
    DenuoDirectSwapCapacity,
    #[error("persisted direct HNS/BTC swap is corrupt or noncanonical")]
    CorruptDenuoDirectSwap,
    #[error("invalid, unexpected, or resource-exhausting Denuo peer message")]
    InvalidDenuoPeerMessage,
    #[error("unsupported or inconsistent asset pair")]
    InvalidPair,
    #[error("unsafe settlement timeouts")]
    UnsafeTimeouts,
    #[error("verified evidence does not permit this transition")]
    InvalidTransition,
    #[error("chain evidence is invalid")]
    InvalidEvidence,
    #[error("peer status is a hint, not local chain evidence")]
    PeerHintNotEvidence,
    #[error("state invariant failed")]
    Invariant,
    #[error("persisted workflow revision is stale")]
    StaleRevision,
    #[error("wallet persistence failed")]
    Persistence,
}

impl From<StoreError> for MarketError {
    fn from(error: StoreError) -> Self {
        if matches!(error, StoreError::StaleRevision { .. }) {
            Self::StaleRevision
        } else {
            Self::Persistence
        }
    }
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        AssetAmount, MARKETPLACE_PROTOCOL_VERSION, MarketPair, NetworkBinding, SettlementDeadline,
        SignedObjectHeader, SwapSessionHello,
    };
    use hns_primitives::BlockHash;

    use super::*;

    fn quote() -> VerifiedQuote {
        VerifiedQuote {
            terms_id: ObjectHash::new([3; 32]),
            offered: Amount::new(WalletAsset::Hns, 1_000),
            received: Amount::new(WalletAsset::Btc, 25),
            valid_until_unix: 1_000,
        }
    }

    #[test]
    fn swap_success_requires_persisted_verified_evidence() {
        let mut session = SwapSession::new(
            SessionId::new([4; 32]),
            ModuleId::Handshake,
            ModuleId::Bitcoin,
            quote(),
            ObjectHash::new([5; 32]),
            TimeoutPlan {
                first_chain_refund_at: 500,
                second_chain_refund_at: 300,
                minimum_safety_margin: 100,
            },
            10,
        )
        .expect("session");
        let mut journal = MemoryJournal::default();
        let steps = [
            VerifiedEvidence::OfferTakeValidated,
            VerifiedEvidence::OfferReserved,
            VerifiedEvidence::TermsApproved {
                terms_id: ObjectHash::new([3; 32]),
            },
            VerifiedEvidence::RefundsValidated,
            VerifiedEvidence::FundingReady,
            VerifiedEvidence::FirstFundingConfirmed {
                evidence: ObjectHash::new([6; 32]),
            },
            VerifiedEvidence::SecondFundingReady,
            VerifiedEvidence::SecondFundingConfirmed {
                evidence: ObjectHash::new([7; 32]),
            },
            VerifiedEvidence::FirstRedemptionConfirmed {
                evidence: ObjectHash::new([8; 32]),
            },
            VerifiedEvidence::SecretExtracted {
                hashlock: ObjectHash::new([5; 32]),
            },
            VerifiedEvidence::SecondRedemptionConfirmed {
                evidence: ObjectHash::new([9; 32]),
            },
            VerifiedEvidence::CompletionValidated,
        ];
        for (index, evidence) in steps.into_iter().enumerate() {
            session
                .apply(evidence, 20 + index as u64, &mut journal)
                .expect("verified transition");
        }
        assert_eq!(session.state, SwapState::Completed);
        assert_eq!(journal.saved.len(), 12);
        assert_eq!(journal.saved.last(), Some(&session));
        assert_eq!(
            session.observe_peer_hint(PeerHint::RefundedClaimed),
            Err(MarketError::PeerHintNotEvidence)
        );
    }

    #[test]
    fn refund_path_is_available_after_first_funding() {
        let mut session = SwapSession::new(
            SessionId::new([10; 32]),
            ModuleId::Handshake,
            ModuleId::Bitcoin,
            quote(),
            ObjectHash::new([11; 32]),
            TimeoutPlan {
                first_chain_refund_at: 500,
                second_chain_refund_at: 300,
                minimum_safety_margin: 100,
            },
            10,
        )
        .expect("session");
        let mut journal = MemoryJournal::default();
        for evidence in [
            VerifiedEvidence::OfferTakeValidated,
            VerifiedEvidence::OfferReserved,
            VerifiedEvidence::TermsApproved {
                terms_id: ObjectHash::new([3; 32]),
            },
            VerifiedEvidence::RefundsValidated,
            VerifiedEvidence::FundingReady,
            VerifiedEvidence::FirstFundingConfirmed {
                evidence: ObjectHash::new([12; 32]),
            },
            VerifiedEvidence::RefundEligibilityValidated,
            VerifiedEvidence::RefundBroadcast {
                evidence: ObjectHash::new([13; 32]),
            },
            VerifiedEvidence::RefundConfirmed {
                evidence: ObjectHash::new([13; 32]),
            },
        ] {
            session
                .apply(evidence, 20, &mut journal)
                .expect("transition");
        }
        assert_eq!(session.state, SwapState::Refunded);
    }

    fn accepted_terms(first_funding_chain: ChainId) -> SwapSessionHello {
        SwapSessionHello {
            header: SignedObjectHeader {
                version: MARKETPLACE_PROTOCOL_VERSION,
                network: NetworkBinding {
                    hns_magic: 0x5b6e_c393,
                    hns_genesis: BlockHash::new([1; 32]),
                    counterchain: ChainId::BITCOIN,
                    counterchain_network: 1,
                    counterchain_genesis: [2; 32],
                },
                pair: MarketPair::HNS_BTC,
                signer_public_key: [2; 33],
                sequence: 1,
                created_at: 10,
                expires_at: 900,
            },
            direct_offer_id: [3; 32],
            swap_session_id: [4; 32],
            maker_settlement_public_key: [2; 33],
            taker_settlement_public_key: [3; 33],
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(1_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(25),
            hashlock: [6; 32],
            first_funding_chain,
            offered_lock_commitment: [7; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 800,
            },
            offered_minimum_confirmations: 2,
            received_lock_commitment: [8; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 500,
            },
            received_minimum_confirmations: 2,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        }
    }

    #[test]
    fn accepted_denuo_terms_open_a_resumable_execution_in_signed_chain_order() {
        let hns_first = swap_session_from_accepted_hello(&accepted_terms(ChainId::HANDSHAKE), 100)
            .expect("HNS first terms");
        assert_eq!(hns_first.state, SwapState::TermsFrozen);
        assert_eq!(hns_first.revision, 1);
        assert_eq!(hns_first.first_module, ModuleId::Handshake);
        assert_eq!(hns_first.second_module, ModuleId::Bitcoin);
        assert_eq!(hns_first.timeouts.first_chain_refund_at, 800);
        assert_eq!(hns_first.timeouts.second_chain_refund_at, 500);

        let mut btc_first_terms = accepted_terms(ChainId::BITCOIN);
        btc_first_terms.offered_refund_deadline.value = 500;
        btc_first_terms.received_refund_deadline.value = 800;
        let btc_first =
            swap_session_from_accepted_hello(&btc_first_terms, 100).expect("Bitcoin first terms");
        assert_eq!(btc_first.first_module, ModuleId::Bitcoin);
        assert_eq!(btc_first.second_module, ModuleId::Handshake);
        assert_eq!(btc_first.timeouts.first_chain_refund_at, 800);
        assert_eq!(btc_first.timeouts.second_chain_refund_at, 500);
        assert_eq!(
            denuo_execution_workflow_id(hns_first.id),
            denuo_execution_workflow_id(btc_first.id),
            "workflow identity is session-bound, not chain-order-bound"
        );
    }
}
