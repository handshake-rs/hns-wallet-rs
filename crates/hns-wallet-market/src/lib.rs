#![doc = "Chain-neutral, evidence-driven market and atomic-swap workflow state."]
#![forbid(unsafe_code)]

mod direct_board;
mod direct_offer;
mod direct_responder;
mod session_board;
mod settlement_key;

use hns_marketplace_protocol::{
    AssetId, ChainId, DeadlineKind, SettlementDeadline, SwapAssetSide, SwapSessionHello,
    hns_refund_time_lock,
};
use hns_wallet_bitcoin_kyoto::{
    HtlcSpendBranch, VerifiedBitcoinHtlcSpendObservation, VerifiedBitcoinLock,
    build_shakescape_bitcoin_htlc,
};
use hns_wallet_chain_api::{Preimage, VerifiedLock};
use hns_wallet_hns::{HnsSettlementBroadcastGuard, VerifiedNativeHtlcSpend};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, EntityRevisionAssertion, SecretKind,
    StoreError, StoredWorkflow, WalletStore, WorkflowRevisionAssertion,
};
use hns_wallet_types::{
    Amount, ModuleId, ObjectHash, SessionId, WalletAsset, WalletId, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use direct_board::{
    MAX_SHAKESCAPE_DIRECT_OFFERS, ShakescapeDirectOfferAdmission, ShakescapeDirectOfferBoardPolicy,
    ShakescapeDirectOfferCancellationAdmission, ShakescapeDirectOfferLevel,
    ShakescapeDirectOfferRecord, ShakescapeDirectOfferSnapshot, admit_shakescape_direct_offer,
    admit_shakescape_direct_offer_cancellation, live_shakescape_direct_offer_levels,
    load_shakescape_direct_offer, load_shakescape_direct_offers, shakescape_direct_offer_inventory,
};
pub use direct_offer::{
    ShakescapeBtcForHnsMakerProposal, ShakescapeBtcForHnsMakerProposalRequest,
    ShakescapeBtcForHnsOfferRequest, ShakescapeDirectMakerProposal,
    ShakescapeDirectMakerProposalRequest, ShakescapeDirectOfferRequest,
    ShakescapeHnsForBtcOfferRequest, ShakescapeLocalDirectOffer,
    cancel_shakescape_local_direct_offer, create_shakescape_btc_for_hns_maker_proposal,
    create_shakescape_btc_for_hns_offer, create_shakescape_direct_maker_proposal,
    create_shakescape_direct_offer, create_shakescape_hns_for_btc_offer,
    derive_local_btc_for_hns_maker_key, derive_local_direct_maker_key,
    is_local_shakescape_direct_maker, is_local_shakescape_direct_offer_setter,
    list_local_shakescape_direct_offer_cancellations, list_local_shakescape_direct_offers,
    load_shakescape_btc_for_hns_maker_preimage, load_shakescape_direct_maker_preimage,
    reserved_local_shakescape_offer_setter_amount,
};
pub use direct_responder::{
    ShakescapeBtcForHnsOfferAcceptanceRequest, ShakescapeDirectOfferAcceptanceRequest,
    ShakescapeHnsForBtcOfferAcceptanceRequest, ShakescapeLocalDirectOfferAcceptance,
    ShakescapeOfferSetterAcceptedSession, abandon_pending_local_shakescape_direct_offer_acceptance,
    accept_shakescape_direct_maker_proposal, accept_shakescape_hns_for_btc_maker_proposal,
    create_shakescape_btc_for_hns_offer_acceptance, create_shakescape_direct_offer_acceptance,
    create_shakescape_hns_for_btc_offer_acceptance, derive_local_direct_taker_key,
    derive_local_hns_for_btc_taker_key, is_local_shakescape_direct_taker,
    list_local_shakescape_direct_offer_acceptances,
    list_pending_local_shakescape_direct_offer_acceptances,
    reserved_local_shakescape_responder_amount,
};
pub use session_board::{
    MAX_SHAKESCAPE_DIRECT_SWAP_HISTORY, MAX_SHAKESCAPE_DIRECT_SWAP_RECORDS,
    MAX_SHAKESCAPE_DIRECT_SWAPS, ShakescapeDirectSwapAdmission, ShakescapeDirectSwapPeerStatus,
    ShakescapeDirectSwapPolicy, ShakescapeDirectSwapRecord, ShakescapeDirectSwapSnapshot,
    ShakescapeDirectSwapStage, ShakescapePeerFundingStatusRecord,
    admit_shakescape_direct_offer_acceptance, admit_shakescape_direct_swap_hello,
    admit_shakescape_direct_swap_peer_status, admit_shakescape_direct_swap_proposal,
    admit_shakescape_direct_swap_watch_ready, load_shakescape_direct_swap,
    load_shakescape_direct_swaps, validate_shakescape_direct_swap_peer_status,
};
pub use settlement_key::{
    CrossChainSwapKey, CrossChainSwapKeyAllocation, CrossChainSwapKeyError,
    CrossChainSwapKeyRequest, SwapParticipant, allocate_cross_chain_swap_key,
    derive_cross_chain_swap_key_from_store, load_cross_chain_swap_key_allocation,
};

/// Terminal reason used when a countersigned session reaches its funding
/// deadline before either participant has supplied locally verified chain
/// evidence. A later exact-chain observation is allowed to recover only this
/// narrowly identified pre-funding timeout (and the independently proven
/// Bitcoin-absence variant below); arbitrary failed sessions stay terminal.
pub const PREFUNDING_DEADLINE_FAILURE: &str =
    "funding deadline expired before first-chain authorization";

/// Terminal reason used after the local Bitcoin backend independently proves
/// that an expired first-chain lock is absent. Chain evidence can still race
/// that snapshot, so a later verified exact lock must supersede the absence
/// result and restore the funded recovery path.
pub const PREFUNDING_BITCOIN_ABSENCE_FAILURE: &str =
    "funding deadline expired with verified absence of a Bitcoin lock";

pub const MAX_CONCURRENT_SWAP_SESSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShakescapeDirectMarketPruneReport {
    pub expired_unowned_sessions_removed: usize,
    pub terminal_session_history_removed: usize,
    pub expired_unreferenced_offers_removed: usize,
}

/// Repair legacy physical-capacity rows without deleting local history or any
/// offer referenced by a retained session. This is restart-idempotent and may
/// be run before every board read or admission.
pub fn prune_expired_shakescape_direct_market_state(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<ShakescapeDirectMarketPruneReport, MarketError> {
    if wallet_id.as_bytes().iter().all(|byte| *byte == 0) || now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let expired_unowned_sessions_removed =
        session_board::prune_expired_unowned_shakescape_direct_swaps(
            store, policy, wallet_id, now_unix,
        )?;
    let terminal_session_history_removed =
        session_board::prune_terminal_shakescape_direct_swap_history(store, policy, wallet_id)?;
    let mut protected_offer_ids = direct_offer::local_direct_offer_ids(store, wallet_id)?;
    protected_offer_ids.extend(session_board::referenced_direct_offer_ids(store, policy)?);
    let expired_unreferenced_offers_removed =
        direct_board::prune_expired_unreferenced_shakescape_direct_offers(
            store,
            &policy.board_policy(),
            &protected_offer_ids,
            now_unix,
        )?;
    Ok(ShakescapeDirectMarketPruneReport {
        expired_unowned_sessions_removed,
        terminal_session_history_removed,
        expired_unreferenced_offers_removed,
    })
}

/// Product-level headroom required between the effective refund times of the
/// first-funded and second-funded chains. Native HNS deadlines are rounded to
/// HSD's 512-second encoding, so validating only the signed Unix values is not
/// sufficient.
pub const MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS: u64 = 60 * 60;

/// Minimum time left to fund and redeem the second chain after the signed
/// new-funding window closes. Without this independent floor, a peer can
/// preserve the nominal refund ordering while making the second lock
/// immediately refundable as soon as it is allowed to be funded.
pub const MIN_SECOND_CHAIN_REDEMPTION_WINDOW_SECONDS: u64 = 60 * 60;
pub const SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS: u32 = 1;
pub const SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS: u32 = 2;
pub const SHAKESCAPE_MAX_SETTLEMENT_HORIZON_SECONDS: u64 = 7 * 24 * 60 * 60;

const SHAKESCAPE_EXECUTION_WORKFLOW_DOMAIN: &[u8] =
    b"hns-wallet-rs/shakescape-execution-workflow/v1";
const SHAKESCAPE_OBSERVED_PREIMAGE_DOMAIN: &[u8] = b"hns-wallet-rs/shakescape-observed-preimage/v1";
const SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_DOMAIN: &[u8] =
    b"hns-wallet-rs/shakescape-second-funding-authorization/v1\0";
const SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedQuote {
    /// Identifier of the signed exact terms that authorized this quote. For a
    /// direct HNS/BTC swap this is the offer setter's signed intent ID.
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

/// One durable, single-use authorization for funding the second chain. It is
/// bound to the exact first-chain evidence that was current when issued and
/// is cleared whenever that evidence is refreshed or invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecondFundingAuthorization {
    pub id: ObjectHash,
    pub module: ModuleId,
    pub first_funding: ObjectHash,
    pub first_funding_observation_generation: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSecondFundingAuthorization {
    schema_version: u16,
    session_id: SessionId,
    execution_workflow_id: WorkflowId,
    execution_revision: u64,
    issued_entity_revision: u64,
    authorization: SecondFundingAuthorization,
}

/// Exact durable authority which a chain runtime must consume in the same
/// SQLite transaction that makes a signed second-chain funding transaction
/// recoverably broadcastable. Reconciliation removes this row atomically with
/// any execution change that revokes the first-chain proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecondFundingBroadcastGuard {
    session_id: SessionId,
    execution_workflow_id: WorkflowId,
    execution_revision: u64,
    authorization_entity_id: Vec<u8>,
    authorization_entity_revision: u64,
    authorization: SecondFundingAuthorization,
}

impl SecondFundingBroadcastGuard {
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn module(&self) -> ModuleId {
        self.authorization.module
    }

    pub const fn authorization_id(&self) -> ObjectHash {
        self.authorization.id
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.authorization.expires_at_unix
    }

    pub fn workflow_assertion(&self) -> WorkflowRevisionAssertion {
        WorkflowRevisionAssertion {
            id: self.execution_workflow_id,
            kind: WorkflowKind::AtomicSwap,
            expected_revision: self.execution_revision,
        }
    }

    pub fn authorization_assertion(&self) -> EntityRevisionAssertion {
        EntityRevisionAssertion {
            id: self.authorization_entity_id.clone(),
            expected_revision: self.authorization_entity_revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapState {
    OfferPublished,
    /// The offer responder has committed to act as the executable swap maker.
    OfferAcceptanceReceived,
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
    /// Canonical encoded, jointly signed Shakescape `SwapSessionHello` for an
    /// execution opened from the Shakescape board. Generic non-Shakescape sessions keep
    /// this empty; a Shakescape execution never relies on a board record surviving
    /// independently of its durable recovery journal.
    #[serde(default, alias = "accepted_denuo_terms")]
    pub accepted_shakescape_terms: Option<Vec<u8>>,
    pub timeouts: TimeoutPlan,
    pub first_funding: Option<ObjectHash>,
    /// The first-chain evidence was previously verified but a later current
    /// chain view no longer contains it. The evidence remains journaled so an
    /// already-broadcast second leg can still be tracked and refunded, while
    /// this flag removes its authority for new funding and redemption.
    #[serde(default)]
    pub first_funding_revoked: bool,
    /// Monotonic durable fence allocated before a first-chain read begins.
    /// A proof or absence result is accepted only for the latest generation.
    #[serde(default)]
    pub first_funding_observation_generation: u64,
    /// Generation whose current-chain read most recently confirmed the exact
    /// first lock. Unscoped legacy observations never populate this field and
    /// therefore cannot authorize second-chain value movement.
    #[serde(default)]
    pub first_funding_confirmed_generation: Option<u64>,
    /// Revocable cross-controller authority for a second-chain preparation or
    /// broadcast. Older rows decode without a lease and therefore cannot
    /// authorize new value movement until the first chain is freshly proven.
    #[serde(default)]
    pub second_funding_authorization: Option<SecondFundingAuthorization>,
    pub second_funding: Option<ObjectHash>,
    pub first_redemption: Option<ObjectHash>,
    pub second_redemption: Option<ObjectHash>,
    /// Legacy aggregate refund evidence retained for backwards-compatible
    /// workflow decoding. New settlement records use the per-funded-leg
    /// fields below and treat this value only as migration evidence.
    pub refund: Option<ObjectHash>,
    #[serde(default)]
    pub first_refund: Option<ObjectHash>,
    #[serde(default)]
    pub second_refund: Option<ObjectHash>,
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
            accepted_shakescape_terms: None,
            timeouts,
            first_funding: None,
            first_funding_revoked: false,
            first_funding_observation_generation: 0,
            first_funding_confirmed_generation: None,
            second_funding_authorization: None,
            second_funding: None,
            first_redemption: None,
            second_redemption: None,
            refund: None,
            first_refund: None,
            second_refund: None,
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

    pub fn refund_for_module(&self, module: ModuleId) -> Option<ObjectHash> {
        if module == self.first_module {
            self.first_refund
        } else if module == self.second_module {
            self.second_refund
        } else {
            None
        }
    }

    pub fn can_refund_module(&self, module: ModuleId) -> bool {
        if module == self.first_module {
            self.first_funding_is_current()
                && self.first_refund.is_none()
                && self.second_redemption.is_none()
        } else if module == self.second_module {
            self.second_funding.is_some()
                && self.second_refund.is_none()
                && self.first_redemption.is_none()
        } else {
            false
        }
    }

    fn can_record_refund_for_module(&self, module: ModuleId) -> bool {
        if module == self.first_module {
            self.first_funding.is_some()
                && self.first_refund.is_none()
                && self.second_redemption.is_none()
        } else if module == self.second_module {
            self.second_funding.is_some()
                && self.second_refund.is_none()
                && self.first_redemption.is_none()
        } else {
            false
        }
    }

    /// Whether the latest completed local observation still proves the first
    /// lock current. Legacy rows which have never entered the generation
    /// protocol retain their prior behavior; once an observation starts, no
    /// value-moving action may use the lock until that exact generation
    /// confirms it.
    pub fn first_funding_is_current(&self) -> bool {
        self.first_funding.is_some()
            && !self.first_funding_revoked
            && (self.first_funding_observation_generation == 0
                || self.first_funding_confirmed_generation
                    == Some(self.first_funding_observation_generation))
    }

    pub fn module_is_funded(&self, module: ModuleId) -> bool {
        if module == self.first_module {
            self.first_funding.is_some()
        } else if module == self.second_module {
            self.second_funding.is_some()
        } else {
            false
        }
    }

    pub fn funded_module_is_settled(&self, module: ModuleId) -> bool {
        if module == self.first_module {
            self.first_funding.is_some()
                && (self.first_refund.is_some() || self.second_redemption.is_some())
        } else if module == self.second_module {
            self.second_funding.is_some()
                && (self.second_refund.is_some() || self.first_redemption.is_some())
        } else {
            false
        }
    }

    pub fn has_confirmed_refund(&self) -> bool {
        self.first_refund.is_some() || self.second_refund.is_some()
    }

    pub fn all_funded_legs_settled(&self) -> bool {
        let any_funded = self.first_funding.is_some() || self.second_funding.is_some();
        let first_settled = self.first_funding.is_none()
            || self.first_refund.is_some()
            || self.second_redemption.is_some();
        let second_settled = self.second_funding.is_none()
            || self.second_refund.is_some()
            || self.first_redemption.is_some();
        any_funded && first_settled && second_settled
    }

    fn transition(&mut self, evidence: VerifiedEvidence, now_unix: u64) -> Result<(), MarketError> {
        let next = match (self.state, evidence) {
            (SwapState::OfferPublished, VerifiedEvidence::OfferAcceptanceValidated) => {
                SwapState::OfferAcceptanceReceived
            }
            (SwapState::OfferAcceptanceReceived, VerifiedEvidence::OfferReserved) => {
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
                state @ (SwapState::FirstFundingPending
                | SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Refunded
                | SwapState::Failed),
                VerifiedEvidence::FirstFundingObservationStarted { module, generation },
            ) if self.first_module == module
                && (state == SwapState::FirstFundingPending
                    || self.first_funding.is_some()
                    || (state == SwapState::Failed
                        && self.second_funding.is_none()
                        && matches!(
                            self.failure_reason.as_deref(),
                            Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
                        )))
                && self.second_redemption.is_none()
                && self.first_refund.is_none()
                && self.first_funding_observation_generation.checked_add(1) == Some(generation) =>
            {
                self.first_funding_observation_generation = generation;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                state
            }
            (
                SwapState::FirstFundingPending,
                VerifiedEvidence::FirstFundingConfirmed { evidence },
            ) => {
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                SwapState::FirstFunded
            }
            (
                SwapState::FirstFundingPending,
                VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                    evidence,
                    module,
                    generation,
                },
            ) if self.first_module == module
                && self.first_funding_observation_generation == generation
                && self.first_refund.is_none()
                && self.second_redemption.is_none() =>
            {
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = Some(generation);
                self.second_funding_authorization = None;
                SwapState::FirstFunded
            }
            (SwapState::Failed, VerifiedEvidence::FirstFundingConfirmed { evidence })
                if self.first_funding.is_none()
                    && self.second_funding.is_none()
                    && matches!(
                        self.failure_reason.as_deref(),
                        Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
                    ) =>
            {
                // A timeout is evidence that the coordinator had not yet
                // observed a lock, not evidence that no lock can exist. Once
                // the local chain verifier proves the exact terms-bound HTLC,
                // restoring FirstFunded is the only safe state: settlement or
                // refund recovery must remain available for locked funds.
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                self.failure_reason = None;
                SwapState::FirstFunded
            }
            (
                SwapState::Failed,
                VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                    evidence,
                    module,
                    generation,
                },
            ) if self.first_module == module
                && self.first_funding_observation_generation == generation
                && self.first_funding.is_none()
                && self.second_funding.is_none()
                && matches!(
                    self.failure_reason.as_deref(),
                    Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
                ) =>
            {
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = Some(generation);
                self.second_funding_authorization = None;
                self.failure_reason = None;
                SwapState::FirstFunded
            }
            (SwapState::FirstFunded, VerifiedEvidence::SecondFundingReady) => {
                SwapState::SecondFundingPending
            }
            (
                SwapState::SecondFundingPending,
                VerifiedEvidence::SecondFundingAuthorizationIssued { authorization },
            ) if self.first_funding == Some(authorization.first_funding)
                && !self.first_funding_revoked
                && self.second_funding.is_none()
                && self.second_module == authorization.module
                && self.first_funding_observation_generation
                    == authorization.first_funding_observation_generation
                && self.first_funding_confirmed_generation
                    == Some(authorization.first_funding_observation_generation)
                && authorization.id.as_bytes().iter().any(|byte| *byte != 0)
                && now_unix < authorization.expires_at_unix =>
            {
                self.second_funding_authorization = Some(authorization);
                SwapState::SecondFundingPending
            }
            (
                state @ (SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Refunded
                | SwapState::Failed),
                VerifiedEvidence::FirstFundingConfirmed { evidence },
            ) if self.first_funding.is_some()
                && !self.first_funding_revoked
                && self.second_funding.is_none() =>
            {
                // A reorganization can replace an exact terms-bound lock with
                // another transaction. Fresh local chain verification may
                // update that evidence. Recovery-only states can also regain
                // redemption authority if the exact lock becomes current.
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                if matches!(state, SwapState::Refunded | SwapState::Failed) {
                    SwapState::RefundEligible
                } else {
                    state
                }
            }
            (
                state @ (SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Refunded
                | SwapState::Failed),
                VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                    evidence,
                    module,
                    generation,
                },
            ) if self.first_module == module
                && self.first_funding_observation_generation == generation
                && self.first_refund.is_none()
                && self.second_redemption.is_none() =>
            {
                self.first_funding = Some(evidence);
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = Some(generation);
                self.second_funding_authorization = None;
                if matches!(state, SwapState::Refunded | SwapState::Failed) {
                    SwapState::RefundEligible
                } else {
                    state
                }
            }
            (SwapState::FirstFunded, VerifiedEvidence::FirstFundingInvalidated { evidence })
                if self.first_funding == Some(evidence) && self.second_funding.is_none() =>
            {
                self.first_funding = None;
                self.first_funding_revoked = false;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                SwapState::FirstFundingPending
            }
            (
                state @ (SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Refunded
                | SwapState::Failed),
                VerifiedEvidence::FirstFundingInvalidated { evidence },
            ) if self.first_funding == Some(evidence)
                && self.second_redemption.is_none()
                && self.first_refund.is_none() =>
            {
                // SecondFundingPending may already correspond to a signed or
                // broadcast transaction. Preserve evidence for recovery, but
                // revoke every authority that depended on its currentness.
                self.first_funding_revoked = true;
                self.first_funding_confirmed_generation = None;
                self.second_funding_authorization = None;
                if state == SwapState::Refunded {
                    SwapState::RefundEligible
                } else {
                    state
                }
            }
            (
                SwapState::SecondFundingPending,
                VerifiedEvidence::SecondFundingConfirmed { evidence },
            ) => {
                self.second_funding = Some(evidence);
                SwapState::BothFunded
            }
            (
                SwapState::BothFunded | SwapState::RefundEligible,
                VerifiedEvidence::FirstRedemptionConfirmed { evidence },
            ) if self.second_funding.is_some()
                && self.second_refund.is_none()
                && self.first_redemption.is_none() =>
            {
                self.first_redemption = Some(evidence);
                SwapState::FirstRedeemed
            }
            (SwapState::FirstRedeemed, VerifiedEvidence::SecretExtracted { hashlock })
                if hashlock == self.hashlock =>
            {
                if self.all_funded_legs_settled() {
                    SwapState::Refunded
                } else {
                    SwapState::SecretObserved
                }
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
                SwapState::FirstFunded | SwapState::SecondFundingPending,
                VerifiedEvidence::RefundEligibilityValidated,
            ) if self.first_funding.is_some() && self.second_funding.is_none() => {
                SwapState::RefundEligible
            }
            (SwapState::RefundEligible, VerifiedEvidence::RefundBroadcast { evidence }) => {
                self.refund = Some(evidence);
                SwapState::RefundBroadcast
            }
            (SwapState::RefundBroadcast, VerifiedEvidence::RefundConfirmed { evidence })
                if self.refund == Some(evidence)
                    && self.first_funding.is_some()
                    && self.second_funding.is_none() =>
            {
                self.first_refund = Some(evidence);
                SwapState::Refunded
            }
            (
                SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Failed
                | SwapState::Refunded,
                VerifiedEvidence::ChainRefundConfirmed { module, evidence },
            ) if self.can_record_refund_for_module(module) => {
                if module == self.first_module {
                    self.first_refund = Some(evidence);
                } else {
                    self.second_refund = Some(evidence);
                }
                self.refund = Some(evidence);
                if self.all_funded_legs_settled() {
                    SwapState::Refunded
                } else {
                    SwapState::RefundEligible
                }
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
        if next != SwapState::SecondFundingPending {
            self.second_funding_authorization = None;
        }
        self.state = next;
        self.last_verified_at_unix = now_unix;
        Ok(())
    }
}

/// Return the deterministic workflow identity for the executable side of one
/// accepted Shakescape session. The bilateral session ID is already a 256-bit
/// signed protocol identity; hashing it again domain-separates its local
/// durable execution record from every other workflow namespace.
pub fn shakescape_execution_workflow_id(session_id: SessionId) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(SHAKESCAPE_EXECUTION_WORKFLOW_DOMAIN);
    hasher.update(session_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

/// Promote one already admitted, fully countersigned Shakescape HNS/BTC session
/// into the durable execution journal.  This is deliberately a local-store
/// operation: the board and the counterparty are not consulted, and no
/// transaction is funded or broadcast here.
///
/// The returned session is at `TermsFrozen`, so the next permitted action is
/// local refund preparation. A restart can call this function again: the
/// exact existing journal is returned, while any mismatch fails closed. If a
/// crash left the authenticated direct record without its derived execution
/// row, recovery is also permitted after the funding window: construction is
/// evaluated at the original admission instant and every actual funding path
/// must still pass `verify_new_funding_at` against the current time.
pub fn open_shakescape_execution(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    let expected_accepted_at = record
        .hello_accepted_at_unix
        .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
    // Re-authenticate the retained record at its original admission moment.
    // This permits recovery after a funding deadline, but does not let this
    // constructor authorize new funding after that deadline.
    hello
        .verify_agreement(policy.network())
        .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    verify_canonical_shakescape_lock_commitments(hello)?;
    if now_unix < expected_accepted_at {
        return Err(MarketError::InvalidEvidence);
    }
    let encoded_terms = hello
        .encode()
        .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    let workflow_id = shakescape_execution_workflow_id(session_id);
    if let Some(existing) = store.load_workflow::<SwapSession>(workflow_id)? {
        if existing.kind != WorkflowKind::AtomicSwap
            || existing.state.id != session_id
            || existing.state.accepted_shakescape_terms.as_deref() != Some(encoded_terms.as_slice())
        {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
        return Ok(existing.state);
    }
    let retained = load_shakescape_direct_swaps(store, policy)?;
    let active_obligations = retained
        .iter()
        .map(|record| session_board::swap_has_active_obligation(store, policy, record))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|active| *active)
        .count();
    // The current countersigned record is already included. Persisting its
    // derivative workflow is allowed at the sixteenth slot, while a
    // seventeenth locally countersigned obligation fails without evicting
    // recovery state.
    if active_obligations > MAX_CONCURRENT_SWAP_SESSIONS {
        return Err(MarketError::ShakescapeDirectSwapCapacity);
    }
    // The countersigned direct record is the durable authority and was
    // admitted only after time-bound verification. Reconstruct its missing
    // derivative at that original instant. Using `now_unix` here used to make
    // a crash between the direct-record write and execution-journal write
    // permanently unrecoverable once the funding window elapsed. This does
    // not reopen funding: all mobile funding permits independently call
    // `verify_new_funding_at(policy.network(), now_unix)` before progressing.
    let mut expected = swap_session_from_accepted_hello(hello, expected_accepted_at)?;
    expected.accepted_shakescape_terms = Some(encoded_terms);
    expected.last_verified_at_unix = now_unix;
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

/// Load one durable accepted Shakescape execution without consulting the peer or
/// reopening its funding window. Every persisted identity, revision, workflow
/// identifier, and countersigned term is re-authenticated before projection.
pub fn load_shakescape_execution(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
) -> Result<Option<SwapSession>, MarketError> {
    let workflow_id = shakescape_execution_workflow_id(session_id);
    store
        .load_workflow::<SwapSession>(workflow_id)?
        .map(|stored| validate_shakescape_execution(policy, session_id, workflow_id, stored))
        .transpose()
}

/// Capture the exact current ShakeScape authority that must still exist when
/// a second-chain HNS redeem becomes irreversibly broadcastable. The returned
/// guard is opaque outside the HNS runtime and compares both the execution
/// workflow and the countersigned session row in the checkpoint transaction.
pub fn authorize_hns_redeem_broadcast_guard(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
) -> Result<HnsSettlementBroadcastGuard, MarketError> {
    let execution = load_shakescape_execution(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if !execution.first_funding_is_current()
        || execution.second_module != ModuleId::Handshake
        || record.hello.is_none()
    {
        return Err(MarketError::InvalidTransition);
    }
    HnsSettlementBroadcastGuard::new(
        session_id,
        shakescape_execution_workflow_id(session_id),
        execution.revision,
        session_board::record_id(policy, session_id),
        record.store_revision,
    )
    .map_err(|_| MarketError::InvalidEvidence)
}

/// Return every durable Shakescape execution within the protocol capacity. This is
/// the recovery/UI source of truth: active board listings may expire or be
/// cancelled after bilateral terms are frozen, but their execution journals
/// remain independently discoverable and resumable.
pub fn list_shakescape_executions(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
) -> Result<Vec<SwapSession>, MarketError> {
    // `WorkflowKind::AtomicSwap` is intentionally shared by more than one
    // authenticated wallet protocol, including the older HNS name-swap
    // workflow. Its encrypted JSON rows therefore do not share one Rust
    // schema and must never be bulk-deserialized as `SwapSession` merely
    // because their broad workflow kind matches.
    //
    // The direct ShakeScape record namespace is the exact durable registry
    // for this protocol. Enumerate those authenticated records first, then
    // derive and load only the corresponding execution workflow IDs. This is
    // both an authority boundary and a schema boundary: an unrelated valid
    // atomic workflow can no longer suppress HNS synchronization or swap
    // recovery with a misleading persistence failure.
    let records = load_shakescape_direct_swaps(store, policy)?;
    let mut executions = Vec::with_capacity(records.len());
    for record in records {
        if record.hello.is_none() {
            continue;
        }
        let session_id = SessionId::new(record.acceptance.swap_session_id);
        let execution = load_shakescape_execution(store, policy, session_id)?
            .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
        executions.push(execution);
    }
    executions.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    Ok(executions)
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
/// wallet's current checkpoint. Shakescape peer messages are never accepted here.
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
                    hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcChainSpend {
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
                    spend: hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcChainSpend {
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

/// Allocate a durable generation before reading the first chain. Starting a
/// newer observation immediately revokes any unconsumed second-funding lease;
/// only a result carrying the latest generation may restore authority.
pub fn begin_shakescape_first_funding_observation(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    module: ModuleId,
    now_unix: u64,
) -> Result<u64, MarketError> {
    let Some(mut session) = load_shakescape_execution(store, policy, session_id)? else {
        return Err(MarketError::UnknownShakescapeDirectSwap);
    };
    if !matches!(
        session.state,
        SwapState::FirstFundingPending
            | SwapState::FirstFunded
            | SwapState::SecondFundingPending
            | SwapState::BothFunded
            | SwapState::FirstRedeemed
            | SwapState::SecretObserved
            | SwapState::RefundEligible
            | SwapState::RefundBroadcast
            | SwapState::Refunded
            | SwapState::Failed
    ) || session.first_module != module
        || (session.state != SwapState::FirstFundingPending
            && session.first_funding.is_none()
            && !(session.state == SwapState::Failed
                && session.second_funding.is_none()
                && matches!(
                    session.failure_reason.as_deref(),
                    Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
                )))
        || session.second_redemption.is_some()
        || session.first_refund.is_some()
    {
        return Err(MarketError::InvalidTransition);
    }
    let generation = session
        .first_funding_observation_generation
        .checked_add(1)
        .ok_or(MarketError::Invariant)?;
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::FirstFundingObservationStarted { module, generation },
        now_unix,
        &mut journal,
    )?;
    Ok(generation)
}

/// Advance a durable Shakescape execution only with locally verified funding
/// evidence. The peer's Shakescape funding status is intentionally not accepted as
/// an argument here: it can inform UI/transport state, but cannot cause this
/// state transition. This compatibility path records no observation generation
/// and therefore cannot authorize second-chain value movement.
pub fn apply_locally_verified_shakescape_funding(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    funding: LocallyVerifiedSwapFunding,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    apply_locally_verified_shakescape_funding_inner(
        store, policy, session_id, funding, None, now_unix,
    )
}

/// Apply the result of the exact first-chain read whose durable generation was
/// allocated before the read began.
pub fn apply_locally_verified_shakescape_funding_at_generation(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    funding: LocallyVerifiedSwapFunding,
    observation_generation: u64,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    apply_locally_verified_shakescape_funding_inner(
        store,
        policy,
        session_id,
        funding,
        Some(observation_generation),
        now_unix,
    )
}

fn apply_locally_verified_shakescape_funding_inner(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    funding: LocallyVerifiedSwapFunding,
    observation_generation: Option<u64>,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let stored = store
        .load_workflow::<SwapSession>(workflow_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if stored.kind != WorkflowKind::AtomicSwap || stored.state.id != session_id {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let terms = stored
        .state
        .accepted_shakescape_terms
        .as_deref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    let hello =
        SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    if hello.encode().ok().as_deref() != Some(terms)
        || SessionId::new(hello.swap_session_id) != session_id
        || hello.verify_agreement(policy.network()).is_err()
    {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    verify_local_funding_against_shakescape_terms(&hello, &funding)?;
    if observation_generation.is_none()
        && funding.module() == stored.state.first_module
        && stored.state.first_funding_observation_generation != 0
    {
        // Once a caller has entered the durable observation protocol, an
        // unscoped proof can no longer race a newer authoritative absence.
        return Err(MarketError::InvalidTransition);
    }
    if observation_generation.is_some_and(|generation| {
        funding.module() != stored.state.first_module
            || stored.state.first_funding_observation_generation != generation
            || stored.state.first_refund.is_some()
            || stored.state.second_redemption.is_some()
            || !matches!(
                stored.state.state,
                SwapState::FirstFundingPending
                    | SwapState::FirstFunded
                    | SwapState::SecondFundingPending
                    | SwapState::BothFunded
                    | SwapState::FirstRedeemed
                    | SwapState::SecretObserved
                    | SwapState::RefundEligible
                    | SwapState::RefundBroadcast
                    | SwapState::Refunded
                    | SwapState::Failed
            )
    }) {
        return Err(MarketError::InvalidTransition);
    }
    let funding_evidence = funding_evidence_id(&funding);
    let first_funding_evidence = || match observation_generation {
        Some(generation) => VerifiedEvidence::FirstFundingConfirmedAtGeneration {
            evidence: funding_evidence,
            module: funding.module(),
            generation,
        },
        None => VerifiedEvidence::FirstFundingConfirmed {
            evidence: funding_evidence,
        },
    };
    // Re-scanning the exact confirmed lock is expected after reconnects,
    // upgrades, and reorg checks. Treat already-journaled chain evidence as
    // idempotent so the coordination layer can repair or replay its locator
    // without attempting an impossible second state transition.
    let refreshes_unsettled_first_funding = funding.module() == stored.state.first_module
        && stored.state.first_funding == Some(funding_evidence)
        && (observation_generation.is_some()
            || stored.state.second_funding.is_none()
            || stored.state.first_funding_revoked)
        && matches!(
            stored.state.state,
            SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
                | SwapState::Refunded
                | SwapState::Failed
        );
    if !refreshes_unsettled_first_funding
        && ((funding.module() == stored.state.first_module
            && stored.state.first_funding == Some(funding_evidence))
            || (funding.module() == stored.state.second_module
                && stored.state.second_funding == Some(funding_evidence)))
    {
        return Ok(stored.state);
    }
    let evidence = match stored.state.state {
        SwapState::FirstFundingPending if funding.module() == stored.state.first_module => {
            vec![first_funding_evidence()]
        }
        SwapState::Failed
            if funding.module() == stored.state.first_module
                && stored.state.first_funding.is_none()
                && stored.state.second_funding.is_none()
                && matches!(
                    stored.state.failure_reason.as_deref(),
                    Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
                ) =>
        {
            vec![first_funding_evidence()]
        }
        SwapState::FirstFunded
        | SwapState::SecondFundingPending
        | SwapState::BothFunded
        | SwapState::FirstRedeemed
        | SwapState::SecretObserved
        | SwapState::RefundEligible
        | SwapState::RefundBroadcast
        | SwapState::Refunded
        | SwapState::Failed
            if funding.module() == stored.state.first_module
                && (observation_generation.is_some()
                    || stored.state.second_funding.is_none()
                    || stored.state.first_funding_revoked) =>
        {
            vec![first_funding_evidence()]
        }
        SwapState::SecondFundingPending if funding.module() == stored.state.second_module => {
            vec![VerifiedEvidence::SecondFundingConfirmed {
                evidence: funding_evidence,
            }]
        }
        // The party that does not construct the second lock has no local
        // preparation call to cross this checkpoint. Its independently
        // verified counterparty lock is both readiness evidence and funding
        // evidence, persisted as two restart-safe journal revisions.
        SwapState::FirstFunded if funding.module() == stored.state.second_module => {
            vec![
                VerifiedEvidence::SecondFundingReady,
                VerifiedEvidence::SecondFundingConfirmed {
                    evidence: funding_evidence,
                },
            ]
        }
        _ => return Err(MarketError::InvalidTransition),
    };
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    for evidence in evidence {
        session.apply(evidence, now_unix, &mut journal)?;
    }
    Ok(session)
}

/// Revoke a previously confirmed first-chain observation after that chain's
/// local verifier has reconciled the exact watch to its current checkpoint and
/// no longer confirms the lock. If a second-chain transaction may already
/// exist, the evidence is retained for recovery while every authority derived
/// from its currentness is revoked.
pub fn invalidate_locally_verified_shakescape_first_funding(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    invalidate_locally_verified_shakescape_first_funding_inner(
        store, policy, session_id, None, now_unix,
    )
}

/// Apply authoritative absence only to the durable observation generation
/// allocated before that exact chain read began.
pub fn invalidate_locally_verified_shakescape_first_funding_at_generation(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    observation_generation: u64,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    invalidate_locally_verified_shakescape_first_funding_inner(
        store,
        policy,
        session_id,
        Some(observation_generation),
        now_unix,
    )
}

fn invalidate_locally_verified_shakescape_first_funding_inner(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    observation_generation: Option<u64>,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let Some(mut session) = load_shakescape_execution(store, policy, session_id)? else {
        return Err(MarketError::UnknownShakescapeDirectSwap);
    };
    if observation_generation.is_some_and(|generation| {
        session.first_funding_observation_generation != generation
            || !matches!(
                session.state,
                SwapState::FirstFundingPending
                    | SwapState::FirstFunded
                    | SwapState::SecondFundingPending
                    | SwapState::BothFunded
                    | SwapState::FirstRedeemed
                    | SwapState::SecretObserved
                    | SwapState::RefundEligible
                    | SwapState::RefundBroadcast
                    | SwapState::Refunded
                    | SwapState::Failed
            )
    }) {
        return Err(MarketError::InvalidTransition);
    }
    if (session.state == SwapState::FirstFundingPending
        && session.first_funding.is_none()
        && session.second_funding.is_none())
        || (session.state == SwapState::Failed
            && session.first_funding.is_none()
            && session.second_funding.is_none()
            && matches!(
                session.failure_reason.as_deref(),
                Some(PREFUNDING_DEADLINE_FAILURE | PREFUNDING_BITCOIN_ABSENCE_FAILURE)
            ))
        || (session.first_funding_revoked
            && session.first_funding.is_some()
            && session.first_refund.is_none()
            && session.second_redemption.is_none())
    {
        return Ok(session);
    }
    if !matches!(
        session.state,
        SwapState::FirstFunded
            | SwapState::SecondFundingPending
            | SwapState::BothFunded
            | SwapState::FirstRedeemed
            | SwapState::SecretObserved
            | SwapState::RefundEligible
            | SwapState::RefundBroadcast
            | SwapState::Refunded
            | SwapState::Failed
    ) || session.first_refund.is_some()
        || session.second_redemption.is_some()
    {
        return Err(MarketError::InvalidTransition);
    }
    let evidence = session
        .first_funding
        .ok_or(MarketError::InvalidTransition)?;
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::FirstFundingInvalidated { evidence },
        now_unix,
        &mut journal,
    )?;
    Ok(session)
}

fn second_funding_authorization_entity_id(session_id: SessionId) -> Vec<u8> {
    let mut id = Vec::with_capacity(
        SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_DOMAIN.len() + session_id.as_bytes().len(),
    );
    id.extend_from_slice(SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_DOMAIN);
    id.extend_from_slice(session_id.as_bytes());
    id
}

fn persisted_second_funding_authorization(
    session: &SwapSession,
    authorization: SecondFundingAuthorization,
    issued_entity_revision: u64,
) -> PersistedSecondFundingAuthorization {
    PersistedSecondFundingAuthorization {
        schema_version: SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_SCHEMA_VERSION,
        session_id: session.id,
        execution_workflow_id: shakescape_execution_workflow_id(session.id),
        execution_revision: session.revision,
        issued_entity_revision,
        authorization,
    }
}

fn validate_persisted_second_funding_authorization(
    record: &PersistedSecondFundingAuthorization,
    session: &SwapSession,
) -> Result<(), MarketError> {
    if record.schema_version != SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_SCHEMA_VERSION
        || record.session_id != session.id
        || record.execution_workflow_id != shakescape_execution_workflow_id(session.id)
        || record.execution_revision != session.revision
        || record.issued_entity_revision == 0
        || session.second_funding_authorization != Some(record.authorization)
        || record.authorization.module != session.second_module
        || record.authorization.first_funding
            != session
                .first_funding
                .ok_or(MarketError::InvalidTransition)?
        || record.authorization.first_funding_observation_generation
            != session.first_funding_observation_generation
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok(())
}

fn validate_previous_second_funding_authorization(
    record: &PersistedSecondFundingAuthorization,
    stored_entity_revision: u64,
    session_id: SessionId,
    workflow_id: WorkflowId,
    expected_execution_revision: u64,
) -> Result<(), MarketError> {
    if record.schema_version != SHAKESCAPE_SECOND_FUNDING_AUTHORIZATION_SCHEMA_VERSION
        || record.session_id != session_id
        || record.execution_workflow_id != workflow_id
        || record.issued_entity_revision == 0
        || (stored_entity_revision == record.issued_entity_revision
            && record.execution_revision != expected_execution_revision)
        || (stored_entity_revision == record.issued_entity_revision.saturating_add(1)
            && record.execution_revision > expected_execution_revision)
        || (stored_entity_revision != record.issued_entity_revision
            && stored_entity_revision != record.issued_entity_revision.saturating_add(1))
        || record
            .authorization
            .id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || record.authorization.expires_at_unix == 0
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok(())
}

/// Load the exact single-use row that a chain broadcast checkpoint must
/// consume. Merely constructing or displaying a transaction never consumes
/// it; a current reconciliation can therefore revoke authority until the
/// signed transaction is durably recoverable.
pub fn shakescape_second_funding_broadcast_guard(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    module: ModuleId,
    authorization_id: ObjectHash,
    now_unix: u64,
) -> Result<SecondFundingBroadcastGuard, MarketError> {
    let session = load_shakescape_execution(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let entity_id = second_funding_authorization_entity_id(session_id);
    let stored = store
        .load_entity::<PersistedSecondFundingAuthorization>(
            EntityKind::SwapFundingAuthorization,
            &entity_id,
        )?
        .ok_or(MarketError::InvalidTransition)?;
    validate_persisted_second_funding_authorization(&stored.value, &session)?;
    if stored.revision != stored.value.issued_entity_revision {
        return Err(MarketError::InvalidTransition);
    }
    let authorization = stored.value.authorization;
    if session.state != SwapState::SecondFundingPending
        || !session.first_funding_is_current()
        || session.second_funding.is_some()
        || authorization.id != authorization_id
        || authorization.module != module
        || now_unix >= authorization.expires_at_unix
    {
        return Err(MarketError::InvalidTransition);
    }
    Ok(SecondFundingBroadcastGuard {
        session_id,
        execution_workflow_id: stored.value.execution_workflow_id,
        execution_revision: stored.value.execution_revision,
        authorization_entity_id: stored.id,
        authorization_entity_revision: stored.revision,
        authorization,
    })
}

/// Persist one single-use authorization for a second-chain preparation or
/// broadcast. Issuance rechecks the signed funding window and the product's
/// effective refund floors while holding the same store mutex used by chain
/// reconciliation.
pub fn issue_shakescape_second_funding_authorization(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    module: ModuleId,
    authorization_id: ObjectHash,
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let Some(mut session) = load_shakescape_execution(store, policy, session_id)? else {
        return Err(MarketError::UnknownShakescapeDirectSwap);
    };
    if session.state != SwapState::SecondFundingPending
        || session.second_module != module
        || session.first_funding.is_none()
        || session.first_funding_revoked
        || session.first_funding_confirmed_generation
            != Some(session.first_funding_observation_generation)
        || session.second_funding.is_some()
        || authorization_id.as_bytes().iter().all(|byte| *byte == 0)
        || expires_at_unix <= now_unix
    {
        return Err(MarketError::InvalidTransition);
    }
    let terms = session
        .accepted_shakescape_terms
        .as_deref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    let hello =
        SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    hello
        .verify_new_funding_at(policy.network(), now_unix)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    validate_shakescape_effective_refund_safety(&hello)?;
    if expires_at_unix > hello.header.expires_at {
        return Err(MarketError::InvalidTransition);
    }
    let authorization = SecondFundingAuthorization {
        id: authorization_id,
        module,
        first_funding: session
            .first_funding
            .ok_or(MarketError::InvalidTransition)?,
        first_funding_observation_generation: session.first_funding_observation_generation,
        expires_at_unix,
    };
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    session.apply(
        VerifiedEvidence::SecondFundingAuthorizationIssued { authorization },
        now_unix,
        &mut journal,
    )?;
    Ok(session)
}

/// Advance a funded Shakescape execution through both the first observed redeem
/// and its secret extraction, using only one wallet's independently verified
/// chain observation. In the agreed HTLC ordering, the second-funded chain is
/// redeemed first; that transaction reveals the preimage needed to redeem the
/// first-funded chain. The preimage is encrypted in the local wallet before
/// the durable state transition, so an interruption cannot strand recovery.
pub fn apply_locally_verified_shakescape_first_redemption(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let stored =
        load_shakescape_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if spend.module() != stored.state.second_module
        || spend.confirmation_count() == 0
        || stored.state.second_refund.is_some()
    {
        return Err(MarketError::InvalidTransition);
    }
    let preimage = spend.redeem_preimage()?;
    if ObjectHash::new(Sha256::digest(preimage.expose_for_settlement()).into())
        != stored.state.hashlock
    {
        return Err(MarketError::InvalidEvidence);
    }
    let evidence = spend_evidence_id(&spend);
    match stored.state.first_redemption {
        Some(existing) if existing != evidence => return Err(MarketError::InvalidEvidence),
        None if !matches!(
            stored.state.state,
            SwapState::BothFunded | SwapState::RefundEligible
        ) =>
        {
            return Err(MarketError::InvalidTransition);
        }
        _ => {}
    }
    let preimage_id = shakescape_observed_preimage_id(session_id);
    match store.get_secret(&preimage_id, SecretKind::HtlcPreimage)? {
        Some(persisted) if persisted.as_slice() != preimage.expose_for_settlement().as_slice() => {
            return Err(MarketError::InvalidEvidence);
        }
        Some(_) => {}
        None if stored.state.first_redemption.is_none() => store.put_secret(
            &preimage_id,
            SecretKind::HtlcPreimage,
            preimage.expose_for_settlement(),
            now_unix,
        )?,
        None => return Err(MarketError::InvalidEvidence),
    }
    let mut session = stored.state;
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    if session.first_redemption.is_none() {
        session.apply(
            VerifiedEvidence::FirstRedemptionConfirmed { evidence },
            now_unix,
            &mut journal,
        )?;
    }
    if session.state == SwapState::FirstRedeemed {
        session.apply(
            VerifiedEvidence::SecretExtracted {
                hashlock: session.hashlock,
            },
            now_unix,
            &mut journal,
        )?;
    }
    Ok(session)
}

/// Advance a Shakescape execution after the locally verified redeem of the
/// first-funded chain. The preceding first redeem must already have persisted
/// the matching preimage, so this cannot be used to skip the recovery-safe
/// secret handoff step.
pub fn apply_locally_verified_shakescape_second_redemption(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let stored =
        load_shakescape_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if spend.module() != stored.state.first_module || spend.confirmation_count() == 0 {
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
            &shakescape_observed_preimage_id(session_id),
            SecretKind::HtlcPreimage,
        )?
        .is_none_or(|stored| stored.as_slice() != preimage.expose_for_settlement().as_slice())
    {
        return Err(MarketError::InvalidEvidence);
    }
    let evidence = spend_evidence_id(&spend);
    let mut session = stored.state;
    match session.second_redemption {
        Some(existing) if existing != evidence => return Err(MarketError::InvalidEvidence),
        None if session.state != SwapState::SecretObserved => {
            return Err(MarketError::InvalidTransition);
        }
        _ => {}
    }
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    if session.second_redemption.is_none() {
        session.apply(
            VerifiedEvidence::SecondRedemptionConfirmed { evidence },
            now_unix,
            &mut journal,
        )?;
    }
    if session.state == SwapState::SecondRedeemed {
        session.apply(
            VerifiedEvidence::CompletionValidated,
            now_unix,
            &mut journal,
        )?;
    }
    Ok(session)
}

/// Mark the execution terminal only after a locally verified timeout refund.
/// Each chain verifier is responsible for consensus maturity and the exact
/// descriptor/signature branch; the coordinator records the resulting
/// confirmed observation rather than trusting a peer refund status.
pub fn apply_locally_verified_shakescape_refund(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = shakescape_execution_workflow_id(session_id);
    let stored =
        load_shakescape_execution_for_local_evidence(store, policy, session_id, workflow_id)?;
    if !spend.is_refund()
        || (spend.module() != stored.state.first_module
            && spend.module() != stored.state.second_module)
        || spend.confirmation_count() == 0
    {
        return Err(MarketError::InvalidEvidence);
    }
    let module = spend.module();
    let evidence = spend_evidence_id(&spend);
    let mut session = stored.state;
    if let Some(existing) = session.refund_for_module(module) {
        if existing != evidence {
            return Err(MarketError::InvalidEvidence);
        }
    } else if !session.can_record_refund_for_module(module) {
        return Err(MarketError::InvalidTransition);
    }
    let mut journal = WalletStoreJournal {
        store,
        workflow_id,
        updated_at_unix: now_unix,
    };
    if session.refund_for_module(module).is_none() {
        session.apply(
            VerifiedEvidence::ChainRefundConfirmed { module, evidence },
            now_unix,
            &mut journal,
        )?;
    }
    Ok(session)
}

/// Load the locally retained preimage that was authenticated by a first
/// redemption. This never returns a peer-provided value and requires the
/// encrypted wallet store to be unlocked.
pub fn load_locally_verified_shakescape_preimage(
    store: &WalletStore,
    session_id: SessionId,
) -> Result<Option<Preimage>, MarketError> {
    store
        .get_secret(
            &shakescape_observed_preimage_id(session_id),
            SecretKind::HtlcPreimage,
        )?
        .map(|value| {
            let bytes = <[u8; Preimage::LENGTH]>::try_from(value.as_slice())
                .map_err(|_| MarketError::InvalidEvidence)?;
            Ok(Preimage::new(bytes))
        })
        .transpose()
}

fn load_shakescape_execution_for_local_evidence(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    workflow_id: WorkflowId,
) -> Result<hns_wallet_store::StoredWorkflow<SwapSession>, MarketError> {
    let stored = store
        .load_workflow::<SwapSession>(workflow_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    validate_shakescape_execution_record(policy, session_id, workflow_id, &stored)?;
    Ok(stored)
}

fn validate_shakescape_execution(
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    workflow_id: WorkflowId,
    stored: StoredWorkflow<SwapSession>,
) -> Result<SwapSession, MarketError> {
    validate_shakescape_execution_record(policy, session_id, workflow_id, &stored)?;
    Ok(stored.state)
}

fn validate_shakescape_execution_record(
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
    workflow_id: WorkflowId,
    stored: &StoredWorkflow<SwapSession>,
) -> Result<(), MarketError> {
    if stored.kind != WorkflowKind::AtomicSwap
        || stored.id != workflow_id
        || stored.state.id != session_id
        || stored.revision != stored.state.revision
        || stored.updated_at_unix != stored.state.last_verified_at_unix
        || (stored.state.first_funding_revoked && stored.state.first_funding.is_none())
        || stored
            .state
            .first_funding_confirmed_generation
            .is_some_and(|generation| {
                generation == 0 || generation != stored.state.first_funding_observation_generation
            })
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let terms = stored
        .state
        .accepted_shakescape_terms
        .as_deref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    let hello =
        SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    if hello.encode().ok().as_deref() != Some(terms)
        || SessionId::new(hello.swap_session_id) != session_id
        || hello.verify_agreement(policy.network()).is_err()
    {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    if stored
        .state
        .second_funding_authorization
        .is_some_and(|authorization| {
            stored.state.state != SwapState::SecondFundingPending
                || stored.state.second_module != authorization.module
                || stored.state.first_funding != Some(authorization.first_funding)
                || stored.state.first_funding_revoked
                || stored.state.first_funding_observation_generation
                    != authorization.first_funding_observation_generation
                || stored.state.first_funding_confirmed_generation
                    != Some(authorization.first_funding_observation_generation)
                || stored.state.second_funding.is_some()
                || authorization.id.as_bytes().iter().all(|byte| *byte == 0)
                || authorization.expires_at_unix > hello.header.expires_at
        })
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok(())
}

fn shakescape_observed_preimage_id(session_id: SessionId) -> Vec<u8> {
    let mut id =
        Vec::with_capacity(SHAKESCAPE_OBSERVED_PREIMAGE_DOMAIN.len() + session_id.as_bytes().len());
    id.extend_from_slice(SHAKESCAPE_OBSERVED_PREIMAGE_DOMAIN);
    id.extend_from_slice(session_id.as_bytes());
    id
}

fn spend_evidence_id(spend: &LocallyVerifiedSwapSpend) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/verified-shakescape-spend/v1");
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

fn verify_local_funding_against_shakescape_terms(
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
            let descriptor = build_shakescape_bitcoin_htlc(hello, side)
                .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
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
    hasher.update(b"hns-wallet-rs/verified-shakescape-funding/v1");
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
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)
}

fn confirmation_minimum(hello: &SwapSessionHello, side: SwapAssetSide) -> u32 {
    match side {
        SwapAssetSide::Offered => hello.offered_minimum_confirmations,
        SwapAssetSide::Received => hello.received_minimum_confirmations,
    }
}

/// Reconstruct both lock descriptors from the mutually signed terms.  The
/// HNS protocol owns its descriptor format; the Kyoto adapter owns the
/// Bitcoin P2WSH format and its domain-separated Shakescape commitment.  Keeping
/// this check at the durable-execution boundary means a board record cannot
/// turn an opaque or substituted 32-byte lock claim into a fundable swap.
fn verify_canonical_shakescape_lock_commitments(
    hello: &SwapSessionHello,
) -> Result<(), MarketError> {
    verify_canonical_shakescape_lock_commitment(hello, SwapAssetSide::Offered)?;
    verify_canonical_shakescape_lock_commitment(hello, SwapAssetSide::Received)
}

pub(crate) fn shakescape_effective_refund_at(
    asset: AssetId,
    deadline: SettlementDeadline,
) -> Result<u64, MarketError> {
    if deadline.kind != DeadlineKind::UnixTime {
        return Err(MarketError::UnsafeTimeouts);
    }
    match asset {
        AssetId::HNS => hns_refund_time_lock(deadline)
            .map(|lock| lock.effective_time_seconds)
            .map_err(|_| MarketError::UnsafeTimeouts),
        AssetId::BTC => Ok(deadline.value),
        _ => Err(MarketError::InvalidPair),
    }
}

/// Validate executable refund ordering after each chain's consensus encoding
/// is applied. This is called before countersigning and again before every new
/// funding authorization. Historical sessions remain loadable so already
/// locked funds can still be redeemed or refunded.
pub fn validate_shakescape_effective_refund_safety(
    hello: &SwapSessionHello,
) -> Result<(), MarketError> {
    if hello.first_funding_chain != hello.offered_asset.chain() {
        return Err(MarketError::InvalidPair);
    }
    let expected_confirmations = |asset| match asset {
        AssetId::BTC => Ok(SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS),
        AssetId::HNS => Ok(SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS),
        _ => Err(MarketError::InvalidPair),
    };
    if hello.offered_minimum_confirmations != expected_confirmations(hello.offered_asset)?
        || hello.received_minimum_confirmations != expected_confirmations(hello.received_asset)?
    {
        return Err(MarketError::UnsafeTimeouts);
    }
    let first_refund =
        shakescape_effective_refund_at(hello.offered_asset, hello.offered_refund_deadline)?;
    let second_refund =
        shakescape_effective_refund_at(hello.received_asset, hello.received_refund_deadline)?;
    let maximum_refund = hello
        .header
        .created_at
        .checked_add(SHAKESCAPE_MAX_SETTLEMENT_HORIZON_SECONDS)
        .ok_or(MarketError::UnsafeTimeouts)?;
    let minimum_second_refund = hello
        .header
        .expires_at
        .checked_add(MIN_SECOND_CHAIN_REDEMPTION_WINDOW_SECONDS)
        .ok_or(MarketError::UnsafeTimeouts)?;
    if first_refund > maximum_refund
        || second_refund > maximum_refund
        || second_refund < minimum_second_refund
        || first_refund
            .checked_sub(second_refund)
            .is_none_or(|margin| margin < MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS)
    {
        return Err(MarketError::UnsafeTimeouts);
    }
    Ok(())
}

fn verify_canonical_shakescape_lock_commitment(
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
                .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?
                .descriptor_hash
        }
        AssetId::BTC => build_shakescape_bitcoin_htlc(hello, side)
            .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?
            .commitment
            .into_bytes(),
        _ => return Err(MarketError::InvalidPair),
    };
    if computed != commitment {
        return Err(MarketError::InvalidShakescapeDirectSwap);
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
    // The Shakescape board has already admitted the exact direct offer, its take,
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
    OfferAcceptanceValidated,
    OfferReserved,
    TermsApproved {
        terms_id: ObjectHash,
    },
    RefundsValidated,
    FundingReady,
    FirstFundingObservationStarted {
        module: ModuleId,
        generation: u64,
    },
    FirstFundingConfirmed {
        evidence: ObjectHash,
    },
    FirstFundingConfirmedAtGeneration {
        evidence: ObjectHash,
        module: ModuleId,
        generation: u64,
    },
    FirstFundingInvalidated {
        evidence: ObjectHash,
    },
    SecondFundingReady,
    SecondFundingAuthorizationIssued {
        authorization: SecondFundingAuthorization,
    },
    SecondFundingConfirmed {
        evidence: ObjectHash,
    },
    FirstRedemptionConfirmed {
        evidence: ObjectHash,
    },
    SecretExtracted {
        hashlock: ObjectHash,
    },
    SecondRedemptionConfirmed {
        evidence: ObjectHash,
    },
    CompletionValidated,
    RefundEligibilityValidated,
    RefundBroadcast {
        evidence: ObjectHash,
    },
    RefundConfirmed {
        evidence: ObjectHash,
    },
    ChainRefundConfirmed {
        module: ModuleId,
        evidence: ObjectHash,
    },
    TerminalFailure {
        reason: String,
    },
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
        let irreversible = matches!(
            session.state,
            SwapState::FirstFundingPending
                | SwapState::FirstFunded
                | SwapState::SecondFundingPending
                | SwapState::BothFunded
                | SwapState::FirstRedeemed
                | SwapState::SecretObserved
                | SwapState::SecondRedeemed
                | SwapState::RefundEligible
                | SwapState::RefundBroadcast
        );
        if session.accepted_shakescape_terms.is_none() {
            let next = self.store.save_workflow(
                self.workflow_id,
                WorkflowKind::AtomicSwap,
                expected_revision,
                session,
                irreversible,
                self.updated_at_unix,
            )?;
            if next != session.revision {
                return Err(MarketError::Invariant);
            }
            return Ok(());
        }
        if self.workflow_id != shakescape_execution_workflow_id(session.id) {
            return Err(MarketError::Invariant);
        }
        let entity_id = second_funding_authorization_entity_id(session.id);
        let stored_authorization = self
            .store
            .load_entity::<PersistedSecondFundingAuthorization>(
                EntityKind::SwapFundingAuthorization,
                &entity_id,
            )?;
        if let Some(stored) = stored_authorization.as_ref() {
            validate_previous_second_funding_authorization(
                &stored.value,
                stored.revision,
                session.id,
                self.workflow_id,
                expected_revision,
            )?;
        }
        let mut authorization_saves = Vec::new();
        let mut authorization_deletes = Vec::new();
        match session.second_funding_authorization {
            Some(authorization) => {
                if stored_authorization
                    .as_ref()
                    .is_some_and(|stored| stored.revision != stored.value.issued_entity_revision)
                {
                    return Err(MarketError::InvalidTransition);
                }
                let expected_entity_revision = stored_authorization
                    .as_ref()
                    .map_or(0, |stored| stored.revision);
                let issued_entity_revision = expected_entity_revision
                    .checked_add(1)
                    .ok_or(MarketError::Invariant)?;
                authorization_saves.push(EntityBatchSave {
                    id: entity_id.clone(),
                    expected_revision: expected_entity_revision,
                    value: persisted_second_funding_authorization(
                        session,
                        authorization,
                        issued_entity_revision,
                    ),
                    updated_at_unix: self.updated_at_unix,
                });
            }
            None => {
                if let Some(stored) = stored_authorization {
                    let consumed = stored.revision != stored.value.issued_entity_revision;
                    if !consumed || session.second_funding.is_some() {
                        authorization_deletes.push(EntityBatchDelete {
                            id: entity_id,
                            expected_revision: stored.revision,
                        });
                    }
                }
            }
        }
        let next = if authorization_saves.is_empty() && authorization_deletes.is_empty() {
            self.store.save_workflow(
                self.workflow_id,
                WorkflowKind::AtomicSwap,
                expected_revision,
                session,
                irreversible,
                self.updated_at_unix,
            )?
        } else {
            self.store.save_workflow_with_entity_batch(
                self.workflow_id,
                WorkflowKind::AtomicSwap,
                expected_revision,
                session,
                irreversible,
                self.updated_at_unix,
                EntityKind::SwapFundingAuthorization,
                &authorization_saves,
                &authorization_deletes,
            )?
        };
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
    InvalidShakescapeDirectOfferPolicy,
    #[error("invalid or unexpected canonical direct HNS/BTC offer envelope")]
    InvalidShakescapeDirectOffer,
    #[error("direct HNS/BTC offer conflicts with retained signed terms")]
    ShakescapeDirectOfferConflict,
    #[error("persisted direct HNS/BTC offer board is corrupt or noncanonical")]
    CorruptShakescapeDirectOfferBoard,
    #[error("direct HNS/BTC offer board reached its bounded capacity")]
    ShakescapeDirectOfferCapacity,
    #[error("requested direct HNS/BTC offer is unknown")]
    UnknownShakescapeDirectOffer,
    #[error("invalid direct HNS/BTC swap policy")]
    InvalidShakescapeDirectSwapPolicy,
    #[error("invalid or unexpected canonical direct HNS/BTC swap message")]
    InvalidShakescapeDirectSwap,
    #[error("the referenced direct HNS/BTC swap is unknown")]
    UnknownShakescapeDirectSwap,
    #[error("direct HNS/BTC swap conflicts with accepted state")]
    ShakescapeDirectSwapConflict,
    #[error("direct HNS/BTC swap capacity reached")]
    ShakescapeDirectSwapCapacity,
    #[error("persisted direct HNS/BTC swap is corrupt or noncanonical")]
    CorruptShakescapeDirectSwap,
    #[error("persisted direct HNS/BTC swap failed canonical invariant: {0}")]
    CorruptShakescapeDirectSwapDetail(&'static str),
    #[error("invalid, unexpected, or resource-exhausting Shakescape peer message")]
    InvalidShakescapePeerMessage,
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
    /// Closed local persistence diagnostic retained for native recovery logs.
    /// `StoreError` descriptions contain no decrypted wallet values, keys, or
    /// caller-controlled record contents. Keeping the category here prevents
    /// an actionable schema/capacity/lock failure from being flattened into
    /// the same message as an unrelated signing-adapter failure.
    #[error("wallet store failed: {0}")]
    StoreFailure(String),
}

impl From<StoreError> for MarketError {
    fn from(error: StoreError) -> Self {
        if matches!(error, StoreError::StaleRevision { .. }) {
            Self::StaleRevision
        } else {
            Self::StoreFailure(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        AssetAmount, CrossChainMessage, MARKETPLACE_PROTOCOL_VERSION, MarketPair, NetworkBinding,
        SettlementDeadline, SignedObjectHeader, SwapSessionHello,
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

    fn seeded_market_store(wallet_id: WalletId, seed: u8) -> WalletStore {
        let mut store = WalletStore::create(":memory:", "direct market capacity test")
            .expect("create market test store");
        store
            .put_secret(
                wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[seed; 64],
                1,
            )
            .expect("persist deterministic recovery seed");
        store
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
            VerifiedEvidence::OfferAcceptanceValidated,
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
    fn offer_acceptance_state_uses_canonical_name() {
        assert_eq!(
            serde_json::to_string(&SwapState::OfferAcceptanceReceived).unwrap(),
            "\"offer_acceptance_received\""
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
            VerifiedEvidence::OfferAcceptanceValidated,
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
        assert_eq!(session.first_refund, Some(ObjectHash::new([13; 32])));
        assert!(session.all_funded_legs_settled());
    }

    #[test]
    fn both_funded_legs_must_settle_before_refund_is_terminal() {
        let mut session = SwapSession::new(
            SessionId::new([0x21; 32]),
            ModuleId::Handshake,
            ModuleId::Bitcoin,
            quote(),
            ObjectHash::new([0x22; 32]),
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
            VerifiedEvidence::OfferAcceptanceValidated,
            VerifiedEvidence::OfferReserved,
            VerifiedEvidence::TermsApproved {
                terms_id: ObjectHash::new([3; 32]),
            },
            VerifiedEvidence::RefundsValidated,
            VerifiedEvidence::FundingReady,
            VerifiedEvidence::FirstFundingConfirmed {
                evidence: ObjectHash::new([0x23; 32]),
            },
            VerifiedEvidence::SecondFundingReady,
            VerifiedEvidence::SecondFundingConfirmed {
                evidence: ObjectHash::new([0x24; 32]),
            },
        ] {
            session
                .apply(evidence, 20, &mut journal)
                .expect("fund both legs");
        }

        session
            .apply(
                VerifiedEvidence::ChainRefundConfirmed {
                    module: ModuleId::Handshake,
                    evidence: ObjectHash::new([0x25; 32]),
                },
                30,
                &mut journal,
            )
            .expect("first leg refund");
        assert_eq!(session.state, SwapState::RefundEligible);
        assert!(!session.all_funded_legs_settled());
        assert!(session.can_refund_module(ModuleId::Bitcoin));

        session
            .apply(
                VerifiedEvidence::ChainRefundConfirmed {
                    module: ModuleId::Bitcoin,
                    evidence: ObjectHash::new([0x26; 32]),
                },
                31,
                &mut journal,
            )
            .expect("second leg refund");
        assert_eq!(session.state, SwapState::Refunded);
        assert!(session.all_funded_legs_settled());
    }

    #[test]
    fn verified_first_funding_recovers_only_a_prefunding_timeout_failure() {
        let mut timed_out = SwapSession::new(
            SessionId::new([0x41; 32]),
            ModuleId::Bitcoin,
            ModuleId::Handshake,
            quote(),
            ObjectHash::new([0x42; 32]),
            TimeoutPlan {
                first_chain_refund_at: 500,
                second_chain_refund_at: 300,
                minimum_safety_margin: 100,
            },
            10,
        )
        .expect("session");
        timed_out.state = SwapState::FirstFundingPending;
        let mut journal = MemoryJournal::default();
        timed_out
            .apply(
                VerifiedEvidence::TerminalFailure {
                    reason: PREFUNDING_DEADLINE_FAILURE.to_owned(),
                },
                20,
                &mut journal,
            )
            .expect("record timeout");
        timed_out
            .apply(
                VerifiedEvidence::FirstFundingConfirmed {
                    evidence: ObjectHash::new([0x43; 32]),
                },
                21,
                &mut journal,
            )
            .expect("verified lock supersedes timeout");
        assert_eq!(timed_out.state, SwapState::FirstFunded);
        assert_eq!(timed_out.first_funding, Some(ObjectHash::new([0x43; 32])));
        assert_eq!(timed_out.failure_reason, None);

        let mut unrelated_failure = timed_out.clone();
        unrelated_failure.state = SwapState::Failed;
        unrelated_failure.first_funding = None;
        unrelated_failure.failure_reason = Some("corrupt settlement terms".to_owned());
        assert_eq!(
            unrelated_failure.apply(
                VerifiedEvidence::FirstFundingConfirmed {
                    evidence: ObjectHash::new([0x44; 32]),
                },
                22,
                &mut journal,
            ),
            Err(MarketError::InvalidTransition)
        );
    }

    #[test]
    fn unsettled_first_funding_can_be_refreshed_and_revoked() {
        let mut session = SwapSession::new(
            SessionId::new([0x51; 32]),
            ModuleId::Handshake,
            ModuleId::Bitcoin,
            quote(),
            ObjectHash::new([0x52; 32]),
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
            VerifiedEvidence::OfferAcceptanceValidated,
            VerifiedEvidence::OfferReserved,
            VerifiedEvidence::TermsApproved {
                terms_id: ObjectHash::new([3; 32]),
            },
            VerifiedEvidence::RefundsValidated,
            VerifiedEvidence::FundingReady,
            VerifiedEvidence::FirstFundingConfirmed {
                evidence: ObjectHash::new([0x53; 32]),
            },
        ] {
            session
                .apply(evidence, 20, &mut journal)
                .expect("funding transition");
        }
        let mut not_yet_authorized = session.clone();
        not_yet_authorized
            .apply(
                VerifiedEvidence::FirstFundingInvalidated {
                    evidence: ObjectHash::new([0x53; 32]),
                },
                21,
                &mut journal,
            )
            .expect("uncommitted second leg permits a full rollback");
        assert_eq!(not_yet_authorized.state, SwapState::FirstFundingPending);
        assert_eq!(not_yet_authorized.first_funding, None);

        session
            .apply(VerifiedEvidence::SecondFundingReady, 20, &mut journal)
            .expect("authorize second funding");
        assert_eq!(session.state, SwapState::SecondFundingPending);

        session
            .apply(
                VerifiedEvidence::FirstFundingConfirmed {
                    evidence: ObjectHash::new([0x54; 32]),
                },
                21,
                &mut journal,
            )
            .expect("replacement lock is independently verified");
        assert_eq!(session.first_funding, Some(ObjectHash::new([0x54; 32])));
        assert_eq!(session.last_verified_at_unix, 21);
        assert_eq!(
            session.apply(
                VerifiedEvidence::FirstFundingInvalidated {
                    evidence: ObjectHash::new([0x53; 32]),
                },
                22,
                &mut journal,
            ),
            Err(MarketError::InvalidTransition),
            "stale evidence cannot revoke a replacement lock"
        );

        session
            .apply(
                VerifiedEvidence::FirstFundingInvalidated {
                    evidence: ObjectHash::new([0x54; 32]),
                },
                23,
                &mut journal,
            )
            .expect("current-chain absence revokes second-funding readiness");
        assert_eq!(session.state, SwapState::SecondFundingPending);
        assert_eq!(session.first_funding, Some(ObjectHash::new([0x54; 32])));
        assert!(session.first_funding_revoked);
        assert_eq!(session.second_funding, None);
        session
            .apply(
                VerifiedEvidence::FirstFundingConfirmed {
                    evidence: ObjectHash::new([0x54; 32]),
                },
                24,
                &mut journal,
            )
            .expect("fresh proof restores authority without losing recovery state");
        assert!(!session.first_funding_revoked);
        assert_eq!(session.state, SwapState::SecondFundingPending);
    }

    #[test]
    fn observation_generations_revoke_stale_value_authority_and_recover_both_funded_swaps() {
        let mut session = SwapSession::new(
            SessionId::new([0x61; 32]),
            ModuleId::Bitcoin,
            ModuleId::Handshake,
            quote(),
            ObjectHash::new([0x62; 32]),
            TimeoutPlan {
                first_chain_refund_at: 10_000,
                second_chain_refund_at: 5_000,
                minimum_safety_margin: 3_600,
            },
            10,
        )
        .expect("session");
        let mut journal = MemoryJournal::default();
        for evidence in [
            VerifiedEvidence::OfferAcceptanceValidated,
            VerifiedEvidence::OfferReserved,
            VerifiedEvidence::TermsApproved {
                terms_id: ObjectHash::new([3; 32]),
            },
            VerifiedEvidence::RefundsValidated,
            VerifiedEvidence::FundingReady,
            VerifiedEvidence::FirstFundingObservationStarted {
                module: ModuleId::Bitcoin,
                generation: 1,
            },
            VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                evidence: ObjectHash::new([0x63; 32]),
                module: ModuleId::Bitcoin,
                generation: 1,
            },
            VerifiedEvidence::SecondFundingReady,
        ] {
            session
                .apply(evidence, 20, &mut journal)
                .expect("generation-bound first funding");
        }
        let authorization = SecondFundingAuthorization {
            id: ObjectHash::new([0x64; 32]),
            module: ModuleId::Handshake,
            first_funding: ObjectHash::new([0x63; 32]),
            first_funding_observation_generation: 1,
            expires_at_unix: 100,
        };
        session
            .apply(
                VerifiedEvidence::SecondFundingAuthorizationIssued { authorization },
                21,
                &mut journal,
            )
            .expect("second funding lease");
        session
            .apply(
                VerifiedEvidence::FirstFundingObservationStarted {
                    module: ModuleId::Bitcoin,
                    generation: 2,
                },
                22,
                &mut journal,
            )
            .expect("new observation revokes old lease");
        assert!(!session.first_funding_is_current());
        assert_eq!(session.second_funding_authorization, None);
        assert_eq!(
            session.apply(
                VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                    evidence: ObjectHash::new([0x63; 32]),
                    module: ModuleId::Bitcoin,
                    generation: 1,
                },
                23,
                &mut journal,
            ),
            Err(MarketError::InvalidTransition),
            "a proof from an older read cannot restore authority"
        );
        session
            .apply(
                VerifiedEvidence::FirstFundingInvalidated {
                    evidence: ObjectHash::new([0x63; 32]),
                },
                24,
                &mut journal,
            )
            .expect("current authoritative absence revokes first funding");
        assert!(session.first_funding_revoked);

        session
            .apply(
                VerifiedEvidence::SecondFundingConfirmed {
                    evidence: ObjectHash::new([0x65; 32]),
                },
                25,
                &mut journal,
            )
            .expect("an already-created second lock remains recoverable");
        assert_eq!(session.state, SwapState::BothFunded);
        assert!(!session.all_funded_legs_settled());
        assert!(!session.can_refund_module(ModuleId::Bitcoin));

        session
            .apply(
                VerifiedEvidence::FirstFundingObservationStarted {
                    module: ModuleId::Bitcoin,
                    generation: 3,
                },
                26,
                &mut journal,
            )
            .expect("recovery read");
        session
            .apply(
                VerifiedEvidence::FirstFundingConfirmedAtGeneration {
                    evidence: ObjectHash::new([0x63; 32]),
                    module: ModuleId::Bitcoin,
                    generation: 3,
                },
                27,
                &mut journal,
            )
            .expect("reappearing first lock restores refund authority");
        assert!(session.first_funding_is_current());
        assert!(session.can_refund_module(ModuleId::Bitcoin));

        session
            .apply(
                VerifiedEvidence::FirstFundingInvalidated {
                    evidence: ObjectHash::new([0x63; 32]),
                },
                28,
                &mut journal,
            )
            .expect("later absence revokes new spending authority");
        session
            .apply(
                VerifiedEvidence::ChainRefundConfirmed {
                    module: ModuleId::Bitcoin,
                    evidence: ObjectHash::new([0x66; 32]),
                },
                29,
                &mut journal,
            )
            .expect("verified first-chain refund is still recorded after revocation");
        assert_eq!(session.first_refund, Some(ObjectHash::new([0x66; 32])));
        assert!(!session.all_funded_legs_settled());
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
                value: 10_000,
            },
            offered_minimum_confirmations: 2,
            received_lock_commitment: [8; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 5_000,
            },
            received_minimum_confirmations: 1,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        }
    }

    #[test]
    fn accepted_shakescape_terms_open_a_resumable_execution_in_signed_chain_order() {
        let hns_first = swap_session_from_accepted_hello(&accepted_terms(ChainId::HANDSHAKE), 100)
            .expect("HNS first terms");
        assert_eq!(hns_first.state, SwapState::TermsFrozen);
        assert_eq!(hns_first.revision, 1);
        assert_eq!(hns_first.first_module, ModuleId::Handshake);
        assert_eq!(hns_first.second_module, ModuleId::Bitcoin);
        assert_eq!(hns_first.timeouts.first_chain_refund_at, 10_000);
        assert_eq!(hns_first.timeouts.second_chain_refund_at, 5_000);

        let mut btc_first_terms = accepted_terms(ChainId::BITCOIN);
        btc_first_terms.offered_refund_deadline.value = 5_000;
        btc_first_terms.received_refund_deadline.value = 10_000;
        let btc_first =
            swap_session_from_accepted_hello(&btc_first_terms, 100).expect("Bitcoin first terms");
        assert_eq!(btc_first.first_module, ModuleId::Bitcoin);
        assert_eq!(btc_first.second_module, ModuleId::Handshake);
        assert_eq!(btc_first.timeouts.first_chain_refund_at, 10_000);
        assert_eq!(btc_first.timeouts.second_chain_refund_at, 5_000);
        assert_eq!(
            shakescape_execution_workflow_id(hns_first.id),
            shakescape_execution_workflow_id(btc_first.id),
            "workflow identity is session-bound, not chain-order-bound"
        );
    }

    #[test]
    fn effective_refund_safety_accounts_for_hns_time_lock_rounding() {
        let mut terms = accepted_terms(ChainId::BITCOIN);
        terms.offered_asset = AssetId::BTC;
        terms.offered_amount = AssetAmount::new(25);
        terms.offered_minimum_confirmations = SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS;
        terms.received_asset = AssetId::HNS;
        terms.received_amount = AssetAmount::new(1_000);
        terms.received_minimum_confirmations = SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS;
        terms.received_refund_deadline.value = 6_401;
        terms.offered_refund_deadline.value =
            terms.received_refund_deadline.value + MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS;

        assert_eq!(
            validate_shakescape_effective_refund_safety(&terms),
            Err(MarketError::UnsafeTimeouts),
            "a nominal one-hour gap is shorter after the HNS deadline rounds up"
        );

        let effective_hns_refund =
            shakescape_effective_refund_at(AssetId::HNS, terms.received_refund_deadline)
                .expect("effective HNS deadline");
        terms.offered_refund_deadline.value =
            effective_hns_refund + MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS;
        validate_shakescape_effective_refund_safety(&terms)
            .expect("effective one-hour margin is safe");
    }

    #[test]
    fn effective_refund_safety_preserves_a_second_chain_redemption_window() {
        let mut terms = accepted_terms(ChainId::HANDSHAKE);
        terms.header.expires_at = 500;
        terms.received_refund_deadline.value =
            terms.header.expires_at + MIN_SECOND_CHAIN_REDEMPTION_WINDOW_SECONDS - 1;
        terms.offered_refund_deadline.value =
            terms.received_refund_deadline.value + MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS;

        assert_eq!(
            validate_shakescape_effective_refund_safety(&terms),
            Err(MarketError::UnsafeTimeouts),
            "refund ordering alone must not admit an immediately refundable second lock"
        );

        terms.received_refund_deadline.value =
            terms.header.expires_at + MIN_SECOND_CHAIN_REDEMPTION_WINDOW_SECONDS;
        terms.offered_refund_deadline.value =
            terms.received_refund_deadline.value + MIN_EFFECTIVE_REFUND_SAFETY_MARGIN_SECONDS;
        validate_shakescape_effective_refund_safety(&terms)
            .expect("the minimum post-funding redemption window is accepted");
    }

    #[test]
    fn seventeenth_countersigned_session_is_rejected_before_hello_persistence() {
        const START: u64 = 1_700_000_000;
        const FUNDING_WINDOW: u64 = 24 * 60 * 60;
        const OFFER_LIFETIME: u64 = 2 * FUNDING_WINDOW;

        let network = accepted_terms(ChainId::HANDSHAKE).header.network;
        let policy = ShakescapeDirectSwapPolicy::new(
            ShakescapeDirectOfferBoardPolicy::new(network).expect("board policy"),
        )
        .expect("swap policy");
        let offer_setter_id = WalletId::new([0x31; 16]);
        let mut offer_setter = seeded_market_store(offer_setter_id, 0x41);
        let mut sessions = Vec::new();

        // Admit all negotiations before any hello becomes active. This is the
        // race which previously let every pre-hello row pass the active cap
        // and then persist a poisoned seventeenth countersigned obligation.
        for index in 0..=MAX_CONCURRENT_SWAP_SESSIONS {
            let marker = u8::try_from(index + 1).expect("bounded fixture marker");
            let responder_id = WalletId::new([0x60_u8 + marker; 16]);
            let mut responder = seeded_market_store(responder_id, 0x80_u8 + marker);
            let offer = create_shakescape_hns_for_btc_offer(
                &mut offer_setter,
                &policy.board_policy(),
                ShakescapeHnsForBtcOfferRequest {
                    wallet_id: offer_setter_id,
                    hns_amount_dollarydoos: 2_000_000,
                    btc_amount_sats: 9_000,
                    hns_fee_reserve_dollarydoos: 10_000,
                    created_at_unix: START,
                    expires_at_unix: START + OFFER_LIFETIME,
                    nonce: [marker; 32],
                },
            )
            .expect("create offer");
            let signed_offer = load_shakescape_direct_offer(
                &offer_setter,
                &policy.board_policy(),
                offer.offer.offer_id.into_bytes(),
            )
            .expect("load offer")
            .expect("offer exists")
            .offer;
            let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
                .encode_envelope(1)
                .expect("offer envelope");
            admit_shakescape_direct_offer(
                &mut responder,
                &policy.board_policy(),
                &offer_envelope,
                START,
            )
            .expect("responder admits offer");
            let acceptance = create_shakescape_btc_for_hns_offer_acceptance(
                &mut responder,
                &policy,
                ShakescapeBtcForHnsOfferAcceptanceRequest {
                    wallet_id: responder_id,
                    offer_id: offer.offer.offer_id,
                    bitcoin_fee_reserve_sats: 1_000,
                    created_at_unix: START + 10,
                    expires_at_unix: START + OFFER_LIFETIME,
                    nonce: [marker.wrapping_add(32); 32],
                },
            )
            .expect("create acceptance");
            admit_shakescape_direct_offer_acceptance(
                &mut offer_setter,
                &policy,
                &acceptance.envelope,
                START + 10,
            )
            .expect("offer setter admits acceptance");
            let proposal = create_shakescape_btc_for_hns_maker_proposal(
                &mut responder,
                &policy,
                ShakescapeBtcForHnsMakerProposalRequest {
                    wallet_id: responder_id,
                    session_id: offer.offer.session_id,
                    now_unix: START + 20,
                    funding_window_seconds: FUNDING_WINDOW,
                    second_refund_after_seconds: 2 * FUNDING_WINDOW,
                    refund_safety_margin_seconds: FUNDING_WINDOW,
                    bitcoin_minimum_confirmations: SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS,
                    hns_minimum_confirmations: SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS,
                },
            )
            .expect("create maker proposal");
            admit_shakescape_direct_swap_proposal(
                &mut offer_setter,
                &policy,
                &proposal.envelope,
                START + 20,
            )
            .expect("offer setter admits proposal");
            sessions.push(offer.offer.session_id);
        }

        for session_id in sessions.iter().take(MAX_CONCURRENT_SWAP_SESSIONS) {
            accept_shakescape_hns_for_btc_maker_proposal(
                &mut offer_setter,
                &policy,
                offer_setter_id,
                *session_id,
                START + 30,
            )
            .expect("first sixteen sessions become active");
        }

        let rejected_session = *sessions.last().expect("seventeenth session");
        assert_eq!(
            accept_shakescape_hns_for_btc_maker_proposal(
                &mut offer_setter,
                &policy,
                offer_setter_id,
                rejected_session,
                START + 30,
            )
            .expect_err("seventeenth active obligation must fail"),
            MarketError::ShakescapeDirectSwapCapacity
        );
        let rejected = load_shakescape_direct_swap(&offer_setter, &policy, rejected_session)
            .expect("load rejected negotiation")
            .expect("pre-hello row is retained");
        assert!(rejected.proposal.is_some());
        assert!(rejected.hello.is_none());
        assert!(
            load_shakescape_execution(&offer_setter, &policy, rejected_session)
                .expect("load rejected execution")
                .is_none()
        );

        let prune = prune_expired_shakescape_direct_market_state(
            &mut offer_setter,
            &policy,
            offer_setter_id,
            START + OFFER_LIFETIME + 1,
        )
        .expect("expired pre-hello negotiation is prunable");
        assert_eq!(prune.expired_unowned_sessions_removed, 1);
        assert!(
            load_shakescape_direct_swap(&offer_setter, &policy, rejected_session)
                .expect("load pruned negotiation")
                .is_none()
        );
        assert_eq!(
            load_shakescape_direct_swaps(&offer_setter, &policy)
                .expect("retained active sessions")
                .len(),
            MAX_CONCURRENT_SWAP_SESSIONS
        );
    }

    #[test]
    fn shakedex_terms_require_exact_product_confirmations_and_a_bounded_horizon() {
        let mut terms = accepted_terms(ChainId::HANDSHAKE);
        validate_shakescape_effective_refund_safety(&terms).expect("baseline terms");

        terms.offered_minimum_confirmations = SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS + 1;
        assert_eq!(
            validate_shakescape_effective_refund_safety(&terms),
            Err(MarketError::UnsafeTimeouts)
        );
        terms.offered_minimum_confirmations = SHAKESCAPE_HNS_MINIMUM_CONFIRMATIONS;
        terms.received_minimum_confirmations = SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS + 1;
        assert_eq!(
            validate_shakescape_effective_refund_safety(&terms),
            Err(MarketError::UnsafeTimeouts)
        );

        terms.received_minimum_confirmations = SHAKESCAPE_BITCOIN_MINIMUM_CONFIRMATIONS;
        terms.offered_refund_deadline.value =
            terms.header.created_at + SHAKESCAPE_MAX_SETTLEMENT_HORIZON_SECONDS + 1;
        assert_eq!(
            validate_shakescape_effective_refund_safety(&terms),
            Err(MarketError::UnsafeTimeouts),
            "an attacker cannot force years of retained settlement state"
        );
    }

    #[test]
    fn expired_authenticated_terms_can_reconstruct_a_missing_execution_baseline() {
        let terms = accepted_terms(ChainId::HANDSHAKE);
        let accepted_at = 100;
        let recovered_at = terms.header.expires_at + 1;

        // `open_shakescape_execution` first authenticates the persisted hello
        // at its original admission and then reconstructs the missing
        // derivative using that same instant. Its durable update timestamp is
        // the recovery time so the workflow-store invariant remains exact.
        let mut recovered = swap_session_from_accepted_hello(&terms, accepted_at)
            .expect("originally admitted terms remain reconstructible");
        recovered.last_verified_at_unix = recovered_at;

        assert_eq!(recovered.state, SwapState::TermsFrozen);
        assert_eq!(recovered.revision, 1);
        assert_eq!(recovered.last_verified_at_unix, recovered_at);
        assert!(swap_session_from_accepted_hello(&terms, recovered_at).is_err());
    }
}
