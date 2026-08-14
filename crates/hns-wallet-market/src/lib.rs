#![doc = "Chain-neutral, evidence-driven market and atomic-swap workflow state."]
#![forbid(unsafe_code)]

mod price_board;

use std::collections::BTreeMap;

use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{
    Amount, BaseUnits, ModuleId, ObjectHash, SessionId, WalletAsset, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use price_board::{
    DenuoPriceRoundAdmission, DenuoPriceRoundPolicy, DenuoPriceRoundSnapshot,
    MAX_DENUO_PRICE_ROUND_HISTORY, admit_denuo_price_round, bootstrap_denuo_price_round_cache,
    load_denuo_price_round_cache,
};

pub const MAX_ACTIVE_RESERVATIONS: usize = 64;
pub const MAX_CONCURRENT_SWAP_SESSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedQuote {
    pub price_round_hash: ObjectHash,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketIntentState {
    pub intent_id: ObjectHash,
    pub sequence: u64,
    pub offered_asset: WalletAsset,
    pub accepted_asset: WalletAsset,
    pub total: BaseUnits,
    pub reserved: BaseUnits,
    pub completed: BaseUnits,
    pub minimum_partial_fill: BaseUnits,
    pub partial_fills: bool,
    pub expires_at_unix: u64,
    pub reservations: BTreeMap<SessionId, Reservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketIntentParameters {
    pub intent_id: ObjectHash,
    pub sequence: u64,
    pub offered_asset: WalletAsset,
    pub accepted_asset: WalletAsset,
    pub total: BaseUnits,
    pub minimum_partial_fill: BaseUnits,
    pub partial_fills: bool,
    pub expires_at_unix: u64,
}

impl MarketIntentState {
    pub fn new(parameters: MarketIntentParameters, now_unix: u64) -> Result<Self, MarketError> {
        if parameters.sequence == 0
            || parameters.offered_asset == parameters.accepted_asset
            || parameters.total.is_zero()
            || parameters.minimum_partial_fill.is_zero()
            || parameters.minimum_partial_fill > parameters.total
            || parameters.expires_at_unix <= now_unix
        {
            return Err(MarketError::InvalidIntent);
        }
        Ok(Self {
            intent_id: parameters.intent_id,
            sequence: parameters.sequence,
            offered_asset: parameters.offered_asset,
            accepted_asset: parameters.accepted_asset,
            total: parameters.total,
            reserved: BaseUnits::ZERO,
            completed: BaseUnits::ZERO,
            minimum_partial_fill: parameters.minimum_partial_fill,
            partial_fills: parameters.partial_fills,
            expires_at_unix: parameters.expires_at_unix,
            reservations: BTreeMap::new(),
        })
    }

    pub fn available(&self) -> Result<BaseUnits, MarketError> {
        self.total
            .checked_sub(self.completed)
            .and_then(|remaining| remaining.checked_sub(self.reserved))
            .map_err(|_| MarketError::Invariant)
    }

    pub fn reserve(
        &mut self,
        session_id: SessionId,
        quote: VerifiedQuote,
        fill_grant_expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<FillGrantState, MarketError> {
        quote.validate(now_unix)?;
        self.expire_reservations(now_unix)?;
        if now_unix >= self.expires_at_unix
            || fill_grant_expires_at_unix <= now_unix
            || fill_grant_expires_at_unix > self.expires_at_unix
            || self.reservations.contains_key(&session_id)
            || self.reservations.len() >= MAX_ACTIVE_RESERVATIONS
            || quote.offered.asset != self.offered_asset
            || quote.received.asset != self.accepted_asset
            || quote.offered.base_units < self.minimum_partial_fill
        {
            return Err(MarketError::ReservationRejected);
        }
        let available = self.available()?;
        if quote.offered.base_units > available
            || (!self.partial_fills && quote.offered.base_units != available)
        {
            return Err(MarketError::ReservationRejected);
        }
        self.reserved = self
            .reserved
            .checked_add(quote.offered.base_units)
            .map_err(|_| MarketError::Invariant)?;
        let reservation_sequence = self
            .sequence
            .checked_add(
                u64::try_from(self.reservations.len()).map_err(|_| MarketError::Invariant)? + 1,
            )
            .ok_or(MarketError::Invariant)?;
        self.reservations.insert(
            session_id,
            Reservation {
                offered: quote.offered.base_units,
                received: quote.received.base_units,
                price_round_hash: quote.price_round_hash,
                expires_at_unix: fill_grant_expires_at_unix,
                reservation_sequence,
            },
        );
        Ok(FillGrantState {
            intent_id: self.intent_id,
            intent_sequence: self.sequence,
            session_id,
            offered: quote.offered,
            received: quote.received,
            price_round_hash: quote.price_round_hash,
            expires_at_unix: fill_grant_expires_at_unix,
            reservation_sequence,
        })
    }

    pub fn complete_reservation(&mut self, session_id: SessionId) -> Result<(), MarketError> {
        let reservation = self
            .reservations
            .remove(&session_id)
            .ok_or(MarketError::UnknownReservation)?;
        self.reserved = self
            .reserved
            .checked_sub(reservation.offered)
            .map_err(|_| MarketError::Invariant)?;
        self.completed = self
            .completed
            .checked_add(reservation.offered)
            .map_err(|_| MarketError::Invariant)?;
        if self.completed > self.total {
            return Err(MarketError::Invariant);
        }
        Ok(())
    }

    pub fn release_reservation(&mut self, session_id: SessionId) -> Result<(), MarketError> {
        let reservation = self
            .reservations
            .remove(&session_id)
            .ok_or(MarketError::UnknownReservation)?;
        self.reserved = self
            .reserved
            .checked_sub(reservation.offered)
            .map_err(|_| MarketError::Invariant)?;
        Ok(())
    }

    pub fn expire_reservations(&mut self, now_unix: u64) -> Result<usize, MarketError> {
        let expired: Vec<_> = self
            .reservations
            .iter()
            .filter_map(|(session, reservation)| {
                (reservation.expires_at_unix <= now_unix).then_some(*session)
            })
            .collect();
        for session in &expired {
            self.release_reservation(*session)?;
        }
        Ok(expired.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Reservation {
    pub offered: BaseUnits,
    pub received: BaseUnits,
    pub price_round_hash: ObjectHash,
    pub expires_at_unix: u64,
    pub reservation_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FillGrantState {
    pub intent_id: ObjectHash,
    pub intent_sequence: u64,
    pub session_id: SessionId,
    pub offered: Amount,
    pub received: Amount,
    pub price_round_hash: ObjectHash,
    pub expires_at_unix: u64,
    pub reservation_sequence: u64,
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
    IntentPublished,
    MatchRequested,
    FillReserved,
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
    pub price_round_hash: ObjectHash,
    pub hashlock: ObjectHash,
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
            || first_module.asset() != quote.offered.asset
            || second_module.asset() != quote.received.asset
        {
            return Err(MarketError::InvalidPair);
        }
        Ok(Self {
            id,
            revision: 0,
            state: SwapState::IntentPublished,
            first_module,
            second_module,
            offered: quote.offered,
            received: quote.received,
            price_round_hash: quote.price_round_hash,
            hashlock,
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
            (SwapState::IntentPublished, VerifiedEvidence::MatchRequestValidated) => {
                SwapState::MatchRequested
            }
            (SwapState::MatchRequested, VerifiedEvidence::FillGrantValidated) => {
                SwapState::FillReserved
            }
            (SwapState::FillReserved, VerifiedEvidence::TermsApproved { price_round_hash })
                if price_round_hash == self.price_round_hash =>
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedEvidence {
    MatchRequestValidated,
    FillGrantValidated,
    TermsApproved { price_round_hash: ObjectHash },
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
    #[error("invalid market intent")]
    InvalidIntent,
    #[error("invalid or stale verified quote")]
    InvalidQuote,
    #[error("invalid Denuo price-round admission policy")]
    InvalidDenuoPriceRoundPolicy,
    #[error("invalid or unexpected canonical Denuo V2 price-round envelope")]
    InvalidDenuoPriceRound,
    #[error("Denuo price-round cache was created under another admission policy")]
    DenuoPriceRoundPolicyMismatch,
    #[error("Denuo price-round replay, rollback, or equivocation was rejected")]
    DenuoPriceRoundReplay,
    #[error("persisted Denuo price-round cache is corrupt or noncanonical")]
    CorruptDenuoPriceRoundCache,
    #[error("unsupported or inconsistent asset pair")]
    InvalidPair,
    #[error("quantity reservation rejected")]
    ReservationRejected,
    #[error("reservation is unknown")]
    UnknownReservation,
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
    use super::*;

    fn quote() -> VerifiedQuote {
        VerifiedQuote {
            price_round_hash: ObjectHash::new([3; 32]),
            offered: Amount::new(WalletAsset::Hns, 1_000),
            received: Amount::new(WalletAsset::Btc, 25),
            valid_until_unix: 1_000,
        }
    }

    #[test]
    fn reservations_cannot_double_spend_and_expiry_releases_quantity() {
        let mut intent = MarketIntentState::new(
            MarketIntentParameters {
                intent_id: ObjectHash::new([1; 32]),
                sequence: 1,
                offered_asset: WalletAsset::Hns,
                accepted_asset: WalletAsset::Btc,
                total: BaseUnits::new(2_000),
                minimum_partial_fill: BaseUnits::new(100),
                partial_fills: true,
                expires_at_unix: 900,
            },
            1,
        )
        .expect("intent");
        let session = SessionId::new([2; 32]);
        intent.reserve(session, quote(), 20, 10).expect("reserve");
        assert!(intent.reserve(session, quote(), 21, 11).is_err());
        assert_eq!(intent.reserved, BaseUnits::new(1_000));
        assert_eq!(intent.expire_reservations(20).expect("expire"), 1);
        assert_eq!(intent.reserved, BaseUnits::ZERO);
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
            VerifiedEvidence::MatchRequestValidated,
            VerifiedEvidence::FillGrantValidated,
            VerifiedEvidence::TermsApproved {
                price_round_hash: ObjectHash::new([3; 32]),
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
            VerifiedEvidence::MatchRequestValidated,
            VerifiedEvidence::FillGrantValidated,
            VerifiedEvidence::TermsApproved {
                price_round_hash: ObjectHash::new([3; 32]),
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
}
