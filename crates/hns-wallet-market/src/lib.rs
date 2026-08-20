#![doc = "Chain-neutral, evidence-driven market and atomic-swap workflow state."]
#![forbid(unsafe_code)]

mod intent_board;
mod price_board;
mod session_board;
mod settlement_key;

use std::collections::BTreeMap;

use hns_marketplace_protocol::{AssetId, ChainId, DeadlineKind, SwapAssetSide, SwapSessionHello};
use hns_wallet_bitcoin_kyoto::{VerifiedBitcoinLock, build_denuo_bitcoin_htlc};
use hns_wallet_chain_api::VerifiedLock;
use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{
    Amount, BaseUnits, ModuleId, ObjectHash, SessionId, WalletAsset, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use intent_board::{
    DenuoIntentBoardPolicy, DenuoIntentPeerEvent, DenuoIntentPeerSession, DenuoIntentPeerStep,
    DenuoMarketIntentAdmission, DenuoMarketIntentCancellationAdmission, DenuoMarketIntentRecord,
    DenuoMarketIntentSnapshot, MAX_DENUO_MARKET_INTENTS, MAX_PENDING_DENUO_INTENT_REQUESTS,
    admit_denuo_market_intent, admit_denuo_market_intent_cancellation,
    denuo_market_intent_inventory, load_denuo_market_intent, load_denuo_market_intents,
    prune_denuo_market_intents,
};
pub use price_board::{
    DenuoPriceRoundAdmission, DenuoPriceRoundPolicy, DenuoPriceRoundSnapshot,
    DenuoVerifiedPriceRound, MAX_DENUO_PRICE_ROUND_HISTORY, admit_denuo_price_round,
    bootstrap_denuo_price_round_cache, load_denuo_price_round_cache,
    load_denuo_verified_price_round,
};
pub use session_board::{
    DenuoSwapHandshakeAdmission, DenuoSwapHandshakePolicy, DenuoSwapHandshakeRecord,
    DenuoSwapHandshakeSnapshot, DenuoSwapHandshakeStage, DenuoSwapPeerStatus,
    MAX_DENUO_SWAP_HANDSHAKES, admit_denuo_fill_grant, admit_denuo_match_request,
    admit_denuo_swap_hello, admit_denuo_swap_proposal, load_denuo_swap_handshake,
    load_denuo_swap_handshakes, validate_denuo_swap_peer_status,
};
pub use settlement_key::{
    CrossChainSwapKey, CrossChainSwapKeyAllocation, CrossChainSwapKeyError,
    CrossChainSwapKeyRequest, SwapParticipant, allocate_cross_chain_swap_key,
    derive_cross_chain_swap_key_from_store, load_cross_chain_swap_key_allocation,
};

pub const MAX_ACTIVE_RESERVATIONS: usize = 64;
pub const MAX_CONCURRENT_SWAP_SESSIONS: usize = 16;

const DENUO_EXECUTION_WORKFLOW_DOMAIN: &[u8] = b"hns-wallet-rs/denuo-execution-workflow/v1";

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
            state: SwapState::IntentPublished,
            first_module,
            second_module,
            offered: quote.offered,
            received: quote.received,
            price_round_hash: quote.price_round_hash,
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
    policy: &DenuoSwapHandshakePolicy,
    session_id: SessionId,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let record = load_denuo_swap_handshake(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    let expected_accepted_at = record
        .hello_accepted_at_unix
        .ok_or(MarketError::CorruptDenuoSwapHandshake)?;
    // Re-authenticate the retained record at its original admission moment.
    // This permits recovery after a funding deadline, but does not let this
    // constructor authorize new funding after that deadline.
    hello
        .verify_agreement(policy.network())
        .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    verify_canonical_denuo_lock_commitments(hello)?;
    if now_unix < expected_accepted_at {
        return Err(MarketError::InvalidEvidence);
    }
    let encoded_terms = hello
        .encode()
        .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    let workflow_id = denuo_execution_workflow_id(session_id);
    if let Some(existing) = store.load_workflow::<SwapSession>(workflow_id)? {
        if existing.kind != WorkflowKind::AtomicSwap
            || existing.state.id != session_id
            || existing.state.accepted_denuo_terms.as_deref() != Some(encoded_terms.as_slice())
        {
            return Err(MarketError::DenuoSwapHandshakeConflict);
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

/// Advance a durable Denuo execution only with locally verified funding
/// evidence. The peer's Denuo funding status is intentionally not accepted as
/// an argument here: it can inform UI/transport state, but cannot cause this
/// state transition.
pub fn apply_locally_verified_denuo_funding(
    store: &mut WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    session_id: SessionId,
    funding: LocallyVerifiedSwapFunding,
    now_unix: u64,
) -> Result<SwapSession, MarketError> {
    let workflow_id = denuo_execution_workflow_id(session_id);
    let stored = store
        .load_workflow::<SwapSession>(workflow_id)?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    if stored.kind != WorkflowKind::AtomicSwap || stored.state.id != session_id {
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }
    let terms = stored
        .state
        .accepted_denuo_terms
        .as_deref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    let hello =
        SwapSessionHello::decode(terms).map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    if hello.encode().ok().as_deref() != Some(terms)
        || SessionId::new(hello.swap_session_id) != session_id
        || hello.verify_agreement(policy.network()).is_err()
    {
        return Err(MarketError::CorruptDenuoSwapHandshake);
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
                .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?;
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
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)
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
                .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?
                .descriptor_hash
        }
        AssetId::BTC => build_denuo_bitcoin_htlc(hello, side)
            .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?
            .commitment
            .into_bytes(),
        _ => return Err(MarketError::InvalidPair),
    };
    if computed != commitment {
        return Err(MarketError::InvalidDenuoSwapHandshake);
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
            price_round_hash: ObjectHash::new(hello.price_round_hash),
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
    // The Denuo board has already admitted MatchRequest, FillGrant and the
    // exact double-signed terms. Persist one execution baseline instead of
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
    #[error("the retained Denuo price round no longer has its required predecessor")]
    DenuoPriceRoundHistoryUnavailable,
    #[error("invalid Denuo market-intent board policy")]
    InvalidDenuoIntentBoardPolicy,
    #[error("invalid or unexpected canonical Denuo V2 market-intent envelope")]
    InvalidDenuoMarketIntent,
    #[error("Denuo market-intent replay, resurrection, or conflict was rejected")]
    DenuoMarketIntentReplay,
    #[error("persisted Denuo market-intent board is corrupt or noncanonical")]
    CorruptDenuoMarketIntentBoard,
    #[error("Denuo market-intent board reached its bounded capacity")]
    DenuoMarketIntentCapacity,
    #[error("requested Denuo market intent is unknown")]
    UnknownDenuoMarketIntent,
    #[error("invalid Denuo bilateral swap-handshake policy")]
    InvalidDenuoSwapHandshakePolicy,
    #[error("invalid or unexpected canonical Denuo V2 bilateral swap message")]
    InvalidDenuoSwapHandshake,
    #[error("the referenced Denuo price round is not retained locally")]
    UnknownDenuoPriceRound,
    #[error("the referenced Denuo bilateral swap handshake is unknown")]
    UnknownDenuoSwapHandshake,
    #[error("Denuo bilateral swap handshake conflicts with accepted state")]
    DenuoSwapHandshakeConflict,
    #[error("Denuo bilateral swap handshake capacity reached")]
    DenuoSwapHandshakeCapacity,
    #[error("persisted Denuo bilateral swap handshake is corrupt or noncanonical")]
    CorruptDenuoSwapHandshake,
    #[error("invalid, unexpected, or resource-exhausting Denuo peer message")]
    InvalidDenuoPeerMessage,
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
    use hns_marketplace_protocol::{
        AssetAmount, MARKETPLACE_PROTOCOL_VERSION, MarketPair, NetworkBinding, SettlementDeadline,
        SignedObjectHeader, SwapSessionHello,
    };
    use hns_primitives::BlockHash;

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
            fill_grant_hash: [3; 32],
            swap_session_id: [4; 32],
            maker_settlement_public_key: [2; 33],
            taker_settlement_public_key: [3; 33],
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(1_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(25),
            price_round_hash: [5; 32],
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
