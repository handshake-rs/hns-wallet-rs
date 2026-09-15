//! Durable admission for one direct fixed-terms HNS/BTC swap session.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOffer, DirectOfferTake, MarketPair, MarketplaceError,
    NetworkBinding, SwapFundingStatus, SwapRedeemStatus, SwapRefundStatus, SwapSessionHello,
    SwapSessionProposal, SwapWatchReady,
};
use hns_wallet_store::{EntityKind, StoredEntity, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::direct_board::decode_canonical_envelope;
use crate::{MarketError, ShakescapeDirectOfferBoardPolicy, load_shakescape_direct_offer};

const SHAKESCAPE_DIRECT_SWAP_SCHEMA_VERSION: u16 = 1;
const SHAKESCAPE_DIRECT_SWAP_POLICY_DOMAIN: &[u8] =
    b"hns-wallet-shakescape-direct-swap-policy-v1\0";
const SHAKESCAPE_DIRECT_SWAP_RECORD_PREFIX: &[u8] = b"shakescape-v2-direct-swap\0";

pub const MAX_SHAKESCAPE_DIRECT_SWAPS: usize = crate::MAX_CONCURRENT_SWAP_SESSIONS;

/// The direct-session policy has precisely one authority: the locally
/// reconstructed HNS/BTC network binding. It contains no price inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeDirectSwapPolicy {
    board_policy: ShakescapeDirectOfferBoardPolicy,
    fingerprint: ObjectHash,
}

impl ShakescapeDirectSwapPolicy {
    pub fn new(board_policy: ShakescapeDirectOfferBoardPolicy) -> Result<Self, MarketError> {
        if board_policy.pair() != MarketPair::HNS_BTC {
            return Err(MarketError::InvalidShakescapeDirectSwapPolicy);
        }
        let mut hasher = Sha256::new();
        hasher.update(SHAKESCAPE_DIRECT_SWAP_POLICY_DOMAIN);
        hasher.update(board_policy.fingerprint().as_bytes());
        Ok(Self {
            board_policy,
            fingerprint: ObjectHash::new(hasher.finalize().into()),
        })
    }

    pub const fn network(self) -> NetworkBinding {
        self.board_policy.network()
    }

    pub const fn board_policy(self) -> ShakescapeDirectOfferBoardPolicy {
        self.board_policy
    }

    pub const fn fingerprint(self) -> ObjectHash {
        self.fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakescapeDirectSwapStage {
    TakeReceived,
    MakerProposed,
    Accepted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeDirectSwapRecord {
    pub store_revision: u64,
    pub take_request_id: u64,
    pub proposal_request_id: Option<u64>,
    pub take_accepted_at_unix: u64,
    pub proposal_accepted_at_unix: Option<u64>,
    pub hello_accepted_at_unix: Option<u64>,
    pub offer: DirectOffer,
    pub take: DirectOfferTake,
    pub proposal: Option<SwapSessionProposal>,
    pub hello: Option<SwapSessionHello>,
    pub watch_ready_accepted_at_unix: Option<u64>,
    pub first_chain_watch_ready: Option<SwapWatchReady>,
    /// Latest signed counterparty funding locator for each chain. This is
    /// coordination metadata only; local chain verification remains required.
    pub peer_funding_statuses: Vec<ShakescapePeerFundingStatusRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapePeerFundingStatusRecord {
    pub accepted_at_unix: u64,
    pub status: SwapFundingStatus,
}

impl ShakescapeDirectSwapRecord {
    pub fn stage(&self) -> ShakescapeDirectSwapStage {
        if self.hello.is_some() {
            ShakescapeDirectSwapStage::Accepted
        } else if self.proposal.is_some() {
            ShakescapeDirectSwapStage::MakerProposed
        } else {
            ShakescapeDirectSwapStage::TakeReceived
        }
    }

    pub fn snapshot(&self) -> ShakescapeDirectSwapSnapshot {
        let terms = self
            .hello
            .as_ref()
            .or_else(|| self.proposal.as_ref().map(SwapSessionProposal::terms));
        ShakescapeDirectSwapSnapshot {
            store_revision: self.store_revision,
            stage: self.stage(),
            session_id: SessionId::new(self.take.swap_session_id),
            offer_id: ObjectHash::new(self.offer.offer_id),
            take_request_id: self.take_request_id,
            proposal_request_id: self.proposal_request_id,
            offered_asset: self.offer.offered_asset,
            offered_amount: self.offer.offered_amount.get(),
            received_asset: self.offer.received_asset,
            received_amount: self.offer.received_amount.get(),
            hashlock: terms.map(|terms| ObjectHash::new(terms.hashlock)),
            offered_refund_at_unix: terms.map(|terms| terms.offered_refund_deadline.value),
            received_refund_at_unix: terms.map(|terms| terms.received_refund_deadline.value),
            last_accepted_at_unix: self
                .peer_funding_statuses
                .iter()
                .map(|status| status.accepted_at_unix)
                .max()
                .or(self.watch_ready_accepted_at_unix)
                .or(self.hello_accepted_at_unix)
                .or(self.proposal_accepted_at_unix)
                .unwrap_or(self.take_accepted_at_unix),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeDirectSwapSnapshot {
    pub store_revision: u64,
    pub stage: ShakescapeDirectSwapStage,
    pub session_id: SessionId,
    pub offer_id: ObjectHash,
    pub take_request_id: u64,
    pub proposal_request_id: Option<u64>,
    pub offered_asset: AssetId,
    pub offered_amount: u128,
    pub received_asset: AssetId,
    pub received_amount: u128,
    pub hashlock: Option<ObjectHash>,
    pub offered_refund_at_unix: Option<u64>,
    pub received_refund_at_unix: Option<u64>,
    pub last_accepted_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakescapeDirectSwapAdmission {
    Created(ShakescapeDirectSwapSnapshot),
    Advanced(ShakescapeDirectSwapSnapshot),
    Existing(ShakescapeDirectSwapSnapshot),
}

impl ShakescapeDirectSwapAdmission {
    pub const fn snapshot(self) -> ShakescapeDirectSwapSnapshot {
        match self {
            Self::Created(snapshot) | Self::Advanced(snapshot) | Self::Existing(snapshot) => {
                snapshot
            }
        }
    }
}

/// Signed peer status is coordination metadata only. Local HNS and Kyoto
/// verification remains the authority for execution-state transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShakescapeDirectSwapPeerStatus {
    Funding(SwapFundingStatus),
    Redeem(SwapRedeemStatus),
    Refund(SwapRefundStatus),
    WatchReady(SwapWatchReady),
}

impl ShakescapeDirectSwapPeerStatus {
    pub const fn session_id(&self) -> SessionId {
        match self {
            Self::Funding(status) => SessionId::new(status.swap_session_id),
            Self::Redeem(status) => SessionId::new(status.swap_session_id),
            Self::Refund(status) => SessionId::new(status.swap_session_id),
            Self::WatchReady(status) => SessionId::new(status.swap_session_id),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedShakescapeDirectSwap {
    schema_version: u16,
    policy_fingerprint: ObjectHash,
    session_id: SessionId,
    take_request_id: u64,
    proposal_request_id: Option<u64>,
    take_accepted_at_unix: u64,
    proposal_accepted_at_unix: Option<u64>,
    hello_accepted_at_unix: Option<u64>,
    offer_hex: String,
    take_hex: String,
    proposal_hex: Option<String>,
    hello_hex: Option<String>,
    #[serde(default)]
    watch_ready_accepted_at_unix: Option<u64>,
    #[serde(default)]
    first_chain_watch_ready_hex: Option<String>,
    #[serde(default)]
    peer_funding_statuses: Vec<PersistedPeerFundingStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPeerFundingStatus {
    accepted_at_unix: u64,
    status_hex: String,
}

pub fn load_shakescape_direct_swap(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    session_id: SessionId,
) -> Result<Option<ShakescapeDirectSwapRecord>, MarketError> {
    store
        .load_entity::<PersistedShakescapeDirectSwap>(
            EntityKind::SwapSession,
            &record_id(policy, session_id),
        )?
        .map(|stored| decode_stored_swap(policy, stored))
        .transpose()
}

pub fn load_shakescape_direct_swaps(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
) -> Result<Vec<ShakescapeDirectSwapRecord>, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedShakescapeDirectSwap>(
        EntityKind::SwapSession,
        &record_prefix(policy),
        MAX_SHAKESCAPE_DIRECT_SWAPS + 1,
    )?;
    if stored.len() > MAX_SHAKESCAPE_DIRECT_SWAPS {
        return Err(MarketError::ShakescapeDirectSwapCapacity);
    }
    stored
        .into_iter()
        .map(|stored| decode_stored_swap(policy, stored))
        .collect()
}

/// Freeze a locally retained direct offer and a taker's signed exact request.
/// It performs no reservation, funding, or broadcast; the maker must still
/// create the separately signed proposal with HTLC commitments.
pub fn admit_shakescape_direct_offer_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<ShakescapeDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::TakeDirectOffer(take) = message else {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    };
    let offer = load_shakescape_direct_offer(store, &policy.board_policy(), take.offer_id)?
        .ok_or(MarketError::UnknownShakescapeDirectOffer)?;
    if !offer.is_active_at(accepted_at_unix) {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    take.verify_for_offer(&offer.offer, policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let session_id = SessionId::new(take.swap_session_id);
    if let Some(existing) = load_shakescape_direct_swap(store, policy, session_id)? {
        // The transport correlation ID is deliberately outside the signed
        // take. A reconnecting wallet may replay the same durable take on a
        // new socket whose request-ID sequence is different. Treat the exact
        // signed offer/take pair as idempotent and retain the first admitted
        // request ID so an already-created proposal/hello exchange keeps its
        // original correlation.
        if existing.offer == offer.offer && existing.take == take {
            return Ok(ShakescapeDirectSwapAdmission::Existing(existing.snapshot()));
        }
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    if load_shakescape_direct_swaps(store, policy)?.len() >= MAX_SHAKESCAPE_DIRECT_SWAPS {
        return Err(MarketError::ShakescapeDirectSwapCapacity);
    }
    let persisted = PersistedShakescapeDirectSwap {
        schema_version: SHAKESCAPE_DIRECT_SWAP_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint(),
        session_id,
        take_request_id: request_id,
        proposal_request_id: None,
        take_accepted_at_unix: accepted_at_unix,
        proposal_accepted_at_unix: None,
        hello_accepted_at_unix: None,
        offer_hex: encode_hex(&offer.offer)?,
        take_hex: encode_hex(&take)?,
        proposal_hex: None,
        hello_hex: None,
        watch_ready_accepted_at_unix: None,
        first_chain_watch_ready_hex: None,
        peer_funding_statuses: Vec::new(),
    };
    let revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        0,
        &persisted,
        accepted_at_unix,
    )?;
    let record = ShakescapeDirectSwapRecord {
        store_revision: revision,
        take_request_id: request_id,
        proposal_request_id: None,
        take_accepted_at_unix: accepted_at_unix,
        proposal_accepted_at_unix: None,
        hello_accepted_at_unix: None,
        offer: offer.offer,
        take,
        proposal: None,
        hello: None,
        watch_ready_accepted_at_unix: None,
        first_chain_watch_ready: None,
        peer_funding_statuses: Vec::new(),
    };
    Ok(ShakescapeDirectSwapAdmission::Created(record.snapshot()))
}

pub fn admit_shakescape_direct_swap_proposal(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<ShakescapeDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionProposal(proposal) = message else {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    };
    let session_id = SessionId::new(proposal.terms().swap_session_id);
    let mut record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if let Some(existing) = &record.proposal {
        if record.proposal_request_id == Some(request_id) && existing == &proposal {
            return Ok(ShakescapeDirectSwapAdmission::Existing(record.snapshot()));
        }
        // A maker-only proposal is a bounded invitation to begin funding, not
        // a countersigned agreement. If that invitation expired in transit,
        // permit the same maker to refresh its time bounds for the exact
        // signed offer/take pair. Once the taker has countersigned, every term
        // is frozen and even an expired proposal remains immutable.
        let expired_maker_only = record.hello.is_none()
            && matches!(
                existing.verify_at(policy.network(), accepted_at_unix),
                Err(MarketplaceError::Expired { .. })
            );
        if !expired_maker_only {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
    }
    proposal
        .verify_for_direct_offer(
            &record.offer,
            &record.take,
            policy.network(),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.proposal_request_id = Some(request_id);
    persisted.proposal_accepted_at_unix = Some(accepted_at_unix);
    persisted.proposal_hex = Some(encode_hex(&proposal)?);
    let next_revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        record.store_revision,
        &persisted,
        accepted_at_unix,
    )?;
    record.store_revision = next_revision;
    record.proposal_request_id = Some(request_id);
    record.proposal_accepted_at_unix = Some(accepted_at_unix);
    record.proposal = Some(proposal);
    Ok(ShakescapeDirectSwapAdmission::Advanced(record.snapshot()))
}

pub fn admit_shakescape_direct_swap_hello(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<ShakescapeDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionHello(hello) = message else {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    };
    let session_id = SessionId::new(hello.swap_session_id);
    let mut record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if record.proposal_request_id != Some(request_id) {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    if let Some(existing) = &record.hello {
        if existing == &hello {
            return Ok(ShakescapeDirectSwapAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    hello
        .verify_for_direct_offer(
            &record.offer,
            &record.take,
            policy.network(),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let proposal = record
        .proposal
        .as_ref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    let mut maker_terms = hello.clone();
    maker_terms.taker_signature = [0; 64];
    if proposal.terms() != &maker_terms {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.hello_accepted_at_unix = Some(accepted_at_unix);
    persisted.hello_hex = Some(encode_hex(&hello)?);
    let next_revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        record.store_revision,
        &persisted,
        accepted_at_unix,
    )?;
    record.store_revision = next_revision;
    record.hello_accepted_at_unix = Some(accepted_at_unix);
    record.hello = Some(hello);
    Ok(ShakescapeDirectSwapAdmission::Advanced(record.snapshot()))
}

/// Authenticate and durably retain the receiver's acknowledgement that the
/// exact first-chain HTLC watch is installed. Replays of the identical
/// canonical message are idempotent; conflicting acknowledgements fail.
pub fn admit_shakescape_direct_swap_watch_ready(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<ShakescapeDirectSwapAdmission, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapWatchReady(ready) = message else {
        return Err(MarketError::InvalidShakescapePeerMessage);
    };
    let session_id = SessionId::new(ready.swap_session_id);
    let mut record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    if ready.chain != hello.first_funding_chain {
        return Err(MarketError::InvalidShakescapePeerMessage);
    }
    ready
        .verify_for_session(hello, policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidShakescapePeerMessage)?;
    if let Some(existing) = &record.first_chain_watch_ready {
        if existing == &ready {
            return Ok(ShakescapeDirectSwapAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.watch_ready_accepted_at_unix = Some(accepted_at_unix);
    persisted.first_chain_watch_ready_hex = Some(encode_hex(&ready)?);
    let next_revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        record.store_revision,
        &persisted,
        accepted_at_unix,
    )?;
    record.store_revision = next_revision;
    record.watch_ready_accepted_at_unix = Some(accepted_at_unix);
    record.first_chain_watch_ready = Some(ready);
    Ok(ShakescapeDirectSwapAdmission::Advanced(record.snapshot()))
}

pub fn validate_shakescape_direct_swap_peer_status(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    now_unix: u64,
) -> Result<ShakescapeDirectSwapPeerStatus, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let status = match message {
        CrossChainMessage::SwapFundingStatus(status) => {
            ShakescapeDirectSwapPeerStatus::Funding(status)
        }
        CrossChainMessage::SwapRedeemStatus(status) => {
            ShakescapeDirectSwapPeerStatus::Redeem(status)
        }
        CrossChainMessage::SwapRefundStatus(status) => {
            ShakescapeDirectSwapPeerStatus::Refund(status)
        }
        CrossChainMessage::SwapWatchReady(status) => {
            ShakescapeDirectSwapPeerStatus::WatchReady(status)
        }
        _ => return Err(MarketError::InvalidShakescapePeerMessage),
    };
    let record = load_shakescape_direct_swap(store, policy, status.session_id())?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    match &status {
        ShakescapeDirectSwapPeerStatus::Funding(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        ShakescapeDirectSwapPeerStatus::Redeem(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        ShakescapeDirectSwapPeerStatus::Refund(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        ShakescapeDirectSwapPeerStatus::WatchReady(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
    }
    .map_err(|_| MarketError::InvalidShakescapePeerMessage)?;
    Ok(status)
}

/// Validate peer coordination status and retain only the latest signed
/// funding locator for each chain. The locator is never treated as funding
/// evidence; it lets the local chain adapter fetch and verify the transaction.
pub fn admit_shakescape_direct_swap_peer_status(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    envelope_bytes: &[u8],
    now_unix: u64,
) -> Result<ShakescapeDirectSwapPeerStatus, MarketError> {
    let status =
        validate_shakescape_direct_swap_peer_status(store, policy, envelope_bytes, now_unix)?;
    let ShakescapeDirectSwapPeerStatus::Funding(funding) = &status else {
        return Ok(status);
    };
    let session_id = SessionId::new(funding.swap_session_id);
    let mut record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if let Some(existing) = record
        .peer_funding_statuses
        .iter()
        .find(|existing| existing.status.chain == funding.chain)
    {
        if existing.status == *funding {
            return Ok(status);
        }
        if funding.header.sequence <= existing.status.header.sequence {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
    }
    record
        .peer_funding_statuses
        .retain(|existing| existing.status.chain != funding.chain);
    record
        .peer_funding_statuses
        .push(ShakescapePeerFundingStatusRecord {
            accepted_at_unix: now_unix,
            status: funding.clone(),
        });
    record
        .peer_funding_statuses
        .sort_by_key(|existing| existing.status.chain);
    if record.peer_funding_statuses.len() > 2 {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    let persisted = encode_persisted(policy, &record)?;
    let revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        record.store_revision,
        &persisted,
        now_unix,
    )?;
    debug_assert_ne!(revision, 0);
    Ok(status)
}

fn decode_stored_swap(
    policy: &ShakescapeDirectSwapPolicy,
    stored: StoredEntity<PersistedShakescapeDirectSwap>,
) -> Result<ShakescapeDirectSwapRecord, MarketError> {
    let value = stored.value;
    let malformed_envelope = value.schema_version != SHAKESCAPE_DIRECT_SWAP_SCHEMA_VERSION
        || value.policy_fingerprint != policy.fingerprint()
        || value.take_request_id == 0
        || value.proposal_request_id == Some(0)
        || stored.id != record_id(policy, value.session_id)
        || value.proposal_accepted_at_unix.is_some() != value.proposal_hex.is_some()
        || value.proposal_request_id.is_some() != value.proposal_hex.is_some()
        || value.hello_accepted_at_unix.is_some() != value.hello_hex.is_some()
        || value.hello_hex.is_some() && value.proposal_hex.is_none()
        || value.watch_ready_accepted_at_unix.is_some()
            != value.first_chain_watch_ready_hex.is_some()
        || value.first_chain_watch_ready_hex.is_some() && value.hello_hex.is_none();
    if malformed_envelope {
        return Err(MarketError::CorruptShakescapeDirectSwapDetail(
            "record envelope",
        ));
    }
    let offer = decode_hex::<DirectOffer>(&value.offer_hex)
        .map_err(|_| MarketError::CorruptShakescapeDirectSwapDetail("canonical offer encoding"))?;
    let take = decode_hex::<DirectOfferTake>(&value.take_hex)
        .map_err(|_| MarketError::CorruptShakescapeDirectSwapDetail("canonical take encoding"))?;
    if SessionId::new(take.swap_session_id) != value.session_id
        || take
            .verify_for_offer(&offer, policy.network(), value.take_accepted_at_unix)
            .is_err()
    {
        return Err(MarketError::CorruptShakescapeDirectSwapDetail(
            "take authentication",
        ));
    }
    let proposal = value
        .proposal_hex
        .as_deref()
        .map(decode_hex)
        .transpose()
        .map_err(|_| {
            MarketError::CorruptShakescapeDirectSwapDetail("canonical proposal encoding")
        })?;
    let hello = value
        .hello_hex
        .as_deref()
        .map(decode_hex)
        .transpose()
        .map_err(|_| MarketError::CorruptShakescapeDirectSwapDetail("canonical hello encoding"))?;
    let first_chain_watch_ready = value
        .first_chain_watch_ready_hex
        .as_deref()
        .map(decode_hex)
        .transpose()
        .map_err(|_| {
            MarketError::CorruptShakescapeDirectSwapDetail("canonical watch-ready encoding")
        })?;
    let peer_funding_statuses = value
        .peer_funding_statuses
        .into_iter()
        .map(|status| {
            Ok(ShakescapePeerFundingStatusRecord {
                accepted_at_unix: status.accepted_at_unix,
                status: decode_hex(&status.status_hex).map_err(|_| {
                    MarketError::CorruptShakescapeDirectSwapDetail(
                        "canonical peer-funding encoding",
                    )
                })?,
            })
        })
        .collect::<Result<Vec<_>, MarketError>>()?;
    let record = ShakescapeDirectSwapRecord {
        store_revision: stored.revision,
        take_request_id: value.take_request_id,
        proposal_request_id: value.proposal_request_id,
        take_accepted_at_unix: value.take_accepted_at_unix,
        proposal_accepted_at_unix: value.proposal_accepted_at_unix,
        hello_accepted_at_unix: value.hello_accepted_at_unix,
        offer,
        take,
        proposal,
        hello,
        watch_ready_accepted_at_unix: value.watch_ready_accepted_at_unix,
        first_chain_watch_ready,
        peer_funding_statuses,
    };
    if let (Some(proposal), Some(at)) = (&record.proposal, record.proposal_accepted_at_unix) {
        proposal
            .verify_for_direct_offer(&record.offer, &record.take, policy.network(), at)
            .map_err(|_| {
                MarketError::CorruptShakescapeDirectSwapDetail("proposal authentication")
            })?;
    }
    if let (Some(hello), Some(at)) = (&record.hello, record.hello_accepted_at_unix) {
        hello
            .verify_for_direct_offer(&record.offer, &record.take, policy.network(), at)
            .map_err(|_| MarketError::CorruptShakescapeDirectSwapDetail("hello authentication"))?;
        let proposal =
            record
                .proposal
                .as_ref()
                .ok_or(MarketError::CorruptShakescapeDirectSwapDetail(
                    "hello without proposal",
                ))?;
        let mut maker_terms = hello.clone();
        maker_terms.taker_signature = [0; 64];
        if proposal.terms() != &maker_terms {
            return Err(MarketError::CorruptShakescapeDirectSwapDetail(
                "proposal/hello term mismatch",
            ));
        }
    }
    if let (Some(ready), Some(at), Some(hello)) = (
        &record.first_chain_watch_ready,
        record.watch_ready_accepted_at_unix,
        &record.hello,
    ) && (ready.chain != hello.first_funding_chain
        || ready
            .verify_for_session(hello, policy.network(), at)
            .is_err())
    {
        return Err(MarketError::CorruptShakescapeDirectSwapDetail(
            "watch-ready authentication",
        ));
    }
    if record.peer_funding_statuses.len() > 2
        || record
            .peer_funding_statuses
            .windows(2)
            .any(|window| window[0].status.chain >= window[1].status.chain)
        || record.peer_funding_statuses.iter().any(|funding| {
            record.hello.as_ref().is_none_or(|hello| {
                funding
                    .status
                    .verify_for_session(hello, policy.network(), funding.accepted_at_unix)
                    .is_err()
            })
        })
    {
        return Err(MarketError::CorruptShakescapeDirectSwapDetail(
            "peer-funding authentication",
        ));
    }
    if stored.updated_at_unix != record.snapshot().last_accepted_at_unix
        || !timestamps_monotonic(&record)
    {
        return Err(MarketError::CorruptShakescapeDirectSwapDetail(
            "record timestamps",
        ));
    }
    Ok(record)
}

fn encode_persisted(
    policy: &ShakescapeDirectSwapPolicy,
    record: &ShakescapeDirectSwapRecord,
) -> Result<PersistedShakescapeDirectSwap, MarketError> {
    Ok(PersistedShakescapeDirectSwap {
        schema_version: SHAKESCAPE_DIRECT_SWAP_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint(),
        session_id: SessionId::new(record.take.swap_session_id),
        take_request_id: record.take_request_id,
        proposal_request_id: record.proposal_request_id,
        take_accepted_at_unix: record.take_accepted_at_unix,
        proposal_accepted_at_unix: record.proposal_accepted_at_unix,
        hello_accepted_at_unix: record.hello_accepted_at_unix,
        offer_hex: encode_hex(&record.offer)?,
        take_hex: encode_hex(&record.take)?,
        proposal_hex: record.proposal.as_ref().map(encode_hex).transpose()?,
        hello_hex: record.hello.as_ref().map(encode_hex).transpose()?,
        watch_ready_accepted_at_unix: record.watch_ready_accepted_at_unix,
        first_chain_watch_ready_hex: record
            .first_chain_watch_ready
            .as_ref()
            .map(encode_hex)
            .transpose()?,
        peer_funding_statuses: record
            .peer_funding_statuses
            .iter()
            .map(|status| {
                Ok(PersistedPeerFundingStatus {
                    accepted_at_unix: status.accepted_at_unix,
                    status_hex: encode_hex(&status.status)?,
                })
            })
            .collect::<Result<Vec<_>, MarketError>>()?,
    })
}

fn timestamps_monotonic(record: &ShakescapeDirectSwapRecord) -> bool {
    [
        Some(record.take_accepted_at_unix),
        record.proposal_accepted_at_unix,
        record.hello_accepted_at_unix,
        record.watch_ready_accepted_at_unix,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .windows(2)
    .all(|window| window[0] <= window[1])
}

trait CanonicalDirectObject: Sized {
    fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError>;
    fn decode_canonical(bytes: &[u8]) -> Result<Self, hns_marketplace_protocol::MarketplaceError>;
}

macro_rules! canonical_direct_object {
    ($($type:ty),+ $(,)?) => {
        $(
            impl CanonicalDirectObject for $type {
                fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError> {
                    self.encode()
                }

                fn decode_canonical(bytes: &[u8]) -> Result<Self, hns_marketplace_protocol::MarketplaceError> {
                    Self::decode(bytes)
                }
            }
        )+
    };
}

canonical_direct_object!(
    DirectOffer,
    DirectOfferTake,
    SwapSessionProposal,
    SwapSessionHello,
    SwapFundingStatus,
    SwapWatchReady,
);

fn encode_hex<T: CanonicalDirectObject>(value: &T) -> Result<String, MarketError> {
    value
        .encode_canonical()
        .map(hex::encode)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)
}

fn decode_hex<T: CanonicalDirectObject>(encoded: &str) -> Result<T, MarketError> {
    let bytes = hex::decode(encoded).map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    if hex::encode(&bytes) != encoded {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    let value =
        T::decode_canonical(&bytes).map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    if value.encode_canonical().ok().as_deref() != Some(bytes.as_slice()) {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    Ok(value)
}

fn record_prefix(policy: &ShakescapeDirectSwapPolicy) -> Vec<u8> {
    let mut id = Vec::with_capacity(SHAKESCAPE_DIRECT_SWAP_RECORD_PREFIX.len() + 32);
    id.extend_from_slice(SHAKESCAPE_DIRECT_SWAP_RECORD_PREFIX);
    id.extend_from_slice(policy.fingerprint().as_bytes());
    id
}

fn record_id(policy: &ShakescapeDirectSwapPolicy, session_id: SessionId) -> Vec<u8> {
    let mut id = record_prefix(policy);
    id.extend_from_slice(session_id.as_bytes());
    id
}
