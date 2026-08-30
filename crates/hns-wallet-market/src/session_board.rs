//! Durable admission for one direct fixed-terms HNS/BTC swap session.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOffer, DirectOfferTake, MarketPair, NetworkBinding,
    SwapFundingStatus, SwapRedeemStatus, SwapRefundStatus, SwapSessionHello, SwapSessionProposal,
    SwapWatchReady,
};
use hns_wallet_store::{EntityKind, StoredEntity, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::direct_board::decode_canonical_envelope;
use crate::{DenuoDirectOfferBoardPolicy, MarketError, load_denuo_direct_offer};

const DENUO_DIRECT_SWAP_SCHEMA_VERSION: u16 = 1;
const DENUO_DIRECT_SWAP_POLICY_DOMAIN: &[u8] = b"hns-wallet-denuo-direct-swap-policy-v1\0";
const DENUO_DIRECT_SWAP_RECORD_PREFIX: &[u8] = b"denuo-v2-direct-swap\0";

pub const MAX_DENUO_DIRECT_SWAPS: usize = crate::MAX_CONCURRENT_SWAP_SESSIONS;

/// The direct-session policy has precisely one authority: the locally
/// reconstructed HNS/BTC network binding. It contains no price inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoDirectSwapPolicy {
    board_policy: DenuoDirectOfferBoardPolicy,
    fingerprint: ObjectHash,
}

impl DenuoDirectSwapPolicy {
    pub fn new(board_policy: DenuoDirectOfferBoardPolicy) -> Result<Self, MarketError> {
        if board_policy.pair() != MarketPair::HNS_BTC {
            return Err(MarketError::InvalidDenuoDirectSwapPolicy);
        }
        let mut hasher = Sha256::new();
        hasher.update(DENUO_DIRECT_SWAP_POLICY_DOMAIN);
        hasher.update(board_policy.fingerprint().as_bytes());
        Ok(Self {
            board_policy,
            fingerprint: ObjectHash::new(hasher.finalize().into()),
        })
    }

    pub const fn network(self) -> NetworkBinding {
        self.board_policy.network()
    }

    pub const fn board_policy(self) -> DenuoDirectOfferBoardPolicy {
        self.board_policy
    }

    pub const fn fingerprint(self) -> ObjectHash {
        self.fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoDirectSwapStage {
    TakeReceived,
    MakerProposed,
    Accepted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoDirectSwapRecord {
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
}

impl DenuoDirectSwapRecord {
    pub fn stage(&self) -> DenuoDirectSwapStage {
        if self.hello.is_some() {
            DenuoDirectSwapStage::Accepted
        } else if self.proposal.is_some() {
            DenuoDirectSwapStage::MakerProposed
        } else {
            DenuoDirectSwapStage::TakeReceived
        }
    }

    pub fn snapshot(&self) -> DenuoDirectSwapSnapshot {
        let terms = self
            .hello
            .as_ref()
            .or_else(|| self.proposal.as_ref().map(SwapSessionProposal::terms));
        DenuoDirectSwapSnapshot {
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
                .watch_ready_accepted_at_unix
                .or(self.hello_accepted_at_unix)
                .or(self.proposal_accepted_at_unix)
                .unwrap_or(self.take_accepted_at_unix),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoDirectSwapSnapshot {
    pub store_revision: u64,
    pub stage: DenuoDirectSwapStage,
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
pub enum DenuoDirectSwapAdmission {
    Created(DenuoDirectSwapSnapshot),
    Advanced(DenuoDirectSwapSnapshot),
    Existing(DenuoDirectSwapSnapshot),
}

impl DenuoDirectSwapAdmission {
    pub const fn snapshot(self) -> DenuoDirectSwapSnapshot {
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
pub enum DenuoDirectSwapPeerStatus {
    Funding(SwapFundingStatus),
    Redeem(SwapRedeemStatus),
    Refund(SwapRefundStatus),
    WatchReady(SwapWatchReady),
}

impl DenuoDirectSwapPeerStatus {
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
struct PersistedDenuoDirectSwap {
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
}

pub fn load_denuo_direct_swap(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    session_id: SessionId,
) -> Result<Option<DenuoDirectSwapRecord>, MarketError> {
    store
        .load_entity::<PersistedDenuoDirectSwap>(
            EntityKind::SwapSession,
            &record_id(policy, session_id),
        )?
        .map(|stored| decode_stored_swap(policy, stored))
        .transpose()
}

pub fn load_denuo_direct_swaps(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
) -> Result<Vec<DenuoDirectSwapRecord>, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedDenuoDirectSwap>(
        EntityKind::SwapSession,
        &record_prefix(policy),
        MAX_DENUO_DIRECT_SWAPS + 1,
    )?;
    if stored.len() > MAX_DENUO_DIRECT_SWAPS {
        return Err(MarketError::DenuoDirectSwapCapacity);
    }
    stored
        .into_iter()
        .map(|stored| decode_stored_swap(policy, stored))
        .collect()
}

/// Freeze a locally retained direct offer and a taker's signed exact request.
/// It performs no reservation, funding, or broadcast; the maker must still
/// create the separately signed proposal with HTLC commitments.
pub fn admit_denuo_direct_offer_take(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::TakeDirectOffer(take) = message else {
        return Err(MarketError::InvalidDenuoDirectSwap);
    };
    let offer = load_denuo_direct_offer(store, &policy.board_policy(), take.offer_id)?
        .ok_or(MarketError::UnknownDenuoDirectOffer)?;
    if !offer.is_active_at(accepted_at_unix) {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    take.verify_for_offer(&offer.offer, policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let session_id = SessionId::new(take.swap_session_id);
    if let Some(existing) = load_denuo_direct_swap(store, policy, session_id)? {
        if existing.take_request_id == request_id
            && existing.offer == offer.offer
            && existing.take == take
        {
            return Ok(DenuoDirectSwapAdmission::Existing(existing.snapshot()));
        }
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    if load_denuo_direct_swaps(store, policy)?.len() >= MAX_DENUO_DIRECT_SWAPS {
        return Err(MarketError::DenuoDirectSwapCapacity);
    }
    let persisted = PersistedDenuoDirectSwap {
        schema_version: DENUO_DIRECT_SWAP_SCHEMA_VERSION,
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
    };
    let revision = store.save_entity(
        EntityKind::SwapSession,
        &record_id(policy, session_id),
        0,
        &persisted,
        accepted_at_unix,
    )?;
    let record = DenuoDirectSwapRecord {
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
    };
    Ok(DenuoDirectSwapAdmission::Created(record.snapshot()))
}

pub fn admit_denuo_direct_swap_proposal(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionProposal(proposal) = message else {
        return Err(MarketError::InvalidDenuoDirectSwap);
    };
    let session_id = SessionId::new(proposal.terms().swap_session_id);
    let mut record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if let Some(existing) = &record.proposal {
        if record.proposal_request_id == Some(request_id) && existing == &proposal {
            return Ok(DenuoDirectSwapAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    proposal
        .verify_for_direct_offer(
            &record.offer,
            &record.take,
            policy.network(),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
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
    Ok(DenuoDirectSwapAdmission::Advanced(record.snapshot()))
}

pub fn admit_denuo_direct_swap_hello(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectSwapAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionHello(hello) = message else {
        return Err(MarketError::InvalidDenuoDirectSwap);
    };
    let session_id = SessionId::new(hello.swap_session_id);
    let mut record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if record.proposal_request_id != Some(request_id) {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    if let Some(existing) = &record.hello {
        if existing == &hello {
            return Ok(DenuoDirectSwapAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    hello
        .verify_for_direct_offer(
            &record.offer,
            &record.take,
            policy.network(),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let proposal = record
        .proposal
        .as_ref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    let mut maker_terms = hello.clone();
    maker_terms.taker_signature = [0; 64];
    if proposal.terms() != &maker_terms {
        return Err(MarketError::DenuoDirectSwapConflict);
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
    Ok(DenuoDirectSwapAdmission::Advanced(record.snapshot()))
}

/// Authenticate and durably retain the receiver's acknowledgement that the
/// exact first-chain HTLC watch is installed. Replays of the identical
/// canonical message are idempotent; conflicting acknowledgements fail.
pub fn admit_denuo_direct_swap_watch_ready(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectSwapAdmission, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapWatchReady(ready) = message else {
        return Err(MarketError::InvalidDenuoPeerMessage);
    };
    let session_id = SessionId::new(ready.swap_session_id);
    let mut record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    if ready.chain != hello.first_funding_chain {
        return Err(MarketError::InvalidDenuoPeerMessage);
    }
    ready
        .verify_for_session(hello, policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
    if let Some(existing) = &record.first_chain_watch_ready {
        if existing == &ready {
            return Ok(DenuoDirectSwapAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoDirectSwapConflict);
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
    Ok(DenuoDirectSwapAdmission::Advanced(record.snapshot()))
}

pub fn validate_denuo_direct_swap_peer_status(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    envelope_bytes: &[u8],
    now_unix: u64,
) -> Result<DenuoDirectSwapPeerStatus, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let status = match message {
        CrossChainMessage::SwapFundingStatus(status) => DenuoDirectSwapPeerStatus::Funding(status),
        CrossChainMessage::SwapRedeemStatus(status) => DenuoDirectSwapPeerStatus::Redeem(status),
        CrossChainMessage::SwapRefundStatus(status) => DenuoDirectSwapPeerStatus::Refund(status),
        CrossChainMessage::SwapWatchReady(status) => DenuoDirectSwapPeerStatus::WatchReady(status),
        _ => return Err(MarketError::InvalidDenuoPeerMessage),
    };
    let record = load_denuo_direct_swap(store, policy, status.session_id())?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidDenuoDirectSwap)?;
    match &status {
        DenuoDirectSwapPeerStatus::Funding(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        DenuoDirectSwapPeerStatus::Redeem(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        DenuoDirectSwapPeerStatus::Refund(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
        DenuoDirectSwapPeerStatus::WatchReady(status) => {
            status.verify_for_session(hello, policy.network(), now_unix)
        }
    }
    .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
    Ok(status)
}

fn decode_stored_swap(
    policy: &DenuoDirectSwapPolicy,
    stored: StoredEntity<PersistedDenuoDirectSwap>,
) -> Result<DenuoDirectSwapRecord, MarketError> {
    let value = stored.value;
    if value.schema_version != DENUO_DIRECT_SWAP_SCHEMA_VERSION
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
        || value.first_chain_watch_ready_hex.is_some() && value.hello_hex.is_none()
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    let offer = decode_hex::<DirectOffer>(&value.offer_hex)?;
    let take = decode_hex::<DirectOfferTake>(&value.take_hex)?;
    if SessionId::new(take.swap_session_id) != value.session_id
        || take
            .verify_for_offer(&offer, policy.network(), value.take_accepted_at_unix)
            .is_err()
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    let proposal = value.proposal_hex.as_deref().map(decode_hex).transpose()?;
    let hello = value.hello_hex.as_deref().map(decode_hex).transpose()?;
    let first_chain_watch_ready = value
        .first_chain_watch_ready_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;
    let record = DenuoDirectSwapRecord {
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
    };
    if let (Some(proposal), Some(at)) = (&record.proposal, record.proposal_accepted_at_unix) {
        proposal
            .verify_for_direct_offer(&record.offer, &record.take, policy.network(), at)
            .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    }
    if let (Some(hello), Some(at)) = (&record.hello, record.hello_accepted_at_unix) {
        hello
            .verify_for_direct_offer(&record.offer, &record.take, policy.network(), at)
            .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
        let proposal = record
            .proposal
            .as_ref()
            .ok_or(MarketError::CorruptDenuoDirectSwap)?;
        let mut maker_terms = hello.clone();
        maker_terms.taker_signature = [0; 64];
        if proposal.terms() != &maker_terms {
            return Err(MarketError::CorruptDenuoDirectSwap);
        }
    }
    if let (Some(ready), Some(at), Some(hello)) = (
        &record.first_chain_watch_ready,
        record.watch_ready_accepted_at_unix,
        &record.hello,
    ) {
        if ready.chain != hello.first_funding_chain
            || ready
                .verify_for_session(hello, policy.network(), at)
                .is_err()
        {
            return Err(MarketError::CorruptDenuoDirectSwap);
        }
    }
    if stored.updated_at_unix != record.snapshot().last_accepted_at_unix
        || !timestamps_monotonic(&record)
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    Ok(record)
}

fn encode_persisted(
    policy: &DenuoDirectSwapPolicy,
    record: &DenuoDirectSwapRecord,
) -> Result<PersistedDenuoDirectSwap, MarketError> {
    Ok(PersistedDenuoDirectSwap {
        schema_version: DENUO_DIRECT_SWAP_SCHEMA_VERSION,
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
    })
}

fn timestamps_monotonic(record: &DenuoDirectSwapRecord) -> bool {
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
    SwapWatchReady,
);

fn encode_hex<T: CanonicalDirectObject>(value: &T) -> Result<String, MarketError> {
    value
        .encode_canonical()
        .map(hex::encode)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)
}

fn decode_hex<T: CanonicalDirectObject>(encoded: &str) -> Result<T, MarketError> {
    let bytes = hex::decode(encoded).map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    if hex::encode(&bytes) != encoded {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    let value = T::decode_canonical(&bytes).map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    if value.encode_canonical().ok().as_deref() != Some(bytes.as_slice()) {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    Ok(value)
}

fn record_prefix(policy: &DenuoDirectSwapPolicy) -> Vec<u8> {
    let mut id = Vec::with_capacity(DENUO_DIRECT_SWAP_RECORD_PREFIX.len() + 32);
    id.extend_from_slice(DENUO_DIRECT_SWAP_RECORD_PREFIX);
    id.extend_from_slice(policy.fingerprint().as_bytes());
    id
}

fn record_id(policy: &DenuoDirectSwapPolicy, session_id: SessionId) -> Vec<u8> {
    let mut id = record_prefix(policy);
    id.extend_from_slice(session_id.as_bytes());
    id
}
