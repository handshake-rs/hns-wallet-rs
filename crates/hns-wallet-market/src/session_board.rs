use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, FillGrant, MarketIntent, MarketPair, MatchRequest, NetworkBinding,
    PriceRound, SwapFundingStatus, SwapRedeemStatus, SwapRefundStatus, SwapSessionHello,
    SwapSessionProposal,
};
use hns_wallet_store::{
    EntityBatchSave, EntityKind, EntityPrefixSetLease, StoreError, StoredEntity, WalletStore,
};
use hns_wallet_types::{ObjectHash, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent_board::decode_canonical_envelope;
use crate::{
    DenuoIntentBoardPolicy, DenuoPriceRoundPolicy, MarketError, load_denuo_market_intent,
    load_denuo_verified_price_round,
};

const DENUO_SWAP_HANDSHAKE_SCHEMA_VERSION: u16 = 1;
const DENUO_SWAP_HANDSHAKE_POLICY_DOMAIN: &[u8] = b"hns-wallet-denuo-swap-policy-v1\0";
const DENUO_SWAP_HANDSHAKE_RECORD_PREFIX: &[u8] = b"denuo-v2-swap-handshake\0";

/// One wallet retains only a bounded set of nonterminal bilateral handshakes.
/// Terminal execution is journaled separately by [`crate::SwapSession`].
pub const MAX_DENUO_SWAP_HANDSHAKES: usize = crate::MAX_CONCURRENT_SWAP_SESSIONS;

/// Exact local policy joining the signed intent board and price-round cache.
/// The policy is rebuilt by the product on startup and is not learned from a
/// peer, relay, node, or persisted handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoSwapHandshakePolicy {
    intent_policy: DenuoIntentBoardPolicy,
    price_policy: DenuoPriceRoundPolicy,
    fingerprint: ObjectHash,
}

impl DenuoSwapHandshakePolicy {
    pub fn new(
        intent_policy: DenuoIntentBoardPolicy,
        price_policy: DenuoPriceRoundPolicy,
    ) -> Result<Self, MarketError> {
        if intent_policy.network() != price_policy.network()
            || intent_policy.pair() != price_policy.pair()
            || intent_policy.pair() != MarketPair::HNS_BTC
        {
            return Err(MarketError::InvalidDenuoSwapHandshakePolicy);
        }
        let mut hasher = Sha256::new();
        hasher.update(DENUO_SWAP_HANDSHAKE_POLICY_DOMAIN);
        hasher.update(intent_policy.fingerprint().as_bytes());
        hasher.update(price_policy.fingerprint().as_bytes());
        Ok(Self {
            intent_policy,
            price_policy,
            fingerprint: ObjectHash::new(hasher.finalize().into()),
        })
    }

    pub const fn network(&self) -> NetworkBinding {
        self.intent_policy.network()
    }

    pub const fn pair(&self) -> MarketPair {
        self.intent_policy.pair()
    }

    pub const fn fingerprint(&self) -> ObjectHash {
        self.fingerprint
    }

    pub const fn intent_policy(&self) -> &DenuoIntentBoardPolicy {
        &self.intent_policy
    }

    pub const fn price_policy(&self) -> &DenuoPriceRoundPolicy {
        &self.price_policy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoSwapHandshakeStage {
    MatchRequested,
    FillGranted,
    MakerProposed,
    Accepted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoSwapHandshakeRecord {
    pub store_revision: u64,
    pub match_request_id: u64,
    pub proposal_request_id: Option<u64>,
    pub match_accepted_at_unix: u64,
    pub fill_accepted_at_unix: Option<u64>,
    pub price_round_accepted_at_unix: Option<u64>,
    pub proposal_accepted_at_unix: Option<u64>,
    pub hello_accepted_at_unix: Option<u64>,
    pub intent: MarketIntent,
    pub match_request: MatchRequest,
    pub fill_grant: Option<FillGrant>,
    pub price_round: Option<PriceRound>,
    pub previous_price_round: Option<PriceRound>,
    pub proposal: Option<SwapSessionProposal>,
    pub hello: Option<SwapSessionHello>,
}

impl DenuoSwapHandshakeRecord {
    pub fn stage(&self) -> DenuoSwapHandshakeStage {
        if self.hello.is_some() {
            DenuoSwapHandshakeStage::Accepted
        } else if self.proposal.is_some() {
            DenuoSwapHandshakeStage::MakerProposed
        } else if self.fill_grant.is_some() {
            DenuoSwapHandshakeStage::FillGranted
        } else {
            DenuoSwapHandshakeStage::MatchRequested
        }
    }

    pub fn snapshot(&self) -> DenuoSwapHandshakeSnapshot {
        let fill = self.fill_grant.as_ref();
        let terms = self
            .hello
            .as_ref()
            .or_else(|| self.proposal.as_ref().map(SwapSessionProposal::terms));
        DenuoSwapHandshakeSnapshot {
            store_revision: self.store_revision,
            stage: self.stage(),
            session_id: SessionId::new(self.match_request.swap_session_id),
            intent_id: ObjectHash::new(self.intent.intent_id),
            match_request_id: self.match_request_id,
            proposal_request_id: self.proposal_request_id,
            offered_asset: self.intent.offered_asset,
            offered_amount: fill.map(|grant| grant.offered_amount.get()),
            received_asset: terms.map(|hello| hello.received_asset),
            received_amount: fill.map(|grant| grant.received_amount.get()),
            price_round_hash: fill.map(|grant| ObjectHash::new(grant.price_round_hash)),
            hashlock: terms.map(|hello| ObjectHash::new(hello.hashlock)),
            offered_refund_at_unix: terms.map(|hello| hello.offered_refund_deadline.value),
            received_refund_at_unix: terms.map(|hello| hello.received_refund_deadline.value),
            last_accepted_at_unix: self
                .hello_accepted_at_unix
                .or(self.proposal_accepted_at_unix)
                .or(self.fill_accepted_at_unix)
                .unwrap_or(self.match_accepted_at_unix),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoSwapHandshakeSnapshot {
    pub store_revision: u64,
    pub stage: DenuoSwapHandshakeStage,
    pub session_id: SessionId,
    pub intent_id: ObjectHash,
    pub match_request_id: u64,
    pub proposal_request_id: Option<u64>,
    pub offered_asset: AssetId,
    pub offered_amount: Option<u128>,
    pub received_asset: Option<AssetId>,
    pub received_amount: Option<u128>,
    pub price_round_hash: Option<ObjectHash>,
    pub hashlock: Option<ObjectHash>,
    pub offered_refund_at_unix: Option<u64>,
    pub received_refund_at_unix: Option<u64>,
    pub last_accepted_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoSwapHandshakeAdmission {
    Created(DenuoSwapHandshakeSnapshot),
    Advanced(DenuoSwapHandshakeSnapshot),
    Existing(DenuoSwapHandshakeSnapshot),
}

/// A signed, session-correlated status received directly from a Denuo peer.
/// It is intentionally not execution evidence: callers must verify the
/// referenced transaction through their own HNS or Kyoto light-client before
/// applying any [`crate::VerifiedEvidence`] to the durable swap journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DenuoSwapPeerStatus {
    Funding(SwapFundingStatus),
    Redeem(SwapRedeemStatus),
    Refund(SwapRefundStatus),
}

impl DenuoSwapPeerStatus {
    pub const fn session_id(&self) -> SessionId {
        match self {
            Self::Funding(status) => SessionId::new(status.swap_session_id),
            Self::Redeem(status) => SessionId::new(status.swap_session_id),
            Self::Refund(status) => SessionId::new(status.swap_session_id),
        }
    }
}

impl DenuoSwapHandshakeAdmission {
    pub const fn snapshot(self) -> DenuoSwapHandshakeSnapshot {
        match self {
            Self::Created(snapshot) | Self::Advanced(snapshot) | Self::Existing(snapshot) => {
                snapshot
            }
        }
    }

    pub const fn changed(self) -> bool {
        !matches!(self, Self::Existing(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDenuoSwapHandshake {
    schema_version: u16,
    policy_fingerprint: ObjectHash,
    session_id: SessionId,
    match_request_id: u64,
    proposal_request_id: Option<u64>,
    match_accepted_at_unix: u64,
    fill_accepted_at_unix: Option<u64>,
    price_round_accepted_at_unix: Option<u64>,
    proposal_accepted_at_unix: Option<u64>,
    hello_accepted_at_unix: Option<u64>,
    intent_hex: String,
    match_request_hex: String,
    fill_grant_hex: Option<String>,
    price_round_hex: Option<String>,
    previous_price_round_hex: Option<String>,
    proposal_hex: Option<String>,
    hello_hex: Option<String>,
}

pub fn load_denuo_swap_handshake(
    store: &WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    session_id: SessionId,
) -> Result<Option<DenuoSwapHandshakeRecord>, MarketError> {
    let id = handshake_record_id(policy, session_id);
    store
        .swap_session::<PersistedDenuoSwapHandshake>(&id)?
        .map(|stored| decode_stored_handshake(policy, stored))
        .transpose()
}

pub fn load_denuo_swap_handshakes(
    store: &WalletStore,
    policy: &DenuoSwapHandshakePolicy,
) -> Result<Vec<DenuoSwapHandshakeRecord>, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedDenuoSwapHandshake>(
        EntityKind::SwapSession,
        &handshake_record_prefix(policy),
        MAX_DENUO_SWAP_HANDSHAKES + 1,
    )?;
    decode_handshakes(policy, stored)
}

/// Admit a canonical match request against an active, locally authenticated
/// intent. The request ID becomes the required correlation ID for the fill
/// grant response on both wallets.
pub fn admit_denuo_match_request(
    store: &mut WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoSwapHandshakeAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::MatchRequest(request) = message else {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    };
    let intent = load_denuo_market_intent(store, policy.intent_policy(), request.intent_id)?
        .ok_or(MarketError::UnknownDenuoMarketIntent)?;
    if !intent.is_active_at(accepted_at_unix) {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    }
    request
        .verify_at(policy.network(), accepted_at_unix)
        .and_then(|_| request.verify_for_intent(&intent.intent))
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?;
    let session_id = SessionId::new(request.swap_session_id);
    if let Some(existing) = load_denuo_swap_handshake(store, policy, session_id)? {
        if existing.match_request_id == request_id
            && existing.intent == intent.intent
            && existing.match_request == request
        {
            return Ok(DenuoSwapHandshakeAdmission::Existing(existing.snapshot()));
        }
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }

    let (existing, lease) = load_handshakes_with_lease(store, policy)?;
    let records = decode_handshakes(policy, existing)?;
    if records.len() >= MAX_DENUO_SWAP_HANDSHAKES {
        return Err(MarketError::DenuoSwapHandshakeCapacity);
    }
    let persisted = PersistedDenuoSwapHandshake {
        schema_version: DENUO_SWAP_HANDSHAKE_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint,
        session_id,
        match_request_id: request_id,
        proposal_request_id: None,
        match_accepted_at_unix: accepted_at_unix,
        fill_accepted_at_unix: None,
        price_round_accepted_at_unix: None,
        proposal_accepted_at_unix: None,
        hello_accepted_at_unix: None,
        intent_hex: encode_hex(&intent.intent)?,
        match_request_hex: encode_hex(&request)?,
        fill_grant_hex: None,
        price_round_hex: None,
        previous_price_round_hex: None,
        proposal_hex: None,
        hello_hex: None,
    };
    store.apply_entity_batch_with_assertions_and_prefix_lease(
        EntityKind::SwapSession,
        &[EntityBatchSave {
            id: handshake_record_id(policy, session_id),
            expected_revision: 0,
            value: persisted,
            updated_at_unix: accepted_at_unix,
        }],
        &[],
        &[],
        lease,
    )?;
    let record = DenuoSwapHandshakeRecord {
        store_revision: 1,
        match_request_id: request_id,
        proposal_request_id: None,
        match_accepted_at_unix: accepted_at_unix,
        fill_accepted_at_unix: None,
        price_round_accepted_at_unix: None,
        proposal_accepted_at_unix: None,
        hello_accepted_at_unix: None,
        intent: intent.intent,
        match_request: request,
        fill_grant: None,
        price_round: None,
        previous_price_round: None,
        proposal: None,
        hello: None,
    };
    Ok(DenuoSwapHandshakeAdmission::Created(record.snapshot()))
}

/// Admit the maker's correlated fill grant using one locally authenticated
/// price round. The round bytes are frozen into the encrypted session record
/// so later board pruning cannot alter the agreed price.
pub fn admit_denuo_fill_grant(
    store: &mut WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoSwapHandshakeAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::FillGrant(grant) = message else {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    };
    let session_id = SessionId::new(grant.swap_session_id);
    let mut record = load_denuo_swap_handshake(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    if request_id != record.match_request_id {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    }
    if let Some(existing) = &record.fill_grant {
        if existing == &grant {
            return Ok(DenuoSwapHandshakeAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }
    let verified_round =
        load_denuo_verified_price_round(store, policy.price_policy(), grant.price_round_hash)?
            .ok_or(MarketError::UnknownDenuoPriceRound)?;
    if verified_round.accepted_at_unix() > accepted_at_unix {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    }
    grant
        .verify_for_request(&record.intent, &record.match_request)
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?;
    grant
        .verify_for_price_round(
            &record.intent,
            verified_round.round(),
            policy.price_policy.verifier()?,
            verified_round.previous_round(),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?;

    let id = handshake_record_id(policy, session_id);
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.fill_grant_hex = Some(encode_hex(&grant)?);
    persisted.price_round_hex = Some(encode_hex(verified_round.round())?);
    persisted.previous_price_round_hex = verified_round
        .previous_round()
        .map(encode_hex)
        .transpose()?;
    persisted.fill_accepted_at_unix = Some(accepted_at_unix);
    persisted.price_round_accepted_at_unix = Some(verified_round.accepted_at_unix());
    let next_revision =
        store.save_swap_session(&id, record.store_revision, &persisted, accepted_at_unix)?;
    record.store_revision = next_revision;
    record.fill_accepted_at_unix = Some(accepted_at_unix);
    record.price_round_accepted_at_unix = Some(verified_round.accepted_at_unix());
    record.fill_grant = Some(grant);
    record.price_round = Some(verified_round.round().clone());
    record.previous_price_round = verified_round.previous_round().cloned();
    Ok(DenuoSwapHandshakeAdmission::Advanced(record.snapshot()))
}

/// Admit the maker-signed, non-funding-capable proposal under a new nonzero
/// correlation ID. The taker returns the accepted hello under this exact ID.
pub fn admit_denuo_swap_proposal(
    store: &mut WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoSwapHandshakeAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionProposal(proposal) = message else {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    };
    let session_id = SessionId::new(proposal.terms().swap_session_id);
    let mut record = load_denuo_swap_handshake(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    if let Some(existing) = &record.proposal {
        if record.proposal_request_id == Some(request_id) && existing == &proposal {
            return Ok(DenuoSwapHandshakeAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }
    verify_proposal(policy, &record, &proposal, accepted_at_unix)?;
    let id = handshake_record_id(policy, session_id);
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.proposal_request_id = Some(request_id);
    persisted.proposal_hex = Some(encode_hex(&proposal)?);
    persisted.proposal_accepted_at_unix = Some(accepted_at_unix);
    let next_revision =
        store.save_swap_session(&id, record.store_revision, &persisted, accepted_at_unix)?;
    record.store_revision = next_revision;
    record.proposal_request_id = Some(request_id);
    record.proposal_accepted_at_unix = Some(accepted_at_unix);
    record.proposal = Some(proposal);
    Ok(DenuoSwapHandshakeAdmission::Advanced(record.snapshot()))
}

/// Admit the taker-countersigned agreement. This compares the complete
/// maker-signed terms byte-for-byte and changes only the taker signature.
pub fn admit_denuo_swap_hello(
    store: &mut WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoSwapHandshakeAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::SwapSessionHello(hello) = message else {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    };
    let session_id = SessionId::new(hello.swap_session_id);
    let mut record = load_denuo_swap_handshake(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    if record.proposal_request_id != Some(request_id) {
        return Err(MarketError::InvalidDenuoSwapHandshake);
    }
    if let Some(existing) = &record.hello {
        if existing == &hello {
            return Ok(DenuoSwapHandshakeAdmission::Existing(record.snapshot()));
        }
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }
    verify_hello(policy, &record, &hello, accepted_at_unix)?;
    let id = handshake_record_id(policy, session_id);
    let mut persisted = encode_persisted(policy, &record)?;
    persisted.hello_hex = Some(encode_hex(&hello)?);
    persisted.hello_accepted_at_unix = Some(accepted_at_unix);
    let next_revision =
        store.save_swap_session(&id, record.store_revision, &persisted, accepted_at_unix)?;
    record.store_revision = next_revision;
    record.hello_accepted_at_unix = Some(accepted_at_unix);
    record.hello = Some(hello);
    Ok(DenuoSwapHandshakeAdmission::Advanced(record.snapshot()))
}

/// Authenticate one direct-peer Denuo settlement status against the exact
/// locally retained bilateral agreement. This function performs no workflow
/// mutation: a counterparty signature is coordination metadata, never proof
/// that the claimed funding, redemption, or refund occurred on either chain.
pub fn validate_denuo_swap_peer_status(
    store: &WalletStore,
    policy: &DenuoSwapHandshakePolicy,
    envelope_bytes: &[u8],
    now_unix: u64,
) -> Result<DenuoSwapPeerStatus, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let status = match message {
        CrossChainMessage::SwapFundingStatus(status) => DenuoSwapPeerStatus::Funding(status),
        CrossChainMessage::SwapRedeemStatus(status) => DenuoSwapPeerStatus::Redeem(status),
        CrossChainMessage::SwapRefundStatus(status) => DenuoSwapPeerStatus::Refund(status),
        _ => return Err(MarketError::InvalidDenuoPeerMessage),
    };
    let record = load_denuo_swap_handshake(store, policy, status.session_id())?
        .ok_or(MarketError::UnknownDenuoSwapHandshake)?;
    let hello = record
        .hello
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    match &status {
        DenuoSwapPeerStatus::Funding(status) => status
            .verify_for_session(hello, policy.network(), now_unix)
            .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
        DenuoSwapPeerStatus::Redeem(status) => status
            .verify_for_session(hello, policy.network(), now_unix)
            .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
        DenuoSwapPeerStatus::Refund(status) => status
            .verify_for_session(hello, policy.network(), now_unix)
            .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
    }
    Ok(status)
}

fn verify_proposal(
    policy: &DenuoSwapHandshakePolicy,
    record: &DenuoSwapHandshakeRecord,
    proposal: &SwapSessionProposal,
    now_unix: u64,
) -> Result<(), MarketError> {
    let grant = record
        .fill_grant
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    let round = record
        .price_round
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    proposal
        .verify_for_grant(
            &record.intent,
            grant,
            round,
            policy.price_policy.verifier()?,
            record.previous_price_round.as_ref(),
            now_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)
}

fn verify_hello(
    policy: &DenuoSwapHandshakePolicy,
    record: &DenuoSwapHandshakeRecord,
    hello: &SwapSessionHello,
    now_unix: u64,
) -> Result<(), MarketError> {
    let proposal = record
        .proposal
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    let grant = record
        .fill_grant
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    let round = record
        .price_round
        .as_ref()
        .ok_or(MarketError::InvalidDenuoSwapHandshake)?;
    hello
        .verify_for_grant(
            &record.intent,
            grant,
            round,
            policy.price_policy.verifier()?,
            record.previous_price_round.as_ref(),
            now_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)?;
    let mut maker_terms = hello.clone();
    maker_terms.taker_signature = [0; 64];
    if proposal.terms() != &maker_terms {
        return Err(MarketError::DenuoSwapHandshakeConflict);
    }
    Ok(())
}

fn decode_stored_handshake(
    policy: &DenuoSwapHandshakePolicy,
    stored: StoredEntity<PersistedDenuoSwapHandshake>,
) -> Result<DenuoSwapHandshakeRecord, MarketError> {
    let value = stored.value;
    if value.schema_version != DENUO_SWAP_HANDSHAKE_SCHEMA_VERSION
        || value.policy_fingerprint != policy.fingerprint
        || value.match_request_id == 0
        || stored.id != handshake_record_id(policy, value.session_id)
    {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    let intent = decode_hex::<MarketIntent>(&value.intent_hex)?;
    let match_request = decode_hex::<MatchRequest>(&value.match_request_hex)?;
    if SessionId::new(match_request.swap_session_id) != value.session_id {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    intent
        .verify_at(policy.network(), value.match_accepted_at_unix)
        .and_then(|_| match_request.verify_at(policy.network(), value.match_accepted_at_unix))
        .and_then(|_| match_request.verify_for_intent(&intent))
        .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;

    let fill_grant = value
        .fill_grant_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;
    let price_round = value
        .price_round_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;
    let previous_price_round = value
        .previous_price_round_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;
    let proposal = value.proposal_hex.as_deref().map(decode_hex).transpose()?;
    let hello = value.hello_hex.as_deref().map(decode_hex).transpose()?;
    if value.fill_accepted_at_unix.is_some() != fill_grant.is_some()
        || fill_grant.is_some() != price_round.is_some()
        || value.price_round_accepted_at_unix.is_some() != price_round.is_some()
        || value.proposal_accepted_at_unix.is_some() != proposal.is_some()
        || value.proposal_request_id.is_some() != proposal.is_some()
        || value.hello_accepted_at_unix.is_some() != hello.is_some()
        || proposal.is_some() && fill_grant.is_none()
        || hello.is_some() && proposal.is_none()
        || previous_price_round.is_some() && price_round.is_none()
        || value.proposal_request_id == Some(0)
    {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    let record = DenuoSwapHandshakeRecord {
        store_revision: stored.revision,
        match_request_id: value.match_request_id,
        proposal_request_id: value.proposal_request_id,
        match_accepted_at_unix: value.match_accepted_at_unix,
        fill_accepted_at_unix: value.fill_accepted_at_unix,
        price_round_accepted_at_unix: value.price_round_accepted_at_unix,
        proposal_accepted_at_unix: value.proposal_accepted_at_unix,
        hello_accepted_at_unix: value.hello_accepted_at_unix,
        intent,
        match_request,
        fill_grant,
        price_round,
        previous_price_round,
        proposal,
        hello,
    };
    if let Some(accepted_at) = record.fill_accepted_at_unix {
        let grant = record
            .fill_grant
            .as_ref()
            .ok_or(MarketError::CorruptDenuoSwapHandshake)?;
        let round = record
            .price_round
            .as_ref()
            .ok_or(MarketError::CorruptDenuoSwapHandshake)?;
        let round_accepted_at = record
            .price_round_accepted_at_unix
            .ok_or(MarketError::CorruptDenuoSwapHandshake)?;
        if round_accepted_at > accepted_at {
            return Err(MarketError::CorruptDenuoSwapHandshake);
        }
        round
            .verify(
                policy.price_policy.verifier()?,
                record.previous_price_round.as_ref(),
                round_accepted_at,
            )
            .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
        grant
            .verify_for_request(&record.intent, &record.match_request)
            .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
        grant
            .verify_for_price_round(
                &record.intent,
                round,
                policy.price_policy.verifier()?,
                record.previous_price_round.as_ref(),
                accepted_at,
            )
            .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    }
    if let (Some(proposal), Some(accepted_at)) =
        (record.proposal.as_ref(), record.proposal_accepted_at_unix)
    {
        verify_proposal(policy, &record, proposal, accepted_at)
            .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    }
    if let (Some(hello), Some(accepted_at)) = (record.hello.as_ref(), record.hello_accepted_at_unix)
    {
        verify_hello(policy, &record, hello, accepted_at)
            .map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    }
    let expected_updated = record.snapshot().last_accepted_at_unix;
    if stored.updated_at_unix != expected_updated || !timestamps_monotonic(&record) {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    Ok(record)
}

fn timestamps_monotonic(record: &DenuoSwapHandshakeRecord) -> bool {
    let timestamps = [
        Some(record.match_accepted_at_unix),
        record.fill_accepted_at_unix,
        record.proposal_accepted_at_unix,
        record.hello_accepted_at_unix,
    ];
    let present = timestamps.into_iter().flatten().collect::<Vec<_>>();
    present.windows(2).all(|window| window[0] <= window[1])
}

fn encode_persisted(
    policy: &DenuoSwapHandshakePolicy,
    record: &DenuoSwapHandshakeRecord,
) -> Result<PersistedDenuoSwapHandshake, MarketError> {
    Ok(PersistedDenuoSwapHandshake {
        schema_version: DENUO_SWAP_HANDSHAKE_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint,
        session_id: SessionId::new(record.match_request.swap_session_id),
        match_request_id: record.match_request_id,
        proposal_request_id: record.proposal_request_id,
        match_accepted_at_unix: record.match_accepted_at_unix,
        fill_accepted_at_unix: record.fill_accepted_at_unix,
        price_round_accepted_at_unix: record.price_round_accepted_at_unix,
        proposal_accepted_at_unix: record.proposal_accepted_at_unix,
        hello_accepted_at_unix: record.hello_accepted_at_unix,
        intent_hex: encode_hex(&record.intent)?,
        match_request_hex: encode_hex(&record.match_request)?,
        fill_grant_hex: record.fill_grant.as_ref().map(encode_hex).transpose()?,
        price_round_hex: record.price_round.as_ref().map(encode_hex).transpose()?,
        previous_price_round_hex: record
            .previous_price_round
            .as_ref()
            .map(encode_hex)
            .transpose()?,
        proposal_hex: record.proposal.as_ref().map(encode_hex).transpose()?,
        hello_hex: record.hello.as_ref().map(encode_hex).transpose()?,
    })
}

trait CanonicalMarketObject: Sized {
    fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError>;
    fn decode_canonical(bytes: &[u8]) -> Result<Self, hns_marketplace_protocol::MarketplaceError>;
}

macro_rules! canonical_object {
    ($($type:ty),+ $(,)?) => {
        $(
            impl CanonicalMarketObject for $type {
                fn encode_canonical(
                    &self,
                ) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError> {
                    self.encode()
                }

                fn decode_canonical(
                    bytes: &[u8],
                ) -> Result<Self, hns_marketplace_protocol::MarketplaceError> {
                    Self::decode(bytes)
                }
            }
        )+
    };
}

canonical_object!(
    MarketIntent,
    MatchRequest,
    FillGrant,
    PriceRound,
    SwapSessionProposal,
    SwapSessionHello,
);

fn encode_hex<T: CanonicalMarketObject>(value: &T) -> Result<String, MarketError> {
    value
        .encode_canonical()
        .map(hex::encode)
        .map_err(|_| MarketError::InvalidDenuoSwapHandshake)
}

fn decode_hex<T: CanonicalMarketObject>(encoded: &str) -> Result<T, MarketError> {
    let bytes = hex::decode(encoded).map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    if hex::encode(&bytes) != encoded {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    let value = T::decode_canonical(&bytes).map_err(|_| MarketError::CorruptDenuoSwapHandshake)?;
    if value.encode_canonical().ok().as_deref() != Some(bytes.as_slice()) {
        return Err(MarketError::CorruptDenuoSwapHandshake);
    }
    Ok(value)
}

fn load_handshakes_with_lease(
    store: &WalletStore,
    policy: &DenuoSwapHandshakePolicy,
) -> Result<
    (
        Vec<StoredEntity<PersistedDenuoSwapHandshake>>,
        EntityPrefixSetLease,
    ),
    MarketError,
> {
    let prefix = handshake_record_prefix(policy);
    store
        .try_with_entity_read_snapshot(|snapshot| {
            let stored = snapshot.list_entities_by_id_prefix(
                EntityKind::SwapSession,
                &prefix,
                MAX_DENUO_SWAP_HANDSHAKES + 1,
            )?;
            let lease = snapshot.entity_prefix_set_lease(
                EntityKind::SwapSession,
                &prefix,
                MAX_DENUO_SWAP_HANDSHAKES + 1,
            )?;
            Ok::<_, StoreError>((stored, lease))
        })
        .map_err(MarketError::from)
}

fn decode_handshakes(
    policy: &DenuoSwapHandshakePolicy,
    stored: Vec<StoredEntity<PersistedDenuoSwapHandshake>>,
) -> Result<Vec<DenuoSwapHandshakeRecord>, MarketError> {
    if stored.len() > MAX_DENUO_SWAP_HANDSHAKES {
        return Err(MarketError::DenuoSwapHandshakeCapacity);
    }
    stored
        .into_iter()
        .map(|stored| decode_stored_handshake(policy, stored))
        .collect()
}

fn handshake_record_prefix(policy: &DenuoSwapHandshakePolicy) -> Vec<u8> {
    let mut id = Vec::with_capacity(DENUO_SWAP_HANDSHAKE_RECORD_PREFIX.len() + 32);
    id.extend_from_slice(DENUO_SWAP_HANDSHAKE_RECORD_PREFIX);
    id.extend_from_slice(policy.fingerprint.as_bytes());
    id
}

fn handshake_record_id(policy: &DenuoSwapHandshakePolicy, session_id: SessionId) -> Vec<u8> {
    let mut id = handshake_record_prefix(policy);
    id.extend_from_slice(session_id.as_bytes());
    id
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        AssetAmount, ChainAnchor, ChainId, DeadlineKind, FundingState,
        MARKETPLACE_PROTOCOL_VERSION, PriceObservation, PriceRoundPolicy, RationalPrice,
        SettlementDeadline, SignedObjectHeader,
    };
    use hns_primitives::BlockHash;

    use super::*;
    use crate::{
        DenuoSwapHandshakeStage, admit_denuo_market_intent, bootstrap_denuo_price_round_cache,
        open_denuo_execution,
    };
    use hns_wallet_bitcoin_kyoto::build_denuo_bitcoin_htlc;

    const MAKER_IDENTITY_SECRET: [u8; 32] = [7; 32];
    const TAKER_IDENTITY_SECRET: [u8; 32] = [6; 32];
    const MAKER_SETTLEMENT_SECRET: [u8; 32] = [9; 32];
    const TAKER_SETTLEMENT_SECRET: [u8; 32] = [8; 32];

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn header(sequence: u64, created_at: u64, expires_at: u64) -> SignedObjectHeader {
        SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at,
            expires_at,
        }
    }

    fn anchors() -> (ChainAnchor, ChainAnchor) {
        (
            ChainAnchor {
                chain: ChainId::HANDSHAKE,
                height: 100,
                block_hash: [3; 32],
            },
            ChainAnchor {
                chain: ChainId::BITCOIN,
                height: 200,
                block_hash: [4; 32],
            },
        )
    }

    fn round_policy() -> PriceRoundPolicy {
        PriceRoundPolicy {
            minimum_reporters: 3,
            minimum_sources: 3,
            maximum_observation_age: 100,
            trim_each_side: 0,
            maximum_movement_basis_points: 2_000,
        }
    }

    fn observation(secret: u8, source: u8, sequence: u64) -> PriceObservation {
        let (hns_anchor, counterchain_anchor) = anchors();
        let mut observation = PriceObservation {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            price: RationalPrice::new(100, 10).expect("price"),
            source_id: [source; 32],
            reporter_public_key: [0; 33],
            observed_at: 110,
            valid_until: 180,
            hns_anchor,
            counterchain_anchor,
            sequence,
            signature: [0; 64],
        };
        observation.sign(&[secret; 32]).expect("sign observation");
        observation
    }

    fn public_key(secret: u8) -> [u8; 33] {
        observation(secret, secret.saturating_add(20), 1).reporter_public_key
    }

    fn price_round() -> PriceRound {
        let (hns_anchor, counterchain_anchor) = anchors();
        let mut round = PriceRound {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            round_id: [10; 32],
            interval_start: 100,
            interval_end: 120,
            canonical_price: RationalPrice::new(1, 1).expect("placeholder"),
            observations: vec![
                observation(1, 21, 1_001),
                observation(2, 22, 1_002),
                observation(3, 23, 1_003),
            ],
            reporter_set: Vec::new(),
            source_set: Vec::new(),
            policy: round_policy(),
            hns_anchor,
            counterchain_anchor,
            valid_until: 170,
            previous_round_hash: [0; 32],
            round_hash: [0; 32],
        };
        round.refresh_derived().expect("derive round");
        round
    }

    fn intent() -> MarketIntent {
        let mut intent = MarketIntent {
            header: header(1, 100, 500),
            intent_id: [0; 32],
            offered_asset: AssetId::HNS,
            maximum_amount: AssetAmount::new(10_000),
            minimum_fill: AssetAmount::new(1_000),
            partial_fills: true,
            signature: [0; 64],
        };
        intent.sign(&MAKER_IDENTITY_SECRET).expect("sign intent");
        intent
    }

    fn match_request(intent: &MarketIntent) -> MatchRequest {
        let mut request = MatchRequest {
            header: header(1, 122, 160),
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            swap_session_id: [12; 32],
            settlement_public_key: public_key(8),
            requested_amount: AssetAmount::new(1_000),
            signature: [0; 64],
        };
        request
            .sign(&TAKER_IDENTITY_SECRET)
            .expect("sign match request");
        request
    }

    fn fill_grant(intent: &MarketIntent, request: &MatchRequest, round: &PriceRound) -> FillGrant {
        let mut grant = FillGrant {
            header: header(2, 125, 155),
            grant_hash: [0; 32],
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            swap_session_id: request.swap_session_id,
            maker_settlement_key: public_key(9),
            counterparty_settlement_key: request.settlement_public_key,
            offered_amount: request.requested_amount,
            received_amount: AssetAmount::new(10_000),
            price_round_hash: round.round_hash,
            reservation_sequence: 1,
            signature: [0; 64],
        };
        grant.sign(&MAKER_IDENTITY_SECRET).expect("sign fill grant");
        grant
    }

    fn maker_proposal(intent: &MarketIntent, grant: &FillGrant) -> SwapSessionProposal {
        let mut session_header = header(3, 126, 150);
        session_header.signer_public_key = intent.header.signer_public_key;
        let mut hello = SwapSessionHello {
            header: session_header,
            fill_grant_hash: grant.grant_hash,
            swap_session_id: grant.swap_session_id,
            maker_settlement_public_key: grant.maker_settlement_key,
            taker_settlement_public_key: grant.counterparty_settlement_key,
            offered_asset: intent.offered_asset,
            offered_amount: grant.offered_amount,
            received_asset: AssetId::BTC,
            received_amount: grant.received_amount,
            price_round_hash: grant.price_round_hash,
            hashlock: [13; 32],
            first_funding_chain: ChainId::HANDSHAKE,
            offered_lock_commitment: [0; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 1_800_000_000,
            },
            offered_minimum_confirmations: 2,
            received_lock_commitment: [0; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 1_700_000_000,
            },
            received_minimum_confirmations: 2,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        };
        hello
            .build_and_bind_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Offered,
                grant.counterparty_settlement_key,
                grant.maker_settlement_key,
            )
            .expect("canonical HNS lock");
        hello.received_lock_commitment =
            build_denuo_bitcoin_htlc(&hello, hns_marketplace_protocol::SwapAssetSide::Received)
                .expect("canonical Bitcoin lock")
                .commitment
                .into_bytes();
        hello
            .into_maker_proposal(&MAKER_SETTLEMENT_SECRET)
            .expect("sign maker proposal")
    }

    fn envelope(message: CrossChainMessage, request_id: u64) -> Vec<u8> {
        message
            .encode_envelope(request_id)
            .expect("canonical Denuo envelope")
    }

    #[test]
    fn two_wallets_persist_the_same_bilateral_funding_agreement() {
        let intent = intent();
        let round = price_round();
        let intent_policy =
            DenuoIntentBoardPolicy::new(network(), MarketPair::HNS_BTC).expect("intent policy");
        let price_policy = DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            round.reporter_set.clone(),
            round.source_set.clone(),
        )
        .expect("price policy");
        let policy = DenuoSwapHandshakePolicy::new(intent_policy, price_policy.clone())
            .expect("handshake policy");
        let intent_envelope = envelope(CrossChainMessage::MarketIntent(intent.clone()), 9);
        let round_envelope = envelope(CrossChainMessage::PriceRound(round.clone()), 0);
        let mut maker_store = WalletStore::create(":memory:", "maker-wallet").expect("maker store");
        let mut taker_store = WalletStore::create(":memory:", "taker-wallet").expect("taker store");
        for store in [&mut maker_store, &mut taker_store] {
            admit_denuo_market_intent(store, &intent_policy, &intent_envelope, 121)
                .expect("admit intent");
            bootstrap_denuo_price_round_cache(store, &price_policy, None, &round_envelope, 121)
                .expect("bootstrap price round");
        }

        let request = match_request(&intent);
        let request_envelope = envelope(CrossChainMessage::MatchRequest(request.clone()), 41);
        for store in [&mut maker_store, &mut taker_store] {
            assert_eq!(
                admit_denuo_match_request(store, &policy, &request_envelope, 123)
                    .expect("admit request")
                    .snapshot()
                    .stage,
                DenuoSwapHandshakeStage::MatchRequested
            );
        }

        let grant = fill_grant(&intent, &request, &round);
        let grant_envelope = envelope(CrossChainMessage::FillGrant(grant.clone()), 41);
        for store in [&mut maker_store, &mut taker_store] {
            assert_eq!(
                admit_denuo_fill_grant(store, &policy, &grant_envelope, 126)
                    .expect("admit grant")
                    .snapshot()
                    .stage,
                DenuoSwapHandshakeStage::FillGranted
            );
        }

        let proposal = maker_proposal(&intent, &grant);
        let proposal_envelope =
            envelope(CrossChainMessage::SwapSessionProposal(proposal.clone()), 77);
        for store in [&mut maker_store, &mut taker_store] {
            assert_eq!(
                admit_denuo_swap_proposal(store, &policy, &proposal_envelope, 127)
                    .expect("admit proposal")
                    .snapshot()
                    .stage,
                DenuoSwapHandshakeStage::MakerProposed
            );
        }

        let hello = proposal
            .clone()
            .accept_taker(network(), 128, &TAKER_SETTLEMENT_SECRET)
            .expect("accept proposal");
        let hello_envelope = envelope(CrossChainMessage::SwapSessionHello(hello.clone()), 77);
        for store in [&mut maker_store, &mut taker_store] {
            let admitted = admit_denuo_swap_hello(store, &policy, &hello_envelope, 128)
                .expect("admit accepted hello");
            assert_eq!(admitted.snapshot().stage, DenuoSwapHandshakeStage::Accepted);
        }

        let session_id = SessionId::new(request.swap_session_id);
        let maker = load_denuo_swap_handshake(&maker_store, &policy, session_id)
            .expect("load maker")
            .expect("maker record");
        let taker = load_denuo_swap_handshake(&taker_store, &policy, session_id)
            .expect("load taker")
            .expect("taker record");
        assert_eq!(maker, taker);
        assert_eq!(maker.hello, Some(hello.clone()));
        assert_eq!(maker.store_revision, 4);

        let maker_execution = open_denuo_execution(&mut maker_store, &policy, session_id, 129)
            .expect("open maker execution");
        let taker_execution = open_denuo_execution(&mut taker_store, &policy, session_id, 129)
            .expect("open taker execution");
        assert_eq!(maker_execution, taker_execution);
        assert_eq!(maker_execution.state, crate::SwapState::TermsFrozen);
        assert!(maker_execution.accepted_denuo_terms.is_some());
        assert_eq!(
            open_denuo_execution(&mut maker_store, &policy, session_id, 1_900_000_000)
                .expect("reopen existing execution"),
            maker_execution,
        );

        let mut funding_status = SwapFundingStatus {
            header: header(4, 129, 200),
            swap_session_id: session_id.into_bytes(),
            chain: ChainId::HANDSHAKE,
            lock_commitment: hello.offered_lock_commitment,
            transaction_id: [42; 32],
            output_index: 0,
            amount: hello.offered_amount,
            confirmations: hello.offered_minimum_confirmations,
            state: FundingState::Confirmed,
            signature: [0; 64],
        };
        funding_status
            .sign(&MAKER_SETTLEMENT_SECRET)
            .expect("sign peer funding status");
        let funding_envelope = envelope(CrossChainMessage::SwapFundingStatus(funding_status), 78);
        for store in [&maker_store, &taker_store] {
            assert!(matches!(
                validate_denuo_swap_peer_status(store, &policy, &funding_envelope, 129)
                    .expect("validate signed peer status"),
                DenuoSwapPeerStatus::Funding(_)
            ));
        }
        // The authenticated peer claim is not sufficient to move durable
        // execution state; each wallet still needs independent chain proof.
        assert_eq!(
            open_denuo_execution(&mut taker_store, &policy, session_id, 1_900_000_000)
                .expect("status does not mutate execution"),
            taker_execution,
        );

        let wrong_correlation = envelope(CrossChainMessage::SwapSessionHello(hello), 78);
        assert_eq!(
            admit_denuo_swap_hello(&mut maker_store, &policy, &wrong_correlation, 129),
            Err(MarketError::InvalidDenuoSwapHandshake)
        );
    }
}
