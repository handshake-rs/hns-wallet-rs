//! Wallet-derived authority for responding to exact direct HNS/BTC offers.
//!
//! The responder initializes the executable swap as maker. The original offer
//! setter countersigns the resulting proposal as the execution taker.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOfferAcceptance, MARKETPLACE_PROTOCOL_VERSION, MarketPair,
    SignedObjectHeader, SwapSessionHello,
};
use hns_wallet_store::{EntityBatchDelete, EntityKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use serde::{Deserialize, Serialize};

use crate::direct_offer::derive_board_identity;
use crate::{
    CrossChainSwapKeyRequest, MarketError, ShakescapeDirectSwapPolicy, SwapParticipant,
    SwapSession, admit_shakescape_direct_offer_acceptance, admit_shakescape_direct_swap_hello,
    allocate_cross_chain_swap_key, derive_cross_chain_swap_key_from_store,
    load_shakescape_direct_offer, load_shakescape_direct_swap, open_shakescape_execution,
};

const STORAGE_VERSION: u16 = 1;
const RECORD_PREFIX: &[u8] = b"local-direct-acceptance/v1/";
const ABANDONMENT_STORAGE_VERSION: u16 = 1;
const ABANDONMENT_RECORD_PREFIX: &[u8] = b"local-direct-acceptance-abandonment/v1/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeHnsForBtcOfferAcceptanceRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    pub hns_fee_reserve_dollarydoos: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeBtcForHnsOfferAcceptanceRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    pub bitcoin_fee_reserve_sats: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeDirectOfferAcceptanceRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    /// Fee reserve in the responder's asset (the offer's received asset).
    pub received_fee_reserve: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeLocalDirectOfferAcceptance {
    pub offer_id: ObjectHash,
    pub session_id: SessionId,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub hns_fee_reserve_dollarydoos: u64,
    pub received_fee_reserve: u64,
    pub offered_asset: AssetId,
    pub offered_amount: u64,
    pub received_asset: AssetId,
    pub received_amount: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeOfferSetterAcceptedSession {
    pub hello: SwapSessionHello,
    pub execution: SwapSession,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedLocalDirectAcceptance {
    pub(crate) storage_version: u16,
    pub(crate) wallet_id: WalletId,
    pub(crate) offer_id: ObjectHash,
    pub(crate) session_id: SessionId,
    pub(crate) received_fee_reserve: u64,
    pub(crate) created_at_unix: u64,
}

/// Durable local-only tombstone for an acceptance abandoned before exact
/// terms were countersigned. Keeping a tombstone instead of deleting the acceptance
/// prevents a delayed maker proposal from reactivating released funds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLocalDirectAcceptanceAbandonment {
    storage_version: u16,
    wallet_id: WalletId,
    offer_id: ObjectHash,
    session_id: SessionId,
    abandoned_at_unix: u64,
}

/// Sign and durably admit one exact acceptance. The session identifier comes
/// from the signed offer; the responding maker has no authority to replace it.
pub fn create_shakescape_hns_for_btc_offer_acceptance(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeHnsForBtcOfferAcceptanceRequest,
) -> Result<ShakescapeLocalDirectOfferAcceptance, MarketError> {
    create_shakescape_direct_offer_acceptance(
        store,
        policy,
        ShakescapeDirectOfferAcceptanceRequest {
            wallet_id: request.wallet_id,
            offer_id: request.offer_id,
            received_fee_reserve: request.hns_fee_reserve_dollarydoos,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            nonce: request.nonce,
        },
    )
}

pub fn create_shakescape_btc_for_hns_offer_acceptance(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeBtcForHnsOfferAcceptanceRequest,
) -> Result<ShakescapeLocalDirectOfferAcceptance, MarketError> {
    create_shakescape_direct_offer_acceptance(
        store,
        policy,
        ShakescapeDirectOfferAcceptanceRequest {
            wallet_id: request.wallet_id,
            offer_id: request.offer_id,
            received_fee_reserve: request.bitcoin_fee_reserve_sats,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            nonce: request.nonce,
        },
    )
}

pub fn create_shakescape_direct_offer_acceptance(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeDirectOfferAcceptanceRequest,
) -> Result<ShakescapeLocalDirectOfferAcceptance, MarketError> {
    validate_direct_acceptance_request(request)?;
    crate::prune_expired_shakescape_direct_market_state(
        store,
        policy,
        request.wallet_id,
        request.created_at_unix,
    )?;
    let offer =
        load_shakescape_direct_offer(store, &policy.board_policy(), request.offer_id.into_bytes())?
            .ok_or(MarketError::UnknownShakescapeDirectOffer)?;
    if !offer.is_active_at(request.created_at_unix)
        || offer.offer.swap_session_id == [0; 32]
        || request.expires_at_unix > offer.offer.header.expires_at
    {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let session_id = SessionId::new(offer.offer.swap_session_id);
    if let Some(existing) = load_local_acceptance(store, request.wallet_id, session_id)? {
        if existing.offer_id != request.offer_id {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
        if load_local_acceptance_abandonment(store, request.wallet_id, session_id)?.is_some() {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
        return project_local_acceptance(store, policy, existing);
    }
    if load_shakescape_direct_swap(store, policy, session_id)?.is_some() {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let settlement = allocate_cross_chain_swap_key(
        store,
        CrossChainSwapKeyRequest {
            wallet_id: request.wallet_id,
            session_id,
            participant: SwapParticipant::Maker,
            network: policy.network(),
        },
        request.created_at_unix,
    )
    .map_err(|_| MarketError::Persistence)?;
    let identity = derive_board_identity(store, request.wallet_id, &policy.board_policy())?;
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&request.nonce[..8]);
    let sequence = (u64::from_be_bytes(sequence_bytes) & i64::MAX as u64).max(1);
    let mut acceptance = DirectOfferAcceptance {
        header: SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: policy.network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at: request.created_at_unix,
            expires_at: request.expires_at_unix,
        },
        offer_id: request.offer_id.into_bytes(),
        swap_session_id: session_id.into_bytes(),
        responding_maker_settlement_public_key: settlement.compressed_public_key(),
        signature: [0; 64],
    };
    acceptance
        .sign(&identity)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let request_id = sequence.max(1);
    let envelope = CrossChainMessage::AcceptDirectOffer(acceptance)
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    admit_shakescape_direct_offer_acceptance(store, policy, &envelope, request.created_at_unix)?;
    let persisted = PersistedLocalDirectAcceptance {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        offer_id: request.offer_id,
        session_id,
        received_fee_reserve: request.received_fee_reserve,
        created_at_unix: request.created_at_unix,
    };
    store.save_entity(
        EntityKind::ShakescapeBoardObject,
        &record_id(request.wallet_id, session_id),
        0,
        &persisted,
        request.created_at_unix,
    )?;
    project_local_acceptance(store, policy, persisted)
}

/// Verify and countersign the maker proposal, admit the accepted hello, and
/// open the restart-safe execution journal before returning bytes to send.
pub fn accept_shakescape_hns_for_btc_maker_proposal(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeOfferSetterAcceptedSession, MarketError> {
    accept_shakescape_direct_maker_proposal(store, policy, wallet_id, session_id, now_unix)
}

pub fn accept_shakescape_direct_maker_proposal(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeOfferSetterAcceptedSession, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let local = crate::direct_offer::load_local_offer(store, wallet_id, record.offer.offer_id)?;
    if local.session_id != session_id || local.offer_id != ObjectHash::new(record.offer.offer_id) {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let expected_taker_key = record.offer.offer_setter_settlement_public_key;
    if let Some(hello) = record.hello {
        let execution = open_shakescape_execution(store, policy, session_id, now_unix)?;
        let request_id = record
            .proposal_request_id
            .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
        let envelope = CrossChainMessage::SwapSessionHello(hello.clone())
            .encode_envelope(request_id)
            .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
        return Ok(ShakescapeOfferSetterAcceptedSession {
            hello,
            execution,
            envelope,
        });
    }
    let proposal = record
        .proposal
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    crate::validate_shakescape_effective_refund_safety(proposal.terms())?;
    let request_id = record
        .proposal_request_id
        .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
    let settlement = derive_cross_chain_swap_key_from_store(
        store,
        CrossChainSwapKeyRequest {
            wallet_id,
            session_id,
            participant: SwapParticipant::Taker,
            network: policy.network(),
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if settlement.public_key() != expected_taker_key {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let hello = settlement
        .accept_taker(proposal, now_unix)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let envelope = CrossChainMessage::SwapSessionHello(hello.clone())
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    admit_shakescape_direct_swap_hello(store, policy, &envelope, now_unix)?;
    let execution = open_shakescape_execution(store, policy, session_id, now_unix)?;
    Ok(ShakescapeOfferSetterAcceptedSession {
        hello,
        execution,
        envelope,
    })
}

pub fn list_local_shakescape_direct_offer_acceptances(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
) -> Result<Vec<ShakescapeLocalDirectOfferAcceptance>, MarketError> {
    store
        .list_entities_by_id_prefix::<PersistedLocalDirectAcceptance>(
            EntityKind::ShakescapeBoardObject,
            &record_prefix(wallet_id),
            crate::MAX_SHAKESCAPE_DIRECT_SWAP_RECORDS,
        )?
        .into_iter()
        .map(|stored| {
            validate_stored(wallet_id, stored)
                .and_then(|row| project_local_acceptance(store, policy, row))
        })
        .collect()
}

/// List local acceptances which still reserve funds but have not reached a
/// durable countersigned execution. These are the only acceptances a user may
/// abandon.
pub fn list_pending_local_shakescape_direct_offer_acceptances(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<Vec<ShakescapeLocalDirectOfferAcceptance>, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let mut pending = Vec::new();
    for acceptance in list_local_shakescape_direct_offer_acceptances(store, policy, wallet_id)? {
        if local_acceptance_has_execution(store, acceptance.session_id)?
            || local_acceptance_is_released(store, policy, wallet_id, &acceptance, now_unix)?
        {
            continue;
        }
        pending.push(acceptance);
    }
    Ok(pending)
}

/// Release one local acceptance before exact terms are countersigned. This
/// cannot abandon a terms-frozen or funded execution. The durable tombstone
/// also makes all delayed maker proposals for the session non-actionable.
pub fn abandon_pending_local_shakescape_direct_offer_acceptance(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeLocalDirectOfferAcceptance, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let local = load_local_acceptance(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let projected = project_local_acceptance(store, policy, local.clone())?;
    let swap = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if swap.hello.is_some() || local_acceptance_has_execution(store, session_id)? {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    if let Some(existing) = load_local_acceptance_abandonment(store, wallet_id, session_id)? {
        if existing.offer_id != local.offer_id {
            return Err(MarketError::CorruptShakescapeDirectSwap);
        }
        return Ok(projected);
    }
    let abandonment = PersistedLocalDirectAcceptanceAbandonment {
        storage_version: ABANDONMENT_STORAGE_VERSION,
        wallet_id,
        offer_id: local.offer_id,
        session_id,
        abandoned_at_unix: now_unix,
    };
    store.save_entity(
        EntityKind::ShakescapeBoardObject,
        &abandonment_record_id(wallet_id, session_id),
        0,
        &abandonment,
        now_unix,
    )?;
    Ok(projected)
}

/// Sum funds committed by local offer responses for one asset.
///
/// Responses make this wallet the execution maker, which funds the offer's
/// received asset on the first chain.
pub fn reserved_local_shakescape_responder_amount(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    asset: AssetId,
    now_unix: u64,
) -> Result<u64, MarketError> {
    if !matches!(asset, AssetId::BTC | AssetId::HNS) || now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let mut total = 0_u64;
    for acceptance in list_local_shakescape_direct_offer_acceptances(store, policy, wallet_id)? {
        if acceptance.received_asset != asset {
            continue;
        }
        let execution = store.load_workflow::<SwapSession>(
            crate::shakescape_execution_workflow_id(acceptance.session_id),
        )?;
        let reserve = match execution.as_ref().map(|row| row.state.state) {
            Some(
                crate::SwapState::TermsFrozen
                | crate::SwapState::RefundsPrepared
                | crate::SwapState::FirstFundingPending,
            ) => true,
            Some(_) => false,
            None => !local_acceptance_is_released(store, policy, wallet_id, &acceptance, now_unix)?,
        };
        if reserve {
            total = total
                .checked_add(acceptance.received_amount)
                .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
        }
    }
    Ok(total)
}

#[doc(hidden)]
pub fn derive_local_hns_for_btc_taker_key(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<(crate::CrossChainSwapKey, u64), MarketError> {
    let result = derive_local_direct_taker_key(store, policy, wallet_id, session_id)?;
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let hello = record
        .hello
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if hello.offered_asset != AssetId::BTC || hello.received_asset != AssetId::HNS {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok(result)
}

#[doc(hidden)]
pub fn derive_local_direct_taker_key(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<(crate::CrossChainSwapKey, u64), MarketError> {
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let local = crate::direct_offer::load_local_offer(store, wallet_id, record.offer.offer_id)?;
    if local.session_id != session_id {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let fee_reserve = local.offered_fee_reserve;
    let expected_key = record.offer.offer_setter_settlement_public_key;
    if record.hello.as_ref().is_none_or(|hello| {
        hello.swap_session_id != session_id.into_bytes()
            || !matches!(
                (hello.offered_asset, hello.received_asset),
                (AssetId::BTC, AssetId::HNS) | (AssetId::HNS, AssetId::BTC)
            )
    }) {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let key = derive_cross_chain_swap_key_from_store(
        store,
        CrossChainSwapKeyRequest {
            wallet_id,
            session_id,
            participant: SwapParticipant::Taker,
            network: policy.network(),
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if key.public_key() != expected_key {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok((key, fee_reserve))
}

fn validate_direct_acceptance_request(
    request: ShakescapeDirectOfferAcceptanceRequest,
) -> Result<(), MarketError> {
    if request.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.offer_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.received_fee_reserve == 0
        || request.created_at_unix == 0
        || request.expires_at_unix <= request.created_at_unix
        || request.nonce.iter().all(|byte| *byte == 0)
    {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    Ok(())
}

fn project_local_acceptance(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    local: PersistedLocalDirectAcceptance,
) -> Result<ShakescapeLocalDirectOfferAcceptance, MarketError> {
    let record = load_shakescape_direct_swap(store, policy, local.session_id)?
        .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
    if record.offer.offer_id != local.offer_id.into_bytes()
        || record.offer.swap_session_id != local.session_id.into_bytes()
        || record.acceptance.swap_session_id != local.session_id.into_bytes()
    {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    let offered_amount = u64::try_from(record.offer.offered_amount.get())
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let received_amount = u64::try_from(record.offer.received_amount.get())
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let (btc_amount_sats, hns_amount_dollarydoos) =
        match (record.offer.offered_asset, record.offer.received_asset) {
            (AssetId::BTC, AssetId::HNS) => (offered_amount, received_amount),
            (AssetId::HNS, AssetId::BTC) => (received_amount, offered_amount),
            _ => return Err(MarketError::InvalidPair),
        };
    let envelope = CrossChainMessage::AcceptDirectOffer(record.acceptance.clone())
        .encode_envelope(record.acceptance_request_id)
        .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    Ok(ShakescapeLocalDirectOfferAcceptance {
        offer_id: local.offer_id,
        session_id: local.session_id,
        btc_amount_sats,
        hns_amount_dollarydoos,
        hns_fee_reserve_dollarydoos: local.received_fee_reserve,
        received_fee_reserve: local.received_fee_reserve,
        offered_asset: record.offer.offered_asset,
        offered_amount,
        received_asset: record.offer.received_asset,
        received_amount,
        created_at_unix: local.created_at_unix,
        expires_at_unix: record.acceptance.header.expires_at,
        envelope,
    })
}

pub(crate) fn load_local_acceptance(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectAcceptance>, MarketError> {
    store
        .load_entity::<PersistedLocalDirectAcceptance>(
            EntityKind::ShakescapeBoardObject,
            &record_id(wallet_id, session_id),
        )?
        .map(|stored| validate_stored(wallet_id, stored))
        .transpose()
}

pub(crate) fn local_acceptance_retirement_delete(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<EntityBatchDelete>, MarketError> {
    if load_local_acceptance(store, wallet_id, session_id)?.is_none() {
        return Ok(None);
    }
    Ok(Some(EntityBatchDelete {
        id: record_id(wallet_id, session_id),
        // Signed local acceptances are immutable; abandonment uses a separate
        // tombstone which cannot coexist with an executable terminal swap.
        expected_revision: 1,
    }))
}

pub(crate) fn local_acceptance_abandonment_retirement_delete(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<EntityBatchDelete>, MarketError> {
    if load_local_acceptance_abandonment(store, wallet_id, session_id)?.is_none() {
        return Ok(None);
    }
    Ok(Some(EntityBatchDelete {
        id: abandonment_record_id(wallet_id, session_id),
        expected_revision: 1,
    }))
}

/// Identify the local atomic-swap taker without deriving settlement key
/// material. The local taker is always the original offer setter.
pub fn is_local_shakescape_direct_taker(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    Ok(crate::direct_offer::load_local_offer_for_session(store, wallet_id, session_id)?.is_some())
}

fn local_acceptance_has_execution(
    store: &WalletStore,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    Ok(store
        .load_workflow::<SwapSession>(crate::shakescape_execution_workflow_id(session_id))?
        .is_some())
}

fn local_acceptance_is_released(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    acceptance: &ShakescapeLocalDirectOfferAcceptance,
    now_unix: u64,
) -> Result<bool, MarketError> {
    if acceptance.expires_at_unix <= now_unix
        || load_local_acceptance_abandonment(store, wallet_id, acceptance.session_id)?.is_some()
    {
        return Ok(true);
    }
    Ok(load_shakescape_direct_offer(
        store,
        &policy.board_policy(),
        acceptance.offer_id.into_bytes(),
    )?
    .is_some_and(|offer| !offer.is_active_at(now_unix)))
}

pub(crate) fn is_local_acceptance_abandoned(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    Ok(load_local_acceptance_abandonment(store, wallet_id, session_id)?.is_some())
}

fn load_local_acceptance_abandonment(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectAcceptanceAbandonment>, MarketError> {
    load_abandonment(
        store,
        wallet_id,
        session_id,
        abandonment_record_id(wallet_id, session_id),
    )
}

fn load_abandonment(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    expected_id: Vec<u8>,
) -> Result<Option<PersistedLocalDirectAcceptanceAbandonment>, MarketError> {
    store
        .load_entity::<PersistedLocalDirectAcceptanceAbandonment>(
            EntityKind::ShakescapeBoardObject,
            &expected_id,
        )?
        .map(|stored| {
            let row = stored.value;
            if stored.revision != 1
                || row.storage_version != ABANDONMENT_STORAGE_VERSION
                || row.wallet_id != wallet_id
                || row.session_id != session_id
                || row.offer_id.as_bytes().iter().all(|byte| *byte == 0)
                || row.abandoned_at_unix == 0
                || row.abandoned_at_unix != stored.updated_at_unix
                || stored.id != expected_id
            {
                return Err(MarketError::CorruptShakescapeDirectSwap);
            }
            Ok(row)
        })
        .transpose()
}

fn validate_stored(
    wallet_id: WalletId,
    stored: hns_wallet_store::StoredEntity<PersistedLocalDirectAcceptance>,
) -> Result<PersistedLocalDirectAcceptance, MarketError> {
    let row = stored.value;
    if stored.revision != 1
        || row.storage_version != STORAGE_VERSION
        || row.wallet_id != wallet_id
        || row.offer_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.session_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.received_fee_reserve == 0
        || row.created_at_unix != stored.updated_at_unix
        || stored.id != record_id(wallet_id, row.session_id)
    {
        return Err(MarketError::CorruptShakescapeDirectSwap);
    }
    Ok(row)
}

fn record_prefix(wallet_id: WalletId) -> Vec<u8> {
    let mut id = Vec::with_capacity(RECORD_PREFIX.len() + 16);
    id.extend_from_slice(RECORD_PREFIX);
    id.extend_from_slice(wallet_id.as_bytes());
    id
}

fn record_id(wallet_id: WalletId, session_id: SessionId) -> Vec<u8> {
    let mut id = record_prefix(wallet_id);
    id.extend_from_slice(session_id.as_bytes());
    id
}

fn abandonment_record_id(wallet_id: WalletId, session_id: SessionId) -> Vec<u8> {
    let mut id = Vec::with_capacity(ABANDONMENT_RECORD_PREFIX.len() + 16 + 32);
    id.extend_from_slice(ABANDONMENT_RECORD_PREFIX);
    id.extend_from_slice(wallet_id.as_bytes());
    id.extend_from_slice(session_id.as_bytes());
    id
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{ChainId, NetworkBinding};
    use hns_wallet_store::{RECOVERY_SEED_BYTES, SecretKind};

    use super::*;
    use crate::{
        ShakescapeBtcForHnsMakerProposalRequest, ShakescapeBtcForHnsOfferRequest,
        ShakescapeDirectOfferBoardPolicy, ShakescapeHnsForBtcOfferRequest,
        accept_shakescape_direct_maker_proposal, cancel_shakescape_local_direct_offer,
        create_shakescape_btc_for_hns_maker_proposal, create_shakescape_btc_for_hns_offer,
        create_shakescape_direct_maker_proposal, create_shakescape_hns_for_btc_offer,
    };

    const PASSPHRASE: &str = "two-party direct atomic swap test";
    const START: u64 = 1_700_000_000;

    fn policy() -> ShakescapeDirectSwapPolicy {
        use bdk_wallet::bitcoin::hashes::Hash;
        let hns =
            hns_wallet_hns::direct_shakescape_network_binding(hns_wallet_hns::HnsNetwork::Mainnet)
                .unwrap();
        ShakescapeDirectSwapPolicy::new(
            ShakescapeDirectOfferBoardPolicy::new(NetworkBinding {
                hns_magic: hns.magic,
                hns_genesis: hns.genesis,
                counterchain: ChainId::BITCOIN,
                counterchain_network: 1,
                counterchain_genesis: bdk_wallet::bitcoin::blockdata::constants::genesis_block(
                    bdk_wallet::bitcoin::Network::Bitcoin,
                )
                .block_hash()
                .to_byte_array(),
            })
            .expect("board policy"),
        )
        .expect("swap policy")
    }

    fn store(wallet_id: WalletId, seed_byte: u8) -> WalletStore {
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("store");
        store
            .put_secret(
                wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[seed_byte; RECOVERY_SEED_BYTES],
                1,
            )
            .expect("seed");
        store
    }

    fn assert_seed_restore_retains_both_contract_authorities(
        hello: &SwapSessionHello,
        maker_seed: u8,
        taker_seed: u8,
    ) {
        use hns_marketplace_protocol::SwapAssetSide;
        use hns_wallet_chain_api::SettlementSigner;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};

        hello
            .verify_agreement(policy().network())
            .expect("authenticated public terms");
        // Exercise the publication format for both assets and both offer
        // directions. These tests authenticate data, not transaction ancestry.
        for side in [SwapAssetSide::Offered, SwapAssetSide::Received] {
            let publication = crate::SwapRecoveryPublication::new(hello, side, policy().network())
                .expect("bounded chain recovery publication");
            let restored_publication = crate::SwapRecoveryPublication::decode(
                policy().network(),
                publication.chain(),
                publication.marker(),
                publication.frames(),
            )
            .expect("authenticated published terms");
            assert_eq!(
                restored_publication.terms(),
                &crate::SwapRecoveryTerms::from_hello(hello, policy().network())
                    .expect("canonical recovery terms")
            );
            let mut truncated = publication.frames().to_vec();
            truncated.pop();
            assert!(
                crate::SwapRecoveryPublication::decode(
                    policy().network(),
                    publication.chain(),
                    publication.marker(),
                    &truncated,
                )
                .is_err()
            );
            let mut changed = publication.frames().to_vec();
            changed[0][4] ^= 1;
            assert!(
                crate::SwapRecoveryPublication::decode(
                    policy().network(),
                    publication.chain(),
                    publication.marker(),
                    &changed,
                )
                .is_err()
            );
            let mut reordered = publication.frames().to_vec();
            reordered.swap(0, 1);
            assert!(
                crate::SwapRecoveryPublication::decode(
                    policy().network(),
                    publication.chain(),
                    publication.marker(),
                    &reordered,
                )
                .is_err()
            );
            let mut wrong_network = policy().network();
            wrong_network.counterchain_genesis[0] ^= 1;
            assert!(
                crate::SwapRecoveryPublication::decode(
                    wrong_network,
                    publication.chain(),
                    publication.marker(),
                    publication.frames(),
                )
                .is_err()
            );
        }
        let (btc_side, hns_side, hns_receiver, hns_refund) = if hello.offered_asset == AssetId::BTC
        {
            (
                SwapAssetSide::Offered,
                SwapAssetSide::Received,
                hello.maker_settlement_public_key,
                hello.taker_settlement_public_key,
            )
        } else {
            (
                SwapAssetSide::Received,
                SwapAssetSide::Offered,
                hello.taker_settlement_public_key,
                hello.maker_settlement_public_key,
            )
        };
        let bitcoin = hns_wallet_bitcoin_kyoto::build_shakescape_bitcoin_htlc(hello, btc_side)
            .expect("canonical Bitcoin contract");
        let hns = hello
            .build_hns_htlc(hns_side, hns_receiver, hns_refund)
            .expect("canonical HNS contract");
        let (bitcoin_commitment, hns_commitment) = if hello.offered_asset == AssetId::BTC {
            (
                hello.offered_lock_commitment,
                hello.received_lock_commitment,
            )
        } else {
            (
                hello.received_lock_commitment,
                hello.offered_lock_commitment,
            )
        };
        assert_eq!(bitcoin.commitment.into_bytes(), bitcoin_commitment);
        assert_eq!(hns.descriptor_hash, hns_commitment);

        for (participant, seed, profile, expected_key, funding_asset) in [
            (
                SwapParticipant::Maker,
                maker_seed,
                91,
                hello.maker_settlement_public_key,
                hello.offered_asset,
            ),
            (
                SwapParticipant::Taker,
                taker_seed,
                92,
                hello.taker_settlement_public_key,
                hello.received_asset,
            ),
        ] {
            // Publish complete funding ancestry, then retain only the public
            // chain transactions. The fresh store below has none of the
            // original offers, acceptances, allocations or execution journals.
            let wallet_id = WalletId::new([profile; 16]);
            let funded = published_owned_funding(hello, participant, seed, wallet_id);
            if let Some(lock) = &funded.bitcoin {
                assert_eq!(lock.htlc, bitcoin.htlc);
                assert_eq!(lock.value_sats, bitcoin.value_sats);
            }
            if let Some((descriptor, _)) = &funded.hns {
                assert_eq!(*descriptor, hns.descriptor);
            }
            let mut restored = store(wallet_id, seed);
            let request = CrossChainSwapKeyRequest {
                wallet_id,
                session_id: SessionId::new(hello.swap_session_id),
                participant,
                network: hello.header.network,
            };
            assert!(
                crate::load_cross_chain_swap_key_allocation(
                    &restored,
                    wallet_id,
                    request.session_id,
                    participant,
                )
                .expect("fresh allocation lookup")
                .is_none()
            );
            let recovered = crate::retain_recovered_swap_candidate(
                &mut restored,
                wallet_id,
                &funded.terms,
                funded.side,
                funded.transaction,
                funded.output_index,
                policy().network(),
                START + 40,
            )
            .expect("reconstructed owned allocation without original records")
            .expect("seed owns the recovered contract");
            assert_eq!(recovered.participant, participant);
            let key = derive_cross_chain_swap_key_from_store(&restored, request)
                .expect("restored signing authority");
            assert_eq!(key.public_key(), expected_key);
            assert_funded_refund(&funded, &key);
            let counterparty = if participant == SwapParticipant::Maker {
                SwapParticipant::Taker
            } else {
                SwapParticipant::Maker
            };
            let counterparty_seed = if counterparty == SwapParticipant::Maker {
                maker_seed
            } else {
                taker_seed
            };
            let receiving = published_owned_funding(
                hello,
                counterparty,
                counterparty_seed,
                WalletId::new([94; 16]),
            );
            let maker_origin = store(WalletId::new([95; 16]), maker_seed);
            let preimage = crate::direct_offer::derive_maker_preimage(
                &maker_origin,
                WalletId::new([95; 16]),
                request.session_id,
                funded.terms.direct_offer_id,
            )
            .unwrap();
            assert_funded_redeem(&receiving, &key, *preimage.expose_for_settlement());
            if funding_asset == AssetId::BTC {
                assert_eq!(bitcoin.htlc.refund_public_key.as_slice(), key.public_key());
                assert_eq!(hns.descriptor.receiver_public_key, key.public_key());
            } else {
                assert_eq!(hns.descriptor.refund_public_key, key.public_key());
                assert_eq!(
                    bitcoin.htlc.receiver_public_key.as_slice(),
                    key.public_key()
                );
            }
            // Verify ownership of the authorities in both canonical contracts.
            // These are digest signatures, not funded transaction broadcasts.
            let verifier = VerifyingKey::from_sec1_bytes(&expected_key).expect("public authority");
            for digest in [bitcoin_commitment, hns_commitment] {
                let signature =
                    Signature::from_slice(&key.sign_digest(digest).expect("restored signature"))
                        .expect("compact signature");
                verifier
                    .verify_prehash(&digest, &signature)
                    .expect("valid restored signature");
            }
        }
        let wrong_wallet_id = WalletId::new([93; 16]);
        let mut wrong_wallet = store(wrong_wallet_id, 0xf1);
        assert!(
            crate::recover_cross_chain_swap_key_allocation(
                &mut wrong_wallet,
                wrong_wallet_id,
                &crate::SwapRecoveryTerms::from_hello(hello, policy().network())
                    .expect("public terms"),
                policy().network(),
                START + 40,
            )
            .is_err()
        );
        for participant in [SwapParticipant::Maker, SwapParticipant::Taker] {
            assert!(
                crate::load_cross_chain_swap_key_allocation(
                    &wrong_wallet,
                    wrong_wallet_id,
                    SessionId::new(hello.swap_session_id),
                    participant,
                )
                .expect("rejected ownership leaves no allocation")
                .is_none()
            );
        }
    }

    struct PublishedFundingFixture {
        terms: crate::SwapRecoveryTerms,
        side: hns_marketplace_protocol::SwapAssetSide,
        transaction: hns_wallet_types::TransactionHash,
        output_index: u32,
        bitcoin: Option<hns_wallet_bitcoin_kyoto::VerifiedBitcoinLock>,
        hns: Option<(hns_swap::HnsHtlc, hns_transaction::Coin)>,
    }

    fn published_owned_funding(
        hello: &SwapSessionHello,
        participant: SwapParticipant,
        seed: u8,
        wallet_id: WalletId,
    ) -> PublishedFundingFixture {
        use bdk_wallet::bitcoin::{self, hashes::Hash};
        use hns_marketplace_protocol::SwapAssetSide;
        let side = match participant {
            SwapParticipant::Maker => SwapAssetSide::Offered,
            SwapParticipant::Taker => SwapAssetSide::Received,
        };
        let publication =
            crate::SwapRecoveryPublication::new(hello, side, policy().network()).unwrap();
        if publication.chain() == ChainId::BITCOIN {
            let mut wallet = hns_wallet_bitcoin_kyoto::create_descriptor_wallet_from_seed(
                &[seed; 64],
                bitcoin::Network::Bitcoin,
            )
            .unwrap();
            let receive = wallet
                .reveal_next_address(bdk_wallet::KeychainKind::External)
                .address;
            let deposit = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([42; 32]),
                        vout: 0,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(10_000_000),
                    script_pubkey: receive.script_pubkey(),
                }],
            };
            let mut update = bdk_wallet::chain::TxUpdate::default();
            update.anchors.insert((
                bdk_wallet::chain::ConfirmationBlockTime {
                    block_id: wallet.latest_checkpoint().block_id(),
                    confirmation_time: 1,
                },
                deposit.compute_txid(),
            ));
            update.txs.push(std::sync::Arc::new(deposit));
            wallet
                .apply_update(bdk_wallet::Update {
                    tx_update: update,
                    ..Default::default()
                })
                .unwrap();
            let funded = hns_wallet_bitcoin_kyoto::prepare_bitcoin_recoverable_htlc_funding(
                &mut wallet,
                &hns_wallet_bitcoin_kyoto::bitcoin_value_runtime_permit().unwrap(),
                &publication,
                1,
                1_000,
                &[],
            )
            .unwrap();
            let mut seed_only = hns_wallet_bitcoin_kyoto::create_descriptor_wallet_from_seed(
                &[seed; 64],
                bitcoin::Network::Bitcoin,
            )
            .unwrap();
            let _ = seed_only
                .reveal_addresses_to(bdk_wallet::KeychainKind::Internal, 0)
                .count();
            for raw in funded
                .publication_transactions()
                .iter()
                .map(Vec::as_slice)
                .chain(std::iter::once(funded.funding.raw_transaction()))
            {
                seed_only.apply_unconfirmed_txs([(
                    bitcoin::consensus::deserialize::<bitcoin::Transaction>(raw).unwrap(),
                    1,
                )]);
            }
            let mut contracts = hns_wallet_bitcoin_kyoto::discover_bitcoin_recovery_contracts(
                &seed_only,
                policy().network(),
            )
            .unwrap();
            assert_eq!(contracts.len(), 1);
            let recovered = contracts.pop().unwrap();
            PublishedFundingFixture {
                terms: recovered.terms,
                side: recovered.side,
                transaction: recovered.lock.funding_txid,
                output_index: recovered.lock.output_index,
                bitcoin: Some(recovered.lock),
                hns: None,
            }
        } else {
            let origin = store(wallet_id, seed);
            let config = hns_wallet_hns::HnsRuntimeConfig::default_non_value(
                wallet_id,
                hns_wallet_types::AccountId::new([9; 16]),
                hns_wallet_hns::HnsBootstrapPolicy::new(hns_wallet_hns::HnsNetwork::Mainnet, 0),
            )
            .unwrap();
            let account = hns_wallet_hns::HnsAccountRecord::initial_non_value(config).unwrap();
            let derivation = hns_wallet_types::DerivationReference {
                role: hns_wallet_types::KeyRole::HnsCoin,
                account: 0,
                change: 0,
                index: 0,
            };
            let public =
                hns_wallet_hns::derive_hns_account_public_key(&origin, &account, derivation)
                    .unwrap();
            let address =
                hns_wallet_hns::receive_address(hns_wallet_hns::HnsNetwork::Mainnet, &public)
                    .unwrap();
            let (_, _, program) = bech32::segwit::decode(&address).unwrap();
            let coin = hns_wallet_hns::TrackedHnsCoin {
                coin: hns_wallet_hns::WalletCoin {
                    outpoint: hns_wallet_hns::HnsOutpoint {
                        transaction: hns_wallet_types::TransactionHash::new([42; 32]),
                        output_index: 0,
                    },
                    value: hns_wallet_types::BaseUnits::new(100_000_000),
                    confirmation_count: 2,
                    confirmed_height: Some(1),
                    coinbase: false,
                    covenant: hns_covenants::Covenant::default().encode().unwrap(),
                    name_locked: false,
                },
                derivation,
                address_program: program,
            };
            let funded = hns_wallet_hns::prepare_hns_recoverable_funding(
                &origin,
                &account,
                vec![coin],
                &publication,
                hns_wallet_types::BaseUnits::new(1_000),
                hns_wallet_types::BaseUnits::new(10_000),
            )
            .unwrap();
            let mut chain_transactions = funded
                .publication_transactions()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
            chain_transactions.push(funded.funding_transaction().to_vec());
            // Discard the source store: discovery consumes only chain bytes.
            drop(origin);
            let mut contracts = hns_wallet_hns::discover_hns_recovery_contracts(
                policy().network(),
                &chain_transactions,
            )
            .unwrap();
            assert_eq!(contracts.len(), 1);
            let recovered = contracts.pop().unwrap();
            let output = recovered.descriptor.funding_output().unwrap();
            let coin = hns_transaction::Coin {
                outpoint: hns_transaction::Outpoint {
                    transaction_hash: hns_primitives::TransactionHash::new(
                        recovered.funding_id.into_bytes(),
                    ),
                    index: recovered.output_index,
                },
                value: output.value,
                height: hns_primitives::Height::new(1),
                coinbase: false,
                address: output.address,
                covenant: output.covenant,
            };
            PublishedFundingFixture {
                terms: recovered.terms,
                side: recovered.side,
                transaction: recovered.funding_id,
                output_index: recovered.output_index,
                bitcoin: None,
                hns: Some((recovered.descriptor, coin)),
            }
        }
    }

    fn assert_funded_redeem(
        funded: &PublishedFundingFixture,
        key: &crate::CrossChainSwapKey,
        preimage: [u8; 32],
    ) {
        use hns_wallet_chain_api::SettlementSigner;
        if let Some(lock) = &funded.bitcoin {
            use bdk_wallet::bitcoin::{self, hashes::Hash};
            let raw = hns_wallet_bitcoin_kyoto::sign_bitcoin_htlc_spend_with_settlement_signer(
                lock,
                &hns_wallet_bitcoin_kyoto::bitcoin_value_runtime_permit().unwrap(),
                hns_wallet_bitcoin_kyoto::BitcoinHtlcSpendRequest {
                    destination: bitcoin::ScriptBuf::new_p2wpkh(
                        &bitcoin::WPubkeyHash::from_byte_array([8; 20]),
                    ),
                    fee_sats: 100,
                    branch: hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Redeem,
                    preimage: Some(preimage),
                    chain_context: hns_wallet_bitcoin_kyoto::BitcoinChainLockContext {
                        next_block_height: 1,
                        median_time_past: 1,
                    },
                },
                key,
            )
            .unwrap();
            let verified = hns_wallet_bitcoin_kyoto::verify_signed_bitcoin_htlc_spend(
                &raw,
                lock,
                hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Redeem,
            )
            .unwrap();
            assert_eq!(verified.revealed_preimage, Some(preimage));
        }
        if let Some((descriptor, coin)) = &funded.hns {
            let mut redeem = hns_transaction::Transaction {
                version: 0,
                locktime: 0,
                inputs: vec![hns_transaction::Input {
                    previous_output: coin.outpoint,
                    sequence: u32::MAX,
                    witness: hns_transaction::Witness::default(),
                }],
                outputs: vec![hns_transaction::Output {
                    value: hns_primitives::Dollarydoos::new(coin.value.get() - 100),
                    address: hns_transaction::Address::new(0, vec![8; 20]).unwrap(),
                    covenant: hns_covenants::Covenant::default(),
                }],
            };
            let mut signature = key
                .sign_digest(descriptor.signature_hash(&redeem, 0, coin).unwrap())
                .unwrap()
                .to_vec();
            signature.push(hns_swap::HNS_HTLC_SIGHASH);
            redeem.inputs[0].witness = descriptor
                .redeem_witness(&signature.try_into().unwrap(), &preimage)
                .unwrap();
            assert_eq!(
                descriptor
                    .extract_preimage(&redeem.inputs[0].witness)
                    .unwrap(),
                preimage
            );
            assert!(matches!(
                descriptor.verify_spend(&redeem, 0, coin).unwrap(),
                hns_swap::HnsHtlcSpend::Redeem { .. }
            ));
        }
    }

    fn assert_funded_refund(funded: &PublishedFundingFixture, key: &crate::CrossChainSwapKey) {
        use hns_wallet_chain_api::SettlementSigner;
        if let Some(lock) = &funded.bitcoin {
            use bdk_wallet::bitcoin::{self, hashes::Hash};
            let destination =
                bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([8; 20]));
            let deadline = lock.htlc.refund_locktime;
            let request = hns_wallet_bitcoin_kyoto::BitcoinHtlcSpendRequest {
                destination,
                fee_sats: 100,
                branch: hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Refund,
                preimage: None,
                chain_context: hns_wallet_bitcoin_kyoto::BitcoinChainLockContext {
                    next_block_height: 1,
                    median_time_past: deadline + 1,
                },
            };
            let raw = hns_wallet_bitcoin_kyoto::sign_bitcoin_htlc_spend_with_settlement_signer(
                lock,
                &hns_wallet_bitcoin_kyoto::bitcoin_value_runtime_permit().unwrap(),
                request.clone(),
                key,
            )
            .unwrap();
            hns_wallet_bitcoin_kyoto::verify_signed_bitcoin_htlc_spend(
                &raw,
                lock,
                hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Refund,
            )
            .unwrap();
            let mut premature = request;
            premature.chain_context.median_time_past = deadline;
            assert!(
                hns_wallet_bitcoin_kyoto::sign_bitcoin_htlc_spend_with_settlement_signer(
                    lock,
                    &hns_wallet_bitcoin_kyoto::bitcoin_value_runtime_permit().unwrap(),
                    premature,
                    key
                )
                .is_err()
            );
        }
        if let Some((descriptor, coin)) = &funded.hns {
            let mut refund = hns_transaction::Transaction {
                version: 0,
                locktime: descriptor.refund_locktime,
                inputs: vec![hns_transaction::Input {
                    previous_output: coin.outpoint,
                    sequence: u32::MAX - 1,
                    witness: hns_transaction::Witness::default(),
                }],
                outputs: vec![hns_transaction::Output {
                    value: hns_primitives::Dollarydoos::new(coin.value.get() - 100),
                    address: hns_transaction::Address::new(0, vec![8; 20]).unwrap(),
                    covenant: hns_covenants::Covenant::default(),
                }],
            };
            let mut signature = key
                .sign_digest(descriptor.signature_hash(&refund, 0, coin).unwrap())
                .unwrap()
                .to_vec();
            signature.push(hns_swap::HNS_HTLC_SIGHASH);
            refund.inputs[0].witness = descriptor
                .refund_witness(&signature.try_into().unwrap())
                .unwrap();
            assert_eq!(
                descriptor.verify_spend(&refund, 0, coin).unwrap(),
                hns_swap::HnsHtlcSpend::Refund
            );
            let mut premature = refund;
            premature.locktime -= 1;
            let mut signature = key
                .sign_digest(descriptor.signature_hash(&premature, 0, coin).unwrap())
                .unwrap()
                .to_vec();
            signature.push(hns_swap::HNS_HTLC_SIGHASH);
            premature.inputs[0].witness = descriptor
                .refund_witness(&signature.try_into().unwrap())
                .unwrap();
            assert!(descriptor.verify_spend(&premature, 0, coin).is_err());
        }
    }

    #[test]
    fn two_wallets_reach_the_same_countersigned_restart_safe_execution() {
        let policy = policy();
        let offer_setter_id = WalletId::new([3; 16]);
        let responder_id = WalletId::new([4; 16]);
        let mut offer_setter_store = store(offer_setter_id, 0x31);
        let mut responder_store = store(responder_id, 0x41);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut offer_setter_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: offer_setter_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [7; 32],
            },
        )
        .expect("offer-setter intent");
        let signed_offer = load_shakescape_direct_offer(
            &offer_setter_store,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer-setter intent")
        .expect("offer-setter intent exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        crate::admit_shakescape_direct_offer(
            &mut responder_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("responder admits offer");

        let acceptance = create_shakescape_hns_for_btc_offer_acceptance(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcOfferAcceptanceRequest {
                wallet_id: responder_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [8; 32],
            },
        )
        .expect("responder signs acceptance");
        crate::admit_shakescape_direct_offer_acceptance(
            &mut offer_setter_store,
            &policy,
            &acceptance.envelope,
            START + 10,
        )
        .expect("offer setter admits acceptance");
        let (original_request_id, replay_message) =
            CrossChainMessage::decode_envelope(&acceptance.envelope)
                .expect("decode durable acceptance");
        let replay_envelope = replay_message
            .encode_envelope(original_request_id + 1)
            .expect("re-encode replay on a new socket sequence");
        let replay = crate::admit_shakescape_direct_offer_acceptance(
            &mut offer_setter_store,
            &policy,
            &replay_envelope,
            START + 11,
        )
        .expect("identical signed acceptance is idempotent across request IDs");
        assert!(matches!(
            replay,
            crate::ShakescapeDirectSwapAdmission::Existing(snapshot)
                if snapshot.acceptance_request_id == original_request_id
        ));

        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut responder_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: responder_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 4_200,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 2,
            },
        )
        .expect("maker proposal");
        crate::admit_shakescape_direct_swap_proposal(
            &mut offer_setter_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("offer setter admits proposal");
        let accepted = accept_shakescape_hns_for_btc_maker_proposal(
            &mut offer_setter_store,
            &policy,
            offer_setter_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("offer setter countersigns proposal");
        crate::admit_shakescape_direct_swap_hello(
            &mut responder_store,
            &policy,
            &accepted.envelope,
            START + 30,
        )
        .expect("responder-maker admits hello");
        let maker_execution = open_shakescape_execution(
            &mut responder_store,
            &policy,
            offer.offer.session_id,
            START + 30,
        )
        .expect("maker execution");
        assert_seed_restore_retains_both_contract_authorities(&accepted.hello, 0x41, 0x31);
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(
            list_local_shakescape_direct_offer_acceptances(&responder_store, &policy, responder_id)
                .expect("local acceptances"),
            vec![acceptance]
        );
        let retried = accept_shakescape_hns_for_btc_maker_proposal(
            &mut offer_setter_store,
            &policy,
            offer_setter_id,
            offer.offer.session_id,
            START + 31,
        )
        .expect("idempotent acceptance");
        assert_eq!(retried.envelope, accepted.envelope);
        assert_eq!(retried.execution, accepted.execution);

        let mut maker_execution = open_shakescape_execution(
            &mut responder_store,
            &policy,
            offer.offer.session_id,
            START + 31,
        )
        .expect("responder-maker execution");
        let workflow_id = crate::shakescape_execution_workflow_id(offer.offer.session_id);
        for (evidence, now_unix) in [
            (crate::VerifiedEvidence::RefundsValidated, START + 32),
            (crate::VerifiedEvidence::FundingReady, START + 33),
            (
                crate::VerifiedEvidence::FirstFundingConfirmed {
                    evidence: ObjectHash::new([0x91; 32]),
                },
                START + 34,
            ),
        ] {
            let mut journal = crate::WalletStoreJournal {
                store: &mut responder_store,
                workflow_id,
                updated_at_unix: now_unix,
            };
            maker_execution
                .apply(evidence, now_unix, &mut journal)
                .expect("advance independently verified first funding");
        }
        assert_eq!(maker_execution.state, crate::SwapState::FirstFunded);
        assert_eq!(
            reserved_local_shakescape_responder_amount(
                &responder_store,
                &policy,
                responder_id,
                AssetId::HNS,
                START + 619,
            )
            .expect("first-funding amount is consumed"),
            0,
        );
    }

    #[test]
    fn btc_responder_maker_and_hns_offer_setter_reach_countersigned_execution() {
        let policy = policy();
        let offer_setter_id = WalletId::new([5; 16]);
        let responder_id = WalletId::new([6; 16]);
        let mut offer_setter_store = store(offer_setter_id, 0x51);
        let mut responder_store = store(responder_id, 0x61);
        let offer = create_shakescape_hns_for_btc_offer(
            &mut offer_setter_store,
            &policy.board_policy(),
            ShakescapeHnsForBtcOfferRequest {
                wallet_id: offer_setter_id,
                hns_amount_dollarydoos: 2_000_000,
                btc_amount_sats: 9_000,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [9; 32],
            },
        )
        .expect("HNS offer-setter intent");
        let signed_offer = load_shakescape_direct_offer(
            &offer_setter_store,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load HNS offer")
        .expect("HNS offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        crate::admit_shakescape_direct_offer(
            &mut responder_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("BTC responder admits offer");

        let acceptance = create_shakescape_btc_for_hns_offer_acceptance(
            &mut responder_store,
            &policy,
            ShakescapeBtcForHnsOfferAcceptanceRequest {
                wallet_id: responder_id,
                offer_id: offer.offer.offer_id,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [10; 32],
            },
        )
        .expect("BTC responder signs acceptance");
        crate::admit_shakescape_direct_offer_acceptance(
            &mut offer_setter_store,
            &policy,
            &acceptance.envelope,
            START + 10,
        )
        .expect("HNS offer setter admits acceptance");

        let proposal = create_shakescape_direct_maker_proposal(
            &mut responder_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: responder_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 4_200,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 2,
            },
        )
        .expect("BTC responder-maker proposal");
        assert_eq!(proposal.proposal.terms().offered_asset, AssetId::BTC);
        assert_eq!(proposal.proposal.terms().received_asset, AssetId::HNS);
        assert_eq!(
            proposal.proposal.terms().first_funding_chain,
            ChainId::BITCOIN
        );
        crate::admit_shakescape_direct_swap_proposal(
            &mut offer_setter_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("HNS offer-setter taker admits proposal");
        let accepted = accept_shakescape_direct_maker_proposal(
            &mut offer_setter_store,
            &policy,
            offer_setter_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("HNS offer-setter taker countersigns proposal");
        crate::admit_shakescape_direct_swap_hello(
            &mut responder_store,
            &policy,
            &accepted.envelope,
            START + 30,
        )
        .expect("BTC responder-maker admits hello");
        let maker_execution = open_shakescape_execution(
            &mut responder_store,
            &policy,
            offer.offer.session_id,
            START + 30,
        )
        .expect("maker execution");
        assert_seed_restore_retains_both_contract_authorities(&accepted.hello, 0x61, 0x51);
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(acceptance.offered_asset, AssetId::HNS);
        assert_eq!(acceptance.received_asset, AssetId::BTC);
    }

    #[test]
    fn abandoned_unfunded_acceptance_releases_hns_and_rejects_a_late_proposal() {
        let policy = policy();
        let offer_setter_id = WalletId::new([7; 16]);
        let responder_id = WalletId::new([8; 16]);
        let mut offer_setter_store = store(offer_setter_id, 0x71);
        let mut responder_store = store(responder_id, 0x81);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut offer_setter_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: offer_setter_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [11; 32],
            },
        )
        .expect("offer-setter intent");
        let signed_offer = load_shakescape_direct_offer(
            &offer_setter_store,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        crate::admit_shakescape_direct_offer(
            &mut responder_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("admit offer");
        let acceptance = create_shakescape_hns_for_btc_offer_acceptance(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcOfferAcceptanceRequest {
                wallet_id: responder_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 50_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [12; 32],
            },
        )
        .expect("acceptance");
        crate::admit_shakescape_direct_offer_acceptance(
            &mut offer_setter_store,
            &policy,
            &acceptance.envelope,
            START + 10,
        )
        .expect("offer setter admits acceptance");
        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut responder_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: responder_id,
                session_id: acceptance.session_id,
                now_unix: START + 11,
                funding_window_seconds: 600,
                second_refund_after_seconds: 4_200,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 2,
            },
        )
        .expect("responding maker signs proposal before abandonment");
        assert_eq!(
            reserved_local_shakescape_responder_amount(
                &responder_store,
                &policy,
                responder_id,
                AssetId::HNS,
                START + 11,
            )
            .expect("reservation"),
            1_000_000,
        );
        assert_eq!(
            list_pending_local_shakescape_direct_offer_acceptances(
                &responder_store,
                &policy,
                responder_id,
                START + 11,
            )
            .expect("pending acceptances"),
            vec![acceptance.clone()],
        );

        abandon_pending_local_shakescape_direct_offer_acceptance(
            &mut responder_store,
            &policy,
            responder_id,
            acceptance.session_id,
            START + 12,
        )
        .expect("abandon acceptance");
        assert_eq!(
            reserved_local_shakescape_responder_amount(
                &responder_store,
                &policy,
                responder_id,
                AssetId::HNS,
                START + 13,
            )
            .expect("released reservation"),
            0,
        );
        assert!(
            list_pending_local_shakescape_direct_offer_acceptances(
                &responder_store,
                &policy,
                responder_id,
                START + 13,
            )
            .expect("pending acceptances")
            .is_empty()
        );

        crate::admit_shakescape_direct_swap_proposal(
            &mut offer_setter_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("admit late proposal for audit");
        let accepted = accept_shakescape_direct_maker_proposal(
            &mut offer_setter_store,
            &policy,
            offer_setter_id,
            acceptance.session_id,
            START + 21,
        )
        .expect("offer setter may audit and countersign a delayed valid proposal");
        crate::admit_shakescape_direct_swap_hello(
            &mut responder_store,
            &policy,
            &accepted.envelope,
            START + 21,
        )
        .expect("abandoned responder retains the signed session for audit");
        assert!(
            !crate::is_local_shakescape_direct_maker(
                &responder_store,
                &policy,
                responder_id,
                acceptance.session_id,
            )
            .expect("local role")
        );
        assert!(matches!(
            crate::derive_local_direct_maker_key(
                &responder_store,
                &policy,
                responder_id,
                acceptance.session_id,
            ),
            Err(MarketError::ShakescapeDirectSwapConflict)
        ));
    }

    #[test]
    fn signed_offer_cancellation_automatically_releases_an_unfunded_acceptance() {
        let policy = policy();
        let offer_setter_id = WalletId::new([9; 16]);
        let responder_id = WalletId::new([10; 16]);
        let mut offer_setter_store = store(offer_setter_id, 0x91);
        let mut responder_store = store(responder_id, 0xa1);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut offer_setter_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: offer_setter_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [13; 32],
            },
        )
        .expect("offer-setter intent");
        let signed_offer = load_shakescape_direct_offer(
            &offer_setter_store,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        crate::admit_shakescape_direct_offer(
            &mut responder_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("admit offer");
        create_shakescape_hns_for_btc_offer_acceptance(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcOfferAcceptanceRequest {
                wallet_id: responder_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 50_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [14; 32],
            },
        )
        .expect("acceptance");
        let cancelled = cancel_shakescape_local_direct_offer(
            &mut offer_setter_store,
            &policy.board_policy(),
            offer_setter_id,
            offer.offer.offer_id.into_bytes(),
            START + 20,
        )
        .expect("cancel offer");
        let cancellation = load_shakescape_direct_offer(
            &offer_setter_store,
            &policy.board_policy(),
            cancelled.offer_id.into_bytes(),
        )
        .expect("load cancelled offer")
        .expect("cancelled offer exists")
        .cancellation
        .expect("signed cancellation");
        let cancellation_envelope = CrossChainMessage::CancelDirectOffer(cancellation)
            .encode_envelope(2)
            .expect("cancellation envelope");
        crate::admit_shakescape_direct_offer_cancellation(
            &mut responder_store,
            &policy.board_policy(),
            &cancellation_envelope,
            START + 20,
        )
        .expect("admit cancellation");
        assert_eq!(
            reserved_local_shakescape_responder_amount(
                &responder_store,
                &policy,
                responder_id,
                AssetId::HNS,
                START + 21,
            )
            .expect("released reservation"),
            0,
        );
    }
}
