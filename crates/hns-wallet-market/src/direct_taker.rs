//! Wallet-derived taker authority for exact direct BTC-for-HNS offers.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOfferTake, MARKETPLACE_PROTOCOL_VERSION, MarketPair,
    SignedObjectHeader, SwapSessionHello,
};
use hns_wallet_store::{EntityKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use serde::{Deserialize, Serialize};

use crate::direct_maker::derive_board_identity;
use crate::{
    CrossChainSwapKeyRequest, MarketError, ShakescapeDirectSwapPolicy, SwapParticipant,
    SwapSession, admit_shakescape_direct_offer_take, admit_shakescape_direct_swap_hello,
    allocate_cross_chain_swap_key, derive_cross_chain_swap_key_from_store,
    load_shakescape_direct_offer, load_shakescape_direct_swap, open_shakescape_execution,
};

const STORAGE_VERSION: u16 = 1;
const RECORD_PREFIX: &[u8] = b"local-direct-take/v1/";
const ABANDONMENT_STORAGE_VERSION: u16 = 1;
const ABANDONMENT_RECORD_PREFIX: &[u8] = b"local-direct-take-abandonment/v1/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeHnsForBtcTakeRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    pub hns_fee_reserve_dollarydoos: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeBtcForHnsTakeRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    pub bitcoin_fee_reserve_sats: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeDirectTakeRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    /// Fee reserve in the taker's asset (the offer's received asset).
    pub received_fee_reserve: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeLocalDirectTake {
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
pub struct ShakescapeTakerAcceptedSession {
    pub hello: SwapSessionHello,
    pub execution: SwapSession,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLocalDirectTake {
    storage_version: u16,
    wallet_id: WalletId,
    offer_id: ObjectHash,
    session_id: SessionId,
    hns_fee_reserve_dollarydoos: u64,
    created_at_unix: u64,
}

/// Durable local-only tombstone for an acceptance abandoned before exact
/// terms were countersigned. Keeping a tombstone instead of deleting the take
/// prevents a delayed maker proposal from reactivating released funds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLocalDirectTakeAbandonment {
    storage_version: u16,
    wallet_id: WalletId,
    offer_id: ObjectHash,
    session_id: SessionId,
    abandoned_at_unix: u64,
}

/// Sign and durably admit one exact take. The session identifier comes from
/// the signed offer; the taker has no authority to replace it.
pub fn create_shakescape_hns_for_btc_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeHnsForBtcTakeRequest,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    create_shakescape_direct_take(
        store,
        policy,
        ShakescapeDirectTakeRequest {
            wallet_id: request.wallet_id,
            offer_id: request.offer_id,
            received_fee_reserve: request.hns_fee_reserve_dollarydoos,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            nonce: request.nonce,
        },
    )
}

pub fn create_shakescape_btc_for_hns_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeBtcForHnsTakeRequest,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    create_shakescape_direct_take(
        store,
        policy,
        ShakescapeDirectTakeRequest {
            wallet_id: request.wallet_id,
            offer_id: request.offer_id,
            received_fee_reserve: request.bitcoin_fee_reserve_sats,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            nonce: request.nonce,
        },
    )
}

pub fn create_shakescape_direct_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeDirectTakeRequest,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    validate_direct_take_request(request)?;
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
    if let Some(existing) = load_local_take(store, request.wallet_id, session_id)? {
        if existing.offer_id != request.offer_id {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
        if load_local_take_abandonment(store, request.wallet_id, session_id)?.is_some() {
            return Err(MarketError::ShakescapeDirectSwapConflict);
        }
        return project_local_take(store, policy, existing);
    }
    if load_shakescape_direct_swap(store, policy, session_id)?.is_some() {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let settlement = allocate_cross_chain_swap_key(
        store,
        CrossChainSwapKeyRequest {
            wallet_id: request.wallet_id,
            session_id,
            participant: SwapParticipant::Taker,
            network: policy.network(),
            intent_id: request.offer_id,
        },
        request.created_at_unix,
    )
    .map_err(|_| MarketError::Persistence)?;
    let identity = derive_board_identity(store, request.wallet_id, &policy.board_policy())?;
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&request.nonce[..8]);
    let sequence = (u64::from_be_bytes(sequence_bytes) & i64::MAX as u64).max(1);
    let mut take = DirectOfferTake {
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
        taker_settlement_public_key: settlement.compressed_public_key(),
        signature: [0; 64],
    };
    take.sign(&identity)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let request_id = sequence.max(1);
    let envelope = CrossChainMessage::TakeDirectOffer(take)
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    admit_shakescape_direct_offer_take(store, policy, &envelope, request.created_at_unix)?;
    let persisted = PersistedLocalDirectTake {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        offer_id: request.offer_id,
        session_id,
        // Storage field predates bidirectional takes. It now holds the fee
        // reserve in the offer's received asset base unit.
        hns_fee_reserve_dollarydoos: request.received_fee_reserve,
        created_at_unix: request.created_at_unix,
    };
    store.save_entity(
        EntityKind::ShakescapeBoardObject,
        &record_id(request.wallet_id, session_id),
        0,
        &persisted,
        request.created_at_unix,
    )?;
    project_local_take(store, policy, persisted)
}

/// Verify and countersign the maker proposal, admit the accepted hello, and
/// open the restart-safe execution journal before returning bytes to send.
pub fn accept_shakescape_hns_for_btc_maker_proposal(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeTakerAcceptedSession, MarketError> {
    accept_shakescape_direct_maker_proposal(store, policy, wallet_id, session_id, now_unix)
}

pub fn accept_shakescape_direct_maker_proposal(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeTakerAcceptedSession, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let local = load_local_take(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if local.offer_id != ObjectHash::new(record.offer.offer_id) {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    if let Some(hello) = record.hello {
        let execution = open_shakescape_execution(store, policy, session_id, now_unix)?;
        let request_id = record
            .proposal_request_id
            .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
        let envelope = CrossChainMessage::SwapSessionHello(hello.clone())
            .encode_envelope(request_id)
            .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
        return Ok(ShakescapeTakerAcceptedSession {
            hello,
            execution,
            envelope,
        });
    }
    if load_local_take_abandonment(store, wallet_id, session_id)?.is_some()
        || load_shakescape_direct_offer(store, &policy.board_policy(), local.offer_id.into_bytes())?
            .is_none_or(|offer| !offer.is_active_at(now_unix))
    {
        // Treat a delayed proposal for a locally released acceptance as
        // unknown. The transport can safely ignore it without dropping an
        // otherwise healthy peer connection. An already-countersigned hello
        // above remains replayable after its board offer expires or cancels.
        return Err(MarketError::UnknownShakescapeDirectSwap);
    }
    let proposal = record
        .proposal
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
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
            intent_id: local.offer_id,
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if settlement.public_key() != record.take.taker_settlement_public_key {
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
    Ok(ShakescapeTakerAcceptedSession {
        hello,
        execution,
        envelope,
    })
}

pub fn list_local_shakescape_direct_takes(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
) -> Result<Vec<ShakescapeLocalDirectTake>, MarketError> {
    store
        .list_entities_by_id_prefix::<PersistedLocalDirectTake>(
            EntityKind::ShakescapeBoardObject,
            &record_prefix(wallet_id),
            crate::MAX_SHAKESCAPE_DIRECT_SWAPS + 1,
        )?
        .into_iter()
        .map(|stored| {
            validate_stored(wallet_id, stored)
                .and_then(|row| project_local_take(store, policy, row))
        })
        .collect()
}

/// List local takes which still reserve funds but have not reached a durable
/// countersigned execution. These are the only takes a user may abandon.
pub fn list_pending_local_shakescape_direct_takes(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<Vec<ShakescapeLocalDirectTake>, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let mut pending = Vec::new();
    for take in list_local_shakescape_direct_takes(store, policy, wallet_id)? {
        if local_take_has_execution(store, take.session_id)?
            || local_take_is_released(store, policy, wallet_id, &take, now_unix)?
        {
            continue;
        }
        pending.push(take);
    }
    Ok(pending)
}

/// Release one local acceptance before exact terms are countersigned. This
/// cannot abandon a terms-frozen or funded execution. The durable tombstone
/// also makes all delayed maker proposals for the session non-actionable.
pub fn abandon_pending_local_shakescape_direct_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidShakescapeDirectSwap);
    }
    let local = load_local_take(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let projected = project_local_take(store, policy, local.clone())?;
    let swap = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if swap.hello.is_some() || local_take_has_execution(store, session_id)? {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    if let Some(existing) = load_local_take_abandonment(store, wallet_id, session_id)? {
        if existing.offer_id != local.offer_id {
            return Err(MarketError::CorruptShakescapeDirectSwap);
        }
        return Ok(projected);
    }
    let abandonment = PersistedLocalDirectTakeAbandonment {
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

/// Sum funds still committed by this wallet's accepted takes for one asset.
/// A taker funds the offer's received asset on the second chain, so the
/// reservation remains live until that funding is independently confirmed.
pub fn reserved_local_shakescape_taker_amount(
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
    for take in list_local_shakescape_direct_takes(store, policy, wallet_id)? {
        if take.received_asset != asset {
            continue;
        }
        let execution = store.load_workflow::<SwapSession>(
            crate::shakescape_execution_workflow_id(take.session_id),
        )?;
        let reserve = match execution.map(|stored| stored.state.state) {
            Some(
                crate::SwapState::TermsFrozen
                | crate::SwapState::RefundsPrepared
                | crate::SwapState::FirstFundingPending
                | crate::SwapState::FirstFunded
                | crate::SwapState::SecondFundingPending,
            ) => true,
            Some(_) => false,
            None => !local_take_is_released(store, policy, wallet_id, &take, now_unix)?,
        };
        if reserve {
            total = total
                .checked_add(take.received_amount)
                .and_then(|value| value.checked_add(take.received_fee_reserve))
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
    if record.offer.offered_asset != AssetId::BTC || record.offer.received_asset != AssetId::HNS {
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
    let local = load_local_take(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if record.offer.offer_id != local.offer_id.into_bytes()
        || record.hello.as_ref().is_none_or(|hello| {
            hello.swap_session_id != session_id.into_bytes()
                || !matches!(
                    (hello.offered_asset, hello.received_asset),
                    (AssetId::BTC, AssetId::HNS) | (AssetId::HNS, AssetId::BTC)
                )
        })
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let key = derive_cross_chain_swap_key_from_store(
        store,
        CrossChainSwapKeyRequest {
            wallet_id,
            session_id,
            participant: SwapParticipant::Taker,
            network: policy.network(),
            intent_id: local.offer_id,
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if key.public_key() != record.take.taker_settlement_public_key {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok((key, local.hns_fee_reserve_dollarydoos))
}

fn validate_direct_take_request(request: ShakescapeDirectTakeRequest) -> Result<(), MarketError> {
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

fn project_local_take(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    local: PersistedLocalDirectTake,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    let record = load_shakescape_direct_swap(store, policy, local.session_id)?
        .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
    if record.offer.offer_id != local.offer_id.into_bytes()
        || record.offer.swap_session_id != local.session_id.into_bytes()
        || record.take.swap_session_id != local.session_id.into_bytes()
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
    let envelope = CrossChainMessage::TakeDirectOffer(record.take.clone())
        .encode_envelope(record.take_request_id)
        .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
    Ok(ShakescapeLocalDirectTake {
        offer_id: local.offer_id,
        session_id: local.session_id,
        btc_amount_sats,
        hns_amount_dollarydoos,
        hns_fee_reserve_dollarydoos: local.hns_fee_reserve_dollarydoos,
        received_fee_reserve: local.hns_fee_reserve_dollarydoos,
        offered_asset: record.offer.offered_asset,
        offered_amount,
        received_asset: record.offer.received_asset,
        received_amount,
        created_at_unix: local.created_at_unix,
        expires_at_unix: record.take.header.expires_at,
        envelope,
    })
}

fn load_local_take(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectTake>, MarketError> {
    store
        .load_entity::<PersistedLocalDirectTake>(
            EntityKind::ShakescapeBoardObject,
            &record_id(wallet_id, session_id),
        )?
        .map(|stored| validate_stored(wallet_id, stored))
        .transpose()
}

/// Identify a locally-created taker session from its validated durable take
/// record without deriving settlement key material.
pub fn is_local_shakescape_direct_taker(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    load_local_take(store, wallet_id, session_id).map(|record| record.is_some())
}

fn local_take_has_execution(
    store: &WalletStore,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    Ok(store
        .load_workflow::<SwapSession>(crate::shakescape_execution_workflow_id(session_id))?
        .is_some())
}

fn local_take_is_released(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    take: &ShakescapeLocalDirectTake,
    now_unix: u64,
) -> Result<bool, MarketError> {
    if take.expires_at_unix <= now_unix
        || load_local_take_abandonment(store, wallet_id, take.session_id)?.is_some()
    {
        return Ok(true);
    }
    Ok(
        load_shakescape_direct_offer(store, &policy.board_policy(), take.offer_id.into_bytes())?
            .is_some_and(|offer| !offer.is_active_at(now_unix)),
    )
}

fn load_local_take_abandonment(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectTakeAbandonment>, MarketError> {
    store
        .load_entity::<PersistedLocalDirectTakeAbandonment>(
            EntityKind::ShakescapeBoardObject,
            &abandonment_record_id(wallet_id, session_id),
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
                || stored.id != abandonment_record_id(wallet_id, session_id)
            {
                return Err(MarketError::CorruptShakescapeDirectSwap);
            }
            Ok(row)
        })
        .transpose()
}

fn validate_stored(
    wallet_id: WalletId,
    stored: hns_wallet_store::StoredEntity<PersistedLocalDirectTake>,
) -> Result<PersistedLocalDirectTake, MarketError> {
    let row = stored.value;
    if stored.revision != 1
        || row.storage_version != STORAGE_VERSION
        || row.wallet_id != wallet_id
        || row.offer_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.session_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.hns_fee_reserve_dollarydoos == 0
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
    use hns_primitives::BlockHash;
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
        ShakescapeDirectSwapPolicy::new(
            ShakescapeDirectOfferBoardPolicy::new(NetworkBinding {
                hns_magic: 0x5b6e_c393,
                hns_genesis: BlockHash::new([1; 32]),
                counterchain: ChainId::BITCOIN,
                counterchain_network: 1,
                counterchain_genesis: [2; 32],
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

    #[test]
    fn two_wallets_reach_the_same_countersigned_restart_safe_execution() {
        let policy = policy();
        let maker_id = WalletId::new([3; 16]);
        let taker_id = WalletId::new([4; 16]);
        let mut maker_store = store(maker_id, 0x31);
        let mut taker_store = store(taker_id, 0x41);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [7; 32],
            },
        )
        .expect("maker offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker_store,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load maker offer")
        .expect("maker offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        crate::admit_shakescape_direct_offer(
            &mut taker_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("taker admits offer");

        let take = create_shakescape_hns_for_btc_take(
            &mut taker_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [8; 32],
            },
        )
        .expect("taker signs take");
        crate::admit_shakescape_direct_offer_take(
            &mut maker_store,
            &policy,
            &take.envelope,
            START + 10,
        )
        .expect("maker admits take");
        let (original_request_id, replay_message) =
            CrossChainMessage::decode_envelope(&take.envelope).expect("decode durable take");
        let replay_envelope = replay_message
            .encode_envelope(original_request_id + 1)
            .expect("re-encode replay on a new socket sequence");
        let replay = crate::admit_shakescape_direct_offer_take(
            &mut maker_store,
            &policy,
            &replay_envelope,
            START + 11,
        )
        .expect("identical signed take is idempotent across request IDs");
        assert!(matches!(
            replay,
            crate::ShakescapeDirectSwapAdmission::Existing(snapshot)
                if snapshot.take_request_id == original_request_id
        ));

        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut maker_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("maker proposal");
        crate::admit_shakescape_direct_swap_proposal(
            &mut taker_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("taker admits proposal");
        let accepted = accept_shakescape_hns_for_btc_maker_proposal(
            &mut taker_store,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("taker accepts proposal");
        crate::admit_shakescape_direct_swap_hello(
            &mut maker_store,
            &policy,
            &accepted.envelope,
            START + 30,
        )
        .expect("maker admits hello");
        let maker_execution = open_shakescape_execution(
            &mut maker_store,
            &policy,
            offer.offer.session_id,
            START + 30,
        )
        .expect("maker execution");
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(
            list_local_shakescape_direct_takes(&taker_store, &policy, taker_id)
                .expect("local takes"),
            vec![take]
        );
        let retried = accept_shakescape_hns_for_btc_maker_proposal(
            &mut taker_store,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 31,
        )
        .expect("idempotent acceptance");
        assert_eq!(retried.envelope, accepted.envelope);
        assert_eq!(retried.execution, accepted.execution);
    }

    #[test]
    fn hns_maker_and_btc_taker_reach_countersigned_execution() {
        let policy = policy();
        let maker_id = WalletId::new([5; 16]);
        let taker_id = WalletId::new([6; 16]);
        let mut maker_store = store(maker_id, 0x51);
        let mut taker_store = store(taker_id, 0x61);
        let offer = create_shakescape_hns_for_btc_offer(
            &mut maker_store,
            &policy.board_policy(),
            ShakescapeHnsForBtcOfferRequest {
                wallet_id: maker_id,
                hns_amount_dollarydoos: 2_000_000,
                btc_amount_sats: 9_000,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [9; 32],
            },
        )
        .expect("HNS maker offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker_store,
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
            &mut taker_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("BTC taker admits offer");

        let take = create_shakescape_btc_for_hns_take(
            &mut taker_store,
            &policy,
            ShakescapeBtcForHnsTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [10; 32],
            },
        )
        .expect("BTC taker signs take");
        crate::admit_shakescape_direct_offer_take(
            &mut maker_store,
            &policy,
            &take.envelope,
            START + 10,
        )
        .expect("HNS maker admits take");

        let proposal = create_shakescape_direct_maker_proposal(
            &mut maker_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("HNS maker proposal");
        assert_eq!(proposal.proposal.terms().offered_asset, AssetId::HNS);
        assert_eq!(proposal.proposal.terms().received_asset, AssetId::BTC);
        assert_eq!(
            proposal.proposal.terms().first_funding_chain,
            ChainId::HANDSHAKE
        );
        crate::admit_shakescape_direct_swap_proposal(
            &mut taker_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("BTC taker admits proposal");
        let accepted = accept_shakescape_direct_maker_proposal(
            &mut taker_store,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("BTC taker accepts proposal");
        crate::admit_shakescape_direct_swap_hello(
            &mut maker_store,
            &policy,
            &accepted.envelope,
            START + 30,
        )
        .expect("HNS maker admits hello");
        let maker_execution = open_shakescape_execution(
            &mut maker_store,
            &policy,
            offer.offer.session_id,
            START + 30,
        )
        .expect("maker execution");
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(take.offered_asset, AssetId::HNS);
        assert_eq!(take.received_asset, AssetId::BTC);
    }

    #[test]
    fn abandoned_unfunded_take_releases_hns_and_rejects_a_late_proposal() {
        let policy = policy();
        let maker_id = WalletId::new([7; 16]);
        let taker_id = WalletId::new([8; 16]);
        let mut maker_store = store(maker_id, 0x71);
        let mut taker_store = store(taker_id, 0x81);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [11; 32],
            },
        )
        .expect("maker offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker_store,
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
            &mut taker_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("admit offer");
        let take = create_shakescape_hns_for_btc_take(
            &mut taker_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 50_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [12; 32],
            },
        )
        .expect("take");
        assert_eq!(
            reserved_local_shakescape_taker_amount(
                &taker_store,
                &policy,
                taker_id,
                AssetId::HNS,
                START + 11,
            )
            .expect("reservation"),
            1_050_000,
        );
        assert_eq!(
            list_pending_local_shakescape_direct_takes(
                &taker_store,
                &policy,
                taker_id,
                START + 11,
            )
            .expect("pending takes"),
            vec![take.clone()],
        );

        abandon_pending_local_shakescape_direct_take(
            &mut taker_store,
            &policy,
            taker_id,
            take.session_id,
            START + 12,
        )
        .expect("abandon take");
        assert_eq!(
            reserved_local_shakescape_taker_amount(
                &taker_store,
                &policy,
                taker_id,
                AssetId::HNS,
                START + 13,
            )
            .expect("released reservation"),
            0,
        );
        assert!(
            list_pending_local_shakescape_direct_takes(
                &taker_store,
                &policy,
                taker_id,
                START + 13,
            )
            .expect("pending takes")
            .is_empty()
        );

        crate::admit_shakescape_direct_offer_take(
            &mut maker_store,
            &policy,
            &take.envelope,
            START + 14,
        )
        .expect("maker admits take");
        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut maker_store,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: take.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("late maker proposal");
        crate::admit_shakescape_direct_swap_proposal(
            &mut taker_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("admit late proposal for audit");
        assert!(matches!(
            accept_shakescape_direct_maker_proposal(
                &mut taker_store,
                &policy,
                taker_id,
                take.session_id,
                START + 21,
            ),
            Err(MarketError::UnknownShakescapeDirectSwap)
        ));
    }

    #[test]
    fn signed_offer_cancellation_automatically_releases_an_unfunded_take() {
        let policy = policy();
        let maker_id = WalletId::new([9; 16]);
        let taker_id = WalletId::new([10; 16]);
        let mut maker_store = store(maker_id, 0x91);
        let mut taker_store = store(taker_id, 0xa1);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker_store,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [13; 32],
            },
        )
        .expect("maker offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker_store,
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
            &mut taker_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("admit offer");
        create_shakescape_hns_for_btc_take(
            &mut taker_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 50_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [14; 32],
            },
        )
        .expect("take");
        let cancelled = cancel_shakescape_local_direct_offer(
            &mut maker_store,
            &policy.board_policy(),
            maker_id,
            offer.offer.offer_id.into_bytes(),
            START + 20,
        )
        .expect("cancel offer");
        let cancellation = load_shakescape_direct_offer(
            &maker_store,
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
            &mut taker_store,
            &policy.board_policy(),
            &cancellation_envelope,
            START + 20,
        )
        .expect("admit cancellation");
        assert_eq!(
            reserved_local_shakescape_taker_amount(
                &taker_store,
                &policy,
                taker_id,
                AssetId::HNS,
                START + 21,
            )
            .expect("released reservation"),
            0,
        );
    }
}
