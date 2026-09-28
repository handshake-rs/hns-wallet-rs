//! Wallet-derived authority for responding to exact direct HNS/BTC offers.
//!
//! In the current role model the responder initializes the executable swap as
//! maker. Legacy records in this module represent the old responder-as-taker
//! model and are retained only so already-countersigned sessions can recover.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOfferAcceptance, DirectOfferRoleModel,
    MARKETPLACE_PROTOCOL_VERSION, MarketPair, SignedObjectHeader, SwapSessionHello,
};
use hns_wallet_store::{EntityKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use serde::{Deserialize, Serialize};

use crate::direct_maker::derive_board_identity;
use crate::{
    CrossChainSwapKeyRequest, MarketError, ShakescapeDirectSwapPolicy, SwapParticipant,
    SwapSession, admit_shakescape_direct_offer_acceptance, admit_shakescape_direct_swap_hello,
    allocate_cross_chain_swap_key, derive_cross_chain_swap_key_from_store,
    load_shakescape_direct_offer, load_shakescape_direct_swap, open_shakescape_execution,
};

const STORAGE_VERSION: u16 = 2;
const LEGACY_STORAGE_VERSION: u16 = 1;
const RECORD_PREFIX: &[u8] = b"local-direct-acceptance/v2/";
const LEGACY_RECORD_PREFIX: &[u8] = b"local-direct-take/v1/";
const ABANDONMENT_STORAGE_VERSION: u16 = 1;
const ABANDONMENT_RECORD_PREFIX: &[u8] = b"local-direct-acceptance-abandonment/v1/";
const LEGACY_ABANDONMENT_RECORD_PREFIX: &[u8] = b"local-direct-take-abandonment/v1/";

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

// Source-compatible names for downstream applications compiled against the
// pre-v2 role terminology. New code should use the acceptance/responder names
// above; wire and storage compatibility are handled independently.
pub type ShakescapeDirectTakeRequest = ShakescapeDirectOfferAcceptanceRequest;
pub type ShakescapeLocalDirectTake = ShakescapeLocalDirectOfferAcceptance;
pub type ShakescapeTakerAcceptedSession = ShakescapeOfferSetterAcceptedSession;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedLocalDirectAcceptance {
    pub(crate) storage_version: u16,
    pub(crate) wallet_id: WalletId,
    pub(crate) offer_id: ObjectHash,
    pub(crate) session_id: SessionId,
    pub(crate) hns_fee_reserve_dollarydoos: u64,
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
pub fn create_shakescape_hns_for_btc_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeHnsForBtcTakeRequest,
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

pub fn create_shakescape_btc_for_hns_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeBtcForHnsTakeRequest,
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
            intent_id: request.offer_id,
        },
        request.created_at_unix,
    )
    .map_err(|_| MarketError::Persistence)?;
    let identity = derive_board_identity(store, request.wallet_id, &policy.board_policy())?;
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&request.nonce[..8]);
    let sequence = (u64::from_be_bytes(sequence_bytes) & i64::MAX as u64).max(1);
    let mut acceptance = DirectOfferAcceptance {
        role_model: DirectOfferRoleModel::OfferSetterTaker,
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
    project_local_acceptance(store, policy, persisted)
}

/// Compatibility entry point retained for callers using the old UI action
/// name. The responder created here is the executable swap maker.
pub fn create_shakescape_direct_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    request: ShakescapeDirectTakeRequest,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    create_shakescape_direct_offer_acceptance(store, policy, request)
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
    let (intent_id, expected_taker_key) = match record.offer.role_model {
        DirectOfferRoleModel::LegacyOfferSetterMaker => {
            let local = load_legacy_local_take(store, wallet_id, session_id)?
                .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
            if local.offer_id != ObjectHash::new(record.offer.offer_id)
                || load_legacy_local_take_abandonment(store, wallet_id, session_id)?.is_some()
            {
                return Err(MarketError::ShakescapeDirectSwapConflict);
            }
            (
                local.offer_id,
                record.acceptance.responding_maker_settlement_public_key,
            )
        }
        DirectOfferRoleModel::OfferSetterTaker => {
            let local =
                crate::direct_maker::load_local_offer(store, wallet_id, record.offer.offer_id)?;
            if local.session_id != session_id
                || local.offer_id != ObjectHash::new(record.offer.offer_id)
            {
                return Err(MarketError::ShakescapeDirectSwapConflict);
            }
            (
                local.intent_id,
                record.offer.offer_setter_settlement_public_key,
            )
        }
    };
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
            intent_id,
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
            crate::MAX_SHAKESCAPE_DIRECT_SWAPS + 1,
        )?
        .into_iter()
        .map(|stored| {
            validate_stored(wallet_id, stored)
                .and_then(|row| project_local_acceptance(store, policy, row))
        })
        .collect()
}

pub fn list_local_shakescape_direct_takes(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
) -> Result<Vec<ShakescapeLocalDirectTake>, MarketError> {
    list_local_shakescape_direct_offer_acceptances(store, policy, wallet_id)
}

/// List local takes which still reserve funds but have not reached a durable
/// countersigned execution. These are the only takes a user may abandon.
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

pub fn list_pending_local_shakescape_direct_takes(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<Vec<ShakescapeLocalDirectTake>, MarketError> {
    list_pending_local_shakescape_direct_offer_acceptances(store, policy, wallet_id, now_unix)
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

pub fn abandon_pending_local_shakescape_direct_take(
    store: &mut WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<ShakescapeLocalDirectTake, MarketError> {
    abandon_pending_local_shakescape_direct_offer_acceptance(
        store, policy, wallet_id, session_id, now_unix,
    )
}

/// Sum funds committed by local offer responses for one asset.
///
/// Current responses make this wallet the execution maker, which funds the
/// offer's received asset on the first chain. Legacy responses made this
/// wallet the taker and therefore retain the old second-chain reservation
/// rules while an already-countersigned session is being recovered.
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
        let record = load_shakescape_direct_swap(store, policy, acceptance.session_id)?
            .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
        let execution = store.load_workflow::<SwapSession>(
            crate::shakescape_execution_workflow_id(acceptance.session_id),
        )?;
        if record.offer.role_model != DirectOfferRoleModel::OfferSetterTaker {
            return Err(MarketError::CorruptShakescapeDirectSwap);
        }
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
    total = total
        .checked_add(reserved_legacy_local_taker_amount(
            store, policy, wallet_id, asset, now_unix,
        )?)
        .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
    Ok(total)
}

/// Preserve reservations only for legacy sessions that had already reached a
/// countersigned execution before the role-model upgrade. Legacy offer/acceptance
/// packets are not accepted by the current transport, so a record without an
/// execution cannot acquire new funding authority.
fn reserved_legacy_local_taker_amount(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    asset: AssetId,
    now_unix: u64,
) -> Result<u64, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedLocalDirectAcceptance>(
        EntityKind::ShakescapeBoardObject,
        &legacy_record_prefix(wallet_id),
        crate::MAX_SHAKESCAPE_DIRECT_SWAPS + 1,
    )?;
    if stored.len() > crate::MAX_SHAKESCAPE_DIRECT_SWAPS {
        return Err(MarketError::ShakescapeDirectSwapCapacity);
    }
    let mut total = 0_u64;
    for stored in stored {
        let local = validate_stored_version(wallet_id, stored, LEGACY_STORAGE_VERSION, true)?;
        let record = load_shakescape_direct_swap(store, policy, local.session_id)?
            .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
        if record.offer.role_model != DirectOfferRoleModel::LegacyOfferSetterMaker
            || record.offer.offer_id != local.offer_id.into_bytes()
            || record.offer.received_asset != asset
        {
            continue;
        }
        let Some(execution) = store.load_workflow::<SwapSession>(
            crate::shakescape_execution_workflow_id(local.session_id),
        )?
        else {
            continue;
        };
        let reserve = match execution.state.state {
            crate::SwapState::TermsFrozen
            | crate::SwapState::RefundsPrepared
            | crate::SwapState::FirstFundingPending
            | crate::SwapState::SecondFundingPending => true,
            crate::SwapState::FirstFunded => {
                let hello = record
                    .hello
                    .ok_or(MarketError::CorruptShakescapeDirectSwap)?;
                now_unix < hello.header.expires_at
            }
            _ => false,
        };
        if reserve {
            let amount = u64::try_from(record.offer.received_amount.get())
                .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
            total = total
                .checked_add(amount)
                .ok_or(MarketError::InvalidShakescapeDirectSwap)?;
        }
    }
    Ok(total)
}

/// Compatibility name retained for downstream callers. New code should use
/// [`reserved_local_shakescape_responder_amount`], because a current local
/// response is the atomic-swap maker rather than the taker.
pub fn reserved_local_shakescape_taker_amount(
    store: &WalletStore,
    policy: &ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    asset: AssetId,
    now_unix: u64,
) -> Result<u64, MarketError> {
    reserved_local_shakescape_responder_amount(store, policy, wallet_id, asset, now_unix)
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
    let (intent_id, fee_reserve, expected_key) = match record.offer.role_model {
        DirectOfferRoleModel::LegacyOfferSetterMaker => {
            let local = load_legacy_local_take(store, wallet_id, session_id)?
                .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
            if record.offer.offer_id != local.offer_id.into_bytes() {
                return Err(MarketError::ShakescapeDirectSwapConflict);
            }
            (
                local.offer_id,
                local.hns_fee_reserve_dollarydoos,
                record.acceptance.responding_maker_settlement_public_key,
            )
        }
        DirectOfferRoleModel::OfferSetterTaker => {
            let local =
                crate::direct_maker::load_local_offer(store, wallet_id, record.offer.offer_id)?;
            if local.session_id != session_id {
                return Err(MarketError::ShakescapeDirectSwapConflict);
            }
            (
                local.intent_id,
                local.bitcoin_fee_reserve_sats,
                record.offer.offer_setter_settlement_public_key,
            )
        }
    };
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
            intent_id,
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
        hns_fee_reserve_dollarydoos: local.hns_fee_reserve_dollarydoos,
        received_fee_reserve: local.hns_fee_reserve_dollarydoos,
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

pub(crate) fn load_legacy_local_take(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectAcceptance>, MarketError> {
    store
        .load_entity::<PersistedLocalDirectAcceptance>(
            EntityKind::ShakescapeBoardObject,
            &legacy_record_id(wallet_id, session_id),
        )?
        .map(|stored| validate_stored_version(wallet_id, stored, LEGACY_STORAGE_VERSION, true))
        .transpose()
}

/// Identify the local atomic-swap taker without deriving settlement key
/// material. Current sessions use the original offer-setter record; legacy
/// sessions use the responder record that was historically called a take.
pub fn is_local_shakescape_direct_taker(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<bool, MarketError> {
    if load_legacy_local_take(store, wallet_id, session_id)?.is_some() {
        return Ok(true);
    }
    Ok(crate::direct_maker::load_local_offer_for_session(store, wallet_id, session_id)?.is_some())
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

fn load_legacy_local_take_abandonment(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<Option<PersistedLocalDirectAcceptanceAbandonment>, MarketError> {
    load_abandonment(
        store,
        wallet_id,
        session_id,
        legacy_abandonment_record_id(wallet_id, session_id),
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
    validate_stored_version(wallet_id, stored, STORAGE_VERSION, false)
}

fn validate_stored_version(
    wallet_id: WalletId,
    stored: hns_wallet_store::StoredEntity<PersistedLocalDirectAcceptance>,
    expected_version: u16,
    legacy: bool,
) -> Result<PersistedLocalDirectAcceptance, MarketError> {
    let row = stored.value;
    if stored.revision != 1
        || row.storage_version != expected_version
        || row.wallet_id != wallet_id
        || row.offer_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.session_id.as_bytes().iter().all(|byte| *byte == 0)
        || row.hns_fee_reserve_dollarydoos == 0
        || row.created_at_unix != stored.updated_at_unix
        || stored.id
            != if legacy {
                legacy_record_id(wallet_id, row.session_id)
            } else {
                record_id(wallet_id, row.session_id)
            }
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

fn legacy_record_prefix(wallet_id: WalletId) -> Vec<u8> {
    let mut id = Vec::with_capacity(LEGACY_RECORD_PREFIX.len() + 16);
    id.extend_from_slice(LEGACY_RECORD_PREFIX);
    id.extend_from_slice(wallet_id.as_bytes());
    id
}

fn legacy_record_id(wallet_id: WalletId, session_id: SessionId) -> Vec<u8> {
    let mut id = legacy_record_prefix(wallet_id);
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

fn legacy_abandonment_record_id(wallet_id: WalletId, session_id: SessionId) -> Vec<u8> {
    let mut id = Vec::with_capacity(LEGACY_ABANDONMENT_RECORD_PREFIX.len() + 16 + 32);
    id.extend_from_slice(LEGACY_ABANDONMENT_RECORD_PREFIX);
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

        let acceptance = create_shakescape_hns_for_btc_take(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
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
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
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
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(
            list_local_shakescape_direct_takes(&responder_store, &policy, responder_id)
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

        let acceptance = create_shakescape_btc_for_hns_take(
            &mut responder_store,
            &policy,
            ShakescapeBtcForHnsTakeRequest {
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
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
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
        let acceptance = create_shakescape_hns_for_btc_take(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
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
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
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
            list_pending_local_shakescape_direct_takes(
                &responder_store,
                &policy,
                responder_id,
                START + 11,
            )
            .expect("pending acceptances"),
            vec![acceptance.clone()],
        );

        abandon_pending_local_shakescape_direct_take(
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
            list_pending_local_shakescape_direct_takes(
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
        create_shakescape_hns_for_btc_take(
            &mut responder_store,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
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

    #[test]
    fn legacy_take_and_abandonment_namespaces_remain_exactly_readable() {
        let wallet_id = WalletId::new([0xb1; 16]);
        let session_id = SessionId::new([0xb2; 32]);
        let offer_id = ObjectHash::new([0xb3; 32]);
        let mut store = store(wallet_id, 0xb4);
        let legacy = PersistedLocalDirectAcceptance {
            storage_version: LEGACY_STORAGE_VERSION,
            wallet_id,
            offer_id,
            session_id,
            hns_fee_reserve_dollarydoos: 42_000,
            created_at_unix: START,
        };
        store
            .save_entity(
                EntityKind::ShakescapeBoardObject,
                &legacy_record_id(wallet_id, session_id),
                0,
                &legacy,
                START,
            )
            .expect("persist legacy take");
        assert_eq!(
            load_legacy_local_take(&store, wallet_id, session_id).expect("load legacy take"),
            Some(legacy)
        );
        assert!(
            load_local_acceptance(&store, wallet_id, session_id)
                .expect("current namespace remains separate")
                .is_none()
        );

        let abandoned = PersistedLocalDirectAcceptanceAbandonment {
            storage_version: ABANDONMENT_STORAGE_VERSION,
            wallet_id,
            offer_id,
            session_id,
            abandoned_at_unix: START + 1,
        };
        store
            .save_entity(
                EntityKind::ShakescapeBoardObject,
                &legacy_abandonment_record_id(wallet_id, session_id),
                0,
                &abandoned,
                START + 1,
            )
            .expect("persist legacy abandonment");
        assert_eq!(
            load_legacy_local_take_abandonment(&store, wallet_id, session_id)
                .expect("load legacy abandonment"),
            Some(abandoned)
        );
        assert!(
            load_local_acceptance_abandonment(&store, wallet_id, session_id)
                .expect("current abandonment namespace remains separate")
                .is_none()
        );
    }
}
