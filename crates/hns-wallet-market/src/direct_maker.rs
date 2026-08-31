//! Wallet-derived maker authority for exact direct BTC-for-HNS offers.
//!
//! Listing signatures and per-offer settlement signatures deliberately use
//! independent HKDF domains. Only public bindings and exact approved terms are
//! persisted; both signing scalars are re-derived from the encrypted recovery
//! seed when needed.

use hkdf::Hkdf;
use hns_marketplace_protocol::{
    AssetAmount, AssetId, ChainId, CrossChainMessage, DeadlineKind, DirectOffer,
    DirectOfferCancellation, MARKETPLACE_PROTOCOL_VERSION, MarketPair, SettlementDeadline,
    SignedObjectHeader, SwapAssetSide, SwapSessionHello, SwapSessionProposal,
};
use hns_wallet_bitcoin_kyoto::build_shakescape_bitcoin_htlc;
use hns_wallet_chain_api::Preimage;
use hns_wallet_store::{EntityKind, RECOVERY_SEED_BYTES, SecretKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    CrossChainSwapKeyRequest, MarketError, ShakescapeDirectOfferBoardPolicy,
    ShakescapeDirectOfferSnapshot, SwapParticipant, admit_shakescape_direct_offer,
    admit_shakescape_direct_offer_cancellation, admit_shakescape_direct_swap_proposal,
    allocate_cross_chain_swap_key, derive_cross_chain_swap_key_from_store,
    load_shakescape_direct_swap,
};

const STORAGE_VERSION: u16 = 2;
const RECORD_PREFIX: &[u8] = b"local-direct-offer/v1/";
const INTENT_DOMAIN: &[u8] = b"hns-wallet/direct-offer-intent/v1\0";
const SESSION_DOMAIN: &[u8] = b"hns-wallet/direct-offer-session/v1\0";
const IDENTITY_SALT: &[u8] = b"hns-wallet/direct-board-identity/hkdf-sha256/v1\0";
const IDENTITY_INFO: &[u8] = b"hns-wallet/direct-board-identity/scalar/v1\0";
const MAKER_PREIMAGE_SALT: &[u8] = b"hns-wallet/direct-maker-preimage/hkdf-sha256/v1\0";
const MAKER_PREIMAGE_INFO: &[u8] = b"hns-wallet/direct-maker-preimage/value/v1\0";
const MAKER_PREIMAGE_RECORD_DOMAIN: &[u8] = b"hns-wallet/direct-maker-preimage/record/v1\0";
const MAX_DERIVATION_ATTEMPTS: u32 = 256;
const MIN_FUNDING_WINDOW_SECONDS: u64 = 10 * 60;
const MIN_SECOND_REFUND_AFTER_SECONDS: u64 = 60 * 60;
const MIN_REFUND_SAFETY_MARGIN_SECONDS: u64 = 60 * 60;
const MAX_SETTLEMENT_HORIZON_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeBtcForHnsOfferRequest {
    pub wallet_id: WalletId,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub bitcoin_fee_reserve_sats: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

impl ShakescapeBtcForHnsOfferRequest {
    fn validate(self) -> Result<(), MarketError> {
        if self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.btc_amount_sats == 0
            || self.hns_amount_dollarydoos == 0
            || self.bitcoin_fee_reserve_sats == 0
            || self.created_at_unix == 0
            || self.expires_at_unix <= self.created_at_unix
            || self.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(MarketError::InvalidShakescapeDirectOffer);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLocalDirectOffer {
    storage_version: u16,
    wallet_id: WalletId,
    offer_id: ObjectHash,
    session_id: SessionId,
    intent_id: ObjectHash,
    bitcoin_fee_reserve_sats: u64,
    created_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeBtcForHnsMakerProposalRequest {
    pub wallet_id: WalletId,
    pub session_id: SessionId,
    pub now_unix: u64,
    pub funding_window_seconds: u64,
    pub second_refund_after_seconds: u64,
    pub refund_safety_margin_seconds: u64,
    pub bitcoin_minimum_confirmations: u32,
    pub hns_minimum_confirmations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeBtcForHnsMakerProposal {
    pub proposal: SwapSessionProposal,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapeLocalDirectOffer {
    pub offer: ShakescapeDirectOfferSnapshot,
    pub session_id: SessionId,
    pub bitcoin_fee_reserve_sats: u64,
}

pub fn create_shakescape_btc_for_hns_offer(
    store: &mut WalletStore,
    policy: &ShakescapeDirectOfferBoardPolicy,
    request: ShakescapeBtcForHnsOfferRequest,
) -> Result<ShakescapeLocalDirectOffer, MarketError> {
    request.validate()?;
    let intent = offer_intent(policy, request)?;
    let session_id = offer_session_id(request.wallet_id, request.nonce, intent);
    let settlement = allocate_cross_chain_swap_key(
        store,
        CrossChainSwapKeyRequest {
            wallet_id: request.wallet_id,
            session_id,
            participant: SwapParticipant::Maker,
            network: policy.network(),
            intent_id: intent,
        },
        request.created_at_unix,
    )
    .map_err(|_| MarketError::Persistence)?;
    let identity = derive_board_identity(store, request.wallet_id, policy)?;
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&request.nonce[..8]);
    let sequence = (u64::from_be_bytes(sequence_bytes) & i64::MAX as u64).max(1);
    let mut offer = DirectOffer {
        header: SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: policy.network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at: request.created_at_unix,
            expires_at: request.expires_at_unix,
        },
        offer_id: [0; 32],
        swap_session_id: session_id.into_bytes(),
        maker_settlement_public_key: settlement.compressed_public_key(),
        offered_asset: AssetId::BTC,
        offered_amount: AssetAmount::new(u128::from(request.btc_amount_sats)),
        received_asset: AssetId::HNS,
        received_amount: AssetAmount::new(u128::from(request.hns_amount_dollarydoos)),
        signature: [0; 64],
    };
    offer
        .sign(&identity)
        .map_err(|_| MarketError::InvalidShakescapeDirectOffer)?;
    let envelope = CrossChainMessage::DirectOffer(offer.clone())
        .encode_envelope(1)
        .map_err(|_| MarketError::InvalidShakescapeDirectOffer)?;
    let snapshot =
        admit_shakescape_direct_offer(store, policy, &envelope, request.created_at_unix)?
            .snapshot();
    let offer_id = ObjectHash::new(offer.offer_id);
    let record = PersistedLocalDirectOffer {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        offer_id,
        session_id,
        intent_id: intent,
        bitcoin_fee_reserve_sats: request.bitcoin_fee_reserve_sats,
        created_at_unix: request.created_at_unix,
    };
    store.save_entity(
        EntityKind::ShakescapeBoardObject,
        &local_record_id(request.wallet_id, offer.offer_id),
        0,
        &record,
        request.created_at_unix,
    )?;
    Ok(ShakescapeLocalDirectOffer {
        offer: snapshot,
        session_id,
        bitcoin_fee_reserve_sats: request.bitcoin_fee_reserve_sats,
    })
}

/// Turn one already admitted exact take of a local BTC-for-HNS offer into the
/// maker-signed canonical HTLC proposal. The maker's preimage is derived from
/// the encrypted recovery seed and persisted before the proposal is admitted,
/// making restart recovery independent of process memory.
pub fn create_shakescape_btc_for_hns_maker_proposal(
    store: &mut WalletStore,
    policy: &crate::ShakescapeDirectSwapPolicy,
    request: ShakescapeBtcForHnsMakerProposalRequest,
) -> Result<ShakescapeBtcForHnsMakerProposal, MarketError> {
    validate_maker_proposal_request(request)?;
    let record = load_shakescape_direct_swap(store, policy, request.session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    if record.offer.swap_session_id != request.session_id.into_bytes()
        || record.take.swap_session_id != request.session_id.into_bytes()
        || record.offer.offered_asset != AssetId::BTC
        || record.offer.received_asset != AssetId::HNS
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let local = load_local_offer(store, request.wallet_id, record.offer.offer_id)?;
    if local.session_id != request.session_id
        || local.offer_id != ObjectHash::new(record.offer.offer_id)
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    if let Some(proposal) = record.proposal {
        let envelope = CrossChainMessage::SwapSessionProposal(proposal.clone())
            .encode_envelope(record.take_request_id)
            .map_err(|_| MarketError::CorruptShakescapeDirectSwap)?;
        return Ok(ShakescapeBtcForHnsMakerProposal { proposal, envelope });
    }
    let funding_expires_at = request
        .now_unix
        .checked_add(request.funding_window_seconds)
        .ok_or(MarketError::UnsafeTimeouts)?;
    let received_refund_at = request
        .now_unix
        .checked_add(request.second_refund_after_seconds)
        .ok_or(MarketError::UnsafeTimeouts)?;
    let offered_refund_at = received_refund_at
        .checked_add(request.refund_safety_margin_seconds)
        .ok_or(MarketError::UnsafeTimeouts)?;
    if funding_expires_at > record.take.header.expires_at
        || funding_expires_at > received_refund_at
        || u32::try_from(offered_refund_at).is_err()
    {
        return Err(MarketError::UnsafeTimeouts);
    }

    let preimage = derive_maker_preimage(
        store,
        request.wallet_id,
        request.session_id,
        local.intent_id,
        record.offer.offer_id,
    )?;
    store.put_secret(
        &maker_preimage_record_id(request.session_id),
        SecretKind::HtlcPreimage,
        preimage.expose_for_settlement(),
        request.now_unix,
    )?;
    let hashlock = Sha256::digest(preimage.expose_for_settlement()).into();
    let settlement = derive_cross_chain_swap_key_from_store(
        store,
        CrossChainSwapKeyRequest {
            wallet_id: request.wallet_id,
            session_id: request.session_id,
            participant: SwapParticipant::Maker,
            network: policy.network(),
            intent_id: local.intent_id,
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if settlement.public_key() != record.offer.maker_settlement_public_key {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let mut hello = SwapSessionHello {
        header: SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: policy.network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: record.offer.header.signer_public_key,
            sequence: record
                .offer
                .header
                .sequence
                .checked_add(1)
                .ok_or(MarketError::InvalidShakescapeDirectSwap)?,
            created_at: request.now_unix,
            expires_at: funding_expires_at,
        },
        direct_offer_id: record.offer.offer_id,
        swap_session_id: request.session_id.into_bytes(),
        maker_settlement_public_key: settlement.public_key(),
        taker_settlement_public_key: record.take.taker_settlement_public_key,
        offered_asset: record.offer.offered_asset,
        offered_amount: record.offer.offered_amount,
        received_asset: record.offer.received_asset,
        received_amount: record.offer.received_amount,
        hashlock,
        first_funding_chain: ChainId::BITCOIN,
        offered_lock_commitment: [1; 32],
        offered_refund_deadline: SettlementDeadline {
            kind: DeadlineKind::UnixTime,
            value: offered_refund_at,
        },
        offered_minimum_confirmations: request.bitcoin_minimum_confirmations,
        received_lock_commitment: [1; 32],
        received_refund_deadline: SettlementDeadline {
            kind: DeadlineKind::UnixTime,
            value: received_refund_at,
        },
        received_minimum_confirmations: request.hns_minimum_confirmations,
        maker_signature: [0; 64],
        taker_signature: [0; 64],
    };
    hello
        .build_and_bind_hns_htlc(
            SwapAssetSide::Received,
            hello.maker_settlement_public_key,
            hello.taker_settlement_public_key,
        )
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    hello.offered_lock_commitment = build_shakescape_bitcoin_htlc(&hello, SwapAssetSide::Offered)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?
        .commitment
        .into_bytes();
    let proposal = settlement
        .into_maker_proposal(hello)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    let envelope = CrossChainMessage::SwapSessionProposal(proposal.clone())
        .encode_envelope(record.take_request_id)
        .map_err(|_| MarketError::InvalidShakescapeDirectSwap)?;
    admit_shakescape_direct_swap_proposal(store, policy, &envelope, request.now_unix)?;
    Ok(ShakescapeBtcForHnsMakerProposal { proposal, envelope })
}

pub fn load_shakescape_btc_for_hns_maker_preimage(
    store: &WalletStore,
    session_id: SessionId,
) -> Result<Option<Preimage>, MarketError> {
    store
        .get_secret(
            &maker_preimage_record_id(session_id),
            SecretKind::HtlcPreimage,
        )?
        .map(|stored| {
            let bytes = <[u8; Preimage::LENGTH]>::try_from(stored.as_slice())
                .map_err(|_| MarketError::InvalidEvidence)?;
            Ok(Preimage::new(bytes))
        })
        .transpose()
}

#[doc(hidden)]
pub fn derive_local_btc_for_hns_maker_key(
    store: &WalletStore,
    policy: &crate::ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<(crate::CrossChainSwapKey, u64), MarketError> {
    let record = load_shakescape_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let local = load_local_offer(store, wallet_id, record.offer.offer_id)?;
    if local.session_id != session_id
        || record.offer.swap_session_id != session_id.into_bytes()
        || record.offer.offered_asset != AssetId::BTC
        || record.offer.received_asset != AssetId::HNS
    {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    let key = derive_cross_chain_swap_key_from_store(
        store,
        CrossChainSwapKeyRequest {
            wallet_id,
            session_id,
            participant: SwapParticipant::Maker,
            network: policy.network(),
            intent_id: local.intent_id,
        },
    )
    .map_err(|_| MarketError::Persistence)?;
    if key.public_key() != record.offer.maker_settlement_public_key {
        return Err(MarketError::ShakescapeDirectSwapConflict);
    }
    Ok((key, local.bitcoin_fee_reserve_sats))
}

pub fn cancel_shakescape_local_direct_offer(
    store: &mut WalletStore,
    policy: &ShakescapeDirectOfferBoardPolicy,
    wallet_id: WalletId,
    offer_id: [u8; 32],
    now_unix: u64,
) -> Result<ShakescapeDirectOfferSnapshot, MarketError> {
    if now_unix == 0 || offer_id.iter().all(|byte| *byte == 0) {
        return Err(MarketError::InvalidShakescapeDirectOffer);
    }
    let local = store
        .load_entity::<PersistedLocalDirectOffer>(
            EntityKind::ShakescapeBoardObject,
            &local_record_id(wallet_id, offer_id),
        )?
        .ok_or(MarketError::UnknownShakescapeDirectOffer)?;
    if local.revision != 1
        || local.value.storage_version != STORAGE_VERSION
        || local.value.wallet_id != wallet_id
        || local.value.offer_id.into_bytes() != offer_id
        || local
            .value
            .session_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || local
            .value
            .intent_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(MarketError::CorruptShakescapeDirectOfferBoard);
    }
    let offer = crate::load_shakescape_direct_offer(store, policy, offer_id)?
        .ok_or(MarketError::UnknownShakescapeDirectOffer)?;
    if !offer.is_active_at(now_unix) {
        return Err(MarketError::InvalidShakescapeDirectOffer);
    }
    if offer.offer.swap_session_id != local.value.session_id.into_bytes() {
        return Err(MarketError::CorruptShakescapeDirectOfferBoard);
    }
    let identity = derive_board_identity(store, wallet_id, policy)?;
    let mut cancellation = DirectOfferCancellation {
        header: SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: policy.network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence: offer
                .offer
                .header
                .sequence
                .checked_add(1)
                .ok_or(MarketError::InvalidShakescapeDirectOffer)?,
            created_at: now_unix,
            expires_at: offer.offer.header.expires_at,
        },
        offer_id,
        offer_sequence: offer.offer.header.sequence,
        signature: [0; 64],
    };
    cancellation
        .sign(&identity)
        .map_err(|_| MarketError::InvalidShakescapeDirectOffer)?;
    let envelope = CrossChainMessage::CancelDirectOffer(cancellation)
        .encode_envelope(1)
        .map_err(|_| MarketError::InvalidShakescapeDirectOffer)?;
    Ok(admit_shakescape_direct_offer_cancellation(store, policy, &envelope, now_unix)?.snapshot())
}

pub fn list_local_shakescape_direct_offers(
    store: &WalletStore,
    policy: &ShakescapeDirectOfferBoardPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<Vec<ShakescapeLocalDirectOffer>, MarketError> {
    let prefix = local_record_prefix(wallet_id);
    let stored = store.list_entities_by_id_prefix::<PersistedLocalDirectOffer>(
        EntityKind::ShakescapeBoardObject,
        &prefix,
        crate::MAX_SHAKESCAPE_DIRECT_OFFERS,
    )?;
    let mut offers = Vec::with_capacity(stored.len());
    for stored in stored {
        let record = stored.value;
        if stored.revision != 1
            || record.storage_version != STORAGE_VERSION
            || record.wallet_id != wallet_id
            || record.intent_id.as_bytes().iter().all(|byte| *byte == 0)
            || record.created_at_unix != stored.updated_at_unix
        {
            return Err(MarketError::CorruptShakescapeDirectOfferBoard);
        }
        let Some(offer) =
            crate::load_shakescape_direct_offer(store, policy, record.offer_id.into_bytes())?
        else {
            return Err(MarketError::CorruptShakescapeDirectOfferBoard);
        };
        if offer.offer.swap_session_id != record.session_id.into_bytes() {
            return Err(MarketError::CorruptShakescapeDirectOfferBoard);
        }
        if offer.is_active_at(now_unix) {
            offers.push(ShakescapeLocalDirectOffer {
                offer: offer.snapshot(),
                session_id: record.session_id,
                bitcoin_fee_reserve_sats: record.bitcoin_fee_reserve_sats,
            });
        }
    }
    Ok(offers)
}

/// Sum Bitcoin still committed by local maker offers. Once a countersigned
/// execution exists, its durable state—not board expiry—controls reservation:
/// funds remain reserved through pending first funding and are released only
/// after locally verified first-chain funding has consumed them (or the
/// execution reaches a terminal state).
pub fn reserved_local_shakescape_btc_maker_sats(
    store: &WalletStore,
    policy: &crate::ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<u64, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedLocalDirectOffer>(
        EntityKind::ShakescapeBoardObject,
        &local_record_prefix(wallet_id),
        crate::MAX_SHAKESCAPE_DIRECT_OFFERS + 1,
    )?;
    if stored.len() > crate::MAX_SHAKESCAPE_DIRECT_OFFERS {
        return Err(MarketError::ShakescapeDirectOfferCapacity);
    }
    let mut total = 0_u64;
    for stored in stored {
        let local = load_local_offer(store, wallet_id, stored.value.offer_id.into_bytes())?;
        let offer = crate::load_shakescape_direct_offer(
            store,
            &policy.board_policy(),
            local.offer_id.into_bytes(),
        )?
        .ok_or(MarketError::CorruptShakescapeDirectOfferBoard)?;
        let execution = store.load_workflow::<crate::SwapSession>(
            crate::shakescape_execution_workflow_id(local.session_id),
        )?;
        let reserve = match execution.map(|stored| stored.state.state) {
            Some(
                crate::SwapState::TermsFrozen
                | crate::SwapState::RefundsPrepared
                | crate::SwapState::FirstFundingPending,
            ) => true,
            Some(_) => false,
            None => offer.is_active_at(now_unix),
        };
        if reserve {
            let amount = u64::try_from(offer.offer.offered_amount.get())
                .map_err(|_| MarketError::InvalidShakescapeDirectOffer)?;
            total = total
                .checked_add(amount)
                .and_then(|value| value.checked_add(local.bitcoin_fee_reserve_sats))
                .ok_or(MarketError::InvalidShakescapeDirectOffer)?;
        }
    }
    Ok(total)
}

fn validate_maker_proposal_request(
    request: ShakescapeBtcForHnsMakerProposalRequest,
) -> Result<(), MarketError> {
    if request.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.session_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.now_unix == 0
        || !(MIN_FUNDING_WINDOW_SECONDS..=MAX_SETTLEMENT_HORIZON_SECONDS)
            .contains(&request.funding_window_seconds)
        || !(MIN_SECOND_REFUND_AFTER_SECONDS..=MAX_SETTLEMENT_HORIZON_SECONDS)
            .contains(&request.second_refund_after_seconds)
        || !(MIN_REFUND_SAFETY_MARGIN_SECONDS..=MAX_SETTLEMENT_HORIZON_SECONDS)
            .contains(&request.refund_safety_margin_seconds)
        || request.funding_window_seconds >= request.second_refund_after_seconds
        || request
            .second_refund_after_seconds
            .checked_add(request.refund_safety_margin_seconds)
            .is_none_or(|horizon| horizon > MAX_SETTLEMENT_HORIZON_SECONDS)
        || request.bitcoin_minimum_confirmations == 0
        || request.hns_minimum_confirmations == 0
    {
        return Err(MarketError::UnsafeTimeouts);
    }
    Ok(())
}

fn load_local_offer(
    store: &WalletStore,
    wallet_id: WalletId,
    offer_id: [u8; 32],
) -> Result<PersistedLocalDirectOffer, MarketError> {
    let stored = store
        .load_entity::<PersistedLocalDirectOffer>(
            EntityKind::ShakescapeBoardObject,
            &local_record_id(wallet_id, offer_id),
        )?
        .ok_or(MarketError::UnknownShakescapeDirectOffer)?;
    let record = stored.value;
    if stored.revision != 1
        || record.storage_version != STORAGE_VERSION
        || record.wallet_id != wallet_id
        || record.offer_id != ObjectHash::new(offer_id)
        || record.session_id.as_bytes().iter().all(|byte| *byte == 0)
        || record.intent_id.as_bytes().iter().all(|byte| *byte == 0)
        || record.created_at_unix != stored.updated_at_unix
    {
        return Err(MarketError::CorruptShakescapeDirectOfferBoard);
    }
    Ok(record)
}

fn derive_maker_preimage(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    intent_id: ObjectHash,
    offer_id: [u8; 32],
) -> Result<Preimage, MarketError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(MarketError::Invariant)?;
    if seed.len() != RECOVERY_SEED_BYTES {
        return Err(MarketError::Invariant);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(MAKER_PREIMAGE_SALT), &seed);
    let mut info = Vec::with_capacity(MAKER_PREIMAGE_INFO.len() + 32 + 32 + 32);
    info.extend_from_slice(MAKER_PREIMAGE_INFO);
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(intent_id.as_bytes());
    info.extend_from_slice(&offer_id);
    let mut preimage = Zeroizing::new([0_u8; Preimage::LENGTH]);
    hkdf.expand(&info, &mut *preimage)
        .map_err(|_| MarketError::Invariant)?;
    if preimage.iter().all(|byte| *byte == 0) {
        return Err(MarketError::Invariant);
    }
    Ok(Preimage::new(*preimage))
}

fn maker_preimage_record_id(session_id: SessionId) -> Vec<u8> {
    let mut id = Vec::with_capacity(MAKER_PREIMAGE_RECORD_DOMAIN.len() + 32);
    id.extend_from_slice(MAKER_PREIMAGE_RECORD_DOMAIN);
    id.extend_from_slice(session_id.as_bytes());
    id
}

pub(crate) fn derive_board_identity(
    store: &WalletStore,
    wallet_id: WalletId,
    policy: &ShakescapeDirectOfferBoardPolicy,
) -> Result<Zeroizing<[u8; 32]>, MarketError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(MarketError::Invariant)?;
    if seed.len() != RECOVERY_SEED_BYTES {
        return Err(MarketError::Invariant);
    }
    let network = policy
        .network()
        .encode()
        .map_err(|_| MarketError::InvalidShakescapeDirectOfferPolicy)?;
    let hkdf = Hkdf::<Sha256>::new(Some(IDENTITY_SALT), &seed);
    for attempt in 0..MAX_DERIVATION_ATTEMPTS {
        let mut info = Vec::with_capacity(IDENTITY_INFO.len() + 32 + network.len() + 4);
        info.extend_from_slice(IDENTITY_INFO);
        info.extend_from_slice(wallet_id.as_bytes());
        info.extend_from_slice(&network);
        info.extend_from_slice(&attempt.to_be_bytes());
        let mut secret = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, &mut *secret)
            .map_err(|_| MarketError::Invariant)?;
        if SigningKey::from_bytes((&*secret).into()).is_ok() {
            return Ok(secret);
        }
    }
    Err(MarketError::Invariant)
}

fn offer_intent(
    policy: &ShakescapeDirectOfferBoardPolicy,
    request: ShakescapeBtcForHnsOfferRequest,
) -> Result<ObjectHash, MarketError> {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DOMAIN);
    hasher.update(STORAGE_VERSION.to_be_bytes());
    hasher.update(request.wallet_id.as_bytes());
    hasher.update(
        policy
            .network()
            .encode()
            .map_err(|_| MarketError::InvalidShakescapeDirectOfferPolicy)?,
    );
    hasher.update(request.btc_amount_sats.to_be_bytes());
    hasher.update(request.hns_amount_dollarydoos.to_be_bytes());
    hasher.update(request.bitcoin_fee_reserve_sats.to_be_bytes());
    hasher.update(request.created_at_unix.to_be_bytes());
    hasher.update(request.expires_at_unix.to_be_bytes());
    hasher.update(request.nonce);
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn offer_session_id(wallet_id: WalletId, nonce: [u8; 32], intent: ObjectHash) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(wallet_id.as_bytes());
    hasher.update(nonce);
    hasher.update(intent.as_bytes());
    SessionId::new(hasher.finalize().into())
}

fn local_record_prefix(wallet_id: WalletId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(RECORD_PREFIX.len() + 32);
    prefix.extend_from_slice(RECORD_PREFIX);
    prefix.extend_from_slice(wallet_id.as_bytes());
    prefix
}

fn local_record_id(wallet_id: WalletId, offer_id: [u8; 32]) -> Vec<u8> {
    let mut id = local_record_prefix(wallet_id);
    id.extend_from_slice(&offer_id);
    id
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        ChainId, DirectOfferTake, NetworkBinding, SignedObjectHeader, SwapAssetSide,
    };
    use hns_primitives::BlockHash;
    use hns_wallet_store::WalletStore;

    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn policy() -> ShakescapeDirectOfferBoardPolicy {
        ShakescapeDirectOfferBoardPolicy::new(NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        })
        .expect("policy")
    }

    fn seeded_store(wallet_id: WalletId) -> WalletStore {
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("store");
        store
            .put_secret(
                wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[0x31; RECOVERY_SEED_BYTES],
                1,
            )
            .expect("seed");
        store
    }

    fn public_key(secret: [u8; 32]) -> [u8; 33] {
        SigningKey::from_bytes((&secret).into())
            .expect("signing key")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key")
    }

    #[test]
    fn creates_recoverable_btc_for_hns_offer_and_lists_exact_reserve() {
        let wallet_id = WalletId::new([9; 16]);
        let mut store = seeded_store(wallet_id);
        let request = ShakescapeBtcForHnsOfferRequest {
            wallet_id,
            btc_amount_sats: 9_000,
            hns_amount_dollarydoos: 5_000_000,
            bitcoin_fee_reserve_sats: 1_000,
            created_at_unix: 100,
            expires_at_unix: 1_000,
            nonce: [7; 32],
        };
        let created = create_shakescape_btc_for_hns_offer(&mut store, &policy(), request)
            .expect("created offer");
        assert_eq!(created.offer.offered_asset, AssetId::BTC);
        assert_eq!(created.offer.offered_amount, 9_000);
        assert_eq!(created.offer.received_asset, AssetId::HNS);
        assert_eq!(created.offer.received_amount, 5_000_000);
        assert_ne!(
            created.offer.signer_public_key,
            created.offer.maker_settlement_public_key
        );
        let listed = list_local_shakescape_direct_offers(&store, &policy(), wallet_id, 101)
            .expect("local offers");
        assert_eq!(listed, vec![created]);
        assert!(
            list_local_shakescape_direct_offers(&store, &policy(), wallet_id, 1_000)
                .expect("expired list")
                .is_empty()
        );
    }

    #[test]
    fn rejects_zero_fee_reserve_before_allocating_authority() {
        let wallet_id = WalletId::new([8; 16]);
        let mut store = seeded_store(wallet_id);
        let result = create_shakescape_btc_for_hns_offer(
            &mut store,
            &policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1,
                bitcoin_fee_reserve_sats: 0,
                created_at_unix: 100,
                expires_at_unix: 1_000,
                nonce: [6; 32],
            },
        );
        assert_eq!(result, Err(MarketError::InvalidShakescapeDirectOffer));
    }

    #[test]
    fn local_maker_can_cancel_its_retained_live_offer() {
        let wallet_id = WalletId::new([7; 16]);
        let mut store = seeded_store(wallet_id);
        let created = create_shakescape_btc_for_hns_offer(
            &mut store,
            &policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id,
                btc_amount_sats: 8_500,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_500,
                created_at_unix: 100,
                expires_at_unix: 1_000,
                nonce: [0xff; 32],
            },
        )
        .expect("created");
        let cancelled = cancel_shakescape_local_direct_offer(
            &mut store,
            &policy(),
            wallet_id,
            created.offer.offer_id.into_bytes(),
            200,
        )
        .expect("cancelled");
        assert_eq!(cancelled.cancelled_at_unix, Some(200));
        assert!(
            list_local_shakescape_direct_offers(&store, &policy(), wallet_id, 201)
                .expect("live offers")
                .is_empty()
        );
    }

    #[test]
    fn admitted_take_creates_one_recoverable_canonical_btc_first_proposal() {
        const START: u64 = 1_700_000_000;
        let wallet_id = WalletId::new([6; 16]);
        let mut store = seeded_store(wallet_id);
        let board_policy = policy();
        let swap_policy =
            crate::ShakescapeDirectSwapPolicy::new(board_policy).expect("swap policy");
        let created = create_shakescape_btc_for_hns_offer(
            &mut store,
            &board_policy,
            ShakescapeBtcForHnsOfferRequest {
                wallet_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [5; 32],
            },
        )
        .expect("offer");
        let mut take = DirectOfferTake {
            header: SignedObjectHeader {
                version: MARKETPLACE_PROTOCOL_VERSION,
                network: board_policy.network(),
                pair: MarketPair::HNS_BTC,
                signer_public_key: [0; 33],
                sequence: 2,
                created_at: START + 10,
                expires_at: START + 10_000,
            },
            offer_id: created.offer.offer_id.into_bytes(),
            swap_session_id: created.offer.session_id.into_bytes(),
            taker_settlement_public_key: public_key([11; 32]),
            signature: [0; 64],
        };
        take.sign(&[10; 32]).expect("take signature");
        let take_envelope = CrossChainMessage::TakeDirectOffer(take.clone())
            .encode_envelope(77)
            .expect("take envelope");
        crate::admit_shakescape_direct_offer_take(
            &mut store,
            &swap_policy,
            &take_envelope,
            START + 10,
        )
        .expect("admit take");

        let made = create_shakescape_btc_for_hns_maker_proposal(
            &mut store,
            &swap_policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id,
                session_id: created.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("maker proposal");
        made.proposal
            .verify_for_direct_offer(
                &crate::load_shakescape_direct_offer(
                    &store,
                    &board_policy,
                    created.offer.offer_id.into_bytes(),
                )
                .expect("load offer")
                .expect("offer exists")
                .offer,
                &take,
                board_policy.network(),
                START + 20,
            )
            .expect("proposal verifies");
        let terms = made.proposal.terms();
        assert_eq!(terms.first_funding_chain, ChainId::BITCOIN);
        assert_eq!(terms.offered_refund_deadline.value, START + 7_220);
        assert_eq!(terms.received_refund_deadline.value, START + 3_620);
        assert_eq!(
            build_shakescape_bitcoin_htlc(terms, SwapAssetSide::Offered)
                .expect("bitcoin descriptor")
                .commitment
                .into_bytes(),
            terms.offered_lock_commitment
        );
        let preimage = load_shakescape_btc_for_hns_maker_preimage(&store, created.offer.session_id)
            .expect("load preimage")
            .expect("preimage retained");
        assert_eq!(
            Sha256::digest(preimage.expose_for_settlement()).as_slice(),
            terms.hashlock
        );
        let (request_id, wire) =
            CrossChainMessage::decode_envelope(&made.envelope).expect("decode proposal envelope");
        assert_eq!(request_id, 77);
        assert_eq!(wire, CrossChainMessage::SwapSessionProposal(made.proposal));
        let retried = create_shakescape_btc_for_hns_maker_proposal(
            &mut store,
            &swap_policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id,
                session_id: created.offer.session_id,
                now_unix: START + 21,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("idempotent retry");
        assert_eq!(retried.envelope, made.envelope);
    }
}
