//! Wallet-derived taker authority for exact direct BTC-for-HNS offers.

use hns_marketplace_protocol::{
    CrossChainMessage, DirectOfferTake, MARKETPLACE_PROTOCOL_VERSION, MarketPair,
    SignedObjectHeader, SwapSessionHello,
};
use hns_wallet_store::{EntityKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use serde::{Deserialize, Serialize};

use crate::direct_maker::derive_board_identity;
use crate::{
    CrossChainSwapKeyRequest, DenuoDirectSwapPolicy, MarketError, SwapParticipant, SwapSession,
    admit_denuo_direct_offer_take, admit_denuo_direct_swap_hello, allocate_cross_chain_swap_key,
    derive_cross_chain_swap_key_from_store, load_denuo_direct_offer, load_denuo_direct_swap,
    open_denuo_execution,
};

const STORAGE_VERSION: u16 = 1;
const RECORD_PREFIX: &[u8] = b"local-direct-take/v1/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoHnsForBtcTakeRequest {
    pub wallet_id: WalletId,
    pub offer_id: ObjectHash,
    pub hns_fee_reserve_dollarydoos: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoLocalDirectTake {
    pub offer_id: ObjectHash,
    pub session_id: SessionId,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub hns_fee_reserve_dollarydoos: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoTakerAcceptedSession {
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

/// Sign and durably admit one exact take. The session identifier comes from
/// the signed offer; the taker has no authority to replace it.
pub fn create_denuo_hns_for_btc_take(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    request: DenuoHnsForBtcTakeRequest,
) -> Result<DenuoLocalDirectTake, MarketError> {
    validate_request(request)?;
    let offer =
        load_denuo_direct_offer(store, &policy.board_policy(), request.offer_id.into_bytes())?
            .ok_or(MarketError::UnknownDenuoDirectOffer)?;
    if !offer.is_active_at(request.created_at_unix)
        || offer.offer.swap_session_id == [0; 32]
        || request.expires_at_unix > offer.offer.header.expires_at
    {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    let session_id = SessionId::new(offer.offer.swap_session_id);
    if let Some(existing) = load_local_take(store, request.wallet_id, session_id)? {
        if existing.offer_id != request.offer_id {
            return Err(MarketError::DenuoDirectSwapConflict);
        }
        return project_local_take(store, policy, existing);
    }
    if load_denuo_direct_swap(store, policy, session_id)?.is_some() {
        return Err(MarketError::DenuoDirectSwapConflict);
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
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let request_id = sequence.max(1);
    let envelope = CrossChainMessage::TakeDirectOffer(take)
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    admit_denuo_direct_offer_take(store, policy, &envelope, request.created_at_unix)?;
    let persisted = PersistedLocalDirectTake {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        offer_id: request.offer_id,
        session_id,
        hns_fee_reserve_dollarydoos: request.hns_fee_reserve_dollarydoos,
        created_at_unix: request.created_at_unix,
    };
    store.save_entity(
        EntityKind::DenuoBoardObject,
        &record_id(request.wallet_id, session_id),
        0,
        &persisted,
        request.created_at_unix,
    )?;
    project_local_take(store, policy, persisted)
}

/// Verify and countersign the maker proposal, admit the accepted hello, and
/// open the restart-safe execution journal before returning bytes to send.
pub fn accept_denuo_hns_for_btc_maker_proposal(
    store: &mut WalletStore,
    policy: &DenuoDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
    now_unix: u64,
) -> Result<DenuoTakerAcceptedSession, MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    let local = load_local_take(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    let record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if local.offer_id != ObjectHash::new(record.offer.offer_id) {
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    if let Some(hello) = record.hello {
        let execution = open_denuo_execution(store, policy, session_id, now_unix)?;
        let request_id = record
            .proposal_request_id
            .ok_or(MarketError::CorruptDenuoDirectSwap)?;
        let envelope = CrossChainMessage::SwapSessionHello(hello.clone())
            .encode_envelope(request_id)
            .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
        return Ok(DenuoTakerAcceptedSession {
            hello,
            execution,
            envelope,
        });
    }
    let proposal = record.proposal.ok_or(MarketError::InvalidDenuoDirectSwap)?;
    let request_id = record
        .proposal_request_id
        .ok_or(MarketError::CorruptDenuoDirectSwap)?;
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
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    let hello = settlement
        .accept_taker(proposal, now_unix)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let envelope = CrossChainMessage::SwapSessionHello(hello.clone())
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    admit_denuo_direct_swap_hello(store, policy, &envelope, now_unix)?;
    let execution = open_denuo_execution(store, policy, session_id, now_unix)?;
    Ok(DenuoTakerAcceptedSession {
        hello,
        execution,
        envelope,
    })
}

pub fn list_local_denuo_direct_takes(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    wallet_id: WalletId,
) -> Result<Vec<DenuoLocalDirectTake>, MarketError> {
    store
        .list_entities_by_id_prefix::<PersistedLocalDirectTake>(
            EntityKind::DenuoBoardObject,
            &record_prefix(wallet_id),
            crate::MAX_DENUO_DIRECT_SWAPS + 1,
        )?
        .into_iter()
        .map(|stored| {
            validate_stored(wallet_id, stored)
                .and_then(|row| project_local_take(store, policy, row))
        })
        .collect()
}

#[doc(hidden)]
pub fn derive_local_hns_for_btc_taker_key(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    wallet_id: WalletId,
    session_id: SessionId,
) -> Result<(crate::CrossChainSwapKey, u64), MarketError> {
    let local = load_local_take(store, wallet_id, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    let record = load_denuo_direct_swap(store, policy, session_id)?
        .ok_or(MarketError::UnknownDenuoDirectSwap)?;
    if record.offer.offer_id != local.offer_id.into_bytes()
        || record.hello.as_ref().is_none_or(|hello| {
            hello.swap_session_id != session_id.into_bytes()
                || hello.offered_asset != hns_marketplace_protocol::AssetId::BTC
                || hello.received_asset != hns_marketplace_protocol::AssetId::HNS
        })
    {
        return Err(MarketError::DenuoDirectSwapConflict);
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
        return Err(MarketError::DenuoDirectSwapConflict);
    }
    Ok((key, local.hns_fee_reserve_dollarydoos))
}

fn validate_request(request: DenuoHnsForBtcTakeRequest) -> Result<(), MarketError> {
    if request.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.offer_id.as_bytes().iter().all(|byte| *byte == 0)
        || request.hns_fee_reserve_dollarydoos == 0
        || request.created_at_unix == 0
        || request.expires_at_unix <= request.created_at_unix
        || request.nonce.iter().all(|byte| *byte == 0)
    {
        return Err(MarketError::InvalidDenuoDirectSwap);
    }
    Ok(())
}

fn project_local_take(
    store: &WalletStore,
    policy: &DenuoDirectSwapPolicy,
    local: PersistedLocalDirectTake,
) -> Result<DenuoLocalDirectTake, MarketError> {
    let record = load_denuo_direct_swap(store, policy, local.session_id)?
        .ok_or(MarketError::CorruptDenuoDirectSwap)?;
    if record.offer.offer_id != local.offer_id.into_bytes()
        || record.offer.swap_session_id != local.session_id.into_bytes()
        || record.take.swap_session_id != local.session_id.into_bytes()
    {
        return Err(MarketError::CorruptDenuoDirectSwap);
    }
    let btc_amount_sats = u64::try_from(record.offer.offered_amount.get())
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let hns_amount_dollarydoos = u64::try_from(record.offer.received_amount.get())
        .map_err(|_| MarketError::InvalidDenuoDirectSwap)?;
    let envelope = CrossChainMessage::TakeDirectOffer(record.take.clone())
        .encode_envelope(record.take_request_id)
        .map_err(|_| MarketError::CorruptDenuoDirectSwap)?;
    Ok(DenuoLocalDirectTake {
        offer_id: local.offer_id,
        session_id: local.session_id,
        btc_amount_sats,
        hns_amount_dollarydoos,
        hns_fee_reserve_dollarydoos: local.hns_fee_reserve_dollarydoos,
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
            EntityKind::DenuoBoardObject,
            &record_id(wallet_id, session_id),
        )?
        .map(|stored| validate_stored(wallet_id, stored))
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
        return Err(MarketError::CorruptDenuoDirectSwap);
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

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{ChainId, NetworkBinding};
    use hns_primitives::BlockHash;
    use hns_wallet_store::{RECOVERY_SEED_BYTES, SecretKind};

    use super::*;
    use crate::{
        DenuoBtcForHnsMakerProposalRequest, DenuoBtcForHnsOfferRequest,
        DenuoDirectOfferBoardPolicy, create_denuo_btc_for_hns_maker_proposal,
        create_denuo_btc_for_hns_offer,
    };

    const PASSPHRASE: &str = "two-party direct atomic swap test";
    const START: u64 = 1_700_000_000;

    fn policy() -> DenuoDirectSwapPolicy {
        DenuoDirectSwapPolicy::new(
            DenuoDirectOfferBoardPolicy::new(NetworkBinding {
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
        let offer = create_denuo_btc_for_hns_offer(
            &mut maker_store,
            &policy.board_policy(),
            DenuoBtcForHnsOfferRequest {
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
        let signed_offer = load_denuo_direct_offer(
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
        crate::admit_denuo_direct_offer(
            &mut taker_store,
            &policy.board_policy(),
            &offer_envelope,
            START,
        )
        .expect("taker admits offer");

        let take = create_denuo_hns_for_btc_take(
            &mut taker_store,
            &policy,
            DenuoHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [8; 32],
            },
        )
        .expect("taker signs take");
        crate::admit_denuo_direct_offer_take(&mut maker_store, &policy, &take.envelope, START + 10)
            .expect("maker admits take");

        let proposal = create_denuo_btc_for_hns_maker_proposal(
            &mut maker_store,
            &policy,
            DenuoBtcForHnsMakerProposalRequest {
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
        crate::admit_denuo_direct_swap_proposal(
            &mut taker_store,
            &policy,
            &proposal.envelope,
            START + 20,
        )
        .expect("taker admits proposal");
        let accepted = accept_denuo_hns_for_btc_maker_proposal(
            &mut taker_store,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("taker accepts proposal");
        crate::admit_denuo_direct_swap_hello(
            &mut maker_store,
            &policy,
            &accepted.envelope,
            START + 30,
        )
        .expect("maker admits hello");
        let maker_execution = open_denuo_execution(
            &mut maker_store,
            &policy,
            offer.offer.session_id,
            START + 30,
        )
        .expect("maker execution");
        assert_eq!(accepted.execution, maker_execution);
        assert_eq!(accepted.execution.state, crate::SwapState::TermsFrozen);
        assert_eq!(
            list_local_denuo_direct_takes(&taker_store, &policy, taker_id).expect("local takes"),
            vec![take]
        );
        let retried = accept_denuo_hns_for_btc_maker_proposal(
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
}
