//! Wallet-derived maker authority for exact direct BTC-for-HNS offers.
//!
//! Listing signatures and per-offer settlement signatures deliberately use
//! independent HKDF domains. Only public bindings and exact approved terms are
//! persisted; both signing scalars are re-derived from the encrypted recovery
//! seed when needed.

use hkdf::Hkdf;
use hns_marketplace_protocol::{
    AssetAmount, AssetId, CrossChainMessage, DirectOffer, DirectOfferCancellation,
    MARKETPLACE_PROTOCOL_VERSION, MarketPair, SignedObjectHeader,
};
use hns_wallet_store::{EntityKind, RECOVERY_SEED_BYTES, SecretKind, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    CrossChainSwapKeyRequest, DenuoDirectOfferBoardPolicy, DenuoDirectOfferSnapshot, MarketError,
    SwapParticipant, admit_denuo_direct_offer, admit_denuo_direct_offer_cancellation,
    allocate_cross_chain_swap_key,
};

const STORAGE_VERSION: u16 = 1;
const RECORD_PREFIX: &[u8] = b"local-direct-offer/v1/";
const INTENT_DOMAIN: &[u8] = b"hns-wallet/direct-offer-intent/v1\0";
const SESSION_DOMAIN: &[u8] = b"hns-wallet/direct-offer-session/v1\0";
const IDENTITY_SALT: &[u8] = b"hns-wallet/direct-board-identity/hkdf-sha256/v1\0";
const IDENTITY_INFO: &[u8] = b"hns-wallet/direct-board-identity/scalar/v1\0";
const MAX_DERIVATION_ATTEMPTS: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoBtcForHnsOfferRequest {
    pub wallet_id: WalletId,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub bitcoin_fee_reserve_sats: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 32],
}

impl DenuoBtcForHnsOfferRequest {
    fn validate(self) -> Result<(), MarketError> {
        if self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.btc_amount_sats == 0
            || self.hns_amount_dollarydoos == 0
            || self.bitcoin_fee_reserve_sats == 0
            || self.created_at_unix == 0
            || self.expires_at_unix <= self.created_at_unix
            || self.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(MarketError::InvalidDenuoDirectOffer);
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
    bitcoin_fee_reserve_sats: u64,
    created_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoLocalDirectOffer {
    pub offer: DenuoDirectOfferSnapshot,
    pub session_id: SessionId,
    pub bitcoin_fee_reserve_sats: u64,
}

pub fn create_denuo_btc_for_hns_offer(
    store: &mut WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    request: DenuoBtcForHnsOfferRequest,
) -> Result<DenuoLocalDirectOffer, MarketError> {
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
        maker_settlement_public_key: settlement.compressed_public_key(),
        offered_asset: AssetId::BTC,
        offered_amount: AssetAmount::new(u128::from(request.btc_amount_sats)),
        received_asset: AssetId::HNS,
        received_amount: AssetAmount::new(u128::from(request.hns_amount_dollarydoos)),
        signature: [0; 64],
    };
    offer
        .sign(&identity)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    let envelope = CrossChainMessage::DirectOffer(offer.clone())
        .encode_envelope(1)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    let snapshot =
        admit_denuo_direct_offer(store, policy, &envelope, request.created_at_unix)?.snapshot();
    let offer_id = ObjectHash::new(offer.offer_id);
    let record = PersistedLocalDirectOffer {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        offer_id,
        session_id,
        bitcoin_fee_reserve_sats: request.bitcoin_fee_reserve_sats,
        created_at_unix: request.created_at_unix,
    };
    store.save_entity(
        EntityKind::DenuoBoardObject,
        &local_record_id(request.wallet_id, offer.offer_id),
        0,
        &record,
        request.created_at_unix,
    )?;
    Ok(DenuoLocalDirectOffer {
        offer: snapshot,
        session_id,
        bitcoin_fee_reserve_sats: request.bitcoin_fee_reserve_sats,
    })
}

pub fn cancel_denuo_local_direct_offer(
    store: &mut WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    wallet_id: WalletId,
    offer_id: [u8; 32],
    now_unix: u64,
) -> Result<DenuoDirectOfferSnapshot, MarketError> {
    if now_unix == 0 || offer_id.iter().all(|byte| *byte == 0) {
        return Err(MarketError::InvalidDenuoDirectOffer);
    }
    let local = store
        .load_entity::<PersistedLocalDirectOffer>(
            EntityKind::DenuoBoardObject,
            &local_record_id(wallet_id, offer_id),
        )?
        .ok_or(MarketError::UnknownDenuoDirectOffer)?;
    if local.revision != 1
        || local.value.storage_version != STORAGE_VERSION
        || local.value.wallet_id != wallet_id
        || local.value.offer_id.into_bytes() != offer_id
    {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    let offer = crate::load_denuo_direct_offer(store, policy, offer_id)?
        .ok_or(MarketError::UnknownDenuoDirectOffer)?;
    if !offer.is_active_at(now_unix) {
        return Err(MarketError::InvalidDenuoDirectOffer);
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
                .ok_or(MarketError::InvalidDenuoDirectOffer)?,
            created_at: now_unix,
            expires_at: offer.offer.header.expires_at,
        },
        offer_id,
        offer_sequence: offer.offer.header.sequence,
        signature: [0; 64],
    };
    cancellation
        .sign(&identity)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    let envelope = CrossChainMessage::CancelDirectOffer(cancellation)
        .encode_envelope(1)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    Ok(admit_denuo_direct_offer_cancellation(store, policy, &envelope, now_unix)?.snapshot())
}

pub fn list_local_denuo_direct_offers(
    store: &WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    wallet_id: WalletId,
    now_unix: u64,
) -> Result<Vec<DenuoLocalDirectOffer>, MarketError> {
    let prefix = local_record_prefix(wallet_id);
    let stored = store.list_entities_by_id_prefix::<PersistedLocalDirectOffer>(
        EntityKind::DenuoBoardObject,
        &prefix,
        crate::MAX_DENUO_DIRECT_OFFERS,
    )?;
    let mut offers = Vec::with_capacity(stored.len());
    for stored in stored {
        let record = stored.value;
        if stored.revision != 1
            || record.storage_version != STORAGE_VERSION
            || record.wallet_id != wallet_id
            || record.created_at_unix != stored.updated_at_unix
        {
            return Err(MarketError::CorruptDenuoDirectOfferBoard);
        }
        let Some(offer) =
            crate::load_denuo_direct_offer(store, policy, record.offer_id.into_bytes())?
        else {
            return Err(MarketError::CorruptDenuoDirectOfferBoard);
        };
        if offer.is_active_at(now_unix) {
            offers.push(DenuoLocalDirectOffer {
                offer: offer.snapshot(),
                session_id: record.session_id,
                bitcoin_fee_reserve_sats: record.bitcoin_fee_reserve_sats,
            });
        }
    }
    Ok(offers)
}

fn derive_board_identity(
    store: &WalletStore,
    wallet_id: WalletId,
    policy: &DenuoDirectOfferBoardPolicy,
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
        .map_err(|_| MarketError::InvalidDenuoDirectOfferPolicy)?;
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
    policy: &DenuoDirectOfferBoardPolicy,
    request: DenuoBtcForHnsOfferRequest,
) -> Result<ObjectHash, MarketError> {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DOMAIN);
    hasher.update(STORAGE_VERSION.to_be_bytes());
    hasher.update(request.wallet_id.as_bytes());
    hasher.update(
        policy
            .network()
            .encode()
            .map_err(|_| MarketError::InvalidDenuoDirectOfferPolicy)?,
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
    use hns_marketplace_protocol::{ChainId, NetworkBinding};
    use hns_primitives::BlockHash;
    use hns_wallet_store::WalletStore;

    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn policy() -> DenuoDirectOfferBoardPolicy {
        DenuoDirectOfferBoardPolicy::new(NetworkBinding {
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

    #[test]
    fn creates_recoverable_btc_for_hns_offer_and_lists_exact_reserve() {
        let wallet_id = WalletId::new([9; 16]);
        let mut store = seeded_store(wallet_id);
        let request = DenuoBtcForHnsOfferRequest {
            wallet_id,
            btc_amount_sats: 9_000,
            hns_amount_dollarydoos: 5_000_000,
            bitcoin_fee_reserve_sats: 1_000,
            created_at_unix: 100,
            expires_at_unix: 1_000,
            nonce: [7; 32],
        };
        let created =
            create_denuo_btc_for_hns_offer(&mut store, &policy(), request).expect("created offer");
        assert_eq!(created.offer.offered_asset, AssetId::BTC);
        assert_eq!(created.offer.offered_amount, 9_000);
        assert_eq!(created.offer.received_asset, AssetId::HNS);
        assert_eq!(created.offer.received_amount, 5_000_000);
        assert_ne!(
            created.offer.signer_public_key,
            created.offer.maker_settlement_public_key
        );
        let listed = list_local_denuo_direct_offers(&store, &policy(), wallet_id, 101)
            .expect("local offers");
        assert_eq!(listed, vec![created]);
        assert!(
            list_local_denuo_direct_offers(&store, &policy(), wallet_id, 1_000)
                .expect("expired list")
                .is_empty()
        );
    }

    #[test]
    fn rejects_zero_fee_reserve_before_allocating_authority() {
        let wallet_id = WalletId::new([8; 16]);
        let mut store = seeded_store(wallet_id);
        let result = create_denuo_btc_for_hns_offer(
            &mut store,
            &policy(),
            DenuoBtcForHnsOfferRequest {
                wallet_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 1,
                bitcoin_fee_reserve_sats: 0,
                created_at_unix: 100,
                expires_at_unix: 1_000,
                nonce: [6; 32],
            },
        );
        assert_eq!(result, Err(MarketError::InvalidDenuoDirectOffer));
    }

    #[test]
    fn local_maker_can_cancel_its_retained_live_offer() {
        let wallet_id = WalletId::new([7; 16]);
        let mut store = seeded_store(wallet_id);
        let created = create_denuo_btc_for_hns_offer(
            &mut store,
            &policy(),
            DenuoBtcForHnsOfferRequest {
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
        let cancelled = cancel_denuo_local_direct_offer(
            &mut store,
            &policy(),
            wallet_id,
            created.offer.offer_id.into_bytes(),
            200,
        )
        .expect("cancelled");
        assert_eq!(cancelled.cancelled_at_unix, Some(200));
        assert!(
            list_local_denuo_direct_offers(&store, &policy(), wallet_id, 201)
                .expect("live offers")
                .is_empty()
        );
    }
}
