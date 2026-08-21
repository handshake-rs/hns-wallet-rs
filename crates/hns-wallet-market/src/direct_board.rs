//! Wallet-owned admission and presentation state for live direct HNS/BTC offers.
//!
//! The board stores signed exact terms.  It deliberately stores no oracle,
//! reporter, source, historical trade tape, or derived execution price.

use std::collections::{BTreeMap, BTreeSet};

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, DirectOffer, DirectOfferCancellation, MarketPair, NetworkBinding,
};
use hns_wallet_store::{EntityKind, StoredEntity, WalletStore};
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MarketError;

const DIRECT_OFFER_BOARD_SCHEMA_VERSION: u16 = 1;
const DIRECT_OFFER_BOARD_POLICY_DOMAIN: &[u8] = b"hns-wallet-direct-offer-board-policy-v1\0";
const DIRECT_OFFER_BOARD_RECORD_PREFIX: &[u8] = b"denuo-v2-direct-offer\0";

/// A full board fits into the protocol inventory bound. The wallet fails
/// closed rather than silently dropping live offers.
pub const MAX_DENUO_DIRECT_OFFERS: usize = hns_marketplace_protocol::MAX_INVENTORY_ENTRIES;

/// The exact local network binding for direct HNS/BTC offers. This has no
/// price-policy fields: a signed offer owns its exact amounts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoDirectOfferBoardPolicy {
    network: NetworkBinding,
    fingerprint: ObjectHash,
}

impl DenuoDirectOfferBoardPolicy {
    pub fn new(network: NetworkBinding) -> Result<Self, MarketError> {
        network
            .validate_for_pair(MarketPair::HNS_BTC)
            .map_err(|_| MarketError::InvalidDenuoDirectOfferPolicy)?;
        let mut hasher = Sha256::new();
        hasher.update(DIRECT_OFFER_BOARD_POLICY_DOMAIN);
        hasher.update(
            network
                .encode()
                .map_err(|_| MarketError::InvalidDenuoDirectOfferPolicy)?,
        );
        Ok(Self {
            network,
            fingerprint: ObjectHash::new(hasher.finalize().into()),
        })
    }

    pub const fn network(self) -> NetworkBinding {
        self.network
    }

    pub const fn pair(self) -> MarketPair {
        MarketPair::HNS_BTC
    }

    pub const fn fingerprint(self) -> ObjectHash {
        self.fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDirectOffer {
    schema_version: u16,
    policy_fingerprint: ObjectHash,
    offer_id: ObjectHash,
    accepted_at_unix: u64,
    offer_hex: String,
    cancellation_hex: Option<String>,
    cancelled_at_unix: Option<u64>,
}

/// Fully re-authenticated board material. It is retained locally to let a
/// later take/session bind to precisely the same signed maker terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoDirectOfferRecord {
    pub store_revision: u64,
    pub accepted_at_unix: u64,
    pub cancelled_at_unix: Option<u64>,
    pub offer: DirectOffer,
    pub cancellation: Option<DirectOfferCancellation>,
}

impl DenuoDirectOfferRecord {
    pub fn snapshot(&self) -> DenuoDirectOfferSnapshot {
        DenuoDirectOfferSnapshot {
            store_revision: self.store_revision,
            offer_id: ObjectHash::new(self.offer.offer_id),
            signer_public_key: self.offer.header.signer_public_key,
            maker_settlement_public_key: self.offer.maker_settlement_public_key,
            offered_asset: self.offer.offered_asset,
            offered_amount: self.offer.offered_amount.get(),
            received_asset: self.offer.received_asset,
            received_amount: self.offer.received_amount.get(),
            created_at_unix: self.offer.header.created_at,
            expires_at_unix: self.offer.header.expires_at,
            accepted_at_unix: self.accepted_at_unix,
            cancelled_at_unix: self.cancelled_at_unix,
        }
    }

    pub fn is_active_at(&self, now_unix: u64) -> bool {
        self.cancellation.is_none()
            && self.offer.header.created_at <= now_unix
            && now_unix < self.offer.header.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoDirectOfferSnapshot {
    pub store_revision: u64,
    pub offer_id: ObjectHash,
    pub signer_public_key: [u8; 33],
    pub maker_settlement_public_key: [u8; 33],
    pub offered_asset: AssetId,
    pub offered_amount: u128,
    pub received_asset: AssetId,
    pub received_amount: u128,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub accepted_at_unix: u64,
    pub cancelled_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoDirectOfferAdmission {
    Inserted(DenuoDirectOfferSnapshot),
    Existing(DenuoDirectOfferSnapshot),
}

impl DenuoDirectOfferAdmission {
    pub const fn snapshot(self) -> DenuoDirectOfferSnapshot {
        match self {
            Self::Inserted(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoDirectOfferCancellationAdmission {
    Applied(DenuoDirectOfferSnapshot),
    Existing(DenuoDirectOfferSnapshot),
}

impl DenuoDirectOfferCancellationAdmission {
    pub const fn snapshot(self) -> DenuoDirectOfferSnapshot {
        match self {
            Self::Applied(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

/// One display level of the live board. The ratio is exact integer units of
/// satoshis per HNS base unit, reduced before grouping. It is UI metadata;
/// taking an offer always reuses its signed exact amounts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoDirectOfferLevel {
    pub maker_sells_hns: bool,
    pub btc_per_hns_numerator: u128,
    pub btc_per_hns_denominator: u128,
    pub total_hns_amount: u128,
    pub total_btc_amount: u128,
    pub offer_count: usize,
}

pub fn load_denuo_direct_offers(
    store: &WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    now_unix: u64,
) -> Result<Vec<DenuoDirectOfferRecord>, MarketError> {
    let stored = store.list_entities_by_id_prefix::<PersistedDirectOffer>(
        EntityKind::DenuoBoardObject,
        &record_prefix(policy),
        MAX_DENUO_DIRECT_OFFERS + 1,
    )?;
    if stored.len() > MAX_DENUO_DIRECT_OFFERS {
        return Err(MarketError::DenuoDirectOfferCapacity);
    }
    let mut records = stored
        .into_iter()
        .map(|stored| decode_stored_offer(policy, stored))
        .collect::<Result<Vec<_>, _>>()?;
    records.retain(|record| {
        record.offer.header.expires_at > now_unix
            && record
                .cancellation
                .as_ref()
                .is_none_or(|cancellation| cancellation.header.expires_at > now_unix)
    });
    records.sort_by_key(|record| record.offer.offer_id);
    Ok(records)
}

pub fn load_denuo_direct_offer(
    store: &WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    offer_id: [u8; 32],
) -> Result<Option<DenuoDirectOfferRecord>, MarketError> {
    if offer_id == [0; 32] {
        return Err(MarketError::InvalidDenuoDirectOffer);
    }
    store
        .load_entity::<PersistedDirectOffer>(
            EntityKind::DenuoBoardObject,
            &record_id(policy, offer_id),
        )?
        .map(|stored| decode_stored_offer(policy, stored))
        .transpose()
}

pub fn live_denuo_direct_offer_levels(
    store: &WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    now_unix: u64,
) -> Result<Vec<DenuoDirectOfferLevel>, MarketError> {
    let mut grouped = BTreeMap::<(bool, u128, u128), DenuoDirectOfferLevel>::new();
    for record in load_denuo_direct_offers(store, policy, now_unix)? {
        if !record.is_active_at(now_unix) {
            continue;
        }
        let (maker_sells_hns, hns, btc) = if record.offer.offered_asset == AssetId::HNS {
            (
                true,
                record.offer.offered_amount.get(),
                record.offer.received_amount.get(),
            )
        } else {
            (
                false,
                record.offer.received_amount.get(),
                record.offer.offered_amount.get(),
            )
        };
        let divisor = gcd(btc, hns);
        let key = (maker_sells_hns, btc / divisor, hns / divisor);
        let entry = grouped.entry(key).or_insert(DenuoDirectOfferLevel {
            maker_sells_hns,
            btc_per_hns_numerator: key.1,
            btc_per_hns_denominator: key.2,
            total_hns_amount: 0,
            total_btc_amount: 0,
            offer_count: 0,
        });
        entry.total_hns_amount = entry
            .total_hns_amount
            .checked_add(hns)
            .ok_or(MarketError::Invariant)?;
        entry.total_btc_amount = entry
            .total_btc_amount
            .checked_add(btc)
            .ok_or(MarketError::Invariant)?;
        entry.offer_count = entry
            .offer_count
            .checked_add(1)
            .ok_or(MarketError::Invariant)?;
    }
    Ok(grouped.into_values().collect())
}

/// Admit one direct offer from a canonical Denuo envelope. The same entry
/// point is also used for a wallet's own offer before it is sent, ensuring a
/// later inbound take can only reference local exact terms.
pub fn admit_denuo_direct_offer(
    store: &mut WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectOfferAdmission, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::DirectOffer(offer) = message else {
        return Err(MarketError::InvalidDenuoDirectOffer);
    };
    offer
        .verify_at(policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    let offer_id = offer.offer_id;
    if let Some(existing) = load_denuo_direct_offer(store, policy, offer_id)? {
        if existing.offer == offer {
            return Ok(DenuoDirectOfferAdmission::Existing(existing.snapshot()));
        }
        return Err(MarketError::DenuoDirectOfferConflict);
    }
    if load_denuo_direct_offers(store, policy, accepted_at_unix)?.len() >= MAX_DENUO_DIRECT_OFFERS {
        return Err(MarketError::DenuoDirectOfferCapacity);
    }
    let persisted = PersistedDirectOffer {
        schema_version: DIRECT_OFFER_BOARD_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint(),
        offer_id: ObjectHash::new(offer_id),
        accepted_at_unix,
        offer_hex: encode_hex(&offer)?,
        cancellation_hex: None,
        cancelled_at_unix: None,
    };
    let revision = store.save_entity(
        EntityKind::DenuoBoardObject,
        &record_id(policy, offer_id),
        0,
        &persisted,
        accepted_at_unix,
    )?;
    let record = DenuoDirectOfferRecord {
        store_revision: revision,
        accepted_at_unix,
        cancelled_at_unix: None,
        offer,
        cancellation: None,
    };
    Ok(DenuoDirectOfferAdmission::Inserted(record.snapshot()))
}

pub fn admit_denuo_direct_offer_cancellation(
    store: &mut WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoDirectOfferCancellationAdmission, MarketError> {
    let (_, message) = decode_canonical_envelope(envelope_bytes)?;
    let CrossChainMessage::CancelDirectOffer(cancellation) = message else {
        return Err(MarketError::InvalidDenuoDirectOffer);
    };
    let mut record = load_denuo_direct_offer(store, policy, cancellation.offer_id)?
        .ok_or(MarketError::UnknownDenuoDirectOffer)?;
    cancellation
        .verify_for_offer(&record.offer, policy.network(), accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)?;
    if let Some(existing) = &record.cancellation {
        if existing == &cancellation {
            return Ok(DenuoDirectOfferCancellationAdmission::Existing(
                record.snapshot(),
            ));
        }
        return Err(MarketError::DenuoDirectOfferConflict);
    }
    let persisted = PersistedDirectOffer {
        schema_version: DIRECT_OFFER_BOARD_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint(),
        offer_id: ObjectHash::new(record.offer.offer_id),
        accepted_at_unix: record.accepted_at_unix,
        offer_hex: encode_hex(&record.offer)?,
        cancellation_hex: Some(encode_hex(&cancellation)?),
        cancelled_at_unix: Some(accepted_at_unix),
    };
    let next_revision = store.save_entity(
        EntityKind::DenuoBoardObject,
        &record_id(policy, record.offer.offer_id),
        record.store_revision,
        &persisted,
        accepted_at_unix,
    )?;
    record.store_revision = next_revision;
    record.cancelled_at_unix = Some(accepted_at_unix);
    record.cancellation = Some(cancellation);
    Ok(DenuoDirectOfferCancellationAdmission::Applied(
        record.snapshot(),
    ))
}

pub fn denuo_direct_offer_inventory(
    store: &WalletStore,
    policy: &DenuoDirectOfferBoardPolicy,
    now_unix: u64,
) -> Result<Vec<[u8; 32]>, MarketError> {
    let ids = load_denuo_direct_offers(store, policy, now_unix)?
        .into_iter()
        .filter(|record| record.is_active_at(now_unix))
        .map(|record| record.offer.offer_id)
        .collect::<Vec<_>>();
    if ids.len() > MAX_DENUO_DIRECT_OFFERS || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
    {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    Ok(ids)
}

pub(crate) fn decode_canonical_envelope(
    envelope_bytes: &[u8],
) -> Result<(u64, CrossChainMessage), MarketError> {
    if envelope_bytes.is_empty() {
        return Err(MarketError::InvalidDenuoPeerMessage);
    }
    let (request_id, message) = CrossChainMessage::decode_envelope(envelope_bytes)
        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
    if message
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?
        != envelope_bytes
    {
        return Err(MarketError::InvalidDenuoPeerMessage);
    }
    Ok((request_id, message))
}

fn decode_stored_offer(
    policy: &DenuoDirectOfferBoardPolicy,
    stored: StoredEntity<PersistedDirectOffer>,
) -> Result<DenuoDirectOfferRecord, MarketError> {
    let value = stored.value;
    if value.schema_version != DIRECT_OFFER_BOARD_SCHEMA_VERSION
        || value.policy_fingerprint != policy.fingerprint()
        || value.offer_id.into_bytes() == [0; 32]
        || stored.id != record_id(policy, value.offer_id.into_bytes())
        || value.cancellation_hex.is_some() != value.cancelled_at_unix.is_some()
    {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    let offer_bytes = decode_hex_bytes(&value.offer_hex)?;
    let offer =
        DirectOffer::decode(&offer_bytes).map_err(|_| MarketError::CorruptDenuoDirectOfferBoard)?;
    if offer.offer_id != value.offer_id.into_bytes()
        || offer
            .verify_at(policy.network(), value.accepted_at_unix)
            .is_err()
        || offer.encode().ok().as_deref() != Some(offer_bytes.as_slice())
    {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    let cancellation = value
        .cancellation_hex
        .as_deref()
        .map(decode_hex_bytes)
        .transpose()?
        .map(|bytes| {
            let cancellation = DirectOfferCancellation::decode(&bytes)
                .map_err(|_| MarketError::CorruptDenuoDirectOfferBoard)?;
            let cancelled_at = value
                .cancelled_at_unix
                .ok_or(MarketError::CorruptDenuoDirectOfferBoard)?;
            if cancelled_at < value.accepted_at_unix
                || cancellation
                    .verify_for_offer(&offer, policy.network(), cancelled_at)
                    .is_err()
                || cancellation.encode().ok().as_deref() != Some(bytes.as_slice())
            {
                return Err(MarketError::CorruptDenuoDirectOfferBoard);
            }
            Ok(cancellation)
        })
        .transpose()?;
    if stored.updated_at_unix != value.cancelled_at_unix.unwrap_or(value.accepted_at_unix) {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    Ok(DenuoDirectOfferRecord {
        store_revision: stored.revision,
        accepted_at_unix: value.accepted_at_unix,
        cancelled_at_unix: value.cancelled_at_unix,
        offer,
        cancellation,
    })
}

fn encode_hex<T: CanonicalDirectObject>(value: &T) -> Result<String, MarketError> {
    value
        .encode_canonical()
        .map(hex::encode)
        .map_err(|_| MarketError::InvalidDenuoDirectOffer)
}

fn decode_hex_bytes(encoded: &str) -> Result<Vec<u8>, MarketError> {
    let bytes = hex::decode(encoded).map_err(|_| MarketError::CorruptDenuoDirectOfferBoard)?;
    if hex::encode(&bytes) != encoded {
        return Err(MarketError::CorruptDenuoDirectOfferBoard);
    }
    Ok(bytes)
}

trait CanonicalDirectObject {
    fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError>;
}

impl CanonicalDirectObject for DirectOffer {
    fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError> {
        self.encode()
    }
}

impl CanonicalDirectObject for DirectOfferCancellation {
    fn encode_canonical(&self) -> Result<Vec<u8>, hns_marketplace_protocol::MarketplaceError> {
        self.encode()
    }
}

fn record_prefix(policy: &DenuoDirectOfferBoardPolicy) -> Vec<u8> {
    let mut id = Vec::with_capacity(DIRECT_OFFER_BOARD_RECORD_PREFIX.len() + 32);
    id.extend_from_slice(DIRECT_OFFER_BOARD_RECORD_PREFIX);
    id.extend_from_slice(policy.fingerprint().as_bytes());
    id
}

fn record_id(policy: &DenuoDirectOfferBoardPolicy, offer_id: [u8; 32]) -> Vec<u8> {
    let mut id = record_prefix(policy);
    id.extend_from_slice(&offer_id);
    id
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        AssetAmount, ChainId, MARKETPLACE_PROTOCOL_VERSION, SignedObjectHeader,
    };
    use hns_primitives::BlockHash;
    use k256::ecdsa::SigningKey;

    use super::*;

    const PASSPHRASE: &str = "direct-offer board test";

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn key(byte: u8) -> [u8; 33] {
        SigningKey::from_bytes((&[byte; 32]).into())
            .expect("valid deterministic signing key")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed SEC1 public key")
    }

    fn header(sequence: u64) -> SignedObjectHeader {
        SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at: 100,
            expires_at: 300,
        }
    }

    #[test]
    fn exact_offers_are_persisted_and_grouped_without_an_oracle_or_history() {
        let policy = DenuoDirectOfferBoardPolicy::new(network()).expect("board policy");
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("wallet store");
        let mut offer = DirectOffer {
            header: header(1),
            offer_id: [0; 32],
            maker_settlement_public_key: key(9),
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(10_000_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(2_000),
            signature: [0; 64],
        };
        offer.sign(&[7; 32]).expect("signed exact offer");
        let offer_envelope = CrossChainMessage::DirectOffer(offer.clone())
            .encode_envelope(1)
            .expect("canonical offer envelope");
        assert!(matches!(
            admit_denuo_direct_offer(&mut store, &policy, &offer_envelope, 150),
            Ok(DenuoDirectOfferAdmission::Inserted(_))
        ));
        let levels = live_denuo_direct_offer_levels(&store, &policy, 150).expect("live levels");
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].offer_count, 1);
        assert_eq!(levels[0].total_hns_amount, 10_000_000);
        assert_eq!(levels[0].total_btc_amount, 2_000);
        assert_eq!(levels[0].btc_per_hns_numerator, 1);
        assert_eq!(levels[0].btc_per_hns_denominator, 5_000);

        let mut cancellation = DirectOfferCancellation {
            header: header(2),
            offer_id: offer.offer_id,
            offer_sequence: offer.header.sequence,
            signature: [0; 64],
        };
        cancellation.sign(&[7; 32]).expect("signed cancellation");
        let cancellation_envelope = CrossChainMessage::CancelDirectOffer(cancellation)
            .encode_envelope(0)
            .expect("canonical cancellation envelope");
        assert!(matches!(
            admit_denuo_direct_offer_cancellation(&mut store, &policy, &cancellation_envelope, 151),
            Ok(DenuoDirectOfferCancellationAdmission::Applied(_))
        ));
        assert!(
            live_denuo_direct_offer_levels(&store, &policy, 151)
                .expect("cancelled levels")
                .is_empty()
        );
    }
}
