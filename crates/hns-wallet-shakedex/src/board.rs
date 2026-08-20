use std::collections::{BTreeMap, BTreeSet};

use hns_swap::{FixedPriceListing, ListingCancellation};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, EntityPrefixSetLease, EntityReadSnapshot,
    EntityRevisionAssertion, StoreError, StoredEntity, StoredEntityMetadata, WalletStore,
};
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};

use crate::{
    MAX_NAME_MARKET_BOARD_OFFERS, ShakedexError, VerifiedFixedPriceListing,
    VerifiedListingCancellation,
};

const NAME_MARKET_BOARD_SCHEMA_VERSION: u16 = 1;
pub const NAME_MARKET_BOARD_RECORD_ID: &[u8] = b"canonical-name-market-board-v1";
const NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION: u16 = 2;
const NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_PREFIX: &[u8] = b"canonical-name-market-board-";
const NORMALIZED_NAME_MARKET_BOARD_HEAD_ID: &[u8] = b"canonical-name-market-board-head-v2";
const NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX: &[u8] = b"canonical-name-market-board-row-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX: &[u8] =
    b"canonical-name-market-board-listing-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_ROW_ID_DOMAIN: &[u8] =
    b"hns-wallet-name-market-board-row-id-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_ID_DOMAIN: &[u8] =
    b"hns-wallet-name-market-board-listing-index-id-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_ROW_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet-name-market-board-row-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_SET_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet-name-market-board-set-v2\0";
const NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_SET_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet-name-market-board-listing-index-set-v2\0";
const MAX_NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_RECORDS: usize =
    MAX_NAME_MARKET_BOARD_OFFERS * 2 + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardOfferStatus {
    Active,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedBoardOffer {
    pub listing_hash: ObjectHash,
    pub listing_bytes: Vec<u8>,
    pub network_magic: u32,
    pub network_genesis: ObjectHash,
    pub name_hash: ObjectHash,
    pub seller_public_key: Vec<u8>,
    pub sequence: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: BoardOfferStatus,
    pub cancellation_hash: Option<ObjectHash>,
    pub cancellation_bytes: Option<Vec<u8>>,
    pub cancellation_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SequenceWatermark {
    network_magic: u32,
    network_genesis: ObjectHash,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "record")]
enum PersistedNameMarketBoardEntity {
    HeadV2 {
        schema_version: u16,
        logical_revision: u64,
        row_count: u32,
        rows: Vec<PersistedNameMarketBoardRowIndexV2>,
        row_set_commitment: ObjectHash,
    },
    HeadV2Indexed {
        schema_version: u16,
        logical_revision: u64,
        row_count: u32,
        rows: Vec<PersistedNameMarketBoardRowIndex>,
        row_set_commitment: ObjectHash,
        listing_index_set_commitment: ObjectHash,
    },
    RowV2 {
        offer: Box<PersistedBoardOfferV2>,
        watermark: SequenceWatermarkV2,
    },
    ListingIndexV2 {
        listing_hash: ObjectHash,
        row_id_digest: ObjectHash,
    },
}

// Keep the normalized wire projection strict without changing the legacy v1
// aggregate's public serde contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedBoardOfferV2 {
    listing_hash: ObjectHash,
    listing_bytes: Vec<u8>,
    network_magic: u32,
    network_genesis: ObjectHash,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    sequence: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
    status: BoardOfferStatus,
    cancellation_hash: Option<ObjectHash>,
    cancellation_bytes: Option<Vec<u8>>,
    cancellation_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SequenceWatermarkV2 {
    network_magic: u32,
    network_genesis: ObjectHash,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    sequence: u64,
}

impl From<&PersistedBoardOffer> for PersistedBoardOfferV2 {
    fn from(offer: &PersistedBoardOffer) -> Self {
        Self {
            listing_hash: offer.listing_hash,
            listing_bytes: offer.listing_bytes.clone(),
            network_magic: offer.network_magic,
            network_genesis: offer.network_genesis,
            name_hash: offer.name_hash,
            seller_public_key: offer.seller_public_key.clone(),
            sequence: offer.sequence,
            created_at_unix: offer.created_at_unix,
            expires_at_unix: offer.expires_at_unix,
            status: offer.status,
            cancellation_hash: offer.cancellation_hash,
            cancellation_bytes: offer.cancellation_bytes.clone(),
            cancellation_sequence: offer.cancellation_sequence,
        }
    }
}

impl From<PersistedBoardOfferV2> for PersistedBoardOffer {
    fn from(offer: PersistedBoardOfferV2) -> Self {
        Self {
            listing_hash: offer.listing_hash,
            listing_bytes: offer.listing_bytes,
            network_magic: offer.network_magic,
            network_genesis: offer.network_genesis,
            name_hash: offer.name_hash,
            seller_public_key: offer.seller_public_key,
            sequence: offer.sequence,
            created_at_unix: offer.created_at_unix,
            expires_at_unix: offer.expires_at_unix,
            status: offer.status,
            cancellation_hash: offer.cancellation_hash,
            cancellation_bytes: offer.cancellation_bytes,
            cancellation_sequence: offer.cancellation_sequence,
        }
    }
}

impl From<&SequenceWatermark> for SequenceWatermarkV2 {
    fn from(watermark: &SequenceWatermark) -> Self {
        Self {
            network_magic: watermark.network_magic,
            network_genesis: watermark.network_genesis,
            name_hash: watermark.name_hash,
            seller_public_key: watermark.seller_public_key.clone(),
            sequence: watermark.sequence,
        }
    }
}

impl From<SequenceWatermarkV2> for SequenceWatermark {
    fn from(watermark: SequenceWatermarkV2) -> Self {
        Self {
            network_magic: watermark.network_magic,
            network_genesis: watermark.network_genesis,
            name_hash: watermark.name_hash,
            seller_public_key: watermark.seller_public_key,
            sequence: watermark.sequence,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedNameMarketBoardRowIndexV2 {
    id_digest: ObjectHash,
    store_revision: u64,
    updated_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedNameMarketBoardRowIndex {
    id_digest: ObjectHash,
    store_revision: u64,
    updated_at_unix: u64,
    row_value_commitment: ObjectHash,
    listing_hash: ObjectHash,
}

impl Serialize for PersistedNameMarketBoardRowIndex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoded = [0_u8; 112];
        encoded[..32].copy_from_slice(self.id_digest.as_bytes());
        encoded[32..40].copy_from_slice(&self.store_revision.to_le_bytes());
        encoded[40..48].copy_from_slice(&self.updated_at_unix.to_le_bytes());
        encoded[48..80].copy_from_slice(self.row_value_commitment.as_bytes());
        encoded[80..].copy_from_slice(self.listing_hash.as_bytes());
        serializer.serialize_str(&hex::encode(encoded))
    }
}

impl<'de> Deserialize<'de> for PersistedNameMarketBoardRowIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 224
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom("noncanonical normalized row index"));
        }
        let mut decoded = [0_u8; 112];
        hex::decode_to_slice(&encoded, &mut decoded).map_err(D::Error::custom)?;
        let mut id_digest = [0_u8; 32];
        id_digest.copy_from_slice(&decoded[..32]);
        let mut store_revision = [0_u8; 8];
        store_revision.copy_from_slice(&decoded[32..40]);
        let mut updated_at_unix = [0_u8; 8];
        updated_at_unix.copy_from_slice(&decoded[40..48]);
        let mut row_value_commitment = [0_u8; 32];
        row_value_commitment.copy_from_slice(&decoded[48..80]);
        let mut listing_hash = [0_u8; 32];
        listing_hash.copy_from_slice(&decoded[80..]);
        Ok(Self {
            id_digest: ObjectHash::new(id_digest),
            store_revision: u64::from_le_bytes(store_revision),
            updated_at_unix: u64::from_le_bytes(updated_at_unix),
            row_value_commitment: ObjectHash::new(row_value_commitment),
            listing_hash: ObjectHash::new(listing_hash),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedNameMarketBoardRow {
    id: Vec<u8>,
    store_revision: u64,
    updated_at_unix: u64,
    offer: PersistedBoardOffer,
    watermark: SequenceWatermark,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedNameMarketBoardListingIndex {
    id: Vec<u8>,
    store_revision: u64,
    updated_at_unix: u64,
    listing_hash: ObjectHash,
    row_id_digest: ObjectHash,
}

enum NameMarketBoardStorage {
    Empty,
    Legacy {
        store_revision: u64,
    },
    Normalized {
        head_store_revision: u64,
        rows: Vec<NormalizedNameMarketBoardRow>,
        listing_indexes: Vec<NormalizedNameMarketBoardListingIndex>,
    },
}

pub(crate) struct LoadedNameMarketBoard {
    pub(crate) logical_revision: u64,
    pub(crate) board: NameMarketBoard,
    storage: NameMarketBoardStorage,
    namespace_lease: EntityPrefixSetLease,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameMarketBoard {
    schema_version: u16,
    offers: Vec<PersistedBoardOffer>,
    watermarks: Vec<SequenceWatermark>,
}

impl Default for NameMarketBoard {
    fn default() -> Self {
        Self {
            schema_version: NAME_MARKET_BOARD_SCHEMA_VERSION,
            offers: Vec::new(),
            watermarks: Vec::new(),
        }
    }
}

impl NameMarketBoard {
    pub fn offers(&self) -> &[PersistedBoardOffer] {
        &self.offers
    }

    pub fn offer(&self, hash: ObjectHash) -> Option<&PersistedBoardOffer> {
        self.offers.iter().find(|offer| offer.listing_hash == hash)
    }

    pub(crate) fn retain_transport_active_listings(
        &mut self,
        network: hns_swap::NetworkBinding,
        active_listing_hashes: &BTreeSet<ObjectHash>,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let before = self.offers.len();
        self.offers.retain(|offer| {
            offer.status == BoardOfferStatus::Cancelled
                || offer.network_magic != network.magic
                || offer.network_genesis.as_bytes() != network.genesis.as_bytes()
                || active_listing_hashes.contains(&offer.listing_hash)
        });
        self.validate()?;
        Ok(self.offers.len() != before)
    }

    pub fn apply_offer(
        &mut self,
        listing: &VerifiedFixedPriceListing,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let name_hash = listing.name_hash()?;
        let network = listing.network();
        let seller_public_key = listing.seller_public_key().to_vec();
        if let Some(existing) = self.offer(listing.listing_hash()) {
            if existing.listing_bytes == listing.encoded()
                && existing.sequence == listing.sequence()
            {
                return Ok(false);
            }
            return Err(ShakedexError::NameMarketReplay);
        }

        let offer_index = self.offers.iter().position(|offer| {
            offer.network_magic == network.magic
                && offer.network_genesis.into_bytes() == *network.genesis.as_bytes()
                && offer.name_hash == name_hash
                && offer.seller_public_key == seller_public_key
        });
        if offer_index.is_none() && self.offers.len() >= MAX_NAME_MARKET_BOARD_OFFERS {
            return Err(ShakedexError::NameMarketBoardCapacity);
        }

        let watermark = self.watermarks.iter_mut().find(|watermark| {
            watermark.network_magic == network.magic
                && watermark.network_genesis.into_bytes() == *network.genesis.as_bytes()
                && watermark.name_hash == name_hash
                && watermark.seller_public_key == seller_public_key
        });
        match watermark {
            Some(watermark) if listing.sequence() <= watermark.sequence => {
                return Err(ShakedexError::NameMarketReplay);
            }
            Some(watermark) => watermark.sequence = listing.sequence(),
            None => {
                if self.watermarks.len() >= MAX_NAME_MARKET_BOARD_OFFERS {
                    return Err(ShakedexError::NameMarketBoardCapacity);
                }
                self.watermarks.push(SequenceWatermark {
                    network_magic: network.magic,
                    network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
                    name_hash,
                    seller_public_key: seller_public_key.clone(),
                    sequence: listing.sequence(),
                });
            }
        }

        let replacement = PersistedBoardOffer {
            listing_hash: listing.listing_hash(),
            listing_bytes: listing.encoded().to_vec(),
            network_magic: network.magic,
            network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
            name_hash,
            seller_public_key,
            sequence: listing.sequence(),
            created_at_unix: listing.created_at_unix(),
            expires_at_unix: listing.expires_at_unix(),
            status: BoardOfferStatus::Active,
            cancellation_hash: None,
            cancellation_bytes: None,
            cancellation_sequence: None,
        };
        if let Some(index) = offer_index {
            self.offers[index] = replacement;
        } else {
            self.offers.push(replacement);
        }
        self.offers.sort_by_key(|offer| offer.listing_hash);
        self.watermarks
            .sort_by(|left, right| watermark_key(left).cmp(&watermark_key(right)));
        Ok(true)
    }

    pub fn apply_cancellation(
        &mut self,
        cancellation: &VerifiedListingCancellation,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let offer_index = self
            .offers
            .iter()
            .position(|offer| offer.listing_hash == cancellation.listing_hash())
            .ok_or(ShakedexError::InvalidCancellation)?;
        let identity = {
            let offer = &self.offers[offer_index];
            (
                offer.network_magic,
                offer.network_genesis,
                offer.name_hash,
                offer.seller_public_key.clone(),
            )
        };
        let watermark = self
            .watermarks
            .iter_mut()
            .find(|watermark| {
                watermark.network_magic == identity.0
                    && watermark.network_genesis == identity.1
                    && watermark.name_hash == identity.2
                    && watermark.seller_public_key == identity.3
            })
            .ok_or(ShakedexError::CorruptNameMarketBoard)?;
        let offer = &mut self.offers[offer_index];
        if offer.cancellation_hash == Some(cancellation.cancellation_hash())
            && offer.cancellation_bytes.as_deref() == Some(cancellation.encoded())
        {
            return Ok(false);
        }
        if cancellation.sequence() <= watermark.sequence {
            return Err(ShakedexError::NameMarketReplay);
        }
        watermark.sequence = cancellation.sequence();
        offer.status = BoardOfferStatus::Cancelled;
        offer.cancellation_hash = Some(cancellation.cancellation_hash());
        offer.cancellation_bytes = Some(cancellation.encoded().to_vec());
        offer.cancellation_sequence = Some(cancellation.sequence());
        Ok(true)
    }

    pub fn active_inventory(&self, now_unix: u64) -> Result<Vec<ObjectHash>, ShakedexError> {
        self.validate()?;
        Ok(self
            .offers
            .iter()
            .filter(|offer| {
                offer.status == BoardOfferStatus::Active
                    && offer.created_at_unix <= now_unix
                    && now_unix < offer.expires_at_unix
            })
            .map(|offer| offer.listing_hash)
            .collect())
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        self.validate_structure()?;
        for offer in &self.offers {
            validate_offer(offer)?;
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ShakedexError> {
        if self.schema_version != NAME_MARKET_BOARD_SCHEMA_VERSION
            || self.offers.len() > MAX_NAME_MARKET_BOARD_OFFERS
            || self.watermarks.len() > MAX_NAME_MARKET_BOARD_OFFERS
            || self.offers.len() != self.watermarks.len()
            || self
                .offers
                .windows(2)
                .any(|window| window[0].listing_hash >= window[1].listing_hash)
            || self
                .watermarks
                .windows(2)
                .any(|window| watermark_key(&window[0]) >= watermark_key(&window[1]))
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let mut watermarks = self
            .watermarks
            .iter()
            .map(|watermark| (watermark_identity(watermark), watermark.sequence))
            .collect::<BTreeMap<_, _>>();
        if watermarks.len() != self.watermarks.len() {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        for offer in &self.offers {
            let minimum = offer.cancellation_sequence.unwrap_or(offer.sequence);
            if watermarks.remove(&offer_identity(offer)) != Some(minimum) {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
        }
        if watermarks.is_empty() {
            Ok(())
        } else {
            Err(ShakedexError::CorruptNameMarketBoard)
        }
    }
}

fn validate_offer(offer: &PersistedBoardOffer) -> Result<(), ShakedexError> {
    let listing = FixedPriceListing::decode(&offer.listing_bytes)
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    // `decode` authenticates the canonical hash tail and signature. Reusing
    // that authenticated tail avoids a second full signature verification.
    let listing_hash = offer
        .listing_bytes
        .get(offer.listing_bytes.len().saturating_sub(32)..)
        .and_then(|tail| <[u8; 32]>::try_from(tail).ok())
        .ok_or(ShakedexError::CorruptNameMarketBoard)?;
    let name_hash = listing
        .name_hash()
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    if listing_hash != offer.listing_hash.into_bytes()
        || listing.network().magic != offer.network_magic
        || listing.network().genesis.as_bytes() != &offer.network_genesis.into_bytes()
        || name_hash.as_bytes() != offer.name_hash.as_bytes()
        || listing.seller_public_key().as_slice() != offer.seller_public_key
        || listing.sequence != offer.sequence
        || listing.created_at != offer.created_at_unix
        || listing.expires_at != offer.expires_at_unix
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    match (
        offer.status,
        offer.cancellation_hash,
        offer.cancellation_bytes.as_deref(),
        offer.cancellation_sequence,
    ) {
        (BoardOfferStatus::Cancelled, Some(hash), Some(bytes), Some(sequence)) => {
            let cancellation = ListingCancellation::decode(bytes)
                .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
            cancellation
                .verify_for_listing(&listing, listing.network(), cancellation.created_at)
                .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
            let cancellation_hash = bytes
                .get(bytes.len().saturating_sub(32)..)
                .and_then(|tail| <[u8; 32]>::try_from(tail).ok())
                .ok_or(ShakedexError::CorruptNameMarketBoard)?;
            if cancellation_hash != hash.into_bytes() || cancellation.sequence != sequence {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
        }
        (BoardOfferStatus::Active, None, None, None) => {}
        _ => return Err(ShakedexError::CorruptNameMarketBoard),
    }
    Ok(())
}

type BoardIdentity = (u32, ObjectHash, ObjectHash, Vec<u8>);

fn offer_identity(offer: &PersistedBoardOffer) -> BoardIdentity {
    (
        offer.network_magic,
        offer.network_genesis,
        offer.name_hash,
        offer.seller_public_key.clone(),
    )
}

fn watermark_identity(watermark: &SequenceWatermark) -> BoardIdentity {
    (
        watermark.network_magic,
        watermark.network_genesis,
        watermark.name_hash,
        watermark.seller_public_key.clone(),
    )
}

fn same_listing(left: &PersistedBoardOffer, right: &PersistedBoardOffer) -> bool {
    left.listing_hash == right.listing_hash
        && left.listing_bytes == right.listing_bytes
        && left.network_magic == right.network_magic
        && left.network_genesis == right.network_genesis
        && left.name_hash == right.name_hash
        && left.seller_public_key == right.seller_public_key
        && left.sequence == right.sequence
        && left.created_at_unix == right.created_at_unix
        && left.expires_at_unix == right.expires_at_unix
}

fn validate_monotonic_board_transition(
    current: &NameMarketBoard,
    target: &NameMarketBoard,
) -> Result<(), ShakedexError> {
    let target_offers = target
        .offers
        .iter()
        .map(|offer| (offer_identity(offer), offer))
        .collect::<BTreeMap<_, _>>();
    for current_offer in &current.offers {
        let target_offer = target_offers
            .get(&offer_identity(current_offer))
            .ok_or(ShakedexError::NameMarketReplay)?;
        let current_sequence = current_offer
            .cancellation_sequence
            .unwrap_or(current_offer.sequence);
        let target_sequence = target_offer
            .cancellation_sequence
            .unwrap_or(target_offer.sequence);
        if target_sequence < current_sequence {
            return Err(ShakedexError::NameMarketReplay);
        }
        if target_sequence == current_sequence {
            if *target_offer != current_offer {
                return Err(ShakedexError::NameMarketReplay);
            }
            continue;
        }

        // A higher listing sequence is a relist. Otherwise the existing exact
        // listing may only advance through a higher signed cancellation.
        let higher_relist = target_offer.sequence > current_sequence;
        let higher_cancellation = same_listing(current_offer, target_offer)
            && target_offer.status == BoardOfferStatus::Cancelled
            && target_offer.cancellation_sequence == Some(target_sequence);
        if !higher_relist && !higher_cancellation {
            return Err(ShakedexError::NameMarketReplay);
        }
    }
    Ok(())
}

fn watermark_key(watermark: &SequenceWatermark) -> (u32, [u8; 32], [u8; 32], &[u8]) {
    (
        watermark.network_magic,
        watermark.network_genesis.into_bytes(),
        watermark.name_hash.into_bytes(),
        &watermark.seller_public_key,
    )
}

fn normalized_row_id(watermark: &SequenceWatermark) -> Result<Vec<u8>, ShakedexError> {
    let seller_key_length = u64::try_from(watermark.seller_public_key.len())
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_NAME_MARKET_BOARD_ROW_ID_DOMAIN);
    hasher.update(watermark.network_magic.to_le_bytes());
    hasher.update(watermark.network_genesis.as_bytes());
    hasher.update(watermark.name_hash.as_bytes());
    hasher.update(seller_key_length.to_le_bytes());
    hasher.update(&watermark.seller_public_key);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = Vec::with_capacity(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX.len() + digest.len());
    id.extend_from_slice(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX);
    id.extend_from_slice(&digest);
    Ok(id)
}

fn normalized_row_id_from_digest(id_digest: ObjectHash) -> Vec<u8> {
    let mut id = Vec::with_capacity(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX.len() + 32);
    id.extend_from_slice(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX);
    id.extend_from_slice(id_digest.as_bytes());
    id
}

fn normalized_row_id_digest(id: &[u8]) -> Result<ObjectHash, ShakedexError> {
    let digest = id
        .strip_prefix(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX)
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .ok_or(ShakedexError::CorruptNameMarketBoard)?;
    Ok(ObjectHash::new(digest))
}

fn normalized_listing_index_id(listing_hash: ObjectHash) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_ID_DOMAIN);
    hasher.update(listing_hash.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id =
        Vec::with_capacity(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX.len() + digest.len());
    id.extend_from_slice(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX);
    id.extend_from_slice(&digest);
    id
}

fn normalized_listing_index_from_row(
    row: &NormalizedNameMarketBoardRow,
) -> Result<NormalizedNameMarketBoardListingIndex, ShakedexError> {
    Ok(NormalizedNameMarketBoardListingIndex {
        id: normalized_listing_index_id(row.offer.listing_hash),
        store_revision: 0,
        updated_at_unix: 0,
        listing_hash: row.offer.listing_hash,
        row_id_digest: normalized_row_id_digest(&row.id)?,
    })
}

fn normalized_row_index(
    row: &NormalizedNameMarketBoardRow,
) -> Result<PersistedNameMarketBoardRowIndex, ShakedexError> {
    if row.store_revision == 0 {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(PersistedNameMarketBoardRowIndex {
        id_digest: normalized_row_id_digest(&row.id)?,
        store_revision: row.store_revision,
        updated_at_unix: row.updated_at_unix,
        row_value_commitment: normalized_row_value_commitment(row)?,
        listing_hash: row.offer.listing_hash,
    })
}

fn normalized_listing_index_entity(
    index: &NormalizedNameMarketBoardListingIndex,
) -> PersistedNameMarketBoardEntity {
    PersistedNameMarketBoardEntity::ListingIndexV2 {
        listing_hash: index.listing_hash,
        row_id_digest: index.row_id_digest,
    }
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<(), ShakedexError> {
    let length = u64::try_from(value.len()).map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn normalized_row_value_commitment(
    row: &NormalizedNameMarketBoardRow,
) -> Result<ObjectHash, ShakedexError> {
    let offer = &row.offer;
    let watermark = &row.watermark;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_NAME_MARKET_BOARD_ROW_COMMITMENT_DOMAIN);
    hasher.update(offer.listing_hash.as_bytes());
    update_length_prefixed(&mut hasher, &offer.listing_bytes)?;
    hasher.update(offer.network_magic.to_le_bytes());
    hasher.update(offer.network_genesis.as_bytes());
    hasher.update(offer.name_hash.as_bytes());
    update_length_prefixed(&mut hasher, &offer.seller_public_key)?;
    hasher.update(offer.sequence.to_le_bytes());
    hasher.update(offer.created_at_unix.to_le_bytes());
    hasher.update(offer.expires_at_unix.to_le_bytes());
    hasher.update([match offer.status {
        BoardOfferStatus::Active => 0,
        BoardOfferStatus::Cancelled => 1,
    }]);
    match offer.cancellation_hash {
        Some(hash) => {
            hasher.update([1]);
            hasher.update(hash.as_bytes());
        }
        None => hasher.update([0]),
    }
    match &offer.cancellation_bytes {
        Some(bytes) => {
            hasher.update([1]);
            update_length_prefixed(&mut hasher, bytes)?;
        }
        None => hasher.update([0]),
    }
    match offer.cancellation_sequence {
        Some(sequence) => {
            hasher.update([1]);
            hasher.update(sequence.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(watermark.network_magic.to_le_bytes());
    hasher.update(watermark.network_genesis.as_bytes());
    hasher.update(watermark.name_hash.as_bytes());
    update_length_prefixed(&mut hasher, &watermark.seller_public_key)?;
    hasher.update(watermark.sequence.to_le_bytes());
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn normalized_row_set_commitment(
    rows: &[NormalizedNameMarketBoardRow],
) -> Result<ObjectHash, ShakedexError> {
    if rows.len() > MAX_NAME_MARKET_BOARD_OFFERS
        || rows.windows(2).any(|window| window[0].id >= window[1].id)
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let row_count = u64::try_from(rows.len()).map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_NAME_MARKET_BOARD_SET_COMMITMENT_DOMAIN);
    hasher.update(row_count.to_le_bytes());
    for row in rows {
        if row.store_revision == 0 {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        update_length_prefixed(&mut hasher, &row.id)?;
        hasher.update(row.store_revision.to_le_bytes());
        hasher.update(row.updated_at_unix.to_le_bytes());
        hasher.update(normalized_row_value_commitment(row)?.as_bytes());
    }
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn normalized_listing_index_metadata(
    indexes: &[NormalizedNameMarketBoardListingIndex],
) -> Result<Vec<StoredEntityMetadata>, ShakedexError> {
    if indexes.len() > MAX_NAME_MARKET_BOARD_OFFERS
        || indexes
            .windows(2)
            .any(|window| window[0].id >= window[1].id)
        || indexes.iter().any(|index| {
            index.store_revision == 0 || index.id != normalized_listing_index_id(index.listing_hash)
        })
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(indexes
        .iter()
        .map(|index| StoredEntityMetadata {
            kind: EntityKind::DenuoBoardObject,
            id: index.id.clone(),
            revision: index.store_revision,
            updated_at_unix: index.updated_at_unix,
        })
        .collect())
}

fn normalized_listing_index_set_commitment(
    metadata: &[StoredEntityMetadata],
) -> Result<ObjectHash, ShakedexError> {
    if metadata.len() > MAX_NAME_MARKET_BOARD_OFFERS
        || metadata
            .windows(2)
            .any(|window| window[0].id >= window[1].id)
        || metadata.iter().any(|entry| {
            entry.kind != EntityKind::DenuoBoardObject
                || entry.revision == 0
                || entry.id.len() != NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX.len() + 32
                || !entry
                    .id
                    .starts_with(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX)
        })
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let count = u64::try_from(metadata.len()).map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_SET_COMMITMENT_DOMAIN);
    hasher.update(count.to_le_bytes());
    for entry in metadata {
        update_length_prefixed(&mut hasher, &entry.id)?;
        hasher.update(entry.revision.to_le_bytes());
        hasher.update(entry.updated_at_unix.to_le_bytes());
    }
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn validate_normalized_row(row: &NormalizedNameMarketBoardRow) -> Result<(), ShakedexError> {
    validate_offer(&row.offer)?;
    let expected_sequence = row
        .offer
        .cancellation_sequence
        .unwrap_or(row.offer.sequence);
    if row.watermark.network_magic != row.offer.network_magic
        || row.watermark.network_genesis != row.offer.network_genesis
        || row.watermark.name_hash != row.offer.name_hash
        || row.watermark.seller_public_key != row.offer.seller_public_key
        || row.watermark.sequence != expected_sequence
        || normalized_row_id(&row.watermark)? != row.id
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(())
}

fn normalized_rows_from_board(
    board: &NameMarketBoard,
) -> Result<Vec<NormalizedNameMarketBoardRow>, ShakedexError> {
    let watermarks = board
        .watermarks
        .iter()
        .map(|watermark| (watermark_identity(watermark), watermark))
        .collect::<BTreeMap<_, _>>();
    let mut rows = BTreeMap::new();
    for offer in &board.offers {
        let watermark = watermarks
            .get(&offer_identity(offer))
            .ok_or(ShakedexError::CorruptNameMarketBoard)?;
        let id = normalized_row_id(watermark)?;
        let row = NormalizedNameMarketBoardRow {
            id: id.clone(),
            store_revision: 0,
            updated_at_unix: 0,
            offer: offer.clone(),
            watermark: (*watermark).clone(),
        };
        if rows.insert(id, row).is_some() {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
    }
    Ok(rows.into_values().collect())
}

fn normalized_row_entity(row: &NormalizedNameMarketBoardRow) -> PersistedNameMarketBoardEntity {
    PersistedNameMarketBoardEntity::RowV2 {
        offer: Box::new((&row.offer).into()),
        watermark: (&row.watermark).into(),
    }
}

fn normalized_row_from_stored(
    stored: StoredEntity<PersistedNameMarketBoardEntity>,
) -> Result<NormalizedNameMarketBoardRow, ShakedexError> {
    let PersistedNameMarketBoardEntity::RowV2 { offer, watermark } = stored.value else {
        return Err(ShakedexError::CorruptNameMarketBoard);
    };
    if stored.kind != EntityKind::DenuoBoardObject
        || stored.id.len() != NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX.len() + 32
        || !stored
            .id
            .starts_with(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX)
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let row = NormalizedNameMarketBoardRow {
        id: stored.id,
        store_revision: stored.revision,
        updated_at_unix: stored.updated_at_unix,
        offer: (*offer).into(),
        watermark: watermark.into(),
    };
    validate_normalized_row(&row)?;
    Ok(row)
}

fn normalized_listing_index_from_stored(
    stored: StoredEntity<PersistedNameMarketBoardEntity>,
) -> Result<NormalizedNameMarketBoardListingIndex, ShakedexError> {
    let PersistedNameMarketBoardEntity::ListingIndexV2 {
        listing_hash,
        row_id_digest,
    } = stored.value
    else {
        return Err(ShakedexError::CorruptNameMarketBoard);
    };
    let index = NormalizedNameMarketBoardListingIndex {
        id: stored.id,
        store_revision: stored.revision,
        updated_at_unix: stored.updated_at_unix,
        listing_hash,
        row_id_digest,
    };
    if stored.kind != EntityKind::DenuoBoardObject
        || index.store_revision == 0
        || index.id.len() != NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX.len() + 32
        || index.id != normalized_listing_index_id(index.listing_hash)
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(index)
}

fn list_normalized_metadata(
    snapshot: &EntityReadSnapshot<'_>,
    prefix: &[u8],
    limit: usize,
) -> Result<Vec<StoredEntityMetadata>, ShakedexError> {
    snapshot
        .list_untrusted_entity_metadata_by_id_prefix(EntityKind::DenuoBoardObject, prefix, limit)
        .map_err(|error| {
            if matches!(error, StoreError::ListCapacity) {
                ShakedexError::CorruptNameMarketBoard
            } else {
                ShakedexError::from(error)
            }
        })
}

fn load_snapshot_entity<T: for<'de> Deserialize<'de>>(
    snapshot: &EntityReadSnapshot<'_>,
    id: &[u8],
) -> Result<Option<StoredEntity<T>>, ShakedexError> {
    snapshot
        .load_entity(EntityKind::DenuoBoardObject, id)
        .map_err(ShakedexError::from)
}

fn normalized_metadata_from_index(
    indexes: &[PersistedNameMarketBoardRowIndex],
) -> Result<Vec<StoredEntityMetadata>, ShakedexError> {
    if indexes.len() > MAX_NAME_MARKET_BOARD_OFFERS
        || indexes
            .windows(2)
            .any(|window| window[0].id_digest >= window[1].id_digest)
        || indexes.iter().any(|index| index.store_revision == 0)
        || indexes
            .iter()
            .map(|index| index.listing_hash)
            .collect::<BTreeSet<_>>()
            .len()
            != indexes.len()
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(indexes
        .iter()
        .map(|index| StoredEntityMetadata {
            kind: EntityKind::DenuoBoardObject,
            id: normalized_row_id_from_digest(index.id_digest),
            revision: index.store_revision,
            updated_at_unix: index.updated_at_unix,
        })
        .collect())
}

fn normalized_listing_index_ids_from_row_index(
    indexes: &[PersistedNameMarketBoardRowIndex],
) -> Result<Vec<Vec<u8>>, ShakedexError> {
    normalized_metadata_from_index(indexes)?;
    let mut ids = indexes
        .iter()
        .map(|index| normalized_listing_index_id(index.listing_hash))
        .collect::<Vec<_>>();
    ids.sort();
    if ids.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(ids)
}

fn normalized_metadata_from_v2_index(
    indexes: &[PersistedNameMarketBoardRowIndexV2],
) -> Result<Vec<StoredEntityMetadata>, ShakedexError> {
    if indexes.len() > MAX_NAME_MARKET_BOARD_OFFERS
        || indexes
            .windows(2)
            .any(|window| window[0].id_digest >= window[1].id_digest)
        || indexes.iter().any(|index| index.store_revision == 0)
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(indexes
        .iter()
        .map(|index| StoredEntityMetadata {
            kind: EntityKind::DenuoBoardObject,
            id: normalized_row_id_from_digest(index.id_digest),
            revision: index.store_revision,
            updated_at_unix: index.updated_at_unix,
        })
        .collect())
}

fn load_indexed_normalized_rows(
    snapshot: &EntityReadSnapshot<'_>,
    indexes: &[PersistedNameMarketBoardRowIndex],
) -> Result<Vec<NormalizedNameMarketBoardRow>, ShakedexError> {
    let mut rows = Vec::with_capacity(indexes.len());
    for index in indexes {
        let id = normalized_row_id_from_digest(index.id_digest);
        let Some(stored): Option<StoredEntity<PersistedNameMarketBoardEntity>> =
            load_snapshot_entity(snapshot, &id)?
        else {
            return Err(ShakedexError::CorruptNameMarketBoard);
        };
        if stored.revision != index.store_revision
            || stored.updated_at_unix != index.updated_at_unix
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        // Validate and shrink each independently bounded row before loading
        // the next one. A hostile authenticated record can therefore consume
        // at most one store-record bound, never `row_count * MAX_STATE_BYTES`.
        let row = normalized_row_from_stored(stored)?;
        if row.offer.listing_hash != index.listing_hash
            || normalized_row_value_commitment(&row)? != index.row_value_commitment
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        rows.push(row);
    }
    Ok(rows)
}

fn load_v2_normalized_rows(
    snapshot: &EntityReadSnapshot<'_>,
    indexes: &[PersistedNameMarketBoardRowIndexV2],
) -> Result<Vec<NormalizedNameMarketBoardRow>, ShakedexError> {
    let mut rows = Vec::with_capacity(indexes.len());
    for index in indexes {
        let id = normalized_row_id_from_digest(index.id_digest);
        let Some(stored): Option<StoredEntity<PersistedNameMarketBoardEntity>> =
            load_snapshot_entity(snapshot, &id)?
        else {
            return Err(ShakedexError::CorruptNameMarketBoard);
        };
        if stored.revision != index.store_revision
            || stored.updated_at_unix != index.updated_at_unix
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        rows.push(normalized_row_from_stored(stored)?);
    }
    Ok(rows)
}

fn load_indexed_normalized_listing_indexes(
    snapshot: &EntityReadSnapshot<'_>,
    metadata: &[StoredEntityMetadata],
) -> Result<Vec<NormalizedNameMarketBoardListingIndex>, ShakedexError> {
    let mut indexes = Vec::with_capacity(metadata.len());
    for expected in metadata {
        let Some(stored): Option<StoredEntity<PersistedNameMarketBoardEntity>> =
            load_snapshot_entity(snapshot, &expected.id)?
        else {
            return Err(ShakedexError::CorruptNameMarketBoard);
        };
        if stored.revision != expected.revision
            || stored.updated_at_unix != expected.updated_at_unix
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        indexes.push(normalized_listing_index_from_stored(stored)?);
    }
    Ok(indexes)
}

fn validate_normalized_listing_bijection(
    rows: &[NormalizedNameMarketBoardRow],
    indexes: &[NormalizedNameMarketBoardListingIndex],
) -> Result<(), ShakedexError> {
    if rows.len() != indexes.len() {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let expected = rows
        .iter()
        .map(|row| Ok((row.offer.listing_hash, normalized_row_id_digest(&row.id)?)))
        .collect::<Result<BTreeMap<_, _>, ShakedexError>>()?;
    let actual = indexes
        .iter()
        .map(|index| (index.listing_hash, index.row_id_digest))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != rows.len() || actual.len() != indexes.len() || expected != actual {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(())
}

fn validate_normalized_namespace_metadata(
    metadata: &[StoredEntityMetadata],
) -> Result<(), ShakedexError> {
    if metadata.len() > MAX_NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_RECORDS
        || metadata
            .windows(2)
            .any(|window| window[0].id >= window[1].id)
        || metadata.iter().any(|entry| {
            if entry.kind != EntityKind::DenuoBoardObject
                || !entry
                    .id
                    .starts_with(NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_PREFIX)
                || entry.revision == 0
            {
                return true;
            }
            entry.id != NAME_MARKET_BOARD_RECORD_ID
                && entry.id != NORMALIZED_NAME_MARKET_BOARD_HEAD_ID
                && !(entry.id.len() == NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX.len() + 32
                    && entry
                        .id
                        .starts_with(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX))
                && !(entry.id.len() == NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX.len() + 32
                    && entry
                        .id
                        .starts_with(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX))
        })
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    Ok(())
}

fn board_from_normalized_rows(
    rows: &[NormalizedNameMarketBoardRow],
) -> Result<NameMarketBoard, ShakedexError> {
    let mut offers = rows.iter().map(|row| row.offer.clone()).collect::<Vec<_>>();
    offers.sort_by_key(|offer| offer.listing_hash);
    let mut watermarks = rows
        .iter()
        .map(|row| row.watermark.clone())
        .collect::<Vec<_>>();
    watermarks.sort_by(|left, right| watermark_key(left).cmp(&watermark_key(right)));
    let board = NameMarketBoard {
        schema_version: NAME_MARKET_BOARD_SCHEMA_VERSION,
        offers,
        watermarks,
    };
    // Every row was already cryptographically validated exactly once; this
    // pass verifies aggregate ordering and identity linkage.
    board.validate_structure()?;
    Ok(board)
}

pub(crate) fn load_name_market_board_state_from_snapshot(
    snapshot: &EntityReadSnapshot<'_>,
) -> Result<LoadedNameMarketBoard, ShakedexError> {
    let namespace_lease = snapshot
        .entity_prefix_set_lease(
            EntityKind::DenuoBoardObject,
            NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_PREFIX,
            MAX_NORMALIZED_NAME_MARKET_BOARD_NAMESPACE_RECORDS,
        )
        .map_err(|error| {
            if matches!(error, StoreError::ListCapacity) {
                ShakedexError::CorruptNameMarketBoard
            } else {
                ShakedexError::from(error)
            }
        })?;
    let namespace_metadata = namespace_lease.metadata();
    validate_normalized_namespace_metadata(namespace_metadata)?;
    let head: Option<StoredEntity<PersistedNameMarketBoardEntity>> =
        load_snapshot_entity(snapshot, NORMALIZED_NAME_MARKET_BOARD_HEAD_ID)?;
    let legacy: Option<StoredEntity<NameMarketBoard>> =
        load_snapshot_entity(snapshot, NAME_MARKET_BOARD_RECORD_ID)?;
    if head.is_some() && legacy.is_some() {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let row_metadata = namespace_metadata
        .iter()
        .filter(|entry| {
            entry
                .id
                .starts_with(NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX)
        })
        .cloned()
        .collect::<Vec<_>>();
    let listing_index_metadata = namespace_metadata
        .iter()
        .filter(|entry| {
            entry
                .id
                .starts_with(NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX)
        })
        .cloned()
        .collect::<Vec<_>>();

    match (head, legacy, namespace_metadata.len()) {
        (None, None, 0) => Ok(LoadedNameMarketBoard {
            logical_revision: 0,
            board: NameMarketBoard::default(),
            storage: NameMarketBoardStorage::Empty,
            namespace_lease,
        }),
        (None, Some(stored), 1) if stored.id == NAME_MARKET_BOARD_RECORD_ID => {
            stored.value.validate()?;
            Ok(LoadedNameMarketBoard {
                logical_revision: stored.revision,
                board: stored.value,
                storage: NameMarketBoardStorage::Legacy {
                    store_revision: stored.revision,
                },
                namespace_lease,
            })
        }
        (Some(head), None, _) => {
            if head.kind != EntityKind::DenuoBoardObject
                || head.id != NORMALIZED_NAME_MARKET_BOARD_HEAD_ID
            {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
            let head_store_revision = head.revision;
            match head.value {
                PersistedNameMarketBoardEntity::HeadV2 {
                    schema_version,
                    logical_revision,
                    row_count,
                    rows: row_index,
                    row_set_commitment,
                } => {
                    if schema_version != NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION
                        || logical_revision == 0
                        || usize::try_from(row_count).ok() != Some(row_index.len())
                        || namespace_metadata.len()
                            != row_index
                                .len()
                                .checked_add(1)
                                .ok_or(ShakedexError::CorruptNameMarketBoard)?
                        || normalized_metadata_from_v2_index(&row_index)? != row_metadata
                        || !listing_index_metadata.is_empty()
                    {
                        return Err(ShakedexError::CorruptNameMarketBoard);
                    }
                    let rows = load_v2_normalized_rows(snapshot, &row_index)?;
                    if normalized_row_set_commitment(&rows)? != row_set_commitment {
                        return Err(ShakedexError::CorruptNameMarketBoard);
                    }
                    let board = board_from_normalized_rows(&rows)?;
                    Ok(LoadedNameMarketBoard {
                        logical_revision,
                        board,
                        storage: NameMarketBoardStorage::Normalized {
                            head_store_revision,
                            rows,
                            listing_indexes: Vec::new(),
                        },
                        namespace_lease,
                    })
                }
                PersistedNameMarketBoardEntity::HeadV2Indexed {
                    schema_version,
                    logical_revision,
                    row_count,
                    rows: row_index,
                    row_set_commitment,
                    listing_index_set_commitment,
                } => {
                    if schema_version != NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION
                        || logical_revision == 0
                        || usize::try_from(row_count).ok() != Some(row_index.len())
                        || namespace_metadata.len()
                            != row_index
                                .len()
                                .checked_mul(2)
                                .and_then(|count| count.checked_add(1))
                                .ok_or(ShakedexError::CorruptNameMarketBoard)?
                        || normalized_metadata_from_index(&row_index)? != row_metadata
                        || listing_index_metadata.len() != row_index.len()
                        || normalized_listing_index_set_commitment(&listing_index_metadata)?
                            != listing_index_set_commitment
                    {
                        return Err(ShakedexError::CorruptNameMarketBoard);
                    }
                    let rows = load_indexed_normalized_rows(snapshot, &row_index)?;
                    if normalized_row_set_commitment(&rows)? != row_set_commitment {
                        return Err(ShakedexError::CorruptNameMarketBoard);
                    }
                    let listing_indexes =
                        load_indexed_normalized_listing_indexes(snapshot, &listing_index_metadata)?;
                    validate_normalized_listing_bijection(&rows, &listing_indexes)?;
                    let board = board_from_normalized_rows(&rows)?;
                    Ok(LoadedNameMarketBoard {
                        logical_revision,
                        board,
                        storage: NameMarketBoardStorage::Normalized {
                            head_store_revision,
                            rows,
                            listing_indexes,
                        },
                        namespace_lease,
                    })
                }
                _ => Err(ShakedexError::CorruptNameMarketBoard),
            }
        }
        _ => Err(ShakedexError::CorruptNameMarketBoard),
    }
}

fn load_name_market_board_state(
    store: &WalletStore,
) -> Result<LoadedNameMarketBoard, ShakedexError> {
    store.try_with_entity_read_snapshot(load_name_market_board_state_from_snapshot)
}

pub struct StoredNameMarketBoard {
    pub revision: u64,
    pub board: NameMarketBoard,
}

pub fn load_name_market_board(store: &WalletStore) -> Result<StoredNameMarketBoard, ShakedexError> {
    let loaded = load_name_market_board_state(store)?;
    Ok(StoredNameMarketBoard {
        revision: loaded.logical_revision,
        board: loaded.board,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredNameMarketBoardOffers {
    pub(crate) revision: u64,
    pub(crate) offers: Vec<Option<PersistedBoardOffer>>,
}

pub(crate) fn load_name_market_board_offers_from_snapshot(
    snapshot: &EntityReadSnapshot<'_>,
    listing_hashes: &[ObjectHash],
) -> Result<StoredNameMarketBoardOffers, ShakedexError> {
    if listing_hashes.len() > MAX_NAME_MARKET_BOARD_OFFERS {
        return Err(ShakedexError::NameMarketBoardCapacity);
    }
    let head: Option<StoredEntity<PersistedNameMarketBoardEntity>> =
        load_snapshot_entity(snapshot, NORMALIZED_NAME_MARKET_BOARD_HEAD_ID)?;
    let legacy: Option<StoredEntity<NameMarketBoard>> =
        load_snapshot_entity(snapshot, NAME_MARKET_BOARD_RECORD_ID)?;
    let Some(head) = head else {
        let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
        return Ok(StoredNameMarketBoardOffers {
            revision: loaded.logical_revision,
            offers: listing_hashes
                .iter()
                .map(|listing_hash| loaded.board.offer(*listing_hash).cloned())
                .collect(),
        });
    };
    if legacy.is_some() {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    if matches!(&head.value, PersistedNameMarketBoardEntity::HeadV2 { .. }) {
        let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
        return Ok(StoredNameMarketBoardOffers {
            revision: loaded.logical_revision,
            offers: listing_hashes
                .iter()
                .map(|listing_hash| loaded.board.offer(*listing_hash).cloned())
                .collect(),
        });
    }
    let PersistedNameMarketBoardEntity::HeadV2Indexed {
        schema_version,
        logical_revision,
        row_count,
        rows,
        listing_index_set_commitment,
        ..
    } = &head.value
    else {
        return Err(ShakedexError::CorruptNameMarketBoard);
    };
    let expected_row_metadata = normalized_metadata_from_index(rows)?;
    let expected_listing_index_ids = normalized_listing_index_ids_from_row_index(rows)?;
    if head.kind != EntityKind::DenuoBoardObject
        || head.id != NORMALIZED_NAME_MARKET_BOARD_HEAD_ID
        || *schema_version != NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION
        || *logical_revision == 0
        || usize::try_from(*row_count).ok() != Some(rows.len())
        || expected_row_metadata.len() != rows.len()
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    let row_metadata = list_normalized_metadata(
        snapshot,
        NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX,
        MAX_NAME_MARKET_BOARD_OFFERS,
    )?;
    let listing_index_metadata = list_normalized_metadata(
        snapshot,
        NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX,
        MAX_NAME_MARKET_BOARD_OFFERS,
    )?;
    if row_metadata != expected_row_metadata
        || listing_index_metadata.len() != rows.len()
        || listing_index_metadata
            .iter()
            .map(|entry| &entry.id)
            .ne(expected_listing_index_ids.iter())
        || normalized_listing_index_set_commitment(&listing_index_metadata)?
            != *listing_index_set_commitment
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }

    let row_positions_by_listing_hash = rows
        .iter()
        .enumerate()
        .map(|(position, row)| (row.listing_hash, position))
        .collect::<BTreeMap<_, _>>();

    // A head/index-only negative cannot prove that every authenticated row
    // agrees with its selector. Preserve authoritative absence by falling
    // back to the full semantic loader whenever any requested index is
    // missing. Successful indexed hits still authenticate only their K row
    // and index values after the complete O(N) metadata comparison.
    if listing_hashes.iter().any(|listing_hash| {
        let index_id = normalized_listing_index_id(*listing_hash);
        listing_index_metadata
            .binary_search_by(|entry| entry.id.as_slice().cmp(index_id.as_slice()))
            .is_err()
    }) {
        let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
        return Ok(StoredNameMarketBoardOffers {
            revision: loaded.logical_revision,
            offers: listing_hashes
                .iter()
                .map(|listing_hash| loaded.board.offer(*listing_hash).cloned())
                .collect(),
        });
    }

    let mut offers = Vec::with_capacity(listing_hashes.len());
    for listing_hash in listing_hashes {
        let index_id = normalized_listing_index_id(*listing_hash);
        let metadata_position = listing_index_metadata
            .binary_search_by(|entry| entry.id.as_slice().cmp(index_id.as_slice()))
            .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
        let expected_index = &listing_index_metadata[metadata_position];
        let Some(stored_index): Option<StoredEntity<PersistedNameMarketBoardEntity>> =
            load_snapshot_entity(snapshot, &index_id)?
        else {
            return Err(ShakedexError::CorruptNameMarketBoard);
        };
        if stored_index.revision != expected_index.revision
            || stored_index.updated_at_unix != expected_index.updated_at_unix
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let index = normalized_listing_index_from_stored(stored_index)?;
        if index.listing_hash != *listing_hash {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let row_position = *row_positions_by_listing_hash
            .get(listing_hash)
            .ok_or(ShakedexError::CorruptNameMarketBoard)?;
        if index.row_id_digest != rows[row_position].id_digest {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let expected_row = &row_metadata[row_position];
        let Some(stored_row): Option<StoredEntity<PersistedNameMarketBoardEntity>> =
            load_snapshot_entity(snapshot, &expected_row.id)?
        else {
            return Err(ShakedexError::CorruptNameMarketBoard);
        };
        if stored_row.revision != expected_row.revision
            || stored_row.updated_at_unix != expected_row.updated_at_unix
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let row = normalized_row_from_stored(stored_row)?;
        if row.offer.listing_hash != *listing_hash
            || normalized_row_id_digest(&row.id)? != index.row_id_digest
            || normalized_row_value_commitment(&row)? != rows[row_position].row_value_commitment
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        offers.push(Some(row.offer));
    }
    Ok(StoredNameMarketBoardOffers {
        revision: *logical_revision,
        offers,
    })
}

pub(crate) fn load_name_market_board_offers(
    store: &WalletStore,
    listing_hashes: &[ObjectHash],
) -> Result<StoredNameMarketBoardOffers, ShakedexError> {
    store.try_with_entity_read_snapshot(|snapshot| {
        load_name_market_board_offers_from_snapshot(snapshot, listing_hashes)
    })
}

pub fn save_name_market_board(
    store: &mut WalletStore,
    expected_revision: u64,
    board: &NameMarketBoard,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    let loaded = load_name_market_board_state(store)?;
    save_loaded_name_market_board(
        store,
        expected_revision,
        board,
        updated_at_unix,
        loaded,
        None,
    )
}

pub(crate) fn save_loaded_name_market_board_with_guard(
    store: &mut WalletStore,
    expected_revision: u64,
    board: &NameMarketBoard,
    updated_at_unix: u64,
    loaded: LoadedNameMarketBoard,
    account_prefix_lease: EntityPrefixSetLease,
) -> Result<u64, ShakedexError> {
    save_loaded_name_market_board(
        store,
        expected_revision,
        board,
        updated_at_unix,
        loaded,
        Some(account_prefix_lease),
    )
}

fn save_loaded_name_market_board(
    store: &mut WalletStore,
    expected_revision: u64,
    board: &NameMarketBoard,
    updated_at_unix: u64,
    loaded: LoadedNameMarketBoard,
    account_prefix_lease: Option<EntityPrefixSetLease>,
) -> Result<u64, ShakedexError> {
    board.validate()?;
    let LoadedNameMarketBoard {
        logical_revision: loaded_revision,
        board: loaded_board,
        storage,
        namespace_lease,
    } = loaded;
    if loaded_revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    validate_monotonic_board_transition(&loaded_board, board)?;
    let logical_revision = expected_revision
        .checked_add(1)
        .ok_or(ShakedexError::Persistence)?;

    let (head_store_revision, legacy_store_revision, current_rows, current_listing_indexes) =
        match storage {
            NameMarketBoardStorage::Empty => (0, None, Vec::new(), Vec::new()),
            NameMarketBoardStorage::Legacy { store_revision } => {
                (0, Some(store_revision), Vec::new(), Vec::new())
            }
            NameMarketBoardStorage::Normalized {
                head_store_revision,
                rows,
                listing_indexes,
            } => (head_store_revision, None, rows, listing_indexes),
        };
    let mut current_rows = current_rows
        .into_iter()
        .map(|row| (row.id.clone(), row))
        .collect::<BTreeMap<_, _>>();
    let mut prospective_rows = Vec::new();
    let mut saves = Vec::new();
    let mut assertions = Vec::new();
    for mut target in normalized_rows_from_board(board)? {
        match current_rows.remove(&target.id) {
            Some(current)
                if current.offer == target.offer && current.watermark == target.watermark =>
            {
                assertions.push(EntityRevisionAssertion {
                    id: current.id.clone(),
                    expected_revision: current.store_revision,
                });
                prospective_rows.push(current);
            }
            Some(current) => {
                target.store_revision = current
                    .store_revision
                    .checked_add(1)
                    .ok_or(ShakedexError::Persistence)?;
                target.updated_at_unix = updated_at_unix;
                saves.push(EntityBatchSave {
                    id: target.id.clone(),
                    expected_revision: current.store_revision,
                    value: normalized_row_entity(&target),
                    updated_at_unix,
                });
                prospective_rows.push(target);
            }
            None => {
                target.store_revision = 1;
                target.updated_at_unix = updated_at_unix;
                saves.push(EntityBatchSave {
                    id: target.id.clone(),
                    expected_revision: 0,
                    value: normalized_row_entity(&target),
                    updated_at_unix,
                });
                prospective_rows.push(target);
            }
        }
    }
    prospective_rows.sort_by(|left, right| left.id.cmp(&right.id));

    let mut current_listing_indexes = current_listing_indexes
        .into_iter()
        .map(|index| (index.id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut prospective_listing_indexes = Vec::with_capacity(prospective_rows.len());
    for row in &prospective_rows {
        let mut target = normalized_listing_index_from_row(row)?;
        match current_listing_indexes.remove(&target.id) {
            Some(current)
                if current.listing_hash == target.listing_hash
                    && current.row_id_digest == target.row_id_digest =>
            {
                assertions.push(EntityRevisionAssertion {
                    id: current.id.clone(),
                    expected_revision: current.store_revision,
                });
                prospective_listing_indexes.push(current);
            }
            Some(_) => return Err(ShakedexError::CorruptNameMarketBoard),
            None => {
                target.store_revision = 1;
                target.updated_at_unix = updated_at_unix;
                saves.push(EntityBatchSave {
                    id: target.id.clone(),
                    expected_revision: 0,
                    value: normalized_listing_index_entity(&target),
                    updated_at_unix,
                });
                prospective_listing_indexes.push(target);
            }
        }
    }
    prospective_listing_indexes.sort_by(|left, right| left.id.cmp(&right.id));

    let mut deletes = current_rows
        .into_values()
        .map(|row| EntityBatchDelete {
            id: row.id,
            expected_revision: row.store_revision,
        })
        .collect::<Vec<_>>();
    deletes.extend(
        current_listing_indexes
            .into_values()
            .map(|index| EntityBatchDelete {
                id: index.id,
                expected_revision: index.store_revision,
            }),
    );
    if let Some(store_revision) = legacy_store_revision {
        deletes.push(EntityBatchDelete {
            id: NAME_MARKET_BOARD_RECORD_ID.to_vec(),
            expected_revision: store_revision,
        });
    }

    let row_count = u32::try_from(prospective_rows.len())
        .map_err(|_| ShakedexError::NameMarketBoardCapacity)?;
    let row_index = prospective_rows
        .iter()
        .map(normalized_row_index)
        .collect::<Result<Vec<_>, _>>()?;
    let row_set_commitment = normalized_row_set_commitment(&prospective_rows)?;
    let listing_index_set_commitment = normalized_listing_index_set_commitment(
        &normalized_listing_index_metadata(&prospective_listing_indexes)?,
    )?;
    saves.push(EntityBatchSave {
        id: NORMALIZED_NAME_MARKET_BOARD_HEAD_ID.to_vec(),
        expected_revision: head_store_revision,
        value: PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version: NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION,
            logical_revision,
            row_count,
            rows: row_index,
            row_set_commitment,
            listing_index_set_commitment,
        },
        updated_at_unix,
    });
    if let Some(account_prefix_lease) = account_prefix_lease {
        store.apply_entity_batch_with_assertions_and_prefix_lease_guard(
            EntityKind::DenuoBoardObject,
            &saves,
            &deletes,
            &assertions,
            namespace_lease,
            account_prefix_lease,
        )?;
    } else {
        store.apply_entity_batch_with_assertions_and_prefix_lease(
            EntityKind::DenuoBoardObject,
            &saves,
            &deletes,
            &assertions,
            namespace_lease,
        )?;
    }
    Ok(logical_revision)
}

#[cfg(test)]
mod normalized_storage_tests {
    use hns_covenants::FinalizeCovenant;
    use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash};
    use hns_swap::{NetworkBinding, SwapProof, lock_script_hash};
    use hns_transaction::{Address, Coin, Outpoint};
    use hns_wallet_store::MAX_STATE_BYTES;
    use k256::ecdsa::SigningKey;
    use serde_json::json;

    use super::*;

    const PASSPHRASE: &str = "normalized board persistence passphrase";
    const UPDATED_AT: u64 = 1_900_000_000;
    const OUTBOX_RECORD_ID: &[u8] = b"canonical-name-market-outbox-v1";
    const FROZEN_PRE_INDEX_HEAD_JSON: &str = r#"{
        "record":"head_v2",
        "schema_version":2,
        "logical_revision":1,
        "row_count":1,
        "rows":[{
            "id_digest":[81,101,214,138,21,89,175,67,122,58,109,93,250,110,177,117,148,152,44,22,173,238,35,126,51,12,121,181,106,32,20,22],
            "store_revision":1,
            "updated_at_unix":1900000000
        }],
        "row_set_commitment":[184,201,24,127,6,155,45,96,4,131,68,156,151,201,23,198,2,14,37,129,101,149,133,84,60,116,167,210,221,101,11,211]
    }"#;

    fn fixture_board_with_price(specifications: &[(u32, u64)], price: u64) -> NameMarketBoard {
        let signing_key = SigningKey::from_slice(&[0x61; 32]).expect("seller key");
        let seller_public_key: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let name = b"normalized-board".to_vec();
        let locking_outpoint = Outpoint {
            transaction_hash: TransactionHash::new([0x62; 32]),
            index: 7,
        };
        let coin = Coin {
            outpoint: locking_outpoint,
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&seller_public_key).to_vec())
                .expect("lock address"),
            covenant: FinalizeCovenant::new(
                name.clone(),
                Height::new(1),
                false,
                Height::new(0),
                0,
                BlockHash::new([0x63; 32]),
            )
            .expect("finalize covenant")
            .to_covenant()
            .expect("canonical covenant"),
        };
        let mut offers = Vec::with_capacity(specifications.len());
        let mut watermarks = Vec::with_capacity(specifications.len());
        for &(magic, sequence) in specifications {
            let network = NetworkBinding {
                magic,
                genesis: BlockHash::new([0x64; 32]),
            };
            let mut proof = SwapProof {
                network,
                locking_outpoint,
                name: name.clone(),
                seller_public_key,
                payment_address: Address::new(0, vec![0x65; 20]).expect("payment address"),
                price: Dollarydoos::new(price),
                lock_time_seconds: UPDATED_AT - 100,
                signature: None,
                fee_address: Some(Address::new(0, vec![0x66; 20]).expect("fee address")),
                fee: Dollarydoos::new(25_000),
            };
            proof.sign(&coin, &signing_key).expect("signed swap proof");
            let mut listing = FixedPriceListing {
                proof,
                created_at: UPDATED_AT - 50,
                expires_at: UPDATED_AT + 3_600,
                sequence,
                signature: None,
            };
            listing
                .sign(&signing_key)
                .expect("signed fixed-price listing");
            let listing_bytes = listing.encode().expect("canonical listing encoding");
            let listing_hash = ObjectHash::new(
                listing_bytes[listing_bytes.len() - 32..]
                    .try_into()
                    .expect("canonical listing hash tail"),
            );
            let name_hash =
                ObjectHash::new(*listing.name_hash().expect("canonical name hash").as_bytes());
            offers.push(PersistedBoardOffer {
                listing_hash,
                listing_bytes,
                network_magic: magic,
                network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
                name_hash,
                seller_public_key: seller_public_key.to_vec(),
                sequence,
                created_at_unix: listing.created_at,
                expires_at_unix: listing.expires_at,
                status: BoardOfferStatus::Active,
                cancellation_hash: None,
                cancellation_bytes: None,
                cancellation_sequence: None,
            });
            watermarks.push(SequenceWatermark {
                network_magic: magic,
                network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
                name_hash,
                seller_public_key: seller_public_key.to_vec(),
                sequence,
            });
        }
        offers.sort_by_key(|offer| offer.listing_hash);
        watermarks.sort_by(|left, right| watermark_key(left).cmp(&watermark_key(right)));
        let board = NameMarketBoard {
            schema_version: NAME_MARKET_BOARD_SCHEMA_VERSION,
            offers,
            watermarks,
        };
        board.validate().expect("valid fixture board");
        board
    }

    fn fixture_board(specifications: &[(u32, u64)]) -> NameMarketBoard {
        fixture_board_with_price(specifications, 12_345_678)
    }

    fn maximum_fixture_board() -> NameMarketBoard {
        let specifications = (1..=MAX_NAME_MARKET_BOARD_OFFERS)
            .map(|value| {
                (
                    u32::try_from(value).expect("bounded network magic"),
                    u64::try_from(value).expect("bounded sequence"),
                )
            })
            .collect::<Vec<_>>();
        fixture_board(&specifications)
    }

    fn normalized_store(board: &NameMarketBoard) -> WalletStore {
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("wallet store");
        assert_eq!(
            save_name_market_board(&mut store, 0, board, UPDATED_AT).expect("normalized board"),
            1
        );
        store
    }

    fn stored_normalized_rows(
        store: &WalletStore,
    ) -> Vec<StoredEntity<PersistedNameMarketBoardEntity>> {
        store
            .list_entities_by_id_prefix(
                EntityKind::DenuoBoardObject,
                NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX,
                MAX_NAME_MARKET_BOARD_OFFERS,
            )
            .expect("normalized rows")
    }

    fn stored_normalized_listing_indexes(
        store: &WalletStore,
    ) -> Vec<StoredEntity<PersistedNameMarketBoardEntity>> {
        store
            .list_entities_by_id_prefix(
                EntityKind::DenuoBoardObject,
                NORMALIZED_NAME_MARKET_BOARD_LISTING_INDEX_PREFIX,
                MAX_NAME_MARKET_BOARD_OFFERS,
            )
            .expect("normalized listing indexes")
    }

    fn assert_corrupt(store: &WalletStore) {
        assert!(matches!(
            load_name_market_board(store),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));
    }

    #[test]
    fn compact_row_index_codec_is_canonical_strict_and_golden() {
        const GOLDEN_HEX: &str = concat!(
            "abababababababababababababababababababababababababababababababab",
            "0807060504030201",
            "1817161514131211",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
        );
        const GOLDEN_JSON: &str = concat!(
            "\"",
            "abababababababababababababababababababababababababababababababab",
            "0807060504030201",
            "1817161514131211",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            "\""
        );
        let index = PersistedNameMarketBoardRowIndex {
            id_digest: ObjectHash::new([0xab; 32]),
            store_revision: 0x0102_0304_0506_0708,
            updated_at_unix: 0x1112_1314_1516_1718,
            row_value_commitment: ObjectHash::new([0xcd; 32]),
            listing_hash: ObjectHash::new([0xef; 32]),
        };
        assert_eq!(GOLDEN_HEX.len(), 224);
        assert_eq!(
            serde_json::to_string(&index).expect("compact index"),
            GOLDEN_JSON
        );
        assert_eq!(
            serde_json::from_str::<PersistedNameMarketBoardRowIndex>(GOLDEN_JSON)
                .expect("golden compact index"),
            index
        );

        let uppercase = format!("\"{}\"", GOLDEN_HEX.to_ascii_uppercase());
        let truncated = format!("\"{}\"", &GOLDEN_HEX[..GOLDEN_HEX.len() - 1]);
        let non_hex = format!("\"g{}\"", &GOLDEN_HEX[1..]);
        let object_shaped = serde_json::to_string(&json!({
            "id_digest": vec![0xab; 32],
            "store_revision": 1,
            "updated_at_unix": 2,
            "row_value_commitment": vec![0xcd; 32],
            "listing_hash": vec![0xef; 32],
        }))
        .expect("object-shaped row index");
        for malformed in [uppercase, truncated, non_hex, object_shaped] {
            assert!(
                serde_json::from_str::<PersistedNameMarketBoardRowIndex>(&malformed).is_err(),
                "accepted noncanonical row index: {malformed}"
            );
        }

        let mut head = serde_json::to_value(PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version: NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION,
            logical_revision: 1,
            row_count: 1,
            rows: vec![index],
            row_set_commitment: ObjectHash::new([0x31; 32]),
            listing_index_set_commitment: ObjectHash::new([0x32; 32]),
        })
        .expect("indexed head JSON");
        head["unexpected_head_field"] = json!(true);
        assert!(serde_json::from_value::<PersistedNameMarketBoardEntity>(head).is_err());
    }

    #[test]
    fn normalized_row_value_commitment_is_frozen() {
        let row = NormalizedNameMarketBoardRow {
            id: b"not-part-of-the-value-commitment".to_vec(),
            store_revision: 23,
            updated_at_unix: 24,
            offer: PersistedBoardOffer {
                listing_hash: ObjectHash::new([1; 32]),
                listing_bytes: vec![2, 3, 4],
                network_magic: 0x0506_0708,
                network_genesis: ObjectHash::new([9; 32]),
                name_hash: ObjectHash::new([10; 32]),
                seller_public_key: vec![11, 12],
                sequence: 13,
                created_at_unix: 14,
                expires_at_unix: 15,
                status: BoardOfferStatus::Cancelled,
                cancellation_hash: Some(ObjectHash::new([16; 32])),
                cancellation_bytes: Some(vec![17, 18]),
                cancellation_sequence: Some(19),
            },
            watermark: SequenceWatermark {
                network_magic: 0x0506_0708,
                network_genesis: ObjectHash::new([9; 32]),
                name_hash: ObjectHash::new([10; 32]),
                seller_public_key: vec![11, 12],
                sequence: 19,
            },
        };
        assert_eq!(
            hex::encode(
                normalized_row_value_commitment(&row)
                    .expect("row value commitment")
                    .as_bytes()
            ),
            "a66982bca93d9afac65171ea60199c31078df9255ed50797331f755d26ea8698"
        );
    }

    #[test]
    fn legacy_board_migrates_atomically_and_preserves_logical_revision_and_namespace() {
        let legacy = fixture_board(&[(1, 1)]);
        let updated = fixture_board(&[(1, 1), (2, 2)]);
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("wallet store");
        assert_eq!(
            store
                .save_denuo_board_object(NAME_MARKET_BOARD_RECORD_ID, 0, &legacy, UPDATED_AT - 1)
                .expect("legacy board"),
            1
        );
        let outbox_sentinel = json!({"outbox_sentinel": true});
        assert_eq!(
            store
                .save_denuo_board_object(OUTBOX_RECORD_ID, 0, &outbox_sentinel, UPDATED_AT - 1)
                .expect("outbox sentinel"),
            1
        );

        assert!(matches!(
            save_name_market_board(&mut store, 0, &updated, UPDATED_AT),
            Err(ShakedexError::StaleRevision)
        ));
        assert!(
            store
                .denuo_board_object::<NameMarketBoard>(NAME_MARKET_BOARD_RECORD_ID)
                .expect("legacy lookup")
                .is_some()
        );
        assert!(
            store
                .denuo_board_object::<PersistedNameMarketBoardEntity>(
                    NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                )
                .expect("head lookup")
                .is_none()
        );
        assert!(stored_normalized_rows(&store).is_empty());

        assert_eq!(
            save_name_market_board(&mut store, 1, &updated, UPDATED_AT)
                .expect("atomic normalized migration"),
            2
        );
        assert!(
            store
                .denuo_board_object::<NameMarketBoard>(NAME_MARKET_BOARD_RECORD_ID)
                .expect("legacy lookup after migration")
                .is_none()
        );
        assert_eq!(stored_normalized_rows(&store).len(), 2);
        let loaded = load_name_market_board(&store).expect("migrated board");
        assert_eq!(loaded.revision, 2);
        assert_eq!(loaded.board, updated);
        let retained = store
            .denuo_board_object::<serde_json::Value>(OUTBOX_RECORD_ID)
            .expect("outbox lookup")
            .expect("retained outbox sentinel");
        assert_eq!(retained.revision, 1);
        assert_eq!(retained.value, outbox_sentinel);
    }

    #[test]
    fn pre_index_v2_head_loads_and_migrates_on_the_next_mutation() {
        let board = fixture_board(&[(1, 1)]);
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("wallet store");
        let mut rows = normalized_rows_from_board(&board).expect("normalized rows");
        for row in &mut rows {
            row.store_revision = 1;
            row.updated_at_unix = UPDATED_AT;
            assert_eq!(
                store
                    .save_denuo_board_object(&row.id, 0, &normalized_row_entity(row), UPDATED_AT,)
                    .expect("pre-index row"),
                1
            );
        }
        let frozen_head: serde_json::Value = serde_json::from_str(FROZEN_PRE_INDEX_HEAD_JSON)
            .expect("frozen historical HeadV2 JSON");
        assert!(matches!(
            serde_json::from_str::<PersistedNameMarketBoardEntity>(FROZEN_PRE_INDEX_HEAD_JSON)
                .expect("decode frozen historical HeadV2"),
            PersistedNameMarketBoardEntity::HeadV2 { .. }
        ));
        store
            .save_denuo_board_object(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                0,
                &frozen_head,
                UPDATED_AT,
            )
            .expect("pre-index v2 head");

        let selected_hash = board.offers()[0].listing_hash;
        let loaded = load_name_market_board(&store).expect("pre-index v2 full load");
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.board, board);
        let selected = load_name_market_board_offers(&store, &[selected_hash])
            .expect("pre-index targeted fallback");
        assert_eq!(selected.offers, vec![board.offer(selected_hash).cloned()]);
        assert!(stored_normalized_listing_indexes(&store).is_empty());

        assert_eq!(
            save_name_market_board(&mut store, 1, &board, UPDATED_AT + 1)
                .expect("atomic indexed-v2 migration"),
            2
        );
        assert_eq!(stored_normalized_listing_indexes(&store).len(), 1);
        assert!(
            stored_normalized_rows(&store)
                .iter()
                .all(|row| row.revision == 1 && row.updated_at_unix == UPDATED_AT)
        );
        let migrated_head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("migrated head lookup")
            .expect("migrated indexed head");
        assert!(matches!(
            migrated_head.value,
            PersistedNameMarketBoardEntity::HeadV2Indexed { .. }
        ));
    }

    #[test]
    fn normalized_board_rejects_missing_extra_wrong_revision_id_and_torn_coexistence() {
        let board = fixture_board(&[(1, 1)]);

        let mut missing = normalized_store(&board);
        let missing_row = stored_normalized_rows(&missing).pop().expect("one row");
        assert!(
            missing
                .delete_denuo_board_object(&missing_row.id, missing_row.revision)
                .expect("delete row")
        );
        assert_corrupt(&missing);

        let mut extra = normalized_store(&board);
        let second_board = fixture_board(&[(1, 1), (2, 2)]);
        let extra_row = normalized_rows_from_board(&second_board)
            .expect("target rows")
            .into_iter()
            .find(|row| row.offer.network_magic == 2)
            .expect("extra identity");
        extra
            .save_denuo_board_object(
                &extra_row.id,
                0,
                &normalized_row_entity(&extra_row),
                UPDATED_AT + 1,
            )
            .expect("extra row");
        assert_corrupt(&extra);

        let mut wrong_revision = normalized_store(&board);
        let row = stored_normalized_rows(&wrong_revision)
            .pop()
            .expect("one row");
        wrong_revision
            .save_denuo_board_object(&row.id, row.revision, &row.value, UPDATED_AT + 1)
            .expect("advance row without head");
        assert_corrupt(&wrong_revision);

        let mut wrong_id = normalized_store(&board);
        let row = stored_normalized_rows(&wrong_id).pop().expect("one row");
        let mut substituted_id = NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX.to_vec();
        substituted_id.extend_from_slice(&[0xa5; 32]);
        assert_ne!(substituted_id, row.id);
        wrong_id
            .apply_entity_batch(
                EntityKind::DenuoBoardObject,
                &[EntityBatchSave {
                    id: substituted_id,
                    expected_revision: 0,
                    value: row.value,
                    updated_at_unix: UPDATED_AT + 1,
                }],
                &[EntityBatchDelete {
                    id: row.id,
                    expected_revision: row.revision,
                }],
            )
            .expect("substitute wrong row ID");
        assert_corrupt(&wrong_id);

        let mut torn = normalized_store(&board);
        torn.save_denuo_board_object(NAME_MARKET_BOARD_RECORD_ID, 0, &board, UPDATED_AT + 1)
            .expect("inject torn legacy coexistence");
        assert_corrupt(&torn);
    }

    #[test]
    fn normalized_listing_index_is_complete_targeted_and_relist_safe() {
        let initial = fixture_board(&[(1, 1), (2, 2), (3, 3)]);
        let old_hash = initial
            .offers()
            .iter()
            .find(|offer| offer.network_magic == 1)
            .expect("old indexed offer")
            .listing_hash;
        let retained_hash = initial
            .offers()
            .iter()
            .find(|offer| offer.network_magic == 2)
            .expect("retained indexed offer")
            .listing_hash;
        let absent_hash = ObjectHash::new([0xff; 32]);
        assert!(initial.offer(absent_hash).is_none());
        let mut store = normalized_store(&initial);

        let indexes = stored_normalized_listing_indexes(&store);
        assert_eq!(indexes.len(), initial.offers().len());
        assert!(indexes.iter().all(|stored| matches!(
            stored.value,
            PersistedNameMarketBoardEntity::ListingIndexV2 { .. }
        )));
        let selected =
            load_name_market_board_offers(&store, &[old_hash, retained_hash, absent_hash])
                .expect("targeted indexed selection");
        assert_eq!(selected.revision, 1);
        assert_eq!(selected.offers[0], initial.offer(old_hash).cloned());
        assert_eq!(selected.offers[1], initial.offer(retained_hash).cloned());
        assert_eq!(selected.offers[2], None);

        let replacement = fixture_board(&[(1, 4), (2, 2), (3, 3)]);
        let new_hash = replacement
            .offers()
            .iter()
            .find(|offer| offer.network_magic == 1)
            .expect("replacement indexed offer")
            .listing_hash;
        assert_ne!(old_hash, new_hash);
        assert_eq!(
            save_name_market_board(&mut store, 1, &replacement, UPDATED_AT + 1)
                .expect("atomic relist index replacement"),
            2
        );
        let selected = load_name_market_board_offers(&store, &[old_hash, new_hash, retained_hash])
            .expect("post-relist indexed selection");
        assert_eq!(selected.revision, 2);
        assert_eq!(selected.offers[0], None);
        assert_eq!(selected.offers[1], replacement.offer(new_hash).cloned());
        assert_eq!(
            selected.offers[2],
            replacement.offer(retained_hash).cloned()
        );
        assert_eq!(
            stored_normalized_listing_indexes(&store).len(),
            replacement.offers().len()
        );
    }

    #[test]
    fn targeted_indexed_read_authenticates_only_requested_row_values() {
        let board = fixture_board(&[(1, 1), (2, 2)]);
        let selected_hash = board
            .offers()
            .iter()
            .find(|offer| offer.network_magic == 1)
            .expect("selected offer")
            .listing_hash;
        let mut store = normalized_store(&board);
        let unselected = stored_normalized_rows(&store)
            .into_iter()
            .find(|stored| {
                let PersistedNameMarketBoardEntity::RowV2 { offer, .. } = &stored.value else {
                    return false;
                };
                offer.network_magic == 2
            })
            .expect("unselected row");
        store
            .save_denuo_board_object(
                &unselected.id,
                unselected.revision,
                &json!({"record": "row_v2", "malformed": true}),
                UPDATED_AT + 1,
            )
            .expect("authenticated malformed unselected row");

        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("normalized head");
        let PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            row_count,
            mut rows,
            row_set_commitment,
            listing_index_set_commitment,
        } = head.value
        else {
            panic!("normalized head variant");
        };
        let unselected_digest = normalized_row_id_digest(&unselected.id).expect("row digest");
        let index = rows
            .iter_mut()
            .find(|index| index.id_digest == unselected_digest)
            .expect("unselected head index");
        index.store_revision = unselected.revision + 1;
        index.updated_at_unix = UPDATED_AT + 1;
        store
            .save_denuo_board_object(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                head.revision,
                &PersistedNameMarketBoardEntity::HeadV2Indexed {
                    schema_version,
                    logical_revision,
                    row_count,
                    rows,
                    row_set_commitment,
                    listing_index_set_commitment,
                },
                UPDATED_AT + 1,
            )
            .expect("head matching unselected metadata");

        let selected = load_name_market_board_offers(&store, &[selected_hash])
            .expect("targeted read ignores unrequested ciphertext");
        assert_eq!(selected.revision, 1);
        assert_eq!(selected.offers, vec![board.offer(selected_hash).cloned()]);
        assert!(matches!(
            load_name_market_board(&store),
            Err(ShakedexError::Persistence)
        ));
    }

    #[test]
    fn targeted_indexed_read_rejects_selected_row_same_metadata_aba() {
        let active_board = fixture_board(&[(1, 1)]);
        let selected_offer = active_board.offers()[0].clone();
        let listing = FixedPriceListing::decode(&selected_offer.listing_bytes)
            .expect("canonical fixture listing");
        let authenticated = crate::authenticate_fixed_price_listing(
            &selected_offer.listing_bytes,
            selected_offer.listing_hash,
        )
        .expect("authenticated fixture listing");
        let signing_key = SigningKey::from_slice(&[0x61; 32]).expect("seller key");
        let mut cancellation = ListingCancellation::for_listing(
            &listing,
            UPDATED_AT + 1,
            listing.expires_at + 600,
            listing.sequence + 1,
        )
        .expect("cancellation terms");
        cancellation
            .sign(&signing_key)
            .expect("signed cancellation");
        let cancellation_bytes = cancellation.encode().expect("cancellation encoding");
        let verified_cancellation = crate::verify_listing_cancellation(
            &cancellation_bytes,
            &authenticated,
            NetworkBinding {
                magic: selected_offer.network_magic,
                genesis: BlockHash::new(selected_offer.network_genesis.into_bytes()),
            },
            UPDATED_AT + 2,
        )
        .expect("verified cancellation");
        let mut cancelled_board = active_board.clone();
        assert!(
            cancelled_board
                .apply_cancellation(&verified_cancellation)
                .expect("apply cancellation")
        );
        let cancelled_row = normalized_rows_from_board(&cancelled_board)
            .expect("cancelled normalized row")
            .pop()
            .expect("one cancelled row");

        let mut store = normalized_store(&active_board);
        let selected_row = stored_normalized_rows(&store).pop().expect("selected row");
        let metadata_before = store
            .list_untrusted_entity_metadata_by_id_prefix(
                EntityKind::DenuoBoardObject,
                NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX,
                1,
            )
            .expect("selected metadata before ABA");
        assert!(
            store
                .delete_denuo_board_object(&selected_row.id, selected_row.revision)
                .expect("delete selected row")
        );
        assert_eq!(
            store
                .save_denuo_board_object(
                    &selected_row.id,
                    0,
                    &normalized_row_entity(&cancelled_row),
                    selected_row.updated_at_unix,
                )
                .expect("recreate selected row at identical metadata"),
            selected_row.revision
        );
        assert_eq!(
            store
                .list_untrusted_entity_metadata_by_id_prefix(
                    EntityKind::DenuoBoardObject,
                    NORMALIZED_NAME_MARKET_BOARD_ROW_PREFIX,
                    1,
                )
                .expect("selected metadata after ABA"),
            metadata_before,
            "the selected row ABA must restore its exact public metadata"
        );

        assert!(matches!(
            load_name_market_board_offers(&store, &[selected_offer.listing_hash]),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));
        assert_corrupt(&store);
    }

    #[test]
    fn targeted_indexed_read_rejects_substituted_committed_listing_index_set() {
        let board = fixture_board(&[(1, 1)]);
        let target_hash = board.offers()[0].listing_hash;
        let substitute_hash = ObjectHash::new([0xa5; 32]);
        assert_ne!(substitute_hash, target_hash);
        let mut store = normalized_store(&board);

        let original_index = stored_normalized_listing_indexes(&store)
            .pop()
            .expect("one listing index");
        let PersistedNameMarketBoardEntity::ListingIndexV2 { row_id_digest, .. } =
            original_index.value
        else {
            panic!("normalized listing-index variant");
        };
        let substitute_id = normalized_listing_index_id(substitute_hash);
        let substitute_metadata = vec![StoredEntityMetadata {
            kind: EntityKind::DenuoBoardObject,
            id: substitute_id.clone(),
            revision: 1,
            updated_at_unix: UPDATED_AT + 1,
        }];
        let substituted_set_commitment =
            normalized_listing_index_set_commitment(&substitute_metadata)
                .expect("substituted listing-index set commitment");

        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("normalized head");
        let PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            row_count,
            mut rows,
            row_set_commitment,
            ..
        } = head.value
        else {
            panic!("normalized head variant");
        };
        assert_eq!(rows.len(), 1);
        rows[0].listing_hash = substitute_hash;
        store
            .apply_entity_batch(
                EntityKind::DenuoBoardObject,
                &[
                    EntityBatchSave {
                        id: substitute_id,
                        expected_revision: 0,
                        value: PersistedNameMarketBoardEntity::ListingIndexV2 {
                            listing_hash: substitute_hash,
                            row_id_digest,
                        },
                        updated_at_unix: UPDATED_AT + 1,
                    },
                    EntityBatchSave {
                        id: NORMALIZED_NAME_MARKET_BOARD_HEAD_ID.to_vec(),
                        expected_revision: head.revision,
                        value: PersistedNameMarketBoardEntity::HeadV2Indexed {
                            schema_version,
                            logical_revision,
                            row_count,
                            rows,
                            row_set_commitment,
                            listing_index_set_commitment: substituted_set_commitment,
                        },
                        updated_at_unix: UPDATED_AT + 1,
                    },
                ],
                &[EntityBatchDelete {
                    id: original_index.id,
                    expected_revision: original_index.revision,
                }],
            )
            .expect("atomically remap the head selector and committed listing-index set");

        // The head and metadata now claim that only `substitute_hash` exists,
        // while the authenticated row still contains `target_hash`. A
        // head-only miss would return a false absence; the full semantic
        // fallback must reject the combined remap.
        assert!(matches!(
            load_name_market_board_offers(&store, &[target_hash]),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));
        assert_corrupt(&store);
    }

    #[test]
    fn permuted_head_listing_hash_selectors_are_rejected_by_full_and_targeted_reads() {
        let board = fixture_board(&[(1, 1), (2, 2)]);
        let target_hash = board.offers()[0].listing_hash;
        let mut store = normalized_store(&board);
        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("normalized head");
        let PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            row_count,
            mut rows,
            row_set_commitment,
            listing_index_set_commitment,
        } = head.value
        else {
            panic!("normalized head variant");
        };
        assert_eq!(rows.len(), 2);
        let first_listing_hash = rows[0].listing_hash;
        rows[0].listing_hash = rows[1].listing_hash;
        rows[1].listing_hash = first_listing_hash;
        store
            .save_denuo_board_object(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                head.revision,
                &PersistedNameMarketBoardEntity::HeadV2Indexed {
                    schema_version,
                    logical_revision,
                    row_count,
                    rows,
                    row_set_commitment,
                    listing_index_set_commitment,
                },
                UPDATED_AT + 1,
            )
            .expect("authenticated head with permuted listing selectors");

        assert_corrupt(&store);
        assert!(matches!(
            load_name_market_board_offers(&store, &[target_hash]),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));
    }

    #[test]
    fn normalized_listing_index_rejects_missing_extra_and_substituted_records() {
        let board = fixture_board(&[(1, 1)]);
        let listing_hash = board.offers()[0].listing_hash;

        let mut missing = normalized_store(&board);
        let index = stored_normalized_listing_indexes(&missing)
            .pop()
            .expect("one listing index");
        assert!(
            missing
                .delete_denuo_board_object(&index.id, index.revision)
                .expect("delete listing index")
        );
        assert_corrupt(&missing);
        assert!(matches!(
            load_name_market_board_offers(&missing, &[listing_hash]),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));

        let mut extra = normalized_store(&board);
        let extra_board = fixture_board(&[(1, 1), (2, 2)]);
        let extra_row = normalized_rows_from_board(&extra_board)
            .expect("extra rows")
            .into_iter()
            .find(|row| row.offer.network_magic == 2)
            .expect("extra row");
        let extra_index = normalized_listing_index_from_row(&extra_row).expect("extra index");
        extra
            .save_denuo_board_object(
                &extra_index.id,
                0,
                &normalized_listing_index_entity(&extra_index),
                UPDATED_AT + 1,
            )
            .expect("inject extra listing index");
        assert_corrupt(&extra);

        let mut substituted = normalized_store(&board);
        let index = stored_normalized_listing_indexes(&substituted)
            .pop()
            .expect("one listing index");
        let wrong = PersistedNameMarketBoardEntity::ListingIndexV2 {
            listing_hash,
            row_id_digest: ObjectHash::new([0xa5; 32]),
        };
        substituted
            .save_denuo_board_object(&index.id, index.revision, &wrong, UPDATED_AT + 1)
            .expect("substitute listing mapping");
        assert_corrupt(&substituted);
    }

    #[test]
    fn normalized_head_is_bounded_and_set_checked_before_indexed_row_decode() {
        let board = fixture_board(&[(1, 1)]);
        let mut store = normalized_store(&board);
        let row = stored_normalized_rows(&store).pop().expect("one row");
        let malformed_row = json!({"record": "row_v2", "malformed": true});
        store
            .save_denuo_board_object(&row.id, row.revision, &malformed_row, UPDATED_AT + 1)
            .expect("authenticated malformed row");

        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("head present");
        let PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            mut rows,
            row_set_commitment,
            listing_index_set_commitment,
            ..
        } = head.value
        else {
            panic!("normalized head variant");
        };
        rows[0].store_revision = row.revision + 1;
        rows[0].updated_at_unix = UPDATED_AT + 1;
        rows.push(rows[0].clone());
        let malformed_head = PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            row_count: 2,
            rows,
            row_set_commitment,
            listing_index_set_commitment,
        };
        store
            .save_denuo_board_object(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                head.revision,
                &malformed_head,
                UPDATED_AT + 1,
            )
            .expect("authenticated malformed head");

        // A row decode would surface Persistence. Corrupt proves the duplicate
        // selector was rejected before it could drive even the first row read.
        assert_corrupt(&store);
    }

    #[test]
    fn normalized_row_rejects_authenticated_nested_unknown_fields() {
        let board = fixture_board(&[(1, 1)]);
        let mut store = normalized_store(&board);
        let row = stored_normalized_rows(&store).pop().expect("one row");
        let mut value = serde_json::to_value(&row.value).expect("row JSON");
        value["offer"]["unexpected_v2_field"] = json!(true);
        store
            .save_denuo_board_object(&row.id, row.revision, &value, UPDATED_AT + 1)
            .expect("authenticated row with nested unknown field");

        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("head present");
        let PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version,
            logical_revision,
            row_count,
            mut rows,
            row_set_commitment,
            listing_index_set_commitment,
        } = head.value
        else {
            panic!("normalized head variant");
        };
        rows[0].store_revision = row.revision + 1;
        rows[0].updated_at_unix = UPDATED_AT + 1;
        store
            .save_denuo_board_object(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
                head.revision,
                &PersistedNameMarketBoardEntity::HeadV2Indexed {
                    schema_version,
                    logical_revision,
                    row_count,
                    rows,
                    row_set_commitment,
                    listing_index_set_commitment,
                },
                UPDATED_AT + 1,
            )
            .expect("head matching rewritten row metadata");
        assert!(matches!(
            load_name_market_board(&store),
            Err(ShakedexError::Persistence)
        ));
    }

    #[test]
    fn raw_board_save_cannot_remove_or_rewrite_durable_identity_lineage() {
        let initial = fixture_board(&[(1, 1), (2, 2)]);
        let mut store = normalized_store(&initial);
        let removed_identity = fixture_board(&[(1, 1)]);
        assert!(matches!(
            save_name_market_board(&mut store, 1, &removed_identity, UPDATED_AT + 1),
            Err(ShakedexError::NameMarketReplay)
        ));
        let same_sequence_rewrite = fixture_board_with_price(&[(1, 1), (2, 2)], 12_345_679);
        assert!(matches!(
            save_name_market_board(&mut store, 1, &same_sequence_rewrite, UPDATED_AT + 1),
            Err(ShakedexError::NameMarketReplay)
        ));
        let retained = load_name_market_board(&store).expect("unchanged board");
        assert_eq!(retained.revision, 1);
        assert_eq!(retained.board, initial);
    }

    #[test]
    fn normalized_board_preserves_exact_rows_and_logical_cas() {
        let initial = fixture_board(&[(1, 1)]);
        let replacement = fixture_board(&[(1, 2)]);
        let mut store = normalized_store(&initial);
        let first_row = stored_normalized_rows(&store).pop().expect("first row");

        assert_eq!(
            save_name_market_board(&mut store, 1, &initial, UPDATED_AT + 1)
                .expect("logical no-content save"),
            2
        );
        let unchanged_row = stored_normalized_rows(&store).pop().expect("unchanged row");
        assert_eq!(unchanged_row.revision, first_row.revision);
        assert_eq!(unchanged_row.updated_at_unix, first_row.updated_at_unix);
        assert_eq!(unchanged_row.value, first_row.value);

        assert_eq!(
            save_name_market_board(&mut store, 2, &replacement, UPDATED_AT + 2)
                .expect("same-identity replacement"),
            3
        );
        let replaced_row = stored_normalized_rows(&store).pop().expect("replaced row");
        assert_eq!(replaced_row.revision, first_row.revision + 1);
        assert_eq!(replaced_row.updated_at_unix, UPDATED_AT + 2);
        let loaded = load_name_market_board(&store).expect("replacement board");
        assert_eq!(loaded.revision, 3);
        assert_eq!(loaded.board, replacement);
        assert!(matches!(
            save_name_market_board(&mut store, 2, &replacement, UPDATED_AT + 3),
            Err(ShakedexError::StaleRevision)
        ));
    }

    #[test]
    fn guarded_board_save_rejects_account_set_aba_and_rolls_back() {
        let initial = fixture_board(&[(1, 1)]);
        let replacement = fixture_board(&[(1, 2)]);
        let mut store = normalized_store(&initial);
        let account_prefix = b"guarded-account/";
        let account_id = b"guarded-account/selected";
        assert_eq!(
            store
                .save_entity(
                    EntityKind::WalletAccount,
                    account_id,
                    0,
                    &json!({"account": "original"}),
                    UPDATED_AT,
                )
                .expect("guard account"),
            1
        );
        let (loaded, account_prefix_lease) = store
            .try_with_entity_read_snapshot(|snapshot| {
                Ok::<_, ShakedexError>((
                    load_name_market_board_state_from_snapshot(snapshot)?,
                    snapshot.entity_prefix_set_lease(
                        EntityKind::WalletAccount,
                        account_prefix,
                        1,
                    )?,
                ))
            })
            .expect("coherent board and account leases");
        assert!(
            store
                .delete_entity(EntityKind::WalletAccount, account_id, 1)
                .expect("delete guarded account")
        );
        assert_eq!(
            store
                .save_entity(
                    EntityKind::WalletAccount,
                    account_id,
                    0,
                    &json!({"account": "substituted"}),
                    UPDATED_AT,
                )
                .expect("recreate guarded account at identical metadata"),
            1
        );

        assert!(matches!(
            save_loaded_name_market_board_with_guard(
                &mut store,
                1,
                &replacement,
                UPDATED_AT + 1,
                loaded,
                account_prefix_lease,
            ),
            Err(ShakedexError::StaleRevision)
        ));
        let retained = load_name_market_board(&store).expect("unchanged guarded board");
        assert_eq!(retained.revision, 1);
        assert_eq!(retained.board, initial);
    }

    #[test]
    fn maximum_head_and_row_encodings_fit_the_per_record_bound() {
        let board = fixture_board(&[(1, 1)]);
        let mut row = normalized_rows_from_board(&board)
            .expect("normalized row")
            .pop()
            .expect("one row");
        row.store_revision = 1;
        row.updated_at_unix = UPDATED_AT;
        assert!(
            serde_json::to_vec(&normalized_row_entity(&row))
                .expect("row encoding")
                .len()
                <= MAX_STATE_BYTES
        );

        let rows = (0..MAX_NAME_MARKET_BOARD_OFFERS)
            .map(|index| {
                let mut digest = [0xff_u8; 32];
                digest[24..].copy_from_slice(
                    &u64::try_from(index)
                        .expect("bounded row index")
                        .to_be_bytes(),
                );
                let mut listing_hash = [0xee_u8; 32];
                listing_hash[24..].copy_from_slice(
                    &u64::try_from(index)
                        .expect("bounded listing index")
                        .to_be_bytes(),
                );
                PersistedNameMarketBoardRowIndex {
                    id_digest: ObjectHash::new(digest),
                    store_revision: u64::MAX,
                    updated_at_unix: u64::MAX,
                    row_value_commitment: ObjectHash::new([0xff; 32]),
                    listing_hash: ObjectHash::new(listing_hash),
                }
            })
            .collect::<Vec<_>>();
        assert!(normalized_metadata_from_index(&rows).is_ok());
        let head = PersistedNameMarketBoardEntity::HeadV2Indexed {
            schema_version: NORMALIZED_NAME_MARKET_BOARD_SCHEMA_VERSION,
            logical_revision: 1,
            row_count: u32::try_from(rows.len()).expect("bounded row count"),
            rows: rows.clone(),
            row_set_commitment: ObjectHash::new([0x7a; 32]),
            listing_index_set_commitment: ObjectHash::new([0xff; 32]),
        };
        assert!(
            serde_json::to_vec(&head)
                .expect("maximum head encoding")
                .len()
                <= MAX_STATE_BYTES
        );
        let mut over_capacity = rows;
        over_capacity.push(PersistedNameMarketBoardRowIndex {
            id_digest: ObjectHash::new([0xff; 32]),
            store_revision: 1,
            updated_at_unix: UPDATED_AT,
            row_value_commitment: ObjectHash::new([0xff; 32]),
            listing_hash: ObjectHash::new([0xff; 32]),
        });
        assert!(matches!(
            normalized_metadata_from_index(&over_capacity),
            Err(ShakedexError::CorruptNameMarketBoard)
        ));
    }

    #[test]
    fn normalized_board_default_roundtrip_is_cryptographically_real() {
        let board = fixture_board(
            &(1..=32)
                .map(|value| (value, u64::from(value)))
                .collect::<Vec<_>>(),
        );
        let store = normalized_store(&board);
        assert_eq!(
            load_name_market_board(&store)
                .expect("default normalized roundtrip")
                .board,
            board
        );
    }

    #[test]
    #[ignore = "release-mode 4,096-row persistence qualification"]
    fn maximum_board_uses_bounded_normalized_records() {
        let board = maximum_fixture_board();
        assert_eq!(board.offers().len(), MAX_NAME_MARKET_BOARD_OFFERS);
        assert!(
            serde_json::to_vec(&board)
                .expect("legacy aggregate encoding")
                .len()
                > MAX_STATE_BYTES,
            "the normalized regression must exercise the legacy aggregate limit"
        );

        let store = normalized_store(&board);
        let head = store
            .denuo_board_object::<PersistedNameMarketBoardEntity>(
                NORMALIZED_NAME_MARKET_BOARD_HEAD_ID,
            )
            .expect("head lookup")
            .expect("normalized head");
        assert!(
            serde_json::to_vec(&head.value)
                .expect("head encoding")
                .len()
                <= MAX_STATE_BYTES
        );
        let rows = stored_normalized_rows(&store);
        assert_eq!(rows.len(), MAX_NAME_MARKET_BOARD_OFFERS);
        assert!(rows.iter().all(|row| {
            serde_json::to_vec(&row.value).expect("row encoding").len() <= MAX_STATE_BYTES
        }));
        let listing_indexes = stored_normalized_listing_indexes(&store);
        assert_eq!(listing_indexes.len(), MAX_NAME_MARKET_BOARD_OFFERS);
        assert!(listing_indexes.iter().all(|index| {
            serde_json::to_vec(&index.value)
                .expect("listing-index encoding")
                .len()
                <= MAX_STATE_BYTES
        }));
        let loaded = load_name_market_board(&store).expect("maximum normalized board");
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.board, board);
    }
}
