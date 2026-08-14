use hns_marketplace_protocol::{
    DenuoRegistryVersion, MAX_NAME_OFFERS_PER_MESSAGE, NameMarketMessage,
};
use hns_wallet_hns::{HnsBackend, HnsClock, MAX_CURRENT_SHAKEDEX_LOCK_BATCH};
use hns_wallet_types::ObjectHash;

use crate::board_runtime::{
    CurrentDenuoBoardInventory, CurrentDenuoBoardOffers, CurrentDenuoBoardOffersResolution,
};
use crate::{
    CurrentDenuoBoardOffer, DenuoBoardRuntime, DenuoNameMarketRequest, ShakedexError,
    decode_denuo_authenticated_offer, decode_denuo_inventory, decode_denuo_request,
    encode_denuo_inventory, encode_denuo_offer,
};

/// Closed query-scoped plan for the nonempty current subset of one exact
/// canonical V2 `GetOffers` request.
///
/// Exact request hashes, verified listings, current locks, and temporary wire
/// bytes remain private. This object is non-cloneable and non-serializable and
/// exposes no signing, transport, provider, or value capability.
#[must_use = "a Denuo board offers plan is point-in-time evidence, not transport authority"]
pub struct PreparedDenuoBoardOffersResponse {
    request_id: u64,
    current: Box<CurrentDenuoBoardOffers>,
}

impl PreparedDenuoBoardOffersResponse {
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn board_revision(&self) -> u64 {
        self.current.board_revision()
    }

    pub fn requested_count(&self) -> usize {
        self.current.requested_listing_hashes().len()
    }

    pub fn returned_count(&self) -> usize {
        self.current.listings().len()
    }
}

impl core::fmt::Debug for PreparedDenuoBoardOffersResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedDenuoBoardOffersResponse")
            .field("request_id", &self.request_id)
            .field("board_revision", &self.current.board_revision())
            .field(
                "requested_count",
                &self.current.requested_listing_hashes().len(),
            )
            .field("returned_count", &self.current.listings().len())
            .finish_non_exhaustive()
    }
}

/// Result of resolving one canonical V2 `GetOffers` request.
///
/// Missing and cancelled rows are omitted from the response subset. `Absent`
/// means every requested row was missing or cancelled and deliberately
/// carries no wire response, because canonical type-5 `Offers` cannot be
/// empty. `Current` retains one private coherent current-lock batch.
#[must_use = "a Denuo board offers response plan must be handled explicitly"]
pub enum DenuoBoardOffersResponsePlan {
    Absent {
        request_id: u64,
        requested_count: usize,
        board_revision: u64,
    },
    Current(Box<PreparedDenuoBoardOffersResponse>),
}

impl DenuoBoardOffersResponsePlan {
    pub const fn request_id(&self) -> u64 {
        match self {
            Self::Absent { request_id, .. } => *request_id,
            Self::Current(prepared) => prepared.request_id(),
        }
    }

    pub fn requested_count(&self) -> usize {
        match self {
            Self::Absent {
                requested_count, ..
            } => *requested_count,
            Self::Current(prepared) => prepared.requested_count(),
        }
    }

    pub fn returned_count(&self) -> usize {
        match self {
            Self::Absent { .. } => 0,
            Self::Current(prepared) => prepared.returned_count(),
        }
    }

    pub const fn board_revision(&self) -> u64 {
        match self {
            Self::Absent { board_revision, .. } => *board_revision,
            Self::Current(prepared) => prepared.board_revision(),
        }
    }
}

impl core::fmt::Debug for DenuoBoardOffersResponsePlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent {
                request_id,
                requested_count,
                board_revision,
            } => formatter
                .debug_struct("Absent")
                .field("request_id", request_id)
                .field("requested_count", requested_count)
                .field("board_revision", board_revision)
                .finish(),
            Self::Current(prepared) => formatter.debug_tuple("Current").field(prepared).finish(),
        }
    }
}

/// Closed point-in-time plan for one exact current board inventory.
///
/// The selected-account context and exact hashes remain private. This type is
/// non-cloneable and non-serializable and exposes no response bytes, listing,
/// current lock, signing, transport, provider, or value capability. A future
/// transport boundary must reacquire and fence current authority again.
#[must_use = "a Denuo board inventory plan is point-in-time evidence, not transport authority"]
pub struct PreparedDenuoBoardInventoryResponse {
    request_id: u64,
    current: CurrentDenuoBoardInventory,
}

impl PreparedDenuoBoardInventoryResponse {
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn board_revision(&self) -> u64 {
        self.current.board_revision()
    }

    pub fn listing_count(&self) -> usize {
        self.current.listing_hashes().len()
    }
}

impl core::fmt::Debug for PreparedDenuoBoardInventoryResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedDenuoBoardInventoryResponse")
            .field("request_id", &self.request_id)
            .field("board_revision", &self.current.board_revision())
            .field("listing_count", &self.current.listing_hashes().len())
            .finish_non_exhaustive()
    }
}

/// Closed query-scoped plan for one exact current board offer.
///
/// The retained current-lock/listing authority is deliberately private. This
/// type is non-cloneable and non-serializable and exposes no response bytes,
/// listing, lock, signing, transport, provider, or value capability. A future
/// transport boundary must reacquire and fence current authority again before
/// it encodes or sends any response.
#[must_use = "a Denuo board response plan is point-in-time evidence, not transport authority"]
pub struct PreparedDenuoBoardOfferResponse {
    request_id: u64,
    listing_hash: ObjectHash,
    current: CurrentDenuoBoardOffer,
}

impl PreparedDenuoBoardOfferResponse {
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        self.listing_hash
    }

    pub const fn board_revision(&self) -> u64 {
        self.current.board_revision()
    }
}

impl core::fmt::Debug for PreparedDenuoBoardOfferResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedDenuoBoardOfferResponse")
            .field("request_id", &self.request_id)
            .field("listing_hash", &self.listing_hash)
            .field("board_revision", &self.current.board_revision())
            .finish_non_exhaustive()
    }
}

/// Result of evaluating one canonical V2 `GetOffer` request against fresh
/// board and HNS current-lock authority.
///
/// `Absent` covers both a missing row and a persisted cancellation tombstone.
/// `Current` retains private query-scoped authority but still carries no bytes
/// that a caller could send. This enum is non-cloneable and non-serializable.
#[must_use = "a Denuo board response plan must be handled explicitly"]
pub enum DenuoBoardOfferResponsePlan {
    Absent {
        request_id: u64,
        listing_hash: ObjectHash,
    },
    Current(Box<PreparedDenuoBoardOfferResponse>),
}

impl DenuoBoardOfferResponsePlan {
    pub const fn request_id(&self) -> u64 {
        match self {
            Self::Absent { request_id, .. } => *request_id,
            Self::Current(prepared) => prepared.request_id(),
        }
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        match self {
            Self::Absent { listing_hash, .. } => *listing_hash,
            Self::Current(prepared) => prepared.listing_hash(),
        }
    }

    pub const fn board_revision(&self) -> Option<u64> {
        match self {
            Self::Absent { .. } => None,
            Self::Current(prepared) => Some(prepared.board_revision()),
        }
    }
}

impl core::fmt::Debug for DenuoBoardOfferResponsePlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent {
                request_id,
                listing_hash,
            } => formatter
                .debug_struct("Absent")
                .field("request_id", request_id)
                .field("listing_hash", listing_hash)
                .finish(),
            Self::Current(prepared) => formatter.debug_tuple("Current").field(prepared).finish(),
        }
    }
}

/// Prepare a closed response plan for one canonical Denuo V2 `GetOffers`
/// request containing at most 64 exact sorted, unique, nonzero hashes.
///
/// The row limit is checked after canonical request decoding but before any
/// account, store, backend, or clock access. Missing and cancelled rows are
/// omitted; an all-absent request yields a typed local `Absent` result rather
/// than trying to encode the protocol-invalid empty `Offers` message. Every
/// nonempty result is bound to one coherent HNS current-lock batch and an
/// unchanged selected account plus exact board revision/rows. The canonical
/// response is encoded and decoded internally under the exact request ID and
/// exact ordered subset, then all temporary wire objects are discarded.
pub fn prepare_denuo_board_offers_response<B: HnsBackend, C: HnsClock>(
    encoded_request: &[u8],
    board: &DenuoBoardRuntime<'_, B, C>,
) -> Result<DenuoBoardOffersResponsePlan, ShakedexError> {
    let (request_id, request) = decode_denuo_request(encoded_request, DenuoRegistryVersion::V2)?;
    let DenuoNameMarketRequest::Offers(listing_hashes) = request else {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    };
    if listing_hashes.is_empty()
        || listing_hashes.len() > MAX_NAME_OFFERS_PER_MESSAGE
        || listing_hashes.len() > MAX_CURRENT_SHAKEDEX_LOCK_BATCH
        || listing_hashes
            .iter()
            .any(|listing_hash| *listing_hash.as_bytes() == [0; 32])
        || listing_hashes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    }
    let requested_count = listing_hashes.len();
    let current = match board.current_offers(&listing_hashes)? {
        CurrentDenuoBoardOffersResolution::Absent { board_revision } => {
            return Ok(DenuoBoardOffersResponsePlan::Absent {
                request_id,
                requested_count,
                board_revision,
            });
        }
        CurrentDenuoBoardOffersResolution::Current(current) => current,
    };

    let response_bytes = NameMarketMessage::Offers(
        current
            .listings()
            .iter()
            .map(|listing| listing.authenticated().canonical().clone())
            .collect(),
    )
    .encode_envelope(DenuoRegistryVersion::V2, request_id)
    .map_err(|_| ShakedexError::InvalidDenuoEnvelope)?;
    let (decoded_registry, decoded_request_id, decoded_message) =
        NameMarketMessage::decode_envelope(&response_bytes)
            .map_err(|_| ShakedexError::InvalidDenuoEnvelope)?;
    let NameMarketMessage::Offers(decoded_listings) = decoded_message else {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    };
    if decoded_registry != DenuoRegistryVersion::V2
        || decoded_request_id != request_id
        || decoded_listings.len() != current.listings().len()
    {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    }
    for (decoded, expected) in decoded_listings.iter().zip(current.listings()) {
        let decoded_hash = ObjectHash::new(
            decoded
                .listing_hash()
                .map_err(|_| ShakedexError::InvalidDenuoEnvelope)?,
        );
        let decoded_bytes = decoded
            .encode()
            .map_err(|_| ShakedexError::InvalidDenuoEnvelope)?;
        if decoded_hash != expected.listing_hash()
            || decoded_bytes != expected.encoded()
            || current
                .requested_listing_hashes()
                .binary_search(&decoded_hash)
                .is_err()
        {
            return Err(ShakedexError::InvalidDenuoEnvelope);
        }
    }
    drop(decoded_listings);
    drop(response_bytes);

    Ok(DenuoBoardOffersResponsePlan::Current(Box::new(
        PreparedDenuoBoardOffersResponse {
            request_id,
            current,
        },
    )))
}

/// Prepare a closed response plan for exactly one canonical Denuo V2
/// `GetOffer` request.
///
/// The canonical Denuo envelope requires a nonzero correlation ID for both
/// `GetOffer` and `Offer`; zero is rejected during decoding before board or
/// node access. The function calls only `DenuoBoardRuntime::current_offer`
/// after decoding the request. A current offer is encoded and authenticated
/// back internally under the exact request ID/hash/listing bytes, after which
/// both temporary response objects are discarded. No encoded response is
/// retained or returned.
pub fn prepare_denuo_board_offer_response<B: HnsBackend, C: HnsClock>(
    encoded_request: &[u8],
    board: &DenuoBoardRuntime<'_, B, C>,
) -> Result<DenuoBoardOfferResponsePlan, ShakedexError> {
    let (request_id, request) = decode_denuo_request(encoded_request, DenuoRegistryVersion::V2)?;
    let DenuoNameMarketRequest::Offer(listing_hash) = request else {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    };
    let Some(current) = board.current_offer(listing_hash)? else {
        return Ok(DenuoBoardOfferResponsePlan::Absent {
            request_id,
            listing_hash,
        });
    };

    let response_bytes = encode_denuo_offer(
        DenuoRegistryVersion::V2,
        request_id,
        current.listing().authenticated(),
    )?;
    let (decoded_request_id, decoded_listing) =
        decode_denuo_authenticated_offer(&response_bytes, DenuoRegistryVersion::V2, listing_hash)?;
    if decoded_request_id != request_id
        || decoded_listing.listing_hash() != listing_hash
        || decoded_listing.encoded() != current.listing().encoded()
    {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    }
    drop(decoded_listing);
    drop(response_bytes);

    Ok(DenuoBoardOfferResponsePlan::Current(Box::new(
        PreparedDenuoBoardOfferResponse {
            request_id,
            listing_hash,
            current,
        },
    )))
}

/// Prepare a closed response plan for exactly one canonical Denuo V2
/// `GetOfferInventory` request.
///
/// Both the inventory request and its type-3 response require the same nonzero
/// correlation ID. Decoding and request-family selection occur before account,
/// clock, store, or backend access. The current selected account/network/time
/// context then selects only active in-window hashes without a node query or
/// write. A canonical response is encoded and decoded internally to verify its
/// exact request ID and ordered hashes, after which both temporary response
/// objects are discarded. An empty inventory is a valid response plan.
pub fn prepare_denuo_board_inventory_response<B: HnsBackend, C: HnsClock>(
    encoded_request: &[u8],
    board: &DenuoBoardRuntime<'_, B, C>,
) -> Result<PreparedDenuoBoardInventoryResponse, ShakedexError> {
    let (request_id, request) = decode_denuo_request(encoded_request, DenuoRegistryVersion::V2)?;
    if request != DenuoNameMarketRequest::Inventory {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    }
    let current = board.current_inventory()?;
    let response_bytes = encode_denuo_inventory(
        DenuoRegistryVersion::V2,
        request_id,
        current.listing_hashes(),
    )?;
    let (decoded_request_id, decoded_listing_hashes) =
        decode_denuo_inventory(&response_bytes, DenuoRegistryVersion::V2)?;
    if decoded_request_id != request_id
        || decoded_listing_hashes.as_slice() != current.listing_hashes()
    {
        return Err(ShakedexError::InvalidDenuoEnvelope);
    }
    drop(decoded_listing_hashes);
    drop(response_bytes);

    Ok(PreparedDenuoBoardInventoryResponse {
        request_id,
        current,
    })
}
