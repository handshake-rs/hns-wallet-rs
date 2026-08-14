use hns_marketplace_protocol::DenuoRegistryVersion;
use hns_wallet_hns::{HnsBackend, HnsClock};
use hns_wallet_types::ObjectHash;

use crate::board_runtime::CurrentDenuoBoardInventory;
use crate::{
    CurrentDenuoBoardOffer, DenuoBoardRuntime, DenuoNameMarketRequest, ShakedexError,
    decode_denuo_authenticated_offer, decode_denuo_inventory, decode_denuo_request,
    encode_denuo_inventory, encode_denuo_offer,
};

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
