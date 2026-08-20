#![doc = "Release-gated fixed-price Shakedex persistence boundary."]
#![forbid(unsafe_code)]

mod acceptance;
mod board;
mod board_read;
mod board_runtime;
mod canonical;
mod outbox;
mod plans;
mod seller_offer;
mod trade_runtime;
mod transactions;
mod value_workflow;

pub use acceptance::{
    DenuoHnsaEndpointBinding, DenuoHrmRootBinding, DenuoPublicationAcceptancePolicy,
    DenuoPublicationAcceptanceSnapshot, HNSA_NAMED_SERVICE_RESOURCE_PROFILE,
    MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES,
};
pub use board::{
    BoardOfferStatus, NameMarketBoard, PersistedBoardOffer, StoredNameMarketBoard,
    load_name_market_board, save_name_market_board,
};
pub use board_read::{
    DenuoBoardOfferResponsePlan, DenuoBoardOffersResponsePlan, PreparedDenuoBoardInventoryResponse,
    PreparedDenuoBoardOfferResponse, PreparedDenuoBoardOffersResponse,
    prepare_denuo_board_inventory_response, prepare_denuo_board_offer_response,
    prepare_denuo_board_offers_response,
};
pub use board_runtime::{
    CurrentDenuoBoardOffer, DenuoBoardCancellationAdmission, DenuoBoardOfferAdmission,
    DenuoBoardRuntime,
};
pub use canonical::{
    AuthenticatedFixedPriceListing, AuthenticatedListingCancellation, DenuoNameMarketRequest,
    VerifiedFixedPriceListing, VerifiedListingCancellation, authenticate_fixed_price_listing,
    authenticate_listing_cancellation, decode_denuo_authenticated_cancellation,
    decode_denuo_authenticated_offer, decode_denuo_cancellation, decode_denuo_inventory,
    decode_denuo_offer, decode_denuo_request, encode_denuo_cancellation, encode_denuo_inventory,
    encode_denuo_offer, encode_denuo_request, verify_authenticated_fixed_price_listing,
    verify_authenticated_listing_cancellation, verify_fixed_price_listing,
    verify_listing_cancellation,
};
pub use outbox::{
    DenuoHandoffAcceptanceResult, DenuoHandoffFailureResult, DenuoHandoffPreparation,
    DenuoOutboxEnqueue, DenuoOutboxMessageKind, DenuoOutboxState, DenuoPreparedHandoff,
    DenuoPublicationOutbox, MAX_DENUO_OUTBOX_ENTRIES, MAX_DENUO_OUTBOX_ENVELOPE_BYTES,
    MAX_DENUO_OUTBOX_RETRY_ATTEMPTS, MAX_DENUO_OUTBOX_SERIALIZED_BYTES,
    StoredDenuoPublicationOutbox, denuo_outbox_envelope_id, load_denuo_publication_outbox,
    load_prepared_denuo_handoff, prepare_next_denuo_handoff, record_denuo_handoff_acceptance,
    record_denuo_handoff_failure, recover_denuo_handoff_as_retry, save_denuo_publication_outbox,
};
pub use plans::{
    BuyerLockPlan, BuyerLockPlanState, MAX_SHAKEDEX_TRANSACTION_PLANS, SellerLockPlan,
    SellerLockPlanState, StoredBuyerLockPlan, StoredSellerLockPlan, list_buyer_lock_plans,
    list_seller_lock_plans, load_buyer_lock_plan, load_seller_lock_plan, save_buyer_lock_plan,
    save_seller_lock_plan,
};
pub use seller_offer::{
    MAX_SELLER_LISTING_LIFETIME_SECONDS, MAX_SELLER_OFFER_WORKFLOWS,
    MIN_SELLER_LISTING_LIFETIME_SECONDS, PrepareSellerOffer, SellerOfferPreview, SellerOfferStage,
    ShakedexSellerPolicy, seller_offer_workflow_id,
};
pub use trade_runtime::{
    MAX_SHAKEDEX_OFFER_PAGE_SIZE, PrepareBuyerTrade, PrepareScriptFinalize, ShakedexOfferPage,
    ShakedexOfferPreview, ShakedexStartupRecoveryEntry, ShakedexStartupRecoveryReport,
    ShakedexTradePreview, ShakedexTradeRuntime, buyer_trade_workflow_id,
};
pub use transactions::{
    CurrentPreparedSellerRecovery, MAX_SHAKEDEX_FUNDING_INPUTS, PreparedBuyerFulfillment,
    PreparedScriptFinalize, PreparedSellerRecovery, SellerAuthorizedRecovery, SuppliedShakedexLock,
    VerifiedBuyerFulfillment, VerifiedScriptFinalize, VerifiedSellerRecovery,
    VerifiedShakedexTransfer, prepare_buyer_fulfillment, prepare_current_buyer_fulfillment,
    prepare_current_script_finalize, prepare_current_seller_recovery, prepare_script_finalize,
    prepare_seller_recovery, verify_signed_buyer_fulfillment, verify_signed_script_finalize,
    verify_signed_seller_recovery,
};
pub use value_workflow::{
    MAX_SHAKEDEX_VALUE_WORKFLOWS, ShakedexChainObservation, ShakedexReservationReleaseEvidence,
    ShakedexReservationReleaseReason, ShakedexScriptFinalizeParent, ShakedexValueAction,
    ShakedexValueRuntime, ShakedexValueStage, ShakedexValueWorkflow, StoredShakedexValueWorkflow,
    list_shakedex_value_workflows, load_shakedex_value_workflow, shakedex_value_workflow_id,
    validate_shakedex_value_workflow_reservations,
};

use hns_swap::{FixedPriceListing, MAX_FIXED_PRICE_LISTING_SIZE};
use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{ObjectHash, TransactionHash, WorkflowId, WorkflowKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_LISTING_BYTES: usize = MAX_FIXED_PRICE_LISTING_SIZE;
pub const MAX_NAME_BYTES: usize = 63;
pub const MAX_NAME_MARKET_BOARD_OFFERS: usize = 4_096;

/// Canonical Shakedex V2 protocol integration has not been release-qualified.
pub const SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED: bool = false;
/// Live Denuo V2 transport, relay publication, and product discovery have not
/// been release-qualified. Offline canonical envelope and board operations do
/// not bypass this product/runtime gate.
pub const SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED: bool = false;
/// Shakedex transaction construction and value movement have not been release-qualified.
pub const SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SellerState {
    NameSelected,
    TransferPrepared,
    TransferBroadcast,
    TransferLocked,
    FinalizePrepared,
    Locked,
    OfferSigned,
    Published,
    Cancelled,
    Fulfilled,
    RecoveryPrepared,
    RecoveryBroadcast,
    Recovered,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SellerSession {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub state: SellerState,
    pub name: Vec<u8>,
    pub name_hash: ObjectHash,
    pub transfer_txid: Option<TransactionHash>,
    pub finalize_txid: Option<TransactionHash>,
    pub locked_owner_outpoint: Option<Vec<u8>>,
    pub listing_hash: Option<ObjectHash>,
    pub listing_bytes: Option<Vec<u8>>,
    pub fulfillment_txid: Option<TransactionHash>,
    pub recovery_txid: Option<TransactionHash>,
    pub last_verified_height: u64,
    pub failure: Option<String>,
}

impl SellerSession {
    pub fn new(
        workflow_id: WorkflowId,
        name: Vec<u8>,
        name_hash: ObjectHash,
    ) -> Result<Self, ShakedexError> {
        require_release_qualified()?;
        validate_name(&name)?;
        Ok(Self {
            workflow_id,
            revision: 0,
            state: SellerState::NameSelected,
            name,
            name_hash,
            transfer_txid: None,
            finalize_txid: None,
            locked_owner_outpoint: None,
            listing_hash: None,
            listing_bytes: None,
            fulfillment_txid: None,
            recovery_txid: None,
            last_verified_height: 0,
            failure: None,
        })
    }

    pub fn apply<J: ShakedexJournal>(
        &mut self,
        evidence: SellerEvidence,
        journal: &mut J,
    ) -> Result<(), ShakedexError> {
        require_release_qualified()?;
        let mut next = self.clone();
        next.transition(evidence)?;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        journal.save_seller(&next, self.revision)?;
        *self = next;
        Ok(())
    }

    fn transition(&mut self, evidence: SellerEvidence) -> Result<(), ShakedexError> {
        self.state = match (self.state, evidence) {
            (SellerState::NameSelected, SellerEvidence::OwnershipVerified { height }) => {
                self.last_verified_height = height;
                SellerState::TransferPrepared
            }
            (
                SellerState::TransferPrepared,
                SellerEvidence::TransferPersistedAndBroadcast { txid },
            ) => {
                self.transfer_txid = Some(txid);
                SellerState::TransferBroadcast
            }
            (SellerState::TransferBroadcast, SellerEvidence::TransferLockVerified { height }) => {
                self.last_verified_height = height;
                SellerState::TransferLocked
            }
            (SellerState::TransferLocked, SellerEvidence::FinalizePrepared) => {
                SellerState::FinalizePrepared
            }
            (
                SellerState::FinalizePrepared,
                SellerEvidence::LockFinalizeVerified {
                    txid,
                    owner_outpoint,
                    height,
                },
            ) => {
                if owner_outpoint.is_empty() || owner_outpoint.len() > 128 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.finalize_txid = Some(txid);
                self.locked_owner_outpoint = Some(owner_outpoint);
                self.last_verified_height = height;
                SellerState::Locked
            }
            (
                SellerState::Locked,
                SellerEvidence::FixedPriceListingVerified {
                    listing,
                    listing_hash,
                },
            ) => {
                let _ = decode_canonical_listing(&listing, listing_hash)?;
                self.listing_bytes = Some(listing);
                self.listing_hash = Some(listing_hash);
                SellerState::OfferSigned
            }
            (SellerState::OfferSigned, SellerEvidence::DenuoPublicationPersisted) => {
                SellerState::Published
            }
            (SellerState::Published, SellerEvidence::CancellationVerified) => {
                SellerState::Cancelled
            }
            (SellerState::Published, SellerEvidence::FulfillmentVerified { txid, height }) => {
                self.fulfillment_txid = Some(txid);
                self.last_verified_height = height;
                SellerState::Fulfilled
            }
            (
                SellerState::Locked
                | SellerState::OfferSigned
                | SellerState::Published
                | SellerState::Cancelled,
                SellerEvidence::RecoveryPrepared,
            ) => SellerState::RecoveryPrepared,
            (
                SellerState::RecoveryPrepared,
                SellerEvidence::RecoveryPersistedAndBroadcast { txid },
            ) => {
                self.recovery_txid = Some(txid);
                SellerState::RecoveryBroadcast
            }
            (
                SellerState::RecoveryBroadcast,
                SellerEvidence::RecoveryOwnershipVerified { height },
            ) => {
                self.last_verified_height = height;
                SellerState::Recovered
            }
            (state, SellerEvidence::TerminalFailure(reason))
                if !matches!(state, SellerState::Fulfilled | SellerState::Recovered) =>
            {
                if reason.is_empty() || reason.len() > 256 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.failure = Some(reason);
                SellerState::Failed
            }
            _ => return Err(ShakedexError::InvalidTransition),
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SellerEvidence {
    OwnershipVerified {
        height: u64,
    },
    TransferPersistedAndBroadcast {
        txid: TransactionHash,
    },
    TransferLockVerified {
        height: u64,
    },
    FinalizePrepared,
    LockFinalizeVerified {
        txid: TransactionHash,
        owner_outpoint: Vec<u8>,
        height: u64,
    },
    FixedPriceListingVerified {
        listing: Vec<u8>,
        listing_hash: ObjectHash,
    },
    DenuoPublicationPersisted,
    CancellationVerified,
    FulfillmentVerified {
        txid: TransactionHash,
        height: u64,
    },
    RecoveryPrepared,
    RecoveryPersistedAndBroadcast {
        txid: TransactionHash,
    },
    RecoveryOwnershipVerified {
        height: u64,
    },
    TerminalFailure(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyerState {
    Discovered,
    ListingVerified,
    FulfillmentPrepared,
    FulfillmentBroadcast,
    TransferLocked,
    FinalizePrepared,
    FinalizeBroadcast,
    Finalized,
    Conflicted,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuyerSession {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub state: BuyerState,
    pub listing_hash: ObjectHash,
    pub listing_bytes: Vec<u8>,
    pub fulfillment_txid: Option<TransactionHash>,
    pub finalize_txid: Option<TransactionHash>,
    pub last_verified_height: u64,
    pub failure: Option<String>,
}

impl BuyerSession {
    pub fn discover(
        workflow_id: WorkflowId,
        listing_hash: ObjectHash,
        listing_bytes: Vec<u8>,
    ) -> Result<Self, ShakedexError> {
        require_release_qualified()?;
        let _ = decode_canonical_listing(&listing_bytes, listing_hash)?;
        Ok(Self {
            workflow_id,
            revision: 0,
            state: BuyerState::Discovered,
            listing_hash,
            listing_bytes,
            fulfillment_txid: None,
            finalize_txid: None,
            last_verified_height: 0,
            failure: None,
        })
    }

    pub fn apply<J: ShakedexJournal>(
        &mut self,
        evidence: BuyerEvidence,
        journal: &mut J,
    ) -> Result<(), ShakedexError> {
        require_release_qualified()?;
        let mut next = self.clone();
        next.transition(evidence)?;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        journal.save_buyer(&next, self.revision)?;
        *self = next;
        Ok(())
    }

    fn transition(&mut self, evidence: BuyerEvidence) -> Result<(), ShakedexError> {
        self.state = match (self.state, evidence) {
            (BuyerState::Discovered, BuyerEvidence::CurrentNameAndPresignVerified { height }) => {
                self.last_verified_height = height;
                BuyerState::ListingVerified
            }
            (BuyerState::ListingVerified, BuyerEvidence::FulfillmentPrepared) => {
                BuyerState::FulfillmentPrepared
            }
            (
                BuyerState::FulfillmentPrepared,
                BuyerEvidence::FulfillmentPersistedAndBroadcast { txid },
            ) => {
                self.fulfillment_txid = Some(txid);
                BuyerState::FulfillmentBroadcast
            }
            (
                BuyerState::FulfillmentBroadcast,
                BuyerEvidence::BuyerTransferLockVerified { height },
            ) => {
                self.last_verified_height = height;
                BuyerState::TransferLocked
            }
            (BuyerState::TransferLocked, BuyerEvidence::FinalizePrepared) => {
                BuyerState::FinalizePrepared
            }
            (
                BuyerState::FinalizePrepared,
                BuyerEvidence::FinalizePersistedAndBroadcast { txid },
            ) => {
                self.finalize_txid = Some(txid);
                BuyerState::FinalizeBroadcast
            }
            (BuyerState::FinalizeBroadcast, BuyerEvidence::FinalOwnershipVerified { height }) => {
                self.last_verified_height = height;
                BuyerState::Finalized
            }
            (
                BuyerState::Discovered
                | BuyerState::ListingVerified
                | BuyerState::FulfillmentPrepared
                | BuyerState::FulfillmentBroadcast,
                BuyerEvidence::ConflictingFulfillmentVerified,
            ) => BuyerState::Conflicted,
            (state, BuyerEvidence::TerminalFailure(reason)) if state != BuyerState::Finalized => {
                if reason.is_empty() || reason.len() > 256 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.failure = Some(reason);
                BuyerState::Failed
            }
            _ => return Err(ShakedexError::InvalidTransition),
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuyerEvidence {
    CurrentNameAndPresignVerified { height: u64 },
    FulfillmentPrepared,
    FulfillmentPersistedAndBroadcast { txid: TransactionHash },
    BuyerTransferLockVerified { height: u64 },
    FinalizePrepared,
    FinalizePersistedAndBroadcast { txid: TransactionHash },
    FinalOwnershipVerified { height: u64 },
    ConflictingFulfillmentVerified,
    TerminalFailure(String),
}

pub trait ShakedexJournal {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError>;
    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError>;
}

pub struct WalletShakedexJournal<'a> {
    pub store: &'a mut WalletStore,
    pub updated_at_unix: u64,
}

impl ShakedexJournal for WalletShakedexJournal<'_> {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        let revision = self.store.save_workflow(
            session.workflow_id,
            WorkflowKind::ShakedexSeller,
            expected_revision,
            session,
            matches!(
                session.state,
                SellerState::TransferPrepared
                    | SellerState::FinalizePrepared
                    | SellerState::RecoveryPrepared
            ),
            self.updated_at_unix,
        )?;
        if revision != session.revision {
            return Err(ShakedexError::Invariant);
        }
        Ok(())
    }

    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        let revision = self.store.save_workflow(
            session.workflow_id,
            WorkflowKind::ShakedexBuyer,
            expected_revision,
            session,
            matches!(
                session.state,
                BuyerState::FulfillmentPrepared | BuyerState::FinalizePrepared
            ),
            self.updated_at_unix,
        )?;
        if revision != session.revision {
            return Err(ShakedexError::Invariant);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryJournal {
    pub seller: Vec<SellerSession>,
    pub buyer: Vec<BuyerSession>,
}

impl ShakedexJournal for MemoryJournal {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        if session.revision != expected_revision + 1 {
            return Err(ShakedexError::StaleRevision);
        }
        self.seller.push(session.clone());
        Ok(())
    }

    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        if session.revision != expected_revision + 1 {
            return Err(ShakedexError::StaleRevision);
        }
        self.buyer.push(session.clone());
        Ok(())
    }
}

fn validate_name(name: &[u8]) -> Result<(), ShakedexError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || !name.is_ascii() {
        return Err(ShakedexError::InvalidName);
    }
    Ok(())
}

fn require_release_qualified() -> Result<(), ShakedexError> {
    if !SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED {
        return Err(ShakedexError::CanonicalProtocolUnavailable);
    }
    if !SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED {
        return Err(ShakedexError::DenuoProtocolUnavailable);
    }
    if !SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED {
        return Err(ShakedexError::ValueRuntimeUnavailable);
    }
    Ok(())
}

/// Decodes the immutable canonical V2 fixed-price listing for bounded
/// persisted-state inspection. This verifies the signed envelope and its
/// content identifier, but not its current network, time window, ownership, or
/// locking coin; those checks remain mandatory at an action boundary.
fn decode_canonical_listing(
    bytes: &[u8],
    expected_hash: ObjectHash,
) -> Result<FixedPriceListing, ShakedexError> {
    if bytes.is_empty() || bytes.len() > MAX_LISTING_BYTES {
        return Err(ShakedexError::InvalidListing);
    }
    let listing = FixedPriceListing::decode(bytes).map_err(|_| ShakedexError::InvalidListing)?;
    let actual_hash = listing
        .listing_hash()
        .map_err(|_| ShakedexError::InvalidListing)?;
    require_listing_hash(actual_hash, expected_hash)?;
    Ok(listing)
}

fn require_listing_hash(
    actual_hash: [u8; 32],
    expected_hash: ObjectHash,
) -> Result<(), ShakedexError> {
    if actual_hash != expected_hash.into_bytes() {
        return Err(ShakedexError::InvalidListing);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ShakedexError {
    #[error("canonical Shakedex V2 protocol is not release-qualified")]
    CanonicalProtocolUnavailable,
    #[error("Denuo V2 publication and discovery are not release-qualified")]
    DenuoProtocolUnavailable,
    #[error("Shakedex value runtime is not release-qualified")]
    ValueRuntimeUnavailable,
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("invalid, oversized, or mismatched Shakedex listing")]
    InvalidListing,
    #[error("invalid, oversized, or mismatched Shakedex cancellation")]
    InvalidCancellation,
    #[error("invalid or unexpected Denuo name-market envelope")]
    InvalidDenuoEnvelope,
    #[error("Denuo registry version differs from the requested version")]
    DenuoRegistryMismatch,
    #[error("Denuo name-market object was replayed or rolled back")]
    NameMarketReplay,
    #[error("Denuo name-market board reached its explicit capacity")]
    NameMarketBoardCapacity,
    #[error("persisted Denuo name-market board is corrupt or noncanonical")]
    CorruptNameMarketBoard,
    #[error("Denuo board runtime does not share the HNS account store authority")]
    StoreAuthorityMismatch,
    #[error("invalid, noncanonical, or unsupported Denuo publication outbox envelope")]
    InvalidDenuoOutboxEnvelope,
    #[error("Denuo publication outbox identity or request correlation conflicts")]
    DenuoOutboxConflict,
    #[error("Denuo publication outbox reached its explicit capacity")]
    DenuoOutboxCapacity,
    #[error("persisted Denuo publication outbox is corrupt or noncanonical")]
    CorruptDenuoOutbox,
    #[error("Denuo publication outbox handoff attempt does not match durable state")]
    DenuoOutboxHandoffMismatch,
    #[error("Denuo publication outbox transition is not monotonic")]
    InvalidDenuoOutboxTransition,
    #[error("Denuo publication outbox retry limit was reached")]
    DenuoOutboxRetryLimit,
    #[error("Denuo relay acceptance policy is invalid")]
    InvalidDenuoPublicationAcceptancePolicy,
    #[error("Denuo relay acceptance is invalid, noncanonical, or mismatched")]
    InvalidDenuoPublicationAcceptance,
    #[error("Denuo relay acceptance conflicts with the durable terminal receipt")]
    DenuoPublicationAcceptanceConflict,
    #[error("verified evidence does not permit this transition")]
    InvalidTransition,
    #[error("name or transaction evidence is invalid")]
    InvalidEvidence,
    #[error("persisted state invariant failed")]
    Invariant,
    #[error("persisted workflow encoding failed")]
    Encoding,
    #[error("an exact unexpired value approval is required")]
    ApprovalRequired,
    #[error("exact Handshake fee evidence is invalid")]
    InvalidFeeEvidence,
    #[error("persisted workflow revision is stale")]
    StaleRevision,
    #[error("terminal finality evidence no longer holds; manual recovery is required")]
    RecoveryRequired,
    #[error("wallet persistence failed")]
    Persistence,
    #[error("Handshake value-runtime evidence or authority failed")]
    HnsIntegration,
}

impl From<StoreError> for ShakedexError {
    fn from(error: StoreError) -> Self {
        if matches!(
            error,
            StoreError::StaleRevision { .. } | StoreError::StaleEntitySet
        ) {
            Self::StaleRevision
        } else {
            Self::Persistence
        }
    }
}

impl From<hns_wallet_hns::HnsWalletError> for ShakedexError {
    fn from(error: hns_wallet_hns::HnsWalletError) -> Self {
        use hns_wallet_hns::HnsWalletError;

        match error {
            HnsWalletError::ApprovalRequired => Self::ApprovalRequired,
            HnsWalletError::FeeQuoteInputUnavailable
            | HnsWalletError::InvalidFeeQuoteTransaction
            | HnsWalletError::InvalidFeeQuote
            | HnsWalletError::FeeLimit => Self::InvalidFeeEvidence,
            HnsWalletError::StaleNodeSnapshot
            | HnsWalletError::InvalidEvidence
            | HnsWalletError::InvalidPreparedArtifact
            | HnsWalletError::InvalidWorkflow => Self::InvalidEvidence,
            HnsWalletError::Store => Self::Persistence,
            HnsWalletError::RuntimeIntegrationUnavailable | HnsWalletError::MainnetDisabled => {
                Self::ValueRuntimeUnavailable
            }
            HnsWalletError::StoreAuthorityMismatch => Self::StoreAuthorityMismatch,
            _ => Self::HnsIntegration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "these compile-time release gates are asserted deliberately so a qualification flip requires an explicit test review"
    )]
    fn canonical_hns_v2_seller_entrypoints_remain_fail_closed() {
        assert!(!SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
        assert!(!SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED);
        assert!(!SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
        assert!(matches!(
            SellerSession::new(
                WorkflowId::new([1; 16]),
                b"example".to_vec(),
                ObjectHash::new([2; 32]),
            ),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));

        // Existing persisted records can deserialize directly into this public
        // schema, so apply must enforce the gate independently of creation.
        let mut session = SellerSession {
            workflow_id: WorkflowId::new([1; 16]),
            revision: 7,
            state: SellerState::Cancelled,
            name: b"example".to_vec(),
            name_hash: ObjectHash::new([2; 32]),
            transfer_txid: None,
            finalize_txid: None,
            locked_owner_outpoint: None,
            listing_hash: None,
            listing_bytes: None,
            fulfillment_txid: None,
            recovery_txid: None,
            last_verified_height: 0,
            failure: None,
        };
        let original = session.clone();
        let mut journal = MemoryJournal::default();
        assert!(matches!(
            session.apply(SellerEvidence::RecoveryPrepared, &mut journal),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));
        assert_eq!(session, original);
        assert!(journal.seller.is_empty());
    }

    #[test]
    fn canonical_hns_v2_buyer_entrypoints_remain_fail_closed() {
        assert!(matches!(
            BuyerSession::discover(WorkflowId::new([3; 16]), ObjectHash::new([4; 32]), vec![1],),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));

        // A deserialized pre-gate session must not bypass the apply boundary.
        let mut buyer = BuyerSession {
            workflow_id: WorkflowId::new([3; 16]),
            revision: 9,
            state: BuyerState::ListingVerified,
            listing_hash: ObjectHash::new([4; 32]),
            listing_bytes: vec![1],
            fulfillment_txid: None,
            finalize_txid: None,
            last_verified_height: 0,
            failure: None,
        };
        let original = buyer.clone();
        let mut journal = MemoryJournal::default();
        assert!(matches!(
            buyer.apply(BuyerEvidence::FulfillmentPrepared, &mut journal),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));
        assert_eq!(buyer, original);
        assert!(journal.buyer.is_empty());
    }

    #[test]
    fn canonical_hns_v2_listing_requires_bounded_envelope_and_identity() {
        let expected = ObjectHash::new([4; 32]);
        assert!(matches!(
            decode_canonical_listing(&[], expected),
            Err(ShakedexError::InvalidListing)
        ));
        assert!(matches!(
            decode_canonical_listing(&vec![0; MAX_LISTING_BYTES + 1], expected),
            Err(ShakedexError::InvalidListing)
        ));
        assert!(matches!(
            decode_canonical_listing(&[1], expected),
            Err(ShakedexError::InvalidListing)
        ));
        assert!(require_listing_hash([4; 32], expected).is_ok());
        assert!(matches!(
            require_listing_hash([5; 32], expected),
            Err(ShakedexError::InvalidListing)
        ));
    }
}
