use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsNetwork, HnsShakedexFundingPurpose, HnsShakedexKeyAllocationRequest,
    HnsWalletError, HnsWalletRuntime,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::{ApprovalId, BaseUnits, ObjectHash, WorkflowId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::board_runtime::CurrentShakescapeBoardOffersResolution;
use crate::seller_offer::SellerOfferRuntime;
use crate::{
    BuyerLockPlan, MAX_SHAKEDEX_FUNDING_INPUTS, PrepareSellerOffer, SellerLockPlan,
    SellerOfferPreview, ShakedexError, ShakedexScriptFinalizeParent, ShakedexSellerPolicy,
    ShakedexValueAction, ShakedexValueRuntime, ShakedexValueStage, ShakedexValueWorkflow,
    ShakescapeBoardRuntime, StoredShakedexValueWorkflow, VerifiedBuyerFulfillment,
    VerifiedSellerRecovery, VerifiedShakedexTransfer, prepare_current_buyer_fulfillment,
    prepare_current_script_finalize, prepare_current_seller_recovery, shakedex_value_workflow_id,
    verify_signed_buyer_fulfillment, verify_signed_seller_recovery,
};

pub const MAX_SHAKEDEX_OFFER_PAGE_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareBuyerTrade {
    pub listing_hash: ObjectHash,
    pub request_nonce: u64,
    pub maximum_fee: BaseUnits,
    /// A separately disclosed cap for the delayed script FINALIZE. `None`
    /// retains the legacy one-more-approval behavior.
    pub automatic_finalize_maximum_fee: Option<BaseUnits>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareScriptFinalize {
    pub parent_value_workflow_id: WorkflowId,
    pub maximum_fee: BaseUnits,
}

/// Closed provider/UI projection. It deliberately excludes transaction bytes,
/// coins, derivations, node bindings, and signing material while retaining all
/// economic terms needed for trusted user review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexTradePreview {
    pub revision: u64,
    pub workflow_id: WorkflowId,
    pub parent_workflow_id: WorkflowId,
    pub action: ShakedexValueAction,
    pub stage: ShakedexValueStage,
    pub name: Vec<u8>,
    pub listing_hash: Option<ObjectHash>,
    pub trade_value: BaseUnits,
    pub purchase_price: Option<BaseUnits>,
    pub marketplace_fee: BaseUnits,
    pub network_fee: BaseUnits,
    pub maximum_network_fee: BaseUnits,
    pub expires_at_unix: u64,
    pub recipient: String,
    pub seller_payment_address: Option<String>,
    pub transaction: Option<hns_wallet_types::TransactionHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakedexPurchaseFinalizePhase {
    TransferPending,
    FinalizeWaiting,
    FinalizeAvailable,
    FinalizePending,
}

/// A minimized, restart-safe view of a buyer fulfillment that has not yet
/// reached a confirmed script FINALIZE. The buyer session remains internal to
/// native code; hosts display the name, transaction and block progress only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakedexPurchaseFinalizeNotice {
    pub buyer_session_id: WorkflowId,
    pub name: Vec<u8>,
    pub transfer_transaction: hns_wallet_types::TransactionHash,
    pub phase: ShakedexPurchaseFinalizePhase,
    pub current_height: u64,
    pub finalize_eligible_height: Option<u64>,
    pub maximum_fee: BaseUnits,
    pub automatic_finalize_maximum_fee: Option<BaseUnits>,
}

impl ShakedexTradePreview {
    fn from_stored<B: HnsBackend, C: HnsClock>(
        hns: &HnsWalletRuntime<B, C>,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<Self, ShakedexError> {
        stored.workflow.validate()?;
        let recipient = hns.shakedex_address_display(&stored.workflow.recipient()?)?;
        let seller_payment_address = stored
            .workflow
            .seller_payment_address()?
            .as_ref()
            .map(|address| hns.shakedex_address_display(address))
            .transpose()?;
        Ok(Self {
            revision: stored.revision,
            workflow_id: stored.workflow.workflow_id(),
            parent_workflow_id: stored.workflow.parent_workflow_id(),
            action: stored.workflow.action(),
            stage: stored.workflow.stage(),
            name: stored.workflow.name().to_vec(),
            listing_hash: stored.workflow.listing_hash(),
            trade_value: stored.workflow.value_base_units(),
            purchase_price: stored.workflow.purchase_price_base_units()?,
            marketplace_fee: stored.workflow.marketplace_fee_base_units()?,
            network_fee: stored.workflow.fee_base_units(),
            maximum_network_fee: stored.workflow.maximum_fee(),
            expires_at_unix: stored.workflow.expires_at_unix(),
            recipient,
            seller_payment_address,
            transaction: stored.workflow.transaction(),
        })
    }
}

/// Current, chain-revalidated marketplace discovery projection. Raw listing
/// bytes, locking coins, outpoints, public keys, and transaction material are
/// retained inside the runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexOfferPreview {
    pub listing_hash: ObjectHash,
    pub name: Vec<u8>,
    pub price: BaseUnits,
    pub marketplace_fee: BaseUnits,
    pub seller_payment_address: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexOfferPage {
    pub board_revision: u64,
    pub offers: Vec<ShakedexOfferPreview>,
    pub next_cursor: Option<ObjectHash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexStartupRecoveryEntry {
    pub workflow_id: WorkflowId,
    pub previous_stage: ShakedexValueStage,
    pub current_stage: ShakedexValueStage,
    pub requires_manual_recovery: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexStartupRecoveryReport {
    pub workflows: Vec<ShakedexStartupRecoveryEntry>,
}

/// One same-store product controller for buyer fulfillment, seller recovery,
/// script FINALIZE, exact approval, broadcast, and startup recovery.
pub struct ShakedexTradeRuntime<'a, B, C> {
    hns: &'a HnsWalletRuntime<B, C>,
    board: ShakescapeBoardRuntime<'a, B, C>,
    seller: SellerOfferRuntime<'a, B, C>,
    value: ShakedexValueRuntime<'a, B, C>,
}

impl<'a, B: HnsBackend, C: HnsClock> ShakedexTradeRuntime<'a, B, C> {
    pub fn new(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        let board = ShakescapeBoardRuntime::new_value(hns, store.clone())?;
        let seller = SellerOfferRuntime::new(hns, store.clone())?;
        let value = ShakedexValueRuntime::new(store.clone(), hns)?;
        Ok(Self {
            hns,
            board,
            seller,
            value,
        })
    }

    pub fn prepare_seller_offer(
        &self,
        request: PrepareSellerOffer,
        policy: &ShakedexSellerPolicy,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        self.seller.prepare(request, policy)
    }

    pub fn queue_seller_listing(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        self.seller.queue_listing(workflow_id)
    }

    pub fn cancel_seller_offer(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        self.seller.queue_cancellation(workflow_id)
    }

    pub fn load_seller_offer(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<SellerOfferPreview>, ShakedexError> {
        self.seller.load_preview(workflow_id)
    }

    pub fn list_seller_offers(&self) -> Result<Vec<SellerOfferPreview>, ShakedexError> {
        self.seller.list_previews()
    }

    /// Advance a seller workflow once its exact script lock becomes current.
    /// `InvalidEvidence` is left as a non-mutating waiting state because the
    /// ordinary name TRANSFER may still be confirming; every successful
    /// transition signs and queues the exact listing atomically.
    pub fn advance_seller_offer(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        let preview = self
            .seller
            .load_preview(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        if preview.stage != crate::SellerOfferStage::NameLockRequired {
            return Ok(preview);
        }
        match self.seller.queue_listing(workflow_id) {
            Ok(advanced) => Ok(advanced),
            Err(ShakedexError::InvalidEvidence) => Ok(preview),
            Err(error) => Err(error),
        }
    }

    pub fn recover_seller_publications(&self) -> Result<Vec<SellerOfferPreview>, ShakedexError> {
        self.seller
            .list_previews()?
            .into_iter()
            .map(|preview| self.advance_seller_offer(preview.workflow_id))
            .collect()
    }

    pub fn list_current_offers(
        &self,
        cursor: Option<ObjectHash>,
        limit: usize,
    ) -> Result<ShakedexOfferPage, ShakedexError> {
        if limit == 0 || limit > MAX_SHAKEDEX_OFFER_PAGE_SIZE {
            return Err(ShakedexError::InvalidTransition);
        }
        let inventory = self.board.current_inventory()?;
        let hashes = inventory.listing_hashes();
        if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let start = cursor.map_or(0, |cursor| hashes.partition_point(|hash| *hash <= cursor));
        let selected = hashes
            .get(start..)
            .ok_or(ShakedexError::Invariant)?
            .iter()
            .take(limit)
            .copied()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(ShakedexOfferPage {
                board_revision: inventory.board_revision(),
                offers: Vec::new(),
                next_cursor: None,
            });
        }
        let current = match self.board.current_offers(&selected)? {
            CurrentShakescapeBoardOffersResolution::Absent { board_revision } => {
                if board_revision != inventory.board_revision() {
                    return Err(ShakedexError::StaleRevision);
                }
                return Ok(ShakedexOfferPage {
                    board_revision,
                    offers: Vec::new(),
                    next_cursor: None,
                });
            }
            CurrentShakescapeBoardOffersResolution::Current(current) => current,
        };
        if current.board_revision() != inventory.board_revision()
            || current.listings().len() != selected.len()
        {
            return Err(ShakedexError::StaleRevision);
        }
        let offers = current
            .listings()
            .iter()
            .map(|listing| {
                Ok(ShakedexOfferPreview {
                    listing_hash: listing.listing_hash(),
                    name: listing.name().to_vec(),
                    price: BaseUnits::new(u128::from(listing.price_base_units())),
                    marketplace_fee: BaseUnits::new(u128::from(listing.proof().fee.get())),
                    seller_payment_address: self
                        .hns
                        .shakedex_address_display(&listing.proof().payment_address)?,
                    created_at_unix: listing.created_at_unix(),
                    expires_at_unix: listing.expires_at_unix(),
                })
            })
            .collect::<Result<Vec<_>, ShakedexError>>()?;
        let next_cursor = (start + selected.len() < hashes.len())
            .then(|| selected.last().copied())
            .flatten();
        Ok(ShakedexOfferPage {
            board_revision: current.board_revision(),
            offers,
            next_cursor,
        })
    }

    pub fn load_preview(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<ShakedexTradePreview>, ShakedexError> {
        self.value
            .load(workflow_id)?
            .as_ref()
            .map(|stored| ShakedexTradePreview::from_stored(self.hns, stored))
            .transpose()
    }

    pub fn refresh_preview(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<ShakedexTradePreview>, ShakedexError> {
        let Some(stored) = self.value.load(workflow_id)? else {
            return Ok(None);
        };
        match stored.workflow.stage() {
            ShakedexValueStage::Broadcast
            | ShakedexValueStage::Mempool
            | ShakedexValueStage::Confirming
            | ShakedexValueStage::Confirmed
            | ShakedexValueStage::Conflicted => self.reconcile(workflow_id).map(Some),
            _ => ShakedexTradePreview::from_stored(self.hns, &stored).map(Some),
        }
    }

    pub fn prepare_buyer_fulfillment(
        &self,
        request: PrepareBuyerTrade,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        if request.request_nonce == 0
            || request
                .listing_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || request.maximum_fee.is_zero()
            || request
                .automatic_finalize_maximum_fee
                .is_some_and(BaseUnits::is_zero)
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let config = self.hns.configured_runtime_config()?;
        let parent_workflow_id = buyer_trade_workflow_id(
            config.wallet_id,
            config.account_id,
            request.listing_hash,
            request.request_nonce,
        );
        let workflow_id =
            shakedex_value_workflow_id(parent_workflow_id, ShakedexValueAction::BuyerFulfillment);
        if let Some(existing) = self.value.load(workflow_id)? {
            if existing.workflow.automatic_finalize_maximum_fee()
                != request.automatic_finalize_maximum_fee
            {
                return Err(ShakedexError::InvalidTransition);
            }
            validate_existing_trade(
                &existing,
                parent_workflow_id,
                ShakedexValueAction::BuyerFulfillment,
                request.maximum_fee,
                Some(request.listing_hash),
            )?;
            return ShakedexTradePreview::from_stored(self.hns, &existing);
        }

        let offer = self
            .board
            .current_offer(request.listing_hash)?
            .ok_or(ShakedexError::InvalidListing)?;
        let recipient = self.hns.shakedex_name_receive_address()?;
        let plan = BuyerLockPlan::offer_verified(
            config.wallet_id,
            config.account_id,
            parent_workflow_id,
            offer.listing(),
            offer.current_lock().locking_coin(),
        )?;
        let ordinary_value = u128::from(offer.listing().price_base_units())
            .checked_add(u128::from(offer.listing().proof().fee.get()))
            .map(BaseUnits::new)
            .ok_or(ShakedexError::Invariant)?;
        let funded = self.hns.prepare_current_shakedex_lock_funding(
            offer.current_lock(),
            workflow_id,
            HnsShakedexFundingPurpose::BuyerFulfillment,
            ordinary_value,
            request.maximum_fee,
            MAX_SHAKEDEX_FUNDING_INPUTS,
            Some(offer.listing().expires_at_unix()),
            |inputs, coins, outputs, fee| {
                let prepared = prepare_current_buyer_fulfillment(
                    offer.listing(),
                    offer.current_lock(),
                    offer.current_lock().observed_at_unix(),
                    recipient.clone(),
                    inputs,
                    coins,
                    outputs,
                    fee,
                )
                .map_err(protocol_build_error)?;
                Ok((prepared.transaction_bytes().to_vec(), prepared))
            },
        )?;
        let (prepared, scope, reservation, change, _, maximum_fee, expires_at_unix) =
            funded.into_parts();
        let workflow = ShakedexValueWorkflow::prepared_buyer_fulfillment(
            plan,
            &prepared,
            reservation,
            maximum_fee,
            request.automatic_finalize_maximum_fee,
            config.minimum_confirmations,
            expires_at_unix,
        )?;
        let stored = self
            .value
            .save_prepared_with_change(&scope, &workflow, change.as_ref())?;
        ShakedexTradePreview::from_stored(self.hns, &stored)
    }

    pub fn prepare_seller_offer_recovery(
        &self,
        seller_offer_workflow_id: WorkflowId,
        maximum_fee: BaseUnits,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        let allocation_request = self.seller.allocation_request(seller_offer_workflow_id)?;
        self.prepare_seller_recovery(&allocation_request, maximum_fee)
    }

    fn prepare_seller_recovery(
        &self,
        allocation_request: &HnsShakedexKeyAllocationRequest,
        maximum_fee: BaseUnits,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        if maximum_fee.is_zero() {
            return Err(ShakedexError::InvalidTransition);
        }
        let config = self.hns.configured_runtime_config()?;
        let parent_workflow_id = allocation_request.workflow_id;
        let workflow_id =
            shakedex_value_workflow_id(parent_workflow_id, ShakedexValueAction::SellerRecovery);
        if let Some(existing) = self.value.load(workflow_id)? {
            validate_existing_trade(
                &existing,
                parent_workflow_id,
                ShakedexValueAction::SellerRecovery,
                maximum_fee,
                None,
            )?;
            return ShakedexTradePreview::from_stored(self.hns, &existing);
        }
        let current_lock = self
            .hns
            .verify_allocated_current_shakedex_lock(allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let signer = self
            .hns
            .load_shakedex_signer(allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let recipient = self.hns.shakedex_name_receive_address()?;
        let plan = SellerLockPlan::locked(
            config.wallet_id,
            config.account_id,
            parent_workflow_id,
            current_lock.descriptor().network,
            current_lock.locking_coin(),
            *signer.compressed_public_key(),
        )?;
        let funded = self.hns.prepare_current_shakedex_lock_funding(
            &current_lock,
            workflow_id,
            HnsShakedexFundingPurpose::SellerRecovery,
            BaseUnits::ZERO,
            maximum_fee,
            MAX_SHAKEDEX_FUNDING_INPUTS,
            None,
            |inputs, coins, outputs, fee| {
                let prepared = prepare_current_seller_recovery(
                    &current_lock,
                    recipient.clone(),
                    inputs,
                    coins,
                    outputs,
                    fee,
                )
                .map_err(protocol_build_error)?;
                let authorized = prepared
                    .authorize_with_hns_signer(&current_lock, &signer)
                    .map_err(protocol_build_error)?;
                Ok((authorized.transaction_bytes().to_vec(), authorized))
            },
        )?;
        let (prepared, scope, reservation, change, _, maximum_fee, expires_at_unix) =
            funded.into_parts();
        let workflow = ShakedexValueWorkflow::prepared_seller_recovery(
            plan,
            &prepared,
            reservation,
            maximum_fee,
            config.minimum_confirmations,
            expires_at_unix,
        )?;
        let stored = self
            .value
            .save_prepared_with_change(&scope, &workflow, change.as_ref())?;
        ShakedexTradePreview::from_stored(self.hns, &stored)
    }

    pub fn prepare_script_finalize(
        &self,
        request: PrepareScriptFinalize,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        if request.maximum_fee.is_zero() {
            return Err(ShakedexError::InvalidTransition);
        }
        let parent_value = self
            .value
            .load(request.parent_value_workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        let parent_workflow_id = parent_value.workflow.parent_workflow_id();
        let workflow_id = shakedex_value_workflow_id(
            parent_workflow_id,
            ShakedexValueAction::SellerScriptFinalize,
        );
        if let Some(existing) = self.value.load(workflow_id)? {
            validate_existing_trade(
                &existing,
                parent_workflow_id,
                ShakedexValueAction::SellerScriptFinalize,
                request.maximum_fee,
                parent_value.workflow.listing_hash(),
            )?;
            return ShakedexTradePreview::from_stored(self.hns, &existing);
        }
        let parent = parent_value.workflow.script_finalize_parent()?;
        let verified_parent = OwnedVerifiedParent::from_parent(&parent)?;
        let supplied_lock = parent_value.workflow.supplied_lock()?;
        let parent_transaction = parent_value
            .workflow
            .transaction()
            .ok_or(ShakedexError::InvalidTransition)?;
        let current_transfer = self
            .hns
            .verify_current_shakedex_transfer(supplied_lock.descriptor(), parent_transaction)?;
        let recipient = parent_value.workflow.recipient()?;
        let config = self.hns.configured_runtime_config()?;
        let funded = self.hns.prepare_current_shakedex_finalize_funding(
            &current_transfer,
            workflow_id,
            request.maximum_fee,
            MAX_SHAKEDEX_FUNDING_INPUTS,
            |inputs, coins, outputs, fee| {
                let prepared = prepare_current_script_finalize(
                    &supplied_lock,
                    verified_parent.as_transfer(),
                    &current_transfer,
                    recipient.clone(),
                    inputs,
                    coins,
                    outputs,
                    fee,
                )
                .map_err(protocol_build_error)?;
                Ok((prepared.transaction_bytes().to_vec(), prepared))
            },
        )?;
        let (prepared, scope, reservation, change, _, maximum_fee, expires_at_unix) =
            funded.into_parts();
        let workflow = ShakedexValueWorkflow::prepared_seller_script_finalize(
            parent,
            &current_transfer,
            &prepared,
            reservation,
            maximum_fee,
            config.minimum_confirmations,
            expires_at_unix,
        )?;
        let stored = self
            .value
            .save_prepared_with_change(&scope, &workflow, change.as_ref())?;
        ShakedexTradePreview::from_stored(self.hns, &stored)
    }

    pub fn register_approval(
        &self,
        workflow_id: WorkflowId,
        approval_id: ApprovalId,
        origin: &str,
        expires_at_unix: u64,
    ) -> Result<(), ShakedexError> {
        let stored = self
            .value
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        self.value
            .register_approval(&stored, approval_id, origin, expires_at_unix)
    }

    pub fn authorize(
        &self,
        workflow_id: WorkflowId,
        approval_id: ApprovalId,
        origin: &str,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        let stored = self
            .value
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        let authorized = self.value.authorize_current(&stored, approval_id, origin)?;
        ShakedexTradePreview::from_stored(self.hns, &authorized)
    }

    pub fn submit(&self, workflow_id: WorkflowId) -> Result<ShakedexTradePreview, ShakedexError> {
        let scope = self.hns.shakedex_funding_scope()?;
        let stored = self
            .value
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        let submitted = match stored.workflow.stage() {
            ShakedexValueStage::Authorized => self.value.submit(&scope, &stored)?,
            ShakedexValueStage::RequiresRebroadcast => self.value.rebroadcast(&scope, &stored)?,
            _ => return Err(ShakedexError::InvalidTransition),
        };
        ShakedexTradePreview::from_stored(self.hns, &submitted)
    }

    pub fn reconcile(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<ShakedexTradePreview, ShakedexError> {
        let scope = self.hns.shakedex_funding_scope()?;
        let stored = self
            .value
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        let reconciled = self.value.reconcile(&scope, &stored)?;
        ShakedexTradePreview::from_stored(self.hns, &reconciled)
    }

    /// Resolve every durable value workflow before the installed service
    /// advertises readiness. Exact signed transactions are submitted or
    /// rebroadcast; expired unsigned plans release reservations; confirmed
    /// outcomes release reservations only after fresh terminal evidence.
    pub fn recover_startup(&self) -> Result<ShakedexStartupRecoveryReport, ShakedexError> {
        let now_unix = self.hns.shakedex_now_unix()?;
        let scope = self.hns.shakedex_funding_scope()?;
        let mut report = ShakedexStartupRecoveryReport::default();
        for stored in self.value.list()? {
            let previous_stage = stored.workflow.stage();
            let mut current = match previous_stage {
                ShakedexValueStage::Prepared if stored.workflow.expires_at_unix() <= now_unix => {
                    self.value.expire_prepared(&scope, &stored)?
                }
                ShakedexValueStage::Authorized => self.value.submit(&scope, &stored)?,
                ShakedexValueStage::RequiresRebroadcast => {
                    self.value.rebroadcast(&scope, &stored)?
                }
                ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted => self.value.reconcile(&scope, &stored)?,
                ShakedexValueStage::Prepared
                | ShakedexValueStage::ReservationsReleased
                | ShakedexValueStage::Expired
                | ShakedexValueStage::Cancelled => stored,
            };
            if current.workflow.stage() == ShakedexValueStage::RequiresRebroadcast {
                current = self.value.rebroadcast(&scope, &current)?;
            }
            if current.workflow.stage() == ShakedexValueStage::Confirmed {
                current = self.value.release_terminal_reservations(&scope, &current)?;
            }
            let current_stage = current.workflow.stage();
            report.workflows.push(ShakedexStartupRecoveryEntry {
                workflow_id: current.workflow.workflow_id(),
                previous_stage,
                current_stage,
                requires_manual_recovery: current_stage == ShakedexValueStage::Conflicted,
            });
        }
        Ok(report)
    }

    /// Return every buyer purchase which still has a live TRANSFER-to-
    /// FINALIZE obligation. This derives height from the authenticated chain
    /// observation persisted by reconciliation, never from a host clock or UI
    /// field.
    pub fn purchase_finalize_notices(
        &self,
    ) -> Result<Vec<ShakedexPurchaseFinalizeNotice>, ShakedexError> {
        let config = self.hns.configured_runtime_config()?;
        let transfer_lockup = match config.network {
            HnsNetwork::Mainnet | HnsNetwork::Testnet => 288,
            HnsNetwork::Regtest => 10,
            HnsNetwork::Simnet => 5,
        };
        let mut notices = Vec::new();
        for stored in self.value.list()? {
            let buyer = &stored.workflow;
            if buyer.action() != ShakedexValueAction::BuyerFulfillment
                || matches!(
                    buyer.stage(),
                    ShakedexValueStage::Prepared
                        | ShakedexValueStage::Authorized
                        | ShakedexValueStage::Expired
                        | ShakedexValueStage::Cancelled
                        | ShakedexValueStage::Conflicted
                )
            {
                continue;
            }
            let Some(transfer_transaction) = buyer.transaction() else {
                continue;
            };
            let finalize_id = shakedex_value_workflow_id(
                buyer.parent_workflow_id(),
                ShakedexValueAction::SellerScriptFinalize,
            );
            if let Some(finalize) = self.value.load(finalize_id)? {
                if matches!(
                    finalize.workflow.stage(),
                    ShakedexValueStage::Confirmed | ShakedexValueStage::ReservationsReleased
                ) {
                    continue;
                }
                if matches!(
                    finalize.workflow.stage(),
                    ShakedexValueStage::Broadcast
                        | ShakedexValueStage::Mempool
                        | ShakedexValueStage::Confirming
                        | ShakedexValueStage::RequiresRebroadcast
                ) {
                    let observation = finalize
                        .workflow
                        .last_chain_observation()
                        .or_else(|| buyer.last_chain_observation());
                    let current_height = observation
                        .map(|observation| observation.binding.tip.height)
                        .unwrap_or_default();
                    notices.push(ShakedexPurchaseFinalizeNotice {
                        buyer_session_id: buyer.workflow_id(),
                        name: buyer.name().to_vec(),
                        transfer_transaction,
                        phase: ShakedexPurchaseFinalizePhase::FinalizePending,
                        current_height,
                        finalize_eligible_height: buyer
                            .last_chain_observation()
                            .and_then(|observation| observation.inclusion)
                            .and_then(|inclusion| inclusion.height.checked_add(transfer_lockup)),
                        maximum_fee: buyer.maximum_fee(),
                        automatic_finalize_maximum_fee: buyer.automatic_finalize_maximum_fee(),
                    });
                    continue;
                }
            }
            let Some(observation) = buyer.last_chain_observation() else {
                continue;
            };
            let current_height = observation.binding.tip.height;
            let (phase, finalize_eligible_height) = match observation.inclusion {
                None => (ShakedexPurchaseFinalizePhase::TransferPending, None),
                Some(inclusion) => {
                    let eligible = inclusion
                        .height
                        .checked_add(transfer_lockup)
                        .ok_or(ShakedexError::Invariant)?;
                    let phase = if current_height >= eligible {
                        ShakedexPurchaseFinalizePhase::FinalizeAvailable
                    } else {
                        ShakedexPurchaseFinalizePhase::FinalizeWaiting
                    };
                    (phase, Some(eligible))
                }
            };
            notices.push(ShakedexPurchaseFinalizeNotice {
                buyer_session_id: buyer.workflow_id(),
                name: buyer.name().to_vec(),
                transfer_transaction,
                phase,
                current_height,
                finalize_eligible_height,
                maximum_fee: buyer.maximum_fee(),
                automatic_finalize_maximum_fee: buyer.automatic_finalize_maximum_fee(),
            });
        }
        notices.sort_by(|left, right| {
            left.name.cmp(&right.name).then_with(|| {
                left.buyer_session_id
                    .as_bytes()
                    .cmp(right.buyer_session_id.as_bytes())
            })
        });
        Ok(notices)
    }

    /// Consume only the fee authority explicitly committed by the original
    /// buyer approval. The name recipient is already fixed by the confirmed
    /// TRANSFER; this method cannot create or redirect another purchase.
    pub fn recover_approved_mature_purchases(
        &self,
    ) -> Result<Vec<ShakedexTradePreview>, ShakedexError> {
        let mut submitted = Vec::new();
        for notice in self.purchase_finalize_notices()? {
            if notice.phase != ShakedexPurchaseFinalizePhase::FinalizeAvailable {
                continue;
            }
            let Some(maximum_fee) = notice.automatic_finalize_maximum_fee else {
                continue;
            };
            let prepared = self.prepare_script_finalize(PrepareScriptFinalize {
                parent_value_workflow_id: notice.buyer_session_id,
                maximum_fee,
            })?;
            if prepared.stage != ShakedexValueStage::Prepared {
                continue;
            }
            let now_unix = self.hns.shakedex_now_unix()?;
            let expires_at_unix = prepared.expires_at_unix;
            if expires_at_unix <= now_unix {
                return Err(ShakedexError::InvalidTransition);
            }
            let approval_id =
                automatic_finalize_approval_id(prepared.workflow_id, prepared.revision);
            self.register_approval(
                prepared.workflow_id,
                approval_id,
                "native://automatic-shakedex-finalize",
                expires_at_unix,
            )?;
            let authorized = self.authorize(
                prepared.workflow_id,
                approval_id,
                "native://automatic-shakedex-finalize",
            )?;
            submitted.push(self.submit(authorized.workflow_id)?);
        }
        Ok(submitted)
    }
}

fn automatic_finalize_approval_id(workflow_id: WorkflowId, revision: u64) -> ApprovalId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/automatic-shakedex-finalize-approval/v1");
    hasher.update(workflow_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    let digest = hasher.finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    ApprovalId::new(id)
}

pub fn buyer_trade_workflow_id(
    wallet_id: hns_wallet_types::WalletId,
    account_id: hns_wallet_types::AccountId,
    listing_hash: ObjectHash,
    request_nonce: u64,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-buyer-trade/v1");
    hasher.update(wallet_id.as_bytes());
    hasher.update(account_id.as_bytes());
    hasher.update(listing_hash.as_bytes());
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn validate_existing_trade(
    stored: &StoredShakedexValueWorkflow,
    parent_workflow_id: WorkflowId,
    action: ShakedexValueAction,
    maximum_fee: BaseUnits,
    listing_hash: Option<ObjectHash>,
) -> Result<(), ShakedexError> {
    stored.workflow.validate()?;
    if stored.workflow.parent_workflow_id() != parent_workflow_id
        || stored.workflow.action() != action
        || stored.workflow.maximum_fee() != maximum_fee
        || stored.workflow.listing_hash() != listing_hash
    {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(())
}

fn protocol_build_error(_: ShakedexError) -> HnsWalletError {
    HnsWalletError::InvalidPreparedArtifact
}

enum OwnedVerifiedParent {
    Buyer(VerifiedBuyerFulfillment),
    Seller(VerifiedSellerRecovery),
}

impl OwnedVerifiedParent {
    fn from_parent(parent: &ShakedexScriptFinalizeParent) -> Result<Self, ShakedexError> {
        match parent {
            ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => {
                let recipient = plan
                    .fulfillment_recipient()?
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let funding = plan
                    .fulfillment_funding_input_coins()?
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let fee = plan
                    .fulfillment_fee_base_units()
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let raw = plan
                    .fulfillment_transaction_bytes()
                    .ok_or(ShakedexError::InvalidEvidence)?;
                Ok(Self::Buyer(verify_signed_buyer_fulfillment(
                    &plan.authenticated_listing()?,
                    &plan.supplied_lock()?,
                    &recipient,
                    &funding,
                    fee,
                    raw,
                )?))
            }
            ShakedexScriptFinalizeParent::SellerRecovery { plan } => {
                let recipient = plan
                    .recovery_recipient()?
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let funding = plan
                    .recovery_funding_input_coins()?
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let fee = plan
                    .recovery_fee_base_units()
                    .ok_or(ShakedexError::InvalidEvidence)?;
                let raw = plan
                    .recovery_transaction_bytes()
                    .ok_or(ShakedexError::InvalidEvidence)?;
                Ok(Self::Seller(verify_signed_seller_recovery(
                    &plan.supplied_lock()?,
                    &recipient,
                    &funding,
                    fee,
                    raw,
                )?))
            }
        }
    }

    fn as_transfer(&self) -> VerifiedShakedexTransfer<'_> {
        match self {
            Self::Buyer(verified) => VerifiedShakedexTransfer::Fulfillment(verified),
            Self::Seller(verified) => VerifiedShakedexTransfer::Recovery(verified),
        }
    }
}
