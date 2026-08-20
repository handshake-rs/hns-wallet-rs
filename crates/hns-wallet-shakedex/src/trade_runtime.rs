use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsShakedexFundingPurpose, HnsShakedexKeyAllocationRequest,
    HnsWalletError, HnsWalletRuntime,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::{ApprovalId, BaseUnits, ObjectHash, WorkflowId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::seller_offer::SellerOfferRuntime;
use crate::{
    BuyerLockPlan, DenuoBoardRuntime, MAX_SHAKEDEX_FUNDING_INPUTS, PrepareSellerOffer,
    SellerLockPlan, SellerOfferPreview, ShakedexError, ShakedexScriptFinalizeParent,
    ShakedexSellerPolicy, ShakedexValueAction, ShakedexValueRuntime, ShakedexValueStage,
    ShakedexValueWorkflow, StoredShakedexValueWorkflow, VerifiedBuyerFulfillment,
    VerifiedSellerRecovery, VerifiedShakedexTransfer, prepare_current_buyer_fulfillment,
    prepare_current_script_finalize, prepare_current_seller_recovery, shakedex_value_workflow_id,
    verify_signed_buyer_fulfillment, verify_signed_seller_recovery,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareBuyerTrade {
    pub listing_hash: ObjectHash,
    pub request_nonce: u64,
    pub maximum_fee: BaseUnits,
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
    pub marketplace_fee: BaseUnits,
    pub network_fee: BaseUnits,
    pub maximum_network_fee: BaseUnits,
    pub expires_at_unix: u64,
    pub transaction: Option<hns_wallet_types::TransactionHash>,
}

impl ShakedexTradePreview {
    fn from_stored(stored: &StoredShakedexValueWorkflow) -> Result<Self, ShakedexError> {
        stored.workflow.validate()?;
        Ok(Self {
            revision: stored.revision,
            workflow_id: stored.workflow.workflow_id(),
            parent_workflow_id: stored.workflow.parent_workflow_id(),
            action: stored.workflow.action(),
            stage: stored.workflow.stage(),
            name: stored.workflow.name().to_vec(),
            listing_hash: stored.workflow.listing_hash(),
            trade_value: stored.workflow.value_base_units(),
            marketplace_fee: stored.workflow.marketplace_fee_base_units()?,
            network_fee: stored.workflow.fee_base_units(),
            maximum_network_fee: stored.workflow.maximum_fee(),
            expires_at_unix: stored.workflow.expires_at_unix(),
            transaction: stored.workflow.transaction(),
        })
    }
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
    board: DenuoBoardRuntime<'a, B, C>,
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
        let board = DenuoBoardRuntime::new_value(hns, store.clone())?;
        let seller = SellerOfferRuntime::new(hns, store.clone())?;
        let value = ShakedexValueRuntime::new(store, hns)?;
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

    pub fn load_seller_offer(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<SellerOfferPreview>, ShakedexError> {
        self.seller.load_preview(workflow_id)
    }

    pub fn load_preview(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<ShakedexTradePreview>, ShakedexError> {
        self.value
            .load(workflow_id)?
            .as_ref()
            .map(ShakedexTradePreview::from_stored)
            .transpose()
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
            validate_existing_trade(
                &existing,
                parent_workflow_id,
                ShakedexValueAction::BuyerFulfillment,
                request.maximum_fee,
                Some(request.listing_hash),
            )?;
            return ShakedexTradePreview::from_stored(&existing);
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
            config.minimum_confirmations,
            expires_at_unix,
        )?;
        let stored = self
            .value
            .save_prepared_with_change(&scope, &workflow, change.as_ref())?;
        ShakedexTradePreview::from_stored(&stored)
    }

    pub fn prepare_seller_recovery(
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
            return ShakedexTradePreview::from_stored(&existing);
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
        ShakedexTradePreview::from_stored(&stored)
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
            return ShakedexTradePreview::from_stored(&existing);
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
        ShakedexTradePreview::from_stored(&stored)
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
        ShakedexTradePreview::from_stored(&authorized)
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
        ShakedexTradePreview::from_stored(&submitted)
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
        ShakedexTradePreview::from_stored(&reconciled)
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
