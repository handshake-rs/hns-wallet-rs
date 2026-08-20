use hns_covenants::NameState;
use hns_primitives::{BlockHash, NameHash};
use hns_transaction::{Address, Coin, Transaction};
use hns_wallet_hns::{
    DEFAULT_FEE_TARGET_BLOCKS, HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED,
    HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED, HNS_VALUE_RUNTIME_RELEASE_QUALIFIED, HnsBackend,
    HnsClock, HnsInputReservation, HnsShakedexChangeReservation,
    HnsShakedexFundingApprovalExpectation, HnsShakedexFundingPurpose,
    HnsShakedexFundingReservation, HnsShakedexFundingReservationState, HnsShakedexFundingScope,
    HnsTransactionFeeQuote, HnsWalletRuntime, MempoolSnapshotBinding, OutpointSpendEvidence,
    PREPARED_ARTIFACT_LIFETIME_SECONDS, SnapshotBinding, TransactionEvidence, TransactionInclusion,
    VerifiedCurrentShakedexLock, VerifiedCurrentShakedexTransfer,
    activate_hns_shakedex_funding_reservations, create_hns_shakedex_funding_reservations,
    delete_hns_shakedex_funding_reservations, retain_active_hns_shakedex_funding_reservations,
    validate_hns_shakedex_final_fee_quote_evidence,
    validate_hns_shakedex_finalize_final_fee_quote_evidence,
    validate_hns_shakedex_funding_reservations, validate_persisted_hns_shakedex_fee_quote_evidence,
};
use hns_wallet_store::{EntityKind, SharedWalletStore, StoredWorkflow, WalletStore};
use hns_wallet_types::{
    ApprovalId, BaseUnits, ObjectHash, TransactionHash, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plans::{AddressEvidence, CoinEvidence};
use crate::transactions::{
    verify_prepared_buyer_funding, verify_prepared_script_finalize,
    verify_prepared_seller_recovery_funding,
};
use crate::{
    BuyerLockPlan, BuyerLockPlanState, PreparedBuyerFulfillment, PreparedScriptFinalize,
    SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED, SellerAuthorizedRecovery, SellerLockPlan,
    SellerLockPlanState, ShakedexError, SuppliedShakedexLock, VerifiedShakedexTransfer,
    verify_signed_buyer_fulfillment, verify_signed_script_finalize, verify_signed_seller_recovery,
};

// Schema v1 gains `StructuralPlan::ScriptFinalize` as an additive tagged
// variant: this reader continues to decode every legacy v1 row. An older
// binary cannot decode the new variant, so downgrading a wallet after writing
// one is unsupported and remains unqualified.
const SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION: u16 = 1;
pub const MAX_SHAKEDEX_VALUE_WORKFLOWS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakedexValueAction {
    BuyerFulfillment,
    SellerRecovery,
    SellerScriptFinalize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakedexValueStage {
    Prepared,
    Authorized,
    RequiresRebroadcast,
    Broadcast,
    Mempool,
    Confirming,
    Confirmed,
    Conflicted,
    ReservationsReleased,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakedexReservationReleaseReason {
    ExactTransactionConfirmed,
    ConfirmedCompetingSpend,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum StructuralPlan {
    Buyer {
        plan: BuyerLockPlan,
    },
    Seller {
        plan: SellerLockPlan,
    },
    ScriptFinalize {
        parent: Box<ShakedexScriptFinalizeParent>,
        transfer: CurrentShakedexTransferEvidence,
    },
}

/// A script-FINALIZE can only descend from a fully signed, structurally
/// verified Shakedex TRANSFER. Keeping the exact parent action in this enum
/// prevents a buyer fulfillment and seller recovery with similar bytes from
/// being retyped after persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "parent_action")]
pub enum ShakedexScriptFinalizeParent {
    BuyerFulfillment { plan: BuyerLockPlan },
    SellerRecovery { plan: SellerLockPlan },
}

/// Historical evidence captured from the ephemeral current-TRANSFER
/// authority. It is structural identity, never restored signing authority:
/// signing and submission must reacquire `VerifiedCurrentShakedexTransfer`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentShakedexTransferEvidence {
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    transfer_transaction: Vec<u8>,
    transfer_coin: CoinEvidence,
    owner_inclusion: TransactionInclusion,
    current_name_state: Vec<u8>,
    renewal_block_height: u64,
    renewal_block_hash: [u8; 32],
}

impl ShakedexScriptFinalizeParent {
    fn validate(&self) -> Result<(), ShakedexError> {
        match self {
            Self::BuyerFulfillment { plan } => {
                plan.validate()?;
                if plan.state() != BuyerLockPlanState::FulfillmentPrepared {
                    return Err(ShakedexError::InvalidTransition);
                }
                let supplied_lock = plan.supplied_lock()?;
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
                let verified = verify_signed_buyer_fulfillment(
                    &plan.authenticated_listing()?,
                    &supplied_lock,
                    &recipient,
                    &funding,
                    fee,
                    raw,
                )?;
                if plan.fulfillment_transaction() != Some(verified.transaction()) {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
            Self::SellerRecovery { plan } => {
                plan.validate()?;
                if plan.state() != SellerLockPlanState::RecoveryPrepared {
                    return Err(ShakedexError::InvalidTransition);
                }
                let supplied_lock = plan.supplied_lock()?;
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
                let verified =
                    verify_signed_seller_recovery(&supplied_lock, &recipient, &funding, fee, raw)?;
                if plan.recovery_transaction() != Some(verified.transaction()) {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
        }
        Ok(())
    }

    const fn workflow_id(&self) -> WorkflowId {
        match self {
            Self::BuyerFulfillment { plan } => plan.workflow_id(),
            Self::SellerRecovery { plan } => plan.workflow_id(),
        }
    }

    const fn wallet_id(&self) -> hns_wallet_types::WalletId {
        match self {
            Self::BuyerFulfillment { plan } => plan.wallet_id(),
            Self::SellerRecovery { plan } => plan.wallet_id(),
        }
    }

    const fn account_id(&self) -> hns_wallet_types::AccountId {
        match self {
            Self::BuyerFulfillment { plan } => plan.account_id(),
            Self::SellerRecovery { plan } => plan.account_id(),
        }
    }

    const fn name_hash(&self) -> ObjectHash {
        match self {
            Self::BuyerFulfillment { plan } => plan.name_hash(),
            Self::SellerRecovery { plan } => plan.name_hash(),
        }
    }

    fn supplied_lock(&self) -> Result<SuppliedShakedexLock, ShakedexError> {
        match self {
            Self::BuyerFulfillment { plan } => plan.supplied_lock(),
            Self::SellerRecovery { plan } => plan.supplied_lock(),
        }
    }

    fn transaction(&self) -> Result<TransactionHash, ShakedexError> {
        match self {
            Self::BuyerFulfillment { plan } => plan
                .fulfillment_transaction()
                .ok_or(ShakedexError::InvalidEvidence),
            Self::SellerRecovery { plan } => plan
                .recovery_transaction()
                .ok_or(ShakedexError::InvalidEvidence),
        }
    }

    fn transaction_bytes(&self) -> Result<&[u8], ShakedexError> {
        match self {
            Self::BuyerFulfillment { plan } => plan
                .fulfillment_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence),
            Self::SellerRecovery { plan } => plan
                .recovery_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence),
        }
    }

    fn recipient(&self) -> Result<Address, ShakedexError> {
        match self {
            Self::BuyerFulfillment { plan } => plan
                .fulfillment_recipient()?
                .ok_or(ShakedexError::InvalidEvidence),
            Self::SellerRecovery { plan } => plan
                .recovery_recipient()?
                .ok_or(ShakedexError::InvalidEvidence),
        }
    }
}

impl CurrentShakedexTransferEvidence {
    fn from_current(
        parent: &ShakedexScriptFinalizeParent,
        current: &VerifiedCurrentShakedexTransfer,
    ) -> Result<Self, ShakedexError> {
        parent.validate()?;
        let evidence = Self {
            binding: current.binding(),
            mempool: current.mempool_binding(),
            transfer_transaction: current
                .transfer_transaction()
                .encode()
                .map_err(|_| ShakedexError::InvalidEvidence)?,
            transfer_coin: CoinEvidence::from_coin(current.transfer_coin())?,
            owner_inclusion: current.owner_inclusion(),
            current_name_state: current
                .current_name_state()
                .encode()
                .map_err(|_| ShakedexError::InvalidEvidence)?,
            renewal_block_height: current.renewal_block_height(),
            renewal_block_hash: current.renewal_block_hash(),
        };
        evidence.validate(parent)?;
        evidence.validate_current(parent, current)?;
        Ok(evidence)
    }

    fn transfer_coin(&self) -> Result<Coin, ShakedexError> {
        self.transfer_coin.to_coin()
    }

    fn current_name_state(&self, name_hash: ObjectHash) -> Result<NameState, ShakedexError> {
        let state = NameState::decode(
            NameHash::new(name_hash.into_bytes()),
            &self.current_name_state,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
        if state.encode().map_err(|_| ShakedexError::InvalidEvidence)? != self.current_name_state {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(state)
    }

    const fn renewal_block(&self) -> BlockHash {
        BlockHash::new(self.renewal_block_hash)
    }

    fn validate(&self, parent: &ShakedexScriptFinalizeParent) -> Result<(), ShakedexError> {
        parent.validate()?;
        let transaction = canonical_transaction(&self.transfer_transaction)?;
        let transaction_hash = canonical_transaction_hash(&transaction)?;
        let coin = self.transfer_coin()?;
        let state = self.current_name_state(parent.name_hash())?;
        let supplied_lock = parent.supplied_lock()?;
        let output = transaction
            .outputs
            .first()
            .ok_or(ShakedexError::InvalidEvidence)?;
        let confirmed_height = u32::try_from(self.owner_inclusion.height)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        if self.transfer_transaction.as_slice() != parent.transaction_bytes()?
            || transaction_hash != parent.transaction()?
            || coin.outpoint.transaction_hash.as_bytes() != transaction_hash.as_bytes()
            || coin.outpoint.index != 0
            || coin.height.get() != confirmed_height
            || coin.coinbase
            || coin.value != output.value
            || coin.address != output.address
            || coin.covenant != output.covenant
            || self.owner_inclusion.height > self.binding.tip.height
            || self
                .owner_inclusion
                .block_hash
                .iter()
                .all(|byte| *byte == 0)
            || self.binding.tip.block_hash.iter().all(|byte| *byte == 0)
            || self.binding.tip.tree_root.iter().all(|byte| *byte == 0)
            || self.binding.tip.median_time_past == 0
            || self.mempool.instance_nonce.iter().all(|byte| *byte == 0)
            || self.renewal_block_height == 0
            || self.renewal_block_height > self.binding.tip.height
            || self.renewal_block_hash.iter().all(|byte| *byte == 0)
            || state.owner != coin.outpoint
            || state.name.as_slice() != supplied_lock.descriptor().name.as_slice()
            || state.name_hash.as_bytes() != parent.name_hash().as_bytes()
            || state.value != coin.value
            || u64::from(state.transfer.get()) != self.owner_inclusion.height
            || transaction
                .inputs
                .first()
                .is_none_or(|input| input.previous_output != supplied_lock.locking_coin().outpoint)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    fn validate_current(
        &self,
        parent: &ShakedexScriptFinalizeParent,
        current: &VerifiedCurrentShakedexTransfer,
    ) -> Result<(), ShakedexError> {
        // Persisted snapshot tokens authenticate historical construction, not
        // liveness. The HNS runtime separately requires exact live bindings
        // around each immediate reacquisition/signing/submission fence.
        self.validate_stable_current_identity(
            parent,
            current.descriptor(),
            current.transfer_transaction(),
            current.transfer_coin(),
            current.owner_inclusion(),
            current.current_name_state(),
            current.renewal_block_height(),
            current.renewal_block_hash(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_stable_current_identity(
        &self,
        parent: &ShakedexScriptFinalizeParent,
        descriptor: &hns_swap::ShakedexLockDescriptor,
        transfer_transaction: &Transaction,
        transfer_coin: &Coin,
        owner_inclusion: TransactionInclusion,
        current_name_state: &NameState,
        renewal_block_height: u64,
        renewal_block_hash: [u8; 32],
    ) -> Result<(), ShakedexError> {
        let supplied_lock = parent.supplied_lock()?;
        if descriptor != supplied_lock.descriptor()
            || transfer_transaction
                .encode()
                .map_err(|_| ShakedexError::InvalidEvidence)?
                != self.transfer_transaction
            || transfer_coin != &self.transfer_coin()?
            || owner_inclusion != self.owner_inclusion
            || current_name_state != &self.current_name_state(parent.name_hash())?
            || renewal_block_height != self.renewal_block_height
            || renewal_block_hash != self.renewal_block_hash
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_reacquired_evidence(
        &self,
        parent: &ShakedexScriptFinalizeParent,
        reacquired: &Self,
    ) -> Result<(), ShakedexError> {
        let transaction = canonical_transaction(&reacquired.transfer_transaction)?;
        let coin = reacquired.transfer_coin()?;
        let state = reacquired.current_name_state(parent.name_hash())?;
        let supplied_lock = parent.supplied_lock()?;
        self.validate_stable_current_identity(
            parent,
            supplied_lock.descriptor(),
            &transaction,
            &coin,
            reacquired.owner_inclusion,
            &state,
            reacquired.renewal_block_height,
            reacquired.renewal_block_hash,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_prepared_script_finalize_for_parent(
    parent: &ShakedexScriptFinalizeParent,
    transfer_coin: &Coin,
    current_state: &NameState,
    renewal_block: BlockHash,
    recipient: &Address,
    funding: &[Coin],
    fee: u64,
    prepared: &[u8],
) -> Result<(), ShakedexError> {
    match parent {
        ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => {
            let supplied_lock = plan.supplied_lock()?;
            let parent_recipient = plan
                .fulfillment_recipient()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_funding = plan
                .fulfillment_funding_input_coins()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_fee = plan
                .fulfillment_fee_base_units()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_raw = plan
                .fulfillment_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let verified_parent = verify_signed_buyer_fulfillment(
                &plan.authenticated_listing()?,
                &supplied_lock,
                &parent_recipient,
                &parent_funding,
                parent_fee,
                parent_raw,
            )?;
            verify_prepared_script_finalize(
                &supplied_lock,
                VerifiedShakedexTransfer::Fulfillment(&verified_parent),
                transfer_coin,
                current_state,
                renewal_block,
                recipient,
                funding,
                fee,
                prepared,
            )
        }
        ShakedexScriptFinalizeParent::SellerRecovery { plan } => {
            let supplied_lock = plan.supplied_lock()?;
            let parent_recipient = plan
                .recovery_recipient()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_funding = plan
                .recovery_funding_input_coins()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_fee = plan
                .recovery_fee_base_units()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_raw = plan
                .recovery_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let verified_parent = verify_signed_seller_recovery(
                &supplied_lock,
                &parent_recipient,
                &parent_funding,
                parent_fee,
                parent_raw,
            )?;
            verify_prepared_script_finalize(
                &supplied_lock,
                VerifiedShakedexTransfer::Recovery(&verified_parent),
                transfer_coin,
                current_state,
                renewal_block,
                recipient,
                funding,
                fee,
                prepared,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_signed_script_finalize_for_parent(
    parent: &ShakedexScriptFinalizeParent,
    transfer_coin: &Coin,
    current_state: &NameState,
    renewal_block: BlockHash,
    recipient: &Address,
    funding: &[Coin],
    fee: u64,
    signed: &[u8],
) -> Result<TransactionHash, ShakedexError> {
    match parent {
        ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => {
            let supplied_lock = plan.supplied_lock()?;
            let parent_recipient = plan
                .fulfillment_recipient()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_funding = plan
                .fulfillment_funding_input_coins()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_fee = plan
                .fulfillment_fee_base_units()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_raw = plan
                .fulfillment_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let verified_parent = verify_signed_buyer_fulfillment(
                &plan.authenticated_listing()?,
                &supplied_lock,
                &parent_recipient,
                &parent_funding,
                parent_fee,
                parent_raw,
            )?;
            verify_signed_script_finalize(
                &supplied_lock,
                VerifiedShakedexTransfer::Fulfillment(&verified_parent),
                transfer_coin,
                current_state,
                renewal_block,
                recipient,
                funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction())
        }
        ShakedexScriptFinalizeParent::SellerRecovery { plan } => {
            let supplied_lock = plan.supplied_lock()?;
            let parent_recipient = plan
                .recovery_recipient()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_funding = plan
                .recovery_funding_input_coins()?
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_fee = plan
                .recovery_fee_base_units()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let parent_raw = plan
                .recovery_transaction_bytes()
                .ok_or(ShakedexError::InvalidEvidence)?;
            let verified_parent = verify_signed_seller_recovery(
                &supplied_lock,
                &parent_recipient,
                &parent_funding,
                parent_fee,
                parent_raw,
            )?;
            verify_signed_script_finalize(
                &supplied_lock,
                VerifiedShakedexTransfer::Recovery(&verified_parent),
                transfer_coin,
                current_state,
                renewal_block,
                recipient,
                funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedTransaction {
    approval_id: ApprovalId,
    transaction: TransactionHash,
    transaction_bytes: Vec<u8>,
    fee_quote: HnsTransactionFeeQuote,
    authorized_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexChainObservation {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub inclusion: Option<TransactionInclusion>,
    pub in_mempool: bool,
    pub confirmation_count: u32,
    pub conflicted: bool,
    pub observed_at_unix: u64,
}

/// Immutable finality evidence that permitted the aggregate to release every
/// protected source/funding reservation. A later observation that no longer
/// proves the same terminal outcome is recovery-required; it never rolls the
/// workflow back into an automatically spendable state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexReservationReleaseEvidence {
    reason: ShakedexReservationReleaseReason,
    transaction_evidence: TransactionEvidence,
    spend_evidence: OutpointSpendEvidence,
    observed_at_unix: u64,
    released_at_unix: u64,
}

impl ShakedexReservationReleaseEvidence {
    pub const fn reason(&self) -> ShakedexReservationReleaseReason {
        self.reason
    }

    pub const fn binding(&self) -> SnapshotBinding {
        self.transaction_evidence.binding
    }

    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub const fn released_at_unix(&self) -> u64 {
        self.released_at_unix
    }
}

/// One aggregate funds-safety record for a post-lock Shakedex value action.
/// The canonical structural plan, exact primary/funding coins, prepared bytes,
/// approval, final fee quote, signed bytes, submission fence, and chain
/// observation advance under one encrypted workflow CAS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexValueWorkflow {
    schema_version: u16,
    workflow_id: WorkflowId,
    action: ShakedexValueAction,
    structural_plan: StructuralPlan,
    structural_plan_commitment: ObjectHash,
    funding_reservation: HnsShakedexFundingReservation,
    source_coin: CoinEvidence,
    funding_input_coins: Vec<CoinEvidence>,
    recipient: AddressEvidence,
    value_base_units: BaseUnits,
    fee_base_units: BaseUnits,
    maximum_fee: BaseUnits,
    minimum_confirmations: u32,
    prepared_transaction: Vec<u8>,
    expires_at_unix: u64,
    stage: ShakedexValueStage,
    authorized: Option<AuthorizedTransaction>,
    submission_attempts: u32,
    submission_started_at_unix: Option<u64>,
    accepted_at_unix: Option<u64>,
    last_chain_observation: Option<ShakedexChainObservation>,
    confirmed_once: bool,
    conflicted_once: bool,
    competing_spenders: Vec<TransactionHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reservation_release: Option<ShakedexReservationReleaseEvidence>,
}

impl ShakedexValueWorkflow {
    #[allow(clippy::too_many_arguments)]
    pub fn prepared_buyer_fulfillment(
        plan: BuyerLockPlan,
        prepared: &PreparedBuyerFulfillment,
        funding_reservation: HnsShakedexFundingReservation,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if plan.state() != BuyerLockPlanState::OfferVerified
            || plan.supplied_lock()?.descriptor() != prepared.supplied_lock().descriptor()
            || plan.supplied_lock()?.locking_coin() != prepared.supplied_lock().locking_coin()
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let listing = plan.authenticated_listing()?;
        verify_prepared_buyer_funding(
            &listing,
            prepared.supplied_lock(),
            prepared.expected_recipient(),
            prepared.buyer_input_coins(),
            prepared.fee_base_units(),
            prepared.transaction_bytes(),
        )?;
        let value_base_units = BaseUnits::new(u128::from(listing.price_base_units()));
        Self::prepared(
            ShakedexValueAction::BuyerFulfillment,
            StructuralPlan::Buyer { plan },
            funding_reservation,
            prepared.supplied_lock().locking_coin(),
            prepared.buyer_input_coins(),
            prepared.expected_recipient(),
            value_base_units,
            prepared.fee_base_units(),
            maximum_fee,
            minimum_confirmations,
            prepared.transaction_bytes(),
            expires_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepared_seller_recovery(
        plan: SellerLockPlan,
        prepared: &SellerAuthorizedRecovery,
        funding_reservation: HnsShakedexFundingReservation,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if plan.state() != SellerLockPlanState::Locked
            || plan.supplied_lock()?.descriptor() != prepared.supplied_lock().descriptor()
            || plan.supplied_lock()?.locking_coin() != prepared.supplied_lock().locking_coin()
        {
            return Err(ShakedexError::InvalidTransition);
        }
        verify_prepared_seller_recovery_funding(
            prepared.supplied_lock(),
            prepared.recovery_recipient(),
            prepared.funding_input_coins(),
            prepared.fee_base_units(),
            prepared.transaction_bytes(),
        )?;
        let value_base_units = BaseUnits::new(u128::from(
            prepared.supplied_lock().locking_coin().value.get(),
        ));
        Self::prepared(
            ShakedexValueAction::SellerRecovery,
            StructuralPlan::Seller { plan },
            funding_reservation,
            prepared.supplied_lock().locking_coin(),
            prepared.funding_input_coins(),
            prepared.recovery_recipient(),
            value_base_units,
            prepared.fee_base_units(),
            maximum_fee,
            minimum_confirmations,
            prepared.transaction_bytes(),
            expires_at_unix,
        )
    }

    /// Persist a script-controlled FINALIZE only from the distinct ephemeral
    /// current-TRANSFER authority and a fully signed canonical Shakedex parent
    /// action. The historical snapshot is retained as immutable evidence, but
    /// it is never treated as authority after restart.
    #[allow(clippy::too_many_arguments)]
    pub fn prepared_seller_script_finalize(
        parent: ShakedexScriptFinalizeParent,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        prepared: &PreparedScriptFinalize,
        funding_reservation: HnsShakedexFundingReservation,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        parent.validate()?;
        let supplied_lock = parent.supplied_lock()?;
        let parent_recipient = parent.recipient()?;
        let renewal_block = BlockHash::new(current_transfer.renewal_block_hash());
        if prepared.supplied_lock().descriptor() != supplied_lock.descriptor()
            || prepared.supplied_lock().locking_coin() != supplied_lock.locking_coin()
            || prepared.parent_transaction() != parent.transaction()?
            || prepared.parent_transaction_bytes() != parent.transaction_bytes()?
            || prepared.parent_recipient() != &parent_recipient
            || prepared.transfer_coin() != current_transfer.transfer_coin()
            || prepared.current_name_state() != current_transfer.current_name_state()
            || prepared.renewal_block() != renewal_block
            || prepared.expected_recipient() != &parent_recipient
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let transfer = CurrentShakedexTransferEvidence::from_current(&parent, current_transfer)?;
        verify_prepared_script_finalize_for_parent(
            &parent,
            current_transfer.transfer_coin(),
            current_transfer.current_name_state(),
            renewal_block,
            prepared.expected_recipient(),
            prepared.funding_input_coins(),
            prepared.fee_base_units(),
            prepared.transaction_bytes(),
        )?;
        let value_base_units =
            BaseUnits::new(u128::from(current_transfer.transfer_coin().value.get()));
        Self::prepared(
            ShakedexValueAction::SellerScriptFinalize,
            StructuralPlan::ScriptFinalize {
                parent: Box::new(parent),
                transfer,
            },
            funding_reservation,
            current_transfer.transfer_coin(),
            prepared.funding_input_coins(),
            prepared.expected_recipient(),
            value_base_units,
            prepared.fee_base_units(),
            maximum_fee,
            minimum_confirmations,
            prepared.transaction_bytes(),
            expires_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepared(
        action: ShakedexValueAction,
        structural_plan: StructuralPlan,
        funding_reservation: HnsShakedexFundingReservation,
        source_coin: &Coin,
        funding_input_coins: &[Coin],
        recipient: &Address,
        value_base_units: BaseUnits,
        fee_base_units: u64,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        prepared_transaction: &[u8],
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        let parent_workflow_id = match &structural_plan {
            StructuralPlan::Buyer { plan } => plan.workflow_id(),
            StructuralPlan::Seller { plan } => plan.workflow_id(),
            StructuralPlan::ScriptFinalize { parent, .. } => parent.workflow_id(),
        };
        let workflow_id = shakedex_value_workflow_id(parent_workflow_id, action);
        let structural_plan_commitment = structural_plan_commitment(&structural_plan)?;
        let workflow = Self {
            schema_version: SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION,
            workflow_id,
            action,
            structural_plan,
            structural_plan_commitment,
            funding_reservation,
            source_coin: CoinEvidence::from_coin(source_coin)?,
            funding_input_coins: funding_input_coins
                .iter()
                .map(CoinEvidence::from_coin)
                .collect::<Result<_, _>>()?,
            recipient: AddressEvidence::from_address(recipient)?,
            value_base_units,
            fee_base_units: BaseUnits::new(u128::from(fee_base_units)),
            maximum_fee,
            minimum_confirmations,
            prepared_transaction: prepared_transaction.to_vec(),
            expires_at_unix,
            stage: ShakedexValueStage::Prepared,
            authorized: None,
            submission_attempts: 0,
            submission_started_at_unix: None,
            accepted_at_unix: None,
            last_chain_observation: None,
            confirmed_once: false,
            conflicted_once: false,
            competing_spenders: Vec::new(),
            reservation_release: None,
        };
        workflow.validate()?;
        Ok(workflow)
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub const fn parent_workflow_id(&self) -> WorkflowId {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.workflow_id(),
            StructuralPlan::Seller { plan } => plan.workflow_id(),
            StructuralPlan::ScriptFinalize { parent, .. } => parent.workflow_id(),
        }
    }

    pub const fn action(&self) -> ShakedexValueAction {
        self.action
    }

    pub const fn stage(&self) -> ShakedexValueStage {
        self.stage
    }

    pub const fn value_base_units(&self) -> BaseUnits {
        self.value_base_units
    }

    pub const fn fee_base_units(&self) -> BaseUnits {
        self.fee_base_units
    }

    pub const fn maximum_fee(&self) -> BaseUnits {
        self.maximum_fee
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }

    pub fn prepared_transaction(&self) -> &[u8] {
        &self.prepared_transaction
    }

    pub fn signed_transaction(&self) -> Option<&[u8]> {
        self.authorized
            .as_ref()
            .map(|authorized| authorized.transaction_bytes.as_slice())
    }

    pub fn transaction(&self) -> Option<TransactionHash> {
        self.authorized
            .as_ref()
            .map(|authorized| authorized.transaction)
    }

    pub fn fee_quote(&self) -> Option<&HnsTransactionFeeQuote> {
        self.authorized
            .as_ref()
            .map(|authorized| &authorized.fee_quote)
    }

    pub const fn last_chain_observation(&self) -> Option<&ShakedexChainObservation> {
        self.last_chain_observation.as_ref()
    }

    pub fn competing_spenders(&self) -> &[TransactionHash] {
        &self.competing_spenders
    }

    pub const fn reservation_release(&self) -> Option<&ShakedexReservationReleaseEvidence> {
        self.reservation_release.as_ref()
    }

    pub(crate) fn source_coin(&self) -> Result<Coin, ShakedexError> {
        self.source_coin.to_coin()
    }

    pub const fn funding_reservation(&self) -> &HnsShakedexFundingReservation {
        &self.funding_reservation
    }

    pub(crate) fn funding_input_coins(&self) -> Result<Vec<Coin>, ShakedexError> {
        self.funding_input_coins
            .iter()
            .map(CoinEvidence::to_coin)
            .collect()
    }

    fn all_input_coins(&self) -> Result<Vec<Coin>, ShakedexError> {
        let mut coins = Vec::with_capacity(self.funding_input_coins.len() + 1);
        coins.push(self.source_coin()?);
        coins.extend(self.funding_input_coins()?);
        Ok(coins)
    }

    pub fn recipient(&self) -> Result<Address, ShakedexError> {
        self.recipient.to_address()
    }

    /// Public seller payment destination committed by the authenticated
    /// listing for buyer-originated workflows. Seller recovery has no buyer
    /// payment destination and therefore returns `None`.
    pub fn seller_payment_address(&self) -> Result<Option<Address>, ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => Ok(Some(
                plan.authenticated_listing()?
                    .proof()
                    .payment_address
                    .clone(),
            )),
            StructuralPlan::ScriptFinalize { parent, .. } => match parent.as_ref() {
                ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => Ok(Some(
                    plan.authenticated_listing()?
                        .proof()
                        .payment_address
                        .clone(),
                )),
                ShakedexScriptFinalizeParent::SellerRecovery { .. } => Ok(None),
            },
            StructuralPlan::Seller { .. } => Ok(None),
        }
    }

    pub fn name(&self) -> &[u8] {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.name(),
            StructuralPlan::Seller { plan } => plan.name(),
            StructuralPlan::ScriptFinalize { parent, .. } => match parent.as_ref() {
                ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => plan.name(),
                ShakedexScriptFinalizeParent::SellerRecovery { plan } => plan.name(),
            },
        }
    }

    pub fn listing_hash(&self) -> Option<ObjectHash> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => Some(plan.listing_hash()),
            StructuralPlan::ScriptFinalize { parent, .. } => match parent.as_ref() {
                ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => {
                    Some(plan.listing_hash())
                }
                ShakedexScriptFinalizeParent::SellerRecovery { .. } => None,
            },
            StructuralPlan::Seller { .. } => None,
        }
    }

    pub fn marketplace_fee_base_units(&self) -> Result<BaseUnits, ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => Ok(BaseUnits::new(u128::from(
                plan.authenticated_listing()?.proof().fee.get(),
            ))),
            StructuralPlan::Seller { .. } | StructuralPlan::ScriptFinalize { .. } => {
                Ok(BaseUnits::ZERO)
            }
        }
    }

    pub fn purchase_price_base_units(&self) -> Result<Option<BaseUnits>, ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => Ok(Some(BaseUnits::new(u128::from(
                plan.authenticated_listing()?.price_base_units(),
            )))),
            StructuralPlan::ScriptFinalize { parent, .. } => match parent.as_ref() {
                ShakedexScriptFinalizeParent::BuyerFulfillment { plan } => Ok(Some(
                    BaseUnits::new(u128::from(plan.authenticated_listing()?.price_base_units())),
                )),
                ShakedexScriptFinalizeParent::SellerRecovery { .. } => Ok(None),
            },
            StructuralPlan::Seller { .. } => Ok(None),
        }
    }

    /// Rebuild the exact signed TRANSFER parent required by the later
    /// script-FINALIZE stage. Historical prepared bytes alone are never
    /// promoted: the aggregate's signed transaction is reverified first.
    pub fn script_finalize_parent(&self) -> Result<ShakedexScriptFinalizeParent, ShakedexError> {
        let signed = self
            .signed_transaction()
            .ok_or(ShakedexError::InvalidTransition)?;
        let recipient = self.recipient()?;
        let funding = self.funding_input_coins()?;
        let fee =
            u64::try_from(self.fee_base_units.get()).map_err(|_| ShakedexError::InvalidEvidence)?;
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => {
                let verified = verify_signed_buyer_fulfillment(
                    &plan.authenticated_listing()?,
                    &plan.supplied_lock()?,
                    &recipient,
                    &funding,
                    fee,
                    signed,
                )?;
                Ok(ShakedexScriptFinalizeParent::BuyerFulfillment {
                    plan: plan.with_fulfillment(&verified, &funding)?,
                })
            }
            StructuralPlan::Seller { plan } => {
                let verified = verify_signed_seller_recovery(
                    &plan.supplied_lock()?,
                    &recipient,
                    &funding,
                    fee,
                    signed,
                )?;
                Ok(ShakedexScriptFinalizeParent::SellerRecovery {
                    plan: plan.with_recovery(&verified, &funding)?,
                })
            }
            StructuralPlan::ScriptFinalize { .. } => Err(ShakedexError::InvalidTransition),
        }
    }

    pub(crate) fn wallet_and_account(
        &self,
    ) -> (hns_wallet_types::WalletId, hns_wallet_types::AccountId) {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => (plan.wallet_id(), plan.account_id()),
            StructuralPlan::Seller { plan } => (plan.wallet_id(), plan.account_id()),
            StructuralPlan::ScriptFinalize { parent, .. } => {
                (parent.wallet_id(), parent.account_id())
            }
        }
    }

    pub(crate) fn name_hash(&self) -> ObjectHash {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.name_hash(),
            StructuralPlan::Seller { plan } => plan.name_hash(),
            StructuralPlan::ScriptFinalize { parent, .. } => parent.name_hash(),
        }
    }

    pub(crate) fn supplied_lock(&self) -> Result<SuppliedShakedexLock, ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.supplied_lock(),
            StructuralPlan::Seller { plan } => plan.supplied_lock(),
            StructuralPlan::ScriptFinalize { parent, .. } => parent.supplied_lock(),
        }
    }

    pub(crate) fn approval_commitment(&self, revision: u64) -> Result<Vec<u8>, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared || self.authorized.is_some() {
            return Err(ShakedexError::InvalidTransition);
        }
        serde_json::to_vec(&ShakedexValueApprovalCommitment {
            domain: "hns-wallet-rs/shakedex-value-approval/v1",
            revision,
            workflow: self,
        })
        .map_err(|_| ShakedexError::Encoding)
    }

    pub(crate) fn authorize(
        &self,
        approval_id: ApprovalId,
        signed_transaction: Vec<u8>,
        fee_quote: HnsTransactionFeeQuote,
        authorized_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared
            || self.authorized.is_some()
            || authorized_at_unix >= self.expires_at_unix
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let transaction = self.verify_signed(&signed_transaction)?;
        if fee_quote.txid != transaction || fee_quote.actual_fee != self.fee_base_units {
            return Err(ShakedexError::InvalidFeeEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::Authorized;
        next.authorized = Some(AuthorizedTransaction {
            approval_id,
            transaction,
            transaction_bytes: signed_transaction,
            fee_quote,
            authorized_at_unix,
        });
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn begin_submission(
        &self,
        refreshed_quote: HnsTransactionFeeQuote,
        started_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if !matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
        ) {
            return Err(ShakedexError::InvalidTransition);
        }
        let authorized = self
            .authorized
            .as_ref()
            .ok_or(ShakedexError::InvalidTransition)?;
        if refreshed_quote.txid != authorized.transaction
            || refreshed_quote.actual_fee != self.fee_base_units
            || !snapshot_binding_not_older(refreshed_quote.binding, authorized.fee_quote.binding)
            || !mempool_binding_not_older(refreshed_quote.mempool, authorized.fee_quote.mempool)
            || started_at_unix < authorized.authorized_at_unix
            || self
                .last_chain_observation
                .as_ref()
                .is_some_and(|observation| {
                    !submission_evidence_not_older(
                        refreshed_quote.binding,
                        refreshed_quote.mempool,
                        started_at_unix,
                        observation,
                    )
                })
        {
            return Err(ShakedexError::InvalidFeeEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::RequiresRebroadcast;
        next.submission_attempts = next
            .submission_attempts
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        next.submission_started_at_unix = Some(started_at_unix);
        next.accepted_at_unix = None;
        next.last_chain_observation = None;
        next.competing_spenders.clear();
        next.authorized
            .as_mut()
            .ok_or(ShakedexError::Invariant)?
            .fee_quote = refreshed_quote;
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn record_broadcast(
        &self,
        returned_transaction: TransactionHash,
        accepted_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        let expected = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        if self.stage != ShakedexValueStage::RequiresRebroadcast
            || returned_transaction != expected
            || self.submission_started_at_unix.is_none()
            || self
                .submission_started_at_unix
                .is_some_and(|started| accepted_at_unix < started)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::Broadcast;
        next.accepted_at_unix = Some(accepted_at_unix);
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn reconcile(
        &self,
        transaction_evidence: &TransactionEvidence,
        spend_evidence: &OutpointSpendEvidence,
        observed_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if !matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
        ) {
            return Err(ShakedexError::InvalidTransition);
        }
        let transaction = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        validate_transaction_evidence(self, transaction_evidence)?;
        let competing_spenders =
            validate_spend_evidence(self, spend_evidence, transaction, transaction_evidence)?;
        let status = transaction_evidence.status;
        let next_stage = if status.conflicted || !competing_spenders.is_empty() {
            ShakedexValueStage::Conflicted
        } else if status.confirmation_count >= self.minimum_confirmations {
            ShakedexValueStage::Confirmed
        } else if status.confirmation_count > 0 {
            ShakedexValueStage::Confirming
        } else if status.in_mempool {
            ShakedexValueStage::Mempool
        } else if matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
                | ShakedexValueStage::RequiresRebroadcast
        ) {
            ShakedexValueStage::RequiresRebroadcast
        } else {
            self.stage
        };
        let mut next = self.clone();
        next.stage = next_stage;
        next.confirmed_once |= next_stage == ShakedexValueStage::Confirmed;
        next.conflicted_once |= next_stage == ShakedexValueStage::Conflicted;
        next.competing_spenders = competing_spenders;
        next.last_chain_observation = Some(ShakedexChainObservation {
            binding: transaction_evidence.binding,
            mempool: transaction_evidence.mempool,
            inclusion: transaction_evidence.inclusion,
            in_mempool: status.in_mempool,
            confirmation_count: status.confirmation_count,
            conflicted: status.conflicted,
            observed_at_unix,
        });
        next.validate()?;
        Ok(next)
    }

    fn release_reservations(
        &self,
        transaction_evidence: TransactionEvidence,
        spend_evidence: OutpointSpendEvidence,
        observed_at_unix: u64,
        released_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if !matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
        ) || self.authorized.is_none()
            || self.reservation_release.is_some()
            || released_at_unix < observed_at_unix
            || self
                .last_chain_observation
                .as_ref()
                .is_some_and(|previous| {
                    observed_at_unix < previous.observed_at_unix
                        || !snapshot_binding_not_older(
                            transaction_evidence.binding,
                            previous.binding,
                        )
                        || !mempool_binding_not_older(
                            transaction_evidence.mempool,
                            previous.mempool,
                        )
                })
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let transaction = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        validate_transaction_evidence(self, &transaction_evidence)?;
        let competing_spenders =
            validate_spend_evidence(self, &spend_evidence, transaction, &transaction_evidence)?;
        let reason = terminal_release_reason(
            transaction,
            self.minimum_confirmations,
            &transaction_evidence,
            &spend_evidence,
            &competing_spenders,
        )?;
        let mut next = self.reconcile(&transaction_evidence, &spend_evidence, observed_at_unix)?;
        if !matches!(
            (reason, next.stage),
            (
                ShakedexReservationReleaseReason::ExactTransactionConfirmed,
                ShakedexValueStage::Confirmed
            ) | (
                ShakedexReservationReleaseReason::ConfirmedCompetingSpend,
                ShakedexValueStage::Conflicted
            )
        ) {
            return Err(ShakedexError::InvalidEvidence);
        }
        next.stage = ShakedexValueStage::ReservationsReleased;
        next.reservation_release = Some(ShakedexReservationReleaseEvidence {
            reason,
            transaction_evidence,
            spend_evidence,
            observed_at_unix,
            released_at_unix,
        });
        next.validate()?;
        Ok(next)
    }

    pub fn validate_current_lock(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
    ) -> Result<(), ShakedexError> {
        if self.action == ShakedexValueAction::SellerScriptFinalize {
            return Err(ShakedexError::InvalidTransition);
        }
        let supplied = self.supplied_lock()?;
        if current_lock.descriptor() != supplied.descriptor()
            || current_lock.locking_coin() != supplied.locking_coin()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn validate_current_transfer(
        &self,
        current_transfer: &VerifiedCurrentShakedexTransfer,
    ) -> Result<(), ShakedexError> {
        let StructuralPlan::ScriptFinalize { parent, transfer } = &self.structural_plan else {
            return Err(ShakedexError::InvalidTransition);
        };
        if self.action != ShakedexValueAction::SellerScriptFinalize {
            return Err(ShakedexError::InvalidEvidence);
        }
        transfer.validate_current(parent, current_transfer)
    }

    fn script_finalize_transfer_identity(
        &self,
    ) -> Result<
        (
            &ShakedexScriptFinalizeParent,
            &CurrentShakedexTransferEvidence,
        ),
        ShakedexError,
    > {
        match &self.structural_plan {
            StructuralPlan::ScriptFinalize { parent, transfer }
                if self.action == ShakedexValueAction::SellerScriptFinalize =>
            {
                Ok((parent, transfer))
            }
            _ => Err(ShakedexError::InvalidTransition),
        }
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        if self.schema_version != SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION
            || self.workflow_id.as_bytes() == &[0; 16]
            || self.structural_plan_commitment != structural_plan_commitment(&self.structural_plan)?
            || self.value_base_units.is_zero()
            || self.fee_base_units.is_zero()
            || self.maximum_fee < self.fee_base_units
            || self.minimum_confirmations == 0
            || self.expires_at_unix == 0
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let (plan_workflow_id, plan_action, plan_source, expected_value) =
            self.validate_structural_plan()?;
        if let StructuralPlan::Buyer { plan } = &self.structural_plan
            && self.expires_at_unix > plan.authenticated_listing()?.expires_at_unix()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let (wallet_id, account_id) = self.wallet_and_account();
        let expected_purpose = match self.action {
            ShakedexValueAction::BuyerFulfillment => HnsShakedexFundingPurpose::BuyerFulfillment,
            ShakedexValueAction::SellerRecovery => HnsShakedexFundingPurpose::SellerRecovery,
            ShakedexValueAction::SellerScriptFinalize => {
                HnsShakedexFundingPurpose::SellerScriptFinalize
            }
        };
        let source_outpoint = hns_wallet_hns::HnsOutpoint {
            transaction: TransactionHash::new(plan_source.outpoint.transaction_hash.into_bytes()),
            output_index: plan_source.outpoint.index,
        };
        if shakedex_value_workflow_id(plan_workflow_id, plan_action) != self.workflow_id
            || plan_action != self.action
            || self.source_coin.to_coin()? != plan_source
            || self.value_base_units != expected_value
            || self.funding_reservation.wallet_id() != wallet_id
            || self.funding_reservation.account_id() != account_id
            || self.funding_reservation.workflow_id() != self.workflow_id
            || self.funding_reservation.purpose() != expected_purpose
            || self.funding_reservation.name_hash() != self.name_hash().into_bytes()
            || self.funding_reservation.source_outpoint() != source_outpoint
            || self.funding_reservation.expires_at_unix() != self.expires_at_unix
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let prepared = canonical_transaction(&self.prepared_transaction)?;
        let funding = self.funding_input_coins()?;
        if funding.is_empty()
            || funding.len() > crate::MAX_SHAKEDEX_FUNDING_INPUTS
            || prepared.inputs.len() != funding.len() + 1
            || self.competing_spenders.len() > prepared.inputs.len()
            || self
                .competing_spenders
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self.funding_reservation.funding_inputs().len() != funding.len()
            || self
                .funding_reservation
                .funding_inputs()
                .iter()
                .zip(&funding)
                .any(|(tracked, canonical)| {
                    !matches!(tracked.to_canonical_coin(), Ok(coin) if coin == *canonical)
                })
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.verify_prepared()?;
        match (self.stage, self.authorized.as_ref()) {
            (
                ShakedexValueStage::Prepared
                | ShakedexValueStage::Expired
                | ShakedexValueStage::Cancelled,
                None,
            ) => {
                if self.submission_attempts != 0
                    || self.submission_started_at_unix.is_some()
                    || self.accepted_at_unix.is_some()
                    || self.last_chain_observation.is_some()
                    || self.confirmed_once
                    || self.conflicted_once
                    || !self.competing_spenders.is_empty()
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
            (
                ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
                | ShakedexValueStage::ReservationsReleased,
                Some(authorized),
            ) => {
                if self.verify_signed(&authorized.transaction_bytes)? != authorized.transaction
                    || authorized.fee_quote.txid != authorized.transaction
                    || authorized.fee_quote.actual_fee != self.fee_base_units
                {
                    return Err(ShakedexError::InvalidFeeEvidence);
                }
                validate_persisted_hns_shakedex_fee_quote_evidence(
                    &plan_source,
                    &funding,
                    &authorized.transaction_bytes,
                    &authorized.fee_quote,
                    self.fee_base_units,
                    self.maximum_fee,
                )?;
            }
            _ => return Err(ShakedexError::InvalidEvidence),
        }
        if (self.stage == ShakedexValueStage::ReservationsReleased)
            != self.reservation_release.is_some()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        if self.stage == ShakedexValueStage::Authorized
            && (self.submission_attempts != 0
                || self.submission_started_at_unix.is_some()
                || self.accepted_at_unix.is_some()
                || self.last_chain_observation.is_some()
                || self.confirmed_once
                || self.conflicted_once
                || !self.competing_spenders.is_empty())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let post_authorization_stage = matches!(
            self.stage,
            ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
                | ShakedexValueStage::ReservationsReleased
        );
        if post_authorization_stage
            && ((self.submission_attempts == 0) != self.submission_started_at_unix.is_none()
                || self.submission_attempts == 0 && self.last_chain_observation.is_none())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        if self.accepted_at_unix.is_some_and(|accepted| {
            self.submission_attempts == 0
                || self
                    .submission_started_at_unix
                    .is_none_or(|started| accepted < started)
        }) {
            return Err(ShakedexError::InvalidEvidence);
        }
        if self.stage == ShakedexValueStage::Broadcast
            && (self.submission_attempts == 0 || self.accepted_at_unix.is_none())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.validate_chain_observation()?;
        self.validate_reservation_release()?;
        Ok(())
    }

    fn validate_chain_observation(&self) -> Result<(), ShakedexError> {
        let Some(observation) = self.last_chain_observation.as_ref() else {
            if matches!(
                self.stage,
                ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted
                    | ShakedexValueStage::ReservationsReleased
            ) {
                return Err(ShakedexError::InvalidEvidence);
            }
            return Ok(());
        };
        if self.authorized.as_ref().is_none_or(|authorized| {
            observation.observed_at_unix < authorized.authorized_at_unix
                || !snapshot_binding_not_older(observation.binding, authorized.fee_quote.binding)
                || !mempool_binding_not_older(observation.mempool, authorized.fee_quote.mempool)
        }) {
            return Err(ShakedexError::InvalidEvidence);
        }
        let confirmation_count_matches = match observation.inclusion {
            Some(inclusion) => {
                inclusion.height <= observation.binding.tip.height
                    && observation.confirmation_count
                        == u32::try_from(
                            observation
                                .binding
                                .tip
                                .height
                                .checked_sub(inclusion.height)
                                .and_then(|depth| depth.checked_add(1))
                                .ok_or(ShakedexError::InvalidEvidence)?,
                        )
                        .map_err(|_| ShakedexError::InvalidEvidence)?
            }
            None => observation.confirmation_count == 0,
        };
        if observation.observed_at_unix == 0
            || !confirmation_count_matches
            || observation.confirmation_count > 0 && observation.inclusion.is_none()
            || observation.confirmation_count == 0 && observation.inclusion.is_some()
            || observation.conflicted
                && (observation.in_mempool || observation.confirmation_count > 0)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let valid_for_stage = match self.stage {
            ShakedexValueStage::RequiresRebroadcast => {
                !observation.in_mempool
                    && observation.confirmation_count == 0
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Mempool => {
                observation.in_mempool
                    && observation.confirmation_count == 0
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Confirming => {
                !observation.in_mempool
                    && observation.confirmation_count > 0
                    && observation.confirmation_count < self.minimum_confirmations
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Confirmed => {
                !observation.in_mempool
                    && observation.confirmation_count >= self.minimum_confirmations
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
                    && self.confirmed_once
            }
            ShakedexValueStage::Conflicted => {
                self.conflicted_once
                    && (observation.conflicted || !self.competing_spenders.is_empty())
            }
            ShakedexValueStage::ReservationsReleased => self
                .reservation_release
                .as_ref()
                .is_some_and(|release| match release.reason {
                    ShakedexReservationReleaseReason::ExactTransactionConfirmed => {
                        !observation.in_mempool
                            && observation.confirmation_count >= self.minimum_confirmations
                            && !observation.conflicted
                            && self.competing_spenders.is_empty()
                            && self.confirmed_once
                    }
                    ShakedexReservationReleaseReason::ConfirmedCompetingSpend => {
                        self.conflicted_once
                            && (observation.conflicted || !self.competing_spenders.is_empty())
                    }
                }),
            ShakedexValueStage::Prepared
            | ShakedexValueStage::Authorized
            | ShakedexValueStage::Broadcast
            | ShakedexValueStage::Expired
            | ShakedexValueStage::Cancelled => false,
        };
        if !valid_for_stage {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    fn validate_reservation_release(&self) -> Result<(), ShakedexError> {
        let Some(release) = self.reservation_release.as_ref() else {
            return if self.stage == ShakedexValueStage::ReservationsReleased {
                Err(ShakedexError::InvalidEvidence)
            } else {
                Ok(())
            };
        };
        if self.stage != ShakedexValueStage::ReservationsReleased
            || release.observed_at_unix == 0
            || release.released_at_unix < release.observed_at_unix
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let transaction = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        validate_transaction_evidence(self, &release.transaction_evidence)?;
        let competing_spenders = validate_spend_evidence(
            self,
            &release.spend_evidence,
            transaction,
            &release.transaction_evidence,
        )?;
        let reason = terminal_release_reason(
            transaction,
            self.minimum_confirmations,
            &release.transaction_evidence,
            &release.spend_evidence,
            &competing_spenders,
        )?;
        let expected_observation = ShakedexChainObservation {
            binding: release.transaction_evidence.binding,
            mempool: release.transaction_evidence.mempool,
            inclusion: release.transaction_evidence.inclusion,
            in_mempool: release.transaction_evidence.status.in_mempool,
            confirmation_count: release.transaction_evidence.status.confirmation_count,
            conflicted: release.transaction_evidence.status.conflicted,
            observed_at_unix: release.observed_at_unix,
        };
        if release.reason != reason
            || self.competing_spenders != competing_spenders
            || self.last_chain_observation.as_ref() != Some(&expected_observation)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    fn validate_structural_plan(
        &self,
    ) -> Result<(WorkflowId, ShakedexValueAction, Coin, BaseUnits), ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => {
                plan.validate()?;
                if plan.state() != BuyerLockPlanState::OfferVerified {
                    return Err(ShakedexError::InvalidTransition);
                }
                Ok((
                    plan.workflow_id(),
                    ShakedexValueAction::BuyerFulfillment,
                    plan.locking_coin()?,
                    BaseUnits::new(u128::from(plan.authenticated_listing()?.price_base_units())),
                ))
            }
            StructuralPlan::Seller { plan } => {
                plan.validate()?;
                if plan.state() != SellerLockPlanState::Locked {
                    return Err(ShakedexError::InvalidTransition);
                }
                let source = plan.locking_coin()?;
                Ok((
                    plan.workflow_id(),
                    ShakedexValueAction::SellerRecovery,
                    source.clone(),
                    BaseUnits::new(u128::from(source.value.get())),
                ))
            }
            StructuralPlan::ScriptFinalize { parent, transfer } => {
                parent.validate()?;
                transfer.validate(parent)?;
                let source = transfer.transfer_coin()?;
                Ok((
                    parent.workflow_id(),
                    ShakedexValueAction::SellerScriptFinalize,
                    source.clone(),
                    BaseUnits::new(u128::from(source.value.get())),
                ))
            }
        }
    }

    fn verify_prepared(&self) -> Result<(), ShakedexError> {
        let recipient = self.recipient()?;
        let funding = self.funding_input_coins()?;
        let fee =
            u64::try_from(self.fee_base_units.get()).map_err(|_| ShakedexError::InvalidEvidence)?;
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => verify_prepared_buyer_funding(
                &plan.authenticated_listing()?,
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                &self.prepared_transaction,
            ),
            StructuralPlan::Seller { plan } => verify_prepared_seller_recovery_funding(
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                &self.prepared_transaction,
            ),
            StructuralPlan::ScriptFinalize { parent, transfer } => {
                let source = transfer.transfer_coin()?;
                let state = transfer.current_name_state(parent.name_hash())?;
                verify_prepared_script_finalize_for_parent(
                    parent,
                    &source,
                    &state,
                    transfer.renewal_block(),
                    &recipient,
                    &funding,
                    fee,
                    &self.prepared_transaction,
                )
            }
        }
    }

    fn verify_signed(&self, signed: &[u8]) -> Result<TransactionHash, ShakedexError> {
        require_only_funding_witness_changes(&self.prepared_transaction, signed)?;
        let recipient = self.recipient()?;
        let funding = self.funding_input_coins()?;
        let fee =
            u64::try_from(self.fee_base_units.get()).map_err(|_| ShakedexError::InvalidEvidence)?;
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => verify_signed_buyer_fulfillment(
                &plan.authenticated_listing()?,
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction()),
            StructuralPlan::Seller { plan } => verify_signed_seller_recovery(
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction()),
            StructuralPlan::ScriptFinalize { parent, transfer } => {
                let source = transfer.transfer_coin()?;
                let state = transfer.current_name_state(parent.name_hash())?;
                verify_signed_script_finalize_for_parent(
                    parent,
                    &source,
                    &state,
                    transfer.renewal_block(),
                    &recipient,
                    &funding,
                    fee,
                    signed,
                )
            }
        }
    }

    fn terminate_prepared(&self, stage: ShakedexValueStage) -> Result<Self, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared
            || self.authorized.is_some()
            || !matches!(
                stage,
                ShakedexValueStage::Expired | ShakedexValueStage::Cancelled
            )
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let mut next = self.clone();
        next.stage = stage;
        next.validate()?;
        Ok(next)
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.workflow_id == other.workflow_id
            && self.action == other.action
            && self.structural_plan == other.structural_plan
            && self.structural_plan_commitment == other.structural_plan_commitment
            && self.funding_reservation == other.funding_reservation
            && self.source_coin == other.source_coin
            && self.funding_input_coins == other.funding_input_coins
            && self.recipient == other.recipient
            && self.value_base_units == other.value_base_units
            && self.fee_base_units == other.fee_base_units
            && self.maximum_fee == other.maximum_fee
            && self.minimum_confirmations == other.minimum_confirmations
            && self.prepared_transaction == other.prepared_transaction
            && self.expires_at_unix == other.expires_at_unix
    }

    fn same_authorization_identity(&self, other: &Self) -> bool {
        match (self.authorized.as_ref(), other.authorized.as_ref()) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.approval_id == right.approval_id
                    && left.transaction == right.transaction
                    && left.transaction_bytes == right.transaction_bytes
                    && left.authorized_at_unix == right.authorized_at_unix
            }
            _ => false,
        }
    }
}

#[derive(Serialize)]
struct ShakedexValueApprovalCommitment<'a> {
    domain: &'static str,
    revision: u64,
    workflow: &'a ShakedexValueWorkflow,
}

/// Derives the distinct persisted value-workflow key for one structural plan.
/// This prevents the aggregate transaction journal from replacing its parent
/// seller/buyer plan in the store's workflow primary-key namespace.
pub fn shakedex_value_workflow_id(
    parent_workflow_id: WorkflowId,
    action: ShakedexValueAction,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-value-workflow/v1");
    hasher.update(parent_workflow_id.as_bytes());
    hasher.update([match action {
        ShakedexValueAction::BuyerFulfillment => 0,
        ShakedexValueAction::SellerRecovery => 1,
        ShakedexValueAction::SellerScriptFinalize => 2,
    }]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredShakedexValueWorkflow {
    pub revision: u64,
    pub workflow: ShakedexValueWorkflow,
}

/// Same-store production controller for every Shakedex value transition.
///
/// The full HNS runtime and this controller must retain clones of one literal
/// [`SharedWalletStore`] authority. Each local database phase is bounded by a
/// closure; node, clock, signing, fee-quote, and broadcast calls run only
/// after that closure releases the mutex. This prevents both independently
/// unlocked database connections and self-deadlock through runtime reentry.
pub struct ShakedexValueRuntime<'a, B, C> {
    store: SharedWalletStore,
    hns: &'a HnsWalletRuntime<B, C>,
}

impl<'a, B: HnsBackend, C: HnsClock> ShakedexValueRuntime<'a, B, C> {
    pub fn new(
        store: SharedWalletStore,
        hns: &'a HnsWalletRuntime<B, C>,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(Self { store, hns })
    }

    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.store.is_same_authority(store) && self.hns.shares_store_authority(store)
    }

    pub fn load(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<StoredShakedexValueWorkflow>, ShakedexError> {
        self.require_store_authority()?;
        self.store
            .try_with_store(|store| load_shakedex_value_workflow(store, workflow_id))
    }

    pub fn list(&self) -> Result<Vec<StoredShakedexValueWorkflow>, ShakedexError> {
        self.require_store_authority()?;
        self.store.try_with_store(list_shakedex_value_workflows)
    }

    pub fn save_prepared(
        &self,
        scope: &HnsShakedexFundingScope,
        workflow: &ShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        save_prepared_shakedex_value_workflow(&self.store, self.hns, scope, workflow, None)
    }

    /// Persist a product-planned workflow and reserve its internal change
    /// address in the same immediate transaction as all source/input rows.
    pub fn save_prepared_with_change(
        &self,
        scope: &HnsShakedexFundingScope,
        workflow: &ShakedexValueWorkflow,
        change: Option<&HnsShakedexChangeReservation>,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        save_prepared_shakedex_value_workflow(&self.store, self.hns, scope, workflow, change)
    }

    pub fn register_approval(
        &self,
        stored: &StoredShakedexValueWorkflow,
        approval_id: ApprovalId,
        origin: &str,
        expires_at_unix: u64,
    ) -> Result<(), ShakedexError> {
        self.require_store_authority()?;
        register_shakedex_value_approval(
            &self.store,
            self.hns,
            stored,
            approval_id,
            origin,
            expires_at_unix,
        )
    }

    pub fn authorize(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
        current_lock: &VerifiedCurrentShakedexLock,
        approval_id: ApprovalId,
        origin: &str,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        authorize_shakedex_value_workflow(
            &self.store,
            self.hns,
            scope,
            stored,
            current_lock,
            approval_id,
            origin,
        )
    }

    pub fn authorize_script_finalize(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        approval_id: ApprovalId,
        origin: &str,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        authorize_shakedex_script_finalize_workflow(
            &self.store,
            self.hns,
            scope,
            stored,
            current_transfer,
            approval_id,
            origin,
        )
    }

    /// Reacquire the exact current lock or current TRANSFER internally before
    /// authorizing. Product callers provide only the durable workflow ID and
    /// exact approval identity, never a caller-authored chain authority.
    pub fn authorize_current(
        &self,
        stored: &StoredShakedexValueWorkflow,
        approval_id: ApprovalId,
        origin: &str,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        let scope = self.hns.shakedex_funding_scope()?;
        match stored.workflow.action {
            ShakedexValueAction::SellerScriptFinalize => {
                let current =
                    reacquire_current_script_finalize_transfer(self.hns, &stored.workflow)?;
                authorize_shakedex_script_finalize_workflow(
                    &self.store,
                    self.hns,
                    &scope,
                    stored,
                    &current,
                    approval_id,
                    origin,
                )
            }
            ShakedexValueAction::BuyerFulfillment | ShakedexValueAction::SellerRecovery => {
                let supplied = stored.workflow.supplied_lock()?;
                let current = self.hns.verify_current_shakedex_lock(
                    &supplied.descriptor().name,
                    supplied.descriptor().seller_public_key,
                )?;
                authorize_shakedex_value_workflow(
                    &self.store,
                    self.hns,
                    &scope,
                    stored,
                    &current,
                    approval_id,
                    origin,
                )
            }
        }
    }

    pub fn cancel_prepared(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        cancel_prepared_shakedex_value_workflow(&self.store, self.hns, scope, stored)
    }

    pub fn expire_prepared(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        expire_prepared_shakedex_value_workflow(&self.store, self.hns, scope, stored)
    }

    pub fn submit(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        submit_shakedex_value_workflow(&self.store, self.hns, scope, stored)
    }

    pub fn rebroadcast(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        rebroadcast_shakedex_value_workflow(&self.store, self.hns, scope, stored)
    }

    pub fn release_terminal_reservations(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        release_terminal_shakedex_value_workflow_reservations(&self.store, self.hns, scope, stored)
    }

    pub fn reconcile(
        &self,
        scope: &HnsShakedexFundingScope,
        stored: &StoredShakedexValueWorkflow,
    ) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
        self.require_store_authority()?;
        reconcile_shakedex_value_workflow(&self.store, self.hns, scope, stored)
    }

    fn require_store_authority(&self) -> Result<(), ShakedexError> {
        if !self.hns.shares_store_authority(&self.store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(())
    }
}

fn save_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    workflow: &ShakedexValueWorkflow,
    change: Option<&HnsShakedexChangeReservation>,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let updated_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    workflow.validate()?;
    if workflow.stage != ShakedexValueStage::Prepared
        || workflow.authorized.is_some()
        || updated_at_unix >= workflow.expires_at_unix
        || workflow.expires_at_unix
            > updated_at_unix.saturating_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let (wallet_id, account_id) = workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    match workflow.action {
        ShakedexValueAction::SellerScriptFinalize => {
            let current_transfer = reacquire_current_script_finalize_transfer(runtime, workflow)?;
            if runtime.validate_current_shakedex_finalize_funding_reservation(
                &current_transfer,
                workflow.funding_reservation(),
            )? != *scope
            {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
        ShakedexValueAction::BuyerFulfillment | ShakedexValueAction::SellerRecovery => {
            let supplied_lock = workflow.supplied_lock()?;
            let current_lock = runtime.verify_current_shakedex_lock(
                &supplied_lock.descriptor().name,
                supplied_lock.descriptor().seller_public_key,
            )?;
            workflow.validate_current_lock(&current_lock)?;
            if runtime.validate_current_shakedex_funding_reservation(
                &current_lock,
                workflow.funding_reservation(),
            )? != *scope
            {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
    }
    let (stored, committed_account_revision) = store.try_with_store_mut(|store| {
        if let Some(current) = load_shakedex_value_workflow(store, workflow.workflow_id)? {
            if current.workflow != *workflow {
                return Err(ShakedexError::InvalidTransition);
            }
            validate_hns_shakedex_funding_reservations(
                store,
                scope,
                workflow.funding_reservation(),
                HnsShakedexFundingReservationState::Prepared,
            )?;
            return Ok((current, None));
        }
        let batch = create_hns_shakedex_funding_reservations(
            store,
            scope,
            workflow.funding_reservation(),
            updated_at_unix,
        )?;
        if !batch.deletes().is_empty() || batch.saves().is_empty() {
            return Err(ShakedexError::Invariant);
        }
        let (revision, committed_account_revision) = match change {
            Some(change) => {
                let (revision, account_revision) = store
                    .save_workflow_with_account_and_entity_batch(
                        workflow.workflow_id,
                        WorkflowKind::ShakedexValue,
                        0,
                        workflow,
                        false,
                        updated_at_unix,
                        change.account_save(),
                        EntityKind::InputReservation,
                        batch.saves(),
                        batch.deletes(),
                    )?;
                (revision, Some(account_revision))
            }
            None => {
                let revision = store.save_workflow_with_entity_batch(
                    workflow.workflow_id,
                    WorkflowKind::ShakedexValue,
                    0,
                    workflow,
                    false,
                    updated_at_unix,
                    EntityKind::InputReservation,
                    batch.saves(),
                    batch.deletes(),
                )?;
                (revision, None)
            }
        };
        Ok((
            StoredShakedexValueWorkflow {
                revision,
                workflow: workflow.clone(),
            },
            committed_account_revision,
        ))
    })?;
    if let (Some(change), Some(account_revision)) = (change, committed_account_revision) {
        runtime.install_committed_shakedex_change(change, account_revision)?;
    }
    Ok(stored)
}

fn register_shakedex_value_approval<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    stored: &StoredShakedexValueWorkflow,
    approval_id: ApprovalId,
    origin: &str,
    expires_at_unix: u64,
) -> Result<(), ShakedexError> {
    let now_unix = runtime.shakedex_now_unix()?;
    stored.workflow.validate()?;
    let runtime_scope = runtime.shakedex_funding_scope()?;
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if runtime_scope.wallet_id() != wallet_id || runtime_scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    if stored.workflow.stage != ShakedexValueStage::Prepared
        || now_unix >= expires_at_unix
        || expires_at_unix > stored.workflow.expires_at_unix
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let commitment = stored.workflow.approval_commitment(stored.revision)?;
    store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        store
            .put_pending_approval(approval_id, origin, &commitment, now_unix, expires_at_unix)
            .map_err(ShakedexError::from)
    })
}

#[allow(clippy::too_many_arguments)]
fn authorize_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
    current_lock: &VerifiedCurrentShakedexLock,
    approval_id: ApprovalId,
    origin: &str,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    if stored.workflow.action == ShakedexValueAction::SellerScriptFinalize {
        return Err(ShakedexError::InvalidTransition);
    }
    require_value_runtime_release_qualified()?;
    let authorized_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    stored.workflow.validate()?;
    stored.workflow.validate_current_lock(current_lock)?;
    if stored.workflow.stage != ShakedexValueStage::Prepared
        || authorized_at_unix >= stored.workflow.expires_at_unix
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    let expectation = store.try_with_store(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            stored.workflow.funding_reservation(),
            HnsShakedexFundingReservationState::Prepared,
        )?;
        let approval = store
            .get_pending_approval(approval_id, authorized_at_unix)?
            .ok_or(ShakedexError::ApprovalRequired)?;
        let commitment = stored.workflow.approval_commitment(stored.revision)?;
        if approval.origin != origin || approval.request_json.as_slice() != commitment {
            return Err(ShakedexError::ApprovalRequired);
        }
        HnsShakedexFundingApprovalExpectation::new(
            approval_id,
            origin.to_owned(),
            commitment,
            approval.expires_at_unix,
        )
        .map_err(ShakedexError::from)
    })?;
    let authorization = runtime.authorize_shakedex_funding_suffix(
        current_lock,
        stored.workflow.funding_reservation(),
        &stored.workflow.prepared_transaction,
        &expectation,
    )?;
    let (signed_transaction, pending_approval) = authorization.into_parts();
    if pending_approval.id != expectation.approval_id()
        || pending_approval.origin != expectation.origin()
        || pending_approval.request_json.as_slice() != expectation.request_bytes()
        || pending_approval.expires_at_unix != expectation.expires_at_unix()
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let input_coins = stored.workflow.all_input_coins()?;
    let quote = runtime.backend().quote_transaction_fee(
        &signed_transaction,
        &input_coins,
        DEFAULT_FEE_TARGET_BLOCKS,
        current_lock.binding(),
        current_lock.mempool_binding(),
    )?;
    validate_hns_shakedex_final_fee_quote_evidence(
        current_lock,
        stored.workflow.funding_reservation(),
        &signed_transaction,
        &quote,
        stored.workflow.fee_base_units,
        stored.workflow.maximum_fee,
    )?;
    let commit_now = runtime.shakedex_now_unix()?;
    if commit_now < authorized_at_unix
        || commit_now >= stored.workflow.expires_at_unix
        || commit_now >= pending_approval.expires_at_unix
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let next = stored
        .workflow
        .authorize(approval_id, signed_transaction, quote, commit_now)?;
    store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        let batch = activate_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            commit_now,
        )?;
        let revision = store
            .consume_approval_and_save_workflow_with_entity_batch(
                &pending_approval,
                commit_now,
                next.workflow_id,
                WorkflowKind::ShakedexValue,
                stored.revision,
                &next,
                true,
                EntityKind::InputReservation,
                batch.saves(),
                batch.deletes(),
            )?
            .ok_or(ShakedexError::ApprovalRequired)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )?;
        Ok(StoredShakedexValueWorkflow {
            revision,
            workflow: next,
        })
    })
}

/// Authorize the exact script-FINALIZE funding suffix through current
/// TRANSFER authority. This intentionally does not accept the lock authority
/// used by buyer fulfillment and seller recovery.
#[allow(clippy::too_many_arguments)]
fn authorize_shakedex_script_finalize_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
    current_transfer: &VerifiedCurrentShakedexTransfer,
    approval_id: ApprovalId,
    origin: &str,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    if stored.workflow.action != ShakedexValueAction::SellerScriptFinalize {
        return Err(ShakedexError::InvalidTransition);
    }
    require_value_runtime_release_qualified()?;
    let authorized_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    stored.workflow.validate()?;
    stored
        .workflow
        .validate_current_transfer(current_transfer)?;
    if stored.workflow.stage != ShakedexValueStage::Prepared
        || authorized_at_unix >= stored.workflow.expires_at_unix
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    let expectation = store.try_with_store(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            stored.workflow.funding_reservation(),
            HnsShakedexFundingReservationState::Prepared,
        )?;
        let approval = store
            .get_pending_approval(approval_id, authorized_at_unix)?
            .ok_or(ShakedexError::ApprovalRequired)?;
        let commitment = stored.workflow.approval_commitment(stored.revision)?;
        if approval.origin != origin || approval.request_json.as_slice() != commitment {
            return Err(ShakedexError::ApprovalRequired);
        }
        HnsShakedexFundingApprovalExpectation::new(
            approval_id,
            origin.to_owned(),
            commitment,
            approval.expires_at_unix,
        )
        .map_err(ShakedexError::from)
    })?;
    // The runtime reacquires and byte-compares this exact transfer immediately
    // before invoking any ordinary-wallet signing key.
    let authorization = runtime.authorize_shakedex_finalize_funding_suffix(
        current_transfer,
        stored.workflow.funding_reservation(),
        &stored.workflow.prepared_transaction,
        &expectation,
    )?;
    let (signed_transaction, pending_approval) = authorization.into_parts();
    if pending_approval.id != expectation.approval_id()
        || pending_approval.origin != expectation.origin()
        || pending_approval.request_json.as_slice() != expectation.request_bytes()
        || pending_approval.expires_at_unix != expectation.expires_at_unix()
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let input_coins = stored.workflow.all_input_coins()?;
    let quote = runtime.backend().quote_transaction_fee(
        &signed_transaction,
        &input_coins,
        DEFAULT_FEE_TARGET_BLOCKS,
        current_transfer.binding(),
        current_transfer.mempool_binding(),
    )?;
    validate_hns_shakedex_finalize_final_fee_quote_evidence(
        current_transfer,
        stored.workflow.funding_reservation(),
        &signed_transaction,
        &quote,
        stored.workflow.fee_base_units,
        stored.workflow.maximum_fee,
    )?;
    let commit_now = runtime.shakedex_now_unix()?;
    if commit_now < authorized_at_unix
        || commit_now >= stored.workflow.expires_at_unix
        || commit_now >= pending_approval.expires_at_unix
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let next = stored
        .workflow
        .authorize(approval_id, signed_transaction, quote, commit_now)?;
    store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        let batch = activate_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            commit_now,
        )?;
        let revision = store
            .consume_approval_and_save_workflow_with_entity_batch(
                &pending_approval,
                commit_now,
                next.workflow_id,
                WorkflowKind::ShakedexValue,
                stored.revision,
                &next,
                true,
                EntityKind::InputReservation,
                batch.saves(),
                batch.deletes(),
            )?
            .ok_or(ShakedexError::ApprovalRequired)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )?;
        Ok(StoredShakedexValueWorkflow {
            revision,
            workflow: next,
        })
    })
}

fn cancel_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let cancelled_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    store.try_with_store_mut(|store| {
        terminate_prepared_value_workflow(
            store,
            scope,
            stored,
            ShakedexValueStage::Cancelled,
            cancelled_at_unix,
        )
    })
}

fn expire_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let now_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    if now_unix < stored.workflow.expires_at_unix {
        return Err(ShakedexError::InvalidTransition);
    }
    store.try_with_store_mut(|store| {
        terminate_prepared_value_workflow(
            store,
            scope,
            stored,
            ShakedexValueStage::Expired,
            now_unix,
        )
    })
}

fn submit_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_value_runtime_release_qualified()?;
    if stored.workflow.stage != ShakedexValueStage::Authorized {
        return Err(ShakedexError::InvalidTransition);
    }
    submit_value_workflow(store, runtime, scope, stored)
}

fn rebroadcast_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_value_runtime_release_qualified()?;
    if stored.workflow.stage != ShakedexValueStage::RequiresRebroadcast {
        return Err(ShakedexError::InvalidTransition);
    }
    submit_value_workflow(store, runtime, scope, stored)
}

fn terminate_prepared_value_workflow(
    store: &mut WalletStore,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
    stage: ShakedexValueStage,
    updated_at_unix: u64,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_exact_stored_value_workflow(store, stored)?;
    let next = stored.workflow.terminate_prepared(stage)?;
    let batch = delete_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        HnsShakedexFundingReservationState::Prepared,
    )?;
    if !batch.saves().is_empty() || batch.deletes().is_empty() {
        return Err(ShakedexError::Invariant);
    }
    let revision = store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
        next.workflow_id,
        WorkflowKind::ShakedexValue,
        stored.revision,
        &next,
        false,
        updated_at_unix,
        EntityKind::InputReservation,
        batch.saves(),
        batch.deletes(),
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: next,
    })
}

fn submit_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    stored.workflow.validate()?;
    validate_runtime_scope(runtime, scope)?;
    store.try_with_store(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        validate_shakedex_value_workflow_reservations(store, scope, stored)
    })?;
    let signed = stored
        .workflow
        .signed_transaction()
        .ok_or(ShakedexError::InvalidTransition)?;
    let input_coins = stored.workflow.all_input_coins()?;
    let refreshed_quote = match stored.workflow.action {
        ShakedexValueAction::SellerScriptFinalize => {
            let current_transfer =
                reacquire_current_script_finalize_transfer(runtime, &stored.workflow)?;
            let quote = runtime.backend().quote_transaction_fee(
                signed,
                &input_coins,
                DEFAULT_FEE_TARGET_BLOCKS,
                current_transfer.binding(),
                current_transfer.mempool_binding(),
            )?;
            validate_hns_shakedex_finalize_final_fee_quote_evidence(
                &current_transfer,
                stored.workflow.funding_reservation(),
                signed,
                &quote,
                stored.workflow.fee_base_units,
                stored.workflow.maximum_fee,
            )?;
            // A second acquisition immediately before the durable broadcast
            // fence prevents a reorged/replaced TRANSFER from inheriting the
            // historical approval or fee quote.
            let fence_transfer =
                reacquire_current_script_finalize_transfer(runtime, &stored.workflow)?;
            if fence_transfer.binding() != quote.binding
                || fence_transfer.mempool_binding() != quote.mempool
            {
                return Err(ShakedexError::InvalidEvidence);
            }
            quote
        }
        ShakedexValueAction::BuyerFulfillment | ShakedexValueAction::SellerRecovery => {
            let supplied_lock = stored.workflow.supplied_lock()?;
            let current_lock = runtime.verify_current_shakedex_lock(
                &supplied_lock.descriptor().name,
                supplied_lock.descriptor().seller_public_key,
            )?;
            stored.workflow.validate_current_lock(&current_lock)?;
            let quote = runtime.backend().quote_transaction_fee(
                signed,
                &input_coins,
                DEFAULT_FEE_TARGET_BLOCKS,
                current_lock.binding(),
                current_lock.mempool_binding(),
            )?;
            validate_hns_shakedex_final_fee_quote_evidence(
                &current_lock,
                stored.workflow.funding_reservation(),
                signed,
                &quote,
                stored.workflow.fee_base_units,
                stored.workflow.maximum_fee,
            )?;
            let fence_lock = runtime.verify_current_shakedex_lock(
                &supplied_lock.descriptor().name,
                supplied_lock.descriptor().seller_public_key,
            )?;
            stored.workflow.validate_current_lock(&fence_lock)?;
            if fence_lock.binding() != quote.binding
                || fence_lock.mempool_binding() != quote.mempool
            {
                return Err(ShakedexError::InvalidEvidence);
            }
            quote
        }
    };
    let submission_started_at_unix = runtime.shakedex_now_unix()?;
    let fenced = stored
        .workflow
        .begin_submission(refreshed_quote, submission_started_at_unix)?;
    let fenced_revision = store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        let reservation_batch = retain_active_hns_shakedex_funding_reservations(
            store,
            scope,
            fenced.funding_reservation(),
            submission_started_at_unix,
        )?;
        if reservation_batch.saves().is_empty() || !reservation_batch.deletes().is_empty() {
            return Err(ShakedexError::Invariant);
        }
        fenced.validate()?;
        if validate_save_transition(store, stored.revision, &fenced)?.is_some() {
            return Err(ShakedexError::InvalidTransition);
        }
        store
            .save_workflow_with_entity_batch(
                fenced.workflow_id,
                WorkflowKind::ShakedexValue,
                stored.revision,
                &fenced,
                true,
                submission_started_at_unix,
                EntityKind::InputReservation,
                reservation_batch.saves(),
                reservation_batch.deletes(),
            )
            .map_err(ShakedexError::from)
    })?;
    let returned_transaction = runtime.backend().broadcast_transaction(
        fenced
            .signed_transaction()
            .ok_or(ShakedexError::Invariant)?,
    )?;
    let accepted_at_unix = runtime.shakedex_now_unix()?;
    let submitted = fenced.record_broadcast(returned_transaction, accepted_at_unix)?;
    store.try_with_store_mut(|store| {
        let revision = save_value_workflow(store, fenced_revision, &submitted, accepted_at_unix)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            submitted.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )?;
        Ok(StoredShakedexValueWorkflow {
            revision,
            workflow: submitted,
        })
    })
}

fn require_value_runtime_release_qualified() -> Result<(), ShakedexError> {
    if !SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED
        || !HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
    {
        return Err(ShakedexError::ValueRuntimeUnavailable);
    }
    Ok(())
}

/// Release every protected source/funding row only after one fresh runtime
/// snapshot proves the signed transaction, or an authenticated competing
/// spender, has reached the workflow's already-approved finality threshold.
/// This recovery operation is intentionally available while value entrypoints
/// remain gated: it cannot sign or broadcast new bytes.
fn release_terminal_shakedex_value_workflow_reservations<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    validate_runtime_scope(runtime, scope)?;
    stored.workflow.validate()?;
    if stored.workflow.stage == ShakedexValueStage::ReservationsReleased {
        store.try_with_store(|store| {
            require_exact_stored_value_workflow(store, stored)?;
            validate_shakedex_value_workflow_reservations(store, scope, stored)
        })?;
        return Ok(stored.clone());
    }
    if !matches!(
        stored.workflow.stage,
        ShakedexValueStage::Authorized
            | ShakedexValueStage::RequiresRebroadcast
            | ShakedexValueStage::Broadcast
            | ShakedexValueStage::Mempool
            | ShakedexValueStage::Confirming
            | ShakedexValueStage::Confirmed
            | ShakedexValueStage::Conflicted
    ) {
        return Err(ShakedexError::InvalidTransition);
    }
    store.try_with_store(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            stored.workflow.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )
        .map_err(ShakedexError::from)
    })?;
    let signed = stored
        .workflow
        .signed_transaction()
        .ok_or(ShakedexError::InvalidTransition)?;
    let observation =
        runtime.observe_shakedex_transaction(stored.workflow.funding_reservation(), signed)?;
    if observation.transaction()
        != stored
            .workflow
            .transaction()
            .ok_or(ShakedexError::InvalidTransition)?
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let observed_at_unix = observation.observed_at_unix();
    let (transaction_evidence, spend_evidence) = observation.into_parts();
    let released_at_unix = runtime.shakedex_now_unix()?;
    let next = stored.workflow.release_reservations(
        transaction_evidence,
        spend_evidence,
        observed_at_unix,
        released_at_unix,
    )?;
    store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        let batch = delete_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )?;
        if !batch.saves().is_empty() || batch.deletes().is_empty() {
            return Err(ShakedexError::Invariant);
        }
        let revision = store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            next.workflow_id,
            WorkflowKind::ShakedexValue,
            stored.revision,
            &next,
            true,
            released_at_unix,
            EntityKind::InputReservation,
            batch.saves(),
            batch.deletes(),
        )?;
        let released = StoredShakedexValueWorkflow {
            revision,
            workflow: next,
        };
        validate_shakedex_value_workflow_reservations(store, scope, &released)?;
        Ok(released)
    })
}

/// Reconcile reversible signed states. For `ReservationsReleased`, this is a
/// read-only finality audit: it performs no workflow/reservation mutation and
/// returns `RecoveryRequired` rather than transitioning out of the terminal
/// stage when the persisted outcome no longer holds.
fn reconcile_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &SharedWalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    validate_runtime_scope(runtime, scope)?;
    let reservations_released = stored.workflow.stage == ShakedexValueStage::ReservationsReleased;
    store.try_with_store(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            stored.workflow.funding_reservation(),
            if reservations_released {
                HnsShakedexFundingReservationState::Released
            } else {
                HnsShakedexFundingReservationState::Active
            },
        )
        .map_err(ShakedexError::from)
    })?;
    let signed = stored
        .workflow
        .signed_transaction()
        .ok_or(ShakedexError::InvalidTransition)?;
    let observation =
        runtime.observe_shakedex_transaction(stored.workflow.funding_reservation(), signed)?;
    if observation.transaction()
        != stored
            .workflow
            .transaction()
            .ok_or(ShakedexError::InvalidTransition)?
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let observed_at_unix = observation.observed_at_unix();
    let (transaction_evidence, spend_evidence) = observation.into_parts();
    if reservations_released {
        let previous = stored
            .workflow
            .last_chain_observation()
            .ok_or(ShakedexError::InvalidEvidence)?;
        if observed_at_unix < previous.observed_at_unix
            || !snapshot_binding_not_older(transaction_evidence.binding, previous.binding)
            || !mempool_binding_not_older(transaction_evidence.mempool, previous.mempool)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        validate_transaction_evidence(&stored.workflow, &transaction_evidence)?;
        let competing_spenders = validate_spend_evidence(
            &stored.workflow,
            &spend_evidence,
            stored
                .workflow
                .transaction()
                .ok_or(ShakedexError::InvalidTransition)?,
            &transaction_evidence,
        )?;
        let current_reason = audit_terminal_release_reason(
            stored
                .workflow
                .transaction()
                .ok_or(ShakedexError::InvalidTransition)?,
            stored.workflow.minimum_confirmations,
            &transaction_evidence,
            &spend_evidence,
            &competing_spenders,
        )?;
        if stored
            .workflow
            .reservation_release()
            .is_none_or(|release| release.reason() != current_reason)
        {
            return Err(ShakedexError::RecoveryRequired);
        }
        store.try_with_store(|store| {
            require_exact_stored_value_workflow(store, stored)?;
            validate_shakedex_value_workflow_reservations(store, scope, stored)
        })?;
        return Ok(stored.clone());
    }
    let next =
        stored
            .workflow
            .reconcile(&transaction_evidence, &spend_evidence, observed_at_unix)?;
    store.try_with_store_mut(|store| {
        require_exact_stored_value_workflow(store, stored)?;
        let reservation_batch = retain_active_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            observed_at_unix,
        )?;
        if reservation_batch.saves().is_empty() || !reservation_batch.deletes().is_empty() {
            return Err(ShakedexError::Invariant);
        }
        let revision = match validate_save_transition(store, stored.revision, &next)? {
            Some(revision) => revision,
            None => store.save_workflow_with_entity_batch(
                next.workflow_id,
                WorkflowKind::ShakedexValue,
                stored.revision,
                &next,
                true,
                observed_at_unix,
                EntityKind::InputReservation,
                reservation_batch.saves(),
                reservation_batch.deletes(),
            )?,
        };
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            next.funding_reservation(),
            HnsShakedexFundingReservationState::Active,
        )?;
        Ok(StoredShakedexValueWorkflow {
            revision,
            workflow: next,
        })
    })
}

pub fn load_shakedex_value_workflow(
    store: &WalletStore,
    workflow_id: WorkflowId,
) -> Result<Option<StoredShakedexValueWorkflow>, ShakedexError> {
    store
        .load_workflow::<ShakedexValueWorkflow>(workflow_id)?
        .map(validate_stored_value_workflow)
        .transpose()
}

/// Reauthenticate the exact reservation rows required by a loaded aggregate.
/// Prepared terminal and evidence-backed released workflows have no rows;
/// nonterminal signed workflows retain both source and funding reservations.
pub fn validate_shakedex_value_workflow_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<(), ShakedexError> {
    stored.workflow.validate()?;
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    let expected_state = match stored.workflow.stage {
        ShakedexValueStage::Prepared => HnsShakedexFundingReservationState::Prepared,
        ShakedexValueStage::Expired
        | ShakedexValueStage::Cancelled
        | ShakedexValueStage::ReservationsReleased => HnsShakedexFundingReservationState::Released,
        ShakedexValueStage::Authorized
        | ShakedexValueStage::RequiresRebroadcast
        | ShakedexValueStage::Broadcast
        | ShakedexValueStage::Mempool
        | ShakedexValueStage::Confirming
        | ShakedexValueStage::Confirmed
        | ShakedexValueStage::Conflicted => HnsShakedexFundingReservationState::Active,
    };
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        expected_state,
    )?;
    Ok(())
}

fn validate_runtime_scope<B: HnsBackend, C: HnsClock>(
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
) -> Result<(), ShakedexError> {
    if runtime.shakedex_funding_scope()? != *scope {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn reacquire_current_script_finalize_transfer<B: HnsBackend, C: HnsClock>(
    runtime: &HnsWalletRuntime<B, C>,
    workflow: &ShakedexValueWorkflow,
) -> Result<VerifiedCurrentShakedexTransfer, ShakedexError> {
    let (parent, _) = workflow.script_finalize_transfer_identity()?;
    let supplied_lock = parent.supplied_lock()?;
    let current = runtime
        .verify_current_shakedex_transfer(supplied_lock.descriptor(), parent.transaction()?)?;
    workflow.validate_current_transfer(&current)?;
    Ok(current)
}

fn require_exact_stored_value_workflow(
    store: &WalletStore,
    supplied: &StoredShakedexValueWorkflow,
) -> Result<(), ShakedexError> {
    let current = load_shakedex_value_workflow(store, supplied.workflow.workflow_id)?
        .ok_or(ShakedexError::InvalidTransition)?;
    if current.revision != supplied.revision {
        return Err(ShakedexError::StaleRevision);
    }
    if current.workflow != supplied.workflow {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

pub fn list_shakedex_value_workflows(
    store: &WalletStore,
) -> Result<Vec<StoredShakedexValueWorkflow>, ShakedexError> {
    store
        .list_workflows_complete::<ShakedexValueWorkflow>(
            WorkflowKind::ShakedexValue,
            MAX_SHAKEDEX_VALUE_WORKFLOWS,
        )?
        .into_iter()
        .map(validate_stored_value_workflow)
        .collect()
}

pub(crate) fn save_value_workflow(
    store: &mut WalletStore,
    expected_revision: u64,
    workflow: &ShakedexValueWorkflow,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    workflow.validate()?;
    if let Some(revision) = validate_save_transition(store, expected_revision, workflow)? {
        return Ok(revision);
    }
    store
        .save_workflow(
            workflow.workflow_id,
            WorkflowKind::ShakedexValue,
            expected_revision,
            workflow,
            workflow.authorized.is_some(),
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}

fn validate_stored_value_workflow(
    stored: StoredWorkflow<ShakedexValueWorkflow>,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    if stored.kind != WorkflowKind::ShakedexValue
        || stored.id != stored.state.workflow_id
        || stored.irreversible_broadcast_prepared != stored.state.authorized.is_some()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    stored.state.validate()?;
    Ok(StoredShakedexValueWorkflow {
        revision: stored.revision,
        workflow: stored.state,
    })
}

fn validate_save_transition(
    store: &WalletStore,
    expected_revision: u64,
    next: &ShakedexValueWorkflow,
) -> Result<Option<u64>, ShakedexError> {
    let Some(current) = load_shakedex_value_workflow(store, next.workflow_id)? else {
        if expected_revision != 0 || next.stage != ShakedexValueStage::Prepared {
            return Err(ShakedexError::InvalidTransition);
        }
        return Ok(None);
    };
    if current.workflow == *next
        && (expected_revision == current.revision
            || expected_revision.checked_add(1) == Some(current.revision))
    {
        return Ok(Some(current.revision));
    }
    if current.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    if !current.workflow.same_identity(next) {
        return Err(ShakedexError::InvalidEvidence);
    }
    if current.workflow.authorized.is_some() && !current.workflow.same_authorization_identity(next)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if next.submission_attempts < current.workflow.submission_attempts
        || current.workflow.confirmed_once && !next.confirmed_once
        || current.workflow.conflicted_once && !next.conflicted_once
        || current.workflow.reservation_release.is_some()
            && current.workflow.reservation_release != next.reservation_release
        || matches!(
            (
                current.workflow.submission_started_at_unix,
                next.submission_started_at_unix,
            ),
            (Some(current), Some(next)) if next < current
        )
        || matches!(
            (
                current.workflow.last_chain_observation.as_ref(),
                next.last_chain_observation.as_ref(),
            ),
            (Some(current), Some(next))
                if next.observed_at_unix < current.observed_at_unix
                    || !snapshot_binding_not_older(next.binding, current.binding)
                    || !mempool_binding_not_older(next.mempool, current.mempool)
        )
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if !valid_stage_transition(current.workflow.stage, next.stage) {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(None)
}

fn valid_stage_transition(current: ShakedexValueStage, next: ShakedexValueStage) -> bool {
    matches!(
        (current, next),
        (
            ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted,
            same,
        ) if current == same
    ) || matches!(
        (current, next),
        (ShakedexValueStage::Prepared, ShakedexValueStage::Authorized)
            | (ShakedexValueStage::Prepared, ShakedexValueStage::Expired)
            | (ShakedexValueStage::Prepared, ShakedexValueStage::Cancelled)
            | (
                ShakedexValueStage::Authorized
                    | ShakedexValueStage::RequiresRebroadcast
                    | ShakedexValueStage::Broadcast
                    | ShakedexValueStage::Mempool
                    | ShakedexValueStage::Conflicted,
                ShakedexValueStage::RequiresRebroadcast
            )
            | (
                ShakedexValueStage::RequiresRebroadcast,
                ShakedexValueStage::Broadcast
            )
            | (
                ShakedexValueStage::Authorized
                    | ShakedexValueStage::RequiresRebroadcast
                    | ShakedexValueStage::Broadcast
                    | ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted,
                ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted
            )
            | (
                ShakedexValueStage::Confirming | ShakedexValueStage::Confirmed,
                ShakedexValueStage::RequiresRebroadcast
            )
            | (
                ShakedexValueStage::Authorized
                    | ShakedexValueStage::RequiresRebroadcast
                    | ShakedexValueStage::Broadcast
                    | ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted,
                ShakedexValueStage::ReservationsReleased
            )
    )
}

fn structural_plan_commitment(plan: &StructuralPlan) -> Result<ObjectHash, ShakedexError> {
    let encoded = serde_json::to_vec(plan).map_err(|_| ShakedexError::Encoding)?;
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-structural-plan/v1");
    hasher.update(encoded);
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn canonical_transaction(raw: &[u8]) -> Result<Transaction, ShakedexError> {
    let transaction = Transaction::decode(raw).map_err(|_| ShakedexError::InvalidEvidence)?;
    if transaction
        .encode()
        .map_err(|_| ShakedexError::InvalidEvidence)?
        != raw
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(transaction)
}

fn canonical_transaction_hash(transaction: &Transaction) -> Result<TransactionHash, ShakedexError> {
    transaction
        .transaction_hash()
        .map(|hash| TransactionHash::new(hash.into_bytes()))
        .map_err(|_| ShakedexError::InvalidEvidence)
}

fn require_only_funding_witness_changes(
    prepared_raw: &[u8],
    signed_raw: &[u8],
) -> Result<(), ShakedexError> {
    let prepared = canonical_transaction(prepared_raw)?;
    let signed = canonical_transaction(signed_raw)?;
    if prepared.version != signed.version
        || prepared.outputs != signed.outputs
        || prepared.locktime != signed.locktime
        || prepared.inputs.len() != signed.inputs.len()
        || prepared.inputs[0] != signed.inputs[0]
        || prepared.inputs[1..]
            .iter()
            .zip(&signed.inputs[1..])
            .any(|(left, right)| {
                left.previous_output != right.previous_output
                    || left.sequence != right.sequence
                    || !left.witness.items.is_empty()
                    || right.witness.items.is_empty()
            })
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn validate_transaction_evidence(
    workflow: &ShakedexValueWorkflow,
    evidence: &TransactionEvidence,
) -> Result<(), ShakedexError> {
    let quote = workflow
        .fee_quote()
        .ok_or(ShakedexError::InvalidTransition)?;
    let confirmation_count_matches = match evidence.inclusion {
        Some(inclusion) => {
            inclusion.height <= evidence.binding.tip.height
                && evidence.status.confirmation_count
                    == u32::try_from(
                        evidence
                            .binding
                            .tip
                            .height
                            .checked_sub(inclusion.height)
                            .and_then(|depth| depth.checked_add(1))
                            .ok_or(ShakedexError::InvalidEvidence)?,
                    )
                    .map_err(|_| ShakedexError::InvalidEvidence)?
        }
        None => evidence.status.confirmation_count == 0,
    };
    if evidence
        .raw
        .as_deref()
        .is_some_and(|raw| workflow.signed_transaction() != Some(raw))
        || !snapshot_binding_not_older(evidence.binding, quote.binding)
        || !mempool_binding_not_older(evidence.mempool, quote.mempool)
        || !confirmation_count_matches
        || evidence.status.confirmation_count > 0 && evidence.inclusion.is_none()
        || evidence.status.confirmation_count == 0 && evidence.inclusion.is_some()
        || evidence.status.conflicted
            && (evidence.status.in_mempool || evidence.status.confirmation_count > 0)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn snapshot_binding_not_older(candidate: SnapshotBinding, floor: SnapshotBinding) -> bool {
    candidate.chain_epoch > floor.chain_epoch
        || candidate.chain_epoch == floor.chain_epoch
            && (candidate.tip.height > floor.tip.height || candidate.tip == floor.tip)
}

fn mempool_binding_not_older(
    candidate: MempoolSnapshotBinding,
    floor: MempoolSnapshotBinding,
) -> bool {
    candidate.instance_nonce != floor.instance_nonce || candidate.generation >= floor.generation
}

fn submission_evidence_not_older(
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    started_at_unix: u64,
    observation: &ShakedexChainObservation,
) -> bool {
    started_at_unix >= observation.observed_at_unix
        && snapshot_binding_not_older(binding, observation.binding)
        && mempool_binding_not_older(mempool, observation.mempool)
}

fn validate_spend_evidence(
    workflow: &ShakedexValueWorkflow,
    evidence: &OutpointSpendEvidence,
    expected_transaction: TransactionHash,
    transaction_evidence: &TransactionEvidence,
) -> Result<Vec<TransactionHash>, ShakedexError> {
    let transaction = canonical_transaction(
        workflow
            .signed_transaction()
            .ok_or(ShakedexError::InvalidTransition)?,
    )?;
    if evidence.binding != transaction_evidence.binding
        || evidence.entries.len() != transaction.inputs.len()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let mut competing: std::collections::BTreeMap<
        TransactionHash,
        (u64, [u8; 32], std::collections::BTreeSet<u32>),
    > = std::collections::BTreeMap::new();
    for (index, (input, entry)) in transaction.inputs.iter().zip(&evidence.entries).enumerate() {
        if entry.outpoint.transaction.as_bytes()
            != input.previous_output.transaction_hash.as_bytes()
            || entry.outpoint.output_index != input.previous_output.index
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        if let Some(spending) = entry.spending {
            if spending.height > evidence.binding.tip.height {
                return Err(ShakedexError::InvalidEvidence);
            }
            if spending.transaction == expected_transaction {
                let inclusion = transaction_evidence
                    .inclusion
                    .ok_or(ShakedexError::InvalidEvidence)?;
                if transaction_evidence.status.conflicted
                    || transaction_evidence.status.confirmation_count == 0
                    || spending.input_position
                        != u32::try_from(index).map_err(|_| ShakedexError::InvalidEvidence)?
                    || spending.height != inclusion.height
                    || spending.block_hash != inclusion.block_hash
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            } else {
                if transaction_evidence.status.in_mempool
                    || transaction_evidence.status.confirmation_count > 0
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
                let observed = competing.entry(spending.transaction).or_insert_with(|| {
                    (
                        spending.height,
                        spending.block_hash,
                        std::collections::BTreeSet::new(),
                    )
                });
                if observed.0 != spending.height
                    || observed.1 != spending.block_hash
                    || !observed.2.insert(spending.input_position)
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
        } else if transaction_evidence.status.confirmation_count > 0 {
            return Err(ShakedexError::InvalidEvidence);
        }
    }
    Ok(competing.into_keys().collect())
}

fn terminal_release_reason(
    expected_transaction: TransactionHash,
    minimum_confirmations: u32,
    transaction_evidence: &TransactionEvidence,
    spend_evidence: &OutpointSpendEvidence,
    competing_spenders: &[TransactionHash],
) -> Result<ShakedexReservationReleaseReason, ShakedexError> {
    if minimum_confirmations == 0
        || spend_evidence.binding != transaction_evidence.binding
        || spend_evidence.entries.is_empty()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if transaction_evidence.status.confirmation_count >= minimum_confirmations
        && !transaction_evidence.status.in_mempool
        && !transaction_evidence.status.conflicted
        && competing_spenders.is_empty()
    {
        let inclusion = transaction_evidence
            .inclusion
            .ok_or(ShakedexError::InvalidEvidence)?;
        let every_input_spent_by_exact_transaction =
            spend_evidence
                .entries
                .iter()
                .enumerate()
                .all(|(position, entry)| {
                    entry.spending.is_some_and(|spending| {
                        spending.transaction == expected_transaction
                            && usize::try_from(spending.input_position)
                                .is_ok_and(|candidate| candidate == position)
                            && spending.height == inclusion.height
                            && spending.block_hash == inclusion.block_hash
                    })
                });
        if every_input_spent_by_exact_transaction {
            return Ok(ShakedexReservationReleaseReason::ExactTransactionConfirmed);
        }
        return Err(ShakedexError::InvalidEvidence);
    }
    if transaction_evidence.status.confirmation_count != 0
        || transaction_evidence.inclusion.is_some()
        || transaction_evidence.status.in_mempool
        || competing_spenders.is_empty()
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let tip_height = transaction_evidence.binding.tip.height;
    let final_competitor = spend_evidence.entries.iter().any(|entry| {
        entry.spending.is_some_and(|spending| {
            spending.transaction != expected_transaction
                && competing_spenders
                    .binary_search(&spending.transaction)
                    .is_ok()
                && tip_height
                    .checked_sub(spending.height)
                    .and_then(|depth| depth.checked_add(1))
                    .is_some_and(|depth| depth >= u64::from(minimum_confirmations))
        })
    });
    if !final_competitor {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(ShakedexReservationReleaseReason::ConfirmedCompetingSpend)
}

fn audit_terminal_release_reason(
    expected_transaction: TransactionHash,
    minimum_confirmations: u32,
    transaction_evidence: &TransactionEvidence,
    spend_evidence: &OutpointSpendEvidence,
    competing_spenders: &[TransactionHash],
) -> Result<ShakedexReservationReleaseReason, ShakedexError> {
    terminal_release_reason(
        expected_transaction,
        minimum_confirmations,
        transaction_evidence,
        spend_evidence,
        competing_spenders,
    )
    .map_err(|error| {
        if matches!(error, ShakedexError::InvalidTransition) {
            ShakedexError::RecoveryRequired
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Blake2bVar;
    use blake2::digest::VariableOutput;
    use hns_covenants::{Covenant, FinalizeCovenant, hash_name};
    use hns_primitives::{Dollarydoos, Height, TransactionHash as CanonicalTransactionHash};
    use hns_script::{
        OP_BLAKE160, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, SIGHASH_ALL, signature_hash,
    };
    use hns_swap::{FixedPriceListing, NetworkBinding, SwapProof, lock_script_hash};
    use hns_transaction::{Input, Outpoint, Output, Witness};
    use hns_wallet_hns::{
        ChainTip, HnsOutpoint, OutpointSpendEntry, SpendingTransactionEvidence, TrackedHnsCoin,
        TransactionStatus, WalletCoin,
    };
    #[cfg(unix)]
    use hns_wallet_hns::{
        HnsNameAction, HnsNetwork, HnsRuntimeConfig, HnsWalletError, SystemClock,
    };
    use hns_wallet_types::{AccountId, DerivationReference, KeyRole, WalletId};
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    const PRODUCTION_NEXT_ACTIVE_TIME: u64 = 1_800_000_200;
    const PRODUCTION_NEXT_FEE: u64 = 1_000;

    #[cfg(unix)]
    struct ProductionNextUnusedBackend;

    #[cfg(unix)]
    impl HnsBackend for ProductionNextUnusedBackend {
        fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_block_hash(
            &self,
            _height: u64,
            _binding: SnapshotBinding,
        ) -> Result<hns_wallet_hns::BlockHashEvidence, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_confirmed_wallet_page(
            &self,
            _request: hns_wallet_hns::ConfirmedWalletPageRequest<'_>,
        ) -> Result<hns_wallet_hns::ConfirmedWalletPage, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_mempool_wallet_page(
            &self,
            _request: hns_wallet_hns::MempoolWalletPageRequest<'_>,
        ) -> Result<hns_wallet_hns::MempoolWalletPage, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_transaction_evidence(
            &self,
            _txid: TransactionHash,
            _binding: SnapshotBinding,
            _expected_mempool: Option<MempoolSnapshotBinding>,
        ) -> Result<TransactionEvidence, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_outpoint_spend_evidence(
            &self,
            _outpoints: &[HnsOutpoint],
            _binding: SnapshotBinding,
        ) -> Result<OutpointSpendEvidence, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn broadcast_transaction(&self, _raw: &[u8]) -> Result<TransactionHash, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn quote_transaction_fee(
            &self,
            _raw: &[u8],
            _input_coins: &[Coin],
            _target_blocks: u16,
            _binding: SnapshotBinding,
            _expected_mempool: MempoolSnapshotBinding,
        ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<BaseUnits, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_name_evidence(
            &self,
            _name_hash: [u8; 32],
            _binding: SnapshotBinding,
        ) -> Result<hns_wallet_hns::NameEvidence, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }

        fn get_name_action_context(
            &self,
            _action: HnsNameAction,
            _name_hash: [u8; 32],
            _binding: SnapshotBinding,
            _expected_mempool: MempoolSnapshotBinding,
        ) -> Result<hns_wallet_hns::NameActionContextEvidence, HnsWalletError> {
            panic!("backend is not used while opening the persistence fixture")
        }
    }

    fn binding(epoch: u64, height: u64, hash: u8) -> SnapshotBinding {
        SnapshotBinding {
            tip: ChainTip {
                height,
                block_hash: [hash; 32],
                tree_root: [hash.wrapping_add(1); 32],
                median_time_past: 1_800_000_000 + height,
            },
            chain_epoch: epoch,
        }
    }

    fn production_next_public_key_hash(key: &SigningKey) -> ([u8; 33], [u8; 20]) {
        let public_key: [u8; 33] = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed public key");
        let mut hasher = Blake2bVar::new(20).expect("Blake2b-160");
        blake2::digest::Update::update(&mut hasher, &public_key);
        let mut program = [0_u8; 20];
        hasher
            .finalize_variable(&mut program)
            .expect("Blake2b-160 output");
        (public_key, program)
    }

    fn production_next_funding_coin(tag: u8, key: &SigningKey, value: u64) -> Coin {
        let (_, program) = production_next_public_key_hash(key);
        Coin {
            outpoint: Outpoint {
                transaction_hash: CanonicalTransactionHash::new([tag; 32]),
                index: u32::from(tag),
            },
            value: Dollarydoos::new(value),
            height: Height::new(150),
            coinbase: false,
            address: Address::new(0, program.to_vec()).expect("funding address"),
            covenant: Covenant::default(),
        }
    }

    fn production_next_unsigned_input(coin: &Coin) -> Input {
        Input {
            previous_output: coin.outpoint,
            sequence: u32::MAX,
            witness: Witness::default(),
        }
    }

    fn production_next_ordinary_output(address: Address, value: u64) -> Output {
        Output {
            value: Dollarydoos::new(value),
            address,
            covenant: Covenant::default(),
        }
    }

    fn production_next_sign_p2pkh(
        transaction: &mut Transaction,
        index: usize,
        coin: &Coin,
        key: &SigningKey,
    ) {
        let (public_key, program) = production_next_public_key_hash(key);
        let mut script = Vec::with_capacity(25);
        script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
        script.extend_from_slice(&program);
        script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        let digest = signature_hash(transaction, index, &script, coin.value.get(), SIGHASH_ALL)
            .expect("P2PKH signature hash");
        let signature: Signature = key.sign_prehash(&digest).expect("P2PKH signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut encoded = signature.to_bytes().to_vec();
        encoded.push(SIGHASH_ALL as u8);
        transaction.inputs[index].witness = Witness {
            items: vec![encoded, public_key.to_vec()],
        };
    }

    fn production_next_script_finalize_fixture() -> ShakedexValueWorkflow {
        let seller_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = production_next_public_key_hash(&seller_key).0;
        let network = NetworkBinding {
            magic: 0x5b6e_c393,
            genesis: BlockHash::new([0x11; 32]),
        };
        let mut proof = SwapProof {
            network,
            locking_outpoint: Outpoint {
                transaction_hash: CanonicalTransactionHash::new([0x22; 32]),
                index: 7,
            },
            name: b"market-name".to_vec(),
            seller_public_key,
            payment_address: Address::new(0, vec![0x33; 20]).expect("payment address"),
            price: Dollarydoos::new(12_345_678),
            lock_time_seconds: 1_800_000_000,
            signature: None,
            fee_address: Some(Address::new(0, vec![0x44; 20]).expect("fee address")),
            fee: Dollarydoos::new(25_000),
        };
        let locking_coin = Coin {
            outpoint: proof.locking_outpoint,
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&seller_public_key).to_vec())
                .expect("lock address"),
            covenant: FinalizeCovenant::new(
                proof.name.clone(),
                Height::new(1),
                false,
                Height::new(0),
                0,
                BlockHash::new([0x55; 32]),
            )
            .expect("FINALIZE covenant")
            .to_covenant()
            .expect("canonical covenant"),
        };
        proof.sign(&locking_coin, &seller_key).expect("presign");
        let mut listing = FixedPriceListing {
            proof,
            created_at: PRODUCTION_NEXT_ACTIVE_TIME - 100,
            expires_at: PRODUCTION_NEXT_ACTIVE_TIME + 3_500,
            sequence: 42,
            signature: None,
        };
        listing.sign(&seller_key).expect("listing signature");
        let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
        let listing_bytes = listing.encode().expect("listing bytes");
        let verified_listing = crate::verify_fixed_price_listing(
            &listing_bytes,
            listing_hash,
            network,
            PRODUCTION_NEXT_ACTIVE_TIME,
            &locking_coin,
        )
        .expect("verified listing");
        let supplied_lock =
            SuppliedShakedexLock::verify(network, locking_coin.clone(), seller_public_key)
                .expect("supplied lock");

        let buyer_key = SigningKey::from_slice(&[0x41; 32]).expect("buyer key");
        let (_, buyer_program) = production_next_public_key_hash(&buyer_key);
        let buyer_recipient = Address::new(0, buyer_program.to_vec()).expect("buyer recipient");
        let buyer_coin = production_next_funding_coin(0x61, &buyer_key, 13_000_000);
        let prepared_fulfillment = crate::prepare_buyer_fulfillment(
            &verified_listing,
            &supplied_lock,
            PRODUCTION_NEXT_ACTIVE_TIME,
            PRODUCTION_NEXT_ACTIVE_TIME,
            buyer_recipient.clone(),
            vec![production_next_unsigned_input(&buyer_coin)],
            vec![buyer_coin.clone()],
            vec![production_next_ordinary_output(
                buyer_recipient.clone(),
                628_322,
            )],
            PRODUCTION_NEXT_FEE,
        )
        .expect("prepared fulfillment");
        let mut fulfillment =
            Transaction::decode(prepared_fulfillment.transaction_bytes()).expect("fulfillment");
        production_next_sign_p2pkh(&mut fulfillment, 1, &buyer_coin, &buyer_key);
        let fulfillment_bytes = fulfillment.encode().expect("fulfillment bytes");
        let verified_fulfillment = prepared_fulfillment
            .verify_signed(&fulfillment_bytes)
            .expect("verified fulfillment");

        let wallet_id = WalletId::new([0x71; 16]);
        let account_id = AccountId::new([0x72; 16]);
        let parent_workflow_id = WorkflowId::new([0x74; 16]);
        let parent_plan = BuyerLockPlan::offer_verified(
            wallet_id,
            account_id,
            parent_workflow_id,
            &verified_listing,
            &locking_coin,
        )
        .expect("buyer plan")
        .with_fulfillment(&verified_fulfillment, &[buyer_coin])
        .expect("signed parent plan");
        let parent = ShakedexScriptFinalizeParent::BuyerFulfillment { plan: parent_plan };

        let transfer_output = fulfillment.outputs[0].clone();
        let transfer_coin = Coin {
            outpoint: Outpoint {
                transaction_hash: fulfillment.transaction_hash().expect("fulfillment txid"),
                index: 0,
            },
            value: transfer_output.value,
            height: Height::new(200),
            coinbase: false,
            address: transfer_output.address,
            covenant: transfer_output.covenant,
        };
        let mut current_state = NameState::null(hash_name(b"market-name").expect("name hash"));
        current_state.name = b"market-name".to_vec();
        current_state.height = Height::new(1);
        current_state.owner = transfer_coin.outpoint;
        current_state.value = transfer_coin.value;
        current_state.transfer = transfer_coin.height;
        current_state.registered = true;
        let finalize_coin = production_next_funding_coin(0x63, &buyer_key, 100_000);
        let renewal_block = BlockHash::new([0x66; 32]);
        let prepared_finalize = crate::prepare_script_finalize(
            &supplied_lock,
            VerifiedShakedexTransfer::Fulfillment(&verified_fulfillment),
            transfer_coin.clone(),
            current_state.clone(),
            renewal_block,
            buyer_recipient.clone(),
            vec![production_next_unsigned_input(&finalize_coin)],
            vec![finalize_coin.clone()],
            vec![production_next_ordinary_output(
                buyer_recipient.clone(),
                99_000,
            )],
            PRODUCTION_NEXT_FEE,
        )
        .expect("prepared script FINALIZE");
        let transfer = CurrentShakedexTransferEvidence {
            binding: binding(9, 500, 0x70),
            mempool: MempoolSnapshotBinding {
                instance_nonce: [0x71; 32],
                generation: 4,
            },
            transfer_transaction: fulfillment_bytes,
            transfer_coin: CoinEvidence::from_coin(&transfer_coin).expect("transfer coin"),
            owner_inclusion: TransactionInclusion {
                block_hash: [0x72; 32],
                height: 200,
                transaction_index: Some(3),
            },
            current_name_state: current_state.encode().expect("name state"),
            renewal_block_height: 100,
            renewal_block_hash: renewal_block.into_bytes(),
        };
        let workflow_id = shakedex_value_workflow_id(
            parent_workflow_id,
            ShakedexValueAction::SellerScriptFinalize,
        );
        let tracked_finalize_coin = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new(
                        finalize_coin.outpoint.transaction_hash.into_bytes(),
                    ),
                    output_index: finalize_coin.outpoint.index,
                },
                value: BaseUnits::new(u128::from(finalize_coin.value.get())),
                confirmation_count: 10,
                confirmed_height: Some(finalize_coin.height.get()),
                coinbase: false,
                covenant: finalize_coin.covenant.encode().expect("funding covenant"),
                name_locked: false,
            },
            derivation: DerivationReference {
                role: KeyRole::HnsCoin,
                account: 7,
                change: 0,
                index: 1,
            },
            address_program: finalize_coin.address.hash.clone(),
        };
        let expires_at_unix = PRODUCTION_NEXT_ACTIVE_TIME + 200;
        let reservation: HnsShakedexFundingReservation =
            serde_json::from_value(serde_json::json!({
                "wallet_id": wallet_id,
                "account_id": account_id,
                "workflow_id": workflow_id,
                "purpose": HnsShakedexFundingPurpose::SellerScriptFinalize,
                "name_hash": hash_name(b"market-name").expect("name hash").into_bytes(),
                "source_outpoint": HnsOutpoint {
                    transaction: TransactionHash::new(
                        transfer_coin.outpoint.transaction_hash.into_bytes(),
                    ),
                    output_index: transfer_coin.outpoint.index,
                },
                "funding_inputs": [tracked_finalize_coin],
                "expires_at_unix": expires_at_unix,
            }))
            .expect("reservation evidence");
        ShakedexValueWorkflow::prepared(
            ShakedexValueAction::SellerScriptFinalize,
            StructuralPlan::ScriptFinalize {
                parent: Box::new(parent),
                transfer,
            },
            reservation,
            &transfer_coin,
            &[finalize_coin],
            &buyer_recipient,
            BaseUnits::new(u128::from(transfer_coin.value.get())),
            PRODUCTION_NEXT_FEE,
            BaseUnits::new(2_000),
            3,
            prepared_finalize.transaction_bytes(),
            expires_at_unix,
        )
        .expect("durable script FINALIZE")
    }

    fn production_next_refresh_structural_plan_commitment(workflow: &mut ShakedexValueWorkflow) {
        workflow.structural_plan_commitment =
            structural_plan_commitment(&workflow.structural_plan).expect("structural commitment");
    }

    #[cfg(unix)]
    struct ProductionNextWalletDirectory(PathBuf);

    #[cfg(unix)]
    impl Drop for ProductionNextWalletDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn production_next_test_store() -> (
        ProductionNextWalletDirectory,
        PathBuf,
        HnsShakedexFundingScope,
        WalletStore,
    ) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hns-wallet-shakedex-finalize-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("test wallet directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private test wallet directory");
        let database = directory.join("wallet.sqlite3");
        let store = WalletStore::create(&database, "production-next-finalize-passphrase")
            .expect("encrypted store");
        let runtime = HnsWalletRuntime::open(
            ProductionNextUnusedBackend,
            store,
            HnsRuntimeConfig {
                wallet_id: WalletId::new([0x71; 16]),
                account_id: AccountId::new([0x72; 16]),
                account_derivation_index: 7,
                network: HnsNetwork::Regtest,
                birthday_height: 1,
                restore_lookahead: 10,
                minimum_confirmations: 1,
                dust_threshold: BaseUnits::new(1),
                value_operations_enabled: false,
                settlement_enabled: false,
            },
            SystemClock,
        )
        .expect("persistence-fixture runtime");
        let scope = runtime
            .shakedex_funding_scope()
            .expect("runtime-owned scope");
        drop(runtime);
        let mut store = WalletStore::open(&database).expect("reopen persistence-fixture store");
        store
            .unlock("production-next-finalize-passphrase")
            .expect("unlock persistence-fixture store");
        (
            ProductionNextWalletDirectory(directory),
            database,
            scope,
            store,
        )
    }

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "these compile-time release gates are asserted deliberately so a qualification flip requires an explicit test review"
    )]
    fn production_value_and_board_controllers_require_one_shared_store_authority() {
        let config = HnsRuntimeConfig {
            wallet_id: WalletId::new([0x81; 16]),
            account_id: AccountId::new([0x82; 16]),
            account_derivation_index: 3,
            network: HnsNetwork::Regtest,
            birthday_height: 1,
            restore_lookahead: 10,
            minimum_confirmations: 1,
            dust_threshold: BaseUnits::new(1),
            value_operations_enabled: false,
            settlement_enabled: false,
        };
        let store = SharedWalletStore::new(
            WalletStore::create(":memory:", "same-store-controller-passphrase")
                .expect("shared controller store"),
        );
        let runtime = HnsWalletRuntime::open_shared(
            ProductionNextUnusedBackend,
            store.clone(),
            config,
            SystemClock,
        )
        .expect("same-store full runtime");
        let value = ShakedexValueRuntime::new(store.clone(), &runtime)
            .expect("same-store value controller");
        assert!(value.shares_store_authority(&store));
        let board = crate::DenuoBoardRuntime::new_value(&runtime, store.clone())
            .expect("same-store board controller");
        assert!(board.shares_store_authority(&store));

        let different = SharedWalletStore::new(
            WalletStore::create(":memory:", "different-controller-passphrase")
                .expect("different controller store"),
        );
        assert!(matches!(
            ShakedexValueRuntime::new(different.clone(), &runtime),
            Err(ShakedexError::StoreAuthorityMismatch)
        ));
        assert!(matches!(
            crate::DenuoBoardRuntime::new_value(&runtime, different),
            Err(ShakedexError::StoreAuthorityMismatch)
        ));
    }

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "these compile-time release gates are asserted deliberately so a qualification flip requires an explicit test review"
    )]
    fn production_next_script_finalize_restart_preserves_canonical_transfer_identity() {
        assert!(!SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
        assert!(!HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED);
        assert!(!HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
        assert!(!HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
        let workflow = production_next_script_finalize_fixture();
        assert_eq!(workflow.action(), ShakedexValueAction::SellerScriptFinalize);
        assert_eq!(workflow.stage(), ShakedexValueStage::Prepared);
        assert_eq!(
            workflow.funding_reservation().purpose(),
            HnsShakedexFundingPurpose::SellerScriptFinalize
        );
        let encoded = serde_json::to_vec(&workflow).expect("workflow encoding");
        let restarted: ShakedexValueWorkflow =
            serde_json::from_slice(&encoded).expect("workflow restart decode");
        restarted.validate().expect("restart reauthentication");
        assert_eq!(restarted, workflow);
        let (parent, transfer) = restarted
            .script_finalize_transfer_identity()
            .expect("script FINALIZE identity");
        assert_eq!(parent.transaction().expect("parent txid"), {
            let transaction = canonical_transaction(&transfer.transfer_transaction)
                .expect("canonical parent transaction");
            canonical_transaction_hash(&transaction).expect("canonical parent txid")
        });
        assert_eq!(
            transfer
                .transfer_coin()
                .expect("transfer coin")
                .outpoint
                .index,
            0
        );
        assert_eq!(transfer.owner_inclusion.height, 200);
        assert_eq!(transfer.renewal_block_hash, [0x66; 32]);
    }

    #[test]
    fn production_next_script_finalize_harmless_binding_advance_preserves_stable_identity() {
        let workflow = production_next_script_finalize_fixture();
        let encoded = serde_json::to_vec(&workflow).expect("workflow encoding");
        let restarted: ShakedexValueWorkflow =
            serde_json::from_slice(&encoded).expect("workflow restart decode");
        let (parent, historical) = restarted
            .script_finalize_transfer_identity()
            .expect("script FINALIZE identity");
        let mut reacquired = historical.clone();
        reacquired.binding = binding(10, 501, 0x73);
        reacquired.mempool = MempoolSnapshotBinding {
            instance_nonce: [0x74; 32],
            generation: 1,
        };
        assert_ne!(reacquired.binding, historical.binding);
        assert_ne!(reacquired.mempool, historical.mempool);
        reacquired
            .validate(parent)
            .expect("advanced historical evidence remains structural");
        historical
            .validate_reacquired_evidence(parent, &reacquired)
            .expect("harmless live binding advance");

        reacquired.owner_inclusion.height += 1;
        assert!(
            historical
                .validate_reacquired_evidence(parent, &reacquired)
                .is_err(),
            "stable owner identity changes must still fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_next_script_finalize_encrypted_lock_drop_reopen() {
        let workflow = production_next_script_finalize_fixture();
        let (_directory, database, scope, mut store) = production_next_test_store();
        let batch = create_hns_shakedex_funding_reservations(
            &store,
            &scope,
            workflow.funding_reservation(),
            PRODUCTION_NEXT_ACTIVE_TIME,
        )
        .expect("source/funding reservation batch");
        let revision = store
            .save_workflow_with_entity_batch(
                workflow.workflow_id(),
                WorkflowKind::ShakedexValue,
                0,
                &workflow,
                false,
                PRODUCTION_NEXT_ACTIVE_TIME,
                EntityKind::InputReservation,
                batch.saves(),
                batch.deletes(),
            )
            .expect("atomically persist FINALIZE and reservations");
        assert_eq!(revision, 1);
        let stored = StoredShakedexValueWorkflow {
            revision,
            workflow: workflow.clone(),
        };
        validate_shakedex_value_workflow_reservations(&store, &scope, &stored)
            .expect("prepared source/funding reservation join");
        store.lock();
        assert!(store.is_locked());
        assert!(load_shakedex_value_workflow(&store, workflow.workflow_id()).is_err());
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("open locked store");
        assert!(reopened.is_locked());
        reopened
            .unlock("production-next-finalize-passphrase")
            .expect("unlock reopened store");
        let loaded = load_shakedex_value_workflow(&reopened, workflow.workflow_id())
            .expect("load FINALIZE")
            .expect("persisted FINALIZE");
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.workflow, workflow);
        loaded.workflow.validate().expect("reopened evidence");
        assert_eq!(
            loaded.workflow.funding_reservation().purpose(),
            HnsShakedexFundingPurpose::SellerScriptFinalize
        );
        validate_shakedex_value_workflow_reservations(&reopened, &scope, &loaded)
            .expect("reopened prepared source/funding reservation join");
    }

    #[cfg(unix)]
    #[test]
    fn production_next_script_finalize_stale_cas_and_identity_replacement_fail_closed() {
        let workflow = production_next_script_finalize_fixture();
        let (_directory, _database, _scope, mut store) = production_next_test_store();
        let revision = save_value_workflow(&mut store, 0, &workflow, PRODUCTION_NEXT_ACTIVE_TIME)
            .expect("persist FINALIZE");

        let mut changed_identity = workflow.clone();
        let StructuralPlan::ScriptFinalize { transfer, .. } = &mut changed_identity.structural_plan
        else {
            panic!("script FINALIZE plan");
        };
        transfer.binding.chain_epoch += 1;
        changed_identity.structural_plan_commitment =
            structural_plan_commitment(&changed_identity.structural_plan)
                .expect("changed identity commitment");
        changed_identity
            .validate()
            .expect("individually valid changed snapshot identity");
        assert!(matches!(
            save_value_workflow(
                &mut store,
                revision,
                &changed_identity,
                PRODUCTION_NEXT_ACTIVE_TIME + 1,
            ),
            Err(ShakedexError::InvalidEvidence)
        ));

        let cancelled = workflow
            .terminate_prepared(ShakedexValueStage::Cancelled)
            .expect("cancel prepared FINALIZE");
        assert_eq!(
            save_value_workflow(
                &mut store,
                revision,
                &cancelled,
                PRODUCTION_NEXT_ACTIVE_TIME + 2,
            )
            .expect("advance FINALIZE"),
            revision + 1
        );
        let expired = workflow
            .terminate_prepared(ShakedexValueStage::Expired)
            .expect("expire stale FINALIZE");
        assert!(matches!(
            save_value_workflow(
                &mut store,
                revision,
                &expired,
                PRODUCTION_NEXT_ACTIVE_TIME + 3,
            ),
            Err(ShakedexError::StaleRevision)
        ));
    }

    #[test]
    fn production_next_script_finalize_wrong_parent_purpose_transfer_owner_and_renewal_fail() {
        let workflow = production_next_script_finalize_fixture();
        let canonical = serde_json::to_value(&workflow).expect("workflow JSON");

        let mut wrong_purpose = canonical.clone();
        wrong_purpose["funding_reservation"]["purpose"] = serde_json::json!("buyer_fulfillment");
        let mut wrong_purpose: ShakedexValueWorkflow =
            serde_json::from_value(wrong_purpose).expect("typed wrong purpose");
        production_next_refresh_structural_plan_commitment(&mut wrong_purpose);
        assert!(wrong_purpose.validate().is_err());

        let mut replaced_transfer = canonical.clone();
        replaced_transfer["structural_plan"]["transfer"]["transfer_transaction"]
            .as_array_mut()
            .expect("transfer bytes")[0] = serde_json::json!(0xff);
        let mut replaced_transfer: ShakedexValueWorkflow =
            serde_json::from_value(replaced_transfer).expect("typed replacement");
        production_next_refresh_structural_plan_commitment(&mut replaced_transfer);
        assert!(replaced_transfer.validate().is_err());

        let mut wrong_owner = canonical.clone();
        wrong_owner["structural_plan"]["transfer"]["owner_inclusion"]["height"] =
            serde_json::json!(201);
        let mut wrong_owner: ShakedexValueWorkflow =
            serde_json::from_value(wrong_owner).expect("typed wrong owner");
        production_next_refresh_structural_plan_commitment(&mut wrong_owner);
        assert!(wrong_owner.validate().is_err());

        let mut wrong_renewal = canonical.clone();
        wrong_renewal["structural_plan"]["transfer"]["renewal_block_hash"]
            .as_array_mut()
            .expect("renewal hash")[0] = serde_json::json!(0x67);
        let mut wrong_renewal: ShakedexValueWorkflow =
            serde_json::from_value(wrong_renewal).expect("typed wrong renewal");
        production_next_refresh_structural_plan_commitment(&mut wrong_renewal);
        assert!(wrong_renewal.validate().is_err());

        let mut wrong_parent_action = canonical;
        wrong_parent_action["structural_plan"]["parent"]["parent_action"] =
            serde_json::json!("seller_recovery");
        assert!(
            serde_json::from_value::<ShakedexValueWorkflow>(wrong_parent_action).is_err(),
            "a buyer parent cannot be retyped as seller recovery"
        );
    }

    #[test]
    fn production_next_script_finalize_reorg_and_finality_negatives_keep_reservations_protected() {
        let floor = binding(20, 500, 0x80);
        assert!(!snapshot_binding_not_older(binding(20, 499, 0x81), floor));
        assert!(!snapshot_binding_not_older(binding(20, 500, 0x82), floor));

        let expected = TransactionHash::new([0x83; 32]);
        let competitor = TransactionHash::new([0x84; 32]);
        let transaction_evidence = TransactionEvidence {
            binding: floor,
            mempool: MempoolSnapshotBinding {
                instance_nonce: [0x85; 32],
                generation: 3,
            },
            raw: None,
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 0,
                conflicted: true,
            },
            inclusion: None,
        };
        let mut spend_evidence = OutpointSpendEvidence {
            binding: floor,
            entries: vec![
                OutpointSpendEntry {
                    outpoint: HnsOutpoint {
                        transaction: TransactionHash::new([0x86; 32]),
                        output_index: 0,
                    },
                    spending: Some(SpendingTransactionEvidence {
                        transaction: competitor,
                        input_position: 0,
                        block_hash: [0x87; 32],
                        height: 499,
                    }),
                },
                OutpointSpendEntry {
                    outpoint: HnsOutpoint {
                        transaction: TransactionHash::new([0x88; 32]),
                        output_index: 1,
                    },
                    spending: None,
                },
            ],
        };
        assert!(matches!(
            terminal_release_reason(
                expected,
                3,
                &transaction_evidence,
                &spend_evidence,
                &[competitor],
            ),
            Err(ShakedexError::InvalidTransition)
        ));
        spend_evidence.entries[0]
            .spending
            .as_mut()
            .expect("competitor")
            .height = 498;
        assert!(matches!(
            terminal_release_reason(
                expected,
                3,
                &transaction_evidence,
                &spend_evidence,
                &[competitor],
            ),
            Ok(ShakedexReservationReleaseReason::ConfirmedCompetingSpend)
        ));

        let exact_inclusion = TransactionInclusion {
            block_hash: [0x89; 32],
            height: 498,
            transaction_index: Some(2),
        };
        let exact_evidence = TransactionEvidence {
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 3,
                conflicted: false,
            },
            inclusion: Some(exact_inclusion),
            ..transaction_evidence
        };
        spend_evidence.entries[0].spending = Some(SpendingTransactionEvidence {
            transaction: expected,
            input_position: 0,
            block_hash: exact_inclusion.block_hash,
            height: exact_inclusion.height,
        });
        spend_evidence.entries[1].spending = None;
        assert!(matches!(
            terminal_release_reason(expected, 3, &exact_evidence, &spend_evidence, &[]),
            Err(ShakedexError::InvalidEvidence)
        ));
        assert!(!valid_stage_transition(
            ShakedexValueStage::ReservationsReleased,
            ShakedexValueStage::RequiresRebroadcast,
        ));
    }

    #[test]
    fn hns_shakedex_value_child_identity_and_reorg_transitions() {
        let parent = WorkflowId::new([0x41; 16]);
        let buyer = shakedex_value_workflow_id(parent, ShakedexValueAction::BuyerFulfillment);
        let seller = shakedex_value_workflow_id(parent, ShakedexValueAction::SellerRecovery);
        let finalize =
            shakedex_value_workflow_id(parent, ShakedexValueAction::SellerScriptFinalize);
        assert_ne!(buyer, parent);
        assert_ne!(seller, parent);
        assert_ne!(finalize, parent);
        assert_ne!(buyer, seller);
        assert_ne!(buyer, finalize);
        assert_ne!(seller, finalize);
        assert_eq!(
            buyer,
            shakedex_value_workflow_id(parent, ShakedexValueAction::BuyerFulfillment)
        );

        assert!(valid_stage_transition(
            ShakedexValueStage::Conflicted,
            ShakedexValueStage::RequiresRebroadcast
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Conflicted,
            ShakedexValueStage::Confirmed
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Authorized,
            ShakedexValueStage::RequiresRebroadcast
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Authorized,
            ShakedexValueStage::Mempool
        ));
        assert!(!valid_stage_transition(
            ShakedexValueStage::Confirmed,
            ShakedexValueStage::Authorized
        ));

        let floor = binding(7, 500, 0x51);
        assert!(snapshot_binding_not_older(floor, floor));
        assert!(!snapshot_binding_not_older(binding(7, 499, 0x50), floor));
        assert!(!snapshot_binding_not_older(binding(7, 500, 0x52), floor));
        assert!(snapshot_binding_not_older(binding(8, 480, 0x53), floor));

        let mempool = MempoolSnapshotBinding {
            instance_nonce: [0x61; 32],
            generation: 9,
        };
        assert!(!mempool_binding_not_older(
            MempoolSnapshotBinding {
                generation: 8,
                ..mempool
            },
            mempool
        ));
        assert!(mempool_binding_not_older(
            MempoolSnapshotBinding {
                instance_nonce: [0x62; 32],
                generation: 0,
            },
            mempool
        ));

        let observation = ShakedexChainObservation {
            binding: floor,
            mempool,
            inclusion: None,
            in_mempool: false,
            confirmation_count: 0,
            conflicted: false,
            observed_at_unix: 1_800_000_500,
        };
        assert!(!submission_evidence_not_older(
            binding(7, 499, 0x50),
            mempool,
            observation.observed_at_unix,
            &observation,
        ));
        assert!(!submission_evidence_not_older(
            floor,
            MempoolSnapshotBinding {
                generation: 8,
                ..mempool
            },
            observation.observed_at_unix,
            &observation,
        ));
        assert!(!submission_evidence_not_older(
            floor,
            mempool,
            observation.observed_at_unix - 1,
            &observation,
        ));
        assert!(submission_evidence_not_older(
            binding(8, 480, 0x53),
            MempoolSnapshotBinding {
                instance_nonce: [0x62; 32],
                generation: 0,
            },
            observation.observed_at_unix,
            &observation,
        ));
    }

    #[test]
    fn production_tranche_hns_shakedex_terminal_release_requires_exact_spenders() {
        let expected = TransactionHash::new([0x71; 32]);
        let chain = binding(9, 500, 0x72);
        let mempool = MempoolSnapshotBinding {
            instance_nonce: [0x73; 32],
            generation: 4,
        };
        let inclusion = TransactionInclusion {
            block_hash: [0x74; 32],
            height: 498,
            transaction_index: Some(2),
        };
        let transaction_evidence = TransactionEvidence {
            binding: chain,
            mempool,
            raw: None,
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 3,
                conflicted: false,
            },
            inclusion: Some(inclusion),
        };
        let mut spend_evidence = OutpointSpendEvidence {
            binding: chain,
            entries: (0_u8..2)
                .map(|position| OutpointSpendEntry {
                    outpoint: HnsOutpoint {
                        transaction: TransactionHash::new([position.wrapping_add(1); 32]),
                        output_index: u32::from(position),
                    },
                    spending: Some(SpendingTransactionEvidence {
                        transaction: expected,
                        input_position: u32::from(position),
                        block_hash: inclusion.block_hash,
                        height: inclusion.height,
                    }),
                })
                .collect(),
        };
        assert!(matches!(
            terminal_release_reason(expected, 3, &transaction_evidence, &spend_evidence, &[],),
            Ok(ShakedexReservationReleaseReason::ExactTransactionConfirmed)
        ));

        spend_evidence.entries[1]
            .spending
            .as_mut()
            .expect("spending evidence")
            .input_position = 0;
        assert!(matches!(
            terminal_release_reason(expected, 3, &transaction_evidence, &spend_evidence, &[],),
            Err(ShakedexError::InvalidEvidence)
        ));
    }

    #[test]
    fn production_tranche_hns_shakedex_terminal_audit_requires_recovery_after_finality_loss() {
        let expected = TransactionHash::new([0x78; 32]);
        let chain = binding(11, 900, 0x79);
        let inclusion = TransactionInclusion {
            block_hash: [0x7a; 32],
            height: 899,
            transaction_index: Some(1),
        };
        let transaction_evidence = TransactionEvidence {
            binding: chain,
            mempool: MempoolSnapshotBinding {
                instance_nonce: [0x7b; 32],
                generation: 6,
            },
            raw: None,
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 2,
                conflicted: false,
            },
            inclusion: Some(inclusion),
        };
        let spend_evidence = OutpointSpendEvidence {
            binding: chain,
            entries: vec![OutpointSpendEntry {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([0x7c; 32]),
                    output_index: 0,
                },
                spending: Some(SpendingTransactionEvidence {
                    transaction: expected,
                    input_position: 0,
                    block_hash: inclusion.block_hash,
                    height: inclusion.height,
                }),
            }],
        };

        assert!(matches!(
            audit_terminal_release_reason(expected, 3, &transaction_evidence, &spend_evidence, &[],),
            Err(ShakedexError::RecoveryRequired)
        ));
    }

    #[test]
    fn production_tranche_hns_shakedex_terminal_release_requires_final_competitor() {
        let expected = TransactionHash::new([0x81; 32]);
        let competitor = TransactionHash::new([0x82; 32]);
        let chain = binding(10, 700, 0x83);
        let transaction_evidence = TransactionEvidence {
            binding: chain,
            mempool: MempoolSnapshotBinding {
                instance_nonce: [0x84; 32],
                generation: 5,
            },
            raw: None,
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 0,
                conflicted: true,
            },
            inclusion: None,
        };
        let mut spend_evidence = OutpointSpendEvidence {
            binding: chain,
            entries: vec![OutpointSpendEntry {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([0x85; 32]),
                    output_index: 1,
                },
                spending: Some(SpendingTransactionEvidence {
                    transaction: competitor,
                    input_position: 0,
                    block_hash: [0x86; 32],
                    height: 699,
                }),
            }],
        };
        assert!(matches!(
            terminal_release_reason(
                expected,
                3,
                &transaction_evidence,
                &spend_evidence,
                &[competitor],
            ),
            Err(ShakedexError::InvalidTransition)
        ));

        spend_evidence.entries[0]
            .spending
            .as_mut()
            .expect("competing spend")
            .height = 698;
        assert!(matches!(
            terminal_release_reason(
                expected,
                3,
                &transaction_evidence,
                &spend_evidence,
                &[competitor],
            ),
            Ok(ShakedexReservationReleaseReason::ConfirmedCompetingSpend)
        ));

        spend_evidence.binding = binding(10, 701, 0x87);
        assert!(matches!(
            terminal_release_reason(
                expected,
                3,
                &transaction_evidence,
                &spend_evidence,
                &[competitor],
            ),
            Err(ShakedexError::InvalidEvidence)
        ));
    }

    #[test]
    fn production_tranche_hns_shakedex_terminal_release_stage_is_irreversible() {
        for current in [
            ShakedexValueStage::Authorized,
            ShakedexValueStage::RequiresRebroadcast,
            ShakedexValueStage::Broadcast,
            ShakedexValueStage::Mempool,
            ShakedexValueStage::Confirming,
            ShakedexValueStage::Confirmed,
            ShakedexValueStage::Conflicted,
        ] {
            assert!(valid_stage_transition(
                current,
                ShakedexValueStage::ReservationsReleased
            ));
        }
        for next in [
            ShakedexValueStage::Authorized,
            ShakedexValueStage::RequiresRebroadcast,
            ShakedexValueStage::Broadcast,
            ShakedexValueStage::Mempool,
            ShakedexValueStage::Confirming,
            ShakedexValueStage::Confirmed,
            ShakedexValueStage::Conflicted,
            ShakedexValueStage::ReservationsReleased,
        ] {
            assert!(!valid_stage_transition(
                ShakedexValueStage::ReservationsReleased,
                next
            ));
        }
    }
}
