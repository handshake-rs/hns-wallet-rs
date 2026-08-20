//! Same-store native HNS signing composition.
//!
//! This module is deliberately a service/runtime join, not a second wallet
//! implementation. The HNS runtime remains the only component that prepares,
//! signs, persists, and broadcasts transactions. The service contributes the
//! hostile-page permission boundary and binds its exact approval identifier to
//! the encrypted, single-use approval consumed by the HNS runtime.

use std::collections::BTreeSet;

use hns_wallet_chain_api::{
    AuthorizeSend, BroadcastReceipt, BroadcastSend, ChainError, ChainModule, SendRequest,
};
use hns_wallet_ffi::{
    AccountSummary, ApprovalSummary, ApprovalWarning, NameMarketApprovalAction, ServiceCapability,
    ServiceErrorCode, ServiceFailure, WalletRequest, WalletResponse, WalletRuntimeStatus,
    WorkflowSummary,
};
use hns_wallet_hns::{
    HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED, HNS_VALUE_RUNTIME_RELEASE_QUALIFIED, HnsBackend,
    HnsClock, HnsNetwork, HnsRuntimeConfig, HnsWalletError, HnsWalletRuntime, KnownName,
    NameOperation, NameOperationState, PrepareNameFinalize, PrepareNameTransfer,
};
use hns_wallet_provider::{ApprovedCall, PendingApproval, ProviderMethod, SelectedNamespace};
use hns_wallet_shakedex::{
    MAX_SHAKEDEX_OFFER_PAGE_SIZE, PrepareBuyerTrade, PrepareScriptFinalize, PrepareSellerOffer,
    SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED, SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED,
    SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED, SellerOfferPreview, SellerOfferStage, ShakedexError,
    ShakedexOfferPage, ShakedexSellerPolicy, ShakedexTradePreview, ShakedexTradeRuntime,
    ShakedexValueAction, ShakedexValueStage,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::{
    AccountId, Amount, ApprovalId, ApprovalKind, BaseUnits, FinalityModel, ModuleId, ObjectHash,
    WalletAsset, WorkflowId,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    MAX_HNS_NAME_BYTES, MAX_JAVASCRIPT_SAFE_INTEGER, MAX_PROVIDER_HNS_READ_ITEMS,
    MAX_PUBLIC_STRING_BYTES, ServiceError, ServiceRuntime, WalletService, bounded_provider_value,
    hns_native_name_import_failure, hns_read_failure, hns_read_result_bound, hns_runtime_failure,
    invalid_request, is_printable_ascii, lowercase_hex, persistent_store_failure,
    public_hns_amount, public_hns_name_read, public_hns_name_summary, public_hns_receive_target,
    public_hns_transaction_summary, validate_empty_params, validate_hns_account_summary,
    validate_hns_wallet_read_scope, wallet_locked,
};

/// Trusted product inputs for a full HNS runtime that was opened over the
/// same unlocked store and then relocked before service construction.
pub struct PersistentHnsValueConfig<B, C> {
    pub runtime: HnsWalletRuntime<B, C>,
    pub account_label: String,
    pub shakedex: Option<PersistentShakedexConfig>,
}

/// Trusted installed-product policy for Shakedex. Website callers cannot
/// supply or override marketplace fee destinations or amounts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentShakedexConfig {
    pub seller_policy: ShakedexSellerPolicy,
}

impl Default for PersistentShakedexConfig {
    fn default() -> Self {
        Self {
            seller_policy: ShakedexSellerPolicy::no_marketplace_fee(),
        }
    }
}

/// Provider-capable HNS runtime with one exact account and one exact encrypted
/// store authority. There is no alternate signing store or caller-selected
/// wallet/account path.
pub struct PersistentHnsValueRuntime<B, C> {
    store: SharedWalletStore,
    runtime: HnsWalletRuntime<B, C>,
    account_label: String,
    configured: HnsRuntimeConfig,
    shakedex: Option<PersistentShakedexConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HnsSendParams {
    account: AccountId,
    recipient: String,
    amount: BaseUnits,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HnsTransferNameParams {
    account: AccountId,
    name: String,
    recipient: String,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HnsFinalizeNameParams {
    account: AccountId,
    name: String,
    expected_recipient: Option<String>,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HnsImportKnownNameParams {
    account: AccountId,
    name: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketListOffersParams {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketCreateOfferParams {
    account: String,
    name: String,
    price: BaseUnits,
    maximum_fee: BaseUnits,
    listing_lifetime_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketAcceptOfferParams {
    account: String,
    listing_id: String,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketSessionParams {
    account: String,
    session_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketFinalizeParams {
    account: String,
    session_id: String,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketSellerActionParams {
    account: String,
    seller_session_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NameMarketRecoverParams {
    account: String,
    seller_session_id: String,
    maximum_fee: BaseUnits,
}

struct PreparedSellerOfferCreation {
    params: NameMarketCreateOfferParams,
    seller: SellerOfferPreview,
    transfer: hns_wallet_hns::PreparedNameOperation,
}

impl<B: HnsBackend, C: HnsClock> PersistentHnsValueRuntime<B, C> {
    fn new(
        store: SharedWalletStore,
        config: PersistentHnsValueConfig<B, C>,
        configured: HnsRuntimeConfig,
    ) -> Self {
        Self {
            store,
            runtime: config.runtime,
            account_label: config.account_label,
            configured,
            shakedex: config.shakedex,
        }
    }

    fn status(&self) -> Result<WalletRuntimeStatus, ServiceFailure> {
        let locked = self.store.is_locked().map_err(persistent_store_failure)?;
        Ok(WalletRuntimeStatus {
            locked,
            active_wallet: (!locked).then_some(self.configured.wallet_id),
            enabled_modules: BTreeSet::from([ModuleId::Handshake]),
            mainnet_settlement_enabled: self.configured.network == HnsNetwork::Mainnet
                && self.configured.value_operations_enabled,
        })
    }

    fn exact_account(&self) -> Result<AccountSummary, ServiceFailure> {
        if self.store.is_locked().map_err(persistent_store_failure)? {
            return Err(wallet_locked());
        }
        let selected = self
            .runtime
            .selected_account_with_revision()
            .map_err(hns_runtime_failure)?;
        if selected.account.config != self.configured {
            return Err(hns_runtime_failure(
                HnsWalletError::AccountConfigurationMismatch,
            ));
        }
        let account = AccountSummary {
            account_id: selected.account.config.account_id,
            module: ModuleId::Handshake,
            label: self.account_label.clone(),
            receive_display: None,
        };
        validate_hns_account_summary(&account)?;
        Ok(account)
    }

    fn unlock(&self, passphrase: &str) -> Result<(), ServiceFailure> {
        self.store
            .unlock(passphrase)
            .map_err(persistent_store_failure)?;
        if let Err(error) = self
            .exact_account()
            .and_then(|_| self.recover_shakedex_startup())
        {
            self.store.lock().map_err(persistent_store_failure)?;
            return Err(error);
        }
        Ok(())
    }

    fn recover_shakedex_startup(&self) -> Result<(), ServiceFailure> {
        if !self.shakedex_available() {
            return Ok(());
        }
        self.runtime.reconcile().map_err(hns_read_failure)?;
        let trade = self.shakedex_runtime()?;
        trade.recover_startup().map_err(shakedex_failure)?;
        trade
            .recover_seller_publications()
            .map_err(shakedex_failure)?;
        Ok(())
    }

    fn reconcile(&self) -> Result<AccountSummary, ServiceFailure> {
        let before = self.exact_account()?;
        self.runtime.reconcile().map_err(hns_read_failure)?;
        let after = self.exact_account()?;
        if after != before {
            return Err(hns_read_failure(HnsWalletError::StaleAccountRead));
        }
        Ok(after)
    }

    fn assert_hns_call(&self, call: &ApprovedCall) -> Result<AccountSummary, ServiceFailure> {
        if call.namespace != SelectedNamespace::Hns || call.request_nonce == 0 {
            return Err(invalid_request(
                "value request does not match the active HNS namespace",
            ));
        }
        self.exact_account()
    }

    fn parse_account_params<T: DeserializeOwned>(
        &self,
        call: &ApprovedCall,
        account: impl FnOnce(&T) -> AccountId,
    ) -> Result<T, ServiceFailure> {
        let selected = self.assert_hns_call(call)?;
        let params: T = serde_json::from_value(call.params.clone())
            .map_err(|_| invalid_request("HNS value parameters are invalid"))?;
        if account(&params) != selected.account_id {
            return Err(invalid_request(
                "HNS value request does not match the selected account",
            ));
        }
        Ok(params)
    }

    fn shakedex_available(&self) -> bool {
        self.shakedex.is_some()
            && self.configured.settlement_enabled
            && HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
            && HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED
            && SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED
            && SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED
            && SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED
    }

    fn require_shakedex(&self) -> Result<&PersistentShakedexConfig, ServiceFailure> {
        if !self.shakedex_available() {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::DenuoShakedexV1,
            ));
        }
        self.shakedex
            .as_ref()
            .ok_or_else(|| ServiceFailure::unsupported(ServiceCapability::DenuoShakedexV1))
    }

    fn shakedex_runtime(&self) -> Result<ShakedexTradeRuntime<'_, B, C>, ServiceFailure> {
        self.require_shakedex()?;
        ShakedexTradeRuntime::new(&self.runtime, self.store.clone()).map_err(shakedex_failure)
    }

    fn parse_market_params<T: DeserializeOwned>(
        &self,
        call: &ApprovedCall,
        account: impl FnOnce(&T) -> &str,
    ) -> Result<T, ServiceFailure> {
        let selected = self.assert_hns_call(call)?;
        let params: T = serde_json::from_value(call.params.clone())
            .map_err(|_| invalid_request("name-market parameters are invalid"))?;
        if account(&params) != lowercase_hex(selected.account_id.as_bytes()) {
            return Err(invalid_request(
                "name-market request does not match the selected account",
            ));
        }
        Ok(params)
    }

    fn prepare_seller_offer_creation(
        &self,
        call: &ApprovedCall,
    ) -> Result<PreparedSellerOfferCreation, ServiceFailure> {
        let params = self.parse_market_params(call, |params: &NameMarketCreateOfferParams| {
            params.account.as_str()
        })?;
        if params.name.len() > MAX_HNS_NAME_BYTES
            || !is_printable_ascii(&params.name)
            || params.price.is_zero()
            || params.maximum_fee.is_zero()
            || params.listing_lifetime_seconds > MAX_JAVASCRIPT_SAFE_INTEGER
        {
            return Err(invalid_request("seller offer parameters are invalid"));
        }
        self.reconcile()?;
        let policy = &self.require_shakedex()?.seller_policy;
        let trade = self.shakedex_runtime()?;
        let seller = trade
            .prepare_seller_offer(
                PrepareSellerOffer {
                    name: params.name.as_bytes().to_vec(),
                    price: params.price,
                    request_nonce: call.request_nonce,
                    listing_lifetime_seconds: params.listing_lifetime_seconds,
                },
                policy,
            )
            .map_err(shakedex_failure)?;
        let transfer_nonce =
            shakedex_child_nonce(b"seller-name-lock", seller.workflow_id, call.request_nonce);
        let transfer = self
            .runtime
            .prepare_name_transfer(PrepareNameTransfer {
                account: self.configured.account_id,
                request_nonce: transfer_nonce,
                name: seller.name.clone(),
                recipient: seller.lock_address.clone(),
                maximum_fee: params.maximum_fee,
            })
            .map_err(hns_runtime_failure)?;
        if transfer.name != seller.name
            || transfer.recipient != seller.lock_address
            || transfer.maximum_fee != params.maximum_fee
        {
            return Err(invalid_request(
                "seller offer lock transfer does not match the prepared offer",
            ));
        }
        Ok(PreparedSellerOfferCreation {
            params,
            seller,
            transfer,
        })
    }

    fn prepare_buyer_trade(
        &self,
        call: &ApprovedCall,
    ) -> Result<(NameMarketAcceptOfferParams, ShakedexTradePreview), ServiceFailure> {
        let params = self.parse_market_params(call, |params: &NameMarketAcceptOfferParams| {
            params.account.as_str()
        })?;
        if params.maximum_fee.is_zero() {
            return Err(invalid_request("buyer maximum fee must be nonzero"));
        }
        let listing_hash = parse_object_hash(&params.listing_id, "listingId")?;
        self.reconcile()?;
        let preview = self
            .shakedex_runtime()?
            .prepare_buyer_fulfillment(PrepareBuyerTrade {
                listing_hash,
                request_nonce: call.request_nonce,
                maximum_fee: params.maximum_fee,
            })
            .map_err(shakedex_failure)?;
        Ok((params, preview))
    }

    fn prepare_script_finalize(
        &self,
        call: &ApprovedCall,
    ) -> Result<(NameMarketFinalizeParams, ShakedexTradePreview), ServiceFailure> {
        let params = self.parse_market_params(call, |params: &NameMarketFinalizeParams| {
            params.account.as_str()
        })?;
        if params.maximum_fee.is_zero() {
            return Err(invalid_request("finalize maximum fee must be nonzero"));
        }
        let parent_value_workflow_id = parse_workflow_id(&params.session_id, "sessionId")?;
        self.reconcile()?;
        let preview = self
            .shakedex_runtime()?
            .prepare_script_finalize(PrepareScriptFinalize {
                parent_value_workflow_id,
                maximum_fee: params.maximum_fee,
            })
            .map_err(shakedex_failure)?;
        Ok((params, preview))
    }

    fn prepare_seller_recovery(
        &self,
        call: &ApprovedCall,
    ) -> Result<
        (
            NameMarketRecoverParams,
            SellerOfferPreview,
            ShakedexTradePreview,
        ),
        ServiceFailure,
    > {
        let params = self.parse_market_params(call, |params: &NameMarketRecoverParams| {
            params.account.as_str()
        })?;
        if params.maximum_fee.is_zero() {
            return Err(invalid_request("recovery maximum fee must be nonzero"));
        }
        let seller_workflow_id = parse_workflow_id(&params.seller_session_id, "sellerSessionId")?;
        self.reconcile()?;
        let trade = self.shakedex_runtime()?;
        let seller = trade
            .load_seller_offer(seller_workflow_id)
            .map_err(shakedex_failure)?
            .ok_or_else(|| invalid_request("seller session is unknown"))?;
        let preview = trade
            .prepare_seller_offer_recovery(seller_workflow_id, params.maximum_fee)
            .map_err(shakedex_failure)?;
        Ok((params, seller, preview))
    }

    fn prepare_send(
        &self,
        call: &ApprovedCall,
    ) -> Result<(HnsSendParams, hns_wallet_chain_api::PreparedSend), ServiceFailure> {
        let params = self.parse_account_params(call, |params: &HnsSendParams| params.account)?;
        self.reconcile()?;
        let prepared = self
            .runtime
            .prepare_send(SendRequest {
                account: params.account,
                destination: params.recipient.clone(),
                amount: Amount {
                    asset: WalletAsset::Hns,
                    base_units: params.amount,
                },
                maximum_fee: params.maximum_fee,
                request_nonce: call.request_nonce,
            })
            .map_err(chain_failure)?;
        Ok((params, prepared))
    }

    fn prepare_transfer(
        &self,
        call: &ApprovedCall,
    ) -> Result<(HnsTransferNameParams, hns_wallet_hns::PreparedNameOperation), ServiceFailure>
    {
        let params =
            self.parse_account_params(call, |params: &HnsTransferNameParams| params.account)?;
        self.reconcile()?;
        let prepared = self
            .runtime
            .prepare_name_transfer(PrepareNameTransfer {
                account: params.account,
                request_nonce: call.request_nonce,
                name: params.name.as_bytes().to_vec(),
                recipient: params.recipient.clone(),
                maximum_fee: params.maximum_fee,
            })
            .map_err(hns_runtime_failure)?;
        Ok((params, prepared))
    }

    fn prepare_finalize(
        &self,
        call: &ApprovedCall,
    ) -> Result<(HnsFinalizeNameParams, hns_wallet_hns::PreparedNameOperation), ServiceFailure>
    {
        let params =
            self.parse_account_params(call, |params: &HnsFinalizeNameParams| params.account)?;
        self.reconcile()?;
        let prepared = self
            .runtime
            .prepare_name_finalize(PrepareNameFinalize {
                account: params.account,
                request_nonce: call.request_nonce,
                name: params.name.as_bytes().to_vec(),
                expected_recipient: params.expected_recipient.clone(),
                maximum_fee: params.maximum_fee,
            })
            .map_err(hns_runtime_failure)?;
        Ok((params, prepared))
    }

    fn current_names(&self) -> Result<Vec<KnownName>, ServiceFailure> {
        self.reconcile()?;
        self.runtime.list_names().map_err(hns_read_failure)
    }

    fn import_known_name(&self, call: &ApprovedCall) -> Result<Value, ServiceFailure> {
        let params =
            self.parse_account_params(call, |params: &HnsImportKnownNameParams| params.account)?;
        self.reconcile()?;
        let imported = self
            .runtime
            .import_name(params.name.as_bytes())
            .map_err(hns_native_name_import_failure)?;
        bounded_provider_value(json!({
            "name": public_hns_name_summary(&imported)?,
        }))
    }

    fn provider_balance(&self) -> Result<Value, ServiceFailure> {
        self.reconcile()?;
        let amount = self.runtime.balance().map_err(chain_failure)?;
        bounded_provider_value(json!({ "amount": public_hns_amount(amount)? }))
    }

    fn provider_history(&self) -> Result<Value, ServiceFailure> {
        self.reconcile()?;
        let transactions = self.runtime.transaction_history().map_err(chain_failure)?;
        if transactions.len() > MAX_PROVIDER_HNS_READ_ITEMS {
            return Err(hns_read_result_bound());
        }
        let transactions = transactions
            .iter()
            .map(public_hns_transaction_summary)
            .collect::<Result<Vec<_>, _>>()?;
        bounded_provider_value(json!({ "transactions": transactions }))
    }

    fn provider_receive_target(&self) -> Result<Value, ServiceFailure> {
        let selected = self.reconcile()?;
        let target = self.runtime.receive_target().map_err(chain_failure)?;
        bounded_provider_value(json!({
            "target": public_hns_receive_target(&target, selected.account_id)?,
        }))
    }

    fn provider_market_offers(&self, call: &ApprovedCall) -> Result<Value, ServiceFailure> {
        self.assert_hns_call(call)?;
        let params: NameMarketListOffersParams = if call.params.is_null() {
            NameMarketListOffersParams::default()
        } else {
            serde_json::from_value(call.params.clone())
                .map_err(|_| invalid_request("name-market list parameters are invalid"))?
        };
        let cursor = params
            .cursor
            .as_deref()
            .map(|cursor| parse_object_hash(cursor, "cursor"))
            .transpose()?;
        let limit = usize::from(params.limit.unwrap_or(32));
        if limit == 0 || limit > MAX_SHAKEDEX_OFFER_PAGE_SIZE {
            return Err(invalid_request("name-market page limit is invalid"));
        }
        self.reconcile()?;
        let page = self
            .shakedex_runtime()?
            .list_current_offers(cursor, limit)
            .map_err(shakedex_failure)?;
        public_offer_page(page)
    }

    fn provider_market_session(&self, call: &ApprovedCall) -> Result<Value, ServiceFailure> {
        let params = self.parse_market_params(call, |params: &NameMarketSessionParams| {
            params.account.as_str()
        })?;
        let session_id = parse_workflow_id(&params.session_id, "sessionId")?;
        self.reconcile()?;
        let trade = self.shakedex_runtime()?;
        if trade
            .load_seller_offer(session_id)
            .map_err(shakedex_failure)?
            .is_some()
        {
            let seller = trade
                .advance_seller_offer(session_id)
                .map_err(shakedex_failure)?;
            return bounded_provider_value(json!({
                "kind": "sellerOffer",
                "session": public_seller_offer(&seller)?,
            }));
        }
        let value = trade
            .refresh_preview(session_id)
            .map_err(shakedex_failure)?
            .ok_or_else(|| invalid_request("name-market session is unknown"))?;
        bounded_provider_value(json!({
            "kind": "trade",
            "session": public_trade_preview(&value)?,
        }))
    }

    fn prepare_cancel_offer(
        &self,
        call: &ApprovedCall,
    ) -> Result<(NameMarketSellerActionParams, SellerOfferPreview), ServiceFailure> {
        let params = self.parse_market_params(call, |params: &NameMarketSellerActionParams| {
            params.account.as_str()
        })?;
        let workflow_id = parse_workflow_id(&params.seller_session_id, "sellerSessionId")?;
        self.reconcile()?;
        let seller = self
            .shakedex_runtime()?
            .load_seller_offer(workflow_id)
            .map_err(shakedex_failure)?
            .ok_or_else(|| invalid_request("seller session is unknown"))?;
        if seller.stage != SellerOfferStage::PublicationQueued {
            return Err(invalid_request("seller offer is not cancellable"));
        }
        Ok((params, seller))
    }

    fn execute_approved_seller_creation(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
        approved_at_unix: u64,
    ) -> Result<Value, ServiceFailure> {
        let prepared = self.prepare_seller_offer_creation(call)?;
        let authorized = self
            .runtime
            .authorize_name_operation(approval_id, &prepared.transfer, approved_at_unix)
            .map_err(hns_runtime_failure)?;
        let receipt = self
            .runtime
            .broadcast_name_operation(&authorized)
            .map_err(hns_runtime_failure)?;
        if receipt.module != ModuleId::Handshake {
            return Err(invalid_request(
                "seller lock transfer receipt does not match Handshake",
            ));
        }
        bounded_provider_value(json!({
            "sellerSession": public_seller_offer(&prepared.seller)?,
            "lockTransfer": {
                "workflowId": lowercase_hex(prepared.transfer.workflow_id.as_bytes()),
                "txid": lowercase_hex(receipt.txid.as_bytes()),
                "acceptedAtUnix": public_safe_u64(receipt.accepted_at_unix, "acceptedAtUnix")?,
            },
        }))
    }

    fn execute_approved_buyer_trade(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
    ) -> Result<Value, ServiceFailure> {
        let (_, prepared) = self.prepare_buyer_trade(call)?;
        let trade = self.shakedex_runtime()?;
        let authorized = trade
            .authorize(prepared.workflow_id, approval_id, call.origin.as_str())
            .map_err(shakedex_failure)?;
        let submitted = trade
            .submit(authorized.workflow_id)
            .map_err(shakedex_failure)?;
        public_trade_preview(&submitted)
    }

    fn execute_approved_script_finalize(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
    ) -> Result<Value, ServiceFailure> {
        let (_, prepared) = self.prepare_script_finalize(call)?;
        let trade = self.shakedex_runtime()?;
        let authorized = trade
            .authorize(prepared.workflow_id, approval_id, call.origin.as_str())
            .map_err(shakedex_failure)?;
        let submitted = trade
            .submit(authorized.workflow_id)
            .map_err(shakedex_failure)?;
        public_trade_preview(&submitted)
    }

    fn execute_approved_cancel_offer(&self, call: &ApprovedCall) -> Result<Value, ServiceFailure> {
        let (params, _) = self.prepare_cancel_offer(call)?;
        let workflow_id = parse_workflow_id(&params.seller_session_id, "sellerSessionId")?;
        let cancelled = self
            .shakedex_runtime()?
            .cancel_seller_offer(workflow_id)
            .map_err(shakedex_failure)?;
        public_seller_offer(&cancelled)
    }

    fn execute_approved_seller_recovery(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
    ) -> Result<Value, ServiceFailure> {
        let (_, _, prepared) = self.prepare_seller_recovery(call)?;
        let trade = self.shakedex_runtime()?;
        let authorized = trade
            .authorize(prepared.workflow_id, approval_id, call.origin.as_str())
            .map_err(shakedex_failure)?;
        let submitted = trade
            .submit(authorized.workflow_id)
            .map_err(shakedex_failure)?;
        public_trade_preview(&submitted)
    }

    fn name_workflow_summary(operation: NameOperation) -> WorkflowSummary {
        let (state, next_action, terminal) = match operation.state {
            NameOperationState::Prepared => ("prepared", Some("approve"), false),
            NameOperationState::Authorized => ("authorized", Some("broadcast"), false),
            NameOperationState::RequiresRebroadcast => {
                ("requiresRebroadcast", Some("rebroadcast"), false)
            }
            NameOperationState::Broadcast => ("broadcast", Some("waitForMempool"), false),
            NameOperationState::Mempool => ("mempool", Some("waitForConfirmation"), false),
            NameOperationState::TransferLocked => {
                ("transferLocked", Some("waitForFinalizeHeight"), false)
            }
            NameOperationState::FinalizeEligible => ("finalizeEligible", Some("finalize"), false),
            NameOperationState::ReapprovalRequired => {
                ("reapprovalRequired", Some("prepareAgain"), false)
            }
            NameOperationState::Finalized => ("finalized", None, true),
            NameOperationState::TransferCancelled => ("transferCancelled", None, true),
            NameOperationState::Conflicted => ("conflicted", None, true),
            NameOperationState::Expired => ("expired", None, true),
            NameOperationState::Cancelled => ("cancelled", None, true),
        };
        WorkflowSummary {
            workflow_id: operation.workflow_id,
            state: state.to_owned(),
            next_action: next_action.map(str::to_owned),
            terminal,
        }
    }

    fn execute_approved_send(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
        approved_at_unix: u64,
    ) -> Result<Value, ServiceFailure> {
        let (_, prepared) = self.prepare_send(call)?;
        let authorized = self
            .runtime
            .authorize_send(AuthorizeSend {
                prepared,
                approval_id,
                approved_at_unix,
            })
            .map_err(chain_failure)?;
        let receipt = self
            .runtime
            .broadcast_send(BroadcastSend { authorized })
            .map_err(chain_failure)?;
        provider_broadcast_receipt(receipt, call.request_nonce, None)
    }

    fn execute_approved_transfer(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
        approved_at_unix: u64,
    ) -> Result<Value, ServiceFailure> {
        let (_, prepared) = self.prepare_transfer(call)?;
        let workflow_id = prepared.workflow_id;
        let authorized = self
            .runtime
            .authorize_name_operation(approval_id, &prepared, approved_at_unix)
            .map_err(hns_runtime_failure)?;
        let receipt = self
            .runtime
            .broadcast_name_operation(&authorized)
            .map_err(hns_runtime_failure)?;
        provider_broadcast_receipt(receipt, call.request_nonce, Some(workflow_id.to_string()))
    }

    fn execute_approved_finalize(
        &self,
        call: &ApprovedCall,
        approval_id: ApprovalId,
        approved_at_unix: u64,
    ) -> Result<Value, ServiceFailure> {
        let (_, prepared) = self.prepare_finalize(call)?;
        let workflow_id = prepared.workflow_id;
        let authorized = self
            .runtime
            .authorize_name_operation(approval_id, &prepared, approved_at_unix)
            .map_err(hns_runtime_failure)?;
        let receipt = self
            .runtime
            .broadcast_name_operation(&authorized)
            .map_err(hns_runtime_failure)?;
        provider_broadcast_receipt(receipt, call.request_nonce, Some(workflow_id.to_string()))
    }
}

impl<B: HnsBackend, C: HnsClock> ServiceRuntime for PersistentHnsValueRuntime<B, C> {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        let mut capabilities = BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
            ServiceCapability::HnsWalletAuthorityContextV1,
            ServiceCapability::HnsValueOperationsV1,
            ServiceCapability::ProviderDispatch,
            ServiceCapability::ValueMovement,
        ]);
        if self.shakedex_available() {
            capabilities.insert(ServiceCapability::DenuoShakedexV1);
        }
        capabilities
    }

    fn supports_provider_method(&self, method: ProviderMethod) -> bool {
        matches!(
            method,
            ProviderMethod::WalletGetStatus
                | ProviderMethod::HnsRequestAccounts
                | ProviderMethod::HnsGetBalance
                | ProviderMethod::HnsGetTransactions
                | ProviderMethod::HnsGetReceiveAddress
                | ProviderMethod::HnsSend
                | ProviderMethod::HnsGetNames
                | ProviderMethod::HnsGetName
                | ProviderMethod::HnsImportKnownName
                | ProviderMethod::HnsTransferName
                | ProviderMethod::HnsFinalizeName
        ) || (self.shakedex_available()
            && matches!(
                method,
                ProviderMethod::NameMarketListOffers
                    | ProviderMethod::NameMarketCreateFixedPriceOffer
                    | ProviderMethod::NameMarketCancelOffer
                    | ProviderMethod::NameMarketAcceptOffer
                    | ProviderMethod::NameMarketGetSession
                    | ProviderMethod::NameMarketFinalizePurchase
                    | ProviderMethod::NameMarketRecoverName
            ))
    }

    fn prepare_approval(
        &mut self,
        approval: &PendingApproval,
    ) -> Result<ApprovalSummary, ServiceFailure> {
        match (approval.kind, approval.call.method) {
            (ApprovalKind::Send, ProviderMethod::HnsSend) => {
                let (params, prepared) = self.prepare_send(&approval.call)?;
                self.runtime
                    .register_send_approval(
                        approval.id,
                        approval.call.origin.as_str(),
                        &prepared,
                        approval.expires_at_unix,
                    )
                    .map_err(hns_runtime_failure)?;
                Ok(ApprovalSummary::Send {
                    amount: prepared.amount,
                    recipient: prepared.destination,
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: params.maximum_fee,
                    },
                    chain: ModuleId::Handshake,
                    finality: FinalityModel::ProofOfWorkConfirmations,
                    warnings: BTreeSet::from([ApprovalWarning::FeeEstimateMayChange]),
                })
            }
            (ApprovalKind::NameTransfer, ProviderMethod::HnsTransferName) => {
                let (_, prepared) = self.prepare_transfer(&approval.call)?;
                self.runtime
                    .register_name_operation_approval(
                        approval.id,
                        approval.call.origin.as_str(),
                        &prepared,
                        approval.expires_at_unix,
                    )
                    .map_err(hns_runtime_failure)?;
                Ok(ApprovalSummary::NameTransfer {
                    name: prepared_name_text(&prepared.name)?,
                    recipient: prepared.recipient,
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: prepared.maximum_fee,
                    },
                    warnings: BTreeSet::from([
                        ApprovalWarning::FeeEstimateMayChange,
                        ApprovalWarning::NameTransferIsIrreversible,
                    ]),
                })
            }
            (ApprovalKind::NameFinalize, ProviderMethod::HnsFinalizeName) => {
                let (_, prepared) = self.prepare_finalize(&approval.call)?;
                self.runtime
                    .register_name_operation_approval(
                        approval.id,
                        approval.call.origin.as_str(),
                        &prepared,
                        approval.expires_at_unix,
                    )
                    .map_err(hns_runtime_failure)?;
                Ok(ApprovalSummary::NameFinalize {
                    name: prepared_name_text(&prepared.name)?,
                    recipient: prepared.recipient,
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: prepared.maximum_fee,
                    },
                    warnings: BTreeSet::from([ApprovalWarning::FeeEstimateMayChange]),
                })
            }
            (ApprovalKind::NameMarketOffer, ProviderMethod::NameMarketCreateFixedPriceOffer) => {
                let prepared = self.prepare_seller_offer_creation(&approval.call)?;
                self.runtime
                    .register_name_operation_approval(
                        approval.id,
                        approval.call.origin.as_str(),
                        &prepared.transfer,
                        approval.expires_at_unix,
                    )
                    .map_err(hns_runtime_failure)?;
                Ok(ApprovalSummary::NameMarketOffer {
                    action: NameMarketApprovalAction::Create,
                    name: prepared.params.name,
                    listing_id: None,
                    price: Amount {
                        asset: WalletAsset::Hns,
                        base_units: prepared.params.price,
                    },
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: prepared.params.maximum_fee,
                    },
                    warnings: BTreeSet::from([
                        ApprovalWarning::FeeEstimateMayChange,
                        ApprovalWarning::NameTransferIsIrreversible,
                        ApprovalWarning::SettlementCanBeDelayed,
                    ]),
                })
            }
            (ApprovalKind::NameMarketOffer, ProviderMethod::NameMarketCancelOffer) => {
                let (_, seller) = self.prepare_cancel_offer(&approval.call)?;
                Ok(ApprovalSummary::NameMarketOffer {
                    action: NameMarketApprovalAction::Cancel,
                    name: prepared_name_text(&seller.name)?,
                    listing_id: seller
                        .listing_hash
                        .map(|hash| lowercase_hex(hash.as_bytes())),
                    price: Amount {
                        asset: WalletAsset::Hns,
                        base_units: seller.price,
                    },
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: BaseUnits::ZERO,
                    },
                    warnings: BTreeSet::new(),
                })
            }
            (ApprovalKind::NameMarketPurchase, ProviderMethod::NameMarketAcceptOffer) => {
                let (params, prepared) = self.prepare_buyer_trade(&approval.call)?;
                self.shakedex_runtime()?
                    .register_approval(
                        prepared.workflow_id,
                        approval.id,
                        approval.call.origin.as_str(),
                        approval.expires_at_unix,
                    )
                    .map_err(shakedex_failure)?;
                Ok(ApprovalSummary::NameMarketPurchase {
                    name: prepared_name_text(&prepared.name)?,
                    listing_id: params.listing_id,
                    payment: Amount {
                        asset: WalletAsset::Hns,
                        base_units: shakedex_purchase_payment(&prepared)?,
                    },
                    recipient: prepared
                        .seller_payment_address
                        .ok_or_else(|| invalid_request("buyer trade has no seller payment"))?,
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: params.maximum_fee,
                    },
                    warnings: BTreeSet::from([
                        ApprovalWarning::FeeEstimateMayChange,
                        ApprovalWarning::SettlementCanBeDelayed,
                    ]),
                })
            }
            (ApprovalKind::NameMarketPurchase, ProviderMethod::NameMarketFinalizePurchase) => {
                let (params, prepared) = self.prepare_script_finalize(&approval.call)?;
                self.shakedex_runtime()?
                    .register_approval(
                        prepared.workflow_id,
                        approval.id,
                        approval.call.origin.as_str(),
                        approval.expires_at_unix,
                    )
                    .map_err(shakedex_failure)?;
                Ok(ApprovalSummary::NameMarketPurchase {
                    name: prepared_name_text(&prepared.name)?,
                    listing_id: prepared
                        .listing_hash
                        .map(|hash| lowercase_hex(hash.as_bytes()))
                        .unwrap_or(params.session_id),
                    payment: Amount {
                        asset: WalletAsset::Hns,
                        base_units: shakedex_purchase_payment(&prepared)?,
                    },
                    recipient: prepared.recipient,
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: params.maximum_fee,
                    },
                    warnings: BTreeSet::from([
                        ApprovalWarning::FeeEstimateMayChange,
                        ApprovalWarning::SettlementCanBeDelayed,
                    ]),
                })
            }
            (ApprovalKind::NameMarketOffer, ProviderMethod::NameMarketRecoverName) => {
                let (params, seller, prepared) = self.prepare_seller_recovery(&approval.call)?;
                self.shakedex_runtime()?
                    .register_approval(
                        prepared.workflow_id,
                        approval.id,
                        approval.call.origin.as_str(),
                        approval.expires_at_unix,
                    )
                    .map_err(shakedex_failure)?;
                Ok(ApprovalSummary::NameMarketOffer {
                    action: NameMarketApprovalAction::Recover,
                    name: prepared_name_text(&seller.name)?,
                    listing_id: seller
                        .listing_hash
                        .map(|hash| lowercase_hex(hash.as_bytes())),
                    price: Amount {
                        asset: WalletAsset::Hns,
                        base_units: seller.price,
                    },
                    maximum_fee: Amount {
                        asset: WalletAsset::Hns,
                        base_units: params.maximum_fee,
                    },
                    warnings: BTreeSet::from([
                        ApprovalWarning::FeeEstimateMayChange,
                        ApprovalWarning::RefundRequiresManualAction,
                        ApprovalWarning::SettlementCanBeDelayed,
                    ]),
                })
            }
            _ => Err(ServiceFailure::unsupported(
                ServiceCapability::HnsValueOperationsV1,
            )),
        }
    }

    fn prepare_hns_account_grant(
        &mut self,
        _: &ApprovedCall,
    ) -> Result<AccountSummary, ServiceFailure> {
        self.exact_account()
    }

    fn selected_hns_account(&self) -> Result<AccountSummary, ServiceFailure> {
        self.exact_account()
    }

    fn current_hns_names(&mut self) -> Result<Vec<KnownName>, ServiceFailure> {
        self.current_names()
    }

    fn execute_hns_name_read(
        &mut self,
        call: ApprovedCall,
        approved_names: &BTreeSet<[u8; 32]>,
    ) -> Result<Value, ServiceFailure> {
        let names = self.current_names()?;
        public_hns_name_read(&call, approved_names, &names)
    }

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure> {
        match call.method {
            ProviderMethod::WalletGetStatus => {
                validate_empty_params(&call.params)?;
                serde_json::to_value(self.status()?)
                    .map_err(|_| invalid_request("wallet status encoding failed"))
            }
            ProviderMethod::HnsGetBalance => {
                validate_empty_params(&call.params)?;
                self.provider_balance()
            }
            ProviderMethod::HnsGetTransactions => {
                validate_empty_params(&call.params)?;
                self.provider_history()
            }
            ProviderMethod::HnsGetReceiveAddress => {
                validate_empty_params(&call.params)?;
                self.provider_receive_target()
            }
            ProviderMethod::HnsImportKnownName => self.import_known_name(&call),
            ProviderMethod::NameMarketListOffers => self.provider_market_offers(&call),
            ProviderMethod::NameMarketGetSession => self.provider_market_session(&call),
            ProviderMethod::HnsGetNames | ProviderMethod::HnsGetName => Err(
                ServiceFailure::unsupported(ServiceCapability::ProviderDispatch),
            ),
            ProviderMethod::HnsSend
            | ProviderMethod::HnsTransferName
            | ProviderMethod::HnsFinalizeName
            | ProviderMethod::NameMarketCreateFixedPriceOffer
            | ProviderMethod::NameMarketCancelOffer
            | ProviderMethod::NameMarketAcceptOffer
            | ProviderMethod::NameMarketFinalizePurchase
            | ProviderMethod::NameMarketRecoverName => Err(ServiceFailure::unsupported(
                ServiceCapability::StructuredApprovals,
            )),
            _ => Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            )),
        }
    }

    fn execute_approved_provider(
        &mut self,
        call: ApprovedCall,
        approval_id: ApprovalId,
        approved_at_unix: u64,
    ) -> Result<Value, ServiceFailure> {
        if approval_id.into_bytes().iter().all(|byte| *byte == 0) {
            return Err(invalid_request("provider approval identifier is invalid"));
        }
        match call.method {
            ProviderMethod::HnsSend => {
                self.execute_approved_send(&call, approval_id, approved_at_unix)
            }
            ProviderMethod::HnsTransferName => {
                self.execute_approved_transfer(&call, approval_id, approved_at_unix)
            }
            ProviderMethod::HnsFinalizeName => {
                self.execute_approved_finalize(&call, approval_id, approved_at_unix)
            }
            ProviderMethod::NameMarketCreateFixedPriceOffer => {
                self.execute_approved_seller_creation(&call, approval_id, approved_at_unix)
            }
            ProviderMethod::NameMarketCancelOffer => self.execute_approved_cancel_offer(&call),
            ProviderMethod::NameMarketAcceptOffer => {
                self.execute_approved_buyer_trade(&call, approval_id)
            }
            ProviderMethod::NameMarketFinalizePurchase => {
                self.execute_approved_script_finalize(&call, approval_id)
            }
            ProviderMethod::NameMarketRecoverName => {
                self.execute_approved_seller_recovery(&call, approval_id)
            }
            _ => self.execute_provider(call),
        }
    }

    fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
        self.store.lock().map_err(persistent_store_failure)
    }

    fn execute_wallet(&mut self, request: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
        match request {
            WalletRequest::Status => Ok(WalletResponse::Status {
                status: self.status()?,
            }),
            WalletRequest::Unlock { passphrase } => {
                self.unlock(passphrase.expose_secret())?;
                Ok(WalletResponse::Unlocked)
            }
            WalletRequest::Lock => {
                self.lock_wallet()?;
                Ok(WalletResponse::Locked)
            }
            WalletRequest::ListAccounts => Ok(WalletResponse::Accounts {
                accounts: vec![self.exact_account()?],
            }),
            WalletRequest::Balance { module, account } => {
                let selected = self.reconcile()?;
                validate_hns_wallet_read_scope(module, account, selected.account_id)?;
                Ok(WalletResponse::Balance {
                    amount: self.runtime.balance().map_err(chain_failure)?,
                })
            }
            WalletRequest::ReceiveTarget { module, account } => {
                let selected = self.reconcile()?;
                validate_hns_wallet_read_scope(module, account, selected.account_id)?;
                Ok(WalletResponse::ReceiveTarget {
                    target: self.runtime.receive_target().map_err(chain_failure)?,
                })
            }
            WalletRequest::TransactionHistory { module, account } => {
                let selected = self.reconcile()?;
                validate_hns_wallet_read_scope(module, account, selected.account_id)?;
                let transactions = self.runtime.transaction_history().map_err(chain_failure)?;
                if transactions.len() > MAX_PROVIDER_HNS_READ_ITEMS {
                    return Err(hns_read_result_bound());
                }
                Ok(WalletResponse::TransactionHistory { transactions })
            }
            WalletRequest::ModuleStatus {
                module: ModuleId::Handshake,
            } => {
                self.reconcile()?;
                Ok(WalletResponse::ModuleStatus {
                    status: self.runtime.sync_status(),
                })
            }
            WalletRequest::WorkflowStatus { workflow_id } => {
                let operation = self
                    .runtime
                    .get_name_operation(workflow_id)
                    .map_err(hns_runtime_failure)?
                    .ok_or_else(|| invalid_request("HNS workflow is unknown"))?;
                Ok(WalletResponse::Workflow {
                    summary: Self::name_workflow_summary(operation),
                })
            }
            WalletRequest::CreateWallet { .. }
            | WalletRequest::RestoreWallet { .. }
            | WalletRequest::ModuleStatus { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
        }
    }
}

impl<B: HnsBackend, C: HnsClock> WalletService<SharedWalletStore, PersistentHnsValueRuntime<B, C>> {
    /// Compose the hostile-page provider and the full HNS signing runtime over
    /// one literal SharedWalletStore authority. The runtime must have been
    /// opened while that store was privately unlocked; construction is
    /// accepted only after the caller has relocked it.
    pub fn new_persistent_hns_value(
        store: SharedWalletStore,
        config: PersistentHnsValueConfig<B, C>,
    ) -> Result<Self, ServiceError> {
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked);
        }
        if !config.runtime.shares_store_authority(&store) {
            return Err(ServiceError::PersistentStoreAuthorityMismatch);
        }
        let configured = config
            .runtime
            .configured_runtime_config()
            .map_err(|_| ServiceError::InvalidPersistentHnsAccount)?;
        if !configured.value_operations_enabled
            || config.account_label.is_empty()
            || config.account_label.len() > MAX_PUBLIC_STRING_BYTES
            || !is_printable_ascii(&config.account_label)
        {
            return Err(ServiceError::InvalidPersistentHnsAccount);
        }
        if config.shakedex.as_ref().is_some_and(|shakedex| {
            !configured.settlement_enabled || shakedex.seller_policy.validate().is_err()
        }) {
            return Err(ServiceError::InvalidPersistentHnsAccount);
        }
        configured
            .validate()
            .map_err(|_| ServiceError::InvalidPersistentHnsAccount)?;
        let runtime = PersistentHnsValueRuntime::new(store.clone(), config, configured);
        Self::new(store, runtime, true)
    }
}

fn shakedex_child_nonce(domain: &[u8], workflow_id: WorkflowId, request_nonce: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-service/shakedex-child-nonce/v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(workflow_id.as_bytes());
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut nonce_bytes = [0_u8; 8];
    nonce_bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(nonce_bytes).max(1)
}

fn parse_lowercase_hex<const N: usize>(
    encoded: &str,
    field: &str,
) -> Result<[u8; N], ServiceFailure> {
    if encoded.len() != N * 2 {
        return Err(invalid_request(&format!(
            "{field} must be {}-byte lowercase hexadecimal",
            N
        )));
    }
    let mut output = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = decode(pair[0])
            .ok_or_else(|| invalid_request(&format!("{field} is not canonical hexadecimal")))?;
        let low = decode(pair[1])
            .ok_or_else(|| invalid_request(&format!("{field} is not canonical hexadecimal")))?;
        output[index] = (high << 4) | low;
    }
    if output.iter().all(|byte| *byte == 0) {
        return Err(invalid_request(&format!("{field} cannot be zero")));
    }
    Ok(output)
}

fn parse_object_hash(encoded: &str, field: &str) -> Result<ObjectHash, ServiceFailure> {
    Ok(ObjectHash::new(parse_lowercase_hex(encoded, field)?))
}

fn parse_workflow_id(encoded: &str, field: &str) -> Result<WorkflowId, ServiceFailure> {
    Ok(WorkflowId::new(parse_lowercase_hex(encoded, field)?))
}

fn public_safe_u64(value: u64, field: &str) -> Result<u64, ServiceFailure> {
    if value > MAX_JAVASCRIPT_SAFE_INTEGER {
        return Err(invalid_request(&format!(
            "{field} exceeds JavaScript integer precision"
        )));
    }
    Ok(value)
}

fn seller_stage(stage: SellerOfferStage) -> &'static str {
    match stage {
        SellerOfferStage::NameLockRequired => "nameLockRequired",
        SellerOfferStage::PublicationQueued => "publicationQueued",
        SellerOfferStage::CancellationQueued => "cancellationQueued",
    }
}

fn publication_state(state: hns_wallet_shakedex::DenuoOutboxState) -> &'static str {
    use hns_wallet_shakedex::DenuoOutboxState;

    match state {
        DenuoOutboxState::Pending => "pending",
        DenuoOutboxState::HandoffPrepared { .. } => "handoffPrepared",
        DenuoOutboxState::RetryScheduled { .. } => "retryScheduled",
        DenuoOutboxState::RelayAccepted { .. } => "relayAccepted",
        DenuoOutboxState::Acknowledged { .. } => "acknowledged",
        DenuoOutboxState::Exhausted { .. } => "exhausted",
    }
}

fn public_seller_offer(preview: &SellerOfferPreview) -> Result<Value, ServiceFailure> {
    bounded_provider_value(json!({
        "revision": public_safe_u64(preview.revision, "revision")?,
        "sessionId": lowercase_hex(preview.workflow_id.as_bytes()),
        "requestNonce": preview.request_nonce.to_string(),
        "stage": seller_stage(preview.stage),
        "name": prepared_name_text(&preview.name)?,
        "price": preview.price.get().to_string(),
        "lockAddress": preview.lock_address,
        "listingLifetimeSeconds": public_safe_u64(
            preview.listing_lifetime_seconds,
            "listingLifetimeSeconds",
        )?,
        "listingId": preview
            .listing_hash
            .map(|hash| lowercase_hex(hash.as_bytes())),
        "cancellationId": preview
            .cancellation_hash
            .map(|hash| lowercase_hex(hash.as_bytes())),
        "publicationState": preview.publication_state.map(publication_state),
    }))
}

fn trade_action(action: ShakedexValueAction) -> &'static str {
    match action {
        ShakedexValueAction::BuyerFulfillment => "buyerFulfillment",
        ShakedexValueAction::SellerRecovery => "sellerRecovery",
        ShakedexValueAction::SellerScriptFinalize => "scriptFinalize",
    }
}

fn trade_stage(stage: ShakedexValueStage) -> &'static str {
    match stage {
        ShakedexValueStage::Prepared => "prepared",
        ShakedexValueStage::Authorized => "authorized",
        ShakedexValueStage::RequiresRebroadcast => "requiresRebroadcast",
        ShakedexValueStage::Broadcast => "broadcast",
        ShakedexValueStage::Mempool => "mempool",
        ShakedexValueStage::Confirming => "confirming",
        ShakedexValueStage::Confirmed => "confirmed",
        ShakedexValueStage::Conflicted => "conflicted",
        ShakedexValueStage::ReservationsReleased => "reservationsReleased",
        ShakedexValueStage::Expired => "expired",
        ShakedexValueStage::Cancelled => "cancelled",
    }
}

fn public_trade_preview(preview: &ShakedexTradePreview) -> Result<Value, ServiceFailure> {
    bounded_provider_value(json!({
        "revision": public_safe_u64(preview.revision, "revision")?,
        "sessionId": lowercase_hex(preview.workflow_id.as_bytes()),
        "parentSessionId": lowercase_hex(preview.parent_workflow_id.as_bytes()),
        "action": trade_action(preview.action),
        "stage": trade_stage(preview.stage),
        "name": prepared_name_text(&preview.name)?,
        "listingId": preview.listing_hash.map(|hash| lowercase_hex(hash.as_bytes())),
        "tradeValue": preview.trade_value.get().to_string(),
        "purchasePrice": preview.purchase_price.map(|price| price.get().to_string()),
        "marketplaceFee": preview.marketplace_fee.get().to_string(),
        "networkFee": preview.network_fee.get().to_string(),
        "maximumNetworkFee": preview.maximum_network_fee.get().to_string(),
        "expiresAtUnix": public_safe_u64(preview.expires_at_unix, "expiresAtUnix")?,
        "recipient": preview.recipient,
        "sellerPaymentAddress": preview.seller_payment_address,
        "txid": preview.transaction.map(|txid| lowercase_hex(txid.as_bytes())),
    }))
}

fn public_offer_page(page: ShakedexOfferPage) -> Result<Value, ServiceFailure> {
    let offers = page
        .offers
        .into_iter()
        .map(|offer| {
            Ok(json!({
                "listingId": lowercase_hex(offer.listing_hash.as_bytes()),
                "name": prepared_name_text(&offer.name)?,
                "price": offer.price.get().to_string(),
                "marketplaceFee": offer.marketplace_fee.get().to_string(),
                "sellerPaymentAddress": offer.seller_payment_address,
                "createdAtUnix": public_safe_u64(offer.created_at_unix, "createdAtUnix")?,
                "expiresAtUnix": public_safe_u64(offer.expires_at_unix, "expiresAtUnix")?,
            }))
        })
        .collect::<Result<Vec<_>, ServiceFailure>>()?;
    bounded_provider_value(json!({
        "boardRevision": public_safe_u64(page.board_revision, "boardRevision")?,
        "offers": offers,
        "nextCursor": page.next_cursor.map(|hash| lowercase_hex(hash.as_bytes())),
    }))
}

fn shakedex_purchase_payment(preview: &ShakedexTradePreview) -> Result<BaseUnits, ServiceFailure> {
    let price = preview
        .purchase_price
        .ok_or_else(|| invalid_request("trade has no authenticated purchase price"))?;
    price
        .checked_add(preview.marketplace_fee)
        .map_err(|_| invalid_request("purchase payment overflows"))
}

fn shakedex_failure(error: ShakedexError) -> ServiceFailure {
    match error {
        ShakedexError::CanonicalProtocolUnavailable
        | ShakedexError::DenuoProtocolUnavailable
        | ShakedexError::ValueRuntimeUnavailable => {
            ServiceFailure::unsupported(ServiceCapability::DenuoShakedexV1)
        }
        ShakedexError::ApprovalRequired => ServiceFailure {
            code: ServiceErrorCode::ApprovalStale,
            message: "Shakedex approval is missing, stale, or mismatched".to_owned(),
            unsupported_capability: None,
        },
        ShakedexError::InvalidName
        | ShakedexError::InvalidListing
        | ShakedexError::InvalidCancellation
        | ShakedexError::InvalidDenuoEnvelope
        | ShakedexError::DenuoRegistryMismatch
        | ShakedexError::InvalidTransition => {
            invalid_request("name-market request or current state is invalid")
        }
        ShakedexError::Persistence
        | ShakedexError::CorruptNameMarketBoard
        | ShakedexError::CorruptDenuoOutbox => ServiceFailure {
            code: ServiceErrorCode::PersistenceFailure,
            message: "persisted Shakedex state failed authentication".to_owned(),
            unsupported_capability: None,
        },
        _ => ServiceFailure {
            code: ServiceErrorCode::RuntimeFailure,
            message: "Shakedex runtime could not complete the requested operation".to_owned(),
            unsupported_capability: None,
        },
    }
}

fn prepared_name_text(name: &[u8]) -> Result<String, ServiceFailure> {
    std::str::from_utf8(name)
        .ok()
        .filter(|name| {
            !name.is_empty() && name.len() <= MAX_HNS_NAME_BYTES && is_printable_ascii(name)
        })
        .map(str::to_owned)
        .ok_or_else(|| invalid_request("prepared HNS name is not canonical public text"))
}

fn provider_broadcast_receipt(
    receipt: BroadcastReceipt,
    request_nonce: u64,
    workflow_id: Option<String>,
) -> Result<Value, ServiceFailure> {
    if receipt.module != ModuleId::Handshake {
        return Err(invalid_request(
            "broadcast receipt does not match the HNS module",
        ));
    }
    bounded_provider_value(json!({
        "module": "handshake",
        "workflowId": workflow_id,
        "requestNonce": request_nonce,
        "txid": lowercase_hex(receipt.txid.as_bytes()),
        "acceptedAtUnix": receipt.accepted_at_unix,
    }))
}

fn chain_failure(error: ChainError) -> ServiceFailure {
    let (code, message) = match error {
        ChainError::Locked => (ServiceErrorCode::WalletLocked, "wallet is locked"),
        ChainError::ApprovalRequired => (
            ServiceErrorCode::ApprovalStale,
            "HNS value approval is missing, stale, or mismatched",
        ),
        ChainError::InvalidRequest(_) => (
            ServiceErrorCode::InvalidRequest,
            "HNS value request is invalid",
        ),
        ChainError::FeeLimit => (
            ServiceErrorCode::RuntimeFailure,
            "HNS transaction fee exceeds the approved maximum",
        ),
        ChainError::InvalidEvidence | ChainError::InvalidTransactionSize => (
            ServiceErrorCode::RuntimeFailure,
            "HNS transaction evidence failed authentication",
        ),
        ChainError::Disabled | ChainError::Unsupported => (
            ServiceErrorCode::UnsupportedCapability,
            "HNS value operations are unavailable",
        ),
        ChainError::NotSynchronized | ChainError::Overflow | ChainError::Backend(_) => {
            (ServiceErrorCode::RuntimeFailure, "HNS value runtime failed")
        }
    };
    ServiceFailure {
        code,
        message: message.to_owned(),
        unsupported_capability: None,
    }
}
