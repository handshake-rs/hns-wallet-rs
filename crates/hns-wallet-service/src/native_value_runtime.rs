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
    AccountSummary, ApprovalSummary, ApprovalWarning, ServiceCapability, ServiceErrorCode,
    ServiceFailure, WalletRequest, WalletResponse, WalletRuntimeStatus, WorkflowSummary,
};
use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsNetwork, HnsRuntimeConfig, HnsWalletError, HnsWalletRuntime,
    KnownName, NameOperation, NameOperationState, PrepareNameFinalize, PrepareNameTransfer,
};
use hns_wallet_provider::{ApprovedCall, PendingApproval, ProviderMethod, SelectedNamespace};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::{
    AccountId, Amount, ApprovalId, ApprovalKind, BaseUnits, FinalityModel, ModuleId, WalletAsset,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{
    MAX_HNS_NAME_BYTES, MAX_PROVIDER_HNS_READ_ITEMS, MAX_PUBLIC_STRING_BYTES, ServiceError,
    ServiceRuntime, WalletService, bounded_provider_value, hns_native_name_import_failure,
    hns_read_failure, hns_read_result_bound, hns_runtime_failure, invalid_request,
    is_printable_ascii, lowercase_hex, persistent_store_failure, public_hns_amount,
    public_hns_name_read, public_hns_name_summary, public_hns_receive_target,
    public_hns_transaction_summary, validate_empty_params, validate_hns_account_summary,
    validate_hns_wallet_read_scope, wallet_locked,
};

/// Trusted product inputs for a full HNS runtime that was opened over the
/// same unlocked store and then relocked before service construction.
pub struct PersistentHnsValueConfig<B, C> {
    pub runtime: HnsWalletRuntime<B, C>,
    pub account_label: String,
}

/// Provider-capable HNS runtime with one exact account and one exact encrypted
/// store authority. There is no alternate signing store or caller-selected
/// wallet/account path.
pub struct PersistentHnsValueRuntime<B, C> {
    store: SharedWalletStore,
    runtime: HnsWalletRuntime<B, C>,
    account_label: String,
    configured: HnsRuntimeConfig,
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
        if let Err(error) = self.exact_account() {
            self.store.lock().map_err(persistent_store_failure)?;
            return Err(error);
        }
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
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
            ServiceCapability::HnsValueOperationsV1,
            ServiceCapability::ProviderDispatch,
            ServiceCapability::ValueMovement,
        ])
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
        )
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
            ProviderMethod::HnsGetNames | ProviderMethod::HnsGetName => Err(
                ServiceFailure::unsupported(ServiceCapability::ProviderDispatch),
            ),
            ProviderMethod::HnsSend
            | ProviderMethod::HnsTransferName
            | ProviderMethod::HnsFinalizeName => Err(ServiceFailure::unsupported(
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
        configured
            .validate()
            .map_err(|_| ServiceError::InvalidPersistentHnsAccount)?;
        let runtime = PersistentHnsValueRuntime::new(store.clone(), config, configured);
        Self::new(store, runtime, true)
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
