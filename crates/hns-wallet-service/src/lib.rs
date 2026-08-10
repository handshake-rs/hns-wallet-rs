#![doc = "Private wallet service composition without browser-engine policy."]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hns_wallet_ffi::{
    APPROVAL_SCHEMA_VERSION, AccountSummary, ApprovalPrompt, ApprovalSummary, HnsNameDisclosure,
    HostAuthorityFacts, HostFrame, MAX_HNS_NAME_BYTES, MAX_HNS_NAME_DISCLOSURES,
    MAX_PROVIDER_RESULT_BYTES, MAX_PUBLIC_STRING_BYTES, ModuleApprovalAction,
    PROVIDER_SCHEMA_VERSION, ProviderBinding, ProviderCapabilitySnapshot, ProviderEventEnvelope,
    ProviderEventPayload, ProviderNamespace, ServiceCapability, ServiceErrorCode, ServiceFailure,
    ServiceFrame, ServiceHello, ServiceLimits, ServiceRequest, ServiceResponse, SessionEnvelope,
    WALLET_ABI_VERSION, WalletRequest, WalletResponse, WalletRuntimeStatus, encode_service_frame,
};
use hns_wallet_hns::{
    HnsAccountReadRuntime, HnsAccountReadSnapshot, HnsBackend, HnsClock,
    HnsExistingAccountSelector, HnsWalletError, KnownName, NameOwnershipStatus, NameResourceStatus,
};
use hns_wallet_provider::{
    ApprovedCall, HostAuthorityRegistration, Origin, PROVIDER_API_VERSION, PendingApproval,
    PermissionSnapshot, ProviderAction, ProviderCore, ProviderError, ProviderMethod,
    ProviderStateStore, SelectedNamespace,
};
use hns_wallet_store::{SharedWalletStore, StoreError};
use hns_wallet_types::{
    Amount, ApprovalId, ApprovalKind, HostAuthorityHandleId, HostSessionId, LocalTransactionStatus,
    ModuleId, PermissionCapability, ProviderApprovalId, ProviderRequestId, ReceiveTarget,
    TransactionSummary, WalletAsset, WalletServiceSessionId, WalletSessionId,
};
use serde_json::{Value, json};
use thiserror::Error;

pub const MAX_SEEN_REQUEST_IDS: usize = 4_096;
pub const MAX_SERVICE_PENDING_APPROVALS: usize = 128;
pub const MAX_PROVIDER_HNS_READ_ITEMS: usize = 128;
pub const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

type HnsReadPermissionExtension = (
    BTreeSet<PermissionCapability>,
    BTreeSet<hns_wallet_types::AccountId>,
    BTreeSet<[u8; 32]>,
    Option<u64>,
);

/// Execution boundary supplied by a wallet composition. Runtime method support
/// is checked independently from the closed provider vocabulary, and value or
/// browser capability is never inferred merely because protocol source exists.
pub trait ServiceRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability>;

    fn supports_provider_method(&self, method: ProviderMethod) -> bool;

    fn prepare_approval(
        &mut self,
        approval: &PendingApproval,
    ) -> Result<ApprovalSummary, ServiceFailure>;

    /// Select the one minimized Handshake account that an approved origin may
    /// learn through `hns_requestAccounts`. The service validates and persists
    /// the exact account identifier before returning it.
    fn prepare_hns_account_grant(
        &mut self,
        _: &ApprovedCall,
    ) -> Result<AccountSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    /// Return the runtime's current single HNS account selection without
    /// prompting or accepting a caller-selected identity. Persisted account
    /// permissions are rechecked against this value after every restart.
    fn selected_hns_account(&self) -> Result<AccountSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    /// Reconcile and return the current bounded known names before a `Names`
    /// permission prompt is emitted. The service minimizes and freezes this
    /// set for display and later approval-time reauthentication.
    fn current_hns_names(&mut self) -> Result<Vec<KnownName>, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    /// Execute a name read under the exact persisted name-hash set. Other
    /// runtimes cannot accidentally inherit unscoped name disclosure merely
    /// by advertising a method name.
    fn execute_hns_name_read(
        &mut self,
        _: ApprovedCall,
        _: &BTreeSet<[u8; 32]>,
    ) -> Result<Value, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure>;

    fn lock_wallet(&mut self) -> Result<(), ServiceFailure>;

    fn execute_wallet(&mut self, request: WalletRequest) -> Result<WalletResponse, ServiceFailure>;
}

#[derive(Default)]
pub struct UnavailableRuntime;

impl ServiceRuntime for UnavailableRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::new()
    }

    fn supports_provider_method(&self, _: ProviderMethod) -> bool {
        false
    }

    fn prepare_approval(&mut self, _: &PendingApproval) -> Result<ApprovalSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::WalletOperations,
        ))
    }

    fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::WalletOperations,
        ))
    }
}

/// Existing-database control plane used by the checked-in subprocess. It owns
/// no chain adapter or account selector and cannot move value. The same shared
/// store handle is installed in `ProviderCore`, so `wallet_lock` clears the one
/// decrypted record key used by both runtime control and permission state.
pub struct PersistentControlRuntime {
    store: SharedWalletStore,
}

impl PersistentControlRuntime {
    fn new(store: SharedWalletStore) -> Self {
        Self { store }
    }

    fn status(&self) -> Result<WalletRuntimeStatus, ServiceFailure> {
        Ok(WalletRuntimeStatus {
            locked: self.store.is_locked().map_err(persistent_store_failure)?,
            active_wallet: None,
            enabled_modules: BTreeSet::new(),
            mainnet_settlement_enabled: false,
        })
    }
}

impl ServiceRuntime for PersistentControlRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::ProviderDispatch,
        ])
    }

    fn supports_provider_method(&self, method: ProviderMethod) -> bool {
        method == ProviderMethod::WalletGetStatus
    }

    fn prepare_approval(&mut self, _: &PendingApproval) -> Result<ApprovalSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure> {
        if call.method != ProviderMethod::WalletGetStatus {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        validate_empty_params(&call.params)?;
        serde_json::to_value(self.status()?)
            .map_err(|_| invalid_request("wallet status encoding failed"))
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
                self.store
                    .unlock(passphrase.expose_secret())
                    .map_err(persistent_store_failure)?;
                Ok(WalletResponse::Unlocked)
            }
            WalletRequest::Lock => {
                self.lock_wallet()?;
                Ok(WalletResponse::Locked)
            }
            WalletRequest::CreateWallet { .. }
            | WalletRequest::RestoreWallet { .. }
            | WalletRequest::ListAccounts
            | WalletRequest::Balance { .. }
            | WalletRequest::ReceiveTarget { .. }
            | WalletRequest::TransactionHistory { .. }
            | WalletRequest::ModuleStatus { .. }
            | WalletRequest::WorkflowStatus { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
        }
    }
}

/// Trusted library inputs for the exact-existing-account HNS composition.
/// The checked-in executable intentionally has no insecure CLI defaults for
/// wallet/account selection, so product code must build the selector from the
/// same shared store handle passed to the service.
pub struct PersistentHnsAccountConfig {
    pub selector: HnsExistingAccountSelector,
    pub account_label: String,
}

/// Concrete non-value runtime which can select and disclose only one exact
/// authenticated pre-existing HNS account. Synchronized chain reads remain a
/// separate unavailable composition.
pub struct PersistentHnsAccountRuntime {
    store: SharedWalletStore,
    selector: HnsExistingAccountSelector,
    account_label: String,
}

impl PersistentHnsAccountRuntime {
    fn new(store: SharedWalletStore, config: PersistentHnsAccountConfig) -> Self {
        Self {
            store,
            selector: config.selector,
            account_label: config.account_label,
        }
    }

    fn status(&self) -> Result<WalletRuntimeStatus, ServiceFailure> {
        let locked = self.store.is_locked().map_err(persistent_store_failure)?;
        let active_wallet = if locked {
            None
        } else {
            Some(
                self.selector
                    .selected_account()
                    .map_err(hns_runtime_failure)?
                    .config
                    .wallet_id,
            )
        };
        Ok(WalletRuntimeStatus {
            locked,
            active_wallet,
            enabled_modules: BTreeSet::new(),
            mainnet_settlement_enabled: false,
        })
    }

    fn exact_account(&self) -> Result<AccountSummary, ServiceFailure> {
        if self.store.is_locked().map_err(persistent_store_failure)? {
            return Err(wallet_locked());
        }
        let selected = self
            .selector
            .selected_account()
            .map_err(hns_runtime_failure)?;
        let account = AccountSummary {
            account_id: selected.config.account_id,
            module: ModuleId::Handshake,
            label: self.account_label.clone(),
            receive_display: None,
        };
        validate_hns_account_summary(&account)
            .map_err(|_| hns_runtime_failure(HnsWalletError::InvalidEvidence))?;
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
}

impl ServiceRuntime for PersistentHnsAccountRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::ProviderDispatch,
        ])
    }

    fn supports_provider_method(&self, method: ProviderMethod) -> bool {
        matches!(
            method,
            ProviderMethod::WalletGetStatus | ProviderMethod::HnsRequestAccounts
        )
    }

    fn prepare_approval(&mut self, _: &PendingApproval) -> Result<ApprovalSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
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

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure> {
        if call.method != ProviderMethod::WalletGetStatus {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        validate_empty_params(&call.params)?;
        serde_json::to_value(self.status()?)
            .map_err(|_| invalid_request("wallet status encoding failed"))
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
            WalletRequest::CreateWallet { .. }
            | WalletRequest::RestoreWallet { .. }
            | WalletRequest::Balance { .. }
            | WalletRequest::ReceiveTarget { .. }
            | WalletRequest::TransactionHistory { .. }
            | WalletRequest::ModuleStatus { .. }
            | WalletRequest::WorkflowStatus { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
        }
    }
}

/// Trusted library inputs for the synchronized HNS read composition. The
/// runtime already owns the exact selector/store/backend join; the service
/// accepts it only when its Arc-backed store authority is identical.
pub struct PersistentHnsReadConfig<B, C> {
    pub runtime: HnsAccountReadRuntime<B, C>,
    pub account_label: String,
}

/// Product-composable HNS account runtime that performs one live, bounded
/// reconciliation for every balance/history/receive/name result. It exposes
/// no value, signing, import, module, marketplace, or settlement path.
pub struct PersistentHnsReadRuntime<B, C> {
    store: SharedWalletStore,
    runtime: HnsAccountReadRuntime<B, C>,
    account_label: String,
}

impl<B: HnsBackend, C: HnsClock> PersistentHnsReadRuntime<B, C> {
    fn new(store: SharedWalletStore, config: PersistentHnsReadConfig<B, C>) -> Self {
        Self {
            store,
            runtime: config.runtime,
            account_label: config.account_label,
        }
    }

    fn status(&self) -> Result<WalletRuntimeStatus, ServiceFailure> {
        let locked = self.store.is_locked().map_err(persistent_store_failure)?;
        let active_wallet = if locked {
            None
        } else {
            Some(
                self.runtime
                    .selected_account()
                    .map_err(hns_read_failure)?
                    .config
                    .wallet_id,
            )
        };
        Ok(WalletRuntimeStatus {
            locked,
            active_wallet,
            enabled_modules: BTreeSet::from([ModuleId::Handshake]),
            mainnet_settlement_enabled: false,
        })
    }

    fn exact_account(&self) -> Result<AccountSummary, ServiceFailure> {
        if self.store.is_locked().map_err(persistent_store_failure)? {
            return Err(wallet_locked());
        }
        let selected = self.runtime.selected_account().map_err(hns_read_failure)?;
        let account = AccountSummary {
            account_id: selected.config.account_id,
            module: ModuleId::Handshake,
            label: self.account_label.clone(),
            receive_display: None,
        };
        validate_hns_account_summary(&account)?;
        Ok(account)
    }

    fn synchronize(&self) -> Result<HnsAccountReadSnapshot, ServiceFailure> {
        let selected = self.exact_account()?;
        let snapshot = self.runtime.synchronize().map_err(hns_read_failure)?;
        if snapshot.account_id != selected.account_id {
            return Err(hns_read_failure(HnsWalletError::StaleAccountRead));
        }
        Ok(snapshot)
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
}

impl<B: HnsBackend, C: HnsClock> ServiceRuntime for PersistentHnsReadRuntime<B, C> {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::ProviderDispatch,
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
                | ProviderMethod::HnsGetNames
                | ProviderMethod::HnsGetName
        )
    }

    fn prepare_approval(&mut self, _: &PendingApproval) -> Result<ApprovalSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
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
        Ok(self.synchronize()?.known_names)
    }

    fn execute_hns_name_read(
        &mut self,
        call: ApprovedCall,
        approved_names: &BTreeSet<[u8; 32]>,
    ) -> Result<Value, ServiceFailure> {
        if approved_names.len() > MAX_PROVIDER_HNS_READ_ITEMS {
            return Err(provider_failure(ProviderError::Persistence));
        }
        let snapshot = self.synchronize()?;
        public_hns_name_read(&call, approved_names, &snapshot.known_names)
    }

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure> {
        match call.method {
            ProviderMethod::WalletGetStatus => {
                validate_empty_params(&call.params)?;
                serde_json::to_value(self.status()?)
                    .map_err(|_| invalid_request("wallet status encoding failed"))
            }
            ProviderMethod::HnsGetBalance
            | ProviderMethod::HnsGetTransactions
            | ProviderMethod::HnsGetReceiveAddress => {
                let snapshot = self.synchronize()?;
                public_hns_non_name_read(&call, &snapshot)
            }
            ProviderMethod::HnsGetNames | ProviderMethod::HnsGetName => Err(
                ServiceFailure::unsupported(ServiceCapability::ProviderDispatch),
            ),
            _ => Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            )),
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
                let snapshot = self.synchronize()?;
                validate_hns_wallet_read_scope(module, account, snapshot.account_id)?;
                Ok(WalletResponse::Balance {
                    amount: snapshot.balance,
                })
            }
            WalletRequest::ReceiveTarget { module, account } => {
                let snapshot = self.synchronize()?;
                validate_hns_wallet_read_scope(module, account, snapshot.account_id)?;
                Ok(WalletResponse::ReceiveTarget {
                    target: snapshot.receive_target,
                })
            }
            WalletRequest::TransactionHistory { module, account } => {
                let snapshot = self.synchronize()?;
                validate_hns_wallet_read_scope(module, account, snapshot.account_id)?;
                if snapshot.transactions.len() > MAX_PROVIDER_HNS_READ_ITEMS {
                    return Err(hns_read_result_bound());
                }
                Ok(WalletResponse::TransactionHistory {
                    transactions: snapshot.transactions,
                })
            }
            WalletRequest::ModuleStatus {
                module: ModuleId::Handshake,
            } => {
                let snapshot = self.synchronize()?;
                Ok(WalletResponse::ModuleStatus {
                    status: hns_wallet_types::SyncStatus {
                        phase: hns_wallet_types::SyncPhase::Ready,
                        validated_height: snapshot.binding.chain.tip.height,
                        scanned_height: snapshot.binding.chain.tip.height,
                        target_height: Some(snapshot.binding.chain.tip.height),
                        last_error: None,
                    },
                })
            }
            WalletRequest::CreateWallet { .. }
            | WalletRequest::RestoreWallet { .. }
            | WalletRequest::ModuleStatus { .. }
            | WalletRequest::WorkflowStatus { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
        }
    }
}

#[derive(Clone, Copy)]
struct SessionState {
    host_session_id: HostSessionId,
    restart_generation: u64,
    next_host_sequence: u64,
    next_service_sequence: u64,
}

#[derive(Clone)]
struct PendingState {
    binding: ProviderBinding,
    kind: ApprovalKind,
    expires_at_unix: u64,
    hns_permission_scope: Option<PendingHnsPermissionScope>,
}

#[derive(Clone)]
struct PendingHnsPermissionScope {
    account: AccountSummary,
    names: Option<PendingHnsNameScope>,
}

#[derive(Clone, Eq, PartialEq)]
struct PendingHnsNameScope {
    disclosures: Vec<HnsNameDisclosure>,
    hashes: BTreeSet<[u8; 32]>,
}

/// One process-local service generation. Construction rotates both the service
/// and wallet session identifiers and starts with no authority handles,
/// approvals, replay entries, rate windows, request IDs, or event cursors.
/// The supplied state store remains the sole source of permission records and
/// tombstone generations.
pub struct WalletService<S, R> {
    provider: ProviderCore<S>,
    runtime: R,
    service_session_id: WalletServiceSessionId,
    wallet_session_id: WalletSessionId,
    capabilities: BTreeSet<ServiceCapability>,
    session: Option<SessionState>,
    seen_request_ids: BTreeSet<ProviderRequestId>,
    request_order: VecDeque<ProviderRequestId>,
    pending: BTreeMap<ProviderApprovalId, PendingState>,
    event_sequences: BTreeMap<(HostAuthorityHandleId, u64), u64>,
}

impl<S: ProviderStateStore, R: ServiceRuntime> WalletService<S, R> {
    pub fn new_ephemeral(state: S, runtime: R) -> Result<Self, ServiceError> {
        Self::new(state, runtime, false)
    }

    fn new(state: S, runtime: R, persistent_permissions: bool) -> Result<Self, ServiceError> {
        let service_session_id = random_service_session()?;
        let wallet_session_id = random_wallet_session()?;
        let mut capabilities = BTreeSet::from([
            ServiceCapability::CanonicalFraming,
            ServiceCapability::RestartIsolation,
            ServiceCapability::OpaqueAuthorityRegistry,
            ServiceCapability::StructuredApprovals,
            ServiceCapability::TypedEvents,
        ]);
        if persistent_permissions {
            capabilities.insert(ServiceCapability::PersistentPermissions);
        }
        capabilities.extend(runtime.capabilities());
        capabilities.remove(&ServiceCapability::BrowserIntegration);
        if !persistent_permissions {
            capabilities.remove(&ServiceCapability::PersistentPermissions);
        }
        if !capabilities.contains(&ServiceCapability::ProviderDispatch) {
            capabilities.remove(&ServiceCapability::ValueMovement);
        }
        Ok(Self {
            provider: ProviderCore::new(state, wallet_session_id, true),
            runtime,
            service_session_id,
            wallet_session_id,
            capabilities,
            session: None,
            seen_request_ids: BTreeSet::new(),
            request_order: VecDeque::new(),
            pending: BTreeMap::new(),
            event_sequences: BTreeMap::new(),
        })
    }

    pub fn process_frame(
        &mut self,
        encoded: &[u8],
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        let frame = hns_wallet_ffi::decode_host_frame(encoded)?;
        match frame {
            HostFrame::Hello { hello } => self.negotiate(hello),
            HostFrame::Request { envelope } => self.process_request(envelope, now_unix_ms),
        }
    }

    pub fn rotate_wallet_session(&mut self, locked: bool) -> Result<(), ServiceError> {
        self.pending.clear();
        self.event_sequences.clear();
        match random_wallet_session() {
            Ok(wallet_session_id) => {
                self.wallet_session_id = wallet_session_id;
                self.provider.set_wallet_state(wallet_session_id, locked);
                Ok(())
            }
            Err(error) => {
                self.provider.set_wallet_state(self.wallet_session_id, true);
                Err(error)
            }
        }
    }

    pub fn emit_event(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        payload: ProviderEventPayload,
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        let permission = match self.provider.permission_snapshot(
            authority_handle,
            authority_revision,
            now_unix_ms,
        ) {
            Ok(permission) => permission,
            Err(error) => {
                self.event_sequences.clear();
                return Err(ServiceError::from(error));
            }
        };
        if permission.record.is_none()
            && !matches!(&payload, ProviderEventPayload::Disconnect { .. })
        {
            self.event_sequences.clear();
            return Err(ServiceError::Provider(ProviderError::Unauthorized));
        }
        let retire_after_emit = permission.record.is_none();
        let event_sequence = self
            .event_sequences
            .entry((authority_handle, authority_revision))
            .or_insert(0);
        *event_sequence = event_sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        let event_sequence = *event_sequence;
        let (session, channel_sequence) = self.next_service_sequence()?;
        let encoded = encode_service_frame(&ServiceFrame::Event {
            event: ProviderEventEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: session.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: session.restart_generation,
                channel_sequence,
                binding: ProviderBinding {
                    authority_handle,
                    authority_revision,
                    wallet_session_id: self.provider.wallet_session_id(),
                    permission_generation: permission.generation,
                },
                event_sequence,
                payload,
            },
        })
        .map_err(ServiceError::from);
        if retire_after_emit {
            self.event_sequences
                .remove(&(authority_handle, authority_revision));
        }
        encoded
    }

    fn negotiate(&mut self, hello: hns_wallet_ffi::HostHello) -> Result<Vec<u8>, ServiceError> {
        if self.session.is_some() {
            return Err(ServiceError::AlreadyNegotiated);
        }
        self.session = Some(SessionState {
            host_session_id: hello.host_session_id,
            restart_generation: hello.restart_generation,
            next_host_sequence: 1,
            next_service_sequence: 1,
        });
        encode_service_frame(&ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: hello.platform,
                host_session_id: hello.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: hello.restart_generation,
                capabilities: self.capabilities.clone(),
                limits: ServiceLimits::default(),
            },
        })
        .map_err(ServiceError::from)
    }

    fn process_request(
        &mut self,
        envelope: SessionEnvelope<ServiceRequest>,
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        self.accept_request_header(&envelope)?;
        self.prune_pending(now_unix_ms / 1_000);
        let request_id = envelope.request_id;
        let response = self
            .dispatch(envelope.body, now_unix_ms)
            .unwrap_or_else(|failure| ServiceResponse::Failure { failure });
        let (session, channel_sequence) = self.next_service_sequence()?;
        encode_service_frame(&ServiceFrame::Response {
            envelope: SessionEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: session.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: session.restart_generation,
                channel_sequence,
                request_id,
                body: response,
            },
        })
        .map_err(ServiceError::from)
    }

    fn accept_request_header<T>(
        &mut self,
        envelope: &SessionEnvelope<T>,
    ) -> Result<(), ServiceError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ServiceError::HandshakeRequired)?;
        if envelope.host_session_id != session.host_session_id
            || envelope.service_session_id != self.service_session_id
            || envelope.restart_generation != session.restart_generation
        {
            return Err(ServiceError::SessionMismatch);
        }
        if envelope.channel_sequence != session.next_host_sequence {
            return Err(ServiceError::SequenceMismatch {
                expected: session.next_host_sequence,
                received: envelope.channel_sequence,
            });
        }
        if self.seen_request_ids.contains(&envelope.request_id) {
            return Err(ServiceError::DuplicateRequest);
        }
        session.next_host_sequence = session
            .next_host_sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        self.seen_request_ids.insert(envelope.request_id);
        self.request_order.push_back(envelope.request_id);
        if self.request_order.len() > MAX_SEEN_REQUEST_IDS
            && let Some(expired) = self.request_order.pop_front()
        {
            self.seen_request_ids.remove(&expired);
        }
        Ok(())
    }

    fn next_service_sequence(&mut self) -> Result<(SessionState, u64), ServiceError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ServiceError::HandshakeRequired)?;
        let sequence = session.next_service_sequence;
        session.next_service_sequence = sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        Ok((*session, sequence))
    }

    fn dispatch(
        &mut self,
        request: ServiceRequest,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        match request {
            ServiceRequest::RegisterAuthority {
                authority_handle,
                authority,
            } => {
                let revision = self
                    .provider
                    .register_authority(
                        authority_handle,
                        provider_authority(authority)?,
                        now_unix_ms,
                    )
                    .map_err(provider_failure)?;
                Ok(ServiceResponse::AuthorityRegistered {
                    authority_handle,
                    authority_revision: revision,
                })
            }
            ServiceRequest::ReplaceAuthority {
                authority_handle,
                expected_authority_revision,
                authority,
            } => {
                let revision = self
                    .provider
                    .replace_authority(
                        authority_handle,
                        expected_authority_revision,
                        provider_authority(authority)?,
                        now_unix_ms,
                    )
                    .map_err(provider_failure)?;
                self.pending
                    .retain(|_, pending| pending.binding.authority_handle != authority_handle);
                self.event_sequences
                    .retain(|(handle, _), _| *handle != authority_handle);
                Ok(ServiceResponse::AuthorityReplaced {
                    authority_handle,
                    authority_revision: revision,
                })
            }
            ServiceRequest::RevokeAuthority {
                authority_handle,
                expected_authority_revision,
            } => {
                self.provider
                    .revoke_authority(authority_handle, expected_authority_revision)
                    .map_err(provider_failure)?;
                self.pending
                    .retain(|_, pending| pending.binding.authority_handle != authority_handle);
                self.event_sequences
                    .retain(|(handle, _), _| *handle != authority_handle);
                Ok(ServiceResponse::AuthorityRevoked { authority_handle })
            }
            ServiceRequest::ProviderCapabilities {
                authority_handle,
                authority_revision,
            } => self.provider_capabilities(authority_handle, authority_revision, now_unix_ms),
            ServiceRequest::ProviderRequest {
                authority_handle,
                authority_revision,
                request_nonce,
                method,
                params,
            } => self.provider_request(
                authority_handle,
                authority_revision,
                request_nonce,
                method,
                params,
                now_unix_ms,
            ),
            ServiceRequest::ApprovalDecision {
                authority_handle,
                authority_revision,
                approval_id,
                decision,
            } => self.approval_decision(
                authority_handle,
                authority_revision,
                approval_id,
                decision,
                now_unix_ms,
            ),
            ServiceRequest::Wallet { request } => {
                if !self
                    .capabilities
                    .contains(&ServiceCapability::WalletOperations)
                {
                    return Err(ServiceFailure::unsupported(
                        ServiceCapability::WalletOperations,
                    ));
                }
                let response = self.runtime.execute_wallet(request)?;
                match &response {
                    WalletResponse::Locked => self
                        .rotate_wallet_session(true)
                        .map_err(ServiceFailure::from)?,
                    WalletResponse::Unlocked
                    | WalletResponse::WalletCreated { .. }
                    | WalletResponse::WalletRestored { .. } => {
                        if let Err(error) = self.rotate_wallet_session(false) {
                            // The runtime has already exposed decrypted state.
                            // If fresh session entropy is unavailable, clear
                            // that state synchronously before returning the
                            // rotation failure. `rotate_wallet_session` has
                            // independently put ProviderCore in its locked
                            // posture and cleared its ephemeral registries.
                            self.runtime.lock_wallet()?;
                            return Err(ServiceFailure::from(error));
                        }
                    }
                    _ => {}
                }
                Ok(ServiceResponse::Wallet { response })
            }
        }
    }

    fn provider_capabilities(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        let binding = self.provider_binding(authority_handle, authority_revision, now_unix_ms)?;
        let capabilities = ProviderCapabilitySnapshot {
            provider_schema_version: PROVIDER_SCHEMA_VERSION,
            approval_schema_version: APPROVAL_SCHEMA_VERSION,
            wallet_session_id: binding.wallet_session_id,
            permission_generation: binding.permission_generation,
            methods: self.supported_provider_method_names(),
        };
        Ok(ServiceResponse::ProviderCapabilities {
            binding,
            capabilities,
        })
    }

    fn provider_request(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        request_nonce: u64,
        method_name: String,
        params: Value,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        if !self
            .capabilities
            .contains(&ServiceCapability::ProviderDispatch)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        let method = ProviderMethod::parse(&method_name).map_err(provider_failure)?;
        if method == ProviderMethod::WalletLock
            && !self
                .capabilities
                .contains(&ServiceCapability::WalletOperations)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ));
        }
        if method.approval().is_some_and(value_movement_approval)
            && !self
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ValueMovement,
            ));
        }
        if matches!(
            method,
            ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
        ) && !self
            .runtime
            .supports_provider_method(ProviderMethod::HnsRequestAccounts)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        if !service_owned_method(method) && !self.runtime.supports_provider_method(method) {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        // Runtime and release-gate availability is decided before
        // method-specific parameter parsing. An unavailable runtime surface
        // must have one fail-closed response regardless of attacker-controlled
        // parameter shape. The service-owned permission request remains below
        // because its closed vocabulary distinguishes invalid capabilities
        // from otherwise valid but currently ungrantable capabilities.
        if matches!(
            method,
            ProviderMethod::HnsRequestAccounts
                | ProviderMethod::HnsAccounts
                | ProviderMethod::HnsGetBalance
                | ProviderMethod::HnsGetTransactions
                | ProviderMethod::HnsGetReceiveAddress
                | ProviderMethod::HnsGetNames
        ) {
            validate_empty_params(&params)?;
        }
        if method == ProviderMethod::HnsGetName {
            hns_name_hash_param(&params)?;
        }
        if matches!(
            method,
            ProviderMethod::WalletGetCapabilities
                | ProviderMethod::WalletGetPermissions
                | ProviderMethod::WalletGetStatus
                | ProviderMethod::WalletRevokePermissions
                | ProviderMethod::WalletLock
        ) {
            validate_empty_params(&params)?;
        }
        if method == ProviderMethod::WalletRequestPermissions {
            let requested = requested_capabilities_from_params(&params)?;
            if !requested.is_subset(&self.grantable_permission_capabilities()) {
                return Err(ServiceFailure::unsupported(
                    ServiceCapability::ProviderDispatch,
                ));
            }
        }
        let encoded_request = serde_json::to_vec(&json!({
            "method": method_name.clone(),
            "params": params,
        }))
        .map_err(|_| invalid_request("provider request encoding failed"))?;
        let action = match self.provider.request(
            authority_handle,
            authority_revision,
            request_nonce,
            now_unix_ms,
            &encoded_request,
        ) {
            Ok(action) => action,
            Err(error) => {
                if matches!(
                    &error,
                    ProviderError::Unauthorized | ProviderError::ClockRollback
                ) {
                    self.event_sequences.clear();
                }
                if matches!(&error, ProviderError::ClockRollback) {
                    self.pending.clear();
                }
                return Err(provider_failure(error));
            }
        };
        match action {
            ProviderAction::Execute(call) => {
                let lock_permission_generation = if call.method == ProviderMethod::WalletLock {
                    Some(
                        self.provider_binding(authority_handle, authority_revision, now_unix_ms)?
                            .permission_generation,
                    )
                } else {
                    None
                };
                let value = self.execute_call(
                    authority_handle,
                    authority_revision,
                    call,
                    None,
                    now_unix_ms,
                )?;
                let binding = match lock_permission_generation {
                    Some(permission_generation) => ProviderBinding {
                        authority_handle,
                        authority_revision,
                        wallet_session_id: self.provider.wallet_session_id(),
                        permission_generation,
                    },
                    None => {
                        self.provider_binding(authority_handle, authority_revision, now_unix_ms)?
                    }
                };
                Ok(ServiceResponse::ProviderResult { binding, value })
            }
            ProviderAction::ApprovalRequired(approval) => {
                if self.pending.len() >= MAX_SERVICE_PENDING_APPROVALS {
                    self.provider
                        .reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        )
                        .map_err(provider_failure)?;
                    return Err(invalid_request("too many pending approvals"));
                }
                let (summary, hns_permission_scope) =
                    match self.approval_summary(&approval, now_unix_ms) {
                        Ok(prepared) => prepared,
                        Err(failure) => {
                            let _ = self.provider.reject(
                                authority_handle,
                                authority_revision,
                                approval.id,
                                now_unix_ms,
                            );
                            return Err(failure);
                        }
                    };
                let wire_id = match wire_approval_id(approval.id) {
                    Ok(wire_id) => wire_id,
                    Err(failure) => {
                        let _ = self.provider.reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        );
                        return Err(failure);
                    }
                };
                let expires_at_unix_ms = match approval.expires_at_unix.checked_mul(1_000) {
                    Some(expiry) => expiry,
                    None => {
                        let _ = self.provider.reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        );
                        return Err(invalid_request("approval expiry overflow"));
                    }
                };
                let prompt = ApprovalPrompt {
                    approval_id: wire_id,
                    binding: ProviderBinding {
                        authority_handle,
                        authority_revision,
                        wallet_session_id: approval.wallet_session,
                        permission_generation: approval.permission_generation,
                    },
                    origin: approval.call.origin.as_str().to_owned(),
                    method: method_name,
                    expires_at_unix_ms,
                    summary,
                };
                if let Err(error) = prompt.validate(approval.kind, now_unix_ms) {
                    let _ = self.provider.reject(
                        authority_handle,
                        authority_revision,
                        approval.id,
                        now_unix_ms,
                    );
                    return Err(ServiceFailure {
                        code: ServiceErrorCode::InvalidRequest,
                        message: error.to_string(),
                        unsupported_capability: None,
                    });
                }
                self.pending.insert(
                    wire_id,
                    PendingState {
                        binding: prompt.binding,
                        kind: approval.kind,
                        expires_at_unix: approval.expires_at_unix,
                        hns_permission_scope,
                    },
                );
                Ok(ServiceResponse::ApprovalRequired { approval: prompt })
            }
        }
    }

    fn approval_decision(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        approval_id: ProviderApprovalId,
        decision: hns_wallet_ffi::ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        let pending = self
            .pending
            .get(&approval_id)
            .cloned()
            .ok_or_else(stale_approval)?;
        if pending.binding.authority_handle != authority_handle
            || pending.binding.authority_revision != authority_revision
            || pending.expires_at_unix <= now_unix_ms / 1_000
        {
            return Err(stale_approval());
        }
        let binding = self.provider_binding(authority_handle, authority_revision, now_unix_ms)?;
        if pending.binding != binding {
            return Err(stale_approval());
        }
        let internal_id = ApprovalId::new(approval_id.into_bytes());
        match decision {
            hns_wallet_ffi::ApprovalDecision::Reject => {
                self.provider
                    .reject(
                        authority_handle,
                        authority_revision,
                        internal_id,
                        now_unix_ms,
                    )
                    .map_err(provider_failure)?;
                self.pending.remove(&approval_id);
                Ok(ServiceResponse::ApprovalRejected { approval_id })
            }
            hns_wallet_ffi::ApprovalDecision::Approve => {
                if let Err(failure) = self.verify_pending_hns_permission_scope(
                    authority_handle,
                    authority_revision,
                    &pending,
                    now_unix_ms,
                ) {
                    let _ = self.provider.reject(
                        authority_handle,
                        authority_revision,
                        internal_id,
                        now_unix_ms,
                    );
                    self.pending.remove(&approval_id);
                    return Err(failure);
                }
                let call = self
                    .provider
                    .approve(
                        authority_handle,
                        authority_revision,
                        internal_id,
                        now_unix_ms,
                    )
                    .map_err(provider_failure)?;
                if call.method.approval() != Some(pending.kind) {
                    self.pending.remove(&approval_id);
                    return Err(stale_approval());
                }
                self.pending.remove(&approval_id);
                let value = self.execute_call(
                    authority_handle,
                    authority_revision,
                    call,
                    Some(&pending),
                    now_unix_ms,
                )?;
                let binding =
                    self.provider_binding(authority_handle, authority_revision, now_unix_ms)?;
                Ok(ServiceResponse::ProviderResult { binding, value })
            }
        }
    }

    fn approval_summary(
        &mut self,
        approval: &PendingApproval,
        now_unix_ms: u64,
    ) -> Result<(ApprovalSummary, Option<PendingHnsPermissionScope>), ServiceFailure> {
        let mut hns_permission_scope = None;
        let summary = match approval.call.method {
            ProviderMethod::WalletRequestPermissions => {
                let capabilities = requested_capabilities(&approval.call)?;
                hns_permission_scope =
                    self.prepare_hns_permission_scope(approval, &capabilities, now_unix_ms)?;
                let hns_names = hns_permission_scope
                    .as_ref()
                    .and_then(|scope| scope.names.as_ref())
                    .map(|scope| scope.disclosures.clone())
                    .unwrap_or_default();
                Ok(ApprovalSummary::Permissions {
                    capabilities,
                    hns_names,
                })
            }
            ProviderMethod::HnsRequestAccounts => Ok(ApprovalSummary::Permissions {
                capabilities: requested_capabilities(&approval.call)?,
                hns_names: Vec::new(),
            }),
            ProviderMethod::WalletEnableModule | ProviderMethod::WalletDisableModule => {
                let module = requested_module(&approval.call.params)?;
                let action = if approval.call.method == ProviderMethod::WalletEnableModule {
                    ModuleApprovalAction::Enable
                } else {
                    ModuleApprovalAction::Disable
                };
                Ok(ApprovalSummary::ModuleEnablement { module, action })
            }
            _ => self.runtime.prepare_approval(approval),
        }?;
        validate_approval_summary(&approval.call, &summary)?;
        Ok((summary, hns_permission_scope))
    }

    fn hns_permission_request_is_account_scoped(
        &self,
        requested: &BTreeSet<PermissionCapability>,
    ) -> bool {
        ProviderMethod::ALL.into_iter().any(|method| {
            hns_account_read_method(method)
                && self.runtime.supports_provider_method(method)
                && method
                    .permission()
                    .is_some_and(|capability| requested.contains(&capability))
        })
    }

    fn prepare_hns_permission_scope(
        &mut self,
        approval: &PendingApproval,
        requested: &BTreeSet<PermissionCapability>,
        now_unix_ms: u64,
    ) -> Result<Option<PendingHnsPermissionScope>, ServiceFailure> {
        if !self.hns_permission_request_is_account_scoped(requested) {
            return Ok(None);
        }
        if approval.call.namespace != SelectedNamespace::Hns {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        let permission = self
            .provider
            .permission_snapshot(
                approval.authority_handle,
                approval.authority_revision,
                now_unix_ms,
            )
            .map_err(provider_failure)?;
        if permission.generation != approval.permission_generation {
            return Err(stale_approval());
        }
        let record = permission
            .record
            .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
        let selected = self.runtime.selected_hns_account()?;
        validate_hns_account_summary(&selected)?;
        if !record
            .capabilities
            .contains(&PermissionCapability::Accounts)
            || record.approved_accounts != BTreeSet::from([selected.account_id])
        {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        let names = if requested.contains(&PermissionCapability::Names) {
            Some(hns_name_approval_scope(self.runtime.current_hns_names()?)?)
        } else {
            None
        };
        Ok(Some(PendingHnsPermissionScope {
            account: selected,
            names,
        }))
    }

    fn verify_pending_hns_permission_scope(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        pending: &PendingState,
        now_unix_ms: u64,
    ) -> Result<(), ServiceFailure> {
        let Some(expected) = pending.hns_permission_scope.as_ref() else {
            return Ok(());
        };
        let permission = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        let Some(record) = permission.record else {
            return Err(stale_approval());
        };
        if permission.generation != pending.binding.permission_generation
            || !record
                .capabilities
                .contains(&PermissionCapability::Accounts)
            || record.approved_accounts != BTreeSet::from([expected.account.account_id])
        {
            return Err(stale_approval());
        }
        let selected = self.runtime.selected_hns_account()?;
        validate_hns_account_summary(&selected)?;
        if selected != expected.account {
            return Err(stale_approval());
        }
        if let Some(expected_names) = expected.names.as_ref() {
            let current_names = self.runtime.current_hns_names()?;
            let current = hns_name_approval_scope(current_names).map_err(|_| stale_approval())?;
            if &current != expected_names {
                return Err(stale_approval());
            }
        }
        Ok(())
    }

    fn execute_call(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: ApprovedCall,
        approved_pending: Option<&PendingState>,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        match call.method {
            ProviderMethod::WalletGetCapabilities => Ok(json!({
                "providerApiVersion": PROVIDER_API_VERSION,
                "methods": self.supported_provider_method_names(),
            })),
            ProviderMethod::WalletGetPermissions => {
                let permission = self
                    .provider
                    .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
                    .map_err(provider_failure)?;
                if permission.record.is_none() {
                    self.event_sequences.clear();
                }
                permission_value(permission)
            }
            ProviderMethod::WalletRevokePermissions => {
                let generation = self
                    .provider
                    .revoke_permissions(authority_handle, authority_revision, now_unix_ms)
                    .map_err(provider_failure)?;
                self.pending.clear();
                self.event_sequences.clear();
                Ok(json!({
                    "permissionGeneration": generation,
                    "capabilities": [],
                    "accounts": []
                }))
            }
            ProviderMethod::WalletRequestPermissions => {
                let requested = requested_capabilities(&call)?;
                if !requested.is_subset(&self.grantable_permission_capabilities()) {
                    return Err(ServiceFailure::unsupported(
                        ServiceCapability::ProviderDispatch,
                    ));
                }
                let approved_pending = approved_pending.ok_or_else(stale_approval)?;
                let expected_generation = approved_pending.binding.permission_generation;
                let (capabilities, approved_accounts, approved_names, expires_at_unix) = self
                    .hns_read_permission_extension(
                        authority_handle,
                        authority_revision,
                        &call,
                        expected_generation,
                        requested,
                        approved_pending.hns_permission_scope.as_ref(),
                        now_unix_ms,
                    )?;
                let permission = self
                    .provider
                    .grant_scoped_permissions_at_generation(
                        authority_handle,
                        authority_revision,
                        expected_generation,
                        capabilities,
                        approved_accounts,
                        approved_names,
                        now_unix_ms,
                        expires_at_unix,
                    )
                    .map_err(provider_failure)?;
                self.pending.clear();
                self.event_sequences.clear();
                permission_value(PermissionSnapshot {
                    generation: permission.generation,
                    record: Some(permission),
                })
            }
            ProviderMethod::HnsRequestAccounts => self.approve_hns_account_grant(
                authority_handle,
                authority_revision,
                &call,
                approved_pending
                    .map(|pending| pending.binding.permission_generation)
                    .ok_or_else(stale_approval)?,
                now_unix_ms,
            ),
            ProviderMethod::HnsAccounts => {
                self.approved_hns_accounts(authority_handle, authority_revision, &call, now_unix_ms)
            }
            ProviderMethod::WalletLock => {
                self.runtime.lock_wallet()?;
                self.rotate_wallet_session(true)
                    .map_err(ServiceFailure::from)?;
                Ok(json!({ "locked": true }))
            }
            _ if hns_account_read_method(call.method) => {
                let approved_names = self.authorize_hns_account_read(
                    authority_handle,
                    authority_revision,
                    &call,
                    now_unix_ms,
                )?;
                if matches!(
                    call.method,
                    ProviderMethod::HnsGetNames | ProviderMethod::HnsGetName
                ) {
                    self.runtime.execute_hns_name_read(call, &approved_names)
                } else {
                    self.runtime.execute_provider(call)
                }
            }
            _ => self.runtime.execute_provider(call),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn hns_read_permission_extension(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        expected_generation: u64,
        requested: BTreeSet<PermissionCapability>,
        pending_scope: Option<&PendingHnsPermissionScope>,
        now_unix_ms: u64,
    ) -> Result<HnsReadPermissionExtension, ServiceFailure> {
        let account_scoped = self.hns_permission_request_is_account_scoped(&requested);
        if !account_scoped {
            if pending_scope.is_some() {
                return Err(stale_approval());
            }
            return Ok((requested, BTreeSet::new(), BTreeSet::new(), None));
        }
        if call.namespace != SelectedNamespace::Hns {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        let snapshot = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        if snapshot.generation != expected_generation {
            return Err(stale_approval());
        }
        let record = snapshot
            .record
            .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
        let selected = self.runtime.selected_hns_account()?;
        validate_hns_account_summary(&selected)?;
        let approved_accounts = BTreeSet::from([selected.account_id]);
        if !record
            .capabilities
            .contains(&PermissionCapability::Accounts)
            || record.approved_accounts != approved_accounts
        {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        let pending_scope = pending_scope.ok_or_else(stale_approval)?;
        if pending_scope.account != selected {
            return Err(stale_approval());
        }
        let refresh_name_scope = requested.contains(&PermissionCapability::Names);
        let approved_names = if refresh_name_scope {
            pending_scope
                .names
                .as_ref()
                .ok_or_else(stale_approval)?
                .hashes
                .clone()
        } else {
            if pending_scope.names.is_some() {
                return Err(stale_approval());
            }
            record.approved_names
        };
        if approved_names.len() > MAX_PROVIDER_HNS_READ_ITEMS {
            return Err(hns_read_result_bound());
        }
        let mut capabilities = record.capabilities;
        capabilities.extend(requested);
        Ok((
            capabilities,
            approved_accounts,
            approved_names,
            record.expires_at_unix,
        ))
    }

    fn authorize_hns_account_read(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        now_unix_ms: u64,
    ) -> Result<BTreeSet<[u8; 32]>, ServiceFailure> {
        if call.namespace != SelectedNamespace::Hns {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        let required = call
            .method
            .permission()
            .ok_or_else(|| invalid_request("HNS read has no permission capability"))?;
        let record = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?
            .record
            .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
        let selected = self.runtime.selected_hns_account()?;
        validate_hns_account_summary(&selected)?;
        if !record
            .capabilities
            .contains(&PermissionCapability::Accounts)
            || !record.capabilities.contains(&required)
            || record.approved_accounts != BTreeSet::from([selected.account_id])
        {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        if record.approved_names.len() > MAX_PROVIDER_HNS_READ_ITEMS {
            return Err(provider_failure(ProviderError::Persistence));
        }
        if call.method == ProviderMethod::HnsGetName {
            let requested = hns_name_hash_param(&call.params)?;
            if !record.approved_names.contains(&requested) {
                return Err(provider_failure(ProviderError::Unauthorized));
            }
        }
        Ok(record.approved_names)
    }

    fn provider_binding(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<ProviderBinding, ServiceFailure> {
        let permission = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        Ok(ProviderBinding {
            authority_handle,
            authority_revision,
            wallet_session_id: self.provider.wallet_session_id(),
            permission_generation: permission.generation,
        })
    }

    fn supported_provider_methods(&self) -> BTreeSet<ProviderMethod> {
        if !self
            .capabilities
            .contains(&ServiceCapability::ProviderDispatch)
        {
            return BTreeSet::new();
        }
        ProviderMethod::ALL
            .into_iter()
            .filter(|method| {
                if *method == ProviderMethod::WalletRequestPermissions {
                    return !self.grantable_permission_capabilities().is_empty();
                }
                if matches!(
                    method,
                    ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
                ) {
                    return self
                        .runtime
                        .supports_provider_method(ProviderMethod::HnsRequestAccounts);
                }
                if *method == ProviderMethod::WalletLock
                    && !self
                        .capabilities
                        .contains(&ServiceCapability::WalletOperations)
                {
                    return false;
                }
                if method.approval().is_some_and(value_movement_approval)
                    && !self
                        .capabilities
                        .contains(&ServiceCapability::ValueMovement)
                {
                    return false;
                }
                service_owned_method(*method) || self.runtime.supports_provider_method(*method)
            })
            .collect()
    }

    fn grantable_permission_capabilities(&self) -> BTreeSet<PermissionCapability> {
        ProviderMethod::ALL
            .into_iter()
            .filter(|method| {
                !matches!(
                    method,
                    ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
                ) && self.runtime.supports_provider_method(*method)
                    && (!method.approval().is_some_and(value_movement_approval)
                        || self
                            .capabilities
                            .contains(&ServiceCapability::ValueMovement))
            })
            .filter_map(ProviderMethod::permission)
            .filter(|capability| *capability != PermissionCapability::Accounts)
            .collect()
    }

    fn supported_provider_method_names(&self) -> BTreeSet<String> {
        self.supported_provider_methods()
            .into_iter()
            .map(|method| method.wire_name().to_owned())
            .collect()
    }

    fn prune_pending(&mut self, now_unix: u64) {
        self.pending
            .retain(|_, pending| pending.expires_at_unix > now_unix);
    }

    fn approve_hns_account_grant(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        expected_permission_generation: u64,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        validate_empty_params(&call.params)?;
        if call.namespace != SelectedNamespace::Hns {
            return Err(invalid_request(
                "Handshake accounts require the HNS namespace",
            ));
        }
        if !self
            .runtime
            .supports_provider_method(ProviderMethod::HnsRequestAccounts)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        let account = self.runtime.prepare_hns_account_grant(call)?;
        validate_hns_account_summary(&account)?;
        let account_id = account.account_id;
        let value = json!([account_id.to_string()]);
        if serde_json::to_vec(&value)
            .map_err(|_| invalid_request("account result encoding failed"))?
            .len()
            > MAX_PROVIDER_RESULT_BYTES
        {
            return Err(invalid_request("account result exceeds the provider bound"));
        }
        let permission = self
            .provider
            .grant_scoped_permissions_at_generation(
                authority_handle,
                authority_revision,
                expected_permission_generation,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::from([account_id]),
                BTreeSet::new(),
                now_unix_ms,
                None,
            )
            .map_err(provider_failure)?;
        if permission.approved_accounts != BTreeSet::from([account_id]) {
            return Err(provider_failure(ProviderError::Persistence));
        }
        self.pending.clear();
        self.event_sequences.clear();
        Ok(value)
    }

    fn approved_hns_accounts(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        validate_empty_params(&call.params)?;
        if call.namespace != SelectedNamespace::Hns {
            return Err(invalid_request(
                "Handshake accounts require the HNS namespace",
            ));
        }
        let permission = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        let record = permission
            .record
            .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
        let selected = self.runtime.selected_hns_account()?;
        validate_hns_account_summary(&selected)?;
        let selected_accounts = BTreeSet::from([selected.account_id]);
        if !record
            .capabilities
            .contains(&PermissionCapability::Accounts)
            || record.approved_accounts != selected_accounts
        {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        Ok(json!([selected.account_id.to_string()]))
    }
}

impl WalletService<SharedWalletStore, PersistentControlRuntime> {
    /// Compose the existing-database subprocess around one locked store
    /// authority. Constructing the runtime here prevents callers from pairing
    /// ProviderCore with a different independently unlocked database handle.
    pub fn new_persistent_control(store: SharedWalletStore) -> Result<Self, ServiceError> {
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked);
        }
        let runtime = PersistentControlRuntime::new(store.clone());
        Self::new(store, runtime, true)
    }
}

impl WalletService<SharedWalletStore, PersistentHnsAccountRuntime> {
    /// Compose a locked exact-account HNS provider around the identical shared
    /// store/key authority used by `ProviderCore`. Another handle to the same
    /// database path is not sufficient: Arc identity must match.
    pub fn new_persistent_hns_accounts(
        store: SharedWalletStore,
        config: PersistentHnsAccountConfig,
    ) -> Result<Self, ServiceError> {
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked);
        }
        if !config.selector.shares_store_authority(&store) {
            return Err(ServiceError::PersistentStoreAuthorityMismatch);
        }
        if config.account_label.is_empty()
            || config.account_label.len() > MAX_PUBLIC_STRING_BYTES
            || !is_printable_ascii(&config.account_label)
        {
            return Err(ServiceError::InvalidPersistentHnsAccount);
        }
        let runtime = PersistentHnsAccountRuntime::new(store.clone(), config);
        Self::new(store, runtime, true)
    }
}

impl<B: HnsBackend, C: HnsClock> WalletService<SharedWalletStore, PersistentHnsReadRuntime<B, C>> {
    /// Compose synchronized HNS reads around one exact SharedWalletStore
    /// authority. The backend remains a concrete product type; no public mutex
    /// guard or dynamic backend crosses this boundary.
    pub fn new_persistent_hns_reads(
        store: SharedWalletStore,
        config: PersistentHnsReadConfig<B, C>,
    ) -> Result<Self, ServiceError> {
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked);
        }
        if !config.runtime.shares_store_authority(&store) {
            return Err(ServiceError::PersistentStoreAuthorityMismatch);
        }
        if config.account_label.is_empty()
            || config.account_label.len() > MAX_PUBLIC_STRING_BYTES
            || !is_printable_ascii(&config.account_label)
        {
            return Err(ServiceError::InvalidPersistentHnsAccount);
        }
        let runtime = PersistentHnsReadRuntime::new(store.clone(), config);
        Self::new(store, runtime, true)
    }
}

fn provider_authority(
    authority: HostAuthorityFacts,
) -> Result<HostAuthorityRegistration, ServiceFailure> {
    Ok(HostAuthorityRegistration {
        origin: Origin::parse(&authority.origin).map_err(provider_failure)?,
        namespace: match authority.namespace {
            ProviderNamespace::Hns => SelectedNamespace::Hns,
            ProviderNamespace::Icann => SelectedNamespace::Icann,
        },
        runtime_session: authority.runtime_session_id,
        runtime_generation: authority.runtime_generation,
        policy_generation: authority.policy_generation,
        navigation_generation: authority.navigation_generation,
        decision_fingerprint: authority.decision_fingerprint,
        valid_until_unix_ms: authority.valid_until_unix_ms,
    })
}

fn service_owned_method(method: ProviderMethod) -> bool {
    matches!(
        method,
        ProviderMethod::WalletGetCapabilities
            | ProviderMethod::WalletRequestPermissions
            | ProviderMethod::WalletGetPermissions
            | ProviderMethod::WalletRevokePermissions
            | ProviderMethod::HnsAccounts
            | ProviderMethod::WalletLock
    )
}

fn hns_account_read_method(method: ProviderMethod) -> bool {
    matches!(
        method,
        ProviderMethod::HnsGetBalance
            | ProviderMethod::HnsGetTransactions
            | ProviderMethod::HnsGetReceiveAddress
            | ProviderMethod::HnsGetNames
            | ProviderMethod::HnsGetName
    )
}

fn value_movement_approval(kind: ApprovalKind) -> bool {
    matches!(
        kind,
        ApprovalKind::Send
            | ApprovalKind::NameTransfer
            | ApprovalKind::NameFinalize
            | ApprovalKind::NameMarketOffer
            | ApprovalKind::NameMarketPurchase
            | ApprovalKind::MarketIntent
            | ApprovalKind::FillAcceptance
            | ApprovalKind::SwapRedeem
            | ApprovalKind::SwapRefund
    )
}

fn requested_capabilities(
    call: &ApprovedCall,
) -> Result<BTreeSet<PermissionCapability>, ServiceFailure> {
    if call.method == ProviderMethod::HnsRequestAccounts {
        return Ok(BTreeSet::from([PermissionCapability::Accounts]));
    }
    requested_capabilities_from_params(&call.params)
}

fn requested_capabilities_from_params(
    params: &Value,
) -> Result<BTreeSet<PermissionCapability>, ServiceFailure> {
    let value = params
        .get("capabilities")
        .or_else(|| params.get("scopes"))
        .cloned()
        .ok_or_else(|| invalid_request("permission capabilities are required"))?;
    let capabilities: BTreeSet<PermissionCapability> = serde_json::from_value(value)
        .map_err(|_| invalid_request("permission capabilities are invalid"))?;
    if capabilities.is_empty() {
        return Err(invalid_request("permission capabilities are empty"));
    }
    if capabilities.contains(&PermissionCapability::Accounts) {
        return Err(invalid_request(
            "Accounts permission requires hns_requestAccounts",
        ));
    }
    Ok(capabilities)
}

fn validate_empty_params(params: &Value) -> Result<(), ServiceFailure> {
    if params.is_null() || params.as_object().is_some_and(|object| object.is_empty()) {
        Ok(())
    } else {
        Err(invalid_request("method does not accept parameters"))
    }
}

fn bounded_provider_value(value: Value) -> Result<Value, ServiceFailure> {
    if serde_json::to_vec(&value)
        .map_err(|_| invalid_request("provider result encoding failed"))?
        .len()
        > MAX_PROVIDER_RESULT_BYTES
    {
        return Err(invalid_request(
            "provider result exceeds the provider bound",
        ));
    }
    Ok(value)
}

fn hns_name_hash_param(params: &Value) -> Result<[u8; 32], ServiceFailure> {
    let object = params
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| invalid_request("hns_getName requires only nameHash"))?;
    let encoded = object
        .get("nameHash")
        .and_then(Value::as_str)
        .filter(|encoded| encoded.len() == 64)
        .ok_or_else(|| invalid_request("nameHash must be 32-byte lowercase hexadecimal"))?;
    let mut output = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = decode(pair[0])
            .ok_or_else(|| invalid_request("nameHash must be canonical lowercase hexadecimal"))?;
        let low = decode(pair[1])
            .ok_or_else(|| invalid_request("nameHash must be canonical lowercase hexadecimal"))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn public_hns_non_name_read(
    call: &ApprovedCall,
    snapshot: &HnsAccountReadSnapshot,
) -> Result<Value, ServiceFailure> {
    validate_empty_params(&call.params)?;
    match call.method {
        ProviderMethod::HnsGetBalance => bounded_provider_value(json!({
            "amount": public_hns_amount(snapshot.balance)?,
        })),
        ProviderMethod::HnsGetTransactions => {
            if snapshot.transactions.len() > MAX_PROVIDER_HNS_READ_ITEMS {
                return Err(hns_read_result_bound());
            }
            let transactions = snapshot
                .transactions
                .iter()
                .map(public_hns_transaction_summary)
                .collect::<Result<Vec<_>, _>>()?;
            bounded_provider_value(json!({ "transactions": transactions }))
        }
        ProviderMethod::HnsGetReceiveAddress => bounded_provider_value(json!({
            "target": public_hns_receive_target(&snapshot.receive_target, snapshot.account_id)?,
        })),
        _ => Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        )),
    }
}

fn hns_name_approval_scope(
    known_names: Vec<KnownName>,
) -> Result<PendingHnsNameScope, ServiceFailure> {
    if known_names.len() > MAX_HNS_NAME_DISCLOSURES {
        return Err(hns_read_result_bound());
    }
    let mut hashes = BTreeSet::new();
    let mut canonical_names = BTreeSet::new();
    let mut disclosures = Vec::with_capacity(known_names.len());
    for known_name in &known_names {
        let disclosure = hns_name_disclosure(known_name)?;
        if !hashes.insert(known_name.name_hash) || !canonical_names.insert(disclosure.name.clone())
        {
            return Err(hns_read_failure(HnsWalletError::InvalidEvidence));
        }
        disclosures.push(disclosure);
    }
    disclosures.sort();
    Ok(PendingHnsNameScope {
        disclosures,
        hashes,
    })
}

fn hns_name_disclosure(name: &KnownName) -> Result<HnsNameDisclosure, ServiceFailure> {
    let disclosure = HnsNameDisclosure {
        name: canonical_hns_name(name)?.to_owned(),
        name_hash: lowercase_hex(&name.name_hash),
    };
    disclosure
        .validate()
        .map_err(|_| hns_read_failure(HnsWalletError::InvalidEvidence))?;
    Ok(disclosure)
}

fn canonical_hns_name(name: &KnownName) -> Result<&str, ServiceFailure> {
    std::str::from_utf8(&name.name)
        .ok()
        .filter(|display| {
            !display.is_empty()
                && display.len() <= MAX_HNS_NAME_BYTES
                && is_printable_ascii(display)
        })
        .ok_or_else(|| invalid_request("known HNS name is not canonical public text"))
}

fn public_hns_name_read(
    call: &ApprovedCall,
    approved_names: &BTreeSet<[u8; 32]>,
    known_names: &[KnownName],
) -> Result<Value, ServiceFailure> {
    if approved_names.len() > MAX_PROVIDER_HNS_READ_ITEMS {
        return Err(hns_read_result_bound());
    }
    let current_names = known_names
        .iter()
        .map(|name| (name.name_hash, name))
        .collect::<BTreeMap<_, _>>();
    if current_names.len() != known_names.len()
        || !approved_names
            .iter()
            .all(|name_hash| current_names.contains_key(name_hash))
    {
        return Err(provider_failure(ProviderError::Unauthorized));
    }
    match call.method {
        ProviderMethod::HnsGetNames => {
            validate_empty_params(&call.params)?;
            let names = approved_names
                .iter()
                .map(|name_hash| {
                    current_names
                        .get(name_hash)
                        .ok_or_else(|| provider_failure(ProviderError::Unauthorized))
                        .and_then(|name| public_hns_name_summary(name))
                })
                .collect::<Result<Vec<_>, _>>()?;
            bounded_provider_value(json!({ "names": names }))
        }
        ProviderMethod::HnsGetName => {
            let name_hash = hns_name_hash_param(&call.params)?;
            if !approved_names.contains(&name_hash) {
                return Err(provider_failure(ProviderError::Unauthorized));
            }
            let name = current_names
                .get(&name_hash)
                .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
            bounded_provider_value(json!({ "name": public_hns_name_summary(name)? }))
        }
        _ => Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        )),
    }
}

fn public_hns_amount(amount: Amount) -> Result<Value, ServiceFailure> {
    if amount.asset != WalletAsset::Hns {
        return Err(invalid_request("HNS balance contains a non-HNS asset"));
    }
    Ok(json!({
        "asset": "HNS",
        "baseUnits": amount.base_units.get().to_string(),
    }))
}

fn public_hns_receive_target(
    target: &ReceiveTarget,
    expected_account: hns_wallet_types::AccountId,
) -> Result<Value, ServiceFailure> {
    if target.module != ModuleId::Handshake || target.account != expected_account {
        return Err(invalid_request(
            "HNS receive target does not match the synchronized account",
        ));
    }
    target
        .validate()
        .map_err(|_| invalid_request("HNS receive target is invalid"))?;
    if !is_printable_ascii(&target.display) {
        return Err(invalid_request(
            "HNS receive target is not canonical public text",
        ));
    }
    Ok(json!({
        "module": "handshake",
        "account": lowercase_hex(target.account.as_bytes()),
        "display": &target.display,
        "derivationIndex": target.derivation_index,
    }))
}

fn public_hns_transaction_summary(
    transaction: &TransactionSummary,
) -> Result<Value, ServiceFailure> {
    if transaction.module != ModuleId::Handshake {
        return Err(invalid_request(
            "HNS transaction history contains a non-HNS transaction",
        ));
    }
    if transaction
        .block_height
        .is_some_and(|height| height > MAX_JAVASCRIPT_SAFE_INTEGER)
        || transaction
            .first_seen_unix
            .is_some_and(|time| time > MAX_JAVASCRIPT_SAFE_INTEGER)
    {
        return Err(invalid_request(
            "HNS transaction history exceeds JavaScript integer precision",
        ));
    }
    let status = match transaction.status {
        LocalTransactionStatus::Prepared => "prepared",
        LocalTransactionStatus::Authorized => "authorized",
        LocalTransactionStatus::Broadcast => "broadcast",
        LocalTransactionStatus::Mempool => "mempool",
        LocalTransactionStatus::Confirmed => "confirmed",
        LocalTransactionStatus::Replaced => "replaced",
        LocalTransactionStatus::Conflicted => "conflicted",
        LocalTransactionStatus::Reorged => "reorged",
        LocalTransactionStatus::Dropped => "dropped",
        LocalTransactionStatus::Failed => "failed",
    };
    Ok(json!({
        "module": "handshake",
        "txid": lowercase_hex(transaction.txid.as_bytes()),
        "status": status,
        "netAmount": {
            "negative": transaction.net_amount.negative,
            "magnitude": transaction.net_amount.magnitude.get().to_string(),
        },
        "fee": transaction.fee.map(|fee| fee.get().to_string()),
        "blockHeight": transaction.block_height,
        "firstSeenUnix": transaction.first_seen_unix,
        "confirmationCount": transaction.confirmation_count,
    }))
}

fn public_hns_name_summary(name: &KnownName) -> Result<Value, ServiceFailure> {
    if name.proof_height > MAX_JAVASCRIPT_SAFE_INTEGER {
        return Err(invalid_request(
            "known HNS name proof height exceeds JavaScript integer precision",
        ));
    }
    let disclosure = hns_name_disclosure(name)?;
    let resource_status = match &name.resource_status {
        NameResourceStatus::UnavailableCanonicalBinding => "unavailableCanonicalBinding",
        NameResourceStatus::NoCurrentState => "noCurrentState",
        NameResourceStatus::Empty => "empty",
        NameResourceStatus::CanonicalDecoded => "canonicalDecoded",
        NameResourceStatus::CanonicalOpaque => "canonicalOpaque",
    };
    let ownership_status = match &name.ownership_status {
        NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable => {
            "watchOnlyCanonicalStateDecoderUnavailable"
        }
        NameOwnershipStatus::WalletContextUnavailable => "walletContextUnavailable",
        NameOwnershipStatus::NoCurrentOwner => "noCurrentOwner",
        NameOwnershipStatus::NotWalletOwned => "notWalletOwned",
        NameOwnershipStatus::WalletOwned { .. } => "walletOwned",
        NameOwnershipStatus::IncomingTransfer { .. } => "incomingTransfer",
        NameOwnershipStatus::OutgoingTransfer { .. } => "outgoingTransfer",
    };
    let (registered, expired) = name
        .canonical_current_state
        .as_ref()
        .map_or((None, None), |state| {
            (Some(state.registered), Some(state.expired))
        });
    Ok(json!({
        "name": disclosure.name,
        "nameHash": disclosure.name_hash,
        "proofHeight": name.proof_height,
        "resourceStatus": resource_status,
        "ownershipStatus": ownership_status,
        "registered": registered,
        "expired": expired,
    }))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn hns_read_result_bound() -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::RuntimeFailure,
        message: "synchronized Handshake read exceeds its public result bound".to_owned(),
        unsupported_capability: None,
    }
}

fn validate_hns_wallet_read_scope(
    module: ModuleId,
    requested: hns_wallet_types::AccountId,
    selected: hns_wallet_types::AccountId,
) -> Result<(), ServiceFailure> {
    if module != ModuleId::Handshake || requested != selected {
        return Err(invalid_request(
            "wallet read does not match the selected HNS account",
        ));
    }
    Ok(())
}

fn validate_hns_account_summary(account: &AccountSummary) -> Result<(), ServiceFailure> {
    let valid_receive = account.receive_display.as_ref().is_none_or(|value| {
        !value.is_empty() && value.len() <= MAX_PUBLIC_STRING_BYTES && is_printable_ascii(value)
    });
    if account.module != ModuleId::Handshake
        || account.account_id.as_bytes().iter().all(|byte| *byte == 0)
        || account.label.is_empty()
        || account.label.len() > MAX_PUBLIC_STRING_BYTES
        || !is_printable_ascii(&account.label)
        || !valid_receive
    {
        return Err(invalid_request("runtime returned an invalid HNS account"));
    }
    Ok(())
}

fn requested_module(params: &Value) -> Result<ModuleId, ServiceFailure> {
    serde_json::from_value(
        params
            .get("module")
            .cloned()
            .ok_or_else(|| invalid_request("module is required"))?,
    )
    .map_err(|_| invalid_request("module is invalid"))
}

fn validate_approval_summary(
    call: &ApprovedCall,
    summary: &ApprovalSummary,
) -> Result<(), ServiceFailure> {
    let ApprovalSummary::Send {
        amount,
        maximum_fee,
        chain,
        ..
    } = summary
    else {
        if matches!(
            call.method,
            ProviderMethod::HnsSend | ProviderMethod::AssetSend
        ) {
            return Err(invalid_request("send approval summary is mismatched"));
        }
        return Ok(());
    };

    let expected_chain = match call.method {
        ProviderMethod::HnsSend => ModuleId::Handshake,
        ProviderMethod::AssetSend => {
            let module = requested_module(&call.params)?;
            if !matches!(module, ModuleId::Bitcoin | ModuleId::Ethereum) {
                return Err(invalid_request("external send module is invalid"));
            }
            module
        }
        _ => return Ok(()),
    };
    if *chain != expected_chain
        || amount.asset != expected_chain.asset()
        || maximum_fee.asset != expected_chain.asset()
    {
        return Err(invalid_request(
            "send approval asset or chain is mismatched",
        ));
    }
    Ok(())
}

fn permission_value(permission: PermissionSnapshot) -> Result<Value, ServiceFailure> {
    let Some(record) = permission.record else {
        return Ok(json!({
            "permissionGeneration": permission.generation,
            "capabilities": [],
            "accounts": []
        }));
    };
    let origin = record.origin.as_str().to_owned();
    let capabilities = record.capabilities;
    let accounts = record
        .approved_accounts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    Ok(json!({
        "origin": origin,
        "permissionGeneration": permission.generation,
        "capabilities": capabilities,
        "accounts": accounts,
        "expiresAtUnix": record.expires_at_unix,
    }))
}

fn wire_approval_id(id: ApprovalId) -> Result<ProviderApprovalId, ServiceFailure> {
    ProviderApprovalId::from_bytes(id.into_bytes())
        .map_err(|_| invalid_request("approval identifier is invalid"))
}

fn random_service_session() -> Result<WalletServiceSessionId, ServiceError> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ServiceError::Randomness)?;
        if let Ok(id) = WalletServiceSessionId::from_bytes(bytes) {
            return Ok(id);
        }
    }
}

fn random_wallet_session() -> Result<WalletSessionId, ServiceError> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ServiceError::Randomness)?;
        if let Ok(id) = WalletSessionId::from_bytes(bytes) {
            return Ok(id);
        }
    }
}

fn invalid_request(message: &str) -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::InvalidRequest,
        message: message.to_owned(),
        unsupported_capability: None,
    }
}

fn wallet_locked() -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::WalletLocked,
        message: "wallet is locked".to_owned(),
        unsupported_capability: None,
    }
}

fn hns_runtime_failure(error: HnsWalletError) -> ServiceFailure {
    let (code, message) = match error {
        HnsWalletError::StoreLocked => (ServiceErrorCode::WalletLocked, "wallet is locked"),
        HnsWalletError::Store
        | HnsWalletError::AccountConfigurationMismatch
        | HnsWalletError::DuplicateAccountDerivation
        | HnsWalletError::InvalidEvidence => (
            ServiceErrorCode::PersistenceFailure,
            "exact Handshake account selection failed",
        ),
        _ => (
            ServiceErrorCode::RuntimeFailure,
            "Handshake account selector failed",
        ),
    };
    ServiceFailure {
        code,
        message: message.to_owned(),
        unsupported_capability: None,
    }
}

fn hns_read_failure(error: HnsWalletError) -> ServiceFailure {
    let (code, message) = match error {
        HnsWalletError::StoreLocked => (ServiceErrorCode::WalletLocked, "wallet is locked"),
        HnsWalletError::StaleNodeSnapshot | HnsWalletError::StaleAccountRead => (
            ServiceErrorCode::RuntimeFailure,
            "Handshake read snapshot changed during synchronization",
        ),
        HnsWalletError::Store
        | HnsWalletError::StoreAuthorityMismatch
        | HnsWalletError::AccountConfigurationMismatch
        | HnsWalletError::DuplicateAccountDerivation
        | HnsWalletError::InvalidEvidence => (
            ServiceErrorCode::PersistenceFailure,
            "synchronized Handshake account state failed authentication",
        ),
        HnsWalletError::ScanCapacityExhausted | HnsWalletError::HistoryLimit => (
            ServiceErrorCode::RuntimeFailure,
            "synchronized Handshake read exceeds its configured bound",
        ),
        _ => (
            ServiceErrorCode::RuntimeFailure,
            "Handshake account synchronization failed",
        ),
    };
    ServiceFailure {
        code,
        message: message.to_owned(),
        unsupported_capability: None,
    }
}

fn stale_approval() -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::ApprovalStale,
        message: "approval is stale, expired, or belongs to another authority".to_owned(),
        unsupported_capability: None,
    }
}

fn provider_failure(error: ProviderError) -> ServiceFailure {
    let code = match error {
        ProviderError::AuthorityNotFound => ServiceErrorCode::AuthorityUnknown,
        ProviderError::DuplicateAuthority
        | ProviderError::AuthorityCapacity
        | ProviderError::StaleContext
        | ProviderError::ClockRollback => ServiceErrorCode::AuthorityStale,
        ProviderError::Unauthorized => ServiceErrorCode::PermissionDenied,
        ProviderError::WalletLocked => ServiceErrorCode::WalletLocked,
        ProviderError::RateLimited => ServiceErrorCode::RateLimited,
        ProviderError::Replay => ServiceErrorCode::Replay,
        ProviderError::StaleApproval => ServiceErrorCode::ApprovalStale,
        ProviderError::Persistence => ServiceErrorCode::PersistenceFailure,
        _ => ServiceErrorCode::InvalidRequest,
    };
    ServiceFailure {
        code,
        message: error.to_string(),
        unsupported_capability: None,
    }
}

fn persistent_store_failure(error: StoreError) -> ServiceFailure {
    let code = match &error {
        StoreError::Locked => ServiceErrorCode::WalletLocked,
        StoreError::InvalidPassphrase => ServiceErrorCode::PermissionDenied,
        _ => ServiceErrorCode::PersistenceFailure,
    };
    ServiceFailure {
        code,
        message: error.to_string(),
        unsupported_capability: None,
    }
}

impl From<ServiceError> for ServiceFailure {
    fn from(error: ServiceError) -> Self {
        Self {
            code: ServiceErrorCode::RuntimeFailure,
            message: error.to_string(),
            unsupported_capability: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("wallet service ABI rejected a frame: {0}")]
    Abi(#[from] hns_wallet_ffi::AbiError),
    #[error("provider authority or state rejected an operation: {0}")]
    Provider(#[from] ProviderError),
    #[error("wallet persistence failed: {0}")]
    Store(#[from] StoreError),
    #[error("persistent wallet service must start with a locked store")]
    PersistentStoreMustStartLocked,
    #[error("persistent HNS selector must share the identical store authority")]
    PersistentStoreAuthorityMismatch,
    #[error("persistent HNS account configuration is invalid")]
    InvalidPersistentHnsAccount,
    #[error("host must negotiate a private service session first")]
    HandshakeRequired,
    #[error("wallet service session was already negotiated")]
    AlreadyNegotiated,
    #[error("host, service, or restart session does not match")]
    SessionMismatch,
    #[error("host channel sequence mismatch: expected {expected}, received {received}")]
    SequenceMismatch { expected: u64, received: u64 },
    #[error("request identifier was already consumed")]
    DuplicateRequest,
    #[error("channel or event sequence is exhausted")]
    SequenceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_wallet_ffi::{HostHello, decode_service_frame, encode_host_frame};
    use hns_wallet_hns::{
        CanonicalNameStateSummary, ChainTip, HnsAccountReadBinding, HnsAccountRecord, HnsNetwork,
        HnsRuntimeConfig, MempoolSnapshotBinding, SnapshotBinding,
    };
    use hns_wallet_provider::MemoryProviderState;
    use hns_wallet_store::WalletStore;
    use hns_wallet_types::{
        AccountId, BaseUnits, BrowserRuntimeSessionId, ProviderAuthorityFingerprint,
        SignedBaseUnits, TransactionHash, WalletId,
    };

    const NOW_MS: u64 = 100_000;

    #[derive(Default)]
    struct ProviderRuntime;

    impl ServiceRuntime for ProviderRuntime {
        fn capabilities(&self) -> BTreeSet<ServiceCapability> {
            BTreeSet::from([ServiceCapability::ProviderDispatch])
        }

        fn supports_provider_method(&self, _: ProviderMethod) -> bool {
            false
        }

        fn prepare_approval(
            &mut self,
            _: &PendingApproval,
        ) -> Result<ApprovalSummary, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }

        fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }
    }

    struct AccountRuntime {
        account: AccountSummary,
        account_join_available: bool,
    }

    impl ServiceRuntime for AccountRuntime {
        fn capabilities(&self) -> BTreeSet<ServiceCapability> {
            BTreeSet::from([ServiceCapability::ProviderDispatch])
        }

        fn supports_provider_method(&self, method: ProviderMethod) -> bool {
            self.account_join_available && method == ProviderMethod::HnsRequestAccounts
        }

        fn prepare_approval(
            &mut self,
            _: &PendingApproval,
        ) -> Result<ApprovalSummary, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn prepare_hns_account_grant(
            &mut self,
            _: &ApprovedCall,
        ) -> Result<AccountSummary, ServiceFailure> {
            Ok(self.account.clone())
        }

        fn selected_hns_account(&self) -> Result<AccountSummary, ServiceFailure> {
            if self.account_join_available {
                Ok(self.account.clone())
            } else {
                Err(ServiceFailure::unsupported(
                    ServiceCapability::ProviderDispatch,
                ))
            }
        }

        fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }

        fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }
    }

    struct ProductionFollowupProjectionRuntime {
        account: AccountSummary,
        snapshot: HnsAccountReadSnapshot,
    }

    impl ServiceRuntime for ProductionFollowupProjectionRuntime {
        fn capabilities(&self) -> BTreeSet<ServiceCapability> {
            BTreeSet::from([ServiceCapability::ProviderDispatch])
        }

        fn supports_provider_method(&self, method: ProviderMethod) -> bool {
            matches!(
                method,
                ProviderMethod::HnsRequestAccounts
                    | ProviderMethod::HnsGetBalance
                    | ProviderMethod::HnsGetTransactions
                    | ProviderMethod::HnsGetReceiveAddress
                    | ProviderMethod::HnsGetNames
                    | ProviderMethod::HnsGetName
            )
        }

        fn prepare_approval(
            &mut self,
            _: &PendingApproval,
        ) -> Result<ApprovalSummary, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn prepare_hns_account_grant(
            &mut self,
            _: &ApprovedCall,
        ) -> Result<AccountSummary, ServiceFailure> {
            Ok(self.account.clone())
        }

        fn selected_hns_account(&self) -> Result<AccountSummary, ServiceFailure> {
            Ok(self.account.clone())
        }

        fn current_hns_names(&mut self) -> Result<Vec<KnownName>, ServiceFailure> {
            Ok(self.snapshot.known_names.clone())
        }

        fn execute_hns_name_read(
            &mut self,
            call: ApprovedCall,
            approved_names: &BTreeSet<[u8; 32]>,
        ) -> Result<Value, ServiceFailure> {
            public_hns_name_read(&call, approved_names, &self.snapshot.known_names)
        }

        fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure> {
            public_hns_non_name_read(&call, &self.snapshot)
        }

        fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }

        fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }
    }

    fn production_followup_alpha_hash() -> [u8; 32] {
        [
            0x27, 0x18, 0x78, 0xf8, 0xa9, 0x27, 0xb4, 0x56, 0x6a, 0xc9, 0x51, 0xfc, 0x81, 0x5b,
            0x18, 0xdf, 0xad, 0x8d, 0x03, 0x02, 0xd6, 0x1d, 0x11, 0xd8, 0x0c, 0xbe, 0x15, 0xb7,
            0xa3, 0xa0, 0x56, 0xaf,
        ]
    }

    fn production_followup_beta_hash() -> [u8; 32] {
        [
            0xf0, 0x27, 0x7d, 0x92, 0x06, 0x2b, 0xd9, 0xa4, 0x1d, 0xd2, 0x6c, 0xdd, 0xba, 0xf2,
            0xc4, 0x1d, 0x57, 0x6c, 0xf7, 0xb0, 0x17, 0x3c, 0xbe, 0x96, 0xc2, 0x3d, 0x5f, 0x5a,
            0x4f, 0x92, 0xcc, 0x8f,
        ]
    }

    fn production_followup_known_name() -> KnownName {
        KnownName {
            name: b"alpha".to_vec(),
            name_hash: production_followup_alpha_hash(),
            proof_height: 99,
            unbound_proof_owner_outpoint: None,
            unbound_current_owner_outpoint: None,
            proof_state: Some(vec![1, 2, 3]),
            current_state: Some(vec![4, 5, 6]),
            canonical_proof_state: None,
            canonical_current_state: Some(CanonicalNameStateSummary {
                owner_outpoint: None,
                value: 1,
                highest: 2,
                start_height: 3,
                renewal_height: 4,
                transfer_height: 0,
                revoked_height: 0,
                claimed_height: 0,
                renewals: 1,
                registered: true,
                expired: false,
                weak: false,
            }),
            current_raw_resource: Some(vec![7, 8, 9]),
            resource_status: NameResourceStatus::CanonicalDecoded,
            ownership_status: NameOwnershipStatus::WalletContextUnavailable,
        }
    }

    fn production_followup_projection_service()
    -> WalletService<MemoryProviderState, ProductionFollowupProjectionRuntime> {
        let account_id = AccountId::new([9; 16]);
        let runtime = ProductionFollowupProjectionRuntime {
            account: AccountSummary {
                account_id,
                module: ModuleId::Handshake,
                label: "Handshake".to_owned(),
                receive_display: None,
            },
            snapshot: HnsAccountReadSnapshot {
                account_id,
                binding: HnsAccountReadBinding {
                    chain: SnapshotBinding {
                        tip: ChainTip {
                            height: 99,
                            block_hash: [12; 32],
                            tree_root: [13; 32],
                            median_time_past: 1_700_000_000,
                        },
                        chain_epoch: 3,
                    },
                    mempool: MempoolSnapshotBinding {
                        instance_nonce: [14; 32],
                        generation: 4,
                    },
                },
                balance: Amount::new(WalletAsset::Hns, 42),
                transactions: vec![TransactionSummary {
                    module: ModuleId::Handshake,
                    txid: TransactionHash::new([0xab; 32]),
                    status: LocalTransactionStatus::Confirmed,
                    net_amount: SignedBaseUnits {
                        negative: false,
                        magnitude: BaseUnits::new(17),
                    },
                    fee: Some(BaseUnits::new(2)),
                    block_height: Some(99),
                    first_seen_unix: Some(1_700_000_000),
                    confirmation_count: 3,
                }],
                receive_target: ReceiveTarget {
                    module: ModuleId::Handshake,
                    account: account_id,
                    display: "rs1qproductionfollowup".to_owned(),
                    derivation_index: 7,
                },
                known_names: vec![production_followup_known_name()],
            },
        };
        let mut service = WalletService::new_ephemeral(MemoryProviderState::default(), runtime)
            .expect("projection service");
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("projection HNS authority");
        service
            .provider
            .set_wallet_state(service.wallet_session_id, false);
        service
    }

    fn host_session() -> HostSessionId {
        HostSessionId::from_bytes([1_u8; 32]).expect("host session")
    }

    fn handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes([2_u8; 32]).expect("handle")
    }

    fn restart_handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes([6_u8; 32]).expect("restart handle")
    }

    fn registration() -> HostAuthorityRegistration {
        HostAuthorityRegistration {
            origin: Origin::parse("https://wallet.example").expect("origin"),
            namespace: SelectedNamespace::Hns,
            runtime_session: BrowserRuntimeSessionId::from_bytes([3_u8; 16])
                .expect("runtime session"),
            runtime_generation: 1,
            policy_generation: 1,
            navigation_generation: 1,
            decision_fingerprint: ProviderAuthorityFingerprint::from_bytes([4_u8; 32])
                .expect("fingerprint"),
            valid_until_unix_ms: NOW_MS + 60_000,
        }
    }

    fn provider_service() -> WalletService<MemoryProviderState, ProviderRuntime> {
        let mut service =
            WalletService::new_ephemeral(MemoryProviderState::default(), ProviderRuntime)
                .expect("service");
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        service
    }

    fn account_service() -> WalletService<MemoryProviderState, AccountRuntime> {
        let mut service = WalletService::new_ephemeral(
            MemoryProviderState::default(),
            AccountRuntime {
                account: AccountSummary {
                    account_id: AccountId::new([9_u8; 16]),
                    module: ModuleId::Handshake,
                    label: "Handshake".to_owned(),
                    receive_display: None,
                },
                account_join_available: true,
            },
        )
        .expect("service");
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        service
            .provider
            .set_wallet_state(service.wallet_session_id, false);
        service
    }

    #[cfg(target_os = "linux")]
    fn production_hns_config(account_byte: u8, derivation_index: u32) -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: WalletId::new([8_u8; 16]),
            account_id: AccountId::new([account_byte; 16]),
            account_derivation_index: derivation_index,
            network: HnsNetwork::Regtest,
            birthday_height: 0,
            restore_lookahead: 1,
            minimum_confirmations: 1,
            dust_threshold: BaseUnits::new(1),
            value_operations_enabled: false,
            settlement_enabled: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn production_hns_account(config: HnsRuntimeConfig) -> HnsAccountRecord {
        HnsAccountRecord {
            config,
            next_receive_index: 0,
            next_change_index: 0,
            next_name_index: 0,
            next_shakedex_index: 0,
            external_scan_end: 0,
            internal_scan_end: 0,
            name_scan_end: 0,
            shakedex_scan_end: 0,
            shakedex_scan_complete: false,
            shakedex_scan_in_progress: false,
            last_used_external: None,
            last_used_internal: None,
            last_used_name: None,
            last_used_shakedex: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn production_hns_record_id(config: &HnsRuntimeConfig) -> [u8; 32] {
        let mut record_id = [0_u8; 32];
        record_id[..16].copy_from_slice(config.wallet_id.as_bytes());
        record_id[16..].copy_from_slice(config.account_id.as_bytes());
        record_id
    }

    #[cfg(target_os = "linux")]
    fn production_hns_store(
        database_path: &std::path::Path,
        configs: &[HnsRuntimeConfig],
    ) -> SharedWalletStore {
        const PASSPHRASE: &str = "correct horse battery staple";
        let store = SharedWalletStore::new(
            WalletStore::create(database_path, PASSPHRASE).expect("create HNS account store"),
        );
        for (index, config) in configs.iter().cloned().enumerate() {
            let record_id = production_hns_record_id(&config);
            let account = production_hns_account(config);
            store
                .with_store_mut(|wallet| {
                    wallet
                        .save_wallet_account(&record_id, 0, &account, 10 + index as u64)
                        .map(|_| ())
                })
                .expect("persist exact HNS account");
        }
        store.lock().expect("lock HNS account store");
        store
    }

    #[cfg(target_os = "linux")]
    fn production_hns_service(
        store: SharedWalletStore,
        config: HnsRuntimeConfig,
    ) -> WalletService<SharedWalletStore, PersistentHnsAccountRuntime> {
        let selector =
            HnsExistingAccountSelector::new(store.clone(), config).expect("exact account selector");
        WalletService::new_persistent_hns_accounts(
            store,
            PersistentHnsAccountConfig {
                selector,
                account_label: "Handshake".to_owned(),
            },
        )
        .expect("persistent HNS account service")
    }

    #[cfg(target_os = "linux")]
    fn unlock_production_hns(
        service: &mut WalletService<SharedWalletStore, PersistentHnsAccountRuntime>,
        now_unix_ms: u64,
    ) {
        const PASSPHRASE: &str = "correct horse battery staple";
        let ServiceResponse::Wallet {
            response: WalletResponse::Unlocked,
        } = service
            .dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Unlock {
                        passphrase: hns_wallet_ffi::SecretString::new(PASSPHRASE.to_owned()),
                    },
                },
                now_unix_ms,
            )
            .expect("unlock production HNS account service")
        else {
            panic!("unlock response")
        };
    }

    fn hello() -> zeroize::Zeroizing<Vec<u8>> {
        encode_host_frame(&HostFrame::Hello {
            hello: HostHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: hns_wallet_ffi::HostPlatform::ChromiumNativeHost,
                host_session_id: host_session(),
                restart_generation: 1,
            },
        })
        .expect("hello")
    }

    #[test]
    fn production_followup_account_grant_extends_to_minimized_hns_read_results() {
        let mut service = production_followup_projection_service();
        let methods = service.supported_provider_method_names();
        for method in [
            "hns_requestAccounts",
            "hns_accounts",
            "hns_getBalance",
            "hns_getTransactions",
            "hns_getReceiveAddress",
            "hns_getNames",
            "hns_getName",
            "wallet_requestPermissions",
        ] {
            assert!(methods.contains(method), "missing {method}");
        }
        for method in [
            "hns_send",
            "hns_importKnownName",
            "hns_transferName",
            "hns_finalizeName",
            "hns_signTypedMessage",
            "wallet_enableModule",
            "wallet_disableModule",
        ] {
            assert!(!methods.contains(method), "unexpected {method}");
        }

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 1,
            )
            .expect("account approval")
        else {
            panic!("account approval response")
        };
        let ServiceResponse::ProviderResult { value, .. } = service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 2,
            )
            .expect("account grant")
        else {
            panic!("account grant result")
        };
        assert_eq!(value, json!([AccountId::new([9; 16]).to_string()]));

        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                2,
                ProviderMethod::HnsGetBalance.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 3,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                3,
                ProviderMethod::WalletRequestPermissions
                    .wire_name()
                    .to_owned(),
                json!({
                    "capabilities": ["balance", "transactions", "receive_target", "names"],
                }),
                NOW_MS + 4,
            )
            .expect("read permission approval")
        else {
            panic!("read permission approval response")
        };
        assert_eq!(
            approval.summary,
            ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([
                    PermissionCapability::Balance,
                    PermissionCapability::Transactions,
                    PermissionCapability::ReceiveTarget,
                    PermissionCapability::Names,
                ]),
                hns_names: vec![HnsNameDisclosure {
                    name: "alpha".to_owned(),
                    name_hash: "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
                        .to_owned(),
                }],
            }
        );
        service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 5,
            )
            .expect("read permission grant");
        let permission = service
            .provider
            .permission(handle(), 1, NOW_MS + 5)
            .expect("permission")
            .expect("read permission record");
        assert_eq!(
            permission.capabilities,
            BTreeSet::from([
                PermissionCapability::Accounts,
                PermissionCapability::Balance,
                PermissionCapability::Transactions,
                PermissionCapability::ReceiveTarget,
                PermissionCapability::Names,
            ])
        );
        assert_eq!(
            permission.approved_accounts,
            BTreeSet::from([AccountId::new([9; 16])])
        );
        assert_eq!(
            permission.approved_names,
            BTreeSet::from([production_followup_alpha_hash()])
        );

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                4,
                ProviderMethod::HnsGetBalance.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 6,
            )
            .expect("balance read")
        else {
            panic!("balance result")
        };
        assert_eq!(
            value,
            json!({ "amount": { "asset": "HNS", "baseUnits": "42" } })
        );

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                5,
                ProviderMethod::HnsGetTransactions.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 7,
            )
            .expect("history read")
        else {
            panic!("history result")
        };
        assert_eq!(
            value,
            json!({
                "transactions": [{
                    "module": "handshake",
                    "txid": "abababababababababababababababababababababababababababababababab",
                    "status": "confirmed",
                    "netAmount": { "negative": false, "magnitude": "17" },
                    "fee": "2",
                    "blockHeight": 99,
                    "firstSeenUnix": 1_700_000_000_u64,
                    "confirmationCount": 3,
                }],
            })
        );

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                6,
                ProviderMethod::HnsGetReceiveAddress.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 8,
            )
            .expect("receive read")
        else {
            panic!("receive result")
        };
        assert_eq!(
            value,
            json!({
                "target": {
                    "module": "handshake",
                    "account": AccountId::new([9; 16]).to_string(),
                    "display": "rs1qproductionfollowup",
                    "derivationIndex": 7,
                },
            })
        );

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                7,
                ProviderMethod::HnsGetNames.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 9,
            )
            .expect("name list read")
        else {
            panic!("name list result")
        };
        let expected_name = json!({
            "name": "alpha",
            "nameHash": "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af",
            "proofHeight": 99,
            "resourceStatus": "canonicalDecoded",
            "ownershipStatus": "walletContextUnavailable",
            "registered": true,
            "expired": false,
        });
        assert_eq!(value, json!({ "names": [expected_name.clone()] }));
        let encoded = serde_json::to_string(&value).expect("encode minimized name");
        for private_field in [
            "proof_state",
            "proofState",
            "current_state",
            "currentState",
            "current_raw_resource",
            "currentRawResource",
            "ownerOutpoint",
            "derivation",
            "chainEpoch",
            "mempool",
        ] {
            assert!(!encoded.contains(private_field), "leaked {private_field}");
        }

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                8,
                ProviderMethod::HnsGetName.wire_name().to_owned(),
                json!({
                    "nameHash": "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af",
                }),
                NOW_MS + 10,
            )
            .expect("one approved name")
        else {
            panic!("one name result")
        };
        assert_eq!(value, json!({ "name": expected_name }));

        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                9,
                ProviderMethod::HnsGetName.wire_name().to_owned(),
                json!({
                    "nameHash": "1212121212121212121212121212121212121212121212121212121212121212",
                }),
                NOW_MS + 11,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));
        service.runtime.snapshot.known_names.clear();
        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                10,
                ProviderMethod::HnsGetNames.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 12,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));
    }

    #[test]
    fn production_followup_name_permission_rejects_post_prompt_scope_or_account_change() {
        let mut service = production_followup_projection_service();
        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 1,
            )
            .expect("account approval")
        else {
            panic!("account approval response")
        };
        service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 2,
            )
            .expect("account grant");

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::WalletRequestPermissions
                    .wire_name()
                    .to_owned(),
                json!({ "capabilities": ["names"] }),
                NOW_MS + 3,
            )
            .expect("exact name disclosure")
        else {
            panic!("name approval response")
        };
        let mut beta = production_followup_known_name();
        beta.name = b"beta".to_vec();
        beta.name_hash = production_followup_beta_hash();
        service.runtime.snapshot.known_names.push(beta);
        assert!(matches!(
            service.approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 4,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::ApprovalStale,
                ..
            })
        ));
        let permission = service
            .provider
            .permission(handle(), 1, NOW_MS + 4)
            .expect("permission")
            .expect("account permission");
        assert_eq!(
            permission.capabilities,
            BTreeSet::from([PermissionCapability::Accounts])
        );
        assert!(permission.approved_names.is_empty());

        service.runtime.snapshot.known_names = vec![production_followup_known_name()];
        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                3,
                ProviderMethod::WalletRequestPermissions
                    .wire_name()
                    .to_owned(),
                json!({ "capabilities": ["names"] }),
                NOW_MS + 5,
            )
            .expect("second exact name disclosure")
        else {
            panic!("second name approval response")
        };
        service.runtime.account.account_id = AccountId::new([10; 16]);
        assert!(matches!(
            service.approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 6,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::ApprovalStale,
                ..
            })
        ));
    }

    #[test]
    fn production_followup_hns_reads_reject_namespace_malformed_bounds_and_value_surfaces() {
        let mut service = production_followup_projection_service();
        let mut icann = registration();
        icann.namespace = SelectedNamespace::Icann;
        service
            .provider
            .register_authority(restart_handle(), icann, NOW_MS)
            .expect("ICANN authority");
        assert!(matches!(
            service.provider_request(
                restart_handle(),
                1,
                1,
                ProviderMethod::HnsGetBalance.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 1,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));
        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsGetName.wire_name().to_owned(),
                json!({ "nameHash": "AA", "extra": true }),
                NOW_MS + 2,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));
        for (nonce, method) in [
            ProviderMethod::HnsSend,
            ProviderMethod::HnsImportKnownName,
            ProviderMethod::HnsTransferName,
            ProviderMethod::HnsFinalizeName,
            ProviderMethod::HnsSignTypedMessage,
            ProviderMethod::WalletEnableModule,
            ProviderMethod::WalletDisableModule,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(matches!(
                service.provider_request(
                    handle(),
                    1,
                    nonce as u64 + 2,
                    method.wire_name().to_owned(),
                    Value::Null,
                    NOW_MS + nonce as u64 + 3,
                ),
                Err(ServiceFailure {
                    code: ServiceErrorCode::UnsupportedCapability,
                    ..
                })
            ));
        }

        let mut oversized = service.runtime.snapshot.clone();
        oversized.transactions = vec![oversized.transactions[0].clone(); 129];
        let call = ApprovedCall {
            origin: Origin::parse("https://wallet.example").expect("origin"),
            namespace: SelectedNamespace::Hns,
            method: ProviderMethod::HnsGetTransactions,
            params: Value::Null,
            request_nonce: 99,
        };
        assert!(matches!(
            public_hns_non_name_read(&call, &oversized),
            Err(ServiceFailure {
                code: ServiceErrorCode::RuntimeFailure,
                ..
            })
        ));
        oversized.transactions.truncate(1);
        oversized.transactions[0].block_height = Some(MAX_JAVASCRIPT_SAFE_INTEGER + 1);
        assert!(matches!(
            public_hns_non_name_read(&call, &oversized),
            Err(ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));
        let invalid_account = AccountSummary {
            account_id: AccountId::new([9; 16]),
            module: ModuleId::Handshake,
            label: "Handshake\nWallet".to_owned(),
            receive_display: None,
        };
        assert!(validate_hns_account_summary(&invalid_account).is_err());
        let mut unsafe_name = production_followup_known_name();
        unsafe_name.proof_height = MAX_JAVASCRIPT_SAFE_INTEGER + 1;
        assert!(public_hns_name_summary(&unsafe_name).is_err());
    }

    #[test]
    fn default_subprocess_never_claims_provider_value_or_browser_availability() {
        let mut service =
            WalletService::new_ephemeral(MemoryProviderState::default(), UnavailableRuntime)
                .expect("service");
        let response = service.process_frame(&hello(), 1).expect("hello response");
        let ServiceFrame::Hello { hello } = decode_service_frame(&response).expect("decode") else {
            panic!("expected hello")
        };
        assert!(
            !hello
                .capabilities
                .contains(&ServiceCapability::ProviderDispatch)
        );
        assert!(
            !hello
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        );
        assert!(
            !hello
                .capabilities
                .contains(&ServiceCapability::BrowserIntegration)
        );
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("private capability snapshot")
        else {
            panic!("private capabilities")
        };
        assert!(capabilities.methods.is_empty());
    }

    #[test]
    fn a_new_service_process_rotates_sessions_and_drops_ephemeral_state() {
        let first =
            WalletService::new_ephemeral(MemoryProviderState::default(), UnavailableRuntime)
                .expect("first");
        let second =
            WalletService::new_ephemeral(MemoryProviderState::default(), UnavailableRuntime)
                .expect("second");
        assert_ne!(first.service_session_id, second.service_session_id);
        assert!(second.pending.is_empty());
        assert!(second.event_sequences.is_empty());
        assert!(second.seen_request_ids.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_tranche_persistent_control_reopens_locked_and_preserves_only_permission_authority()
     {
        use std::os::unix::fs::PermissionsExt as _;

        const PASSPHRASE: &str = "correct horse battery staple";
        let directory = tempfile::tempdir().expect("temporary wallet directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private wallet directory permissions");
        let database_path = directory.path().join("wallet.sqlite3");
        let first_store = SharedWalletStore::new(
            WalletStore::create(&database_path, PASSPHRASE).expect("create store"),
        );
        assert!(matches!(
            WalletService::new_persistent_control(first_store.clone()),
            Err(ServiceError::PersistentStoreMustStartLocked)
        ));
        first_store.lock().expect("lock created store");
        let mut first = WalletService::new_persistent_control(first_store.clone())
            .expect("first persistent service");
        assert!(first_store.is_locked().expect("first lock state"));
        assert!(
            first
                .capabilities
                .contains(&ServiceCapability::PersistentPermissions)
        );
        assert!(
            !first
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        );
        assert!(
            !first
                .capabilities
                .contains(&ServiceCapability::BrowserIntegration)
        );
        first
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("first authority");
        assert!(matches!(
            first.provider_capabilities(handle(), 1, NOW_MS),
            Err(ServiceFailure {
                code: ServiceErrorCode::WalletLocked,
                ..
            })
        ));

        let ServiceResponse::Wallet {
            response: WalletResponse::Unlocked,
        } = first
            .dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Unlock {
                        passphrase: hns_wallet_ffi::SecretString::new(PASSPHRASE.to_owned()),
                    },
                },
                NOW_MS,
            )
            .expect("unlock first service")
        else {
            panic!("unlock response")
        };
        assert!(!first_store.is_locked().expect("unlocked first store"));
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = first
            .provider_capabilities(handle(), 1, NOW_MS + 1)
            .expect("first capabilities")
        else {
            panic!("first capabilities response")
        };
        assert_eq!(
            capabilities.methods,
            BTreeSet::from([
                "wallet_getCapabilities".to_owned(),
                "wallet_getPermissions".to_owned(),
                "wallet_getStatus".to_owned(),
                "wallet_lock".to_owned(),
                "wallet_revokePermissions".to_owned(),
            ])
        );
        assert!(!capabilities.methods.contains("wallet_requestPermissions"));
        assert!(matches!(
            first.provider_request(
                handle(),
                1,
                1,
                ProviderMethod::WalletRequestPermissions
                    .wire_name()
                    .to_owned(),
                json!({ "capabilities": ["balance"] }),
                NOW_MS + 2,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));

        first
            .provider
            .grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Balance]),
                BTreeSet::new(),
                NOW_MS + 3,
                None,
            )
            .expect("seed persisted permission");
        let ServiceResponse::ProviderResult { binding, value } = first
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::WalletRevokePermissions
                    .wire_name()
                    .to_owned(),
                Value::Null,
                NOW_MS + 4,
            )
            .expect("persist tombstone")
        else {
            panic!("tombstone response")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_eq!(value["permissionGeneration"], json!(2));

        let first_service_session = first.service_session_id;
        let first_wallet_session = first.wallet_session_id;
        let ServiceResponse::Wallet {
            response: WalletResponse::Locked,
        } = first
            .dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Lock,
                },
                NOW_MS + 5,
            )
            .expect("lock first service")
        else {
            panic!("lock response")
        };
        assert!(first_store.is_locked().expect("locked first store"));
        drop(first);
        drop(first_store);

        let second_store =
            SharedWalletStore::new(WalletStore::open(&database_path).expect("reopen locked store"));
        let mut second = WalletService::new_persistent_control(second_store.clone())
            .expect("second persistent service");
        assert!(second_store.is_locked().expect("restart lock state"));
        assert_ne!(second.service_session_id, first_service_session);
        assert_ne!(second.wallet_session_id, first_wallet_session);
        assert!(second.pending.is_empty());
        assert!(second.event_sequences.is_empty());
        assert!(second.seen_request_ids.is_empty());
        assert!(second.request_order.is_empty());
        assert!(matches!(
            second.provider_capabilities(handle(), 1, NOW_MS + 6),
            Err(ServiceFailure {
                code: ServiceErrorCode::AuthorityUnknown,
                ..
            })
        ));
        second
            .provider
            .register_authority(restart_handle(), registration(), NOW_MS + 6)
            .expect("fresh restart authority");
        assert!(matches!(
            second.provider_capabilities(restart_handle(), 1, NOW_MS + 6),
            Err(ServiceFailure {
                code: ServiceErrorCode::WalletLocked,
                ..
            })
        ));

        let ServiceResponse::Wallet {
            response: WalletResponse::Unlocked,
        } = second
            .dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Unlock {
                        passphrase: hns_wallet_ffi::SecretString::new(PASSPHRASE.to_owned()),
                    },
                },
                NOW_MS + 7,
            )
            .expect("unlock restarted service")
        else {
            panic!("restart unlock response")
        };
        let ServiceResponse::ProviderCapabilities {
            binding,
            capabilities,
        } = second
            .provider_capabilities(restart_handle(), 1, NOW_MS + 8)
            .expect("restart capabilities")
        else {
            panic!("restart capabilities response")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_eq!(capabilities.permission_generation, 2);
        assert!(!capabilities.methods.contains("wallet_requestPermissions"));
        let permission = second
            .provider
            .permission_snapshot(restart_handle(), 1, NOW_MS + 8)
            .expect("restart permission snapshot");
        assert_eq!(permission.generation, 2);
        assert!(permission.record.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_next_advertises_only_exact_account_and_control_surface() {
        use std::os::unix::fs::PermissionsExt as _;

        let first_directory = tempfile::tempdir().expect("first private directory");
        std::fs::set_permissions(
            first_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("first private permissions");
        let config = production_hns_config(9, 0);
        let first_store = production_hns_store(
            &first_directory.path().join("wallet.sqlite3"),
            std::slice::from_ref(&config),
        );
        let first_selector = HnsExistingAccountSelector::new(first_store.clone(), config.clone())
            .expect("first selector");

        let second_directory = tempfile::tempdir().expect("second private directory");
        std::fs::set_permissions(
            second_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("second private permissions");
        let second_store = production_hns_store(
            &second_directory.path().join("wallet.sqlite3"),
            std::slice::from_ref(&config),
        );
        assert!(matches!(
            WalletService::new_persistent_hns_accounts(
                second_store.clone(),
                PersistentHnsAccountConfig {
                    selector: first_selector.clone(),
                    account_label: "Handshake".to_owned(),
                },
            ),
            Err(ServiceError::PersistentStoreAuthorityMismatch)
        ));

        let missing_selector =
            HnsExistingAccountSelector::new(second_store.clone(), production_hns_config(10, 1))
                .expect("missing-account selector configuration");
        let mut missing_account_service = WalletService::new_persistent_hns_accounts(
            second_store.clone(),
            PersistentHnsAccountConfig {
                selector: missing_selector,
                account_label: "Handshake".to_owned(),
            },
        )
        .expect("locked missing-account composition");
        assert!(matches!(
            missing_account_service.dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Unlock {
                        passphrase: hns_wallet_ffi::SecretString::new(
                            "correct horse battery staple".to_owned(),
                        ),
                    },
                },
                NOW_MS,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PersistenceFailure,
                ..
            })
        ));
        assert!(
            second_store
                .is_locked()
                .expect("failed unlock relocks store")
        );

        let mut service = WalletService::new_persistent_hns_accounts(
            first_store,
            PersistentHnsAccountConfig {
                selector: first_selector,
                account_label: "Handshake".to_owned(),
            },
        )
        .expect("same-authority composition");
        assert!(
            !service
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        );
        assert!(
            !service
                .capabilities
                .contains(&ServiceCapability::BrowserIntegration)
        );
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        unlock_production_hns(&mut service, NOW_MS + 1);
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = service
            .provider_capabilities(handle(), 1, NOW_MS + 2)
            .expect("capabilities")
        else {
            panic!("capabilities response")
        };
        assert_eq!(
            capabilities.methods,
            BTreeSet::from([
                "hns_accounts".to_owned(),
                "hns_requestAccounts".to_owned(),
                "wallet_getCapabilities".to_owned(),
                "wallet_getPermissions".to_owned(),
                "wallet_getStatus".to_owned(),
                "wallet_lock".to_owned(),
                "wallet_revokePermissions".to_owned(),
            ])
        );
        assert!(!capabilities.methods.contains("wallet_requestPermissions"));
        assert!(!capabilities.methods.contains("hns_getBalance"));
        assert!(!capabilities.methods.contains("hns_send"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_next_rejects_authenticated_zero_account_rows_without_exposure() {
        use std::os::unix::fs::PermissionsExt as _;

        let zero_directory = tempfile::tempdir().expect("zero-account private directory");
        std::fs::set_permissions(
            zero_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("zero-account private permissions");
        let zero_config = production_hns_config(0, 0);
        let zero_store = production_hns_store(
            &zero_directory.path().join("wallet.sqlite3"),
            std::slice::from_ref(&zero_config),
        );
        assert!(matches!(
            HnsExistingAccountSelector::new(zero_store.clone(), zero_config),
            Err(HnsWalletError::InvalidRuntimeConfiguration)
        ));
        assert!(
            zero_store
                .is_locked()
                .expect("zero-account store remains locked")
        );

        let malformed_directory = tempfile::tempdir().expect("malformed private directory");
        std::fs::set_permissions(
            malformed_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("malformed private permissions");
        let expected = production_hns_config(9, 0);
        let malformed = production_hns_account(production_hns_config(0, 0));
        let malformed_store = SharedWalletStore::new(
            WalletStore::create(
                malformed_directory.path().join("wallet.sqlite3"),
                "correct horse battery staple",
            )
            .expect("create malformed account store"),
        );
        malformed_store
            .with_store_mut(|wallet| {
                wallet
                    .save_wallet_account(&production_hns_record_id(&expected), 0, &malformed, 10)
                    .map(|_| ())
            })
            .expect("persist authenticated malformed row");
        malformed_store
            .lock()
            .expect("lock malformed account store");
        let selector = HnsExistingAccountSelector::new(malformed_store.clone(), expected)
            .expect("valid expected selector");
        let mut service = WalletService::new_persistent_hns_accounts(
            malformed_store.clone(),
            PersistentHnsAccountConfig {
                selector,
                account_label: "Handshake".to_owned(),
            },
        )
        .expect("locked malformed-row composition");
        assert!(matches!(
            service.dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Unlock {
                        passphrase: hns_wallet_ffi::SecretString::new(
                            "correct horse battery staple".to_owned(),
                        ),
                    },
                },
                NOW_MS,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PersistenceFailure,
                ..
            })
        ));
        assert!(
            malformed_store
                .is_locked()
                .expect("malformed unlock relocks")
        );
        assert!(matches!(
            service.dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::ListAccounts,
                },
                NOW_MS + 1,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::WalletLocked,
                ..
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_next_minimizes_and_rechecks_the_runtime_selected_singleton_account() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("private directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let config = production_hns_config(9, 0);
        let alternate_config = production_hns_config(10, 1);
        let store = production_hns_store(
            &directory.path().join("wallet.sqlite3"),
            &[config.clone(), alternate_config.clone()],
        );
        let mut service = production_hns_service(store.clone(), config.clone());
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("HNS authority");
        let mut icann = registration();
        icann.namespace = SelectedNamespace::Icann;
        service
            .provider
            .register_authority(restart_handle(), icann, NOW_MS)
            .expect("ICANN authority");
        unlock_production_hns(&mut service, NOW_MS + 1);

        assert!(matches!(
            service.provider_request(
                restart_handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 2,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 3,
            )
            .expect("account approval")
        else {
            panic!("account approval response")
        };
        let ServiceResponse::ProviderResult { value, .. } = service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 4,
            )
            .expect("account approval decision")
        else {
            panic!("account result")
        };
        assert_eq!(value, json!([config.account_id.to_string()]));
        let permission = service
            .provider
            .permission(handle(), 1, NOW_MS + 4)
            .expect("permission read")
            .expect("account permission");
        assert_eq!(
            permission.approved_accounts,
            BTreeSet::from([config.account_id])
        );
        assert_eq!(
            permission.capabilities,
            BTreeSet::from([PermissionCapability::Accounts])
        );

        let ServiceResponse::ProviderResult { value, .. } = service
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::HnsAccounts.wire_name().to_owned(),
                Value::Object(serde_json::Map::new()),
                NOW_MS + 5,
            )
            .expect("minimized account projection")
        else {
            panic!("account projection")
        };
        assert_eq!(value, json!([config.account_id.to_string()]));
        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                3,
                ProviderMethod::HnsAccounts.wire_name().to_owned(),
                json!({ "account": config.account_id }),
                NOW_MS + 6,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));

        let ServiceResponse::Wallet {
            response: WalletResponse::Locked,
        } = service
            .dispatch(
                ServiceRequest::Wallet {
                    request: WalletRequest::Lock,
                },
                NOW_MS + 7,
            )
            .expect("lock before alternate selection restart")
        else {
            panic!("lock response")
        };
        drop(service);

        let mut restarted = production_hns_service(store, alternate_config);
        restarted
            .provider
            .register_authority(handle(), registration(), NOW_MS + 8)
            .expect("restarted authority");
        unlock_production_hns(&mut restarted, NOW_MS + 9);
        assert!(matches!(
            restarted.provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 10,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::PermissionDenied,
                ..
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_next_restarts_locked_preserves_tombstone_and_returns_provider_lock() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("private directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let database_path = directory.path().join("wallet.sqlite3");
        let config = production_hns_config(9, 0);
        let first_store = production_hns_store(&database_path, std::slice::from_ref(&config));
        let mut first = production_hns_service(first_store.clone(), config.clone());
        first
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("first authority");
        assert!(matches!(
            first.provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::WalletLocked,
                ..
            })
        ));
        unlock_production_hns(&mut first, NOW_MS + 1);
        let ServiceResponse::ApprovalRequired { approval } = first
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 2,
            )
            .expect("account approval")
        else {
            panic!("approval")
        };
        first
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 3,
            )
            .expect("grant account");
        let ServiceResponse::ProviderResult { binding, .. } = first
            .provider_request(
                handle(),
                1,
                3,
                ProviderMethod::WalletRevokePermissions
                    .wire_name()
                    .to_owned(),
                Value::Null,
                NOW_MS + 4,
            )
            .expect("revoke permission")
        else {
            panic!("revoke result")
        };
        assert_eq!(binding.permission_generation, 2);
        let old_wallet_session = first.wallet_session_id;
        let old_service_session = first.service_session_id;
        let ServiceResponse::ProviderResult { binding, value } = first
            .provider_request(
                handle(),
                1,
                4,
                ProviderMethod::WalletLock.wire_name().to_owned(),
                Value::Null,
                NOW_MS + 5,
            )
            .expect("provider lock result")
        else {
            panic!("provider lock")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_ne!(binding.wallet_session_id, old_wallet_session);
        assert_eq!(value, json!({ "locked": true }));
        assert!(first_store.is_locked().expect("locked shared store"));
        drop(first);
        drop(first_store);

        let reopened_store =
            SharedWalletStore::new(WalletStore::open(&database_path).expect("reopen wallet store"));
        let mut restarted = production_hns_service(reopened_store.clone(), config);
        assert!(reopened_store.is_locked().expect("restart locked"));
        assert_ne!(restarted.wallet_session_id, old_wallet_session);
        assert_ne!(restarted.service_session_id, old_service_session);
        assert!(restarted.pending.is_empty());
        assert!(restarted.seen_request_ids.is_empty());
        assert!(restarted.event_sequences.is_empty());
        restarted
            .provider
            .register_authority(restart_handle(), registration(), NOW_MS + 6)
            .expect("restart authority");
        unlock_production_hns(&mut restarted, NOW_MS + 7);
        let ServiceResponse::ProviderCapabilities {
            binding,
            capabilities,
        } = restarted
            .provider_capabilities(restart_handle(), 1, NOW_MS + 8)
            .expect("restart capabilities")
        else {
            panic!("restart capabilities")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_eq!(capabilities.permission_generation, 2);
        let tombstone = restarted
            .provider
            .permission_snapshot(restart_handle(), 1, NOW_MS + 8)
            .expect("restart tombstone");
        assert_eq!(tombstone.generation, 2);
        assert!(tombstone.record.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_next_rejects_all_value_module_and_unspecified_chain_reads() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("private directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let config = production_hns_config(9, 0);
        let store = production_hns_store(
            &directory.path().join("wallet.sqlite3"),
            std::slice::from_ref(&config),
        );
        let mut service = production_hns_service(store, config);
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        unlock_production_hns(&mut service, NOW_MS + 1);
        let unsupported = [
            ProviderMethod::HnsGetBalance,
            ProviderMethod::HnsGetTransactions,
            ProviderMethod::HnsGetReceiveAddress,
            ProviderMethod::HnsGetNames,
            ProviderMethod::HnsGetName,
            ProviderMethod::HnsImportKnownName,
            ProviderMethod::HnsSend,
            ProviderMethod::HnsTransferName,
            ProviderMethod::HnsFinalizeName,
            ProviderMethod::HnsSignTypedMessage,
            ProviderMethod::WalletEnableModule,
            ProviderMethod::WalletDisableModule,
        ];
        for (index, method) in unsupported.into_iter().enumerate() {
            assert!(matches!(
                service.provider_request(
                    handle(),
                    1,
                    u64::try_from(index).expect("bounded index") + 1,
                    method.wire_name().to_owned(),
                    Value::Null,
                    NOW_MS + 2 + u64::try_from(index).expect("bounded index"),
                ),
                Err(ServiceFailure {
                    code: ServiceErrorCode::UnsupportedCapability,
                    ..
                })
            ));
        }
        assert!(matches!(
            service.provider_request(
                handle(),
                1,
                100,
                ProviderMethod::WalletRequestPermissions
                    .wire_name()
                    .to_owned(),
                json!({ "capabilities": ["balance"] }),
                NOW_MS + 100,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));
        assert!(
            !service
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        );
        assert!(
            !service
                .capabilities
                .contains(&ServiceCapability::BrowserIntegration)
        );
    }

    #[test]
    fn private_provider_capabilities_are_typed_exact_and_bound() {
        let mut service = provider_service();
        let response = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("capabilities");
        let ServiceResponse::ProviderCapabilities {
            binding,
            capabilities: snapshot,
        } = response
        else {
            panic!("private capabilities")
        };
        assert_eq!(binding.wallet_session_id, service.wallet_session_id);
        assert_eq!(binding.permission_generation, 0);
        assert_eq!(snapshot.provider_schema_version, 1);
        assert_eq!(snapshot.approval_schema_version, 3);
        assert_eq!(snapshot.permission_generation, 0);
        assert!(!snapshot.methods.contains("hns_requestAccounts"));
        assert_eq!(
            snapshot.methods,
            BTreeSet::from([
                "wallet_getCapabilities".to_owned(),
                "wallet_getPermissions".to_owned(),
                "wallet_revokePermissions".to_owned(),
            ])
        );
    }

    #[test]
    fn canonical_provider_account_join_persists_and_projects_only_the_approved_account() {
        let mut service = account_service();
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("capabilities")
        else {
            panic!("private capabilities")
        };
        assert!(capabilities.methods.contains("hns_requestAccounts"));
        assert!(capabilities.methods.contains("hns_accounts"));

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("account request")
        else {
            panic!("approval")
        };
        assert_eq!(
            approval.summary,
            ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Accounts]),
                hns_names: Vec::new(),
            }
        );

        let ServiceResponse::ProviderResult { binding, value } = service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 1,
            )
            .expect("approved account join")
        else {
            panic!("account result")
        };
        let account = AccountId::new([9_u8; 16]);
        assert_eq!(binding.permission_generation, 1);
        assert_eq!(value, json!([account.to_string()]));
        let permission = service
            .provider
            .permission(handle(), 1, NOW_MS + 1)
            .expect("permission")
            .expect("grant");
        assert_eq!(permission.approved_accounts, BTreeSet::from([account]));

        let ServiceResponse::ProviderResult { binding, value } = service
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::HnsAccounts.wire_name().to_owned(),
                Value::Object(serde_json::Map::new()),
                NOW_MS + 2,
            )
            .expect("account projection")
        else {
            panic!("account projection")
        };
        assert_eq!(binding.permission_generation, 1);
        assert_eq!(value, json!([account.to_string()]));

        service.runtime.account_join_available = false;
        let failure = service.provider_request(
            handle(),
            1,
            3,
            ProviderMethod::HnsAccounts.wire_name().to_owned(),
            Value::Null,
            NOW_MS + 3,
        );
        assert!(matches!(
            failure,
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));

        let failure = service.provider_request(
            handle(),
            1,
            4,
            ProviderMethod::WalletRequestPermissions
                .wire_name()
                .to_owned(),
            json!({ "capabilities": ["accounts"] }),
            NOW_MS + 4,
        );
        assert!(matches!(
            failure,
            Err(ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));
    }

    #[test]
    fn canonical_provider_account_join_rechecks_runtime_when_approval_executes() {
        let mut service = account_service();
        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("account request")
        else {
            panic!("approval")
        };
        service.runtime.account_join_available = false;
        assert!(matches!(
            service.approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 1,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));
        let permission = service
            .provider
            .permission_snapshot(handle(), 1, NOW_MS + 1)
            .expect("permission snapshot");
        assert_eq!(permission.generation, 0);
        assert!(permission.record.is_none());
    }

    #[test]
    fn website_capabilities_expose_only_public_api_version_and_methods() {
        let mut service = provider_service();
        let response = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::WalletGetCapabilities.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("website capabilities");
        let ServiceResponse::ProviderResult { binding, value } = response else {
            panic!("provider result")
        };
        assert_eq!(binding.permission_generation, 0);
        assert_eq!(
            value
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["methods".to_owned(), "providerApiVersion".to_owned()])
        );
        assert_eq!(value["providerApiVersion"], json!(1));
    }

    #[test]
    fn get_permissions_returns_the_revocation_tombstone_generation() {
        let mut service = provider_service();
        service
            .provider
            .set_wallet_state(service.wallet_session_id, false);
        service
            .provider
            .grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Send]),
                BTreeSet::new(),
                NOW_MS,
                None,
            )
            .expect("grant");
        assert_eq!(
            service
                .provider
                .revoke_permissions(handle(), 1, NOW_MS)
                .expect("revoke"),
            2
        );
        let response = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::WalletGetPermissions.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("permissions");
        let ServiceResponse::ProviderResult { binding, value } = response else {
            panic!("provider result")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_eq!(value["permissionGeneration"], json!(2));
        assert_eq!(value["capabilities"], json!([]));
    }
}
