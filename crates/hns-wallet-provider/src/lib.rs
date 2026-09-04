#![doc = "Hostile-page request, permission, approval, and event policy core."]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use hns_wallet_store::{SharedWalletStore, StoreError, WalletStore};
use hns_wallet_types::{
    AccountId, ApprovalId, ApprovalKind, BrowserRuntimeSessionId, HostAuthorityHandleId,
    PROVIDER_METHOD_WIRE_NAMES, PermissionCapability, ProviderAuthorityFingerprint,
    WalletSessionId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

pub const MAX_PROVIDER_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_METHOD_BYTES: usize = 96;
pub const MAX_ORIGIN_BYTES: usize = 512;
pub const APPROVAL_LIFETIME_SECONDS: u64 = 90;
pub const RATE_WINDOW_SECONDS: u64 = 60;
pub const MAX_REGISTERED_AUTHORITIES: usize = 256;
pub const MAX_PENDING_APPROVALS: usize = 128;
pub const MAX_REPLAY_NONCES: usize = 4_096;
pub const MAX_APPROVED_ACCOUNTS: usize = 16;
pub const MAX_APPROVED_NAMES: usize = 128;
pub const PROVIDER_API_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Origin {
    serialized: String,
}

impl Origin {
    pub fn parse(input: &str) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > MAX_ORIGIN_BYTES || !input.is_ascii() {
            return Err(ProviderError::InvalidOrigin);
        }
        let parsed = Url::parse(input).map_err(|_| ProviderError::InvalidOrigin)?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(ProviderError::InvalidOrigin);
        }
        let host = parsed.host().ok_or(ProviderError::InvalidOrigin)?;
        let loopback = match host {
            Host::Domain(domain) => domain == "localhost",
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        };
        let secure = parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback);
        if !secure {
            return Err(ProviderError::InsecureContext);
        }
        let port = parsed
            .port_or_known_default()
            .ok_or(ProviderError::InvalidOrigin)?;
        let default_port = (parsed.scheme() == "https" && port == 443)
            || (parsed.scheme() == "http" && port == 80);
        let serialized_host = parsed.host_str().ok_or(ProviderError::InvalidOrigin)?;
        let serialized = if default_port {
            format!("{}://{serialized_host}", parsed.scheme())
        } else {
            format!("{}://{serialized_host}:{port}", parsed.scheme())
        };
        Ok(Self { serialized })
    }

    pub fn as_str(&self) -> &str {
        &self.serialized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectedNamespace {
    Hns,
    Icann,
}

/// Facts copied from an engine-issued authority by the trusted browser host.
///
/// The affirmative registration operation is the authorization signal. There
/// are deliberately no caller-constructible authentication or injection
/// booleans here, and wallet lock/session/permission state is never supplied
/// by the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAuthorityRegistration {
    pub origin: Origin,
    pub namespace: SelectedNamespace,
    pub runtime_session: BrowserRuntimeSessionId,
    pub runtime_generation: u64,
    pub policy_generation: u64,
    pub navigation_generation: u64,
    pub decision_fingerprint: ProviderAuthorityFingerprint,
    pub valid_until_unix_ms: u64,
}

impl HostAuthorityRegistration {
    fn validate(&self, now_unix_ms: u64) -> Result<(), ProviderError> {
        if self.runtime_generation == 0
            || self.policy_generation == 0
            || self.navigation_generation == 0
            || self.valid_until_unix_ms <= now_unix_ms
        {
            return Err(ProviderError::StaleContext);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl ProviderRequest {
    pub fn decode(input: &[u8]) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > MAX_PROVIDER_REQUEST_BYTES {
            return Err(ProviderError::RequestTooLarge);
        }
        let request: Self =
            serde_json::from_slice(input).map_err(|_| ProviderError::InvalidParams)?;
        if request.method.is_empty() || request.method.len() > MAX_METHOD_BYTES {
            return Err(ProviderError::MethodNotFound);
        }
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProviderMethod {
    WalletGetCapabilities,
    WalletGetEnabledModules,
    WalletEnableModule,
    WalletDisableModule,
    WalletRequestPermissions,
    WalletGetPermissions,
    WalletRevokePermissions,
    WalletLock,
    WalletGetStatus,
    HnsRequestAccounts,
    HnsAccounts,
    HnsGetBalance,
    HnsGetTransactions,
    HnsGetReceiveAddress,
    HnsSend,
    HnsGetNames,
    HnsGetName,
    HnsImportKnownName,
    HnsTransferName,
    HnsFinalizeName,
    HnsSignTypedMessage,
    AssetGetAccount,
    AssetGetBalance,
    AssetGetTransactions,
    AssetGetReceiveTarget,
    AssetSend,
    NameMarketListOffers,
    NameMarketCreateFixedPriceOffer,
    NameMarketCancelOffer,
    NameMarketAcceptOffer,
    NameMarketGetSession,
    NameMarketFinalizePurchase,
    NameMarketRecoverName,
    SwapGetSupportedPairs,
    SwapListDirectOffers,
    SwapPublishDirectOffer,
    SwapCancelDirectOffer,
    SwapTakeDirectOffer,
    SwapAcceptDirectOffer,
    SwapGetSession,
    SwapRedeem,
    SwapRefund,
    /// Set the exact Handshake resource bytes for a currently owned name.
    /// Appended to preserve every existing stable enum/wire index.
    HnsUpdateName,
}

impl ProviderMethod {
    pub const ALL: [Self; PROVIDER_METHOD_WIRE_NAMES.len()] = [
        Self::WalletGetCapabilities,
        Self::WalletGetEnabledModules,
        Self::WalletEnableModule,
        Self::WalletDisableModule,
        Self::WalletRequestPermissions,
        Self::WalletGetPermissions,
        Self::WalletRevokePermissions,
        Self::WalletLock,
        Self::WalletGetStatus,
        Self::HnsRequestAccounts,
        Self::HnsAccounts,
        Self::HnsGetBalance,
        Self::HnsGetTransactions,
        Self::HnsGetReceiveAddress,
        Self::HnsSend,
        Self::HnsGetNames,
        Self::HnsGetName,
        Self::HnsImportKnownName,
        Self::HnsTransferName,
        Self::HnsFinalizeName,
        Self::HnsSignTypedMessage,
        Self::AssetGetAccount,
        Self::AssetGetBalance,
        Self::AssetGetTransactions,
        Self::AssetGetReceiveTarget,
        Self::AssetSend,
        Self::NameMarketListOffers,
        Self::NameMarketCreateFixedPriceOffer,
        Self::NameMarketCancelOffer,
        Self::NameMarketAcceptOffer,
        Self::NameMarketGetSession,
        Self::NameMarketFinalizePurchase,
        Self::NameMarketRecoverName,
        Self::SwapGetSupportedPairs,
        Self::SwapListDirectOffers,
        Self::SwapPublishDirectOffer,
        Self::SwapCancelDirectOffer,
        Self::SwapTakeDirectOffer,
        Self::SwapAcceptDirectOffer,
        Self::SwapGetSession,
        Self::SwapRedeem,
        Self::SwapRefund,
        Self::HnsUpdateName,
    ];

    pub const fn wire_name(self) -> &'static str {
        PROVIDER_METHOD_WIRE_NAMES[self as usize]
    }

    pub fn parse(method: &str) -> Result<Self, ProviderError> {
        if let Some(index) = PROVIDER_METHOD_WIRE_NAMES
            .iter()
            .position(|candidate| *candidate == method)
        {
            return Ok(Self::ALL[index]);
        }
        if FORBIDDEN_METHODS.contains(&method) {
            Err(ProviderError::ForbiddenMethod)
        } else {
            Err(ProviderError::MethodNotFound)
        }
    }

    pub const fn requires_hns_namespace(self) -> bool {
        matches!(
            self,
            Self::HnsRequestAccounts
                | Self::HnsAccounts
                | Self::HnsGetBalance
                | Self::HnsGetTransactions
                | Self::HnsGetReceiveAddress
                | Self::HnsSend
                | Self::HnsGetNames
                | Self::HnsGetName
                | Self::HnsImportKnownName
                | Self::HnsTransferName
                | Self::HnsFinalizeName
                | Self::HnsUpdateName
                | Self::HnsSignTypedMessage
                | Self::NameMarketListOffers
                | Self::NameMarketCreateFixedPriceOffer
                | Self::NameMarketCancelOffer
                | Self::NameMarketAcceptOffer
                | Self::NameMarketGetSession
                | Self::NameMarketFinalizePurchase
                | Self::NameMarketRecoverName
        )
    }

    pub const fn permission(self) -> Option<PermissionCapability> {
        match self {
            Self::WalletGetCapabilities
            | Self::WalletGetEnabledModules
            | Self::WalletRequestPermissions
            | Self::WalletGetPermissions
            | Self::WalletRevokePermissions
            | Self::WalletLock
            | Self::WalletGetStatus
            | Self::HnsRequestAccounts
            | Self::SwapGetSupportedPairs => None,
            Self::HnsAccounts | Self::AssetGetAccount => Some(PermissionCapability::Accounts),
            Self::HnsGetBalance | Self::AssetGetBalance => Some(PermissionCapability::Balance),
            Self::HnsGetTransactions | Self::AssetGetTransactions => {
                Some(PermissionCapability::Transactions)
            }
            Self::HnsGetReceiveAddress | Self::AssetGetReceiveTarget => {
                Some(PermissionCapability::ReceiveTarget)
            }
            Self::HnsSend | Self::AssetSend => Some(PermissionCapability::Send),
            Self::HnsGetNames | Self::HnsGetName | Self::HnsImportKnownName => {
                Some(PermissionCapability::Names)
            }
            Self::HnsTransferName => Some(PermissionCapability::NameTransfer),
            Self::HnsFinalizeName => Some(PermissionCapability::NameFinalize),
            Self::HnsUpdateName => Some(PermissionCapability::NameUpdate),
            Self::HnsSignTypedMessage => Some(PermissionCapability::TypedIdentitySignature),
            Self::NameMarketListOffers
            | Self::NameMarketCreateFixedPriceOffer
            | Self::NameMarketCancelOffer
            | Self::NameMarketAcceptOffer
            | Self::NameMarketGetSession
            | Self::NameMarketFinalizePurchase
            | Self::NameMarketRecoverName => Some(PermissionCapability::NameMarket),
            Self::SwapListDirectOffers
            | Self::SwapPublishDirectOffer
            | Self::SwapCancelDirectOffer
            | Self::SwapTakeDirectOffer
            | Self::SwapAcceptDirectOffer => Some(PermissionCapability::CrossChainMarket),
            Self::SwapGetSession | Self::SwapRedeem | Self::SwapRefund => {
                Some(PermissionCapability::SwapSettlement)
            }
            Self::WalletEnableModule | Self::WalletDisableModule => None,
        }
    }

    pub const fn approval(self) -> Option<ApprovalKind> {
        match self {
            Self::WalletEnableModule | Self::WalletDisableModule => {
                Some(ApprovalKind::ModuleEnablement)
            }
            Self::WalletRequestPermissions | Self::HnsRequestAccounts => {
                Some(ApprovalKind::Permission)
            }
            Self::HnsSend | Self::AssetSend => Some(ApprovalKind::Send),
            Self::HnsTransferName => Some(ApprovalKind::NameTransfer),
            Self::HnsFinalizeName => Some(ApprovalKind::NameFinalize),
            Self::HnsUpdateName => Some(ApprovalKind::NameUpdate),
            Self::HnsSignTypedMessage => Some(ApprovalKind::TypedSignature),
            Self::NameMarketCreateFixedPriceOffer | Self::NameMarketCancelOffer => {
                Some(ApprovalKind::NameMarketOffer)
            }
            Self::NameMarketAcceptOffer | Self::NameMarketFinalizePurchase => {
                Some(ApprovalKind::NameMarketPurchase)
            }
            Self::NameMarketRecoverName => Some(ApprovalKind::NameMarketOffer),
            Self::SwapPublishDirectOffer | Self::SwapCancelDirectOffer => {
                Some(ApprovalKind::DirectOffer)
            }
            Self::SwapTakeDirectOffer | Self::SwapAcceptDirectOffer => {
                Some(ApprovalKind::DirectOfferTake)
            }
            Self::SwapRedeem => Some(ApprovalKind::SwapRedeem),
            Self::SwapRefund => Some(ApprovalKind::SwapRefund),
            _ => None,
        }
    }

    const fn rate_limit(self) -> u32 {
        if self.approval().is_some() { 10 } else { 120 }
    }
}

const FORBIDDEN_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_call",
    "eth_estimateGas",
    "eth_sign",
    "personal_sign",
    "wallet_addEthereumChain",
    "wallet_switchEthereumChain",
    "bitcoin_signPsbt",
    "signRawTransaction",
    "wallet_getSeed",
    "wallet_getPrivateKey",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionRecord {
    pub origin: Origin,
    pub namespace: SelectedNamespace,
    pub generation: u64,
    pub capabilities: BTreeSet<PermissionCapability>,
    /// Exact wallet-local accounts visible to this origin. Legacy records that
    /// claimed `Accounts` without this binding deserialize but fail closed.
    #[serde(default)]
    pub approved_accounts: BTreeSet<AccountId>,
    pub approved_names: BTreeSet<[u8; 32]>,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

/// The current authority-scoped permission view. `generation` survives an
/// absent or expired record so a revocation tombstone can never project as a
/// fresh generation zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    pub generation: u64,
    pub record: Option<PermissionRecord>,
}

impl PermissionRecord {
    fn permits(&self, capability: PermissionCapability, now_unix: u64) -> bool {
        self.capabilities.contains(&capability)
            && self.expires_at_unix.is_none_or(|expiry| expiry > now_unix)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovedCall {
    pub origin: Origin,
    pub namespace: SelectedNamespace,
    pub method: ProviderMethod,
    pub params: Value,
    pub request_nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: ApprovalId,
    pub kind: ApprovalKind,
    pub call: ApprovedCall,
    pub authority_handle: HostAuthorityHandleId,
    pub authority_revision: u64,
    pub wallet_session: WalletSessionId,
    pub permission_generation: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProviderAction {
    Execute(ApprovedCall),
    ApprovalRequired(PendingApproval),
}

pub trait ProviderStateStore {
    fn permission(&self, scope: &str) -> Result<Option<PermissionRecord>, ProviderError>;
    fn permission_generation(&self, scope: &str) -> Result<Option<u64>, ProviderError>;
    fn save_permission(
        &mut self,
        scope: &str,
        record: &PermissionRecord,
    ) -> Result<(), ProviderError>;
    fn revoke_permission(
        &mut self,
        scope: &str,
        expected_generation: u64,
        next_generation: u64,
        now_unix: u64,
    ) -> Result<(), ProviderError>;
}

impl ProviderStateStore for WalletStore {
    fn permission(&self, scope: &str) -> Result<Option<PermissionRecord>, ProviderError> {
        self.provider_permission(scope)?
            .map(|(_, bytes)| serde_json::from_slice(&bytes).map_err(ProviderError::from))
            .transpose()
    }

    fn permission_generation(&self, scope: &str) -> Result<Option<u64>, ProviderError> {
        Ok(self.provider_permission_generation(scope)?)
    }

    fn save_permission(
        &mut self,
        scope: &str,
        record: &PermissionRecord,
    ) -> Result<(), ProviderError> {
        self.put_provider_permission(
            scope,
            record.generation,
            &serde_json::to_vec(record)?,
            record.created_at_unix,
        )?;
        Ok(())
    }

    fn revoke_permission(
        &mut self,
        scope: &str,
        expected_generation: u64,
        next_generation: u64,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        self.revoke_provider_permission(scope, expected_generation, next_generation, now_unix)?;
        Ok(())
    }
}

impl ProviderStateStore for SharedWalletStore {
    fn permission(&self, scope: &str) -> Result<Option<PermissionRecord>, ProviderError> {
        self.with_store(|store| store.provider_permission(scope))?
            .map(|(_, bytes)| serde_json::from_slice(&bytes).map_err(ProviderError::from))
            .transpose()
    }

    fn permission_generation(&self, scope: &str) -> Result<Option<u64>, ProviderError> {
        Ok(self.with_store(|store| store.provider_permission_generation(scope))?)
    }

    fn save_permission(
        &mut self,
        scope: &str,
        record: &PermissionRecord,
    ) -> Result<(), ProviderError> {
        let encoded = serde_json::to_vec(record)?;
        self.with_store_mut(|store| {
            store.put_provider_permission(
                scope,
                record.generation,
                &encoded,
                record.created_at_unix,
            )
        })?;
        Ok(())
    }

    fn revoke_permission(
        &mut self,
        scope: &str,
        expected_generation: u64,
        next_generation: u64,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        self.with_store_mut(|store| {
            store.revoke_provider_permission(scope, expected_generation, next_generation, now_unix)
        })?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryProviderState {
    permissions: BTreeMap<String, PermissionRecord>,
    permission_generations: BTreeMap<String, u64>,
}

impl ProviderStateStore for MemoryProviderState {
    fn permission(&self, scope: &str) -> Result<Option<PermissionRecord>, ProviderError> {
        Ok(self.permissions.get(scope).cloned())
    }

    fn permission_generation(&self, scope: &str) -> Result<Option<u64>, ProviderError> {
        Ok(self.permission_generations.get(scope).copied())
    }

    fn save_permission(
        &mut self,
        scope: &str,
        record: &PermissionRecord,
    ) -> Result<(), ProviderError> {
        let expected = match self.permission_generations.get(scope).copied() {
            Some(current) => current.checked_add(1).ok_or(ProviderError::StaleContext)?,
            None => record.generation,
        };
        if record.generation != expected {
            return Err(ProviderError::StaleContext);
        }
        self.permission_generations
            .insert(scope.to_owned(), record.generation);
        self.permissions.insert(scope.to_owned(), record.clone());
        Ok(())
    }

    fn revoke_permission(
        &mut self,
        scope: &str,
        expected_generation: u64,
        next_generation: u64,
        _: u64,
    ) -> Result<(), ProviderError> {
        if self.permission_generations.get(scope).copied() != Some(expected_generation)
            || next_generation
                != expected_generation
                    .checked_add(1)
                    .ok_or(ProviderError::StaleContext)?
        {
            return Err(ProviderError::StaleContext);
        }
        self.permissions.remove(scope);
        self.permission_generations
            .insert(scope.to_owned(), next_generation);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegisteredAuthority {
    facts: HostAuthorityRegistration,
    revision: u64,
}

/// Provider policy and persisted state behind a bounded registry of opaque,
/// host-issued handles. Pages never construct or observe a registered
/// authority, and no engine policy is duplicated here.
pub struct ProviderCore<S> {
    state: S,
    authorities: BTreeMap<HostAuthorityHandleId, RegisteredAuthority>,
    wallet_session: WalletSessionId,
    wallet_locked: bool,
    last_now_unix_ms: u64,
    pending: BTreeMap<ApprovalId, PendingApproval>,
    replay: BTreeMap<(HostAuthorityHandleId, u64), u64>,
    rate: BTreeMap<(HostAuthorityHandleId, ProviderMethod), RateWindow>,
}

impl<S: ProviderStateStore> ProviderCore<S> {
    pub fn new(state: S, wallet_session: WalletSessionId, wallet_locked: bool) -> Self {
        Self {
            state,
            authorities: BTreeMap::new(),
            wallet_session,
            wallet_locked,
            last_now_unix_ms: 0,
            pending: BTreeMap::new(),
            replay: BTreeMap::new(),
            rate: BTreeMap::new(),
        }
    }

    pub fn register_authority(
        &mut self,
        handle: HostAuthorityHandleId,
        facts: HostAuthorityRegistration,
        now_unix_ms: u64,
    ) -> Result<u64, ProviderError> {
        self.accept_time(now_unix_ms)?;
        facts.validate(now_unix_ms)?;
        self.prune_expired_authorities(now_unix_ms);
        if self.authorities.contains_key(&handle) {
            return Err(ProviderError::DuplicateAuthority);
        }
        if self.authorities.len() >= MAX_REGISTERED_AUTHORITIES {
            return Err(ProviderError::AuthorityCapacity);
        }
        self.authorities
            .insert(handle, RegisteredAuthority { facts, revision: 1 });
        Ok(1)
    }

    pub fn replace_authority(
        &mut self,
        handle: HostAuthorityHandleId,
        expected_revision: u64,
        replacement: HostAuthorityRegistration,
        now_unix_ms: u64,
    ) -> Result<u64, ProviderError> {
        self.accept_time(now_unix_ms)?;
        replacement.validate(now_unix_ms)?;
        let current = self
            .authorities
            .get(&handle)
            .cloned()
            .ok_or(ProviderError::AuthorityNotFound)?;
        if expected_revision == 0
            || current.revision != expected_revision
            || current.facts.valid_until_unix_ms <= now_unix_ms
            || replacement.origin != current.facts.origin
            || replacement.namespace != current.facts.namespace
            || replacement.runtime_session != current.facts.runtime_session
            || replacement.runtime_generation < current.facts.runtime_generation
            || replacement.policy_generation < current.facts.policy_generation
            || replacement.navigation_generation < current.facts.navigation_generation
        {
            return Err(ProviderError::StaleContext);
        }
        let revision = current
            .revision
            .checked_add(1)
            .ok_or(ProviderError::StaleContext)?;
        self.authorities.insert(
            handle,
            RegisteredAuthority {
                facts: replacement,
                revision,
            },
        );
        self.pending
            .retain(|_, approval| approval.authority_handle != handle);
        self.rate.retain(|(candidate, _), _| *candidate != handle);
        self.replay.retain(|(candidate, _), _| *candidate != handle);
        Ok(revision)
    }

    pub fn revoke_authority(
        &mut self,
        handle: HostAuthorityHandleId,
        expected_revision: u64,
    ) -> Result<(), ProviderError> {
        let authority = self
            .authorities
            .get(&handle)
            .ok_or(ProviderError::AuthorityNotFound)?;
        if expected_revision == 0 || authority.revision != expected_revision {
            return Err(ProviderError::StaleContext);
        }
        self.authorities.remove(&handle);
        self.pending
            .retain(|_, approval| approval.authority_handle != handle);
        self.rate.retain(|(candidate, _), _| *candidate != handle);
        self.replay.retain(|(candidate, _), _| *candidate != handle);
        Ok(())
    }

    pub fn set_wallet_state(&mut self, wallet_session: WalletSessionId, wallet_locked: bool) {
        if wallet_session != self.wallet_session || wallet_locked != self.wallet_locked {
            self.pending.clear();
            self.replay.clear();
            self.rate.clear();
        }
        self.wallet_session = wallet_session;
        self.wallet_locked = wallet_locked;
    }

    pub const fn wallet_session_id(&self) -> WalletSessionId {
        self.wallet_session
    }

    pub fn request(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        request_nonce: u64,
        now_unix_ms: u64,
        request_bytes: &[u8],
    ) -> Result<ProviderAction, ProviderError> {
        self.accept_time(now_unix_ms)?;
        let request = ProviderRequest::decode(request_bytes)?;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        if request_nonce == 0 {
            return Err(ProviderError::Replay);
        }
        let method = ProviderMethod::parse(&request.method)?;
        if method.requires_hns_namespace() && authority.facts.namespace != SelectedNamespace::Hns {
            return Err(ProviderError::Unauthorized);
        }
        validate_module_params(method, &request.params)?;
        let now_unix = now_unix_ms / 1_000;
        self.enforce_rate(handle, method, now_unix)?;
        let expires_at_unix = now_unix_ms
            .checked_add(APPROVAL_LIFETIME_SECONDS * 1_000)
            .ok_or(ProviderError::StaleContext)?
            / 1_000;
        self.consume_nonce(handle, request_nonce, now_unix, expires_at_unix)?;

        if self.wallet_locked
            && !matches!(
                method,
                ProviderMethod::WalletGetStatus | ProviderMethod::WalletGetCapabilities
            )
        {
            return Err(ProviderError::WalletLocked);
        }
        let scope = permission_scope(&authority.facts);
        let permission_generation = self.state.permission_generation(&scope)?.unwrap_or(0);
        if let Some(required) = method.permission() {
            let permission = validate_permission_identity(
                self.state.permission(&scope)?,
                &authority.facts,
                now_unix,
            )?
            .ok_or(ProviderError::Unauthorized)?;
            if permission.generation != permission_generation
                || !permission.permits(required, now_unix)
            {
                return Err(ProviderError::Unauthorized);
            }
        }

        let call = ApprovedCall {
            origin: authority.facts.origin.clone(),
            namespace: authority.facts.namespace,
            method,
            params: request.params,
            request_nonce,
        };
        let Some(kind) = method.approval() else {
            return Ok(ProviderAction::Execute(call));
        };
        self.pending
            .retain(|_, approval| approval.expires_at_unix > now_unix);
        if self.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(ProviderError::RateLimited);
        }
        let approval = PendingApproval {
            id: approval_id(
                handle,
                authority_revision,
                self.wallet_session,
                request_nonce,
                method,
                authority.facts.namespace,
                &authority.facts.origin,
            ),
            kind,
            call,
            authority_handle: handle,
            authority_revision,
            wallet_session: self.wallet_session,
            permission_generation,
            expires_at_unix,
        };
        self.pending.insert(approval.id, approval.clone());
        Ok(ProviderAction::ApprovalRequired(approval))
    }

    pub fn approve(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        id: ApprovalId,
        now_unix_ms: u64,
    ) -> Result<ApprovedCall, ProviderError> {
        self.accept_time(now_unix_ms)?;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        let approval = self
            .pending
            .get(&id)
            .cloned()
            .ok_or(ProviderError::StaleApproval)?;
        let now_unix = now_unix_ms / 1_000;
        let scope = permission_scope(&authority.facts);
        let permission_generation = self.state.permission_generation(&scope)?.unwrap_or(0);
        if approval.expires_at_unix <= now_unix_ms / 1_000
            || approval.call.origin != authority.facts.origin
            || approval.call.namespace != authority.facts.namespace
            || approval.authority_handle != handle
            || approval.authority_revision != authority_revision
            || approval.wallet_session != self.wallet_session
            || approval.permission_generation != permission_generation
        {
            return Err(ProviderError::StaleApproval);
        }
        if let Some(required) = approval.call.method.permission() {
            let permission = validate_permission_identity(
                self.state.permission(&scope)?,
                &authority.facts,
                now_unix,
            )?
            .ok_or(ProviderError::StaleApproval)?;
            if permission.generation != permission_generation
                || !permission.permits(required, now_unix)
            {
                return Err(ProviderError::StaleApproval);
            }
        }
        self.pending.remove(&id);
        Ok(approval.call)
    }

    pub fn reject(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        id: ApprovalId,
        now_unix_ms: u64,
    ) -> Result<(), ProviderError> {
        self.accept_time(now_unix_ms)?;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        let approval = self
            .pending
            .get(&id)
            .cloned()
            .ok_or(ProviderError::StaleApproval)?;
        let scope = permission_scope(&authority.facts);
        let permission_generation = self.state.permission_generation(&scope)?.unwrap_or(0);
        if approval.expires_at_unix <= now_unix_ms / 1_000
            || approval.call.origin != authority.facts.origin
            || approval.call.namespace != authority.facts.namespace
            || approval.authority_handle != handle
            || approval.authority_revision != authority_revision
            || approval.wallet_session != self.wallet_session
            || approval.permission_generation != permission_generation
        {
            return Err(ProviderError::StaleApproval);
        }
        self.pending.remove(&id);
        Ok(())
    }

    pub fn permission_snapshot(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<PermissionSnapshot, ProviderError> {
        self.accept_time(now_unix_ms)?;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        let scope = permission_scope(&authority.facts);
        let generation = self.state.permission_generation(&scope)?.unwrap_or(0);
        let stored = self.state.permission(&scope)?;
        if stored
            .as_ref()
            .is_some_and(|permission| permission.generation != generation)
        {
            return Err(ProviderError::Persistence);
        }
        let permission =
            validate_permission_identity(stored, &authority.facts, now_unix_ms / 1_000)?;
        Ok(PermissionSnapshot {
            generation,
            record: permission,
        })
    }

    pub fn permission(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<Option<PermissionRecord>, ProviderError> {
        Ok(self
            .permission_snapshot(handle, authority_revision, now_unix_ms)?
            .record)
    }

    pub fn grant_permissions(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        capabilities: BTreeSet<PermissionCapability>,
        approved_names: BTreeSet<[u8; 32]>,
        now_unix_ms: u64,
        expires_at_unix: Option<u64>,
    ) -> Result<PermissionRecord, ProviderError> {
        self.grant_scoped_permissions(
            handle,
            authority_revision,
            capabilities,
            BTreeSet::new(),
            approved_names,
            now_unix_ms,
            expires_at_unix,
        )
    }

    /// Persist one generation of origin/namespace permission authority with
    /// an exact account disclosure set. Account capability without a binding,
    /// or a binding without account capability, is never accepted.
    // These fields form the explicit permission-grant boundary; grouping them
    // would obscure the public API's security-relevant inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_scoped_permissions(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        capabilities: BTreeSet<PermissionCapability>,
        approved_accounts: BTreeSet<AccountId>,
        approved_names: BTreeSet<[u8; 32]>,
        now_unix_ms: u64,
        expires_at_unix: Option<u64>,
    ) -> Result<PermissionRecord, ProviderError> {
        self.grant_scoped_permissions_inner(
            handle,
            authority_revision,
            None,
            capabilities,
            approved_accounts,
            approved_names,
            now_unix_ms,
            expires_at_unix,
        )
    }

    /// Persist a permission grant only if it still targets the exact
    /// generation authenticated by an approval prompt.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_scoped_permissions_at_generation(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        expected_generation: u64,
        capabilities: BTreeSet<PermissionCapability>,
        approved_accounts: BTreeSet<AccountId>,
        approved_names: BTreeSet<[u8; 32]>,
        now_unix_ms: u64,
        expires_at_unix: Option<u64>,
    ) -> Result<PermissionRecord, ProviderError> {
        self.grant_scoped_permissions_inner(
            handle,
            authority_revision,
            Some(expected_generation),
            capabilities,
            approved_accounts,
            approved_names,
            now_unix_ms,
            expires_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn grant_scoped_permissions_inner(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        expected_generation: Option<u64>,
        capabilities: BTreeSet<PermissionCapability>,
        approved_accounts: BTreeSet<AccountId>,
        approved_names: BTreeSet<[u8; 32]>,
        now_unix_ms: u64,
        expires_at_unix: Option<u64>,
    ) -> Result<PermissionRecord, ProviderError> {
        self.accept_time(now_unix_ms)?;
        let now_unix = now_unix_ms / 1_000;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        let binds_accounts = !approved_accounts.is_empty();
        if capabilities.is_empty()
            || approved_accounts.len() > MAX_APPROVED_ACCOUNTS
            || approved_names.len() > MAX_APPROVED_NAMES
            || approved_accounts
                .iter()
                .any(|account| account.as_bytes().iter().all(|byte| *byte == 0))
            || capabilities.contains(&PermissionCapability::Accounts) != binds_accounts
            || (binds_accounts && authority.facts.namespace != SelectedNamespace::Hns)
            || (!approved_names.is_empty()
                && (!capabilities.contains(&PermissionCapability::Names)
                    || !capabilities.contains(&PermissionCapability::Accounts)
                    || approved_accounts.is_empty()
                    || authority.facts.namespace != SelectedNamespace::Hns))
            || expires_at_unix.is_some_and(|expiry| expiry <= now_unix)
        {
            return Err(ProviderError::InvalidPermission);
        }
        let scope = permission_scope(&authority.facts);
        let current_generation = self.state.permission_generation(&scope)?.unwrap_or(0);
        if expected_generation.is_some_and(|expected| expected != current_generation) {
            return Err(ProviderError::StaleApproval);
        }
        let next_generation = current_generation
            .checked_add(1)
            .ok_or(ProviderError::StaleContext)?;
        let record = PermissionRecord {
            origin: authority.facts.origin.clone(),
            namespace: authority.facts.namespace,
            generation: next_generation,
            capabilities,
            approved_accounts,
            approved_names,
            created_at_unix: now_unix,
            expires_at_unix,
        };
        self.state.save_permission(&scope, &record)?;
        self.pending.retain(|_, approval| {
            approval.call.origin != authority.facts.origin
                || approval.call.namespace != authority.facts.namespace
        });
        Ok(record)
    }

    pub fn revoke_permissions(
        &mut self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<u64, ProviderError> {
        self.accept_time(now_unix_ms)?;
        let now_unix = now_unix_ms / 1_000;
        let authority = self
            .authority(handle, authority_revision, now_unix_ms)?
            .clone();
        let scope = permission_scope(&authority.facts);
        let expected_generation = self
            .state
            .permission_generation(&scope)?
            .ok_or(ProviderError::InvalidPermission)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(ProviderError::StaleContext)?;
        self.state
            .revoke_permission(&scope, expected_generation, next_generation, now_unix)?;
        self.pending.retain(|_, approval| {
            approval.call.origin != authority.facts.origin
                || approval.call.namespace != authority.facts.namespace
        });
        Ok(next_generation)
    }

    fn accept_time(&mut self, now_unix_ms: u64) -> Result<(), ProviderError> {
        if now_unix_ms < self.last_now_unix_ms {
            return Err(ProviderError::ClockRollback);
        }
        self.last_now_unix_ms = now_unix_ms;
        Ok(())
    }

    fn authority(
        &self,
        handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<&RegisteredAuthority, ProviderError> {
        let authority = self
            .authorities
            .get(&handle)
            .ok_or(ProviderError::AuthorityNotFound)?;
        if authority_revision == 0
            || authority.revision != authority_revision
            || authority.facts.valid_until_unix_ms <= now_unix_ms
        {
            return Err(ProviderError::StaleContext);
        }
        Ok(authority)
    }

    fn prune_expired_authorities(&mut self, now_unix_ms: u64) {
        let expired: Vec<_> = self
            .authorities
            .iter()
            .filter_map(|(handle, authority)| {
                (authority.facts.valid_until_unix_ms <= now_unix_ms).then_some(*handle)
            })
            .collect();
        for handle in expired {
            self.authorities.remove(&handle);
            self.pending
                .retain(|_, approval| approval.authority_handle != handle);
            self.rate.retain(|(candidate, _), _| *candidate != handle);
            self.replay.retain(|(candidate, _), _| *candidate != handle);
        }
    }

    fn consume_nonce(
        &mut self,
        handle: HostAuthorityHandleId,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), ProviderError> {
        self.replay.retain(|_, expiry| *expiry > now_unix);
        if self.replay.contains_key(&(handle, nonce)) {
            return Err(ProviderError::Replay);
        }
        if self.replay.len() >= MAX_REPLAY_NONCES {
            return Err(ProviderError::RateLimited);
        }
        self.replay.insert((handle, nonce), expires_at_unix);
        Ok(())
    }

    fn enforce_rate(
        &mut self,
        handle: HostAuthorityHandleId,
        method: ProviderMethod,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        let window = self.rate.entry((handle, method)).or_insert(RateWindow {
            starts_at_unix: now_unix,
            count: 0,
        });
        if now_unix.saturating_sub(window.starts_at_unix) >= RATE_WINDOW_SECONDS {
            *window = RateWindow {
                starts_at_unix: now_unix,
                count: 0,
            };
        }
        if window.count >= method.rate_limit() {
            return Err(ProviderError::RateLimited);
        }
        window.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RateWindow {
    starts_at_unix: u64,
    count: u32,
}

fn permission_scope(facts: &HostAuthorityRegistration) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let namespace = match facts.namespace {
        SelectedNamespace::Hns => b"hns".as_slice(),
        SelectedNamespace::Icann => b"icann".as_slice(),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"hns-provider-permission-scope/v2");
    hasher.update([0_u8]);
    hasher.update(namespace);
    hasher.update([0_u8]);
    hasher.update(facts.origin.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut scope = String::with_capacity(31 + namespace.len() + digest.len() * 2);
    scope.push_str("hns-provider-permission-v2:");
    scope.push_str(match facts.namespace {
        SelectedNamespace::Hns => "hns:",
        SelectedNamespace::Icann => "icann:",
    });
    for byte in digest {
        scope.push(HEX[(byte >> 4) as usize] as char);
        scope.push(HEX[(byte & 0x0f) as usize] as char);
    }
    scope
}

fn validate_permission_identity(
    permission: Option<PermissionRecord>,
    facts: &HostAuthorityRegistration,
    now_unix: u64,
) -> Result<Option<PermissionRecord>, ProviderError> {
    let Some(permission) = permission else {
        return Ok(None);
    };
    if permission.origin != facts.origin
        || permission.namespace != facts.namespace
        || permission.generation == 0
        || permission.capabilities.is_empty()
        || permission.approved_accounts.len() > MAX_APPROVED_ACCOUNTS
        || permission.approved_names.len() > MAX_APPROVED_NAMES
        || permission
            .approved_accounts
            .iter()
            .any(|account| account.as_bytes().iter().all(|byte| *byte == 0))
        || permission
            .capabilities
            .contains(&PermissionCapability::Accounts)
            == permission.approved_accounts.is_empty()
        || (!permission.approved_accounts.is_empty()
            && permission.namespace != SelectedNamespace::Hns)
        || (!permission.approved_names.is_empty()
            && (!permission
                .capabilities
                .contains(&PermissionCapability::Names)
                || !permission
                    .capabilities
                    .contains(&PermissionCapability::Accounts)
                || permission.approved_accounts.is_empty()
                || permission.namespace != SelectedNamespace::Hns))
        || permission.created_at_unix > now_unix
        || permission
            .expires_at_unix
            .is_some_and(|expiry| expiry <= permission.created_at_unix)
    {
        return Err(ProviderError::Persistence);
    }
    if permission
        .expires_at_unix
        .is_some_and(|expiry| expiry <= now_unix)
    {
        return Ok(None);
    }
    Ok(Some(permission))
}

fn approval_id(
    handle: HostAuthorityHandleId,
    authority_revision: u64,
    wallet_session: WalletSessionId,
    request_nonce: u64,
    method: ProviderMethod,
    namespace: SelectedNamespace,
    origin: &Origin,
) -> ApprovalId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-provider-approval/v2");
    hasher.update(handle.as_bytes());
    hasher.update(authority_revision.to_be_bytes());
    hasher.update(wallet_session.as_bytes());
    hasher.update(request_nonce.to_be_bytes());
    hasher.update([match namespace {
        SelectedNamespace::Hns => 0_u8,
        SelectedNamespace::Icann => 1_u8,
    }]);
    hasher.update((origin.as_str().len() as u64).to_be_bytes());
    hasher.update(origin.as_str().as_bytes());
    hasher.update(method.wire_name().as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    ApprovalId::new(id)
}

fn validate_module_params(method: ProviderMethod, params: &Value) -> Result<(), ProviderError> {
    if !matches!(
        method,
        ProviderMethod::AssetGetAccount
            | ProviderMethod::AssetGetBalance
            | ProviderMethod::AssetGetTransactions
            | ProviderMethod::AssetGetReceiveTarget
            | ProviderMethod::AssetSend
    ) {
        return Ok(());
    }
    let module = params
        .as_object()
        .and_then(|object| object.get("module"))
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidParams)?;
    if !matches!(module, "bitcoin" | "ethereum") {
        return Err(ProviderError::InvalidParams);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderEvent {
    Connect,
    Disconnect,
    PermissionsChanged,
    ModulesChanged,
    AccountsChanged,
    BalancesChanged,
    TransactionsChanged,
    NamesChanged,
    NameMarketChanged,
    DirectOfferChanged,
    SwapSessionChanged,
    WalletLocked,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid logical origin")]
    InvalidOrigin,
    #[error("provider requires an authenticated secure context")]
    InsecureContext,
    #[error("opaque browser authority handle is unknown or revoked")]
    AuthorityNotFound,
    #[error("opaque browser authority handle is already registered")]
    DuplicateAuthority,
    #[error("browser authority registry reached its bounded capacity")]
    AuthorityCapacity,
    #[error("request context is stale or mismatched")]
    StaleContext,
    #[error("provider wall clock moved backwards within this process")]
    ClockRollback,
    #[error("provider request exceeds its bounded maximum")]
    RequestTooLarge,
    #[error("provider method was not found")]
    MethodNotFound,
    #[error("method is intentionally forbidden")]
    ForbiddenMethod,
    #[error("provider parameters are invalid")]
    InvalidParams,
    #[error("origin lacks the required permission")]
    Unauthorized,
    #[error("wallet is locked")]
    WalletLocked,
    #[error("request rate limit exceeded")]
    RateLimited,
    #[error("request replay rejected")]
    Replay,
    #[error("approval is stale, expired, or belongs to another context")]
    StaleApproval,
    #[error("permission grant is invalid")]
    InvalidPermission,
    #[error("persistent provider state failed")]
    Persistence,
}

impl From<StoreError> for ProviderError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Replay => Self::Replay,
            StoreError::Locked => Self::WalletLocked,
            _ => Self::Persistence,
        }
    }
}

impl From<serde_json::Error> for ProviderError {
    fn from(_: serde_json::Error) -> Self {
        Self::Persistence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 100_000;

    fn origin() -> Origin {
        Origin::parse("https://wallet.example").expect("origin")
    }

    fn wire_id<const N: usize>(byte: u8) -> [u8; N] {
        [byte; N]
    }

    fn handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes(wire_id(1)).expect("handle")
    }

    fn wallet_session() -> WalletSessionId {
        WalletSessionId::from_bytes(wire_id(2)).expect("wallet session")
    }

    fn registration() -> HostAuthorityRegistration {
        HostAuthorityRegistration {
            origin: origin(),
            namespace: SelectedNamespace::Hns,
            runtime_session: BrowserRuntimeSessionId::from_bytes(wire_id(3))
                .expect("runtime session"),
            runtime_generation: 2,
            policy_generation: 3,
            navigation_generation: 6,
            decision_fingerprint: ProviderAuthorityFingerprint::from_bytes(wire_id(4))
                .expect("fingerprint"),
            valid_until_unix_ms: NOW_MS + 60_000,
        }
    }

    fn provider() -> ProviderCore<MemoryProviderState> {
        let mut provider =
            ProviderCore::new(MemoryProviderState::default(), wallet_session(), false);
        provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("register authority");
        provider
    }

    #[test]
    fn canonical_provider_method_set_has_exact_wire_round_trips() {
        assert_eq!(ProviderMethod::ALL.len(), 43);
        let names: BTreeSet<_> = ProviderMethod::ALL
            .into_iter()
            .map(ProviderMethod::wire_name)
            .collect();
        assert_eq!(names.len(), 43);
        for (index, method) in ProviderMethod::ALL.into_iter().enumerate() {
            assert_eq!(method.wire_name(), PROVIDER_METHOD_WIRE_NAMES[index]);
            assert!(matches!(
                ProviderMethod::parse(method.wire_name()),
                Ok(parsed) if parsed == method
            ));
        }
        assert!(matches!(
            ProviderMethod::parse("wallet_unknown"),
            Err(ProviderError::MethodNotFound)
        ));
        assert!(matches!(
            ProviderMethod::parse("eth_sendTransaction"),
            Err(ProviderError::ForbiddenMethod)
        ));
    }

    #[test]
    fn production_next_rejects_every_hns_method_outside_the_hns_namespace() {
        let mut icann_registration = registration();
        icann_registration.namespace = SelectedNamespace::Icann;
        let mut provider =
            ProviderCore::new(MemoryProviderState::default(), wallet_session(), false);
        provider
            .register_authority(handle(), icann_registration, NOW_MS)
            .expect("register ICANN authority");

        let hns_methods = ProviderMethod::ALL
            .into_iter()
            .filter(|method| method.requires_hns_namespace())
            .collect::<Vec<_>>();
        assert_eq!(hns_methods.len(), 20);
        for (index, method) in hns_methods.into_iter().enumerate() {
            let request = serde_json::to_vec(&serde_json::json!({
                "method": method.wire_name(),
                "params": null,
            }))
            .expect("encode provider request");
            assert!(matches!(
                provider.request(
                    handle(),
                    1,
                    u64::try_from(index).expect("bounded method index") + 1,
                    NOW_MS,
                    &request,
                ),
                Err(ProviderError::Unauthorized)
            ));
        }
        assert!(provider.pending.is_empty());
        let permission = provider
            .permission_snapshot(handle(), 1, NOW_MS)
            .expect("ICANN permission snapshot");
        assert_eq!(permission.generation, 0);
        assert!(permission.record.is_none());
    }

    #[test]
    fn permission_snapshot_preserves_fresh_and_tombstone_generations() {
        let mut provider = provider();
        let fresh = provider
            .permission_snapshot(handle(), 1, NOW_MS)
            .expect("fresh snapshot");
        assert_eq!(fresh.generation, 0);
        assert!(fresh.record.is_none());

        let account = AccountId::new([7_u8; 16]);
        let granted = provider
            .grant_scoped_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::from([account]),
                BTreeSet::new(),
                NOW_MS,
                None,
            )
            .expect("grant");
        assert_eq!(granted.generation, 1);
        assert_eq!(granted.approved_accounts, BTreeSet::from([account]));
        let revoked_generation = provider
            .revoke_permissions(handle(), 1, NOW_MS)
            .expect("revoke");
        assert_eq!(revoked_generation, 2);

        let tombstone = provider
            .permission_snapshot(handle(), 1, NOW_MS)
            .expect("tombstone snapshot");
        assert_eq!(tombstone.generation, 2);
        assert!(tombstone.record.is_none());
    }

    #[test]
    fn production_followup_name_scope_requires_bounded_hns_account_authority() {
        let account = AccountId::new([7_u8; 16]);
        let name = [8_u8; 32];
        let mut provider = provider();
        assert!(matches!(
            provider.grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Names]),
                BTreeSet::from([name]),
                NOW_MS,
                None,
            ),
            Err(ProviderError::InvalidPermission)
        ));
        assert!(matches!(
            provider.grant_scoped_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Names]),
                BTreeSet::from([account]),
                BTreeSet::from([name]),
                NOW_MS,
                None,
            ),
            Err(ProviderError::InvalidPermission)
        ));
        let granted = provider
            .grant_scoped_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Accounts, PermissionCapability::Names]),
                BTreeSet::from([account]),
                BTreeSet::from([name]),
                NOW_MS,
                None,
            )
            .expect("account-bound name scope");
        assert_eq!(granted.approved_names, BTreeSet::from([name]));

        let oversized = (0_u16..=MAX_APPROVED_NAMES as u16)
            .map(|index| {
                let mut name_hash = [0_u8; 32];
                name_hash[..2].copy_from_slice(&index.to_be_bytes());
                name_hash
            })
            .collect();
        assert!(matches!(
            provider.grant_scoped_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Accounts, PermissionCapability::Names,]),
                BTreeSet::from([account]),
                oversized,
                NOW_MS,
                None,
            ),
            Err(ProviderError::InvalidPermission)
        ));

        let orphan = PermissionRecord {
            origin: origin(),
            namespace: SelectedNamespace::Hns,
            generation: 1,
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            approved_accounts: BTreeSet::new(),
            approved_names: BTreeSet::from([name]),
            created_at_unix: 1,
            expires_at_unix: None,
        };
        assert!(matches!(
            validate_permission_identity(Some(orphan), &registration(), NOW_MS / 1_000),
            Err(ProviderError::Persistence)
        ));
    }

    #[test]
    fn canonical_provider_account_join_rejects_unbound_and_legacy_account_authority() {
        let mut scoped_provider = provider();
        assert!(matches!(
            scoped_provider.grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::new(),
                NOW_MS,
                None,
            ),
            Err(ProviderError::InvalidPermission)
        ));

        let account = AccountId::new([8_u8; 16]);
        let record = scoped_provider
            .grant_scoped_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::from([account]),
                BTreeSet::new(),
                NOW_MS,
                None,
            )
            .expect("scoped account grant");
        let mut legacy = serde_json::to_value(record).expect("record");
        legacy
            .as_object_mut()
            .expect("record object")
            .remove("approved_accounts");
        let legacy: PermissionRecord = serde_json::from_value(legacy).expect("legacy record");
        assert!(legacy.approved_accounts.is_empty());
        assert!(matches!(
            validate_permission_identity(Some(legacy), &registration(), NOW_MS / 1_000),
            Err(ProviderError::Persistence)
        ));

        let mut provider = provider();
        let ProviderAction::ApprovalRequired(approval) = provider
            .request(
                handle(),
                1,
                1,
                NOW_MS,
                br#"{"method":"hns_requestAccounts","params":null}"#,
            )
            .expect("account approval")
        else {
            panic!("account approval required")
        };
        let approved_generation = approval.permission_generation;
        let approved_call = provider
            .approve(handle(), 1, approval.id, NOW_MS)
            .expect("approval validated");
        assert_eq!(approved_call.method, ProviderMethod::HnsRequestAccounts);
        provider
            .grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Send]),
                BTreeSet::new(),
                NOW_MS,
                None,
            )
            .expect("concurrent permission generation");
        assert!(matches!(
            provider.grant_scoped_permissions_at_generation(
                handle(),
                1,
                approved_generation,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::from([account]),
                BTreeSet::new(),
                NOW_MS,
                None,
            ),
            Err(ProviderError::StaleApproval)
        ));
        let current = provider
            .permission(handle(), 1, NOW_MS)
            .expect("permission read")
            .expect("concurrent grant retained");
        assert_eq!(current.generation, 1);
        assert_eq!(
            current.capabilities,
            BTreeSet::from([PermissionCapability::Send])
        );
        assert!(current.approved_accounts.is_empty());
    }

    #[test]
    fn pages_have_no_constructible_trust_booleans_or_origin_context() {
        assert!(matches!(
            Origin::parse("http://wallet.example"),
            Err(ProviderError::InsecureContext)
        ));
        let mut provider = provider();
        assert!(matches!(
            provider.request(
                HostAuthorityHandleId::from_bytes(wire_id(9)).expect("other handle"),
                1,
                1,
                NOW_MS,
                br#"{"method":"wallet_getStatus"}"#
            ),
            Err(ProviderError::AuthorityNotFound)
        ));
        assert!(matches!(
            provider.request(
                handle(),
                1,
                2,
                NOW_MS,
                br#"{"method":"eth_sendTransaction","params":{}}"#
            ),
            Err(ProviderError::ForbiddenMethod)
        ));
    }

    #[test]
    fn permissions_are_origin_scoped_and_value_movement_always_prompts() {
        let mut provider = provider();
        let scope = permission_scope(&registration());
        provider
            .state
            .save_permission(
                &scope,
                &PermissionRecord {
                    origin: origin(),
                    namespace: SelectedNamespace::Hns,
                    generation: 1,
                    capabilities: BTreeSet::from([PermissionCapability::Send]),
                    approved_accounts: BTreeSet::new(),
                    approved_names: BTreeSet::new(),
                    created_at_unix: 1,
                    expires_at_unix: None,
                },
            )
            .expect("permission");
        let action = provider
            .request(
                handle(),
                1,
                9,
                NOW_MS,
                br#"{"method":"hns_send","params":{"amount":"1","recipient":"hs1q"}}"#,
            )
            .expect("authorized request");
        let ProviderAction::ApprovalRequired(approval) = action else {
            panic!("send must require approval")
        };
        let mut replacement = registration();
        replacement.navigation_generation += 1;
        let revision = provider
            .replace_authority(handle(), 1, replacement, NOW_MS)
            .expect("replace");
        assert!(matches!(
            provider.approve(handle(), revision, approval.id, NOW_MS),
            Err(ProviderError::StaleApproval)
        ));
    }

    #[test]
    fn duplicate_request_nonce_is_rejected() {
        let mut provider = provider();
        let bytes = br#"{"method":"wallet_getStatus"}"#;
        provider
            .request(handle(), 1, 11, NOW_MS, bytes)
            .expect("first");
        assert!(matches!(
            provider.request(handle(), 1, 11, NOW_MS, bytes),
            Err(ProviderError::Replay)
        ));
    }

    #[test]
    fn external_asset_methods_are_generic_and_module_bounded() {
        let mut provider = provider();
        assert!(matches!(
            provider.request(
                handle(),
                1,
                12,
                NOW_MS,
                br#"{"method":"asset_getBalance","params":{"module":"litecoin"}}"#
            ),
            Err(ProviderError::InvalidParams)
        ));
    }

    #[test]
    fn handle_replacement_is_exact_and_cannot_regress() {
        let mut provider = provider();
        let mut regressed = registration();
        regressed.navigation_generation -= 1;
        assert!(matches!(
            provider.replace_authority(handle(), 1, regressed, NOW_MS),
            Err(ProviderError::StaleContext)
        ));
        let mut replacement = registration();
        replacement.policy_generation += 1;
        assert_eq!(
            provider
                .replace_authority(handle(), 1, replacement, NOW_MS)
                .expect("fresh replacement"),
            2
        );
        assert!(matches!(
            provider.revoke_authority(handle(), 1),
            Err(ProviderError::StaleContext)
        ));
        provider
            .revoke_authority(handle(), 2)
            .expect("exact revision revoke");
    }

    #[test]
    fn permission_tombstone_prevents_generation_reset() {
        let mut state = MemoryProviderState::default();
        let scope = permission_scope(&registration());
        let record = PermissionRecord {
            origin: origin(),
            namespace: SelectedNamespace::Hns,
            generation: 5,
            capabilities: BTreeSet::from([PermissionCapability::Send]),
            approved_accounts: BTreeSet::new(),
            approved_names: BTreeSet::new(),
            created_at_unix: 1,
            expires_at_unix: None,
        };
        state
            .save_permission(&scope, &record)
            .expect("trusted bootstrap");
        state.revoke_permission(&scope, 5, 6, 2).expect("revoke");
        let mut reset = record.clone();
        reset.generation = 6;
        assert!(matches!(
            state.save_permission(&scope, &reset),
            Err(ProviderError::StaleContext)
        ));
        reset.generation = 7;
        state
            .save_permission(&scope, &reset)
            .expect("next monotonic generation");
    }
}
