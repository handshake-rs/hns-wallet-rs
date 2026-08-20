#![doc = "Versioned, framed, secret-minimizing private wallet service ABI."]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use hns_covenants::{hash_name, validate_name};
use hns_wallet_types::{
    AccountId, Amount, ApprovalKind, BaseUnits, BrowserRuntimeSessionId, FinalityModel,
    HostAuthorityHandleId, HostSessionId, ModuleId, PROVIDER_METHOD_WIRE_NAMES,
    PermissionCapability, ProviderApprovalId, ProviderAuthorityFingerprint, ProviderRequestId,
    ReceiveTarget, SyncStatus, TransactionSummary, WalletAsset, WalletId, WalletServiceSessionId,
    WalletSessionId, WorkflowId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

pub const WALLET_ABI_VERSION: u16 = 2;
pub const LENGTH_PREFIX_BYTES: usize = 4;
pub const MAX_ABI_FRAME_BYTES: usize = 1_048_576;
pub const MAX_PROVIDER_REQUEST_BYTES: usize = 65_536;
pub const MAX_PROVIDER_RESULT_BYTES: usize = 262_144;
pub const MAX_PROVIDER_EVENT_BYTES: usize = 65_536;
pub const MAX_APPROVAL_FRAME_BYTES: usize = 16_384;
pub const MAX_APPROVAL_LIFETIME_MS: u64 = 90_000;
pub const MAX_PASSPHRASE_BYTES: usize = 1_024;
pub const MAX_RECOVERY_PHRASE_BYTES: usize = 1_024;
pub const MAX_METHOD_BYTES: usize = 96;
pub const MAX_ORIGIN_BYTES: usize = 512;
pub const MAX_PUBLIC_STRING_BYTES: usize = 4_096;
pub const MAX_PUBLIC_ITEMS: usize = 128;
pub const MAX_HNS_NAME_DISCLOSURES: usize = 64;
pub const MAX_HNS_NAME_BYTES: usize = 63;
pub const MAX_FAILURE_MESSAGE_BYTES: usize = 1_024;
pub const PROVIDER_SCHEMA_VERSION: u16 = 1;
pub const APPROVAL_SCHEMA_VERSION: u16 = 3;
pub const MAX_PROVIDER_METHODS: usize = PROVIDER_METHOD_WIRE_NAMES.len();

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostPlatform {
    Android,
    Ios,
    ChromiumNativeHost,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceCapability {
    CanonicalFraming,
    RestartIsolation,
    OpaqueAuthorityRegistry,
    PersistentPermissions,
    StructuredApprovals,
    TypedEvents,
    WalletOperations,
    HnsReadOperationsV1,
    HnsWalletAuthorityContextV1,
    ProviderDispatch,
    ValueMovement,
    BrowserIntegration,
}

/// Canonical Handshake network identity used by the native-only wallet
/// authority-context operation. Simnet is intentionally absent because the
/// browser authority broker admits only production, public test, and local
/// regression networks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletHandshakeNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl WalletHandshakeNetwork {
    /// Return the canonical Handshake wire magic for this network.
    pub const fn magic(self) -> u32 {
        match self {
            Self::Mainnet => 0x5b6e_f2d3,
            Self::Testnet => 0xb152_0dd2,
            Self::Regtest => 0xae38_95cf,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderNamespace {
    Hns,
    Icann,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceLimits {
    pub outer_frame_bytes: u32,
    pub provider_request_bytes: u32,
    pub provider_result_bytes: u32,
    pub provider_event_bytes: u32,
    pub approval_frame_bytes: u32,
    pub approval_lifetime_ms: u64,
}

impl Default for ServiceLimits {
    fn default() -> Self {
        Self {
            outer_frame_bytes: MAX_ABI_FRAME_BYTES as u32,
            provider_request_bytes: MAX_PROVIDER_REQUEST_BYTES as u32,
            provider_result_bytes: MAX_PROVIDER_RESULT_BYTES as u32,
            provider_event_bytes: MAX_PROVIDER_EVENT_BYTES as u32,
            approval_frame_bytes: MAX_APPROVAL_FRAME_BYTES as u32,
            approval_lifetime_ms: MAX_APPROVAL_LIFETIME_MS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HostHello {
    pub protocol_version: u16,
    pub platform: HostPlatform,
    pub host_session_id: HostSessionId,
    pub restart_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceHello {
    pub protocol_version: u16,
    pub platform: HostPlatform,
    pub host_session_id: HostSessionId,
    pub service_session_id: WalletServiceSessionId,
    pub restart_generation: u64,
    pub capabilities: BTreeSet<ServiceCapability>,
    pub limits: ServiceLimits,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionEnvelope<T> {
    pub protocol_version: u16,
    pub host_session_id: HostSessionId,
    pub service_session_id: WalletServiceSessionId,
    pub restart_generation: u64,
    pub channel_sequence: u64,
    pub request_id: ProviderRequestId,
    pub body: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HostAuthorityFacts {
    pub origin: String,
    pub namespace: ProviderNamespace,
    pub runtime_session_id: BrowserRuntimeSessionId,
    pub runtime_generation: u64,
    pub policy_generation: u64,
    pub navigation_generation: u64,
    pub decision_fingerprint: ProviderAuthorityFingerprint,
    pub valid_until_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServiceRequest {
    RegisterAuthority {
        authority_handle: HostAuthorityHandleId,
        authority: HostAuthorityFacts,
    },
    ReplaceAuthority {
        authority_handle: HostAuthorityHandleId,
        expected_authority_revision: u64,
        authority: HostAuthorityFacts,
    },
    RevokeAuthority {
        authority_handle: HostAuthorityHandleId,
        expected_authority_revision: u64,
    },
    ProviderCapabilities {
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
    },
    ProviderRequest {
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        request_nonce: u64,
        method: String,
        #[serde(default)]
        params: Value,
    },
    ApprovalDecision {
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        approval_id: ProviderApprovalId,
        decision: ApprovalDecision,
    },
    Wallet {
        request: WalletRequest,
    },
    WalletAuthority {
        request: WalletAuthorityContextRequest,
    },
}

/// Additive native-only request kept outside [`WalletRequest`] so the exact
/// six-operation `hnsReadOperationsV1` subset remains unchanged.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WalletAuthorityContextRequest {
    CurrentHnsContext {
        network: WalletHandshakeNetwork,
        network_magic: u32,
        namespace_id: [u8; 16],
        namespace_lease_generation: u64,
        module: ModuleId,
    },
}

impl std::fmt::Debug for WalletAuthorityContextRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentHnsContext { module, .. } => formatter
                .debug_struct("CurrentHnsContext")
                .field("network", &"<bound>")
                .field("network_magic", &"<bound>")
                .field("namespace_id", &"<opaque>")
                .field("namespace_lease_generation", &"<bound>")
                .field("module", module)
                .finish(),
        }
    }
}

/// An owned ABI secret that zeroizes its allocation on drop and never prints
/// its plaintext. It deliberately does not implement `Clone`.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for SecretString {}

impl Serialize for SecretString {
    fn serialize<Serializer>(
        &self,
        serializer: Serializer,
    ) -> Result<Serializer::Ok, Serializer::Error>
    where
        Serializer: serde::Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WalletRequest {
    Status,
    CreateWallet {
        passphrase: SecretString,
    },
    RestoreWallet {
        passphrase: SecretString,
        recovery_phrase: SecretString,
    },
    Unlock {
        passphrase: SecretString,
    },
    Lock,
    ListAccounts,
    Balance {
        module: ModuleId,
        account: AccountId,
    },
    ReceiveTarget {
        module: ModuleId,
        account: AccountId,
    },
    TransactionHistory {
        module: ModuleId,
        account: AccountId,
    },
    ModuleStatus {
        module: ModuleId,
    },
    WorkflowStatus {
        workflow_id: WorkflowId,
    },
}

// Keep the payload inline: boxing would change this public Rust ABI wrapper,
// while serde already bounds and validates the frame at the transport edge.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostFrame {
    Hello {
        hello: HostHello,
    },
    Request {
        envelope: SessionEnvelope<ServiceRequest>,
    },
}

// Keep the payload inline to preserve the public frame representation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServiceFrame {
    Hello {
        hello: ServiceHello,
    },
    Response {
        envelope: SessionEnvelope<ServiceResponse>,
    },
    Event {
        event: ProviderEventEnvelope,
    },
}

/// Wallet-owned provider authority binding carried by every private provider
/// output. Generation zero is valid only while the authority has never had a
/// permission grant or revocation tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderBinding {
    pub authority_handle: HostAuthorityHandleId,
    pub authority_revision: u64,
    pub wallet_session_id: WalletSessionId,
    pub permission_generation: u64,
}

impl ProviderBinding {
    fn validate(&self) -> Result<(), AbiError> {
        if self.authority_revision == 0 {
            return Err(AbiError::InvalidEnvelope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderCapabilitySnapshot {
    pub provider_schema_version: u16,
    pub approval_schema_version: u16,
    pub wallet_session_id: WalletSessionId,
    pub permission_generation: u64,
    pub methods: BTreeSet<String>,
}

impl ProviderCapabilitySnapshot {
    fn validate(&self, binding: &ProviderBinding) -> Result<(), AbiError> {
        if self.provider_schema_version != PROVIDER_SCHEMA_VERSION
            || self.approval_schema_version != APPROVAL_SCHEMA_VERSION
            || self.wallet_session_id != binding.wallet_session_id
            || self.permission_generation != binding.permission_generation
            || self.methods.len() > MAX_PROVIDER_METHODS
        {
            return Err(AbiError::InvalidEnvelope);
        }
        for method in &self.methods {
            if method.is_empty()
                || method.len() > MAX_METHOD_BYTES
                || !method.is_ascii()
                || !PROVIDER_METHOD_WIRE_NAMES.contains(&method.as_str())
            {
                return Err(AbiError::InvalidEnvelope);
            }
        }
        Ok(())
    }
}

// Response variants mirror the stable wire schema and remain inline so callers
// do not inherit an allocation solely to equalize enum variant sizes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "result",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServiceResponse {
    AuthorityRegistered {
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
    },
    AuthorityReplaced {
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
    },
    AuthorityRevoked {
        authority_handle: HostAuthorityHandleId,
    },
    ProviderCapabilities {
        binding: ProviderBinding,
        capabilities: ProviderCapabilitySnapshot,
    },
    ProviderResult {
        binding: ProviderBinding,
        value: Value,
    },
    ApprovalRequired {
        approval: ApprovalPrompt,
    },
    ApprovalRejected {
        approval_id: ProviderApprovalId,
    },
    Wallet {
        response: WalletResponse,
    },
    WalletAuthority {
        context: WalletHnsAuthorityContext,
    },
    Failure {
        failure: ServiceFailure,
    },
}

/// Wallet-service evidence joined to a trusted native broker lease by the
/// browser host. This value is not independently an authority and is never a
/// website/provider projection.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletHnsAuthorityContext {
    pub network: WalletHandshakeNetwork,
    pub network_magic: u32,
    pub namespace_id: [u8; 16],
    pub namespace_lease_generation: u64,
    pub active_wallet: WalletId,
    pub account: AccountId,
    pub wallet_authority_revision: u64,
    pub account_authority_revision: u64,
    pub locked: bool,
    pub module: ModuleId,
    pub persistent_wallet_confirmed: bool,
    pub recovery_pending: bool,
    pub retirement_pending: bool,
    pub hns_reads_ready: bool,
}

impl std::fmt::Debug for WalletHnsAuthorityContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletHnsAuthorityContext")
            .field("network", &"<bound>")
            .field("network_magic", &"<bound>")
            .field("namespace_id", &"<opaque>")
            .field("namespace_lease_generation", &"<bound>")
            .field("active_wallet", &"<opaque>")
            .field("account", &"<opaque>")
            .field("wallet_authority_revision", &"<bound>")
            .field("account_authority_revision", &"<bound>")
            .field("lifecycle", &"<positive evidence>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "result",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WalletResponse {
    Status {
        status: WalletRuntimeStatus,
    },
    WalletCreated {
        wallet_id: WalletId,
    },
    WalletRestored {
        wallet_id: WalletId,
    },
    Locked,
    Unlocked,
    Accounts {
        accounts: Vec<AccountSummary>,
    },
    Balance {
        amount: Amount,
    },
    ReceiveTarget {
        target: ReceiveTarget,
    },
    TransactionHistory {
        transactions: Vec<TransactionSummary>,
    },
    ModuleStatus {
        status: SyncStatus,
    },
    Workflow {
        summary: WorkflowSummary,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletRuntimeStatus {
    pub locked: bool,
    pub active_wallet: Option<WalletId>,
    pub enabled_modules: BTreeSet<ModuleId>,
    pub mainnet_settlement_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountSummary {
    pub account_id: AccountId,
    pub module: ModuleId,
    pub label: String,
    pub receive_display: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkflowSummary {
    pub workflow_id: WorkflowId,
    pub state: String,
    pub next_action: Option<String>,
    pub terminal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModuleApprovalAction {
    Enable,
    Disable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NameMarketApprovalAction {
    Create,
    Cancel,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MarketIntentApprovalAction {
    Publish,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalWarning {
    FeeEstimateMayChange,
    NameTransferIsIrreversible,
    RefundRequiresManualAction,
    SettlementCanBeDelayed,
}

/// One canonical Handshake name disclosed by a permission prompt. The hash is
/// lowercase hexadecimal so a trusted UI can render and compare the exact
/// authority being granted without receiving private wallet/name state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HnsNameDisclosure {
    pub name: String,
    pub name_hash: String,
}

impl HnsNameDisclosure {
    pub fn validate(&self) -> Result<(), AbiError> {
        if validate_name(self.name.as_bytes()) && hns_name_hash_matches(&self.name, &self.name_hash)
        {
            Ok(())
        } else {
            Err(AbiError::InvalidApproval)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ApprovalSummary {
    Permissions {
        capabilities: BTreeSet<PermissionCapability>,
        #[serde(rename = "hnsNames")]
        hns_names: Vec<HnsNameDisclosure>,
    },
    ModuleEnablement {
        module: ModuleId,
        action: ModuleApprovalAction,
    },
    Send {
        amount: Amount,
        recipient: String,
        maximum_fee: Amount,
        chain: ModuleId,
        finality: FinalityModel,
        warnings: BTreeSet<ApprovalWarning>,
    },
    NameTransfer {
        name: String,
        recipient: String,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    NameFinalize {
        name: String,
        recipient: String,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    TypedSignature {
        message_type: String,
        message_digest: String,
    },
    NameMarketOffer {
        action: NameMarketApprovalAction,
        name: String,
        listing_id: Option<String>,
        price: Amount,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    NameMarketPurchase {
        name: String,
        listing_id: String,
        payment: Amount,
        recipient: String,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    MarketIntent {
        action: MarketIntentApprovalAction,
        market_intent_id: Option<String>,
        offered: Amount,
        requested_asset: WalletAsset,
        price_round: String,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    FillAcceptance {
        market_intent_id: String,
        fill_id: String,
        offered: Amount,
        expected: Amount,
        price_round: String,
        refund_timeout_unix_ms: u64,
        maximum_fee: Amount,
        warnings: BTreeSet<ApprovalWarning>,
    },
    SwapRedeem {
        swap_session_id: String,
        amount: Amount,
        recipient: String,
        maximum_fee: Amount,
        finality: FinalityModel,
        warnings: BTreeSet<ApprovalWarning>,
    },
    SwapRefund {
        swap_session_id: String,
        amount: Amount,
        recipient: String,
        maximum_fee: Amount,
        refund_available_at_unix_ms: u64,
        warnings: BTreeSet<ApprovalWarning>,
    },
}

impl ApprovalSummary {
    pub const fn approval_kind(&self) -> ApprovalKind {
        match self {
            Self::Permissions { .. } => ApprovalKind::Permission,
            Self::ModuleEnablement { .. } => ApprovalKind::ModuleEnablement,
            Self::Send { .. } => ApprovalKind::Send,
            Self::NameTransfer { .. } => ApprovalKind::NameTransfer,
            Self::NameFinalize { .. } => ApprovalKind::NameFinalize,
            Self::TypedSignature { .. } => ApprovalKind::TypedSignature,
            Self::NameMarketOffer { .. } => ApprovalKind::NameMarketOffer,
            Self::NameMarketPurchase { .. } => ApprovalKind::NameMarketPurchase,
            Self::MarketIntent { .. } => ApprovalKind::MarketIntent,
            Self::FillAcceptance { .. } => ApprovalKind::FillAcceptance,
            Self::SwapRedeem { .. } => ApprovalKind::SwapRedeem,
            Self::SwapRefund { .. } => ApprovalKind::SwapRefund,
        }
    }

    fn validate(&self) -> Result<(), AbiError> {
        match self {
            Self::Permissions {
                capabilities,
                hns_names,
            } => {
                if capabilities.is_empty() || capabilities.len() > MAX_PUBLIC_ITEMS {
                    return Err(AbiError::InvalidApproval);
                }
                if !capabilities.contains(&PermissionCapability::Names) && !hns_names.is_empty() {
                    return Err(AbiError::InvalidApproval);
                }
                validate_hns_name_disclosures(hns_names)?;
            }
            Self::ModuleEnablement { .. } => {}
            Self::Send {
                amount,
                recipient,
                maximum_fee,
                chain,
                warnings,
                ..
            } => {
                if amount.asset != chain.asset() {
                    return Err(AbiError::InvalidApproval);
                }
                validate_value_movement(*amount, recipient, *maximum_fee, warnings)?;
            }
            Self::NameTransfer {
                name,
                recipient,
                maximum_fee,
                warnings,
            }
            | Self::NameFinalize {
                name,
                recipient,
                maximum_fee,
                warnings,
            } => {
                if maximum_fee.asset != WalletAsset::Hns {
                    return Err(AbiError::InvalidApproval);
                }
                validate_public_string(name)?;
                validate_value_movement(
                    Amount::new(WalletAsset::Hns, 1),
                    recipient,
                    *maximum_fee,
                    warnings,
                )?;
            }
            Self::TypedSignature {
                message_type,
                message_digest,
            } => {
                validate_public_string(message_type)?;
                validate_public_string(message_digest)?;
            }
            Self::NameMarketOffer {
                name,
                listing_id,
                price,
                maximum_fee,
                warnings,
                ..
            } => {
                if price.asset != WalletAsset::Hns || maximum_fee.asset != WalletAsset::Hns {
                    return Err(AbiError::InvalidApproval);
                }
                validate_public_string(name)?;
                validate_optional_public_string(listing_id)?;
                validate_amount(*price, false)?;
                validate_amount(*maximum_fee, true)?;
                validate_warnings(warnings)?;
            }
            Self::NameMarketPurchase {
                name,
                listing_id,
                payment,
                recipient,
                maximum_fee,
                warnings,
            } => {
                if payment.asset != WalletAsset::Hns || maximum_fee.asset != WalletAsset::Hns {
                    return Err(AbiError::InvalidApproval);
                }
                validate_public_string(name)?;
                validate_public_string(listing_id)?;
                validate_value_movement(*payment, recipient, *maximum_fee, warnings)?;
            }
            Self::MarketIntent {
                market_intent_id,
                offered,
                requested_asset,
                price_round,
                maximum_fee,
                warnings,
                ..
            } => {
                if offered.asset == *requested_asset || maximum_fee.asset != offered.asset {
                    return Err(AbiError::InvalidApproval);
                }
                validate_optional_public_string(market_intent_id)?;
                validate_public_string(price_round)?;
                validate_amount(*offered, false)?;
                validate_amount(*maximum_fee, true)?;
                validate_warnings(warnings)?;
            }
            Self::FillAcceptance {
                market_intent_id,
                fill_id,
                offered,
                expected,
                price_round,
                refund_timeout_unix_ms,
                maximum_fee,
                warnings,
            } => {
                if offered.asset == expected.asset || maximum_fee.asset != offered.asset {
                    return Err(AbiError::InvalidApproval);
                }
                validate_public_string(market_intent_id)?;
                validate_public_string(fill_id)?;
                validate_public_string(price_round)?;
                validate_amount(*offered, false)?;
                validate_amount(*expected, false)?;
                validate_amount(*maximum_fee, true)?;
                validate_warnings(warnings)?;
                if *refund_timeout_unix_ms == 0 {
                    return Err(AbiError::InvalidApproval);
                }
            }
            Self::SwapRedeem {
                swap_session_id,
                amount,
                recipient,
                maximum_fee,
                warnings,
                ..
            } => {
                validate_public_string(swap_session_id)?;
                validate_value_movement(*amount, recipient, *maximum_fee, warnings)?;
            }
            Self::SwapRefund {
                swap_session_id,
                amount,
                recipient,
                maximum_fee,
                refund_available_at_unix_ms,
                warnings,
            } => {
                validate_public_string(swap_session_id)?;
                validate_value_movement(*amount, recipient, *maximum_fee, warnings)?;
                if *refund_available_at_unix_ms == 0 {
                    return Err(AbiError::InvalidApproval);
                }
            }
        }
        Ok(())
    }

    fn validate_method(&self, method: &str) -> Result<(), AbiError> {
        let matches = match self {
            Self::Permissions {
                capabilities,
                hns_names,
            } => match method {
                "hns_requestAccounts" => {
                    capabilities.len() == 1
                        && capabilities.contains(&PermissionCapability::Accounts)
                        && hns_names.is_empty()
                }
                "wallet_requestPermissions" => {
                    !capabilities.contains(&PermissionCapability::Accounts)
                }
                _ => false,
            },
            Self::ModuleEnablement { action, .. } => matches!(
                (method, *action),
                ("wallet_enableModule", ModuleApprovalAction::Enable)
                    | ("wallet_disableModule", ModuleApprovalAction::Disable)
            ),
            Self::Send { .. } => matches!(method, "hns_send" | "asset_send"),
            Self::NameTransfer { .. } => method == "hns_transferName",
            Self::NameFinalize { .. } => method == "hns_finalizeName",
            Self::TypedSignature { .. } => method == "hns_signTypedMessage",
            Self::NameMarketOffer { action, .. } => matches!(
                (method, *action),
                (
                    "nameMarket_createFixedPriceOffer",
                    NameMarketApprovalAction::Create
                ) | ("nameMarket_cancelOffer", NameMarketApprovalAction::Cancel)
                    | ("nameMarket_recoverName", NameMarketApprovalAction::Recover)
            ),
            Self::NameMarketPurchase { .. } => matches!(
                method,
                "nameMarket_acceptOffer" | "nameMarket_finalizePurchase"
            ),
            Self::MarketIntent { action, .. } => matches!(
                (method, *action),
                (
                    "swap_publishMarketIntent",
                    MarketIntentApprovalAction::Publish
                ) | (
                    "swap_cancelMarketIntent",
                    MarketIntentApprovalAction::Cancel
                )
            ),
            Self::FillAcceptance { .. } => {
                matches!(method, "swap_requestMatch" | "swap_acceptFill")
            }
            Self::SwapRedeem { .. } => method == "swap_redeem",
            Self::SwapRefund { .. } => method == "swap_refund",
        };
        if matches {
            Ok(())
        } else {
            Err(AbiError::InvalidApproval)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovalPrompt {
    pub approval_id: ProviderApprovalId,
    pub binding: ProviderBinding,
    pub origin: String,
    pub method: String,
    pub expires_at_unix_ms: u64,
    pub summary: ApprovalSummary,
}

impl ApprovalPrompt {
    pub fn validate(&self, expected_kind: ApprovalKind, now_unix_ms: u64) -> Result<(), AbiError> {
        self.binding
            .validate()
            .map_err(|_| AbiError::InvalidApproval)?;
        if self.expires_at_unix_ms <= now_unix_ms
            || self.expires_at_unix_ms > now_unix_ms.saturating_add(MAX_APPROVAL_LIFETIME_MS)
            || self.origin.is_empty()
            || self.origin.len() > MAX_ORIGIN_BYTES
            || !self.origin.is_ascii()
            || self.method.is_empty()
            || self.method.len() > MAX_METHOD_BYTES
            || !self.method.is_ascii()
            || self.summary.approval_kind() != expected_kind
        {
            return Err(AbiError::InvalidApproval);
        }
        self.summary.validate()?;
        self.summary.validate_method(&self.method)?;
        if serde_json::to_vec(self)
            .map_err(|_| AbiError::Encoding)?
            .len()
            > MAX_APPROVAL_FRAME_BYTES
        {
            return Err(AbiError::ApprovalTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DisconnectReason {
    AuthorityRevoked,
    AuthorityExpired,
    NavigationChanged,
    PolicyChanged,
    WalletSessionChanged,
    ServiceRestarted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "event",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderEventPayload {
    Connect {
        permission_generation: u64,
    },
    Disconnect {
        reason: DisconnectReason,
    },
    PermissionsChanged {
        permission_generation: u64,
        capabilities: BTreeSet<PermissionCapability>,
    },
    ModulesChanged {
        modules: BTreeSet<ModuleId>,
    },
    AccountsChanged {
        modules: BTreeSet<ModuleId>,
    },
    BalancesChanged {
        modules: BTreeSet<ModuleId>,
    },
    TransactionsChanged {
        modules: BTreeSet<ModuleId>,
    },
    NamesChanged {
        names: Vec<String>,
    },
    NameMarketChanged {
        listing_ids: Vec<String>,
    },
    PriceRoundChanged {
        pairs: Vec<String>,
    },
    MarketIntentChanged {
        market_intent_ids: Vec<String>,
    },
    SwapSessionChanged {
        swap_session_ids: Vec<String>,
    },
    WalletLocked,
}

impl ProviderEventPayload {
    fn validate(&self) -> Result<(), AbiError> {
        match self {
            Self::Connect {
                permission_generation,
            }
            | Self::PermissionsChanged {
                permission_generation,
                ..
            } if *permission_generation == 0 => return Err(AbiError::InvalidEvent),
            Self::PermissionsChanged { capabilities, .. } => {
                if capabilities.len() > MAX_PUBLIC_ITEMS {
                    return Err(AbiError::InvalidEvent);
                }
            }
            Self::ModulesChanged { modules }
            | Self::AccountsChanged { modules }
            | Self::BalancesChanged { modules }
            | Self::TransactionsChanged { modules } => {
                if modules.len() > MAX_PUBLIC_ITEMS {
                    return Err(AbiError::InvalidEvent);
                }
            }
            Self::NamesChanged { names } => validate_public_strings(names)?,
            Self::NameMarketChanged { listing_ids } => validate_public_strings(listing_ids)?,
            Self::PriceRoundChanged { pairs } => validate_public_strings(pairs)?,
            Self::MarketIntentChanged { market_intent_ids } => {
                validate_public_strings(market_intent_ids)?;
            }
            Self::SwapSessionChanged { swap_session_ids } => {
                validate_public_strings(swap_session_ids)?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderEventEnvelope {
    pub protocol_version: u16,
    pub host_session_id: HostSessionId,
    pub service_session_id: WalletServiceSessionId,
    pub restart_generation: u64,
    pub channel_sequence: u64,
    pub binding: ProviderBinding,
    pub event_sequence: u64,
    pub payload: ProviderEventPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceErrorCode {
    InvalidFrame,
    VersionMismatch,
    SessionMismatch,
    SequenceMismatch,
    AuthorityUnknown,
    AuthorityStale,
    PermissionDenied,
    ApprovalStale,
    WalletLocked,
    RateLimited,
    Replay,
    UnsupportedCapability,
    InvalidRequest,
    PersistenceFailure,
    RuntimeFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceFailure {
    pub code: ServiceErrorCode,
    pub message: String,
    pub unsupported_capability: Option<ServiceCapability>,
}

impl ServiceFailure {
    pub fn unsupported(capability: ServiceCapability) -> Self {
        Self {
            code: ServiceErrorCode::UnsupportedCapability,
            message: "requested wallet capability is not available".to_owned(),
            unsupported_capability: Some(capability),
        }
    }

    fn validate(&self) -> Result<(), AbiError> {
        if self.message.is_empty()
            || self.message.len() > MAX_FAILURE_MESSAGE_BYTES
            || !self.message.is_ascii()
            || (self.code == ServiceErrorCode::UnsupportedCapability)
                != self.unsupported_capability.is_some()
        {
            return Err(AbiError::InvalidFailure);
        }
        Ok(())
    }
}

pub fn declared_payload_len(prefix: [u8; LENGTH_PREFIX_BYTES]) -> Result<usize, AbiError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_ABI_FRAME_BYTES {
        return Err(AbiError::FrameSize);
    }
    Ok(length)
}

pub fn decode_host_frame(frame: &[u8]) -> Result<HostFrame, AbiError> {
    let payload = decode_payload(frame)?;
    let decoded: HostFrame =
        serde_json::from_slice(payload).map_err(|_| AbiError::InvalidEnvelope)?;
    validate_host_frame(&decoded)?;
    Ok(decoded)
}

/// Encode a host frame into an owned buffer that clears its allocation on
/// drop. Host requests can contain wallet passphrases or restore phrases, so
/// callers must retain this owner through the transport write instead of
/// copying the bytes into an ordinary `Vec<u8>`.
pub fn encode_host_frame(frame: &HostFrame) -> Result<Zeroizing<Vec<u8>>, AbiError> {
    validate_host_frame(frame)?;
    encode_zeroizing_frame(frame)
}

pub fn decode_service_frame(frame: &[u8]) -> Result<ServiceFrame, AbiError> {
    let payload = decode_payload(frame)?;
    let decoded: ServiceFrame =
        serde_json::from_slice(payload).map_err(|_| AbiError::InvalidEnvelope)?;
    validate_service_frame(&decoded)?;
    Ok(decoded)
}

pub fn encode_service_frame(frame: &ServiceFrame) -> Result<Vec<u8>, AbiError> {
    validate_service_frame(frame)?;
    encode_frame(frame)
}

fn decode_payload(frame: &[u8]) -> Result<&[u8], AbiError> {
    if frame.len() < LENGTH_PREFIX_BYTES {
        return Err(AbiError::TruncatedFrame);
    }
    let prefix: [u8; LENGTH_PREFIX_BYTES] = frame[..LENGTH_PREFIX_BYTES]
        .try_into()
        .map_err(|_| AbiError::TruncatedFrame)?;
    let length = declared_payload_len(prefix)?;
    if frame.len() != LENGTH_PREFIX_BYTES + length {
        return Err(AbiError::TruncatedFrame);
    }
    Ok(&frame[LENGTH_PREFIX_BYTES..])
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, AbiError> {
    let payload = Zeroizing::new(serde_json::to_vec(value).map_err(|_| AbiError::Encoding)?);
    if payload.is_empty() || payload.len() > MAX_ABI_FRAME_BYTES {
        return Err(AbiError::FrameSize);
    }
    let length = u32::try_from(payload.len()).map_err(|_| AbiError::FrameSize)?;
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

fn encode_zeroizing_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, AbiError> {
    let payload = Zeroizing::new(serde_json::to_vec(value).map_err(|_| AbiError::Encoding)?);
    if payload.is_empty() || payload.len() > MAX_ABI_FRAME_BYTES {
        return Err(AbiError::FrameSize);
    }
    let length = u32::try_from(payload.len()).map_err(|_| AbiError::FrameSize)?;
    let mut framed = Zeroizing::new(Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len()));
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

fn validate_host_frame(frame: &HostFrame) -> Result<(), AbiError> {
    match frame {
        HostFrame::Hello { hello } => {
            if hello.protocol_version != WALLET_ABI_VERSION || hello.restart_generation == 0 {
                return Err(AbiError::VersionMismatch);
            }
        }
        HostFrame::Request { envelope } => {
            validate_session_envelope(envelope)?;
            validate_service_request(&envelope.body)?;
        }
    }
    Ok(())
}

fn validate_session_envelope<T>(envelope: &SessionEnvelope<T>) -> Result<(), AbiError> {
    if envelope.protocol_version != WALLET_ABI_VERSION {
        return Err(AbiError::VersionMismatch);
    }
    if envelope.restart_generation == 0 || envelope.channel_sequence == 0 {
        return Err(AbiError::InvalidEnvelope);
    }
    Ok(())
}

fn validate_service_request(request: &ServiceRequest) -> Result<(), AbiError> {
    match request {
        ServiceRequest::RegisterAuthority { authority, .. } => validate_authority(authority),
        ServiceRequest::ReplaceAuthority {
            expected_authority_revision,
            authority,
            ..
        } => {
            if *expected_authority_revision == 0 {
                return Err(AbiError::InvalidAuthority);
            }
            validate_authority(authority)
        }
        ServiceRequest::RevokeAuthority {
            expected_authority_revision,
            ..
        } => {
            if *expected_authority_revision == 0 {
                return Err(AbiError::InvalidAuthority);
            }
            Ok(())
        }
        ServiceRequest::ProviderCapabilities {
            authority_revision, ..
        } => {
            if *authority_revision == 0 {
                return Err(AbiError::InvalidAuthority);
            }
            Ok(())
        }
        ServiceRequest::ProviderRequest {
            authority_revision,
            request_nonce,
            method,
            params,
            ..
        } => {
            if *authority_revision == 0
                || *request_nonce == 0
                || method.is_empty()
                || method.len() > MAX_METHOD_BYTES
                || !method.is_ascii()
            {
                return Err(AbiError::InvalidProviderRequest);
            }
            let provider = serde_json::json!({ "method": method, "params": params });
            if serde_json::to_vec(&provider)
                .map_err(|_| AbiError::Encoding)?
                .len()
                > MAX_PROVIDER_REQUEST_BYTES
            {
                return Err(AbiError::ProviderRequestTooLarge);
            }
            Ok(())
        }
        ServiceRequest::ApprovalDecision {
            authority_revision, ..
        } => {
            if *authority_revision == 0 {
                return Err(AbiError::InvalidApproval);
            }
            Ok(())
        }
        ServiceRequest::Wallet { request } => validate_wallet_request(request),
        ServiceRequest::WalletAuthority { request } => {
            validate_wallet_authority_context_request(request)
        }
    }
}

fn validate_authority(authority: &HostAuthorityFacts) -> Result<(), AbiError> {
    if authority.origin.is_empty()
        || authority.origin.len() > MAX_ORIGIN_BYTES
        || !authority.origin.is_ascii()
        || authority.runtime_generation == 0
        || authority.policy_generation == 0
        || authority.navigation_generation == 0
        || authority.valid_until_unix_ms == 0
    {
        return Err(AbiError::InvalidAuthority);
    }
    Ok(())
}

fn validate_wallet_request(request: &WalletRequest) -> Result<(), AbiError> {
    match request {
        WalletRequest::CreateWallet { passphrase } | WalletRequest::Unlock { passphrase } => {
            validate_secret(passphrase.expose_secret(), MAX_PASSPHRASE_BYTES)
        }
        WalletRequest::RestoreWallet {
            passphrase,
            recovery_phrase,
        } => {
            validate_secret(passphrase.expose_secret(), MAX_PASSPHRASE_BYTES)?;
            validate_secret(recovery_phrase.expose_secret(), MAX_RECOVERY_PHRASE_BYTES)
        }
        _ => Ok(()),
    }
}

fn validate_wallet_authority_context_request(
    request: &WalletAuthorityContextRequest,
) -> Result<(), AbiError> {
    match request {
        WalletAuthorityContextRequest::CurrentHnsContext {
            network,
            network_magic,
            namespace_id,
            namespace_lease_generation,
            module,
        } if *network_magic == network.magic()
            && namespace_id.iter().any(|byte| *byte != 0)
            && *namespace_lease_generation != 0
            && *module == ModuleId::Handshake =>
        {
            Ok(())
        }
        WalletAuthorityContextRequest::CurrentHnsContext { .. } => Err(AbiError::InvalidAuthority),
    }
}

fn validate_service_frame(frame: &ServiceFrame) -> Result<(), AbiError> {
    match frame {
        ServiceFrame::Hello { hello } => {
            if hello.protocol_version != WALLET_ABI_VERSION
                || hello.restart_generation == 0
                || hello.limits != ServiceLimits::default()
                || hello.capabilities.len() > MAX_PUBLIC_ITEMS
                || (hello
                    .capabilities
                    .contains(&ServiceCapability::HnsReadOperationsV1)
                    && !hello
                        .capabilities
                        .contains(&ServiceCapability::WalletOperations))
                || (hello
                    .capabilities
                    .contains(&ServiceCapability::HnsWalletAuthorityContextV1)
                    && (!hello
                        .capabilities
                        .contains(&ServiceCapability::WalletOperations)
                        || !hello
                            .capabilities
                            .contains(&ServiceCapability::HnsReadOperationsV1)))
            {
                return Err(AbiError::InvalidEnvelope);
            }
        }
        ServiceFrame::Response { envelope } => {
            validate_session_envelope(envelope)?;
            validate_service_response(&envelope.body)?;
        }
        ServiceFrame::Event { event } => {
            if event.protocol_version != WALLET_ABI_VERSION
                || event.restart_generation == 0
                || event.channel_sequence == 0
                || event.event_sequence == 0
            {
                return Err(AbiError::InvalidEvent);
            }
            event
                .binding
                .validate()
                .map_err(|_| AbiError::InvalidEvent)?;
            event.payload.validate()?;
            match &event.payload {
                ProviderEventPayload::Connect {
                    permission_generation,
                }
                | ProviderEventPayload::PermissionsChanged {
                    permission_generation,
                    ..
                } if *permission_generation != event.binding.permission_generation => {
                    return Err(AbiError::InvalidEvent);
                }
                ProviderEventPayload::Disconnect { .. } => {}
                _ if event.binding.permission_generation == 0 => {
                    return Err(AbiError::InvalidEvent);
                }
                _ => {}
            }
            if serde_json::to_vec(event)
                .map_err(|_| AbiError::Encoding)?
                .len()
                > MAX_PROVIDER_EVENT_BYTES
            {
                return Err(AbiError::EventTooLarge);
            }
        }
    }
    Ok(())
}

fn validate_service_response(response: &ServiceResponse) -> Result<(), AbiError> {
    match response {
        ServiceResponse::AuthorityRegistered {
            authority_revision, ..
        }
        | ServiceResponse::AuthorityReplaced {
            authority_revision, ..
        } if *authority_revision == 0 => Err(AbiError::InvalidEnvelope),
        ServiceResponse::ProviderResult { binding, value } => {
            binding.validate()?;
            if serde_json::to_vec(value)
                .map_err(|_| AbiError::Encoding)?
                .len()
                > MAX_PROVIDER_RESULT_BYTES
            {
                return Err(AbiError::ProviderResultTooLarge);
            }
            Ok(())
        }
        ServiceResponse::ProviderCapabilities {
            binding,
            capabilities,
        } => {
            binding.validate()?;
            capabilities.validate(binding)
        }
        ServiceResponse::ApprovalRequired { approval } => {
            approval
                .binding
                .validate()
                .map_err(|_| AbiError::InvalidApproval)?;
            if approval.origin.is_empty()
                || approval.method.is_empty()
                || approval.expires_at_unix_ms == 0
            {
                return Err(AbiError::InvalidApproval);
            }
            approval.summary.validate()?;
            approval.summary.validate_method(&approval.method)?;
            if serde_json::to_vec(approval)
                .map_err(|_| AbiError::Encoding)?
                .len()
                > MAX_APPROVAL_FRAME_BYTES
            {
                return Err(AbiError::ApprovalTooLarge);
            }
            Ok(())
        }
        ServiceResponse::Wallet { response } => validate_wallet_response(response),
        ServiceResponse::WalletAuthority { context } => {
            validate_wallet_hns_authority_context(context)
        }
        ServiceResponse::Failure { failure } => failure.validate(),
        _ => Ok(()),
    }
}

fn validate_wallet_hns_authority_context(
    context: &WalletHnsAuthorityContext,
) -> Result<(), AbiError> {
    if context.network_magic != context.network.magic()
        || context.namespace_id.iter().all(|byte| *byte == 0)
        || context.namespace_lease_generation == 0
        || context
            .active_wallet
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || context.account.as_bytes().iter().all(|byte| *byte == 0)
        || context.wallet_authority_revision == 0
        || context.account_authority_revision == 0
        || context.locked
        || context.module != ModuleId::Handshake
        || !context.persistent_wallet_confirmed
        || context.recovery_pending
        || context.retirement_pending
        || !context.hns_reads_ready
    {
        return Err(AbiError::InvalidAuthority);
    }
    Ok(())
}

fn validate_wallet_response(response: &WalletResponse) -> Result<(), AbiError> {
    match response {
        WalletResponse::Accounts { accounts } if accounts.len() > MAX_PUBLIC_ITEMS => {
            Err(AbiError::ProviderResultTooLarge)
        }
        WalletResponse::TransactionHistory { transactions }
            if transactions.len() > MAX_PUBLIC_ITEMS =>
        {
            Err(AbiError::ProviderResultTooLarge)
        }
        WalletResponse::Accounts { accounts } => {
            for account in accounts {
                validate_public_string(&account.label)?;
                validate_optional_public_string(&account.receive_display)?;
            }
            Ok(())
        }
        WalletResponse::Workflow { summary } => {
            validate_public_string(&summary.state)?;
            validate_optional_public_string(&summary.next_action)
        }
        _ => Ok(()),
    }
}

fn validate_secret(value: &str, maximum: usize) -> Result<(), AbiError> {
    if value.is_empty() || value.len() > maximum {
        return Err(AbiError::InvalidSecretInput);
    }
    Ok(())
}

fn validate_value_movement(
    amount: Amount,
    recipient: &str,
    maximum_fee: Amount,
    warnings: &BTreeSet<ApprovalWarning>,
) -> Result<(), AbiError> {
    if amount.asset != maximum_fee.asset {
        return Err(AbiError::InvalidApproval);
    }
    validate_amount(amount, false)?;
    validate_public_string(recipient)?;
    validate_amount(maximum_fee, true)?;
    validate_warnings(warnings)
}

fn validate_amount(amount: Amount, allow_zero: bool) -> Result<(), AbiError> {
    if !allow_zero && amount.base_units == BaseUnits::ZERO {
        return Err(AbiError::InvalidApproval);
    }
    Ok(())
}

fn validate_warnings(warnings: &BTreeSet<ApprovalWarning>) -> Result<(), AbiError> {
    if warnings.len() > MAX_PUBLIC_ITEMS {
        return Err(AbiError::InvalidApproval);
    }
    Ok(())
}

fn validate_hns_name_disclosures(names: &[HnsNameDisclosure]) -> Result<(), AbiError> {
    if names.len() > MAX_HNS_NAME_DISCLOSURES || names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AbiError::InvalidApproval);
    }
    let mut canonical_names = BTreeSet::new();
    let mut canonical_hashes = BTreeSet::new();
    for disclosure in names {
        disclosure.validate()?;
        if !canonical_names.insert(disclosure.name.as_str())
            || !canonical_hashes.insert(disclosure.name_hash.as_str())
        {
            return Err(AbiError::InvalidApproval);
        }
    }
    Ok(())
}

fn hns_name_hash_matches(name: &str, encoded: &str) -> bool {
    if encoded.len() != 64 {
        return false;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let Some(high) = nibble(pair[0]) else {
            return false;
        };
        let Some(low) = nibble(pair[1]) else {
            return false;
        };
        decoded[index] = (high << 4) | low;
    }
    hash_name(name.as_bytes()).is_ok_and(|expected| decoded == expected.into_bytes())
}

fn validate_public_string(value: &str) -> Result<(), AbiError> {
    if value.is_empty() || value.len() > MAX_PUBLIC_STRING_BYTES || !value.is_ascii() {
        return Err(AbiError::InvalidPublicValue);
    }
    Ok(())
}

fn validate_optional_public_string(value: &Option<String>) -> Result<(), AbiError> {
    if let Some(value) = value {
        validate_public_string(value)?;
    }
    Ok(())
}

fn validate_public_strings(values: &[String]) -> Result<(), AbiError> {
    if values.len() > MAX_PUBLIC_ITEMS {
        return Err(AbiError::InvalidEvent);
    }
    for value in values {
        validate_public_string(value)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AbiError {
    #[error("frame is empty or exceeds the bounded outer maximum")]
    FrameSize,
    #[error("length-prefixed frame is truncated or has trailing bytes")]
    TruncatedFrame,
    #[error("wallet service protocol version mismatch")]
    VersionMismatch,
    #[error("invalid wallet service envelope")]
    InvalidEnvelope,
    #[error("invalid or stale host authority registration")]
    InvalidAuthority,
    #[error("provider request is invalid")]
    InvalidProviderRequest,
    #[error("provider request exceeds 64 KiB")]
    ProviderRequestTooLarge,
    #[error("provider result exceeds 256 KiB")]
    ProviderResultTooLarge,
    #[error("provider event exceeds 64 KiB")]
    EventTooLarge,
    #[error("approval prompt exceeds 16 KiB")]
    ApprovalTooLarge,
    #[error("approval prompt is incomplete, stale, or mismatched")]
    InvalidApproval,
    #[error("provider event is invalid")]
    InvalidEvent,
    #[error("secret input is empty or exceeds its bounded maximum")]
    InvalidSecretInput,
    #[error("public response value is empty, non-ASCII, or unbounded")]
    InvalidPublicValue,
    #[error("failure response is invalid or unbounded")]
    InvalidFailure,
    #[error("frame JSON encoding failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn host_session() -> HostSessionId {
        HostSessionId::from_bytes([1_u8; 32]).expect("host session")
    }

    fn service_session() -> WalletServiceSessionId {
        WalletServiceSessionId::from_bytes([2_u8; 32]).expect("service session")
    }

    fn wallet_session() -> WalletSessionId {
        WalletSessionId::from_bytes([5_u8; 32]).expect("wallet session")
    }

    fn request_id() -> ProviderRequestId {
        ProviderRequestId::from_bytes([3_u8; 16]).expect("request id")
    }

    fn handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes([4_u8; 32]).expect("handle")
    }

    fn approval_id() -> ProviderApprovalId {
        ProviderApprovalId::from_bytes([6_u8; 16]).expect("approval id")
    }

    fn wallet_id() -> WalletId {
        WalletId::new([8_u8; 16])
    }

    fn assert_json_round_trip<T>(value: &T, expected: Value)
    where
        T: DeserializeOwned + std::fmt::Debug + PartialEq + Serialize,
    {
        let encoded = serde_json::to_value(value).expect("serialize schema-shaped value");
        assert_eq!(encoded, expected);
        let bytes = serde_json::to_vec(&encoded).expect("encode schema-shaped JSON");
        let decoded: T = serde_json::from_slice(&bytes).expect("deserialize schema-shaped value");
        assert_eq!(&decoded, value);
    }

    fn request(body: ServiceRequest) -> HostFrame {
        HostFrame::Request {
            envelope: SessionEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: host_session(),
                service_session_id: service_session(),
                restart_generation: 7,
                channel_sequence: 1,
                request_id: request_id(),
                body,
            },
        }
    }

    #[test]
    fn golden_hello_is_length_prefixed_v2_with_canonical_ids() {
        let encoded = encode_host_frame(&HostFrame::Hello {
            hello: HostHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: HostPlatform::ChromiumNativeHost,
                host_session_id: host_session(),
                restart_generation: 7,
            },
        })
        .expect("encode");
        let declared = u32::from_be_bytes(encoded[..4].try_into().expect("prefix")) as usize;
        assert_eq!(declared, encoded.len() - 4);
        assert!(
            std::str::from_utf8(&encoded[4..])
                .expect("json")
                .contains("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        );
        assert_eq!(
            decode_host_frame(&encoded).expect("decode"),
            decode_host_frame(&encoded).expect("decode twice")
        );
    }

    #[test]
    fn hns_read_operations_v1_is_exact_and_requires_wallet_operations() {
        assert_json_round_trip(
            &ServiceCapability::HnsReadOperationsV1,
            serde_json::json!("hnsReadOperationsV1"),
        );
        assert!(
            serde_json::from_value::<ServiceCapability>(serde_json::json!("hnsReadOperationsV2"))
                .is_err()
        );

        let service_hello = |capabilities| ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: HostPlatform::ChromiumNativeHost,
                host_session_id: host_session(),
                service_session_id: service_session(),
                restart_generation: 7,
                capabilities,
                limits: ServiceLimits::default(),
            },
        };
        assert_eq!(
            encode_service_frame(&service_hello(BTreeSet::from([
                ServiceCapability::HnsReadOperationsV1,
            ]))),
            Err(AbiError::InvalidEnvelope)
        );

        let framed = encode_service_frame(&service_hello(BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ])))
        .expect("exact HNS read hello");
        assert_eq!(
            decode_service_frame(&framed).expect("decode exact HNS read hello"),
            service_hello(BTreeSet::from([
                ServiceCapability::WalletOperations,
                ServiceCapability::HnsReadOperationsV1,
            ]))
        );
    }

    #[test]
    fn hns_wallet_authority_context_v1_is_additive_exact_and_positive_only() {
        assert_json_round_trip(
            &ServiceCapability::HnsWalletAuthorityContextV1,
            serde_json::json!("hnsWalletAuthorityContextV1"),
        );
        let namespace_id = [7_u8; 16];
        let authority_request = WalletAuthorityContextRequest::CurrentHnsContext {
            network: WalletHandshakeNetwork::Regtest,
            network_magic: 0xae38_95cf,
            namespace_id,
            namespace_lease_generation: 9_007_199_254_740_997,
            module: ModuleId::Handshake,
        };
        let request_debug = format!("{authority_request:?}");
        assert!(!request_debug.contains("9007199254740997"));
        assert!(!request_debug.contains("[7, 7"));
        assert_json_round_trip(
            &ServiceRequest::WalletAuthority {
                request: authority_request,
            },
            serde_json::json!({
                "operation": "walletAuthority",
                "request": {
                    "operation": "currentHnsContext",
                    "network": "regtest",
                    "networkMagic": 2_922_943_951_u32,
                    "namespaceId": namespace_id,
                    "namespaceLeaseGeneration": 9_007_199_254_740_997_u64,
                    "module": "handshake",
                },
            }),
        );

        let context = WalletHnsAuthorityContext {
            network: WalletHandshakeNetwork::Regtest,
            network_magic: 0xae38_95cf,
            namespace_id,
            namespace_lease_generation: 9_007_199_254_740_997,
            active_wallet: wallet_id(),
            account: AccountId::new([9_u8; 16]),
            wallet_authority_revision: 9_007_199_254_740_993,
            account_authority_revision: 9_007_199_254_740_995,
            locked: false,
            module: ModuleId::Handshake,
            persistent_wallet_confirmed: true,
            recovery_pending: false,
            retirement_pending: false,
            hns_reads_ready: true,
        };
        let context_debug = format!("{context:?}");
        for private_value in [
            "9007199254740993",
            "9007199254740995",
            "9007199254740997",
            "[7, 7",
            "[8, 8",
            "[9, 9",
        ] {
            assert!(!context_debug.contains(private_value));
        }
        assert_json_round_trip(
            &ServiceResponse::WalletAuthority { context },
            serde_json::json!({
                "result": "walletAuthority",
                "context": {
                    "network": "regtest",
                    "networkMagic": 2_922_943_951_u32,
                    "namespaceId": namespace_id,
                    "namespaceLeaseGeneration": 9_007_199_254_740_997_u64,
                    "activeWallet": [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
                    "account": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                    "walletAuthorityRevision": 9_007_199_254_740_993_u64,
                    "accountAuthorityRevision": 9_007_199_254_740_995_u64,
                    "locked": false,
                    "module": "handshake",
                    "persistentWalletConfirmed": true,
                    "recoveryPending": false,
                    "retirementPending": false,
                    "hnsReadsReady": true,
                },
            }),
        );

        for invalid in [
            WalletAuthorityContextRequest::CurrentHnsContext {
                network: WalletHandshakeNetwork::Regtest,
                network_magic: 1,
                namespace_id,
                namespace_lease_generation: 1,
                module: ModuleId::Handshake,
            },
            WalletAuthorityContextRequest::CurrentHnsContext {
                network: WalletHandshakeNetwork::Regtest,
                network_magic: 0xae38_95cf,
                namespace_id: [0_u8; 16],
                namespace_lease_generation: 1,
                module: ModuleId::Handshake,
            },
            WalletAuthorityContextRequest::CurrentHnsContext {
                network: WalletHandshakeNetwork::Regtest,
                network_magic: 0xae38_95cf,
                namespace_id,
                namespace_lease_generation: 0,
                module: ModuleId::Handshake,
            },
            WalletAuthorityContextRequest::CurrentHnsContext {
                network: WalletHandshakeNetwork::Regtest,
                network_magic: 0xae38_95cf,
                namespace_id,
                namespace_lease_generation: 1,
                module: ModuleId::Bitcoin,
            },
        ] {
            assert_eq!(
                encode_host_frame(&request(ServiceRequest::WalletAuthority {
                    request: invalid,
                })),
                Err(AbiError::InvalidAuthority)
            );
        }

        let service_hello = |capabilities| ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: HostPlatform::ChromiumNativeHost,
                host_session_id: host_session(),
                service_session_id: service_session(),
                restart_generation: 7,
                capabilities,
                limits: ServiceLimits::default(),
            },
        };
        for capabilities in [
            BTreeSet::from([ServiceCapability::HnsWalletAuthorityContextV1]),
            BTreeSet::from([
                ServiceCapability::WalletOperations,
                ServiceCapability::HnsWalletAuthorityContextV1,
            ]),
            BTreeSet::from([
                ServiceCapability::HnsReadOperationsV1,
                ServiceCapability::HnsWalletAuthorityContextV1,
            ]),
        ] {
            assert_eq!(
                encode_service_frame(&service_hello(capabilities)),
                Err(AbiError::InvalidEnvelope)
            );
        }
        encode_service_frame(&service_hello(BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
            ServiceCapability::HnsWalletAuthorityContextV1,
        ])))
        .expect("complete HNS authority capability prerequisites");

        let invalid_context = WalletHnsAuthorityContext {
            locked: true,
            ..context
        };
        let invalid_response = ServiceFrame::Response {
            envelope: SessionEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: host_session(),
                service_session_id: service_session(),
                restart_generation: 7,
                channel_sequence: 1,
                request_id: request_id(),
                body: ServiceResponse::WalletAuthority {
                    context: invalid_context,
                },
            },
        };
        assert_eq!(
            encode_service_frame(&invalid_response),
            Err(AbiError::InvalidAuthority)
        );
    }

    #[test]
    fn v1_unframed_json_and_unknown_fields_are_rejected() {
        assert!(decode_host_frame(br#"{"abi_version":1}"#).is_err());
        let payload = br#"{"frameType":"hello","hello":{"protocolVersion":2,"platform":"chromiumNativeHost","hostSessionId":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","restartGeneration":1,"trusted":true}}"#;
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        assert_eq!(decode_host_frame(&frame), Err(AbiError::InvalidEnvelope));
    }

    #[test]
    fn provider_context_is_only_an_opaque_handle_and_revision() {
        let frame = request(ServiceRequest::ProviderRequest {
            authority_handle: handle(),
            authority_revision: 1,
            request_nonce: 9,
            method: "wallet_getStatus".to_owned(),
            params: Value::Null,
        });
        let encoded = encode_host_frame(&frame).expect("frame");
        let json: Value = serde_json::from_slice(&encoded[LENGTH_PREFIX_BYTES..]).expect("json");
        assert_eq!(
            json["envelope"]["body"],
            serde_json::json!({
                "operation": "providerRequest",
                "authorityHandle": serde_json::to_value(handle()).expect("handle"),
                "authorityRevision": 1,
                "requestNonce": 9,
                "method": "wallet_getStatus",
                "params": null,
            })
        );
        assert_eq!(decode_host_frame(&encoded), Ok(frame));
    }

    #[test]
    fn every_tagged_enum_uses_schema_shaped_camel_case_fields() {
        assert_json_round_trip(
            &ServiceFrame::Response {
                envelope: SessionEnvelope {
                    protocol_version: WALLET_ABI_VERSION,
                    host_session_id: host_session(),
                    service_session_id: service_session(),
                    restart_generation: 7,
                    channel_sequence: 1,
                    request_id: request_id(),
                    body: ServiceResponse::AuthorityRegistered {
                        authority_handle: handle(),
                        authority_revision: 2,
                    },
                },
            },
            serde_json::json!({
                "frameType": "response",
                "envelope": {
                    "protocolVersion": WALLET_ABI_VERSION,
                    "hostSessionId": serde_json::to_value(host_session()).expect("host session"),
                    "serviceSessionId": serde_json::to_value(service_session()).expect("service session"),
                    "restartGeneration": 7,
                    "channelSequence": 1,
                    "requestId": serde_json::to_value(request_id()).expect("request id"),
                    "body": {
                        "result": "authorityRegistered",
                        "authorityHandle": serde_json::to_value(handle()).expect("handle"),
                        "authorityRevision": 2,
                    },
                },
            }),
        );
        assert_json_round_trip(
            &WalletRequest::RestoreWallet {
                passphrase: SecretString::new("correct horse battery staple".to_owned()),
                recovery_phrase: SecretString::new(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        .to_owned(),
                ),
            },
            serde_json::json!({
                "operation": "restoreWallet",
                "passphrase": "correct horse battery staple",
                "recoveryPhrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            }),
        );
        assert_json_round_trip(
            &ServiceResponse::AuthorityRegistered {
                authority_handle: handle(),
                authority_revision: 2,
            },
            serde_json::json!({
                "result": "authorityRegistered",
                "authorityHandle": serde_json::to_value(handle()).expect("handle"),
                "authorityRevision": 2,
            }),
        );
        assert_json_round_trip(
            &WalletResponse::WalletCreated {
                wallet_id: wallet_id(),
            },
            serde_json::json!({
                "result": "walletCreated",
                "walletId": serde_json::to_value(wallet_id()).expect("wallet id"),
            }),
        );
        assert_json_round_trip(
            &ApprovalSummary::TypedSignature {
                message_type: "hns-name-auth".to_owned(),
                message_digest: "00".repeat(32),
            },
            serde_json::json!({
                "kind": "typedSignature",
                "messageType": "hns-name-auth",
                "messageDigest": "00".repeat(32),
            }),
        );
        assert_json_round_trip(
            &ProviderEventPayload::MarketIntentChanged {
                market_intent_ids: vec!["intent-1".to_owned()],
            },
            serde_json::json!({
                "event": "marketIntentChanged",
                "marketIntentIds": ["intent-1"],
            }),
        );
    }

    #[test]
    fn provider_outputs_carry_the_private_authority_binding() {
        let response = ServiceResponse::ProviderResult {
            binding: ProviderBinding {
                authority_handle: handle(),
                authority_revision: 3,
                wallet_session_id: wallet_session(),
                permission_generation: 0,
            },
            value: Value::Null,
        };
        validate_service_response(&response).expect("fresh generation is valid");
        let json = serde_json::to_string(&response).expect("json");
        assert!(json.contains("walletSessionId"));
        assert!(json.contains("permissionGeneration"));

        let prompt = ApprovalPrompt {
            approval_id: approval_id(),
            binding: ProviderBinding {
                authority_handle: handle(),
                authority_revision: 3,
                wallet_session_id: wallet_session(),
                permission_generation: 0,
            },
            origin: "https://wallet.example".to_owned(),
            method: "wallet_requestPermissions".to_owned(),
            expires_at_unix_ms: 10_000,
            summary: ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Balance]),
                hns_names: Vec::new(),
            },
        };
        prompt
            .validate(ApprovalKind::Permission, 1_000)
            .expect("bound prompt");
    }

    #[test]
    fn canonical_provider_account_join_private_capability_snapshot_is_exact_and_bound() {
        assert_eq!(
            validate_service_request(&ServiceRequest::ProviderCapabilities {
                authority_handle: handle(),
                authority_revision: 0,
            }),
            Err(AbiError::InvalidAuthority)
        );
        let binding = ProviderBinding {
            authority_handle: handle(),
            authority_revision: 1,
            wallet_session_id: wallet_session(),
            permission_generation: 0,
        };
        let capabilities = ProviderCapabilitySnapshot {
            provider_schema_version: PROVIDER_SCHEMA_VERSION,
            approval_schema_version: APPROVAL_SCHEMA_VERSION,
            wallet_session_id: wallet_session(),
            permission_generation: 0,
            methods: BTreeSet::from(["wallet_getCapabilities".to_owned()]),
        };
        validate_service_response(&ServiceResponse::ProviderCapabilities {
            binding,
            capabilities: capabilities.clone(),
        })
        .expect("matching snapshot");

        let mut mismatched = capabilities.clone();
        mismatched.permission_generation = 1;
        assert_eq!(
            validate_service_response(&ServiceResponse::ProviderCapabilities {
                binding,
                capabilities: mismatched,
            }),
            Err(AbiError::InvalidEnvelope)
        );
        let mut mismatched_session = capabilities.clone();
        mismatched_session.wallet_session_id =
            WalletSessionId::from_bytes([7_u8; 32]).expect("other wallet session");
        assert_eq!(
            validate_service_response(&ServiceResponse::ProviderCapabilities {
                binding,
                capabilities: mismatched_session,
            }),
            Err(AbiError::InvalidEnvelope)
        );
        let mut invalid_schema = capabilities.clone();
        invalid_schema.provider_schema_version += 1;
        assert_eq!(
            validate_service_response(&ServiceResponse::ProviderCapabilities {
                binding,
                capabilities: invalid_schema,
            }),
            Err(AbiError::InvalidEnvelope)
        );
        let mut unknown_method = capabilities.clone();
        unknown_method.methods = BTreeSet::from(["wallet_unknown".to_owned()]);
        assert_eq!(
            validate_service_response(&ServiceResponse::ProviderCapabilities {
                binding,
                capabilities: unknown_method,
            }),
            Err(AbiError::InvalidEnvelope)
        );
        let mut account_join = capabilities.clone();
        account_join.methods = BTreeSet::from(["hns_requestAccounts".to_owned()]);
        validate_service_response(&ServiceResponse::ProviderCapabilities {
            binding,
            capabilities: account_join,
        })
        .expect("canonical account join method");

        let account_prompt = ApprovalPrompt {
            approval_id: approval_id(),
            binding,
            origin: "https://wallet.example".to_owned(),
            method: "hns_requestAccounts".to_owned(),
            expires_at_unix_ms: 10_000,
            summary: ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Accounts]),
                hns_names: Vec::new(),
            },
        };
        account_prompt
            .validate(ApprovalKind::Permission, 1_000)
            .expect("exact account permission prompt");
        let mut wrong_account_prompt = account_prompt.clone();
        wrong_account_prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Balance]),
            hns_names: Vec::new(),
        };
        assert_eq!(
            wrong_account_prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );
        let mut generic_accounts = account_prompt;
        generic_accounts.method = "wallet_requestPermissions".to_owned();
        assert_eq!(
            generic_accounts.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );
        let mut oversized_method = capabilities;
        oversized_method.methods = BTreeSet::from(["m".repeat(MAX_METHOD_BYTES + 1)]);
        assert_eq!(
            validate_service_response(&ServiceResponse::ProviderCapabilities {
                binding,
                capabilities: oversized_method,
            }),
            Err(AbiError::InvalidEnvelope)
        );
    }

    #[test]
    fn production_followup_permission_name_disclosures_are_exact_sorted_and_bounded() {
        let alpha = HnsNameDisclosure {
            name: "alpha".to_owned(),
            name_hash: "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
                .to_owned(),
        };
        let beta = HnsNameDisclosure {
            name: "beta".to_owned(),
            name_hash: "f0277d92062bd9a41dd26cddbaf2c41d576cf7b0173cbe96c23d5f5a4f92cc8f"
                .to_owned(),
        };
        let mut prompt = ApprovalPrompt {
            approval_id: approval_id(),
            binding: ProviderBinding {
                authority_handle: handle(),
                authority_revision: 3,
                wallet_session_id: wallet_session(),
                permission_generation: 1,
            },
            origin: "https://wallet.example".to_owned(),
            method: "wallet_requestPermissions".to_owned(),
            expires_at_unix_ms: 10_000,
            summary: ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Names]),
                hns_names: vec![alpha.clone(), beta.clone()],
            },
        };
        prompt
            .validate(ApprovalKind::Permission, 1_000)
            .expect("sorted exact name disclosure");
        let encoded = serde_json::to_value(&prompt).expect("name prompt JSON");
        assert_eq!(
            encoded["summary"]["hnsNames"],
            serde_json::json!([
                { "name": "alpha", "nameHash": "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af" },
                { "name": "beta", "nameHash": "f0277d92062bd9a41dd26cddbaf2c41d576cf7b0173cbe96c23d5f5a4f92cc8f" },
            ])
        );

        let ApprovalSummary::Permissions { hns_names, .. } = &mut prompt.summary else {
            panic!("permission summary")
        };
        hns_names.swap(0, 1);
        assert_eq!(
            prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );

        let oversized = (0..=MAX_HNS_NAME_DISCLOSURES)
            .map(|index| HnsNameDisclosure {
                name: format!("name-{index:03}"),
                name_hash: format!("{index:064x}"),
            })
            .collect();
        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            hns_names: oversized,
        };
        assert_eq!(
            prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );

        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            hns_names: vec![HnsNameDisclosure {
                name: "alpha".to_owned(),
                name_hash: "f0277d92062bd9a41dd26cddbaf2c41d576cf7b0173cbe96c23d5f5a4f92cc8f"
                    .to_owned(),
            }],
        };
        assert_eq!(
            prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );

        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            hns_names: vec![alpha.clone(), alpha.clone()],
        };
        assert_eq!(
            prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );

        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Balance]),
            hns_names: vec![alpha],
        };
        assert_eq!(
            prompt.validate(ApprovalKind::Permission, 1_000),
            Err(AbiError::InvalidApproval)
        );
        assert!(
            serde_json::from_value::<ApprovalSummary>(serde_json::json!({
                "kind": "permissions",
                "capabilities": ["balance"],
            }))
            .is_err()
        );
    }

    #[test]
    fn event_generation_must_match_its_authority_binding() {
        let mut event = ProviderEventEnvelope {
            protocol_version: WALLET_ABI_VERSION,
            host_session_id: host_session(),
            service_session_id: service_session(),
            restart_generation: 1,
            channel_sequence: 1,
            binding: ProviderBinding {
                authority_handle: handle(),
                authority_revision: 1,
                wallet_session_id: wallet_session(),
                permission_generation: 6,
            },
            event_sequence: 1,
            payload: ProviderEventPayload::Connect {
                permission_generation: 7,
            },
        };
        assert_eq!(
            validate_service_frame(&ServiceFrame::Event {
                event: event.clone()
            }),
            Err(AbiError::InvalidEvent)
        );
        event.binding.permission_generation = 7;
        validate_service_frame(&ServiceFrame::Event { event }).expect("matching generation");
    }

    #[test]
    fn oversized_declared_payload_fails_before_payload_allocation() {
        assert_eq!(
            declared_payload_len(((MAX_ABI_FRAME_BYTES as u32) + 1).to_be_bytes()),
            Err(AbiError::FrameSize)
        );
    }

    #[test]
    fn every_provider_approval_kind_has_a_typed_wire_variant() {
        let kinds = [
            ApprovalKind::Permission,
            ApprovalKind::ModuleEnablement,
            ApprovalKind::Send,
            ApprovalKind::NameTransfer,
            ApprovalKind::NameFinalize,
            ApprovalKind::TypedSignature,
            ApprovalKind::NameMarketOffer,
            ApprovalKind::NameMarketPurchase,
            ApprovalKind::MarketIntent,
            ApprovalKind::FillAcceptance,
            ApprovalKind::SwapRedeem,
            ApprovalKind::SwapRefund,
        ];
        assert_eq!(kinds.len(), 12);
        assert!(!kinds.contains(&ApprovalKind::RecoveryPhraseDisplay));
    }
}
