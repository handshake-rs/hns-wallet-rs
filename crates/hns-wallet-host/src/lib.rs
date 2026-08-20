#![doc = "Fail-closed private ABI-v2 host state for browser and mobile adapters."]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use hns_wallet_ffi::{
    APPROVAL_SCHEMA_VERSION, ApprovalDecision, ApprovalPrompt, DisconnectReason,
    HostAuthorityFacts, HostFrame, HostHello, HostPlatform, MAX_METHOD_BYTES, MAX_ORIGIN_BYTES,
    MAX_PROVIDER_METHODS, MAX_PROVIDER_REQUEST_BYTES, MAX_PUBLIC_ITEMS, MAX_PUBLIC_STRING_BYTES,
    PROVIDER_SCHEMA_VERSION, ProviderBinding, ProviderCapabilitySnapshot, ProviderEventEnvelope,
    ProviderEventPayload, ServiceCapability, ServiceErrorCode, ServiceFrame, ServiceHello,
    ServiceLimits, ServiceRequest, ServiceResponse, SessionEnvelope, WALLET_ABI_VERSION,
    WalletAuthorityContextRequest, WalletHnsAuthorityContext, WalletRequest, WalletResponse,
};
use hns_wallet_types::{
    AccountId, HostAuthorityHandleId, HostSessionId, ModuleId, PROVIDER_METHOD_WIRE_NAMES,
    ProviderApprovalId, ProviderRequestId, SyncPhase, WalletAsset, WalletServiceSessionId,
};
use serde_json::Value;
use thiserror::Error;

pub const MAX_AUTHORITIES: usize = 256;
pub const MAX_PENDING_REQUESTS: usize = 1_024;
pub const MAX_PENDING_APPROVALS: usize = 128;
pub const MAX_RECENT_REQUEST_IDS: usize = 4_096;
pub const MAX_RECENT_PROVIDER_NONCES: usize = 4_096;
pub const MAX_ISSUED_AUTHORITY_IDS: usize = 4_096;
pub const MAX_ISSUED_APPROVAL_IDS: usize = 4_096;

const RANDOM_ATTEMPTS: usize = 16;

/// A clock owned by [`WalletHost`]. Implementations must report Unix
/// milliseconds and must not silently substitute a monotonic-process epoch.
pub trait Clock {
    fn now_unix_ms(&self) -> Result<u64, ClockError>;
}

/// An entropy source owned by [`WalletHost`]. A successful call must fill the
/// complete destination with cryptographically secure random bytes.
pub trait Entropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClockError {
    #[error("system time is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("trusted wall clock is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EntropyError {
    #[error("operating-system entropy is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, ClockError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeUnixEpoch)?;
        u64::try_from(duration.as_millis()).map_err(|_| ClockError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    AwaitingHello,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityLifecycle {
    Detached,
    Registering,
    Active { revision: u64 },
    Replacing { revision: u64 },
    Revoking { revision: u64 },
    Stale { revision: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshot {
    pub facts: HostAuthorityFacts,
    pub lifecycle: AuthorityLifecycle,
    pub binding: Option<ProviderBinding>,
    pub capabilities: Option<ProviderCapabilitySnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedSession {
    pub protocol_version: u16,
    pub platform: HostPlatform,
    pub host_session_id: HostSessionId,
    pub service_session_id: WalletServiceSessionId,
    pub restart_generation: u64,
    pub capabilities: BTreeSet<ServiceCapability>,
    pub limits: ServiceLimits,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedResponse {
    pub request_id: ProviderRequestId,
    pub response: ServiceResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedEvent {
    pub binding: ProviderBinding,
    pub event_sequence: u64,
    pub payload: ProviderEventPayload,
}

#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "this public output enum preserves its established by-value variant representation for downstream host integrations"
)]
pub enum HostOutput {
    Negotiated(NegotiatedSession),
    Response(AcceptedResponse),
    Event(AcceptedEvent),
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error(transparent)]
    Clock(#[from] ClockError),
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    #[error("clock moved backwards")]
    ClockRollback,
    #[error("restart generation must be nonzero and strictly increase")]
    InvalidRestartGeneration,
    #[error("random source repeatedly returned a zero or colliding identifier")]
    RandomIdentityUnavailable,
    #[error("service hello is required")]
    HandshakeRequired,
    #[error("the host/service channel has failed and must be restarted")]
    ChannelFailed,
    #[error("unexpected service hello")]
    UnexpectedHello,
    #[error("service hello does not exactly match the host negotiation")]
    HelloMismatch,
    #[error("required negotiated service capability is absent")]
    CapabilityUnavailable,
    #[error("request is not in the exact HNS read-operations-v1 surface")]
    InvalidHnsReadRequest,
    #[error("request is not a valid native HNS wallet authority-context claim")]
    InvalidHnsWalletAuthorityRequest,
    #[error("pending request capacity is exhausted")]
    PendingRequestCapacity,
    #[error("authority capacity is exhausted")]
    AuthorityCapacity,
    #[error("authority identifier lifetime capacity is exhausted")]
    AuthorityIdentityCapacity,
    #[error("pending approval capacity is exhausted")]
    ApprovalCapacity,
    #[error("approval identifier lifetime capacity is exhausted")]
    ApprovalIdentityCapacity,
    #[error("channel sequence is exhausted")]
    SequenceExhausted,
    #[error("invalid host-owned authority facts")]
    InvalidAuthorityFacts,
    #[error("host-owned authority facts have expired")]
    AuthorityExpired,
    #[error("authority is unknown")]
    AuthorityUnknown,
    #[error("authority lifecycle does not permit this operation")]
    AuthorityLifecycle,
    #[error("authority or provider binding is stale")]
    StaleBinding,
    #[error("provider method is not present in the current exact capability snapshot")]
    MethodUnavailable,
    #[error("provider request is malformed or exceeds its ABI bound")]
    InvalidProviderRequest,
    #[error("pending request is unknown, duplicated, or stale")]
    PendingRequestMismatch,
    #[error("service response class does not match its request")]
    ResponseClassMismatch,
    #[error("service frame session does not exactly match the negotiated session")]
    SessionMismatch,
    #[error("service channel sequence mismatch: expected {expected}, received {received}")]
    SequenceMismatch { expected: u64, received: u64 },
    #[error("provider capability snapshot is not exact")]
    InvalidCapabilitySnapshot,
    #[error("approval is unknown, mismatched, already decided, or stale")]
    ApprovalMismatch,
    #[error("approval has expired")]
    ApprovalExpired,
    #[error("provider event binding is not current")]
    EventBindingMismatch,
    #[error("provider event is stale or replayed")]
    EventReplay,
    #[error("service reported a protocol-level failure")]
    ReportedProtocolFailure,
    #[error("JSON sizing failed")]
    Encoding,
}

#[derive(Clone)]
enum AuthorityPhase {
    Detached,
    Registering,
    Active {
        revision: u64,
    },
    Replacing {
        revision: u64,
        replacement: HostAuthorityFacts,
    },
    Revoking {
        revision: u64,
    },
    Stale {
        revision: u64,
    },
}

#[derive(Clone)]
struct AuthorityState {
    facts: HostAuthorityFacts,
    phase: AuthorityPhase,
    binding: Option<ProviderBinding>,
    capabilities: Option<ProviderCapabilitySnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventCursorKey {
    authority_handle: HostAuthorityHandleId,
    authority_revision: u64,
    wallet_session_id: hns_wallet_types::WalletSessionId,
    permission_generation: u64,
}

impl EventCursorKey {
    fn from_binding(binding: ProviderBinding) -> Self {
        Self {
            authority_handle: binding.authority_handle,
            authority_revision: binding.authority_revision,
            wallet_session_id: binding.wallet_session_id,
            permission_generation: binding.permission_generation,
        }
    }
}

#[derive(Clone, Copy)]
enum ApprovalPhase {
    Available,
    Deciding { request_id: ProviderRequestId },
}

#[derive(Clone)]
struct HostApproval {
    prompt: ApprovalPrompt,
    phase: ApprovalPhase,
}

#[derive(Clone)]
enum RequestClass {
    Register {
        handle: HostAuthorityHandleId,
    },
    Replace {
        handle: HostAuthorityHandleId,
        expected_revision: u64,
        replacement: HostAuthorityFacts,
    },
    Revoke {
        handle: HostAuthorityHandleId,
        expected_revision: u64,
    },
    Capabilities {
        handle: HostAuthorityHandleId,
        revision: u64,
    },
    Provider {
        handle: HostAuthorityHandleId,
        revision: u64,
        method: String,
    },
    Approval {
        handle: HostAuthorityHandleId,
        revision: u64,
        approval_id: ProviderApprovalId,
        decision: ApprovalDecision,
        method: String,
    },
    Wallet(WalletResponseClass),
    HnsRead(HnsReadResponseClass),
    HnsWalletAuthority(HnsWalletAuthorityResponseClass),
}

impl RequestClass {
    fn authority(&self) -> Option<HostAuthorityHandleId> {
        match self {
            Self::Register { handle }
            | Self::Replace { handle, .. }
            | Self::Revoke { handle, .. }
            | Self::Capabilities { handle, .. }
            | Self::Provider { handle, .. }
            | Self::Approval { handle, .. } => Some(*handle),
            Self::Wallet(_) | Self::HnsRead(_) | Self::HnsWalletAuthority(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
struct HnsWalletAuthorityResponseClass {
    request: WalletAuthorityContextRequest,
}

impl HnsWalletAuthorityResponseClass {
    fn for_request(request: WalletAuthorityContextRequest) -> Result<Self, HostError> {
        let WalletAuthorityContextRequest::CurrentHnsContext {
            network,
            network_magic,
            namespace_id,
            namespace_lease_generation,
            module,
        } = request;
        if network_magic != network.magic()
            || namespace_id.iter().all(|byte| *byte == 0)
            || namespace_lease_generation == 0
            || module != ModuleId::Handshake
        {
            return Err(HostError::InvalidHnsWalletAuthorityRequest);
        }
        Ok(Self { request })
    }

    fn matches(self, context: &WalletHnsAuthorityContext) -> bool {
        let WalletAuthorityContextRequest::CurrentHnsContext {
            network,
            network_magic,
            namespace_id,
            namespace_lease_generation,
            module,
        } = self.request;
        context.network == network
            && context.network_magic == network_magic
            && context.namespace_id == namespace_id
            && context.namespace_lease_generation == namespace_lease_generation
            && context.active_wallet.as_bytes() != &[0_u8; 16]
            && context.account.as_bytes() != &[0_u8; 16]
            && context.wallet_authority_revision != 0
            && context.account_authority_revision != 0
            && !context.locked
            && context.module == module
            && context.persistent_wallet_confirmed
            && !context.recovery_pending
            && !context.retirement_pending
            && context.hns_reads_ready
    }
}

#[derive(Clone, Copy)]
enum HnsReadResponseClass {
    Status,
    Accounts,
    Balance,
    ReceiveTarget { account: AccountId },
    Transactions,
    ModuleStatus,
}

impl HnsReadResponseClass {
    fn for_request(request: &WalletRequest) -> Result<Self, HostError> {
        match request {
            WalletRequest::Status => Ok(Self::Status),
            WalletRequest::ListAccounts => Ok(Self::Accounts),
            WalletRequest::Balance {
                module: ModuleId::Handshake,
                ..
            } => Ok(Self::Balance),
            WalletRequest::ReceiveTarget {
                module: ModuleId::Handshake,
                account,
            } => Ok(Self::ReceiveTarget { account: *account }),
            WalletRequest::TransactionHistory {
                module: ModuleId::Handshake,
                ..
            } => Ok(Self::Transactions),
            WalletRequest::ModuleStatus {
                module: ModuleId::Handshake,
            } => Ok(Self::ModuleStatus),
            _ => Err(HostError::InvalidHnsReadRequest),
        }
    }

    fn matches(self, response: &WalletResponse) -> bool {
        match (self, response) {
            (Self::Status, WalletResponse::Status { status }) => {
                !status.mainnet_settlement_enabled
                    && status.locked == status.active_wallet.is_none()
                    && status
                        .active_wallet
                        .is_none_or(|wallet| wallet.as_bytes() != &[0_u8; 16])
                    && status.enabled_modules.len() <= 1
                    && status
                        .enabled_modules
                        .iter()
                        .all(|module| *module == ModuleId::Handshake)
            }
            (Self::Accounts, WalletResponse::Accounts { accounts }) => {
                matches!(accounts.as_slice(), [account]
                    if account.module == ModuleId::Handshake
                        && account.account_id.as_bytes() != &[0_u8; 16]
                        && !account.label.is_empty()
                        && account.label.len() <= MAX_PUBLIC_STRING_BYTES
                        && account
                            .label
                            .bytes()
                            .all(|byte| (0x20..=0x7e).contains(&byte))
                        && account.receive_display.is_none())
            }
            (Self::Balance, WalletResponse::Balance { amount }) => amount.asset == WalletAsset::Hns,
            (Self::ReceiveTarget { account }, WalletResponse::ReceiveTarget { target }) => {
                target.module == ModuleId::Handshake
                    && target.account == account
                    && !target.display.is_empty()
                    && target.display.len() <= 512
                    && target
                        .display
                        .bytes()
                        .all(|byte| (0x21..=0x7e).contains(&byte))
            }
            (Self::Transactions, WalletResponse::TransactionHistory { transactions }) => {
                let mut txids = BTreeSet::new();
                transactions.iter().all(|transaction| {
                    transaction.module == ModuleId::Handshake
                        && transaction.txid.as_bytes() != &[0_u8; 32]
                        && !(transaction.net_amount.negative
                            && transaction.net_amount.magnitude.is_zero())
                        && txids.insert(transaction.txid)
                })
            }
            (Self::ModuleStatus, WalletResponse::ModuleStatus { status }) => {
                status.phase == SyncPhase::Ready
                    && status.validated_height == status.scanned_height
                    && status.target_height == Some(status.validated_height)
                    && status.last_error.is_none()
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
enum WalletResponseClass {
    Status,
    Create,
    Restore,
    Unlock,
    Lock,
    Accounts,
    Balance,
    ReceiveTarget,
    Transactions,
    ModuleStatus,
    Workflow,
}

impl WalletResponseClass {
    fn for_request(request: &WalletRequest) -> Self {
        match request {
            WalletRequest::Status => Self::Status,
            WalletRequest::CreateWallet { .. } => Self::Create,
            WalletRequest::RestoreWallet { .. } => Self::Restore,
            WalletRequest::Unlock { .. } => Self::Unlock,
            WalletRequest::Lock => Self::Lock,
            WalletRequest::ListAccounts => Self::Accounts,
            WalletRequest::Balance { .. } => Self::Balance,
            WalletRequest::ReceiveTarget { .. } => Self::ReceiveTarget,
            WalletRequest::TransactionHistory { .. } => Self::Transactions,
            WalletRequest::ModuleStatus { .. } => Self::ModuleStatus,
            WalletRequest::WorkflowStatus { .. } => Self::Workflow,
        }
    }

    fn matches(self, response: &WalletResponse) -> bool {
        matches!(
            (self, response),
            (Self::Status, WalletResponse::Status { .. })
                | (Self::Create, WalletResponse::WalletCreated { .. })
                | (Self::Restore, WalletResponse::WalletRestored { .. })
                | (Self::Unlock, WalletResponse::Unlocked)
                | (Self::Lock, WalletResponse::Locked)
                | (Self::Accounts, WalletResponse::Accounts { .. })
                | (Self::Balance, WalletResponse::Balance { .. })
                | (Self::ReceiveTarget, WalletResponse::ReceiveTarget { .. })
                | (
                    Self::Transactions,
                    WalletResponse::TransactionHistory { .. }
                )
                | (Self::ModuleStatus, WalletResponse::ModuleStatus { .. })
                | (Self::Workflow, WalletResponse::Workflow { .. })
        )
    }
}

struct SessionState {
    service_session_id: WalletServiceSessionId,
    capabilities: BTreeSet<ServiceCapability>,
    next_host_sequence: u64,
    next_service_sequence: u64,
}

enum ChannelState {
    AwaitingHello,
    Ready(SessionState),
    Failed,
}

struct QueuedRequest {
    request_id: ProviderRequestId,
    frame: HostFrame,
}

/// Process-local host state. It deliberately does not implement `Clone` or
/// serialization: session, authority, approval, and replay state must not be
/// persisted or projected into a website context.
pub struct WalletHost<C, E> {
    platform: HostPlatform,
    host_session_id: HostSessionId,
    restart_generation: u64,
    clock: C,
    entropy: E,
    last_now_unix_ms: Option<u64>,
    channel: ChannelState,
    pending: BTreeMap<ProviderRequestId, RequestClass>,
    recent_request_ids: BTreeSet<ProviderRequestId>,
    request_id_order: VecDeque<ProviderRequestId>,
    aged_out_request_ids: BTreeSet<ProviderRequestId>,
    recent_nonces: BTreeSet<(HostAuthorityHandleId, u64)>,
    nonce_order: VecDeque<(HostAuthorityHandleId, u64)>,
    authorities: BTreeMap<HostAuthorityHandleId, AuthorityState>,
    issued_authority_ids: BTreeSet<HostAuthorityHandleId>,
    approvals: BTreeMap<ProviderApprovalId, HostApproval>,
    issued_approval_ids: BTreeSet<ProviderApprovalId>,
    event_cursors: BTreeMap<EventCursorKey, u64>,
}

impl WalletHost<SystemClock, SystemEntropy> {
    pub fn new_system(platform: HostPlatform, restart_generation: u64) -> Result<Self, HostError> {
        Self::new(platform, restart_generation, SystemClock, SystemEntropy)
    }
}

impl<C: Clock, E: Entropy> WalletHost<C, E> {
    pub fn new(
        platform: HostPlatform,
        restart_generation: u64,
        clock: C,
        mut entropy: E,
    ) -> Result<Self, HostError> {
        if restart_generation == 0 {
            return Err(HostError::InvalidRestartGeneration);
        }
        let host_session_id = random_host_session(&mut entropy)?;
        Ok(Self {
            platform,
            host_session_id,
            restart_generation,
            clock,
            entropy,
            last_now_unix_ms: None,
            channel: ChannelState::AwaitingHello,
            pending: BTreeMap::new(),
            recent_request_ids: BTreeSet::new(),
            request_id_order: VecDeque::new(),
            aged_out_request_ids: BTreeSet::new(),
            recent_nonces: BTreeSet::new(),
            nonce_order: VecDeque::new(),
            authorities: BTreeMap::new(),
            issued_authority_ids: BTreeSet::new(),
            approvals: BTreeMap::new(),
            issued_approval_ids: BTreeSet::new(),
            event_cursors: BTreeMap::new(),
        })
    }

    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }

    pub const fn host_session_id(&self) -> HostSessionId {
        self.host_session_id
    }

    pub const fn restart_generation(&self) -> u64 {
        self.restart_generation
    }

    pub fn connection_state(&self) -> ConnectionState {
        match &self.channel {
            ChannelState::AwaitingHello => ConnectionState::AwaitingHello,
            ChannelState::Ready(_) => ConnectionState::Ready,
            ChannelState::Failed => ConnectionState::Failed,
        }
    }

    pub fn hello_frame(&self) -> Result<HostFrame, HostError> {
        match &self.channel {
            ChannelState::AwaitingHello => Ok(HostFrame::Hello {
                hello: HostHello {
                    protocol_version: WALLET_ABI_VERSION,
                    platform: self.platform,
                    host_session_id: self.host_session_id,
                    restart_generation: self.restart_generation,
                },
            }),
            ChannelState::Ready(_) => Err(HostError::UnexpectedHello),
            ChannelState::Failed => Err(HostError::ChannelFailed),
        }
    }

    /// Starts negotiation for a newer service process while retaining the
    /// random host session. All service-derived state is invalidated first.
    pub fn restart(&mut self, restart_generation: u64) -> Result<HostFrame, HostError> {
        if restart_generation == 0 || restart_generation <= self.restart_generation {
            return Err(HostError::InvalidRestartGeneration);
        }
        self.invalidate_service_state();
        self.restart_generation = restart_generation;
        self.channel = ChannelState::AwaitingHello;
        self.hello_frame()
    }

    /// Starts a completely fresh host session. The supplied restart generation
    /// is scoped to the new random session and therefore need only be nonzero.
    pub fn reset(&mut self, restart_generation: u64) -> Result<HostFrame, HostError> {
        if restart_generation == 0 {
            return Err(HostError::InvalidRestartGeneration);
        }
        let host_session_id = random_host_session(&mut self.entropy)?;
        self.invalidate_service_state();
        self.host_session_id = host_session_id;
        self.restart_generation = restart_generation;
        self.last_now_unix_ms = None;
        self.recent_request_ids.clear();
        self.request_id_order.clear();
        self.aged_out_request_ids.clear();
        self.recent_nonces.clear();
        self.nonce_order.clear();
        self.issued_approval_ids.clear();
        self.channel = ChannelState::AwaitingHello;
        self.hello_frame()
    }

    pub fn negotiated_session(&self) -> Option<NegotiatedSession> {
        let ChannelState::Ready(session) = &self.channel else {
            return None;
        };
        Some(NegotiatedSession {
            protocol_version: WALLET_ABI_VERSION,
            platform: self.platform,
            host_session_id: self.host_session_id,
            service_session_id: session.service_session_id,
            restart_generation: self.restart_generation,
            capabilities: session.capabilities.clone(),
            limits: ServiceLimits::default(),
        })
    }

    pub fn authority(&self, handle: HostAuthorityHandleId) -> Option<AuthoritySnapshot> {
        self.authorities
            .get(&handle)
            .map(|state| AuthoritySnapshot {
                facts: state.facts.clone(),
                lifecycle: lifecycle(&state.phase),
                binding: state.binding,
                capabilities: state.capabilities.clone(),
            })
    }

    /// Forgets host facts that can no longer authorize work. A live,
    /// non-expired authority must use the correlated revoke operation instead.
    pub fn discard_authority(&mut self, handle: HostAuthorityHandleId) -> Result<(), HostError> {
        let now = self.now()?;
        let discardable = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            matches!(
                &state.phase,
                AuthorityPhase::Detached | AuthorityPhase::Stale { .. }
            ) || state.facts.valid_until_unix_ms <= now
        };
        if !discardable {
            return Err(HostError::AuthorityLifecycle);
        }
        let cancelled = self
            .pending
            .iter()
            .filter_map(|(request_id, class)| {
                (class.authority() == Some(handle)).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in cancelled {
            self.pending.remove(&request_id);
            if self.aged_out_request_ids.remove(&request_id) {
                self.recent_request_ids.remove(&request_id);
            }
        }
        self.invalidate_authority_derived(handle);
        self.authorities.remove(&handle);
        Ok(())
    }

    pub fn approval(
        &mut self,
        approval_id: ProviderApprovalId,
    ) -> Result<ApprovalPrompt, HostError> {
        let now = self.now()?;
        let approval = self
            .approvals
            .get(&approval_id)
            .ok_or(HostError::ApprovalMismatch)?;
        if approval.prompt.expires_at_unix_ms <= now {
            self.approvals.remove(&approval_id);
            return Err(HostError::ApprovalExpired);
        }
        if !matches!(approval.phase, ApprovalPhase::Available) {
            return Err(HostError::ApprovalMismatch);
        }
        Ok(approval.prompt.clone())
    }

    /// Registers facts supplied by the trusted engine/mobile policy boundary.
    /// The returned handle is private host state and must never be page input.
    pub fn register_authority(
        &mut self,
        facts: HostAuthorityFacts,
    ) -> Result<(HostAuthorityHandleId, HostFrame), HostError> {
        self.require_capability(ServiceCapability::OpaqueAuthorityRegistry)?;
        if self.authorities.len() >= MAX_AUTHORITIES {
            return Err(HostError::AuthorityCapacity);
        }
        if self.issued_authority_ids.len() >= MAX_ISSUED_AUTHORITY_IDS {
            return Err(HostError::AuthorityIdentityCapacity);
        }
        let now = self.now()?;
        validate_authority_facts(&facts, now)?;
        let handle = self.random_authority_handle()?;
        let queued = self.enqueue(
            ServiceRequest::RegisterAuthority {
                authority_handle: handle,
                authority: facts.clone(),
            },
            RequestClass::Register { handle },
        )?;
        self.issued_authority_ids.insert(handle);
        self.authorities.insert(
            handle,
            AuthorityState {
                facts,
                phase: AuthorityPhase::Registering,
                binding: None,
                capabilities: None,
            },
        );
        Ok((handle, queued.frame))
    }

    /// Re-registers preserved host facts after [`Self::restart`] or
    /// [`Self::reset`]. Service revisions always begin again at exactly one.
    pub fn register_detached_authority(
        &mut self,
        handle: HostAuthorityHandleId,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::OpaqueAuthorityRegistry)?;
        let now = self.now()?;
        let facts = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            if !matches!(&state.phase, AuthorityPhase::Detached) {
                return Err(HostError::AuthorityLifecycle);
            }
            validate_authority_facts(&state.facts, now)?;
            state.facts.clone()
        };
        let queued = self.enqueue(
            ServiceRequest::RegisterAuthority {
                authority_handle: handle,
                authority: facts,
            },
            RequestClass::Register { handle },
        )?;
        self.authorities
            .get_mut(&handle)
            .ok_or(HostError::AuthorityUnknown)?
            .phase = AuthorityPhase::Registering;
        Ok(queued.frame)
    }

    pub fn replace_authority(
        &mut self,
        handle: HostAuthorityHandleId,
        replacement: HostAuthorityFacts,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::OpaqueAuthorityRegistry)?;
        let now = self.now()?;
        validate_authority_facts(&replacement, now)?;
        let (revision, current) = {
            let state = self.active_authority(handle, now)?;
            let revision = active_revision(state)?;
            (revision, state.facts.clone())
        };
        validate_replacement(&current, &replacement)?;
        let queued = self.enqueue(
            ServiceRequest::ReplaceAuthority {
                authority_handle: handle,
                expected_authority_revision: revision,
                authority: replacement.clone(),
            },
            RequestClass::Replace {
                handle,
                expected_revision: revision,
                replacement: replacement.clone(),
            },
        )?;
        self.invalidate_authority_derived(handle);
        let state = self
            .authorities
            .get_mut(&handle)
            .ok_or(HostError::AuthorityUnknown)?;
        state.phase = AuthorityPhase::Replacing {
            revision,
            replacement,
        };
        Ok(queued.frame)
    }

    pub fn revoke_authority(
        &mut self,
        handle: HostAuthorityHandleId,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::OpaqueAuthorityRegistry)?;
        let now = self.now()?;
        let revision = {
            let state = self.active_authority(handle, now)?;
            active_revision(state)?
        };
        let queued = self.enqueue(
            ServiceRequest::RevokeAuthority {
                authority_handle: handle,
                expected_authority_revision: revision,
            },
            RequestClass::Revoke {
                handle,
                expected_revision: revision,
            },
        )?;
        self.invalidate_authority_derived(handle);
        self.authorities
            .get_mut(&handle)
            .ok_or(HostError::AuthorityUnknown)?
            .phase = AuthorityPhase::Revoking { revision };
        Ok(queued.frame)
    }

    pub fn request_provider_capabilities(
        &mut self,
        handle: HostAuthorityHandleId,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::OpaqueAuthorityRegistry)?;
        let now = self.now()?;
        let revision = active_revision(self.active_authority(handle, now)?)?;
        let queued = self.enqueue(
            ServiceRequest::ProviderCapabilities {
                authority_handle: handle,
                authority_revision: revision,
            },
            RequestClass::Capabilities { handle, revision },
        )?;
        Ok(queued.frame)
    }

    pub fn provider_request(
        &mut self,
        handle: HostAuthorityHandleId,
        method: String,
        params: Value,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::ProviderDispatch)?;
        let now = self.now()?;
        let revision = {
            let state = self.active_authority(handle, now)?;
            let revision = active_revision(state)?;
            let binding = state.binding.ok_or(HostError::StaleBinding)?;
            let capabilities = state.capabilities.as_ref().ok_or(HostError::StaleBinding)?;
            if binding.authority_handle != handle
                || binding.authority_revision != revision
                || capabilities.wallet_session_id != binding.wallet_session_id
                || capabilities.permission_generation != binding.permission_generation
            {
                return Err(HostError::StaleBinding);
            }
            if !capabilities.methods.contains(&method) {
                return Err(HostError::MethodUnavailable);
            }
            revision
        };
        validate_provider_request(&method, &params)?;
        if value_movement_method(&method) {
            self.require_capability(ServiceCapability::ValueMovement)?;
        }
        let nonce = self.random_provider_nonce(handle)?;
        let queued = self.enqueue(
            ServiceRequest::ProviderRequest {
                authority_handle: handle,
                authority_revision: revision,
                request_nonce: nonce,
                method: method.clone(),
                params,
            },
            RequestClass::Provider {
                handle,
                revision,
                method,
            },
        )?;
        self.remember_nonce(handle, nonce);
        Ok(queued.frame)
    }

    pub fn decide_approval(
        &mut self,
        approval_id: ProviderApprovalId,
        decision: ApprovalDecision,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::StructuredApprovals)?;
        let now = self.now()?;
        let (binding, origin, method) = {
            let approval = self
                .approvals
                .get(&approval_id)
                .ok_or(HostError::ApprovalMismatch)?;
            if approval.prompt.expires_at_unix_ms <= now {
                return Err(HostError::ApprovalExpired);
            }
            if !matches!(approval.phase, ApprovalPhase::Available) {
                return Err(HostError::ApprovalMismatch);
            }
            (
                approval.prompt.binding,
                approval.prompt.origin.clone(),
                approval.prompt.method.clone(),
            )
        };
        let handle = binding.authority_handle;
        let revision = binding.authority_revision;
        let state = self.active_authority(handle, now)?;
        if active_revision(state)? != revision
            || state.binding != Some(binding)
            || state.facts.origin != origin
        {
            return Err(HostError::ApprovalMismatch);
        }
        let queued = self.enqueue(
            ServiceRequest::ApprovalDecision {
                authority_handle: handle,
                authority_revision: revision,
                approval_id,
                decision,
            },
            RequestClass::Approval {
                handle,
                revision,
                approval_id,
                decision,
                method,
            },
        )?;
        self.approvals
            .get_mut(&approval_id)
            .ok_or(HostError::ApprovalMismatch)?
            .phase = ApprovalPhase::Deciding {
            request_id: queued.request_id,
        };
        Ok(queued.frame)
    }

    pub fn wallet_request(&mut self, request: WalletRequest) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::WalletOperations)?;
        let class = WalletResponseClass::for_request(&request);
        let queued = self.enqueue(
            ServiceRequest::Wallet { request },
            RequestClass::Wallet(class),
        )?;
        Ok(queued.frame)
    }

    /// Issues one request from the exact private non-value HNS read surface.
    ///
    /// This path deliberately remains separate from [`Self::wallet_request`]:
    /// existing trusted mobile/control callers retain the coarse ABI-v2 API,
    /// while a browser-native read adapter can require the frozen v1 marker
    /// and reject secrets, lifecycle controls, workflows, and other modules
    /// before allocating a request identifier.
    pub fn hns_read_request(&mut self, request: WalletRequest) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::WalletOperations)?;
        self.require_capability(ServiceCapability::HnsReadOperationsV1)?;
        let class = HnsReadResponseClass::for_request(&request)?;
        let queued = self.enqueue(
            ServiceRequest::Wallet { request },
            RequestClass::HnsRead(class),
        )?;
        Ok(queued.frame)
    }

    /// Issue the additive native-only wallet authority-context request.
    ///
    /// The returned service value remains evidence only. A product consumer
    /// must join it to an independently held namespace lease guard and re-read
    /// it around dependent use; this host does not manufacture that guard.
    pub fn hns_wallet_authority_context_request(
        &mut self,
        request: WalletAuthorityContextRequest,
    ) -> Result<HostFrame, HostError> {
        self.require_capability(ServiceCapability::WalletOperations)?;
        self.require_capability(ServiceCapability::HnsReadOperationsV1)?;
        self.require_capability(ServiceCapability::HnsWalletAuthorityContextV1)?;
        let class = HnsWalletAuthorityResponseClass::for_request(request)?;
        let queued = self.enqueue(
            ServiceRequest::WalletAuthority { request },
            RequestClass::HnsWalletAuthority(class),
        )?;
        Ok(queued.frame)
    }

    /// Accepts one already-decoded private service frame. Any validation
    /// failure poisons the channel and clears every service-derived value;
    /// callers must explicitly start a new generation.
    pub fn accept_service_frame(&mut self, frame: ServiceFrame) -> Result<HostOutput, HostError> {
        let result = self.accept_service_frame_inner(frame);
        if result.is_err() {
            self.poison_channel();
        }
        result
    }

    fn accept_service_frame_inner(&mut self, frame: ServiceFrame) -> Result<HostOutput, HostError> {
        match frame {
            ServiceFrame::Hello { hello } => self.accept_hello(hello),
            ServiceFrame::Response { envelope } => self.accept_response(envelope),
            ServiceFrame::Event { event } => self.accept_event(event),
        }
    }

    fn accept_hello(&mut self, hello: ServiceHello) -> Result<HostOutput, HostError> {
        if !matches!(&self.channel, ChannelState::AwaitingHello) {
            return Err(HostError::UnexpectedHello);
        }
        if hello.protocol_version != WALLET_ABI_VERSION
            || hello.platform != self.platform
            || hello.host_session_id != self.host_session_id
            || hello.restart_generation != self.restart_generation
            || hello.limits != ServiceLimits::default()
            || hello.capabilities.len() > MAX_PUBLIC_ITEMS
            || !hello
                .capabilities
                .contains(&ServiceCapability::CanonicalFraming)
            || !hello
                .capabilities
                .contains(&ServiceCapability::RestartIsolation)
            || !hello
                .capabilities
                .contains(&ServiceCapability::OpaqueAuthorityRegistry)
            || (hello
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
                && !hello
                    .capabilities
                    .contains(&ServiceCapability::ProviderDispatch))
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
            return Err(HostError::HelloMismatch);
        }
        let negotiated = NegotiatedSession {
            protocol_version: hello.protocol_version,
            platform: hello.platform,
            host_session_id: hello.host_session_id,
            service_session_id: hello.service_session_id,
            restart_generation: hello.restart_generation,
            capabilities: hello.capabilities.clone(),
            limits: hello.limits.clone(),
        };
        self.channel = ChannelState::Ready(SessionState {
            service_session_id: hello.service_session_id,
            capabilities: hello.capabilities,
            next_host_sequence: 1,
            next_service_sequence: 1,
        });
        Ok(HostOutput::Negotiated(negotiated))
    }

    fn accept_response(
        &mut self,
        envelope: SessionEnvelope<ServiceResponse>,
    ) -> Result<HostOutput, HostError> {
        let next_sequence = self.validate_service_header(
            envelope.protocol_version,
            envelope.host_session_id,
            envelope.service_session_id,
            envelope.restart_generation,
            envelope.channel_sequence,
        )?;
        let class = self
            .pending
            .get(&envelope.request_id)
            .cloned()
            .ok_or(HostError::PendingRequestMismatch)?;
        self.validate_response_authority_time(&class)?;
        self.apply_response(&class, &envelope.body)?;
        self.pending
            .remove(&envelope.request_id)
            .ok_or(HostError::PendingRequestMismatch)?;
        if self.aged_out_request_ids.remove(&envelope.request_id) {
            self.recent_request_ids.remove(&envelope.request_id);
        }
        self.set_next_service_sequence(next_sequence)?;
        Ok(HostOutput::Response(AcceptedResponse {
            request_id: envelope.request_id,
            response: envelope.body,
        }))
    }

    fn accept_event(&mut self, event: ProviderEventEnvelope) -> Result<HostOutput, HostError> {
        self.require_capability(ServiceCapability::TypedEvents)?;
        let next_sequence = self.validate_service_header(
            event.protocol_version,
            event.host_session_id,
            event.service_session_id,
            event.restart_generation,
            event.channel_sequence,
        )?;
        let now = self.now()?;
        self.validate_and_apply_event(&event, now)?;
        self.set_next_service_sequence(next_sequence)?;
        Ok(HostOutput::Event(AcceptedEvent {
            binding: event.binding,
            event_sequence: event.event_sequence,
            payload: event.payload,
        }))
    }

    fn apply_response(
        &mut self,
        class: &RequestClass,
        response: &ServiceResponse,
    ) -> Result<(), HostError> {
        if let ServiceResponse::Failure { failure } = response {
            if matches!(
                failure.code,
                ServiceErrorCode::InvalidFrame
                    | ServiceErrorCode::VersionMismatch
                    | ServiceErrorCode::SessionMismatch
                    | ServiceErrorCode::SequenceMismatch
                    | ServiceErrorCode::Replay
                    | ServiceErrorCode::UnsupportedCapability
            ) {
                return Err(HostError::ReportedProtocolFailure);
            }
            self.apply_failure(class, failure.code);
            return Ok(());
        }
        match (class, response) {
            (
                RequestClass::Register { handle },
                ServiceResponse::AuthorityRegistered {
                    authority_handle,
                    authority_revision,
                },
            ) if handle == authority_handle && *authority_revision == 1 => {
                let state = self
                    .authorities
                    .get_mut(handle)
                    .ok_or(HostError::AuthorityUnknown)?;
                if !matches!(&state.phase, AuthorityPhase::Registering) {
                    return Err(HostError::AuthorityLifecycle);
                }
                state.phase = AuthorityPhase::Active { revision: 1 };
                Ok(())
            }
            (
                RequestClass::Replace {
                    handle,
                    expected_revision,
                    replacement,
                },
                ServiceResponse::AuthorityReplaced {
                    authority_handle,
                    authority_revision,
                },
            ) if handle == authority_handle
                && expected_revision.checked_add(1) == Some(*authority_revision) =>
            {
                let state = self
                    .authorities
                    .get_mut(handle)
                    .ok_or(HostError::AuthorityUnknown)?;
                match &state.phase {
                    AuthorityPhase::Replacing {
                        revision,
                        replacement: pending_replacement,
                    } if revision == expected_revision && pending_replacement == replacement => {}
                    _ => return Err(HostError::AuthorityLifecycle),
                }
                state.facts = replacement.clone();
                state.phase = AuthorityPhase::Active {
                    revision: *authority_revision,
                };
                Ok(())
            }
            (
                RequestClass::Revoke {
                    handle,
                    expected_revision,
                },
                ServiceResponse::AuthorityRevoked { authority_handle },
            ) if handle == authority_handle => {
                let state = self
                    .authorities
                    .get(handle)
                    .ok_or(HostError::AuthorityUnknown)?;
                if !matches!(
                    &state.phase,
                    AuthorityPhase::Revoking { revision } if *revision == *expected_revision
                ) {
                    return Err(HostError::AuthorityLifecycle);
                }
                self.invalidate_authority_derived(*handle);
                self.authorities.remove(handle);
                Ok(())
            }
            (
                RequestClass::Capabilities { handle, revision },
                ServiceResponse::ProviderCapabilities {
                    binding,
                    capabilities,
                },
            ) => self.install_capabilities(*handle, *revision, *binding, capabilities.clone()),
            (
                RequestClass::Provider {
                    handle,
                    revision,
                    method,
                },
                ServiceResponse::ProviderResult { binding, .. },
            ) if !approval_required_method(method) => {
                self.apply_provider_binding(*handle, *revision, method, *binding)
            }
            (
                RequestClass::Provider {
                    handle,
                    revision,
                    method,
                },
                ServiceResponse::ApprovalRequired { approval },
            ) if approval_required_method(method) => {
                self.require_capability(ServiceCapability::StructuredApprovals)?;
                self.install_approval(*handle, *revision, method, approval.clone())
            }
            (
                RequestClass::Approval {
                    handle,
                    revision,
                    approval_id,
                    decision: ApprovalDecision::Approve,
                    method,
                },
                ServiceResponse::ProviderResult { binding, .. },
            ) => {
                self.validate_deciding_approval(*approval_id)?;
                self.apply_provider_binding(*handle, *revision, method, *binding)?;
                self.approvals.remove(approval_id);
                Ok(())
            }
            (
                RequestClass::Approval {
                    approval_id,
                    decision: ApprovalDecision::Reject,
                    ..
                },
                ServiceResponse::ApprovalRejected {
                    approval_id: response_id,
                },
            ) if approval_id == response_id => {
                self.validate_deciding_approval(*approval_id)?;
                self.approvals.remove(approval_id);
                Ok(())
            }
            (RequestClass::Wallet(class), ServiceResponse::Wallet { response })
                if class.matches(response) =>
            {
                if matches!(
                    response,
                    WalletResponse::WalletCreated { .. }
                        | WalletResponse::WalletRestored { .. }
                        | WalletResponse::Locked
                        | WalletResponse::Unlocked
                ) {
                    self.invalidate_all_provider_state();
                }
                Ok(())
            }
            (RequestClass::HnsRead(class), ServiceResponse::Wallet { response })
                if class.matches(response) =>
            {
                Ok(())
            }
            (
                RequestClass::HnsWalletAuthority(class),
                ServiceResponse::WalletAuthority { context },
            ) if class.matches(context) => Ok(()),
            _ => Err(HostError::ResponseClassMismatch),
        }
    }

    fn apply_failure(&mut self, class: &RequestClass, code: ServiceErrorCode) {
        match class {
            RequestClass::Register { handle } => {
                self.invalidate_authority_derived(*handle);
                self.authorities.remove(handle);
            }
            RequestClass::Replace {
                handle,
                expected_revision,
                ..
            } => {
                self.invalidate_authority_derived(*handle);
                if let Some(state) = self.authorities.get_mut(handle) {
                    state.phase = AuthorityPhase::Stale {
                        revision: *expected_revision,
                    };
                }
            }
            RequestClass::Revoke {
                handle,
                expected_revision,
            } => {
                self.invalidate_authority_derived(*handle);
                if let Some(state) = self.authorities.get_mut(handle) {
                    state.phase = AuthorityPhase::Stale {
                        revision: *expected_revision,
                    };
                }
            }
            RequestClass::Approval { approval_id, .. } => {
                self.approvals.remove(approval_id);
            }
            _ => {}
        }
        if matches!(
            code,
            ServiceErrorCode::AuthorityUnknown | ServiceErrorCode::AuthorityStale
        ) && let Some(handle) = class.authority()
        {
            self.mark_authority_stale(handle);
        }
    }

    fn install_capabilities(
        &mut self,
        handle: HostAuthorityHandleId,
        revision: u64,
        binding: ProviderBinding,
        capabilities: ProviderCapabilitySnapshot,
    ) -> Result<(), HostError> {
        let methods_valid = capabilities.provider_schema_version == PROVIDER_SCHEMA_VERSION
            && capabilities.approval_schema_version == APPROVAL_SCHEMA_VERSION
            && capabilities.wallet_session_id == binding.wallet_session_id
            && capabilities.permission_generation == binding.permission_generation
            && capabilities.methods.len() <= MAX_PROVIDER_METHODS
            && capabilities.methods.iter().all(|method| {
                !method.is_empty()
                    && method.len() <= MAX_METHOD_BYTES
                    && method.is_ascii()
                    && PROVIDER_METHOD_WIRE_NAMES.contains(&method.as_str())
            });
        if binding.authority_handle != handle
            || binding.authority_revision != revision
            || revision == 0
            || !methods_valid
        {
            return Err(HostError::InvalidCapabilitySnapshot);
        }
        let dispatch = self.has_capability(ServiceCapability::ProviderDispatch)?;
        let value = self.has_capability(ServiceCapability::ValueMovement)?;
        let approvals = self.has_capability(ServiceCapability::StructuredApprovals)?;
        let wallet_operations = self.has_capability(ServiceCapability::WalletOperations)?;
        if (!dispatch && !capabilities.methods.is_empty())
            || (!approvals
                && capabilities
                    .methods
                    .iter()
                    .any(|method| approval_required_method(method)))
            || (!wallet_operations && capabilities.methods.contains("wallet_lock"))
            || (!value
                && capabilities
                    .methods
                    .iter()
                    .any(|method| value_movement_method(method)))
        {
            return Err(HostError::InvalidCapabilitySnapshot);
        }
        let current = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            if active_revision(state)? != revision {
                return Err(HostError::StaleBinding);
            }
            state.binding
        };
        if let Some(current) = current {
            if current.wallet_session_id != binding.wallet_session_id {
                if current.permission_generation != binding.permission_generation {
                    return Err(HostError::StaleBinding);
                }
                self.invalidate_all_provider_state();
            } else if binding.permission_generation < current.permission_generation {
                return Err(HostError::StaleBinding);
            } else if binding.permission_generation > current.permission_generation {
                self.invalidate_permission_scope(handle)?;
            }
        }
        let state = self
            .authorities
            .get_mut(&handle)
            .ok_or(HostError::AuthorityUnknown)?;
        if active_revision(state)? != revision {
            return Err(HostError::StaleBinding);
        }
        state.binding = Some(binding);
        state.capabilities = Some(capabilities);
        Ok(())
    }

    fn install_approval(
        &mut self,
        handle: HostAuthorityHandleId,
        revision: u64,
        method: &str,
        approval: ApprovalPrompt,
    ) -> Result<(), HostError> {
        let now = self.now()?;
        self.approvals
            .retain(|_, pending| pending.prompt.expires_at_unix_ms > now);
        if self.approvals.len() >= MAX_PENDING_APPROVALS {
            return Err(HostError::ApprovalCapacity);
        }
        if self.issued_approval_ids.len() >= MAX_ISSUED_APPROVAL_IDS {
            return Err(HostError::ApprovalIdentityCapacity);
        }
        if self.issued_approval_ids.contains(&approval.approval_id) {
            return Err(HostError::ApprovalMismatch);
        }
        approval
            .validate(approval.summary.approval_kind(), now)
            .map_err(|_| HostError::ApprovalMismatch)?;
        let state = self
            .authorities
            .get(&handle)
            .ok_or(HostError::AuthorityUnknown)?;
        if active_revision(state)? != revision
            || state.binding != Some(approval.binding)
            || approval.binding.authority_handle != handle
            || approval.binding.authority_revision != revision
            || approval.origin != state.facts.origin
            || approval.method != method
        {
            return Err(HostError::ApprovalMismatch);
        }
        let approval_id = approval.approval_id;
        self.approvals.insert(
            approval_id,
            HostApproval {
                prompt: approval,
                phase: ApprovalPhase::Available,
            },
        );
        self.issued_approval_ids.insert(approval_id);
        Ok(())
    }

    fn validate_deciding_approval(
        &mut self,
        approval_id: ProviderApprovalId,
    ) -> Result<(), HostError> {
        let now = self.now()?;
        let approval = self
            .approvals
            .get(&approval_id)
            .ok_or(HostError::ApprovalMismatch)?;
        if approval.prompt.expires_at_unix_ms <= now {
            return Err(HostError::ApprovalExpired);
        }
        let ApprovalPhase::Deciding { request_id } = approval.phase else {
            return Err(HostError::ApprovalMismatch);
        };
        if !self.pending.contains_key(&request_id) {
            return Err(HostError::ApprovalMismatch);
        }
        Ok(())
    }

    fn apply_provider_binding(
        &mut self,
        handle: HostAuthorityHandleId,
        revision: u64,
        method: &str,
        binding: ProviderBinding,
    ) -> Result<(), HostError> {
        if binding.authority_handle != handle || binding.authority_revision != revision {
            return Err(HostError::StaleBinding);
        }
        let current = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            if active_revision(state)? != revision {
                return Err(HostError::StaleBinding);
            }
            state.binding.ok_or(HostError::StaleBinding)?
        };
        if permission_mutating_method(method) {
            if binding.wallet_session_id != current.wallet_session_id
                || current.permission_generation.checked_add(1)
                    != Some(binding.permission_generation)
            {
                return Err(HostError::StaleBinding);
            }
            self.invalidate_permission_scope(handle)?;
        } else if method == "wallet_lock" {
            if binding.wallet_session_id == current.wallet_session_id
                || binding.permission_generation != current.permission_generation
            {
                return Err(HostError::StaleBinding);
            }
            self.invalidate_all_provider_state();
        } else if binding != current {
            return Err(HostError::StaleBinding);
        } else {
            if capability_mutating_method(method) {
                self.invalidate_all_capability_snapshots();
            }
            return Ok(());
        }
        let state = self
            .authorities
            .get_mut(&handle)
            .ok_or(HostError::AuthorityUnknown)?;
        if active_revision(state)? != revision {
            return Err(HostError::StaleBinding);
        }
        state.binding = Some(binding);
        state.capabilities = None;
        Ok(())
    }

    fn validate_and_apply_event(
        &mut self,
        event: &ProviderEventEnvelope,
        now: u64,
    ) -> Result<(), HostError> {
        let handle = event.binding.authority_handle;
        let (revision, current, expired) = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            (
                active_revision(state)?,
                state.binding.ok_or(HostError::EventBindingMismatch)?,
                state.facts.valid_until_unix_ms <= now,
            )
        };
        if event.binding.authority_revision != revision {
            return Err(HostError::EventBindingMismatch);
        }
        if expired
            && !matches!(
                &event.payload,
                ProviderEventPayload::Disconnect {
                    reason: DisconnectReason::AuthorityExpired
                }
            )
        {
            return Err(HostError::AuthorityExpired);
        }

        let binding_changed = event.binding != current;
        if binding_changed {
            let permission_advanced = event.binding.wallet_session_id == current.wallet_session_id
                && current.permission_generation.checked_add(1)
                    == Some(event.binding.permission_generation)
                && matches!(
                    &event.payload,
                    ProviderEventPayload::Connect { .. }
                        | ProviderEventPayload::PermissionsChanged { .. }
                        | ProviderEventPayload::Disconnect {
                            reason: DisconnectReason::AuthorityRevoked
                        }
                );
            let wallet_rotated = event.binding.wallet_session_id != current.wallet_session_id
                && event.binding.permission_generation == current.permission_generation
                && matches!(
                    &event.payload,
                    ProviderEventPayload::WalletLocked
                        | ProviderEventPayload::Disconnect {
                            reason: DisconnectReason::WalletSessionChanged
                        }
                );
            if !permission_advanced && !wallet_rotated {
                return Err(HostError::EventBindingMismatch);
            }
            if wallet_rotated {
                self.invalidate_all_provider_state();
            } else {
                self.invalidate_permission_scope(handle)?;
            }
            let state = self
                .authorities
                .get_mut(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            if active_revision(state)? != revision {
                return Err(HostError::EventBindingMismatch);
            }
            state.binding = Some(event.binding);
            state.capabilities = None;
        }

        match &event.payload {
            ProviderEventPayload::Connect {
                permission_generation,
            }
            | ProviderEventPayload::PermissionsChanged {
                permission_generation,
                ..
            } if *permission_generation != event.binding.permission_generation => {
                return Err(HostError::EventBindingMismatch);
            }
            ProviderEventPayload::Disconnect {
                reason: DisconnectReason::ServiceRestarted,
            } => return Err(HostError::SessionMismatch),
            _ if event.binding.permission_generation == 0
                && !matches!(&event.payload, ProviderEventPayload::Disconnect { .. }) =>
            {
                return Err(HostError::EventBindingMismatch);
            }
            _ => {}
        }

        let key = EventCursorKey::from_binding(event.binding);
        let expected = match self.event_cursors.get(&key) {
            Some(sequence) => sequence
                .checked_add(1)
                .ok_or(HostError::SequenceExhausted)?,
            None => 1,
        };
        if event.event_sequence != expected {
            return Err(HostError::EventReplay);
        }
        if matches!(
            &event.payload,
            ProviderEventPayload::PermissionsChanged { .. }
        ) {
            self.invalidate_permission_scope(handle)?;
            let state = self
                .authorities
                .get_mut(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            if active_revision(state)? != revision {
                return Err(HostError::EventBindingMismatch);
            }
            state.binding = Some(event.binding);
            state.capabilities = None;
        }
        self.event_cursors.insert(key, event.event_sequence);

        match &event.payload {
            ProviderEventPayload::Disconnect {
                reason:
                    DisconnectReason::AuthorityRevoked
                    | DisconnectReason::AuthorityExpired
                    | DisconnectReason::NavigationChanged
                    | DisconnectReason::PolicyChanged,
            } => self.mark_authority_stale(handle),
            ProviderEventPayload::Disconnect {
                reason: DisconnectReason::WalletSessionChanged,
            } => self.invalidate_all_provider_state(),
            ProviderEventPayload::WalletLocked => self.invalidate_all_provider_state(),
            ProviderEventPayload::ModulesChanged { .. } => {
                self.invalidate_all_capability_snapshots();
            }
            _ => {}
        }
        Ok(())
    }

    fn enqueue(
        &mut self,
        body: ServiceRequest,
        class: RequestClass,
    ) -> Result<QueuedRequest, HostError> {
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(HostError::PendingRequestCapacity);
        }
        let request_id = self.random_request_id()?;
        let (service_session_id, sequence, next_sequence) = {
            let ChannelState::Ready(session) = &self.channel else {
                return Err(match &self.channel {
                    ChannelState::Failed => HostError::ChannelFailed,
                    _ => HostError::HandshakeRequired,
                });
            };
            let next = session
                .next_host_sequence
                .checked_add(1)
                .ok_or(HostError::SequenceExhausted)?;
            (session.service_session_id, session.next_host_sequence, next)
        };
        self.pending.insert(request_id, class);
        self.remember_request_id(request_id);
        let ChannelState::Ready(session) = &mut self.channel else {
            return Err(HostError::HandshakeRequired);
        };
        session.next_host_sequence = next_sequence;
        Ok(QueuedRequest {
            request_id,
            frame: HostFrame::Request {
                envelope: SessionEnvelope {
                    protocol_version: WALLET_ABI_VERSION,
                    host_session_id: self.host_session_id,
                    service_session_id,
                    restart_generation: self.restart_generation,
                    channel_sequence: sequence,
                    request_id,
                    body,
                },
            },
        })
    }

    fn validate_service_header(
        &self,
        protocol_version: u16,
        host_session_id: HostSessionId,
        service_session_id: WalletServiceSessionId,
        restart_generation: u64,
        channel_sequence: u64,
    ) -> Result<u64, HostError> {
        let ChannelState::Ready(session) = &self.channel else {
            return Err(match &self.channel {
                ChannelState::Failed => HostError::ChannelFailed,
                _ => HostError::HandshakeRequired,
            });
        };
        if protocol_version != WALLET_ABI_VERSION
            || host_session_id != self.host_session_id
            || service_session_id != session.service_session_id
            || restart_generation != self.restart_generation
        {
            return Err(HostError::SessionMismatch);
        }
        if channel_sequence != session.next_service_sequence {
            return Err(HostError::SequenceMismatch {
                expected: session.next_service_sequence,
                received: channel_sequence,
            });
        }
        channel_sequence
            .checked_add(1)
            .ok_or(HostError::SequenceExhausted)
    }

    fn set_next_service_sequence(&mut self, next: u64) -> Result<(), HostError> {
        let ChannelState::Ready(session) = &mut self.channel else {
            return Err(HostError::HandshakeRequired);
        };
        session.next_service_sequence = next;
        Ok(())
    }

    fn now(&mut self) -> Result<u64, HostError> {
        let now = self.clock.now_unix_ms()?;
        if self.last_now_unix_ms.is_some_and(|last| now < last) {
            self.poison_channel();
            return Err(HostError::ClockRollback);
        }
        self.last_now_unix_ms = Some(now);
        Ok(now)
    }

    fn validate_response_authority_time(&mut self, class: &RequestClass) -> Result<(), HostError> {
        let Some(handle) = class.authority() else {
            return Ok(());
        };
        let now = self.now()?;
        let expired = self
            .authorities
            .get(&handle)
            .ok_or(HostError::AuthorityUnknown)?
            .facts
            .valid_until_unix_ms
            <= now;
        if expired {
            self.mark_authority_stale(handle);
            return Err(HostError::AuthorityExpired);
        }
        Ok(())
    }

    fn active_authority(
        &mut self,
        handle: HostAuthorityHandleId,
        now: u64,
    ) -> Result<&AuthorityState, HostError> {
        let expired = self
            .authorities
            .get(&handle)
            .ok_or(HostError::AuthorityUnknown)?
            .facts
            .valid_until_unix_ms
            <= now;
        if expired {
            self.mark_authority_stale(handle);
            return Err(HostError::AuthorityExpired);
        }
        let state = self
            .authorities
            .get(&handle)
            .ok_or(HostError::AuthorityUnknown)?;
        if !matches!(&state.phase, AuthorityPhase::Active { .. }) {
            return Err(HostError::AuthorityLifecycle);
        }
        Ok(state)
    }

    fn require_capability(&self, capability: ServiceCapability) -> Result<(), HostError> {
        if self.has_capability(capability)? {
            Ok(())
        } else {
            Err(HostError::CapabilityUnavailable)
        }
    }

    fn has_capability(&self, capability: ServiceCapability) -> Result<bool, HostError> {
        match &self.channel {
            ChannelState::Ready(session) => Ok(session.capabilities.contains(&capability)),
            ChannelState::AwaitingHello => Err(HostError::HandshakeRequired),
            ChannelState::Failed => Err(HostError::ChannelFailed),
        }
    }

    fn random_authority_handle(&mut self) -> Result<HostAuthorityHandleId, HostError> {
        for _ in 0..RANDOM_ATTEMPTS {
            let bytes = random_nonzero::<32, _>(&mut self.entropy)?;
            let handle = HostAuthorityHandleId::from_bytes(bytes)
                .map_err(|_| HostError::RandomIdentityUnavailable)?;
            if !self.issued_authority_ids.contains(&handle) {
                return Ok(handle);
            }
        }
        Err(HostError::RandomIdentityUnavailable)
    }

    fn random_request_id(&mut self) -> Result<ProviderRequestId, HostError> {
        for _ in 0..RANDOM_ATTEMPTS {
            let bytes = random_nonzero::<16, _>(&mut self.entropy)?;
            let request_id = ProviderRequestId::from_bytes(bytes)
                .map_err(|_| HostError::RandomIdentityUnavailable)?;
            if !self.recent_request_ids.contains(&request_id)
                && !self.pending.contains_key(&request_id)
            {
                return Ok(request_id);
            }
        }
        Err(HostError::RandomIdentityUnavailable)
    }

    fn random_provider_nonce(&mut self, handle: HostAuthorityHandleId) -> Result<u64, HostError> {
        for _ in 0..RANDOM_ATTEMPTS {
            let bytes = random_nonzero::<8, _>(&mut self.entropy)?;
            let nonce = u64::from_be_bytes(bytes);
            if nonce != 0 && !self.recent_nonces.contains(&(handle, nonce)) {
                return Ok(nonce);
            }
        }
        Err(HostError::RandomIdentityUnavailable)
    }

    fn remember_request_id(&mut self, request_id: ProviderRequestId) {
        self.recent_request_ids.insert(request_id);
        self.request_id_order.push_back(request_id);
        if self.request_id_order.len() > MAX_RECENT_REQUEST_IDS
            && let Some(expired) = self.request_id_order.pop_front()
        {
            if self.pending.contains_key(&expired) {
                self.aged_out_request_ids.insert(expired);
            } else {
                self.recent_request_ids.remove(&expired);
            }
        }
    }

    fn remember_nonce(&mut self, handle: HostAuthorityHandleId, nonce: u64) {
        self.recent_nonces.insert((handle, nonce));
        self.nonce_order.push_back((handle, nonce));
        if self.nonce_order.len() > MAX_RECENT_PROVIDER_NONCES
            && let Some(expired) = self.nonce_order.pop_front()
        {
            self.recent_nonces.remove(&expired);
        }
    }

    fn invalidate_authority_derived(&mut self, handle: HostAuthorityHandleId) {
        if let Some(state) = self.authorities.get_mut(&handle) {
            state.binding = None;
            state.capabilities = None;
        }
        self.approvals
            .retain(|_, approval| approval.prompt.binding.authority_handle != handle);
        self.event_cursors
            .retain(|key, _| key.authority_handle != handle);
    }

    fn invalidate_permission_scope(
        &mut self,
        handle: HostAuthorityHandleId,
    ) -> Result<(), HostError> {
        let (origin, namespace) = {
            let state = self
                .authorities
                .get(&handle)
                .ok_or(HostError::AuthorityUnknown)?;
            (state.facts.origin.clone(), state.facts.namespace)
        };
        let affected = self
            .authorities
            .iter()
            .filter_map(|(candidate, state)| {
                (state.facts.origin == origin && state.facts.namespace == namespace)
                    .then_some(*candidate)
            })
            .collect::<Vec<_>>();
        for affected_handle in affected {
            self.invalidate_authority_derived(affected_handle);
        }
        // The checked-in service restarts its global event sequence domain on
        // every permission grant or revocation. Mirror that exact reset scope.
        self.event_cursors.clear();
        Ok(())
    }

    fn invalidate_all_capability_snapshots(&mut self) {
        for state in self.authorities.values_mut() {
            state.capabilities = None;
        }
    }

    fn invalidate_all_provider_state(&mut self) {
        for state in self.authorities.values_mut() {
            state.binding = None;
            state.capabilities = None;
        }
        self.approvals.clear();
        self.event_cursors.clear();
    }

    fn mark_authority_stale(&mut self, handle: HostAuthorityHandleId) {
        self.invalidate_authority_derived(handle);
        if let Some(state) = self.authorities.get_mut(&handle) {
            let revision = match &state.phase {
                AuthorityPhase::Active { revision }
                | AuthorityPhase::Replacing { revision, .. }
                | AuthorityPhase::Revoking { revision }
                | AuthorityPhase::Stale { revision } => Some(*revision),
                AuthorityPhase::Detached | AuthorityPhase::Registering => None,
            };
            if let Some(revision) = revision {
                state.phase = AuthorityPhase::Stale { revision };
            }
        }
    }

    fn invalidate_service_state(&mut self) {
        let mut remove = Vec::new();
        for (handle, state) in &mut self.authorities {
            match state.phase.clone() {
                AuthorityPhase::Replacing { replacement, .. } => {
                    state.facts = replacement;
                    state.phase = AuthorityPhase::Detached;
                }
                AuthorityPhase::Revoking { .. } => remove.push(*handle),
                _ => state.phase = AuthorityPhase::Detached,
            }
            state.binding = None;
            state.capabilities = None;
        }
        for handle in remove {
            self.authorities.remove(&handle);
        }
        for request_id in &self.aged_out_request_ids {
            self.recent_request_ids.remove(request_id);
        }
        self.aged_out_request_ids.clear();
        self.pending.clear();
        self.approvals.clear();
        self.event_cursors.clear();
    }

    fn poison_channel(&mut self) {
        self.invalidate_service_state();
        self.channel = ChannelState::Failed;
    }
}

fn lifecycle(phase: &AuthorityPhase) -> AuthorityLifecycle {
    match phase {
        AuthorityPhase::Detached => AuthorityLifecycle::Detached,
        AuthorityPhase::Registering => AuthorityLifecycle::Registering,
        AuthorityPhase::Active { revision } => AuthorityLifecycle::Active {
            revision: *revision,
        },
        AuthorityPhase::Replacing { revision, .. } => AuthorityLifecycle::Replacing {
            revision: *revision,
        },
        AuthorityPhase::Revoking { revision } => AuthorityLifecycle::Revoking {
            revision: *revision,
        },
        AuthorityPhase::Stale { revision } => AuthorityLifecycle::Stale {
            revision: *revision,
        },
    }
}

fn active_revision(state: &AuthorityState) -> Result<u64, HostError> {
    match &state.phase {
        AuthorityPhase::Active { revision } if *revision != 0 => Ok(*revision),
        _ => Err(HostError::AuthorityLifecycle),
    }
}

fn validate_authority_facts(facts: &HostAuthorityFacts, now: u64) -> Result<(), HostError> {
    if facts.origin.is_empty()
        || facts.origin.len() > MAX_ORIGIN_BYTES
        || !facts.origin.is_ascii()
        || facts.runtime_generation == 0
        || facts.policy_generation == 0
        || facts.navigation_generation == 0
        || facts.valid_until_unix_ms <= now
    {
        return Err(HostError::InvalidAuthorityFacts);
    }
    Ok(())
}

fn validate_replacement(
    current: &HostAuthorityFacts,
    replacement: &HostAuthorityFacts,
) -> Result<(), HostError> {
    if replacement.origin != current.origin
        || replacement.namespace != current.namespace
        || replacement.runtime_session_id != current.runtime_session_id
        || replacement.runtime_generation < current.runtime_generation
        || replacement.policy_generation < current.policy_generation
        || replacement.navigation_generation < current.navigation_generation
        || replacement.valid_until_unix_ms < current.valid_until_unix_ms
    {
        return Err(HostError::InvalidAuthorityFacts);
    }
    Ok(())
}

fn validate_provider_request(method: &str, params: &Value) -> Result<(), HostError> {
    if method.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || !method.is_ascii()
        || !PROVIDER_METHOD_WIRE_NAMES.contains(&method)
    {
        return Err(HostError::InvalidProviderRequest);
    }
    let encoded = serde_json::to_vec(&serde_json::json!({
        "method": method,
        "params": params,
    }))
    .map_err(|_| HostError::Encoding)?;
    if encoded.len() > MAX_PROVIDER_REQUEST_BYTES {
        return Err(HostError::InvalidProviderRequest);
    }
    Ok(())
}

fn permission_mutating_method(method: &str) -> bool {
    matches!(
        method,
        "wallet_requestPermissions" | "wallet_revokePermissions" | "hns_requestAccounts"
    )
}

fn capability_mutating_method(method: &str) -> bool {
    matches!(method, "wallet_enableModule" | "wallet_disableModule")
}

fn approval_required_method(method: &str) -> bool {
    matches!(
        method,
        "wallet_enableModule"
            | "wallet_disableModule"
            | "wallet_requestPermissions"
            | "hns_requestAccounts"
            | "hns_send"
            | "asset_send"
            | "hns_transferName"
            | "hns_finalizeName"
            | "hns_signTypedMessage"
            | "nameMarket_createFixedPriceOffer"
            | "nameMarket_cancelOffer"
            | "nameMarket_acceptOffer"
            | "nameMarket_finalizePurchase"
            | "nameMarket_recoverName"
            | "swap_publishMarketIntent"
            | "swap_cancelMarketIntent"
            | "swap_requestMatch"
            | "swap_acceptFill"
            | "swap_redeem"
            | "swap_refund"
    )
}

fn value_movement_method(method: &str) -> bool {
    matches!(
        method,
        "hns_send"
            | "asset_send"
            | "hns_transferName"
            | "hns_finalizeName"
            | "nameMarket_createFixedPriceOffer"
            | "nameMarket_cancelOffer"
            | "nameMarket_acceptOffer"
            | "nameMarket_finalizePurchase"
            | "nameMarket_recoverName"
            | "swap_publishMarketIntent"
            | "swap_cancelMarketIntent"
            | "swap_requestMatch"
            | "swap_acceptFill"
            | "swap_redeem"
            | "swap_refund"
    )
}

fn random_host_session<E: Entropy>(entropy: &mut E) -> Result<HostSessionId, HostError> {
    let bytes = random_nonzero::<32, _>(entropy)?;
    HostSessionId::from_bytes(bytes).map_err(|_| HostError::RandomIdentityUnavailable)
}

fn random_nonzero<const N: usize, E: Entropy>(entropy: &mut E) -> Result<[u8; N], HostError> {
    for _ in 0..RANDOM_ATTEMPTS {
        let mut bytes = [0_u8; N];
        entropy.fill_bytes(&mut bytes)?;
        if bytes != [0_u8; N] {
            return Ok(bytes);
        }
    }
    Err(HostError::RandomIdentityUnavailable)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use hns_wallet_ffi::{
        AccountSummary, ApprovalSummary, HnsNameDisclosure, ProviderNamespace, SecretString,
        WalletHandshakeNetwork, WalletRuntimeStatus,
    };
    use hns_wallet_types::{
        Amount, BaseUnits, BrowserRuntimeSessionId, LocalTransactionStatus, PermissionCapability,
        ProviderAuthorityFingerprint, ReceiveTarget, SignedBaseUnits, SyncPhase, SyncStatus,
        TransactionHash, TransactionSummary, WalletId, WalletSessionId, WorkflowId,
    };

    use super::*;

    #[derive(Clone)]
    struct TestClock(Rc<Cell<u64>>);

    impl Clock for TestClock {
        fn now_unix_ms(&self) -> Result<u64, ClockError> {
            Ok(self.0.get())
        }
    }

    struct TestEntropy {
        next: u8,
    }

    impl Entropy for TestEntropy {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.next);
            self.next = self.next.checked_add(1).unwrap_or(1);
            Ok(())
        }
    }

    type TestHost = WalletHost<TestClock, TestEntropy>;

    fn new_host() -> (TestHost, Rc<Cell<u64>>) {
        let now = Rc::new(Cell::new(1_000));
        let host = WalletHost::new(
            HostPlatform::ChromiumNativeHost,
            1,
            TestClock(now.clone()),
            TestEntropy { next: 1 },
        )
        .expect("host");
        (host, now)
    }

    fn service_session() -> WalletServiceSessionId {
        WalletServiceSessionId::from_bytes([90; 32]).expect("service session")
    }

    fn wallet_session() -> WalletSessionId {
        WalletSessionId::from_bytes([91; 32]).expect("wallet session")
    }

    fn handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes([92; 32]).expect("authority handle")
    }

    fn approval_id() -> ProviderApprovalId {
        ProviderApprovalId::from_bytes([93; 16]).expect("approval id")
    }

    fn required_capabilities() -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::CanonicalFraming,
            ServiceCapability::RestartIsolation,
            ServiceCapability::OpaqueAuthorityRegistry,
        ])
    }

    fn negotiate(host: &mut TestHost, capabilities: BTreeSet<ServiceCapability>) {
        let output = host
            .accept_service_frame(ServiceFrame::Hello {
                hello: ServiceHello {
                    protocol_version: WALLET_ABI_VERSION,
                    platform: host.platform(),
                    host_session_id: host.host_session_id(),
                    service_session_id: service_session(),
                    restart_generation: host.restart_generation(),
                    capabilities,
                    limits: ServiceLimits::default(),
                },
            })
            .expect("negotiate");
        assert!(matches!(output, HostOutput::Negotiated(_)));
    }

    fn facts(valid_until_unix_ms: u64) -> HostAuthorityFacts {
        HostAuthorityFacts {
            origin: "https://wallet.example".to_owned(),
            namespace: ProviderNamespace::Hns,
            runtime_session_id: BrowserRuntimeSessionId::from_bytes([94; 16])
                .expect("runtime session"),
            runtime_generation: 1,
            policy_generation: 1,
            navigation_generation: 1,
            decision_fingerprint: ProviderAuthorityFingerprint::from_bytes([95; 32])
                .expect("authority fingerprint"),
            valid_until_unix_ms,
        }
    }

    fn binding() -> ProviderBinding {
        ProviderBinding {
            authority_handle: handle(),
            authority_revision: 1,
            wallet_session_id: wallet_session(),
            permission_generation: 1,
        }
    }

    fn approval_prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            approval_id: approval_id(),
            binding: binding(),
            origin: "https://wallet.example".to_owned(),
            method: "wallet_requestPermissions".to_owned(),
            expires_at_unix_ms: 1_500,
            summary: ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Balance]),
                hns_names: Vec::new(),
            },
        }
    }

    fn install_active_authority(host: &mut TestHost, valid_until_unix_ms: u64) {
        host.authorities.insert(
            handle(),
            AuthorityState {
                facts: facts(valid_until_unix_ms),
                phase: AuthorityPhase::Active { revision: 1 },
                binding: Some(binding()),
                capabilities: None,
            },
        );
    }

    fn request_id(frame: HostFrame) -> ProviderRequestId {
        let HostFrame::Request { envelope } = frame else {
            panic!("request frame");
        };
        envelope.request_id
    }

    fn response_frame(
        host: &TestHost,
        request_id: ProviderRequestId,
        channel_sequence: u64,
        body: ServiceResponse,
    ) -> ServiceFrame {
        ServiceFrame::Response {
            envelope: SessionEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: host.host_session_id(),
                service_session_id: service_session(),
                restart_generation: host.restart_generation(),
                channel_sequence,
                request_id,
                body,
            },
        }
    }

    #[test]
    fn exact_hello_negotiates_one_session() {
        let (mut host, _) = new_host();
        negotiate(&mut host, required_capabilities());
        assert_eq!(host.connection_state(), ConnectionState::Ready);
        assert_eq!(
            host.negotiated_session()
                .expect("negotiated session")
                .service_session_id,
            service_session()
        );
    }

    #[test]
    fn mismatched_hello_poisons_the_channel() {
        let (mut host, _) = new_host();
        let result = host.accept_service_frame(ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: HostPlatform::Android,
                host_session_id: host.host_session_id(),
                service_session_id: service_session(),
                restart_generation: host.restart_generation(),
                capabilities: required_capabilities(),
                limits: ServiceLimits::default(),
            },
        });
        assert!(matches!(result, Err(HostError::HelloMismatch)));
        assert_eq!(host.connection_state(), ConnectionState::Failed);
    }

    #[test]
    fn hns_read_marker_requires_coarse_wallet_operations_at_hello() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.insert(ServiceCapability::HnsReadOperationsV1);
        let result = host.accept_service_frame(ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: host.platform(),
                host_session_id: host.host_session_id(),
                service_session_id: service_session(),
                restart_generation: host.restart_generation(),
                capabilities,
                limits: ServiceLimits::default(),
            },
        });
        assert!(matches!(result, Err(HostError::HelloMismatch)));
        assert_eq!(host.connection_state(), ConnectionState::Failed);
    }

    #[test]
    fn hns_wallet_authority_marker_requires_both_read_prerequisites_at_hello() {
        for capabilities in [
            BTreeSet::from([ServiceCapability::HnsWalletAuthorityContextV1]),
            BTreeSet::from([
                ServiceCapability::WalletOperations,
                ServiceCapability::HnsWalletAuthorityContextV1,
            ]),
        ] {
            let (mut host, _) = new_host();
            let mut offered = required_capabilities();
            offered.extend(capabilities);
            let result = host.accept_service_frame(ServiceFrame::Hello {
                hello: ServiceHello {
                    protocol_version: WALLET_ABI_VERSION,
                    platform: host.platform(),
                    host_session_id: host.host_session_id(),
                    service_session_id: service_session(),
                    restart_generation: host.restart_generation(),
                    capabilities: offered,
                    limits: ServiceLimits::default(),
                },
            });
            assert!(matches!(result, Err(HostError::HelloMismatch)));
            assert_eq!(host.connection_state(), ConnectionState::Failed);
        }
    }

    #[test]
    fn exact_hns_wallet_authority_context_is_request_scoped_evidence_only() {
        let request = WalletAuthorityContextRequest::CurrentHnsContext {
            network: WalletHandshakeNetwork::Regtest,
            network_magic: WalletHandshakeNetwork::Regtest.magic(),
            namespace_id: [7_u8; 16],
            namespace_lease_generation: 9_007_199_254_740_997,
            module: ModuleId::Handshake,
        };

        let (mut missing_marker, _) = new_host();
        let mut read_capabilities = required_capabilities();
        read_capabilities.extend([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ]);
        negotiate(&mut missing_marker, read_capabilities);
        assert!(matches!(
            missing_marker.hns_wallet_authority_context_request(request),
            Err(HostError::CapabilityUnavailable)
        ));
        assert!(missing_marker.pending.is_empty());

        let capabilities = || {
            let mut capabilities = required_capabilities();
            capabilities.extend([
                ServiceCapability::WalletOperations,
                ServiceCapability::HnsReadOperationsV1,
                ServiceCapability::HnsWalletAuthorityContextV1,
            ]);
            capabilities
        };
        let context = WalletHnsAuthorityContext {
            network: WalletHandshakeNetwork::Regtest,
            network_magic: WalletHandshakeNetwork::Regtest.magic(),
            namespace_id: [7_u8; 16],
            namespace_lease_generation: 9_007_199_254_740_997,
            active_wallet: WalletId::new([8_u8; 16]),
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

        let (mut host, _) = new_host();
        negotiate(&mut host, capabilities());
        let frame = host
            .hns_wallet_authority_context_request(request)
            .expect("exact authority-context request");
        let HostFrame::Request { envelope } = &frame else {
            panic!("authority request frame")
        };
        assert_eq!(envelope.body, ServiceRequest::WalletAuthority { request });
        let first_request_id = request_id(frame);
        let response = response_frame(
            &host,
            first_request_id,
            1,
            ServiceResponse::WalletAuthority { context },
        );
        let accepted = host
            .accept_service_frame(response)
            .expect("exact authority-context response");
        assert!(matches!(
            accepted,
            HostOutput::Response(AcceptedResponse {
                response: ServiceResponse::WalletAuthority { context: accepted },
                ..
            }) if accepted == context
        ));
        assert!(host.pending.is_empty());
        assert_eq!(host.connection_state(), ConnectionState::Ready);

        let (mut mismatch, _) = new_host();
        negotiate(&mut mismatch, capabilities());
        let request_id = request_id(
            mismatch
                .hns_wallet_authority_context_request(request)
                .expect("mismatch authority request"),
        );
        let mismatched_context = WalletHnsAuthorityContext {
            namespace_id: [8_u8; 16],
            ..context
        };
        let response = response_frame(
            &mismatch,
            request_id,
            1,
            ServiceResponse::WalletAuthority {
                context: mismatched_context,
            },
        );
        assert!(matches!(
            mismatch.accept_service_frame(response),
            Err(HostError::ResponseClassMismatch)
        ));
        assert_eq!(mismatch.connection_state(), ConnectionState::Failed);

        let (mut malformed, _) = new_host();
        negotiate(&mut malformed, capabilities());
        assert!(matches!(
            malformed.hns_wallet_authority_context_request(
                WalletAuthorityContextRequest::CurrentHnsContext {
                    network: WalletHandshakeNetwork::Regtest,
                    network_magic: WalletHandshakeNetwork::Regtest.magic(),
                    namespace_id: [0_u8; 16],
                    namespace_lease_generation: 9_007_199_254_740_997,
                    module: ModuleId::Handshake,
                }
            ),
            Err(HostError::InvalidHnsWalletAuthorityRequest)
        ));
        assert!(malformed.pending.is_empty());
        assert_eq!(malformed.connection_state(), ConnectionState::Ready);
    }

    #[test]
    fn exact_hns_read_path_requires_marker_and_rejects_every_other_request() {
        let account = AccountId::new([33; 16]);
        let (mut coarse_only, _) = new_host();
        let mut coarse_capabilities = required_capabilities();
        coarse_capabilities.insert(ServiceCapability::WalletOperations);
        negotiate(&mut coarse_only, coarse_capabilities);
        assert!(matches!(
            coarse_only.hns_read_request(WalletRequest::Status),
            Err(HostError::CapabilityUnavailable)
        ));
        assert!(coarse_only.pending.is_empty());
        coarse_only
            .wallet_request(WalletRequest::Status)
            .expect("legacy coarse request remains available");

        let (mut exact, _) = new_host();
        let mut exact_capabilities = required_capabilities();
        exact_capabilities.extend([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ]);
        negotiate(&mut exact, exact_capabilities);
        for request in [
            WalletRequest::Status,
            WalletRequest::ListAccounts,
            WalletRequest::Balance {
                module: ModuleId::Handshake,
                account,
            },
            WalletRequest::ReceiveTarget {
                module: ModuleId::Handshake,
                account,
            },
            WalletRequest::TransactionHistory {
                module: ModuleId::Handshake,
                account,
            },
            WalletRequest::ModuleStatus {
                module: ModuleId::Handshake,
            },
        ] {
            exact
                .hns_read_request(request)
                .expect("frozen HNS read request");
        }
        assert_eq!(exact.pending.len(), 6);

        let (mut rejected, _) = new_host();
        let mut rejected_capabilities = required_capabilities();
        rejected_capabilities.extend([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ]);
        negotiate(&mut rejected, rejected_capabilities);
        for request in [
            WalletRequest::CreateWallet {
                passphrase: SecretString::new("create secret".to_owned()),
            },
            WalletRequest::RestoreWallet {
                passphrase: SecretString::new("restore secret".to_owned()),
                recovery_phrase: SecretString::new("recovery secret".to_owned()),
            },
            WalletRequest::Unlock {
                passphrase: SecretString::new("unlock secret".to_owned()),
            },
            WalletRequest::Lock,
            WalletRequest::WorkflowStatus {
                workflow_id: WorkflowId::new([44; 16]),
            },
            WalletRequest::Balance {
                module: ModuleId::Bitcoin,
                account,
            },
            WalletRequest::ReceiveTarget {
                module: ModuleId::Ethereum,
                account,
            },
            WalletRequest::TransactionHistory {
                module: ModuleId::Bitcoin,
                account,
            },
            WalletRequest::ModuleStatus {
                module: ModuleId::Ethereum,
            },
        ] {
            assert!(matches!(
                rejected.hns_read_request(request),
                Err(HostError::InvalidHnsReadRequest)
            ));
        }
        assert!(rejected.pending.is_empty());
        assert_eq!(rejected.connection_state(), ConnectionState::Ready);
    }

    #[test]
    fn exact_hns_read_responses_are_minimized_and_request_scoped() {
        let account = AccountId::new([33; 16]);
        let other_account = AccountId::new([34; 16]);
        let status_class =
            HnsReadResponseClass::for_request(&WalletRequest::Status).expect("status class");
        let status =
            |locked, active_wallet, modules, mainnet_settlement_enabled| WalletResponse::Status {
                status: WalletRuntimeStatus {
                    locked,
                    active_wallet,
                    enabled_modules: modules,
                    mainnet_settlement_enabled,
                },
            };
        assert!(status_class.matches(&status(
            false,
            Some(WalletId::new([1; 16])),
            BTreeSet::from([ModuleId::Handshake]),
            false,
        )));
        for response in [
            status(
                false,
                Some(WalletId::new([1; 16])),
                BTreeSet::from([ModuleId::Handshake]),
                true,
            ),
            status(
                false,
                Some(WalletId::new([1; 16])),
                BTreeSet::from([ModuleId::Bitcoin]),
                false,
            ),
            status(false, None, BTreeSet::from([ModuleId::Handshake]), false),
            status(
                true,
                Some(WalletId::new([1; 16])),
                BTreeSet::from([ModuleId::Handshake]),
                false,
            ),
            status(
                false,
                Some(WalletId::new([0; 16])),
                BTreeSet::from([ModuleId::Handshake]),
                false,
            ),
            status(
                false,
                Some(WalletId::new([1; 16])),
                BTreeSet::from([ModuleId::Handshake, ModuleId::Bitcoin]),
                false,
            ),
        ] {
            assert!(!status_class.matches(&response));
        }

        let accounts_class =
            HnsReadResponseClass::for_request(&WalletRequest::ListAccounts).expect("accounts");
        let account_summary = AccountSummary {
            account_id: account,
            module: ModuleId::Handshake,
            label: "Handshake".to_owned(),
            receive_display: None,
        };
        assert!(accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![account_summary.clone()],
        }));
        assert!(!accounts_class.matches(&WalletResponse::Accounts { accounts: vec![] }));
        let mut disclosed = account_summary.clone();
        disclosed.receive_display = Some("hs1qprivate".to_owned());
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![disclosed],
        }));
        let mut wrong_module = account_summary.clone();
        wrong_module.module = ModuleId::Bitcoin;
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![wrong_module],
        }));
        let mut zero_account = account_summary.clone();
        zero_account.account_id = AccountId::new([0; 16]);
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![zero_account],
        }));
        let mut empty_label = account_summary.clone();
        empty_label.label.clear();
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![empty_label],
        }));
        let mut non_printable_label = account_summary.clone();
        non_printable_label.label = "Handshake\nWallet".to_owned();
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![non_printable_label],
        }));
        let mut oversized_label = account_summary.clone();
        oversized_label.label = "H".repeat(MAX_PUBLIC_STRING_BYTES + 1);
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![oversized_label],
        }));
        assert!(!accounts_class.matches(&WalletResponse::Accounts {
            accounts: vec![account_summary.clone(), account_summary],
        }));

        let balance_class = HnsReadResponseClass::for_request(&WalletRequest::Balance {
            module: ModuleId::Handshake,
            account,
        })
        .expect("balance");
        assert!(balance_class.matches(&WalletResponse::Balance {
            amount: Amount::new(WalletAsset::Hns, 1),
        }));
        assert!(!balance_class.matches(&WalletResponse::Balance {
            amount: Amount::new(WalletAsset::Btc, 1),
        }));

        let receive_class = HnsReadResponseClass::for_request(&WalletRequest::ReceiveTarget {
            module: ModuleId::Handshake,
            account,
        })
        .expect("receive");
        let receive = |module, account, display| WalletResponse::ReceiveTarget {
            target: ReceiveTarget {
                module,
                account,
                display,
                derivation_index: 0,
            },
        };
        assert!(receive_class.matches(&receive(
            ModuleId::Handshake,
            account,
            "hs1qread".to_owned(),
        )));
        assert!(!receive_class.matches(&receive(
            ModuleId::Handshake,
            other_account,
            "hs1qread".to_owned(),
        )));
        assert!(!receive_class.matches(&receive(
            ModuleId::Bitcoin,
            account,
            "bc1qread".to_owned(),
        )));
        for display in [
            String::new(),
            "hs1q read".to_owned(),
            "hs1qread\n".to_owned(),
            "hs1qréad".to_owned(),
            "h".repeat(513),
        ] {
            assert!(!receive_class.matches(&receive(ModuleId::Handshake, account, display)));
        }

        let transactions_class =
            HnsReadResponseClass::for_request(&WalletRequest::TransactionHistory {
                module: ModuleId::Handshake,
                account,
            })
            .expect("transactions");
        let transaction = |module, txid_byte, negative, magnitude| TransactionSummary {
            module,
            txid: TransactionHash::new([txid_byte; 32]),
            status: LocalTransactionStatus::Confirmed,
            net_amount: SignedBaseUnits {
                negative,
                magnitude: BaseUnits::new(magnitude),
            },
            fee: None,
            block_height: Some(1),
            first_seen_unix: Some(1),
            confirmation_count: 1,
        };
        let valid_transaction = transaction(ModuleId::Handshake, 55, false, 1);
        assert!(
            transactions_class.matches(&WalletResponse::TransactionHistory {
                transactions: vec![],
            })
        );
        assert!(
            transactions_class.matches(&WalletResponse::TransactionHistory {
                transactions: vec![valid_transaction.clone()],
            })
        );
        for transactions in [
            vec![transaction(ModuleId::Bitcoin, 55, false, 1)],
            vec![transaction(ModuleId::Handshake, 0, false, 1)],
            vec![valid_transaction.clone(), valid_transaction],
            vec![transaction(ModuleId::Handshake, 56, true, 0)],
        ] {
            assert!(
                !transactions_class.matches(&WalletResponse::TransactionHistory { transactions })
            );
        }

        let module_class = HnsReadResponseClass::for_request(&WalletRequest::ModuleStatus {
            module: ModuleId::Handshake,
        })
        .expect("module status");
        let successful_status = SyncStatus {
            phase: SyncPhase::Ready,
            validated_height: 1,
            scanned_height: 1,
            target_height: Some(1),
            last_error: None,
        };
        assert!(module_class.matches(&WalletResponse::ModuleStatus {
            status: successful_status.clone(),
        }));
        for status in [
            SyncStatus {
                phase: SyncPhase::Degraded,
                ..successful_status.clone()
            },
            SyncStatus {
                scanned_height: 0,
                ..successful_status.clone()
            },
            SyncStatus {
                target_height: None,
                ..successful_status.clone()
            },
            SyncStatus {
                target_height: Some(2),
                ..successful_status.clone()
            },
            SyncStatus {
                last_error: Some("not ready".to_owned()),
                ..successful_status
            },
        ] {
            assert!(!module_class.matches(&WalletResponse::ModuleStatus { status }));
        }
    }

    #[test]
    fn exact_hns_read_response_scope_mismatch_poisons_the_channel() {
        let account = AccountId::new([33; 16]);
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.extend([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ]);
        negotiate(&mut host, capabilities);
        let request_id = request_id(
            host.hns_read_request(WalletRequest::ReceiveTarget {
                module: ModuleId::Handshake,
                account,
            })
            .expect("request"),
        );
        let frame = response_frame(
            &host,
            request_id,
            1,
            ServiceResponse::Wallet {
                response: WalletResponse::ReceiveTarget {
                    target: ReceiveTarget {
                        module: ModuleId::Handshake,
                        account: AccountId::new([34; 16]),
                        display: "hs1qwrongaccount".to_owned(),
                        derivation_index: 0,
                    },
                },
            },
        );
        assert!(matches!(
            host.accept_service_frame(frame),
            Err(HostError::ResponseClassMismatch)
        ));
        assert_eq!(host.connection_state(), ConnectionState::Failed);
    }

    #[test]
    fn response_class_mismatch_poisons_the_channel() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.insert(ServiceCapability::WalletOperations);
        negotiate(&mut host, capabilities);
        let request_id = request_id(host.wallet_request(WalletRequest::Status).expect("request"));
        let frame = response_frame(
            &host,
            request_id,
            1,
            ServiceResponse::Wallet {
                response: WalletResponse::Locked,
            },
        );
        let result = host.accept_service_frame(frame);
        assert!(matches!(result, Err(HostError::ResponseClassMismatch)));
        assert_eq!(host.connection_state(), ConnectionState::Failed);
    }

    #[test]
    fn responses_and_events_share_the_service_sequence() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.extend([
            ServiceCapability::TypedEvents,
            ServiceCapability::WalletOperations,
        ]);
        negotiate(&mut host, capabilities);
        let request_id = request_id(host.wallet_request(WalletRequest::Lock).expect("request"));
        let frame = response_frame(
            &host,
            request_id,
            1,
            ServiceResponse::Wallet {
                response: WalletResponse::Locked,
            },
        );
        host.accept_service_frame(frame).expect("response");

        install_active_authority(&mut host, 2_000);
        let event = ProviderEventEnvelope {
            protocol_version: WALLET_ABI_VERSION,
            host_session_id: host.host_session_id(),
            service_session_id: service_session(),
            restart_generation: host.restart_generation(),
            channel_sequence: 2,
            binding: binding(),
            event_sequence: 1,
            payload: ProviderEventPayload::Connect {
                permission_generation: 1,
            },
        };
        assert!(matches!(
            host.accept_service_frame(ServiceFrame::Event { event }),
            Ok(HostOutput::Event(_))
        ));
    }

    #[test]
    fn authority_expiry_rejects_a_delayed_response() {
        let (mut host, now) = new_host();
        negotiate(&mut host, required_capabilities());
        install_active_authority(&mut host, 1_100);
        let request_id = request_id(
            host.request_provider_capabilities(handle())
                .expect("capability request"),
        );
        now.set(1_100);
        let frame = response_frame(
            &host,
            request_id,
            1,
            ServiceResponse::ProviderCapabilities {
                binding: binding(),
                capabilities: ProviderCapabilitySnapshot {
                    provider_schema_version: PROVIDER_SCHEMA_VERSION,
                    approval_schema_version: APPROVAL_SCHEMA_VERSION,
                    wallet_session_id: wallet_session(),
                    permission_generation: 1,
                    methods: BTreeSet::new(),
                },
            },
        );
        let result = host.accept_service_frame(frame);
        assert!(matches!(result, Err(HostError::AuthorityExpired)));
        assert_eq!(host.connection_state(), ConnectionState::Failed);
    }

    #[test]
    fn approval_decision_uses_the_stored_private_binding() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.insert(ServiceCapability::StructuredApprovals);
        negotiate(&mut host, capabilities);
        install_active_authority(&mut host, 2_000);
        host.approvals.insert(
            approval_id(),
            HostApproval {
                prompt: approval_prompt(),
                phase: ApprovalPhase::Available,
            },
        );
        let frame = host
            .decide_approval(approval_id(), ApprovalDecision::Reject)
            .expect("approval decision");
        let HostFrame::Request { envelope } = frame else {
            panic!("request frame");
        };
        assert!(matches!(
            envelope.body,
            ServiceRequest::ApprovalDecision {
                authority_handle,
                authority_revision: 1,
                approval_id: response_approval_id,
                decision: ApprovalDecision::Reject,
            } if authority_handle == handle() && response_approval_id == approval_id()
        ));
    }

    #[test]
    fn production_followup_host_preserves_exact_sorted_name_disclosure() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.insert(ServiceCapability::StructuredApprovals);
        negotiate(&mut host, capabilities);
        install_active_authority(&mut host, 2_000);
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
        let mut prompt = approval_prompt();
        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            hns_names: vec![beta.clone(), alpha.clone()],
        };
        assert!(matches!(
            host.install_approval(handle(), 1, "wallet_requestPermissions", prompt.clone()),
            Err(HostError::ApprovalMismatch)
        ));

        let expected = vec![alpha, beta];
        prompt.summary = ApprovalSummary::Permissions {
            capabilities: BTreeSet::from([PermissionCapability::Names]),
            hns_names: expected.clone(),
        };
        host.install_approval(handle(), 1, "wallet_requestPermissions", prompt)
            .expect("exact disclosure prompt");
        let stored = host.approval(approval_id()).expect("stored disclosure");
        assert_eq!(
            stored.summary,
            ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Names]),
                hns_names: expected,
            }
        );
    }

    #[test]
    fn canonical_provider_account_join_capability_snapshot_is_negotiated() {
        let (mut host, _) = new_host();
        let mut service_capabilities = required_capabilities();
        service_capabilities.insert(ServiceCapability::ProviderDispatch);
        service_capabilities.insert(ServiceCapability::StructuredApprovals);
        negotiate(&mut host, service_capabilities);
        install_active_authority(&mut host, 2_000);
        host.install_capabilities(
            handle(),
            1,
            binding(),
            ProviderCapabilitySnapshot {
                provider_schema_version: PROVIDER_SCHEMA_VERSION,
                approval_schema_version: APPROVAL_SCHEMA_VERSION,
                wallet_session_id: wallet_session(),
                permission_generation: 1,
                methods: BTreeSet::from(["hns_requestAccounts".to_owned()]),
            },
        )
        .expect("account join capability");
    }

    #[test]
    fn expired_authority_can_be_discarded_without_reusing_its_handle() {
        let (mut host, now) = new_host();
        negotiate(&mut host, required_capabilities());
        install_active_authority(&mut host, 1_100);
        host.issued_authority_ids.insert(handle());
        now.set(1_100);
        host.discard_authority(handle()).expect("discard");
        assert!(host.authority(handle()).is_none());
        assert!(host.issued_authority_ids.contains(&handle()));
    }

    #[test]
    fn mandatory_approval_cannot_complete_as_a_direct_provider_result() {
        let (mut host, _) = new_host();
        negotiate(&mut host, required_capabilities());
        install_active_authority(&mut host, 2_000);
        let result = host.apply_response(
            &RequestClass::Provider {
                handle: handle(),
                revision: 1,
                method: "hns_send".to_owned(),
            },
            &ServiceResponse::ProviderResult {
                binding: binding(),
                value: Value::Null,
            },
        );
        assert!(matches!(result, Err(HostError::ResponseClassMismatch)));
    }

    #[test]
    fn permission_mutation_requires_exactly_one_generation_advance() {
        let (mut host, _) = new_host();
        negotiate(&mut host, required_capabilities());
        install_active_authority(&mut host, 2_000);
        let result =
            host.apply_provider_binding(handle(), 1, "wallet_revokePermissions", binding());
        assert!(matches!(result, Err(HostError::StaleBinding)));
    }

    #[test]
    fn wallet_locked_event_clears_current_provider_state() {
        let (mut host, _) = new_host();
        let mut capabilities = required_capabilities();
        capabilities.insert(ServiceCapability::TypedEvents);
        negotiate(&mut host, capabilities);
        install_active_authority(&mut host, 2_000);
        let event = ProviderEventEnvelope {
            protocol_version: WALLET_ABI_VERSION,
            host_session_id: host.host_session_id(),
            service_session_id: service_session(),
            restart_generation: host.restart_generation(),
            channel_sequence: 1,
            binding: binding(),
            event_sequence: 1,
            payload: ProviderEventPayload::WalletLocked,
        };
        host.accept_service_frame(ServiceFrame::Event { event })
            .expect("wallet locked event");
        assert!(
            host.authority(handle())
                .expect("authority")
                .binding
                .is_none()
        );
    }

    #[test]
    fn completed_approval_identifier_cannot_be_reused() {
        let (mut host, _) = new_host();
        negotiate(&mut host, required_capabilities());
        install_active_authority(&mut host, 2_000);
        host.install_approval(handle(), 1, "wallet_requestPermissions", approval_prompt())
            .expect("first prompt");
        host.approvals.remove(&approval_id());
        let result =
            host.install_approval(handle(), 1, "wallet_requestPermissions", approval_prompt());
        assert!(matches!(result, Err(HostError::ApprovalMismatch)));
    }
}
