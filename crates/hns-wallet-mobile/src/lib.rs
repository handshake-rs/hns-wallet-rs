#![doc = "Platform-neutral native wallet control for Android and iOS applications."]
#![forbid(unsafe_code)]

mod bitcoin;
mod market;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

pub use bitcoin::{
    MobileBitcoinBroadcastReceipt, MobileBitcoinDirectConfig, MobileBitcoinHtlcFundingApproval,
    MobileBitcoinHtlcFundingReceipt, MobileBitcoinHtlcSettlementApproval,
    MobileBitcoinHtlcSettlementReceipt, MobileBitcoinSendApproval, MobileBitcoinShutdownHandle,
    MobileBitcoinSnapshot, MobileBitcoinSyncProgress, MobileBitcoinSyncProgressHandle,
    MobileBitcoinValueController,
};
pub use hns_wallet_bitcoin_kyoto::{
    BitcoinBroadcastRecoverySummary, VerifiedBitcoinHtlcSpendObservation, VerifiedBitcoinLock,
};
pub use market::{
    MobileBtcForHnsOfferApproval, MobileBtcForHnsOfferSummary, MobileDenuoBitcoinFundingPermit,
    MobileDenuoBitcoinSettlementPermit, MobileDenuoBitcoinWatchPermit, MobileDenuoDirectAdmission,
    MobileDenuoDirectTransportReport, MobileDenuoExecutionSummary, MobileDenuoHnsFundingPermit,
    MobileDenuoHnsSettlementPermit, MobileDenuoHnsVerificationPermit, MobileDenuoSessionController,
    MobileDenuoSettlementAction,
};

use hns_primitives::BlockHash as ProtocolBlockHash;
use hns_swap::NetworkBinding;
use hns_wallet_chain_api::{PreparedArtifact, PreparedSettlementLock};
use hns_wallet_ffi::{
    AbiError, AccountSummary, ApprovalSummary, HnsNameDisclosure, HostFrame, HostPlatform,
    MAX_HNS_NAME_DISCLOSURES, SecretString, ServiceCapability, ServiceErrorCode, ServiceFailure,
    ServiceResponse, WalletRequest, WalletResponse, WalletRuntimeStatus, decode_service_frame,
    encode_host_frame,
};
/// Backend composition types exposed for downstream native shells. The RPC
/// adapter remains available for explicitly configured local deployments; a
/// host can instead open the wallet-owned direct peer coordinator below and
/// compose its [`EmbeddedHnsBackend`] without endpoint credentials.
pub use hns_wallet_hns::{
    ConnectedHnsPeer, EmbeddedHnsBackend, HnsBackend, HnsBlockScanProgress, HnsBootstrapPolicy,
    HnsClock, HnsDirectDenuoListener, HnsDirectDenuoMessage, HnsDirectDenuoPeer,
    HnsDirectPeerConfig, HnsDirectPeerCoordinator, HnsDirectPeerError, HnsHeaderRoundProgress,
    HnsLightFloor, HnsNetwork, HnsNodeRpcBackend, HnsNodeRpcConfig,
    SystemClock as HnsReadSystemClock,
};
use hns_wallet_hns::{
    HnsAccountReadRuntime, HnsAccountRecord, HnsExistingAccountSelector, HnsRuntimeConfig,
    HnsWalletBootstrap, HnsWalletError, HnsWalletRuntime, KnownName, NameOwnershipStatus,
    NameResourceStatus, RecoveryPhrase, open_wallet_direct_hns_peer_coordinator_with_floor,
    open_wallet_direct_hns_peer_coordinator_with_floor_and_genesis_bootstrap,
};
use hns_wallet_host::{
    Clock, ClockError, HostError, HostOutput, SystemClock, SystemEntropy, WalletHost,
};
use hns_wallet_market::{DenuoDirectOfferBoardPolicy, DenuoDirectSwapPolicy};
use hns_wallet_provider::{
    APPROVAL_LIFETIME_SECONDS, ApprovedCall, Origin, ProviderMethod, SelectedNamespace,
};
use hns_wallet_service::{
    MAX_JAVASCRIPT_SAFE_INTEGER, NATIVE_HNS_SEND_PRE_BROADCAST_RETRY_MESSAGE,
    NativeHnsNameOwnershipStatus, NativeHnsNameResourceStatus, NativeHnsNameSummary,
    NativeHnsValueSnapshot, PersistentDenuoTransport, PersistentHnsAccountConfig,
    PersistentHnsAccountRuntime, PersistentHnsReadConfig, PersistentHnsReadRuntime,
    PersistentHnsValueConfig, PersistentHnsValueRuntime, PersistentShakedexConfig, ServiceError,
    ServiceRuntime, TRUSTED_NATIVE_HNS_VALUE_ORIGIN, TrustedNativeHnsValueAction, WalletService,
};
use hns_wallet_shakedex::{
    DenuoHnsaEndpointBinding, DenuoHrmRootBinding, DenuoPublicationAcceptancePolicy,
    DirectDenuoBoardSyncReport, ShakedexSellerPolicy,
};
use hns_wallet_store::{SharedWalletStore, StoreError, WalletStore};
use hns_wallet_types::{
    AccountId, Amount, ApprovalId, ApprovalKind, BaseUnits, HnsNameReceiveTarget, ModuleId,
    ObjectHash, ReceiveTarget, SyncPhase, SyncStatus, TransactionSummary, WalletAsset,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MOBILE_DATABASE_KEY_BYTES: usize = 32;
pub const MAX_MOBILE_RECOVERY_PHRASE_BYTES: usize = 256;
pub const MAX_MOBILE_SHAKEDEX_POLICY_BYTES: usize = 16 * 1024;
pub const MOBILE_ACCOUNT_LABEL: &str = "Handshake";
pub const MAX_MOBILE_HNS_NAME_PAGE: usize = MAX_HNS_NAME_DISCLOSURES;
const STORE_PASSPHRASE_DOMAIN: &str = "hns-wallet-mobile/store-passphrase/v1:";
const RESTART_GENERATION: u64 = 1;
const MAX_MOBILE_WALLET_ACCOUNTS: usize = 2;
const MOBILE_ACTION_TOKEN_BYTES: usize = 32;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobilePlatform {
    Android,
    Ios,
}

impl From<MobilePlatform> for HostPlatform {
    fn from(platform: MobilePlatform) -> Self {
        match platform {
            MobilePlatform::Android => Self::Android,
            MobilePlatform::Ios => Self::Ios,
        }
    }
}

/// A platform-unwrapped database key. It deliberately implements neither
/// `Clone` nor `Debug`, and it is zeroized when dropped.
pub struct MobileDatabaseKey(Zeroizing<[u8; MOBILE_DATABASE_KEY_BYTES]>);

impl MobileDatabaseKey {
    pub fn new(bytes: [u8; MOBILE_DATABASE_KEY_BYTES]) -> Result<Self, MobileWalletError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MobileWalletError::InvalidDatabaseKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, MobileWalletError> {
        let bytes = <[u8; MOBILE_DATABASE_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| MobileWalletError::InvalidDatabaseKey)?;
        Self::new(bytes)
    }

    fn store_passphrase(&self) -> Zeroizing<String> {
        let mut passphrase = Zeroizing::new(String::with_capacity(
            STORE_PASSPHRASE_DOMAIN.len() + MOBILE_DATABASE_KEY_BYTES * 2,
        ));
        passphrase.push_str(STORE_PASSPHRASE_DOMAIN);
        for byte in self.0.iter() {
            passphrase.push(HEX[usize::from(byte >> 4)] as char);
            passphrase.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        passphrase
    }
}

/// A caller-owned recovery phrase accepted only by the native restore path.
/// It deliberately implements neither `Clone` nor `Debug` and zeroizes its
/// allocation on drop.
pub struct MobileRecoveryPhrase(Zeroizing<String>);

impl MobileRecoveryPhrase {
    pub fn new(value: String) -> Result<Self, MobileWalletError> {
        if value.is_empty() || value.len() > MAX_MOBILE_RECOVERY_PHRASE_BYTES {
            return Err(MobileWalletError::InvalidRecoveryPhrase);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

type MobileHost = WalletHost<SystemClock, SystemEntropy>;

struct MobileControllerSession<R> {
    store: SharedWalletStore,
    host: MobileHost,
    service: WalletService<SharedWalletStore, R>,
    failed: bool,
}

/// One process-local native controller. No raw ABI frame, provider authority,
/// decrypted record key, or recovery phrase is exposed through this type.
pub struct MobileWalletController {
    session: MobileControllerSession<PersistentHnsAccountRuntime>,
    account_config: HnsRuntimeConfig,
    platform: MobilePlatform,
}

/// One minimized, serializable known-name projection for trusted native UI.
/// Raw proofs, name-state bytes, owner outpoints, resource bytes, and key
/// derivations never cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileHnsNameSummary {
    pub name: String,
    pub name_hash: String,
    pub proof_height: u64,
    pub resource_status: MobileHnsNameResourceStatus,
    pub ownership_status: MobileHnsNameOwnershipStatus,
    pub registered: Option<bool>,
    pub expired: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobileHnsNameResourceStatus {
    UnavailableCanonicalBinding,
    NoCurrentState,
    Empty,
    CanonicalDecoded,
    CanonicalOpaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobileHnsNameOwnershipStatus {
    WatchOnlyCanonicalStateDecoderUnavailable,
    WalletContextUnavailable,
    NoCurrentOwner,
    NotWalletOwned,
    WalletOwned,
    IncomingTransfer,
    OutgoingTransfer,
}

/// One exact synchronized read-only HNS projection. Every field comes from the
/// same chain-tip/epoch and mempool instance/generation binding, which remains
/// internal to the controller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileHnsReadSnapshot {
    pub balance: Amount,
    pub receive_target: ReceiveTarget,
    pub name_receive_target: HnsNameReceiveTarget,
    pub transaction_history: Vec<TransactionSummary>,
    /// First page only. Additional pages are obtained from the controller's
    /// last authenticated synchronization without repeating reconciliation.
    pub known_names: Vec<MobileHnsNameSummary>,
    pub known_name_count: u32,
    pub known_names_complete: bool,
    pub module_status: SyncStatus,
}

/// One deterministic page from the last authenticated known-name projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileHnsNamePage {
    pub offset: u32,
    pub total: u32,
    pub names: Vec<MobileHnsNameSummary>,
    pub has_more: bool,
}

/// Backend-injected native HNS read controller. It composes the exact same
/// `SharedWalletStore` authority through account selection, synchronized HNS
/// reconciliation, provider-state persistence, and private ABI lifecycle
/// control. It authenticates a script-free epoch/tip and selected-network
/// genesis before deriving or querying watch scripts. Backend transport remains
/// a product-owned trust boundary. This controller exposes no browser/provider
/// entry point or value operation.
pub struct MobileHnsReadController<B, C = HnsReadSystemClock> {
    session: MobileControllerSession<PersistentHnsReadRuntime<B, C>>,
    account_config: HnsRuntimeConfig,
    known_names: Vec<MobileHnsNameSummary>,
}

/// Full same-store native HNS controller. It retains the signing runtime and
/// the private service behind an installed-product boundary, exposes no raw
/// provider frames, and permits at most one exact process-local value approval
/// at a time.
pub struct MobileHnsValueController<B: HnsBackend, C: HnsClock = HnsReadSystemClock> {
    session: MobileControllerSession<PersistentHnsValueRuntime<B, C>>,
    account_config: HnsRuntimeConfig,
    pending: Option<PendingMobileHnsValueAction>,
    pending_denuo_hns_funding: Option<PendingMobileDenuoHnsFunding>,
    pending_denuo_hns_settlement: Option<PendingMobileDenuoHnsSettlement>,
    known_names: Vec<MobileHnsNameSummary>,
}

/// Full native HNS value controller composed with the wallet-owned direct
/// standard-peer coordinator.
///
/// The inner [`MobileHnsValueController`] and the coordinator share one
/// `EmbeddedHnsBackend`, encrypted light index, header authority, store/key
/// authority, and direct broadcast pool. Keeping them in one value preserves
/// the direct synchronization authority alongside the value runtime rather
/// than requiring an endpoint-backed fallback after activation.
pub struct MobileDirectHnsValueController<C: HnsClock = HnsReadSystemClock> {
    value: MobileHnsValueController<EmbeddedHnsBackend, C>,
    coordinator: HnsDirectPeerCoordinator,
}

/// A direct Denuo listener created by one [`MobileDirectHnsValueController`].
///
/// The underlying listener stays private so accepting a peer has to cross the
/// same controller that owns the value runtime's trusted clock.  It is still
/// an ordinary socket resource: the embedding application must drop it when
/// its native I/O worker stops, including when the wallet is locked.
pub struct MobileDirectDenuoListener {
    listener: HnsDirectDenuoListener,
}

impl MobileDirectDenuoListener {
    /// Return the concrete local socket locator, including a kernel-selected
    /// port when the listener was bound with port zero.
    pub fn local_addr(&self) -> Result<SocketAddr, MobileWalletError> {
        self.listener.local_addr().map_err(Into::into)
    }
}

struct PendingMobileHnsValueAction {
    action_token: [u8; MOBILE_ACTION_TOKEN_BYTES],
    action: TrustedNativeHnsValueAction,
}

/// Closed native value vocabulary. The selected account and native origin are
/// inserted by Rust and can never be supplied or replaced by Kotlin, Swift, a
/// WebView, or website content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MobileHnsValueIntent {
    Send {
        recipient: String,
        amount: BaseUnits,
        maximum_fee: BaseUnits,
    },
    TransferName {
        name: String,
        recipient: String,
        maximum_fee: BaseUnits,
    },
    FinalizeName {
        name: String,
        expected_recipient: Option<String>,
        maximum_fee: BaseUnits,
    },
    CreateFixedPriceOffer {
        name: String,
        price: BaseUnits,
        maximum_fee: BaseUnits,
        listing_lifetime_seconds: u64,
    },
    CancelOffer {
        seller_session_id: String,
    },
    AcceptOffer {
        listing_id: String,
        maximum_fee: BaseUnits,
    },
    FinalizePurchase {
        session_id: String,
        maximum_fee: BaseUnits,
    },
    RecoverName {
        seller_session_id: String,
        maximum_fee: BaseUnits,
    },
}

/// Closed non-signing Shakedex query vocabulary for the installed native UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "query",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MobileShakedexQuery {
    ListOffers {
        cursor: Option<String>,
        limit: Option<u16>,
    },
    GetSession {
        session_id: String,
    },
}

/// Exact summary displayed by native UI before one value action can execute.
/// The opaque action token is process-local, random, single-use, and carries no
/// signing authority after this controller is locked or dropped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileHnsValueApproval {
    pub action_token: String,
    pub expires_at_unix: u64,
    pub summary: ApprovalSummary,
}

struct PendingMobileDenuoHnsFunding {
    action_token: [u8; 32],
    session_id: hns_wallet_types::SessionId,
    prepared: PreparedSettlementLock,
    maximum_fee: BaseUnits,
}

struct PendingMobileDenuoHnsSettlement {
    action_token: [u8; 32],
    session_id: hns_wallet_types::SessionId,
    action: MobileDenuoSettlementAction,
    prepared: PreparedArtifact,
    maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDenuoHnsFundingApproval {
    pub action_token: String,
    pub session_id: String,
    pub transaction_id: String,
    pub amount_dollarydoos: u64,
    pub fee_dollarydoos: u64,
    pub maximum_fee_dollarydoos: u64,
    pub refund_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDenuoHnsFundingReceipt {
    pub session_id: String,
    pub transaction_id: String,
    pub accepted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDenuoHnsSettlementApproval {
    pub action_token: String,
    pub session_id: String,
    pub action: MobileDenuoSettlementAction,
    pub transaction_id: String,
    pub input_amount_dollarydoos: u64,
    pub output_amount_dollarydoos: u64,
    pub fee_dollarydoos: u64,
    pub maximum_fee_dollarydoos: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDenuoHnsSettlementReceipt {
    pub session_id: String,
    pub action: MobileDenuoSettlementAction,
    pub transaction_id: String,
    pub accepted_at_unix: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileDenuoAcceptancePolicyFile {
    network_magic: u32,
    network_genesis: String,
    hrm: MobileDenuoHrmPolicyFile,
    hnsa: MobileDenuoHnsaPolicyFile,
    maximum_receipt_lifetime_seconds: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileDenuoHrmPolicyFile {
    subject: String,
    sequence: u64,
    envelope_hash: String,
    chain_height: u64,
    chain_work_be: String,
    chain_anchor: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileDenuoHnsaPolicyFile {
    canonical_service_name: String,
    application_profile_id: u16,
    service_resource_id: String,
    service_delegation_id: String,
    service_generation: u64,
    endpoint_delegation_id: String,
    endpoint_sequence: u64,
    endpoint_public_key: String,
    effective_not_before_unix: u64,
    effective_expires_at_unix: u64,
}

/// A newly created controller and its one-time dedicated recovery display.
/// The phrase is not exposed as an ordinary public field or through `Debug`.
pub struct MobileWalletCreation {
    controller: MobileWalletController,
    recovery_phrase: RecoveryPhrase,
}

impl MobileWalletCreation {
    pub fn into_parts(self) -> (MobileWalletController, RecoveryPhrase) {
        (self.controller, self.recovery_phrase)
    }
}

impl<R: ServiceRuntime> MobileControllerSession<R> {
    fn new(
        store: SharedWalletStore,
        host: MobileHost,
        service: WalletService<SharedWalletStore, R>,
    ) -> Self {
        Self {
            store,
            host,
            service,
            failed: false,
        }
    }

    fn negotiate_non_value(&mut self) -> Result<(), MobileWalletError> {
        let hello = self.host.hello_frame()?;
        match self.exchange(hello)? {
            HostOutput::Negotiated(session)
                if !session
                    .capabilities
                    .contains(&ServiceCapability::ValueMovement)
                    && !session
                        .capabilities
                        .contains(&ServiceCapability::BrowserIntegration) =>
            {
                Ok(())
            }
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    fn negotiate_value(&mut self, require_shakedex: bool) -> Result<(), MobileWalletError> {
        let hello = self.host.hello_frame()?;
        match self.exchange(hello)? {
            HostOutput::Negotiated(session)
                if session
                    .capabilities
                    .contains(&ServiceCapability::WalletOperations)
                    && session
                        .capabilities
                        .contains(&ServiceCapability::HnsReadOperationsV1)
                    && session
                        .capabilities
                        .contains(&ServiceCapability::HnsValueOperationsV1)
                    && session
                        .capabilities
                        .contains(&ServiceCapability::ProviderDispatch)
                    && session
                        .capabilities
                        .contains(&ServiceCapability::ValueMovement)
                    && (!require_shakedex
                        || session
                            .capabilities
                            .contains(&ServiceCapability::DenuoShakedexV1))
                    && !session
                        .capabilities
                        .contains(&ServiceCapability::BrowserIntegration) =>
            {
                Ok(())
            }
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    fn wallet_request(
        &mut self,
        request: WalletRequest,
    ) -> Result<WalletResponse, MobileWalletError> {
        let result = self.wallet_request_inner(request);
        if result.is_err() {
            self.lock_after_request_error();
        }
        result
    }

    fn wallet_request_inner(
        &mut self,
        request: WalletRequest,
    ) -> Result<WalletResponse, MobileWalletError> {
        if self.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        let frame = self.host.wallet_request(request)?;
        match self.exchange(frame)? {
            HostOutput::Response(accepted) => match accepted.response {
                ServiceResponse::Wallet { response } => Ok(response),
                ServiceResponse::Failure { failure } => Err(mobile_service_failure(failure)),
                _ => Err(MobileWalletError::UnexpectedResponse),
            },
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    fn lock_after_request_error(&mut self) {
        if self.failed {
            let _ = self.store.lock();
            return;
        }
        let locked = matches!(
            self.wallet_request_inner(WalletRequest::Lock),
            Ok(WalletResponse::Locked)
        );
        if !locked {
            self.failed = true;
            let _ = self.store.lock();
        }
    }

    fn exchange(&mut self, frame: HostFrame) -> Result<HostOutput, MobileWalletError> {
        let result = (|| {
            let encoded = encode_host_frame(&frame)?;
            let response = self
                .service
                .process_frame(encoded.as_slice(), SystemClock.now_unix_ms()?)?;
            let response = decode_service_frame(&response)?;
            self.host
                .accept_service_frame(response)
                .map_err(MobileWalletError::from)
        })();
        if result.is_err() {
            self.failed = true;
            let _ = self.store.lock();
        }
        result
    }
}

impl<R> Drop for MobileControllerSession<R> {
    fn drop(&mut self) {
        let _ = self.store.lock();
    }
}

impl MobileWalletController {
    /// Creates one new non-value HNS account. The cleanup guard remains armed
    /// until the account, controller, private ABI session, and recovery-display
    /// object all exist, so a fallible post-bootstrap step cannot strand an
    /// undisclosed mnemonic behind a durable database.
    pub fn create(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        policy: HnsBootstrapPolicy,
    ) -> Result<MobileWalletCreation, MobileWalletError> {
        let bootstrap = HnsWalletBootstrap::generate(policy)?;
        let account_config = bootstrap.account_record().config.clone();
        let host = WalletHost::new_system(platform.into(), RESTART_GENERATION)?;
        let passphrase = database_key.store_passphrase();
        let now_unix = SystemClock.now_unix_ms()? / 1_000;
        WalletStore::create_with_owned_initializer(
            path,
            passphrase.as_str(),
            move |mut store| -> Result<MobileWalletCreation, MobileWalletError> {
                bootstrap.persist(&mut store, now_unix)?;
                bitcoin::persist_mobile_bitcoin_wallet_origin(
                    &mut store,
                    account_config.account_id.as_bytes(),
                    bitcoin::MobileBitcoinWalletOrigin::Generated,
                    now_unix,
                )?;
                let controller = Self::from_unlocked_store(store, account_config, platform, host)?;
                Ok(MobileWalletCreation {
                    controller,
                    recovery_phrase: bootstrap.into_recovery_phrase(),
                })
            },
        )
    }

    /// Restores one new non-value HNS account from an owned, zeroizing 24-word
    /// phrase input. It never opens or fills a pre-existing partial database.
    pub fn restore(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        policy: HnsBootstrapPolicy,
        recovery_phrase: MobileRecoveryPhrase,
    ) -> Result<Self, MobileWalletError> {
        let bootstrap = HnsWalletBootstrap::restore(recovery_phrase.expose_secret(), policy)?;
        drop(recovery_phrase);
        let account_config = bootstrap.account_record().config.clone();
        let host = WalletHost::new_system(platform.into(), RESTART_GENERATION)?;
        let passphrase = database_key.store_passphrase();
        let now_unix = SystemClock.now_unix_ms()? / 1_000;
        WalletStore::create_with_owned_initializer(
            path,
            passphrase.as_str(),
            move |mut store| -> Result<Self, MobileWalletError> {
                bootstrap.persist(&mut store, now_unix)?;
                bitcoin::persist_mobile_bitcoin_wallet_origin(
                    &mut store,
                    account_config.account_id.as_bytes(),
                    bitcoin::MobileBitcoinWalletOrigin::Restored,
                    now_unix,
                )?;
                Self::from_unlocked_store(store, account_config, platform, host)
            },
        )
    }

    /// Open exactly one existing structurally valid HNS account and start
    /// locked. Persisted value flags remain authenticated identity facts but do
    /// not become authority in this lifecycle-only controller. The database key
    /// is used only for discovery and is not retained.
    pub fn open(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
    ) -> Result<Self, MobileWalletError> {
        let host = WalletHost::new_system(platform.into(), RESTART_GENERATION)?;
        let mut store = WalletStore::open(path)?;
        let passphrase = database_key.store_passphrase();
        store.unlock(passphrase.as_str())?;
        let mut accounts = store.wallet_accounts::<HnsAccountRecord>(MAX_MOBILE_WALLET_ACCOUNTS)?;
        if accounts.len() != 1 {
            store.lock();
            return Err(MobileWalletError::InvalidAccountSet);
        }
        let account_config = accounts
            .pop()
            .ok_or(MobileWalletError::InvalidAccountSet)?
            .value
            .config;
        store.validate_single_recovery_seed(account_config.wallet_id.as_bytes())?;
        Self::from_unlocked_store(store, account_config, platform, host)
    }

    fn from_unlocked_store(
        store: WalletStore,
        account_config: HnsRuntimeConfig,
        platform: MobilePlatform,
        host: MobileHost,
    ) -> Result<Self, MobileWalletError> {
        let store = SharedWalletStore::new(store);
        let selector =
            HnsExistingAccountSelector::new_lifecycle(store.clone(), account_config.clone());
        let selector = match selector {
            Ok(selector) => selector,
            Err(error) => {
                let _ = store.lock();
                return Err(error.into());
            }
        };
        let selection = selector.selected_account();
        let lock = store.lock();
        selection?;
        lock?;

        let service = WalletService::new_persistent_hns_accounts(
            store.clone(),
            PersistentHnsAccountConfig {
                selector,
                account_label: MOBILE_ACCOUNT_LABEL.to_owned(),
            },
        )?;
        let mut controller = Self {
            session: MobileControllerSession::new(store, host, service),
            account_config,
            platform,
        };
        controller.session.negotiate_non_value()?;
        Ok(controller)
    }

    pub const fn account_config(&self) -> &HnsRuntimeConfig {
        &self.account_config
    }

    /// Open the wallet-owned direct HNS peer coordinator for this exact
    /// encrypted account. This consumes no endpoint, RPC credential, relay,
    /// or third-party index configuration: the coordinator derives its watch
    /// set from the locally encrypted account and uses ordinary HNS peers.
    ///
    /// The controller returns locked. A host retains the coordinator while it
    /// later consumes this lifecycle controller into the read or value runtime;
    /// synchronization then runs only while that same wallet store is unlocked.
    pub fn open_direct_hns_peer_coordinator(
        &mut self,
        database_key: &MobileDatabaseKey,
        peer_config: HnsDirectPeerConfig,
    ) -> Result<HnsDirectPeerCoordinator, MobileWalletError> {
        self.open_direct_hns_peer_coordinator_with_floor(
            database_key,
            peer_config,
            HnsLightFloor::default(),
        )
    }

    /// Open the direct HNS coordinator with the platform-held monotonic
    /// rollback floor. An installed shell persists this floor outside the
    /// encrypted wallet database after header synchronization and provides it
    /// again on reopen, preventing an older database backup from silently
    /// becoming the wallet's chain authority.
    pub fn open_direct_hns_peer_coordinator_with_floor(
        &mut self,
        database_key: &MobileDatabaseKey,
        peer_config: HnsDirectPeerConfig,
        rollback_floor: HnsLightFloor,
    ) -> Result<HnsDirectPeerCoordinator, MobileWalletError> {
        self.lock()?;
        let store = self.session.store.clone();
        let account_config = self.account_config.clone();
        let passphrase = database_key.store_passphrase();
        store.unlock(passphrase.as_str())?;
        let now_unix = HnsReadSystemClock.now_unix()?;
        let opened = open_wallet_direct_hns_peer_coordinator_with_floor(
            store.clone(),
            &account_config,
            peer_config,
            rollback_floor,
            now_unix,
        );
        let relocked = store.lock();
        match (opened, relocked) {
            (Ok(coordinator), Ok(())) => Ok(coordinator),
            (Err(error), _) => Err(error.into()),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    /// Open the direct coordinator from a locally verified, product-pinned
    /// genesis header acceleration stream. This is only valid for the
    /// pristine new-wallet birthday represented by `expected_height`; restored
    /// wallets must retain their actual discovery birthday.
    pub fn open_direct_hns_peer_coordinator_with_floor_and_genesis_bootstrap<I>(
        &mut self,
        database_key: &MobileDatabaseKey,
        peer_config: HnsDirectPeerConfig,
        rollback_floor: HnsLightFloor,
        expected_height: u32,
        expected_hash: [u8; 32],
        headers: I,
    ) -> Result<HnsDirectPeerCoordinator, MobileWalletError>
    where
        I: IntoIterator<Item = hns_header_consensus::Header>,
    {
        self.lock()?;
        let store = self.session.store.clone();
        let account_config = self.account_config.clone();
        let passphrase = database_key.store_passphrase();
        store.unlock(passphrase.as_str())?;
        let now_unix = HnsReadSystemClock.now_unix()?;
        let opened = open_wallet_direct_hns_peer_coordinator_with_floor_and_genesis_bootstrap(
            store.clone(),
            &account_config,
            peer_config,
            rollback_floor,
            expected_height,
            expected_hash,
            headers,
            now_unix,
        );
        let relocked = store.lock();
        match (opened, relocked) {
            (Ok(coordinator), Ok(())) => Ok(coordinator),
            (Err(error), _) => Err(error.into()),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    /// Consume this lifecycle-only controller and install a synchronized HNS
    /// read backend around the literal same process-local store/key authority.
    /// The controller is locked before its private session is replaced.
    pub fn into_hns_reads<B: HnsBackend>(
        self,
        backend: B,
    ) -> Result<MobileHnsReadController<B>, MobileWalletError> {
        self.into_hns_reads_with_clock(backend, HnsReadSystemClock)
    }

    /// Clock-injectable form of [`Self::into_hns_reads`] for deterministic
    /// products and tests.
    pub fn into_hns_reads_with_clock<B: HnsBackend, C: HnsClock>(
        mut self,
        backend: B,
        clock: C,
    ) -> Result<MobileHnsReadController<B, C>, MobileWalletError> {
        self.lock()?;
        let store = self.session.store.clone();
        let account_config = self.account_config.clone();
        let platform = self.platform;
        drop(self);
        MobileHnsReadController::from_locked_store(
            store,
            account_config,
            WalletHost::new_system(platform.into(), RESTART_GENERATION)?,
            backend,
            clock,
        )
    }

    /// Consume this lifecycle controller and activate the full same-store HNS
    /// value runtime. The database is unlocked only while the full runtime
    /// authenticates and persists its exact account policy, then it is relocked
    /// before the private value service is constructed.
    pub fn into_hns_value<B: HnsBackend>(
        self,
        database_key: &MobileDatabaseKey,
        backend: B,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<MobileHnsValueController<B>, MobileWalletError> {
        self.into_hns_value_with_clock(database_key, backend, HnsReadSystemClock, shakedex)
    }

    /// Consume this lifecycle controller into the full HNS value composition
    /// backed only by its already-opened wallet-owned direct peer coordinator.
    ///
    /// This path accepts no RPC URL, node credential, relay, or indexer. The
    /// coordinator must have been opened from this exact controller before it
    /// is consumed; the account check rejects a generic coordinator or one for
    /// another wallet even when its network happens to match. The returned
    /// wrapper retains that coordinator for the complete value-controller
    /// lifetime, so the embedded backend's header, filtered-block, mempool,
    /// fee, and broadcast boundaries cannot outlive their direct transport.
    pub fn into_wallet_owned_direct_hns_value(
        self,
        database_key: &MobileDatabaseKey,
        coordinator: HnsDirectPeerCoordinator,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<MobileDirectHnsValueController, MobileWalletError> {
        self.into_wallet_owned_direct_hns_value_with_clock(
            database_key,
            coordinator,
            HnsReadSystemClock,
            shakedex,
        )
    }

    /// Clock-injectable form of
    /// [`Self::into_wallet_owned_direct_hns_value`] for deterministic
    /// qualification fixtures.
    pub fn into_wallet_owned_direct_hns_value_with_clock<C: HnsClock>(
        self,
        database_key: &MobileDatabaseKey,
        coordinator: HnsDirectPeerCoordinator,
        clock: C,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<MobileDirectHnsValueController<C>, MobileWalletError> {
        coordinator.require_wallet_account_config(&self.account_config)?;
        let backend = coordinator.embedded_backend();
        let value = self.into_hns_value_with_clock(database_key, backend, clock, shakedex)?;
        Ok(MobileDirectHnsValueController { value, coordinator })
    }

    /// Consume this lifecycle controller into native HNS value and Shakedex
    /// runtimes that both use wallet-owned direct peers.
    ///
    /// This is the direct counterpart to
    /// [`Self::into_hns_value_with_wallet_owned_direct_shakedex`]. It fixes
    /// the marketplace policy to no marketplace fee and wallet-peer board
    /// transport, while retaining the same direct HNS coordinator for chain
    /// evidence, fee evidence, broadcasts, and later direct synchronization.
    pub fn into_wallet_owned_direct_hns_value_with_wallet_owned_direct_shakedex(
        self,
        database_key: &MobileDatabaseKey,
        coordinator: HnsDirectPeerCoordinator,
    ) -> Result<MobileDirectHnsValueController, MobileWalletError> {
        self.into_wallet_owned_direct_hns_value_with_wallet_owned_direct_shakedex_with_clock(
            database_key,
            coordinator,
            HnsReadSystemClock,
        )
    }

    /// Clock-injectable form of
    /// [`Self::into_wallet_owned_direct_hns_value_with_wallet_owned_direct_shakedex`]
    /// for deterministic qualification fixtures.
    pub fn into_wallet_owned_direct_hns_value_with_wallet_owned_direct_shakedex_with_clock<
        C: HnsClock,
    >(
        self,
        database_key: &MobileDatabaseKey,
        coordinator: HnsDirectPeerCoordinator,
        clock: C,
    ) -> Result<MobileDirectHnsValueController<C>, MobileWalletError> {
        self.into_wallet_owned_direct_hns_value_with_clock(
            database_key,
            coordinator,
            clock,
            Some(wallet_owned_direct_shakedex_config()),
        )
    }

    /// Activate the complete native HNS and Shakedex composition from an
    /// exact public relay-acceptance policy. This explicit legacy path is
    /// retained for deployments that choose a relay; the wallet-owned direct
    /// path below does not use or require it.
    /// Marketplace fees are disabled; neither Android nor iOS can supply a fee
    /// destination through this path.
    pub fn into_hns_value_with_shakedex_policy<B: HnsBackend>(
        self,
        database_key: &MobileDatabaseKey,
        backend: B,
        acceptance_policy_json: &[u8],
    ) -> Result<MobileHnsValueController<B>, MobileWalletError> {
        let shakedex = mobile_shakedex_config(acceptance_policy_json)?;
        self.into_hns_value(database_key, backend, Some(shakedex))
    }

    /// Activate the complete native HNS and Shakedex composition with the
    /// board replicated only over negotiated wallet-owned direct peers.
    ///
    /// No relay URL, endpoint key, HRM retrieval, HNSA delegation, or
    /// acceptance receipt is an authority input in this mode. Listings remain
    /// subject to the wallet's local chain and current-lock verification.
    pub fn into_hns_value_with_wallet_owned_direct_shakedex<B: HnsBackend>(
        self,
        database_key: &MobileDatabaseKey,
        backend: B,
    ) -> Result<MobileHnsValueController<B>, MobileWalletError> {
        self.into_hns_value(
            database_key,
            backend,
            Some(wallet_owned_direct_shakedex_config()),
        )
    }

    /// Clock-injectable value activation for deterministic installed products
    /// and qualification fixtures.
    pub fn into_hns_value_with_clock<B: HnsBackend, C: HnsClock>(
        mut self,
        database_key: &MobileDatabaseKey,
        backend: B,
        clock: C,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<MobileHnsValueController<B, C>, MobileWalletError> {
        self.lock()?;
        let store = self.session.store.clone();
        let platform = self.platform;
        let mut account_config = self.account_config.clone();
        account_config.value_operations_enabled = true;
        if shakedex.is_some() {
            account_config.settlement_enabled = true;
        }
        let require_shakedex = shakedex.is_some();
        drop(self);

        let passphrase = database_key.store_passphrase();
        store.unlock(passphrase.as_str())?;
        let opened =
            HnsWalletRuntime::open_shared(backend, store.clone(), account_config.clone(), clock);
        // Construction of the service and all subsequent lifecycle always
        // begin locked, including every full-runtime activation failure.
        store.lock()?;
        let runtime = opened?;
        let service = WalletService::new_persistent_hns_value(
            store.clone(),
            PersistentHnsValueConfig {
                runtime,
                account_label: MOBILE_ACCOUNT_LABEL.to_owned(),
                shakedex,
            },
        )?;
        let mut controller = MobileHnsValueController {
            session: MobileControllerSession::new(
                store,
                WalletHost::new_system(platform.into(), RESTART_GENERATION)?,
                service,
            ),
            account_config,
            pending: None,
            pending_denuo_hns_funding: None,
            pending_denuo_hns_settlement: None,
            known_names: Vec::new(),
        };
        controller.session.negotiate_value(require_shakedex)?;
        Ok(controller)
    }

    pub fn status(&mut self) -> Result<WalletRuntimeStatus, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::Status)? {
            WalletResponse::Status { status } => Ok(status),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn unlock(&mut self, database_key: &MobileDatabaseKey) -> Result<(), MobileWalletError> {
        // Rotate the private wallet session into a coherent locked posture
        // before testing a replacement key. WalletStore intentionally retains
        // its current key when a re-unlock fails, so skipping this step would
        // leave an already unlocked controller unlocked after a bad attempt.
        self.lock()?;
        let mut passphrase = database_key.store_passphrase();
        let passphrase = SecretString::new(std::mem::take(&mut *passphrase));
        match self
            .session
            .wallet_request(WalletRequest::Unlock { passphrase })?
        {
            WalletResponse::Unlocked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn lock(&mut self) -> Result<(), MobileWalletError> {
        match self.session.wallet_request(WalletRequest::Lock)? {
            WalletResponse::Locked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn accounts(&mut self) -> Result<Vec<AccountSummary>, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::ListAccounts)? {
            WalletResponse::Accounts { accounts } => Ok(accounts),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }
}

impl<B: HnsBackend> MobileHnsReadController<B, HnsReadSystemClock> {
    /// Open one existing native wallet around an injected HNS read backend and
    /// the production wall clock. Startup remains locked.
    pub fn open(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        backend: B,
    ) -> Result<Self, MobileWalletError> {
        Self::open_with_clock(path, database_key, platform, backend, HnsReadSystemClock)
    }
}

impl<B: HnsBackend, C: HnsClock> MobileHnsReadController<B, C> {
    /// Clock-injectable open path for deterministic products and tests. The
    /// database key authenticates discovery only and is not retained.
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        backend: B,
        clock: C,
    ) -> Result<Self, MobileWalletError> {
        let host = WalletHost::new_system(platform.into(), RESTART_GENERATION)?;
        let mut store = WalletStore::open(path)?;
        let passphrase = database_key.store_passphrase();
        store.unlock(passphrase.as_str())?;
        let mut accounts = store.wallet_accounts::<HnsAccountRecord>(MAX_MOBILE_WALLET_ACCOUNTS)?;
        if accounts.len() != 1 {
            store.lock();
            return Err(MobileWalletError::InvalidAccountSet);
        }
        let account_config = accounts
            .pop()
            .ok_or(MobileWalletError::InvalidAccountSet)?
            .value
            .config;
        store.validate_single_recovery_seed(account_config.wallet_id.as_bytes())?;
        let store = SharedWalletStore::new(store);
        store.lock()?;
        Self::from_locked_store(store, account_config, host, backend, clock)
    }

    fn from_locked_store(
        store: SharedWalletStore,
        account_config: HnsRuntimeConfig,
        host: MobileHost,
        backend: B,
        clock: C,
    ) -> Result<Self, MobileWalletError> {
        let selector = HnsExistingAccountSelector::new(store.clone(), account_config.clone())?;
        let runtime = HnsAccountReadRuntime::new(backend, clock, store.clone(), selector)?;
        let service = WalletService::new_persistent_hns_reads(
            store.clone(),
            PersistentHnsReadConfig {
                runtime,
                account_label: MOBILE_ACCOUNT_LABEL.to_owned(),
            },
        )?;
        let mut controller = Self {
            session: MobileControllerSession::new(store, host, service),
            account_config,
            known_names: Vec::new(),
        };
        controller.session.negotiate_non_value()?;
        Ok(controller)
    }

    pub const fn account_config(&self) -> &HnsRuntimeConfig {
        &self.account_config
    }

    pub fn status(&mut self) -> Result<WalletRuntimeStatus, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::Status)? {
            WalletResponse::Status { status } => Ok(status),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn unlock(&mut self, database_key: &MobileDatabaseKey) -> Result<(), MobileWalletError> {
        self.lock()?;
        let mut passphrase = database_key.store_passphrase();
        let passphrase = SecretString::new(std::mem::take(&mut *passphrase));
        match self
            .session
            .wallet_request(WalletRequest::Unlock { passphrase })?
        {
            WalletResponse::Unlocked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn lock(&mut self) -> Result<(), MobileWalletError> {
        self.known_names.clear();
        match self.session.wallet_request(WalletRequest::Lock)? {
            WalletResponse::Locked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn accounts(&mut self) -> Result<Vec<AccountSummary>, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::ListAccounts)? {
            WalletResponse::Accounts { accounts } => Ok(accounts),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    /// Perform one fresh bounded reconciliation and return only the minimized
    /// native read projection. The chain/mempool binding remains internal.
    ///
    /// A rejected read does not create a signing artifact, alter wallet value,
    /// or expose a partial projection. It therefore leaves the already
    /// unlocked session intact so the host can retry a transient direct-peer
    /// or snapshot-availability failure.
    pub fn synchronize(&mut self) -> Result<MobileHnsReadSnapshot, MobileWalletError> {
        self.synchronize_inner()
    }

    /// Return balance from one new bounded synchronization.
    pub fn balance(&mut self) -> Result<Amount, MobileWalletError> {
        Ok(self.synchronize()?.balance)
    }

    /// Return the receive target from one new bounded synchronization.
    pub fn receive_target(&mut self) -> Result<ReceiveTarget, MobileWalletError> {
        Ok(self.synchronize()?.receive_target)
    }

    /// Return the ordinary HNS payment receive target deterministically
    /// derived from the unlocked local wallet. This deliberately does not
    /// synchronize a node or peer and therefore must not be used as balance,
    /// history, name, or spend evidence.
    pub fn local_receive_target(&mut self) -> Result<ReceiveTarget, MobileWalletError> {
        let result = (|| {
            if self.session.failed {
                return Err(MobileWalletError::ControllerFailed);
            }
            let target = self
                .session
                .service
                .local_trusted_native_hns_receive_target()
                .map_err(mobile_service_failure)?;
            validate_mobile_hns_payment_receive_target(self.account_config.account_id, &target)?;
            Ok(target)
        })();
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    /// Return the dedicated `HnsName`, change-zero receive target from one new
    /// bounded synchronization. This target is never an ordinary HNS payment
    /// receive address.
    pub fn name_receive_target(&mut self) -> Result<HnsNameReceiveTarget, MobileWalletError> {
        Ok(self.synchronize()?.name_receive_target)
    }

    /// Return transaction history from one new bounded synchronization.
    pub fn transaction_history(&mut self) -> Result<Vec<TransactionSummary>, MobileWalletError> {
        Ok(self.synchronize()?.transaction_history)
    }

    /// Return minimized known-name summaries from one new bounded
    /// synchronization. No proof, resource, owner, or derivation material is
    /// returned.
    pub fn known_names(&mut self) -> Result<Vec<MobileHnsNameSummary>, MobileWalletError> {
        Ok(self.synchronize()?.known_names)
    }

    /// Return one page from the last successful authenticated synchronization
    /// without performing another node reconciliation.
    pub fn known_name_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<MobileHnsNamePage, MobileWalletError> {
        mobile_hns_name_page(&self.known_names, offset, limit)
    }

    /// Import one exact canonical Handshake name through the trusted native
    /// service boundary. The text is passed through byte-for-byte: this method
    /// never trims, lowercases, applies IDNA, normalizes Unicode, or removes a
    /// trailing dot. Only the minimized name summary is returned.
    pub fn import_name_exact_text(
        &mut self,
        name: &str,
    ) -> Result<MobileHnsNameSummary, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        match self
            .session
            .service
            .import_trusted_native_hns_name_exact_text(name)
        {
            Ok(summary) => mobile_native_hns_name_summary(summary),
            Err(failure) => {
                if failure.code != ServiceErrorCode::InvalidRequest {
                    self.session.lock_after_request_error();
                }
                Err(mobile_service_failure(failure))
            }
        }
    }

    /// Atomically import exact names and authenticate every proof before any
    /// row is committed. Synchronization is intentionally caller-controlled.
    pub fn import_names_exact_text(&mut self, names: &[&str]) -> Result<usize, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        match self
            .session
            .service
            .import_trusted_native_hns_names_exact_text(names)
        {
            Ok(imported) => Ok(imported.len()),
            Err(failure) => {
                if failure.code != ServiceErrorCode::InvalidRequest {
                    self.session.lock_after_request_error();
                }
                Err(mobile_service_failure(failure))
            }
        }
    }

    /// Return module status from one new bounded synchronization.
    pub fn module_status(&mut self) -> Result<SyncStatus, MobileWalletError> {
        Ok(self.synchronize()?.module_status)
    }

    fn synchronize_inner(&mut self) -> Result<MobileHnsReadSnapshot, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        let snapshot = self
            .session
            .service
            .synchronize_trusted_native_hns_reads()
            .map_err(mobile_service_failure)?;
        if snapshot.account_id != self.account_config.account_id
            || snapshot.balance.asset != WalletAsset::Hns
            || snapshot
                .transactions
                .iter()
                .any(|transaction| transaction.module != ModuleId::Handshake)
        {
            return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
        }
        validate_mobile_hns_receive_targets(
            snapshot.account_id,
            &snapshot.receive_target,
            &snapshot.name_receive_target,
        )?;
        let mut known_names = snapshot
            .known_names
            .iter()
            .map(mobile_hns_name_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique_names = BTreeSet::new();
        let mut unique_hashes = BTreeSet::new();
        if !known_names.iter().all(|name| {
            unique_names.insert(name.name.clone()) && unique_hashes.insert(name.name_hash.clone())
        }) {
            return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
        }
        known_names.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.name_hash.cmp(&right.name_hash))
        });
        let known_name_count = u32::try_from(known_names.len())
            .map_err(|_| MobileWalletError::Hns(HnsWalletError::HistoryLimit))?;
        self.known_names.clone_from(&known_names);
        known_names.truncate(MAX_MOBILE_HNS_NAME_PAGE);
        let known_names_complete = known_names.len() == self.known_names.len();
        let height = snapshot.binding.chain.tip.height;
        Ok(MobileHnsReadSnapshot {
            balance: snapshot.balance,
            receive_target: snapshot.receive_target,
            name_receive_target: snapshot.name_receive_target,
            transaction_history: snapshot.transactions,
            known_names,
            known_name_count,
            known_names_complete,
            module_status: SyncStatus {
                phase: SyncPhase::Ready,
                validated_height: height,
                scanned_height: height,
                target_height: Some(height),
                last_error: None,
            },
        })
    }
}

impl<B: HnsBackend> MobileHnsValueController<B, HnsReadSystemClock> {
    /// Open one existing installed wallet directly into its full HNS value
    /// composition. Startup remains locked and no pending approval survives a
    /// process restart.
    pub fn open(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        backend: B,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<Self, MobileWalletError> {
        Self::open_with_clock(
            path,
            database_key,
            platform,
            backend,
            HnsReadSystemClock,
            shakedex,
        )
    }
}

impl<B: HnsBackend, C: HnsClock> MobileHnsValueController<B, C> {
    /// Clock-injectable full-value open path. Exact account discovery first
    /// runs through the structural lifecycle controller, which grants no node
    /// or signing authority by itself.
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        database_key: &MobileDatabaseKey,
        platform: MobilePlatform,
        backend: B,
        clock: C,
        shakedex: Option<PersistentShakedexConfig>,
    ) -> Result<Self, MobileWalletError> {
        MobileWalletController::open(path, database_key, platform)?.into_hns_value_with_clock(
            database_key,
            backend,
            clock,
            shakedex,
        )
    }

    pub const fn account_config(&self) -> &HnsRuntimeConfig {
        &self.account_config
    }

    /// Construct the Bitcoin half of the installed direct wallet. The
    /// returned controller uses this exact encrypted store and recovery seed;
    /// it does not create a second mnemonic, node credential, or relay path.
    /// The caller activates it only after this HNS controller unlocks the
    /// shared store.
    pub fn direct_bitcoin_value_controller(
        &self,
        config: MobileBitcoinDirectConfig,
    ) -> Result<MobileBitcoinValueController, MobileWalletError> {
        MobileBitcoinValueController::new(
            self.session.store.clone(),
            self.account_config.clone(),
            config,
        )
    }

    /// Construct the adjacent direct HNS/BTC Denuo controller from this
    /// exact value runtime's encrypted store and selected HNS network. No
    /// peer, relay, indexer, price reporter, or caller-supplied policy enters
    /// this construction.
    pub fn direct_denuo_session_controller(
        &self,
    ) -> Result<MobileDenuoSessionController, MobileWalletError> {
        let hns_network =
            hns_wallet_hns::direct_denuo_network_binding(self.account_config.network)?;
        let (counterchain_network, counterchain_genesis) =
            MobileBitcoinDirectConfig::direct_denuo_counterchain(self.account_config.network);
        let network = hns_marketplace_protocol::NetworkBinding {
            hns_magic: hns_network.magic,
            hns_genesis: hns_network.genesis,
            counterchain: hns_marketplace_protocol::ChainId::BITCOIN,
            counterchain_network,
            counterchain_genesis,
        };
        let board_policy = DenuoDirectOfferBoardPolicy::new(network)?;
        let swap_policy = DenuoDirectSwapPolicy::new(board_policy)?;
        Ok(MobileDenuoSessionController::new(
            self.session.store.clone(),
            swap_policy,
            self.account_config.wallet_id,
        ))
    }

    pub fn status(&mut self) -> Result<WalletRuntimeStatus, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::Status)? {
            WalletResponse::Status { status } => Ok(status),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn unlock(&mut self, database_key: &MobileDatabaseKey) -> Result<(), MobileWalletError> {
        self.lock()?;
        let mut passphrase = database_key.store_passphrase();
        let passphrase = SecretString::new(std::mem::take(&mut *passphrase));
        match self
            .session
            .wallet_request(WalletRequest::Unlock { passphrase })?
        {
            WalletResponse::Unlocked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn lock(&mut self) -> Result<(), MobileWalletError> {
        self.known_names.clear();
        let discard = self.discard_pending_action();
        let discard_denuo = self.discard_pending_denuo_hns_funding();
        let discard_settlement = self.discard_pending_denuo_hns_settlement();
        let lock = match self.session.wallet_request(WalletRequest::Lock) {
            Ok(WalletResponse::Locked) => Ok(()),
            Ok(_) => Err(MobileWalletError::UnexpectedResponse),
            Err(error) => Err(error),
        };
        discard?;
        discard_denuo?;
        discard_settlement?;
        lock
    }

    pub fn accounts(&mut self) -> Result<Vec<AccountSummary>, MobileWalletError> {
        match self.session.wallet_request(WalletRequest::ListAccounts)? {
            WalletResponse::Accounts { accounts } => Ok(accounts),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    /// Perform one full reconciliation and return only the same minimized
    /// native projection used by the read controller.
    ///
    /// Reconciliation is a read-only operation. A failed synchronization does
    /// not grant a balance or authorization, and must not invalidate an
    /// otherwise valid unlocked session that may later prepare an explicit
    /// user-approved send.
    pub fn synchronize(&mut self) -> Result<MobileHnsReadSnapshot, MobileWalletError> {
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        self.synchronize_inner()
    }

    /// Re-submit exact, already approved HNS sends that the most recent
    /// authenticated snapshot classified as dropped. This never accepts raw
    /// transaction bytes or creates a replacement payment.
    pub fn rebroadcast_dropped_hns_sends(&mut self) -> Result<usize, MobileWalletError> {
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        self.session
            .service
            .rebroadcast_trusted_native_dropped_hns_sends()
            .map_err(mobile_service_failure)
    }

    /// Return the ordinary HNS payment receive target deterministically
    /// derived from the unlocked local wallet. No HNS, Bitcoin, Denuo, or
    /// clock operation occurs here; fund state and value operations still
    /// require a separately completed reconciliation.
    pub fn local_receive_target(&mut self) -> Result<ReceiveTarget, MobileWalletError> {
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        let result = (|| {
            if self.session.failed {
                return Err(MobileWalletError::ControllerFailed);
            }
            let target = self
                .session
                .service
                .local_trusted_native_hns_value_receive_target()
                .map_err(mobile_service_failure)?;
            validate_mobile_hns_payment_receive_target(self.account_config.account_id, &target)?;
            Ok(target)
        })();
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    fn synchronize_inner(&mut self) -> Result<MobileHnsReadSnapshot, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        let snapshot = self
            .session
            .service
            .synchronize_trusted_native_hns_value()
            .map_err(mobile_service_failure)?;
        let (snapshot, known_names) =
            mobile_hns_value_snapshot(self.account_config.account_id, snapshot)?;
        self.known_names = known_names;
        Ok(snapshot)
    }

    /// Return the exact clock authority used by the native HNS runtime after
    /// confirming that the same persisted account remains unlocked. Direct
    /// Denuo handshakes carry a timestamp, but an embedding application must
    /// never get to substitute its own clock for the value runtime's clock.
    fn trusted_wallet_peer_now_unix(&mut self) -> Result<u64, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        let result = (|| {
            if self.session.store.is_locked()? {
                return Err(MobileWalletError::Store(StoreError::Locked));
            }
            // This exact-account lookup also detects a separately changed
            // persisted account configuration before a peer sees a direct
            // Denuo handshake for the value controller.
            self.session
                .service
                .local_trusted_native_hns_value_receive_target()
                .map_err(mobile_service_failure)?;
            self.session
                .service
                .trusted_native_hns_value_now_unix()
                .map_err(mobile_service_failure)
        })();
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    /// Query the synchronized Denuo/Shakedex board or one local trade session
    /// without exposing generic provider JSON as an input surface.
    pub fn query_shakedex(
        &mut self,
        query: MobileShakedexQuery,
    ) -> Result<Value, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        let request_nonce = random_nonzero_request_nonce()?;
        let origin = Origin::parse(TRUSTED_NATIVE_HNS_VALUE_ORIGIN)
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        let (method, params) = query.into_provider_parts(self.account_config.account_id);
        let result = self
            .session
            .service
            .query_trusted_native_shakedex(ApprovedCall {
                origin,
                namespace: SelectedNamespace::Hns,
                method,
                params,
                request_nonce,
            })
            .map_err(mobile_service_failure);
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    /// Start one explicit wallet-owned direct board exchange. No hidden
    /// relay/network request occurs: the caller supplies the already
    /// negotiated direct peer and controls the socket lifetime.
    pub fn begin_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        // A direct peer is untrusted transport. A malformed packet, a closed
        // socket, or a timeout must discard that peer at the caller boundary,
        // never lock the wallet that independently owns chain and board state.
        self.session
            .service
            .begin_wallet_owned_direct_shakedex(peer)
            .map_err(mobile_service_failure)
    }

    /// Process an explicitly bounded number of messages from a wallet-owned
    /// direct board peer. The caller must schedule subsequent calls itself.
    pub fn synchronize_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
        message_limit: usize,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        self.session
            .service
            .synchronize_wallet_owned_direct_shakedex(peer, message_limit)
            .map_err(mobile_service_failure)
    }

    /// Service one name-market message classified by the direct peer
    /// multiplexer. This leaves cross-chain HNS/BTC envelopes for the separate
    /// durable direct-session controller.
    pub fn service_wallet_owned_direct_shakedex_message(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
        request_id: u64,
        message: hns_marketplace_protocol::NameMarketMessage,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        self.session
            .service
            .service_wallet_owned_direct_shakedex_message(peer, request_id, message)
            .map_err(mobile_service_failure)
    }

    /// Write one due local board publication to a negotiated wallet peer and
    /// record the resulting local transport observation.
    pub fn announce_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
    ) -> Result<Option<ObjectHash>, MobileWalletError> {
        self.session
            .service
            .announce_wallet_owned_direct_shakedex(peer)
            .map_err(mobile_service_failure)
    }

    /// Import one exact canonical Handshake name while retaining the full
    /// value composition. The input is never normalized or rewritten.
    pub fn import_name_exact_text(
        &mut self,
        name: &str,
    ) -> Result<MobileHnsNameSummary, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        match self
            .session
            .service
            .import_trusted_native_hns_value_name_exact_text(name)
        {
            Ok(summary) => mobile_native_hns_name_summary(summary),
            Err(failure) => {
                if failure.code != ServiceErrorCode::InvalidRequest {
                    self.session.lock_after_request_error();
                }
                Err(mobile_service_failure(failure))
            }
        }
    }

    /// Atomically import exact names after one reconciliation and defer the
    /// caller's one desired post-import snapshot refresh.
    pub fn import_names_exact_text(&mut self, names: &[&str]) -> Result<usize, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        match self
            .session
            .service
            .import_trusted_native_hns_value_names_exact_text(names)
        {
            Ok(imported) => Ok(imported.len()),
            Err(failure) => {
                if failure.code != ServiceErrorCode::InvalidRequest {
                    self.session.lock_after_request_error();
                }
                Err(mobile_service_failure(failure))
            }
        }
    }

    /// Return one page from the last successful authenticated synchronization
    /// without reconciling or loading the full name set into the host UI.
    pub fn known_name_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<MobileHnsNamePage, MobileWalletError> {
        mobile_hns_name_page(&self.known_names, offset, limit)
    }

    /// Prepare one exact value action and return the only summary the installed
    /// UI may approve. A second action is rejected until the first is approved,
    /// rejected, expired, or the controller is locked.
    pub fn prepare_value_action(
        &mut self,
        intent: MobileHnsValueIntent,
    ) -> Result<MobileHnsValueApproval, MobileWalletError> {
        if self.session.failed {
            return Err(MobileWalletError::ControllerFailed);
        }
        if self.pending.is_some() {
            return Err(MobileWalletError::ValueActionPending);
        }
        let now_unix = self
            .session
            .service
            .trusted_native_hns_value_now_unix()
            .map_err(mobile_service_failure)?;
        let expires_at_unix = now_unix
            .checked_add(APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidValueAction)?;
        let action_token = random_nonzero_bytes()?;
        let approval_id = ApprovalId::new(random_nonzero_bytes()?);
        let request_nonce = random_nonzero_request_nonce()?;
        let origin = Origin::parse(TRUSTED_NATIVE_HNS_VALUE_ORIGIN)
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        let (kind, method, params) = intent.into_provider_parts(self.account_config.account_id);
        let call = ApprovedCall {
            origin,
            namespace: SelectedNamespace::Hns,
            method,
            params,
            request_nonce,
        };
        let action = self
            .session
            .service
            .prepare_trusted_native_hns_value_action(approval_id, kind, call, expires_at_unix)
            .map_err(mobile_service_failure)?;
        let summary = action.summary().clone();
        let expires_at_unix = action.expires_at_unix();
        self.pending = Some(PendingMobileHnsValueAction {
            action_token,
            action,
        });
        Ok(MobileHnsValueApproval {
            action_token: lowercase_hex(&action_token),
            expires_at_unix,
            summary,
        })
    }

    /// Consume the process-local token exactly once, then re-prepare and
    /// execute the approval-bound action through the HNS runtime.
    pub fn approve_value_action(&mut self, action_token: &str) -> Result<Value, MobileWalletError> {
        self.require_pending_token(action_token)?;
        let pending = self
            .pending
            .take()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        let result = self
            .session
            .service
            .execute_trusted_native_hns_value_action(pending.action)
            .map_err(mobile_service_failure);
        if result
            .as_ref()
            .err()
            .is_some_and(|error| !hns_send_pre_broadcast_retry_required(error))
        {
            self.session.lock_after_request_error();
        }
        result
    }

    /// Reject one pending action and remove its encrypted runtime approval.
    pub fn reject_value_action(&mut self, action_token: &str) -> Result<(), MobileWalletError> {
        self.require_pending_token(action_token)?;
        let result = self.discard_pending_action();
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    pub fn prepare_denuo_hns_funding(
        &mut self,
        permit: MobileDenuoHnsFundingPermit,
        maximum_fee_dollarydoos: u64,
    ) -> Result<MobileDenuoHnsFundingApproval, MobileWalletError> {
        if self.pending.is_some()
            || self.pending_denuo_hns_funding.is_some()
            || self.pending_denuo_hns_settlement.is_some()
        {
            return Err(MobileWalletError::ValueActionPending);
        }
        if maximum_fee_dollarydoos == 0
            || maximum_fee_dollarydoos > permit.hns_fee_reserve_dollarydoos()
        {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let hello = permit.hello();
        let binding = hello
            .build_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Received,
                hello.maker_settlement_public_key,
                hello.taker_settlement_public_key,
            )
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        if binding.descriptor_hash != hello.received_lock_commitment
            || binding.descriptor.refund_public_key != permit.settlement_key().public_key()
        {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let session_id = hns_wallet_types::SessionId::new(hello.swap_session_id);
        let maximum_fee = BaseUnits::new(u128::from(maximum_fee_dollarydoos));
        let prepared = self
            .session
            .service
            .prepare_trusted_native_hns_htlc_lock(session_id, binding.descriptor, maximum_fee)
            .map_err(mobile_service_failure)?;
        let transaction_id = self
            .session
            .service
            .trusted_native_hns_settlement_transaction_id(&prepared.0)
            .map_err(mobile_service_failure)?;
        let amount_dollarydoos = u64::try_from(hello.received_amount.get())
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        let fee_dollarydoos = u64::try_from(prepared.0.fee.get())
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        let action_token = random_nonzero_bytes()?;
        let approval = MobileDenuoHnsFundingApproval {
            action_token: lowercase_hex(&action_token),
            session_id: lowercase_hex(session_id.as_bytes()),
            transaction_id: lowercase_hex(transaction_id.as_bytes()),
            amount_dollarydoos,
            fee_dollarydoos,
            maximum_fee_dollarydoos,
            refund_at_unix: hello.received_refund_deadline.value,
            expires_at_unix: prepared.0.expires_at_unix,
        };
        self.pending_denuo_hns_funding = Some(PendingMobileDenuoHnsFunding {
            action_token,
            session_id,
            prepared,
            maximum_fee,
        });
        Ok(approval)
    }

    pub fn approve_denuo_hns_funding(
        &mut self,
        action_token: &str,
    ) -> Result<MobileDenuoHnsFundingReceipt, MobileWalletError> {
        let pending = self
            .pending_denuo_hns_funding
            .take()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        if !mobile_action_token_matches(&pending.action_token, action_token) {
            self.pending_denuo_hns_funding = Some(pending);
            return Err(MobileWalletError::InvalidActionToken);
        }
        if pending.prepared.0.fee > pending.maximum_fee {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let receipt = self
            .session
            .service
            .broadcast_trusted_native_hns_settlement(&pending.prepared.0)
            .map_err(mobile_service_failure)?;
        Ok(MobileDenuoHnsFundingReceipt {
            session_id: lowercase_hex(pending.session_id.as_bytes()),
            transaction_id: lowercase_hex(receipt.txid.as_bytes()),
            accepted_at_unix: receipt.accepted_at_unix,
        })
    }

    pub fn reject_denuo_hns_funding(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_denuo_hns_funding
            .take()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        if !mobile_action_token_matches(&pending.action_token, action_token) {
            self.pending_denuo_hns_funding = Some(pending);
            return Err(MobileWalletError::InvalidActionToken);
        }
        self.session
            .service
            .cancel_trusted_native_hns_settlement(&pending.prepared.0)
            .map_err(mobile_service_failure)
    }

    pub fn prepare_denuo_hns_settlement(
        &mut self,
        mut permit: MobileDenuoHnsSettlementPermit,
        maximum_fee_dollarydoos: u64,
    ) -> Result<MobileDenuoHnsSettlementApproval, MobileWalletError> {
        if self.pending.is_some()
            || self.pending_denuo_hns_funding.is_some()
            || self.pending_denuo_hns_settlement.is_some()
        {
            return Err(MobileWalletError::ValueActionPending);
        }
        if maximum_fee_dollarydoos == 0 || maximum_fee_dollarydoos > permit.fee_reserve() {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let hello = permit.hello().clone();
        let binding = hello
            .build_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Received,
                hello.maker_settlement_public_key,
                hello.taker_settlement_public_key,
            )
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        if binding.descriptor_hash != hello.received_lock_commitment {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let expected_key = match permit.action() {
            MobileDenuoSettlementAction::Redeem => binding.descriptor.receiver_public_key,
            MobileDenuoSettlementAction::Refund => binding.descriptor.refund_public_key,
        };
        if expected_key != permit.settlement_key().public_key() {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let session_id = hns_wallet_types::SessionId::new(hello.swap_session_id);
        let lock = self
            .session
            .service
            .verify_trusted_native_persisted_hns_htlc_lock(
                session_id,
                binding.descriptor,
                hello.received_minimum_confirmations,
            )
            .map_err(mobile_service_failure)?
            .ok_or(MobileWalletError::InvalidValueAction)?;
        let maximum_fee = BaseUnits::new(u128::from(maximum_fee_dollarydoos));
        let action = permit.action();
        let prepared = match action {
            MobileDenuoSettlementAction::Redeem => self
                .session
                .service
                .prepare_trusted_native_hns_htlc_redeem(
                    session_id,
                    binding.descriptor,
                    lock,
                    permit
                        .take_preimage()
                        .ok_or(MobileWalletError::InvalidValueAction)?,
                    maximum_fee,
                    permit.settlement_key(),
                )
                .map(|prepared| prepared.0),
            MobileDenuoSettlementAction::Refund => self
                .session
                .service
                .prepare_trusted_native_hns_htlc_refund(
                    session_id,
                    binding.descriptor,
                    lock,
                    maximum_fee,
                    permit.settlement_key(),
                )
                .map(|prepared| prepared.0),
        }
        .map_err(mobile_service_failure)?;
        let transaction_id = self
            .session
            .service
            .trusted_native_hns_settlement_transaction_id(&prepared)
            .map_err(mobile_service_failure)?;
        let input_amount_dollarydoos = u64::try_from(hello.received_amount.get())
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        let fee_dollarydoos =
            u64::try_from(prepared.fee.get()).map_err(|_| MobileWalletError::InvalidValueAction)?;
        let output_amount_dollarydoos = input_amount_dollarydoos
            .checked_sub(fee_dollarydoos)
            .ok_or(MobileWalletError::InvalidValueAction)?;
        let action_token = random_nonzero_bytes()?;
        let approval = MobileDenuoHnsSettlementApproval {
            action_token: lowercase_hex(&action_token),
            session_id: lowercase_hex(session_id.as_bytes()),
            action,
            transaction_id: lowercase_hex(transaction_id.as_bytes()),
            input_amount_dollarydoos,
            output_amount_dollarydoos,
            fee_dollarydoos,
            maximum_fee_dollarydoos,
            expires_at_unix: prepared.expires_at_unix,
        };
        self.pending_denuo_hns_settlement = Some(PendingMobileDenuoHnsSettlement {
            action_token,
            session_id,
            action,
            prepared,
            maximum_fee,
        });
        Ok(approval)
    }

    pub fn approve_denuo_hns_settlement(
        &mut self,
        action_token: &str,
    ) -> Result<MobileDenuoHnsSettlementReceipt, MobileWalletError> {
        let pending = self
            .pending_denuo_hns_settlement
            .take()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        if !mobile_action_token_matches(&pending.action_token, action_token) {
            self.pending_denuo_hns_settlement = Some(pending);
            return Err(MobileWalletError::InvalidActionToken);
        }
        if pending.prepared.fee > pending.maximum_fee {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let receipt = self
            .session
            .service
            .broadcast_trusted_native_hns_settlement(&pending.prepared)
            .map_err(mobile_service_failure)?;
        Ok(MobileDenuoHnsSettlementReceipt {
            session_id: lowercase_hex(pending.session_id.as_bytes()),
            action: pending.action,
            transaction_id: lowercase_hex(receipt.txid.as_bytes()),
            accepted_at_unix: receipt.accepted_at_unix,
        })
    }

    pub fn reject_denuo_hns_settlement(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_denuo_hns_settlement
            .take()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        if !mobile_action_token_matches(&pending.action_token, action_token) {
            self.pending_denuo_hns_settlement = Some(pending);
            return Err(MobileWalletError::InvalidActionToken);
        }
        self.session
            .service
            .cancel_trusted_native_hns_settlement(&pending.prepared)
            .map_err(mobile_service_failure)
    }

    pub fn resume_approved_denuo_hns_settlements(&self) -> Result<usize, MobileWalletError> {
        self.session
            .service
            .rebroadcast_trusted_native_hns_settlements()
            .map_err(mobile_service_failure)
    }

    pub fn verified_denuo_hns_funding(
        &self,
        permit: MobileDenuoHnsVerificationPermit,
    ) -> Result<Option<hns_wallet_chain_api::VerifiedLock>, MobileWalletError> {
        let hello = permit.hello();
        let binding = hello
            .build_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Received,
                hello.maker_settlement_public_key,
                hello.taker_settlement_public_key,
            )
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        if binding.descriptor_hash != hello.received_lock_commitment {
            return Err(MobileWalletError::InvalidValueAction);
        }
        self.session
            .service
            .verify_trusted_native_persisted_hns_htlc_lock(
                hns_wallet_types::SessionId::new(hello.swap_session_id),
                binding.descriptor,
                hello.received_minimum_confirmations,
            )
            .map_err(mobile_service_failure)
    }

    pub fn verified_denuo_hns_spend(
        &self,
        permit: MobileDenuoHnsVerificationPermit,
    ) -> Result<Option<hns_wallet_hns::VerifiedNativeHtlcSpend>, MobileWalletError> {
        let hello = permit.hello();
        let binding = hello
            .build_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Received,
                hello.maker_settlement_public_key,
                hello.taker_settlement_public_key,
            )
            .map_err(|_| MobileWalletError::InvalidValueAction)?;
        if binding.descriptor_hash != hello.received_lock_commitment {
            return Err(MobileWalletError::InvalidValueAction);
        }
        let session_id = hns_wallet_types::SessionId::new(hello.swap_session_id);
        let Some(lock) = self
            .session
            .service
            .verify_trusted_native_persisted_hns_htlc_lock(
                session_id,
                binding.descriptor,
                hello.received_minimum_confirmations,
            )
            .map_err(mobile_service_failure)?
        else {
            return Ok(None);
        };
        self.session
            .service
            .verify_trusted_native_hns_htlc_spend(session_id, binding.descriptor, lock)
            .map_err(mobile_service_failure)
    }

    fn require_pending_token(&self, action_token: &str) -> Result<(), MobileWalletError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(MobileWalletError::NoPendingValueAction)?;
        if !mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidActionToken);
        }
        Ok(())
    }

    fn discard_pending_action(&mut self) -> Result<(), MobileWalletError> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        self.session
            .service
            .discard_trusted_native_hns_value_action(pending.action)
            .map_err(mobile_service_failure)
    }

    fn discard_pending_denuo_hns_funding(&mut self) -> Result<(), MobileWalletError> {
        let Some(pending) = self.pending_denuo_hns_funding.take() else {
            return Ok(());
        };
        self.session
            .service
            .cancel_trusted_native_hns_settlement(&pending.prepared.0)
            .map_err(mobile_service_failure)
    }

    fn discard_pending_denuo_hns_settlement(&mut self) -> Result<(), MobileWalletError> {
        let Some(pending) = self.pending_denuo_hns_settlement.take() else {
            return Ok(());
        };
        self.session
            .service
            .cancel_trusted_native_hns_settlement(&pending.prepared)
            .map_err(mobile_service_failure)
    }
}

impl<C: HnsClock> MobileDirectHnsValueController<C> {
    /// The retained direct-peer coordinator. Callers schedule its bounded
    /// connection, header, filtered-block, proof, and mempool operations only
    /// while the adjacent value controller is unlocked.
    #[must_use]
    pub const fn coordinator(&self) -> &HnsDirectPeerCoordinator {
        &self.coordinator
    }

    /// Resolve configured peers and establish as many bounded direct HNS
    /// connections as are presently available. The peer handshakes use the
    /// value runtime's trusted clock; caller code retains control over when to
    /// retry after a temporary network failure.
    pub fn connect_wallet_owned_direct_hns_peers(
        &mut self,
    ) -> Result<Vec<ConnectedHnsPeer>, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .connect_available(now_unix)
            .map_err(Into::into)
    }

    /// Run one bounded, multi-peer direct HNS header round with the exact
    /// runtime clock. A pending/underfilled result is retained by the
    /// coordinator for the caller's next scheduled tick; it never becomes a
    /// wallet value authorization.
    pub fn synchronize_wallet_owned_direct_hns_headers(
        &mut self,
    ) -> Result<HnsHeaderRoundProgress, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .synchronize_headers_once(now_unix)
            .map_err(Into::into)
    }

    /// Scan at most `max_blocks` authenticated direct-peer block heights with
    /// the wallet's current encrypted watch set. The host cannot substitute a
    /// timestamp, script set, or block evidence through this façade.
    pub fn scan_wallet_owned_direct_hns_blocks(
        &mut self,
        max_blocks: u32,
    ) -> Result<HnsBlockScanProgress, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .scan_wallet_blocks(max_blocks, now_unix)
            .map_err(Into::into)
    }

    /// Refresh the bounded relevant-mempool view from the direct-peer quorum
    /// using the value runtime's clock. The return value counts only locally
    /// admitted transactions; it is not a confirmation or broadcast receipt.
    pub fn refresh_wallet_owned_direct_hns_mempool(&mut self) -> Result<usize, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .refresh_mempool(now_unix)
            .map_err(Into::into)
    }

    /// Extend the authenticated direct restore watch set by one bounded
    /// frontier. The active account configuration and time are both obtained
    /// from the exact unlocked value runtime rather than caller input.
    pub fn extend_wallet_owned_direct_hns_restore_watch_set(
        &mut self,
    ) -> Result<bool, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .extend_wallet_restore_watch_set(now_unix)
            .map_err(Into::into)
    }

    /// Bind one wallet-owned direct Denuo listener with the same network,
    /// address policy, socket deadlines, and explicit peer configuration as
    /// the embedded HNS backend.  Binding the socket does not unlock the
    /// wallet or service a board exchange.
    pub fn bind_wallet_owned_direct_denuo_listener(
        &self,
        address: SocketAddr,
    ) -> Result<MobileDirectDenuoListener, MobileWalletError> {
        self.coordinator
            .bind_denuo_listener(address)
            .map(|listener| MobileDirectDenuoListener { listener })
            .map_err(Into::into)
    }

    /// Establish a direct Denuo peer using the exact policy retained by this
    /// controller and the trusted clock of its unlocked value runtime.
    ///
    /// `local_height` is only the standard peer-handshake height hint. It is
    /// not chain evidence and cannot authorize a wallet action; all value
    /// operations continue to require a later synchronized runtime view.
    pub fn connect_wallet_owned_direct_denuo_peer(
        &mut self,
        address: SocketAddr,
        local_height: u32,
    ) -> Result<HnsDirectDenuoPeer, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        self.coordinator
            .connect_denuo_peer(address, local_height, now_unix)
            .map_err(Into::into)
    }

    /// Accept at most one Denuo peer from a listener created by this direct
    /// controller.  A return value of `Ok(None)` means no TCP connection is
    /// pending.  Handshake time comes from the value runtime rather than a
    /// caller-provided wall clock.
    pub fn accept_wallet_owned_direct_denuo_peer(
        &mut self,
        listener: &MobileDirectDenuoListener,
        local_height: u32,
    ) -> Result<Option<HnsDirectDenuoPeer>, MobileWalletError> {
        let now_unix = self.value.trusted_wallet_peer_now_unix()?;
        listener
            .listener
            .accept_next(local_height, now_unix)
            .map_err(Into::into)
    }

    /// Start one explicitly scheduled wallet-peer Shakedex board exchange.
    /// The supplied peer must have been obtained through this controller's
    /// connect/accept path; the board remains independently authenticated and
    /// no relay or provider transport is involved.
    pub fn begin_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        self.value.begin_wallet_owned_direct_shakedex(peer)
    }

    /// Process one bounded batch from an already negotiated wallet peer.
    pub fn synchronize_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
        message_limit: usize,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        self.value
            .synchronize_wallet_owned_direct_shakedex(peer, message_limit)
    }

    /// Service one already classified name-market message from a negotiated
    /// wallet peer. Cross-chain direct-session messages remain owned by the
    /// adjacent direct HNS/BTC session controller.
    pub fn service_wallet_owned_direct_shakedex_message(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
        request_id: u64,
        message: hns_marketplace_protocol::NameMarketMessage,
    ) -> Result<DirectDenuoBoardSyncReport, MobileWalletError> {
        self.value
            .service_wallet_owned_direct_shakedex_message(peer, request_id, message)
    }

    /// Write one due local board publication to an already negotiated wallet
    /// peer and persist its local transport observation.
    pub fn announce_wallet_owned_direct_shakedex(
        &mut self,
        peer: &mut HnsDirectDenuoPeer,
    ) -> Result<Option<ObjectHash>, MobileWalletError> {
        self.value.announce_wallet_owned_direct_shakedex(peer)
    }

    /// The native value controller sharing the coordinator's exact embedded
    /// backend. It retains the existing closed approval and value-action
    /// vocabulary; no raw key, seed, or generic provider interface is added.
    pub fn value_controller(&mut self) -> &mut MobileHnsValueController<EmbeddedHnsBackend, C> {
        &mut self.value
    }
}

impl MobileHnsValueIntent {
    fn into_provider_parts(self, account: AccountId) -> (ApprovalKind, ProviderMethod, Value) {
        let market_account = lowercase_hex(account.as_bytes());
        match self {
            Self::Send {
                recipient,
                amount,
                maximum_fee,
            } => (
                ApprovalKind::Send,
                ProviderMethod::HnsSend,
                json!({
                    "account": account,
                    "recipient": recipient,
                    "amount": amount,
                    "maximumFee": maximum_fee,
                }),
            ),
            Self::TransferName {
                name,
                recipient,
                maximum_fee,
            } => (
                ApprovalKind::NameTransfer,
                ProviderMethod::HnsTransferName,
                json!({
                    "account": account,
                    "name": name,
                    "recipient": recipient,
                    "maximumFee": maximum_fee,
                }),
            ),
            Self::FinalizeName {
                name,
                expected_recipient,
                maximum_fee,
            } => (
                ApprovalKind::NameFinalize,
                ProviderMethod::HnsFinalizeName,
                json!({
                    "account": account,
                    "name": name,
                    "expectedRecipient": expected_recipient,
                    "maximumFee": maximum_fee,
                }),
            ),
            Self::CreateFixedPriceOffer {
                name,
                price,
                maximum_fee,
                listing_lifetime_seconds,
            } => (
                ApprovalKind::NameMarketOffer,
                ProviderMethod::NameMarketCreateFixedPriceOffer,
                json!({
                    "account": market_account,
                    "name": name,
                    "price": price,
                    "maximumFee": maximum_fee,
                    "listingLifetimeSeconds": listing_lifetime_seconds,
                }),
            ),
            Self::CancelOffer { seller_session_id } => (
                ApprovalKind::NameMarketOffer,
                ProviderMethod::NameMarketCancelOffer,
                json!({
                    "account": market_account,
                    "sellerSessionId": seller_session_id,
                }),
            ),
            Self::AcceptOffer {
                listing_id,
                maximum_fee,
            } => (
                ApprovalKind::NameMarketPurchase,
                ProviderMethod::NameMarketAcceptOffer,
                json!({
                    "account": market_account,
                    "listingId": listing_id,
                    "maximumFee": maximum_fee,
                }),
            ),
            Self::FinalizePurchase {
                session_id,
                maximum_fee,
            } => (
                ApprovalKind::NameMarketPurchase,
                ProviderMethod::NameMarketFinalizePurchase,
                json!({
                    "account": market_account,
                    "sessionId": session_id,
                    "maximumFee": maximum_fee,
                }),
            ),
            Self::RecoverName {
                seller_session_id,
                maximum_fee,
            } => (
                ApprovalKind::NameMarketOffer,
                ProviderMethod::NameMarketRecoverName,
                json!({
                    "account": market_account,
                    "sellerSessionId": seller_session_id,
                    "maximumFee": maximum_fee,
                }),
            ),
        }
    }
}

impl MobileShakedexQuery {
    fn into_provider_parts(self, account: AccountId) -> (ProviderMethod, Value) {
        match self {
            Self::ListOffers { cursor, limit } => (
                ProviderMethod::NameMarketListOffers,
                json!({
                    "cursor": cursor,
                    "limit": limit,
                }),
            ),
            Self::GetSession { session_id } => (
                ProviderMethod::NameMarketGetSession,
                json!({
                    "account": lowercase_hex(account.as_bytes()),
                    "sessionId": session_id,
                }),
            ),
        }
    }
}

fn mobile_hns_value_snapshot(
    expected_account: AccountId,
    snapshot: NativeHnsValueSnapshot,
) -> Result<(MobileHnsReadSnapshot, Vec<MobileHnsNameSummary>), MobileWalletError> {
    if snapshot.account_id != expected_account
        || snapshot.balance.asset != WalletAsset::Hns
        || snapshot
            .transactions
            .iter()
            .any(|transaction| transaction.module != ModuleId::Handshake)
        || snapshot.module_status.phase != SyncPhase::Ready
        || snapshot.module_status.validated_height != snapshot.module_status.scanned_height
        || snapshot.module_status.target_height != Some(snapshot.module_status.validated_height)
        || snapshot.module_status.last_error.is_some()
    {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    validate_mobile_hns_receive_targets(
        expected_account,
        &snapshot.receive_target,
        &snapshot.name_receive_target,
    )?;
    if snapshot.receive_target.display == snapshot.name_receive_target.display {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    let mut known_names = snapshot
        .known_names
        .into_iter()
        .map(mobile_native_hns_name_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let mut unique_names = BTreeSet::new();
    let mut unique_hashes = BTreeSet::new();
    if !known_names.iter().all(|name| {
        unique_names.insert(name.name.clone()) && unique_hashes.insert(name.name_hash.clone())
    }) {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    known_names.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.name_hash.cmp(&right.name_hash))
    });
    let known_name_count = u32::try_from(known_names.len())
        .map_err(|_| MobileWalletError::Hns(HnsWalletError::HistoryLimit))?;
    let mut first_page = known_names.clone();
    first_page.truncate(MAX_MOBILE_HNS_NAME_PAGE);
    let known_names_complete = first_page.len() == known_names.len();
    Ok((
        MobileHnsReadSnapshot {
            balance: snapshot.balance,
            receive_target: snapshot.receive_target,
            name_receive_target: snapshot.name_receive_target,
            transaction_history: snapshot.transactions,
            known_names: first_page,
            known_name_count,
            known_names_complete,
            module_status: snapshot.module_status,
        },
        known_names,
    ))
}

fn mobile_hns_name_page(
    names: &[MobileHnsNameSummary],
    offset: usize,
    limit: usize,
) -> Result<MobileHnsNamePage, MobileWalletError> {
    if limit == 0 || limit > MAX_MOBILE_HNS_NAME_PAGE || offset > names.len() {
        return Err(MobileWalletError::Hns(HnsWalletError::HistoryLimit));
    }
    let end = offset.saturating_add(limit).min(names.len());
    Ok(MobileHnsNamePage {
        offset: u32::try_from(offset)
            .map_err(|_| MobileWalletError::Hns(HnsWalletError::HistoryLimit))?,
        total: u32::try_from(names.len())
            .map_err(|_| MobileWalletError::Hns(HnsWalletError::HistoryLimit))?,
        names: names[offset..end].to_vec(),
        has_more: end < names.len(),
    })
}

fn random_nonzero_bytes<const N: usize>() -> Result<[u8; N], MobileWalletError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; N];
        getrandom::fill(&mut bytes).map_err(|_| MobileWalletError::Randomness)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(MobileWalletError::Randomness)
}

fn random_nonzero_request_nonce() -> Result<u64, MobileWalletError> {
    Ok(u64::from_be_bytes(random_nonzero_bytes()?))
}

fn mobile_action_token_matches(
    expected: &[u8; MOBILE_ACTION_TOKEN_BYTES],
    candidate: &str,
) -> bool {
    if candidate.len() != MOBILE_ACTION_TOKEN_BYTES * 2 {
        return false;
    }
    let mut difference = 0_u8;
    for (index, pair) in candidate.as_bytes().chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let Some(high) = decode(pair[0]) else {
            return false;
        };
        let Some(low) = decode(pair[1]) else {
            return false;
        };
        difference |= expected[index] ^ ((high << 4) | low);
    }
    difference == 0
}

fn validate_mobile_hns_receive_targets(
    expected_account: AccountId,
    receive_target: &ReceiveTarget,
    name_receive_target: &HnsNameReceiveTarget,
) -> Result<(), MobileWalletError> {
    validate_mobile_hns_payment_receive_target(expected_account, receive_target)?;
    if name_receive_target.module != ModuleId::Handshake
        || name_receive_target.account != expected_account
        || name_receive_target.validate().is_err()
        || !name_receive_target
            .display
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    Ok(())
}

fn validate_mobile_hns_payment_receive_target(
    expected_account: AccountId,
    receive_target: &ReceiveTarget,
) -> Result<(), MobileWalletError> {
    if receive_target.module != ModuleId::Handshake
        || receive_target.account != expected_account
        || receive_target.validate().is_err()
        || !receive_target
            .display
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    Ok(())
}

fn mobile_hns_name_summary(name: &KnownName) -> Result<MobileHnsNameSummary, MobileWalletError> {
    if name.proof_height > MAX_JAVASCRIPT_SAFE_INTEGER {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    let display = String::from_utf8(name.name.clone())
        .map_err(|_| MobileWalletError::Hns(HnsWalletError::InvalidEvidence))?;
    let name_hash = lowercase_hex(&name.name_hash);
    HnsNameDisclosure {
        name: display.clone(),
        name_hash: name_hash.clone(),
    }
    .validate()?;
    let resource_status = match name.resource_status {
        NameResourceStatus::UnavailableCanonicalBinding => {
            MobileHnsNameResourceStatus::UnavailableCanonicalBinding
        }
        NameResourceStatus::NoCurrentState => MobileHnsNameResourceStatus::NoCurrentState,
        NameResourceStatus::Empty => MobileHnsNameResourceStatus::Empty,
        NameResourceStatus::CanonicalDecoded => MobileHnsNameResourceStatus::CanonicalDecoded,
        NameResourceStatus::CanonicalOpaque => MobileHnsNameResourceStatus::CanonicalOpaque,
    };
    let ownership_status = match &name.ownership_status {
        NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable => {
            MobileHnsNameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable
        }
        NameOwnershipStatus::WalletContextUnavailable => {
            MobileHnsNameOwnershipStatus::WalletContextUnavailable
        }
        NameOwnershipStatus::NoCurrentOwner => MobileHnsNameOwnershipStatus::NoCurrentOwner,
        NameOwnershipStatus::NotWalletOwned => MobileHnsNameOwnershipStatus::NotWalletOwned,
        NameOwnershipStatus::WalletOwned { .. } => MobileHnsNameOwnershipStatus::WalletOwned,
        NameOwnershipStatus::IncomingTransfer { .. } => {
            MobileHnsNameOwnershipStatus::IncomingTransfer
        }
        NameOwnershipStatus::OutgoingTransfer { .. } => {
            MobileHnsNameOwnershipStatus::OutgoingTransfer
        }
    };
    let (registered, expired) = name
        .canonical_current_state
        .as_ref()
        .map_or((None, None), |state| {
            (Some(state.registered), Some(state.expired))
        });
    Ok(MobileHnsNameSummary {
        name: display,
        name_hash,
        proof_height: name.proof_height,
        resource_status,
        ownership_status,
        registered,
        expired,
    })
}

fn mobile_native_hns_name_summary(
    name: NativeHnsNameSummary,
) -> Result<MobileHnsNameSummary, MobileWalletError> {
    let resource_status = match name.resource_status {
        NativeHnsNameResourceStatus::UnavailableCanonicalBinding => {
            MobileHnsNameResourceStatus::UnavailableCanonicalBinding
        }
        NativeHnsNameResourceStatus::NoCurrentState => MobileHnsNameResourceStatus::NoCurrentState,
        NativeHnsNameResourceStatus::Empty => MobileHnsNameResourceStatus::Empty,
        NativeHnsNameResourceStatus::CanonicalDecoded => {
            MobileHnsNameResourceStatus::CanonicalDecoded
        }
        NativeHnsNameResourceStatus::CanonicalOpaque => {
            MobileHnsNameResourceStatus::CanonicalOpaque
        }
    };
    let ownership_status = match name.ownership_status {
        NativeHnsNameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable => {
            MobileHnsNameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable
        }
        NativeHnsNameOwnershipStatus::WalletContextUnavailable => {
            MobileHnsNameOwnershipStatus::WalletContextUnavailable
        }
        NativeHnsNameOwnershipStatus::NoCurrentOwner => {
            MobileHnsNameOwnershipStatus::NoCurrentOwner
        }
        NativeHnsNameOwnershipStatus::NotWalletOwned => {
            MobileHnsNameOwnershipStatus::NotWalletOwned
        }
        NativeHnsNameOwnershipStatus::WalletOwned => MobileHnsNameOwnershipStatus::WalletOwned,
        NativeHnsNameOwnershipStatus::IncomingTransfer => {
            MobileHnsNameOwnershipStatus::IncomingTransfer
        }
        NativeHnsNameOwnershipStatus::OutgoingTransfer => {
            MobileHnsNameOwnershipStatus::OutgoingTransfer
        }
    };
    let summary = MobileHnsNameSummary {
        name: name.name,
        name_hash: name.name_hash,
        proof_height: name.proof_height,
        resource_status,
        ownership_status,
        registered: name.registered,
        expired: name.expired,
    };
    if summary.proof_height > MAX_JAVASCRIPT_SAFE_INTEGER {
        return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
    }
    HnsNameDisclosure {
        name: summary.name.clone(),
        name_hash: summary.name_hash.clone(),
    }
    .validate()?;
    Ok(summary)
}

fn mobile_shakedex_config(json: &[u8]) -> Result<PersistentShakedexConfig, MobileWalletError> {
    if json.len() < 2
        || json.len() > MAX_MOBILE_SHAKEDEX_POLICY_BYTES
        || json.first() != Some(&b'{')
        || json.last() != Some(&b'}')
    {
        return Err(MobileWalletError::InvalidShakedexConfiguration);
    }
    let wire: MobileDenuoAcceptancePolicyFile = serde_json::from_slice(json)
        .map_err(|_| MobileWalletError::InvalidShakedexConfiguration)?;
    let acceptance_policy = DenuoPublicationAcceptancePolicy::new(
        NetworkBinding {
            magic: wire.network_magic,
            genesis: ProtocolBlockHash::new(mobile_policy_hex(&wire.network_genesis)?),
        },
        DenuoHrmRootBinding {
            subject: ObjectHash::new(mobile_policy_hex(&wire.hrm.subject)?),
            sequence: wire.hrm.sequence,
            envelope_hash: ObjectHash::new(mobile_policy_hex(&wire.hrm.envelope_hash)?),
            chain_height: wire.hrm.chain_height,
            chain_work_be: mobile_policy_hex(&wire.hrm.chain_work_be)?,
            chain_anchor: ObjectHash::new(mobile_policy_hex(&wire.hrm.chain_anchor)?),
        },
        DenuoHnsaEndpointBinding {
            canonical_service_name: wire.hnsa.canonical_service_name.into_bytes(),
            application_profile_id: wire.hnsa.application_profile_id,
            service_resource_id: ObjectHash::new(mobile_policy_hex(
                &wire.hnsa.service_resource_id,
            )?),
            service_delegation_id: ObjectHash::new(mobile_policy_hex(
                &wire.hnsa.service_delegation_id,
            )?),
            service_generation: wire.hnsa.service_generation,
            endpoint_delegation_id: ObjectHash::new(mobile_policy_hex(
                &wire.hnsa.endpoint_delegation_id,
            )?),
            endpoint_sequence: wire.hnsa.endpoint_sequence,
            endpoint_public_key: mobile_policy_hex(&wire.hnsa.endpoint_public_key)?,
            effective_not_before_unix: wire.hnsa.effective_not_before_unix,
            effective_expires_at_unix: wire.hnsa.effective_expires_at_unix,
        },
        wire.maximum_receipt_lifetime_seconds,
    )
    .map_err(|_| MobileWalletError::InvalidShakedexConfiguration)?;
    Ok(PersistentShakedexConfig {
        seller_policy: ShakedexSellerPolicy::no_marketplace_fee(),
        transport: PersistentDenuoTransport::RelayAcceptance(acceptance_policy),
    })
}

fn wallet_owned_direct_shakedex_config() -> PersistentShakedexConfig {
    PersistentShakedexConfig {
        seller_policy: ShakedexSellerPolicy::no_marketplace_fee(),
        transport: PersistentDenuoTransport::WalletPeers,
    }
}

fn mobile_policy_hex<const N: usize>(encoded: &str) -> Result<[u8; N], MobileWalletError> {
    if encoded.len() != N * 2 {
        return Err(MobileWalletError::InvalidShakedexConfiguration);
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = nibble(pair[0]).ok_or(MobileWalletError::InvalidShakedexConfiguration)?;
        let low = nibble(pair[1]).ok_or(MobileWalletError::InvalidShakedexConfiguration)?;
        decoded[index] = (high << 4) | low;
    }
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(MobileWalletError::InvalidShakedexConfiguration);
    }
    Ok(decoded)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn mobile_service_failure(failure: ServiceFailure) -> MobileWalletError {
    MobileWalletError::ServiceFailure {
        code: failure.code,
        message: failure.message,
    }
}

/// The service emits this exact error only from the final re-preparation step
/// of an HNS send, before signing or broadcasting begins. The pending approval
/// has already been discarded, so keeping the session unlocked cannot retain
/// executable authority. A fresh sync and review are still mandatory.
fn hns_send_pre_broadcast_retry_required(error: &MobileWalletError) -> bool {
    matches!(
        error,
        MobileWalletError::ServiceFailure {
            code: ServiceErrorCode::RuntimeFailure,
            message,
        } if message == NATIVE_HNS_SEND_PRE_BROADCAST_RETRY_MESSAGE
    )
}

#[derive(Debug, Error)]
pub enum MobileWalletError {
    #[error("wallet database key must be exactly 32 nonzero bytes")]
    InvalidDatabaseKey,
    #[error("mobile wallet database must contain exactly one valid HNS account")]
    InvalidAccountSet,
    #[error("mobile recovery phrase is empty or exceeds its native input bound")]
    InvalidRecoveryPhrase,
    #[error("the system clock is unavailable for Bitcoin wallet state")]
    BitcoinClockUnavailable,
    #[error("the direct Bitcoin runtime is inactive")]
    BitcoinRuntimeInactive,
    #[error("the direct Bitcoin runtime could not be created")]
    BitcoinRuntimeUnavailable,
    #[error("a direct Bitcoin send approval is already pending")]
    BitcoinActionPending,
    #[error("there is no pending direct Bitcoin send approval")]
    NoPendingBitcoinAction,
    #[error("the direct Bitcoin send approval token is invalid")]
    InvalidBitcoinActionToken,
    #[error("the direct Bitcoin send approval has expired")]
    BitcoinActionExpired,
    #[error("the direct Bitcoin send request is invalid")]
    InvalidBitcoinAction,
    #[error("the direct Denuo HNS/Bitcoin session message is invalid")]
    InvalidDenuoSessionMessage,
    #[error("a direct BTC-for-HNS offer approval is already pending")]
    DirectOfferActionPending,
    #[error("there is no pending direct BTC-for-HNS offer approval")]
    NoPendingDirectOfferAction,
    #[error("the direct BTC-for-HNS offer approval token is invalid")]
    InvalidDirectOfferActionToken,
    #[error("the direct BTC-for-HNS offer approval has expired")]
    DirectOfferActionExpired,
    #[error("the direct BTC-for-HNS offer request is invalid")]
    InvalidDirectOfferAction,
    #[error("confirmed Bitcoin does not cover active offers, this offer, and its fee reserve")]
    InsufficientBitcoinForDirectOffer,
    #[error("private wallet host/service response was unexpected")]
    UnexpectedResponse,
    #[error("private mobile wallet controller failed closed and must be reopened")]
    ControllerFailed,
    #[error("a native HNS value action is already pending")]
    ValueActionPending,
    #[error("there is no pending native HNS value action")]
    NoPendingValueAction,
    #[error("native HNS value action token is invalid")]
    InvalidActionToken,
    #[error("native HNS value action is invalid")]
    InvalidValueAction,
    #[error("native Shakedex acceptance policy is invalid")]
    InvalidShakedexConfiguration,
    #[error("secure native randomness is unavailable")]
    Randomness,
    #[error("wallet service rejected the request ({code:?}): {message}")]
    ServiceFailure {
        code: ServiceErrorCode,
        message: String,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Hns(#[from] HnsWalletError),
    #[error(transparent)]
    DirectHns(#[from] HnsDirectPeerError),
    #[error(transparent)]
    Bitcoin(#[from] hns_wallet_bitcoin_kyoto::BitcoinWalletError),
    #[error(transparent)]
    Market(#[from] hns_wallet_market::MarketError),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Clock(#[from] ClockError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Abi(#[from] AbiError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use hns_transaction::Coin;
    use hns_wallet_hns::{
        BlockHashEvidence, CanonicalNameStateSummary, ChainTip, ConfirmedWalletPage,
        ConfirmedWalletPageRequest, HnsNameAction, HnsOutpoint, HnsTransactionFeeQuote,
        IncomingTransfersPage, IncomingTransfersPageRequest, MempoolSnapshotBinding,
        MempoolWalletPage, MempoolWalletPageRequest, NameActionContextEvidence, NameEvidence,
        OutpointSpendEvidence, SnapshotBinding, TransactionEvidence,
    };
    use hns_wallet_store::EntityKind;
    use hns_wallet_types::{BaseUnits, TransactionHash};

    const MOCK_READ_HEIGHT: u64 = 7;

    #[test]
    fn only_the_exact_pre_broadcast_send_retry_keeps_the_session_unlocked() {
        let safe_retry = MobileWalletError::ServiceFailure {
            code: ServiceErrorCode::RuntimeFailure,
            message: NATIVE_HNS_SEND_PRE_BROADCAST_RETRY_MESSAGE.to_owned(),
        };
        assert!(hns_send_pre_broadcast_retry_required(&safe_retry));

        for error in [
            MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::RuntimeFailure,
                message: "HNS value runtime failed".to_owned(),
            },
            MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                message: NATIVE_HNS_SEND_PRE_BROADCAST_RETRY_MESSAGE.to_owned(),
            },
            MobileWalletError::InvalidActionToken,
        ] {
            assert!(!hns_send_pre_broadcast_retry_required(&error));
        }
    }

    fn denuo_acceptance_policy_json() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "network_magic": 1_535_399_072_u32,
            "network_genesis": "11".repeat(32),
            "hrm": {
                "subject": "21".repeat(32),
                "sequence": 7,
                "envelope_hash": "22".repeat(32),
                "chain_height": 500,
                "chain_work_be": "23".repeat(32),
                "chain_anchor": "24".repeat(32)
            },
            "hnsa": {
                "canonical_service_name": "relay-market",
                "application_profile_id": 17_490,
                "service_resource_id": "31".repeat(32),
                "service_delegation_id": "32".repeat(32),
                "service_generation": 3,
                "endpoint_delegation_id": "33".repeat(32),
                "endpoint_sequence": 9,
                "endpoint_public_key":
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "effective_not_before_unix": 1_800_000_000_u64,
                "effective_expires_at_unix": 1_800_003_600_u64
            },
            "maximum_receipt_lifetime_seconds": 120
        }))
        .expect("serialize Denuo acceptance policy")
    }

    #[test]
    fn installed_denuo_policy_is_exact_and_disables_marketplace_fees() {
        let encoded = denuo_acceptance_policy_json();
        let config = mobile_shakedex_config(&encoded).expect("valid Denuo policy");

        assert_eq!(
            config.seller_policy,
            ShakedexSellerPolicy::no_marketplace_fee()
        );
        let PersistentDenuoTransport::RelayAcceptance(acceptance_policy) = &config.transport else {
            panic!("explicit legacy relay policy must select relay transport");
        };
        assert_eq!(acceptance_policy.network().magic, 1_535_399_072);
        assert_eq!(acceptance_policy.hrm().sequence, 7);
        assert_eq!(
            acceptance_policy.hnsa().canonical_service_name,
            b"relay-market"
        );
        assert_eq!(acceptance_policy.maximum_receipt_lifetime_seconds(), 120);

        let mut unknown_field: Value =
            serde_json::from_slice(&encoded).expect("decode test policy");
        unknown_field
            .as_object_mut()
            .expect("policy object")
            .insert("alternate_relay".to_owned(), Value::Bool(true));
        assert!(matches!(
            mobile_shakedex_config(
                &serde_json::to_vec(&unknown_field).expect("serialize invalid policy")
            ),
            Err(MobileWalletError::InvalidShakedexConfiguration)
        ));
    }

    #[derive(Default)]
    struct MockReadProbe {
        fail_synchronization: AtomicBool,
        snapshot_calls: AtomicUsize,
        tip_calls: AtomicUsize,
        confirmed_calls: AtomicUsize,
        incoming_calls: AtomicUsize,
        mempool_calls: AtomicUsize,
        evidence_calls: AtomicUsize,
        forbidden_calls: AtomicUsize,
    }

    struct MockReadBackend {
        probe: Arc<MockReadProbe>,
    }

    impl MockReadBackend {
        fn new(probe: Arc<MockReadProbe>) -> Self {
            Self { probe }
        }

        fn tip() -> ChainTip {
            ChainTip {
                height: MOCK_READ_HEIGHT,
                block_hash: [0x31; 32],
                tree_root: [0x32; 32],
                median_time_past: 1_800_000_000,
            }
        }

        fn binding() -> SnapshotBinding {
            SnapshotBinding {
                tip: Self::tip(),
                chain_epoch: 3,
            }
        }

        fn mempool() -> MempoolSnapshotBinding {
            MempoolSnapshotBinding {
                instance_nonce: [0x33; 32],
                generation: 4,
            }
        }

        fn regtest_genesis() -> [u8; 32] {
            [
                0xae, 0x38, 0x95, 0xcf, 0x59, 0x7e, 0xff, 0x05, 0xb1, 0x9e, 0x02, 0xa7, 0x0c, 0xee,
                0xee, 0xcb, 0x9d, 0xc7, 0x2d, 0xbf, 0xe6, 0x50, 0x4a, 0x50, 0xe9, 0x34, 0x3a, 0x72,
                0xf0, 0x6a, 0x87, 0xc5,
            ]
        }

        fn unavailable_evidence(&self, method: &str) -> HnsWalletError {
            self.probe.evidence_calls.fetch_add(1, Ordering::SeqCst);
            HnsWalletError::Backend(format!(
                "unexpected evidence call for empty mobile read fixture: {method}"
            ))
        }

        fn forbidden(&self, method: &str) -> HnsWalletError {
            self.probe.forbidden_calls.fetch_add(1, Ordering::SeqCst);
            HnsWalletError::Backend(format!(
                "unexpected value-capable backend call from mobile reads: {method}"
            ))
        }
    }

    impl HnsBackend for MockReadBackend {
        fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
            self.probe.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            if self.probe.fail_synchronization.load(Ordering::SeqCst) {
                return Err(HnsWalletError::Backend(
                    "injected mobile read failure".to_owned(),
                ));
            }
            Ok(Self::binding())
        }

        fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
            self.probe.tip_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Self::tip())
        }

        fn get_block_hash(
            &self,
            height: u64,
            binding: SnapshotBinding,
        ) -> Result<BlockHashEvidence, HnsWalletError> {
            Ok(BlockHashEvidence {
                binding,
                height,
                block_hash: Some(if height == 0 {
                    Self::regtest_genesis()
                } else if height == binding.tip.height {
                    binding.tip.block_hash
                } else {
                    [0x35; 32]
                }),
            })
        }

        fn get_confirmed_wallet_page(
            &self,
            request: ConfirmedWalletPageRequest<'_>,
        ) -> Result<ConfirmedWalletPage, HnsWalletError> {
            self.probe.confirmed_calls.fetch_add(1, Ordering::SeqCst);
            if request.expected_tip != Self::tip()
                || request
                    .expected_epoch
                    .is_some_and(|epoch| epoch != Self::binding().chain_epoch)
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            Ok(ConfirmedWalletPage {
                binding: Self::binding(),
                next_cursor: None,
                history: Vec::new(),
                utxos: Vec::new(),
            })
        }

        fn get_mempool_wallet_page(
            &self,
            request: MempoolWalletPageRequest<'_>,
        ) -> Result<MempoolWalletPage, HnsWalletError> {
            self.probe.mempool_calls.fetch_add(1, Ordering::SeqCst);
            if request.binding != Self::binding()
                || request
                    .expected_mempool
                    .is_some_and(|mempool| mempool != Self::mempool())
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            Ok(MempoolWalletPage {
                binding: Self::binding(),
                mempool: Self::mempool(),
                next_cursor: None,
                history: Vec::new(),
            })
        }

        fn get_incoming_transfers_page(
            &self,
            request: IncomingTransfersPageRequest<'_>,
        ) -> Result<IncomingTransfersPage, HnsWalletError> {
            self.probe.incoming_calls.fetch_add(1, Ordering::SeqCst);
            if request.binding != Self::binding()
                || request.scripts.is_empty()
                || request.cursor.is_some()
                || request.limit == 0
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            Ok(IncomingTransfersPage {
                projection_version: 1,
                binding: Self::binding(),
                entries: Vec::new(),
                script_examinations: request.scripts.len(),
                next_cursor: None,
            })
        }

        fn get_transaction_evidence(
            &self,
            _: TransactionHash,
            _: SnapshotBinding,
            _: Option<MempoolSnapshotBinding>,
        ) -> Result<TransactionEvidence, HnsWalletError> {
            Err(self.unavailable_evidence("get_transaction_evidence"))
        }

        fn get_outpoint_spend_evidence(
            &self,
            _: &[HnsOutpoint],
            _: SnapshotBinding,
        ) -> Result<OutpointSpendEvidence, HnsWalletError> {
            Err(self.unavailable_evidence("get_outpoint_spend_evidence"))
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<TransactionHash, HnsWalletError> {
            Err(self.forbidden("broadcast_transaction"))
        }

        fn quote_transaction_fee(
            &self,
            _: &[u8],
            _: &[Coin],
            _: u16,
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
            Err(self.forbidden("quote_transaction_fee"))
        }

        fn estimate_fee_rate(&self, _: u16) -> Result<BaseUnits, HnsWalletError> {
            Err(self.forbidden("estimate_fee_rate"))
        }

        fn get_name_evidence(
            &self,
            _: [u8; 32],
            _: SnapshotBinding,
        ) -> Result<NameEvidence, HnsWalletError> {
            Err(self.unavailable_evidence("get_name_evidence"))
        }

        fn get_name_action_context(
            &self,
            _: HnsNameAction,
            _: [u8; 32],
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<NameActionContextEvidence, HnsWalletError> {
            Err(self.forbidden("get_name_action_context"))
        }
    }

    #[derive(Clone, Copy)]
    struct MockReadClock;

    impl HnsClock for MockReadClock {
        fn now_unix(&self) -> Result<u64, HnsWalletError> {
            Ok(1_800_000_000)
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let root = std::env::var_os("HNS_WALLET_STORE_TEST_TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = tempfile::Builder::new()
            .prefix("hns-wallet-mobile-")
            .tempdir_in(root)
            .expect("private mobile-wallet test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private mobile-wallet test directory mode");
        }
        directory
    }

    #[test]
    fn database_key_is_exact_nonzero_and_domain_separated() {
        assert!(matches!(
            MobileDatabaseKey::from_slice(&[7_u8; MOBILE_DATABASE_KEY_BYTES - 1]),
            Err(MobileWalletError::InvalidDatabaseKey)
        ));
        assert!(matches!(
            MobileDatabaseKey::new([0_u8; MOBILE_DATABASE_KEY_BYTES]),
            Err(MobileWalletError::InvalidDatabaseKey)
        ));

        let key = MobileDatabaseKey::new([0xab; MOBILE_DATABASE_KEY_BYTES]).expect("key");
        let passphrase = key.store_passphrase();
        assert!(passphrase.starts_with(STORE_PASSPHRASE_DOMAIN));
        assert_eq!(
            passphrase.len(),
            STORE_PASSPHRASE_DOMAIN.len() + MOBILE_DATABASE_KEY_BYTES * 2
        );
        assert!(!passphrase.contains("[171"));
    }

    #[test]
    fn recovery_phrase_input_is_owned_and_bounded() {
        assert!(matches!(
            MobileRecoveryPhrase::new(String::new()),
            Err(MobileWalletError::InvalidRecoveryPhrase)
        ));
        assert!(matches!(
            MobileRecoveryPhrase::new("a".repeat(MAX_MOBILE_RECOVERY_PHRASE_BYTES + 1)),
            Err(MobileWalletError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn android_create_and_ios_open_restore_keep_the_first_slice_fail_closed() {
        let directory = private_tempdir();
        let created_path = directory.path().join("created.sqlite3");
        let restored_path = directory.path().join("restored.sqlite3");
        let key = MobileDatabaseKey::new([0xab; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let policy = HnsBootstrapPolicy::new(HnsNetwork::Regtest, 123);

        let creation =
            MobileWalletController::create(&created_path, &key, MobilePlatform::Android, policy)
                .expect("create Android controller");
        let (mut controller, recovery_phrase) = creation.into_parts();
        let created_config = controller.account_config().clone();
        assert_eq!(created_config.network, HnsNetwork::Regtest);
        assert_eq!(created_config.birthday_height, 123);
        assert_eq!(created_config.account_derivation_index, 0);
        assert!(!created_config.value_operations_enabled);
        assert!(!created_config.settlement_enabled);

        let phrase = recovery_phrase.expose_for_dedicated_display();
        assert_eq!(phrase.split_whitespace().count(), 24);

        let status = controller.status().expect("created status");
        assert!(status.locked);
        assert_eq!(status.active_wallet, None);
        assert!(status.enabled_modules.is_empty());
        assert!(!status.mainnet_settlement_enabled);

        controller.unlock(&key).expect("unlock created wallet");
        let status = controller.status().expect("unlocked created status");
        assert!(!status.locked);
        assert_eq!(status.active_wallet, Some(created_config.wallet_id));
        assert!(status.enabled_modules.is_empty());
        let accounts = controller.accounts().expect("created accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, created_config.account_id);
        assert_eq!(accounts[0].label, MOBILE_ACCOUNT_LABEL);
        assert_eq!(accounts[0].receive_display, None);

        let wrong_key =
            MobileDatabaseKey::new([0xcd; MOBILE_DATABASE_KEY_BYTES]).expect("wrong database key");
        assert!(controller.unlock(&wrong_key).is_err());
        assert!(controller.status().expect("status after bad key").locked);
        controller.unlock(&key).expect("unlock after bad key");
        controller.lock().expect("lock created wallet");
        drop(controller);

        let mut reopened = MobileWalletController::open(&created_path, &key, MobilePlatform::Ios)
            .expect("open created wallet on iOS boundary");
        assert!(reopened.status().expect("reopened status").locked);
        reopened.unlock(&key).expect("unlock reopened wallet");
        assert_eq!(
            reopened
                .status()
                .expect("reopened unlocked status")
                .active_wallet,
            Some(created_config.wallet_id)
        );
        reopened.lock().expect("lock reopened wallet");
        drop(reopened);

        let recovery_phrase = MobileRecoveryPhrase::new(phrase).expect("owned recovery phrase");
        let mut restored = MobileWalletController::restore(
            &restored_path,
            &key,
            MobilePlatform::Ios,
            policy,
            recovery_phrase,
        )
        .expect("restore iOS controller");
        let restored_config = restored.account_config().clone();
        assert_eq!(restored_config.network, HnsNetwork::Regtest);
        assert_eq!(restored_config.birthday_height, 123);
        assert_eq!(restored_config.account_derivation_index, 0);
        assert!(!restored_config.value_operations_enabled);
        assert!(!restored_config.settlement_enabled);
        assert!(restored.status().expect("restored status").locked);
        restored.unlock(&key).expect("unlock restored wallet");
        let accounts = restored.accounts().expect("restored accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, restored_config.account_id);
        restored.lock().expect("lock restored wallet");
    }

    #[test]
    fn lifecycle_opens_a_wallet_owned_direct_peer_coordinator_without_rpc_credentials() {
        let directory = private_tempdir();
        let path = directory.path().join("direct-peer-wallet.sqlite3");
        let key = MobileDatabaseKey::new([0x7a; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create direct-peer wallet");
        let (mut controller, _recovery) = creation.into_parts();
        let coordinator = controller
            .open_direct_hns_peer_coordinator(
                &key,
                HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            )
            .expect("open direct coordinator without an endpoint or credential");
        let scan = coordinator
            .backend()
            .light_scan_status()
            .expect("wallet-owned direct index");
        assert_eq!(
            scan.watched_scripts,
            controller.account_config().restore_lookahead as usize * 4
        );
        assert_eq!(scan.watched_names, 0);
        assert!(controller.status().expect("controller relocked").locked);
    }

    #[test]
    fn direct_value_composition_retains_the_coordinator_and_refreshes_its_account_policy() {
        let directory = private_tempdir();
        let path = directory.path().join("direct-value-wallet.sqlite3");
        let key = MobileDatabaseKey::new([0x7b; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create direct value wallet");
        let (mut controller, _recovery) = creation.into_parts();
        let coordinator = controller
            .open_direct_hns_peer_coordinator(
                &key,
                HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            )
            .expect("open wallet-owned coordinator");

        let mut direct = controller
            .into_wallet_owned_direct_hns_value_with_clock(&key, coordinator, MockReadClock, None)
            .expect("compose direct value controller");
        assert!(
            direct
                .value_controller()
                .account_config()
                .value_operations_enabled
        );
        assert!(
            !direct
                .value_controller()
                .account_config()
                .settlement_enabled
        );

        direct
            .value_controller()
            .unlock(&key)
            .expect("unlock direct value controller");
        // Value activation updates the persisted policy record. A coordinator
        // that retained the original non-value configuration would now reject
        // its own account instead of growing the direct restore frontier.
        assert!(
            direct
                .extend_wallet_owned_direct_hns_restore_watch_set()
                .expect("extend direct restore watch set with the value runtime clock")
        );
        direct
            .value_controller()
            .lock()
            .expect("relock direct value controller");
    }

    #[test]
    fn direct_value_and_shakedex_composition_enables_wallet_peer_settlement() {
        let directory = private_tempdir();
        let path = directory
            .path()
            .join("direct-value-shakedex-wallet.sqlite3");
        let key = MobileDatabaseKey::new([0x7c; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create direct Shakedex wallet");
        let (mut controller, _recovery) = creation.into_parts();
        let coordinator = controller
            .open_direct_hns_peer_coordinator(
                &key,
                HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            )
            .expect("open wallet-owned coordinator");

        let mut direct = controller
            .into_wallet_owned_direct_hns_value_with_wallet_owned_direct_shakedex_with_clock(
                &key,
                coordinator,
                MockReadClock,
            )
            .expect("compose direct value and Shakedex controller");
        assert!(
            direct
                .value_controller()
                .account_config()
                .value_operations_enabled
        );
        assert!(
            direct
                .value_controller()
                .account_config()
                .settlement_enabled
        );
        let listener = direct
            .bind_wallet_owned_direct_denuo_listener((std::net::Ipv4Addr::LOCALHOST, 0).into())
            .expect("bind Denuo listener from the direct value controller");
        assert!(
            listener
                .local_addr()
                .expect("direct Denuo listener address")
                .port()
                != 0
        );
        assert!(matches!(
            direct.connect_wallet_owned_direct_denuo_peer(
                (std::net::Ipv4Addr::LOCALHOST, 1).into(),
                0,
            ),
            Err(MobileWalletError::Store(StoreError::Locked))
        ));
        direct
            .value_controller()
            .unlock(&key)
            .expect("unlock direct value and Shakedex controller");
        assert!(
            direct
                .accept_wallet_owned_direct_denuo_peer(&listener, 0)
                .expect("poll direct Denuo listener with the value runtime clock")
                .is_none()
        );
        direct
            .value_controller()
            .lock()
            .expect("relock direct value and Shakedex controller");
    }

    #[test]
    fn value_unlock_defers_wallet_peer_market_recovery_until_explicit_sync() {
        let directory = private_tempdir();
        let path = directory.path().join("value-unlock-deferred-sync.sqlite3");
        let key = MobileDatabaseKey::new([0x8b; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create direct value wallet");
        let (controller, _recovery) = creation.into_parts();
        let probe = Arc::new(MockReadProbe::default());
        let mut value = controller
            .into_hns_value_with_clock(
                &key,
                MockReadBackend::new(probe.clone()),
                MockReadClock,
                Some(PersistentShakedexConfig {
                    seller_policy: ShakedexSellerPolicy::no_marketplace_fee(),
                    transport: PersistentDenuoTransport::WalletPeers,
                }),
            )
            .expect("compose direct value wallet");

        value.unlock(&key).expect("unlock must not synchronize");
        let receive = value
            .local_receive_target()
            .expect("local value receive target after unlock");
        assert_eq!(receive.module, ModuleId::Handshake);
        assert_eq!(receive.account, value.account_config().account_id);
        assert!(receive.display.starts_with("rs1"));
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.tip_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.confirmed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.mempool_calls.load(Ordering::SeqCst), 0);

        probe.fail_synchronization.store(true, Ordering::SeqCst);
        assert!(matches!(
            value.synchronize(),
            Err(MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::RuntimeFailure,
                ..
            })
        ));
        assert!(
            !value
                .status()
                .expect("status after a rejected value read")
                .locked
        );

        probe.fail_synchronization.store(false, Ordering::SeqCst);
        let snapshot = value.synchronize().expect("explicit sync");
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert!(probe.snapshot_calls.load(Ordering::SeqCst) > 1);
        assert!(probe.confirmed_calls.load(Ordering::SeqCst) > 0);
        assert!(probe.mempool_calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn value_send_preparation_uses_the_staged_verified_snapshot() {
        let directory = private_tempdir();
        let path = directory.path().join("value-send-staged-snapshot.sqlite3");
        let key = MobileDatabaseKey::new([0x8c; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create value wallet");
        let (controller, _recovery) = creation.into_parts();
        let probe = Arc::new(MockReadProbe::default());
        let mut value = controller
            .into_hns_value_with_clock(
                &key,
                MockReadBackend::new(probe.clone()),
                MockReadClock,
                None,
            )
            .expect("compose value wallet");
        value.unlock(&key).expect("unlock value wallet");
        let recipient = value
            .local_receive_target()
            .expect("derive exact local payment target")
            .display;

        // This empty fixture cannot fund a transaction, but preparation must
        // first complete the staged verified read.  The old legacy
        // reconciliation queried `get_chain_tip`; that path can self-deadlock
        // when the backend is the wallet-owned embedded light index.
        assert!(
            value
                .prepare_value_action(MobileHnsValueIntent::Send {
                    recipient,
                    amount: BaseUnits::new(1),
                    maximum_fee: BaseUnits::new(1),
                })
                .is_err()
        );
        assert!(probe.snapshot_calls.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.tip_calls.load(Ordering::SeqCst), 0);
        assert!(probe.confirmed_calls.load(Ordering::SeqCst) > 0);
        assert!(probe.mempool_calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn flagged_value_account_reopens_for_lifecycle_uses_value_composition() {
        let directory = private_tempdir();
        let path = directory.path().join("flagged-lifecycle.sqlite3");
        let key = MobileDatabaseKey::new([0x8a; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create lifecycle controller");
        let (controller, _recovery_phrase) = creation.into_parts();
        drop(controller);

        let mut store = WalletStore::open(&path).expect("open store for release-policy fixture");
        let passphrase = key.store_passphrase();
        store
            .unlock(passphrase.as_str())
            .expect("unlock release-policy fixture");
        let mut accounts = store
            .wallet_accounts::<HnsAccountRecord>(MAX_MOBILE_WALLET_ACCOUNTS)
            .expect("load exact account");
        assert_eq!(accounts.len(), 1);
        let mut stored = accounts.pop().expect("one account");
        stored.value.config.value_operations_enabled = true;
        stored.value.config.settlement_enabled = true;
        store
            .save_wallet_account(&stored.id, stored.revision, &stored.value, 1_800_000_001)
            .expect("persist qualified-policy-shaped fixture");
        store.lock();
        drop(store);

        let lifecycle = MobileWalletController::open(&path, &key, MobilePlatform::Android)
            .expect("flagged account remains lifecycle-reopenable");
        assert!(lifecycle.account_config().value_operations_enabled);
        assert!(lifecycle.account_config().settlement_enabled);
        let probe = Arc::new(MockReadProbe::default());
        assert!(matches!(
            lifecycle.into_hns_reads_with_clock(MockReadBackend::new(probe), MockReadClock),
            Err(MobileWalletError::Hns(
                HnsWalletError::RuntimeIntegrationUnavailable
            ))
        ));

        let lifecycle = MobileWalletController::open(&path, &key, MobilePlatform::Ios)
            .expect("reopen after rejected ordinary-read composition");
        let probe = Arc::new(MockReadProbe::default());
        let mut value = lifecycle
            .into_hns_value_with_clock(&key, MockReadBackend::new(probe), MockReadClock, None)
            .expect("qualified value composition accepts the persisted value flags");
        value.lock().expect("relock qualified value controller");

        let mut reopened = MobileWalletController::open(&path, &key, MobilePlatform::Android)
            .expect("qualified value activation leaves wallet safely reopenable");
        assert!(reopened.status().expect("locked lifecycle status").locked);
    }

    #[test]
    fn native_value_intents_insert_the_exact_account_and_tokens_are_canonical() {
        let account = AccountId::new([0x42; 16]);
        let (kind, method, params) = MobileHnsValueIntent::Send {
            recipient: "rs1qexample".to_owned(),
            amount: BaseUnits::new(12_345),
            maximum_fee: BaseUnits::new(678),
        }
        .into_provider_parts(account);
        assert_eq!(kind, ApprovalKind::Send);
        assert_eq!(method, ProviderMethod::HnsSend);
        assert_eq!(params["account"], json!(account));
        assert_eq!(params["recipient"], "rs1qexample");
        assert_eq!(params["amount"], json!(BaseUnits::new(12_345)));
        assert_eq!(params["maximumFee"], json!(BaseUnits::new(678)));
        assert!(params.get("origin").is_none());

        let token = [0xab; MOBILE_ACTION_TOKEN_BYTES];
        let encoded = lowercase_hex(&token);
        assert!(mobile_action_token_matches(&token, &encoded));
        assert!(!mobile_action_token_matches(
            &token,
            &encoded.to_uppercase()
        ));
        assert!(!mobile_action_token_matches(
            &token,
            &encoded[..encoded.len() - 2]
        ));
        let mut changed = encoded.into_bytes();
        changed[17] = b'0';
        assert!(!mobile_action_token_matches(
            &token,
            std::str::from_utf8(&changed).expect("ASCII token")
        ));
    }

    #[test]
    fn native_value_and_query_wire_vocabulary_is_closed_camel_case() {
        let transfer = MobileHnsValueIntent::TransferName {
            name: "example".to_owned(),
            recipient: "rs1qrecipient".to_owned(),
            maximum_fee: BaseUnits::new(123),
        };
        let encoded = serde_json::to_value(&transfer).expect("serialize native transfer");
        assert_eq!(encoded["action"], "transferName");
        assert_eq!(encoded["maximumFee"], "123");
        assert!(encoded.get("maximum_fee").is_none());
        assert_eq!(
            serde_json::from_value::<MobileHnsValueIntent>(encoded)
                .expect("deserialize native transfer"),
            transfer
        );

        let query = MobileShakedexQuery::GetSession {
            session_id: "11".repeat(32),
        };
        let encoded = serde_json::to_value(&query).expect("serialize native query");
        assert_eq!(encoded["query"], "getSession");
        assert_eq!(encoded["sessionId"], "11".repeat(32));
        assert!(encoded.get("session_id").is_none());
        assert!(
            serde_json::from_value::<MobileShakedexQuery>(json!({
                "query": "getSession",
                "sessionId": "11".repeat(32),
                "account": "caller-controlled"
            }))
            .is_err()
        );
    }

    #[test]
    fn injected_hns_reads_are_coherent_serializable_and_fresh() {
        let directory = private_tempdir();
        let path = directory.path().join("read-controller.sqlite3");
        let key = MobileDatabaseKey::new([0x91; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let policy = HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0);
        let creation = MobileWalletController::create(&path, &key, MobilePlatform::Android, policy)
            .expect("create lifecycle controller");
        let (controller, _recovery_phrase) = creation.into_parts();
        let expected_account = controller.account_config().account_id;
        let probe = Arc::new(MockReadProbe::default());
        let mut reads = controller
            .into_hns_reads_with_clock(MockReadBackend::new(probe.clone()), MockReadClock)
            .expect("compose synchronized HNS reads");

        let status = reads.status().expect("locked read status");
        assert!(status.locked);
        assert_eq!(status.active_wallet, None);
        assert_eq!(
            status.enabled_modules,
            BTreeSet::from([ModuleId::Handshake])
        );
        assert!(!status.mainnet_settlement_enabled);

        reads.unlock(&key).expect("unlock read controller");
        assert!(!reads.account_config().value_operations_enabled);
        assert!(!reads.account_config().settlement_enabled);
        let accounts = reads.accounts().expect("read account");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, expected_account);
        assert_eq!(accounts[0].receive_display, None);

        let local_receive = reads
            .local_receive_target()
            .expect("local payment receive target after unlock");
        assert_eq!(local_receive.module, ModuleId::Handshake);
        assert_eq!(local_receive.account, expected_account);
        assert!(local_receive.display.starts_with("rs1"));
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.tip_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.confirmed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.mempool_calls.load(Ordering::SeqCst), 0);

        let before = probe.snapshot_calls.load(Ordering::SeqCst);
        let snapshot = reads.synchronize().expect("synchronized mobile snapshot");
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), before + 1);
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert_eq!(snapshot.receive_target.module, ModuleId::Handshake);
        assert_eq!(snapshot.receive_target.account, expected_account);
        assert!(snapshot.receive_target.display.starts_with("rs1"));
        assert_eq!(snapshot.name_receive_target.module, ModuleId::Handshake);
        assert_eq!(snapshot.name_receive_target.account, expected_account);
        assert!(snapshot.name_receive_target.display.starts_with("rs1"));
        assert_ne!(
            snapshot.name_receive_target.display,
            snapshot.receive_target.display
        );
        assert!(snapshot.transaction_history.is_empty());
        assert!(snapshot.known_names.is_empty());
        assert_eq!(snapshot.known_name_count, 0);
        assert!(snapshot.known_names_complete);
        assert_eq!(
            reads
                .known_name_page(0, MAX_MOBILE_HNS_NAME_PAGE)
                .expect("empty authenticated name page"),
            MobileHnsNamePage {
                offset: 0,
                total: 0,
                names: Vec::new(),
                has_more: false,
            }
        );
        assert_eq!(
            snapshot.module_status,
            SyncStatus {
                phase: SyncPhase::Ready,
                validated_height: MOCK_READ_HEIGHT,
                scanned_height: MOCK_READ_HEIGHT,
                target_height: Some(MOCK_READ_HEIGHT),
                last_error: None,
            }
        );

        let encoded = serde_json::to_value(&snapshot).expect("serialize mobile HNS snapshot");
        let fields = encoded
            .as_object()
            .expect("snapshot object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fields,
            BTreeSet::from([
                "balance",
                "knownNameCount",
                "knownNames",
                "knownNamesComplete",
                "moduleStatus",
                "nameReceiveTarget",
                "receiveTarget",
                "transactionHistory",
            ])
        );
        let name_target_fields = encoded["nameReceiveTarget"]
            .as_object()
            .expect("name receive target object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            name_target_fields,
            BTreeSet::from(["account", "derivation_index", "display", "module"])
        );
        assert_eq!(
            serde_json::from_value::<MobileHnsReadSnapshot>(encoded.clone())
                .expect("deserialize mobile HNS snapshot"),
            snapshot
        );
        let mut legacy_shape = encoded;
        legacy_shape
            .as_object_mut()
            .expect("legacy snapshot object")
            .remove("nameReceiveTarget");
        assert!(serde_json::from_value::<MobileHnsReadSnapshot>(legacy_shape).is_err());

        let before = probe.snapshot_calls.load(Ordering::SeqCst);
        assert_eq!(
            reads.balance().expect("fresh balance"),
            Amount::new(WalletAsset::Hns, 0)
        );
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), before + 1);
        assert_eq!(
            reads
                .receive_target()
                .expect("fresh receive target")
                .account,
            expected_account
        );
        let fresh_name_target = reads
            .name_receive_target()
            .expect("fresh name receive target");
        assert_eq!(fresh_name_target, snapshot.name_receive_target);
        assert_ne!(fresh_name_target.display, snapshot.receive_target.display);
        assert!(
            reads
                .transaction_history()
                .expect("fresh transaction history")
                .is_empty()
        );
        assert!(reads.known_names().expect("fresh known names").is_empty());
        assert_eq!(
            reads.module_status().expect("fresh module status").phase,
            SyncPhase::Ready
        );
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), before + 6);
        assert_eq!(probe.tip_calls.load(Ordering::SeqCst), 0);
        assert!(probe.confirmed_calls.load(Ordering::SeqCst) > 0);
        assert!(probe.incoming_calls.load(Ordering::SeqCst) > 0);
        assert!(probe.mempool_calls.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.forbidden_calls.load(Ordering::SeqCst), 0);
        reads.lock().expect("lock read controller");

        drop(reads);
        let reopen_probe = Arc::new(MockReadProbe::default());
        let mut reopened = MobileHnsReadController::open_with_clock(
            &path,
            &key,
            MobilePlatform::Ios,
            MockReadBackend::new(reopen_probe.clone()),
            MockReadClock,
        )
        .expect("reopen read controller");
        reopened.unlock(&key).expect("unlock reopened reads");
        assert_eq!(
            reopened
                .synchronize()
                .expect("reopened synchronized snapshot")
                .name_receive_target
                .account,
            expected_account
        );
        assert_eq!(reopen_probe.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopen_probe.forbidden_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn synchronized_read_error_remains_unlocked_for_a_retry() {
        let directory = private_tempdir();
        let path = directory.path().join("read-failure.sqlite3");
        let key = MobileDatabaseKey::new([0x92; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Ios,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create lifecycle controller");
        let (controller, _recovery_phrase) = creation.into_parts();
        let probe = Arc::new(MockReadProbe::default());
        let mut reads = controller
            .into_hns_reads_with_clock(MockReadBackend::new(probe.clone()), MockReadClock)
            .expect("compose synchronized reads");
        reads.unlock(&key).expect("unlock reads");

        probe.fail_synchronization.store(true, Ordering::SeqCst);
        assert!(matches!(
            reads.balance(),
            Err(MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::RuntimeFailure,
                ..
            })
        ));
        assert!(!reads.status().expect("status after read error").locked);
        assert_eq!(probe.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.forbidden_calls.load(Ordering::SeqCst), 0);

        probe.fail_synchronization.store(false, Ordering::SeqCst);
        assert_eq!(
            reads.balance().expect("balance after backend recovery"),
            Amount::new(WalletAsset::Hns, 0)
        );
        assert!(probe.incoming_calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn exact_text_name_import_rejects_input_without_poisoning_and_locks_on_runtime_fault() {
        let directory = private_tempdir();
        let path = directory.path().join("name-import-errors.sqlite3");
        let key = MobileDatabaseKey::new([0x93; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let creation = MobileWalletController::create(
            &path,
            &key,
            MobilePlatform::Android,
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .expect("create lifecycle controller");
        let (controller, _recovery_phrase) = creation.into_parts();
        let probe = Arc::new(MockReadProbe::default());
        let mut reads = controller
            .into_hns_reads_with_clock(MockReadBackend::new(probe.clone()), MockReadClock)
            .expect("compose name import controller");
        reads.unlock(&key).expect("unlock name import controller");

        assert!(matches!(
            reads.import_name_exact_text(" Alpha"),
            Err(MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));
        assert!(!reads.status().expect("status after invalid input").locked);
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.evidence_calls.load(Ordering::SeqCst), 0);

        assert!(matches!(
            reads.import_name_exact_text("alpha"),
            Err(MobileWalletError::ServiceFailure {
                code: ServiceErrorCode::RuntimeFailure,
                ..
            })
        ));
        assert!(reads.status().expect("status after backend fault").locked);
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.evidence_calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.forbidden_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_import_summary_projection_is_minimized_and_exact() {
        let summary = mobile_native_hns_name_summary(NativeHnsNameSummary {
            name: "alpha".to_owned(),
            name_hash: "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
                .to_owned(),
            proof_height: 99,
            resource_status: NativeHnsNameResourceStatus::CanonicalDecoded,
            ownership_status: NativeHnsNameOwnershipStatus::IncomingTransfer,
            registered: Some(true),
            expired: Some(false),
        })
        .expect("mobile native name summary");
        assert_eq!(summary.name, "alpha");
        assert_eq!(
            summary.ownership_status,
            MobileHnsNameOwnershipStatus::IncomingTransfer
        );
        let encoded = serde_json::to_value(summary).expect("serialize minimized import result");
        assert_eq!(
            encoded
                .as_object()
                .expect("summary object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "expired",
                "name",
                "nameHash",
                "ownershipStatus",
                "proofHeight",
                "registered",
                "resourceStatus",
            ])
        );
    }

    #[test]
    fn known_name_projection_is_minimized_typed_and_serializable() {
        let known_name = KnownName {
            name: b"alpha".to_vec(),
            name_hash: [
                0x27, 0x18, 0x78, 0xf8, 0xa9, 0x27, 0xb4, 0x56, 0x6a, 0xc9, 0x51, 0xfc, 0x81, 0x5b,
                0x18, 0xdf, 0xad, 0x8d, 0x03, 0x02, 0xd6, 0x1d, 0x11, 0xd8, 0x0c, 0xbe, 0x15, 0xb7,
                0xa3, 0xa0, 0x56, 0xaf,
            ],
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
        };
        let summary = mobile_hns_name_summary(&known_name).expect("minimized name summary");
        assert_eq!(summary.name, "alpha");
        assert_eq!(summary.name_hash.len(), 64);
        assert_eq!(
            summary.resource_status,
            MobileHnsNameResourceStatus::CanonicalDecoded
        );
        assert_eq!(
            summary.ownership_status,
            MobileHnsNameOwnershipStatus::WalletContextUnavailable
        );
        assert_eq!(summary.registered, Some(true));
        assert_eq!(summary.expired, Some(false));

        let encoded = serde_json::to_string(&summary).expect("serialize name summary");
        for forbidden in [
            "proofState",
            "currentState",
            "rawResource",
            "ownerOutpoint",
            "derivation",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert_eq!(
            serde_json::from_str::<MobileHnsNameSummary>(&encoded)
                .expect("deserialize name summary"),
            summary
        );

        let mut malformed = known_name.clone();
        malformed.name = vec![0xff];
        assert!(mobile_hns_name_summary(&malformed).is_err());
        let mut oversized_height = known_name;
        oversized_height.proof_height = MAX_JAVASCRIPT_SAFE_INTEGER + 1;
        assert!(mobile_hns_name_summary(&oversized_height).is_err());
    }

    #[test]
    fn known_name_pages_are_bounded_ordered_and_complete_without_resync() {
        let names = (0..130)
            .map(|index| MobileHnsNameSummary {
                name: format!("name{index:04}"),
                name_hash: format!("{index:064x}"),
                proof_height: 500,
                resource_status: MobileHnsNameResourceStatus::Empty,
                ownership_status: MobileHnsNameOwnershipStatus::WalletOwned,
                registered: Some(true),
                expired: Some(false),
            })
            .collect::<Vec<_>>();
        let first = mobile_hns_name_page(&names, 0, 64).expect("first page");
        let second = mobile_hns_name_page(&names, 64, 64).expect("second page");
        let final_page = mobile_hns_name_page(&names, 128, 64).expect("final page");
        assert_eq!((first.offset, first.total, first.names.len()), (0, 130, 64));
        assert!(first.has_more);
        assert_eq!((second.offset, second.names.len()), (64, 64));
        assert!(second.has_more);
        assert_eq!((final_page.offset, final_page.names.len()), (128, 2));
        assert!(!final_page.has_more);
        assert!(mobile_hns_name_page(&names, 0, 65).is_err());
        assert!(mobile_hns_name_page(&names, 131, 1).is_err());
    }

    #[test]
    fn trusted_mobile_name_receive_target_revalidates_account_module_and_display() {
        let account = AccountId::new([0x31; 16]);
        let receive = ReceiveTarget {
            module: ModuleId::Handshake,
            account,
            display: "rs1qcoin".to_owned(),
            derivation_index: 2,
        };
        let name = HnsNameReceiveTarget {
            module: ModuleId::Handshake,
            account,
            display: "rs1qname".to_owned(),
            derivation_index: 5,
        };
        validate_mobile_hns_receive_targets(account, &receive, &name)
            .expect("valid trusted native targets");

        for invalid in [
            HnsNameReceiveTarget {
                module: ModuleId::Bitcoin,
                ..name.clone()
            },
            HnsNameReceiveTarget {
                account: AccountId::new([0x32; 16]),
                ..name.clone()
            },
            HnsNameReceiveTarget {
                display: String::new(),
                ..name.clone()
            },
            HnsNameReceiveTarget {
                display: "rs1qname\n".to_owned(),
                ..name.clone()
            },
            HnsNameReceiveTarget {
                display: "rs1qn\u{e9}me".to_owned(),
                ..name.clone()
            },
        ] {
            assert!(validate_mobile_hns_receive_targets(account, &receive, &invalid).is_err());
        }
        for invalid_receive in [
            ReceiveTarget {
                module: ModuleId::Bitcoin,
                ..receive.clone()
            },
            ReceiveTarget {
                account: AccountId::new([0x32; 16]),
                ..receive
            },
        ] {
            assert!(validate_mobile_hns_receive_targets(account, &invalid_receive, &name).is_err());
        }
    }

    #[test]
    fn open_rejects_an_account_only_partial_bootstrap() {
        let directory = private_tempdir();
        let path = directory.path().join("partial.sqlite3");
        let key = MobileDatabaseKey::new([0xef; MOBILE_DATABASE_KEY_BYTES]).expect("database key");
        let policy = HnsBootstrapPolicy::new(HnsNetwork::Regtest, 456);
        let bootstrap = HnsWalletBootstrap::generate(policy).expect("bootstrap");
        let account = bootstrap.account_record().clone();
        let mut account_id = [0_u8; 32];
        account_id[..16].copy_from_slice(account.config.wallet_id.as_bytes());
        account_id[16..].copy_from_slice(account.config.account_id.as_bytes());

        let passphrase = key.store_passphrase();
        let mut store = WalletStore::create(&path, passphrase.as_str()).expect("create partial DB");
        store
            .save_entity(EntityKind::WalletAccount, &account_id, 0, &account, 1)
            .expect("save account without recovery seed");
        store.lock();
        drop(store);

        let error = match MobileWalletController::open(&path, &key, MobilePlatform::Android) {
            Ok(_) => panic!("account-only bootstrap must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            MobileWalletError::Store(StoreError::BootstrapConflict)
        ));
    }
}
