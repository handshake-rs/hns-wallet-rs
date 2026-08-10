#![doc = "Platform-neutral native wallet control for Android and iOS applications."]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::Path;

use hns_wallet_ffi::{
    AbiError, AccountSummary, HnsNameDisclosure, HostFrame, HostPlatform, SecretString,
    ServiceCapability, ServiceErrorCode, ServiceFailure, ServiceResponse, WalletRequest,
    WalletResponse, WalletRuntimeStatus, decode_service_frame, encode_host_frame,
};
use hns_wallet_hns::{
    HnsAccountReadRuntime, HnsAccountRecord, HnsExistingAccountSelector, HnsRuntimeConfig,
    HnsWalletBootstrap, HnsWalletError, KnownName, NameOwnershipStatus, NameResourceStatus,
    RecoveryPhrase,
};
/// Backend composition types exposed for downstream native shells. The
/// concrete RPC adapter accepts authenticated loopback sockets only; production
/// Android/iOS transport and lifecycle integration remain external.
pub use hns_wallet_hns::{
    HnsBackend, HnsBootstrapPolicy, HnsClock, HnsNetwork, HnsNodeRpcBackend, HnsNodeRpcConfig,
    SystemClock as HnsReadSystemClock,
};
use hns_wallet_host::{
    Clock, ClockError, HostError, HostOutput, SystemClock, SystemEntropy, WalletHost,
};
use hns_wallet_service::{
    MAX_JAVASCRIPT_SAFE_INTEGER, PersistentHnsAccountConfig, PersistentHnsAccountRuntime,
    PersistentHnsReadConfig, PersistentHnsReadRuntime, ServiceError, ServiceRuntime, WalletService,
};
use hns_wallet_store::{SharedWalletStore, StoreError, WalletStore};
use hns_wallet_types::{
    Amount, ModuleId, ReceiveTarget, SyncPhase, SyncStatus, TransactionSummary, WalletAsset,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MOBILE_DATABASE_KEY_BYTES: usize = 32;
pub const MAX_MOBILE_RECOVERY_PHRASE_BYTES: usize = 256;
pub const MOBILE_ACCOUNT_LABEL: &str = "Handshake";
const STORE_PASSPHRASE_DOMAIN: &str = "hns-wallet-mobile/store-passphrase/v1:";
const RESTART_GENERATION: u64 = 1;
const MAX_MOBILE_WALLET_ACCOUNTS: usize = 2;
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
    pub transaction_history: Vec<TransactionSummary>,
    pub known_names: Vec<MobileHnsNameSummary>,
    pub module_status: SyncStatus,
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

    fn negotiate(&mut self) -> Result<(), MobileWalletError> {
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
                Self::from_unlocked_store(store, account_config, platform, host)
            },
        )
    }

    /// Open exactly one existing non-value HNS account and start locked. The
    /// database key is used only for authenticated discovery and is not kept by
    /// the controller; native code must unwrap it again for each unlock.
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
        let selector = HnsExistingAccountSelector::new(store.clone(), account_config.clone());
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
        controller.session.negotiate()?;
        Ok(controller)
    }

    pub const fn account_config(&self) -> &HnsRuntimeConfig {
        &self.account_config
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
        };
        controller.session.negotiate()?;
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
    pub fn synchronize(&mut self) -> Result<MobileHnsReadSnapshot, MobileWalletError> {
        let result = self.synchronize_inner();
        if result.is_err() {
            self.session.lock_after_request_error();
        }
        result
    }

    /// Return balance from one new bounded synchronization.
    pub fn balance(&mut self) -> Result<Amount, MobileWalletError> {
        Ok(self.synchronize()?.balance)
    }

    /// Return the receive target from one new bounded synchronization.
    pub fn receive_target(&mut self) -> Result<ReceiveTarget, MobileWalletError> {
        Ok(self.synchronize()?.receive_target)
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
            || snapshot.receive_target.module != ModuleId::Handshake
            || snapshot.receive_target.account != snapshot.account_id
            || snapshot
                .transactions
                .iter()
                .any(|transaction| transaction.module != ModuleId::Handshake)
        {
            return Err(MobileWalletError::Hns(HnsWalletError::InvalidEvidence));
        }
        snapshot
            .receive_target
            .validate()
            .map_err(|_| MobileWalletError::Hns(HnsWalletError::InvalidEvidence))?;
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
        let height = snapshot.binding.chain.tip.height;
        Ok(MobileHnsReadSnapshot {
            balance: snapshot.balance,
            receive_target: snapshot.receive_target,
            transaction_history: snapshot.transactions,
            known_names,
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

#[derive(Debug, Error)]
pub enum MobileWalletError {
    #[error("wallet database key must be exactly 32 nonzero bytes")]
    InvalidDatabaseKey,
    #[error("mobile wallet database must contain exactly one valid HNS account")]
    InvalidAccountSet,
    #[error("mobile recovery phrase is empty or exceeds its native input bound")]
    InvalidRecoveryPhrase,
    #[error("private wallet host/service response was unexpected")]
    UnexpectedResponse,
    #[error("private mobile wallet controller failed closed and must be reopened")]
    ControllerFailed,
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
        MempoolSnapshotBinding, MempoolWalletPage, MempoolWalletPageRequest,
        NameActionContextEvidence, NameEvidence, OutpointSpendEvidence, SnapshotBinding,
        TransactionEvidence,
    };
    use hns_wallet_store::EntityKind;
    use hns_wallet_types::{BaseUnits, TransactionHash};

    const MOCK_READ_HEIGHT: u64 = 7;

    #[derive(Default)]
    struct MockReadProbe {
        fail_synchronization: AtomicBool,
        snapshot_calls: AtomicUsize,
        tip_calls: AtomicUsize,
        confirmed_calls: AtomicUsize,
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
        let accounts = reads.accounts().expect("read account");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, expected_account);
        assert_eq!(accounts[0].receive_display, None);

        let before = probe.snapshot_calls.load(Ordering::SeqCst);
        let snapshot = reads.synchronize().expect("synchronized mobile snapshot");
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), before + 1);
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert_eq!(snapshot.receive_target.module, ModuleId::Handshake);
        assert_eq!(snapshot.receive_target.account, expected_account);
        assert!(snapshot.receive_target.display.starts_with("rs1"));
        assert!(snapshot.transaction_history.is_empty());
        assert!(snapshot.known_names.is_empty());
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
                "knownNames",
                "moduleStatus",
                "receiveTarget",
                "transactionHistory",
            ])
        );
        assert_eq!(
            serde_json::from_value::<MobileHnsReadSnapshot>(encoded)
                .expect("deserialize mobile HNS snapshot"),
            snapshot
        );

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
        assert_eq!(probe.snapshot_calls.load(Ordering::SeqCst), before + 5);
        assert_eq!(probe.tip_calls.load(Ordering::SeqCst), 0);
        assert!(probe.confirmed_calls.load(Ordering::SeqCst) > 0);
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
                .receive_target
                .account,
            expected_account
        );
        assert_eq!(reopen_probe.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopen_probe.forbidden_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn synchronized_read_error_locks_before_a_retry() {
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
        assert!(reads.status().expect("status after read error").locked);
        assert_eq!(probe.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.forbidden_calls.load(Ordering::SeqCst), 0);

        probe.fail_synchronization.store(false, Ordering::SeqCst);
        reads.unlock(&key).expect("unlock after backend recovery");
        assert_eq!(
            reads.balance().expect("balance after backend recovery"),
            Amount::new(WalletAsset::Hns, 0)
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
