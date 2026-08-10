#![doc = "Platform-neutral native wallet control for Android and iOS applications."]
#![forbid(unsafe_code)]

use std::path::Path;

use hns_wallet_ffi::{
    AbiError, AccountSummary, HostFrame, HostPlatform, SecretString, ServiceCapability,
    ServiceErrorCode, ServiceResponse, WalletRequest, WalletResponse, WalletRuntimeStatus,
    decode_service_frame, encode_host_frame,
};
use hns_wallet_hns::{
    HnsAccountRecord, HnsBootstrapPolicy, HnsExistingAccountSelector, HnsRuntimeConfig,
    HnsWalletBootstrap, HnsWalletError, RecoveryPhrase,
};
use hns_wallet_host::{
    Clock, ClockError, HostError, HostOutput, SystemClock, SystemEntropy, WalletHost,
};
use hns_wallet_service::{
    PersistentHnsAccountConfig, PersistentHnsAccountRuntime, ServiceError, WalletService,
};
use hns_wallet_store::{SharedWalletStore, StoreError, WalletStore};
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

type MobileService = WalletService<SharedWalletStore, PersistentHnsAccountRuntime>;
type MobileHost = WalletHost<SystemClock, SystemEntropy>;

/// One process-local native controller. No raw ABI frame, provider authority,
/// decrypted record key, or recovery phrase is exposed through this type.
pub struct MobileWalletController {
    store: SharedWalletStore,
    host: MobileHost,
    service: MobileService,
    account_config: HnsRuntimeConfig,
    failed: bool,
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
                let controller = Self::from_unlocked_store(store, account_config, host)?;
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
                Self::from_unlocked_store(store, account_config, host)
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
        Self::from_unlocked_store(store, account_config, host)
    }

    fn from_unlocked_store(
        store: WalletStore,
        account_config: HnsRuntimeConfig,
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
            store,
            host,
            service,
            account_config,
            failed: false,
        };
        controller.negotiate()?;
        Ok(controller)
    }

    pub const fn account_config(&self) -> &HnsRuntimeConfig {
        &self.account_config
    }

    pub fn status(&mut self) -> Result<WalletRuntimeStatus, MobileWalletError> {
        match self.wallet_request(WalletRequest::Status)? {
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
        match self.wallet_request(WalletRequest::Unlock { passphrase })? {
            WalletResponse::Unlocked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn lock(&mut self) -> Result<(), MobileWalletError> {
        match self.wallet_request(WalletRequest::Lock)? {
            WalletResponse::Locked => Ok(()),
            _ => Err(MobileWalletError::UnexpectedResponse),
        }
    }

    pub fn accounts(&mut self) -> Result<Vec<AccountSummary>, MobileWalletError> {
        match self.wallet_request(WalletRequest::ListAccounts)? {
            WalletResponse::Accounts { accounts } => Ok(accounts),
            _ => Err(MobileWalletError::UnexpectedResponse),
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
                ServiceResponse::Failure { failure } => Err(MobileWalletError::ServiceFailure {
                    code: failure.code,
                    message: failure.message,
                }),
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

impl Drop for MobileWalletController {
    fn drop(&mut self) {
        let _ = self.store.lock();
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
    use hns_wallet_hns::HnsNetwork;
    use hns_wallet_store::EntityKind;

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
