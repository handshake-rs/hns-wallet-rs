#![doc = "Transactional wallet persistence with per-record authenticated encryption."]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use hns_wallet_types::{ApprovalId, WorkflowId, WorkflowKind};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: u32 = 3;
pub const MAX_RECORD_ID_BYTES: usize = 128;
pub const MAX_SECRET_BYTES: usize = 1_048_576;
pub const MAX_STATE_BYTES: usize = 1_048_576;
pub const MAX_REPLAY_ROWS_PER_ORIGIN: usize = 4_096;
pub const MAX_ENTITY_LIST_RESULTS: usize = 10_000;
pub const MAX_PROVIDER_PERMISSIONS: usize = 4_096;
pub const MAX_PENDING_APPROVALS: usize = 4_096;
pub const MAX_REPLAY_ORIGINS: usize = 4_096;
pub const MAX_REPLAY_ROWS: usize = 65_536;
pub const MAX_REPLAY_LIFETIME_SECONDS: u64 = 86_400;
pub const MAX_APPROVAL_LIFETIME_SECONDS: u64 = 3_600;
pub const MAX_ENTITY_BATCH_OPERATIONS: usize = 16_384;
pub const MAX_PASSPHRASE_BYTES: usize = 1_024;
/// Exact output size of `bip39::Mnemonic::to_seed_normalized`.
pub const RECOVERY_SEED_BYTES: usize = 64;

const DATABASE_ID_BYTES: usize = 16;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const SENTINEL: &[u8] = b"hns-wallet-store-key-check-v1";
const AAD_DOMAIN: &[u8] = b"hns-wallet-store/record/v1";
const ORIGIN_TOKEN_DOMAIN: &[u8] = b"hns-wallet-store/origin-token/v1";
const CHECKPOINT_PENDING_KEY: &str = "plaintext_checkpoint_pending";

/// A stable, wallet-local storage namespace. Values in every namespace are
/// authenticated and encrypted; the kind and caller-supplied record ID are
/// bound as associated data so ciphertext cannot be relocated.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EntityKind {
    WalletAccount,
    DerivedAddress,
    HnsUtxo,
    HnsTransaction,
    KnownName,
    NameOwnerOutpoint,
    NameTransfer,
    Shakedex,
    HnsShakedexKeyAllocation,
    DenuoBoardObject,
    BitcoinHeader,
    BitcoinFilterHeader,
    BitcoinPeer,
    BitcoinWalletState,
    BitcoinScanState,
    BitcoinSwapKeyAllocation,
    BitcoinUtxo,
    BitcoinTransaction,
    EthereumAccount,
    EthereumTransaction,
    MarketIntent,
    FillGrant,
    PriceRound,
    SwapSession,
    RefundTransaction,
    HnsRecoveryState,
    HnsVerifiedSettlement,
    PendingApproval,
    InputReservation,
}

impl EntityKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::WalletAccount => "wallet_account",
            Self::DerivedAddress => "derived_address",
            Self::HnsUtxo => "hns_utxo",
            Self::HnsTransaction => "hns_transaction",
            Self::KnownName => "known_name",
            Self::NameOwnerOutpoint => "name_owner_outpoint",
            Self::NameTransfer => "name_transfer",
            Self::Shakedex => "shakedex",
            Self::HnsShakedexKeyAllocation => "hns_shakedex_key_allocation",
            Self::DenuoBoardObject => "denuo_board_object",
            Self::BitcoinHeader => "bitcoin_header",
            Self::BitcoinFilterHeader => "bitcoin_filter_header",
            Self::BitcoinPeer => "bitcoin_peer",
            Self::BitcoinWalletState => "bitcoin_wallet_state",
            Self::BitcoinScanState => "bitcoin_scan_state",
            Self::BitcoinSwapKeyAllocation => "bitcoin_swap_key_allocation",
            Self::BitcoinUtxo => "bitcoin_utxo",
            Self::BitcoinTransaction => "bitcoin_transaction",
            Self::EthereumAccount => "ethereum_account",
            Self::EthereumTransaction => "ethereum_transaction",
            Self::MarketIntent => "market_intent",
            Self::FillGrant => "fill_grant",
            Self::PriceRound => "price_round",
            Self::SwapSession => "swap_session",
            Self::RefundTransaction => "refund_transaction",
            Self::HnsRecoveryState => "hns_recovery_state",
            Self::HnsVerifiedSettlement => "hns_verified_settlement",
            Self::PendingApproval => "pending_approval",
            Self::InputReservation => "input_reservation",
        }
    }

    const fn deletion_protected(self) -> bool {
        matches!(
            self,
            Self::HnsShakedexKeyAllocation
                | Self::BitcoinWalletState
                | Self::BitcoinSwapKeyAllocation
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEntity<T> {
    pub kind: EntityKind,
    pub id: Vec<u8>,
    pub revision: u64,
    pub value: T,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityBatchSave<T> {
    pub id: Vec<u8>,
    pub expected_revision: u64,
    pub value: T,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityBatchDelete {
    pub id: Vec<u8>,
    pub expected_revision: u64,
}

macro_rules! entity_crud_methods {
    ($(($save:ident, $load:ident, $list:ident, $delete:ident, $kind:ident)),+ $(,)?) => {
        $(
            pub fn $save<T: Serialize>(
                &mut self,
                id: &[u8],
                expected_revision: u64,
                value: &T,
                updated_at_unix: u64,
            ) -> Result<u64, StoreError> {
                self.save_entity(
                    EntityKind::$kind,
                    id,
                    expected_revision,
                    value,
                    updated_at_unix,
                )
            }

            pub fn $load<T: for<'de> Deserialize<'de>>(
                &self,
                id: &[u8],
            ) -> Result<Option<StoredEntity<T>>, StoreError> {
                self.load_entity(EntityKind::$kind, id)
            }

            pub fn $list<T: for<'de> Deserialize<'de>>(
                &self,
                limit: usize,
            ) -> Result<Vec<StoredEntity<T>>, StoreError> {
                self.list_entities(EntityKind::$kind, limit)
            }

            pub fn $delete(
                &mut self,
                id: &[u8],
                expected_revision: u64,
            ) -> Result<bool, StoreError> {
                self.delete_entity(EntityKind::$kind, id, expected_revision)
            }
        )+
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KdfConfig {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            lanes: 1,
        }
    }
}

impl KdfConfig {
    fn validate(self) -> Result<(), StoreError> {
        if self.memory_kib < 19_456 || self.iterations < 2 || self.lanes == 0 || self.lanes > 4 {
            return Err(StoreError::UnsafeKdfParameters);
        }
        Params::new(
            self.memory_kib,
            self.iterations,
            self.lanes,
            Some(KEY_BYTES),
        )
        .map_err(|_| StoreError::UnsafeKdfParameters)?;
        Ok(())
    }

    #[cfg(test)]
    const fn testing() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            lanes: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    RecoverySeed,
    PrivateKey,
    MetadataKey,
    HtlcPreimage,
    ProviderCapability,
    SessionAuthorization,
}

impl SecretKind {
    const fn label(self) -> &'static str {
        match self {
            Self::RecoverySeed => "recovery_seed",
            Self::PrivateKey => "private_key",
            Self::MetadataKey => "metadata_key",
            Self::HtlcPreimage => "htlc_preimage",
            Self::ProviderCapability => "provider_capability",
            Self::SessionAuthorization => "session_authorization",
        }
    }
}

pub struct WalletStore {
    connection: Connection,
    database_id: [u8; DATABASE_ID_BYTES],
    salt: [u8; SALT_BYTES],
    kdf: KdfConfig,
    key: Option<Zeroizing<[u8; KEY_BYTES]>>,
}

/// One cloneable process-local authority over a wallet database and its
/// decrypted record key. Provider persistence and wallet execution must share
/// this handle so locking cannot leave a second independently unlocked store
/// connection behind.
///
/// The handle deliberately has no `Debug` implementation. Callers use the
/// bounded closure methods instead of retaining a mutex guard across another
/// wallet component or an external call.
#[derive(Clone)]
pub struct SharedWalletStore {
    inner: Arc<Mutex<WalletStore>>,
}

impl SharedWalletStore {
    pub fn new(store: WalletStore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(store)),
        }
    }

    pub fn with_store<T>(
        &self,
        operation: impl FnOnce(&WalletStore) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.try_with_store(operation)
    }

    /// Run a bounded synchronous read while allowing the caller to preserve a
    /// richer error type. The store mutex is never intended to cross an
    /// external call or an async suspension point.
    pub fn try_with_store<T, E>(
        &self,
        operation: impl FnOnce(&WalletStore) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        let store = match self.inner.lock() {
            Ok(store) => store,
            Err(poisoned) => {
                let mut store = poisoned.into_inner();
                store.lock();
                return Err(StoreError::Concurrency.into());
            }
        };
        operation(&store)
    }

    /// Prove that two components retain clones of the identical Arc-backed
    /// store/key authority. Path equality is deliberately insufficient.
    pub fn is_same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn with_store_mut<T>(
        &self,
        operation: impl FnOnce(&mut WalletStore) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.try_with_store_mut(operation)
    }

    /// Run a bounded synchronous mutation while allowing the caller to
    /// preserve a richer error type. Poison recovery always clears the record
    /// key and fails closed before the operation can run.
    pub fn try_with_store_mut<T, E>(
        &self,
        operation: impl FnOnce(&mut WalletStore) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        let mut store = match self.inner.lock() {
            Ok(store) => store,
            Err(poisoned) => {
                let mut store = poisoned.into_inner();
                store.lock();
                return Err(StoreError::Concurrency.into());
            }
        };
        operation(&mut store)
    }

    pub fn unlock(&self, passphrase: &str) -> Result<(), StoreError> {
        self.with_store_mut(|store| store.unlock(passphrase))
    }

    /// Clear the shared record key before returning. If another operation
    /// poisoned the mutex, recover the contained store only long enough to
    /// clear its key, then report the concurrency failure so callers still
    /// fail closed.
    pub fn lock(&self) -> Result<(), StoreError> {
        match self.inner.lock() {
            Ok(mut store) => {
                store.lock();
                Ok(())
            }
            Err(poisoned) => {
                let mut store = poisoned.into_inner();
                store.lock();
                Err(StoreError::Concurrency)
            }
        }
    }

    pub fn is_locked(&self) -> Result<bool, StoreError> {
        self.with_store(|store| Ok(store.is_locked()))
    }
}

impl WalletStore {
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        Self::create_with_kdf(path, passphrase, KdfConfig::default())
    }

    /// Creates a new wallet database and runs one product initializer before
    /// releasing the new-file cleanup guard.
    ///
    /// The callback receives the same unlocked store that is returned on
    /// success. If it returns an error, the store connection is closed and the
    /// creation guard removes only the database and sidecars attributable to
    /// this invocation. Product initialization should still use an atomic
    /// store operation so a process interruption cannot expose partial rows.
    pub fn create_with_initializer<T>(
        path: impl AsRef<Path>,
        passphrase: &str,
        initializer: impl FnOnce(&mut Self) -> Result<T, StoreError>,
    ) -> Result<(Self, T), StoreError> {
        Self::create_with_kdf_and_initializer(
            path,
            passphrase,
            KdfConfig::default(),
            |_| Ok(()),
            initializer,
        )
    }

    /// Creates a new wallet database and transfers ownership of its unlocked
    /// store into a fallible product constructor before releasing the
    /// new-file cleanup guard.
    ///
    /// This is the product-facing counterpart to `create_with_initializer`:
    /// the callback may return a controller or service that owns the store.
    /// Store setup and final identity-validation failures convert into the
    /// product's error type. If product construction fails after committing
    /// bootstrap records, the still-armed guard removes only artifacts owned
    /// by this creation attempt.
    pub fn create_with_owned_initializer<T, E>(
        path: impl AsRef<Path>,
        passphrase: &str,
        initializer: impl FnOnce(Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        Self::create_with_kdf_and_owned_initializer(
            path,
            passphrase,
            KdfConfig::default(),
            initializer,
        )
    }

    fn create_with_kdf(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
    ) -> Result<Self, StoreError> {
        Self::create_with_kdf_after_migration(path, passphrase, kdf, |_| Ok(()))
    }

    fn create_with_kdf_after_migration(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
        after_migration: impl FnOnce(&Connection) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let (store, ()) =
            Self::create_with_kdf_and_initializer(path, passphrase, kdf, after_migration, |_| {
                Ok(())
            })?;
        Ok(store)
    }

    fn create_with_kdf_and_initializer<T>(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
        after_migration: impl FnOnce(&Connection) -> Result<(), StoreError>,
        initializer: impl FnOnce(&mut Self) -> Result<T, StoreError>,
    ) -> Result<(Self, T), StoreError> {
        let (mut store, mut created_file, path) =
            Self::create_pending_with_kdf(path, passphrase, kdf, after_migration)?;
        let initialized = initializer(&mut store)?;
        complete_wallet_creation(&mut created_file, &path)?;
        Ok((store, initialized))
    }

    fn create_with_kdf_and_owned_initializer<T, E>(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
        initializer: impl FnOnce(Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        let (store, mut created_file, path) =
            Self::create_pending_with_kdf(path, passphrase, kdf, |_| Ok(())).map_err(E::from)?;
        let initialized = initializer(store)?;
        if let Err(error) = complete_wallet_creation(&mut created_file, &path) {
            // A successful product may now own the only live SQLite
            // connection. Close it before the armed guard attempts cleanup.
            drop(initialized);
            return Err(E::from(error));
        }
        Ok(initialized)
    }

    fn create_pending_with_kdf(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
        after_migration: impl FnOnce(&Connection) -> Result<(), StoreError>,
    ) -> Result<(Self, Option<CreatedWalletFile>, PathBuf), StoreError> {
        validate_passphrase(passphrase)?;
        kdf.validate()?;
        let location = validate_wallet_location(path.as_ref(), WalletPathRequirement::Missing)?;
        let created_file = if is_in_memory(&location.path) {
            None
        } else {
            Some(create_new_wallet_file(&location.path)?)
        };
        let connection = open_wallet_connection(&location.path)?;
        if let Some(created_file) = created_file.as_ref() {
            let reopened_location =
                validate_wallet_location(&location.path, WalletPathRequirement::Existing)?;
            validate_created_wallet_location(created_file, &reopened_location)?;
        }
        configure(&connection)?;
        migrate(&connection)?;
        after_migration(&connection)?;
        if meta(&connection, "database_id")?.is_some() {
            return Err(StoreError::AlreadyInitialized);
        }

        let mut database_id = [0_u8; DATABASE_ID_BYTES];
        let mut salt = [0_u8; SALT_BYTES];
        getrandom::fill(&mut database_id).map_err(|_| StoreError::Randomness)?;
        getrandom::fill(&mut salt).map_err(|_| StoreError::Randomness)?;
        let key = derive_key(passphrase, &salt, kdf)?;
        let sentinel = encrypt_record(
            &key,
            &database_id,
            SecretKind::MetadataKey.label(),
            b"key_check",
            SENTINEL,
        )?;
        let kdf_json = serde_json::to_vec(&kdf)?;

        let transaction = connection.unchecked_transaction()?;
        set_meta(&transaction, "database_id", &database_id)?;
        set_meta(&transaction, "kdf_salt", &salt)?;
        set_meta(&transaction, "kdf_config", &kdf_json)?;
        set_meta(&transaction, "key_check", &sentinel)?;
        transaction.commit()?;

        let store = Self {
            connection,
            database_id,
            salt,
            kdf,
            key: Some(key),
        };
        Ok((store, created_file, location.path))
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let location = validate_wallet_location(path.as_ref(), WalletPathRequirement::Existing)?;
        let recognition_connection = open_wallet_connection_read_only(&location.path)?;
        let recognized_location =
            validate_wallet_location(&location.path, WalletPathRequirement::Existing)?;
        validate_wallet_location_identity(&location, &recognized_location)?;
        let recognized_metadata = recognize_wallet_database(&recognition_connection)?;
        drop(recognition_connection);

        let connection = open_wallet_connection(&location.path)?;
        let reopened_location =
            validate_wallet_location(&location.path, WalletPathRequirement::Existing)?;
        validate_wallet_location_identity(&location, &reopened_location)?;
        if recognize_wallet_database(&connection)? != recognized_metadata {
            return Err(StoreError::CorruptMetadata);
        }
        configure(&connection)?;
        migrate(&connection)?;
        let metadata = load_wallet_metadata(&connection)?;
        if metadata != recognized_metadata {
            return Err(StoreError::CorruptMetadata);
        }
        Ok(Self {
            connection,
            database_id: metadata.database_id,
            salt: metadata.salt,
            kdf: metadata.kdf,
            key: None,
        })
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), StoreError> {
        validate_passphrase(passphrase)?;
        let key = derive_key(passphrase, &self.salt, self.kdf)?;
        let encrypted = required_meta(&self.connection, "key_check")?;
        let clear = decrypt_record(
            &key,
            &self.database_id,
            SecretKind::MetadataKey.label(),
            b"key_check",
            &encrypted,
        )
        .map_err(|_| StoreError::InvalidPassphrase)?;
        if clear.as_slice() != SENTINEL {
            return Err(StoreError::InvalidPassphrase);
        }
        self.key = Some(key);
        if let Err(error) = self
            .encrypt_legacy_rows()
            .and_then(|()| self.complete_plaintext_checkpoint())
        {
            self.key = None;
            return Err(error);
        }
        Ok(())
    }

    pub fn lock(&mut self) {
        self.key = None;
    }

    pub const fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    pub const fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    pub fn put_secret(
        &mut self,
        id: &[u8],
        kind: SecretKind,
        cleartext: &[u8],
        updated_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_id(id)?;
        if cleartext.is_empty() || cleartext.len() > MAX_SECRET_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT kind, encrypted_value FROM secrets WHERE id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((current_kind, current_encrypted)) = current {
            if current_kind != kind.label() {
                return Err(StoreError::KindMismatch);
            }
            if kind == SecretKind::RecoverySeed {
                let current_clear =
                    decrypt_record(key, &self.database_id, kind.label(), id, &current_encrypted)?;
                if current_clear.as_slice() == cleartext {
                    transaction.commit()?;
                    return Ok(());
                }
                return Err(StoreError::ProtectedSecret);
            }
        }
        let encrypted = encrypt_record(key, &self.database_id, kind.label(), id, cleartext)?;
        transaction.execute(
            "INSERT INTO secrets(id, kind, encrypted_value, updated_at_unix) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET encrypted_value=excluded.encrypted_value,
             updated_at_unix=excluded.updated_at_unix",
            params![id, kind.label(), encrypted, updated_at_unix],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically initializes the immutable recovery seed and the first wallet
    /// account record. Both namespaces must be empty and both target IDs must
    /// be absent. The immediate transaction serializes competing initializers;
    /// a failure before commit leaves neither row behind.
    pub fn initialize_recovery_seed_and_wallet_account<T: Serialize>(
        &mut self,
        recovery_seed_id: &[u8],
        recovery_seed: &[u8],
        wallet_account_id: &[u8],
        wallet_account: &T,
        updated_at_unix: u64,
    ) -> Result<u64, StoreError> {
        self.initialize_recovery_seed_and_wallet_account_with_hook(
            recovery_seed_id,
            recovery_seed,
            wallet_account_id,
            wallet_account,
            updated_at_unix,
            || Ok(()),
        )
    }

    fn initialize_recovery_seed_and_wallet_account_with_hook<T: Serialize>(
        &mut self,
        recovery_seed_id: &[u8],
        recovery_seed: &[u8],
        wallet_account_id: &[u8],
        wallet_account: &T,
        updated_at_unix: u64,
        after_seed_write: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<u64, StoreError> {
        validate_id(recovery_seed_id)?;
        validate_id(wallet_account_id)?;
        if recovery_seed.len() != RECOVERY_SEED_BYTES {
            return Err(StoreError::InvalidRecoverySeed);
        }
        let encoded_account = Zeroizing::new(serde_json::to_vec(wallet_account)?);
        if encoded_account.is_empty() || encoded_account.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }

        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current_seed: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT kind, encrypted_value FROM secrets WHERE id=?1",
                params![recovery_seed_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((kind, encrypted)) = current_seed {
            if kind != SecretKind::RecoverySeed.label() {
                return Err(StoreError::KindMismatch);
            }
            decrypt_record(
                key,
                &self.database_id,
                SecretKind::RecoverySeed.label(),
                recovery_seed_id,
                &encrypted,
            )?;
            return Err(StoreError::BootstrapConflict);
        }

        let recovery_seed_count: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM secrets WHERE kind=?1",
            params![SecretKind::RecoverySeed.label()],
            |row| row.get(0),
        )?;
        if recovery_seed_count != 0 {
            return Err(StoreError::BootstrapConflict);
        }

        if let Some(actual) = authenticated_entity_revision(
            &transaction,
            key,
            &self.database_id,
            EntityKind::WalletAccount,
            wallet_account_id,
        )? {
            return Err(StoreError::StaleRevision {
                expected: 0,
                actual,
            });
        }
        let wallet_account_count: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM encrypted_entities WHERE entity_kind=?1",
            params![EntityKind::WalletAccount.label()],
            |row| row.get(0),
        )?;
        if wallet_account_count != 0 {
            return Err(StoreError::BootstrapConflict);
        }

        let account_revision = 1_u64;
        let encrypted_seed = encrypt_record(
            key,
            &self.database_id,
            SecretKind::RecoverySeed.label(),
            recovery_seed_id,
            recovery_seed,
        )?;
        let encrypted_account = encrypt_record(
            key,
            &self.database_id,
            &entity_label(EntityKind::WalletAccount),
            &revisioned_aad_id(wallet_account_id, account_revision, updated_at_unix, None)?,
            &encoded_account,
        )?;

        transaction.execute(
            "INSERT INTO secrets(id, kind, encrypted_value, updated_at_unix)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                recovery_seed_id,
                SecretKind::RecoverySeed.label(),
                encrypted_seed,
                updated_at_unix,
            ],
        )?;
        after_seed_write()?;
        transaction.execute(
            "INSERT INTO encrypted_entities(
                 entity_kind, record_id, revision, encrypted_value, updated_at_unix
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                EntityKind::WalletAccount.label(),
                wallet_account_id,
                account_revision,
                encrypted_account,
                updated_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(account_revision)
    }

    /// Authenticates that `recovery_seed_id` is the only recovery seed in this
    /// database. Native products use this with their exact one-account check
    /// so an interrupted or legacy partial bootstrap is never silently
    /// accepted as a complete mobile wallet.
    pub fn validate_single_recovery_seed(
        &mut self,
        recovery_seed_id: &[u8],
    ) -> Result<(), StoreError> {
        validate_id(recovery_seed_id)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT kind, encrypted_value FROM secrets WHERE id=?1",
                params![recovery_seed_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((kind, encrypted)) = current else {
            return Err(StoreError::BootstrapConflict);
        };
        if kind != SecretKind::RecoverySeed.label() {
            return Err(StoreError::KindMismatch);
        }
        let seed = decrypt_record(
            key,
            &self.database_id,
            SecretKind::RecoverySeed.label(),
            recovery_seed_id,
            &encrypted,
        )?;
        if seed.len() != RECOVERY_SEED_BYTES {
            return Err(StoreError::InvalidRecoverySeed);
        }
        let recovery_seed_count: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM secrets WHERE kind=?1",
            params![SecretKind::RecoverySeed.label()],
            |row| row.get(0),
        )?;
        if recovery_seed_count != 1 {
            return Err(StoreError::BootstrapConflict);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_secret(
        &self,
        id: &[u8],
        expected_kind: SecretKind,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        validate_id(id)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let row: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT kind, encrypted_value FROM secrets WHERE id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((kind, encrypted)) = row else {
            return Ok(None);
        };
        if kind != expected_kind.label() {
            return Err(StoreError::KindMismatch);
        }
        decrypt_record(
            key,
            &self.database_id,
            expected_kind.label(),
            id,
            &encrypted,
        )
        .map(Some)
    }

    pub fn delete_secret(&mut self, id: &[u8]) -> Result<bool, StoreError> {
        validate_id(id)?;
        self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_kind: Option<String> = transaction
            .query_row("SELECT kind FROM secrets WHERE id=?1", params![id], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(current_kind) = current_kind else {
            return Ok(false);
        };
        if current_kind == SecretKind::RecoverySeed.label() {
            return Err(StoreError::ProtectedSecret);
        }
        transaction.execute("DELETE FROM secrets WHERE id=?1", params![id])?;
        transaction.commit()?;
        Ok(true)
    }

    /// Saves one typed entity with compare-and-swap semantics. The entity kind,
    /// database identity, and record ID are authenticated with the ciphertext.
    pub fn save_entity<T: Serialize>(
        &mut self,
        kind: EntityKind,
        id: &[u8],
        expected_revision: u64,
        value: &T,
        updated_at_unix: u64,
    ) -> Result<u64, StoreError> {
        validate_id(id)?;
        let encoded = Zeroizing::new(serde_json::to_vec(value)?);
        if encoded.is_empty() || encoded.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let label = entity_label(kind);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u64, Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT revision, encrypted_value, updated_at_unix
                 FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
                params![kind.label(), id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let actual = match current {
            Some((revision, encrypted, current_updated_at)) => {
                decrypt_record(
                    key,
                    &self.database_id,
                    &label,
                    &revisioned_aad_id(id, revision, current_updated_at, None)?,
                    &encrypted,
                )?;
                revision
            }
            None => 0,
        };
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let aad_id = revisioned_aad_id(id, next, updated_at_unix, None)?;
        let encrypted = encrypt_record(key, &self.database_id, &label, &aad_id, &encoded)?;
        transaction.execute(
            "INSERT INTO encrypted_entities(
                 entity_kind, record_id, revision, encrypted_value, updated_at_unix
             ) VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(entity_kind, record_id) DO UPDATE SET
                 revision=excluded.revision,
                 encrypted_value=excluded.encrypted_value,
                 updated_at_unix=excluded.updated_at_unix",
            params![kind.label(), id, next, encrypted, updated_at_unix],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    pub fn load_entity<T: for<'de> Deserialize<'de>>(
        &self,
        kind: EntityKind,
        id: &[u8],
    ) -> Result<Option<StoredEntity<T>>, StoreError> {
        validate_id(id)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let row: Option<(u64, Vec<u8>, u64)> = self
            .connection
            .query_row(
                "SELECT revision, encrypted_value, updated_at_unix
                 FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
                params![kind.label(), id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(revision, encrypted, updated_at_unix)| {
            let clear = decrypt_record(
                key,
                &self.database_id,
                &entity_label(kind),
                &revisioned_aad_id(id, revision, updated_at_unix, None)?,
                &encrypted,
            )?;
            Ok(StoredEntity {
                kind,
                id: id.to_vec(),
                revision,
                value: serde_json::from_slice(&clear)?,
                updated_at_unix,
            })
        })
        .transpose()
    }

    pub fn list_entities<T: for<'de> Deserialize<'de>>(
        &self,
        kind: EntityKind,
        limit: usize,
    ) -> Result<Vec<StoredEntity<T>>, StoreError> {
        if limit == 0 || limit > MAX_ENTITY_LIST_RESULTS {
            return Err(StoreError::InvalidListLimit);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::InvalidListLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision, encrypted_value, updated_at_unix
             FROM encrypted_entities WHERE entity_kind=?1 ORDER BY record_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![kind.label(), limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        let mut entities = Vec::new();
        for row in rows {
            let (id, revision, encrypted, updated_at_unix) = row?;
            validate_id(&id)?;
            let clear = decrypt_record(
                key,
                &self.database_id,
                &entity_label(kind),
                &revisioned_aad_id(&id, revision, updated_at_unix, None)?,
                &encrypted,
            )?;
            entities.push(StoredEntity {
                kind,
                id,
                revision,
                value: serde_json::from_slice(&clear)?,
                updated_at_unix,
            });
        }
        Ok(entities)
    }

    /// Return the complete bounded set for one binary record-ID prefix.
    /// Unlike [`Self::list_entities`], this rejects a matching set larger than
    /// `limit` instead of silently truncating account-scoped recovery state.
    pub fn list_entities_by_id_prefix<T: for<'de> Deserialize<'de>>(
        &self,
        kind: EntityKind,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<StoredEntity<T>>, StoreError> {
        validate_id(prefix)?;
        if limit == 0 || limit > MAX_ENTITY_LIST_RESULTS {
            return Err(StoreError::InvalidListLimit);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let query_limit = limit
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(StoreError::InvalidListLimit)?;
        let prefix_length = i64::try_from(prefix.len()).map_err(|_| StoreError::InvalidRecordId)?;
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision, encrypted_value, updated_at_unix
             FROM encrypted_entities
             WHERE entity_kind=?1 AND substr(record_id, 1, ?2)=?3
             ORDER BY record_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![kind.label(), prefix_length, prefix, query_limit],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            },
        )?;
        let mut encrypted_entities = Vec::new();
        for row in rows {
            encrypted_entities.push(row?);
        }
        if encrypted_entities.len() > limit {
            return Err(StoreError::ListCapacity);
        }
        let mut entities = Vec::with_capacity(encrypted_entities.len());
        for (id, revision, encrypted, updated_at_unix) in encrypted_entities {
            validate_id(&id)?;
            let clear = decrypt_record(
                key,
                &self.database_id,
                &entity_label(kind),
                &revisioned_aad_id(&id, revision, updated_at_unix, None)?,
                &encrypted,
            )?;
            entities.push(StoredEntity {
                kind,
                id,
                revision,
                value: serde_json::from_slice(&clear)?,
                updated_at_unix,
            });
        }
        Ok(entities)
    }

    pub fn delete_entity(
        &mut self,
        kind: EntityKind,
        id: &[u8],
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        validate_id(id)?;
        if kind.deletion_protected() {
            return Err(StoreError::ProtectedEntity);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        if expected_revision == 0 {
            return Err(StoreError::InvalidRevision);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u64, Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT revision, encrypted_value, updated_at_unix
                 FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
                params![kind.label(), id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((actual, encrypted, updated_at_unix)) = current else {
            return Ok(false);
        };
        decrypt_record(
            key,
            &self.database_id,
            &entity_label(kind),
            &revisioned_aad_id(id, actual, updated_at_unix, None)?,
            &encrypted,
        )?;
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        transaction.execute(
            "DELETE FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
            params![kind.label(), id],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    entity_crud_methods!(
        (
            save_wallet_account,
            wallet_account,
            wallet_accounts,
            delete_wallet_account,
            WalletAccount
        ),
        (
            save_derived_address,
            derived_address,
            derived_addresses,
            delete_derived_address,
            DerivedAddress
        ),
        (save_hns_utxo, hns_utxo, hns_utxos, delete_hns_utxo, HnsUtxo),
        (
            save_hns_transaction,
            hns_transaction,
            hns_transactions,
            delete_hns_transaction,
            HnsTransaction
        ),
        (
            save_known_name,
            known_name,
            known_names,
            delete_known_name,
            KnownName
        ),
        (
            save_name_owner_outpoint,
            name_owner_outpoint,
            name_owner_outpoints,
            delete_name_owner_outpoint,
            NameOwnerOutpoint
        ),
        (
            save_name_transfer,
            name_transfer,
            name_transfers,
            delete_name_transfer,
            NameTransfer
        ),
        (
            save_shakedex,
            shakedex,
            shakedex_records,
            delete_shakedex,
            Shakedex
        ),
        (
            save_denuo_board_object,
            denuo_board_object,
            denuo_board_objects,
            delete_denuo_board_object,
            DenuoBoardObject
        ),
        (
            save_bitcoin_header,
            bitcoin_header,
            bitcoin_headers,
            delete_bitcoin_header,
            BitcoinHeader
        ),
        (
            save_bitcoin_filter_header,
            bitcoin_filter_header,
            bitcoin_filter_headers,
            delete_bitcoin_filter_header,
            BitcoinFilterHeader
        ),
        (
            save_bitcoin_peer,
            bitcoin_peer,
            bitcoin_peers,
            delete_bitcoin_peer,
            BitcoinPeer
        ),
        (
            save_bitcoin_wallet_state,
            bitcoin_wallet_state,
            bitcoin_wallet_states,
            delete_bitcoin_wallet_state,
            BitcoinWalletState
        ),
        (
            save_bitcoin_scan_state,
            bitcoin_scan_state,
            bitcoin_scan_states,
            delete_bitcoin_scan_state,
            BitcoinScanState
        ),
        (
            save_bitcoin_utxo,
            bitcoin_utxo,
            bitcoin_utxos,
            delete_bitcoin_utxo,
            BitcoinUtxo
        ),
        (
            save_bitcoin_transaction,
            bitcoin_transaction,
            bitcoin_transactions,
            delete_bitcoin_transaction,
            BitcoinTransaction
        ),
        (
            save_ethereum_account,
            ethereum_account,
            ethereum_accounts,
            delete_ethereum_account,
            EthereumAccount
        ),
        (
            save_ethereum_transaction,
            ethereum_transaction,
            ethereum_transactions,
            delete_ethereum_transaction,
            EthereumTransaction
        ),
        (
            save_market_intent,
            market_intent,
            market_intents,
            delete_market_intent,
            MarketIntent
        ),
        (
            save_fill_grant,
            fill_grant,
            fill_grants,
            delete_fill_grant,
            FillGrant
        ),
        (
            save_price_round,
            price_round,
            price_rounds,
            delete_price_round,
            PriceRound
        ),
        (
            save_swap_session,
            swap_session,
            swap_sessions,
            delete_swap_session,
            SwapSession
        ),
        (
            save_refund_transaction,
            refund_transaction,
            refund_transactions,
            delete_refund_transaction,
            RefundTransaction
        ),
        (
            save_hns_recovery_state,
            hns_recovery_state,
            hns_recovery_states,
            delete_hns_recovery_state,
            HnsRecoveryState
        ),
        (
            save_hns_verified_settlement,
            hns_verified_settlement,
            hns_verified_settlements,
            delete_hns_verified_settlement,
            HnsVerifiedSettlement
        ),
        (
            save_pending_approval_entity,
            pending_approval_entity,
            pending_approval_entities,
            delete_pending_approval_entity,
            PendingApproval
        ),
        (
            save_input_reservation,
            input_reservation,
            input_reservations,
            delete_input_reservation,
            InputReservation
        ),
    );

    /// Compare-and-swap a persisted workflow revision. A caller must complete
    /// this operation before broadcasting the transaction represented by
    /// `state`.
    pub fn save_workflow<T: Serialize>(
        &mut self,
        id: WorkflowId,
        kind: WorkflowKind,
        expected_revision: u64,
        state: &T,
        irreversible_broadcast_prepared: bool,
        updated_at_unix: u64,
    ) -> Result<u64, StoreError> {
        let encoded = Zeroizing::new(serde_json::to_vec(state)?);
        if encoded.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let label = workflow_label(kind);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(String, u64, Vec<u8>, bool, u64, u32)> = transaction
            .query_row(
                "SELECT kind, revision, state_json, broadcast_prepared,
                        updated_at_unix, encryption_version
                 FROM workflows WHERE id=?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let actual = match current {
            Some((stored_kind, revision, encrypted, broadcast, updated_at, version)) => {
                let parsed_kind = parse_workflow_kind(&stored_kind)?;
                if parsed_kind != kind {
                    return Err(StoreError::WorkflowKindMismatch);
                }
                if version != 1 {
                    return Err(StoreError::LegacyEncryptionPending);
                }
                decrypt_record(
                    key,
                    &self.database_id,
                    &workflow_label(parsed_kind),
                    &revisioned_aad_id(id.as_bytes(), revision, updated_at, Some(broadcast))?,
                    &encrypted,
                )?;
                revision
            }
            None => 0,
        };
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let aad_id = revisioned_aad_id(
            id.as_bytes(),
            next,
            updated_at_unix,
            Some(irreversible_broadcast_prepared),
        )?;
        let encrypted = encrypt_record(key, &self.database_id, &label, &aad_id, &encoded)?;
        transaction.execute(
            "INSERT INTO workflows(
                 id, kind, revision, state_json, broadcast_prepared, updated_at_unix,
                 encryption_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
             state_json=excluded.state_json, broadcast_prepared=excluded.broadcast_prepared,
             updated_at_unix=excluded.updated_at_unix,
             encryption_version=excluded.encryption_version",
            params![
                id.as_bytes().as_slice(),
                workflow_kind(kind),
                next,
                encrypted,
                irreversible_broadcast_prepared,
                updated_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    /// Atomically advances a workflow and a complete same-kind entity set.
    /// This is the funds-safety boundary used for input reservation prepare,
    /// activation, cancellation, and terminal release.
    #[allow(clippy::too_many_arguments)]
    pub fn save_workflow_with_entity_batch<W: Serialize, E: Serialize>(
        &mut self,
        id: WorkflowId,
        kind: WorkflowKind,
        expected_revision: u64,
        state: &W,
        irreversible_broadcast_prepared: bool,
        updated_at_unix: u64,
        entity_kind: EntityKind,
        saves: &[EntityBatchSave<E>],
        deletes: &[EntityBatchDelete],
    ) -> Result<u64, StoreError> {
        let encoded_workflow = Zeroizing::new(serde_json::to_vec(state)?);
        if encoded_workflow.is_empty() || encoded_workflow.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let prepared_entities = prepare_entity_batch(saves, deletes)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual =
            authenticated_workflow_revision(&transaction, key, &self.database_id, id, kind)?;
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        apply_entity_batch_in_transaction(
            &transaction,
            key,
            &self.database_id,
            entity_kind,
            &prepared_entities,
            deletes,
        )?;
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let encrypted = encrypt_record(
            key,
            &self.database_id,
            &workflow_label(kind),
            &revisioned_aad_id(
                id.as_bytes(),
                next,
                updated_at_unix,
                Some(irreversible_broadcast_prepared),
            )?,
            &encoded_workflow,
        )?;
        transaction.execute(
            "INSERT INTO workflows(
                 id, kind, revision, state_json, broadcast_prepared, updated_at_unix,
                 encryption_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
             state_json=excluded.state_json, broadcast_prepared=excluded.broadcast_prepared,
             updated_at_unix=excluded.updated_at_unix,
             encryption_version=excluded.encryption_version",
            params![
                id.as_bytes().as_slice(),
                workflow_kind(kind),
                next,
                encrypted,
                irreversible_broadcast_prepared,
                updated_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    /// Atomically consumes an already-authenticated approval, advances one
    /// workflow revision, and applies its reservation/entity changes. A
    /// missing, expired, or changed approval returns None without advancing
    /// the workflow. No validation failure consumes the approval.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_approval_and_save_workflow_with_entity_batch<W: Serialize, E: Serialize>(
        &mut self,
        expected_approval: &PendingApproval,
        now_unix: u64,
        id: WorkflowId,
        kind: WorkflowKind,
        expected_revision: u64,
        state: &W,
        irreversible_broadcast_prepared: bool,
        entity_kind: EntityKind,
        saves: &[EntityBatchSave<E>],
        deletes: &[EntityBatchDelete],
    ) -> Result<Option<u64>, StoreError> {
        let encoded_workflow = Zeroizing::new(serde_json::to_vec(state)?);
        if encoded_workflow.is_empty() || encoded_workflow.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let prepared_entities = prepare_entity_batch(saves, deletes)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(current_approval) = authenticated_pending_approval(
            &transaction,
            key,
            &self.database_id,
            expected_approval.id,
        )?
        else {
            return Ok(None);
        };
        if current_approval.expires_at_unix <= now_unix {
            transaction.execute(
                "DELETE FROM private_pending_approvals WHERE id=?1",
                params![expected_approval.id.as_bytes().as_slice()],
            )?;
            transaction.commit()?;
            return Ok(None);
        }
        if current_approval.origin.as_str() != expected_approval.origin.as_str()
            || current_approval.expires_at_unix != expected_approval.expires_at_unix
            || current_approval.request_json.as_slice() != expected_approval.request_json.as_slice()
        {
            return Ok(None);
        }
        let actual =
            authenticated_workflow_revision(&transaction, key, &self.database_id, id, kind)?;
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let encrypted_entities = authenticate_entity_batch(
            &transaction,
            key,
            &self.database_id,
            entity_kind,
            &prepared_entities,
            deletes,
        )?;
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let encrypted_workflow = encrypt_record(
            key,
            &self.database_id,
            &workflow_label(kind),
            &revisioned_aad_id(
                id.as_bytes(),
                next,
                now_unix,
                Some(irreversible_broadcast_prepared),
            )?,
            &encoded_workflow,
        )?;
        write_entity_batch_in_transaction(&transaction, entity_kind, &encrypted_entities, deletes)?;
        transaction.execute(
            "DELETE FROM private_pending_approvals WHERE id=?1",
            params![expected_approval.id.as_bytes().as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO workflows(
                 id, kind, revision, state_json, broadcast_prepared, updated_at_unix,
                 encryption_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
             state_json=excluded.state_json, broadcast_prepared=excluded.broadcast_prepared,
             updated_at_unix=excluded.updated_at_unix,
             encryption_version=excluded.encryption_version",
            params![
                id.as_bytes().as_slice(),
                workflow_kind(kind),
                next,
                encrypted_workflow,
                irreversible_broadcast_prepared,
                now_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(Some(next))
    }

    /// Atomically advances a workflow, its wallet-account record, and a
    /// bounded second entity set. Every existing revision and ciphertext is
    /// authenticated before the first write. Duplicate `(kind, id)` operations
    /// are rejected across both entity groups.
    #[allow(clippy::too_many_arguments)]
    pub fn save_workflow_with_account_and_entity_batch<W: Serialize, A: Serialize, E: Serialize>(
        &mut self,
        id: WorkflowId,
        kind: WorkflowKind,
        expected_revision: u64,
        state: &W,
        irreversible_broadcast_prepared: bool,
        updated_at_unix: u64,
        account_save: &EntityBatchSave<A>,
        entity_kind: EntityKind,
        saves: &[EntityBatchSave<E>],
        deletes: &[EntityBatchDelete],
    ) -> Result<(u64, u64), StoreError> {
        let operation_count = 1_usize
            .checked_add(saves.len())
            .and_then(|count| count.checked_add(deletes.len()))
            .ok_or(StoreError::BatchCapacity)?;
        if operation_count > MAX_ENTITY_BATCH_OPERATIONS {
            return Err(StoreError::BatchCapacity);
        }

        let encoded_workflow = Zeroizing::new(serde_json::to_vec(state)?);
        if encoded_workflow.is_empty() || encoded_workflow.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let prepared_account = prepare_entity_batch(std::slice::from_ref(account_save), &[])?;
        let prepared_entities = prepare_entity_batch(saves, deletes)?;
        let mut operation_ids = BTreeSet::new();
        for (record_id, ..) in &prepared_account {
            operation_ids.insert((EntityKind::WalletAccount, record_id.clone()));
        }
        for (record_id, ..) in &prepared_entities {
            if !operation_ids.insert((entity_kind, record_id.clone())) {
                return Err(StoreError::DuplicateBatchEntity);
            }
        }
        for delete in deletes {
            if !operation_ids.insert((entity_kind, delete.id.clone())) {
                return Err(StoreError::DuplicateBatchEntity);
            }
        }

        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual =
            authenticated_workflow_revision(&transaction, key, &self.database_id, id, kind)?;
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let authenticated_account = authenticate_entity_batch(
            &transaction,
            key,
            &self.database_id,
            EntityKind::WalletAccount,
            &prepared_account,
            &[],
        )?;
        let authenticated_entities = authenticate_entity_batch(
            &transaction,
            key,
            &self.database_id,
            entity_kind,
            &prepared_entities,
            deletes,
        )?;

        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let account_next = authenticated_account
            .first()
            .map(|(_, revision, _, _)| *revision)
            .ok_or(StoreError::CorruptMetadata)?;
        let encrypted_workflow = encrypt_record(
            key,
            &self.database_id,
            &workflow_label(kind),
            &revisioned_aad_id(
                id.as_bytes(),
                next,
                updated_at_unix,
                Some(irreversible_broadcast_prepared),
            )?,
            &encoded_workflow,
        )?;

        write_entity_batch_in_transaction(
            &transaction,
            EntityKind::WalletAccount,
            &authenticated_account,
            &[],
        )?;
        write_entity_batch_in_transaction(
            &transaction,
            entity_kind,
            &authenticated_entities,
            deletes,
        )?;
        transaction.execute(
            "INSERT INTO workflows(
                 id, kind, revision, state_json, broadcast_prepared, updated_at_unix,
                 encryption_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
             state_json=excluded.state_json, broadcast_prepared=excluded.broadcast_prepared,
             updated_at_unix=excluded.updated_at_unix,
             encryption_version=excluded.encryption_version",
            params![
                id.as_bytes().as_slice(),
                workflow_kind(kind),
                next,
                encrypted_workflow,
                irreversible_broadcast_prepared,
                updated_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok((next, account_next))
    }

    /// Atomically advances one wallet account together with a bounded entity
    /// batch. Both namespaces are authenticated and every expected revision
    /// is checked under the same immediate transaction before the first write.
    pub fn apply_account_and_entity_batch<A: Serialize, E: Serialize>(
        &mut self,
        account_save: &EntityBatchSave<A>,
        entity_kind: EntityKind,
        saves: &[EntityBatchSave<E>],
        deletes: &[EntityBatchDelete],
    ) -> Result<u64, StoreError> {
        if entity_kind == EntityKind::WalletAccount {
            return Err(StoreError::DuplicateBatchEntity);
        }
        let operation_count = 1_usize
            .checked_add(saves.len())
            .and_then(|count| count.checked_add(deletes.len()))
            .ok_or(StoreError::BatchCapacity)?;
        if operation_count > MAX_ENTITY_BATCH_OPERATIONS {
            return Err(StoreError::BatchCapacity);
        }
        let prepared_account = prepare_entity_batch(std::slice::from_ref(account_save), &[])?;
        let prepared_entities = prepare_entity_batch(saves, deletes)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authenticated_account = authenticate_entity_batch(
            &transaction,
            key,
            &self.database_id,
            EntityKind::WalletAccount,
            &prepared_account,
            &[],
        )?;
        let authenticated_entities = authenticate_entity_batch(
            &transaction,
            key,
            &self.database_id,
            entity_kind,
            &prepared_entities,
            deletes,
        )?;
        let account_next = authenticated_account
            .first()
            .map(|(_, revision, _, _)| *revision)
            .ok_or(StoreError::CorruptMetadata)?;
        write_entity_batch_in_transaction(
            &transaction,
            EntityKind::WalletAccount,
            &authenticated_account,
            &[],
        )?;
        write_entity_batch_in_transaction(
            &transaction,
            entity_kind,
            &authenticated_entities,
            deletes,
        )?;
        transaction.commit()?;
        Ok(account_next)
    }

    pub fn apply_entity_batch<E: Serialize>(
        &mut self,
        entity_kind: EntityKind,
        saves: &[EntityBatchSave<E>],
        deletes: &[EntityBatchDelete],
    ) -> Result<(), StoreError> {
        let prepared_entities = prepare_entity_batch(saves, deletes)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        apply_entity_batch_in_transaction(
            &transaction,
            key,
            &self.database_id,
            entity_kind,
            &prepared_entities,
            deletes,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load_workflow<T: for<'de> Deserialize<'de>>(
        &self,
        id: WorkflowId,
    ) -> Result<Option<StoredWorkflow<T>>, StoreError> {
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let row: Option<(String, u64, Vec<u8>, bool, u64, u32)> = self
            .connection
            .query_row(
                "SELECT kind, revision, state_json, broadcast_prepared, updated_at_unix,
                        encryption_version
                 FROM workflows WHERE id=?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(kind, revision, state, broadcast_prepared, updated_at_unix, encryption_version)| {
                if encryption_version != 1 {
                    return Err(StoreError::LegacyEncryptionPending);
                }
                let parsed_kind = parse_workflow_kind(&kind)?;
                let clear = decrypt_record(
                    key,
                    &self.database_id,
                    &workflow_label(parsed_kind),
                    &revisioned_aad_id(
                        id.as_bytes(),
                        revision,
                        updated_at_unix,
                        Some(broadcast_prepared),
                    )?,
                    &state,
                )?;
                Ok(StoredWorkflow {
                    id,
                    kind: parsed_kind,
                    revision,
                    state: serde_json::from_slice(&clear)?,
                    irreversible_broadcast_prepared: broadcast_prepared,
                    updated_at_unix,
                })
            },
        )
        .transpose()
    }

    pub fn list_workflows<T: for<'de> Deserialize<'de>>(
        &self,
        kind: WorkflowKind,
        limit: usize,
    ) -> Result<Vec<StoredWorkflow<T>>, StoreError> {
        if limit == 0 || limit > MAX_ENTITY_LIST_RESULTS {
            return Err(StoreError::InvalidListLimit);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::InvalidListLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT id, revision, state_json, broadcast_prepared, updated_at_unix,
                    encryption_version
             FROM workflows WHERE kind=?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![workflow_kind(kind), limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, u32>(5)?,
            ))
        })?;
        let mut workflows = Vec::new();
        for row in rows {
            let (id, revision, state, broadcast_prepared, updated_at_unix, encryption_version) =
                row?;
            if encryption_version != 1 {
                return Err(StoreError::LegacyEncryptionPending);
            }
            let id = WorkflowId::new(id.try_into().map_err(|_| StoreError::CorruptMetadata)?);
            let clear = decrypt_record(
                key,
                &self.database_id,
                &workflow_label(kind),
                &revisioned_aad_id(
                    id.as_bytes(),
                    revision,
                    updated_at_unix,
                    Some(broadcast_prepared),
                )?,
                &state,
            )?;
            workflows.push(StoredWorkflow {
                id,
                kind,
                revision,
                state: serde_json::from_slice(&clear)?,
                irreversible_broadcast_prepared: broadcast_prepared,
                updated_at_unix,
            });
        }
        Ok(workflows)
    }

    /// Return every workflow of `kind` within one explicit bound, rejecting
    /// overflow instead of silently omitting recovery state with opaque IDs.
    pub fn list_workflows_complete<T: for<'de> Deserialize<'de>>(
        &self,
        kind: WorkflowKind,
        limit: usize,
    ) -> Result<Vec<StoredWorkflow<T>>, StoreError> {
        if limit == 0 || limit > MAX_ENTITY_LIST_RESULTS {
            return Err(StoreError::InvalidListLimit);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let query_limit = limit
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(StoreError::InvalidListLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT id, revision, state_json, broadcast_prepared, updated_at_unix,
                    encryption_version
             FROM workflows WHERE kind=?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![workflow_kind(kind), query_limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, u32>(5)?,
            ))
        })?;
        let mut encrypted_workflows = Vec::new();
        for row in rows {
            encrypted_workflows.push(row?);
        }
        if encrypted_workflows.len() > limit {
            return Err(StoreError::ListCapacity);
        }
        let mut workflows = Vec::with_capacity(encrypted_workflows.len());
        for (id, revision, state, broadcast_prepared, updated_at_unix, encryption_version) in
            encrypted_workflows
        {
            if encryption_version != 1 {
                return Err(StoreError::LegacyEncryptionPending);
            }
            let id = WorkflowId::new(id.try_into().map_err(|_| StoreError::CorruptMetadata)?);
            let clear = decrypt_record(
                key,
                &self.database_id,
                &workflow_label(kind),
                &revisioned_aad_id(
                    id.as_bytes(),
                    revision,
                    updated_at_unix,
                    Some(broadcast_prepared),
                )?,
                &state,
            )?;
            workflows.push(StoredWorkflow {
                id,
                kind,
                revision,
                state: serde_json::from_slice(&clear)?,
                irreversible_broadcast_prepared: broadcast_prepared,
                updated_at_unix,
            });
        }
        Ok(workflows)
    }

    pub fn put_provider_permission(
        &mut self,
        origin: &str,
        generation: u64,
        permission_json: &[u8],
        updated_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if generation == 0 {
            return Err(StoreError::InvalidGeneration);
        }
        if permission_json.is_empty() || permission_json.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let record_id = origin_lookup_token(key, &self.database_id, origin)?;
        let clear = encode_origin_payload(origin, permission_json)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u64, Vec<u8>, u64, bool)> = transaction
            .query_row(
                "SELECT generation, encrypted_record, updated_at_unix, revoked
                 FROM private_provider_permissions WHERE origin_token=?1",
                params![record_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let current_generation = match current.as_ref() {
            Some((generation, encrypted, current_updated_at, revoked)) => {
                let current_clear = decrypt_record(
                    key,
                    &self.database_id,
                    "provider_permission",
                    &permission_record_id(&record_id, *generation, *revoked, *current_updated_at),
                    encrypted,
                )?;
                let (stored_origin, _) = decode_origin_payload(&current_clear)?;
                if stored_origin != origin {
                    return Err(StoreError::Encryption);
                }
                *generation
            }
            None => 0,
        };
        let expected_generation = if current.is_none() {
            generation
        } else {
            current_generation
                .checked_add(1)
                .ok_or(StoreError::RevisionOverflow)?
        };
        if generation != expected_generation {
            return Err(StoreError::StaleGeneration {
                expected: expected_generation,
                actual: generation,
            });
        }
        let encrypted = encrypt_record(
            key,
            &self.database_id,
            "provider_permission",
            &permission_record_id(&record_id, generation, false, updated_at_unix),
            &clear,
        )?;
        if current.is_none() {
            let count: usize = transaction.query_row(
                "SELECT COUNT(*) FROM private_provider_permissions",
                [],
                |row| row.get(0),
            )?;
            if count >= MAX_PROVIDER_PERMISSIONS {
                return Err(StoreError::ProviderCapacity);
            }
        }
        transaction.execute(
            "INSERT INTO private_provider_permissions(
                 origin_token, generation, encrypted_record, updated_at_unix, revoked
             ) VALUES(?1, ?2, ?3, ?4, 0)
             ON CONFLICT(origin_token) DO UPDATE SET generation=excluded.generation,
             encrypted_record=excluded.encrypted_record,
             updated_at_unix=excluded.updated_at_unix, revoked=0",
            params![record_id.as_slice(), generation, encrypted, updated_at_unix],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn provider_permission(&self, origin: &str) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        validate_origin(origin)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let record_id = origin_lookup_token(key, &self.database_id, origin)?;
        let row: Option<(u64, Vec<u8>, u64, bool)> = self
            .connection
            .query_row(
                "SELECT generation, encrypted_record, updated_at_unix, revoked
                 FROM private_provider_permissions WHERE origin_token=?1",
                params![record_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(StoreError::from)?;
        row.map(|(generation, encrypted, updated_at_unix, revoked)| {
            let clear = decrypt_record(
                key,
                &self.database_id,
                "provider_permission",
                &permission_record_id(&record_id, generation, revoked, updated_at_unix),
                &encrypted,
            )?;
            let (stored_origin, permission_json) = decode_origin_payload(&clear)?;
            if stored_origin != origin {
                return Err(StoreError::Encryption);
            }
            if revoked {
                Ok(None)
            } else {
                Ok(Some((generation, permission_json.to_vec())))
            }
        })
        .transpose()
        .map(Option::flatten)
    }

    pub fn provider_permission_generation(&self, origin: &str) -> Result<Option<u64>, StoreError> {
        validate_origin(origin)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let record_id = origin_lookup_token(key, &self.database_id, origin)?;
        let row: Option<(u64, Vec<u8>, u64, bool)> = self
            .connection
            .query_row(
                "SELECT generation, encrypted_record, updated_at_unix, revoked
                 FROM private_provider_permissions WHERE origin_token=?1",
                params![record_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(generation, encrypted, updated_at_unix, revoked)| {
            let clear = decrypt_record(
                key,
                &self.database_id,
                "provider_permission",
                &permission_record_id(&record_id, generation, revoked, updated_at_unix),
                &encrypted,
            )?;
            let (stored_origin, _) = decode_origin_payload(&clear)?;
            if stored_origin != origin {
                return Err(StoreError::Encryption);
            }
            Ok(generation)
        })
        .transpose()
    }

    pub fn revoke_provider_permission(
        &mut self,
        origin: &str,
        expected_generation: u64,
        next_generation: u64,
        updated_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if expected_generation == 0
            || next_generation
                != expected_generation
                    .checked_add(1)
                    .ok_or(StoreError::RevisionOverflow)?
        {
            return Err(StoreError::InvalidGeneration);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let record_id = origin_lookup_token(key, &self.database_id, origin)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u64, Vec<u8>, u64, bool)> = transaction
            .query_row(
                "SELECT generation, encrypted_record, updated_at_unix, revoked
                 FROM private_provider_permissions WHERE origin_token=?1",
                params![record_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((generation, encrypted, current_updated_at, current_revoked)) = current else {
            return Err(StoreError::StaleGeneration {
                expected: expected_generation,
                actual: 0,
            });
        };
        if generation != expected_generation || current_revoked {
            return Err(StoreError::StaleGeneration {
                expected: expected_generation,
                actual: generation,
            });
        }
        let clear = decrypt_record(
            key,
            &self.database_id,
            "provider_permission",
            &permission_record_id(&record_id, generation, current_revoked, current_updated_at),
            &encrypted,
        )?;
        let (stored_origin, _) = decode_origin_payload(&clear)?;
        if stored_origin != origin {
            return Err(StoreError::Encryption);
        }
        let tombstone = encode_origin_payload(origin, b"revoked")?;
        let encrypted = encrypt_record(
            key,
            &self.database_id,
            "provider_permission",
            &permission_record_id(&record_id, next_generation, true, updated_at_unix),
            &tombstone,
        )?;
        transaction.execute(
            "UPDATE private_provider_permissions
             SET generation=?1, encrypted_record=?2, updated_at_unix=?3, revoked=1
             WHERE origin_token=?4",
            params![
                next_generation,
                encrypted,
                updated_at_unix,
                record_id.as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn put_pending_approval(
        &mut self,
        id: ApprovalId,
        origin: &str,
        request_json: &[u8],
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if expires_at_unix <= now_unix || expires_at_unix - now_unix > MAX_APPROVAL_LIFETIME_SECONDS
        {
            return Err(StoreError::InvalidApprovalWindow);
        }
        if request_json.is_empty() || request_json.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let origin_token = origin_lookup_token(key, &self.database_id, origin)?;
        let clear = encode_origin_payload(origin, request_json)?;
        let encrypted = encrypt_record(
            key,
            &self.database_id,
            "pending_approval",
            &approval_record_id(&id, &origin_token, expires_at_unix),
            &clear,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune_expired_approvals(&transaction, key, &self.database_id, now_unix)?;
        let count: usize = transaction.query_row(
            "SELECT COUNT(*) FROM private_pending_approvals",
            [],
            |row| row.get(0),
        )?;
        if count >= MAX_PENDING_APPROVALS {
            return Err(StoreError::ApprovalCapacity);
        }
        transaction.execute(
            "INSERT INTO private_pending_approvals(
                 id, origin_token, encrypted_record, expires_at_unix
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                id.as_bytes().as_slice(),
                origin_token.as_slice(),
                encrypted,
                expires_at_unix
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Authenticates and decrypts one live approval without consuming it.
    /// This permits signing and external evidence checks to complete before
    /// the approval participates in the final workflow CAS.
    pub fn get_pending_approval(
        &self,
        id: ApprovalId,
        now_unix: u64,
    ) -> Result<Option<PendingApproval>, StoreError> {
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        Ok(
            authenticated_pending_approval(&self.connection, key, &self.database_id, id)?
                .filter(|approval| approval.expires_at_unix > now_unix),
        )
    }

    /// Atomically removes and decrypts a pending approval. Expired approvals
    /// are deleted but never returned to the caller.
    pub fn take_pending_approval(
        &mut self,
        id: ApprovalId,
        now_unix: u64,
    ) -> Result<Option<PendingApproval>, StoreError> {
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(approval) =
            authenticated_pending_approval(&transaction, key, &self.database_id, id)?
        else {
            return Ok(None);
        };
        if approval.expires_at_unix <= now_unix {
            transaction.execute(
                "DELETE FROM private_pending_approvals WHERE id=?1",
                params![id.as_bytes().as_slice()],
            )?;
            transaction.commit()?;
            return Ok(None);
        }
        transaction.execute(
            "DELETE FROM private_pending_approvals WHERE id=?1",
            params![id.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        Ok(Some(approval))
    }

    /// Atomically consumes a request nonce. Duplicate live nonces fail.
    pub fn consume_replay_nonce(
        &mut self,
        origin: &str,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if nonce == 0
            || expires_at_unix <= now_unix
            || expires_at_unix - now_unix > MAX_REPLAY_LIFETIME_SECONDS
        {
            return Err(StoreError::InvalidReplayWindow);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let origin_token = origin_lookup_token(key, &self.database_id, origin)?;
        let record_id = replay_record_id(&origin_token, nonce, expires_at_unix);
        let encrypted_origin = encrypt_record(
            key,
            &self.database_id,
            "replay_origin",
            &record_id,
            origin.as_bytes(),
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune_expired_replay(&transaction, key, &self.database_id, now_unix)?;
        let count: usize = transaction.query_row(
            "SELECT COUNT(*) FROM private_replay_protection WHERE origin_token=?1",
            params![origin_token.as_slice()],
            |row| row.get(0),
        )?;
        if count >= MAX_REPLAY_ROWS_PER_ORIGIN {
            return Err(StoreError::ReplayCapacity);
        }
        let total: usize = transaction.query_row(
            "SELECT COUNT(*) FROM private_replay_protection",
            [],
            |row| row.get(0),
        )?;
        if total >= MAX_REPLAY_ROWS {
            return Err(StoreError::ReplayGlobalCapacity);
        }
        if count == 0 {
            let origin_count: usize = transaction.query_row(
                "SELECT COUNT(DISTINCT origin_token) FROM private_replay_protection",
                [],
                |row| row.get(0),
            )?;
            if origin_count >= MAX_REPLAY_ORIGINS {
                return Err(StoreError::ReplayOriginCapacity);
            }
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO private_replay_protection(
                 origin_token, nonce, encrypted_origin, expires_at_unix
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                origin_token.as_slice(),
                nonce,
                encrypted_origin,
                expires_at_unix
            ],
        )?;
        if inserted != 1 {
            return Err(StoreError::Replay);
        }
        transaction.commit()?;
        Ok(())
    }

    fn encrypt_legacy_rows(&mut self) -> Result<(), StoreError> {
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        reject_unmigrated_legacy_entities(&transaction)?;

        let workflows = {
            let mut statement = transaction.prepare(
                "SELECT id, kind, revision, state_json, broadcast_prepared, updated_at_unix
                 FROM workflows
                 WHERE encryption_version=0 ORDER BY id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, u64>(5)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let removed_plaintext = !workflows.is_empty();
        for (id, kind, revision, clear, broadcast_prepared, updated_at_unix) in workflows {
            let clear = Zeroizing::new(clear);
            validate_id(&id)?;
            let kind = parse_workflow_kind(&kind)?;
            let encrypted = encrypt_record(
                key,
                &self.database_id,
                &workflow_label(kind),
                &revisioned_aad_id(&id, revision, updated_at_unix, Some(broadcast_prepared))?,
                &clear,
            )?;
            transaction.execute(
                "UPDATE workflows SET state_json=?1, encryption_version=1 WHERE id=?2",
                params![encrypted, id],
            )?;
        }

        let permissions = {
            let mut statement = transaction.prepare(
                "SELECT origin, generation, permission_json, updated_at_unix
                 FROM provider_permissions ORDER BY origin",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if permissions.len() > MAX_PROVIDER_PERMISSIONS {
            return Err(StoreError::ProviderCapacity);
        }
        let removed_permissions = !permissions.is_empty();
        for (origin, generation, permission_json, updated_at_unix) in permissions {
            let permission_json = Zeroizing::new(permission_json);
            validate_origin(&origin)?;
            if generation == 0 {
                return Err(StoreError::InvalidGeneration);
            }
            let origin_token = origin_lookup_token(key, &self.database_id, &origin)?;
            let clear = encode_origin_payload(&origin, &permission_json)?;
            let encrypted = encrypt_record(
                key,
                &self.database_id,
                "provider_permission",
                &permission_record_id(&origin_token, generation, false, updated_at_unix),
                &clear,
            )?;
            transaction.execute(
                "INSERT INTO private_provider_permissions(
                     origin_token, generation, encrypted_record, updated_at_unix, revoked
                 ) VALUES(?1, ?2, ?3, ?4, 0)",
                params![
                    origin_token.as_slice(),
                    generation,
                    encrypted,
                    updated_at_unix
                ],
            )?;
        }

        // A legacy pending approval has no authenticated creation timestamp or
        // authority binding. It cannot be proven to satisfy the bounded window
        // used by the current schema, so migration deliberately invalidates it.
        let removed_approvals: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM pending_approvals LIMIT 1)",
            [],
            |row| row.get(0),
        )?;

        let replay_rows = {
            let mut statement = transaction.prepare(
                "SELECT origin, nonce, expires_at_unix
                 FROM replay_protection ORDER BY origin, nonce",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        validate_legacy_replay_capacity(&replay_rows)?;
        let removed_replay_rows = !replay_rows.is_empty();
        for (origin, nonce, expires_at_unix) in replay_rows {
            validate_origin(&origin)?;
            let origin_token = origin_lookup_token(key, &self.database_id, &origin)?;
            let record_id = replay_record_id(&origin_token, nonce, expires_at_unix);
            let encrypted_origin = encrypt_record(
                key,
                &self.database_id,
                "replay_origin",
                &record_id,
                origin.as_bytes(),
            )?;
            transaction.execute(
                "INSERT INTO private_replay_protection(
                     origin_token, nonce, encrypted_origin, expires_at_unix
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    origin_token.as_slice(),
                    nonce,
                    encrypted_origin,
                    expires_at_unix
                ],
            )?;
        }

        transaction.execute("DELETE FROM provider_permissions", [])?;
        transaction.execute("DELETE FROM pending_approvals", [])?;
        transaction.execute("DELETE FROM replay_protection", [])?;

        let removed_plaintext =
            removed_plaintext || removed_permissions || removed_approvals || removed_replay_rows;
        if removed_plaintext {
            set_meta(&transaction, CHECKPOINT_PENDING_KEY, b"1")?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn complete_plaintext_checkpoint(&mut self) -> Result<(), StoreError> {
        // Always truncate before returning unlocked. This retries even if a
        // prior process committed plaintext deletion but failed before it
        // could persist or clear the checkpoint marker.
        truncate_wal(&self.connection)?;
        if meta(&self.connection, CHECKPOINT_PENDING_KEY)?.is_some() {
            self.connection.execute(
                "DELETE FROM wallet_meta WHERE key=?1",
                params![CHECKPOINT_PENDING_KEY],
            )?;
            truncate_wal(&self.connection)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn create_in_memory(passphrase: &str) -> Result<Self, StoreError> {
        Self::create_with_kdf(":memory:", passphrase, KdfConfig::testing())
    }
}

fn complete_wallet_creation(
    created_file: &mut Option<CreatedWalletFile>,
    path: &Path,
) -> Result<(), StoreError> {
    if let Some(created_file) = created_file.as_mut() {
        let completed_location = validate_wallet_location(path, WalletPathRequirement::Existing)?;
        validate_created_wallet_location(created_file, &completed_location)?;
        created_file.disarm();
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredWorkflow<T> {
    pub id: WorkflowId,
    pub kind: WorkflowKind,
    pub revision: u64,
    pub state: T,
    pub irreversible_broadcast_prepared: bool,
    pub updated_at_unix: u64,
}

pub struct PendingApproval {
    pub id: ApprovalId,
    pub origin: String,
    pub request_json: Zeroizing<Vec<u8>>,
    pub expires_at_unix: u64,
}

impl core::fmt::Debug for PendingApproval {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingApproval")
            .field("id", &self.id)
            .field("origin", &self.origin)
            .field("request_json", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

type PreparedEntityBatch = Vec<(Vec<u8>, u64, Zeroizing<Vec<u8>>, u64)>;
type AuthenticatedEntityWrites = Vec<(Vec<u8>, u64, Vec<u8>, u64)>;

fn prepare_entity_batch<E: Serialize>(
    saves: &[EntityBatchSave<E>],
    deletes: &[EntityBatchDelete],
) -> Result<PreparedEntityBatch, StoreError> {
    if saves
        .len()
        .checked_add(deletes.len())
        .is_none_or(|count| count > MAX_ENTITY_BATCH_OPERATIONS)
    {
        return Err(StoreError::BatchCapacity);
    }
    let mut ids = BTreeSet::new();
    let mut prepared = Vec::with_capacity(saves.len());
    for save in saves {
        validate_id(&save.id)?;
        if !ids.insert(save.id.clone()) {
            return Err(StoreError::DuplicateBatchEntity);
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&save.value)?);
        if encoded.is_empty() || encoded.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        prepared.push((
            save.id.clone(),
            save.expected_revision,
            encoded,
            save.updated_at_unix,
        ));
    }
    for delete in deletes {
        validate_id(&delete.id)?;
        if delete.expected_revision == 0 || !ids.insert(delete.id.clone()) {
            return Err(StoreError::DuplicateBatchEntity);
        }
    }
    Ok(prepared)
}

fn authenticated_pending_approval(
    connection: &Connection,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    id: ApprovalId,
) -> Result<Option<PendingApproval>, StoreError> {
    let row: Option<(Vec<u8>, Vec<u8>, u64)> = connection
        .query_row(
            "SELECT origin_token, encrypted_record, expires_at_unix
             FROM private_pending_approvals WHERE id=?1",
            params![id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((origin_token, encrypted, expires_at_unix)) = row else {
        return Ok(None);
    };
    let origin_token: [u8; 32] = origin_token
        .try_into()
        .map_err(|_| StoreError::CorruptMetadata)?;
    let clear = decrypt_record(
        key,
        database_id,
        "pending_approval",
        &approval_record_id(&id, &origin_token, expires_at_unix),
        &encrypted,
    )?;
    let (origin, request_json) = decode_origin_payload(&clear)?;
    let expected_token = origin_lookup_token(key, database_id, &origin)?;
    if origin_token != expected_token {
        return Err(StoreError::Encryption);
    }
    Ok(Some(PendingApproval {
        id,
        origin,
        request_json,
        expires_at_unix,
    }))
}

fn authenticated_workflow_revision(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    id: WorkflowId,
    expected_kind: WorkflowKind,
) -> Result<u64, StoreError> {
    let current: Option<(String, u64, Vec<u8>, bool, u64, u32)> = transaction
        .query_row(
            "SELECT kind, revision, state_json, broadcast_prepared,
                    updated_at_unix, encryption_version
             FROM workflows WHERE id=?1",
            params![id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((kind, revision, encrypted, broadcast, updated_at, version)) = current else {
        return Ok(0);
    };
    let kind = parse_workflow_kind(&kind)?;
    if kind != expected_kind {
        return Err(StoreError::WorkflowKindMismatch);
    }
    if version != 1 {
        return Err(StoreError::LegacyEncryptionPending);
    }
    decrypt_record(
        key,
        database_id,
        &workflow_label(kind),
        &revisioned_aad_id(id.as_bytes(), revision, updated_at, Some(broadcast))?,
        &encrypted,
    )?;
    Ok(revision)
}

fn authenticated_entity_revision(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: EntityKind,
    id: &[u8],
) -> Result<Option<u64>, StoreError> {
    let current: Option<(u64, Vec<u8>, u64)> = transaction
        .query_row(
            "SELECT revision, encrypted_value, updated_at_unix
             FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
            params![kind.label(), id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    current
        .map(|(revision, encrypted, updated_at)| {
            decrypt_record(
                key,
                database_id,
                &entity_label(kind),
                &revisioned_aad_id(id, revision, updated_at, None)?,
                &encrypted,
            )?;
            Ok(revision)
        })
        .transpose()
}

fn apply_entity_batch_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: EntityKind,
    saves: &PreparedEntityBatch,
    deletes: &[EntityBatchDelete],
) -> Result<(), StoreError> {
    let encrypted_saves =
        authenticate_entity_batch(transaction, key, database_id, kind, saves, deletes)?;
    write_entity_batch_in_transaction(transaction, kind, &encrypted_saves, deletes)
}

fn authenticate_entity_batch(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: EntityKind,
    saves: &PreparedEntityBatch,
    deletes: &[EntityBatchDelete],
) -> Result<AuthenticatedEntityWrites, StoreError> {
    if kind.deletion_protected() && !deletes.is_empty() {
        return Err(StoreError::ProtectedEntity);
    }
    let mut encrypted_saves = Vec::with_capacity(saves.len());
    for (id, expected_revision, encoded, updated_at) in saves {
        let actual =
            authenticated_entity_revision(transaction, key, database_id, kind, id)?.unwrap_or(0);
        if actual != *expected_revision {
            return Err(StoreError::StaleRevision {
                expected: *expected_revision,
                actual,
            });
        }
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        let encrypted = encrypt_record(
            key,
            database_id,
            &entity_label(kind),
            &revisioned_aad_id(id, next, *updated_at, None)?,
            encoded,
        )?;
        encrypted_saves.push((id.clone(), next, encrypted, *updated_at));
    }
    for delete in deletes {
        let actual =
            authenticated_entity_revision(transaction, key, database_id, kind, &delete.id)?
                .unwrap_or(0);
        if actual != delete.expected_revision {
            return Err(StoreError::StaleRevision {
                expected: delete.expected_revision,
                actual,
            });
        }
    }
    Ok(encrypted_saves)
}

fn write_entity_batch_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    kind: EntityKind,
    encrypted_saves: &AuthenticatedEntityWrites,
    deletes: &[EntityBatchDelete],
) -> Result<(), StoreError> {
    for (id, revision, encrypted, updated_at) in encrypted_saves {
        transaction.execute(
            "INSERT INTO encrypted_entities(
                 entity_kind, record_id, revision, encrypted_value, updated_at_unix
             ) VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(entity_kind, record_id) DO UPDATE SET
                 revision=excluded.revision,
                 encrypted_value=excluded.encrypted_value,
                 updated_at_unix=excluded.updated_at_unix",
            params![kind.label(), id, revision, encrypted, updated_at],
        )?;
    }
    for delete in deletes {
        transaction.execute(
            "DELETE FROM encrypted_entities WHERE entity_kind=?1 AND record_id=?2",
            params![kind.label(), &delete.id],
        )?;
    }
    Ok(())
}

fn is_in_memory(path: &Path) -> bool {
    path == Path::new(":memory:")
}

fn open_wallet_connection(path: &Path) -> Result<Connection, StoreError> {
    if is_in_memory(path) {
        return Connection::open_in_memory().map_err(StoreError::from);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(path, flags).map_err(StoreError::from)
}

fn open_wallet_connection_read_only(path: &Path) -> Result<Connection, StoreError> {
    let connection = if is_in_memory(path) {
        Connection::open_in_memory()?
    } else {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        Connection::open_with_flags(path, flags)?
    };
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")?;
    Ok(connection)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalletPathRequirement {
    Missing,
    Existing,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnixBoundaryKind {
    Directory,
    RegularFile,
    Other,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixBoundaryMetadata {
    kind: UnixBoundaryKind,
    uid: u32,
    mode: u32,
    dev: u64,
    ino: u64,
    nlink: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnixAncestorPolicy {
    Strict,
    AndroidSystemUid1000,
}

#[cfg(unix)]
const fn active_unix_ancestor_policy() -> UnixAncestorPolicy {
    #[cfg(target_os = "android")]
    {
        UnixAncestorPolicy::AndroidSystemUid1000
    }
    #[cfg(not(target_os = "android"))]
    {
        UnixAncestorPolicy::Strict
    }
}

#[cfg(unix)]
fn unix_boundary_metadata(metadata: &std::fs::Metadata) -> UnixBoundaryMetadata {
    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        UnixBoundaryKind::Directory
    } else if file_type.is_file() {
        UnixBoundaryKind::RegularFile
    } else {
        UnixBoundaryKind::Other
    };
    UnixBoundaryMetadata {
        kind,
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        dev: metadata.dev(),
        ino: metadata.ino(),
        nlink: metadata.nlink(),
    }
}

#[cfg(unix)]
fn validate_unix_ancestor_chain(
    ancestors: &[UnixBoundaryMetadata],
    process_uid: u32,
    policy: UnixAncestorPolicy,
) -> Result<(), StoreError> {
    if ancestors.is_empty() {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    for ancestor in ancestors {
        if ancestor.kind != UnixBoundaryKind::Directory {
            return Err(StoreError::UnsafeFilesystemBoundary);
        }
    }

    // The native host chooses the path and therefore owns the non-writable
    // platform prefix above the first process-owned directory. Android app
    // sandboxes additionally traverse uid-1000 platform directories that can
    // be group-writable; that exception is compiled only for Android and still
    // rejects world-writable entries. Once the path enters the process-owned
    // suffix, ownership may not change again.
    let trusted_suffix = ancestors
        .iter()
        .position(|ancestor| ancestor.uid == process_uid)
        .ok_or(StoreError::UnsafeFilesystemBoundary)?;
    for (index, ancestor) in ancestors[..trusted_suffix].iter().enumerate() {
        if ancestor.mode & 0o022 != 0 {
            let sticky = ancestor.mode & 0o1000 != 0;
            let trusted_child = ancestors
                .get(index + 1)
                .is_some_and(|child| child.uid == 0 || child.uid == process_uid);
            let android_platform_group_write = policy == UnixAncestorPolicy::AndroidSystemUid1000
                && ancestor.uid == 1_000
                && ancestor.mode & 0o020 != 0
                && ancestor.mode & 0o002 == 0;
            if (!sticky || !trusted_child) && !android_platform_group_write {
                return Err(StoreError::UnsafeFilesystemBoundary);
            }
        }
    }
    for (offset, ancestor) in ancestors[trusted_suffix..].iter().enumerate() {
        if ancestor.uid != process_uid {
            return Err(StoreError::UnsafeFilesystemBoundary);
        }
        if ancestor.mode & 0o022 != 0 {
            let sticky = ancestor.mode & 0o1000 != 0;
            let trusted_child = ancestors
                .get(trusted_suffix + offset + 1)
                .is_some_and(|child| child.uid == process_uid);
            if !sticky || !trusted_child {
                return Err(StoreError::UnsafeFilesystemBoundary);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_wallet_directory(
    directory: UnixBoundaryMetadata,
    process_uid: u32,
) -> Result<(), StoreError> {
    if directory.kind != UnixBoundaryKind::Directory
        || directory.uid != process_uid
        || directory.mode != 0o700
    {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_wallet_file(
    file: UnixBoundaryMetadata,
    process_uid: u32,
) -> Result<(), StoreError> {
    if file.kind != UnixBoundaryKind::RegularFile
        || file.uid != process_uid
        || file.mode != 0o600
        || file.nlink != 1
    {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_file_identity(
    expected: UnixBoundaryMetadata,
    actual: UnixBoundaryMetadata,
) -> Result<(), StoreError> {
    if expected.kind != UnixBoundaryKind::RegularFile
        || actual.kind != UnixBoundaryKind::RegularFile
        || expected.dev != actual.dev
        || expected.ino != actual.ino
        || expected.nlink != 1
        || actual.nlink != 1
    {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatedWalletLocation {
    path: PathBuf,
    #[cfg(unix)]
    file: Option<UnixBoundaryMetadata>,
}

#[cfg(unix)]
struct CreatedWalletFile {
    file: std::fs::File,
    path: PathBuf,
    identity: Option<UnixBoundaryMetadata>,
    process_uid: u32,
    armed: bool,
}

#[cfg(not(unix))]
struct CreatedWalletFile;

#[cfg(unix)]
impl CreatedWalletFile {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(not(unix))]
impl CreatedWalletFile {
    fn disarm(&mut self) {}
}

#[cfg(unix)]
impl Drop for CreatedWalletFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let expected = self.identity.or_else(|| {
            self.file
                .metadata()
                .ok()
                .map(|metadata| unix_boundary_metadata(&metadata))
        });
        let Some(expected) = expected else {
            return;
        };
        if !unix_cleanup_file_is_owned(expected, self.process_uid) {
            return;
        }
        let Ok(actual) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        let actual = unix_boundary_metadata(&actual);
        if !unix_cleanup_file_is_owned(actual, self.process_uid)
            || validate_unix_file_identity(expected, actual).is_err()
        {
            return;
        }

        // Absence was checked before the database was created. Within the
        // owner-private parent, only regular, same-euid, single-link artifacts
        // can therefore be attributed to this initialization attempt.
        for sidecar in sqlite_sidecar_paths(&self.path) {
            let Ok(metadata) = std::fs::symlink_metadata(&sidecar) else {
                continue;
            };
            if unix_cleanup_file_is_owned(unix_boundary_metadata(&metadata), self.process_uid) {
                let _ = std::fs::remove_file(sidecar);
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn unix_cleanup_file_is_owned(file: UnixBoundaryMetadata, process_uid: u32) -> bool {
    file.kind == UnixBoundaryKind::RegularFile && file.uid == process_uid && file.nlink == 1
}

#[cfg(unix)]
fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 3] {
    ["-wal", "-shm", "-journal"].map(|suffix| {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        PathBuf::from(sidecar)
    })
}

#[cfg(unix)]
fn preflight_sqlite_sidecars(path: &Path) -> Result<(), StoreError> {
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(sidecar) {
            Ok(_) => return Err(StoreError::DatabaseExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_wallet_location(
    path: &Path,
    requirement: WalletPathRequirement,
) -> Result<ValidatedWalletLocation, StoreError> {
    if is_in_memory(path) {
        return Ok(ValidatedWalletLocation {
            path: path.to_path_buf(),
            file: None,
        });
    }
    let file_name = path
        .file_name()
        .ok_or(StoreError::UnsafeFilesystemBoundary)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let supplied_parent_metadata = std::fs::symlink_metadata(parent)?;
    if supplied_parent_metadata.file_type().is_symlink() {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StoreError::UnsafeFilesystemBoundary);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(StoreError::Io(error)),
    }

    // Mobile platforms can expose a sandbox through a system-owned ancestor
    // alias (for example, /var on Apple platforms). Resolve that alias once,
    // then use only the resolved owner-private directory for the SQLite open.
    // The selected parent itself and the database entry may not be symlinks.
    let canonical_parent = std::fs::canonicalize(parent)?;
    let canonical_path = canonical_parent.join(file_name);
    let process_uid = rustix::process::geteuid().as_raw();

    let mut ancestor_paths = canonical_parent.ancestors().collect::<Vec<_>>();
    ancestor_paths.reverse();
    let ancestor_metadata = ancestor_paths
        .into_iter()
        .map(std::fs::symlink_metadata)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(unix_boundary_metadata)
        .collect::<Vec<_>>();
    validate_unix_ancestor_chain(
        &ancestor_metadata,
        process_uid,
        active_unix_ancestor_policy(),
    )?;
    validate_unix_wallet_directory(
        *ancestor_metadata
            .last()
            .ok_or(StoreError::UnsafeFilesystemBoundary)?,
        process_uid,
    )?;

    let file_metadata = match std::fs::symlink_metadata(&canonical_path) {
        Ok(metadata) => Some(unix_boundary_metadata(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(StoreError::Io(error)),
    };
    match (requirement, file_metadata) {
        (WalletPathRequirement::Missing, None) => Ok(ValidatedWalletLocation {
            path: canonical_path,
            file: None,
        }),
        (WalletPathRequirement::Missing, Some(file)) => {
            validate_unix_wallet_file(file, process_uid)?;
            Err(StoreError::DatabaseExists)
        }
        (WalletPathRequirement::Existing, Some(file)) => {
            validate_unix_wallet_file(file, process_uid)?;
            Ok(ValidatedWalletLocation {
                path: canonical_path,
                file: Some(file),
            })
        }
        (WalletPathRequirement::Existing, None) => Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "wallet database does not exist",
        ))),
    }
}

#[cfg(not(unix))]
fn validate_wallet_location(
    path: &Path,
    _: WalletPathRequirement,
) -> Result<ValidatedWalletLocation, StoreError> {
    if is_in_memory(path) {
        Ok(ValidatedWalletLocation {
            path: path.to_path_buf(),
        })
    } else {
        Err(StoreError::UnsupportedFilesystemBoundary)
    }
}

#[cfg(unix)]
fn create_new_wallet_file(path: &Path) -> Result<CreatedWalletFile, StoreError> {
    preflight_sqlite_sidecars(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::DatabaseExists
            } else {
                StoreError::Io(error)
            }
        })?;
    let process_uid = rustix::process::geteuid().as_raw();
    let mut created = CreatedWalletFile {
        file,
        path: path.to_path_buf(),
        identity: None,
        process_uid,
        armed: true,
    };
    created
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let identity = unix_boundary_metadata(&created.file.metadata()?);
    created.identity = Some(identity);
    validate_unix_wallet_file(identity, process_uid)?;
    let path_identity = unix_boundary_metadata(&std::fs::symlink_metadata(path)?);
    validate_unix_wallet_file(path_identity, process_uid)?;
    validate_unix_file_identity(identity, path_identity)?;
    Ok(created)
}

#[cfg(not(unix))]
fn create_new_wallet_file(_: &Path) -> Result<CreatedWalletFile, StoreError> {
    Err(StoreError::UnsupportedFilesystemBoundary)
}

fn validate_wallet_location_identity(
    expected: &ValidatedWalletLocation,
    actual: &ValidatedWalletLocation,
) -> Result<(), StoreError> {
    if expected.path != actual.path {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    #[cfg(unix)]
    match (expected.file, actual.file) {
        (Some(expected), Some(actual)) => validate_unix_file_identity(expected, actual),
        (None, None) if is_in_memory(&expected.path) => Ok(()),
        _ => Err(StoreError::UnsafeFilesystemBoundary),
    }
    #[cfg(not(unix))]
    Ok(())
}

#[cfg(unix)]
fn validate_created_wallet_location(
    created: &CreatedWalletFile,
    actual: &ValidatedWalletLocation,
) -> Result<(), StoreError> {
    if created.path != actual.path {
        return Err(StoreError::UnsafeFilesystemBoundary);
    }
    let identity = created
        .identity
        .ok_or(StoreError::UnsafeFilesystemBoundary)?;
    let actual = actual.file.ok_or(StoreError::UnsafeFilesystemBoundary)?;
    validate_unix_file_identity(identity, actual)
}

#[cfg(not(unix))]
fn validate_created_wallet_location(
    _: &CreatedWalletFile,
    _: &ValidatedWalletLocation,
) -> Result<(), StoreError> {
    Err(StoreError::UnsupportedFilesystemBoundary)
}

#[derive(Debug, Eq, PartialEq)]
struct WalletMetadata {
    database_id: [u8; DATABASE_ID_BYTES],
    salt: [u8; SALT_BYTES],
    kdf: KdfConfig,
    key_check: Vec<u8>,
}

fn recognize_wallet_database(connection: &Connection) -> Result<WalletMetadata, StoreError> {
    let schema_version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version == 0 {
        return Err(StoreError::NotInitialized);
    }
    let schema_anchors: usize = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type='table' AND name IN ('wallet_meta', 'secrets', 'workflows')",
        [],
        |row| row.get(0),
    )?;
    if schema_anchors != 3 {
        return Err(StoreError::NotInitialized);
    }
    let metadata = load_wallet_metadata(connection)?;
    if schema_version > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(schema_version));
    }
    Ok(metadata)
}

fn load_wallet_metadata(connection: &Connection) -> Result<WalletMetadata, StoreError> {
    let database_id = exact_array::<DATABASE_ID_BYTES>(required_meta(connection, "database_id")?)?;
    let salt = exact_array::<SALT_BYTES>(required_meta(connection, "kdf_salt")?)?;
    let kdf: KdfConfig = serde_json::from_slice(&required_meta(connection, "kdf_config")?)?;
    kdf.validate()?;
    let key_check = required_meta(connection, "key_check")?;
    if key_check.len() != NONCE_BYTES + SENTINEL.len() + 16 {
        return Err(StoreError::CorruptMetadata);
    }
    Ok(WalletMetadata {
        database_id,
        salt,
        kdf,
        key_check,
    })
}

fn configure(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA secure_delete=ON;
         PRAGMA synchronous=FULL;
         PRAGMA journal_mode=WAL;",
    )?;
    Ok(())
}

fn migrate(connection: &Connection) -> Result<(), StoreError> {
    let current: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(current));
    }
    if current == 0 {
        connection.execute_batch(SCHEMA_V1)?;
    }
    if current < 2 {
        connection.execute_batch(SCHEMA_V2)?;
    }
    if current < 3 {
        connection.execute_batch(SCHEMA_V3)?;
    }
    Ok(())
}

const SCHEMA_V1: &str = r#"
BEGIN IMMEDIATE;
CREATE TABLE wallet_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE secrets(
    id BLOB PRIMARY KEY, kind TEXT NOT NULL, encrypted_value BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL
) STRICT;
CREATE TABLE wallet_accounts(id BLOB PRIMARY KEY, module TEXT NOT NULL, state_json BLOB NOT NULL) STRICT;
CREATE TABLE derived_addresses(account_id BLOB NOT NULL, derivation_index INTEGER NOT NULL,
    address TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(account_id, derivation_index)) STRICT;
CREATE TABLE hns_utxos(outpoint BLOB PRIMARY KEY, account_id BLOB NOT NULL, value INTEGER NOT NULL,
    script BLOB NOT NULL, height INTEGER, spent_by BLOB) STRICT;
CREATE TABLE hns_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE known_names(name_hash BLOB PRIMARY KEY, name TEXT NOT NULL, state_json BLOB NOT NULL,
    checked_height INTEGER NOT NULL) STRICT;
CREATE TABLE name_owner_outpoints(name_hash BLOB PRIMARY KEY, outpoint BLOB NOT NULL,
    proof_root BLOB NOT NULL, checked_height INTEGER NOT NULL) STRICT;
CREATE TABLE name_transfer_state(name_hash BLOB PRIMARY KEY, workflow_id BLOB NOT NULL,
    state_json BLOB NOT NULL) STRICT;
CREATE TABLE shakedex_state(id BLOB PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE denuo_board_cache(object_hash BLOB PRIMARY KEY, protocol INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_headers(height INTEGER PRIMARY KEY, block_hash BLOB NOT NULL,
    header BLOB NOT NULL, chainwork BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_filter_headers(height INTEGER PRIMARY KEY, block_hash BLOB NOT NULL,
    filter_header BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_peers(peer_id TEXT PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE bitcoin_scan_state(account_id BLOB PRIMARY KEY, birthday_height INTEGER,
    scanned_height INTEGER NOT NULL, checkpoint_json BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_utxos(outpoint BLOB PRIMARY KEY, account_id BLOB NOT NULL,
    value INTEGER NOT NULL, script BLOB NOT NULL, height INTEGER, spent_by BLOB) STRICT;
CREATE TABLE bitcoin_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE ethereum_accounts(id BLOB PRIMARY KEY, address BLOB NOT NULL,
    state_json BLOB NOT NULL) STRICT;
CREATE TABLE ethereum_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE market_intents(id BLOB PRIMARY KEY, sequence INTEGER NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE fill_grants(id BLOB PRIMARY KEY, intent_id BLOB NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE price_rounds(round_hash BLOB PRIMARY KEY, pair TEXT NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE swap_sessions(id BLOB PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE htlc_secrets(session_id BLOB PRIMARY KEY, encrypted_secret BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE refund_transactions(session_id BLOB NOT NULL, module TEXT NOT NULL,
    txid BLOB, state_json BLOB NOT NULL, PRIMARY KEY(session_id, module)) STRICT;
CREATE TABLE provider_permissions(origin TEXT PRIMARY KEY, generation INTEGER NOT NULL,
    permission_json BLOB NOT NULL, updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE pending_approvals(id BLOB PRIMARY KEY, origin TEXT NOT NULL,
    request_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE replay_protection(origin TEXT NOT NULL, nonce INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL, PRIMARY KEY(origin, nonce)) STRICT;
CREATE INDEX replay_expiry ON replay_protection(expires_at_unix);
CREATE TABLE workflows(id BLOB PRIMARY KEY, kind TEXT NOT NULL, revision INTEGER NOT NULL,
    state_json BLOB NOT NULL, broadcast_prepared INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
PRAGMA user_version=1;
COMMIT;
"#;

const SCHEMA_V2: &str = r#"
BEGIN IMMEDIATE;
ALTER TABLE workflows ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE encrypted_entities(
    entity_kind TEXT NOT NULL,
    record_id BLOB NOT NULL,
    revision INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY(entity_kind, record_id)
) STRICT;
CREATE INDEX encrypted_entities_updated
    ON encrypted_entities(entity_kind, updated_at_unix, record_id);
CREATE TABLE private_provider_permissions(
    origin_token BLOB PRIMARY KEY,
    generation INTEGER NOT NULL,
    encrypted_record BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL
) STRICT;
CREATE TABLE private_pending_approvals(
    id BLOB PRIMARY KEY,
    origin_token BLOB NOT NULL,
    encrypted_record BLOB NOT NULL,
    expires_at_unix INTEGER NOT NULL
) STRICT;
CREATE INDEX private_pending_approval_expiry
    ON private_pending_approvals(expires_at_unix);
CREATE TABLE private_replay_protection(
    origin_token BLOB NOT NULL,
    nonce INTEGER NOT NULL,
    encrypted_origin BLOB NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    PRIMARY KEY(origin_token, nonce)
) STRICT;
CREATE INDEX private_replay_expiry
    ON private_replay_protection(expires_at_unix);
PRAGMA user_version=2;
COMMIT;
"#;

const SCHEMA_V3: &str = r#"
BEGIN IMMEDIATE;
ALTER TABLE private_provider_permissions
    ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version=3;
COMMIT;
"#;

const LEGACY_ENTITY_TABLES: &[&str] = &[
    "wallet_accounts",
    "derived_addresses",
    "hns_utxos",
    "hns_transactions",
    "known_names",
    "name_owner_outpoints",
    "name_transfer_state",
    "shakedex_state",
    "denuo_board_cache",
    "bitcoin_headers",
    "bitcoin_filter_headers",
    "bitcoin_peers",
    "bitcoin_scan_state",
    "bitcoin_utxos",
    "bitcoin_transactions",
    "ethereum_accounts",
    "ethereum_transactions",
    "market_intents",
    "fill_grants",
    "price_rounds",
    "swap_sessions",
    "htlc_secrets",
    "refund_transactions",
];

/// Schema v1 exposed no complete, authenticated mapping for these entity rows.
/// Refusing to unlock is safer than silently hiding or ambiguously translating
/// funds-bearing state. An explicit import tool must consume them first.
fn reject_unmigrated_legacy_entities(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    for table in LEGACY_ENTITY_TABLES {
        let query = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
        let populated: bool = transaction.query_row(&query, [], |row| row.get(0))?;
        if populated {
            return Err(StoreError::LegacyEntityMigrationRequired(
                (*table).to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_legacy_replay_capacity(rows: &[(String, u64, u64)]) -> Result<(), StoreError> {
    if rows.len() > MAX_REPLAY_ROWS {
        return Err(StoreError::ReplayGlobalCapacity);
    }
    let mut previous_origin: Option<&str> = None;
    let mut origin_count = 0_usize;
    let mut rows_for_origin = 0_usize;
    for (origin, nonce, _) in rows {
        validate_origin(origin)?;
        if *nonce == 0 {
            return Err(StoreError::InvalidReplayWindow);
        }
        if previous_origin != Some(origin.as_str()) {
            origin_count = origin_count
                .checked_add(1)
                .ok_or(StoreError::ReplayOriginCapacity)?;
            if origin_count > MAX_REPLAY_ORIGINS {
                return Err(StoreError::ReplayOriginCapacity);
            }
            previous_origin = Some(origin);
            rows_for_origin = 0;
        }
        rows_for_origin = rows_for_origin
            .checked_add(1)
            .ok_or(StoreError::ReplayCapacity)?;
        if rows_for_origin > MAX_REPLAY_ROWS_PER_ORIGIN {
            return Err(StoreError::ReplayCapacity);
        }
    }
    Ok(())
}

fn truncate_wal(connection: &Connection) -> Result<(), StoreError> {
    let busy: u32 =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    if busy != 0 {
        return Err(StoreError::WalCheckpointBusy);
    }
    Ok(())
}

fn encode_origin_payload(origin: &str, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_origin(origin)?;
    if payload.is_empty() {
        return Err(StoreError::RecordTooLarge);
    }
    let origin_len = u16::try_from(origin.len()).map_err(|_| StoreError::InvalidOrigin)?;
    let capacity = 2_usize
        .checked_add(origin.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(StoreError::RecordTooLarge)?;
    if capacity > MAX_SECRET_BYTES {
        return Err(StoreError::RecordTooLarge);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.extend_from_slice(&origin_len.to_be_bytes());
    encoded.extend_from_slice(origin.as_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn decode_origin_payload(encoded: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>), StoreError> {
    if encoded.len() < 3 || encoded.len() > MAX_SECRET_BYTES {
        return Err(StoreError::Encryption);
    }
    let origin_len = usize::from(u16::from_be_bytes([encoded[0], encoded[1]]));
    let payload_offset = 2_usize
        .checked_add(origin_len)
        .ok_or(StoreError::Encryption)?;
    if payload_offset >= encoded.len() {
        return Err(StoreError::Encryption);
    }
    let origin = core::str::from_utf8(&encoded[2..payload_offset])
        .map_err(|_| StoreError::Encryption)?
        .to_owned();
    validate_origin(&origin).map_err(|_| StoreError::Encryption)?;
    Ok((origin, Zeroizing::new(encoded[payload_offset..].to_vec())))
}

fn prune_expired_approvals(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    now_unix: u64,
) -> Result<(), StoreError> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT id, origin_token, encrypted_record, expires_at_unix
             FROM private_pending_approvals ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() > MAX_PENDING_APPROVALS {
        return Err(StoreError::ApprovalCapacity);
    }
    for (id, origin_token, encrypted, expires_at_unix) in rows {
        let id = ApprovalId::new(id.try_into().map_err(|_| StoreError::CorruptMetadata)?);
        let origin_token: [u8; 32] = origin_token
            .try_into()
            .map_err(|_| StoreError::CorruptMetadata)?;
        let clear = decrypt_record(
            key,
            database_id,
            "pending_approval",
            &approval_record_id(&id, &origin_token, expires_at_unix),
            &encrypted,
        )?;
        let (origin, _) = decode_origin_payload(&clear)?;
        if origin_lookup_token(key, database_id, &origin)? != origin_token {
            return Err(StoreError::Encryption);
        }
        if expires_at_unix <= now_unix {
            transaction.execute(
                "DELETE FROM private_pending_approvals WHERE id=?1",
                params![id.as_bytes().as_slice()],
            )?;
        }
    }
    Ok(())
}

fn prune_expired_replay(
    transaction: &rusqlite::Transaction<'_>,
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    now_unix: u64,
) -> Result<(), StoreError> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT origin_token, nonce, encrypted_origin, expires_at_unix
             FROM private_replay_protection ORDER BY origin_token, nonce",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() > MAX_REPLAY_ROWS {
        return Err(StoreError::ReplayGlobalCapacity);
    }
    for (origin_token, nonce, encrypted_origin, expires_at_unix) in rows {
        let origin_token: [u8; 32] = origin_token
            .try_into()
            .map_err(|_| StoreError::CorruptMetadata)?;
        let clear = decrypt_record(
            key,
            database_id,
            "replay_origin",
            &replay_record_id(&origin_token, nonce, expires_at_unix),
            &encrypted_origin,
        )?;
        let origin = core::str::from_utf8(&clear).map_err(|_| StoreError::Encryption)?;
        validate_origin(origin).map_err(|_| StoreError::Encryption)?;
        if origin_lookup_token(key, database_id, origin)? != origin_token {
            return Err(StoreError::Encryption);
        }
        if expires_at_unix <= now_unix {
            transaction.execute(
                "DELETE FROM private_replay_protection
                 WHERE origin_token=?1 AND nonce=?2",
                params![origin_token.as_slice(), nonce],
            )?;
        }
    }
    Ok(())
}

fn validate_passphrase(passphrase: &str) -> Result<(), StoreError> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
        Err(StoreError::InvalidPassphrase)
    } else {
        Ok(())
    }
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_BYTES],
    config: KdfConfig,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, StoreError> {
    validate_passphrase(passphrase)?;
    config.validate()?;
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.lanes,
        Some(KEY_BYTES),
    )
    .map_err(|_| StoreError::UnsafeKdfParameters)?;
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| StoreError::KeyDerivation)?;
    Ok(key)
}

fn encrypt_record(
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
    cleartext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if cleartext.is_empty() || cleartext.len() > MAX_SECRET_BYTES {
        return Err(StoreError::RecordTooLarge);
    }
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| StoreError::Randomness)?;
    let aad = record_aad(database_id, kind, id)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: cleartext,
                aad: &aad,
            },
        )
        .map_err(|_| StoreError::Encryption)?;
    let mut envelope = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    nonce.zeroize();
    Ok(envelope)
}

fn decrypt_record(
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if envelope.len() <= NONCE_BYTES || envelope.len() > MAX_SECRET_BYTES + NONCE_BYTES + 16 {
        return Err(StoreError::Encryption);
    }
    let (nonce, ciphertext) = envelope.split_at(NONCE_BYTES);
    let aad = record_aad(database_id, kind, id)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Encryption)
}

fn record_aad(
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if id.is_empty() || id.len() > MAX_RECORD_ID_BYTES + 64 {
        return Err(StoreError::InvalidRecordId);
    }
    if kind.is_empty() || kind.len() > 64 {
        return Err(StoreError::InvalidRecordId);
    }
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + database_id.len() + kind.len() + id.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(database_id);
    aad.extend_from_slice(kind.as_bytes());
    aad.push(0);
    aad.extend_from_slice(id);
    Ok(aad)
}

fn entity_label(kind: EntityKind) -> String {
    format!("entity/{}", kind.label())
}

fn workflow_label(kind: WorkflowKind) -> String {
    format!("workflow/{}", workflow_kind(kind))
}

fn origin_lookup_token(
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    origin: &str,
) -> Result<[u8; 32], StoreError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| StoreError::KeyDerivation)?;
    Mac::update(&mut mac, ORIGIN_TOKEN_DOMAIN);
    Mac::update(&mut mac, database_id);
    Mac::update(&mut mac, origin.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn revisioned_aad_id(
    id: &[u8],
    revision: u64,
    updated_at_unix: u64,
    broadcast_prepared: Option<bool>,
) -> Result<Vec<u8>, StoreError> {
    validate_id(id)?;
    let mut aad_id = Vec::with_capacity(id.len() + 17);
    aad_id.extend_from_slice(id);
    aad_id.extend_from_slice(&revision.to_be_bytes());
    aad_id.extend_from_slice(&updated_at_unix.to_be_bytes());
    if let Some(prepared) = broadcast_prepared {
        aad_id.push(u8::from(prepared));
    }
    Ok(aad_id)
}

fn permission_record_id(
    origin_token: &[u8; 32],
    generation: u64,
    revoked: bool,
    updated_at_unix: u64,
) -> [u8; 49] {
    let mut id = [0_u8; 49];
    id[..32].copy_from_slice(origin_token);
    id[32..40].copy_from_slice(&generation.to_be_bytes());
    id[40] = u8::from(revoked);
    id[41..].copy_from_slice(&updated_at_unix.to_be_bytes());
    id
}

fn approval_record_id(id: &ApprovalId, origin_token: &[u8; 32], expires_at_unix: u64) -> [u8; 56] {
    let mut aad_id = [0_u8; 56];
    aad_id[..16].copy_from_slice(id.as_bytes());
    aad_id[16..48].copy_from_slice(origin_token);
    aad_id[48..].copy_from_slice(&expires_at_unix.to_be_bytes());
    aad_id
}

fn replay_record_id(origin_token: &[u8; 32], nonce: u64, expires_at_unix: u64) -> [u8; 48] {
    let mut id = [0_u8; 48];
    id[..32].copy_from_slice(origin_token);
    id[32..40].copy_from_slice(&nonce.to_be_bytes());
    id[40..].copy_from_slice(&expires_at_unix.to_be_bytes());
    id
}

fn validate_id(id: &[u8]) -> Result<(), StoreError> {
    if id.is_empty() || id.len() > MAX_RECORD_ID_BYTES {
        return Err(StoreError::InvalidRecordId);
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), StoreError> {
    if origin.is_empty() || origin.len() > 512 || !origin.is_ascii() {
        return Err(StoreError::InvalidOrigin);
    }
    Ok(())
}

fn meta(connection: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    connection
        .query_row(
            "SELECT value FROM wallet_meta WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
}

fn required_meta(connection: &Connection, key: &str) -> Result<Vec<u8>, StoreError> {
    meta(connection, key)?.ok_or(StoreError::NotInitialized)
}

fn set_meta(
    transaction: &rusqlite::Transaction<'_>,
    key: &str,
    value: &[u8],
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO wallet_meta(key, value) VALUES(?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptMetadata)
}

const fn workflow_kind(kind: WorkflowKind) -> &'static str {
    match kind {
        WorkflowKind::HnsSend => "hns_send",
        WorkflowKind::NameTransfer => "name_transfer",
        WorkflowKind::NameFinalize => "name_finalize",
        WorkflowKind::ShakedexSeller => "shakedex_seller",
        WorkflowKind::ShakedexBuyer => "shakedex_buyer",
        WorkflowKind::ShakedexSellerPlan => "shakedex_seller_plan",
        WorkflowKind::ShakedexBuyerPlan => "shakedex_buyer_plan",
        WorkflowKind::ShakedexValue => "shakedex_value",
        WorkflowKind::MarketIntent => "market_intent",
        WorkflowKind::FillReservation => "fill_reservation",
        WorkflowKind::AtomicSwap => "atomic_swap",
        WorkflowKind::Refund => "refund",
    }
}

fn parse_workflow_kind(value: &str) -> Result<WorkflowKind, StoreError> {
    match value {
        "hns_send" => Ok(WorkflowKind::HnsSend),
        "name_transfer" => Ok(WorkflowKind::NameTransfer),
        "name_finalize" => Ok(WorkflowKind::NameFinalize),
        "shakedex_seller" => Ok(WorkflowKind::ShakedexSeller),
        "shakedex_buyer" => Ok(WorkflowKind::ShakedexBuyer),
        "shakedex_seller_plan" => Ok(WorkflowKind::ShakedexSellerPlan),
        "shakedex_buyer_plan" => Ok(WorkflowKind::ShakedexBuyerPlan),
        "shakedex_value" => Ok(WorkflowKind::ShakedexValue),
        "market_intent" => Ok(WorkflowKind::MarketIntent),
        "fill_reservation" => Ok(WorkflowKind::FillReservation),
        "atomic_swap" => Ok(WorkflowKind::AtomicSwap),
        "refund" => Ok(WorkflowKind::Refund),
        _ => Err(StoreError::CorruptMetadata),
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("wallet store is already initialized")]
    AlreadyInitialized,
    #[error("wallet database path already exists")]
    DatabaseExists,
    #[error("wallet store is not initialized")]
    NotInitialized,
    #[error("wallet store is locked")]
    Locked,
    #[error("invalid wallet passphrase")]
    InvalidPassphrase,
    #[error("unsafe or unsupported Argon2 parameters")]
    UnsafeKdfParameters,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("authenticated encryption failed")]
    Encryption,
    #[error("secret kind does not match the requested kind")]
    KindMismatch,
    #[error("wallet recovery seed is immutable and cannot be deleted or replaced")]
    ProtectedSecret,
    #[error("wallet recovery seed must be exactly 64 bytes")]
    InvalidRecoverySeed,
    #[error("wallet seed/account bootstrap conflicts with existing initialization state")]
    BootstrapConflict,
    #[error("a workflow identifier cannot change workflow kind")]
    WorkflowKindMismatch,
    #[error("record identifier is invalid")]
    InvalidRecordId,
    #[error("origin is invalid")]
    InvalidOrigin,
    #[error("record exceeds its bounded maximum")]
    RecordTooLarge,
    #[error("wallet metadata is corrupt")]
    CorruptMetadata,
    #[error("database schema {0} is newer than this wallet")]
    NewerSchema(u32),
    #[error("stale workflow revision: expected {expected}, actual {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("workflow revision overflow")]
    RevisionOverflow,
    #[error("request nonce has already been consumed")]
    Replay,
    #[error("request replay window is invalid")]
    InvalidReplayWindow,
    #[error("pending approval lifetime is invalid")]
    InvalidApprovalWindow,
    #[error("origin replay-protection capacity is exhausted")]
    ReplayCapacity,
    #[error("global replay-protection capacity is exhausted")]
    ReplayGlobalCapacity,
    #[error("replay-protection origin capacity is exhausted")]
    ReplayOriginCapacity,
    #[error("provider permission capacity is exhausted")]
    ProviderCapacity,
    #[error("pending approval capacity is exhausted")]
    ApprovalCapacity,
    #[error("provider permission generation must be nonzero")]
    InvalidGeneration,
    #[error("provider permission generation mismatch: expected {expected}, got {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("entity or workflow list limit is invalid")]
    InvalidListLimit,
    #[error("complete bounded entity or workflow list exceeds its capacity")]
    ListCapacity,
    #[error("record revision must be nonzero")]
    InvalidRevision,
    #[error("managed encrypted entity records cannot be deleted")]
    ProtectedEntity,
    #[error("entity batch contains duplicate or invalid operations")]
    DuplicateBatchEntity,
    #[error("entity batch exceeds its bounded operation limit")]
    BatchCapacity,
    #[error("legacy sensitive rows require an unlocked migration")]
    LegacyEncryptionPending,
    #[error("legacy entity table `{0}` requires an explicit authenticated import")]
    LegacyEntityMigrationRequired(String),
    #[error("the plaintext-removal WAL checkpoint could not acquire the database")]
    WalCheckpointBusy,
    #[error("wallet database or parent ownership/mode is unsafe")]
    UnsafeFilesystemBoundary,
    #[error("wallet filesystem ownership validation is unsupported on this platform")]
    UnsupportedFilesystemBoundary,
    #[error("shared wallet store access failed")]
    Concurrency,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(unix)]
    struct OwnedWalletProduct {
        store: WalletStore,
        account_revision: u64,
    }

    #[cfg(unix)]
    #[derive(Debug, Eq, PartialEq)]
    enum OwnedWalletProductError {
        Store,
        Negotiation,
    }

    #[cfg(unix)]
    impl From<StoreError> for OwnedWalletProductError {
        fn from(_: StoreError) -> Self {
            Self::Store
        }
    }

    #[cfg(unix)]
    fn unix_private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::var_os("HNS_WALLET_STORE_TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = tempfile::Builder::new()
            .prefix("hns-wallet-store-")
            .tempdir_in(root)
            .expect("private Unix test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private Unix test directory mode");
        directory
    }

    #[cfg(unix)]
    #[test]
    fn unix_wallet_boundary_policy_is_exact_and_platform_independent() {
        const UID: u32 = 10_123;
        let private_directory = UnixBoundaryMetadata {
            kind: UnixBoundaryKind::Directory,
            uid: UID,
            mode: 0o700,
            dev: 1,
            ino: 2,
            nlink: 2,
        };
        let private_file = UnixBoundaryMetadata {
            kind: UnixBoundaryKind::RegularFile,
            uid: UID,
            mode: 0o600,
            dev: 1,
            ino: 3,
            nlink: 1,
        };
        assert!(validate_unix_wallet_directory(private_directory, UID).is_ok());
        assert!(validate_unix_wallet_file(private_file, UID).is_ok());

        for unsafe_parent in [
            UnixBoundaryMetadata {
                mode: 0o750,
                ..private_directory
            },
            UnixBoundaryMetadata {
                uid: UID + 1,
                ..private_directory
            },
            UnixBoundaryMetadata {
                kind: UnixBoundaryKind::Other,
                ..private_directory
            },
        ] {
            assert!(matches!(
                validate_unix_wallet_directory(unsafe_parent, UID),
                Err(StoreError::UnsafeFilesystemBoundary)
            ));
        }
        for unsafe_file in [
            UnixBoundaryMetadata {
                mode: 0o640,
                ..private_file
            },
            UnixBoundaryMetadata {
                uid: UID + 1,
                ..private_file
            },
            UnixBoundaryMetadata {
                kind: UnixBoundaryKind::Other,
                ..private_file
            },
            UnixBoundaryMetadata {
                nlink: 2,
                ..private_file
            },
        ] {
            assert!(matches!(
                validate_unix_wallet_file(unsafe_file, UID),
                Err(StoreError::UnsafeFilesystemBoundary)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_ancestor_policy_rejects_untrusted_rename_boundaries() {
        const UID: u32 = 10_123;
        const STRICT: UnixAncestorPolicy = UnixAncestorPolicy::Strict;
        const ANDROID: UnixAncestorPolicy = UnixAncestorPolicy::AndroidSystemUid1000;
        let root = UnixBoundaryMetadata {
            kind: UnixBoundaryKind::Directory,
            uid: 0,
            mode: 0o755,
            dev: 1,
            ino: 1,
            nlink: 2,
        };
        let sticky_root = UnixBoundaryMetadata {
            mode: 0o1777,
            ..root
        };
        let private = UnixBoundaryMetadata {
            uid: UID,
            mode: 0o700,
            ino: 2,
            ..root
        };
        let owned_ancestor = UnixBoundaryMetadata {
            uid: UID,
            mode: 0o755,
            ino: 3,
            ..root
        };

        assert!(validate_unix_ancestor_chain(&[root, private], UID, STRICT).is_ok());
        assert!(validate_unix_ancestor_chain(&[sticky_root, private], UID, STRICT).is_ok());
        assert!(matches!(
            validate_unix_ancestor_chain(
                &[
                    UnixBoundaryMetadata {
                        mode: 0o777,
                        ..root
                    },
                    private,
                ],
                UID,
                STRICT,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
        assert!(matches!(
            validate_unix_ancestor_chain(
                &[
                    UnixBoundaryMetadata {
                        mode: 0o775,
                        ..root
                    },
                    private,
                ],
                UID,
                STRICT,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));

        let android_app_data_chain = [
            root,
            UnixBoundaryMetadata {
                uid: 1_000,
                mode: 0o771,
                ino: 4,
                ..root
            },
            UnixBoundaryMetadata {
                uid: 1_000,
                mode: 0o511,
                ino: 5,
                ..root
            },
            UnixBoundaryMetadata {
                uid: 1_000,
                mode: 0o771,
                ino: 6,
                ..root
            },
            private,
        ];
        assert!(matches!(
            validate_unix_ancestor_chain(&android_app_data_chain, UID, STRICT),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
        assert!(validate_unix_ancestor_chain(&android_app_data_chain, UID, ANDROID).is_ok());
        for unsafe_android_prefix in [
            UnixBoundaryMetadata {
                uid: 1_001,
                mode: 0o771,
                ino: 7,
                ..root
            },
            UnixBoundaryMetadata {
                uid: 1_000,
                mode: 0o773,
                ino: 8,
                ..root
            },
        ] {
            assert!(matches!(
                validate_unix_ancestor_chain(&[root, unsafe_android_prefix, private], UID, ANDROID,),
                Err(StoreError::UnsafeFilesystemBoundary)
            ));
        }

        assert!(
            validate_unix_ancestor_chain(&[root, owned_ancestor, private], UID, STRICT).is_ok()
        );
        assert!(
            validate_unix_ancestor_chain(
                &[
                    root,
                    UnixBoundaryMetadata {
                        mode: 0o1777,
                        ..owned_ancestor
                    },
                    private,
                ],
                UID,
                STRICT,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_unix_ancestor_chain(
                &[
                    root,
                    UnixBoundaryMetadata {
                        mode: 0o777,
                        ..owned_ancestor
                    },
                    private,
                ],
                UID,
                STRICT,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
        assert!(matches!(
            validate_unix_ancestor_chain(
                &[
                    root,
                    owned_ancestor,
                    UnixBoundaryMetadata {
                        uid: UID + 1,
                        mode: 0o555,
                        ..private
                    },
                ],
                UID,
                STRICT,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
        assert!(matches!(
            validate_unix_ancestor_chain(
                &[
                    root,
                    UnixBoundaryMetadata {
                        uid: UID + 1,
                        mode: 0o555,
                        ..private
                    },
                ],
                UID,
                STRICT,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_identity_rejects_inode_changes_and_hard_links() {
        let identity = UnixBoundaryMetadata {
            kind: UnixBoundaryKind::RegularFile,
            uid: 10_123,
            mode: 0o600,
            dev: 7,
            ino: 11,
            nlink: 1,
        };
        assert!(validate_unix_file_identity(identity, identity).is_ok());
        for changed in [
            UnixBoundaryMetadata { dev: 8, ..identity },
            UnixBoundaryMetadata {
                ino: 12,
                ..identity
            },
            UnixBoundaryMetadata {
                nlink: 2,
                ..identity
            },
        ] {
            assert!(matches!(
                validate_unix_file_identity(identity, changed),
                Err(StoreError::UnsafeFilesystemBoundary)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_wallet_location_canonicalizes_ancestor_aliases_only() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = unix_private_tempdir();
        let physical_root = directory.path().join("physical");
        let container = physical_root.join("container");
        let private_directory = container.join("wallet-private");
        std::fs::create_dir_all(&private_directory).expect("physical private directory");
        for owned_ancestor in [&physical_root, &container] {
            std::fs::set_permissions(owned_ancestor, std::fs::Permissions::from_mode(0o700))
                .expect("private owned ancestor mode");
        }
        std::fs::set_permissions(&private_directory, std::fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let ancestor_alias = directory.path().join("system-alias");
        symlink(&physical_root, &ancestor_alias).expect("system-style ancestor alias");

        let supplied_database = ancestor_alias
            .join("container")
            .join("wallet-private")
            .join("wallet.sqlite3");
        let physical_database = private_directory.join("wallet.sqlite3");
        assert_eq!(
            validate_wallet_location(&supplied_database, WalletPathRequirement::Missing)
                .expect("missing create target")
                .path,
            physical_database
        );
        std::fs::write(&physical_database, []).expect("empty database fixture");
        std::fs::set_permissions(&physical_database, std::fs::Permissions::from_mode(0o600))
            .expect("private database mode");
        assert_eq!(
            validate_wallet_location(&supplied_database, WalletPathRequirement::Existing)
                .expect("existing database")
                .path,
            physical_database
        );

        let database_alias = private_directory.join("wallet-link.sqlite3");
        symlink(&physical_database, &database_alias).expect("database alias");
        assert!(matches!(
            validate_wallet_location(&database_alias, WalletPathRequirement::Existing),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));

        let parent_alias = directory.path().join("wallet-parent-link");
        symlink(&private_directory, &parent_alias).expect("parent alias");
        assert!(matches!(
            validate_wallet_location(
                &parent_alias.join("wallet.sqlite3"),
                WalletPathRequirement::Existing,
            ),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));

        std::fs::set_permissions(&private_directory, std::fs::Permissions::from_mode(0o750))
            .expect("unsafe parent mode fixture");
        assert!(matches!(
            validate_wallet_location(&supplied_database, WalletPathRequirement::Existing),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_create_rejects_existing_file_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unix_private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let database = directory.path().join("wallet.sqlite3");
        let sentinel = b"existing non-wallet bytes";
        std::fs::write(&database, sentinel).expect("existing database fixture");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("existing database mode");

        assert!(matches!(
            WalletStore::create_with_kdf(
                &database,
                "existing-file-passphrase",
                KdfConfig::testing(),
            ),
            Err(StoreError::DatabaseExists)
        ));
        assert_eq!(
            std::fs::read(&database).expect("unchanged existing database"),
            sentinel
        );
        assert!(!directory.path().join("wallet.sqlite3-wal").exists());
        assert!(!directory.path().join("wallet.sqlite3-shm").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_failed_create_cleans_owned_artifacts_and_allows_retry() {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let directory = unix_private_tempdir();
        let database = directory.path().join("wallet.sqlite3");
        let sidecars = sqlite_sidecar_paths(&database);

        for sidecar in &sidecars {
            std::fs::write(sidecar, b"pre-existing sidecar").expect("sidecar fixture");
            std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o600))
                .expect("sidecar mode");
            assert!(matches!(
                WalletStore::create_with_kdf(
                    &database,
                    "cleanup-retry-passphrase",
                    KdfConfig::testing(),
                ),
                Err(StoreError::DatabaseExists)
            ));
            assert!(!database.exists());
            assert_eq!(
                std::fs::read(sidecar).expect("preserved sidecar"),
                b"pre-existing sidecar"
            );
            std::fs::remove_file(sidecar).expect("remove sidecar fixture");
        }

        assert!(matches!(
            WalletStore::create_with_kdf_after_migration(
                &database,
                "cleanup-retry-passphrase",
                KdfConfig::testing(),
                |_| {
                    for sidecar in &sidecars {
                        if !sidecar.exists() {
                            std::fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .mode(0o600)
                                .open(sidecar)
                                .expect("invocation-owned sidecar fixture");
                        }
                    }
                    Err(StoreError::CorruptMetadata)
                },
            ),
            Err(StoreError::CorruptMetadata)
        ));
        assert!(!database.exists());
        for sidecar in &sidecars {
            assert!(!sidecar.exists());
        }

        let store = WalletStore::create_with_kdf(
            &database,
            "cleanup-retry-passphrase",
            KdfConfig::testing(),
        )
        .expect("retry clean creation");
        drop(store);
        let mut reopened = WalletStore::open(&database).expect("open retried wallet");
        reopened
            .unlock("cleanup-retry-passphrase")
            .expect("unlock retried wallet");
    }

    #[cfg(unix)]
    #[test]
    fn unix_failed_product_initializer_keeps_creation_cleanup_armed() {
        let directory = unix_private_tempdir();
        let database = directory.path().join("wallet.sqlite3");

        assert!(matches!(
            WalletStore::create_with_kdf_and_initializer(
                &database,
                "product-initializer-passphrase",
                KdfConfig::testing(),
                |_| Ok(()),
                |store| {
                    store.initialize_recovery_seed_and_wallet_account(
                        &[61_u8; 16],
                        &[62_u8; 64],
                        &[63_u8; 32],
                        &json!({"account": 63}),
                        1,
                    )?;
                    Err::<(), _>(StoreError::CorruptMetadata)
                },
            ),
            Err(StoreError::CorruptMetadata)
        ));
        assert!(!database.exists());
        for sidecar in sqlite_sidecar_paths(&database) {
            assert!(!sidecar.exists());
        }

        let (store, revision) = WalletStore::create_with_kdf_and_initializer(
            &database,
            "product-initializer-passphrase",
            KdfConfig::testing(),
            |_| Ok(()),
            |store| {
                store.initialize_recovery_seed_and_wallet_account(
                    &[61_u8; 16],
                    &[62_u8; 64],
                    &[63_u8; 32],
                    &json!({"account": 63}),
                    2,
                )
            },
        )
        .expect("retry complete product initialization");
        assert_eq!(revision, 1);
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen initialized wallet");
        reopened
            .unlock("product-initializer-passphrase")
            .expect("unlock initialized wallet");
        assert!(
            reopened
                .get_secret(&[61_u8; 16], SecretKind::RecoverySeed)
                .expect("read initialized seed")
                .is_some()
        );
        assert!(
            reopened
                .wallet_account::<serde_json::Value>(&[63_u8; 32])
                .expect("read initialized account")
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_owned_product_initializer_cleans_failure_and_returns_live_success() {
        let directory = unix_private_tempdir();
        let database = directory.path().join("wallet.sqlite3");
        let passphrase = "owned-product-initializer-passphrase";

        let failure: Result<OwnedWalletProduct, OwnedWalletProductError> =
            WalletStore::create_with_kdf_and_owned_initializer(
                &database,
                passphrase,
                KdfConfig::testing(),
                |mut store| {
                    let account_revision = store
                        .initialize_recovery_seed_and_wallet_account(
                            &[71_u8; 16],
                            &[72_u8; RECOVERY_SEED_BYTES],
                            &[73_u8; 32],
                            &json!({"account": 73}),
                            1,
                        )
                        .map_err(OwnedWalletProductError::from)?;
                    let _product = OwnedWalletProduct {
                        store,
                        account_revision,
                    };
                    Err(OwnedWalletProductError::Negotiation)
                },
            );
        assert!(matches!(failure, Err(OwnedWalletProductError::Negotiation)));
        assert!(!database.exists());
        for sidecar in sqlite_sidecar_paths(&database) {
            assert!(!sidecar.exists());
        }

        let mut product: OwnedWalletProduct = WalletStore::create_with_kdf_and_owned_initializer(
            &database,
            passphrase,
            KdfConfig::testing(),
            |mut store| {
                let account_revision = store
                    .initialize_recovery_seed_and_wallet_account(
                        &[71_u8; 16],
                        &[72_u8; RECOVERY_SEED_BYTES],
                        &[73_u8; 32],
                        &json!({"account": 73}),
                        2,
                    )
                    .map_err(OwnedWalletProductError::from)?;
                Ok::<_, OwnedWalletProductError>(OwnedWalletProduct {
                    store,
                    account_revision,
                })
            },
        )
        .expect("owned product initialization");
        assert_eq!(product.account_revision, 1);
        assert!(database.exists());
        product
            .store
            .validate_single_recovery_seed(&[71_u8; 16])
            .expect("product-owned store remains live");
        assert!(
            product
                .store
                .wallet_account::<serde_json::Value>(&[73_u8; 32])
                .expect("read product-owned account")
                .is_some()
        );
        drop(product);

        let mut reopened = WalletStore::open(&database).expect("reopen owned product wallet");
        reopened
            .unlock(passphrase)
            .expect("unlock owned product wallet");
        reopened
            .validate_single_recovery_seed(&[71_u8; 16])
            .expect("validate reopened product seed");
    }

    #[cfg(unix)]
    #[test]
    fn unix_cleanup_guard_preserves_replaced_database_identity() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unix_private_tempdir();
        let database = directory.path().join("wallet.sqlite3");
        let created = create_new_wallet_file(&database).expect("armed creation guard");
        std::fs::remove_file(&database).expect("unlink original database");
        std::fs::write(&database, b"replacement database").expect("replacement database");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        let sidecar = sqlite_sidecar_paths(&database)[2].clone();
        std::fs::write(&sidecar, b"replacement sidecar").expect("replacement sidecar");
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600))
            .expect("replacement sidecar mode");

        drop(created);
        assert_eq!(
            std::fs::read(&database).expect("preserved replacement database"),
            b"replacement database"
        );
        assert_eq!(
            std::fs::read(&sidecar).expect("preserved replacement sidecar"),
            b"replacement sidecar"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_open_rejects_non_wallet_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unix_private_tempdir();
        let database = directory.path().join("foreign.sqlite3");
        let connection = Connection::open(&database).expect("foreign SQLite database");
        connection
            .execute_batch(
                "CREATE TABLE foreign_records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO foreign_records(value) VALUES('unchanged');
                 PRAGMA user_version=1;",
            )
            .expect("foreign schema");
        drop(connection);
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("foreign database mode");
        let before = std::fs::read(&database).expect("foreign bytes before open");

        assert!(matches!(
            WalletStore::open(&database),
            Err(StoreError::NotInitialized)
        ));
        assert_eq!(
            std::fs::read(&database).expect("foreign bytes after open"),
            before
        );
        for sidecar in sqlite_sidecar_paths(&database) {
            assert!(!sidecar.exists());
        }
        let connection = open_wallet_connection_read_only(&database).expect("inspect foreign DB");
        assert_eq!(
            connection
                .query_row::<u32, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .expect("foreign schema version"),
            1
        );
        assert_eq!(
            connection
                .query_row::<String, _, _>("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("foreign journal mode"),
            "delete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_open_rejects_partial_v1_wallet_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unix_private_tempdir();
        let database = directory.path().join("partial-wallet.sqlite3");
        let connection = Connection::open(&database).expect("partial wallet database");
        connection.execute_batch(SCHEMA_V1).expect("schema v1");
        drop(connection);
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("partial wallet mode");
        let before = std::fs::read(&database).expect("partial wallet bytes before open");

        assert!(matches!(
            WalletStore::open(&database),
            Err(StoreError::NotInitialized)
        ));
        assert_eq!(
            std::fs::read(&database).expect("partial wallet bytes after open"),
            before
        );
        for sidecar in sqlite_sidecar_paths(&database) {
            assert!(!sidecar.exists());
        }
        let connection = open_wallet_connection_read_only(&database).expect("inspect partial DB");
        assert_eq!(
            connection
                .query_row::<u32, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .expect("partial schema version"),
            1
        );
        let has_v2_table: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type='table' AND name='encrypted_entities'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("partial schema inspection");
        assert!(!has_v2_table);
    }

    #[cfg(unix)]
    #[test]
    fn unix_open_recognizes_and_migrates_initialized_v1_wallet() {
        use std::os::unix::fs::PermissionsExt as _;

        const PASSPHRASE: &str = "initialized-v1-passphrase";
        let source = WalletStore::create_in_memory(PASSPHRASE).expect("metadata source");
        let metadata = ["database_id", "kdf_salt", "kdf_config", "key_check"].map(|key| {
            (
                key,
                required_meta(&source.connection, key).expect("source metadata"),
            )
        });

        let directory = unix_private_tempdir();
        let database = directory.path().join("legacy-wallet.sqlite3");
        let connection = Connection::open(&database).expect("legacy wallet database");
        connection.execute_batch(SCHEMA_V1).expect("schema v1");
        let transaction = connection
            .unchecked_transaction()
            .expect("metadata transaction");
        for (key, value) in metadata {
            set_meta(&transaction, key, &value).expect("legacy metadata");
        }
        transaction.commit().expect("commit legacy metadata");
        drop(connection);
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("legacy wallet mode");

        let mut opened = WalletStore::open(&database).expect("recognized legacy wallet");
        assert!(opened.is_locked());
        assert_eq!(
            opened
                .connection
                .query_row::<u32, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .expect("migrated schema version"),
            SCHEMA_VERSION
        );
        opened.unlock(PASSPHRASE).expect("unlock migrated wallet");
    }

    #[cfg(unix)]
    #[test]
    fn unix_open_rejects_malformed_key_check_without_mutation() {
        let directory = unix_private_tempdir();
        let database = directory.path().join("malformed-key-check.sqlite3");
        let store = WalletStore::create_with_kdf(
            &database,
            "malformed-key-check-passphrase",
            KdfConfig::testing(),
        )
        .expect("create wallet fixture");
        let mut malformed = required_meta(&store.connection, "key_check").expect("key check");
        malformed.push(0);
        store
            .connection
            .execute(
                "UPDATE wallet_meta SET value=?1 WHERE key='key_check'",
                params![malformed],
            )
            .expect("write malformed key check");
        store
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .expect("checkpoint malformed fixture");
        drop(store);

        let before = std::fs::read(&database).expect("wallet bytes before rejected open");
        assert!(matches!(
            WalletStore::open(&database),
            Err(StoreError::CorruptMetadata)
        ));
        assert_eq!(
            std::fs::read(&database).expect("wallet bytes after rejected open"),
            before
        );
        for sidecar in sqlite_sidecar_paths(&database) {
            assert!(!sidecar.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_wallet_database_hard_links_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unix_private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let source = directory.path().join("source.sqlite3");
        let database = directory.path().join("wallet.sqlite3");
        std::fs::write(&source, []).expect("hard-link source");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
            .expect("hard-link source mode");
        std::fs::hard_link(&source, &database).expect("database hard link");

        assert!(matches!(
            validate_wallet_location(&database, WalletPathRequirement::Existing),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
        assert!(matches!(
            validate_wallet_location(&database, WalletPathRequirement::Missing),
            Err(StoreError::UnsafeFilesystemBoundary)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_create_atomically_sets_mode_and_reopens() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = unix_private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let database = directory.path().join("wallet.sqlite3");
        let store = WalletStore::create_with_kdf(
            &database,
            "create-reopen-passphrase",
            KdfConfig::testing(),
        )
        .expect("create wallet database");
        let metadata = std::fs::symlink_metadata(&database).expect("created database metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet database");
        assert!(reopened.is_locked());
        reopened
            .unlock("create-reopen-passphrase")
            .expect("unlock reopened wallet database");
    }

    #[test]
    fn secrets_require_unlock_and_ciphertext_does_not_contain_cleartext() {
        let mut store = WalletStore::create_in_memory("correct horse battery staple")
            .expect("create encrypted store");
        store
            .put_secret(
                b"seed",
                SecretKind::RecoverySeed,
                b"never persist me clear",
                1,
            )
            .expect("put secret");
        let raw: Vec<u8> = store
            .connection
            .query_row(
                "SELECT encrypted_value FROM secrets WHERE id=?1",
                params![b"seed".as_slice()],
                |row| row.get(0),
            )
            .expect("raw envelope");
        assert!(
            !raw.windows(b"never persist me clear".len())
                .any(|window| window == b"never persist me clear")
        );
        assert_eq!(
            store
                .get_secret(b"seed", SecretKind::RecoverySeed)
                .expect("decrypt")
                .expect("present")
                .as_slice(),
            b"never persist me clear"
        );
        store.lock();
        assert!(matches!(
            store.get_secret(b"seed", SecretKind::RecoverySeed),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn seed_and_initial_account_commit_together_or_not_at_all() {
        let mut store = WalletStore::create_in_memory("atomic bootstrap passphrase")
            .expect("create encrypted store");
        let seed_id = [41_u8; 16];
        let account_id = [42_u8; 32];
        let account = json!({"wallet": 41, "account": 42});

        assert!(matches!(
            store.initialize_recovery_seed_and_wallet_account_with_hook(
                &seed_id,
                &[43_u8; 64],
                &account_id,
                &account,
                7,
                || Err(StoreError::CorruptMetadata),
            ),
            Err(StoreError::CorruptMetadata)
        ));
        assert!(
            store
                .get_secret(&seed_id, SecretKind::RecoverySeed)
                .expect("read rolled-back seed")
                .is_none()
        );
        assert!(
            store
                .wallet_account::<serde_json::Value>(&account_id)
                .expect("read rolled-back account")
                .is_none()
        );

        let revision = store
            .initialize_recovery_seed_and_wallet_account(
                &seed_id,
                &[43_u8; 64],
                &account_id,
                &account,
                8,
            )
            .expect("atomic bootstrap");
        assert_eq!(revision, 1);
        assert_eq!(
            store
                .get_secret(&seed_id, SecretKind::RecoverySeed)
                .expect("read seed")
                .expect("seed present")
                .as_slice(),
            &[43_u8; 64]
        );
        let stored = store
            .wallet_account::<serde_json::Value>(&account_id)
            .expect("read account")
            .expect("account present");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.value, account);
        store
            .validate_single_recovery_seed(&seed_id)
            .expect("one exact authenticated recovery seed");

        store
            .put_secret(&[44_u8; 16], SecretKind::RecoverySeed, &[45_u8; 64], 9)
            .expect("second seed fixture");
        assert!(matches!(
            store.validate_single_recovery_seed(&seed_id),
            Err(StoreError::BootstrapConflict)
        ));
    }

    #[test]
    fn single_recovery_seed_validation_rejects_malformed_plaintext_length() {
        for (case, length) in [63_usize, 65].into_iter().enumerate() {
            let mut store = WalletStore::create_in_memory(&format!("seed length case {case}"))
                .expect("malformed seed store");
            let seed_id = [81_u8 + case as u8; 16];
            store
                .put_secret(&seed_id, SecretKind::RecoverySeed, &vec![82_u8; length], 1)
                .expect("malformed seed fixture");
            assert!(matches!(
                store.validate_single_recovery_seed(&seed_id),
                Err(StoreError::InvalidRecoverySeed)
            ));
        }

        let mut initializer_store =
            WalletStore::create_in_memory("malformed initializer seed store")
                .expect("initializer store");
        assert!(matches!(
            initializer_store.initialize_recovery_seed_and_wallet_account(
                &[84_u8; 16],
                &[85_u8; RECOVERY_SEED_BYTES - 1],
                &[86_u8; 32],
                &json!({"account": 86}),
                1,
            ),
            Err(StoreError::InvalidRecoverySeed)
        ));
        assert!(
            initializer_store
                .get_secret(&[84_u8; 16], SecretKind::RecoverySeed)
                .expect("read rejected seed")
                .is_none()
        );
        assert!(
            initializer_store
                .wallet_account::<serde_json::Value>(&[86_u8; 32])
                .expect("read rejected account")
                .is_none()
        );
    }

    #[test]
    fn seed_and_initial_account_reject_partial_or_duplicate_state() {
        let seed_id = [51_u8; 16];
        let account_id = [52_u8; 32];
        let account = json!({"wallet": 51, "account": 52});

        let mut seed_only =
            WalletStore::create_in_memory("seed-only passphrase").expect("create seed-only store");
        seed_only
            .put_secret(&seed_id, SecretKind::RecoverySeed, &[53_u8; 64], 1)
            .expect("seed fixture");
        assert!(matches!(
            seed_only.initialize_recovery_seed_and_wallet_account(
                &seed_id,
                &[53_u8; 64],
                &account_id,
                &account,
                2,
            ),
            Err(StoreError::BootstrapConflict)
        ));
        assert!(
            seed_only
                .wallet_account::<serde_json::Value>(&account_id)
                .expect("read absent account")
                .is_none()
        );

        let mut account_only = WalletStore::create_in_memory("account-only passphrase")
            .expect("create account-only store");
        account_only
            .save_wallet_account(&account_id, 0, &account, 1)
            .expect("account fixture");
        assert!(matches!(
            account_only.initialize_recovery_seed_and_wallet_account(
                &seed_id,
                &[53_u8; 64],
                &account_id,
                &account,
                2,
            ),
            Err(StoreError::StaleRevision {
                expected: 0,
                actual: 1,
            })
        ));
        assert!(
            account_only
                .get_secret(&seed_id, SecretKind::RecoverySeed)
                .expect("read absent seed")
                .is_none()
        );

        let other_seed_id = [54_u8; 16];
        let other_account_id = [55_u8; 32];
        assert!(matches!(
            seed_only.initialize_recovery_seed_and_wallet_account(
                &other_seed_id,
                &[56_u8; 64],
                &other_account_id,
                &account,
                3,
            ),
            Err(StoreError::BootstrapConflict)
        ));
        assert!(
            seed_only
                .get_secret(&other_seed_id, SecretKind::RecoverySeed)
                .expect("read absent second seed")
                .is_none()
        );
    }

    #[test]
    fn workflow_updates_are_compare_and_swap_and_persist_before_broadcast() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        let id = WorkflowId::new([7; 16]);
        let revision = store
            .save_workflow(
                id,
                WorkflowKind::AtomicSwap,
                0,
                &json!({"state":"terms_frozen"}),
                true,
                5,
            )
            .expect("first revision");
        assert_eq!(revision, 1);
        assert!(matches!(
            store.save_workflow(id, WorkflowKind::AtomicSwap, 0, &json!({}), true, 6),
            Err(StoreError::StaleRevision { .. })
        ));
        let loaded: StoredWorkflow<serde_json::Value> =
            store.load_workflow(id).expect("load").expect("present");
        assert!(loaded.irreversible_broadcast_prepared);
        assert_eq!(loaded.revision, 1);
        let raw: Vec<u8> = store
            .connection
            .query_row(
                "SELECT state_json FROM workflows WHERE id=?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("encrypted workflow row");
        assert!(!raw.windows(12).any(|window| window == b"terms_frozen"));
    }

    #[test]
    fn typed_entities_are_encrypted_revisioned_and_relocation_bound() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        let id = [4_u8; 36];
        let revision = store
            .save_hns_utxo(&id, 0, &json!({"value":"42000000"}), 10)
            .expect("save entity");
        assert_eq!(revision, 1);
        let loaded: StoredEntity<serde_json::Value> =
            store.hns_utxo(&id).expect("load entity").expect("present");
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.value["value"], "42000000");
        assert!(matches!(
            store.save_hns_utxo(&id, 0, &json!({"value":"1"}), 11),
            Err(StoreError::StaleRevision { .. })
        ));

        let envelope: Vec<u8> = store
            .connection
            .query_row(
                "SELECT encrypted_value FROM encrypted_entities
                 WHERE entity_kind='hns_utxo' AND record_id=?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .expect("ciphertext");
        store
            .connection
            .execute(
                "INSERT INTO encrypted_entities(
                     entity_kind, record_id, revision, encrypted_value, updated_at_unix
                 ) VALUES('bitcoin_utxo', ?1, 1, ?2, 10)",
                params![[5_u8; 36].as_slice(), envelope],
            )
            .expect("relocate ciphertext");
        assert!(matches!(
            store.bitcoin_utxo::<serde_json::Value>(&[5_u8; 36]),
            Err(StoreError::Encryption)
        ));
    }

    #[test]
    fn pending_approval_is_encrypted_single_use_and_expiring() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        let id = ApprovalId::new([9; 16]);
        store
            .put_pending_approval(id, "https://wallet.example", b"approval commitment", 10, 20)
            .expect("put approval");
        let approval = store
            .take_pending_approval(id, 10)
            .expect("take approval")
            .expect("live approval");
        assert_eq!(approval.request_json.as_slice(), b"approval commitment");
        assert!(
            store
                .take_pending_approval(id, 10)
                .expect("second take")
                .is_none()
        );

        let expired = ApprovalId::new([8; 16]);
        store
            .put_pending_approval(expired, "https://wallet.example", b"expired", 20, 30)
            .expect("put expired approval");
        assert!(
            store
                .take_pending_approval(expired, 30)
                .expect("expire approval")
                .is_none()
        );
    }

    #[test]
    fn replay_nonces_are_atomic_and_expiring() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        store
            .consume_replay_nonce("https://example", 1, 10, 20)
            .expect("first use");
        assert!(matches!(
            store.consume_replay_nonce("https://example", 1, 11, 20),
            Err(StoreError::Replay)
        ));
        store
            .consume_replay_nonce("https://example", 1, 20, 30)
            .expect("expired nonce can be reused in a new bounded session");
    }

    #[test]
    fn account_workflow_reservation_batch_is_all_or_nothing() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        let account_id = vec![1_u8; 32];
        store
            .save_wallet_account(&account_id, 0, &json!({"next_change": 0}), 1)
            .expect("initial account");
        let workflow_id = WorkflowId::new([2; 16]);
        let account_save = EntityBatchSave {
            id: account_id.clone(),
            expected_revision: 1,
            value: json!({"next_change": 1}),
            updated_at_unix: 2,
        };
        let stale_reservation = EntityBatchSave {
            id: vec![3_u8; 36],
            expected_revision: 1,
            value: json!({"reserved": true}),
            updated_at_unix: 2,
        };
        assert!(matches!(
            store.save_workflow_with_account_and_entity_batch(
                workflow_id,
                WorkflowKind::HnsSend,
                0,
                &json!({"stage": "prepared"}),
                false,
                2,
                &account_save,
                EntityKind::InputReservation,
                &[stale_reservation],
                &[],
            ),
            Err(StoreError::StaleRevision { .. })
        ));
        let account: StoredEntity<serde_json::Value> = store
            .wallet_account(&account_id)
            .expect("load account")
            .expect("account present");
        assert_eq!(account.revision, 1);
        assert_eq!(account.value["next_change"], 0);
        assert!(
            store
                .load_workflow::<serde_json::Value>(workflow_id)
                .expect("load workflow")
                .is_none()
        );

        let reservation = EntityBatchSave {
            id: vec![3_u8; 36],
            expected_revision: 0,
            value: json!({"reserved": true}),
            updated_at_unix: 2,
        };
        let revisions = store
            .save_workflow_with_account_and_entity_batch(
                workflow_id,
                WorkflowKind::HnsSend,
                0,
                &json!({"stage": "prepared"}),
                false,
                2,
                &account_save,
                EntityKind::InputReservation,
                &[reservation],
                &[],
            )
            .expect("atomic prepare");
        assert_eq!(revisions, (1, 2));
        assert_eq!(
            store
                .wallet_account::<serde_json::Value>(&account_id)
                .expect("load account")
                .expect("account present")
                .value["next_change"],
            1
        );
        assert!(
            store
                .load_workflow::<serde_json::Value>(workflow_id)
                .expect("load workflow")
                .is_some()
        );
        assert!(
            store
                .input_reservation::<serde_json::Value>(&[3_u8; 36])
                .expect("load reservation")
                .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_tranche_shakedex_terminal_workflow_and_reservation_delete_is_atomic() {
        use std::os::unix::fs::PermissionsExt as _;

        const PASSPHRASE: &str = "production-tranche-terminal-release";
        let directory = unix_private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private wallet directory permissions");
        let database = directory.path().join("wallet.sqlite3");
        let mut store = WalletStore::create_with_kdf(&database, PASSPHRASE, KdfConfig::testing())
            .expect("file-backed encrypted store");
        let workflow_id = WorkflowId::new([0x41; 16]);
        let source_id = vec![0x42; 36];
        let funding_id = vec![0x43; 36];
        store
            .save_workflow(
                workflow_id,
                WorkflowKind::ShakedexValue,
                0,
                &json!({"stage": "confirmed"}),
                true,
                10,
            )
            .expect("active workflow");
        store
            .save_input_reservation(&source_id, 0, &json!({"kind": "source"}), 10)
            .expect("source reservation");
        store
            .save_input_reservation(&funding_id, 0, &json!({"kind": "funding"}), 10)
            .expect("funding reservation");

        let stale_deletes = [
            EntityBatchDelete {
                id: source_id.clone(),
                expected_revision: 2,
            },
            EntityBatchDelete {
                id: funding_id.clone(),
                expected_revision: 1,
            },
        ];
        assert!(matches!(
            store.save_workflow_with_entity_batch::<_, serde_json::Value>(
                workflow_id,
                WorkflowKind::ShakedexValue,
                1,
                &json!({"stage": "reservations_released"}),
                true,
                11,
                EntityKind::InputReservation,
                &[],
                &stale_deletes,
            ),
            Err(StoreError::StaleRevision { .. })
        ));
        let unchanged: StoredWorkflow<serde_json::Value> = store
            .load_workflow(workflow_id)
            .expect("load workflow")
            .expect("workflow present");
        assert_eq!(unchanged.revision, 1);
        assert_eq!(unchanged.state["stage"], "confirmed");
        assert!(
            store
                .input_reservation::<serde_json::Value>(&source_id)
                .expect("load source")
                .is_some()
        );
        assert!(
            store
                .input_reservation::<serde_json::Value>(&funding_id)
                .expect("load funding")
                .is_some()
        );

        let deletes = [
            EntityBatchDelete {
                id: source_id.clone(),
                expected_revision: 1,
            },
            EntityBatchDelete {
                id: funding_id.clone(),
                expected_revision: 1,
            },
        ];
        assert_eq!(
            store
                .save_workflow_with_entity_batch::<_, serde_json::Value>(
                    workflow_id,
                    WorkflowKind::ShakedexValue,
                    1,
                    &json!({"stage": "reservations_released"}),
                    true,
                    12,
                    EntityKind::InputReservation,
                    &[],
                    &deletes,
                )
                .expect("atomic terminal release"),
            2
        );
        assert_eq!(
            store
                .load_workflow::<serde_json::Value>(workflow_id)
                .expect("load released workflow")
                .expect("released workflow present")
                .state["stage"],
            "reservations_released"
        );
        assert!(
            store
                .input_reservation::<serde_json::Value>(&source_id)
                .expect("load released source")
                .is_none()
        );
        assert!(
            store
                .input_reservation::<serde_json::Value>(&funding_id)
                .expect("load released funding")
                .is_none()
        );

        store.lock();
        assert!(store.is_locked());
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("open locked encrypted store");
        assert!(reopened.is_locked());
        assert!(matches!(
            reopened.load_workflow::<serde_json::Value>(workflow_id),
            Err(StoreError::Locked)
        ));
        reopened.unlock(PASSPHRASE).expect("unlock reopened store");
        let persisted: StoredWorkflow<serde_json::Value> = reopened
            .load_workflow(workflow_id)
            .expect("load persisted terminal workflow")
            .expect("terminal workflow present after reopen");
        assert_eq!(persisted.revision, 2);
        assert_eq!(persisted.state["stage"], "reservations_released");
        assert!(
            reopened
                .input_reservation::<serde_json::Value>(&source_id)
                .expect("load absent source after reopen")
                .is_none()
        );
        assert!(
            reopened
                .input_reservation::<serde_json::Value>(&funding_id)
                .expect("load absent funding after reopen")
                .is_none()
        );
    }

    #[test]
    fn passphrases_are_bounded_at_the_store_boundary() {
        assert!(matches!(
            WalletStore::create_in_memory(""),
            Err(StoreError::InvalidPassphrase)
        ));
        let oversized = "x".repeat(MAX_PASSPHRASE_BYTES + 1);
        assert!(matches!(
            WalletStore::create_in_memory(&oversized),
            Err(StoreError::InvalidPassphrase)
        ));
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        store.lock();
        assert!(matches!(
            store.unlock(&oversized),
            Err(StoreError::InvalidPassphrase)
        ));
    }
}
