use core::fmt;
use std::net::SocketAddr;

use hns_wallet_ffi::{MAX_PUBLIC_STRING_BYTES, SecretString};
use hns_wallet_hns::{HnsAccountRecord, HnsNetwork, HnsNodeRpcConfig, HnsRuntimeConfig};
use hns_wallet_store::{SharedWalletStore, StoreError, StoredEntity, WalletStore};
use hns_wallet_types::{AccountId, BaseUnits, WalletId};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PersistentNativeHnsReadConfig, is_printable_ascii};

/// Authenticated-record schema for the native HNS read profile.
pub const NATIVE_HNS_READ_PROFILE_SCHEMA_VERSION: u16 = 1;
/// The only record identifier admitted in the native HNS read-profile namespace.
pub const NATIVE_HNS_READ_PROFILE_ID: &[u8] = b"native-hns-read-profile-v1";

/// Wallet-owned configuration for a future trusted native HNS read service.
///
/// The profile is deliberately non-cloneable and non-serializable through its
/// public API. Only this module's private borrowed record can serialize it into
/// the encrypted wallet store. `Debug` redacts the node Authorization value,
/// and validation rejects value or settlement configuration.
///
/// ```compile_fail
/// # fn cannot_serialize(profile: &hns_wallet_service::NativeHnsReadProfile) {
/// let _ = serde_json::to_value(profile);
/// # }
/// ```
///
/// ```compile_fail
/// # fn cannot_clone(profile: &hns_wallet_service::NativeHnsReadProfile) {
/// let _: hns_wallet_service::NativeHnsReadProfile = (*profile).clone();
/// # }
/// ```
pub struct NativeHnsReadProfile {
    schema_version: u16,
    account: HnsRuntimeConfig,
    node_endpoint: SocketAddr,
    node_authorization: SecretString,
    account_label: String,
}

impl NativeHnsReadProfile {
    pub fn new(
        account: HnsRuntimeConfig,
        node_endpoint: SocketAddr,
        node_authorization: SecretString,
        account_label: String,
    ) -> Result<Self, NativeHnsReadProfileError> {
        let profile = Self {
            schema_version: NATIVE_HNS_READ_PROFILE_SCHEMA_VERSION,
            account,
            node_endpoint,
            node_authorization,
            account_label,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn account(&self) -> &HnsRuntimeConfig {
        &self.account
    }

    pub const fn node_endpoint(&self) -> SocketAddr {
        self.node_endpoint
    }

    pub fn account_label(&self) -> &str {
        &self.account_label
    }

    /// Consume the decrypted profile into the existing non-value native-read
    /// composition. The temporary authorization copy is immediately owned by
    /// a zeroizing `HnsNodeRpcConfig`; consuming `self` then zeroizes the
    /// profile's original allocation.
    pub fn into_service_config(
        self,
    ) -> Result<PersistentNativeHnsReadConfig, NativeHnsReadProfileError> {
        self.validate()?;
        let node_rpc = HnsNodeRpcConfig::new(
            self.node_endpoint,
            self.node_authorization.expose_secret().to_owned(),
        )
        .map_err(|_| NativeHnsReadProfileError::InvalidConfiguration)?;
        Ok(PersistentNativeHnsReadConfig {
            account: self.account,
            node_rpc,
            account_label: self.account_label,
        })
    }

    fn validate(&self) -> Result<(), NativeHnsReadProfileError> {
        validate_profile_parts(
            self.schema_version,
            &self.account,
            self.node_endpoint,
            self.node_authorization.expose_secret(),
            &self.account_label,
        )
    }
}

impl fmt::Debug for NativeHnsReadProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHnsReadProfile")
            .field("schema_version", &self.schema_version)
            .field("account", &self.account)
            .field("node_endpoint", &self.node_endpoint)
            .field("node_authorization", &"[REDACTED]")
            .field("account_label", &self.account_label)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHnsReadProfileState {
    Active,
    Revoked,
}

/// Secret-free authenticated metadata for one profile record or tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHnsReadProfileMetadata {
    pub revision: u64,
    pub state: NativeHnsReadProfileState,
    pub updated_at_unix: u64,
}

/// One authenticated encrypted active profile revision returned after exact
/// account reauthentication.
pub struct StoredNativeHnsReadProfile {
    pub revision: u64,
    pub profile: NativeHnsReadProfile,
    pub updated_at_unix: u64,
}

impl StoredNativeHnsReadProfile {
    pub const fn metadata(&self) -> NativeHnsReadProfileMetadata {
        NativeHnsReadProfileMetadata {
            revision: self.revision,
            state: NativeHnsReadProfileState::Active,
            updated_at_unix: self.updated_at_unix,
        }
    }
}

impl fmt::Debug for StoredNativeHnsReadProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNativeHnsReadProfile")
            .field("revision", &self.revision)
            .field("profile", &self.profile)
            .field("updated_at_unix", &self.updated_at_unix)
            .finish()
    }
}

/// Complete result of inspecting the encrypted singleton namespace.
#[derive(Debug)]
pub enum LoadedNativeHnsReadProfile {
    Absent,
    Active(StoredNativeHnsReadProfile),
    Revoked(NativeHnsReadProfileMetadata),
}

/// Create, rotate, or re-provision the single encrypted native-read profile.
///
/// The selected account is authenticated before persistence. Runtime use must
/// authenticate it again after every later unlock; this record is expected
/// configuration, not chain or browser authority. Re-provisioning a tombstone
/// requires its exact revision, so revoke/re-provision cannot reset the record
/// generation.
pub fn provision_native_hns_read_profile(
    store: &SharedWalletStore,
    expected_revision: u64,
    profile: &NativeHnsReadProfile,
    updated_at_unix: u64,
) -> Result<u64, NativeHnsReadProfileError> {
    profile.validate()?;
    let persisted = PersistedNativeHnsReadProfileRef::from(profile);
    store.try_with_store_mut(|wallet| {
        authenticate_exact_account(wallet, profile.account())?;
        let existing = wallet.native_hns_read_profiles::<PersistedNativeHnsReadProfile>(2)?;
        validate_singleton(&existing)?;
        validate_update_fence(existing.first(), expected_revision, updated_at_unix)?;
        wallet
            .save_native_hns_read_profile(
                NATIVE_HNS_READ_PROFILE_ID,
                expected_revision,
                &persisted,
                updated_at_unix,
            )
            .map_err(NativeHnsReadProfileError::from)
    })
}

/// Inspect the single encrypted profile state after wallet unlock. Active
/// profiles reauthenticate their exact account; tombstones return only
/// secret-free revision metadata and absent state remains distinguishable.
pub fn load_native_hns_read_profile(
    store: &SharedWalletStore,
) -> Result<LoadedNativeHnsReadProfile, NativeHnsReadProfileError> {
    store.try_with_store_mut(|wallet| {
        let mut records = wallet.native_hns_read_profiles::<PersistedNativeHnsReadProfile>(2)?;
        validate_singleton(&records)?;
        let Some(record) = records.pop() else {
            return Ok(LoadedNativeHnsReadProfile::Absent);
        };
        let revision = record.revision;
        let updated_at_unix = record.updated_at_unix;
        match record.value {
            PersistedNativeHnsReadProfile::Active {
                schema_version,
                account,
                node_endpoint,
                node_authorization,
                account_label,
            } => {
                let profile = NativeHnsReadProfile {
                    schema_version,
                    account: account.into_runtime_config(),
                    node_endpoint,
                    node_authorization,
                    account_label,
                };
                profile.validate()?;
                authenticate_exact_account(wallet, profile.account())?;
                Ok(LoadedNativeHnsReadProfile::Active(
                    StoredNativeHnsReadProfile {
                        revision,
                        profile,
                        updated_at_unix,
                    },
                ))
            }
            PersistedNativeHnsReadProfile::Revoked { schema_version } => {
                validate_schema(schema_version)?;
                Ok(LoadedNativeHnsReadProfile::Revoked(
                    NativeHnsReadProfileMetadata {
                        revision,
                        state: NativeHnsReadProfileState::Revoked,
                        updated_at_unix,
                    },
                ))
            }
        }
    })
}

/// Compare-and-swap the active profile into a persistent tombstone. The
/// tombstone retains the monotonically increasing revision and update time so
/// later re-provisioning cannot create a revision ABA. This changes future
/// startup configuration only; a future product must separately terminate or
/// revision-revalidate any already-running service before claiming revocation.
pub fn revoke_native_hns_read_profile(
    store: &SharedWalletStore,
    expected_revision: u64,
    updated_at_unix: u64,
) -> Result<u64, NativeHnsReadProfileError> {
    store.try_with_store_mut(|wallet| {
        let existing = wallet.native_hns_read_profiles::<IgnoredAny>(2)?;
        validate_singleton_identity(&existing)?;
        let current = existing.first().ok_or_else(|| {
            NativeHnsReadProfileError::Store(StoreError::StaleRevision {
                expected: expected_revision,
                actual: 0,
            })
        })?;
        validate_update_fence(Some(current), expected_revision, updated_at_unix)?;
        wallet
            .save_native_hns_read_profile(
                NATIVE_HNS_READ_PROFILE_ID,
                expected_revision,
                &PersistedNativeHnsReadProfileRef::Revoked {
                    schema_version: NATIVE_HNS_READ_PROFILE_SCHEMA_VERSION,
                },
                updated_at_unix,
            )
            .map_err(NativeHnsReadProfileError::from)
    })
}

#[derive(Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum PersistedNativeHnsReadProfileRef<'a> {
    Active {
        schema_version: u16,
        account: PersistedHnsRuntimeConfig,
        node_endpoint: SocketAddr,
        node_authorization: &'a SecretString,
        account_label: &'a str,
    },
    Revoked {
        schema_version: u16,
    },
}

impl<'a> From<&'a NativeHnsReadProfile> for PersistedNativeHnsReadProfileRef<'a> {
    fn from(profile: &'a NativeHnsReadProfile) -> Self {
        Self::Active {
            schema_version: profile.schema_version,
            account: PersistedHnsRuntimeConfig::from(&profile.account),
            node_endpoint: profile.node_endpoint,
            node_authorization: &profile.node_authorization,
            account_label: &profile.account_label,
        }
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum PersistedNativeHnsReadProfile {
    Active {
        schema_version: u16,
        account: PersistedHnsRuntimeConfig,
        node_endpoint: SocketAddr,
        node_authorization: SecretString,
        account_label: String,
    },
    Revoked {
        schema_version: u16,
    },
}

/// Closed schema-v1 projection. Persisting `HnsRuntimeConfig` directly would
/// let a future unknown nested field be silently ignored by this older reader.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedHnsRuntimeConfig {
    wallet_id: WalletId,
    account_id: AccountId,
    account_derivation_index: u32,
    network: HnsNetwork,
    birthday_height: u64,
    restore_lookahead: u32,
    minimum_confirmations: u32,
    dust_threshold: BaseUnits,
    value_operations_enabled: bool,
    settlement_enabled: bool,
}

impl From<&HnsRuntimeConfig> for PersistedHnsRuntimeConfig {
    fn from(config: &HnsRuntimeConfig) -> Self {
        Self {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            account_derivation_index: config.account_derivation_index,
            network: config.network,
            birthday_height: config.birthday_height,
            restore_lookahead: config.restore_lookahead,
            minimum_confirmations: config.minimum_confirmations,
            dust_threshold: config.dust_threshold,
            value_operations_enabled: config.value_operations_enabled,
            settlement_enabled: config.settlement_enabled,
        }
    }
}

impl PersistedHnsRuntimeConfig {
    const fn into_runtime_config(self) -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: self.wallet_id,
            account_id: self.account_id,
            account_derivation_index: self.account_derivation_index,
            network: self.network,
            birthday_height: self.birthday_height,
            restore_lookahead: self.restore_lookahead,
            minimum_confirmations: self.minimum_confirmations,
            dust_threshold: self.dust_threshold,
            value_operations_enabled: self.value_operations_enabled,
            settlement_enabled: self.settlement_enabled,
        }
    }

    const fn to_runtime_config(&self) -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: self.wallet_id,
            account_id: self.account_id,
            account_derivation_index: self.account_derivation_index,
            network: self.network,
            birthday_height: self.birthday_height,
            restore_lookahead: self.restore_lookahead,
            minimum_confirmations: self.minimum_confirmations,
            dust_threshold: self.dust_threshold,
            value_operations_enabled: self.value_operations_enabled,
            settlement_enabled: self.settlement_enabled,
        }
    }
}

impl PersistedNativeHnsReadProfile {
    fn validate(&self) -> Result<(), NativeHnsReadProfileError> {
        match self {
            Self::Active {
                schema_version,
                account,
                node_endpoint,
                node_authorization,
                account_label,
            } => {
                let account = account.to_runtime_config();
                validate_profile_parts(
                    *schema_version,
                    &account,
                    *node_endpoint,
                    node_authorization.expose_secret(),
                    account_label,
                )
            }
            Self::Revoked { schema_version } => validate_schema(*schema_version),
        }
    }
}

fn validate_singleton(
    records: &[StoredEntity<PersistedNativeHnsReadProfile>],
) -> Result<(), NativeHnsReadProfileError> {
    validate_singleton_identity(records)?;
    if let Some(record) = records.first() {
        record.value.validate()?;
    }
    Ok(())
}

fn validate_singleton_identity<T>(
    records: &[StoredEntity<T>],
) -> Result<(), NativeHnsReadProfileError> {
    if records.len() > 1
        || records
            .first()
            .is_some_and(|record| record.id != NATIVE_HNS_READ_PROFILE_ID)
    {
        return Err(NativeHnsReadProfileError::SingletonConflict);
    }
    Ok(())
}

fn validate_update_fence<T>(
    current: Option<&StoredEntity<T>>,
    expected_revision: u64,
    updated_at_unix: u64,
) -> Result<(), NativeHnsReadProfileError> {
    let actual = current.map_or(0, |record| record.revision);
    if actual != expected_revision {
        return Err(StoreError::StaleRevision {
            expected: expected_revision,
            actual,
        }
        .into());
    }
    if current.is_some_and(|record| updated_at_unix < record.updated_at_unix) {
        return Err(NativeHnsReadProfileError::TimestampRollback);
    }
    Ok(())
}

fn validate_profile_parts(
    schema_version: u16,
    account: &HnsRuntimeConfig,
    node_endpoint: SocketAddr,
    node_authorization: &str,
    account_label: &str,
) -> Result<(), NativeHnsReadProfileError> {
    validate_schema(schema_version)?;
    account
        .validate()
        .map_err(|_| NativeHnsReadProfileError::InvalidConfiguration)?;
    if account.value_operations_enabled
        || account.settlement_enabled
        // Escaped JSON strings can pass through a serde_json parser scratch
        // buffer before `SecretString` owns the decoded allocation. Restrict
        // the persisted profile to visible ASCII Authorization values whose
        // JSON representation is byte-for-byte escape-free.
        || node_authorization
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'"' | b'\\'))
        || account_label.is_empty()
        || account_label.len() > MAX_PUBLIC_STRING_BYTES
        || !is_printable_ascii(account_label)
    {
        return Err(NativeHnsReadProfileError::InvalidConfiguration);
    }
    HnsNodeRpcConfig::new(node_endpoint, node_authorization.to_owned())
        .map_err(|_| NativeHnsReadProfileError::InvalidConfiguration)?;
    Ok(())
}

fn validate_schema(schema_version: u16) -> Result<(), NativeHnsReadProfileError> {
    if schema_version != NATIVE_HNS_READ_PROFILE_SCHEMA_VERSION {
        return Err(NativeHnsReadProfileError::UnsupportedSchema);
    }
    Ok(())
}

fn authenticate_exact_account(
    wallet: &mut WalletStore,
    account: &HnsRuntimeConfig,
) -> Result<(), NativeHnsReadProfileError> {
    let mut accounts = wallet
        .wallet_accounts::<HnsAccountRecord>(2)
        .map_err(profile_account_store_error)?;
    if accounts.len() != 1 {
        return Err(NativeHnsReadProfileError::AccountMismatch);
    }
    let authenticated = accounts
        .pop()
        .ok_or(NativeHnsReadProfileError::AccountMismatch)?;
    if authenticated.id != account_record_id(account) || authenticated.value.config != *account {
        return Err(NativeHnsReadProfileError::AccountMismatch);
    }
    wallet
        .validate_single_recovery_seed(account.wallet_id.as_bytes())
        .map_err(profile_account_store_error)?;
    Ok(())
}

fn account_record_id(account: &HnsRuntimeConfig) -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(account.wallet_id.as_bytes());
    id[16..].copy_from_slice(account.account_id.as_bytes());
    id
}

fn profile_account_store_error(error: StoreError) -> NativeHnsReadProfileError {
    match error {
        StoreError::Locked | StoreError::Concurrency => error.into(),
        _ => NativeHnsReadProfileError::AccountMismatch,
    }
}

#[derive(Debug, Error)]
pub enum NativeHnsReadProfileError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("native HNS read profile uses an unsupported schema")]
    UnsupportedSchema,
    #[error("native HNS read profile configuration is invalid")]
    InvalidConfiguration,
    #[error("native HNS read profile does not match an authenticated wallet account")]
    AccountMismatch,
    #[error("native HNS read profile namespace is not a singleton")]
    SingletonConflict,
    #[error("native HNS read profile update timestamp would move backwards")]
    TimestampRollback,
}
