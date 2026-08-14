use core::fmt;
use std::collections::BTreeSet;

use hns_wallet_ffi::{
    ApprovalSummary, ServiceCapability, ServiceErrorCode, ServiceFailure, ServiceRequest,
    WalletRequest, WalletResponse,
};
use hns_wallet_provider::{ApprovedCall, PendingApproval, ProviderMethod};
use hns_wallet_store::{SharedWalletStore, StoreError};
use hns_wallet_types::ModuleId;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    LoadedNativeHnsReadProfile, NativeHnsReadProfileError, PersistentNativeHnsReadRuntime,
    PersistentNativeRecoveryReadOnlyRuntime, ServiceError, ServiceRuntime, WalletService,
    load_native_hns_read_profile,
    native_read_profile::load_persisted_recovery_read_only_native_hns_profile,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeHnsReadBootstrapMode {
    OrdinaryNonValue,
    PersistedRecoveryReadOnly,
}

/// One consumable wallet passphrase supplied by a trusted process-local
/// bootstrap composition. The allocation is zeroized on every return path and
/// its diagnostics never expose the passphrase.
///
/// This type is deliberately neither cloneable nor serializable. It is not an
/// ABI request and must not be sourced from an argv or environment field.
///
/// ```compile_fail
/// let secret = hns_wallet_service::NativeHnsReadBootstrapPassphrase::new(
///     zeroize::Zeroizing::new("do not copy me".to_owned()),
/// );
/// let _copied = secret.clone();
/// ```
///
/// ```compile_fail
/// let secret = hns_wallet_service::NativeHnsReadBootstrapPassphrase::new(
///     zeroize::Zeroizing::new("do not serialize me".to_owned()),
/// );
/// let _ = serde_json::to_value(&secret);
/// ```
pub struct NativeHnsReadBootstrapPassphrase(Zeroizing<String>);

impl NativeHnsReadBootstrapPassphrase {
    /// Take ownership of an allocation that is already guarded by zeroization.
    pub const fn new(passphrase: Zeroizing<String>) -> Self {
        Self(passphrase)
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for NativeHnsReadBootstrapPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NativeHnsReadBootstrapPassphrase")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Exact nonsecret active-profile fence supplied by the wallet-owned launch
/// authority. Both fields must match before and after service construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHnsReadProfileFence {
    revision: u64,
    updated_at_unix: u64,
}

impl NativeHnsReadProfileFence {
    /// Construct the exact expected active profile revision and update time.
    pub const fn new(revision: u64, updated_at_unix: u64) -> Self {
        Self {
            revision,
            updated_at_unix,
        }
    }

    /// Return the expected authenticated entity revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Return the expected authenticated entity update time.
    pub const fn updated_at_unix(self) -> u64 {
        self.updated_at_unix
    }
}

/// Closed post-bootstrap runtime. Its wallet-operation implementation admits
/// exactly the six reads frozen by `hnsReadOperationsV1`; lifecycle, recovery,
/// workflow, value, provider, and non-HNS module operations remain rejected.
pub struct ProfileBackedNativeHnsReadRuntime {
    inner: PersistentNativeHnsReadRuntime,
    profile_fence: NativeHnsReadProfileFence,
}

impl ProfileBackedNativeHnsReadRuntime {
    #[cfg(test)]
    pub(crate) fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.inner.store.is_same_authority(store)
            && self.inner.runtime.shares_store_authority(store)
    }

    pub(crate) fn admits_wallet_request(request: &WalletRequest) -> bool {
        admits_wallet_request(request)
    }

    fn revalidate_profile_fence(&self) -> Result<(), ServiceFailure> {
        match require_active_profile(
            &self.inner.store,
            self.profile_fence,
            NativeHnsReadBootstrapMode::OrdinaryNonValue,
        ) {
            Ok(loaded) => {
                drop(loaded);
                Ok(())
            }
            Err(_) => {
                let _ = self.inner.store.lock();
                Err(profile_fence_changed())
            }
        }
    }
}

/// Closed recovery-only post-bootstrap runtime for an exact already-persisted
/// flagged account/profile. Its flags are identity facts only: this type
/// advertises no provider or value capability and admits only the six frozen
/// `hnsReadOperationsV1` wallet reads.
pub struct RecoveryProfileBackedNativeHnsReadRuntime {
    inner: PersistentNativeRecoveryReadOnlyRuntime,
    profile_fence: NativeHnsReadProfileFence,
}

impl RecoveryProfileBackedNativeHnsReadRuntime {
    #[cfg(test)]
    pub(crate) fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.inner.shares_store_authority(store)
    }

    pub(crate) fn admits_wallet_request(request: &WalletRequest) -> bool {
        admits_wallet_request(request)
    }

    fn revalidate_profile_fence(&self) -> Result<(), ServiceFailure> {
        match require_active_profile(
            &self.inner.store,
            self.profile_fence,
            NativeHnsReadBootstrapMode::PersistedRecoveryReadOnly,
        ) {
            Ok(loaded) => {
                drop(loaded);
                Ok(())
            }
            Err(_) => {
                let _ = self.inner.store.lock();
                Err(profile_fence_changed())
            }
        }
    }
}

impl Drop for RecoveryProfileBackedNativeHnsReadRuntime {
    fn drop(&mut self) {
        let _ = self.inner.store.lock();
    }
}

impl ServiceRuntime for RecoveryProfileBackedNativeHnsReadRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ])
    }

    fn admit_service_request(&self, request: &ServiceRequest) -> Result<(), ServiceFailure> {
        match request {
            ServiceRequest::Wallet { request } if Self::admits_wallet_request(request) => Ok(()),
            ServiceRequest::Wallet { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
            _ => Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            )),
        }
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
        self.inner.lock_wallet()
    }

    fn execute_wallet(&mut self, request: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
        if !Self::admits_wallet_request(&request) {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ));
        }
        self.revalidate_profile_fence()?;
        let response = self.inner.execute_wallet(request);
        self.revalidate_profile_fence()?;
        response
    }
}

fn admits_wallet_request(request: &WalletRequest) -> bool {
    matches!(
        request,
        WalletRequest::Status
            | WalletRequest::ListAccounts
            | WalletRequest::Balance {
                module: ModuleId::Handshake,
                ..
            }
            | WalletRequest::ReceiveTarget {
                module: ModuleId::Handshake,
                ..
            }
            | WalletRequest::TransactionHistory {
                module: ModuleId::Handshake,
                ..
            }
            | WalletRequest::ModuleStatus {
                module: ModuleId::Handshake,
            }
    )
}

impl Drop for ProfileBackedNativeHnsReadRuntime {
    fn drop(&mut self) {
        let _ = self.inner.store.lock();
    }
}

impl ServiceRuntime for ProfileBackedNativeHnsReadRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::from([
            ServiceCapability::WalletOperations,
            ServiceCapability::HnsReadOperationsV1,
        ])
    }

    fn admit_service_request(&self, request: &ServiceRequest) -> Result<(), ServiceFailure> {
        match request {
            ServiceRequest::Wallet { request } if Self::admits_wallet_request(request) => Ok(()),
            ServiceRequest::Wallet { .. } => Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            )),
            _ => Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            )),
        }
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
        self.inner.lock_wallet()
    }

    fn execute_wallet(&mut self, request: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
        if !Self::admits_wallet_request(&request) {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ));
        }
        self.revalidate_profile_fence()?;
        let response = self.inner.execute_wallet(request);
        self.revalidate_profile_fence()?;
        response
    }
}

/// Failure from the private profile-backed native-read composition.
#[derive(Debug, Error)]
pub enum NativeHnsReadBootstrapError {
    /// The shared encrypted store rejected bootstrap or relocking.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The encrypted profile failed its closed-schema or account checks.
    #[error(transparent)]
    Profile(#[from] NativeHnsReadProfileError),
    /// The locked native-read service could not be composed.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// An active entity can never have revision zero.
    #[error("native HNS read bootstrap requires a nonzero active profile revision")]
    InvalidProfileFence,
    /// No singleton profile has been provisioned.
    #[error("native HNS read bootstrap requires an active profile, but none exists")]
    ProfileAbsent,
    /// The singleton is a persistent revocation tombstone.
    #[error(
        "native HNS read bootstrap profile is revoked at revision {revision} and update time {updated_at_unix}"
    )]
    ProfileRevoked {
        /// Authenticated tombstone revision.
        revision: u64,
        /// Authenticated tombstone update time.
        updated_at_unix: u64,
    },
    /// Active profile metadata did not equal the wallet-owned launch fence.
    #[error(
        "native HNS read bootstrap profile fence mismatch: expected revision {expected_revision} at {expected_updated_at_unix}, found revision {actual_revision} at {actual_updated_at_unix}"
    )]
    ProfileFenceMismatch {
        /// Expected authenticated revision.
        expected_revision: u64,
        /// Expected authenticated update time.
        expected_updated_at_unix: u64,
        /// Loaded authenticated revision.
        actual_revision: u64,
        /// Loaded authenticated update time.
        actual_updated_at_unix: u64,
    },
    /// The second process-local unlock unexpectedly failed after construction.
    #[error("native HNS read bootstrap internal unlock failed")]
    InternalUnlock,
}

impl WalletService<SharedWalletStore, ProfileBackedNativeHnsReadRuntime> {
    /// Consume one trusted zeroizing passphrase and exact active-profile fence
    /// into an already-unlocked, exact-marker read service.
    ///
    /// Bootstrap requires the supplied `SharedWalletStore` to start locked. It
    /// unlocks only to load and authenticate the encrypted profile, locks the
    /// same Arc-backed authority before calling the ordinary native-read
    /// constructor, performs one private internal unlock, and then reloads the
    /// profile to require the identical revision/update fence. Every error path
    /// clears the shared record key before returning.
    pub fn new_profile_backed_native_hns_reads(
        store: SharedWalletStore,
        passphrase: NativeHnsReadBootstrapPassphrase,
        fence: NativeHnsReadProfileFence,
    ) -> Result<Self, NativeHnsReadBootstrapError> {
        let relock_store = store.clone();
        let result = Self::bootstrap(store, &passphrase, fence);
        if result.is_err() {
            relock_store.lock()?;
        }
        result
    }

    fn bootstrap(
        store: SharedWalletStore,
        passphrase: &NativeHnsReadBootstrapPassphrase,
        fence: NativeHnsReadProfileFence,
    ) -> Result<Self, NativeHnsReadBootstrapError> {
        if fence.revision == 0 {
            return Err(NativeHnsReadBootstrapError::InvalidProfileFence);
        }
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked.into());
        }

        store.unlock(passphrase.expose_secret())?;
        let loaded =
            require_active_profile(&store, fence, NativeHnsReadBootstrapMode::OrdinaryNonValue)?;
        let config = loaded.profile.into_service_config()?;
        store.lock()?;

        let base = WalletService::<SharedWalletStore, PersistentNativeHnsReadRuntime>::
            new_persistent_native_hns_reads(store.clone(), config)?;
        let mut service = Self::from_base(base, fence);
        service
            .runtime
            .inner
            .unlock(passphrase.expose_secret())
            .map_err(|_| NativeHnsReadBootstrapError::InternalUnlock)?;
        service.rotate_wallet_session(false)?;

        let reloaded =
            require_active_profile(&store, fence, NativeHnsReadBootstrapMode::OrdinaryNonValue)?;
        drop(reloaded);
        Ok(service)
    }

    fn from_base(
        base: WalletService<SharedWalletStore, PersistentNativeHnsReadRuntime>,
        profile_fence: NativeHnsReadProfileFence,
    ) -> Self {
        let WalletService {
            provider,
            runtime,
            service_session_id,
            wallet_session_id,
            mut capabilities,
            session,
            seen_request_ids,
            request_order,
            pending,
            event_sequences,
        } = base;
        capabilities.remove(&ServiceCapability::ProviderDispatch);
        capabilities.remove(&ServiceCapability::ValueMovement);
        capabilities.remove(&ServiceCapability::BrowserIntegration);
        Self {
            provider,
            runtime: ProfileBackedNativeHnsReadRuntime {
                inner: runtime,
                profile_fence,
            },
            service_session_id,
            wallet_session_id,
            capabilities,
            session,
            seen_request_ids,
            request_order,
            pending,
            event_sequences,
        }
    }
}

impl WalletService<SharedWalletStore, RecoveryProfileBackedNativeHnsReadRuntime> {
    /// Explicitly reopen an already-persisted flagged account/profile through
    /// the closed six-read recovery surface.
    ///
    /// This does not provision a profile or account, and it rejects an absent,
    /// non-flagged, structurally invalid, mismatched, stale, or revoked record.
    /// The selected value/settlement bits remain exact identity only. Provider
    /// dispatch, current-lock/Denuo authority, signing, import/export,
    /// workflows, value movement, and lifecycle requests remain unreachable.
    pub fn new_recovery_read_only_profile_backed_native_hns_reads(
        store: SharedWalletStore,
        passphrase: NativeHnsReadBootstrapPassphrase,
        fence: NativeHnsReadProfileFence,
    ) -> Result<Self, NativeHnsReadBootstrapError> {
        let relock_store = store.clone();
        let result = Self::bootstrap(store, &passphrase, fence);
        if result.is_err() {
            relock_store.lock()?;
        }
        result
    }

    fn bootstrap(
        store: SharedWalletStore,
        passphrase: &NativeHnsReadBootstrapPassphrase,
        fence: NativeHnsReadProfileFence,
    ) -> Result<Self, NativeHnsReadBootstrapError> {
        if fence.revision == 0 {
            return Err(NativeHnsReadBootstrapError::InvalidProfileFence);
        }
        if !store.is_locked()? {
            return Err(ServiceError::PersistentStoreMustStartLocked.into());
        }

        store.unlock(passphrase.expose_secret())?;
        let loaded = require_active_profile(
            &store,
            fence,
            NativeHnsReadBootstrapMode::PersistedRecoveryReadOnly,
        )?;
        let config = loaded
            .profile
            .into_persisted_recovery_read_only_service_config()?;
        store.lock()?;

        let base = WalletService::<
            SharedWalletStore,
            PersistentNativeRecoveryReadOnlyRuntime,
        >::new_persisted_recovery_read_only_native_hns_reads(store.clone(), config)?;
        let mut service = Self::from_base(base, fence);
        service
            .runtime
            .inner
            .unlock(passphrase.expose_secret())
            .map_err(|_| NativeHnsReadBootstrapError::InternalUnlock)?;
        service.rotate_wallet_session(false)?;

        let reloaded = require_active_profile(
            &store,
            fence,
            NativeHnsReadBootstrapMode::PersistedRecoveryReadOnly,
        )?;
        drop(reloaded);
        Ok(service)
    }

    fn from_base(
        base: WalletService<SharedWalletStore, PersistentNativeRecoveryReadOnlyRuntime>,
        profile_fence: NativeHnsReadProfileFence,
    ) -> Self {
        let WalletService {
            provider,
            runtime,
            service_session_id,
            wallet_session_id,
            mut capabilities,
            session,
            seen_request_ids,
            request_order,
            pending,
            event_sequences,
        } = base;
        capabilities.remove(&ServiceCapability::ProviderDispatch);
        capabilities.remove(&ServiceCapability::ValueMovement);
        capabilities.remove(&ServiceCapability::BrowserIntegration);
        Self {
            provider,
            runtime: RecoveryProfileBackedNativeHnsReadRuntime {
                inner: runtime,
                profile_fence,
            },
            service_session_id,
            wallet_session_id,
            capabilities,
            session,
            seen_request_ids,
            request_order,
            pending,
            event_sequences,
        }
    }
}

fn profile_fence_changed() -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::PersistenceFailure,
        message: "native HNS read profile is unavailable or changed".to_owned(),
        unsupported_capability: None,
    }
}

fn require_active_profile(
    store: &SharedWalletStore,
    expected: NativeHnsReadProfileFence,
    mode: NativeHnsReadBootstrapMode,
) -> Result<crate::StoredNativeHnsReadProfile, NativeHnsReadBootstrapError> {
    let loaded = match match mode {
        NativeHnsReadBootstrapMode::OrdinaryNonValue => load_native_hns_read_profile(store),
        NativeHnsReadBootstrapMode::PersistedRecoveryReadOnly => {
            load_persisted_recovery_read_only_native_hns_profile(store)
        }
    }? {
        LoadedNativeHnsReadProfile::Absent => {
            return Err(NativeHnsReadBootstrapError::ProfileAbsent);
        }
        LoadedNativeHnsReadProfile::Revoked(metadata) => {
            return Err(NativeHnsReadBootstrapError::ProfileRevoked {
                revision: metadata.revision,
                updated_at_unix: metadata.updated_at_unix,
            });
        }
        LoadedNativeHnsReadProfile::Active(loaded) => loaded,
    };
    if loaded.revision != expected.revision || loaded.updated_at_unix != expected.updated_at_unix {
        return Err(NativeHnsReadBootstrapError::ProfileFenceMismatch {
            expected_revision: expected.revision,
            expected_updated_at_unix: expected.updated_at_unix,
            actual_revision: loaded.revision,
            actual_updated_at_unix: loaded.updated_at_unix,
        });
    }
    Ok(loaded)
}
