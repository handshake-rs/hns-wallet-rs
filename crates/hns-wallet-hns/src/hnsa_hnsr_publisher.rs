//! Durable, encrypted sequence reservations for future HNSA/HNSR publication.
//!
//! A sequence is committed before its opaque token is returned. Dropping a
//! token, a signing failure, or a process crash therefore burns a safe gap; a
//! future publication must reserve again and can never reuse that value. The
//! endpoint-delegation and named-route dimensions use separate authenticated
//! records even though both have the exact `(route_key, endpoint_key)` scope.

use core::num::NonZeroU64;

use hns_wallet_store::{EntityBatchSave, EntityKind, StoreError, StoredEntity, WalletStore};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PUBLISHER_SEQUENCE_STORAGE_VERSION: u16 = 1;
const MAX_RESERVATION_ATTEMPTS: usize = 2;

const ENDPOINT_ANCHOR_ID_DOMAIN: &[u8] =
    b"hns-wallet/hnsa-hnsr-publisher/endpoint-delegation/namespace-anchor/v1";
const ENDPOINT_HIGH_WATER_ID_DOMAIN: &[u8] =
    b"hns-wallet/hnsa-hnsr-publisher/endpoint-delegation/high-water/v1";
const ROUTE_ANCHOR_ID_DOMAIN: &[u8] =
    b"hns-wallet/hnsa-hnsr-publisher/named-route/namespace-anchor/v1";
const ROUTE_HIGH_WATER_ID_DOMAIN: &[u8] =
    b"hns-wallet/hnsa-hnsr-publisher/named-route/high-water/v1";

mod compressed_endpoint_key_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| {
                <D::Error as serde::de::Error>::custom(
                    "compressed HNSA endpoint key must contain exactly 33 bytes",
                )
            })
    }
}

/// Exact publisher-counter scope derived by the future trusted signer from a
/// current named-service guard and its protected endpoint signer.
///
/// This type deliberately remains crate-private: a browser page, extension
/// content script, or external caller must never manufacture counter scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HnsaHnsrPublisherScope {
    route_key: [u8; 32],
    #[serde(with = "compressed_endpoint_key_serde")]
    endpoint_key: [u8; 33],
}

impl HnsaHnsrPublisherScope {
    pub(crate) fn new(
        route_key: [u8; 32],
        endpoint_key: [u8; 33],
    ) -> Result<Self, HnsaHnsrPublisherSequenceError> {
        let scope = Self {
            route_key,
            endpoint_key,
        };
        if !scope.is_canonical() {
            return Err(HnsaHnsrPublisherSequenceError::InvalidScope);
        }
        Ok(scope)
    }

    fn is_canonical(self) -> bool {
        VerifyingKey::from_sec1_bytes(&self.endpoint_key).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublisherSequenceDimension {
    EndpointDelegation,
    NamedRoute,
}

impl PublisherSequenceDimension {
    const fn anchor_id_domain(self) -> &'static [u8] {
        match self {
            Self::EndpointDelegation => ENDPOINT_ANCHOR_ID_DOMAIN,
            Self::NamedRoute => ROUTE_ANCHOR_ID_DOMAIN,
        }
    }

    const fn high_water_id_domain(self) -> &'static [u8] {
        match self {
            Self::EndpointDelegation => ENDPOINT_HIGH_WATER_ID_DOMAIN,
            Self::NamedRoute => ROUTE_HIGH_WATER_ID_DOMAIN,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherSequenceNamespaceAnchor {
    storage_version: u16,
    dimension: PublisherSequenceDimension,
    scope: HnsaHnsrPublisherScope,
    initialized_at_unix: u64,
}

impl PublisherSequenceNamespaceAnchor {
    fn validate(
        &self,
        expected_dimension: PublisherSequenceDimension,
        expected_scope: HnsaHnsrPublisherScope,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.storage_version != PUBLISHER_SEQUENCE_STORAGE_VERSION
            || self.dimension != expected_dimension
            || self.scope != expected_scope
            || !self.scope.is_canonical()
            || revision != 1
            || self.initialized_at_unix == 0
            || updated_at_unix != self.initialized_at_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherSequenceHighWater {
    storage_version: u16,
    dimension: PublisherSequenceDimension,
    scope: HnsaHnsrPublisherScope,
    highest_reserved_sequence: u64,
    last_reserved_at_unix: u64,
}

impl PublisherSequenceHighWater {
    fn validate(
        &self,
        expected_dimension: PublisherSequenceDimension,
        expected_scope: HnsaHnsrPublisherScope,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.storage_version != PUBLISHER_SEQUENCE_STORAGE_VERSION
            || self.dimension != expected_dimension
            || self.scope != expected_scope
            || !self.scope.is_canonical()
            || revision == 0
            || self.highest_reserved_sequence == 0
            || self.last_reserved_at_unix == 0
            || updated_at_unix != self.last_reserved_at_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum PublisherSequenceRecord {
    NamespaceAnchor(PublisherSequenceNamespaceAnchor),
    HighWater(PublisherSequenceHighWater),
}

struct LoadedHighWater {
    revision: u64,
    value: PublisherSequenceHighWater,
}

/// A committed endpoint-delegation sequence. It is intentionally neither
/// cloneable, copyable, serializable, nor constructible outside this module.
#[must_use = "dropping a committed reservation burns its sequence"]
pub(crate) struct CommittedEndpointDelegationSequence {
    scope: HnsaHnsrPublisherScope,
    sequence: NonZeroU64,
}

impl CommittedEndpointDelegationSequence {
    pub(crate) fn into_scope_and_sequence(self) -> (HnsaHnsrPublisherScope, NonZeroU64) {
        (self.scope, self.sequence)
    }
}

/// A committed named-route sequence. It is intentionally neither cloneable,
/// copyable, serializable, nor constructible outside this module.
#[must_use = "dropping a committed reservation burns its sequence"]
pub(crate) struct CommittedNamedRouteSequence {
    scope: HnsaHnsrPublisherScope,
    sequence: NonZeroU64,
}

impl CommittedNamedRouteSequence {
    pub(crate) fn into_scope_and_sequence(self) -> (HnsaHnsrPublisherScope, NonZeroU64) {
        (self.scope, self.sequence)
    }
}

/// Fail-closed errors from durable HNSA/HNSR publisher sequence reservation.
#[derive(Debug, Error)]
pub(crate) enum HnsaHnsrPublisherSequenceError {
    #[error("the HNSA/HNSR publisher counter scope is invalid")]
    InvalidScope,
    #[error("the HNSA/HNSR publisher reservation time must be nonzero")]
    InvalidTime,
    #[error("encrypted HNSA/HNSR publisher sequence state is corrupt or incomplete")]
    CorruptState,
    #[error("the HNSA/HNSR publisher reservation clock moved behind durable state")]
    ClockRollback,
    #[error("the HNSA/HNSR publisher sequence is exhausted")]
    SequenceExhausted,
    #[error("the HNSA/HNSR publisher sequence changed concurrently")]
    ConcurrentModification,
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub(crate) fn reserve_endpoint_delegation_sequence(
    store: &mut WalletStore,
    scope: HnsaHnsrPublisherScope,
    now_unix: u64,
) -> Result<CommittedEndpointDelegationSequence, HnsaHnsrPublisherSequenceError> {
    let sequence = reserve_sequence(
        store,
        scope,
        PublisherSequenceDimension::EndpointDelegation,
        now_unix,
    )?;
    Ok(CommittedEndpointDelegationSequence { scope, sequence })
}

pub(crate) fn reserve_named_route_sequence(
    store: &mut WalletStore,
    scope: HnsaHnsrPublisherScope,
    now_unix: u64,
) -> Result<CommittedNamedRouteSequence, HnsaHnsrPublisherSequenceError> {
    let sequence = reserve_sequence(
        store,
        scope,
        PublisherSequenceDimension::NamedRoute,
        now_unix,
    )?;
    Ok(CommittedNamedRouteSequence { scope, sequence })
}

fn reserve_sequence(
    store: &mut WalletStore,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
) -> Result<NonZeroU64, HnsaHnsrPublisherSequenceError> {
    reserve_sequence_with_before_apply(store, scope, dimension, now_unix, |_, _| {})
}

fn reserve_sequence_with_before_apply(
    store: &mut WalletStore,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
    mut before_apply: impl FnMut(&mut WalletStore, usize),
) -> Result<NonZeroU64, HnsaHnsrPublisherSequenceError> {
    if !scope.is_canonical() {
        return Err(HnsaHnsrPublisherSequenceError::InvalidScope);
    }
    if now_unix == 0 {
        return Err(HnsaHnsrPublisherSequenceError::InvalidTime);
    }

    for attempt in 0..MAX_RESERVATION_ATTEMPTS {
        let current = load_high_water(store, scope, dimension)?;
        let (expected_revision, next_sequence, initialized_at_unix) = match current.as_ref() {
            Some(stored) => {
                if now_unix < stored.value.last_reserved_at_unix {
                    return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
                }
                let next = stored
                    .value
                    .highest_reserved_sequence
                    .checked_add(1)
                    .ok_or(HnsaHnsrPublisherSequenceError::SequenceExhausted)?;
                (stored.revision, next, None)
            }
            None => (0, 1, Some(now_unix)),
        };
        let sequence =
            NonZeroU64::new(next_sequence).ok_or(HnsaHnsrPublisherSequenceError::CorruptState)?;
        let mut saves = Vec::with_capacity(if initialized_at_unix.is_some() { 2 } else { 1 });
        if let Some(initialized_at_unix) = initialized_at_unix {
            saves.push(EntityBatchSave {
                id: anchor_record_id(scope, dimension).to_vec(),
                expected_revision: 0,
                value: PublisherSequenceRecord::NamespaceAnchor(PublisherSequenceNamespaceAnchor {
                    storage_version: PUBLISHER_SEQUENCE_STORAGE_VERSION,
                    dimension,
                    scope,
                    initialized_at_unix,
                }),
                updated_at_unix: initialized_at_unix,
            });
        }
        saves.push(EntityBatchSave {
            id: high_water_record_id(scope, dimension).to_vec(),
            expected_revision,
            value: PublisherSequenceRecord::HighWater(PublisherSequenceHighWater {
                storage_version: PUBLISHER_SEQUENCE_STORAGE_VERSION,
                dimension,
                scope,
                highest_reserved_sequence: sequence.get(),
                last_reserved_at_unix: now_unix,
            }),
            updated_at_unix: now_unix,
        });

        before_apply(store, attempt);
        match store.apply_entity_batch(EntityKind::HnsaHnsrPublisherSequence, &saves, &[]) {
            Ok(()) => return Ok(sequence),
            Err(StoreError::StaleRevision { .. }) if attempt + 1 < MAX_RESERVATION_ATTEMPTS => {}
            Err(StoreError::StaleRevision { .. }) => {
                return Err(HnsaHnsrPublisherSequenceError::ConcurrentModification);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(HnsaHnsrPublisherSequenceError::ConcurrentModification)
}

fn load_high_water(
    store: &WalletStore,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
) -> Result<Option<LoadedHighWater>, HnsaHnsrPublisherSequenceError> {
    let anchor_id = anchor_record_id(scope, dimension);
    let high_water_id = high_water_record_id(scope, dimension);

    // A concurrent first reservation commits both rows atomically, but the two
    // reads here are separate snapshots. Retry one apparent partial topology
    // before classifying a persistent partial state as corruption.
    for topology_attempt in 0..MAX_RESERVATION_ATTEMPTS {
        let anchor = load_record(store, &anchor_id)?;
        let high_water = load_record(store, &high_water_id)?;
        match (anchor, high_water) {
            (None, None) => return Ok(None),
            (Some(stored_anchor), Some(stored_high_water)) => {
                if stored_anchor.kind != EntityKind::HnsaHnsrPublisherSequence
                    || stored_anchor.id.as_slice() != anchor_id.as_slice()
                    || stored_high_water.kind != EntityKind::HnsaHnsrPublisherSequence
                    || stored_high_water.id.as_slice() != high_water_id.as_slice()
                {
                    return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                }
                let PublisherSequenceRecord::NamespaceAnchor(anchor) = stored_anchor.value else {
                    return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                };
                anchor.validate(
                    dimension,
                    scope,
                    stored_anchor.revision,
                    stored_anchor.updated_at_unix,
                )?;
                let PublisherSequenceRecord::HighWater(high_water) = stored_high_water.value else {
                    return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                };
                high_water.validate(
                    dimension,
                    scope,
                    stored_high_water.revision,
                    stored_high_water.updated_at_unix,
                )?;
                if high_water.last_reserved_at_unix < anchor.initialized_at_unix {
                    return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                }
                return Ok(Some(LoadedHighWater {
                    revision: stored_high_water.revision,
                    value: high_water,
                }));
            }
            _ if topology_attempt + 1 < MAX_RESERVATION_ATTEMPTS => {}
            _ => return Err(HnsaHnsrPublisherSequenceError::CorruptState),
        }
    }
    Err(HnsaHnsrPublisherSequenceError::CorruptState)
}

fn load_record(
    store: &WalletStore,
    id: &[u8; 32],
) -> Result<Option<StoredEntity<PublisherSequenceRecord>>, HnsaHnsrPublisherSequenceError> {
    store
        .load_entity(EntityKind::HnsaHnsrPublisherSequence, id)
        .map_err(map_load_error)
}

fn map_load_error(error: StoreError) -> HnsaHnsrPublisherSequenceError {
    match error {
        StoreError::Json(_)
        | StoreError::Encryption
        | StoreError::KindMismatch
        | StoreError::CorruptMetadata => HnsaHnsrPublisherSequenceError::CorruptState,
        error => HnsaHnsrPublisherSequenceError::Store(error),
    }
}

fn anchor_record_id(
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
) -> [u8; 32] {
    scoped_record_id(dimension.anchor_id_domain(), scope)
}

fn high_water_record_id(
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
) -> [u8; 32] {
    scoped_record_id(dimension.high_water_id_domain(), scope)
}

fn scoped_record_id(domain: &[u8], scope: HnsaHnsrPublisherScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(scope.route_key);
    hasher.update(scope.endpoint_key);
    hasher.finalize().into()
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use hns_wallet_store::EntityBatchDelete;
    use k256::ecdsa::SigningKey;

    use super::*;

    const PASSPHRASE: &str = "targeted HNSA HNSR publisher counter test";
    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "hns-wallet-hnsa-hnsr-publisher-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create private test directory");
            fs::set_permissions(&path, Permissions::from_mode(0o700))
                .expect("private test directory permissions");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn endpoint_key(secret_byte: u8) -> [u8; 33] {
        let signing = SigningKey::from_slice(&[secret_byte; 32]).expect("valid test scalar");
        signing
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed endpoint key")
    }

    fn scope(route_byte: u8, endpoint_secret_byte: u8) -> HnsaHnsrPublisherScope {
        HnsaHnsrPublisherScope::new([route_byte; 32], endpoint_key(endpoint_secret_byte))
            .expect("valid publisher scope")
    }

    fn endpoint_sequence(reservation: CommittedEndpointDelegationSequence) -> u64 {
        reservation.into_scope_and_sequence().1.get()
    }

    fn route_sequence(reservation: CommittedNamedRouteSequence) -> u64 {
        reservation.into_scope_and_sequence().1.get()
    }

    fn memory_store() -> WalletStore {
        WalletStore::create(":memory:", PASSPHRASE).expect("create in-memory store")
    }

    fn anchor(
        dimension: PublisherSequenceDimension,
        scope: HnsaHnsrPublisherScope,
        initialized_at_unix: u64,
    ) -> PublisherSequenceRecord {
        PublisherSequenceRecord::NamespaceAnchor(PublisherSequenceNamespaceAnchor {
            storage_version: PUBLISHER_SEQUENCE_STORAGE_VERSION,
            dimension,
            scope,
            initialized_at_unix,
        })
    }

    fn high_water(
        dimension: PublisherSequenceDimension,
        scope: HnsaHnsrPublisherScope,
        sequence: u64,
        last_reserved_at_unix: u64,
    ) -> PublisherSequenceRecord {
        PublisherSequenceRecord::HighWater(PublisherSequenceHighWater {
            storage_version: PUBLISHER_SEQUENCE_STORAGE_VERSION,
            dimension,
            scope,
            highest_reserved_sequence: sequence,
            last_reserved_at_unix,
        })
    }

    #[test]
    fn counters_are_nonzero_independent_and_exactly_scope_isolated() {
        let mut store = memory_store();
        let first_scope = scope(0, 1);
        let other_endpoint = scope(0, 2);
        let other_route = scope(3, 1);

        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, first_scope, 10)
                    .expect("first endpoint reservation"),
            ),
            1
        );
        // Abandoning the first committed token cannot make its sequence reusable.
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, first_scope, 10)
                    .expect("second endpoint reservation at equal time"),
            ),
            2
        );
        assert_eq!(
            route_sequence(
                reserve_named_route_sequence(&mut store, first_scope, 10)
                    .expect("independent route reservation"),
            ),
            1
        );
        assert_eq!(
            route_sequence(
                reserve_named_route_sequence(&mut store, first_scope, 11).expect("route refresh"),
            ),
            2
        );
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, first_scope, 11)
                    .expect("endpoint dimension remains independent"),
            ),
            3
        );
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, other_endpoint, 11)
                    .expect("concurrent endpoint has distinct scope"),
            ),
            1
        );
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, other_route, 11)
                    .expect("different route has distinct scope"),
            ),
            1
        );
        assert_ne!(
            high_water_record_id(first_scope, PublisherSequenceDimension::EndpointDelegation),
            high_water_record_id(first_scope, PublisherSequenceDimension::NamedRoute)
        );
    }

    #[test]
    fn committed_gap_survives_store_restart() {
        let directory = TestDirectory::new();
        let database_path = directory.path().join("wallet.sqlite3");
        let publisher_scope = scope(4, 5);

        {
            let mut store =
                WalletStore::create(&database_path, PASSPHRASE).expect("create wallet store");
            let abandoned = reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 100)
                .expect("commit reservation before simulated crash");
            assert_eq!(endpoint_sequence(abandoned), 1);
        }

        let mut reopened = WalletStore::open(&database_path).expect("reopen wallet store");
        reopened.unlock(PASSPHRASE).expect("unlock reopened store");
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut reopened, publisher_scope, 101)
                    .expect("reserve after restart"),
            ),
            2
        );
    }

    #[test]
    fn invalid_scope_lock_and_clock_rollback_fail_without_advancing() {
        let mut store = memory_store();
        assert!(matches!(
            HnsaHnsrPublisherScope::new([9; 32], [0; 33]),
            Err(HnsaHnsrPublisherSequenceError::InvalidScope)
        ));
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, scope(9, 9), 0),
            Err(HnsaHnsrPublisherSequenceError::InvalidTime)
        ));
        assert!(
            store
                .list_entities::<PublisherSequenceRecord>(EntityKind::HnsaHnsrPublisherSequence, 8,)
                .expect("list publisher records")
                .is_empty()
        );

        let publisher_scope = scope(9, 9);
        store.lock();
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 100),
            Err(HnsaHnsrPublisherSequenceError::Store(StoreError::Locked))
        ));
        store.unlock(PASSPHRASE).expect("unlock store");
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 100)
                    .expect("first reservation"),
            ),
            1
        );
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 99),
            Err(HnsaHnsrPublisherSequenceError::ClockRollback)
        ));
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 100)
                    .expect("rollback failure made no write"),
            ),
            2
        );
    }

    #[test]
    fn partial_and_corrupt_topologies_fail_closed() {
        let mut store = memory_store();
        let anchor_only_scope = scope(10, 10);
        store
            .save_entity(
                EntityKind::HnsaHnsrPublisherSequence,
                &anchor_record_id(
                    anchor_only_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                ),
                0,
                &anchor(
                    PublisherSequenceDimension::EndpointDelegation,
                    anchor_only_scope,
                    10,
                ),
                10,
            )
            .expect("persist isolated anchor");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, anchor_only_scope, 11),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let high_water_only_scope = scope(11, 11);
        store
            .save_entity(
                EntityKind::HnsaHnsrPublisherSequence,
                &high_water_record_id(
                    high_water_only_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                ),
                0,
                &high_water(
                    PublisherSequenceDimension::EndpointDelegation,
                    high_water_only_scope,
                    1,
                    10,
                ),
                10,
            )
            .expect("persist isolated high water");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, high_water_only_scope, 11),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let wrong_variant_scope = scope(12, 12);
        let wrong_variant_saves = [
            EntityBatchSave {
                id: anchor_record_id(
                    wrong_variant_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                )
                .to_vec(),
                expected_revision: 0,
                value: anchor(
                    PublisherSequenceDimension::EndpointDelegation,
                    wrong_variant_scope,
                    10,
                ),
                updated_at_unix: 10,
            },
            EntityBatchSave {
                id: high_water_record_id(
                    wrong_variant_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                )
                .to_vec(),
                expected_revision: 0,
                value: anchor(
                    PublisherSequenceDimension::EndpointDelegation,
                    wrong_variant_scope,
                    10,
                ),
                updated_at_unix: 10,
            },
        ];
        store
            .apply_entity_batch(
                EntityKind::HnsaHnsrPublisherSequence,
                &wrong_variant_saves,
                &[],
            )
            .expect("persist wrong record variant");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, wrong_variant_scope, 11),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let timestamp_scope = scope(13, 13);
        let timestamp_saves = [
            EntityBatchSave {
                id: anchor_record_id(
                    timestamp_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                )
                .to_vec(),
                expected_revision: 0,
                value: anchor(
                    PublisherSequenceDimension::EndpointDelegation,
                    timestamp_scope,
                    10,
                ),
                updated_at_unix: 10,
            },
            EntityBatchSave {
                id: high_water_record_id(
                    timestamp_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                )
                .to_vec(),
                expected_revision: 0,
                value: high_water(
                    PublisherSequenceDimension::EndpointDelegation,
                    timestamp_scope,
                    1,
                    10,
                ),
                updated_at_unix: 11,
            },
        ];
        store
            .apply_entity_batch(EntityKind::HnsaHnsrPublisherSequence, &timestamp_saves, &[])
            .expect("persist authenticated timestamp mismatch");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, timestamp_scope, 12),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let wrong_scope = scope(14, 14);
        let substituted_scope = scope(15, 15);
        let wrong_scope_saves = [
            EntityBatchSave {
                id: anchor_record_id(wrong_scope, PublisherSequenceDimension::EndpointDelegation)
                    .to_vec(),
                expected_revision: 0,
                value: anchor(
                    PublisherSequenceDimension::EndpointDelegation,
                    wrong_scope,
                    10,
                ),
                updated_at_unix: 10,
            },
            EntityBatchSave {
                id: high_water_record_id(
                    wrong_scope,
                    PublisherSequenceDimension::EndpointDelegation,
                )
                .to_vec(),
                expected_revision: 0,
                value: high_water(
                    PublisherSequenceDimension::EndpointDelegation,
                    substituted_scope,
                    1,
                    10,
                ),
                updated_at_unix: 10,
            },
        ];
        store
            .apply_entity_batch(
                EntityKind::HnsaHnsrPublisherSequence,
                &wrong_scope_saves,
                &[],
            )
            .expect("persist substituted scope");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, wrong_scope, 11),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));
    }

    #[test]
    fn full_u64_high_water_is_decoupled_from_revision_and_exhausts_one_dimension() {
        const ABOVE_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_992;

        let mut store = memory_store();
        let publisher_scope = scope(16, 16);
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 10)
                    .expect("initialize endpoint high water"),
            ),
            1
        );
        let id = high_water_record_id(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        let stored = load_record(&store, &id)
            .expect("load high water")
            .expect("high water present");
        store
            .save_entity(
                EntityKind::HnsaHnsrPublisherSequence,
                &id,
                stored.revision,
                &high_water(
                    PublisherSequenceDimension::EndpointDelegation,
                    publisher_scope,
                    ABOVE_JAVASCRIPT_SAFE_INTEGER,
                    11,
                ),
                11,
            )
            .expect("persist exact full-width sequence");
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 12)
                    .expect("increment exact full-width sequence"),
            ),
            ABOVE_JAVASCRIPT_SAFE_INTEGER + 1
        );
        let stored = load_record(&store, &id)
            .expect("reload high water")
            .expect("high water present");
        assert_ne!(
            stored.revision,
            ABOVE_JAVASCRIPT_SAFE_INTEGER + 1,
            "SQLite CAS revision is not the protocol sequence"
        );
        store
            .save_entity(
                EntityKind::HnsaHnsrPublisherSequence,
                &id,
                stored.revision,
                &high_water(
                    PublisherSequenceDimension::EndpointDelegation,
                    publisher_scope,
                    u64::MAX,
                    13,
                ),
                13,
            )
            .expect("persist terminal sequence exactly");
        assert!(matches!(
            reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 14),
            Err(HnsaHnsrPublisherSequenceError::SequenceExhausted)
        ));
        let terminal = load_record(&store, &id)
            .expect("load terminal high water")
            .expect("terminal high water present");
        let PublisherSequenceRecord::HighWater(terminal_value) = terminal.value else {
            panic!("terminal record must remain a high water");
        };
        assert_eq!(terminal_value.highest_reserved_sequence, u64::MAX);
        assert_eq!(terminal_value.last_reserved_at_unix, 13);
        assert_eq!(
            route_sequence(
                reserve_named_route_sequence(&mut store, publisher_scope, 14)
                    .expect("route dimension remains available"),
            ),
            1
        );
    }

    #[test]
    fn stale_compare_and_swap_retries_once_then_fails_explicitly() {
        let mut store = memory_store();
        let retry_scope = scope(17, 17);
        let mut injected = false;
        let reserved = reserve_sequence_with_before_apply(
            &mut store,
            retry_scope,
            PublisherSequenceDimension::EndpointDelegation,
            10,
            |store, _| {
                if !injected {
                    injected = true;
                    assert_eq!(
                        endpoint_sequence(
                            reserve_endpoint_delegation_sequence(store, retry_scope, 10)
                                .expect("concurrent first reservation"),
                        ),
                        1
                    );
                }
            },
        )
        .expect("retry reserves the next sequence");
        assert_eq!(reserved.get(), 2);

        let bounded_scope = scope(18, 18);
        let result = reserve_sequence_with_before_apply(
            &mut store,
            bounded_scope,
            PublisherSequenceDimension::EndpointDelegation,
            20,
            |store, attempt| {
                assert_eq!(
                    endpoint_sequence(
                        reserve_endpoint_delegation_sequence(store, bounded_scope, 20)
                            .expect("concurrent reservation"),
                    ),
                    u64::try_from(attempt).expect("attempt fits u64") + 1
                );
            },
        );
        assert!(matches!(
            result,
            Err(HnsaHnsrPublisherSequenceError::ConcurrentModification)
        ));
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, bounded_scope, 20)
                    .expect("later caller advances beyond both committed gaps"),
            ),
            3
        );
    }

    #[test]
    fn publisher_counter_topology_is_deletion_protected() {
        let mut store = memory_store();
        let publisher_scope = scope(19, 19);
        let reservation = reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 10)
            .expect("initialize protected topology");
        assert_eq!(endpoint_sequence(reservation), 1);
        let high_water_id = high_water_record_id(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        assert!(matches!(
            store.delete_entity(EntityKind::HnsaHnsrPublisherSequence, &high_water_id, 1,),
            Err(StoreError::ProtectedEntity)
        ));
        let deletes = [EntityBatchDelete {
            id: high_water_id.to_vec(),
            expected_revision: 1,
        }];
        assert!(matches!(
            store.apply_entity_batch::<PublisherSequenceRecord>(
                EntityKind::HnsaHnsrPublisherSequence,
                &[],
                &deletes,
            ),
            Err(StoreError::ProtectedEntity)
        ));
        assert_eq!(
            endpoint_sequence(
                reserve_endpoint_delegation_sequence(&mut store, publisher_scope, 11)
                    .expect("protected high water remains available"),
            ),
            2
        );
    }
}
