//! Externally fenced sequence reservations for future HNSA/HNSR publication.
//!
//! The authenticated external authority is the sole production allocator and
//! commits a sequence under an exclusive live fence before its opaque token is
//! consumed. Encrypted SQLite v2 state is only an audit and migration mirror,
//! never an allocation authority. The token is consumed only while the lease
//! remains current; dropping it, a signing failure, lease loss, or a process
//! crash burns a safe gap. Endpoint-delegation and named-route dimensions use
//! separate authenticated namespaces for the same `(route_key, endpoint_key)`
//! scope. The legacy local allocator exists only in tests to build v1 migration
//! fixtures and is absent from production builds.

use core::num::NonZeroU64;

use hns_wallet_store::{EntityBatchSave, EntityKind, StoreError, StoredEntity, WalletStore};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PUBLISHER_SEQUENCE_STORAGE_VERSION: u16 = 1;
const EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION: u16 = 2;
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
/// This type deliberately remains module-private: a browser page, extension
/// content script, or external caller must never manufacture counter scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnsaHnsrPublisherScope {
    route_key: [u8; 32],
    #[serde(with = "compressed_endpoint_key_serde")]
    endpoint_key: [u8; 33],
}

impl HnsaHnsrPublisherScope {
    fn new(
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

/// Pinned identity of the independently authenticated counter authority.
///
/// The namespace is stable across wallet-database copies. The authority
/// fingerprint and enrollment generation come from the future trusted HRM
/// guard; neither may be inferred from local counter state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherSequenceExternalAuthority {
    namespace_id: [u8; 32],
    authority_fingerprint: [u8; 32],
    enrollment_generation: NonZeroU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedPublisherSequenceEnrollment {
    authority: PublisherSequenceExternalAuthority,
    dimension: PublisherSequenceDimension,
    scope: HnsaHnsrPublisherScope,
}

impl AuthenticatedPublisherSequenceEnrollment {
    fn validate(
        self,
        expected_authority: PublisherSequenceExternalAuthority,
        expected_dimension: PublisherSequenceDimension,
        expected_scope: HnsaHnsrPublisherScope,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if !self.scope.is_canonical()
            || self.authority != expected_authority
            || self.dimension != expected_dimension
            || self.scope != expected_scope
        {
            return Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityMismatch);
        }
        Ok(())
    }
}

/// Short-lived external fencing lease. Expiry is exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublisherSequenceExternalLease {
    enrollment: AuthenticatedPublisherSequenceEnrollment,
    lease_id: [u8; 32],
    fence_token: NonZeroU64,
    valid_from_unix: u64,
    expires_at_unix: u64,
}

impl PublisherSequenceExternalLease {
    fn validate(
        self,
        expected_enrollment: AuthenticatedPublisherSequenceEnrollment,
        now_unix: u64,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.enrollment != expected_enrollment {
            return Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityMismatch);
        }
        if now_unix == 0
            || self.valid_from_unix == 0
            || self.valid_from_unix > now_unix
            || self.expires_at_unix <= now_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid);
        }
        Ok(())
    }
}

/// Linearizable, authenticated external snapshot observed under one lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedPublisherSequenceState {
    enrollment: AuthenticatedPublisherSequenceEnrollment,
    revision: u64,
    highest_reserved_sequence: u64,
    last_reservation_id: Option<[u8; 32]>,
    last_reserved_at_unix: u64,
    /// Opaque complete-state identity authenticated by the trusted external
    /// authority. It is not an unkeyed locally computed digest.
    authenticated_state_id: [u8; 32],
}

impl AuthenticatedPublisherSequenceState {
    fn validate(
        self,
        expected_enrollment: AuthenticatedPublisherSequenceEnrollment,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.enrollment != expected_enrollment
            || self.revision != self.highest_reserved_sequence
            || self.last_reservation_id.is_some() != (self.highest_reserved_sequence != 0)
            || (self.last_reserved_at_unix != 0) != (self.highest_reserved_sequence != 0)
            || self.last_reservation_id == Some([0; 32])
        {
            return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
        }
        Ok(())
    }
}

/// Exact idempotent CAS proposal. Retrying an ambiguous operation must reuse
/// this value byte-for-byte under the same live fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublisherSequenceExternalProposal {
    lease: PublisherSequenceExternalLease,
    expected_state: AuthenticatedPublisherSequenceState,
    proposed_sequence: NonZeroU64,
    reservation_id: [u8; 32],
    reserved_at_unix: u64,
}

impl PublisherSequenceExternalProposal {
    fn validate(self, now_unix: u64) -> Result<(), HnsaHnsrPublisherSequenceError> {
        self.lease
            .validate(self.expected_state.enrollment, now_unix)?;
        self.expected_state
            .validate(self.expected_state.enrollment)?;
        let expected_next = self
            .expected_state
            .highest_reserved_sequence
            .checked_add(1)
            .ok_or(HnsaHnsrPublisherSequenceError::SequenceExhausted)?;
        if self.proposed_sequence.get() != expected_next
            || self.reservation_id == [0; 32]
            || self.expected_state.last_reservation_id == Some(self.reservation_id)
            || self.reserved_at_unix != now_unix
            || self.reserved_at_unix < self.expected_state.last_reserved_at_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::ExternalProposalInvalid);
        }
        Ok(())
    }

    fn matches_applied_state(
        self,
        state: AuthenticatedPublisherSequenceState,
        _now_unix: u64,
    ) -> Result<bool, HnsaHnsrPublisherSequenceError> {
        state.validate(self.expected_state.enrollment)?;
        Ok(state.enrollment == self.expected_state.enrollment
            && state.revision == self.proposed_sequence.get()
            && state.highest_reserved_sequence == self.proposed_sequence.get()
            && state.last_reservation_id == Some(self.reservation_id)
            && state.last_reserved_at_unix == self.reserved_at_unix
            && state.authenticated_state_id != self.expected_state.authenticated_state_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublisherSequenceExternalCasResult {
    Applied(AuthenticatedPublisherSequenceState),
    Rejected(AuthenticatedPublisherSequenceState),
    Ambiguous,
}

/// Trusted, linearizable external counter boundary.
///
/// Implementations live inside this private module and must authenticate every
/// returned enrollment, lease, state, and CAS receipt against the pinned HRM
/// authority before constructing these private types. Reads and CAS operations
/// must be linearizable under the supplied lease; `authenticated_state_id`
/// must identify the complete durable state and remain stable across lease
/// renewal until that state changes. `compare_and_swap` must atomically reject
/// a stale lease/fence and require exact equality of enrollment/namespace,
/// revision, complete state value, and opaque authenticated state ID. A prior
/// `revalidate_lease` is never a substitute for those CAS predicates. Lease
/// revalidation must consult the authority's live trusted time and current
/// lease/fence ownership; merely re-running structural validation against the
/// caller-supplied operation timestamp is insufficient because that timestamp
/// does not prove currentness or non-expiry.
trait PublisherSequenceExternalBackend {
    fn load_authenticated_enrollment(
        &mut self,
        expected_authority: PublisherSequenceExternalAuthority,
        dimension: PublisherSequenceDimension,
        scope: HnsaHnsrPublisherScope,
    ) -> Result<Option<AuthenticatedPublisherSequenceEnrollment>, HnsaHnsrPublisherSequenceError>;

    fn acquire_lease(
        &mut self,
        enrollment: AuthenticatedPublisherSequenceEnrollment,
        now_unix: u64,
    ) -> Result<Option<PublisherSequenceExternalLease>, HnsaHnsrPublisherSequenceError>;

    fn load_authenticated_state(
        &mut self,
        lease: PublisherSequenceExternalLease,
    ) -> Result<AuthenticatedPublisherSequenceState, HnsaHnsrPublisherSequenceError>;

    fn compare_and_swap(
        &mut self,
        proposal: PublisherSequenceExternalProposal,
    ) -> Result<PublisherSequenceExternalCasResult, HnsaHnsrPublisherSequenceError>;

    fn revalidate_lease(
        &mut self,
        lease: PublisherSequenceExternalLease,
        now_unix: u64,
    ) -> Result<bool, HnsaHnsrPublisherSequenceError>;
}

#[must_use = "an externally committed sequence is burned even if local mirroring fails"]
struct ExternallyCommittedPublisherSequence {
    state: AuthenticatedPublisherSequenceState,
    lease: PublisherSequenceExternalLease,
    sequence: NonZeroU64,
}

struct PreparedExternalPublisherSequence {
    enrollment: AuthenticatedPublisherSequenceEnrollment,
    lease: PublisherSequenceExternalLease,
    state: AuthenticatedPublisherSequenceState,
}

#[derive(Clone, Copy)]
struct PublisherSequenceReservationRequest {
    expected_authority: PublisherSequenceExternalAuthority,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
}

fn externally_commit_sequence(
    backend: &mut impl PublisherSequenceExternalBackend,
    expected_authority: PublisherSequenceExternalAuthority,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
) -> Result<ExternallyCommittedPublisherSequence, HnsaHnsrPublisherSequenceError> {
    let prepared = acquire_and_read_external_sequence(
        backend,
        expected_authority,
        scope,
        dimension,
        now_unix,
    )?;
    externally_commit_sequence_from_exact_read(backend, prepared, now_unix)
}

fn acquire_and_read_external_sequence(
    backend: &mut impl PublisherSequenceExternalBackend,
    expected_authority: PublisherSequenceExternalAuthority,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
) -> Result<PreparedExternalPublisherSequence, HnsaHnsrPublisherSequenceError> {
    if !scope.is_canonical() {
        return Err(HnsaHnsrPublisherSequenceError::InvalidScope);
    }
    if now_unix == 0 {
        return Err(HnsaHnsrPublisherSequenceError::InvalidTime);
    }
    let enrollment = backend
        .load_authenticated_enrollment(expected_authority, dimension, scope)?
        .ok_or(HnsaHnsrPublisherSequenceError::ExternalEnrollmentMissing)?;
    enrollment.validate(expected_authority, dimension, scope)?;
    let lease = backend
        .acquire_lease(enrollment, now_unix)?
        .ok_or(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)?;
    lease.validate(enrollment, now_unix)?;
    require_current_lease(backend, lease, now_unix)?;
    let expected_state = backend.load_authenticated_state(lease)?;
    expected_state.validate(enrollment)?;
    if now_unix < expected_state.last_reserved_at_unix {
        return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
    }
    Ok(PreparedExternalPublisherSequence {
        enrollment,
        lease,
        state: expected_state,
    })
}

fn externally_commit_sequence_from_exact_read(
    backend: &mut impl PublisherSequenceExternalBackend,
    prepared: PreparedExternalPublisherSequence,
    now_unix: u64,
) -> Result<ExternallyCommittedPublisherSequence, HnsaHnsrPublisherSequenceError> {
    prepared.enrollment.validate(
        prepared.enrollment.authority,
        prepared.enrollment.dimension,
        prepared.enrollment.scope,
    )?;
    prepared.lease.validate(prepared.enrollment, now_unix)?;
    prepared.state.validate(prepared.enrollment)?;
    if now_unix < prepared.state.last_reserved_at_unix {
        return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
    }
    let expected_state = prepared.state;
    let lease = prepared.lease;
    let enrollment = prepared.enrollment;
    let proposed_sequence = NonZeroU64::new(
        expected_state
            .highest_reserved_sequence
            .checked_add(1)
            .ok_or(HnsaHnsrPublisherSequenceError::SequenceExhausted)?,
    )
    .ok_or(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)?;
    let reservation_id = fresh_reservation_id(expected_state.last_reservation_id)?;
    let proposal = PublisherSequenceExternalProposal {
        lease,
        expected_state,
        proposed_sequence,
        reservation_id,
        reserved_at_unix: now_unix,
    };
    proposal.validate(now_unix)?;

    require_current_lease(backend, lease, now_unix)?;
    let state = match backend.compare_and_swap(proposal)? {
        PublisherSequenceExternalCasResult::Applied(state) => {
            require_exact_applied_state(proposal, state)?
        }
        PublisherSequenceExternalCasResult::Rejected(state) => {
            state.validate(enrollment)?;
            return Err(HnsaHnsrPublisherSequenceError::ConcurrentModification);
        }
        PublisherSequenceExternalCasResult::Ambiguous => {
            reconcile_ambiguous_external_cas(backend, proposal, now_unix)?
        }
    };
    require_current_lease(backend, lease, now_unix)?;
    Ok(ExternallyCommittedPublisherSequence {
        state,
        lease,
        sequence: proposed_sequence,
    })
}

/// Opaque, single-use input for the future module-internal HNSA/HNSR signer.
/// It is never returned from this module and has no raw sequence accessor.
#[must_use = "dropping the internal publisher token burns its committed sequence"]
struct ExternallyFencedPublisherSequenceToken {
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    sequence: NonZeroU64,
    reservation_id: [u8; 32],
}

fn with_externally_fenced_publisher_sequence<T>(
    store: &mut WalletStore,
    backend: &mut impl PublisherSequenceExternalBackend,
    expected_authority: PublisherSequenceExternalAuthority,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
    consume: impl FnOnce(
        &WalletStore,
        ExternallyFencedPublisherSequenceToken,
    ) -> Result<T, HnsaHnsrPublisherSequenceError>,
) -> Result<T, HnsaHnsrPublisherSequenceError> {
    with_externally_fenced_publisher_sequence_core(
        store,
        backend,
        PublisherSequenceReservationRequest {
            expected_authority,
            scope,
            dimension,
            now_unix,
        },
        |_| Ok(()),
        consume,
    )
}

fn with_externally_fenced_publisher_sequence_core<T>(
    store: &mut WalletStore,
    backend: &mut impl PublisherSequenceExternalBackend,
    request: PublisherSequenceReservationRequest,
    after_external_commit: impl FnOnce(&mut WalletStore) -> Result<(), HnsaHnsrPublisherSequenceError>,
    consume: impl FnOnce(
        &WalletStore,
        ExternallyFencedPublisherSequenceToken,
    ) -> Result<T, HnsaHnsrPublisherSequenceError>,
) -> Result<T, HnsaHnsrPublisherSequenceError> {
    let PublisherSequenceReservationRequest {
        expected_authority,
        scope,
        dimension,
        now_unix,
    } = request;
    let prepared = acquire_and_read_external_sequence(
        backend,
        expected_authority,
        scope,
        dimension,
        now_unix,
    )?;
    let mut local = reconcile_local_before_external_cas(store, &prepared, now_unix)?;
    let committed = externally_commit_sequence_from_exact_read(backend, prepared, now_unix)?;
    if committed.state.highest_reserved_sequence != committed.sequence.get() {
        return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
    }
    let reservation_id = committed
        .state
        .last_reservation_id
        .ok_or(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)?;
    after_external_commit(store)?;

    // The only topology with no anchor here is absent local state paired with
    // an enrolled external floor of zero. Its first anchor and the newly
    // committed N=1 mirror are created together after the external CAS.
    if local.anchor.is_none() {
        local.anchor = Some(externally_fenced_anchor_from_enrollment(
            committed.state.enrollment,
            now_unix,
        ));
    }
    let _mirrored = persist_external_state_locally(store, local, committed.state, now_unix)?;
    require_current_lease(backend, committed.lease, now_unix)?;

    let token = ExternallyFencedPublisherSequenceToken {
        scope,
        dimension,
        sequence: committed.sequence,
        reservation_id,
    };
    let result = consume(store, token);
    require_current_lease(backend, committed.lease, now_unix)?;
    result
}

fn reconcile_ambiguous_external_cas(
    backend: &mut impl PublisherSequenceExternalBackend,
    proposal: PublisherSequenceExternalProposal,
    now_unix: u64,
) -> Result<AuthenticatedPublisherSequenceState, HnsaHnsrPublisherSequenceError> {
    require_current_lease(backend, proposal.lease, now_unix)?;
    let observed = backend.load_authenticated_state(proposal.lease)?;
    observed.validate(proposal.expected_state.enrollment)?;
    if proposal.matches_applied_state(observed, now_unix)? {
        return Ok(observed);
    }
    if observed != proposal.expected_state {
        return Err(HnsaHnsrPublisherSequenceError::ExternalOutcomeAmbiguous);
    }

    // The authoritative state is byte-for-byte old, so retry the exact same
    // proposal once. A second ambiguous response is reconciled by one final
    // authoritative read but is never submitted a third time.
    require_current_lease(backend, proposal.lease, now_unix)?;
    match backend.compare_and_swap(proposal)? {
        PublisherSequenceExternalCasResult::Applied(state)
        | PublisherSequenceExternalCasResult::Rejected(state) => {
            if proposal.matches_applied_state(state, now_unix)? {
                Ok(state)
            } else {
                Err(HnsaHnsrPublisherSequenceError::ExternalOutcomeAmbiguous)
            }
        }
        PublisherSequenceExternalCasResult::Ambiguous => {
            require_current_lease(backend, proposal.lease, now_unix)?;
            let final_state = backend.load_authenticated_state(proposal.lease)?;
            if proposal.matches_applied_state(final_state, now_unix)? {
                Ok(final_state)
            } else {
                Err(HnsaHnsrPublisherSequenceError::ExternalOutcomeAmbiguous)
            }
        }
    }
}

fn require_current_lease(
    backend: &mut impl PublisherSequenceExternalBackend,
    lease: PublisherSequenceExternalLease,
    now_unix: u64,
) -> Result<(), HnsaHnsrPublisherSequenceError> {
    lease.validate(lease.enrollment, now_unix)?;
    if backend.revalidate_lease(lease, now_unix)? {
        Ok(())
    } else {
        Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
    }
}

fn require_exact_applied_state(
    proposal: PublisherSequenceExternalProposal,
    state: AuthenticatedPublisherSequenceState,
) -> Result<AuthenticatedPublisherSequenceState, HnsaHnsrPublisherSequenceError> {
    if proposal.matches_applied_state(state, proposal.reserved_at_unix)? {
        Ok(state)
    } else {
        Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)
    }
}

fn fresh_reservation_id(
    previous: Option<[u8; 32]>,
) -> Result<[u8; 32], HnsaHnsrPublisherSequenceError> {
    for _ in 0..MAX_RESERVATION_ATTEMPTS {
        let mut reservation_id = [0_u8; 32];
        getrandom::fill(&mut reservation_id)
            .map_err(|_| HnsaHnsrPublisherSequenceError::Randomness)?;
        if reservation_id != [0; 32] && Some(reservation_id) != previous {
            return Ok(reservation_id);
        }
    }
    Err(HnsaHnsrPublisherSequenceError::Randomness)
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

/// V2 immutable-value local binding to an already-enrolled external authority.
///
/// Its value and authenticated timestamp never change. Its SQLite revision is
/// deliberately advanced in the same atomic batch as every mirror update so
/// the complete two-record topology is compare-and-swap fenced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternallyFencedPublisherSequenceNamespaceAnchor {
    storage_version: u16,
    dimension: PublisherSequenceDimension,
    scope: HnsaHnsrPublisherScope,
    authority: PublisherSequenceExternalAuthority,
    initialized_at_unix: u64,
}

impl ExternallyFencedPublisherSequenceNamespaceAnchor {
    fn validate(
        &self,
        expected_dimension: PublisherSequenceDimension,
        expected_scope: HnsaHnsrPublisherScope,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.storage_version != EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION
            || self.dimension != expected_dimension
            || self.scope != expected_scope
            || !self.scope.is_canonical()
            || revision == 0
            || self.initialized_at_unix == 0
            || updated_at_unix != self.initialized_at_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
        }
        Ok(())
    }
}

/// V2 encrypted audit mirror of the external allocator's complete state.
///
/// `authenticated_state_id` is opaque evidence for exact comparison only. A
/// local mirror is never authority: every reservation must obtain a fresh
/// authenticated external read under a current lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternallyFencedPublisherSequenceMirror {
    storage_version: u16,
    dimension: PublisherSequenceDimension,
    scope: HnsaHnsrPublisherScope,
    authority: PublisherSequenceExternalAuthority,
    external_revision: u64,
    highest_reserved_sequence: u64,
    last_reservation_id: [u8; 32],
    last_reserved_at_unix: u64,
    authenticated_state_id: [u8; 32],
    mirrored_at_unix: u64,
}

impl ExternallyFencedPublisherSequenceMirror {
    fn validate(
        &self,
        expected_dimension: PublisherSequenceDimension,
        expected_scope: HnsaHnsrPublisherScope,
        expected_authority: PublisherSequenceExternalAuthority,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsaHnsrPublisherSequenceError> {
        if self.storage_version != EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION
            || self.dimension != expected_dimension
            || self.scope != expected_scope
            || !self.scope.is_canonical()
            || self.authority != expected_authority
            || revision == 0
            || self.highest_reserved_sequence == 0
            || self.external_revision != self.highest_reserved_sequence
            || self.last_reservation_id == [0; 32]
            || self.last_reserved_at_unix == 0
            || self.mirrored_at_unix < self.last_reserved_at_unix
            || updated_at_unix != self.mirrored_at_unix
        {
            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
        }
        Ok(())
    }
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
    ExternallyFencedNamespaceAnchor(ExternallyFencedPublisherSequenceNamespaceAnchor),
    ExternallyFencedMirror(ExternallyFencedPublisherSequenceMirror),
}

struct LoadedHighWater {
    revision: u64,
    value: PublisherSequenceHighWater,
}

enum LoadedPublisherSequenceLocalState {
    Absent,
    LegacyV1 {
        anchor_revision: u64,
        anchor: PublisherSequenceNamespaceAnchor,
        high_water: LoadedHighWater,
    },
    ExternallyFencedV2 {
        anchor_revision: u64,
        mirror_revision: u64,
        anchor: ExternallyFencedPublisherSequenceNamespaceAnchor,
        mirror: Box<ExternallyFencedPublisherSequenceMirror>,
    },
}

struct ReconciledLocalPublisherSequence {
    anchor: Option<ExternallyFencedPublisherSequenceNamespaceAnchor>,
    anchor_revision: u64,
    mirror_revision: u64,
}

/// Legacy-v1 test helper retained only to construct migration fixtures.
#[cfg(test)]
#[must_use = "dropping a committed reservation burns its sequence"]
struct CommittedEndpointDelegationSequence {
    scope: HnsaHnsrPublisherScope,
    sequence: NonZeroU64,
}

#[cfg(test)]
impl CommittedEndpointDelegationSequence {
    fn into_scope_and_sequence(self) -> (HnsaHnsrPublisherScope, NonZeroU64) {
        (self.scope, self.sequence)
    }
}

/// Legacy-v1 test helper retained only to construct migration fixtures.
#[cfg(test)]
#[must_use = "dropping a committed reservation burns its sequence"]
struct CommittedNamedRouteSequence {
    scope: HnsaHnsrPublisherScope,
    sequence: NonZeroU64,
}

#[cfg(test)]
impl CommittedNamedRouteSequence {
    fn into_scope_and_sequence(self) -> (HnsaHnsrPublisherScope, NonZeroU64) {
        (self.scope, self.sequence)
    }
}

/// Fail-closed errors from durable HNSA/HNSR publisher sequence reservation.
#[derive(Debug, Error)]
enum HnsaHnsrPublisherSequenceError {
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
    #[error("the local HNSA/HNSR publisher audit state is ahead of external authority")]
    LocalStateAhead,
    #[error("the external HNSA/HNSR publisher counter is not enrolled")]
    ExternalEnrollmentMissing,
    #[error("the external HNSA/HNSR publisher authority binding changed")]
    ExternalAuthorityMismatch,
    #[error("the external HNSA/HNSR publisher fencing lease is absent, stale, or invalid")]
    ExternalLeaseInvalid,
    #[error("the external HNSA/HNSR publisher counter state is invalid or forked")]
    ExternalStateInvalid,
    #[error("the external HNSA/HNSR publisher counter proposal is invalid")]
    ExternalProposalInvalid,
    #[error("the external HNSA/HNSR publisher counter outcome is ambiguous")]
    ExternalOutcomeAmbiguous,
    #[error("the external HNSA/HNSR publisher counter is unavailable")]
    ExternalAuthorityUnavailable,
    #[error("secure randomness for the HNSA/HNSR publisher reservation is unavailable")]
    Randomness,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[cfg(test)]
fn reserve_endpoint_delegation_sequence(
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

#[cfg(test)]
fn reserve_named_route_sequence(
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

#[cfg(test)]
fn reserve_sequence(
    store: &mut WalletStore,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
    now_unix: u64,
) -> Result<NonZeroU64, HnsaHnsrPublisherSequenceError> {
    reserve_sequence_with_before_apply(store, scope, dimension, now_unix, |_, _| {})
}

#[cfg(test)]
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

#[cfg(test)]
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

fn load_publisher_sequence_local_state(
    store: &WalletStore,
    scope: HnsaHnsrPublisherScope,
    dimension: PublisherSequenceDimension,
) -> Result<LoadedPublisherSequenceLocalState, HnsaHnsrPublisherSequenceError> {
    let anchor_id = anchor_record_id(scope, dimension);
    let high_water_id = high_water_record_id(scope, dimension);
    for topology_attempt in 0..MAX_RESERVATION_ATTEMPTS {
        let stored_anchor = load_record(store, &anchor_id)?;
        let stored_high_water = load_record(store, &high_water_id)?;
        match (stored_anchor, stored_high_water) {
            (None, None) => return Ok(LoadedPublisherSequenceLocalState::Absent),
            (Some(stored_anchor), Some(stored_high_water)) => {
                if stored_anchor.kind != EntityKind::HnsaHnsrPublisherSequence
                    || stored_anchor.id.as_slice() != anchor_id.as_slice()
                    || stored_high_water.kind != EntityKind::HnsaHnsrPublisherSequence
                    || stored_high_water.id.as_slice() != high_water_id.as_slice()
                {
                    return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                }
                return match (stored_anchor.value, stored_high_water.value) {
                    (
                        PublisherSequenceRecord::NamespaceAnchor(anchor),
                        PublisherSequenceRecord::HighWater(high_water),
                    ) => {
                        anchor.validate(
                            dimension,
                            scope,
                            stored_anchor.revision,
                            stored_anchor.updated_at_unix,
                        )?;
                        high_water.validate(
                            dimension,
                            scope,
                            stored_high_water.revision,
                            stored_high_water.updated_at_unix,
                        )?;
                        if high_water.last_reserved_at_unix < anchor.initialized_at_unix {
                            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                        }
                        Ok(LoadedPublisherSequenceLocalState::LegacyV1 {
                            anchor_revision: stored_anchor.revision,
                            anchor,
                            high_water: LoadedHighWater {
                                revision: stored_high_water.revision,
                                value: high_water,
                            },
                        })
                    }
                    (
                        PublisherSequenceRecord::ExternallyFencedNamespaceAnchor(anchor),
                        PublisherSequenceRecord::ExternallyFencedMirror(mirror),
                    ) => {
                        anchor.validate(
                            dimension,
                            scope,
                            stored_anchor.revision,
                            stored_anchor.updated_at_unix,
                        )?;
                        mirror.validate(
                            dimension,
                            scope,
                            anchor.authority,
                            stored_high_water.revision,
                            stored_high_water.updated_at_unix,
                        )?;
                        if mirror.mirrored_at_unix < anchor.initialized_at_unix {
                            return Err(HnsaHnsrPublisherSequenceError::CorruptState);
                        }
                        Ok(LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
                            anchor_revision: stored_anchor.revision,
                            mirror_revision: stored_high_water.revision,
                            anchor,
                            mirror: Box::new(mirror),
                        })
                    }
                    _ => Err(HnsaHnsrPublisherSequenceError::CorruptState),
                };
            }
            _ if topology_attempt + 1 < MAX_RESERVATION_ATTEMPTS => {}
            _ => return Err(HnsaHnsrPublisherSequenceError::CorruptState),
        }
    }
    Err(HnsaHnsrPublisherSequenceError::CorruptState)
}

fn reconcile_local_before_external_cas(
    store: &mut WalletStore,
    prepared: &PreparedExternalPublisherSequence,
    now_unix: u64,
) -> Result<ReconciledLocalPublisherSequence, HnsaHnsrPublisherSequenceError> {
    prepared.state.validate(prepared.enrollment)?;
    prepared.lease.validate(prepared.enrollment, now_unix)?;
    if now_unix < prepared.state.last_reserved_at_unix {
        return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
    }
    let scope = prepared.enrollment.scope;
    let dimension = prepared.enrollment.dimension;
    match load_publisher_sequence_local_state(store, scope, dimension)? {
        LoadedPublisherSequenceLocalState::Absent => {
            if prepared.state.highest_reserved_sequence == 0 {
                return Ok(ReconciledLocalPublisherSequence {
                    anchor: None,
                    anchor_revision: 0,
                    mirror_revision: 0,
                });
            }
            let anchor = externally_fenced_anchor_from_enrollment(prepared.enrollment, now_unix);
            persist_external_state_locally(
                store,
                ReconciledLocalPublisherSequence {
                    anchor: Some(anchor),
                    anchor_revision: 0,
                    mirror_revision: 0,
                },
                prepared.state,
                now_unix,
            )
        }
        LoadedPublisherSequenceLocalState::LegacyV1 {
            anchor_revision,
            anchor,
            high_water,
        } => {
            if prepared.state.highest_reserved_sequence < high_water.value.highest_reserved_sequence
            {
                return Err(HnsaHnsrPublisherSequenceError::LocalStateAhead);
            }
            if prepared.state.last_reserved_at_unix < high_water.value.last_reserved_at_unix
                || now_unix < high_water.value.last_reserved_at_unix
            {
                return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
            }
            let fenced_anchor = externally_fenced_anchor_from_enrollment(
                prepared.enrollment,
                anchor.initialized_at_unix,
            );
            persist_external_state_locally(
                store,
                ReconciledLocalPublisherSequence {
                    anchor: Some(fenced_anchor),
                    anchor_revision,
                    mirror_revision: high_water.revision,
                },
                prepared.state,
                now_unix,
            )
        }
        LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
            anchor_revision,
            mirror_revision,
            anchor,
            mirror,
        } => {
            if anchor.authority != prepared.enrollment.authority {
                return Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityMismatch);
            }
            if now_unix < anchor.initialized_at_unix || now_unix < mirror.mirrored_at_unix {
                return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
            }
            if prepared.state.highest_reserved_sequence < mirror.highest_reserved_sequence {
                return Err(HnsaHnsrPublisherSequenceError::LocalStateAhead);
            }
            if prepared.state.revision < mirror.external_revision {
                return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
            }
            if prepared.state.last_reserved_at_unix < mirror.last_reserved_at_unix {
                return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
            }
            let local = ReconciledLocalPublisherSequence {
                anchor: Some(anchor),
                anchor_revision,
                mirror_revision,
            };
            if prepared.state.highest_reserved_sequence == mirror.highest_reserved_sequence {
                if !v2_mirror_exactly_matches_external(&mirror, prepared.state) {
                    return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
                }
                return Ok(local);
            }
            if prepared.state.revision <= mirror.external_revision {
                return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
            }
            if prepared.state.authenticated_state_id == mirror.authenticated_state_id
                || prepared.state.last_reservation_id == Some(mirror.last_reservation_id)
            {
                return Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid);
            }
            persist_external_state_locally(store, local, prepared.state, now_unix)
        }
    }
}

fn externally_fenced_anchor_from_enrollment(
    enrollment: AuthenticatedPublisherSequenceEnrollment,
    initialized_at_unix: u64,
) -> ExternallyFencedPublisherSequenceNamespaceAnchor {
    ExternallyFencedPublisherSequenceNamespaceAnchor {
        storage_version: EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION,
        dimension: enrollment.dimension,
        scope: enrollment.scope,
        authority: enrollment.authority,
        initialized_at_unix,
    }
}

fn persist_external_state_locally(
    store: &mut WalletStore,
    local: ReconciledLocalPublisherSequence,
    state: AuthenticatedPublisherSequenceState,
    mirrored_at_unix: u64,
) -> Result<ReconciledLocalPublisherSequence, HnsaHnsrPublisherSequenceError> {
    let anchor = local
        .anchor
        .ok_or(HnsaHnsrPublisherSequenceError::CorruptState)?;
    state.validate(AuthenticatedPublisherSequenceEnrollment {
        authority: anchor.authority,
        dimension: anchor.dimension,
        scope: anchor.scope,
    })?;
    if state.highest_reserved_sequence == 0
        || mirrored_at_unix == 0
        || mirrored_at_unix < anchor.initialized_at_unix
        || mirrored_at_unix < state.last_reserved_at_unix
    {
        return Err(HnsaHnsrPublisherSequenceError::ClockRollback);
    }
    let last_reservation_id = state
        .last_reservation_id
        .ok_or(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)?;
    let next_anchor_revision = local
        .anchor_revision
        .checked_add(1)
        .ok_or(HnsaHnsrPublisherSequenceError::CorruptState)?;
    let next_mirror_revision = local
        .mirror_revision
        .checked_add(1)
        .ok_or(HnsaHnsrPublisherSequenceError::CorruptState)?;
    let mirror = ExternallyFencedPublisherSequenceMirror {
        storage_version: EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION,
        dimension: anchor.dimension,
        scope: anchor.scope,
        authority: anchor.authority,
        external_revision: state.revision,
        highest_reserved_sequence: state.highest_reserved_sequence,
        last_reservation_id,
        last_reserved_at_unix: state.last_reserved_at_unix,
        authenticated_state_id: state.authenticated_state_id,
        mirrored_at_unix,
    };
    anchor.validate(
        anchor.dimension,
        anchor.scope,
        next_anchor_revision,
        anchor.initialized_at_unix,
    )?;
    mirror.validate(
        anchor.dimension,
        anchor.scope,
        anchor.authority,
        next_mirror_revision,
        mirrored_at_unix,
    )?;
    let saves = [
        EntityBatchSave {
            id: anchor_record_id(anchor.scope, anchor.dimension).to_vec(),
            expected_revision: local.anchor_revision,
            value: PublisherSequenceRecord::ExternallyFencedNamespaceAnchor(anchor.clone()),
            updated_at_unix: anchor.initialized_at_unix,
        },
        EntityBatchSave {
            id: high_water_record_id(anchor.scope, anchor.dimension).to_vec(),
            expected_revision: local.mirror_revision,
            value: PublisherSequenceRecord::ExternallyFencedMirror(mirror),
            updated_at_unix: mirrored_at_unix,
        },
    ];
    match store.apply_entity_batch(EntityKind::HnsaHnsrPublisherSequence, &saves, &[]) {
        Ok(()) => Ok(ReconciledLocalPublisherSequence {
            anchor: Some(anchor),
            anchor_revision: next_anchor_revision,
            mirror_revision: next_mirror_revision,
        }),
        Err(StoreError::StaleRevision { .. }) => {
            Err(HnsaHnsrPublisherSequenceError::ConcurrentModification)
        }
        Err(error) => Err(error.into()),
    }
}

fn v2_mirror_exactly_matches_external(
    mirror: &ExternallyFencedPublisherSequenceMirror,
    state: AuthenticatedPublisherSequenceState,
) -> bool {
    mirror.external_revision == state.revision
        && mirror.highest_reserved_sequence == state.highest_reserved_sequence
        && state.last_reservation_id == Some(mirror.last_reservation_id)
        && mirror.last_reserved_at_unix == state.last_reserved_at_unix
        && mirror.authenticated_state_id == state.authenticated_state_id
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
    use std::collections::VecDeque;
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExternalEvent {
        LoadEnrollment,
        AcquireLease,
        RevalidateLease,
        LoadState,
        CompareAndSwap,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockCasAction {
        Apply,
        AmbiguousApply,
        AmbiguousOld,
        AmbiguousOtherWriter,
    }

    struct MockExternalBackend {
        enrollment: Option<AuthenticatedPublisherSequenceEnrollment>,
        lease: Option<PublisherSequenceExternalLease>,
        state: AuthenticatedPublisherSequenceState,
        cas_actions: VecDeque<MockCasAction>,
        live_authority_now_unix: u64,
        live_fence_current: VecDeque<bool>,
        cas_live_fence_current: bool,
        events: Vec<ExternalEvent>,
        proposals: Vec<PublisherSequenceExternalProposal>,
    }

    impl MockExternalBackend {
        fn live_lease_is_current(&self, lease: PublisherSequenceExternalLease) -> bool {
            self.lease == Some(lease)
                && self.live_authority_now_unix >= lease.valid_from_unix
                && self.live_authority_now_unix < lease.expires_at_unix
        }

        fn advanced_state(
            proposal: PublisherSequenceExternalProposal,
            reservation_id: [u8; 32],
        ) -> AuthenticatedPublisherSequenceState {
            let next_revision = proposal.proposed_sequence.get();
            let mut authenticated_state_id = [0xa5; 32];
            authenticated_state_id[24..].copy_from_slice(&next_revision.to_be_bytes());
            AuthenticatedPublisherSequenceState {
                enrollment: proposal.expected_state.enrollment,
                revision: next_revision,
                highest_reserved_sequence: proposal.proposed_sequence.get(),
                last_reservation_id: Some(reservation_id),
                last_reserved_at_unix: proposal.reserved_at_unix,
                authenticated_state_id,
            }
        }
    }

    impl PublisherSequenceExternalBackend for MockExternalBackend {
        fn load_authenticated_enrollment(
            &mut self,
            _: PublisherSequenceExternalAuthority,
            _: PublisherSequenceDimension,
            _: HnsaHnsrPublisherScope,
        ) -> Result<Option<AuthenticatedPublisherSequenceEnrollment>, HnsaHnsrPublisherSequenceError>
        {
            self.events.push(ExternalEvent::LoadEnrollment);
            Ok(self.enrollment)
        }

        fn acquire_lease(
            &mut self,
            _: AuthenticatedPublisherSequenceEnrollment,
            _: u64,
        ) -> Result<Option<PublisherSequenceExternalLease>, HnsaHnsrPublisherSequenceError>
        {
            self.events.push(ExternalEvent::AcquireLease);
            Ok(self.lease)
        }

        fn load_authenticated_state(
            &mut self,
            lease: PublisherSequenceExternalLease,
        ) -> Result<AuthenticatedPublisherSequenceState, HnsaHnsrPublisherSequenceError> {
            self.events.push(ExternalEvent::LoadState);
            assert_eq!(self.lease, Some(lease));
            Ok(self.state)
        }

        fn compare_and_swap(
            &mut self,
            proposal: PublisherSequenceExternalProposal,
        ) -> Result<PublisherSequenceExternalCasResult, HnsaHnsrPublisherSequenceError> {
            self.events.push(ExternalEvent::CompareAndSwap);
            self.proposals.push(proposal);
            proposal.validate(proposal.reserved_at_unix)?;
            if !self.cas_live_fence_current
                || !self.live_lease_is_current(proposal.lease)
                || proposal.expected_state.enrollment != proposal.lease.enrollment
                || proposal.expected_state != self.state
            {
                return Ok(PublisherSequenceExternalCasResult::Rejected(self.state));
            }
            let action = self.cas_actions.pop_front().expect("scripted CAS action");
            match action {
                MockCasAction::Apply => {
                    self.state = Self::advanced_state(proposal, proposal.reservation_id);
                    Ok(PublisherSequenceExternalCasResult::Applied(self.state))
                }
                MockCasAction::AmbiguousApply => {
                    self.state = Self::advanced_state(proposal, proposal.reservation_id);
                    Ok(PublisherSequenceExternalCasResult::Ambiguous)
                }
                MockCasAction::AmbiguousOld => Ok(PublisherSequenceExternalCasResult::Ambiguous),
                MockCasAction::AmbiguousOtherWriter => {
                    let mut other_reservation_id = proposal.reservation_id;
                    other_reservation_id[0] ^= 0x01;
                    self.state = Self::advanced_state(proposal, other_reservation_id);
                    Ok(PublisherSequenceExternalCasResult::Ambiguous)
                }
            }
        }

        fn revalidate_lease(
            &mut self,
            lease: PublisherSequenceExternalLease,
            _: u64,
        ) -> Result<bool, HnsaHnsrPublisherSequenceError> {
            self.events.push(ExternalEvent::RevalidateLease);
            let authority_says_current = self.live_lease_is_current(lease);
            let scripted_live_fence = self.live_fence_current.pop_front().unwrap_or(true);
            Ok(authority_says_current && scripted_live_fence)
        }
    }

    fn external_fixture(
        publisher_scope: HnsaHnsrPublisherScope,
        dimension: PublisherSequenceDimension,
    ) -> (PublisherSequenceExternalAuthority, MockExternalBackend) {
        let mut namespace_id = [21; 32];
        namespace_id[0] = publisher_scope.route_key[0];
        namespace_id[1] = match dimension {
            PublisherSequenceDimension::EndpointDelegation => 1,
            PublisherSequenceDimension::NamedRoute => 2,
        };
        namespace_id[2] = publisher_scope.endpoint_key[1];
        let authority = PublisherSequenceExternalAuthority {
            namespace_id,
            authority_fingerprint: [22; 32],
            enrollment_generation: NonZeroU64::new(1).expect("nonzero generation"),
        };
        let enrollment = AuthenticatedPublisherSequenceEnrollment {
            authority,
            dimension,
            scope: publisher_scope,
        };
        let lease = PublisherSequenceExternalLease {
            enrollment,
            lease_id: [23; 32],
            fence_token: NonZeroU64::new(1).expect("nonzero fence"),
            valid_from_unix: 1,
            expires_at_unix: 1_000,
        };
        let state = AuthenticatedPublisherSequenceState {
            enrollment,
            revision: 0,
            highest_reserved_sequence: 0,
            last_reservation_id: None,
            last_reserved_at_unix: 0,
            authenticated_state_id: [24; 32],
        };
        (
            authority,
            MockExternalBackend {
                enrollment: Some(enrollment),
                lease: Some(lease),
                state,
                cas_actions: VecDeque::new(),
                live_authority_now_unix: 10,
                live_fence_current: VecDeque::new(),
                cas_live_fence_current: true,
                events: Vec::new(),
                proposals: Vec::new(),
            },
        )
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

    fn legacy_v1_store_at_two(
        publisher_scope: HnsaHnsrPublisherScope,
        dimension: PublisherSequenceDimension,
    ) -> WalletStore {
        let mut store = memory_store();
        assert_eq!(
            reserve_sequence(&mut store, publisher_scope, dimension, 8)
                .expect("create first legacy-v1 reservation")
                .get(),
            1
        );
        assert_eq!(
            reserve_sequence(&mut store, publisher_scope, dimension, 9)
                .expect("create second legacy-v1 reservation")
                .get(),
            2
        );
        store
    }

    fn set_external_floor(
        backend: &mut MockExternalBackend,
        sequence: u64,
        last_reserved_at_unix: u64,
        identity_byte: u8,
    ) {
        backend.state.revision = sequence;
        backend.state.highest_reserved_sequence = sequence;
        backend.state.last_reservation_id = (sequence != 0).then_some([identity_byte; 32]);
        backend.state.last_reserved_at_unix = last_reserved_at_unix;
        backend.state.authenticated_state_id = [identity_byte.wrapping_add(1); 32];
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

    fn externally_fenced_anchor(
        dimension: PublisherSequenceDimension,
        scope: HnsaHnsrPublisherScope,
        authority: PublisherSequenceExternalAuthority,
        initialized_at_unix: u64,
    ) -> PublisherSequenceRecord {
        PublisherSequenceRecord::ExternallyFencedNamespaceAnchor(
            ExternallyFencedPublisherSequenceNamespaceAnchor {
                storage_version: EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION,
                dimension,
                scope,
                authority,
                initialized_at_unix,
            },
        )
    }

    fn externally_fenced_mirror(
        dimension: PublisherSequenceDimension,
        scope: HnsaHnsrPublisherScope,
        authority: PublisherSequenceExternalAuthority,
        sequence: u64,
        last_reserved_at_unix: u64,
        mirrored_at_unix: u64,
    ) -> PublisherSequenceRecord {
        PublisherSequenceRecord::ExternallyFencedMirror(ExternallyFencedPublisherSequenceMirror {
            storage_version: EXTERNALLY_FENCED_PUBLISHER_SEQUENCE_STORAGE_VERSION,
            dimension,
            scope,
            authority,
            external_revision: sequence,
            highest_reserved_sequence: sequence,
            last_reservation_id: [31; 32],
            last_reserved_at_unix,
            authenticated_state_id: [32; 32],
            mirrored_at_unix,
        })
    }

    fn save_local_pair(
        store: &mut WalletStore,
        publisher_scope: HnsaHnsrPublisherScope,
        dimension: PublisherSequenceDimension,
        anchor_value: PublisherSequenceRecord,
        anchor_updated_at_unix: u64,
        mirror_value: PublisherSequenceRecord,
        mirror_updated_at_unix: u64,
    ) {
        let saves = [
            EntityBatchSave {
                id: anchor_record_id(publisher_scope, dimension).to_vec(),
                expected_revision: 0,
                value: anchor_value,
                updated_at_unix: anchor_updated_at_unix,
            },
            EntityBatchSave {
                id: high_water_record_id(publisher_scope, dimension).to_vec(),
                expected_revision: 0,
                value: mirror_value,
                updated_at_unix: mirror_updated_at_unix,
            },
        ];
        store
            .apply_entity_batch(EntityKind::HnsaHnsrPublisherSequence, &saves, &[])
            .expect("save local publisher pair");
    }

    #[test]
    fn local_loader_classifies_absent_legacy_v1_and_complete_v2() {
        let publisher_scope = scope(27, 27);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let empty = memory_store();
        assert!(matches!(
            load_publisher_sequence_local_state(&empty, publisher_scope, dimension)
                .expect("load absent topology"),
            LoadedPublisherSequenceLocalState::Absent
        ));

        let mut legacy = memory_store();
        let _ = reserve_endpoint_delegation_sequence(&mut legacy, publisher_scope, 10)
            .expect("create legacy state");
        match load_publisher_sequence_local_state(&legacy, publisher_scope, dimension)
            .expect("load legacy topology")
        {
            LoadedPublisherSequenceLocalState::LegacyV1 {
                anchor_revision,
                high_water,
                ..
            } => {
                assert_eq!(anchor_revision, 1);
                assert_eq!(high_water.revision, 1);
                assert_eq!(high_water.value.highest_reserved_sequence, 1);
            }
            _ => panic!("expected complete legacy-v1 topology"),
        }

        let (authority, _) = external_fixture(publisher_scope, dimension);
        let mut fenced = memory_store();
        save_local_pair(
            &mut fenced,
            publisher_scope,
            dimension,
            externally_fenced_anchor(dimension, publisher_scope, authority, 10),
            10,
            externally_fenced_mirror(dimension, publisher_scope, authority, 7, 11, 12),
            12,
        );
        match load_publisher_sequence_local_state(&fenced, publisher_scope, dimension)
            .expect("load externally fenced topology")
        {
            LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
                anchor_revision,
                mirror_revision,
                anchor,
                mirror,
            } => {
                assert_eq!(anchor_revision, 1);
                assert_eq!(mirror_revision, 1);
                assert_eq!(anchor.authority, authority);
                assert_eq!(mirror.highest_reserved_sequence, 7);
                assert_eq!(mirror.authenticated_state_id, [32; 32]);
            }
            _ => panic!("expected complete externally-fenced-v2 topology"),
        }
    }

    #[test]
    fn legacy_v1_migration_requires_an_authenticated_equal_or_greater_external_floor() {
        let dimension = PublisherSequenceDimension::EndpointDelegation;

        let equal_scope = scope(39, 8);
        let (equal_authority, mut equal_backend) = external_fixture(equal_scope, dimension);
        set_external_floor(&mut equal_backend, 2, 9, 41);
        equal_backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        let mut equal_store = legacy_v1_store_at_two(equal_scope, dimension);
        let equal_result = with_externally_fenced_publisher_sequence(
            &mut equal_store,
            &mut equal_backend,
            equal_authority,
            equal_scope,
            dimension,
            10,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("equal authenticated floor permits v1 migration");
        assert_eq!(equal_result, 3);
        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 { anchor, mirror, .. } =
            load_publisher_sequence_local_state(&equal_store, equal_scope, dimension)
                .expect("load equal-floor migration")
        else {
            panic!("equal external floor must migrate to v2");
        };
        assert_eq!(anchor.authority, equal_authority);
        assert_eq!(anchor.initialized_at_unix, 8);
        assert_eq!(mirror.highest_reserved_sequence, 3);
        assert_eq!(mirror.external_revision, 3);

        let greater_scope = scope(40, 9);
        let (greater_authority, mut greater_backend) = external_fixture(greater_scope, dimension);
        set_external_floor(&mut greater_backend, 4, 10, 42);
        greater_backend.live_authority_now_unix = 11;
        greater_backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        let mut greater_store = legacy_v1_store_at_two(greater_scope, dimension);
        let greater_result = with_externally_fenced_publisher_sequence(
            &mut greater_store,
            &mut greater_backend,
            greater_authority,
            greater_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("greater authenticated floor rehydrates v1 before allocation");
        assert_eq!(greater_result, 5);
        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 { mirror, .. } =
            load_publisher_sequence_local_state(&greater_store, greater_scope, dimension)
                .expect("load greater-floor migration")
        else {
            panic!("greater external floor must migrate to v2");
        };
        assert_eq!(mirror.highest_reserved_sequence, 5);
        assert_eq!(mirror.external_revision, 5);

        let lower_scope = scope(41, 10);
        let (lower_authority, mut lower_backend) = external_fixture(lower_scope, dimension);
        set_external_floor(&mut lower_backend, 1, 8, 43);
        let mut lower_store = legacy_v1_store_at_two(lower_scope, dimension);
        let mut lower_consumer_ran = false;
        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut lower_store,
                &mut lower_backend,
                lower_authority,
                lower_scope,
                dimension,
                10,
                |_, _| {
                    lower_consumer_ran = true;
                    Ok(())
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::LocalStateAhead)
        ));
        assert!(!lower_consumer_ran);
        assert!(lower_backend.proposals.is_empty());
        assert!(
            !lower_backend
                .events
                .contains(&ExternalEvent::CompareAndSwap)
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&lower_store, lower_scope, dimension)
                .expect("load unchanged lower-floor fixture"),
            LoadedPublisherSequenceLocalState::LegacyV1 { .. }
        ));
    }

    #[test]
    fn copied_and_stale_restored_sqlite_wallets_share_one_external_allocator() {
        let directory = TestDirectory::new();
        let original_path = directory.path().join("original.sqlite3");
        let stale_clone_path = directory.path().join("stale-clone.sqlite3");
        let publisher_scope = scope(42, 11);
        let dimension = PublisherSequenceDimension::NamedRoute;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([
            MockCasAction::Apply,
            MockCasAction::Apply,
            MockCasAction::Apply,
            MockCasAction::Apply,
        ]);

        {
            let mut original =
                WalletStore::create(&original_path, PASSPHRASE).expect("create original wallet");
            let first = with_externally_fenced_publisher_sequence(
                &mut original,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                10,
                |_, token| Ok(token.sequence.get()),
            )
            .expect("reserve before snapshot");
            assert_eq!(first, 1);
        }
        fs::copy(&original_path, &stale_clone_path).expect("copy closed SQLite snapshot");

        let mut original = WalletStore::open(&original_path).expect("reopen original wallet");
        original.unlock(PASSPHRASE).expect("unlock original wallet");
        backend.live_authority_now_unix = 11;
        let second = with_externally_fenced_publisher_sequence(
            &mut original,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("advance original beyond copied snapshot");
        assert_eq!(second, 2);

        let mut stale_clone =
            WalletStore::open(&stale_clone_path).expect("open stale restored clone");
        stale_clone
            .unlock(PASSPHRASE)
            .expect("unlock stale restored clone");
        backend.live_authority_now_unix = 12;
        let third = with_externally_fenced_publisher_sequence(
            &mut stale_clone,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            12,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("rehydrate stale clone and reserve from shared authority");
        assert_eq!(third, 3);

        backend.live_authority_now_unix = 13;
        let fourth = with_externally_fenced_publisher_sequence(
            &mut original,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            13,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("rehydrate now-stale original and reserve again");
        assert_eq!(fourth, 4);
        assert_eq!(backend.state.highest_reserved_sequence, 4);
        assert_eq!(backend.proposals.len(), 4);

        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
            mirror: clone_mirror,
            ..
        } = load_publisher_sequence_local_state(&stale_clone, publisher_scope, dimension)
            .expect("load clone mirror")
        else {
            panic!("clone mirror must be v2");
        };
        assert_eq!(clone_mirror.highest_reserved_sequence, 3);
        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
            mirror: original_mirror,
            ..
        } = load_publisher_sequence_local_state(&original, publisher_scope, dimension)
            .expect("load original mirror")
        else {
            panic!("original mirror must be v2");
        };
        assert_eq!(original_mirror.highest_reserved_sequence, 4);
    }

    #[test]
    fn v2_loader_rejects_partial_mixed_misbound_and_timestamp_state() {
        let publisher_scope = scope(28, 28);
        let dimension = PublisherSequenceDimension::NamedRoute;
        let (authority, _) = external_fixture(publisher_scope, dimension);

        let mut partial = memory_store();
        partial
            .save_entity(
                EntityKind::HnsaHnsrPublisherSequence,
                &anchor_record_id(publisher_scope, dimension),
                0,
                &externally_fenced_anchor(dimension, publisher_scope, authority, 10),
                10,
            )
            .expect("save partial v2 anchor");
        assert!(matches!(
            load_publisher_sequence_local_state(&partial, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let mut mixed = memory_store();
        save_local_pair(
            &mut mixed,
            publisher_scope,
            dimension,
            anchor(dimension, publisher_scope, 10),
            10,
            externally_fenced_mirror(dimension, publisher_scope, authority, 1, 10, 10),
            10,
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&mixed, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let mut misbound = memory_store();
        let mut other_authority = authority;
        other_authority.namespace_id[0] ^= 0x01;
        save_local_pair(
            &mut misbound,
            publisher_scope,
            dimension,
            externally_fenced_anchor(dimension, publisher_scope, authority, 10),
            10,
            externally_fenced_mirror(dimension, publisher_scope, other_authority, 1, 10, 10),
            10,
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&misbound, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let mut wrong_timestamp = memory_store();
        save_local_pair(
            &mut wrong_timestamp,
            publisher_scope,
            dimension,
            externally_fenced_anchor(dimension, publisher_scope, authority, 10),
            10,
            externally_fenced_mirror(dimension, publisher_scope, authority, 1, 10, 12),
            11,
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&wrong_timestamp, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));

        let mut swapped_variants = memory_store();
        save_local_pair(
            &mut swapped_variants,
            publisher_scope,
            dimension,
            externally_fenced_mirror(dimension, publisher_scope, authority, 1, 10, 10),
            10,
            externally_fenced_anchor(dimension, publisher_scope, authority, 10),
            10,
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&swapped_variants, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));
    }

    #[test]
    fn external_counter_requires_exact_existing_enrollment() {
        let publisher_scope = scope(20, 20);
        let (authority, mut missing) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        missing.enrollment = None;
        assert!(matches!(
            externally_commit_sequence(
                &mut missing,
                authority,
                publisher_scope,
                PublisherSequenceDimension::EndpointDelegation,
                10,
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalEnrollmentMissing)
        ));
        assert_eq!(missing.events, [ExternalEvent::LoadEnrollment]);

        let (authority, mut misbound) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        let mut enrollment = misbound.enrollment.expect("mock enrollment");
        enrollment.authority.authority_fingerprint[0] ^= 0x01;
        misbound.enrollment = Some(enrollment);
        assert!(matches!(
            externally_commit_sequence(
                &mut misbound,
                authority,
                publisher_scope,
                PublisherSequenceDimension::EndpointDelegation,
                10,
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityMismatch)
        ));
        assert_eq!(misbound.events, [ExternalEvent::LoadEnrollment]);
    }

    #[test]
    fn lease_revalidation_uses_authority_live_time_not_the_operation_timestamp() {
        let publisher_scope = scope(37, 6);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.live_authority_now_unix = backend.lease.expect("mock lease").expires_at_unix;

        assert!(matches!(
            externally_commit_sequence(&mut backend, authority, publisher_scope, dimension, 10,),
            Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
        ));
        assert_eq!(backend.state.highest_reserved_sequence, 0);
        assert!(backend.proposals.is_empty());
        assert_eq!(
            backend.events,
            [
                ExternalEvent::LoadEnrollment,
                ExternalEvent::AcquireLease,
                ExternalEvent::RevalidateLease,
            ]
        );
    }

    #[test]
    fn atomic_cas_rejects_a_fence_lost_after_successful_preflight_revalidation() {
        let publisher_scope = scope(38, 7);
        let dimension = PublisherSequenceDimension::NamedRoute;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_live_fence_current = false;
        let mut store = memory_store();
        let mut consumer_ran = false;

        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut store,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                10,
                |_, _| {
                    consumer_ran = true;
                    Ok(())
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ConcurrentModification)
        ));
        assert!(!consumer_ran);
        assert_eq!(backend.state.highest_reserved_sequence, 0);
        assert_eq!(backend.state.revision, 0);
        assert_eq!(backend.proposals.len(), 1);
        assert!(matches!(
            load_publisher_sequence_local_state(&store, publisher_scope, dimension)
                .expect("load unchanged local state"),
            LoadedPublisherSequenceLocalState::Absent
        ));
        assert_eq!(
            backend.events,
            [
                ExternalEvent::LoadEnrollment,
                ExternalEvent::AcquireLease,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
                ExternalEvent::CompareAndSwap,
            ]
        );
    }

    #[test]
    fn ambiguous_old_retries_the_byte_identical_proposal_under_current_lease() {
        let publisher_scope = scope(21, 21);
        let (authority, mut backend) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        let initial_state_id = backend.state.authenticated_state_id;
        backend.cas_actions = VecDeque::from([MockCasAction::AmbiguousOld, MockCasAction::Apply]);

        let committed = externally_commit_sequence(
            &mut backend,
            authority,
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
            10,
        )
        .expect("exact-old ambiguity retries safely");
        assert_eq!(committed.sequence.get(), 1);
        assert_eq!(committed.state, backend.state);
        assert_eq!(committed.lease, backend.lease.expect("mock lease"));
        assert_ne!(committed.state.authenticated_state_id, initial_state_id);
        assert_eq!(backend.proposals.len(), 2);
        assert_eq!(backend.proposals[0], backend.proposals[1]);
        assert_eq!(
            backend.events,
            [
                ExternalEvent::LoadEnrollment,
                ExternalEvent::AcquireLease,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
                ExternalEvent::CompareAndSwap,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
                ExternalEvent::CompareAndSwap,
                ExternalEvent::RevalidateLease,
            ]
        );
    }

    #[test]
    fn ambiguous_exact_new_recovers_only_its_own_reservation() {
        let publisher_scope = scope(22, 22);
        let (authority, mut backend) =
            external_fixture(publisher_scope, PublisherSequenceDimension::NamedRoute);
        backend.cas_actions = VecDeque::from([MockCasAction::AmbiguousApply]);

        let committed = externally_commit_sequence(
            &mut backend,
            authority,
            publisher_scope,
            PublisherSequenceDimension::NamedRoute,
            10,
        )
        .expect("exact-new ambiguity is reconciled");
        assert_eq!(committed.sequence.get(), 1);
        assert_eq!(backend.proposals.len(), 1);
        assert_eq!(
            backend.events,
            [
                ExternalEvent::LoadEnrollment,
                ExternalEvent::AcquireLease,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
                ExternalEvent::CompareAndSwap,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
            ]
        );
    }

    #[test]
    fn ambiguous_same_sequence_from_another_writer_is_never_consumed() {
        let publisher_scope = scope(23, 23);
        let (authority, mut backend) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        backend.cas_actions = VecDeque::from([MockCasAction::AmbiguousOtherWriter]);

        assert!(matches!(
            externally_commit_sequence(
                &mut backend,
                authority,
                publisher_scope,
                PublisherSequenceDimension::EndpointDelegation,
                10,
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalOutcomeAmbiguous)
        ));
        assert_eq!(backend.state.highest_reserved_sequence, 1);
        assert_ne!(
            backend.state.last_reservation_id,
            Some(backend.proposals[0].reservation_id)
        );
        assert_eq!(backend.proposals.len(), 1);
    }

    #[test]
    fn post_commit_lease_loss_burns_the_external_sequence() {
        let publisher_scope = scope(24, 24);
        let (authority, mut backend) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        backend.live_fence_current = VecDeque::from([true, true, false]);

        assert!(matches!(
            externally_commit_sequence(
                &mut backend,
                authority,
                publisher_scope,
                PublisherSequenceDimension::EndpointDelegation,
                10,
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
        ));
        assert_eq!(backend.state.highest_reserved_sequence, 1);
        assert_eq!(backend.proposals.len(), 1);
        assert_eq!(backend.events.last(), Some(&ExternalEvent::RevalidateLease));
    }

    #[test]
    fn external_full_u64_sequence_is_reachable_then_exhausts_without_another_cas() {
        let publisher_scope = scope(25, 25);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.state.revision = u64::MAX - 1;
        backend.state.highest_reserved_sequence = u64::MAX - 1;
        backend.state.last_reservation_id = Some([26; 32]);
        backend.state.last_reserved_at_unix = 9;
        backend.state.authenticated_state_id = [27; 32];
        backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        let mut store = memory_store();
        let consumed = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            10,
            |store, token| {
                let LoadedPublisherSequenceLocalState::ExternallyFencedV2 { mirror, .. } =
                    load_publisher_sequence_local_state(store, publisher_scope, dimension)?
                else {
                    panic!("terminal sequence must be mirrored before consumption");
                };
                assert_eq!(mirror.external_revision, u64::MAX);
                assert_eq!(mirror.highest_reserved_sequence, u64::MAX);
                Ok(token.sequence.get())
            },
        )
        .expect("reserve the terminal full-width sequence");
        assert_eq!(consumed, u64::MAX);
        assert_eq!(backend.state.revision, u64::MAX);
        assert_eq!(backend.state.highest_reserved_sequence, u64::MAX);
        assert_eq!(backend.proposals.len(), 1);

        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut store,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                11,
                |_, _| -> Result<(), HnsaHnsrPublisherSequenceError> {
                    panic!("exhaustion must suppress consumption")
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::SequenceExhausted)
        ));
        assert_eq!(backend.proposals.len(), 1);
    }

    #[test]
    fn durable_external_state_identity_survives_lease_renewal() {
        let publisher_scope = scope(26, 26);
        let (_, mut backend) = external_fixture(
            publisher_scope,
            PublisherSequenceDimension::EndpointDelegation,
        );
        let first_lease = backend.lease.expect("initial lease");
        let first_state = backend
            .load_authenticated_state(first_lease)
            .expect("state under initial lease");
        let mut renewed_lease = first_lease;
        renewed_lease.lease_id = [27; 32];
        renewed_lease.fence_token = NonZeroU64::new(2).expect("renewed fence");
        backend.lease = Some(renewed_lease);
        let renewed_state = backend
            .load_authenticated_state(renewed_lease)
            .expect("same state under renewed lease");
        assert_eq!(renewed_state, first_state);
        assert_eq!(
            renewed_state.authenticated_state_id,
            first_state.authenticated_state_id
        );
    }

    #[test]
    fn internal_consumer_runs_only_after_exact_external_state_is_mirrored() {
        let publisher_scope = scope(29, 29);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        let mut store = memory_store();

        let consumed_sequence = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            10,
            |store, token| {
                assert_eq!(token.scope, publisher_scope);
                assert_eq!(token.dimension, dimension);
                let LoadedPublisherSequenceLocalState::ExternallyFencedV2 {
                    anchor_revision,
                    mirror_revision,
                    anchor,
                    mirror,
                } = load_publisher_sequence_local_state(store, publisher_scope, dimension)?
                else {
                    panic!("consumer requires a complete v2 mirror");
                };
                assert_eq!(anchor_revision, 1);
                assert_eq!(mirror_revision, 1);
                assert_eq!(anchor.authority, authority);
                assert_eq!(mirror.highest_reserved_sequence, token.sequence.get());
                assert_eq!(mirror.last_reservation_id, token.reservation_id);
                assert_eq!(mirror.external_revision, 1);
                Ok(token.sequence.get())
            },
        )
        .expect("consume only after external and local commits");
        assert_eq!(consumed_sequence, 1);
        assert_eq!(
            backend.events,
            [
                ExternalEvent::LoadEnrollment,
                ExternalEvent::AcquireLease,
                ExternalEvent::RevalidateLease,
                ExternalEvent::LoadState,
                ExternalEvent::RevalidateLease,
                ExternalEvent::CompareAndSwap,
                ExternalEvent::RevalidateLease,
                ExternalEvent::RevalidateLease,
                ExternalEvent::RevalidateLease,
            ]
        );
    }

    #[test]
    fn failed_post_external_local_write_burns_n_and_next_consumer_gets_n_plus_one() {
        let publisher_scope = scope(30, 30);
        let dimension = PublisherSequenceDimension::NamedRoute;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([MockCasAction::Apply, MockCasAction::Apply]);
        let mut store = memory_store();
        let mut first_callback_ran = false;

        let failed = with_externally_fenced_publisher_sequence_core(
            &mut store,
            &mut backend,
            PublisherSequenceReservationRequest {
                expected_authority: authority,
                scope: publisher_scope,
                dimension,
                now_unix: 10,
            },
            |store| {
                store.lock();
                Ok(())
            },
            |_, _| {
                first_callback_ran = true;
                Ok(())
            },
        );
        assert!(matches!(
            failed,
            Err(HnsaHnsrPublisherSequenceError::Store(StoreError::Locked))
        ));
        assert!(!first_callback_ran);
        assert_eq!(backend.state.highest_reserved_sequence, 1);

        store
            .unlock(PASSPHRASE)
            .expect("unlock after injected failure");
        let next = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("next reservation skips externally burned N");
        assert_eq!(next, 2);
        assert_eq!(backend.state.highest_reserved_sequence, 2);
        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 { mirror, .. } =
            load_publisher_sequence_local_state(&store, publisher_scope, dimension)
                .expect("load final mirror")
        else {
            panic!("final mirror must be v2");
        };
        assert_eq!(mirror.highest_reserved_sequence, 2);
    }

    #[test]
    fn final_lease_loss_suppresses_consumer_but_preserves_burned_gap() {
        let publisher_scope = scope(31, 31);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([MockCasAction::Apply, MockCasAction::Apply]);
        backend.live_fence_current = VecDeque::from([true, true, true, false]);
        let mut store = memory_store();
        let mut first_callback_ran = false;

        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut store,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                10,
                |_, _| {
                    first_callback_ran = true;
                    Ok(())
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
        ));
        assert!(!first_callback_ran);
        assert_eq!(backend.state.highest_reserved_sequence, 1);
        let LoadedPublisherSequenceLocalState::ExternallyFencedV2 { mirror, .. } =
            load_publisher_sequence_local_state(&store, publisher_scope, dimension)
                .expect("load burned mirror")
        else {
            panic!("burned sequence must already be mirrored");
        };
        assert_eq!(mirror.highest_reserved_sequence, 1);

        backend.live_fence_current.clear();
        let next = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("next current lease advances beyond burned gap");
        assert_eq!(next, 2);
    }

    #[test]
    fn post_consumer_lease_loss_suppresses_signed_result_and_burns_n() {
        let publisher_scope = scope(35, 4);
        let dimension = PublisherSequenceDimension::NamedRoute;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([MockCasAction::Apply, MockCasAction::Apply]);
        backend.live_fence_current = VecDeque::from([true, true, true, true, false]);
        let mut store = memory_store();
        let mut callback_ran = false;

        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut store,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                10,
                |_, token| {
                    callback_ran = true;
                    Ok(token.sequence.get().to_be_bytes().to_vec())
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
        ));
        assert!(callback_ran);
        assert_eq!(backend.state.highest_reserved_sequence, 1);

        backend.live_fence_current.clear();
        let next = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("next result uses sequence after suppressed signed bytes");
        assert_eq!(next, 2);
    }

    #[test]
    fn post_consumer_lease_loss_is_checked_even_when_the_consumer_returns_an_error() {
        let publisher_scope = scope(45, 14);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (authority, mut backend) = external_fixture(publisher_scope, dimension);
        backend.cas_actions = VecDeque::from([MockCasAction::Apply, MockCasAction::Apply]);
        backend.live_fence_current = VecDeque::from([true, true, true, true, false]);
        let mut store = memory_store();
        let mut callback_ran = false;

        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut store,
                &mut backend,
                authority,
                publisher_scope,
                dimension,
                10,
                |_, _| -> Result<(), HnsaHnsrPublisherSequenceError> {
                    callback_ran = true;
                    Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityUnavailable)
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalLeaseInvalid)
        ));
        assert!(callback_ran);
        assert_eq!(backend.state.highest_reserved_sequence, 1);

        backend.live_fence_current.clear();
        backend.live_authority_now_unix = 11;
        let next = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut backend,
            authority,
            publisher_scope,
            dimension,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("next reservation advances beyond the errored consumer's burned sequence");
        assert_eq!(next, 2);
    }

    #[test]
    fn zero_external_operation_ids_fail_at_state_proposal_and_mirror_boundaries() {
        let publisher_scope = scope(36, 5);
        let dimension = PublisherSequenceDimension::EndpointDelegation;
        let (_, backend) = external_fixture(publisher_scope, dimension);
        let enrollment = backend.enrollment.expect("mock enrollment");
        let lease = backend.lease.expect("mock lease");

        let mut invalid_state = backend.state;
        invalid_state.revision = 1;
        invalid_state.highest_reserved_sequence = 1;
        invalid_state.last_reservation_id = Some([0; 32]);
        invalid_state.last_reserved_at_unix = 10;
        assert!(matches!(
            invalid_state.validate(enrollment),
            Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)
        ));

        let invalid_proposal = PublisherSequenceExternalProposal {
            lease,
            expected_state: backend.state,
            proposed_sequence: NonZeroU64::new(1).expect("nonzero proposal"),
            reservation_id: [0; 32],
            reserved_at_unix: 10,
        };
        assert!(matches!(
            invalid_proposal.validate(10),
            Err(HnsaHnsrPublisherSequenceError::ExternalProposalInvalid)
        ));

        let mut mirror =
            externally_fenced_mirror(dimension, publisher_scope, enrollment.authority, 1, 10, 10);
        let PublisherSequenceRecord::ExternallyFencedMirror(ref mut value) = mirror else {
            panic!("test helper must construct v2 mirror");
        };
        value.last_reservation_id = [0; 32];
        let mut store = memory_store();
        save_local_pair(
            &mut store,
            publisher_scope,
            dimension,
            externally_fenced_anchor(dimension, publisher_scope, enrollment.authority, 10),
            10,
            mirror,
            10,
        );
        assert!(matches!(
            load_publisher_sequence_local_state(&store, publisher_scope, dimension),
            Err(HnsaHnsrPublisherSequenceError::CorruptState)
        ));
    }

    #[test]
    fn pre_cas_local_ahead_divergence_and_authority_mismatch_never_advance_external() {
        let dimension = PublisherSequenceDimension::NamedRoute;

        let ahead_scope = scope(32, 1);
        let (ahead_authority, mut ahead_backend) = external_fixture(ahead_scope, dimension);
        let mut ahead_store = memory_store();
        save_local_pair(
            &mut ahead_store,
            ahead_scope,
            dimension,
            externally_fenced_anchor(dimension, ahead_scope, ahead_authority, 10),
            10,
            externally_fenced_mirror(dimension, ahead_scope, ahead_authority, 1, 10, 10),
            10,
        );
        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut ahead_store,
                &mut ahead_backend,
                ahead_authority,
                ahead_scope,
                dimension,
                10,
                |_, _| -> Result<(), HnsaHnsrPublisherSequenceError> {
                    panic!("local-ahead state must suppress consumer")
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::LocalStateAhead)
        ));
        assert!(
            !ahead_backend
                .events
                .contains(&ExternalEvent::CompareAndSwap)
        );

        let divergent_scope = scope(33, 2);
        let (divergent_authority, mut divergent_backend) =
            external_fixture(divergent_scope, dimension);
        divergent_backend.state.revision = 7;
        divergent_backend.state.highest_reserved_sequence = 7;
        divergent_backend.state.last_reservation_id = Some([31; 32]);
        divergent_backend.state.last_reserved_at_unix = 11;
        divergent_backend.state.authenticated_state_id = [33; 32];
        let mut divergent_store = memory_store();
        save_local_pair(
            &mut divergent_store,
            divergent_scope,
            dimension,
            externally_fenced_anchor(dimension, divergent_scope, divergent_authority, 10),
            10,
            externally_fenced_mirror(dimension, divergent_scope, divergent_authority, 7, 11, 12),
            12,
        );
        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut divergent_store,
                &mut divergent_backend,
                divergent_authority,
                divergent_scope,
                dimension,
                12,
                |_, _| -> Result<(), HnsaHnsrPublisherSequenceError> {
                    panic!("equal-sequence divergent state must suppress consumer")
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalStateInvalid)
        ));
        assert!(
            !divergent_backend
                .events
                .contains(&ExternalEvent::CompareAndSwap)
        );

        let misbound_scope = scope(34, 3);
        let (expected_authority, mut misbound_backend) =
            external_fixture(misbound_scope, dimension);
        let mut stored_authority = expected_authority;
        stored_authority.namespace_id[0] ^= 0x01;
        let mut misbound_store = memory_store();
        save_local_pair(
            &mut misbound_store,
            misbound_scope,
            dimension,
            externally_fenced_anchor(dimension, misbound_scope, stored_authority, 10),
            10,
            externally_fenced_mirror(dimension, misbound_scope, stored_authority, 1, 10, 10),
            10,
        );
        assert!(matches!(
            with_externally_fenced_publisher_sequence(
                &mut misbound_store,
                &mut misbound_backend,
                expected_authority,
                misbound_scope,
                dimension,
                10,
                |_, _| -> Result<(), HnsaHnsrPublisherSequenceError> {
                    panic!("misbound authority must suppress consumer")
                },
            ),
            Err(HnsaHnsrPublisherSequenceError::ExternalAuthorityMismatch)
        ));
        assert!(
            !misbound_backend
                .events
                .contains(&ExternalEvent::CompareAndSwap)
        );
    }

    #[test]
    fn external_allocator_is_independent_across_dimensions_and_exact_scopes() {
        let first_scope = scope(43, 12);
        let other_scope = scope(44, 13);
        let (endpoint_authority, mut endpoint_backend) =
            external_fixture(first_scope, PublisherSequenceDimension::EndpointDelegation);
        let (route_authority, mut route_backend) =
            external_fixture(first_scope, PublisherSequenceDimension::NamedRoute);
        let (other_authority, mut other_backend) =
            external_fixture(other_scope, PublisherSequenceDimension::EndpointDelegation);
        endpoint_backend.cas_actions = VecDeque::from([MockCasAction::Apply, MockCasAction::Apply]);
        route_backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        other_backend.cas_actions = VecDeque::from([MockCasAction::Apply]);
        assert_ne!(
            endpoint_authority.namespace_id,
            route_authority.namespace_id
        );
        assert_ne!(
            endpoint_authority.namespace_id,
            other_authority.namespace_id
        );

        let mut store = memory_store();
        let endpoint_one = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut endpoint_backend,
            endpoint_authority,
            first_scope,
            PublisherSequenceDimension::EndpointDelegation,
            10,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("first endpoint namespace reservation");
        let route_one = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut route_backend,
            route_authority,
            first_scope,
            PublisherSequenceDimension::NamedRoute,
            10,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("independent named-route namespace reservation");
        let other_one = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut other_backend,
            other_authority,
            other_scope,
            PublisherSequenceDimension::EndpointDelegation,
            10,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("independent exact-scope reservation");
        endpoint_backend.live_authority_now_unix = 11;
        let endpoint_two = with_externally_fenced_publisher_sequence(
            &mut store,
            &mut endpoint_backend,
            endpoint_authority,
            first_scope,
            PublisherSequenceDimension::EndpointDelegation,
            11,
            |_, token| Ok(token.sequence.get()),
        )
        .expect("advance only the endpoint namespace");

        assert_eq!(
            (endpoint_one, route_one, other_one, endpoint_two),
            (1, 1, 1, 2)
        );
        assert_eq!(endpoint_backend.state.highest_reserved_sequence, 2);
        assert_eq!(route_backend.state.highest_reserved_sequence, 1);
        assert_eq!(other_backend.state.highest_reserved_sequence, 1);
        assert_ne!(
            high_water_record_id(first_scope, PublisherSequenceDimension::EndpointDelegation),
            high_water_record_id(first_scope, PublisherSequenceDimension::NamedRoute)
        );
        assert_ne!(
            high_water_record_id(first_scope, PublisherSequenceDimension::EndpointDelegation),
            high_water_record_id(other_scope, PublisherSequenceDimension::EndpointDelegation)
        );
    }

    #[test]
    fn legacy_local_fixture_counters_are_nonzero_independent_and_scope_isolated() {
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
