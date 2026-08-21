use std::collections::BTreeSet;

use hns_marketplace_protocol::{DenuoRegistryVersion, NameMarketMessage};
use hns_wallet_store::{EntityBatchSave, EntityKind, WalletStore};
use hns_wallet_types::{ObjectHash, WorkflowId, WorkflowKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::acceptance::{
    DenuoAcceptanceExpectation, PersistedDenuoPublicationAcceptance,
    validate_denuo_publication_acceptance, validate_persisted_denuo_publication_acceptance,
};
use crate::{
    AuthenticatedFixedPriceListing, DenuoPublicationAcceptancePolicy,
    DenuoPublicationAcceptanceSnapshot, ShakedexError, VerifiedListingCancellation,
};

const LEGACY_DENUO_OUTBOX_SCHEMA_VERSION: u16 = 1;
const HANDOFF_DENUO_OUTBOX_SCHEMA_VERSION: u16 = 2;
const RELAY_DENUO_OUTBOX_SCHEMA_VERSION: u16 = 3;
const DENUO_OUTBOX_SCHEMA_VERSION: u16 = 4;
const DENUO_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-outbox-envelope-v1\0";
const DENUO_OUTBOX_ATTEMPT_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-handoff-attempt-v1\0";
const DENUO_OUTBOX_RECORD_ID: &[u8] = b"canonical-name-market-outbox-v1";
pub const MAX_DENUO_OUTBOX_ENTRIES: usize = 1_024;
pub const MAX_DENUO_OUTBOX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_DENUO_OUTBOX_SERIALIZED_BYTES: usize = 512 * 1024;
pub const MAX_DENUO_OUTBOX_RETRY_ATTEMPTS: u16 = 64;

/// Return the deterministic local outbox identity of one canonical offer or
/// cancellation envelope. This is not a Denuo content identifier, receipt, or
/// publication proof.
pub fn denuo_outbox_envelope_id(envelope_bytes: &[u8]) -> Result<ObjectHash, ShakedexError> {
    canonical_publication(envelope_bytes).map(|publication| publication.envelope_id)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum DenuoOutboxMessageKind {
    Offer,
    Cancellation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DenuoOutboxState {
    Pending,
    HandoffPrepared {
        attempt_id: ObjectHash,
        prepared_at_unix: u64,
    },
    RetryScheduled {
        next_attempt_at_unix: u64,
    },
    /// Terminal endpoint-signed acceptance of this exact prepared envelope.
    RelayAccepted {
        receipt_id: ObjectHash,
        accepted_at_unix: u64,
    },
    /// The wallet durably admitted the exact record to its own board and
    /// successfully wrote it to one negotiated direct wallet peer. This is a
    /// local transport observation, never a peer receipt or inclusion proof.
    DirectAnnounced {
        attempt_id: ObjectHash,
        prepared_at_unix: u64,
        announced_at_unix: u64,
    },
    /// Immutable terminal state retained only for schema-v1 compatibility.
    /// Schemas v2/v3 expose no API that can create protocol acknowledgement.
    Acknowledged {
        acknowledged_at_unix: u64,
    },
    Exhausted {
        exhausted_at_unix: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DenuoOutboxEntry {
    /// Wallet-local, domain-separated digest of the exact Denuo envelope.
    /// This is not a Denuo protocol content identifier.
    pub envelope_id: ObjectHash,
    /// The canonical listing or cancellation content identifier carried by the
    /// exact envelope.
    pub content_id: ObjectHash,
    pub message_kind: DenuoOutboxMessageKind,
    pub request_id: u64,
    pub envelope_bytes: Vec<u8>,
    pub state: DenuoOutboxState,
    pub retry_attempts: u16,
    pub created_at_unix: u64,
    pub last_attempt_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<PersistedDenuoPublicationAcceptance>,
}

/// Public outbox construction is deliberately limited to [`Default`] plus the
/// typed enqueue methods. In particular, arbitrary persisted entries cannot be
/// deserialized into this aggregate outside its validated store loader.
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPublicationOutbox;
/// let _: DenuoPublicationOutbox = serde_json::from_str(
///     r#"{"schema_version":2,"entries":[]}"#,
/// ).unwrap();
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPublicationOutbox;
/// let _ = serde_json::to_vec(&DenuoPublicationOutbox::default()).unwrap();
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPublicationOutbox;
/// let _ = format!("{:?}", DenuoPublicationOutbox::default());
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct DenuoPublicationOutbox {
    schema_version: u16,
    entries: Vec<DenuoOutboxEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDenuoPublicationOutbox {
    schema_version: u16,
    entries: Vec<DenuoOutboxEntry>,
}

#[derive(Serialize)]
struct PersistedDenuoPublicationOutboxRef<'a> {
    schema_version: u16,
    entries: &'a [DenuoOutboxEntry],
}

impl Default for DenuoPublicationOutbox {
    fn default() -> Self {
        Self {
            schema_version: DENUO_OUTBOX_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

impl DenuoPublicationOutbox {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn state(&self, envelope_id: ObjectHash) -> Option<DenuoOutboxState> {
        self.entry(envelope_id).map(|entry| entry.state)
    }

    pub fn retry_attempts(&self, envelope_id: ObjectHash) -> Option<u16> {
        self.entry(envelope_id).map(|entry| entry.retry_attempts)
    }

    fn entry(&self, envelope_id: ObjectHash) -> Option<&DenuoOutboxEntry> {
        self.entries
            .iter()
            .find(|entry| entry.envelope_id == envelope_id)
    }

    /// Enqueue one exact canonical V2 offer envelope for a listing already
    /// authenticated by the canonical wallet boundary.
    pub fn enqueue_offer(
        &mut self,
        envelope_bytes: &[u8],
        listing: &AuthenticatedFixedPriceListing,
        created_at_unix: u64,
    ) -> Result<DenuoOutboxEnqueue, ShakedexError> {
        self.enqueue_expected(
            envelope_bytes,
            DenuoOutboxMessageKind::Offer,
            listing.listing_hash(),
            created_at_unix,
        )
    }

    /// Enqueue one exact canonical V2 cancellation envelope for a cancellation
    /// already verified against its exact authenticated listing.
    pub fn enqueue_cancellation(
        &mut self,
        envelope_bytes: &[u8],
        cancellation: &VerifiedListingCancellation,
        created_at_unix: u64,
    ) -> Result<DenuoOutboxEnqueue, ShakedexError> {
        self.enqueue_expected(
            envelope_bytes,
            DenuoOutboxMessageKind::Cancellation,
            cancellation.cancellation_hash(),
            created_at_unix,
        )
    }

    /// An exact retry is idempotent. The same canonical message under another
    /// request ID is rejected so request churn cannot create ambiguous
    /// correlation or consume another capacity slot.
    fn enqueue_expected(
        &mut self,
        envelope_bytes: &[u8],
        expected_kind: DenuoOutboxMessageKind,
        expected_content_id: ObjectHash,
        created_at_unix: u64,
    ) -> Result<DenuoOutboxEnqueue, ShakedexError> {
        self.validate()?;
        let canonical = canonical_publication(envelope_bytes)?;
        if canonical.message_kind != expected_kind || canonical.content_id != expected_content_id {
            return Err(ShakedexError::InvalidDenuoOutboxEnvelope);
        }
        if let Some(existing) = self.entry(canonical.envelope_id) {
            return if existing.envelope_bytes == envelope_bytes
                && existing.message_kind == canonical.message_kind
                && existing.content_id == canonical.content_id
                && existing.request_id == canonical.request_id
            {
                Ok(DenuoOutboxEnqueue::Existing(canonical.envelope_id))
            } else {
                Err(ShakedexError::DenuoOutboxConflict)
            };
        }
        if self.entries.iter().any(|entry| {
            entry.request_id == canonical.request_id
                || (entry.message_kind == canonical.message_kind
                    && entry.content_id == canonical.content_id)
        }) {
            return Err(ShakedexError::DenuoOutboxConflict);
        }
        if self.entries.len() >= MAX_DENUO_OUTBOX_ENTRIES {
            return Err(ShakedexError::DenuoOutboxCapacity);
        }
        let entry = DenuoOutboxEntry {
            envelope_id: canonical.envelope_id,
            content_id: canonical.content_id,
            message_kind: canonical.message_kind,
            request_id: canonical.request_id,
            envelope_bytes: envelope_bytes.to_vec(),
            state: DenuoOutboxState::Pending,
            retry_attempts: 0,
            created_at_unix,
            last_attempt_at_unix: None,
            acceptance: None,
        };
        self.entries.push(entry);
        self.entries.sort_by_key(|entry| entry.envelope_id);
        if self.validate().is_err() {
            self.entries
                .retain(|entry| entry.envelope_id != canonical.envelope_id);
            return Err(ShakedexError::DenuoOutboxCapacity);
        }
        Ok(DenuoOutboxEnqueue::Inserted(canonical.envelope_id))
    }

    fn prepared_entry(&self) -> Option<&DenuoOutboxEntry> {
        self.entries
            .iter()
            .find(|entry| matches!(entry.state, DenuoOutboxState::HandoffPrepared { .. }))
    }

    fn next_due_index(&self, now_unix: u64) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let due_at_unix = match entry.state {
                    DenuoOutboxState::Pending => entry.created_at_unix,
                    DenuoOutboxState::RetryScheduled {
                        next_attempt_at_unix,
                    } => next_attempt_at_unix,
                    DenuoOutboxState::HandoffPrepared { .. }
                    | DenuoOutboxState::RelayAccepted { .. }
                    | DenuoOutboxState::DirectAnnounced { .. }
                    | DenuoOutboxState::Acknowledged { .. }
                    | DenuoOutboxState::Exhausted { .. } => return None,
                };
                (due_at_unix <= now_unix).then_some((
                    (due_at_unix, entry.created_at_unix, entry.envelope_id),
                    index,
                ))
            })
            .min_by_key(|(key, _)| *key)
            .map(|(_, index)| index)
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        if self.schema_version != DENUO_OUTBOX_SCHEMA_VERSION
            || self.entries.len() > MAX_DENUO_OUTBOX_ENTRIES
            || self
                .entries
                .windows(2)
                .any(|window| window[0].envelope_id >= window[1].envelope_id)
        {
            return Err(ShakedexError::CorruptDenuoOutbox);
        }
        let mut prepared_entries = 0usize;
        let mut request_ids = BTreeSet::new();
        let mut message_identities = BTreeSet::new();
        let mut receipt_ids = BTreeSet::new();
        for entry in &self.entries {
            validate_entry(entry)?;
            if matches!(entry.state, DenuoOutboxState::HandoffPrepared { .. }) {
                prepared_entries += 1;
            }
            if !request_ids.insert(entry.request_id)
                || !message_identities.insert((entry.message_kind, entry.content_id))
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
            if let Some(acceptance) = &entry.acceptance
                && !receipt_ids.insert(acceptance.receipt_id)
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        if prepared_entries > 1 {
            return Err(ShakedexError::CorruptDenuoOutbox);
        }
        let encoded = serde_json::to_vec(&PersistedDenuoPublicationOutboxRef {
            schema_version: self.schema_version,
            entries: &self.entries,
        })
        .map_err(|_| ShakedexError::CorruptDenuoOutbox)?;
        if encoded.len() > MAX_DENUO_OUTBOX_SERIALIZED_BYTES {
            return Err(ShakedexError::CorruptDenuoOutbox);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoOutboxEnqueue {
    Inserted(ObjectHash),
    Existing(ObjectHash),
}

impl DenuoOutboxEnqueue {
    pub const fn envelope_id(self) -> ObjectHash {
        match self {
            Self::Inserted(envelope_id) | Self::Existing(envelope_id) => envelope_id,
        }
    }

    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

/// Exact handoff material returned only after `HandoffPrepared` is durable.
/// It is local crash-recovery state, not peer acceptance or publication proof.
/// Private fields and the absence of serialization and cloning prevent
/// ordinary construction or accidental copying of a correlated artifact.
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPreparedHandoff;
/// let _ = DenuoPreparedHandoff {};
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPreparedHandoff;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<DenuoPreparedHandoff>();
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPreparedHandoff;
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<DenuoPreparedHandoff>();
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPreparedHandoff;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<DenuoPreparedHandoff>();
/// ```
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPreparedHandoff;
/// fn requires_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// requires_deserialize::<DenuoPreparedHandoff>();
/// ```
pub struct DenuoPreparedHandoff {
    outbox_revision: u64,
    envelope_id: ObjectHash,
    content_id: ObjectHash,
    message_kind: DenuoOutboxMessageKind,
    request_id: u64,
    attempt_id: ObjectHash,
    attempt_ordinal: u16,
    prepared_at_unix: u64,
    envelope_bytes: Vec<u8>,
}

impl DenuoPreparedHandoff {
    pub const fn outbox_revision(&self) -> u64 {
        self.outbox_revision
    }

    pub const fn envelope_id(&self) -> ObjectHash {
        self.envelope_id
    }

    pub const fn content_id(&self) -> ObjectHash {
        self.content_id
    }

    pub const fn message_kind(&self) -> DenuoOutboxMessageKind {
        self.message_kind
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn attempt_id(&self) -> ObjectHash {
        self.attempt_id
    }

    pub const fn attempt_ordinal(&self) -> u16 {
        self.attempt_ordinal
    }

    pub const fn prepared_at_unix(&self) -> u64 {
        self.prepared_at_unix
    }

    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    fn matches(&self, revision: u64, entry: &DenuoOutboxEntry) -> bool {
        let DenuoOutboxState::HandoffPrepared {
            attempt_id,
            prepared_at_unix,
        } = entry.state
        else {
            return false;
        };
        self.outbox_revision == revision
            && self.envelope_id == entry.envelope_id
            && self.content_id == entry.content_id
            && self.message_kind == entry.message_kind
            && self.request_id == entry.request_id
            && self.attempt_id == attempt_id
            && self.attempt_ordinal == entry.retry_attempts + 1
            && self.prepared_at_unix == prepared_at_unix
            && self.envelope_bytes == entry.envelope_bytes
    }

    fn matches_identity(&self, entry: &DenuoOutboxEntry) -> bool {
        self.envelope_id == entry.envelope_id
            && self.content_id == entry.content_id
            && self.message_kind == entry.message_kind
            && self.request_id == entry.request_id
            && self.attempt_ordinal == entry.retry_attempts + 1
            && self.envelope_bytes == entry.envelope_bytes
    }
}

pub enum DenuoHandoffPreparation {
    NoDue { outbox_revision: u64 },
    Prepared(DenuoPreparedHandoff),
    Existing(DenuoPreparedHandoff),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoHandoffFailureResult {
    outbox_revision: u64,
    envelope_id: ObjectHash,
    state: DenuoOutboxState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoHandoffAcceptanceResult {
    Inserted(DenuoPublicationAcceptanceSnapshot),
    Existing(DenuoPublicationAcceptanceSnapshot),
}

/// Durable result of one exact direct-wallet transport write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoHandoffDirectAnnouncement {
    outbox_revision: u64,
    envelope_id: ObjectHash,
}

impl DenuoHandoffDirectAnnouncement {
    pub const fn outbox_revision(self) -> u64 {
        self.outbox_revision
    }
    pub const fn envelope_id(self) -> ObjectHash {
        self.envelope_id
    }
}

impl DenuoHandoffAcceptanceResult {
    pub const fn snapshot(self) -> DenuoPublicationAcceptanceSnapshot {
        match self {
            Self::Inserted(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

impl DenuoHandoffFailureResult {
    pub const fn outbox_revision(self) -> u64 {
        self.outbox_revision
    }

    pub const fn envelope_id(self) -> ObjectHash {
        self.envelope_id
    }

    pub const fn state(self) -> DenuoOutboxState {
        self.state
    }
}

/// Persist exactly one deterministic due handoff before returning its bytes.
/// An already prepared attempt is returned unchanged and blocks preparation of
/// every other entry. This function performs no network I/O.
pub fn prepare_next_denuo_handoff(
    store: &mut WalletStore,
    expected_revision: u64,
    prepared_at_unix: u64,
) -> Result<DenuoHandoffPreparation, ShakedexError> {
    let mut stored = load_denuo_publication_outbox(store)?;
    if stored.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    if prepared_at_unix < stored.updated_at_unix {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    if let Some(entry) = stored.outbox.prepared_entry() {
        return prepared_handoff_from_entry(stored.revision, entry)
            .map(DenuoHandoffPreparation::Existing);
    }
    let Some(index) = stored.outbox.next_due_index(prepared_at_unix) else {
        return Ok(DenuoHandoffPreparation::NoDue {
            outbox_revision: stored.revision,
        });
    };
    let entry = &mut stored.outbox.entries[index];
    let attempt_ordinal = entry
        .retry_attempts
        .checked_add(1)
        .filter(|attempt| *attempt <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
        .ok_or(ShakedexError::DenuoOutboxRetryLimit)?;
    let attempt_id = denuo_handoff_attempt_id(
        entry.envelope_id,
        entry.request_id,
        attempt_ordinal,
        prepared_at_unix,
    );
    entry.state = DenuoOutboxState::HandoffPrepared {
        attempt_id,
        prepared_at_unix,
    };
    let revision =
        save_denuo_publication_outbox(store, expected_revision, &stored.outbox, prepared_at_unix)?;
    prepared_handoff_from_entry(revision, &stored.outbox.entries[index])
        .map(DenuoHandoffPreparation::Prepared)
}

/// Reload the single durable outcome-unknown handoff after a crash or restart.
pub fn load_prepared_denuo_handoff(
    store: &WalletStore,
) -> Result<Option<DenuoPreparedHandoff>, ShakedexError> {
    let stored = load_denuo_publication_outbox(store)?;
    stored
        .outbox
        .prepared_entry()
        .map(|entry| prepared_handoff_from_entry(stored.revision, entry))
        .transpose()
}

/// Persist endpoint-signed transport acceptance for one exact durable
/// handoff. This does not prove board inclusion, current listing authority,
/// chain state, price/quote authority, or authorization to move value.
pub fn record_denuo_handoff_acceptance(
    store: &mut WalletStore,
    handoff: &DenuoPreparedHandoff,
    policy: &DenuoPublicationAcceptancePolicy,
    receipt_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoHandoffAcceptanceResult, ShakedexError> {
    let canonical = canonical_publication(&handoff.envelope_bytes)?;
    if canonical.envelope_id != handoff.envelope_id
        || canonical.content_id != handoff.content_id
        || canonical.message_kind != handoff.message_kind
        || canonical.request_id != handoff.request_id
    {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    let expected = acceptance_expectation(handoff, &canonical);
    let acceptance =
        validate_denuo_publication_acceptance(policy, expected, receipt_bytes, accepted_at_unix)?;
    let mut stored = load_denuo_publication_outbox(store)?;
    let index = stored
        .outbox
        .entries
        .iter()
        .position(|entry| entry.envelope_id == handoff.envelope_id)
        .ok_or(ShakedexError::DenuoOutboxHandoffMismatch)?;

    if let DenuoOutboxState::RelayAccepted {
        receipt_id,
        accepted_at_unix: durable_accepted_at,
    } = stored.outbox.entries[index].state
    {
        let entry = &stored.outbox.entries[index];
        let durable = entry
            .acceptance
            .as_ref()
            .ok_or(ShakedexError::CorruptDenuoOutbox)?;
        if handoff.matches_identity(entry)
            && handoff.attempt_id == expected.attempt_id
            && handoff.prepared_at_unix == expected.prepared_at_unix
            && receipt_id == acceptance.receipt_id
            && durable_accepted_at == accepted_at_unix
            && durable == &acceptance
        {
            return Ok(DenuoHandoffAcceptanceResult::Existing(acceptance_snapshot(
                stored.revision,
                entry,
                expected.attempt_id,
                durable,
            )));
        }
        return Err(ShakedexError::DenuoPublicationAcceptanceConflict);
    }

    if stored.revision != handoff.outbox_revision {
        return Err(ShakedexError::StaleRevision);
    }
    let entry = &mut stored.outbox.entries[index];
    if !handoff.matches(stored.revision, entry) {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    entry.state = DenuoOutboxState::RelayAccepted {
        receipt_id: acceptance.receipt_id,
        accepted_at_unix,
    };
    entry.last_attempt_at_unix = Some(accepted_at_unix);
    entry.acceptance = Some(acceptance);
    let revision =
        save_denuo_publication_outbox(store, stored.revision, &stored.outbox, accepted_at_unix)?;
    let entry = &stored.outbox.entries[index];
    let acceptance = entry
        .acceptance
        .as_ref()
        .ok_or(ShakedexError::CorruptDenuoOutbox)?;
    Ok(DenuoHandoffAcceptanceResult::Inserted(acceptance_snapshot(
        revision,
        entry,
        expected.attempt_id,
        acceptance,
    )))
}

/// Record only the local fact that one exact prepared envelope was written to
/// a negotiated direct wallet peer after admission to this wallet's own board.
/// This is not a remote acknowledgement, inclusion proof, or authority grant.
pub fn record_denuo_handoff_direct_announcement(
    store: &mut WalletStore,
    handoff: &DenuoPreparedHandoff,
    announced_at_unix: u64,
) -> Result<DenuoHandoffDirectAnnouncement, ShakedexError> {
    let canonical = canonical_publication(handoff.envelope_bytes())?;
    if canonical.envelope_id != handoff.envelope_id()
        || canonical.content_id != handoff.content_id()
        || canonical.message_kind != handoff.message_kind()
        || canonical.request_id != handoff.request_id()
    {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    let mut stored = load_denuo_publication_outbox(store)?;
    let index = stored
        .outbox
        .entries
        .iter()
        .position(|entry| entry.envelope_id == handoff.envelope_id())
        .ok_or(ShakedexError::DenuoOutboxHandoffMismatch)?;
    if let DenuoOutboxState::DirectAnnounced {
        attempt_id,
        announced_at_unix: durable_at,
        ..
    } = stored.outbox.entries[index].state
    {
        let entry = &stored.outbox.entries[index];
        if handoff.matches_identity(entry)
            && attempt_id == handoff.attempt_id()
            && durable_at == announced_at_unix
        {
            return Ok(DenuoHandoffDirectAnnouncement {
                outbox_revision: stored.revision,
                envelope_id: handoff.envelope_id(),
            });
        }
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    if stored.revision != handoff.outbox_revision() {
        return Err(ShakedexError::StaleRevision);
    }
    let entry = &mut stored.outbox.entries[index];
    if !handoff.matches(stored.revision, entry) || announced_at_unix < handoff.prepared_at_unix() {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    entry.state = DenuoOutboxState::DirectAnnounced {
        attempt_id: handoff.attempt_id(),
        prepared_at_unix: handoff.prepared_at_unix(),
        announced_at_unix,
    };
    entry.last_attempt_at_unix = Some(announced_at_unix);
    let revision =
        save_denuo_publication_outbox(store, stored.revision, &stored.outbox, announced_at_unix)?;
    Ok(DenuoHandoffDirectAnnouncement {
        outbox_revision: revision,
        envelope_id: handoff.envelope_id(),
    })
}

/// Persist a locally observed handoff failure. Consuming the exact artifact
/// correlates the result to the bytes durably prepared before handoff.
pub fn record_denuo_handoff_failure(
    store: &mut WalletStore,
    handoff: DenuoPreparedHandoff,
    failed_at_unix: u64,
    next_attempt_at_unix: u64,
) -> Result<DenuoHandoffFailureResult, ShakedexError> {
    let stored = load_denuo_publication_outbox(store)?;
    if stored.revision != handoff.outbox_revision {
        return Err(ShakedexError::StaleRevision);
    }
    let entry = stored
        .outbox
        .prepared_entry()
        .ok_or(ShakedexError::DenuoOutboxHandoffMismatch)?;
    if !handoff.matches(stored.revision, entry) {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    persist_denuo_handoff_failure(
        store,
        stored,
        handoff.attempt_id,
        failed_at_unix,
        next_attempt_at_unix,
    )
}

/// Resolve an outcome-unknown prepared handoff after restart as one failed
/// attempt. Recovery never assumes peer acceptance and retries the same exact
/// envelope and request ID after the supplied backoff.
pub fn recover_denuo_handoff_as_retry(
    store: &mut WalletStore,
    expected_revision: u64,
    attempt_id: ObjectHash,
    observed_at_unix: u64,
    next_attempt_at_unix: u64,
) -> Result<DenuoHandoffFailureResult, ShakedexError> {
    let stored = load_denuo_publication_outbox(store)?;
    if stored.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    let entry = stored
        .outbox
        .prepared_entry()
        .ok_or(ShakedexError::DenuoOutboxHandoffMismatch)?;
    if !matches!(
        entry.state,
        DenuoOutboxState::HandoffPrepared {
            attempt_id: current,
            ..
        } if current == attempt_id
    ) {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    }
    persist_denuo_handoff_failure(
        store,
        stored,
        attempt_id,
        observed_at_unix,
        next_attempt_at_unix,
    )
}

pub(crate) struct DenuoAcceptedReplay {
    pub(crate) envelope_bytes: Vec<u8>,
    pub(crate) network_magic: u32,
    pub(crate) network_genesis: [u8; 32],
    pub(crate) attempt_id: [u8; 32],
    pub(crate) record_sequence: u64,
    pub(crate) prepared_at_unix: u64,
    pub(crate) envelope_id: [u8; 32],
    pub(crate) envelope_digest: [u8; 32],
    pub(crate) content_id: [u8; 32],
    pub(crate) message_kind: DenuoOutboxMessageKind,
    pub(crate) request_id: u64,
}

pub struct StoredDenuoPublicationOutbox {
    pub revision: u64,
    pub updated_at_unix: u64,
    pub outbox: DenuoPublicationOutbox,
}

pub(crate) fn accepted_denuo_replays(
    store: &WalletStore,
) -> Result<Vec<DenuoAcceptedReplay>, ShakedexError> {
    let stored = load_denuo_publication_outbox(store)?;
    let mut entries = stored
        .outbox
        .entries
        .iter()
        .filter(|entry| matches!(entry.state, DenuoOutboxState::RelayAccepted { .. }))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| (entry.created_at_unix, entry.message_kind, entry.request_id));
    entries
        .into_iter()
        .map(|entry| {
            let acceptance = entry
                .acceptance
                .as_ref()
                .ok_or(ShakedexError::CorruptDenuoOutbox)?;
            let expected = validate_persisted_denuo_publication_acceptance(acceptance)?;
            Ok(DenuoAcceptedReplay {
                envelope_bytes: entry.envelope_bytes.clone(),
                network_magic: expected.network_magic,
                network_genesis: expected.network_genesis.into_bytes(),
                attempt_id: expected.attempt_id.into_bytes(),
                record_sequence: expected.record_sequence,
                prepared_at_unix: expected.prepared_at_unix,
                envelope_id: expected.envelope_id.into_bytes(),
                envelope_digest: expected.envelope_digest.into_bytes(),
                content_id: expected.content_id.into_bytes(),
                message_kind: expected.message_kind,
                request_id: expected.request_id,
            })
        })
        .collect()
}

pub fn load_denuo_publication_outbox(
    store: &WalletStore,
) -> Result<StoredDenuoPublicationOutbox, ShakedexError> {
    match store.denuo_board_object::<PersistedDenuoPublicationOutbox>(DENUO_OUTBOX_RECORD_ID)? {
        Some(stored) => {
            let source_schema_version = stored.value.schema_version;
            if !matches!(
                source_schema_version,
                LEGACY_DENUO_OUTBOX_SCHEMA_VERSION
                    | HANDOFF_DENUO_OUTBOX_SCHEMA_VERSION
                    | RELAY_DENUO_OUTBOX_SCHEMA_VERSION
                    | DENUO_OUTBOX_SCHEMA_VERSION
            ) || stored
                .value
                .entries
                .iter()
                .any(|entry| match source_schema_version {
                    LEGACY_DENUO_OUTBOX_SCHEMA_VERSION => {
                        matches!(
                            entry.state,
                            DenuoOutboxState::HandoffPrepared { .. }
                                | DenuoOutboxState::RelayAccepted { .. }
                        ) || entry.acceptance.is_some()
                    }
                    HANDOFF_DENUO_OUTBOX_SCHEMA_VERSION => {
                        matches!(
                            entry.state,
                            DenuoOutboxState::Acknowledged { .. }
                                | DenuoOutboxState::RelayAccepted { .. }
                        ) || entry.acceptance.is_some()
                    }
                    RELAY_DENUO_OUTBOX_SCHEMA_VERSION | DENUO_OUTBOX_SCHEMA_VERSION => false,
                    _ => true,
                })
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
            let outbox = DenuoPublicationOutbox {
                schema_version: DENUO_OUTBOX_SCHEMA_VERSION,
                entries: stored.value.entries,
            };
            outbox.validate()?;
            validate_record_time(&outbox, stored.updated_at_unix)
                .map_err(|_| ShakedexError::CorruptDenuoOutbox)?;
            Ok(StoredDenuoPublicationOutbox {
                revision: stored.revision,
                updated_at_unix: stored.updated_at_unix,
                outbox,
            })
        }
        None => Ok(StoredDenuoPublicationOutbox {
            revision: 0,
            updated_at_unix: 0,
            outbox: DenuoPublicationOutbox::default(),
        }),
    }
}

fn prepared_handoff_from_entry(
    outbox_revision: u64,
    entry: &DenuoOutboxEntry,
) -> Result<DenuoPreparedHandoff, ShakedexError> {
    let DenuoOutboxState::HandoffPrepared {
        attempt_id,
        prepared_at_unix,
    } = entry.state
    else {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    };
    let attempt_ordinal = entry
        .retry_attempts
        .checked_add(1)
        .filter(|attempt| *attempt <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
        .ok_or(ShakedexError::CorruptDenuoOutbox)?;
    Ok(DenuoPreparedHandoff {
        outbox_revision,
        envelope_id: entry.envelope_id,
        content_id: entry.content_id,
        message_kind: entry.message_kind,
        request_id: entry.request_id,
        attempt_id,
        attempt_ordinal,
        prepared_at_unix,
        envelope_bytes: entry.envelope_bytes.clone(),
    })
}

fn acceptance_expectation(
    handoff: &DenuoPreparedHandoff,
    canonical: &CanonicalPublication,
) -> DenuoAcceptanceExpectation {
    DenuoAcceptanceExpectation {
        network_magic: canonical.network_magic,
        network_genesis: canonical.network_genesis,
        attempt_id: handoff.attempt_id,
        record_sequence: u64::from(handoff.attempt_ordinal),
        prepared_at_unix: handoff.prepared_at_unix,
        envelope_id: handoff.envelope_id,
        envelope_digest: exact_envelope_digest(&handoff.envelope_bytes),
        content_id: handoff.content_id,
        message_kind: handoff.message_kind,
        request_id: handoff.request_id,
    }
}

fn acceptance_snapshot(
    outbox_revision: u64,
    entry: &DenuoOutboxEntry,
    attempt_id: ObjectHash,
    acceptance: &PersistedDenuoPublicationAcceptance,
) -> DenuoPublicationAcceptanceSnapshot {
    DenuoPublicationAcceptanceSnapshot {
        outbox_revision,
        envelope_id: entry.envelope_id,
        content_id: entry.content_id,
        message_kind: entry.message_kind,
        request_id: entry.request_id,
        attempt_id,
        receipt_id: acceptance.receipt_id,
        policy_fingerprint: acceptance.policy_fingerprint,
        accepted_at_unix: acceptance.accepted_at_unix,
        receipt_expires_at_unix: acceptance.receipt_expires_at_unix,
    }
}

fn persist_denuo_handoff_failure(
    store: &mut WalletStore,
    mut stored: StoredDenuoPublicationOutbox,
    attempt_id: ObjectHash,
    failed_at_unix: u64,
    next_attempt_at_unix: u64,
) -> Result<DenuoHandoffFailureResult, ShakedexError> {
    let entry = stored
        .outbox
        .entries
        .iter_mut()
        .find(|entry| {
            matches!(
                entry.state,
                DenuoOutboxState::HandoffPrepared {
                    attempt_id: current,
                    ..
                } if current == attempt_id
            )
        })
        .ok_or(ShakedexError::DenuoOutboxHandoffMismatch)?;
    let DenuoOutboxState::HandoffPrepared {
        prepared_at_unix, ..
    } = entry.state
    else {
        return Err(ShakedexError::DenuoOutboxHandoffMismatch);
    };
    if failed_at_unix < prepared_at_unix || next_attempt_at_unix <= failed_at_unix {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    entry.retry_attempts = entry
        .retry_attempts
        .checked_add(1)
        .filter(|attempts| *attempts <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
        .ok_or(ShakedexError::DenuoOutboxRetryLimit)?;
    entry.last_attempt_at_unix = Some(failed_at_unix);
    entry.state = if entry.retry_attempts == MAX_DENUO_OUTBOX_RETRY_ATTEMPTS {
        DenuoOutboxState::Exhausted {
            exhausted_at_unix: failed_at_unix,
        }
    } else {
        DenuoOutboxState::RetryScheduled {
            next_attempt_at_unix,
        }
    };
    let envelope_id = entry.envelope_id;
    let state = entry.state;
    let revision =
        save_denuo_publication_outbox(store, stored.revision, &stored.outbox, failed_at_unix)?;
    Ok(DenuoHandoffFailureResult {
        outbox_revision: revision,
        envelope_id,
        state,
    })
}

fn denuo_handoff_attempt_id(
    envelope_id: ObjectHash,
    request_id: u64,
    attempt_ordinal: u16,
    prepared_at_unix: u64,
) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(DENUO_OUTBOX_ATTEMPT_ID_DOMAIN);
    hasher.update(envelope_id.into_bytes());
    hasher.update(request_id.to_be_bytes());
    hasher.update(attempt_ordinal.to_be_bytes());
    hasher.update(prepared_at_unix.to_be_bytes());
    ObjectHash::new(hasher.finalize().into())
}

pub fn save_denuo_publication_outbox(
    store: &mut WalletStore,
    expected_revision: u64,
    outbox: &DenuoPublicationOutbox,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    outbox.validate()?;
    validate_record_time(outbox, updated_at_unix)?;
    if let Some(revision) =
        validate_outbox_save_transition(store, expected_revision, outbox, updated_at_unix)?
    {
        return Ok(revision);
    }
    store
        .save_denuo_board_object(
            DENUO_OUTBOX_RECORD_ID,
            expected_revision,
            &PersistedDenuoPublicationOutboxRef {
                schema_version: outbox.schema_version,
                entries: &outbox.entries,
            },
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}

/// Atomically persist a seller-offer workflow transition and enqueue its exact
/// canonical offer envelope. A crash can therefore expose neither an
/// unjournaled publication nor a workflow that claims a publication which was
/// never durably handed to the outbox.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enqueue_denuo_offer_and_save_workflow<W: Serialize>(
    store: &mut WalletStore,
    workflow_id: WorkflowId,
    expected_workflow_revision: u64,
    workflow: &W,
    envelope_bytes: &[u8],
    listing: &AuthenticatedFixedPriceListing,
    updated_at_unix: u64,
) -> Result<(u64, u64, ObjectHash), ShakedexError> {
    let mut stored = load_denuo_publication_outbox(store)?;
    let enqueue = stored
        .outbox
        .enqueue_offer(envelope_bytes, listing, updated_at_unix)?;
    if !enqueue.inserted() {
        return Err(ShakedexError::DenuoOutboxConflict);
    }
    validate_record_time(&stored.outbox, updated_at_unix)?;
    validate_outbox_save_transition(store, stored.revision, &stored.outbox, updated_at_unix)?;
    let outbox_revision = stored
        .revision
        .checked_add(1)
        .ok_or(ShakedexError::Invariant)?;
    let outbox_save = EntityBatchSave {
        id: DENUO_OUTBOX_RECORD_ID.to_vec(),
        expected_revision: stored.revision,
        value: PersistedDenuoPublicationOutboxRef {
            schema_version: stored.outbox.schema_version,
            entries: &stored.outbox.entries,
        },
        updated_at_unix,
    };
    let workflow_revision = store.save_workflow_with_entity_batch(
        workflow_id,
        WorkflowKind::ShakedexSellerOffer,
        expected_workflow_revision,
        workflow,
        false,
        updated_at_unix,
        EntityKind::DenuoBoardObject,
        std::slice::from_ref(&outbox_save),
        &[],
    )?;
    Ok((workflow_revision, outbox_revision, enqueue.envelope_id()))
}

/// Atomically persist a seller-offer cancellation transition and enqueue the
/// exact authenticated Denuo cancellation. This preserves the same crash
/// boundary as offer publication: neither half can become durable alone.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enqueue_denuo_cancellation_and_save_workflow<W: Serialize>(
    store: &mut WalletStore,
    workflow_id: WorkflowId,
    expected_workflow_revision: u64,
    workflow: &W,
    envelope_bytes: &[u8],
    cancellation: &VerifiedListingCancellation,
    updated_at_unix: u64,
) -> Result<(u64, u64, ObjectHash), ShakedexError> {
    let mut stored = load_denuo_publication_outbox(store)?;
    let enqueue =
        stored
            .outbox
            .enqueue_cancellation(envelope_bytes, cancellation, updated_at_unix)?;
    if !enqueue.inserted() {
        return Err(ShakedexError::DenuoOutboxConflict);
    }
    validate_record_time(&stored.outbox, updated_at_unix)?;
    validate_outbox_save_transition(store, stored.revision, &stored.outbox, updated_at_unix)?;
    let outbox_revision = stored
        .revision
        .checked_add(1)
        .ok_or(ShakedexError::Invariant)?;
    let outbox_save = EntityBatchSave {
        id: DENUO_OUTBOX_RECORD_ID.to_vec(),
        expected_revision: stored.revision,
        value: PersistedDenuoPublicationOutboxRef {
            schema_version: stored.outbox.schema_version,
            entries: &stored.outbox.entries,
        },
        updated_at_unix,
    };
    let workflow_revision = store.save_workflow_with_entity_batch(
        workflow_id,
        WorkflowKind::ShakedexSellerOffer,
        expected_workflow_revision,
        workflow,
        false,
        updated_at_unix,
        EntityKind::DenuoBoardObject,
        std::slice::from_ref(&outbox_save),
        &[],
    )?;
    Ok((workflow_revision, outbox_revision, enqueue.envelope_id()))
}

fn validate_outbox_save_transition(
    store: &WalletStore,
    expected_revision: u64,
    next: &DenuoPublicationOutbox,
    updated_at_unix: u64,
) -> Result<Option<u64>, ShakedexError> {
    let current = load_denuo_publication_outbox(store)?;
    if current.revision == 0 {
        if expected_revision != 0 {
            return Err(ShakedexError::StaleRevision);
        }
        if next.entries.iter().any(|entry| {
            !matches!(entry.state, DenuoOutboxState::Pending)
                || entry.retry_attempts != 0
                || entry.last_attempt_at_unix.is_some()
                || entry.acceptance.is_some()
        }) {
            return Err(ShakedexError::InvalidDenuoOutboxTransition);
        }
        return Ok(None);
    }
    if updated_at_unix < current.updated_at_unix {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    if current.outbox == *next
        && (expected_revision == current.revision
            || expected_revision.checked_add(1) == Some(current.revision))
    {
        return Ok(Some(current.revision));
    }
    if current.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    for current_entry in &current.outbox.entries {
        let next_entry = next
            .entry(current_entry.envelope_id)
            .ok_or(ShakedexError::InvalidDenuoOutboxTransition)?;
        validate_entry_save_transition(current_entry, next_entry)?;
    }
    for next_entry in &next.entries {
        if current.outbox.entry(next_entry.envelope_id).is_none()
            && (!matches!(next_entry.state, DenuoOutboxState::Pending)
                || next_entry.retry_attempts != 0
                || next_entry.last_attempt_at_unix.is_some()
                || next_entry.acceptance.is_some())
        {
            return Err(ShakedexError::InvalidDenuoOutboxTransition);
        }
    }
    Ok(None)
}

fn validate_entry_save_transition(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
) -> Result<(), ShakedexError> {
    if current.envelope_id != next.envelope_id
        || current.content_id != next.content_id
        || current.message_kind != next.message_kind
        || current.request_id != next.request_id
        || current.envelope_bytes != next.envelope_bytes
        || current.created_at_unix != next.created_at_unix
    {
        return Err(ShakedexError::DenuoOutboxConflict);
    }
    if current == next {
        return Ok(());
    }
    match (current.state, next.state) {
        (DenuoOutboxState::Pending, DenuoOutboxState::HandoffPrepared { .. }) => {
            validate_handoff_preparation(current, next, None)?
        }
        (
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix,
            },
            DenuoOutboxState::HandoffPrepared { .. },
        ) => validate_handoff_preparation(current, next, Some(next_attempt_at_unix))?,
        (
            DenuoOutboxState::HandoffPrepared { .. },
            DenuoOutboxState::RetryScheduled { .. } | DenuoOutboxState::Exhausted { .. },
        ) => validate_handoff_failure(current, next)?,
        (DenuoOutboxState::HandoffPrepared { .. }, DenuoOutboxState::RelayAccepted { .. }) => {
            validate_handoff_acceptance(current, next)?
        }
        (DenuoOutboxState::HandoffPrepared { .. }, DenuoOutboxState::DirectAnnounced { .. }) => {
            validate_handoff_direct_announcement(current, next)?
        }
        _ => return Err(ShakedexError::InvalidDenuoOutboxTransition),
    }
    Ok(())
}

fn validate_handoff_preparation(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
    due_at_unix: Option<u64>,
) -> Result<(), ShakedexError> {
    let DenuoOutboxState::HandoffPrepared {
        attempt_id,
        prepared_at_unix,
    } = next.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    let attempt_ordinal = current
        .retry_attempts
        .checked_add(1)
        .ok_or(ShakedexError::InvalidDenuoOutboxTransition)?;
    if current.retry_attempts != next.retry_attempts
        || current.last_attempt_at_unix != next.last_attempt_at_unix
        || prepared_at_unix < current.created_at_unix
        || current
            .last_attempt_at_unix
            .is_some_and(|last| prepared_at_unix <= last)
        || due_at_unix.is_some_and(|due| prepared_at_unix < due)
        || attempt_id
            != denuo_handoff_attempt_id(
                current.envelope_id,
                current.request_id,
                attempt_ordinal,
                prepared_at_unix,
            )
    {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    Ok(())
}

fn validate_handoff_failure(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
) -> Result<(), ShakedexError> {
    let DenuoOutboxState::HandoffPrepared {
        prepared_at_unix, ..
    } = current.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    let Some(failed_at_unix) = next.last_attempt_at_unix else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    if current.retry_attempts.checked_add(1) != Some(next.retry_attempts)
        || failed_at_unix < prepared_at_unix
    {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    match next.state {
        DenuoOutboxState::RetryScheduled {
            next_attempt_at_unix,
        } if next.retry_attempts < MAX_DENUO_OUTBOX_RETRY_ATTEMPTS
            && next_attempt_at_unix > failed_at_unix => {}
        DenuoOutboxState::Exhausted { exhausted_at_unix }
            if next.retry_attempts == MAX_DENUO_OUTBOX_RETRY_ATTEMPTS
                && exhausted_at_unix == failed_at_unix => {}
        _ => return Err(ShakedexError::InvalidDenuoOutboxTransition),
    }
    Ok(())
}

fn validate_handoff_acceptance(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
) -> Result<(), ShakedexError> {
    let DenuoOutboxState::HandoffPrepared {
        attempt_id,
        prepared_at_unix,
    } = current.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    let DenuoOutboxState::RelayAccepted {
        receipt_id,
        accepted_at_unix,
    } = next.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    let acceptance = next
        .acceptance
        .as_ref()
        .ok_or(ShakedexError::InvalidDenuoOutboxTransition)?;
    if current.acceptance.is_some()
        || current.retry_attempts != next.retry_attempts
        || next.last_attempt_at_unix != Some(accepted_at_unix)
        || accepted_at_unix < prepared_at_unix
        || receipt_id != acceptance.receipt_id
        || accepted_at_unix != acceptance.accepted_at_unix
    {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    let expected = validate_persisted_denuo_publication_acceptance(acceptance)
        .map_err(|_| ShakedexError::InvalidDenuoOutboxTransition)?;
    if expected.attempt_id != attempt_id || expected.prepared_at_unix != prepared_at_unix {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    Ok(())
}

fn validate_handoff_direct_announcement(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
) -> Result<(), ShakedexError> {
    let DenuoOutboxState::HandoffPrepared {
        attempt_id,
        prepared_at_unix,
    } = current.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    let DenuoOutboxState::DirectAnnounced {
        attempt_id: announced_attempt,
        prepared_at_unix: announced_prepared,
        announced_at_unix,
    } = next.state
    else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    if attempt_id != announced_attempt
        || current.acceptance.is_some()
        || next.acceptance.is_some()
        || current.retry_attempts != next.retry_attempts
        || next.last_attempt_at_unix != Some(announced_at_unix)
        || announced_prepared != prepared_at_unix
        || announced_at_unix < prepared_at_unix
    {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    Ok(())
}

fn validate_record_time(
    outbox: &DenuoPublicationOutbox,
    updated_at_unix: u64,
) -> Result<(), ShakedexError> {
    if outbox.entries.iter().any(|entry| {
        entry.created_at_unix > updated_at_unix
            || entry
                .last_attempt_at_unix
                .is_some_and(|attempt| attempt > updated_at_unix)
            || matches!(
                entry.state,
                DenuoOutboxState::HandoffPrepared {
                    prepared_at_unix,
                    ..
                } if prepared_at_unix > updated_at_unix
            )
            || matches!(
                entry.state,
                DenuoOutboxState::RelayAccepted {
                    accepted_at_unix,
                    ..
                } if accepted_at_unix > updated_at_unix
            )
            || matches!(
                entry.state,
                DenuoOutboxState::DirectAnnounced {
                    announced_at_unix,
                    ..
                } if announced_at_unix > updated_at_unix
            )
            || matches!(
                entry.state,
                DenuoOutboxState::Acknowledged {
                    acknowledged_at_unix
                } if acknowledged_at_unix > updated_at_unix
            )
            || matches!(
                entry.state,
                DenuoOutboxState::Exhausted {
                    exhausted_at_unix
                } if exhausted_at_unix > updated_at_unix
            )
    }) {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    }
    Ok(())
}

struct CanonicalPublication {
    envelope_id: ObjectHash,
    content_id: ObjectHash,
    message_kind: DenuoOutboxMessageKind,
    request_id: u64,
    network_magic: u32,
    network_genesis: ObjectHash,
}

fn canonical_publication(envelope_bytes: &[u8]) -> Result<CanonicalPublication, ShakedexError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_DENUO_OUTBOX_ENVELOPE_BYTES {
        return Err(ShakedexError::InvalidDenuoOutboxEnvelope);
    }
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(envelope_bytes)
        .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?;
    if registry != DenuoRegistryVersion::V2 || request_id == 0 {
        return Err(ShakedexError::InvalidDenuoOutboxEnvelope);
    }
    let (message_kind, content_id, network) = match &message {
        NameMarketMessage::Offer(listing) => (
            DenuoOutboxMessageKind::Offer,
            ObjectHash::new(
                listing
                    .listing_hash()
                    .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?,
            ),
            listing.network(),
        ),
        NameMarketMessage::Cancel(cancellation) => (
            DenuoOutboxMessageKind::Cancellation,
            ObjectHash::new(
                cancellation
                    .cancellation_hash()
                    .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?,
            ),
            cancellation.network,
        ),
        _ => return Err(ShakedexError::InvalidDenuoOutboxEnvelope),
    };
    let reencoded = message
        .encode_envelope(registry, request_id)
        .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?;
    if reencoded != envelope_bytes {
        return Err(ShakedexError::InvalidDenuoOutboxEnvelope);
    }
    let mut hasher = Sha256::new();
    hasher.update(DENUO_OUTBOX_ENVELOPE_ID_DOMAIN);
    hasher.update(envelope_bytes);
    Ok(CanonicalPublication {
        envelope_id: ObjectHash::new(hasher.finalize().into()),
        content_id,
        message_kind,
        request_id,
        network_magic: network.magic,
        network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
    })
}

fn exact_envelope_digest(envelope_bytes: &[u8]) -> ObjectHash {
    ObjectHash::new(Sha256::digest(envelope_bytes).into())
}

fn validate_entry(entry: &DenuoOutboxEntry) -> Result<(), ShakedexError> {
    let canonical = canonical_publication(&entry.envelope_bytes)
        .map_err(|_| ShakedexError::CorruptDenuoOutbox)?;
    if canonical.envelope_id != entry.envelope_id
        || canonical.content_id != entry.content_id
        || canonical.message_kind != entry.message_kind
        || canonical.request_id != entry.request_id
        || entry.retry_attempts > MAX_DENUO_OUTBOX_RETRY_ATTEMPTS
        || entry
            .last_attempt_at_unix
            .is_some_and(|attempt| attempt < entry.created_at_unix)
    {
        return Err(ShakedexError::CorruptDenuoOutbox);
    }
    if matches!(entry.state, DenuoOutboxState::RelayAccepted { .. }) != entry.acceptance.is_some() {
        return Err(ShakedexError::CorruptDenuoOutbox);
    }
    match entry.state {
        DenuoOutboxState::Pending => {
            if entry.retry_attempts != 0 || entry.last_attempt_at_unix.is_some() {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::HandoffPrepared {
            attempt_id,
            prepared_at_unix,
        } => {
            let attempt_ordinal = entry
                .retry_attempts
                .checked_add(1)
                .filter(|attempt| *attempt <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
                .ok_or(ShakedexError::CorruptDenuoOutbox)?;
            if (entry.retry_attempts == 0) != entry.last_attempt_at_unix.is_none()
                || prepared_at_unix < entry.created_at_unix
                || entry
                    .last_attempt_at_unix
                    .is_some_and(|attempt| prepared_at_unix <= attempt)
                || attempt_id
                    != denuo_handoff_attempt_id(
                        entry.envelope_id,
                        entry.request_id,
                        attempt_ordinal,
                        prepared_at_unix,
                    )
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::RetryScheduled {
            next_attempt_at_unix,
        } => {
            if entry.retry_attempts == 0
                || entry.retry_attempts >= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS
                || entry
                    .last_attempt_at_unix
                    .is_none_or(|attempt| next_attempt_at_unix <= attempt)
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::RelayAccepted {
            receipt_id,
            accepted_at_unix,
        } => {
            let acceptance = entry
                .acceptance
                .as_ref()
                .ok_or(ShakedexError::CorruptDenuoOutbox)?;
            let expected = validate_persisted_denuo_publication_acceptance(acceptance)?;
            let attempt_ordinal = entry
                .retry_attempts
                .checked_add(1)
                .filter(|attempt| *attempt <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
                .ok_or(ShakedexError::CorruptDenuoOutbox)?;
            if receipt_id != acceptance.receipt_id
                || accepted_at_unix != acceptance.accepted_at_unix
                || entry.last_attempt_at_unix != Some(accepted_at_unix)
                || expected.network_magic != canonical.network_magic
                || expected.network_genesis != canonical.network_genesis
                || expected.record_sequence != u64::from(attempt_ordinal)
                || expected.prepared_at_unix < entry.created_at_unix
                || accepted_at_unix < expected.prepared_at_unix
                || expected.attempt_id
                    != denuo_handoff_attempt_id(
                        entry.envelope_id,
                        entry.request_id,
                        attempt_ordinal,
                        expected.prepared_at_unix,
                    )
                || expected.envelope_id != entry.envelope_id
                || expected.envelope_digest != exact_envelope_digest(&entry.envelope_bytes)
                || expected.content_id != entry.content_id
                || expected.message_kind != entry.message_kind
                || expected.request_id != entry.request_id
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::DirectAnnounced {
            attempt_id,
            prepared_at_unix,
            announced_at_unix,
        } => {
            let attempt_ordinal = entry
                .retry_attempts
                .checked_add(1)
                .filter(|attempt| *attempt <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
                .ok_or(ShakedexError::CorruptDenuoOutbox)?;
            if entry.acceptance.is_some()
                || entry.last_attempt_at_unix != Some(announced_at_unix)
                || announced_at_unix < entry.created_at_unix
                || announced_at_unix < prepared_at_unix
                || attempt_id
                    != denuo_handoff_attempt_id(
                        entry.envelope_id,
                        entry.request_id,
                        attempt_ordinal,
                        prepared_at_unix,
                    )
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::Acknowledged {
            acknowledged_at_unix,
        } => {
            if acknowledged_at_unix < entry.created_at_unix
                || entry
                    .last_attempt_at_unix
                    .is_some_and(|attempt| acknowledged_at_unix < attempt)
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
            if (entry.retry_attempts == 0) != entry.last_attempt_at_unix.is_none() {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        DenuoOutboxState::Exhausted { exhausted_at_unix } => {
            if entry.retry_attempts != MAX_DENUO_OUTBOX_RETRY_ATTEMPTS
                || entry.last_attempt_at_unix != Some(exhausted_at_unix)
                || exhausted_at_unix < entry.created_at_unix
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    use hns_covenants::FinalizeCovenant;
    use hns_marketplace_protocol::DenuoRegistryVersion;
    use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash};
    use hns_swap::{
        FixedPriceListing, ListingCancellation, NetworkBinding, SwapProof, lock_script_hash,
    };
    use hns_transaction::{Address, Coin, Outpoint};
    #[cfg(unix)]
    use hns_wallet_store::WalletStore;
    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::acceptance::signed_acceptance_for_test;
    use crate::{
        DenuoHnsaEndpointBinding, DenuoHrmRootBinding, authenticate_fixed_price_listing,
        verify_listing_cancellation,
    };

    const CREATED_AT: u64 = 1_800_000_200;

    fn acceptance_policy(
        network: NetworkBinding,
        endpoint_key: &SigningKey,
    ) -> DenuoPublicationAcceptancePolicy {
        let endpoint_public_key = endpoint_key.verifying_key().to_encoded_point(true);
        DenuoPublicationAcceptancePolicy::new(
            network,
            DenuoHrmRootBinding {
                subject: ObjectHash::new([0x61; 32]),
                sequence: 7,
                envelope_hash: ObjectHash::new([0x62; 32]),
                chain_height: 500,
                chain_work_be: [0x63; 32],
                chain_anchor: ObjectHash::new([0x64; 32]),
            },
            DenuoHnsaEndpointBinding {
                canonical_service_name: b"relay-market".to_vec(),
                application_profile_id: 0x4452,
                service_resource_id: ObjectHash::new([0x65; 32]),
                service_delegation_id: ObjectHash::new([0x66; 32]),
                service_generation: 3,
                endpoint_delegation_id: ObjectHash::new([0x67; 32]),
                endpoint_sequence: 9,
                endpoint_public_key: endpoint_public_key
                    .as_bytes()
                    .try_into()
                    .expect("compressed endpoint key"),
                effective_not_before_unix: CREATED_AT - 60,
                effective_expires_at_unix: CREATED_AT + 600,
            },
            120,
        )
        .expect("acceptance policy")
    }

    fn publication_fixtures() -> (
        Vec<u8>,
        AuthenticatedFixedPriceListing,
        Vec<u8>,
        VerifiedListingCancellation,
    ) {
        publication_fixtures_with_sequence(41, 101, 102)
    }

    fn publication_fixtures_with_sequence(
        sequence: u64,
        offer_request_id: u64,
        cancellation_request_id: u64,
    ) -> (
        Vec<u8>,
        AuthenticatedFixedPriceListing,
        Vec<u8>,
        VerifiedListingCancellation,
    ) {
        publication_fixtures_with_network_and_sequence(
            NetworkBinding {
                magic: 0x5b6e_c393,
                genesis: BlockHash::new([0x11; 32]),
            },
            sequence,
            offer_request_id,
            cancellation_request_id,
        )
    }

    fn publication_fixtures_with_network_and_sequence(
        network: NetworkBinding,
        sequence: u64,
        offer_request_id: u64,
        cancellation_request_id: u64,
    ) -> (
        Vec<u8>,
        AuthenticatedFixedPriceListing,
        Vec<u8>,
        VerifiedListingCancellation,
    ) {
        let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let mut proof = SwapProof {
            network,
            locking_outpoint: Outpoint {
                transaction_hash: TransactionHash::new([0x22; 32]),
                index: 7,
            },
            name: b"outbox-name".to_vec(),
            seller_public_key,
            payment_address: Address::new(0, vec![0x33; 20]).expect("payment address"),
            price: Dollarydoos::new(12_345_678),
            lock_time_seconds: 1_800_000_000,
            signature: None,
            fee_address: None,
            fee: Dollarydoos::new(0),
        };
        let coin = Coin {
            outpoint: proof.locking_outpoint,
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&proof.seller_public_key).to_vec())
                .expect("lock address"),
            covenant: FinalizeCovenant::new(
                proof.name.clone(),
                Height::new(1),
                false,
                Height::new(0),
                0,
                BlockHash::new([0x55; 32]),
            )
            .expect("finalize covenant")
            .to_covenant()
            .expect("canonical covenant"),
        };
        proof.sign(&coin, &signing_key).expect("signed proof");
        let mut listing = FixedPriceListing {
            proof,
            created_at: CREATED_AT - 100,
            expires_at: CREATED_AT + 3_600,
            sequence,
            signature: None,
        };
        listing.sign(&signing_key).expect("signed listing");
        let listing_bytes = listing.encode().expect("listing bytes");
        let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
        let authenticated = authenticate_fixed_price_listing(&listing_bytes, listing_hash)
            .expect("authenticated listing");
        let offer = NameMarketMessage::Offer(listing.clone())
            .encode_envelope(DenuoRegistryVersion::V2, offer_request_id)
            .expect("offer envelope");

        let mut cancellation = ListingCancellation::for_listing(
            &listing,
            CREATED_AT + 1,
            listing.expires_at + 600,
            sequence + 1,
        )
        .expect("cancellation terms");
        cancellation
            .sign(&signing_key)
            .expect("signed cancellation");
        let cancellation_bytes = cancellation.encode().expect("cancellation bytes");
        let verified = verify_listing_cancellation(
            &cancellation_bytes,
            &authenticated,
            network,
            CREATED_AT + 2,
        )
        .expect("verified cancellation");
        let cancellation = NameMarketMessage::Cancel(cancellation)
            .encode_envelope(DenuoRegistryVersion::V2, cancellation_request_id)
            .expect("cancellation envelope");
        (offer, authenticated, cancellation, verified)
    }

    #[test]
    fn exact_enqueue_is_typed_bounded_and_idempotent() {
        let (offer, listing, cancellation, verified_cancellation) = publication_fixtures();
        let mut outbox = DenuoPublicationOutbox::default();
        let offer_result = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue offer");
        assert!(offer_result.inserted());
        assert_eq!(
            outbox
                .enqueue_offer(&offer, &listing, CREATED_AT + 1)
                .expect("idempotent enqueue"),
            DenuoOutboxEnqueue::Existing(offer_result.envelope_id())
        );
        assert!(
            outbox
                .enqueue_cancellation(&cancellation, &verified_cancellation, CREATED_AT)
                .expect("enqueue cancellation")
                .inserted()
        );
        assert_eq!(outbox.len(), 2);
        assert_eq!(
            outbox.state(offer_result.envelope_id()),
            Some(DenuoOutboxState::Pending)
        );
        outbox.validate().expect("valid outbox");
    }

    #[test]
    fn rejects_noncanonical_family_registry_identity_and_request_churn() {
        let (offer, listing, _, _) = publication_fixtures();
        let listing_hash = listing.listing_hash();
        let mut outbox = DenuoPublicationOutbox::default();
        outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("initial offer");
        let (_, _, message) = NameMarketMessage::decode_envelope(&offer).unwrap();
        let changed_request = message
            .encode_envelope(DenuoRegistryVersion::V2, 999)
            .expect("changed request envelope");
        assert!(matches!(
            outbox.enqueue_expected(
                &changed_request,
                DenuoOutboxMessageKind::Offer,
                listing_hash,
                CREATED_AT,
            ),
            Err(ShakedexError::DenuoOutboxConflict)
        ));
        let v1 = message
            .encode_envelope(DenuoRegistryVersion::V1, 103)
            .expect("v1 envelope");
        assert!(matches!(
            DenuoPublicationOutbox::default().enqueue_expected(
                &v1,
                DenuoOutboxMessageKind::Offer,
                listing_hash,
                CREATED_AT,
            ),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
        assert!(
            message
                .encode_envelope(DenuoRegistryVersion::V2, 0)
                .is_err()
        );
        let inventory = NameMarketMessage::OfferInventory(vec![listing_hash.into_bytes()])
            .encode_envelope(DenuoRegistryVersion::V2, 104)
            .expect("inventory envelope");
        assert!(matches!(
            DenuoPublicationOutbox::default().enqueue_expected(
                &inventory,
                DenuoOutboxMessageKind::Offer,
                listing_hash,
                CREATED_AT,
            ),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
    }

    #[test]
    fn typed_enqueue_rejects_another_authenticated_message_identity() {
        let (offer, listing, cancellation, verified_cancellation) = publication_fixtures();
        let (_, other_listing, _, other_verified_cancellation) =
            publication_fixtures_with_sequence(43, 201, 202);
        let mut outbox = DenuoPublicationOutbox::default();
        assert!(matches!(
            outbox.enqueue_offer(&offer, &other_listing, CREATED_AT),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
        assert!(matches!(
            outbox.enqueue_offer(&cancellation, &listing, CREATED_AT),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
        assert!(matches!(
            outbox.enqueue_cancellation(&offer, &verified_cancellation, CREATED_AT),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
        assert!(matches!(
            outbox.enqueue_cancellation(&cancellation, &other_verified_cancellation, CREATED_AT),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
        assert!(outbox.is_empty());
    }

    #[cfg(unix)]
    struct TestWalletDirectory(PathBuf);

    #[cfg(unix)]
    impl Drop for TestWalletDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn test_wallet_store() -> (TestWalletDirectory, WalletStore, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let temporary_root = std::env::var_os("HNS_WALLET_STORE_TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = temporary_root.join(format!(
            "hns-wallet-shakedex-outbox-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("test wallet directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private test wallet directory");
        let cleanup = TestWalletDirectory(directory.clone());
        let database = directory.join("wallet.sqlite3");
        let store =
            WalletStore::create(&database, "denuo-outbox-test-passphrase").expect("wallet store");
        (cleanup, store, database)
    }

    #[cfg(unix)]
    #[test]
    fn prepare_is_deterministic_single_flight_and_persisted_before_return() {
        let (offer, listing, _, _) = publication_fixtures();
        let (second_offer, second_listing, _, _) = publication_fixtures_with_sequence(43, 201, 202);
        let (_cleanup, mut store, database) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let first_envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT + 5)
            .expect("enqueue later-created offer")
            .envelope_id();
        let second_envelope_id = outbox
            .enqueue_offer(&second_offer, &second_listing, CREATED_AT)
            .expect("enqueue earlier-created offer")
            .envelope_id();
        let mut skipped_persist_before_return = outbox.clone();
        let skipped_entry = skipped_persist_before_return
            .entries
            .iter_mut()
            .find(|entry| entry.envelope_id == second_envelope_id)
            .expect("second entry");
        skipped_entry.state = DenuoOutboxState::HandoffPrepared {
            attempt_id: denuo_handoff_attempt_id(
                skipped_entry.envelope_id,
                skipped_entry.request_id,
                1,
                CREATED_AT + 5,
            ),
            prepared_at_unix: CREATED_AT + 5,
        };
        assert!(matches!(
            save_denuo_publication_outbox(
                &mut store,
                0,
                &skipped_persist_before_return,
                CREATED_AT + 5,
            ),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        let revision = save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT + 5)
            .expect("save pending encrypted outbox");
        assert_eq!(revision, 1);
        assert!(matches!(
            prepare_next_denuo_handoff(&mut store, 0, CREATED_AT + 5),
            Err(ShakedexError::StaleRevision)
        ));
        assert!(matches!(
            prepare_next_denuo_handoff(&mut store, 1, CREATED_AT + 4),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        let prepared = match prepare_next_denuo_handoff(&mut store, 1, CREATED_AT + 5)
            .expect("persist next handoff")
        {
            DenuoHandoffPreparation::Prepared(prepared) => prepared,
            _ => panic!("due entry must be newly prepared"),
        };
        assert_eq!(prepared.outbox_revision(), 2);
        assert_eq!(prepared.envelope_id(), second_envelope_id);
        assert_ne!(prepared.envelope_id(), first_envelope_id);
        assert_eq!(prepared.request_id(), 201);
        assert_eq!(prepared.attempt_ordinal(), 1);
        assert_eq!(prepared.prepared_at_unix(), CREATED_AT + 5);
        assert_eq!(prepared.envelope_bytes(), second_offer);
        assert_eq!(
            prepared.attempt_id(),
            denuo_handoff_attempt_id(second_envelope_id, 201, 1, CREATED_AT + 5)
        );

        let durable = load_denuo_publication_outbox(&store).expect("load durable prepared state");
        assert_eq!(durable.revision, prepared.outbox_revision());
        assert_eq!(
            durable.outbox.state(second_envelope_id),
            Some(DenuoOutboxState::HandoffPrepared {
                attempt_id: prepared.attempt_id(),
                prepared_at_unix: CREATED_AT + 5,
            })
        );
        assert_eq!(
            durable
                .outbox
                .entries
                .iter()
                .filter(|entry| matches!(entry.state, DenuoOutboxState::HandoffPrepared { .. }))
                .count(),
            1
        );
        let existing = match prepare_next_denuo_handoff(&mut store, 2, CREATED_AT + 6)
            .expect("prepared handoff is idempotent")
        {
            DenuoHandoffPreparation::Existing(existing) => existing,
            _ => panic!("single-flight preparation must return the existing attempt"),
        };
        assert_eq!(existing.attempt_id(), prepared.attempt_id());
        assert_eq!(existing.envelope_bytes(), prepared.envelope_bytes());
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restored = load_prepared_denuo_handoff(&reopened)
            .expect("load prepared handoff")
            .expect("prepared handoff survives restart");
        assert_eq!(restored.outbox_revision(), 2);
        assert_eq!(restored.attempt_id(), prepared.attempt_id());
        assert_eq!(restored.envelope_bytes(), prepared.envelope_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn crash_recovery_and_failure_retry_the_identical_correlated_envelope() {
        let (offer, listing, _, _) = publication_fixtures();
        let (_cleanup, mut store, database) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue")
            .envelope_id();
        let revision = save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT)
            .expect("save pending entry");
        let original = match prepare_next_denuo_handoff(&mut store, revision, CREATED_AT + 1)
            .expect("prepare first attempt")
        {
            DenuoHandoffPreparation::Prepared(prepared) => prepared,
            _ => panic!("first attempt must be prepared"),
        };
        let attempt_id = original.attempt_id();
        assert!(matches!(
            recover_denuo_handoff_as_retry(
                &mut store,
                original.outbox_revision(),
                ObjectHash::new([9; 32]),
                CREATED_AT + 2,
                CREATED_AT + 10,
            ),
            Err(ShakedexError::DenuoOutboxHandoffMismatch)
        ));
        assert!(matches!(
            recover_denuo_handoff_as_retry(
                &mut store,
                revision,
                attempt_id,
                CREATED_AT + 2,
                CREATED_AT + 10,
            ),
            Err(ShakedexError::StaleRevision)
        ));
        assert!(matches!(
            recover_denuo_handoff_as_retry(
                &mut store,
                original.outbox_revision(),
                attempt_id,
                CREATED_AT,
                CREATED_AT + 10,
            ),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));

        drop(store);
        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restored = load_prepared_denuo_handoff(&reopened)
            .expect("load prepared after crash")
            .expect("outcome-unknown attempt");
        assert_eq!(restored.attempt_id(), attempt_id);
        assert_eq!(restored.envelope_bytes(), offer);
        assert_eq!(restored.request_id(), 101);
        let failure = recover_denuo_handoff_as_retry(
            &mut reopened,
            restored.outbox_revision(),
            restored.attempt_id(),
            CREATED_AT + 2,
            CREATED_AT + 10,
        )
        .expect("recover outcome-unknown attempt as failure");
        assert_eq!(failure.envelope_id(), envelope_id);
        assert_eq!(
            failure.state(),
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix: CREATED_AT + 10,
            }
        );
        assert!(matches!(
            record_denuo_handoff_failure(&mut reopened, original, CREATED_AT + 3, CREATED_AT + 11,),
            Err(ShakedexError::StaleRevision)
        ));
        assert!(matches!(
            prepare_next_denuo_handoff(&mut reopened, failure.outbox_revision(), CREATED_AT + 9,)
                .expect("retry not due"),
            DenuoHandoffPreparation::NoDue { .. }
        ));
        let second = match prepare_next_denuo_handoff(
            &mut reopened,
            failure.outbox_revision(),
            CREATED_AT + 10,
        )
        .expect("prepare retry")
        {
            DenuoHandoffPreparation::Prepared(prepared) => prepared,
            _ => panic!("due retry must be prepared"),
        };
        assert_eq!(second.attempt_ordinal(), 2);
        assert_eq!(second.envelope_id(), envelope_id);
        assert_eq!(second.request_id(), 101);
        assert_eq!(second.envelope_bytes(), offer);
        assert_ne!(second.attempt_id(), attempt_id);
        assert!(matches!(
            record_denuo_handoff_failure(&mut reopened, second, CREATED_AT + 11, CREATED_AT + 11,),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn schema_v1_migrates_on_preparation_and_acknowledgement_stays_immutable() {
        let (offer, listing, _, _) = publication_fixtures();
        let (_cleanup, mut store, _) = test_wallet_store();
        let mut pending = DenuoPublicationOutbox::default();
        let envelope_id = pending
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue legacy pending")
            .envelope_id();
        let legacy = PersistedDenuoPublicationOutbox {
            schema_version: LEGACY_DENUO_OUTBOX_SCHEMA_VERSION,
            entries: pending.entries.clone(),
        };
        let revision = store
            .save_denuo_board_object(DENUO_OUTBOX_RECORD_ID, 0, &legacy, CREATED_AT)
            .expect("save schema-v1 pending row");
        let loaded = load_denuo_publication_outbox(&store).expect("load schema-v1 row");
        assert_eq!(loaded.outbox.schema_version, DENUO_OUTBOX_SCHEMA_VERSION);
        let prepared = match prepare_next_denuo_handoff(&mut store, revision, CREATED_AT + 1)
            .expect("prepare migrates schema")
        {
            DenuoHandoffPreparation::Prepared(prepared) => prepared,
            _ => panic!("legacy pending row must prepare"),
        };
        let persisted = store
            .denuo_board_object::<PersistedDenuoPublicationOutbox>(DENUO_OUTBOX_RECORD_ID)
            .expect("read migrated row")
            .expect("migrated row exists");
        assert_eq!(persisted.value.schema_version, DENUO_OUTBOX_SCHEMA_VERSION);
        assert_eq!(prepared.envelope_id(), envelope_id);

        let (_ack_cleanup, mut ack_store, _) = test_wallet_store();
        let mut acknowledged = DenuoPublicationOutbox::default();
        acknowledged
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue legacy acknowledged row");
        acknowledged.entries[0].state = DenuoOutboxState::Acknowledged {
            acknowledged_at_unix: CREATED_AT + 1,
        };
        let legacy_acknowledged = PersistedDenuoPublicationOutbox {
            schema_version: LEGACY_DENUO_OUTBOX_SCHEMA_VERSION,
            entries: acknowledged.entries.clone(),
        };
        ack_store
            .save_denuo_board_object(
                DENUO_OUTBOX_RECORD_ID,
                0,
                &legacy_acknowledged,
                CREATED_AT + 1,
            )
            .expect("save legacy acknowledgement");
        let loaded_ack = load_denuo_publication_outbox(&ack_store)
            .expect("load immutable legacy acknowledgement");
        assert_eq!(
            loaded_ack.outbox.state(envelope_id),
            Some(DenuoOutboxState::Acknowledged {
                acknowledged_at_unix: CREATED_AT + 1,
            })
        );
        assert!(matches!(
            prepare_next_denuo_handoff(&mut ack_store, loaded_ack.revision, CREATED_AT + 2)
                .expect("legacy acknowledgement is not due"),
            DenuoHandoffPreparation::NoDue { .. }
        ));
        let mut rollback = loaded_ack.outbox;
        rollback.entries[0].state = DenuoOutboxState::Pending;
        assert!(matches!(
            save_denuo_publication_outbox(
                &mut ack_store,
                loaded_ack.revision,
                &rollback,
                CREATED_AT + 2,
            ),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));

        let (_schema_v2_ack_cleanup, mut schema_v2_ack_store, _) = test_wallet_store();
        schema_v2_ack_store
            .save_denuo_board_object(
                DENUO_OUTBOX_RECORD_ID,
                0,
                &PersistedDenuoPublicationOutbox {
                    schema_version: HANDOFF_DENUO_OUTBOX_SCHEMA_VERSION,
                    entries: acknowledged.entries.clone(),
                },
                CREATED_AT + 1,
            )
            .expect("authorized test writer stores impossible schema-v2 acknowledgement");
        assert!(matches!(
            load_denuo_publication_outbox(&schema_v2_ack_store),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let (_malicious_cleanup, mut malicious_store, _) = test_wallet_store();
        let mut impossible_legacy = pending.entries.clone();
        impossible_legacy[0].state = DenuoOutboxState::HandoffPrepared {
            attempt_id: denuo_handoff_attempt_id(envelope_id, 101, 1, CREATED_AT + 1),
            prepared_at_unix: CREATED_AT + 1,
        };
        malicious_store
            .save_denuo_board_object(
                DENUO_OUTBOX_RECORD_ID,
                0,
                &PersistedDenuoPublicationOutbox {
                    schema_version: LEGACY_DENUO_OUTBOX_SCHEMA_VERSION,
                    entries: impossible_legacy,
                },
                CREATED_AT + 1,
            )
            .expect("authorized test writer stores impossible legacy phase");
        assert!(matches!(
            load_denuo_publication_outbox(&malicious_store),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn failure_sixty_four_persists_terminal_exhaustion() {
        let (offer, listing, _, _) = publication_fixtures();
        let (_cleanup, mut store, database) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue")
            .envelope_id();
        let mut revision = save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT)
            .expect("save pending entry");

        for attempt in 1..=MAX_DENUO_OUTBOX_RETRY_ATTEMPTS {
            let attempted_at_unix = CREATED_AT + u64::from(attempt);
            let prepared = match prepare_next_denuo_handoff(&mut store, revision, attempted_at_unix)
                .expect("persist prepared attempt")
            {
                DenuoHandoffPreparation::Prepared(prepared) => prepared,
                _ => panic!("each due retry must be prepared"),
            };
            assert_eq!(prepared.attempt_ordinal(), attempt);
            let result = record_denuo_handoff_failure(
                &mut store,
                prepared,
                attempted_at_unix,
                attempted_at_unix + 1,
            )
            .expect("persist failed handoff");
            revision = result.outbox_revision();
            if attempt < MAX_DENUO_OUTBOX_RETRY_ATTEMPTS {
                assert!(matches!(
                    result.state(),
                    DenuoOutboxState::RetryScheduled { .. }
                ));
            } else {
                assert_eq!(
                    result.state(),
                    DenuoOutboxState::Exhausted {
                        exhausted_at_unix: attempted_at_unix,
                    }
                );
            }
        }
        assert!(matches!(
            prepare_next_denuo_handoff(&mut store, revision, CREATED_AT + 1_000)
                .expect("terminal entry is not due"),
            DenuoHandoffPreparation::NoDue { .. }
        ));
        assert!(
            load_prepared_denuo_handoff(&store)
                .expect("load terminal state")
                .is_none()
        );
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restored = load_denuo_publication_outbox(&reopened).expect("load exhausted outbox");
        assert_eq!(restored.revision, revision);
        assert_eq!(restored.outbox.retry_attempts(envelope_id), Some(64));
        assert!(matches!(
            restored.outbox.state(envelope_id),
            Some(DenuoOutboxState::Exhausted { .. })
        ));
    }

    #[test]
    fn restart_validation_fails_closed_on_identity_state_and_size_corruption() {
        let (offer, listing, _, _) = publication_fixtures();
        let listing_hash = listing.listing_hash();
        let mut outbox = DenuoPublicationOutbox::default();
        outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue");

        let mut wrong_id = outbox.clone();
        wrong_id.entries[0].envelope_id = ObjectHash::new([9; 32]);
        assert!(matches!(
            wrong_id.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut regressed = outbox.clone();
        regressed.entries[0].state = DenuoOutboxState::RetryScheduled {
            next_attempt_at_unix: CREATED_AT + 2,
        };
        assert!(matches!(
            regressed.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut wrong_attempt = outbox.clone();
        wrong_attempt.entries[0].state = DenuoOutboxState::HandoffPrepared {
            attempt_id: ObjectHash::new([7; 32]),
            prepared_at_unix: CREATED_AT + 1,
        };
        assert!(matches!(
            wrong_attempt.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let (second_offer, second_listing, _, _) = publication_fixtures_with_sequence(43, 201, 202);
        let mut multiple_prepared = outbox.clone();
        multiple_prepared
            .enqueue_offer(&second_offer, &second_listing, CREATED_AT)
            .expect("enqueue second corruption fixture");
        for entry in &mut multiple_prepared.entries {
            let prepared_at_unix = CREATED_AT + 1;
            entry.state = DenuoOutboxState::HandoffPrepared {
                attempt_id: denuo_handoff_attempt_id(
                    entry.envelope_id,
                    entry.request_id,
                    1,
                    prepared_at_unix,
                ),
                prepared_at_unix,
            };
        }
        assert!(matches!(
            multiple_prepared.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut duplicate = outbox.clone();
        let mut second = duplicate.entries[0].clone();
        second.envelope_id = ObjectHash::new([0xff; 32]);
        duplicate.entries.push(second);
        duplicate.entries.sort_by_key(|entry| entry.envelope_id);
        assert!(matches!(
            duplicate.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut incoherent_ack = outbox.clone();
        incoherent_ack.entries[0].state = DenuoOutboxState::Acknowledged {
            acknowledged_at_unix: CREATED_AT + 1,
        };
        incoherent_ack.entries[0].retry_attempts = 1;
        assert!(matches!(
            incoherent_ack.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));
        incoherent_ack.entries[0].retry_attempts = 0;
        incoherent_ack.entries[0].last_attempt_at_unix = Some(CREATED_AT);
        assert!(matches!(
            incoherent_ack.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut incoherent_exhaustion = outbox.clone();
        incoherent_exhaustion.entries[0].state = DenuoOutboxState::Exhausted {
            exhausted_at_unix: CREATED_AT + 64,
        };
        incoherent_exhaustion.entries[0].retry_attempts = MAX_DENUO_OUTBOX_RETRY_ATTEMPTS;
        incoherent_exhaustion.entries[0].last_attempt_at_unix = Some(CREATED_AT + 63);
        assert!(matches!(
            incoherent_exhaustion.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut unbounded_retry = outbox.clone();
        unbounded_retry.entries[0].state = DenuoOutboxState::RetryScheduled {
            next_attempt_at_unix: CREATED_AT + 65,
        };
        unbounded_retry.entries[0].retry_attempts = MAX_DENUO_OUTBOX_RETRY_ATTEMPTS;
        unbounded_retry.entries[0].last_attempt_at_unix = Some(CREATED_AT + 64);
        assert!(matches!(
            unbounded_retry.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        let mut over_capacity = outbox.clone();
        over_capacity.entries = vec![outbox.entries[0].clone(); MAX_DENUO_OUTBOX_ENTRIES + 1];
        assert!(matches!(
            over_capacity.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));

        assert!(matches!(
            DenuoPublicationOutbox::default().enqueue_expected(
                &vec![0; MAX_DENUO_OUTBOX_ENVELOPE_BYTES + 1],
                DenuoOutboxMessageKind::Offer,
                listing_hash,
                CREATED_AT,
            ),
            Err(ShakedexError::InvalidDenuoOutboxEnvelope)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn direct_announcement_is_durable_terminal_and_has_no_peer_receipt() {
        let (offer, listing, _, _) = publication_fixtures();
        let (_cleanup, mut store, _) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue")
            .envelope_id();
        let revision =
            save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT).expect("save");
        let handoff = match prepare_next_denuo_handoff(&mut store, revision, CREATED_AT + 1)
            .expect("prepare")
        {
            DenuoHandoffPreparation::Prepared(handoff) => handoff,
            _ => panic!("one pending envelope must prepare"),
        };
        let announced =
            record_denuo_handoff_direct_announcement(&mut store, &handoff, CREATED_AT + 2)
                .expect("record local direct write");
        assert_eq!(announced.envelope_id(), envelope_id);
        let stored = load_denuo_publication_outbox(&store).expect("load direct state");
        assert_eq!(stored.revision, announced.outbox_revision());
        assert!(matches!(
            stored.outbox.state(envelope_id),
            Some(DenuoOutboxState::DirectAnnounced {
                attempt_id,
                prepared_at_unix,
                announced_at_unix,
            }) if attempt_id == handoff.attempt_id()
                && prepared_at_unix == CREATED_AT + 1
                && announced_at_unix == CREATED_AT + 2
        ));
        assert!(
            load_prepared_denuo_handoff(&store)
                .expect("terminal direct state")
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn schema_v2_zero_magic_handoff_acceptance_is_durable_exact_and_idempotent() {
        let network = NetworkBinding {
            magic: 0,
            genesis: BlockHash::new([0x11; 32]),
        };
        let (offer, listing, _, _) =
            publication_fixtures_with_network_and_sequence(network, 41, 101, 102);
        let (_cleanup, mut store, database) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue")
            .envelope_id();
        let prepared_at_unix = CREATED_AT + 1;
        let entry = &mut outbox.entries[0];
        entry.state = DenuoOutboxState::HandoffPrepared {
            attempt_id: denuo_handoff_attempt_id(
                entry.envelope_id,
                entry.request_id,
                1,
                prepared_at_unix,
            ),
            prepared_at_unix,
        };
        let revision = store
            .save_denuo_board_object(
                DENUO_OUTBOX_RECORD_ID,
                0,
                &PersistedDenuoPublicationOutbox {
                    schema_version: HANDOFF_DENUO_OUTBOX_SCHEMA_VERSION,
                    entries: outbox.entries.clone(),
                },
                prepared_at_unix,
            )
            .expect("inject schema-v2 prepared row");
        let loaded = load_denuo_publication_outbox(&store).expect("load schema-v2 prepared row");
        let handoff = prepared_handoff_from_entry(revision, &loaded.outbox.entries[0])
            .expect("reconstruct exact handoff");
        let endpoint_key = SigningKey::from_slice(&[0x42; 32]).expect("endpoint key");
        let policy = acceptance_policy(listing.network(), &endpoint_key);
        let wrong_network_policy = acceptance_policy(
            NetworkBinding {
                magic: 1,
                genesis: network.genesis,
            },
            &endpoint_key,
        );
        assert_ne!(policy.fingerprint(), wrong_network_policy.fingerprint());
        let canonical = canonical_publication(handoff.envelope_bytes()).expect("canonical handoff");
        let expected = acceptance_expectation(&handoff, &canonical);
        let accepted_at_unix = CREATED_AT + 2;
        let receipt = signed_acceptance_for_test(
            &policy,
            expected,
            accepted_at_unix,
            accepted_at_unix + 60,
            &endpoint_key,
        );

        let mut malformed_signature = receipt.clone();
        *malformed_signature.last_mut().expect("signature byte") ^= 1;
        assert!(matches!(
            record_denuo_handoff_acceptance(
                &mut store,
                &handoff,
                &policy,
                &malformed_signature,
                accepted_at_unix,
            ),
            Err(ShakedexError::InvalidDenuoPublicationAcceptance)
        ));
        let overlong = signed_acceptance_for_test(
            &policy,
            expected,
            accepted_at_unix,
            accepted_at_unix + 121,
            &endpoint_key,
        );
        assert!(matches!(
            record_denuo_handoff_acceptance(
                &mut store,
                &handoff,
                &policy,
                &overlong,
                accepted_at_unix,
            ),
            Err(ShakedexError::InvalidDenuoPublicationAcceptance)
        ));
        let wrong_content_receipt = signed_acceptance_for_test(
            &policy,
            DenuoAcceptanceExpectation {
                content_id: ObjectHash::new([0x99; 32]),
                ..expected
            },
            accepted_at_unix,
            accepted_at_unix + 60,
            &endpoint_key,
        );
        assert!(matches!(
            record_denuo_handoff_acceptance(
                &mut store,
                &handoff,
                &policy,
                &wrong_content_receipt,
                accepted_at_unix,
            ),
            Err(ShakedexError::InvalidDenuoPublicationAcceptance)
        ));
        let wrong_network_receipt = signed_acceptance_for_test(
            &wrong_network_policy,
            expected,
            accepted_at_unix,
            accepted_at_unix + 60,
            &endpoint_key,
        );
        assert!(matches!(
            record_denuo_handoff_acceptance(
                &mut store,
                &handoff,
                &wrong_network_policy,
                &wrong_network_receipt,
                accepted_at_unix,
            ),
            Err(ShakedexError::InvalidDenuoPublicationAcceptance)
        ));
        let still_prepared = load_denuo_publication_outbox(&store)
            .expect("rejected receipts do not mutate the prepared row");
        assert_eq!(still_prepared.revision, revision);
        assert!(matches!(
            still_prepared.outbox.state(envelope_id),
            Some(DenuoOutboxState::HandoffPrepared { .. })
        ));

        let inserted = record_denuo_handoff_acceptance(
            &mut store,
            &handoff,
            &policy,
            &receipt,
            accepted_at_unix,
        )
        .expect("persist signed relay acceptance");
        assert!(inserted.inserted());
        let snapshot = inserted.snapshot();
        assert_eq!(snapshot.envelope_id, envelope_id);
        assert_eq!(snapshot.attempt_id, handoff.attempt_id());
        assert_eq!(snapshot.policy_fingerprint, policy.fingerprint());
        let accepted_revision = snapshot.outbox_revision;
        assert_eq!(accepted_revision, revision + 1);
        assert!(
            load_prepared_denuo_handoff(&store)
                .expect("load terminal outbox")
                .is_none()
        );
        assert!(matches!(
            prepare_next_denuo_handoff(&mut store, accepted_revision, CREATED_AT + 3)
                .expect("accepted entry is not due"),
            DenuoHandoffPreparation::NoDue { .. }
        ));

        let existing = record_denuo_handoff_acceptance(
            &mut store,
            &handoff,
            &policy,
            &receipt,
            accepted_at_unix,
        )
        .expect("exact replay ignores pre-accept revision");
        assert!(!existing.inserted());
        assert_eq!(existing.snapshot(), snapshot);
        assert_eq!(
            load_denuo_publication_outbox(&store)
                .expect("load after replay")
                .revision,
            accepted_revision
        );

        let conflicting_receipt = signed_acceptance_for_test(
            &policy,
            expected,
            accepted_at_unix,
            accepted_at_unix + 61,
            &endpoint_key,
        );
        assert!(matches!(
            record_denuo_handoff_acceptance(
                &mut store,
                &handoff,
                &policy,
                &conflicting_receipt,
                accepted_at_unix,
            ),
            Err(ShakedexError::DenuoPublicationAcceptanceConflict)
        ));

        let accepted = load_denuo_publication_outbox(&store).expect("load accepted row");
        let mut corrupt = accepted.outbox.clone();
        let receipt_bytes = &mut corrupt.entries[0]
            .acceptance
            .as_mut()
            .expect("durable receipt")
            .receipt_bytes;
        let final_byte = receipt_bytes.last_mut().expect("receipt byte");
        *final_byte ^= 1;
        assert!(matches!(
            corrupt.validate(),
            Err(ShakedexError::CorruptDenuoOutbox)
        ));
        let persisted = store
            .denuo_board_object::<PersistedDenuoPublicationOutbox>(DENUO_OUTBOX_RECORD_ID)
            .expect("read schema-v3 row")
            .expect("schema-v3 row exists");
        assert_eq!(persisted.value.schema_version, DENUO_OUTBOX_SCHEMA_VERSION);
        assert!(matches!(
            record_denuo_handoff_failure(
                &mut store,
                handoff,
                accepted_at_unix + 1,
                accepted_at_unix + 2,
            ),
            Err(ShakedexError::StaleRevision)
        ));
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restarted =
            load_denuo_publication_outbox(&reopened).expect("receipt self-validates after restart");
        assert_eq!(restarted.revision, accepted_revision);
        assert_eq!(
            restarted.outbox.state(envelope_id),
            Some(DenuoOutboxState::RelayAccepted {
                receipt_id: snapshot.receipt_id,
                accepted_at_unix,
            })
        );
    }
}
