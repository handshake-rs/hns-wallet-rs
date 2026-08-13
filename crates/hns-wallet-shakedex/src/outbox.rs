use std::collections::BTreeSet;

use hns_marketplace_protocol::{DenuoRegistryVersion, NameMarketMessage};
use hns_wallet_store::WalletStore;
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthenticatedFixedPriceListing, ShakedexError, VerifiedListingCancellation};

const DENUO_OUTBOX_SCHEMA_VERSION: u16 = 1;
const DENUO_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-outbox-envelope-v1\0";
const DENUO_OUTBOX_RECORD_ID: &[u8] = b"canonical-name-market-outbox-v1";
pub const MAX_DENUO_OUTBOX_ENTRIES: usize = 1_024;
pub const MAX_DENUO_OUTBOX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_DENUO_OUTBOX_SERIALIZED_BYTES: usize = 512 * 1024;
pub const MAX_DENUO_OUTBOX_RETRY_ATTEMPTS: u16 = 64;

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
    RetryScheduled { next_attempt_at_unix: u64 },
    Acknowledged { acknowledged_at_unix: u64 },
    Exhausted { exhausted_at_unix: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenuoOutboxEntry {
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
}

/// Public outbox construction is deliberately limited to [`Default`] plus the
/// typed enqueue methods. In particular, arbitrary persisted entries cannot be
/// deserialized into this aggregate outside its validated store loader.
///
/// ```compile_fail
/// use hns_wallet_shakedex::DenuoPublicationOutbox;
/// let _: DenuoPublicationOutbox = serde_json::from_str(
///     r#"{"schema_version":1,"entries":[]}"#,
/// ).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DenuoPublicationOutbox {
    schema_version: u16,
    entries: Vec<DenuoOutboxEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDenuoPublicationOutbox {
    schema_version: u16,
    entries: Vec<DenuoOutboxEntry>,
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
    pub fn entries(&self) -> &[DenuoOutboxEntry] {
        &self.entries
    }

    pub fn entry(&self, envelope_id: ObjectHash) -> Option<&DenuoOutboxEntry> {
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

    pub fn schedule_retry(
        &mut self,
        envelope_id: ObjectHash,
        attempted_at_unix: u64,
        next_attempt_at_unix: u64,
    ) -> Result<DenuoOutboxState, ShakedexError> {
        self.validate()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.envelope_id == envelope_id)
            .ok_or(ShakedexError::DenuoOutboxNotFound)?;
        let retry_not_due = matches!(
            entry.state,
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix
            } if attempted_at_unix < next_attempt_at_unix
        );
        if matches!(
            entry.state,
            DenuoOutboxState::Acknowledged { .. } | DenuoOutboxState::Exhausted { .. }
        ) || retry_not_due
            || attempted_at_unix < entry.created_at_unix
            || entry
                .last_attempt_at_unix
                .is_some_and(|last| attempted_at_unix <= last)
            || next_attempt_at_unix <= attempted_at_unix
        {
            return Err(ShakedexError::InvalidDenuoOutboxTransition);
        }
        entry.retry_attempts = entry
            .retry_attempts
            .checked_add(1)
            .filter(|attempts| *attempts <= MAX_DENUO_OUTBOX_RETRY_ATTEMPTS)
            .ok_or(ShakedexError::DenuoOutboxRetryLimit)?;
        entry.last_attempt_at_unix = Some(attempted_at_unix);
        entry.state = if entry.retry_attempts == MAX_DENUO_OUTBOX_RETRY_ATTEMPTS {
            DenuoOutboxState::Exhausted {
                exhausted_at_unix: attempted_at_unix,
            }
        } else {
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix,
            }
        };
        Ok(entry.state)
    }

    pub fn acknowledge(
        &mut self,
        envelope_id: ObjectHash,
        acknowledged_at_unix: u64,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.envelope_id == envelope_id)
            .ok_or(ShakedexError::DenuoOutboxNotFound)?;
        if let DenuoOutboxState::Acknowledged {
            acknowledged_at_unix: existing,
        } = entry.state
        {
            return if existing == acknowledged_at_unix {
                Ok(false)
            } else {
                Err(ShakedexError::InvalidDenuoOutboxTransition)
            };
        }
        if matches!(entry.state, DenuoOutboxState::Exhausted { .. }) {
            return Err(ShakedexError::InvalidDenuoOutboxTransition);
        }
        if acknowledged_at_unix < entry.created_at_unix
            || entry
                .last_attempt_at_unix
                .is_some_and(|last| acknowledged_at_unix < last)
        {
            return Err(ShakedexError::InvalidDenuoOutboxTransition);
        }
        entry.state = DenuoOutboxState::Acknowledged {
            acknowledged_at_unix,
        };
        Ok(true)
    }

    /// Return exact envelopes eligible for a caller-owned future transport.
    /// This method performs no I/O and grants no publication authority.
    pub fn due_entries(&self, now_unix: u64) -> Result<Vec<&DenuoOutboxEntry>, ShakedexError> {
        self.validate()?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| match entry.state {
                DenuoOutboxState::Pending => entry.created_at_unix <= now_unix,
                DenuoOutboxState::RetryScheduled {
                    next_attempt_at_unix,
                } => next_attempt_at_unix <= now_unix,
                DenuoOutboxState::Acknowledged { .. } => false,
                DenuoOutboxState::Exhausted { .. } => false,
            })
            .collect())
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
        let mut request_ids = BTreeSet::new();
        let mut message_identities = BTreeSet::new();
        for entry in &self.entries {
            validate_entry(entry)?;
            if !request_ids.insert(entry.request_id)
                || !message_identities.insert((entry.message_kind, entry.content_id))
            {
                return Err(ShakedexError::CorruptDenuoOutbox);
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|_| ShakedexError::CorruptDenuoOutbox)?;
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

pub struct StoredDenuoPublicationOutbox {
    pub revision: u64,
    pub updated_at_unix: u64,
    pub outbox: DenuoPublicationOutbox,
}

pub fn load_denuo_publication_outbox(
    store: &WalletStore,
) -> Result<StoredDenuoPublicationOutbox, ShakedexError> {
    match store.denuo_board_object::<PersistedDenuoPublicationOutbox>(DENUO_OUTBOX_RECORD_ID)? {
        Some(stored) => {
            let outbox = DenuoPublicationOutbox {
                schema_version: stored.value.schema_version,
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
            outbox,
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
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
                || next_entry.last_attempt_at_unix.is_some())
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
        (DenuoOutboxState::Pending, DenuoOutboxState::Pending)
        | (
            DenuoOutboxState::Acknowledged {
                acknowledged_at_unix: _,
            },
            DenuoOutboxState::Acknowledged {
                acknowledged_at_unix: _,
            },
        ) => {
            if current.state != next.state
                || current.retry_attempts != next.retry_attempts
                || current.last_attempt_at_unix != next.last_attempt_at_unix
            {
                return Err(ShakedexError::InvalidDenuoOutboxTransition);
            }
        }
        (
            DenuoOutboxState::Exhausted {
                exhausted_at_unix: _,
            },
            DenuoOutboxState::Exhausted {
                exhausted_at_unix: _,
            },
        ) => {
            if current.state != next.state
                || current.retry_attempts != next.retry_attempts
                || current.last_attempt_at_unix != next.last_attempt_at_unix
            {
                return Err(ShakedexError::InvalidDenuoOutboxTransition);
            }
        }
        (
            DenuoOutboxState::Pending | DenuoOutboxState::RetryScheduled { .. },
            DenuoOutboxState::Acknowledged { .. },
        ) => {
            if current.retry_attempts != next.retry_attempts
                || current.last_attempt_at_unix != next.last_attempt_at_unix
            {
                return Err(ShakedexError::InvalidDenuoOutboxTransition);
            }
        }
        (DenuoOutboxState::Pending, DenuoOutboxState::RetryScheduled { .. }) => {
            validate_retry_advance(current, next, None)?
        }
        (
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix,
            },
            DenuoOutboxState::RetryScheduled { .. },
        ) => validate_retry_advance(current, next, Some(next_attempt_at_unix))?,
        (
            DenuoOutboxState::RetryScheduled {
                next_attempt_at_unix,
            },
            DenuoOutboxState::Exhausted { .. },
        ) => validate_retry_advance(current, next, Some(next_attempt_at_unix))?,
        _ => return Err(ShakedexError::InvalidDenuoOutboxTransition),
    }
    Ok(())
}

fn validate_retry_advance(
    current: &DenuoOutboxEntry,
    next: &DenuoOutboxEntry,
    current_due_at_unix: Option<u64>,
) -> Result<(), ShakedexError> {
    let Some(next_attempt_at_unix) = next.last_attempt_at_unix else {
        return Err(ShakedexError::InvalidDenuoOutboxTransition);
    };
    if current.retry_attempts.checked_add(1) != Some(next.retry_attempts)
        || current
            .last_attempt_at_unix
            .is_some_and(|last| next_attempt_at_unix <= last)
        || current_due_at_unix.is_some_and(|due| next_attempt_at_unix < due)
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
    let (message_kind, content_id) = match &message {
        NameMarketMessage::Offer(listing) => (
            DenuoOutboxMessageKind::Offer,
            ObjectHash::new(
                listing
                    .listing_hash()
                    .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?,
            ),
        ),
        NameMarketMessage::Cancel(cancellation) => (
            DenuoOutboxMessageKind::Cancellation,
            ObjectHash::new(
                cancellation
                    .cancellation_hash()
                    .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?,
            ),
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
    })
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
    match entry.state {
        DenuoOutboxState::Pending => {
            if entry.retry_attempts != 0 || entry.last_attempt_at_unix.is_some() {
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
    use crate::{authenticate_fixed_price_listing, verify_listing_cancellation};

    const CREATED_AT: u64 = 1_800_000_200;

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
        let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let network = NetworkBinding {
            magic: 0x5b6e_c393,
            genesis: BlockHash::new([0x11; 32]),
        };
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
    fn exact_enqueue_retry_acknowledgement_is_monotonic_and_idempotent() {
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
        assert!(outbox.due_entries(CREATED_AT - 1).unwrap().is_empty());
        assert_eq!(outbox.due_entries(CREATED_AT).unwrap().len(), 2);

        outbox
            .schedule_retry(offer_result.envelope_id(), CREATED_AT + 5, CREATED_AT + 20)
            .expect("schedule retry");
        assert!(matches!(
            outbox.schedule_retry(offer_result.envelope_id(), CREATED_AT + 19, CREATED_AT + 30),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        assert_eq!(outbox.due_entries(CREATED_AT + 19).unwrap().len(), 1);
        assert_eq!(outbox.due_entries(CREATED_AT + 20).unwrap().len(), 2);
        assert!(
            outbox
                .acknowledge(offer_result.envelope_id(), CREATED_AT + 21)
                .expect("acknowledge")
        );
        assert!(
            !outbox
                .acknowledge(offer_result.envelope_id(), CREATED_AT + 21)
                .expect("idempotent acknowledgement")
        );
        assert!(matches!(
            outbox.schedule_retry(offer_result.envelope_id(), CREATED_AT + 22, CREATED_AT + 23,),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
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
        assert!(outbox.entries().is_empty());
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
        let directory = std::env::temp_dir().join(format!(
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
    fn encrypted_cas_restart_revalidates_exact_envelope_and_terminal_state() {
        let (offer, listing, cancellation, verified_cancellation) = publication_fixtures();
        let (_cleanup, mut store, database) = test_wallet_store();
        let mut outbox = DenuoPublicationOutbox::default();
        let envelope_id = outbox
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("enqueue")
            .envelope_id();
        let mut skipped_initial_state = outbox.clone();
        skipped_initial_state
            .acknowledge(envelope_id, CREATED_AT + 1)
            .expect("in-memory acknowledgement");
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 0, &skipped_initial_state, CREATED_AT + 1,),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        let revision = save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT)
            .expect("save pending encrypted outbox");
        assert_eq!(revision, 1);
        assert_eq!(
            save_denuo_publication_outbox(&mut store, 1, &outbox, CREATED_AT)
                .expect("exact resave is idempotent"),
            1
        );
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 1, &outbox, CREATED_AT - 1),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        outbox
            .acknowledge(envelope_id, CREATED_AT + 1)
            .expect("acknowledge");
        let revision = save_denuo_publication_outbox(&mut store, 1, &outbox, CREATED_AT + 1)
            .expect("save encrypted outbox");
        assert_eq!(revision, 2);
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 0, &outbox, CREATED_AT + 1),
            Err(ShakedexError::StaleRevision)
        ));

        let mut overwrite = DenuoPublicationOutbox::default();
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 2, &overwrite, CREATED_AT + 2),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        overwrite
            .enqueue_offer(&offer, &listing, CREATED_AT)
            .expect("recreate pending entry");
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 2, &overwrite, CREATED_AT + 2),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));

        outbox
            .enqueue_cancellation(&cancellation, &verified_cancellation, CREATED_AT + 2)
            .expect("enqueue second entry");
        let revision = save_denuo_publication_outbox(&mut store, 2, &outbox, CREATED_AT + 2)
            .expect("save pending second entry");
        assert_eq!(revision, 3);
        let cancellation_envelope_id = outbox
            .entries()
            .iter()
            .find(|entry| entry.message_kind == DenuoOutboxMessageKind::Cancellation)
            .expect("cancellation entry")
            .envelope_id;
        let mut skipped_retry = outbox.clone();
        skipped_retry
            .schedule_retry(cancellation_envelope_id, CREATED_AT + 3, CREATED_AT + 10)
            .expect("first in-memory retry");
        skipped_retry
            .schedule_retry(cancellation_envelope_id, CREATED_AT + 10, CREATED_AT + 20)
            .expect("second in-memory retry");
        assert!(matches!(
            save_denuo_publication_outbox(&mut store, 3, &skipped_retry, CREATED_AT + 10),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        outbox
            .schedule_retry(cancellation_envelope_id, CREATED_AT + 3, CREATED_AT + 10)
            .expect("schedule second retry");
        let revision = save_denuo_publication_outbox(&mut store, 3, &outbox, CREATED_AT + 3)
            .expect("save retry entry");
        assert_eq!(revision, 4);

        let (_, _, second_cancellation, second_verified_cancellation) =
            publication_fixtures_with_sequence(43, 201, 202);
        outbox
            .enqueue_cancellation(
                &second_cancellation,
                &second_verified_cancellation,
                CREATED_AT + 4,
            )
            .expect("enqueue unrelated entry while retry waits");
        let revision = save_denuo_publication_outbox(&mut store, 4, &outbox, CREATED_AT + 4)
            .expect("preserve unchanged retry while adding entry");
        assert_eq!(revision, 5);
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restored = load_denuo_publication_outbox(&reopened).expect("load outbox");
        assert_eq!(restored.revision, 5);
        assert_eq!(restored.updated_at_unix, CREATED_AT + 4);
        assert_eq!(restored.outbox, outbox);
        assert_eq!(
            restored.outbox.due_entries(CREATED_AT + 100).unwrap().len(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn retry_limit_persists_explicit_terminal_exhaustion() {
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
            let state = outbox
                .schedule_retry(envelope_id, attempted_at_unix, attempted_at_unix + 1)
                .expect("record failed attempt");
            if attempt < MAX_DENUO_OUTBOX_RETRY_ATTEMPTS {
                assert!(matches!(state, DenuoOutboxState::RetryScheduled { .. }));
            } else {
                assert_eq!(
                    state,
                    DenuoOutboxState::Exhausted {
                        exhausted_at_unix: attempted_at_unix,
                    }
                );
            }
            revision =
                save_denuo_publication_outbox(&mut store, revision, &outbox, attempted_at_unix)
                    .expect("save monotonic failed attempt");
        }
        assert!(outbox.due_entries(CREATED_AT + 1_000).unwrap().is_empty());
        assert!(matches!(
            outbox.schedule_retry(envelope_id, CREATED_AT + 1_001, CREATED_AT + 1_002),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        assert!(matches!(
            outbox.acknowledge(envelope_id, CREATED_AT + 1_001),
            Err(ShakedexError::InvalidDenuoOutboxTransition)
        ));
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("denuo-outbox-test-passphrase")
            .expect("unlock wallet store");
        let restored = load_denuo_publication_outbox(&reopened).expect("load exhausted outbox");
        assert_eq!(restored.revision, revision);
        assert_eq!(restored.outbox, outbox);
        assert!(matches!(
            restored
                .outbox
                .entry(envelope_id)
                .expect("exhausted entry")
                .state,
            DenuoOutboxState::Exhausted { .. }
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
}
