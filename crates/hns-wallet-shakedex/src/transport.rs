use std::collections::BTreeSet;

use hns_marketplace_protocol::{DenuoRegistryVersion, NameMarketMessage};
use hns_wallet_hns::{
    DenuoPublicationHandoff, DenuoTransportEvent, DenuoTransportMessageKind,
    DenuoTransportSnapshotRecord, HnsBackend, HnsClock, HnsWalletRuntime,
    MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE,
};
use hns_wallet_store::{SharedWalletStore, WalletStore};
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::outbox::{DenuoAcceptedReplay, accepted_denuo_replays};
use crate::{
    DenuoBoardRuntime, DenuoHandoffPreparation, DenuoOutboxMessageKind,
    DenuoPublicationAcceptancePolicy, ShakedexError, load_denuo_publication_outbox,
    prepare_next_denuo_handoff, record_denuo_handoff_acceptance, record_denuo_handoff_failure,
};

const DENUO_TRANSPORT_CURSOR_SCHEMA_VERSION: u16 = 1;
const DENUO_TRANSPORT_CURSOR_RECORD_ID: &[u8] = b"canonical-name-market-transport-cursor-v1";
const DENUO_PUBLICATION_RETRY_SECONDS: u64 = 5;
const MAX_DENUO_PUBLICATIONS_PER_SYNC: usize = 64;
const MAX_DENUO_EVENT_PAGES_PER_SYNC: usize = 32;
const MAX_DENUO_SNAPSHOT_RECORDS: usize = crate::MAX_NAME_MARKET_BOARD_OFFERS;
const DENUO_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-outbox-envelope-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDenuoTransportCursor {
    schema_version: u16,
    instance_nonce: [u8; 32],
    relay_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoTransportCursorSnapshot {
    pub store_revision: u64,
    pub instance_nonce: [u8; 32],
    pub relay_revision: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DenuoTransportSyncReport {
    pub publications_accepted: usize,
    pub publication_failures: usize,
    pub accepted_publications_replayed: usize,
    pub offers_admitted: usize,
    pub cancellations_admitted: usize,
    pub marketplace_records_rejected: usize,
    pub event_pages_consumed: usize,
    pub snapshot_rebuilt: bool,
    pub cursor: Option<DenuoTransportCursorSnapshot>,
}

/// Same-store controller joining the durable publication outbox, authenticated
/// local node transport, process-bound event cursor, and canonical board.
pub struct DenuoTransportRuntime<'a, B, C> {
    hns: &'a HnsWalletRuntime<B, C>,
    board: DenuoBoardRuntime<'a, B, C>,
    store: SharedWalletStore,
    acceptance_policy: DenuoPublicationAcceptancePolicy,
}

impl<'a, B: HnsBackend, C: HnsClock> DenuoTransportRuntime<'a, B, C> {
    pub fn new(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
        acceptance_policy: DenuoPublicationAcceptancePolicy,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        if acceptance_policy.network() != hns.shakedex_network()? {
            return Err(ShakedexError::InvalidDenuoPublicationAcceptancePolicy);
        }
        Ok(Self {
            hns,
            board: DenuoBoardRuntime::new_value(hns, store.clone())?,
            store,
            acceptance_policy,
        })
    }

    pub fn sync(&self) -> Result<DenuoTransportSyncReport, ShakedexError> {
        let mut report = DenuoTransportSyncReport::default();
        self.pump_publications(&mut report)?;
        self.consume_marketplace(&mut report)?;
        report.cursor = self.store.try_with_store(load_transport_cursor)?;
        Ok(report)
    }

    fn pump_publications(
        &self,
        report: &mut DenuoTransportSyncReport,
    ) -> Result<(), ShakedexError> {
        for _ in 0..MAX_DENUO_PUBLICATIONS_PER_SYNC {
            let now = self.hns.trusted_now_unix()?;
            let revision = self
                .store
                .try_with_store(load_denuo_publication_outbox)?
                .revision;
            let preparation = self
                .store
                .try_with_store_mut(|store| prepare_next_denuo_handoff(store, revision, now))?;
            let handoff = match preparation {
                DenuoHandoffPreparation::NoDue { .. } => return Ok(()),
                DenuoHandoffPreparation::Prepared(handoff)
                | DenuoHandoffPreparation::Existing(handoff) => handoff,
            };
            let request = handoff_request(&handoff)?;
            match self
                .hns
                .backend()
                .publish_denuo_name_market(handoff.envelope_bytes(), request)
            {
                Ok(acceptance) => {
                    self.store.try_with_store_mut(|store| {
                        record_denuo_handoff_acceptance(
                            store,
                            &handoff,
                            &self.acceptance_policy,
                            &acceptance.receipt_bytes,
                            acceptance.accepted_at_unix,
                        )
                    })?;
                    report.publications_accepted += 1;
                }
                Err(_) => {
                    let failed_at = self.hns.trusted_now_unix()?.max(handoff.prepared_at_unix());
                    let next_attempt = failed_at
                        .checked_add(DENUO_PUBLICATION_RETRY_SECONDS)
                        .ok_or(ShakedexError::Invariant)?;
                    self.store.try_with_store_mut(|store| {
                        record_denuo_handoff_failure(store, handoff, failed_at, next_attempt)
                    })?;
                    report.publication_failures += 1;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn consume_marketplace(
        &self,
        report: &mut DenuoTransportSyncReport,
    ) -> Result<(), ShakedexError> {
        for _ in 0..MAX_DENUO_EVENT_PAGES_PER_SYNC {
            let cursor = self.store.try_with_store(load_transport_cursor)?;
            let after_revision = cursor.map_or(0, |cursor| cursor.relay_revision);
            let page = self.hns.backend().get_denuo_name_market_events(
                cursor.map(|cursor| cursor.instance_nonce),
                after_revision,
                MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE,
            )?;
            let instance_changed = page.cursor_reset
                || cursor.is_some_and(|cursor| cursor.instance_nonce != page.instance_nonce);
            let window_lost =
                after_revision != 0 && after_revision.saturating_add(1) < page.oldest_revision;
            let initial_window_lost = cursor.is_none() && page.oldest_revision > 1;
            if instance_changed || window_lost || initial_window_lost {
                if instance_changed {
                    self.replay_accepted_publications(report)?;
                }
                self.rebuild_from_snapshot(page.instance_nonce, report)?;
                continue;
            }
            for event in &page.events {
                self.apply_event(event, report)?;
            }
            let consumed_revision = page
                .events
                .last()
                .map_or(after_revision, |event| event.revision);
            let now = self.hns.trusted_now_unix()?;
            let saved = self.store.try_with_store_mut(|store| {
                save_transport_cursor(store, cursor, page.instance_nonce, consumed_revision, now)
            })?;
            report.cursor = Some(saved);
            report.event_pages_consumed += 1;
            if consumed_revision >= page.head_revision {
                return Ok(());
            }
        }
        Ok(())
    }

    fn replay_accepted_publications(
        &self,
        report: &mut DenuoTransportSyncReport,
    ) -> Result<(), ShakedexError> {
        let replays = self.store.try_with_store(accepted_denuo_replays)?;
        let now = self.hns.trusted_now_unix()?;
        for replay in replays {
            if !replay_is_live(&replay, now)? {
                continue;
            }
            self.hns
                .backend()
                .publish_denuo_name_market(&replay.envelope_bytes, replay_handoff(&replay))?;
            report.accepted_publications_replayed += 1;
        }
        Ok(())
    }

    fn rebuild_from_snapshot(
        &self,
        expected_instance_nonce: [u8; 32],
        report: &mut DenuoTransportSyncReport,
    ) -> Result<(), ShakedexError> {
        let mut expected_revision = None;
        let mut offset = 0usize;
        let mut records = Vec::new();
        loop {
            let page = self.hns.backend().get_denuo_name_market_snapshot(
                expected_revision,
                offset,
                MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE,
            )?;
            if page.instance_nonce != expected_instance_nonce
                || expected_revision.is_some_and(|revision| revision != page.snapshot_revision)
                || records
                    .len()
                    .checked_add(page.records.len())
                    .is_none_or(|count| count > MAX_DENUO_SNAPSHOT_RECORDS)
            {
                return Err(ShakedexError::InvalidEvidence);
            }
            expected_revision = Some(page.snapshot_revision);
            offset = match page.next_offset {
                Some(next) => next,
                None => {
                    records.extend(page.records);
                    break;
                }
            };
            records.extend(page.records);
        }

        let mut active_listing_hashes = BTreeSet::new();
        for record in &records {
            if self.apply_snapshot_record(record, report)? == AppliedRecord::Offer {
                active_listing_hashes.insert(ObjectHash::new(record.content_id));
            }
        }
        self.board
            .reconcile_transport_snapshot(&active_listing_hashes)?;
        let now = self.hns.trusted_now_unix()?;
        let current = self.store.try_with_store(load_transport_cursor)?;
        let saved = self.store.try_with_store_mut(|store| {
            save_transport_cursor(
                store,
                current,
                expected_instance_nonce,
                expected_revision.unwrap_or(0),
                now,
            )
        })?;
        report.snapshot_rebuilt = true;
        report.cursor = Some(saved);
        Ok(())
    }

    fn apply_event(
        &self,
        event: &DenuoTransportEvent,
        report: &mut DenuoTransportSyncReport,
    ) -> Result<(), ShakedexError> {
        let record = DenuoTransportSnapshotRecord {
            kind: event.kind,
            content_id: event.content_id,
            envelope_bytes: event.envelope_bytes.clone(),
        };
        self.apply_snapshot_record(&record, report).map(|_| ())
    }

    fn apply_snapshot_record(
        &self,
        record: &DenuoTransportSnapshotRecord,
        report: &mut DenuoTransportSyncReport,
    ) -> Result<AppliedRecord, ShakedexError> {
        let (_, _, message) = NameMarketMessage::decode_envelope(&record.envelope_bytes)
            .map_err(|_| ShakedexError::InvalidDenuoEnvelope)?;
        let result = match (record.kind, message) {
            (DenuoTransportMessageKind::Offer, NameMarketMessage::Offer(listing)) => {
                let listing_hash = ObjectHash::new(
                    listing
                        .listing_hash()
                        .map_err(|_| ShakedexError::InvalidListing)?,
                );
                if listing_hash.into_bytes() != record.content_id {
                    return Err(ShakedexError::InvalidDenuoEnvelope);
                }
                self.board
                    .admit_offer(&record.envelope_bytes, listing_hash)
                    .map(|_| AppliedRecord::Offer)
            }
            (DenuoTransportMessageKind::Cancellation, NameMarketMessage::Cancel(cancellation)) => {
                let cancellation_hash = ObjectHash::new(
                    cancellation
                        .cancellation_hash()
                        .map_err(|_| ShakedexError::InvalidCancellation)?,
                );
                if cancellation_hash.into_bytes() != record.content_id {
                    return Err(ShakedexError::InvalidDenuoEnvelope);
                }
                self.board
                    .admit_cancellation(
                        &record.envelope_bytes,
                        ObjectHash::new(cancellation.listing_hash),
                        cancellation_hash,
                    )
                    .map(|_| AppliedRecord::Cancellation)
            }
            _ => return Err(ShakedexError::InvalidDenuoEnvelope),
        };
        match result {
            Ok(AppliedRecord::Offer) => {
                report.offers_admitted += 1;
                Ok(AppliedRecord::Offer)
            }
            Ok(AppliedRecord::Cancellation) => {
                report.cancellations_admitted += 1;
                Ok(AppliedRecord::Cancellation)
            }
            Ok(AppliedRecord::Rejected) => Err(ShakedexError::Invariant),
            Err(
                ShakedexError::InvalidListing
                | ShakedexError::InvalidCancellation
                | ShakedexError::InvalidEvidence
                | ShakedexError::InvalidDenuoEnvelope
                | ShakedexError::DenuoRegistryMismatch
                | ShakedexError::NameMarketReplay,
            ) => {
                report.marketplace_records_rejected += 1;
                Ok(AppliedRecord::Rejected)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppliedRecord {
    Offer,
    Cancellation,
    Rejected,
}

fn handoff_request(
    handoff: &crate::DenuoPreparedHandoff,
) -> Result<DenuoPublicationHandoff, ShakedexError> {
    let (registry, request_id, message) =
        NameMarketMessage::decode_envelope(handoff.envelope_bytes())
            .map_err(|_| ShakedexError::InvalidDenuoOutboxEnvelope)?;
    if registry != DenuoRegistryVersion::V2 || request_id != handoff.request_id() {
        return Err(ShakedexError::InvalidDenuoOutboxEnvelope);
    }
    let network = match message {
        NameMarketMessage::Offer(listing) => listing.network(),
        NameMarketMessage::Cancel(cancellation) => cancellation.network,
        _ => return Err(ShakedexError::InvalidDenuoOutboxEnvelope),
    };
    let mut envelope_id = Sha256::new();
    envelope_id.update(DENUO_OUTBOX_ENVELOPE_ID_DOMAIN);
    envelope_id.update(handoff.envelope_bytes());
    Ok(DenuoPublicationHandoff {
        network_magic: network.magic,
        network_genesis: *network.genesis.as_bytes(),
        attempt_id: handoff.attempt_id().into_bytes(),
        record_sequence: u64::from(handoff.attempt_ordinal()),
        prepared_at_unix: handoff.prepared_at_unix(),
        envelope_id: envelope_id.finalize().into(),
        envelope_digest: Sha256::digest(handoff.envelope_bytes()).into(),
        content_id: handoff.content_id().into_bytes(),
        message_kind: transport_kind(handoff.message_kind()),
        request_id,
    })
}

fn replay_handoff(replay: &DenuoAcceptedReplay) -> DenuoPublicationHandoff {
    DenuoPublicationHandoff {
        network_magic: replay.network_magic,
        network_genesis: replay.network_genesis,
        attempt_id: replay.attempt_id,
        record_sequence: replay.record_sequence,
        prepared_at_unix: replay.prepared_at_unix,
        envelope_id: replay.envelope_id,
        envelope_digest: replay.envelope_digest,
        content_id: replay.content_id,
        message_kind: transport_kind(replay.message_kind),
        request_id: replay.request_id,
    }
}

fn transport_kind(kind: DenuoOutboxMessageKind) -> DenuoTransportMessageKind {
    match kind {
        DenuoOutboxMessageKind::Offer => DenuoTransportMessageKind::Offer,
        DenuoOutboxMessageKind::Cancellation => DenuoTransportMessageKind::Cancellation,
    }
}

fn replay_is_live(replay: &DenuoAcceptedReplay, now: u64) -> Result<bool, ShakedexError> {
    let (_, _, message) = NameMarketMessage::decode_envelope(&replay.envelope_bytes)
        .map_err(|_| ShakedexError::CorruptDenuoOutbox)?;
    Ok(match message {
        NameMarketMessage::Offer(listing) => listing.created_at <= now && listing.expires_at > now,
        NameMarketMessage::Cancel(cancellation) => {
            cancellation.created_at <= now && cancellation.expires_at > now
        }
        _ => return Err(ShakedexError::CorruptDenuoOutbox),
    })
}

fn load_transport_cursor(
    store: &WalletStore,
) -> Result<Option<DenuoTransportCursorSnapshot>, ShakedexError> {
    let Some(stored) = store
        .denuo_board_object::<PersistedDenuoTransportCursor>(DENUO_TRANSPORT_CURSOR_RECORD_ID)?
    else {
        return Ok(None);
    };
    if stored.value.schema_version != DENUO_TRANSPORT_CURSOR_SCHEMA_VERSION
        || stored.value.instance_nonce == [0; 32]
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(Some(DenuoTransportCursorSnapshot {
        store_revision: stored.revision,
        instance_nonce: stored.value.instance_nonce,
        relay_revision: stored.value.relay_revision,
    }))
}

fn save_transport_cursor(
    store: &mut WalletStore,
    current: Option<DenuoTransportCursorSnapshot>,
    instance_nonce: [u8; 32],
    relay_revision: u64,
    updated_at_unix: u64,
) -> Result<DenuoTransportCursorSnapshot, ShakedexError> {
    if instance_nonce == [0; 32] {
        return Err(ShakedexError::InvalidEvidence);
    }
    if let Some(current) = current {
        if current.instance_nonce == instance_nonce {
            if relay_revision < current.relay_revision {
                return Err(ShakedexError::StaleRevision);
            }
            if relay_revision == current.relay_revision {
                return Ok(current);
            }
        }
    }
    let expected_revision = current.map_or(0, |current| current.store_revision);
    let store_revision = store.save_denuo_board_object(
        DENUO_TRANSPORT_CURSOR_RECORD_ID,
        expected_revision,
        &PersistedDenuoTransportCursor {
            schema_version: DENUO_TRANSPORT_CURSOR_SCHEMA_VERSION,
            instance_nonce,
            relay_revision,
        },
        updated_at_unix,
    )?;
    Ok(DenuoTransportCursorSnapshot {
        store_revision,
        instance_nonce,
        relay_revision,
    })
}
