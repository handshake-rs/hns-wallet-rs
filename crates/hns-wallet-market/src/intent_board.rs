use std::collections::{BTreeMap, BTreeSet};

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, MAX_INVENTORY_ENTRIES, MarketIntent, MarketIntentCancellation,
    MarketPair, NetworkBinding,
};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, EntityPrefixSetLease, StoreError, StoredEntity,
    WalletStore,
};
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MarketError;

const DENUO_INTENT_SCHEMA_VERSION: u16 = 1;
const DENUO_INTENT_POLICY_DOMAIN: &[u8] = b"hns-wallet-denuo-intent-policy-v1\0";
const DENUO_INTENT_RECORD_PREFIX: &[u8] = b"denuo-v2-intent\0";

/// Maximum number of live or cancellation-tombstoned HNS/BTC intents retained
/// under one exact network policy. The bound matches the canonical Denuo V2
/// inventory bound, so one complete local board always fits one inventory.
pub const MAX_DENUO_MARKET_INTENTS: usize = MAX_INVENTORY_ENTRIES;

/// One peer may have only this many outstanding intent fetches. Repeated
/// inventories resume convergence without allowing a peer to allocate an
/// unbounded request table.
pub const MAX_PENDING_DENUO_INTENT_REQUESTS: usize = 64;

/// Exact wallet-owned admission boundary for one Denuo HNS/BTC board.
///
/// Peers and rendezvous mechanisms only deliver bytes. Every retained intent
/// is re-authenticated against this caller-owned network and pair on every
/// load, so neither a relay nor an HNS full node is market authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoIntentBoardPolicy {
    network: NetworkBinding,
    pair: MarketPair,
    fingerprint: ObjectHash,
}

impl DenuoIntentBoardPolicy {
    pub fn new(network: NetworkBinding, pair: MarketPair) -> Result<Self, MarketError> {
        network
            .validate_for_pair(pair)
            .map_err(|_| MarketError::InvalidDenuoIntentBoardPolicy)?;
        if pair != MarketPair::HNS_BTC {
            return Err(MarketError::InvalidDenuoIntentBoardPolicy);
        }
        let mut hasher = Sha256::new();
        hasher.update(DENUO_INTENT_POLICY_DOMAIN);
        hasher.update(
            network
                .encode()
                .map_err(|_| MarketError::InvalidDenuoIntentBoardPolicy)?,
        );
        hasher.update(
            pair.encode()
                .map_err(|_| MarketError::InvalidDenuoIntentBoardPolicy)?,
        );
        Ok(Self {
            network,
            pair,
            fingerprint: ObjectHash::new(hasher.finalize().into()),
        })
    }

    pub const fn network(self) -> NetworkBinding {
        self.network
    }

    pub const fn pair(self) -> MarketPair {
        self.pair
    }

    pub const fn fingerprint(self) -> ObjectHash {
        self.fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDenuoMarketIntent {
    schema_version: u16,
    policy_fingerprint: ObjectHash,
    intent_id: ObjectHash,
    accepted_at_unix: u64,
    intent_hex: String,
    cancellation_hex: Option<String>,
    cancelled_at_unix: Option<u64>,
}

/// Fully re-authenticated wallet-local board row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoMarketIntentRecord {
    pub store_revision: u64,
    pub accepted_at_unix: u64,
    pub cancelled_at_unix: Option<u64>,
    pub intent: MarketIntent,
    pub cancellation: Option<MarketIntentCancellation>,
}

impl DenuoMarketIntentRecord {
    pub fn snapshot(&self) -> DenuoMarketIntentSnapshot {
        DenuoMarketIntentSnapshot {
            store_revision: self.store_revision,
            intent_id: ObjectHash::new(self.intent.intent_id),
            signer_public_key: self.intent.header.signer_public_key,
            sequence: self.intent.header.sequence,
            offered_asset: self.intent.offered_asset,
            maximum_amount: self.intent.maximum_amount.get(),
            minimum_fill: self.intent.minimum_fill.get(),
            partial_fills: self.intent.partial_fills,
            created_at_unix: self.intent.header.created_at,
            expires_at_unix: self.intent.header.expires_at,
            accepted_at_unix: self.accepted_at_unix,
            cancelled_at_unix: self.cancelled_at_unix,
        }
    }

    pub fn is_active_at(&self, now_unix: u64) -> bool {
        self.cancellation.is_none()
            && self.intent.header.created_at <= now_unix
            && now_unix < self.intent.header.expires_at
    }

    fn retained_until_unix(&self) -> u64 {
        self.cancellation
            .as_ref()
            .map_or(self.intent.header.expires_at, |cancellation| {
                cancellation.header.expires_at
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoMarketIntentSnapshot {
    pub store_revision: u64,
    pub intent_id: ObjectHash,
    pub signer_public_key: [u8; 33],
    pub sequence: u64,
    pub offered_asset: AssetId,
    pub maximum_amount: u128,
    pub minimum_fill: u128,
    pub partial_fills: bool,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub accepted_at_unix: u64,
    pub cancelled_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoMarketIntentAdmission {
    Inserted(DenuoMarketIntentSnapshot),
    Existing(DenuoMarketIntentSnapshot),
}

impl DenuoMarketIntentAdmission {
    pub const fn snapshot(self) -> DenuoMarketIntentSnapshot {
        match self {
            Self::Inserted(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoMarketIntentCancellationAdmission {
    Applied(DenuoMarketIntentSnapshot),
    Existing(DenuoMarketIntentSnapshot),
}

impl DenuoMarketIntentCancellationAdmission {
    pub const fn snapshot(self) -> DenuoMarketIntentSnapshot {
        match self {
            Self::Applied(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn applied(self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

/// Load and re-authenticate the complete bounded board for one exact policy.
/// Expired rows remain omitted from the result and may be removed explicitly
/// with [`prune_denuo_market_intents`].
pub fn load_denuo_market_intents(
    store: &WalletStore,
    policy: &DenuoIntentBoardPolicy,
    now_unix: u64,
) -> Result<Vec<DenuoMarketIntentRecord>, MarketError> {
    let prefix = intent_record_prefix(policy);
    let stored = store.list_entities_by_id_prefix::<PersistedDenuoMarketIntent>(
        EntityKind::MarketIntent,
        &prefix,
        MAX_DENUO_MARKET_INTENTS + 1,
    )?;
    if stored.len() > MAX_DENUO_MARKET_INTENTS {
        return Err(MarketError::DenuoMarketIntentCapacity);
    }
    let mut records = stored
        .into_iter()
        .map(|stored| decode_stored_intent(policy, stored))
        .collect::<Result<Vec<_>, _>>()?;
    records.retain(|record| record.retained_until_unix() > now_unix);
    records.sort_by_key(|record| record.intent.intent_id);
    Ok(records)
}

pub fn load_denuo_market_intent(
    store: &WalletStore,
    policy: &DenuoIntentBoardPolicy,
    intent_id: [u8; 32],
) -> Result<Option<DenuoMarketIntentRecord>, MarketError> {
    if intent_id == [0; 32] {
        return Err(MarketError::UnknownDenuoMarketIntent);
    }
    let id = intent_record_id(policy, intent_id);
    store
        .market_intent::<PersistedDenuoMarketIntent>(&id)?
        .map(|stored| decode_stored_intent(policy, stored))
        .transpose()
}

/// Sorted active IDs suitable for an exact canonical Denuo V2 inventory.
pub fn denuo_market_intent_inventory(
    store: &WalletStore,
    policy: &DenuoIntentBoardPolicy,
    now_unix: u64,
) -> Result<Vec<[u8; 32]>, MarketError> {
    Ok(load_denuo_market_intents(store, policy, now_unix)?
        .into_iter()
        .filter(|record| record.is_active_at(now_unix))
        .map(|record| record.intent.intent_id)
        .collect())
}

/// Admit one signed intent delivered by a correlated peer response or local
/// publisher. Denuo V2 requires a nonzero request ID for this message type;
/// the transport correlation value is validated but is not persisted.
pub fn admit_denuo_market_intent(
    store: &mut WalletStore,
    policy: &DenuoIntentBoardPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoMarketIntentAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    let CrossChainMessage::MarketIntent(intent) = message else {
        return Err(MarketError::InvalidDenuoMarketIntent);
    };
    if intent.header.pair != policy.pair {
        return Err(MarketError::InvalidDenuoMarketIntent);
    }
    intent
        .verify_at(policy.network, accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    let canonical_intent = intent
        .encode()
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    if CrossChainMessage::MarketIntent(intent.clone())
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?
        != envelope_bytes
    {
        return Err(MarketError::InvalidDenuoMarketIntent);
    }

    let (stored, lease) = load_board_with_lease(store, policy)?;
    let mut records = decode_board(policy, stored)?;
    if let Some(existing) = records
        .iter()
        .find(|record| record.intent.intent_id == intent.intent_id)
    {
        if existing.intent != intent || existing.cancellation.is_some() {
            return Err(MarketError::DenuoMarketIntentReplay);
        }
        return Ok(DenuoMarketIntentAdmission::Existing(existing.snapshot()));
    }

    let deletes = expired_deletes(policy, &records, accepted_at_unix);
    records.retain(|record| record.retained_until_unix() > accepted_at_unix);
    if records.len() >= MAX_DENUO_MARKET_INTENTS {
        return Err(MarketError::DenuoMarketIntentCapacity);
    }
    let id = intent_record_id(policy, intent.intent_id);
    let persisted = PersistedDenuoMarketIntent {
        schema_version: DENUO_INTENT_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint,
        intent_id: ObjectHash::new(intent.intent_id),
        accepted_at_unix,
        intent_hex: hex::encode(canonical_intent),
        cancellation_hex: None,
        cancelled_at_unix: None,
    };
    store.apply_entity_batch_with_assertions_and_prefix_lease(
        EntityKind::MarketIntent,
        &[EntityBatchSave {
            id,
            expected_revision: 0,
            value: persisted,
            updated_at_unix: accepted_at_unix,
        }],
        &deletes,
        &[],
        lease,
    )?;
    let snapshot = DenuoMarketIntentRecord {
        store_revision: 1,
        accepted_at_unix,
        cancelled_at_unix: None,
        intent,
        cancellation: None,
    }
    .snapshot();
    Ok(DenuoMarketIntentAdmission::Inserted(snapshot))
}

/// Apply a signed cancellation as a durable tombstone. A cancelled intent can
/// never be resurrected by a later peer replay while the original object could
/// still be live.
pub fn admit_denuo_market_intent_cancellation(
    store: &mut WalletStore,
    policy: &DenuoIntentBoardPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoMarketIntentCancellationAdmission, MarketError> {
    let (request_id, message) = decode_canonical_envelope(envelope_bytes)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    let CrossChainMessage::CancelMarketIntent(cancellation) = message else {
        return Err(MarketError::InvalidDenuoMarketIntent);
    };
    if request_id != 0 || cancellation.header.pair != policy.pair {
        return Err(MarketError::InvalidDenuoMarketIntent);
    }
    let canonical = cancellation
        .encode()
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    if CrossChainMessage::CancelMarketIntent(cancellation.clone())
        .encode_envelope(0)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?
        != envelope_bytes
    {
        return Err(MarketError::InvalidDenuoMarketIntent);
    }

    let (stored, lease) = load_board_with_lease(store, policy)?;
    let records = decode_board(policy, stored)?;
    let existing = records
        .iter()
        .find(|record| record.intent.intent_id == cancellation.intent_id)
        .ok_or(MarketError::UnknownDenuoMarketIntent)?;
    cancellation
        .verify_for_intent(&existing.intent, policy.network, accepted_at_unix)
        .map_err(|_| MarketError::InvalidDenuoMarketIntent)?;
    if accepted_at_unix < existing.accepted_at_unix {
        return Err(MarketError::DenuoMarketIntentReplay);
    }
    if let Some(previous) = &existing.cancellation {
        if previous == &cancellation {
            return Ok(DenuoMarketIntentCancellationAdmission::Existing(
                existing.snapshot(),
            ));
        }
        return Err(MarketError::DenuoMarketIntentReplay);
    }

    let deletes =
        expired_deletes_except(policy, &records, accepted_at_unix, cancellation.intent_id);
    let id = intent_record_id(policy, cancellation.intent_id);
    let persisted = PersistedDenuoMarketIntent {
        schema_version: DENUO_INTENT_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint,
        intent_id: ObjectHash::new(existing.intent.intent_id),
        accepted_at_unix: existing.accepted_at_unix,
        intent_hex: hex::encode(
            existing
                .intent
                .encode()
                .map_err(|_| MarketError::CorruptDenuoMarketIntentBoard)?,
        ),
        cancellation_hex: Some(hex::encode(canonical)),
        cancelled_at_unix: Some(accepted_at_unix),
    };
    let next_revision = existing
        .store_revision
        .checked_add(1)
        .ok_or(MarketError::CorruptDenuoMarketIntentBoard)?;
    store.apply_entity_batch_with_assertions_and_prefix_lease(
        EntityKind::MarketIntent,
        &[EntityBatchSave {
            id,
            expected_revision: existing.store_revision,
            value: persisted,
            updated_at_unix: accepted_at_unix,
        }],
        &deletes,
        &[],
        lease,
    )?;
    let snapshot = DenuoMarketIntentRecord {
        store_revision: next_revision,
        accepted_at_unix: existing.accepted_at_unix,
        cancelled_at_unix: Some(accepted_at_unix),
        intent: existing.intent.clone(),
        cancellation: Some(cancellation),
    }
    .snapshot();
    Ok(DenuoMarketIntentCancellationAdmission::Applied(snapshot))
}

pub fn prune_denuo_market_intents(
    store: &mut WalletStore,
    policy: &DenuoIntentBoardPolicy,
    now_unix: u64,
) -> Result<usize, MarketError> {
    let (stored, lease) = load_board_with_lease(store, policy)?;
    let records = decode_board(policy, stored)?;
    let deletes = expired_deletes(policy, &records, now_unix);
    if deletes.is_empty() {
        return Ok(0);
    }
    let deleted = deletes.len();
    let saves: Vec<EntityBatchSave<PersistedDenuoMarketIntent>> = Vec::new();
    store.apply_entity_batch_with_assertions_and_prefix_lease(
        EntityKind::MarketIntent,
        &saves,
        &deletes,
        &[],
        lease,
    )?;
    Ok(deleted)
}

/// Connection-scoped state machine for direct wallet-to-wallet Denuo intent
/// synchronization. It owns only request correlation; the encrypted board is
/// the durable authority and the caller supplies any TCP, QUIC, WebSocket,
/// WebRTC, or native-companion transport.
#[derive(Clone, Debug)]
pub struct DenuoIntentPeerSession {
    next_request_id: u64,
    pending_intents: BTreeMap<u64, [u8; 32]>,
}

impl DenuoIntentPeerSession {
    pub fn new(first_request_id: u64) -> Result<Self, MarketError> {
        if first_request_id == 0 {
            return Err(MarketError::InvalidDenuoPeerMessage);
        }
        Ok(Self {
            next_request_id: first_request_id,
            pending_intents: BTreeMap::new(),
        })
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_intents.len()
    }

    pub fn inventory_envelope(
        &self,
        store: &WalletStore,
        policy: &DenuoIntentBoardPolicy,
        now_unix: u64,
    ) -> Result<Option<Vec<u8>>, MarketError> {
        let inventory = denuo_market_intent_inventory(store, policy, now_unix)?;
        if inventory.is_empty() {
            return Ok(None);
        }
        CrossChainMessage::MarketIntentInventory(inventory)
            .encode_envelope(0)
            .map(Some)
            .map_err(|_| MarketError::InvalidDenuoPeerMessage)
    }

    pub fn receive(
        &mut self,
        store: &mut WalletStore,
        policy: &DenuoIntentBoardPolicy,
        envelope_bytes: &[u8],
        now_unix: u64,
    ) -> Result<DenuoIntentPeerStep, MarketError> {
        let (request_id, message) = decode_canonical_envelope(envelope_bytes)?;
        match message {
            CrossChainMessage::MarketIntentInventory(remote) => {
                if request_id != 0 {
                    return Err(MarketError::InvalidDenuoPeerMessage);
                }
                let local = load_denuo_market_intents(store, policy, now_unix)?;
                let local_by_id = local
                    .iter()
                    .map(|record| (record.intent.intent_id, record))
                    .collect::<BTreeMap<_, _>>();
                let mut outbound = Vec::new();
                let mut requested = 0usize;
                for intent_id in &remote {
                    match local_by_id.get(intent_id) {
                        Some(record) => {
                            if let Some(cancellation) = &record.cancellation {
                                outbound.push(
                                    CrossChainMessage::CancelMarketIntent(cancellation.clone())
                                        .encode_envelope(0)
                                        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
                                );
                            }
                        }
                        None if self.pending_intents.len() < MAX_PENDING_DENUO_INTENT_REQUESTS => {
                            let request_id = self.allocate_request_id()?;
                            self.pending_intents.insert(request_id, *intent_id);
                            outbound.push(
                                CrossChainMessage::GetMarketIntent(*intent_id)
                                    .encode_envelope(request_id)
                                    .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
                            );
                            requested += 1;
                        }
                        None => break,
                    }
                }
                Ok(DenuoIntentPeerStep {
                    outbound,
                    event: DenuoIntentPeerEvent::Inventory {
                        advertised: remote.len(),
                        requested,
                    },
                })
            }
            CrossChainMessage::GetMarketIntent(intent_id) => {
                if request_id == 0 {
                    return Err(MarketError::InvalidDenuoPeerMessage);
                }
                let Some(record) = load_denuo_market_intent(store, policy, intent_id)? else {
                    return Ok(DenuoIntentPeerStep {
                        outbound: Vec::new(),
                        event: DenuoIntentPeerEvent::IntentUnavailable {
                            intent_id: ObjectHash::new(intent_id),
                        },
                    });
                };
                if record.retained_until_unix() <= now_unix {
                    return Ok(DenuoIntentPeerStep {
                        outbound: Vec::new(),
                        event: DenuoIntentPeerEvent::IntentUnavailable {
                            intent_id: ObjectHash::new(intent_id),
                        },
                    });
                }
                let mut outbound = vec![
                    CrossChainMessage::MarketIntent(record.intent.clone())
                        .encode_envelope(request_id)
                        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
                ];
                if let Some(cancellation) = record.cancellation {
                    outbound.push(
                        CrossChainMessage::CancelMarketIntent(cancellation)
                            .encode_envelope(0)
                            .map_err(|_| MarketError::InvalidDenuoPeerMessage)?,
                    );
                }
                Ok(DenuoIntentPeerStep {
                    outbound,
                    event: DenuoIntentPeerEvent::IntentServed {
                        intent_id: ObjectHash::new(intent_id),
                    },
                })
            }
            CrossChainMessage::MarketIntent(intent) => {
                if request_id != 0 {
                    let expected = self
                        .pending_intents
                        .get(&request_id)
                        .ok_or(MarketError::InvalidDenuoPeerMessage)?;
                    if *expected != intent.intent_id {
                        return Err(MarketError::InvalidDenuoPeerMessage);
                    }
                    self.pending_intents.remove(&request_id);
                }
                let canonical = CrossChainMessage::MarketIntent(intent)
                    .encode_envelope(request_id)
                    .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
                let admission = admit_denuo_market_intent(store, policy, &canonical, now_unix)?;
                Ok(DenuoIntentPeerStep {
                    outbound: Vec::new(),
                    event: DenuoIntentPeerEvent::Intent(admission),
                })
            }
            CrossChainMessage::CancelMarketIntent(cancellation) => {
                if request_id != 0 {
                    return Err(MarketError::InvalidDenuoPeerMessage);
                }
                let canonical = CrossChainMessage::CancelMarketIntent(cancellation)
                    .encode_envelope(0)
                    .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
                let admission =
                    admit_denuo_market_intent_cancellation(store, policy, &canonical, now_unix)?;
                Ok(DenuoIntentPeerStep {
                    outbound: Vec::new(),
                    event: DenuoIntentPeerEvent::Cancellation(admission),
                })
            }
            message => Ok(DenuoIntentPeerStep {
                outbound: Vec::new(),
                event: DenuoIntentPeerEvent::BilateralMessage {
                    request_id,
                    message: Box::new(message),
                },
            }),
        }
    }

    fn allocate_request_id(&mut self) -> Result<u64, MarketError> {
        for _ in 0..=MAX_PENDING_DENUO_INTENT_REQUESTS {
            let candidate = self.next_request_id;
            self.next_request_id = self.next_request_id.wrapping_add(1);
            if self.next_request_id == 0 {
                self.next_request_id = 1;
            }
            if candidate != 0 && !self.pending_intents.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(MarketError::InvalidDenuoPeerMessage)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoIntentPeerStep {
    pub outbound: Vec<Vec<u8>>,
    pub event: DenuoIntentPeerEvent,
}

/// Bilateral messages have canonical framing and intrinsic signatures, but
/// remain peer hints until the swap coordinator binds them to locally stored
/// intent/grant/session state and independently verified chain evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DenuoIntentPeerEvent {
    Inventory {
        advertised: usize,
        requested: usize,
    },
    Intent(DenuoMarketIntentAdmission),
    Cancellation(DenuoMarketIntentCancellationAdmission),
    IntentServed {
        intent_id: ObjectHash,
    },
    IntentUnavailable {
        intent_id: ObjectHash,
    },
    BilateralMessage {
        request_id: u64,
        message: Box<CrossChainMessage>,
    },
}

pub(crate) fn decode_canonical_envelope(
    envelope_bytes: &[u8],
) -> Result<(u64, CrossChainMessage), MarketError> {
    if envelope_bytes.is_empty() {
        return Err(MarketError::InvalidDenuoPeerMessage);
    }
    let (request_id, message) = CrossChainMessage::decode_envelope(envelope_bytes)
        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
    let canonical = message
        .encode_envelope(request_id)
        .map_err(|_| MarketError::InvalidDenuoPeerMessage)?;
    if canonical != envelope_bytes {
        return Err(MarketError::InvalidDenuoPeerMessage);
    }
    Ok((request_id, message))
}

fn load_board_with_lease(
    store: &WalletStore,
    policy: &DenuoIntentBoardPolicy,
) -> Result<
    (
        Vec<StoredEntity<PersistedDenuoMarketIntent>>,
        EntityPrefixSetLease,
    ),
    MarketError,
> {
    let prefix = intent_record_prefix(policy);
    store
        .try_with_entity_read_snapshot(|snapshot| {
            let stored = snapshot.list_entities_by_id_prefix(
                EntityKind::MarketIntent,
                &prefix,
                MAX_DENUO_MARKET_INTENTS + 1,
            )?;
            let lease = snapshot.entity_prefix_set_lease(
                EntityKind::MarketIntent,
                &prefix,
                MAX_DENUO_MARKET_INTENTS + 1,
            )?;
            Ok::<_, StoreError>((stored, lease))
        })
        .map_err(MarketError::from)
}

fn decode_board(
    policy: &DenuoIntentBoardPolicy,
    stored: Vec<StoredEntity<PersistedDenuoMarketIntent>>,
) -> Result<Vec<DenuoMarketIntentRecord>, MarketError> {
    if stored.len() > MAX_DENUO_MARKET_INTENTS {
        return Err(MarketError::DenuoMarketIntentCapacity);
    }
    let records = stored
        .into_iter()
        .map(|stored| decode_stored_intent(policy, stored))
        .collect::<Result<Vec<_>, _>>()?;
    let unique = records
        .iter()
        .map(|record| record.intent.intent_id)
        .collect::<BTreeSet<_>>();
    if unique.len() != records.len() {
        return Err(MarketError::CorruptDenuoMarketIntentBoard);
    }
    Ok(records)
}

fn decode_stored_intent(
    policy: &DenuoIntentBoardPolicy,
    stored: StoredEntity<PersistedDenuoMarketIntent>,
) -> Result<DenuoMarketIntentRecord, MarketError> {
    let value = stored.value;
    if value.schema_version != DENUO_INTENT_SCHEMA_VERSION
        || value.policy_fingerprint != policy.fingerprint
        || stored.id != intent_record_id(policy, value.intent_id.into_bytes())
        || value.cancellation_hex.is_some() != value.cancelled_at_unix.is_some()
    {
        return Err(MarketError::CorruptDenuoMarketIntentBoard);
    }
    let intent_bytes = decode_lower_hex(&value.intent_hex)?;
    let intent = MarketIntent::decode(&intent_bytes)
        .map_err(|_| MarketError::CorruptDenuoMarketIntentBoard)?;
    if intent.intent_id != value.intent_id.into_bytes()
        || intent.header.pair != policy.pair
        || intent
            .verify_at(policy.network, value.accepted_at_unix)
            .is_err()
        || intent.encode().ok().as_deref() != Some(intent_bytes.as_slice())
    {
        return Err(MarketError::CorruptDenuoMarketIntentBoard);
    }
    let cancellation = value
        .cancellation_hex
        .as_deref()
        .map(decode_lower_hex)
        .transpose()?
        .map(|bytes| {
            let cancellation = MarketIntentCancellation::decode(&bytes)
                .map_err(|_| MarketError::CorruptDenuoMarketIntentBoard)?;
            let cancelled_at = value
                .cancelled_at_unix
                .ok_or(MarketError::CorruptDenuoMarketIntentBoard)?;
            if cancelled_at < value.accepted_at_unix
                || cancellation
                    .verify_for_intent(&intent, policy.network, cancelled_at)
                    .is_err()
                || cancellation.encode().ok().as_deref() != Some(bytes.as_slice())
            {
                return Err(MarketError::CorruptDenuoMarketIntentBoard);
            }
            Ok(cancellation)
        })
        .transpose()?;
    let expected_updated = value.cancelled_at_unix.unwrap_or(value.accepted_at_unix);
    if stored.updated_at_unix != expected_updated {
        return Err(MarketError::CorruptDenuoMarketIntentBoard);
    }
    Ok(DenuoMarketIntentRecord {
        store_revision: stored.revision,
        accepted_at_unix: value.accepted_at_unix,
        cancelled_at_unix: value.cancelled_at_unix,
        intent,
        cancellation,
    })
}

fn decode_lower_hex(encoded: &str) -> Result<Vec<u8>, MarketError> {
    let decoded = hex::decode(encoded).map_err(|_| MarketError::CorruptDenuoMarketIntentBoard)?;
    if hex::encode(&decoded) != encoded {
        return Err(MarketError::CorruptDenuoMarketIntentBoard);
    }
    Ok(decoded)
}

fn expired_deletes(
    policy: &DenuoIntentBoardPolicy,
    records: &[DenuoMarketIntentRecord],
    now_unix: u64,
) -> Vec<EntityBatchDelete> {
    records
        .iter()
        .filter(|record| record.retained_until_unix() <= now_unix)
        .map(|record| EntityBatchDelete {
            id: intent_record_id(policy, record.intent.intent_id),
            expected_revision: record.store_revision,
        })
        .collect()
}

fn expired_deletes_except(
    policy: &DenuoIntentBoardPolicy,
    records: &[DenuoMarketIntentRecord],
    now_unix: u64,
    except: [u8; 32],
) -> Vec<EntityBatchDelete> {
    records
        .iter()
        .filter(|record| {
            record.intent.intent_id != except && record.retained_until_unix() <= now_unix
        })
        .map(|record| EntityBatchDelete {
            id: intent_record_id(policy, record.intent.intent_id),
            expected_revision: record.store_revision,
        })
        .collect()
}

fn intent_record_prefix(policy: &DenuoIntentBoardPolicy) -> Vec<u8> {
    let mut id = Vec::with_capacity(DENUO_INTENT_RECORD_PREFIX.len() + 32);
    id.extend_from_slice(DENUO_INTENT_RECORD_PREFIX);
    id.extend_from_slice(policy.fingerprint.as_bytes());
    id
}

fn intent_record_id(policy: &DenuoIntentBoardPolicy, intent_id: [u8; 32]) -> Vec<u8> {
    let mut id = intent_record_prefix(policy);
    id.extend_from_slice(&intent_id);
    id
}

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{
        AssetAmount, ChainId, MARKETPLACE_PROTOCOL_VERSION, SignedObjectHeader,
    };
    use hns_primitives::BlockHash;

    use super::*;

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn policy() -> DenuoIntentBoardPolicy {
        DenuoIntentBoardPolicy::new(network(), MarketPair::HNS_BTC).expect("policy")
    }

    fn intent() -> MarketIntent {
        let mut intent = MarketIntent {
            header: SignedObjectHeader {
                version: MARKETPLACE_PROTOCOL_VERSION,
                network: network(),
                pair: MarketPair::HNS_BTC,
                signer_public_key: [0; 33],
                sequence: 1,
                created_at: 100,
                expires_at: 500,
            },
            intent_id: [0; 32],
            offered_asset: AssetId::HNS,
            maximum_amount: AssetAmount::new(10_000),
            minimum_fill: AssetAmount::new(1_000),
            partial_fills: true,
            signature: [0; 64],
        };
        intent.sign(&[7; 32]).expect("sign intent");
        intent
    }

    fn cancellation(intent: &MarketIntent) -> MarketIntentCancellation {
        let mut cancellation = MarketIntentCancellation {
            header: SignedObjectHeader {
                version: MARKETPLACE_PROTOCOL_VERSION,
                network: network(),
                pair: MarketPair::HNS_BTC,
                signer_public_key: [0; 33],
                sequence: 2,
                created_at: 200,
                expires_at: 500,
            },
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            signature: [0; 64],
        };
        cancellation.sign(&[7; 32]).expect("sign cancellation");
        cancellation
    }

    fn intent_envelope(intent: &MarketIntent, request_id: u64) -> Vec<u8> {
        CrossChainMessage::MarketIntent(intent.clone())
            .encode_envelope(request_id)
            .expect("intent envelope")
    }

    fn cancellation_envelope(cancellation: &MarketIntentCancellation) -> Vec<u8> {
        CrossChainMessage::CancelMarketIntent(cancellation.clone())
            .encode_envelope(0)
            .expect("cancellation envelope")
    }

    #[test]
    fn wallet_owned_board_persists_authenticates_and_tombstones() {
        let mut store = WalletStore::create(":memory:", "intent-board").expect("store");
        let policy = policy();
        let intent = intent();
        let inserted =
            admit_denuo_market_intent(&mut store, &policy, &intent_envelope(&intent, 9), 150)
                .expect("insert intent");
        assert!(inserted.inserted());
        assert_eq!(
            denuo_market_intent_inventory(&store, &policy, 151).expect("inventory"),
            vec![intent.intent_id]
        );
        let existing =
            admit_denuo_market_intent(&mut store, &policy, &intent_envelope(&intent, 10), 152)
                .expect("same intent");
        assert!(!existing.inserted());

        let cancellation = cancellation(&intent);
        let applied = admit_denuo_market_intent_cancellation(
            &mut store,
            &policy,
            &cancellation_envelope(&cancellation),
            210,
        )
        .expect("cancel intent");
        assert!(applied.applied());
        assert!(
            denuo_market_intent_inventory(&store, &policy, 211)
                .expect("empty inventory")
                .is_empty()
        );
        assert_eq!(
            admit_denuo_market_intent(&mut store, &policy, &intent_envelope(&intent, 11), 212,),
            Err(MarketError::DenuoMarketIntentReplay)
        );
        assert_eq!(prune_denuo_market_intents(&mut store, &policy, 500), Ok(1));
    }

    #[test]
    fn direct_peer_sessions_converge_without_a_relay() {
        let policy = policy();
        let intent = intent();
        let mut maker = WalletStore::create(":memory:", "maker").expect("maker store");
        let mut taker = WalletStore::create(":memory:", "taker").expect("taker store");
        admit_denuo_market_intent(&mut maker, &policy, &intent_envelope(&intent, 1), 150)
            .expect("maker intent");
        let maker_session = DenuoIntentPeerSession::new(100).expect("maker session");
        let mut taker_session = DenuoIntentPeerSession::new(200).expect("taker session");
        let inventory = maker_session
            .inventory_envelope(&maker, &policy, 151)
            .expect("inventory")
            .expect("nonempty inventory");
        let request = taker_session
            .receive(&mut taker, &policy, &inventory, 151)
            .expect("inventory step")
            .outbound
            .pop()
            .expect("intent request");
        let mut maker_session = maker_session;
        let response = maker_session
            .receive(&mut maker, &policy, &request, 151)
            .expect("serve step")
            .outbound
            .remove(0);
        taker_session
            .receive(&mut taker, &policy, &response, 152)
            .expect("admit response");
        assert_eq!(
            denuo_market_intent_inventory(&taker, &policy, 153).expect("taker inventory"),
            vec![intent.intent_id]
        );

        let cancellation = cancellation(&intent);
        let cancellation = cancellation_envelope(&cancellation);
        maker_session
            .receive(&mut maker, &policy, &cancellation, 210)
            .expect("maker cancellation");
        taker_session
            .receive(&mut taker, &policy, &cancellation, 210)
            .expect("taker cancellation");
        assert!(
            denuo_market_intent_inventory(&taker, &policy, 211)
                .expect("cancelled inventory")
                .is_empty()
        );
    }

    #[test]
    fn wrong_network_and_uncorrelated_responses_are_rejected() {
        let policy = policy();
        let mut store = WalletStore::create(":memory:", "reject").expect("store");
        let intent = intent();
        let mut session = DenuoIntentPeerSession::new(1).expect("session");
        assert_eq!(
            session.receive(&mut store, &policy, &intent_envelope(&intent, 99), 150),
            Err(MarketError::InvalidDenuoPeerMessage)
        );

        let mut wrong = network();
        wrong.counterchain_network = 2;
        let wrong_policy = DenuoIntentBoardPolicy::new(wrong, MarketPair::HNS_BTC).expect("policy");
        assert_eq!(
            admit_denuo_market_intent(&mut store, &wrong_policy, &intent_envelope(&intent, 1), 150,),
            Err(MarketError::InvalidDenuoMarketIntent)
        );
    }
}
