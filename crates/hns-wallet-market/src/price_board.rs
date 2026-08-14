use std::collections::BTreeSet;

use hns_marketplace_protocol::{
    CrossChainMessage, MAX_PRICE_ROUND_SIZE, MAX_ROUND_OBSERVATIONS, MarketPair, NetworkBinding,
    PriceRound, PriceRoundPolicy, PriceRoundVerifier,
};
use hns_wallet_store::{EntityBatchDelete, EntityBatchSave, EntityKind, StoredEntity, WalletStore};
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MarketError;

const DENUO_PRICE_ROUND_SCHEMA_VERSION: u16 = 1;
const DENUO_PRICE_ROUND_POLICY_DOMAIN: &[u8] = b"hns-wallet-denuo-price-round-policy-v1\0";
const DENUO_PRICE_ROUND_HEAD_ID_DOMAIN: &[u8] = b"canonical-denuo-price-round-head-v1\0";
const DENUO_PRICE_ROUND_RECORD_ID_DOMAIN: &[u8] = b"canonical-denuo-price-round-v1\0";

/// The cache retains a fixed-size monotonic suffix plus durable reporter
/// sequence high-watermarks, including the retired-prefix boundary. Round
/// identifiers retired from the suffix leave duplicate detection; reporter
/// observations admitted since the explicit checkpoint do not regain
/// eligibility.
pub const MAX_DENUO_PRICE_ROUND_HISTORY: usize = 128;

/// Caller-owned, exact admission policy for one network and market pair.
///
/// This object is deliberately not serializable. A product must reconstruct
/// it from its current local configuration on every startup; the encrypted
/// cache stores only a fingerprint and rejects a changed policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoPriceRoundPolicy {
    network: NetworkBinding,
    pair: MarketPair,
    round_policy: PriceRoundPolicy,
    admitted_reporters: Vec<[u8; 33]>,
    admitted_sources: Vec<[u8; 32]>,
    fingerprint: ObjectHash,
}

impl DenuoPriceRoundPolicy {
    pub fn new(
        network: NetworkBinding,
        pair: MarketPair,
        round_policy: PriceRoundPolicy,
        admitted_reporters: Vec<[u8; 33]>,
        admitted_sources: Vec<[u8; 32]>,
    ) -> Result<Self, MarketError> {
        network
            .validate_for_pair(pair)
            .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?;
        PriceRoundVerifier::new(
            network,
            round_policy,
            &admitted_reporters,
            &admitted_sources,
        )
        .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?;
        let fingerprint = price_round_policy_fingerprint(
            network,
            pair,
            round_policy,
            &admitted_reporters,
            &admitted_sources,
        )?;
        Ok(Self {
            network,
            pair,
            round_policy,
            admitted_reporters,
            admitted_sources,
            fingerprint,
        })
    }

    pub const fn network(&self) -> NetworkBinding {
        self.network
    }

    pub const fn pair(&self) -> MarketPair {
        self.pair
    }

    pub const fn fingerprint(&self) -> ObjectHash {
        self.fingerprint
    }

    fn verifier(&self) -> Result<PriceRoundVerifier<'_>, MarketError> {
        PriceRoundVerifier::new(
            self.network,
            self.round_policy,
            &self.admitted_reporters,
            &self.admitted_sources,
        )
        .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)
    }
}

/// Non-authoritative cache metadata for display and diagnostics.
///
/// It intentionally carries neither canonical bytes nor an automatic
/// conversion into [`crate::VerifiedQuote`] and does not itself confer quote
/// authority. Current HNS and counterchain anchor authority is a separate,
/// still-unavailable runtime boundary.
///
/// ```compile_fail
/// use hns_wallet_market::{DenuoPriceRoundSnapshot, VerifiedQuote};
/// fn no_automatic_quote_conversion(snapshot: DenuoPriceRoundSnapshot) -> VerifiedQuote {
///     snapshot.into()
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoPriceRoundSnapshot {
    pub revision: u64,
    pub policy_fingerprint: ObjectHash,
    pub pair: MarketPair,
    pub round_hash: ObjectHash,
    pub round_id: ObjectHash,
    pub interval_start_unix: u64,
    pub interval_end_unix: u64,
    pub valid_until_unix: u64,
    pub price_numerator: u128,
    pub price_denominator: u128,
    pub hns_anchor_height: u64,
    pub hns_anchor_hash: ObjectHash,
    pub counterchain_anchor_height: u64,
    pub counterchain_anchor_hash: ObjectHash,
    pub accepted_at_unix: u64,
    pub retained_rounds: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoPriceRoundAdmission {
    Inserted(DenuoPriceRoundSnapshot),
    Existing(DenuoPriceRoundSnapshot),
}

impl DenuoPriceRoundAdmission {
    pub const fn snapshot(self) -> DenuoPriceRoundSnapshot {
        match self {
            Self::Inserted(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPriceRoundIndex {
    round_hash: ObjectHash,
    round_id: ObjectHash,
    interval_start_unix: u64,
    interval_end_unix: u64,
    valid_until_unix: u64,
    accepted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "record_kind")]
enum PersistedPriceRoundEntity {
    Head {
        schema_version: u16,
        policy_fingerprint: ObjectHash,
        first_parent_unretained: bool,
        retired_rounds: u64,
        retired_reporter_sequence_high_watermarks: Vec<u64>,
        reporter_sequence_high_watermarks: Vec<u64>,
        history: Vec<PersistedPriceRoundIndex>,
    },
    Round {
        schema_version: u16,
        policy_fingerprint: ObjectHash,
        round_hash: ObjectHash,
        round_id: ObjectHash,
        accepted_at_unix: u64,
        #[serde(with = "hex_bytes")]
        round_bytes: Vec<u8>,
    },
}

struct DecodedPersistedRound {
    round: PriceRound,
    round_bytes: Vec<u8>,
    accepted_at_unix: u64,
}

struct LoadedPriceRoundHead {
    revision: u64,
    first_parent_unretained: bool,
    retired_rounds: u64,
    retired_reporter_sequence_high_watermarks: Vec<u64>,
    reporter_sequence_high_watermarks: Vec<u64>,
    history: Vec<PersistedPriceRoundIndex>,
    current: DecodedPersistedRound,
}

/// Load and re-authenticate every retained record, adjacent link, and reporter
/// sequence transition under the caller's exact current policy. Validation
/// uses each encrypted record's trusted local acceptance time; this does not
/// assert that the cached round or either chain anchor is current now.
pub fn load_denuo_price_round_cache(
    store: &WalletStore,
    policy: &DenuoPriceRoundPolicy,
) -> Result<Option<DenuoPriceRoundSnapshot>, MarketError> {
    let Some(loaded) = load_price_round_head_tail(store, policy)? else {
        return Ok(None);
    };
    validate_retained_price_round_history(store, policy, &loaded)?;
    Ok(Some(snapshot_from_loaded(policy, &loaded)))
}

/// Bootstrap an empty cache from one canonical current Denuo V2 price-round
/// gossip envelope and, when the current round is already linked, its exact
/// predecessor checkpoint. `None` is valid only for a zero-parent current
/// round; `Some` must be its exact predecessor.
///
/// Both envelopes must use the protocol's uncorrelated zero request ID. The
/// current round is verified at `accepted_at_unix`, which must come from a
/// trusted local/product clock rather than a peer or browser page. A supplied
/// predecessor may already be expired: it is re-authenticated intrinsically
/// and against caller policy through the current round's exact link. Ancestry
/// before a non-genesis predecessor is deliberately not claimed or inferred.
/// The predecessor, current round, and authenticated head are persisted in one
/// atomic batch. Reporter high-watermark positions follow the policy's
/// canonical sorted `admitted_reporters`; zero means unseen.
///
/// This performs no network I/O, does not acknowledge a peer, does not verify
/// either chain anchor against a live chain, provides no quote conversion, and
/// does not itself confer quote authority.
pub fn bootstrap_denuo_price_round_cache(
    store: &mut WalletStore,
    policy: &DenuoPriceRoundPolicy,
    predecessor_envelope: Option<&[u8]>,
    current_envelope: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoPriceRoundAdmission, MarketError> {
    if load_price_round_head_tail(store, policy)?.is_some() {
        return Err(MarketError::DenuoPriceRoundReplay);
    }
    let current = decode_price_round_gossip(current_envelope)?;
    if current.network != policy.network || current.pair != policy.pair {
        return Err(MarketError::InvalidDenuoPriceRound);
    }
    let predecessor = predecessor_envelope
        .map(decode_price_round_gossip)
        .transpose()?;
    match predecessor.as_ref() {
        Some(predecessor) => {
            if predecessor.network != policy.network
                || predecessor.pair != policy.pair
                || predecessor.round_hash == current.round_hash
                || predecessor.round_id == current.round_id
            {
                return Err(MarketError::InvalidDenuoPriceRound);
            }
            current
                .verify(policy.verifier()?, Some(predecessor), accepted_at_unix)
                .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
        }
        None => current
            .verify(policy.verifier()?, None, accepted_at_unix)
            .map_err(|_| MarketError::InvalidDenuoPriceRound)?,
    }

    let mut reporter_sequence_high_watermarks = vec![0; policy.admitted_reporters.len()];
    if let Some(predecessor) = predecessor.as_ref() {
        advance_reporter_sequence_high_watermarks(
            policy,
            &mut reporter_sequence_high_watermarks,
            predecessor,
        )?;
    }
    advance_reporter_sequence_high_watermarks(
        policy,
        &mut reporter_sequence_high_watermarks,
        &current,
    )?;

    let mut rounds = predecessor.iter().chain(std::iter::once(&current));
    let mut history = Vec::with_capacity(if predecessor.is_some() { 2 } else { 1 });
    let mut saves = Vec::with_capacity(if predecessor.is_some() { 3 } else { 2 });
    for round in rounds.by_ref() {
        let (record_id, entity, index) = persisted_round(policy, round, accepted_at_unix)?;
        let existing: Option<StoredEntity<PersistedPriceRoundEntity>> =
            store.price_round(&record_id)?;
        if existing.is_some() {
            return Err(MarketError::CorruptDenuoPriceRoundCache);
        }
        history.push(index);
        saves.push(EntityBatchSave {
            id: record_id,
            expected_revision: 0,
            value: entity,
            updated_at_unix: accepted_at_unix,
        });
    }
    validate_history(&history)?;
    let first_parent_unretained = predecessor
        .as_ref()
        .is_some_and(|round| round.previous_round_hash != [0; 32]);
    saves.push(EntityBatchSave {
        id: price_round_head_id(policy)?,
        expected_revision: 0,
        value: PersistedPriceRoundEntity::Head {
            schema_version: DENUO_PRICE_ROUND_SCHEMA_VERSION,
            policy_fingerprint: policy.fingerprint,
            first_parent_unretained,
            retired_rounds: 0,
            retired_reporter_sequence_high_watermarks: vec![0; policy.admitted_reporters.len()],
            reporter_sequence_high_watermarks,
            history: history.clone(),
        },
        updated_at_unix: accepted_at_unix,
    });
    store.apply_entity_batch(EntityKind::PriceRound, &saves, &[])?;
    Ok(DenuoPriceRoundAdmission::Inserted(snapshot_from_round(
        1,
        policy,
        &current,
        accepted_at_unix,
        history.len(),
    )))
}

/// Admit one exact canonical, zero-request-ID Denuo V2 `PriceRound` gossip
/// envelope as the successor of an already initialized cache.
///
/// `accepted_at_unix` is a trusted local/product clock input, never peer or
/// browser-page data. Use [`bootstrap_denuo_price_round_cache`] to initialize
/// an empty cache or join a mature linked round chain.
///
/// Admission re-authenticates the encrypted head and tail before an atomic
/// append. A retirement additionally re-authenticates the oldest retained
/// pair and their reporter sequence boundary before deletion. Call
/// [`load_denuo_price_round_cache`] for a full retained-row availability and
/// evidence audit; an `Inserted` result alone does not attest that every older
/// retained row remains readable and never confers quote or chain authority.
pub fn admit_denuo_price_round(
    store: &mut WalletStore,
    policy: &DenuoPriceRoundPolicy,
    envelope_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<DenuoPriceRoundAdmission, MarketError> {
    let round = decode_price_round_gossip(envelope_bytes)?;
    if round.network != policy.network || round.pair != policy.pair {
        return Err(MarketError::InvalidDenuoPriceRound);
    }

    let Some(loaded) = load_price_round_head_tail(store, policy)? else {
        return Err(MarketError::InvalidDenuoPriceRound);
    };
    let current_hash = ObjectHash::new(loaded.current.round.round_hash);
    if current_hash == ObjectHash::new(round.round_hash) {
        let round_bytes = round
            .encode()
            .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
        if round_bytes != loaded.current.round_bytes
            || round.round_id != loaded.current.round.round_id
        {
            return Err(MarketError::DenuoPriceRoundReplay);
        }
        return Ok(DenuoPriceRoundAdmission::Existing(snapshot_from_loaded(
            policy, &loaded,
        )));
    }
    if accepted_at_unix < loaded.current.accepted_at_unix
        || loaded.history.iter().any(|entry| {
            entry.round_hash == ObjectHash::new(round.round_hash)
                || entry.round_id == ObjectHash::new(round.round_id)
        })
    {
        return Err(MarketError::DenuoPriceRoundReplay);
    }
    round
        .verify(
            policy.verifier()?,
            Some(&loaded.current.round),
            accepted_at_unix,
        )
        .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
    let mut reporter_sequence_high_watermarks = loaded.reporter_sequence_high_watermarks.clone();
    advance_reporter_sequence_high_watermarks(
        policy,
        &mut reporter_sequence_high_watermarks,
        &round,
    )?;

    let (round_record_id, round_entity, round_index) =
        persisted_round(policy, &round, accepted_at_unix)?;
    let preexisting: Option<StoredEntity<PersistedPriceRoundEntity>> =
        store.price_round(&round_record_id)?;
    if preexisting.is_some() {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }

    let mut history = loaded.history.clone();
    history.push(round_index);
    let mut first_parent_unretained = loaded.first_parent_unretained;
    let mut retired_rounds = loaded.retired_rounds;
    let mut retired_reporter_sequence_high_watermarks =
        loaded.retired_reporter_sequence_high_watermarks.clone();
    let retired = if history.len() > MAX_DENUO_PRICE_ROUND_HISTORY {
        validate_price_round_retirement(
            store,
            policy,
            &history[0],
            &history[1],
            &mut retired_reporter_sequence_high_watermarks,
            &reporter_sequence_high_watermarks,
        )?;
        if retired_reporter_sequence_high_watermarks
            .iter()
            .zip(&reporter_sequence_high_watermarks)
            .any(|(retired, durable)| retired > durable)
        {
            return Err(MarketError::CorruptDenuoPriceRoundCache);
        }
        first_parent_unretained = true;
        retired_rounds = retired_rounds
            .checked_add(1)
            .ok_or(MarketError::Invariant)?;
        Some(history.remove(0).round_hash)
    } else {
        None
    };
    validate_history(&history)?;

    let head_entity = PersistedPriceRoundEntity::Head {
        schema_version: DENUO_PRICE_ROUND_SCHEMA_VERSION,
        policy_fingerprint: policy.fingerprint,
        first_parent_unretained,
        retired_rounds,
        retired_reporter_sequence_high_watermarks,
        reporter_sequence_high_watermarks,
        history: history.clone(),
    };
    let saves = [
        EntityBatchSave {
            id: round_record_id,
            expected_revision: 0,
            value: round_entity,
            updated_at_unix: accepted_at_unix,
        },
        EntityBatchSave {
            id: price_round_head_id(policy)?,
            expected_revision: loaded.revision,
            value: head_entity,
            updated_at_unix: accepted_at_unix,
        },
    ];
    let deletes = retired
        .map(|hash| EntityBatchDelete {
            id: price_round_record_id(hash),
            expected_revision: 1,
        })
        .into_iter()
        .collect::<Vec<_>>();
    store.apply_entity_batch(EntityKind::PriceRound, &saves, &deletes)?;

    let revision = loaded
        .revision
        .checked_add(1)
        .ok_or(MarketError::Invariant)?;
    Ok(DenuoPriceRoundAdmission::Inserted(snapshot_from_round(
        revision,
        policy,
        &round,
        accepted_at_unix,
        history.len(),
    )))
}

fn validate_price_round_retirement(
    store: &WalletStore,
    policy: &DenuoPriceRoundPolicy,
    oldest_index: &PersistedPriceRoundIndex,
    successor_index: &PersistedPriceRoundIndex,
    retired_reporter_sequence_high_watermarks: &mut [u64],
    durable_reporter_sequence_high_watermarks: &[u64],
) -> Result<(), MarketError> {
    if durable_reporter_sequence_high_watermarks.len() != policy.admitted_reporters.len() {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    let oldest = load_round_record(store, policy, oldest_index)?;
    let successor = load_round_record(store, policy, successor_index)?;
    successor
        .round
        .verify(
            policy.verifier()?,
            Some(&oldest.round),
            successor.accepted_at_unix,
        )
        .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    advance_reporter_sequence_high_watermarks(
        policy,
        retired_reporter_sequence_high_watermarks,
        &oldest.round,
    )
    .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    let mut boundary_watermarks = retired_reporter_sequence_high_watermarks.to_vec();
    advance_reporter_sequence_high_watermarks(policy, &mut boundary_watermarks, &successor.round)
        .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    if boundary_watermarks
        .iter()
        .zip(durable_reporter_sequence_high_watermarks)
        .any(|(boundary, durable)| boundary > durable)
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    Ok(())
}

fn decode_price_round_gossip(envelope_bytes: &[u8]) -> Result<PriceRound, MarketError> {
    if envelope_bytes.is_empty() {
        return Err(MarketError::InvalidDenuoPriceRound);
    }
    let (request_id, message) = CrossChainMessage::decode_envelope(envelope_bytes)
        .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
    if request_id != 0 {
        return Err(MarketError::InvalidDenuoPriceRound);
    }
    let CrossChainMessage::PriceRound(round) = message else {
        return Err(MarketError::InvalidDenuoPriceRound);
    };
    let canonical = CrossChainMessage::PriceRound(round.clone())
        .encode_envelope(0)
        .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
    if canonical != envelope_bytes {
        return Err(MarketError::InvalidDenuoPriceRound);
    }
    Ok(round)
}

fn persisted_round(
    policy: &DenuoPriceRoundPolicy,
    round: &PriceRound,
    accepted_at_unix: u64,
) -> Result<(Vec<u8>, PersistedPriceRoundEntity, PersistedPriceRoundIndex), MarketError> {
    let round_bytes = round
        .encode()
        .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
    if round_bytes.is_empty() || round_bytes.len() > MAX_PRICE_ROUND_SIZE {
        return Err(MarketError::InvalidDenuoPriceRound);
    }
    let round_hash = ObjectHash::new(round.round_hash);
    let round_id = ObjectHash::new(round.round_id);
    Ok((
        price_round_record_id(round_hash),
        PersistedPriceRoundEntity::Round {
            schema_version: DENUO_PRICE_ROUND_SCHEMA_VERSION,
            policy_fingerprint: policy.fingerprint,
            round_hash,
            round_id,
            accepted_at_unix,
            round_bytes,
        },
        PersistedPriceRoundIndex {
            round_hash,
            round_id,
            interval_start_unix: round.interval_start,
            interval_end_unix: round.interval_end,
            valid_until_unix: round.valid_until,
            accepted_at_unix,
        },
    ))
}

fn advance_reporter_sequence_high_watermarks(
    policy: &DenuoPriceRoundPolicy,
    watermarks: &mut [u64],
    round: &PriceRound,
) -> Result<(), MarketError> {
    if watermarks.len() != policy.admitted_reporters.len() {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    for observation in &round.observations {
        let index = policy
            .admitted_reporters
            .binary_search(&observation.reporter_public_key)
            .map_err(|_| MarketError::InvalidDenuoPriceRound)?;
        if observation.sequence <= watermarks[index] {
            return Err(MarketError::DenuoPriceRoundReplay);
        }
        watermarks[index] = observation.sequence;
    }
    Ok(())
}

fn replay_reporter_sequences(
    policy: &DenuoPriceRoundPolicy,
    watermarks: &mut [u64],
    rounds: &[DecodedPersistedRound],
) -> Result<(), MarketError> {
    if watermarks.len() != policy.admitted_reporters.len() {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    for decoded in rounds {
        advance_reporter_sequence_high_watermarks(policy, watermarks, &decoded.round)
            .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    }
    Ok(())
}

fn validate_reporter_sequence_tail(
    policy: &DenuoPriceRoundPolicy,
    retired_watermarks: &[u64],
    durable_watermarks: &[u64],
    rounds: &[DecodedPersistedRound],
) -> Result<(), MarketError> {
    if retired_watermarks.len() != policy.admitted_reporters.len()
        || durable_watermarks.len() != policy.admitted_reporters.len()
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    let mut seen_in_tail = vec![false; durable_watermarks.len()];
    for decoded in rounds {
        for observation in &decoded.round.observations {
            let index = policy
                .admitted_reporters
                .binary_search(&observation.reporter_public_key)
                .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
            seen_in_tail[index] = true;
        }
    }
    let mut tail_watermarks = retired_watermarks.to_vec();
    replay_reporter_sequences(policy, &mut tail_watermarks, rounds)?;
    if tail_watermarks
        .iter()
        .zip(durable_watermarks)
        .zip(seen_in_tail)
        .any(|((tail, durable), seen)| seen && tail != durable)
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    Ok(())
}

fn load_price_round_head_tail(
    store: &WalletStore,
    policy: &DenuoPriceRoundPolicy,
) -> Result<Option<LoadedPriceRoundHead>, MarketError> {
    let head_id = price_round_head_id(policy)?;
    let Some(stored): Option<StoredEntity<PersistedPriceRoundEntity>> =
        store.price_round(&head_id)?
    else {
        return Ok(None);
    };
    let PersistedPriceRoundEntity::Head {
        schema_version,
        policy_fingerprint,
        first_parent_unretained,
        retired_rounds,
        retired_reporter_sequence_high_watermarks,
        reporter_sequence_high_watermarks,
        history,
    } = stored.value
    else {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    };
    if schema_version != DENUO_PRICE_ROUND_SCHEMA_VERSION {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    if policy_fingerprint != policy.fingerprint {
        return Err(MarketError::DenuoPriceRoundPolicyMismatch);
    }
    if retired_reporter_sequence_high_watermarks.len() != policy.admitted_reporters.len()
        || reporter_sequence_high_watermarks.len() != policy.admitted_reporters.len()
        || (retired_rounds == 0
            && retired_reporter_sequence_high_watermarks
                .iter()
                .any(|sequence| *sequence != 0))
        || retired_reporter_sequence_high_watermarks
            .iter()
            .zip(&reporter_sequence_high_watermarks)
            .any(|(retired, durable)| retired > durable)
        || (retired_rounds > 0
            && (!first_parent_unretained || history.len() != MAX_DENUO_PRICE_ROUND_HISTORY))
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    validate_history(&history)?;
    let current_index = history
        .last()
        .ok_or(MarketError::CorruptDenuoPriceRoundCache)?;
    if stored.updated_at_unix != current_index.accepted_at_unix {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    let current = load_round_record(store, policy, current_index)?;
    let previous = if history.len() > 1 {
        let previous_index = &history[history.len() - 2];
        Some(load_round_record(store, policy, previous_index)?.round)
    } else {
        None
    };
    current
        .round
        .verify(
            policy.verifier()?,
            previous.as_ref(),
            current.accepted_at_unix,
        )
        .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    let mut tail = Vec::with_capacity(if previous.is_some() { 2 } else { 1 });
    if let Some(previous) = previous.as_ref() {
        tail.push(DecodedPersistedRound {
            round: previous.clone(),
            round_bytes: previous
                .encode()
                .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?,
            accepted_at_unix: history[history.len() - 2].accepted_at_unix,
        });
    }
    tail.push(DecodedPersistedRound {
        round: current.round.clone(),
        round_bytes: current.round_bytes.clone(),
        accepted_at_unix: current.accepted_at_unix,
    });
    validate_reporter_sequence_tail(
        policy,
        &retired_reporter_sequence_high_watermarks,
        &reporter_sequence_high_watermarks,
        &tail,
    )?;
    Ok(Some(LoadedPriceRoundHead {
        revision: stored.revision,
        first_parent_unretained,
        retired_rounds,
        retired_reporter_sequence_high_watermarks,
        reporter_sequence_high_watermarks,
        history,
        current,
    }))
}

fn validate_retained_price_round_history(
    store: &WalletStore,
    policy: &DenuoPriceRoundPolicy,
    loaded: &LoadedPriceRoundHead,
) -> Result<(), MarketError> {
    let rounds = loaded
        .history
        .iter()
        .map(|index| load_round_record(store, policy, index))
        .collect::<Result<Vec<_>, _>>()?;
    let first = rounds
        .first()
        .ok_or(MarketError::CorruptDenuoPriceRoundCache)?;
    if loaded.first_parent_unretained != (first.round.previous_round_hash != [0; 32]) {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    if rounds.len() == 1 {
        first
            .round
            .verify(policy.verifier()?, None, first.accepted_at_unix)
            .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    } else {
        for window in rounds.windows(2) {
            window[1]
                .round
                .verify(
                    policy.verifier()?,
                    Some(&window[0].round),
                    window[1].accepted_at_unix,
                )
                .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
        }
    }
    let mut rebuilt_watermarks = loaded.retired_reporter_sequence_high_watermarks.clone();
    replay_reporter_sequences(policy, &mut rebuilt_watermarks, &rounds)?;
    if rebuilt_watermarks != loaded.reporter_sequence_high_watermarks {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    Ok(())
}

fn load_round_record(
    store: &WalletStore,
    policy: &DenuoPriceRoundPolicy,
    index: &PersistedPriceRoundIndex,
) -> Result<DecodedPersistedRound, MarketError> {
    let record_id = price_round_record_id(index.round_hash);
    let stored: StoredEntity<PersistedPriceRoundEntity> = store
        .price_round(&record_id)?
        .ok_or(MarketError::CorruptDenuoPriceRoundCache)?;
    let PersistedPriceRoundEntity::Round {
        schema_version,
        policy_fingerprint,
        round_hash,
        round_id,
        accepted_at_unix,
        round_bytes,
    } = stored.value
    else {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    };
    if stored.revision != 1
        || schema_version != DENUO_PRICE_ROUND_SCHEMA_VERSION
        || policy_fingerprint != policy.fingerprint
        || round_hash != index.round_hash
        || round_id != index.round_id
        || accepted_at_unix != index.accepted_at_unix
        || stored.updated_at_unix != accepted_at_unix
        || round_bytes.is_empty()
        || round_bytes.len() > MAX_PRICE_ROUND_SIZE
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    let round =
        PriceRound::decode(&round_bytes).map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    let canonical = round
        .encode()
        .map_err(|_| MarketError::CorruptDenuoPriceRoundCache)?;
    if canonical != round_bytes
        || round.network != policy.network
        || round.pair != policy.pair
        || ObjectHash::new(round.round_hash) != round_hash
        || ObjectHash::new(round.round_id) != round_id
        || round.interval_start != index.interval_start_unix
        || round.interval_end != index.interval_end_unix
        || round.valid_until != index.valid_until_unix
    {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    Ok(DecodedPersistedRound {
        round,
        round_bytes,
        accepted_at_unix,
    })
}

fn validate_history(history: &[PersistedPriceRoundIndex]) -> Result<(), MarketError> {
    if history.is_empty() || history.len() > MAX_DENUO_PRICE_ROUND_HISTORY {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    let mut hashes = BTreeSet::new();
    let mut round_ids = BTreeSet::new();
    for (index, entry) in history.iter().enumerate() {
        if entry.round_hash == ObjectHash::new([0; 32])
            || entry.round_id == ObjectHash::new([0; 32])
            || entry.interval_start_unix >= entry.interval_end_unix
            || entry.interval_end_unix >= entry.valid_until_unix
            || entry.accepted_at_unix < entry.interval_end_unix
            || (index > 0 && entry.accepted_at_unix >= entry.valid_until_unix)
            || !hashes.insert(entry.round_hash)
            || !round_ids.insert(entry.round_id)
        {
            return Err(MarketError::CorruptDenuoPriceRoundCache);
        }
    }
    if history.windows(2).any(|window| {
        window[0].interval_end_unix >= window[1].interval_start_unix
            || window[0].accepted_at_unix > window[1].accepted_at_unix
    }) {
        return Err(MarketError::CorruptDenuoPriceRoundCache);
    }
    Ok(())
}

fn snapshot_from_loaded(
    policy: &DenuoPriceRoundPolicy,
    loaded: &LoadedPriceRoundHead,
) -> DenuoPriceRoundSnapshot {
    snapshot_from_round(
        loaded.revision,
        policy,
        &loaded.current.round,
        loaded.current.accepted_at_unix,
        loaded.history.len(),
    )
}

fn snapshot_from_round(
    revision: u64,
    policy: &DenuoPriceRoundPolicy,
    round: &PriceRound,
    accepted_at_unix: u64,
    retained_rounds: usize,
) -> DenuoPriceRoundSnapshot {
    DenuoPriceRoundSnapshot {
        revision,
        policy_fingerprint: policy.fingerprint,
        pair: round.pair,
        round_hash: ObjectHash::new(round.round_hash),
        round_id: ObjectHash::new(round.round_id),
        interval_start_unix: round.interval_start,
        interval_end_unix: round.interval_end,
        valid_until_unix: round.valid_until,
        price_numerator: round.canonical_price.numerator(),
        price_denominator: round.canonical_price.denominator(),
        hns_anchor_height: round.hns_anchor.height,
        hns_anchor_hash: ObjectHash::new(round.hns_anchor.block_hash),
        counterchain_anchor_height: round.counterchain_anchor.height,
        counterchain_anchor_hash: ObjectHash::new(round.counterchain_anchor.block_hash),
        accepted_at_unix,
        retained_rounds,
    }
}

fn price_round_head_id(policy: &DenuoPriceRoundPolicy) -> Result<Vec<u8>, MarketError> {
    let mut id = Vec::with_capacity(DENUO_PRICE_ROUND_HEAD_ID_DOMAIN.len() + 86);
    id.extend_from_slice(DENUO_PRICE_ROUND_HEAD_ID_DOMAIN);
    id.extend_from_slice(
        &policy
            .network
            .encode()
            .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?,
    );
    id.extend_from_slice(
        &policy
            .pair
            .encode()
            .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?,
    );
    Ok(id)
}

fn price_round_record_id(round_hash: ObjectHash) -> Vec<u8> {
    let mut id = Vec::with_capacity(DENUO_PRICE_ROUND_RECORD_ID_DOMAIN.len() + 32);
    id.extend_from_slice(DENUO_PRICE_ROUND_RECORD_ID_DOMAIN);
    id.extend_from_slice(round_hash.as_bytes());
    id
}

fn price_round_policy_fingerprint(
    network: NetworkBinding,
    pair: MarketPair,
    policy: PriceRoundPolicy,
    admitted_reporters: &[[u8; 33]],
    admitted_sources: &[[u8; 32]],
) -> Result<ObjectHash, MarketError> {
    if admitted_reporters.len() > MAX_ROUND_OBSERVATIONS
        || admitted_sources.len() > MAX_ROUND_OBSERVATIONS
    {
        return Err(MarketError::InvalidDenuoPriceRoundPolicy);
    }
    let mut hasher = Sha256::new();
    hasher.update(DENUO_PRICE_ROUND_POLICY_DOMAIN);
    hasher.update(
        network
            .encode()
            .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?,
    );
    hasher.update(
        pair.encode()
            .map_err(|_| MarketError::InvalidDenuoPriceRoundPolicy)?,
    );
    hasher.update(policy.minimum_reporters.to_le_bytes());
    hasher.update(policy.minimum_sources.to_le_bytes());
    hasher.update(policy.maximum_observation_age.to_le_bytes());
    hasher.update(policy.trim_each_side.to_le_bytes());
    hasher.update(policy.maximum_movement_basis_points.to_le_bytes());
    hasher.update((admitted_reporters.len() as u16).to_le_bytes());
    for reporter in admitted_reporters {
        hasher.update(reporter);
    }
    hasher.update((admitted_sources.len() as u16).to_le_bytes());
    for source in admitted_sources {
        hasher.update(source);
    }
    Ok(ObjectHash::new(hasher.finalize().into()))
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        hex::decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    use hns_marketplace_protocol::{
        ChainAnchor, ChainId, MARKETPLACE_PROTOCOL_VERSION, PriceObservation, RationalPrice,
    };
    use hns_primitives::BlockHash;

    use super::*;

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 0xdab5_bffa,
            counterchain_genesis: [2; 32],
        }
    }

    fn round_policy() -> PriceRoundPolicy {
        PriceRoundPolicy {
            minimum_reporters: 3,
            minimum_sources: 3,
            maximum_observation_age: 100,
            trim_each_side: 0,
            maximum_movement_basis_points: 2_000,
        }
    }

    fn anchors() -> (ChainAnchor, ChainAnchor) {
        (
            ChainAnchor {
                chain: ChainId::HANDSHAKE,
                height: 100,
                block_hash: [3; 32],
            },
            ChainAnchor {
                chain: ChainId::BITCOIN,
                height: 200,
                block_hash: [4; 32],
            },
        )
    }

    fn observation(
        index: u8,
        sequence: u64,
        observed_at: u64,
        valid_until: u64,
        price: u128,
    ) -> PriceObservation {
        let (hns_anchor, counterchain_anchor) = anchors();
        let mut observation = PriceObservation {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            price: RationalPrice::new(price, 10).expect("price"),
            source_id: [index.saturating_add(20); 32],
            reporter_public_key: [0; 33],
            observed_at,
            valid_until,
            hns_anchor,
            counterchain_anchor,
            sequence,
            signature: [0; 64],
        };
        observation.sign(&[index; 32]).expect("sign observation");
        observation
    }

    fn price_round(
        identity: u8,
        interval_start: u64,
        interval_end: u64,
        previous_round_hash: [u8; 32],
        price: u128,
    ) -> PriceRound {
        let observations = (1_u8..=3)
            .map(|index| (index, interval_start * 10 + u64::from(index)))
            .collect::<Vec<_>>();
        price_round_with_reporters(
            identity,
            interval_start,
            interval_end,
            previous_round_hash,
            price,
            &observations,
        )
    }

    fn price_round_with_reporters(
        identity: u8,
        interval_start: u64,
        interval_end: u64,
        previous_round_hash: [u8; 32],
        price: u128,
        reporters_and_sequences: &[(u8, u64)],
    ) -> PriceRound {
        let (hns_anchor, counterchain_anchor) = anchors();
        let observation_time = interval_start + 1;
        let valid_until = interval_end + 50;
        let mut round = PriceRound {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            round_id: [identity; 32],
            interval_start,
            interval_end,
            canonical_price: RationalPrice::new(1, 1).expect("placeholder"),
            observations: reporters_and_sequences
                .iter()
                .map(|&(index, sequence)| {
                    observation(index, sequence, observation_time, valid_until + 10, price)
                })
                .collect(),
            reporter_set: Vec::new(),
            source_set: Vec::new(),
            policy: round_policy(),
            hns_anchor,
            counterchain_anchor,
            valid_until,
            previous_round_hash,
            round_hash: [0; 32],
        };
        round.refresh_derived().expect("derive round");
        round
    }

    fn admission_policy_for_reporters(indices: &[u8]) -> DenuoPriceRoundPolicy {
        let mut reporters = indices
            .iter()
            .map(|&index| observation(index, 1, 1, 100, 100).reporter_public_key)
            .collect::<Vec<_>>();
        reporters.sort_unstable();
        let mut sources = indices
            .iter()
            .map(|index| [index.saturating_add(20); 32])
            .collect::<Vec<_>>();
        sources.sort_unstable();
        DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            reporters,
            sources,
        )
        .expect("admission policy")
    }

    fn admission_policy(round: &PriceRound) -> DenuoPriceRoundPolicy {
        DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            round.reporter_set.clone(),
            round.source_set.clone(),
        )
        .expect("admission policy")
    }

    fn gossip(round: &PriceRound) -> Vec<u8> {
        CrossChainMessage::PriceRound(round.clone())
            .encode_envelope(0)
            .expect("price-round envelope")
    }

    fn correlated_envelope(round: &PriceRound, request_id: u64) -> Vec<u8> {
        CrossChainMessage::PriceRound(round.clone())
            .encode_envelope(request_id)
            .expect("correlated price-round envelope")
    }

    #[test]
    fn canonical_price_round_board_admits_restarts_and_detects_policy_change() {
        let first = price_round(9, 100, 120, [0; 32], 100);
        let policy = admission_policy(&first);
        let mut store =
            WalletStore::create(":memory:", "price-round-passphrase").expect("wallet store");

        let inserted =
            bootstrap_denuo_price_round_cache(&mut store, &policy, None, &gossip(&first), 121)
                .expect("first round");
        assert!(inserted.inserted());
        assert_eq!(inserted.snapshot().revision, 1);
        assert_eq!(inserted.snapshot().retained_rounds, 1);

        let retry = admit_denuo_price_round(&mut store, &policy, &gossip(&first), 122)
            .expect("same gossip content");
        assert!(!retry.inserted());
        assert_eq!(retry.snapshot(), inserted.snapshot());

        let second = price_round(10, 121, 140, first.round_hash, 101);
        let inserted = admit_denuo_price_round(&mut store, &policy, &gossip(&second), 141)
            .expect("linked successor");
        assert_eq!(inserted.snapshot().revision, 2);
        assert_eq!(inserted.snapshot().retained_rounds, 2);
        assert_eq!(
            load_denuo_price_round_cache(&store, &policy).expect("load cache"),
            Some(inserted.snapshot())
        );

        let mut changed_reporters = policy.admitted_reporters.clone();
        let extra = observation(4, 1_304, 130, 200, 101).reporter_public_key;
        changed_reporters.push(extra);
        changed_reporters.sort_unstable();
        let changed_policy = DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            changed_reporters,
            policy.admitted_sources.clone(),
        )
        .expect("changed configured policy");
        assert!(matches!(
            load_denuo_price_round_cache(&store, &changed_policy),
            Err(MarketError::DenuoPriceRoundPolicyMismatch)
        ));
    }

    #[test]
    fn canonical_price_round_board_bootstraps_from_an_explicit_mature_checkpoint() {
        let predecessor = price_round(8, 100, 120, [7; 32], 100);
        let current = price_round(9, 160, 170, predecessor.round_hash, 101);
        let policy = admission_policy(&predecessor);

        let mut missing_checkpoint =
            WalletStore::create(":memory:", "missing-checkpoint").expect("store");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut missing_checkpoint,
                &policy,
                None,
                &gossip(&current),
                171,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));
        assert_eq!(
            load_denuo_price_round_cache(&missing_checkpoint, &policy)
                .expect("unchanged empty cache"),
            None
        );

        let wrong_predecessor = price_round(7, 100, 120, [6; 32], 100);
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut missing_checkpoint,
                &policy,
                Some(&gossip(&wrong_predecessor)),
                &gossip(&current),
                171,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let admitted = bootstrap_denuo_price_round_cache(
            &mut missing_checkpoint,
            &policy,
            Some(&gossip(&predecessor)),
            &gossip(&current),
            171,
        )
        .expect("linked mature checkpoint");
        assert_eq!(admitted.snapshot().retained_rounds, 2);
        assert_eq!(
            admitted.snapshot().round_hash,
            ObjectHash::new(current.round_hash)
        );
        assert_eq!(
            load_denuo_price_round_cache(&missing_checkpoint, &policy)
                .expect("load checkpointed cache"),
            Some(admitted.snapshot())
        );
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut missing_checkpoint,
                &policy,
                Some(&gossip(&predecessor)),
                &gossip(&current),
                172,
            ),
            Err(MarketError::DenuoPriceRoundReplay)
        ));
    }

    #[test]
    fn canonical_price_round_board_preserves_reporter_watermarks_across_omission() {
        let policy = admission_policy_for_reporters(&[1, 2, 3, 4]);
        let first =
            price_round_with_reporters(1, 100, 120, [0; 32], 100, &[(1, 101), (2, 102), (3, 103)]);
        let second = price_round_with_reporters(
            2,
            121,
            140,
            first.round_hash,
            100,
            &[(2, 202), (3, 203), (4, 204)],
        );
        let mut store = WalletStore::create(":memory:", "watermark-passphrase").expect("store");
        bootstrap_denuo_price_round_cache(&mut store, &policy, None, &gossip(&first), 121)
            .expect("initial round");
        let second_snapshot = admit_denuo_price_round(&mut store, &policy, &gossip(&second), 141)
            .expect("second round")
            .snapshot();

        let replay_after_omission = price_round_with_reporters(
            3,
            141,
            160,
            second.round_hash,
            100,
            &[(1, 101), (3, 303), (4, 304)],
        );
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&replay_after_omission), 161),
            Err(MarketError::DenuoPriceRoundReplay)
        ));
        assert_eq!(
            load_denuo_price_round_cache(&store, &policy).expect("unchanged cache"),
            Some(second_snapshot)
        );

        let valid_reappearance = price_round_with_reporters(
            4,
            141,
            160,
            second.round_hash,
            100,
            &[(1, 301), (3, 303), (4, 304)],
        );
        assert!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&valid_reappearance), 161)
                .expect("strictly newer reappearance")
                .inserted()
        );
    }

    #[test]
    fn canonical_price_round_board_rejects_envelope_policy_and_chain_substitution() {
        let first = price_round(9, 100, 120, [0; 32], 100);
        let policy = admission_policy(&first);

        let mut request_store =
            WalletStore::create(":memory:", "request-passphrase").expect("store");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &policy,
                None,
                &correlated_envelope(&first, 77),
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let mut trailing = gossip(&first);
        trailing.push(0);
        assert!(matches!(
            bootstrap_denuo_price_round_cache(&mut request_store, &policy, None, &trailing, 121,),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let wrong_family = CrossChainMessage::PriceObservationInventory(vec![[1; 32]])
            .encode_envelope(0)
            .expect("wrong family");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &policy,
                None,
                &wrong_family,
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let mut wrong_registry = gossip(&first);
        wrong_registry[4..6].copy_from_slice(&1_u16.to_le_bytes());
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &policy,
                None,
                &wrong_registry,
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let mut unadmitted_reporters = policy.admitted_reporters.clone();
        unadmitted_reporters[0] = observation(4, 1_104, 110, 180, 100).reporter_public_key;
        unadmitted_reporters.sort_unstable();
        let unadmitted_policy = DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            unadmitted_reporters,
            policy.admitted_sources.clone(),
        )
        .expect("syntactically valid alternative policy");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &unadmitted_policy,
                None,
                &gossip(&first),
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let mut unadmitted_sources = policy.admitted_sources.clone();
        unadmitted_sources[0] = [99; 32];
        unadmitted_sources.sort_unstable();
        let unadmitted_policy = DenuoPriceRoundPolicy::new(
            network(),
            MarketPair::HNS_BTC,
            round_policy(),
            policy.admitted_reporters.clone(),
            unadmitted_sources,
        )
        .expect("syntactically valid source policy");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &unadmitted_policy,
                None,
                &gossip(&first),
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let eth_network = NetworkBinding {
            counterchain: ChainId::ETHEREUM,
            counterchain_network: 1,
            counterchain_genesis: [8; 32],
            ..network()
        };
        let wrong_network_policy = DenuoPriceRoundPolicy::new(
            eth_network,
            MarketPair::HNS_ETH,
            round_policy(),
            policy.admitted_reporters.clone(),
            policy.admitted_sources.clone(),
        )
        .expect("other network policy");
        assert!(matches!(
            bootstrap_denuo_price_round_cache(
                &mut request_store,
                &wrong_network_policy,
                None,
                &gossip(&first),
                121,
            ),
            Err(MarketError::InvalidDenuoPriceRound)
        ));
        assert_eq!(
            load_denuo_price_round_cache(&request_store, &policy).expect("unchanged cache"),
            None
        );
    }

    #[test]
    fn canonical_price_round_board_rejects_rollback_equivocation_and_circuit_breaker() {
        let first = price_round(9, 100, 120, [0; 32], 100);
        let policy = admission_policy(&first);
        let mut store = WalletStore::create(":memory:", "rollback-passphrase").expect("store");
        bootstrap_denuo_price_round_cache(&mut store, &policy, None, &gossip(&first), 121)
            .expect("first round");

        let broken_link = price_round(10, 121, 140, [0; 32], 101);
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&broken_link), 141),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let overlapping = price_round(10, 120, 140, first.round_hash, 101);
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&overlapping), 141),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let excessive_movement = price_round(10, 121, 140, first.round_hash, 200);
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&excessive_movement), 141),
            Err(MarketError::InvalidDenuoPriceRound)
        ));

        let reused_id = price_round(9, 121, 140, first.round_hash, 101);
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&reused_id), 141),
            Err(MarketError::DenuoPriceRoundReplay)
        ));

        let successor = price_round(10, 121, 140, first.round_hash, 101);
        admit_denuo_price_round(&mut store, &policy, &gossip(&successor), 141)
            .expect("valid successor");
        assert!(matches!(
            admit_denuo_price_round(&mut store, &policy, &gossip(&first), 142),
            Err(MarketError::DenuoPriceRoundReplay)
        ));
    }

    #[test]
    fn canonical_price_round_board_rejects_signed_sequence_regression_on_restart() {
        let first =
            price_round_with_reporters(1, 100, 120, [0; 32], 100, &[(1, 101), (2, 102), (3, 103)]);
        let regressed = price_round_with_reporters(
            2,
            121,
            140,
            first.round_hash,
            100,
            &[(1, 51), (2, 52), (3, 53)],
        );
        let policy = admission_policy(&first);
        let mut store = WalletStore::create(":memory:", "regression-passphrase").expect("store");
        bootstrap_denuo_price_round_cache(&mut store, &policy, None, &gossip(&first), 121)
            .expect("first round");

        let head_id = price_round_head_id(&policy).expect("head ID");
        let stored: StoredEntity<PersistedPriceRoundEntity> = store
            .price_round(&head_id)
            .expect("load head")
            .expect("head");
        let head_revision = stored.revision;
        let PersistedPriceRoundEntity::Head {
            schema_version,
            policy_fingerprint,
            first_parent_unretained,
            retired_rounds,
            retired_reporter_sequence_high_watermarks,
            reporter_sequence_high_watermarks,
            mut history,
        } = stored.value
        else {
            panic!("expected head")
        };
        let (record_id, round_entity, round_index) =
            persisted_round(&policy, &regressed, 141).expect("persisted regressed round");
        history.push(round_index);
        let saves = [
            EntityBatchSave {
                id: record_id,
                expected_revision: 0,
                value: round_entity,
                updated_at_unix: 141,
            },
            EntityBatchSave {
                id: head_id,
                expected_revision: head_revision,
                value: PersistedPriceRoundEntity::Head {
                    schema_version,
                    policy_fingerprint,
                    first_parent_unretained,
                    retired_rounds,
                    retired_reporter_sequence_high_watermarks,
                    reporter_sequence_high_watermarks,
                    history,
                },
                updated_at_unix: 141,
            },
        ];
        store
            .apply_entity_batch(EntityKind::PriceRound, &saves, &[])
            .expect("inject authenticated logical corruption");

        assert!(matches!(
            load_denuo_price_round_cache(&store, &policy),
            Err(MarketError::CorruptDenuoPriceRoundCache)
        ));
    }

    #[test]
    fn canonical_price_round_board_bounds_history_and_rejects_corrupt_head() {
        let first = price_round(1, 100, 110, [0; 32], 100);
        let policy = admission_policy(&first);
        let mut store = WalletStore::create(":memory:", "history-passphrase").expect("store");
        let first_hash = ObjectHash::new(first.round_hash);
        let (first_record_id, first_record_entity, _) =
            persisted_round(&policy, &first, 111).expect("first persisted round");
        let mut current = first;
        let mut history = Vec::with_capacity(MAX_DENUO_PRICE_ROUND_HISTORY);
        let mut saves = Vec::with_capacity(MAX_DENUO_PRICE_ROUND_HISTORY + 1);
        let mut reporter_sequence_high_watermarks = vec![0; policy.admitted_reporters.len()];
        for offset in 0..MAX_DENUO_PRICE_ROUND_HISTORY {
            if offset > 0 {
                let interval_start = 100 + (offset as u64 * 11);
                current = price_round(
                    (offset + 1) as u8,
                    interval_start,
                    interval_start + 10,
                    current.round_hash,
                    100,
                );
            }
            advance_reporter_sequence_high_watermarks(
                &policy,
                &mut reporter_sequence_high_watermarks,
                &current,
            )
            .expect("advance seeded watermarks");
            let accepted_at_unix = current.interval_end + 1;
            let (id, value, index) =
                persisted_round(&policy, &current, accepted_at_unix).expect("seeded round");
            history.push(index);
            saves.push(EntityBatchSave {
                id,
                expected_revision: 0,
                value,
                updated_at_unix: accepted_at_unix,
            });
        }
        validate_history(&history).expect("seeded history");
        saves.push(EntityBatchSave {
            id: price_round_head_id(&policy).expect("head ID"),
            expected_revision: 0,
            value: PersistedPriceRoundEntity::Head {
                schema_version: DENUO_PRICE_ROUND_SCHEMA_VERSION,
                policy_fingerprint: policy.fingerprint,
                first_parent_unretained: false,
                retired_rounds: 0,
                retired_reporter_sequence_high_watermarks: vec![0; policy.admitted_reporters.len()],
                reporter_sequence_high_watermarks,
                history,
            },
            updated_at_unix: current.interval_end + 1,
        });
        store
            .apply_entity_batch(EntityKind::PriceRound, &saves, &[])
            .expect("seed full retained suffix atomically");

        let interval_start = current.interval_end + 1;
        current = price_round(
            (MAX_DENUO_PRICE_ROUND_HISTORY + 1) as u8,
            interval_start,
            interval_start + 10,
            current.round_hash,
            100,
        );
        assert!(
            store
                .delete_price_round(&first_record_id, 1)
                .expect("delete oldest test record")
        );
        assert!(matches!(
            admit_denuo_price_round(
                &mut store,
                &policy,
                &gossip(&current),
                current.interval_end + 1,
            ),
            Err(MarketError::CorruptDenuoPriceRoundCache)
        ));
        let candidate_before_retry: Option<StoredEntity<PersistedPriceRoundEntity>> = store
            .price_round(&price_round_record_id(ObjectHash::new(current.round_hash)))
            .expect("query rejected candidate");
        assert!(candidate_before_retry.is_none());
        store
            .save_price_round(&first_record_id, 0, &first_record_entity, 111)
            .expect("restore oldest test record");
        admit_denuo_price_round(
            &mut store,
            &policy,
            &gossip(&current),
            current.interval_end + 1,
        )
        .expect("admit and prune one round");
        let snapshot = load_denuo_price_round_cache(&store, &policy)
            .expect("load bounded history")
            .expect("cached round");
        assert_eq!(snapshot.retained_rounds, MAX_DENUO_PRICE_ROUND_HISTORY);
        let retired: Option<StoredEntity<PersistedPriceRoundEntity>> = store
            .price_round(&price_round_record_id(first_hash))
            .expect("query retired round");
        assert!(retired.is_none());

        let replay_start = current.interval_end + 1;
        let replay_after_prune = price_round_with_reporters(
            200,
            replay_start,
            replay_start + 10,
            current.round_hash,
            100,
            &[(1, 1_001), (2, 1_002), (3, 1_003)],
        );
        assert!(matches!(
            admit_denuo_price_round(
                &mut store,
                &policy,
                &gossip(&replay_after_prune),
                replay_after_prune.interval_end + 1,
            ),
            Err(MarketError::DenuoPriceRoundReplay)
        ));

        let head_id = price_round_head_id(&policy).expect("head ID");
        let stored: StoredEntity<PersistedPriceRoundEntity> = store
            .price_round(&head_id)
            .expect("load head")
            .expect("head");
        let PersistedPriceRoundEntity::Head {
            schema_version,
            policy_fingerprint,
            first_parent_unretained,
            retired_rounds,
            mut retired_reporter_sequence_high_watermarks,
            reporter_sequence_high_watermarks,
            history,
        } = stored.value
        else {
            panic!("expected head")
        };
        retired_reporter_sequence_high_watermarks[0] = reporter_sequence_high_watermarks[0] + 1;
        store
            .save_price_round(
                &head_id,
                stored.revision,
                &PersistedPriceRoundEntity::Head {
                    schema_version,
                    policy_fingerprint,
                    first_parent_unretained,
                    retired_rounds,
                    retired_reporter_sequence_high_watermarks,
                    reporter_sequence_high_watermarks,
                    history,
                },
                stored.updated_at_unix,
            )
            .expect("persist authenticated logical corruption");
        assert!(matches!(
            load_denuo_price_round_cache(&store, &policy),
            Err(MarketError::CorruptDenuoPriceRoundCache)
        ));
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
    #[test]
    fn canonical_price_round_board_reopens_from_encrypted_store() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let configured_root = std::env::var_os("HNS_WALLET_STORE_TEST_TMPDIR")
            .map(PathBuf::from)
            .filter(|path| {
                std::fs::metadata(path).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0
                })
            });
        let root = configured_root.unwrap_or_else(|| PathBuf::from("/tmp"));
        let directory = root.join(format!(
            "hns-wallet-price-round-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("test wallet directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private test wallet directory");
        let _cleanup = TestWalletDirectory(directory.clone());
        let database = directory.join("wallet.sqlite3");

        let first = price_round(9, 100, 120, [0; 32], 100);
        let policy = admission_policy(&first);
        let mut store = WalletStore::create(&database, "restart-passphrase")
            .unwrap_or_else(|error| panic!("store at {}: {error:?}", database.display()));
        let admitted =
            bootstrap_denuo_price_round_cache(&mut store, &policy, None, &gossip(&first), 121)
                .expect("admit round")
                .snapshot();
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen store");
        reopened.unlock("restart-passphrase").expect("unlock store");
        assert_eq!(
            load_denuo_price_round_cache(&reopened, &policy).expect("reload cache"),
            Some(admitted)
        );
    }
}
