use bdk_wallet::bitcoin::consensus::{deserialize, serialize};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Block, OutPoint, ScriptBuf, Transaction};
use bdk_wallet::chain::CheckPoint;
use hns_wallet_chain_api::Preimage;
use hns_wallet_store::{
    EntityBatchSave, EntityKind, EntityPrefixSetLease, StoreError, StoredEntity, WalletStore,
};
use hns_wallet_types::{ObjectHash, SessionId, TransactionHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BitcoinCheckpoint, BitcoinHtlc, BitcoinWalletError, HtlcSpendBranch, MIN_HTLC_DUST_SATS,
    VerifiedBitcoinHtlcSpend, VerifiedBitcoinLock, htlc_commitment, verify_htlc_funding,
    verify_signed_bitcoin_htlc_spend,
};

const BITCOIN_SWAP_WATCH_SCHEMA_VERSION: u16 = 1;
const BITCOIN_SWAP_WATCH_PREFIX: &[u8] = b"bitcoin-htlc-watch-v1\0";
const BITCOIN_SWAP_WATCH_ACCOUNT_DOMAIN: &[u8] = b"hns-wallet-bitcoin-watch-account/v1\0";
const BITCOIN_SWAP_WATCH_TERMS_DOMAIN: &[u8] = b"hns-wallet-bitcoin-watch-terms/v1\0";
pub const MAX_BITCOIN_SWAP_WATCHES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinHtlcWatchRequest {
    pub session_id: SessionId,
    pub htlc: BitcoinHtlc,
    pub expected_value_sats: u64,
    pub minimum_confirmations: u32,
}

impl BitcoinHtlcWatchRequest {
    fn validate(&self) -> Result<(), BitcoinWalletError> {
        self.htlc.validate()?;
        if self.session_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.expected_value_sats < MIN_HTLC_DUST_SATS
            || self.minimum_confirmations == 0
        {
            return Err(BitcoinWalletError::InvalidSwapWatch);
        }
        Ok(())
    }

    pub fn terms_commitment(&self) -> Result<ObjectHash, BitcoinWalletError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(BITCOIN_SWAP_WATCH_TERMS_DOMAIN);
        hasher.update(self.session_id.as_bytes());
        hasher.update(htlc_commitment(&self.htlc).as_bytes());
        hasher.update(self.expected_value_sats.to_be_bytes());
        hasher.update(self.minimum_confirmations.to_be_bytes());
        Ok(ObjectHash::new(hasher.finalize().into()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitcoinHtlcWatchAdmission {
    Registered(BitcoinHtlcWatchSnapshot),
    Existing(BitcoinHtlcWatchSnapshot),
}

impl BitcoinHtlcWatchAdmission {
    pub const fn snapshot(self) -> BitcoinHtlcWatchSnapshot {
        match self {
            Self::Registered(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    pub const fn registered(self) -> bool {
        matches!(self, Self::Registered(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinHtlcWatchSnapshot {
    pub revision: u64,
    pub session_id: SessionId,
    pub terms_commitment: ObjectHash,
    pub registered_checkpoint: BitcoinCheckpoint,
    pub scanned_checkpoint: BitcoinCheckpoint,
    pub funding_txid: Option<TransactionHash>,
    pub funding_height: Option<u32>,
    pub funding_confirmations: u32,
    pub spending_txid: Option<TransactionHash>,
    pub spending_height: Option<u32>,
    pub spending_confirmations: u32,
    pub spend_branch: Option<HtlcSpendBranch>,
    pub preimage_revealed: bool,
}

/// One HTLC spend re-authenticated from this wallet's compact-filter chain
/// view. The observation is available only while the caller presents the
/// exact checkpoint to which the watch was reconciled, preventing stale or
/// reorged watch data from advancing a recovery workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinHtlcSpendObservation {
    pub spend: VerifiedBitcoinHtlcSpend,
    pub confirmation_count: u32,
}

/// Re-authenticated encrypted HTLC observation state. Raw transactions and a
/// revealed preimage are available only through explicit accessors and are
/// never included in `Debug` output.
pub struct BitcoinHtlcWatch {
    revision: u64,
    persisted: PersistedBitcoinHtlcWatch,
}

impl core::fmt::Debug for BitcoinHtlcWatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BitcoinHtlcWatch")
            .field("snapshot", &self.snapshot())
            .field("funding_transaction", &"[REDACTED]")
            .field("spending_transaction", &"[REDACTED]")
            .field("preimage", &"[REDACTED]")
            .finish()
    }
}

impl BitcoinHtlcWatch {
    pub fn snapshot(&self) -> BitcoinHtlcWatchSnapshot {
        snapshot(self.revision, &self.persisted)
    }

    pub fn htlc(&self) -> &BitcoinHtlc {
        &self.persisted.htlc
    }

    pub fn funding_raw_transaction(&self) -> Option<&[u8]> {
        self.persisted
            .funding
            .as_ref()
            .map(|observation| observation.raw_transaction.as_slice())
    }

    pub fn spending_raw_transaction(&self) -> Option<&[u8]> {
        self.persisted
            .spend
            .as_ref()
            .map(|observation| observation.raw_transaction.as_slice())
    }

    pub fn revealed_preimage(&self) -> Option<Preimage> {
        self.persisted.revealed_preimage.map(Preimage::new)
    }

    /// Returns a settlement-authoritative lock only when the caller's current
    /// locally validated tip is exactly the tip against which this record was
    /// reconciled. This prevents a loaded but not-yet-resynchronized record
    /// from silently authorizing settlement after a reorganization.
    pub fn verified_lock_at(
        &self,
        current_checkpoint: BitcoinCheckpoint,
    ) -> Option<VerifiedBitcoinLock> {
        let funding = self.persisted.funding.as_ref()?;
        (current_checkpoint == self.persisted.scanned_checkpoint
            && funding.confirmation_count >= self.persisted.minimum_confirmations)
            .then(|| VerifiedBitcoinLock {
                funding_txid: TransactionHash::new(funding.txid),
                output_index: funding.output_index,
                value_sats: self.persisted.expected_value_sats,
                confirmation_count: funding.confirmation_count,
                htlc: self.persisted.htlc.clone(),
            })
    }

    /// Return a complete, locally re-verified HTLC spend only when this watch
    /// is still reconciled to the caller's current compact-filter checkpoint.
    /// The raw transaction is verified again against the exact retained
    /// funding outpoint and witness branch before it is returned.
    pub fn verified_spend_at(
        &self,
        current_checkpoint: BitcoinCheckpoint,
    ) -> Option<VerifiedBitcoinHtlcSpendObservation> {
        if current_checkpoint != self.persisted.scanned_checkpoint {
            return None;
        }
        let funding = self.persisted.funding.as_ref()?;
        let spend = self.persisted.spend.as_ref()?;
        let branch = spend.branch?;
        let lock = self.verified_lock_at(current_checkpoint)?;
        let verified =
            verify_signed_bitcoin_htlc_spend(&spend.raw_transaction, &lock, branch).ok()?;
        (verified.txid.into_bytes() == spend.txid
            && verified.wtxid == spend.wtxid
            && verified.revealed_preimage == spend.preimage
            && funding.confirmation_count >= self.persisted.minimum_confirmations
            && spend.confirmation_count != 0)
            .then_some(VerifiedBitcoinHtlcSpendObservation {
                spend: verified,
                confirmation_count: spend.confirmation_count,
            })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedBitcoinHtlcWatch {
    schema_version: u16,
    network: bdk_wallet::bitcoin::Network,
    account_binding: [u8; 32],
    session_id: SessionId,
    terms_commitment: ObjectHash,
    htlc: BitcoinHtlc,
    expected_value_sats: u64,
    minimum_confirmations: u32,
    registered_checkpoint: BitcoinCheckpoint,
    scanned_checkpoint: BitcoinCheckpoint,
    funding: Option<PersistedBitcoinSwapObservation>,
    spend: Option<PersistedBitcoinSwapObservation>,
    revealed_preimage: Option<[u8; 32]>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedBitcoinSwapObservation {
    txid: [u8; 32],
    wtxid: [u8; 32],
    block_height: u32,
    block_hash: [u8; 32],
    confirmation_count: u32,
    output_index: u32,
    branch: Option<HtlcSpendBranch>,
    preimage: Option<[u8; 32]>,
    raw_transaction: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct MatchedBitcoinBlock {
    pub height: u32,
    pub block: Block,
}

pub fn load_bitcoin_htlc_watch(
    store: &WalletStore,
    network: bdk_wallet::bitcoin::Network,
    account_id: &[u8],
    session_id: SessionId,
) -> Result<Option<BitcoinHtlcWatch>, BitcoinWalletError> {
    let binding = account_binding(network, account_id)?;
    store
        .bitcoin_swap_watch::<PersistedBitcoinHtlcWatch>(&watch_id(binding, session_id))?
        .map(|stored| decode_watch(network, binding, stored))
        .transpose()
}

pub fn load_bitcoin_htlc_watches(
    store: &WalletStore,
    network: bdk_wallet::bitcoin::Network,
    account_id: &[u8],
) -> Result<Vec<BitcoinHtlcWatch>, BitcoinWalletError> {
    let binding = account_binding(network, account_id)?;
    let stored = store.list_entities_by_id_prefix::<PersistedBitcoinHtlcWatch>(
        EntityKind::BitcoinSwapWatch,
        &watch_prefix(binding),
        MAX_BITCOIN_SWAP_WATCHES + 1,
    )?;
    if stored.len() > MAX_BITCOIN_SWAP_WATCHES {
        return Err(BitcoinWalletError::SwapWatchCapacity);
    }
    stored
        .into_iter()
        .map(|stored| decode_watch(network, binding, stored))
        .collect()
}

pub(crate) fn register_bitcoin_htlc_watch(
    store: &mut WalletStore,
    network: bdk_wallet::bitcoin::Network,
    account_id: &[u8],
    request: &BitcoinHtlcWatchRequest,
    checkpoint: BitcoinCheckpoint,
    now_unix: u64,
) -> Result<BitcoinHtlcWatchAdmission, BitcoinWalletError> {
    request.validate()?;
    checkpoint.validate(network)?;
    let binding = account_binding(network, account_id)?;
    if let Some(existing) = load_bitcoin_htlc_watch(store, network, account_id, request.session_id)?
    {
        if existing.persisted.terms_commitment == request.terms_commitment()?
            && existing.persisted.htlc == request.htlc
            && existing.persisted.expected_value_sats == request.expected_value_sats
            && existing.persisted.minimum_confirmations == request.minimum_confirmations
        {
            return Ok(BitcoinHtlcWatchAdmission::Existing(existing.snapshot()));
        }
        return Err(BitcoinWalletError::SwapWatchConflict);
    }
    let (stored, lease) = load_watch_set_with_lease(store, binding)?;
    for entity in &stored {
        decode_watch(network, binding, entity.clone())?;
    }
    if stored.len() >= MAX_BITCOIN_SWAP_WATCHES {
        return Err(BitcoinWalletError::SwapWatchCapacity);
    }
    let persisted = PersistedBitcoinHtlcWatch {
        schema_version: BITCOIN_SWAP_WATCH_SCHEMA_VERSION,
        network,
        account_binding: binding,
        session_id: request.session_id,
        terms_commitment: request.terms_commitment()?,
        htlc: request.htlc.clone(),
        expected_value_sats: request.expected_value_sats,
        minimum_confirmations: request.minimum_confirmations,
        registered_checkpoint: checkpoint,
        scanned_checkpoint: checkpoint,
        funding: None,
        spend: None,
        revealed_preimage: None,
    };
    store.apply_entity_batch_with_assertions_and_prefix_lease(
        EntityKind::BitcoinSwapWatch,
        &[EntityBatchSave {
            id: watch_id(binding, request.session_id),
            expected_revision: 0,
            value: persisted.clone(),
            updated_at_unix: now_unix,
        }],
        &[],
        &[],
        lease,
    )?;
    Ok(BitcoinHtlcWatchAdmission::Registered(snapshot(
        1, &persisted,
    )))
}

pub(crate) fn watched_scripts(watches: &[BitcoinHtlcWatch]) -> Vec<(SessionId, ScriptBuf)> {
    watches
        .iter()
        .map(|watch| {
            (
                watch.persisted.session_id,
                watch.persisted.htlc.script_pubkey(),
            )
        })
        .collect()
}

pub(crate) fn reconcile_bitcoin_htlc_watches(
    store: &mut WalletStore,
    network: bdk_wallet::bitcoin::Network,
    account_id: &[u8],
    canonical_chain: &CheckPoint,
    tip: BitcoinCheckpoint,
    matched_blocks: &[MatchedBitcoinBlock],
    now_unix: u64,
) -> Result<(), BitcoinWalletError> {
    tip.validate(network)?;
    if canonical_chain.height() != tip.height
        || canonical_chain.hash().to_byte_array() != tip.block_hash
    {
        return Err(BitcoinWalletError::InvalidCheckpoint);
    }
    for matched in matched_blocks {
        validate_matched_block(matched)?;
        if canonical_chain
            .get(matched.height)
            .is_none_or(|checkpoint| checkpoint.hash() != matched.block.block_hash())
        {
            return Err(BitcoinWalletError::InvalidEvidence);
        }
    }
    let binding = account_binding(network, account_id)?;
    let watches = load_bitcoin_htlc_watches(store, network, account_id)?;
    for mut watch in watches {
        let mut changed = false;
        if watch
            .persisted
            .funding
            .as_ref()
            .is_some_and(|observation| !observation_is_canonical(canonical_chain, observation))
        {
            watch.persisted.funding = None;
            watch.persisted.spend = None;
            changed = true;
        } else if watch
            .persisted
            .spend
            .as_ref()
            .is_some_and(|observation| !observation_is_canonical(canonical_chain, observation))
        {
            watch.persisted.spend = None;
            changed = true;
        }

        if watch.persisted.funding.is_none() {
            let candidates = funding_candidates(&watch.persisted, matched_blocks, tip)?;
            match candidates.as_slice() {
                [] => {}
                [candidate] => {
                    watch.persisted.funding = Some(candidate.clone());
                    changed = true;
                }
                _ => return Err(BitcoinWalletError::SwapWatchConflict),
            }
        }
        if watch.persisted.spend.is_none()
            && let Some(funding) = watch.persisted.funding.as_ref()
        {
            let candidates = spend_candidates(&watch.persisted, funding, matched_blocks, tip)?;
            match candidates.as_slice() {
                [] => {}
                [candidate] => {
                    if let Some(preimage) = candidate.preimage {
                        if watch
                            .persisted
                            .revealed_preimage
                            .is_some_and(|known| known != preimage)
                        {
                            return Err(BitcoinWalletError::SwapWatchConflict);
                        }
                        watch.persisted.revealed_preimage = Some(preimage);
                    }
                    watch.persisted.spend = Some(candidate.clone());
                    changed = true;
                }
                _ => return Err(BitcoinWalletError::SwapWatchConflict),
            }
        }
        for observation in watch
            .persisted
            .funding
            .iter_mut()
            .chain(watch.persisted.spend.iter_mut())
        {
            let confirmations = confirmation_count(tip.height, observation.block_height)?;
            if observation.confirmation_count != confirmations {
                observation.confirmation_count = confirmations;
                changed = true;
            }
        }
        if watch.persisted.scanned_checkpoint != tip {
            watch.persisted.scanned_checkpoint = tip;
            changed = true;
        }
        validate_persisted_watch(network, binding, &watch.persisted)?;
        if changed {
            store.save_bitcoin_swap_watch(
                &watch_id(binding, watch.persisted.session_id),
                watch.revision,
                &watch.persisted,
                now_unix,
            )?;
        }
    }
    Ok(())
}

fn funding_candidates(
    watch: &PersistedBitcoinHtlcWatch,
    blocks: &[MatchedBitcoinBlock],
    tip: BitcoinCheckpoint,
) -> Result<Vec<PersistedBitcoinSwapObservation>, BitcoinWalletError> {
    let expected_script = watch.htlc.script_pubkey();
    let mut candidates = Vec::new();
    for matched in blocks {
        if matched.height < watch.registered_checkpoint.height {
            continue;
        }
        validate_matched_block(matched)?;
        for transaction in &matched.block.txdata {
            if !transaction.output.iter().any(|output| {
                output.value.to_sat() == watch.expected_value_sats
                    && output.script_pubkey == expected_script
            }) {
                continue;
            }
            let raw = serialize(transaction);
            let confirmations = confirmation_count(tip.height, matched.height)?;
            let verified = verify_htlc_funding(
                &raw,
                &watch.htlc,
                watch.expected_value_sats,
                confirmations,
                0,
            )?;
            candidates.push(PersistedBitcoinSwapObservation {
                txid: verified.funding_txid.into_bytes(),
                wtxid: transaction.compute_wtxid().to_byte_array(),
                block_height: matched.height,
                block_hash: matched.block.block_hash().to_byte_array(),
                confirmation_count: confirmations,
                output_index: verified.output_index,
                branch: None,
                preimage: None,
                raw_transaction: raw,
            });
        }
    }
    Ok(candidates)
}

fn spend_candidates(
    watch: &PersistedBitcoinHtlcWatch,
    funding: &PersistedBitcoinSwapObservation,
    blocks: &[MatchedBitcoinBlock],
    tip: BitcoinCheckpoint,
) -> Result<Vec<PersistedBitcoinSwapObservation>, BitcoinWalletError> {
    let outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(funding.txid),
        vout: funding.output_index,
    };
    let lock = VerifiedBitcoinLock {
        funding_txid: TransactionHash::new(funding.txid),
        output_index: funding.output_index,
        value_sats: watch.expected_value_sats,
        confirmation_count: funding.confirmation_count,
        htlc: watch.htlc.clone(),
    };
    let mut candidates = Vec::new();
    for matched in blocks {
        if matched.height < funding.block_height {
            continue;
        }
        validate_matched_block(matched)?;
        for transaction in &matched.block.txdata {
            if !transaction
                .input
                .iter()
                .any(|input| input.previous_output == outpoint)
            {
                continue;
            }
            let raw = serialize(transaction);
            let verified = verify_signed_bitcoin_htlc_spend(&raw, &lock, HtlcSpendBranch::Redeem)
                .or_else(|_| {
                verify_signed_bitcoin_htlc_spend(&raw, &lock, HtlcSpendBranch::Refund)
            })?;
            let confirmations = confirmation_count(tip.height, matched.height)?;
            candidates.push(PersistedBitcoinSwapObservation {
                txid: verified.txid.into_bytes(),
                wtxid: verified.wtxid,
                block_height: matched.height,
                block_hash: matched.block.block_hash().to_byte_array(),
                confirmation_count: confirmations,
                output_index: 0,
                branch: Some(verified.branch),
                preimage: verified.revealed_preimage,
                raw_transaction: raw,
            });
        }
    }
    Ok(candidates)
}

fn decode_watch(
    network: bdk_wallet::bitcoin::Network,
    binding: [u8; 32],
    stored: StoredEntity<PersistedBitcoinHtlcWatch>,
) -> Result<BitcoinHtlcWatch, BitcoinWalletError> {
    if stored.id != watch_id(binding, stored.value.session_id) {
        return Err(BitcoinWalletError::CorruptSwapWatch);
    }
    validate_persisted_watch(network, binding, &stored.value)?;
    Ok(BitcoinHtlcWatch {
        revision: stored.revision,
        persisted: stored.value,
    })
}

fn validate_persisted_watch(
    network: bdk_wallet::bitcoin::Network,
    binding: [u8; 32],
    watch: &PersistedBitcoinHtlcWatch,
) -> Result<(), BitcoinWalletError> {
    let request = BitcoinHtlcWatchRequest {
        session_id: watch.session_id,
        htlc: watch.htlc.clone(),
        expected_value_sats: watch.expected_value_sats,
        minimum_confirmations: watch.minimum_confirmations,
    };
    if watch.schema_version != BITCOIN_SWAP_WATCH_SCHEMA_VERSION
        || watch.network != network
        || watch.account_binding != binding
        || watch.terms_commitment != request.terms_commitment()?
        || watch.registered_checkpoint.height > watch.scanned_checkpoint.height
        || watch.spend.is_some() && watch.funding.is_none()
        || watch
            .revealed_preimage
            .is_some_and(|preimage| Sha256::digest(preimage).as_slice() != watch.htlc.hashlock)
    {
        return Err(BitcoinWalletError::CorruptSwapWatch);
    }
    watch.registered_checkpoint.validate(network)?;
    watch.scanned_checkpoint.validate(network)?;
    if let Some(funding) = &watch.funding {
        validate_observation(funding)?;
        if funding.branch.is_some()
            || funding.preimage.is_some()
            || funding.block_height < watch.registered_checkpoint.height
            || confirmation_count(watch.scanned_checkpoint.height, funding.block_height)?
                != funding.confirmation_count
        {
            return Err(BitcoinWalletError::CorruptSwapWatch);
        }
        let verified = verify_htlc_funding(
            &funding.raw_transaction,
            &watch.htlc,
            watch.expected_value_sats,
            funding.confirmation_count,
            0,
        )?;
        if verified.funding_txid.into_bytes() != funding.txid
            || verified.output_index != funding.output_index
        {
            return Err(BitcoinWalletError::CorruptSwapWatch);
        }
    }
    if let (Some(funding), Some(spend)) = (&watch.funding, &watch.spend) {
        validate_observation(spend)?;
        if confirmation_count(watch.scanned_checkpoint.height, spend.block_height)?
            != spend.confirmation_count
        {
            return Err(BitcoinWalletError::CorruptSwapWatch);
        }
        let branch = spend.branch.ok_or(BitcoinWalletError::CorruptSwapWatch)?;
        let lock = VerifiedBitcoinLock {
            funding_txid: TransactionHash::new(funding.txid),
            output_index: funding.output_index,
            value_sats: watch.expected_value_sats,
            confirmation_count: funding.confirmation_count,
            htlc: watch.htlc.clone(),
        };
        let verified = verify_signed_bitcoin_htlc_spend(&spend.raw_transaction, &lock, branch)?;
        if verified.txid.into_bytes() != spend.txid
            || verified.wtxid != spend.wtxid
            || verified.revealed_preimage != spend.preimage
            || spend
                .preimage
                .is_some_and(|preimage| watch.revealed_preimage != Some(preimage))
            || spend.block_height < funding.block_height
        {
            return Err(BitcoinWalletError::CorruptSwapWatch);
        }
    }
    Ok(())
}

fn validate_observation(
    observation: &PersistedBitcoinSwapObservation,
) -> Result<(), BitcoinWalletError> {
    if observation.txid == [0; 32]
        || observation.wtxid == [0; 32]
        || observation.block_hash == [0; 32]
        || observation.confirmation_count == 0
        || observation.raw_transaction.is_empty()
    {
        return Err(BitcoinWalletError::CorruptSwapWatch);
    }
    let transaction: Transaction = deserialize(&observation.raw_transaction)
        .map_err(|_| BitcoinWalletError::CorruptSwapWatch)?;
    if serialize(&transaction) != observation.raw_transaction
        || transaction.compute_txid().to_byte_array() != observation.txid
        || transaction.compute_wtxid().to_byte_array() != observation.wtxid
    {
        return Err(BitcoinWalletError::CorruptSwapWatch);
    }
    Ok(())
}

fn validate_matched_block(block: &MatchedBitcoinBlock) -> Result<(), BitcoinWalletError> {
    if block.block.block_hash().to_byte_array() == [0; 32]
        || !block.block.check_merkle_root()
        || !block.block.check_witness_commitment()
    {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    Ok(())
}

fn observation_is_canonical(
    chain: &CheckPoint,
    observation: &PersistedBitcoinSwapObservation,
) -> bool {
    chain
        .get(observation.block_height)
        .is_some_and(|checkpoint| checkpoint.hash().to_byte_array() == observation.block_hash)
}

fn confirmation_count(tip_height: u32, block_height: u32) -> Result<u32, BitcoinWalletError> {
    tip_height
        .checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or(BitcoinWalletError::InvalidEvidence)
}

fn snapshot(revision: u64, watch: &PersistedBitcoinHtlcWatch) -> BitcoinHtlcWatchSnapshot {
    BitcoinHtlcWatchSnapshot {
        revision,
        session_id: watch.session_id,
        terms_commitment: watch.terms_commitment,
        registered_checkpoint: watch.registered_checkpoint,
        scanned_checkpoint: watch.scanned_checkpoint,
        funding_txid: watch
            .funding
            .as_ref()
            .map(|observation| TransactionHash::new(observation.txid)),
        funding_height: watch
            .funding
            .as_ref()
            .map(|observation| observation.block_height),
        funding_confirmations: watch
            .funding
            .as_ref()
            .map_or(0, |observation| observation.confirmation_count),
        spending_txid: watch
            .spend
            .as_ref()
            .map(|observation| TransactionHash::new(observation.txid)),
        spending_height: watch
            .spend
            .as_ref()
            .map(|observation| observation.block_height),
        spending_confirmations: watch
            .spend
            .as_ref()
            .map_or(0, |observation| observation.confirmation_count),
        spend_branch: watch
            .spend
            .as_ref()
            .and_then(|observation| observation.branch),
        preimage_revealed: watch.revealed_preimage.is_some(),
    }
}

fn load_watch_set_with_lease(
    store: &WalletStore,
    binding: [u8; 32],
) -> Result<
    (
        Vec<StoredEntity<PersistedBitcoinHtlcWatch>>,
        EntityPrefixSetLease,
    ),
    BitcoinWalletError,
> {
    let prefix = watch_prefix(binding);
    store
        .try_with_entity_read_snapshot(|snapshot| {
            let stored = snapshot.list_entities_by_id_prefix(
                EntityKind::BitcoinSwapWatch,
                &prefix,
                MAX_BITCOIN_SWAP_WATCHES + 1,
            )?;
            let lease = snapshot.entity_prefix_set_lease(
                EntityKind::BitcoinSwapWatch,
                &prefix,
                MAX_BITCOIN_SWAP_WATCHES + 1,
            )?;
            Ok::<_, StoreError>((stored, lease))
        })
        .map_err(BitcoinWalletError::from)
}

fn account_binding(
    network: bdk_wallet::bitcoin::Network,
    account_id: &[u8],
) -> Result<[u8; 32], BitcoinWalletError> {
    if account_id.is_empty() || account_id.len() > hns_wallet_store::MAX_RECORD_ID_BYTES {
        return Err(BitcoinWalletError::InvalidSwapWatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(BITCOIN_SWAP_WATCH_ACCOUNT_DOMAIN);
    hasher.update(network.magic().to_bytes());
    hasher.update(
        u64::try_from(account_id.len())
            .map_err(|_| BitcoinWalletError::InvalidSwapWatch)?
            .to_be_bytes(),
    );
    hasher.update(account_id);
    Ok(hasher.finalize().into())
}

fn watch_prefix(binding: [u8; 32]) -> Vec<u8> {
    let mut id = Vec::with_capacity(BITCOIN_SWAP_WATCH_PREFIX.len() + binding.len());
    id.extend_from_slice(BITCOIN_SWAP_WATCH_PREFIX);
    id.extend_from_slice(&binding);
    id
}

fn watch_id(binding: [u8; 32], session_id: SessionId) -> Vec<u8> {
    let mut id = watch_prefix(binding);
    id.extend_from_slice(session_id.as_bytes());
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, CompactTarget, Network, OutPoint, PublicKey, Sequence, TxIn,
        TxMerkleNode, TxOut, Witness, absolute, transaction,
    };
    use bdk_wallet::chain::BlockId;

    use crate::{
        BitcoinHtlcSpendRequest, BitcoinSwapKeyReference, BitcoinSwapKeyRole,
        BitcoinValueRuntimePermit, derive_bitcoin_swap_key, parse_recovery_phrase,
        sign_bitcoin_htlc_spend,
    };

    const ACCOUNT_ID: &[u8] = b"bitcoin-regtest-main";
    const PREIMAGE: [u8; 32] = [9; 32];

    fn public_key(byte: u8) -> PublicKey {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("valid deterministic key");
        PublicKey::new(secret.public_key(&Secp256k1::new()))
    }

    fn funding_transaction(htlc: &BitcoinHtlc, value_sats: u64) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: htlc.script_pubkey(),
            }],
        }
    }

    fn unrelated_transaction(value_sats: u64) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn block(
        previous: BlockHash,
        time: u32,
        nonce: u32,
        mut transactions: Vec<Transaction>,
    ) -> Block {
        let witness_reserved_value = [0; 32];
        let mut commitment_script = Vec::with_capacity(38);
        commitment_script.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
        commitment_script.extend_from_slice(&[0; 32]);
        transactions.insert(
            0,
            Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[witness_reserved_value]),
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(commitment_script),
                }],
            },
        );
        let mut block = Block {
            header: Header {
                version: BlockVersion::default(),
                prev_blockhash: previous,
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce,
            },
            txdata: transactions,
        };
        let witness_root = block.witness_root().expect("non-empty witness tree");
        let commitment = Block::compute_witness_commitment(&witness_root, &witness_reserved_value);
        let mut commitment_script = Vec::with_capacity(38);
        commitment_script.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
        commitment_script.extend_from_slice(&commitment.to_byte_array());
        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(commitment_script);
        block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());
        assert_ne!(block.block_hash().to_byte_array(), [0; 32]);
        block
    }

    fn chain(blocks: impl IntoIterator<Item = BlockId>) -> CheckPoint {
        CheckPoint::from_block_ids(blocks).expect("ascending checkpoint chain")
    }

    fn checkpoint(height: u32, hash: BlockHash) -> BitcoinCheckpoint {
        BitcoinCheckpoint {
            height,
            block_hash: hash.to_byte_array(),
        }
    }

    #[test]
    fn wallet_owned_watch_finds_lock_and_preimage_and_rolls_back_reorgs() {
        let mnemonic = parse_recovery_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("mnemonic");
        let receiver = derive_bitcoin_swap_key(
            &mnemonic,
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::Receiver, 0, 12)
                .expect("receiver reference"),
        )
        .expect("receiver key");
        let htlc = BitcoinHtlc::new(
            Sha256::digest(PREIMAGE).into(),
            receiver
                .public_key()
                .bitcoin_public_key()
                .expect("receiver public key"),
            public_key(4),
            500,
        )
        .expect("HTLC");
        let request = BitcoinHtlcWatchRequest {
            session_id: SessionId::new([7; 32]),
            htlc: htlc.clone(),
            expected_value_sats: 50_000,
            minimum_confirmations: 2,
        };
        let registered_hash = BlockHash::from_byte_array([100; 32]);
        let registered_checkpoint = checkpoint(100, registered_hash);
        let mut store = WalletStore::create(":memory:", "watch-passphrase").expect("store");

        let admission = register_bitcoin_htlc_watch(
            &mut store,
            Network::Regtest,
            ACCOUNT_ID,
            &request,
            registered_checkpoint,
            1,
        )
        .expect("register watch");
        assert!(admission.registered());
        assert!(
            !register_bitcoin_htlc_watch(
                &mut store,
                Network::Regtest,
                ACCOUNT_ID,
                &request,
                registered_checkpoint,
                2,
            )
            .expect("exact registration retry")
            .registered()
        );

        let funding_transaction = funding_transaction(&htlc, request.expected_value_sats);
        let funding_raw = serialize(&funding_transaction);
        let funding_block = block(registered_hash, 101, 1, vec![funding_transaction]);
        let funding_hash = funding_block.block_hash();
        let funding_tip = checkpoint(101, funding_hash);
        let funding_chain = chain([
            BlockId {
                height: 100,
                hash: registered_hash,
            },
            BlockId {
                height: 101,
                hash: funding_hash,
            },
        ]);
        reconcile_bitcoin_htlc_watches(
            &mut store,
            Network::Regtest,
            ACCOUNT_ID,
            &funding_chain,
            funding_tip,
            &[MatchedBitcoinBlock {
                height: 101,
                block: funding_block,
            }],
            3,
        )
        .expect("observe funding");

        let watch =
            load_bitcoin_htlc_watch(&store, Network::Regtest, ACCOUNT_ID, request.session_id)
                .expect("load watch")
                .expect("registered watch");
        assert_eq!(
            watch.funding_raw_transaction(),
            Some(funding_raw.as_slice())
        );
        assert_eq!(watch.snapshot().funding_confirmations, 1);
        assert!(watch.verified_lock_at(funding_tip).is_none());
        assert_eq!(watch.revealed_preimage(), None);

        let signing_lock =
            verify_htlc_funding(&funding_raw, &htlc, request.expected_value_sats, 1, 1)
                .expect("funding lock");
        let destination = ScriptBuf::new_p2wpkh(
            &public_key(8)
                .wpubkey_hash()
                .expect("compressed destination key"),
        );
        let spend_raw = sign_bitcoin_htlc_spend(
            &signing_lock,
            &BitcoinValueRuntimePermit(()),
            BitcoinHtlcSpendRequest {
                destination,
                fee_sats: 500,
                branch: HtlcSpendBranch::Redeem,
                preimage: Some(PREIMAGE),
                chain_context: crate::BitcoinChainLockContext {
                    next_block_height: 400,
                    median_time_past: 500_000_000,
                },
            },
            &receiver,
        )
        .expect("signed redeem");
        let spend_transaction: Transaction = deserialize(&spend_raw).expect("spend transaction");
        let spend_block = block(funding_hash, 102, 2, vec![spend_transaction]);
        let spend_hash = spend_block.block_hash();
        let mut witness_tampered_block = spend_block.clone();
        witness_tampered_block.txdata[1].input[0].witness = Witness::new();
        assert!(witness_tampered_block.check_merkle_root());
        assert!(!witness_tampered_block.check_witness_commitment());
        assert!(matches!(
            validate_matched_block(&MatchedBitcoinBlock {
                height: 102,
                block: witness_tampered_block,
            }),
            Err(BitcoinWalletError::InvalidEvidence)
        ));
        let spend_tip = checkpoint(102, spend_hash);
        let spend_chain = chain([
            BlockId {
                height: 100,
                hash: registered_hash,
            },
            BlockId {
                height: 101,
                hash: funding_hash,
            },
            BlockId {
                height: 102,
                hash: spend_hash,
            },
        ]);
        reconcile_bitcoin_htlc_watches(
            &mut store,
            Network::Regtest,
            ACCOUNT_ID,
            &spend_chain,
            spend_tip,
            &[MatchedBitcoinBlock {
                height: 102,
                block: spend_block,
            }],
            4,
        )
        .expect("observe spend");

        let watch =
            load_bitcoin_htlc_watch(&store, Network::Regtest, ACCOUNT_ID, request.session_id)
                .expect("load reconciled watch")
                .expect("registered watch");
        let snapshot = watch.snapshot();
        assert_eq!(snapshot.funding_confirmations, 2);
        assert_eq!(snapshot.spending_confirmations, 1);
        assert_eq!(snapshot.spend_branch, Some(HtlcSpendBranch::Redeem));
        assert!(snapshot.preimage_revealed);
        assert_eq!(watch.spending_raw_transaction(), Some(spend_raw.as_slice()));
        assert_eq!(
            watch
                .revealed_preimage()
                .expect("revealed preimage")
                .expose_for_settlement(),
            &PREIMAGE
        );
        assert_eq!(
            watch
                .verified_lock_at(spend_tip)
                .expect("mature canonical lock")
                .confirmation_count,
            2
        );
        let observed_spend = watch
            .verified_spend_at(spend_tip)
            .expect("checkpoint-bound canonical spend");
        assert_eq!(observed_spend.spend.branch, HtlcSpendBranch::Redeem);
        assert_eq!(observed_spend.spend.revealed_preimage, Some(PREIMAGE));
        assert_eq!(observed_spend.confirmation_count, 1);
        assert!(
            watch
                .verified_lock_at(BitcoinCheckpoint {
                    height: 102,
                    block_hash: [99; 32],
                })
                .is_none()
        );
        assert!(
            watch
                .verified_spend_at(BitcoinCheckpoint {
                    height: 102,
                    block_hash: [99; 32],
                })
                .is_none()
        );
        assert!(format!("{watch:?}").contains("[REDACTED]"));

        let replacement_spend_block =
            block(funding_hash, 102, 3, vec![unrelated_transaction(1_000)]);
        let replacement_spend_hash = replacement_spend_block.block_hash();
        let replacement_spend_tip = checkpoint(102, replacement_spend_hash);
        let replacement_spend_chain = chain([
            BlockId {
                height: 100,
                hash: registered_hash,
            },
            BlockId {
                height: 101,
                hash: funding_hash,
            },
            BlockId {
                height: 102,
                hash: replacement_spend_hash,
            },
        ]);
        reconcile_bitcoin_htlc_watches(
            &mut store,
            Network::Regtest,
            ACCOUNT_ID,
            &replacement_spend_chain,
            replacement_spend_tip,
            &[],
            5,
        )
        .expect("roll back orphaned spend");
        let watch =
            load_bitcoin_htlc_watch(&store, Network::Regtest, ACCOUNT_ID, request.session_id)
                .expect("load reorged watch")
                .expect("registered watch");
        assert_eq!(watch.snapshot().spending_txid, None);
        assert_eq!(watch.snapshot().funding_confirmations, 2);
        assert_eq!(
            watch
                .revealed_preimage()
                .expect("preimage knowledge is monotonic")
                .expose_for_settlement(),
            &PREIMAGE
        );

        let replacement_funding_block =
            block(registered_hash, 101, 4, vec![unrelated_transaction(2_000)]);
        let replacement_funding_hash = replacement_funding_block.block_hash();
        let replacement_tip_block = block(
            replacement_funding_hash,
            102,
            5,
            vec![unrelated_transaction(3_000)],
        );
        let replacement_tip_hash = replacement_tip_block.block_hash();
        let replacement_chain = chain([
            BlockId {
                height: 100,
                hash: registered_hash,
            },
            BlockId {
                height: 101,
                hash: replacement_funding_hash,
            },
            BlockId {
                height: 102,
                hash: replacement_tip_hash,
            },
        ]);
        let replacement_tip = checkpoint(102, replacement_tip_hash);
        reconcile_bitcoin_htlc_watches(
            &mut store,
            Network::Regtest,
            ACCOUNT_ID,
            &replacement_chain,
            replacement_tip,
            &[],
            6,
        )
        .expect("roll back orphaned funding");
        let watch =
            load_bitcoin_htlc_watch(&store, Network::Regtest, ACCOUNT_ID, request.session_id)
                .expect("load fully reorged watch")
                .expect("registered watch");
        assert_eq!(watch.snapshot().funding_txid, None);
        assert!(watch.verified_lock_at(replacement_tip).is_none());
        assert_eq!(
            watch
                .revealed_preimage()
                .expect("known secret survives chain reorganization")
                .expose_for_settlement(),
            &PREIMAGE
        );
    }
}
