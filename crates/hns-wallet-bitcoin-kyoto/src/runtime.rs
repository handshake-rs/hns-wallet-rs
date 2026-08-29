use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bdk_kyoto::bip157::chain::{BlockHeaderChanges, IndexedHeader};
use bdk_kyoto::bip157::{self, ChainState, Client, Event, SyncUpdate};
use bdk_kyoto::builder::Builder;
use bdk_kyoto::{HashCheckpoint, Info, LoggingSubscribers, Requester, ScanType, Warning};
use bdk_wallet::bitcoin::consensus::{deserialize, serialize};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{BlockHash, Network, ScriptBuf, Transaction};
use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::chain::{
    BlockId, ChainPosition, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, TxUpdate,
};
use bdk_wallet::{KeychainKind, Update, Wallet};
use hns_wallet_store::{EntityBatchSave, SharedWalletStore, WalletStore};
use hns_wallet_types::SessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED, BitcoinChainLockContext, BitcoinHtlcWatchAdmission,
    BitcoinHtlcWatchRequest, BitcoinWalletError, EncryptedPersistedBitcoinWallet, HtlcSpendBranch,
    KyotoRuntimeConfig, MAX_RECOVERY_SCRIPT_INDEX, MatchedBitcoinBlock, VerifiedBitcoinLock,
    load_bitcoin_htlc_watches, reconcile_bitcoin_htlc_watches, register_bitcoin_htlc_watch,
    verify_signed_bitcoin_htlc_spend, watched_scripts,
};

pub const KYOTO_WALLET_STATE_VERSION: u16 = 1;
pub const BITCOIN_TRANSACTION_RECORD_VERSION: u16 = 1;
pub const BITCOIN_UTXO_RECORD_VERSION: u16 = 1;
pub const MAX_RECENT_BITCOIN_CHECKPOINTS: usize = 32;
pub const MAX_TRACKED_BITCOIN_TRANSACTIONS: usize = 4_096;
pub const MAX_TRACKED_BITCOIN_OUTPUTS: usize = 4_096;
pub const MAX_BROADCAST_ATTEMPTS: u16 = 16;
pub const MAX_BROADCAST_APPROVAL_LIFETIME_SECONDS: u64 = 3_600;
pub const MIN_REBROADCAST_INTERVAL_SECONDS: u64 = 60;
pub const MAX_PERSISTED_BROADCAST_TRANSACTION_BYTES: usize = 200_000;
pub const MAX_RECONCILIATION_BATCH_SAVES: usize = 512;
pub const MEDIAN_TIME_PAST_HEADERS: usize = 11;
pub const MIN_DATE_BIRTHDAY_SAFETY_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const MAX_DATE_BIRTHDAY_SAFETY_SECONDS: u64 = 366 * 24 * 60 * 60;
/// One deadline for the complete interactive birthday validation. The normal
/// synchronization path can wait for peer/header convergence; a UI setter
/// must instead fail quickly and leave the existing birthday untouched.
pub const BITCOIN_BIRTHDAY_VALIDATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BitcoinCheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
}

impl BitcoinCheckpoint {
    pub fn from_kyoto(checkpoint: HashCheckpoint) -> Self {
        Self {
            height: checkpoint.height,
            block_hash: checkpoint.hash.to_byte_array(),
        }
    }

    pub fn from_wallet(wallet: &Wallet) -> Self {
        let checkpoint = wallet.latest_checkpoint();
        Self {
            height: checkpoint.height(),
            block_hash: checkpoint.hash().to_byte_array(),
        }
    }

    pub fn to_kyoto(self, network: Network) -> Result<HashCheckpoint, BitcoinWalletError> {
        self.validate(network)?;
        Ok(HashCheckpoint::new(
            self.height,
            BlockHash::from_byte_array(self.block_hash),
        ))
    }

    pub fn validate(self, network: Network) -> Result<(), BitcoinWalletError> {
        if self.block_hash == [0; 32] {
            return Err(BitcoinWalletError::InvalidCheckpoint);
        }
        if self.height == 0 {
            let genesis = HashCheckpoint::from_genesis(network);
            if self.block_hash != genesis.hash.to_byte_array() {
                return Err(BitcoinWalletError::NetworkMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinBirthdaySource {
    NewWalletValidatedTip,
    KnownCheckpoint,
    ConservativelyConvertedDate,
    FullScan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinWalletBirthday {
    pub checkpoint: BitcoinCheckpoint,
    pub source: BitcoinBirthdaySource,
    pub source_date_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDateBirthday {
    network: Network,
    checkpoint: BitcoinCheckpoint,
    source_date_unix: u64,
}

impl ValidatedDateBirthday {
    pub const fn checkpoint(self) -> BitcoinCheckpoint {
        self.checkpoint
    }

    pub const fn source_date_unix(self) -> u64 {
        self.source_date_unix
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KyotoRecoveryReason {
    InterruptedInitialScan,
    InterruptedSynchronization,
    WalletDatabaseRollback,
    DeepReorganization,
    CheckpointMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum KyotoSyncPhase {
    Initialized,
    Starting {
        sequence: u64,
        recovery_scan: bool,
    },
    Synchronizing {
        sequence: u64,
        from: BitcoinCheckpoint,
    },
    Reconciling {
        sequence: u64,
        wallet_tip: BitcoinCheckpoint,
        common_ancestor: Option<BitcoinCheckpoint>,
    },
    Ready,
    RecoveryRequired {
        reason: KyotoRecoveryReason,
    },
}

/// Encrypted wallet-owned metadata around BDK's encrypted changeset snapshot.
/// Kyoto 0.17 does not expose a durable filter-header database, so this record
/// never pretends to be the header/filter authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KyotoWalletState {
    pub schema_version: u16,
    pub network: Network,
    pub birthday: BitcoinWalletBirthday,
    pub recovery_checkpoint: BitcoinCheckpoint,
    pub recovery_script_index: u32,
    pub validated_checkpoint: BitcoinCheckpoint,
    pub scanned_checkpoint: BitcoinCheckpoint,
    pub last_consistent_checkpoint: BitcoinCheckpoint,
    pub recent_checkpoints: Vec<BitcoinCheckpoint>,
    pub phase: KyotoSyncPhase,
    pub pending_sequence: u64,
    pub completed_sequence: u64,
    pub completed_syncs: u64,
    pub restart_count: u64,
    pub reorg_count: u64,
    pub relevant_transaction_count: u32,
    pub wallet_output_count: u32,
    pub connected_peer_count: u8,
    pub last_started_at_unix: u64,
    pub last_completed_at_unix: Option<u64>,
}

impl KyotoWalletState {
    pub fn new_wallet(
        validated_tip: DiscoveredKyotoTip,
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        validated_tip.checkpoint.validate(validated_tip.network)?;
        validated_tip
            .recovery_anchor
            .validate(validated_tip.network)?;
        if validated_tip.recovery_anchor.height == 0
            || validated_tip.recovery_anchor.height > validated_tip.checkpoint.height
            || !validated_tip
                .recent_checkpoints
                .contains(&validated_tip.recovery_anchor)
            || !validated_tip
                .recent_checkpoints
                .contains(&validated_tip.checkpoint)
        {
            return Err(BitcoinWalletError::InvalidBirthday);
        }
        let mut state = Self::initialize(
            validated_tip.network,
            BitcoinWalletBirthday {
                checkpoint: validated_tip.checkpoint,
                source: BitcoinBirthdaySource::NewWalletValidatedTip,
                source_date_unix: None,
            },
            validated_tip.recovery_anchor,
            1,
            now_unix,
        )?;
        state.recent_checkpoints = validated_tip.recent_checkpoints;
        state.validate()?;
        Ok(state)
    }

    pub fn restored_wallet(
        network: Network,
        known_birthday: Option<BitcoinCheckpoint>,
        recovery_script_index: u32,
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        let (checkpoint, source) = match known_birthday {
            Some(checkpoint) => (checkpoint, BitcoinBirthdaySource::KnownCheckpoint),
            None => (
                BitcoinCheckpoint::from_kyoto(HashCheckpoint::from_genesis(network)),
                BitcoinBirthdaySource::FullScan,
            ),
        };
        checkpoint.validate(network)?;
        Self::initialize(
            network,
            BitcoinWalletBirthday {
                checkpoint,
                source,
                source_date_unix: None,
            },
            checkpoint,
            recovery_script_index,
            now_unix,
        )
    }

    pub fn restored_from_conservative_date(
        network: Network,
        validated_birthday: ValidatedDateBirthday,
        recovery_script_index: u32,
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        if validated_birthday.network != network {
            return Err(BitcoinWalletError::NetworkMismatch);
        }
        let checkpoint = validated_birthday.checkpoint;
        let source_date_unix = validated_birthday.source_date_unix;
        checkpoint.validate(network)?;
        Self::initialize(
            network,
            BitcoinWalletBirthday {
                checkpoint,
                source: BitcoinBirthdaySource::ConservativelyConvertedDate,
                source_date_unix: Some(source_date_unix),
            },
            checkpoint,
            recovery_script_index,
            now_unix,
        )
    }

    fn initialize(
        network: Network,
        birthday: BitcoinWalletBirthday,
        recovery_checkpoint: BitcoinCheckpoint,
        recovery_script_index: u32,
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        validate_recovery_script_index(recovery_script_index)?;
        let checkpoint = birthday.checkpoint;
        let mut recent_checkpoints = vec![recovery_checkpoint, checkpoint];
        recent_checkpoints.sort_unstable();
        recent_checkpoints.dedup();
        let state = Self {
            schema_version: KYOTO_WALLET_STATE_VERSION,
            network,
            birthday,
            recovery_checkpoint,
            recovery_script_index,
            validated_checkpoint: checkpoint,
            scanned_checkpoint: checkpoint,
            last_consistent_checkpoint: checkpoint,
            recent_checkpoints,
            phase: KyotoSyncPhase::Initialized,
            pending_sequence: 0,
            completed_sequence: 0,
            completed_syncs: 0,
            restart_count: 0,
            reorg_count: 0,
            relevant_transaction_count: 0,
            wallet_output_count: 0,
            connected_peer_count: 0,
            last_started_at_unix: now_unix,
            last_completed_at_unix: None,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.schema_version != KYOTO_WALLET_STATE_VERSION {
            return Err(BitcoinWalletError::UnsupportedStateVersion);
        }
        validate_recovery_script_index(self.recovery_script_index)?;
        self.birthday.checkpoint.validate(self.network)?;
        self.recovery_checkpoint.validate(self.network)?;
        self.validated_checkpoint.validate(self.network)?;
        self.scanned_checkpoint.validate(self.network)?;
        self.last_consistent_checkpoint.validate(self.network)?;
        let birthday_source_valid = match self.birthday.source {
            BitcoinBirthdaySource::ConservativelyConvertedDate => {
                self.birthday.source_date_unix.is_some_and(|date| date != 0)
            }
            BitcoinBirthdaySource::NewWalletValidatedTip
            | BitcoinBirthdaySource::KnownCheckpoint
            | BitcoinBirthdaySource::FullScan => self.birthday.source_date_unix.is_none(),
        };
        if !birthday_source_valid
            || self.recovery_checkpoint.height > self.birthday.checkpoint.height
            || self.birthday.checkpoint.height > self.validated_checkpoint.height
            || self.birthday.checkpoint.height > self.scanned_checkpoint.height
            || self.birthday.checkpoint.height > self.last_consistent_checkpoint.height
            || self.completed_sequence > self.pending_sequence
            || self.recent_checkpoints.is_empty()
            || self.recent_checkpoints.len() > MAX_RECENT_BITCOIN_CHECKPOINTS
            || !self.recent_checkpoints.contains(&self.recovery_checkpoint)
            || usize::try_from(self.relevant_transaction_count)
                .map_or(true, |count| count > MAX_TRACKED_BITCOIN_TRANSACTIONS)
            || usize::try_from(self.wallet_output_count)
                .map_or(true, |count| count > MAX_TRACKED_BITCOIN_OUTPUTS)
        {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        let mut prior = None;
        for checkpoint in &self.recent_checkpoints {
            checkpoint.validate(self.network)?;
            if prior.is_some_and(|height| checkpoint.height <= height) {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
            prior = Some(checkpoint.height);
        }
        if matches!(&self.phase, KyotoSyncPhase::Ready)
            && (self.completed_sequence != self.pending_sequence
                || self.scanned_checkpoint != self.last_consistent_checkpoint
                || !self
                    .recent_checkpoints
                    .contains(&self.last_consistent_checkpoint))
        {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        let sequence_shape_valid = match &self.phase {
            KyotoSyncPhase::Initialized => {
                self.completed_sequence == 0 && self.pending_sequence == 0
            }
            KyotoSyncPhase::Ready => self.pending_sequence == self.completed_sequence,
            KyotoSyncPhase::Starting { sequence, .. }
            | KyotoSyncPhase::Synchronizing { sequence, .. }
            | KyotoSyncPhase::Reconciling { sequence, .. } => {
                *sequence == self.pending_sequence
                    && self.pending_sequence == self.completed_sequence.saturating_add(1)
            }
            KyotoSyncPhase::RecoveryRequired { .. } => {
                self.pending_sequence == self.completed_sequence
                    || self.pending_sequence == self.completed_sequence.saturating_add(1)
            }
        };
        if !sequence_shape_valid {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        Ok(())
    }

    fn scan_type(&self, force_recovery: bool) -> Result<ScanType, BitcoinWalletError> {
        if force_recovery || self.completed_syncs == 0 {
            Ok(ScanType::Recovery {
                used_script_index: self.recovery_script_index,
                checkpoint: self.recovery_checkpoint.to_kyoto(self.network)?,
            })
        } else {
            Ok(ScanType::Sync)
        }
    }

    fn begin_start(
        &mut self,
        recovery_scan: bool,
        now_unix: u64,
    ) -> Result<u64, BitcoinWalletError> {
        let sequence = self
            .completed_sequence
            .checked_add(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        self.pending_sequence = sequence;
        self.restart_count = self
            .restart_count
            .checked_add(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        self.last_started_at_unix = now_unix;
        self.phase = KyotoSyncPhase::Starting {
            sequence,
            recovery_scan,
        };
        Ok(sequence)
    }

    fn begin_cycle(&mut self, now_unix: u64) -> Result<u64, BitcoinWalletError> {
        let sequence = self
            .completed_sequence
            .checked_add(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        self.pending_sequence = sequence;
        self.last_started_at_unix = now_unix;
        self.phase = KyotoSyncPhase::Starting {
            sequence,
            recovery_scan: false,
        };
        Ok(sequence)
    }
}

fn validate_recovery_script_index(index: u32) -> Result<(), BitcoinWalletError> {
    if index == 0 || index > MAX_RECOVERY_SCRIPT_INDEX {
        return Err(BitcoinWalletError::InvalidRecoveryScriptIndex);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredKyotoTip {
    network: Network,
    checkpoint: BitcoinCheckpoint,
    recovery_anchor: BitcoinCheckpoint,
    recent_checkpoints: Vec<BitcoinCheckpoint>,
}

impl DiscoveredKyotoTip {
    pub const fn network(&self) -> Network {
        self.network
    }

    pub const fn checkpoint(&self) -> BitcoinCheckpoint {
        self.checkpoint
    }

    pub const fn recovery_anchor(&self) -> BitcoinCheckpoint {
        self.recovery_anchor
    }

    pub fn recent_checkpoints(&self) -> &[BitcoinCheckpoint] {
        &self.recent_checkpoints
    }

    #[cfg(test)]
    pub(crate) fn testing(
        network: Network,
        checkpoint: BitcoinCheckpoint,
        recovery_anchor: BitcoinCheckpoint,
        recent_checkpoints: Vec<BitcoinCheckpoint>,
    ) -> Self {
        Self {
            network,
            checkpoint,
            recovery_anchor,
            recent_checkpoints,
        }
    }
}

/// Header/filter synchronization used to obtain a validated birthday before a
/// newly created descriptor wallet is allowed to scan. The caller must drain
/// the returned logging receivers while awaiting the result.
pub struct KyotoTipDiscovery {
    network: Network,
    anchor: BitcoinCheckpoint,
    requester: Requester,
    events: bdk_kyoto::UnboundedReceiver<Event>,
    request_timeout: std::time::Duration,
    sync_timeout: std::time::Duration,
    validated_tip: Option<BitcoinCheckpoint>,
    poisoned: bool,
}

impl KyotoTipDiscovery {
    pub fn start(
        config: KyotoRuntimeConfig,
        trusted_anchor: BitcoinCheckpoint,
    ) -> Result<(Self, LoggingSubscribers), BitcoinWalletError> {
        config.validate()?;
        let KyotoRuntimeConfig {
            network,
            data_dir,
            required_peers,
            response_timeout,
            supervisor_request_timeout,
            supervisor_sync_timeout,
            trusted_peers,
        } = config;
        trusted_anchor.validate(network)?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| BitcoinWalletError::RuntimeUnavailable)?;
        let mut builder = Builder::new(network)
            .data_dir(data_dir)
            .required_peers(required_peers)
            .response_timeout(response_timeout)
            .chain_state(ChainState::Checkpoint(trusted_anchor.to_kyoto(network)?));
        if !trusted_peers.is_empty() {
            builder = builder.add_peers(trusted_peers);
        }
        let (node, client) = builder.build();
        let Client {
            requester,
            info_rx,
            warn_rx,
            event_rx,
        } = client;
        std::mem::drop(runtime.spawn(async move {
            let _ = node.run().await;
        }));
        Ok((
            Self {
                network,
                anchor: trusted_anchor,
                requester,
                events: event_rx,
                request_timeout: supervisor_request_timeout,
                sync_timeout: supervisor_sync_timeout,
                validated_tip: None,
                poisoned: false,
            },
            LoggingSubscribers {
                info_subscriber: info_rx,
                warning_subscriber: warn_rx,
            },
        ))
    }

    pub async fn wait_for_validated_tip(
        &mut self,
    ) -> Result<DiscoveredKyotoTip, BitcoinWalletError> {
        if self.poisoned {
            return Err(BitcoinWalletError::SupervisorPoisoned);
        }
        let sync_timeout = self.sync_timeout;
        match tokio::time::timeout(sync_timeout, self.wait_for_validated_tip_inner()).await {
            Ok(result) => result,
            Err(_) => {
                self.poisoned = true;
                let _ = self.requester.shutdown();
                Err(BitcoinWalletError::OperationTimedOut)
            }
        }
    }

    async fn wait_for_validated_tip_inner(
        &mut self,
    ) -> Result<DiscoveredKyotoTip, BitcoinWalletError> {
        while let Some(event) = self.events.recv().await {
            if let Event::FiltersSynced(update) = event {
                let checkpoint = BitcoinCheckpoint::from_kyoto(update.tip);
                checkpoint.validate(self.network)?;
                if checkpoint.height < self.anchor.height {
                    return Err(BitcoinWalletError::InvalidCheckpoint);
                }
                let mut recent = update
                    .recent_history
                    .iter()
                    .map(|(height, header)| BitcoinCheckpoint {
                        height: *height,
                        block_hash: header.block_hash().to_byte_array(),
                    })
                    .collect::<Vec<_>>();
                if !recent.contains(&self.anchor) {
                    recent.push(self.anchor);
                }
                if !recent.contains(&checkpoint) {
                    recent.push(checkpoint);
                }
                recent.sort_unstable();
                recent.dedup();
                if recent.len() > MAX_RECENT_BITCOIN_CHECKPOINTS {
                    let mut bounded = Vec::with_capacity(MAX_RECENT_BITCOIN_CHECKPOINTS);
                    bounded.push(self.anchor);
                    bounded.extend(
                        recent
                            .iter()
                            .rev()
                            .filter(|candidate| **candidate != self.anchor)
                            .take(MAX_RECENT_BITCOIN_CHECKPOINTS - 1)
                            .copied(),
                    );
                    bounded.sort_unstable();
                    bounded.dedup();
                    recent = bounded;
                }
                self.validated_tip = Some(checkpoint);
                return Ok(DiscoveredKyotoTip {
                    network: self.network,
                    checkpoint,
                    recovery_anchor: self.anchor,
                    recent_checkpoints: recent,
                });
            }
        }
        Err(BitcoinWalletError::KyotoNodeStopped)
    }

    /// Verifies that a caller-selected birthday checkpoint is in the synced
    /// chain and has a header timestamp at least the configured safety window
    /// before the recovery date. It does not guess a height from wall time.
    pub async fn validate_conservative_date_checkpoint(
        &self,
        checkpoint: BitcoinCheckpoint,
        source_date_unix: u64,
        safety_seconds: u64,
    ) -> Result<ValidatedDateBirthday, BitcoinWalletError> {
        if self.poisoned {
            return Err(BitcoinWalletError::SupervisorPoisoned);
        }
        let tip = self
            .validated_tip
            .ok_or(BitcoinWalletError::RuntimeNotReady)?;
        checkpoint.validate(self.network)?;
        if checkpoint.height > tip.height
            || source_date_unix == 0
            || !(MIN_DATE_BIRTHDAY_SAFETY_SECONDS..=MAX_DATE_BIRTHDAY_SAFETY_SECONDS)
                .contains(&safety_seconds)
        {
            return Err(BitcoinWalletError::InvalidBirthday);
        }
        let canonical_height = tokio::time::timeout(
            self.request_timeout,
            self.requester
                .height_of_hash(BlockHash::from_byte_array(checkpoint.block_hash)),
        )
        .await
        .map_err(|_| BitcoinWalletError::OperationTimedOut)?
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
        if canonical_height != Some(checkpoint.height) {
            return Err(BitcoinWalletError::InvalidCheckpoint);
        }
        let header = tokio::time::timeout(
            self.request_timeout,
            self.requester.get_header(checkpoint.height),
        )
        .await
        .map_err(|_| BitcoinWalletError::OperationTimedOut)?
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?
        .ok_or(BitcoinWalletError::InvalidCheckpoint)?;
        if header.block_hash().to_byte_array() != checkpoint.block_hash
            || u64::from(header.header.time)
                .checked_add(safety_seconds)
                .is_none_or(|safe_before| safe_before > source_date_unix)
        {
            return Err(BitcoinWalletError::InvalidBirthday);
        }
        Ok(ValidatedDateBirthday {
            network: self.network,
            checkpoint,
            source_date_unix,
        })
    }

    pub fn shutdown(&self) -> Result<(), BitcoinWalletError> {
        self.requester
            .shutdown()
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
    }
}

/// Authenticated scan journal permanently bound to the shared store authority
/// from which it was created or loaded. It deliberately has no `Debug`
/// implementation.
#[derive(Clone)]
pub struct StoredKyotoWalletState {
    account_id: Vec<u8>,
    revision: u64,
    state: KyotoWalletState,
    store: SharedWalletStore,
}

impl StoredKyotoWalletState {
    pub fn create(
        store: &SharedWalletStore,
        account_id: &[u8],
        state: KyotoWalletState,
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        state.validate()?;
        let revision = store.with_store_mut(|store| {
            store.save_bitcoin_scan_state(account_id, 0, &state, now_unix)
        })?;
        Ok(Self {
            account_id: account_id.to_vec(),
            revision,
            state,
            store: store.clone(),
        })
    }

    pub fn load(store: &SharedWalletStore, account_id: &[u8]) -> Result<Self, BitcoinWalletError> {
        let stored = store
            .with_store(|store| store.bitcoin_scan_state::<KyotoWalletState>(account_id))?
            .ok_or(BitcoinWalletError::BitcoinStateNotFound)?;
        stored.value.validate()?;
        Ok(Self {
            account_id: stored.id,
            revision: stored.revision,
            state: stored.value,
            store: store.clone(),
        })
    }

    pub fn state(&self) -> &KyotoWalletState {
        &self.state
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn persist(&mut self, now_unix: u64) -> Result<(), BitcoinWalletError> {
        self.state.validate()?;
        self.revision = self.store.with_store_mut(|store| {
            store.save_bitcoin_scan_state(&self.account_id, self.revision, &self.state, now_unix)
        })?;
        Ok(())
    }

    fn replace(
        &mut self,
        state: KyotoWalletState,
        now_unix: u64,
    ) -> Result<(), BitcoinWalletError> {
        state.validate()?;
        self.state = state;
        self.persist(now_unix)
    }
}

fn wallet_scripts_for_scan(
    index: &KeychainTxOutIndex<KeychainKind>,
    scan_type: ScanType,
) -> HashSet<ScriptBuf> {
    match scan_type {
        ScanType::Sync => wallet_scripts_to_lookahead(index),
        ScanType::Recovery {
            used_script_index, ..
        } => wallet_scripts(index, used_script_index),
    }
}

fn wallet_scripts_to_lookahead(index: &KeychainTxOutIndex<KeychainKind>) -> HashSet<ScriptBuf> {
    wallet_scripts(index, index.lookahead())
}

fn wallet_scripts(index: &KeychainTxOutIndex<KeychainKind>, to_index: u32) -> HashSet<ScriptBuf> {
    let mut scripts = HashSet::new();
    let last_revealed = index.last_revealed_indices();
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        let Some(unbounded) = index.unbounded_spk_iter(keychain) else {
            continue;
        };
        let revealed = last_revealed.get(&keychain).copied().unwrap_or(0);
        let bound = usize::try_from(revealed.saturating_add(to_index)).unwrap_or(usize::MAX);
        scripts.extend(unbounded.take(bound).map(|(_, script)| script));
    }
    scripts
}

fn walk_back_wallet_checkpoint(checkpoint: CheckPoint) -> HashCheckpoint {
    const REORG_SAFETY_DEPTH: usize = 7;
    let mut start = HashCheckpoint::new(checkpoint.height(), checkpoint.hash());
    for (index, ancestor) in checkpoint.iter().enumerate() {
        if index > REORG_SAFETY_DEPTH {
            break;
        }
        start = HashCheckpoint::new(ancestor.height(), ancestor.hash());
    }
    start
}

fn build_wallet_swap_client(
    wallet: &Wallet,
    config: KyotoRuntimeConfig,
    scan_type: ScanType,
    swap_scripts: Vec<(SessionId, ScriptBuf)>,
) -> Result<(Requester, LoggingSubscribers, KyotoWalletSwapSubscriber), BitcoinWalletError> {
    config.validate()?;
    if wallet.network() != config.network {
        return Err(BitcoinWalletError::NetworkMismatch);
    }
    let start = match scan_type {
        ScanType::Sync => walk_back_wallet_checkpoint(wallet.latest_checkpoint()),
        ScanType::Recovery { checkpoint, .. } => checkpoint,
    };
    let mut builder = Builder::new(config.network)
        .data_dir(config.data_dir)
        .required_peers(config.required_peers)
        .response_timeout(config.response_timeout)
        .chain_state(ChainState::Checkpoint(start));
    if !config.trusted_peers.is_empty() {
        builder = builder.add_peers(config.trusted_peers);
    }
    let (node, client) = builder.build();
    let Client {
        requester,
        info_rx,
        warn_rx,
        event_rx,
    } = client;
    let updates = KyotoWalletSwapSubscriber::new(
        requester.clone(),
        event_rx,
        wallet,
        scan_type,
        swap_scripts,
    );
    bip157::tokio::task::spawn(async move { node.run().await });
    Ok((
        requester,
        LoggingSubscribers {
            info_subscriber: info_rx,
            warning_subscriber: warn_rx,
        },
        updates,
    ))
}

struct KyotoWalletSwapUpdate {
    wallet_update: Update,
    canonical_chain: CheckPoint,
    swap_blocks: Vec<MatchedBitcoinBlock>,
}

/// One compact-filter consumer for both the descriptor wallet and every
/// active native HTLC. Keeping the script sets in one subscriber avoids a
/// second node, a second peer pool, or counterparty-provided chain authority.
struct KyotoWalletSwapSubscriber {
    requester: Requester,
    receiver: bip157::tokio::sync::mpsc::UnboundedReceiver<Event>,
    queued_blocks: BTreeMap<BlockHash, bool>,
    wallet_scripts: HashSet<ScriptBuf>,
    swap_scripts: BTreeMap<SessionId, ScriptBuf>,
    chain: CheckPoint,
    graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
}

impl KyotoWalletSwapSubscriber {
    fn new(
        requester: Requester,
        receiver: bip157::tokio::sync::mpsc::UnboundedReceiver<Event>,
        wallet: &Wallet,
        scan_type: ScanType,
        swap_scripts: Vec<(SessionId, ScriptBuf)>,
    ) -> Self {
        let graph = IndexedTxGraph::new(wallet.spk_index().clone());
        let wallet_scripts = wallet_scripts_for_scan(&graph.index, scan_type);
        Self {
            requester,
            receiver,
            queued_blocks: BTreeMap::new(),
            wallet_scripts,
            swap_scripts: swap_scripts.into_iter().collect(),
            chain: wallet.latest_checkpoint(),
            graph,
        }
    }

    fn register_swap_script(&mut self, session_id: SessionId, script: ScriptBuf) {
        self.swap_scripts.insert(session_id, script);
    }

    async fn update(&mut self) -> Result<KyotoWalletSwapUpdate, BitcoinWalletError> {
        let mut swap_blocks = Vec::new();
        while let Some(event) = self.receiver.recv().await {
            match event {
                Event::IndexedFilter(filter) => {
                    let wallet_match = filter.contains_any(self.wallet_scripts.iter());
                    let swap_match = filter.contains_any(self.swap_scripts.values());
                    if wallet_match || swap_match {
                        self.queued_blocks
                            .entry(filter.block_hash())
                            .and_modify(|queued_for_swap| *queued_for_swap |= swap_match)
                            .or_insert(swap_match);
                    }
                }
                Event::ChainUpdate(changes) => self.apply_chain_event(&changes),
                Event::FiltersSynced(SyncUpdate { .. }) => {
                    for (hash, swap_match) in core::mem::take(&mut self.queued_blocks) {
                        let indexed = self
                            .requester
                            .get_block(hash)
                            .await
                            .map_err(|_| BitcoinWalletError::KyotoNodeStopped)?;
                        let _ = self
                            .graph
                            .apply_block_relevant(&indexed.block, indexed.height);
                        if swap_match {
                            swap_blocks.push(MatchedBitcoinBlock {
                                height: indexed.height,
                                block: indexed.block,
                            });
                        }
                    }
                    self.wallet_scripts
                        .extend(wallet_scripts_to_lookahead(&self.graph.index));
                    let tx_update = TxUpdate::from(self.graph.graph().clone());
                    let graph = core::mem::take(&mut self.graph);
                    let last_active_indices = graph.index.last_used_indices();
                    self.graph = IndexedTxGraph::new(graph.index);
                    let canonical_chain = self.chain.clone();
                    return Ok(KyotoWalletSwapUpdate {
                        wallet_update: Update {
                            tx_update,
                            last_active_indices,
                            chain: Some(canonical_chain.clone()),
                        },
                        canonical_chain,
                        swap_blocks,
                    });
                }
            }
        }
        Err(BitcoinWalletError::KyotoNodeStopped)
    }

    fn apply_chain_event(&mut self, event: &BlockHeaderChanges) {
        match event {
            BlockHeaderChanges::Connected(header) => {
                self.chain = self.chain.clone().insert(BlockId {
                    hash: header.block_hash(),
                    height: header.height,
                });
            }
            BlockHeaderChanges::Reorganized { accepted, .. } => {
                for header in accepted {
                    self.chain = self.chain.clone().insert(BlockId {
                        hash: header.block_hash(),
                        height: header.height,
                    });
                }
            }
            _ => {}
        }
    }
}

pub struct KyotoSupervisor {
    requester: Requester,
    updates: KyotoWalletSwapSubscriber,
    cancellation: Arc<KyotoCancellation>,
    required_peers: u8,
    request_timeout: std::time::Duration,
    sync_timeout: std::time::Duration,
    poisoned: bool,
    resume_reconciliation: Option<(BitcoinCheckpoint, Option<BitcoinCheckpoint>)>,
    durable: StoredKyotoWalletState,
    store: SharedWalletStore,
}

/// A narrow, cloneable stop signal for a running Kyoto node.
///
/// Native shells keep this outside the wallet-controller mutex so lifecycle
/// teardown can wake a synchronization that currently owns that mutex. The
/// handle carries no wallet, descriptor, transaction, or store authority.
#[derive(Clone, Debug)]
pub struct KyotoShutdownHandle {
    requester: Requester,
    cancellation: Arc<KyotoCancellation>,
}

#[derive(Debug, Default)]
struct KyotoCancellation {
    requested: AtomicBool,
    notification: tokio::sync::Notify,
}

impl KyotoCancellation {
    fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.notification.notify_waiters();
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notification.notified();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

/// Public, bounded progress from Kyoto's own validated sync pipeline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KyotoSyncProgress {
    pub successful_handshakes: u8,
    pub connection_failures: u16,
    pub peer_timeouts: u16,
    pub incompatible_peers: u16,
    pub connections_met: bool,
    pub chain_height: Option<u32>,
    pub completion_basis_points: u16,
}

/// Read-only progress mailbox which contains no wallet or peer identity.
#[derive(Clone, Debug)]
pub struct KyotoSyncProgressHandle(Arc<Mutex<KyotoSyncProgress>>);

impl KyotoSyncProgressHandle {
    pub fn snapshot(&self) -> KyotoSyncProgress {
        self.0.lock().map(|progress| *progress).unwrap_or_default()
    }
}

/// Drain Kyoto's informational channel into a bounded public mailbox. Warning
/// strings are deliberately discarded because peers must not control native
/// UI text or diagnostic cardinality.
pub fn monitor_kyoto_sync_progress(mut logging: LoggingSubscribers) -> KyotoSyncProgressHandle {
    let progress = Arc::new(Mutex::new(KyotoSyncProgress::default()));
    let worker_progress = Arc::clone(&progress);
    std::mem::drop(tokio::spawn(async move {
        loop {
            tokio::select! {
                info = logging.info_subscriber.recv() => match info {
                    Some(Info::SuccessfulHandshake) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.successful_handshakes =
                                current.successful_handshakes.saturating_add(1);
                        }
                    }
                    Some(Info::ConnectionsMet) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.connections_met = true;
                        }
                    }
                    Some(Info::Progress(update)) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.chain_height = Some(update.chain_height());
                            current.completion_basis_points =
                                (update.fraction_complete().clamp(0.0, 1.0) * 10_000.0)
                                    .round() as u16;
                        }
                    }
                    Some(Info::BlockReceived(_)) => {}
                    None => break,
                },
                warning = logging.warning_subscriber.recv() => match warning {
                    Some(Warning::CouldNotConnect) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.connection_failures =
                                current.connection_failures.saturating_add(1);
                        }
                    }
                    Some(Warning::PeerTimedOut) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.peer_timeouts = current.peer_timeouts.saturating_add(1);
                        }
                    }
                    Some(Warning::NoCompactFilters) => {
                        if let Ok(mut current) = worker_progress.lock() {
                            current.incompatible_peers =
                                current.incompatible_peers.saturating_add(1);
                        }
                    }
                    Some(_) => {}
                    None => break,
                },
            }
        }
    }));
    KyotoSyncProgressHandle(progress)
}

impl KyotoShutdownHandle {
    pub fn request_shutdown(&self) -> Result<(), BitcoinWalletError> {
        // Wake the controller-owned future first. Kyoto's shutdown request is
        // still sent, but failure to enqueue it must not revoke local
        // cancellation or strand the native caller inside `updates.update()`.
        self.cancellation.request();
        let _ = self.requester.shutdown();
        Ok(())
    }
}

impl KyotoSupervisor {
    pub fn start(
        wallet: &EncryptedPersistedBitcoinWallet,
        config: KyotoRuntimeConfig,
        mut durable: StoredKyotoWalletState,
        now_unix: u64,
    ) -> Result<(Self, LoggingSubscribers), BitcoinWalletError> {
        if wallet.network() != durable.state.network || wallet.network() != config.network {
            return Err(BitcoinWalletError::NetworkMismatch);
        }
        if wallet.account_id() != durable.account_id.as_slice() {
            return Err(BitcoinWalletError::WalletStoreAuthorityMismatch);
        }
        if !wallet.shared_store().is_same_authority(&durable.store) {
            return Err(BitcoinWalletError::WalletStoreAuthorityMismatch);
        }
        let store = durable.store.clone();
        durable.state.validate()?;
        let _runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| BitcoinWalletError::RuntimeUnavailable)?;
        let current_wallet_tip = BitcoinCheckpoint::from_wallet(wallet);
        let resume_reconciliation = match &durable.state.phase {
            KyotoSyncPhase::Reconciling {
                wallet_tip,
                common_ancestor,
                ..
            } if *wallet_tip == current_wallet_tip => Some((*wallet_tip, *common_ancestor)),
            _ => None,
        };
        let force_recovery = restart_requires_recovery(&durable.state, wallet);
        let scan_type = durable.state.scan_type(force_recovery)?;
        durable.state.begin_start(force_recovery, now_unix)?;
        durable.persist(now_unix)?;
        let required_peers = config.required_peers;
        let request_timeout = config.supervisor_request_timeout;
        let sync_timeout = config.supervisor_sync_timeout;
        let watches = store.try_with_store(|store| {
            load_bitcoin_htlc_watches(store, wallet.network(), wallet.account_id())
        })?;
        let (requester, logging, updates) =
            build_wallet_swap_client(wallet, config, scan_type, watched_scripts(&watches))?;
        let cancellation = Arc::new(KyotoCancellation::default());
        Ok((
            Self {
                requester,
                updates,
                cancellation,
                required_peers,
                request_timeout,
                sync_timeout,
                poisoned: false,
                resume_reconciliation,
                durable,
                store,
            },
            logging,
        ))
    }

    pub fn state(&self) -> &KyotoWalletState {
        self.durable.state()
    }

    pub fn state_revision(&self) -> u64 {
        self.durable.revision()
    }

    pub fn shutdown_handle(&self) -> KyotoShutdownHandle {
        KyotoShutdownHandle {
            requester: self.requester.clone(),
            cancellation: Arc::clone(&self.cancellation),
        }
    }

    /// Resolve a user-supplied earliest transaction height against Kyoto's
    /// locally validated most-work header chain, then replace the recovery
    /// journal with the preceding checkpoint. Starting one block earlier is
    /// required because a recovery checkpoint is exclusive: the entered
    /// earliest block itself must still be scanned.
    ///
    /// This is an explicit recovery reset, not a mutable sync preference. The
    /// caller must own the controller exclusively and reconstruct the Kyoto
    /// supervisor after success so its scan subscription starts from the new
    /// durable checkpoint.
    pub async fn reset_birthday_height(
        &mut self,
        earliest_transaction_height: u32,
        now_unix: u64,
    ) -> Result<BitcoinCheckpoint, BitcoinWalletError> {
        if self.poisoned || earliest_transaction_height == 0 {
            return Err(BitcoinWalletError::InvalidBirthday);
        }
        let current = self.durable.state.scanned_checkpoint.height;
        if earliest_transaction_height <= current {
            return Err(BitcoinWalletError::InvalidBirthday);
        }
        let checkpoint_height = earliest_transaction_height
            .checked_sub(1)
            .ok_or(BitcoinWalletError::InvalidBirthday)?;
        let validation = async {
            let tip = self
                .requester
                .chain_tip()
                .await
                .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
            if earliest_transaction_height > tip.height {
                return Err(BitcoinWalletError::InvalidBirthday);
            }
            let header = self
                .requester
                .get_header(checkpoint_height)
                .await
                .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?
                .ok_or(BitcoinWalletError::InvalidCheckpoint)?;
            if header.height != checkpoint_height {
                return Err(BitcoinWalletError::InvalidCheckpoint);
            }
            let checkpoint = BitcoinCheckpoint {
                height: checkpoint_height,
                block_hash: header.header.block_hash().to_byte_array(),
            };
            checkpoint.validate(self.durable.state.network)?;
            let canonical_height = self
                .requester
                .height_of_hash(BlockHash::from_byte_array(checkpoint.block_hash))
                .await
                .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
            if canonical_height != Some(checkpoint_height) {
                return Err(BitcoinWalletError::InvalidCheckpoint);
            }
            Ok(checkpoint)
        };
        let checkpoint = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => {
                return Err(BitcoinWalletError::KyotoNodeStopped);
            }
            result = tokio::time::timeout(BITCOIN_BIRTHDAY_VALIDATION_TIMEOUT, validation) => {
                result.map_err(|_| BitcoinWalletError::OperationTimedOut)??
            }
        };
        let replacement = KyotoWalletState::restored_wallet(
            self.durable.state.network,
            Some(checkpoint),
            self.durable.state.recovery_script_index,
            now_unix,
        )?;
        self.durable.replace(replacement, now_unix)?;
        Ok(checkpoint)
    }

    /// Drives one Kyoto update, durably records matched swap evidence before
    /// advancing the BDK checkpoint, reconciles bounded encrypted
    /// transaction/output mirrors, and only then commits a ready scan
    /// checkpoint. A timeout or explicit cancellation poisons this supervisor
    /// and requires reconstruction because Kyoto's update future is not
    /// cancel safe. Native callers retire the complete supervisor immediately;
    /// a cancelled update future is never polled or reused.
    pub async fn synchronize_once(
        &mut self,
        wallet: &mut EncryptedPersistedBitcoinWallet,
        now_unix: u64,
    ) -> Result<KyotoSyncReceipt, BitcoinWalletError> {
        if wallet.network() != self.durable.state.network
            || wallet.account_id() != self.durable.account_id.as_slice()
            || !wallet.shared_store().is_same_authority(&self.store)
        {
            return Err(BitcoinWalletError::WalletStoreAuthorityMismatch);
        }
        if self.poisoned {
            return Err(BitcoinWalletError::SupervisorPoisoned);
        }
        if matches!(&self.durable.state.phase, KyotoSyncPhase::Ready) {
            self.durable.state.begin_cycle(now_unix)?;
            self.durable.persist(now_unix)?;
        }
        let sequence = self.durable.state.pending_sequence;
        if sequence == 0 || sequence <= self.durable.state.completed_sequence {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        if let Some((wallet_tip, common_ancestor)) = self.resume_reconciliation.take() {
            if BitcoinCheckpoint::from_wallet(wallet) != wallet_tip {
                self.poisoned = true;
                self.durable.state.phase = KyotoSyncPhase::RecoveryRequired {
                    reason: KyotoRecoveryReason::CheckpointMismatch,
                };
                self.durable.persist(now_unix)?;
                return Err(BitcoinWalletError::CheckpointMismatch);
            }
            self.durable.state.validated_checkpoint = wallet_tip;
            self.durable.state.scanned_checkpoint = wallet_tip;
            self.durable.state.phase = KyotoSyncPhase::Reconciling {
                sequence,
                wallet_tip,
                common_ancestor,
            };
            self.durable.persist(now_unix)?;
            return self
                .finish_reconciliation(wallet, sequence, wallet_tip, common_ancestor, now_unix)
                .await;
        }
        let previous_tip = self.durable.state.last_consistent_checkpoint;
        self.durable.state.phase = KyotoSyncPhase::Synchronizing {
            sequence,
            from: previous_tip,
        };
        self.durable.persist(now_unix)?;

        let update_result = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => {
                self.poisoned = true;
                let _ = self.requester.shutdown();
                self.durable.state.phase = KyotoSyncPhase::RecoveryRequired {
                    reason: if self.durable.state.completed_syncs == 0 {
                        KyotoRecoveryReason::InterruptedInitialScan
                    } else {
                        KyotoRecoveryReason::InterruptedSynchronization
                    },
                };
                self.durable.persist(now_unix)?;
                return Err(BitcoinWalletError::KyotoNodeStopped);
            }
            result = tokio::time::timeout(self.sync_timeout, self.updates.update()) => result,
        };
        let update = match update_result {
            Ok(Ok(update)) => update,
            Ok(Err(_)) => {
                self.poisoned = true;
                self.durable.state.phase = KyotoSyncPhase::RecoveryRequired {
                    reason: KyotoRecoveryReason::InterruptedSynchronization,
                };
                self.durable.persist(now_unix)?;
                return Err(BitcoinWalletError::KyotoNodeStopped);
            }
            Err(_) => {
                self.poisoned = true;
                let _ = self.requester.shutdown();
                self.durable.state.phase = KyotoSyncPhase::RecoveryRequired {
                    reason: if self.durable.state.completed_syncs == 0 {
                        KyotoRecoveryReason::InterruptedInitialScan
                    } else {
                        KyotoRecoveryReason::InterruptedSynchronization
                    },
                };
                self.durable.persist(now_unix)?;
                return Err(BitcoinWalletError::OperationTimedOut);
            }
        };
        let announced_tip = update
            .wallet_update
            .chain
            .as_ref()
            .map(|checkpoint| BitcoinCheckpoint {
                height: checkpoint.height(),
                block_hash: checkpoint.hash().to_byte_array(),
            })
            .ok_or(BitcoinWalletError::InvalidCheckpoint)?;
        announced_tip.validate(self.durable.state.network)?;
        self.store.try_with_store_mut(|store| {
            reconcile_bitcoin_htlc_watches(
                store,
                wallet.network(),
                wallet.account_id(),
                &update.canonical_chain,
                announced_tip,
                &update.swap_blocks,
                now_unix,
            )
        })?;
        wallet
            .apply_update(update.wallet_update)
            .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
        wallet.persist(now_unix)?;

        let wallet_tip = BitcoinCheckpoint::from_wallet(wallet);
        if wallet_tip != announced_tip {
            return Err(BitcoinWalletError::CheckpointMismatch);
        }
        let recent = wallet_recent_checkpoints(wallet, self.durable.state.recovery_checkpoint)?;
        let prior_tip_still_canonical = tokio::time::timeout(
            self.request_timeout,
            self.requester
                .height_of_hash(BlockHash::from_byte_array(previous_tip.block_hash)),
        )
        .await
        .map_err(|_| BitcoinWalletError::OperationTimedOut)?
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?
            == Some(previous_tip.height);
        let common_ancestor = if prior_tip_still_canonical {
            Some(previous_tip)
        } else {
            let mut common = None;
            for checkpoint in self.durable.state.recent_checkpoints.iter().rev() {
                let height = tokio::time::timeout(
                    self.request_timeout,
                    self.requester
                        .height_of_hash(BlockHash::from_byte_array(checkpoint.block_hash)),
                )
                .await
                .map_err(|_| BitcoinWalletError::OperationTimedOut)?
                .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
                if height == Some(checkpoint.height) {
                    common = Some(*checkpoint);
                    break;
                }
            }
            common
        };
        if self.durable.state.completed_syncs != 0
            && !prior_tip_still_canonical
            && common_ancestor.is_none()
        {
            self.durable.state.validated_checkpoint = wallet_tip;
            self.durable.state.scanned_checkpoint = wallet_tip;
            self.durable.state.recent_checkpoints = recent;
            self.durable.state.phase = KyotoSyncPhase::RecoveryRequired {
                reason: KyotoRecoveryReason::DeepReorganization,
            };
            self.durable.persist(now_unix)?;
            self.poisoned = true;
            let _ = self.requester.shutdown();
            return Err(BitcoinWalletError::DeepReorganization);
        }
        let reorg_ancestor = if prior_tip_still_canonical {
            None
        } else {
            common_ancestor
        };
        self.durable.state.validated_checkpoint = wallet_tip;
        self.durable.state.scanned_checkpoint = wallet_tip;
        self.durable.state.recent_checkpoints = recent;
        self.durable.state.phase = KyotoSyncPhase::Reconciling {
            sequence,
            wallet_tip,
            common_ancestor: reorg_ancestor,
        };
        self.durable.persist(now_unix)?;

        self.finish_reconciliation(wallet, sequence, wallet_tip, reorg_ancestor, now_unix)
            .await
    }

    async fn finish_reconciliation(
        &mut self,
        wallet: &Wallet,
        sequence: u64,
        wallet_tip: BitcoinCheckpoint,
        reorg_ancestor: Option<BitcoinCheckpoint>,
        now_unix: u64,
    ) -> Result<KyotoSyncReceipt, BitcoinWalletError> {
        let transaction_count = self
            .store
            .try_with_store_mut(|store| reconcile_transaction_records(wallet, store, now_unix))?;
        let output_count = self
            .store
            .try_with_store_mut(|store| reconcile_output_records(wallet, store, now_unix))?;
        let peer_count = tokio::time::timeout(self.request_timeout, self.requester.peer_info())
            .await
            .ok()
            .and_then(Result::ok)
            .map_or(0, |peers| peers.len());
        let peer_count = u8::try_from(peer_count).unwrap_or(u8::MAX);

        self.durable.state.last_consistent_checkpoint = wallet_tip;
        self.durable.state.completed_sequence = sequence;
        self.durable.state.completed_syncs = self
            .durable
            .state
            .completed_syncs
            .checked_add(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        if reorg_ancestor.is_some() {
            self.durable.state.reorg_count = self
                .durable
                .state
                .reorg_count
                .checked_add(1)
                .ok_or(BitcoinWalletError::SequenceOverflow)?;
        }
        self.durable.state.relevant_transaction_count = transaction_count;
        self.durable.state.wallet_output_count = output_count;
        self.durable.state.connected_peer_count = peer_count;
        self.durable.state.last_completed_at_unix = Some(now_unix);
        self.durable.state.phase = KyotoSyncPhase::Ready;
        self.durable.persist(now_unix)?;

        Ok(KyotoSyncReceipt {
            sequence,
            checkpoint: wallet_tip,
            common_ancestor: reorg_ancestor,
            transaction_count,
            output_count,
            connected_peer_count: peer_count,
            required_peer_count: self.required_peers,
        })
    }

    /// Persist and activate one exact HTLC compact-filter watch before either
    /// party can fund it. Registration is bound to this wallet's current
    /// locally validated checkpoint and immediately joins the existing Kyoto
    /// filter stream.
    pub fn register_htlc_watch(
        &mut self,
        wallet: &EncryptedPersistedBitcoinWallet,
        request: BitcoinHtlcWatchRequest,
        now_unix: u64,
    ) -> Result<BitcoinHtlcWatchAdmission, BitcoinWalletError> {
        if self.poisoned
            || !matches!(self.durable.state.phase, KyotoSyncPhase::Ready)
            || wallet.network() != self.durable.state.network
            || wallet.account_id() != self.durable.account_id.as_slice()
            || !wallet.shared_store().is_same_authority(&self.store)
        {
            return Err(BitcoinWalletError::RuntimeNotReady);
        }
        let checkpoint = BitcoinCheckpoint::from_wallet(wallet);
        if checkpoint != self.durable.state.last_consistent_checkpoint
            || checkpoint != self.durable.state.scanned_checkpoint
        {
            return Err(BitcoinWalletError::CheckpointMismatch);
        }
        let admission = self.store.try_with_store_mut(|store| {
            register_bitcoin_htlc_watch(
                store,
                wallet.network(),
                wallet.account_id(),
                &request,
                checkpoint,
                now_unix,
            )
        })?;
        self.updates
            .register_swap_script(request.session_id, request.htlc.script_pubkey());
        Ok(admission)
    }

    pub async fn minimum_broadcast_fee_rate_sat_vb(&self) -> Result<u64, BitcoinWalletError> {
        tokio::time::timeout(self.request_timeout, self.requester.broadcast_min_feerate())
            .await
            .map_err(|_| BitcoinWalletError::OperationTimedOut)?
            .map(|rate| rate.to_sat_per_vb_ceil())
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
    }

    /// Return the exact local consensus context for a new absolute-locktime
    /// transaction. The tip must be the supervisor's durable ready checkpoint;
    /// headers are read from Kyoto's locally validated most-work chain, linked
    /// backwards to that tip, and their median is used for BIP113 timestamp
    /// locks. No wall clock, relay, or remote full node supplies this value.
    pub async fn validated_chain_lock_context(
        &self,
    ) -> Result<BitcoinChainLockContext, BitcoinWalletError> {
        if self.poisoned
            || !matches!(self.durable.state.phase, KyotoSyncPhase::Ready)
            || self.durable.state.scanned_checkpoint
                != self.durable.state.last_consistent_checkpoint
        {
            return Err(BitcoinWalletError::RuntimeNotReady);
        }
        let expected_tip = self.durable.state.last_consistent_checkpoint;
        let observed_tip = tokio::time::timeout(self.request_timeout, self.requester.chain_tip())
            .await
            .map_err(|_| BitcoinWalletError::OperationTimedOut)?
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
        if observed_tip.height != expected_tip.height
            || observed_tip.hash.to_byte_array() != expected_tip.block_hash
        {
            return Err(BitcoinWalletError::CheckpointMismatch);
        }
        let count = usize::try_from(expected_tip.height)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .min(MEDIAN_TIME_PAST_HEADERS);
        let start = expected_tip
            .height
            .checked_add(1)
            .and_then(|height| height.checked_sub(u32::try_from(count).ok()?))
            .ok_or(BitcoinWalletError::InvalidCheckpoint)?;
        let mut headers: Vec<IndexedHeader> = Vec::with_capacity(count);
        for height in start..=expected_tip.height {
            let indexed =
                tokio::time::timeout(self.request_timeout, self.requester.get_header(height))
                    .await
                    .map_err(|_| BitcoinWalletError::OperationTimedOut)?
                    .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?
                    .ok_or(BitcoinWalletError::InvalidCheckpoint)?;
            if indexed.height != height {
                return Err(BitcoinWalletError::InvalidCheckpoint);
            }
            if let Some(prior) = headers.last()
                && indexed.header.prev_blockhash != prior.header.block_hash()
            {
                return Err(BitcoinWalletError::InvalidCheckpoint);
            }
            headers.push(indexed);
        }
        if headers.last().is_none_or(|header| {
            header.header.block_hash().to_byte_array() != expected_tip.block_hash
        }) {
            return Err(BitcoinWalletError::CheckpointMismatch);
        }
        let median_time_past = median_time_past(headers.iter().map(|header| header.header.time))?;
        let next_block_height = expected_tip
            .height
            .checked_add(1)
            .ok_or(BitcoinWalletError::InvalidChainLockContext)?;
        let context = BitcoinChainLockContext {
            next_block_height,
            median_time_past,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn add_trusted_peer(&self, peer: bdk_kyoto::TrustedPeer) -> Result<(), BitcoinWalletError> {
        self.requester
            .add_peer(peer)
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
    }

    pub fn is_running(&self) -> bool {
        self.requester.is_running()
    }

    pub fn shutdown(&self) -> Result<(), BitcoinWalletError> {
        self.cancellation.request();
        self.requester
            .shutdown()
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
    }

    pub async fn broadcast_prepared_transaction(
        &self,
        _permit: &BitcoinValueRuntimePermit,
        txid: [u8; 32],
        now_unix: u64,
    ) -> Result<BitcoinBroadcastReceipt, BitcoinWalletError> {
        if self.poisoned {
            return Err(BitcoinWalletError::SupervisorPoisoned);
        }
        if !matches!(&self.durable.state.phase, KyotoSyncPhase::Ready)
            || self.durable.state.scanned_checkpoint
                != self.durable.state.last_consistent_checkpoint
        {
            return Err(BitcoinWalletError::RuntimeNotReady);
        }
        if !self.requester.is_running() {
            return Err(BitcoinWalletError::KyotoNodeStopped);
        }
        let peers = tokio::time::timeout(self.request_timeout, self.requester.peer_info())
            .await
            .map_err(|_| BitcoinWalletError::OperationTimedOut)?
            .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
        if peers.len() < usize::from(self.required_peers) {
            return Err(BitcoinWalletError::PeerQuorumUnavailable);
        }
        let start = self.store.try_with_store_mut(|store| {
            begin_broadcast_submission(store, self.durable.state.network, txid, now_unix)
        })?;
        let PendingBitcoinSubmission {
            transaction,
            mut record,
            started_revision,
        } = match start {
            BroadcastStart::AlreadyObserved(receipt) => return Ok(receipt),
            BroadcastStart::Submit(submission) => *submission,
        };

        let returned_wtxid = tokio::time::timeout(
            self.request_timeout,
            self.requester.submit_package(transaction.clone()),
        )
        .await
        .map_err(|_| BitcoinWalletError::OperationTimedOut)?
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))?;
        let expected_wtxid = transaction.compute_wtxid();
        if returned_wtxid != expected_wtxid {
            return Err(BitcoinWalletError::BroadcastReceiptMismatch);
        }
        let intent = record
            .broadcast
            .as_mut()
            .ok_or(BitcoinWalletError::BroadcastNotPrepared)?;
        intent.phase = BitcoinBroadcastPhase::Submitted;
        intent.last_submitted_at_unix = Some(now_unix);
        let attempt_count = intent.attempt_count;
        let submitted_at_unix = intent.last_submitted_at_unix;
        self.store.with_store_mut(|store| {
            store
                .save_bitcoin_transaction(&txid, started_revision, &record, now_unix)
                .map(|_| ())
        })?;
        Ok(BitcoinBroadcastReceipt {
            txid,
            wtxid: expected_wtxid.to_byte_array(),
            attempt_count,
            submitted_at_unix,
        })
    }
}

fn median_time_past(
    header_times: impl IntoIterator<Item = u32>,
) -> Result<u32, BitcoinWalletError> {
    let mut times = header_times.into_iter().collect::<Vec<_>>();
    if times.is_empty() || times.len() > MEDIAN_TIME_PAST_HEADERS {
        return Err(BitcoinWalletError::InvalidChainLockContext);
    }
    times.sort_unstable();
    Ok(times[times.len() / 2])
}

enum BroadcastStart {
    AlreadyObserved(BitcoinBroadcastReceipt),
    Submit(Box<PendingBitcoinSubmission>),
}

struct PendingBitcoinSubmission {
    transaction: Transaction,
    record: BitcoinTransactionRecord,
    started_revision: u64,
}

fn begin_broadcast_submission(
    store: &mut WalletStore,
    network: Network,
    txid: [u8; 32],
    now_unix: u64,
) -> Result<BroadcastStart, BitcoinWalletError> {
    let stored = store
        .bitcoin_transaction::<BitcoinTransactionRecord>(&txid)?
        .ok_or(BitcoinWalletError::BroadcastIntentNotFound)?;
    let mut record = stored.value;
    record.validate()?;
    let raw = record
        .raw_transaction
        .as_ref()
        .ok_or(BitcoinWalletError::BroadcastNotPrepared)?;
    let transaction: Transaction =
        deserialize(raw).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    if transaction.compute_txid().to_byte_array() != txid {
        return Err(BitcoinWalletError::BroadcastConflict);
    }
    let intent = record
        .broadcast
        .as_mut()
        .ok_or(BitcoinWalletError::BroadcastNotPrepared)?;
    if intent.network != network {
        return Err(BitcoinWalletError::NetworkMismatch);
    }
    if now_unix < intent.prepared_at_unix {
        return Err(BitcoinWalletError::ClockRollbackDetected);
    }
    if now_unix >= intent.expires_at_unix {
        return Err(BitcoinWalletError::BroadcastApprovalExpired);
    }
    if matches!(
        &record.observation,
        BitcoinChainObservation::Confirmed { .. } | BitcoinChainObservation::Unconfirmed { .. }
    ) {
        return Ok(BroadcastStart::AlreadyObserved(BitcoinBroadcastReceipt {
            txid,
            wtxid: transaction.compute_wtxid().to_byte_array(),
            attempt_count: intent.attempt_count,
            submitted_at_unix: intent.last_submitted_at_unix,
        }));
    }
    let last_attempt_at_unix = match intent.phase {
        BitcoinBroadcastPhase::Prepared => None,
        BitcoinBroadcastPhase::SubmissionStarted => intent.last_submission_started_at_unix,
        BitcoinBroadcastPhase::Submitted => intent.last_submitted_at_unix,
    };
    if let Some(last_attempt_at_unix) = last_attempt_at_unix {
        if now_unix < last_attempt_at_unix {
            return Err(BitcoinWalletError::ClockRollbackDetected);
        }
        let next_allowed = last_attempt_at_unix
            .checked_add(MIN_REBROADCAST_INTERVAL_SECONDS)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        if now_unix < next_allowed {
            return Err(BitcoinWalletError::BroadcastRetryNotReady);
        }
    }
    intent.attempt_count = intent
        .attempt_count
        .checked_add(1)
        .ok_or(BitcoinWalletError::BroadcastAttemptLimit)?;
    if intent.attempt_count > MAX_BROADCAST_ATTEMPTS {
        return Err(BitcoinWalletError::BroadcastAttemptLimit);
    }
    intent.phase = BitcoinBroadcastPhase::SubmissionStarted;
    intent.last_submission_started_at_unix = Some(now_unix);
    let started_revision =
        store.save_bitcoin_transaction(&txid, stored.revision, &record, now_unix)?;
    Ok(BroadcastStart::Submit(Box::new(PendingBitcoinSubmission {
        transaction,
        record,
        started_revision,
    })))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinValueRuntimePermit(pub(crate) ());

pub fn bitcoin_value_runtime_permit() -> Result<BitcoinValueRuntimePermit, BitcoinWalletError> {
    if !BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED {
        return Err(BitcoinWalletError::ValueOperationsDisabled);
    }
    Ok(BitcoinValueRuntimePermit(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KyotoSyncReceipt {
    pub sequence: u64,
    pub checkpoint: BitcoinCheckpoint,
    pub common_ancestor: Option<BitcoinCheckpoint>,
    pub transaction_count: u32,
    pub output_count: u32,
    pub connected_peer_count: u8,
    pub required_peer_count: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "position", rename_all = "snake_case")]
pub enum BitcoinChainObservation {
    AbsentFromCanonicalWalletView,
    Unconfirmed {
        first_seen_at_unix: Option<u64>,
        last_seen_at_unix: Option<u64>,
    },
    Confirmed {
        height: u32,
        block_hash: [u8; 32],
        confirmation_time_unix: u64,
        transitively_confirmed_by: Option<[u8; 32]>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinBroadcastPhase {
    Prepared,
    SubmissionStarted,
    Submitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinBroadcastIntent {
    pub network: Network,
    pub approval_commitment: [u8; 32],
    pub fee_sats: u64,
    pub maximum_fee_sats: u64,
    pub prepared_at_unix: u64,
    pub expires_at_unix: u64,
    pub phase: BitcoinBroadcastPhase,
    pub attempt_count: u16,
    pub last_submission_started_at_unix: Option<u64>,
    pub last_submitted_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinTransactionRecord {
    pub schema_version: u16,
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub input_count: u32,
    pub output_count: u32,
    pub input_outpoint_commitment: [u8; 32],
    pub sent_sats: u64,
    pub received_sats: u64,
    pub fee_sats: Option<u64>,
    pub observation: BitcoinChainObservation,
    pub raw_transaction: Option<Vec<u8>>,
    pub broadcast: Option<BitcoinBroadcastIntent>,
    pub first_observed_at_unix: Option<u64>,
    pub last_changed_at_unix: u64,
}

impl BitcoinTransactionRecord {
    fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.schema_version != BITCOIN_TRANSACTION_RECORD_VERSION
            || self.txid == [0; 32]
            || self.wtxid == [0; 32]
            || self.broadcast.is_some() != self.raw_transaction.is_some()
        {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        if let Some(raw) = &self.raw_transaction {
            if raw.is_empty() || raw.len() > MAX_PERSISTED_BROADCAST_TRANSACTION_BYTES {
                return Err(BitcoinWalletError::TransactionTooLarge);
            }
            let transaction: Transaction =
                deserialize(raw).map_err(|_| BitcoinWalletError::CorruptRuntimeState)?;
            if transaction.compute_txid().to_byte_array() != self.txid
                || transaction.compute_wtxid().to_byte_array() != self.wtxid
                || u32::try_from(transaction.input.len()).ok() != Some(self.input_count)
                || u32::try_from(transaction.output.len()).ok() != Some(self.output_count)
                || input_outpoint_commitment(&transaction) != self.input_outpoint_commitment
                || serialize(&transaction) != *raw
            {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
        }
        if let Some(intent) = &self.broadcast {
            let timestamps_valid = match intent.phase {
                BitcoinBroadcastPhase::Prepared => {
                    intent.attempt_count == 0
                        && intent.last_submission_started_at_unix.is_none()
                        && intent.last_submitted_at_unix.is_none()
                }
                BitcoinBroadcastPhase::SubmissionStarted => {
                    intent.attempt_count != 0
                        && intent.last_submission_started_at_unix.is_some()
                        && intent.last_submitted_at_unix.is_none_or(|submitted| {
                            intent
                                .last_submission_started_at_unix
                                .is_some_and(|started| submitted <= started)
                        })
                }
                BitcoinBroadcastPhase::Submitted => {
                    intent.attempt_count != 0
                        && intent.last_submission_started_at_unix.is_some()
                        && intent.last_submission_started_at_unix == intent.last_submitted_at_unix
                }
            };
            let durable_times_valid = intent
                .last_submission_started_at_unix
                .into_iter()
                .chain(intent.last_submitted_at_unix)
                .all(|timestamp| {
                    timestamp >= intent.prepared_at_unix && timestamp < intent.expires_at_unix
                });
            if intent.approval_commitment == [0; 32]
                || intent.fee_sats == 0
                || intent.fee_sats > intent.maximum_fee_sats
                || intent.expires_at_unix <= intent.prepared_at_unix
                || intent
                    .expires_at_unix
                    .checked_sub(intent.prepared_at_unix)
                    .is_none_or(|lifetime| lifetime > MAX_BROADCAST_APPROVAL_LIFETIME_SECONDS)
                || intent.attempt_count > MAX_BROADCAST_ATTEMPTS
                || !timestamps_valid
                || !durable_times_valid
            {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
            let expected = bitcoin_broadcast_approval_commitment(
                intent.network,
                self.txid,
                self.wtxid,
                intent.fee_sats,
                intent.maximum_fee_sats,
                intent.expires_at_unix,
            );
            if expected != intent.approval_commitment || self.fee_sats != Some(intent.fee_sats) {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinUtxoRecord {
    pub schema_version: u16,
    pub txid: [u8; 32],
    pub output_index: u32,
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
    pub keychain: KeychainKind,
    pub derivation_index: u32,
    pub is_spent: bool,
    pub observation: BitcoinChainObservation,
    pub first_observed_at_unix: u64,
    pub last_changed_at_unix: u64,
}

impl BitcoinUtxoRecord {
    fn id(&self) -> Vec<u8> {
        bitcoin_outpoint_id(self.txid, self.output_index)
    }

    fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.schema_version != BITCOIN_UTXO_RECORD_VERSION
            || self.txid == [0; 32]
            || self.script_pubkey.is_empty()
            || self.script_pubkey.len() > 10_000
        {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedBitcoinBroadcast {
    pub txid: [u8; 32],
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinBroadcastReceipt {
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub attempt_count: u16,
    pub submitted_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinBroadcastApprovalBinding {
    pub network: Network,
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub fee_sats: u64,
    pub maximum_fee_sats: u64,
    pub expires_at_unix: u64,
    pub commitment: [u8; 32],
}

pub fn derive_bitcoin_broadcast_approval(
    wallet: &Wallet,
    raw_transaction: &[u8],
    maximum_fee_sats: u64,
    expires_at_unix: u64,
) -> Result<BitcoinBroadcastApprovalBinding, BitcoinWalletError> {
    if raw_transaction.is_empty()
        || raw_transaction.len() > MAX_PERSISTED_BROADCAST_TRANSACTION_BYTES
    {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    if maximum_fee_sats == 0 || expires_at_unix == 0 {
        return Err(BitcoinWalletError::InvalidBroadcastApproval);
    }
    let transaction: Transaction =
        deserialize(raw_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    if serialize(&transaction) != raw_transaction
        || transaction.input.is_empty()
        || transaction.output.is_empty()
    {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    let mut inputs = BTreeSet::new();
    for input in &transaction.input {
        if !inputs.insert(input.previous_output) {
            return Err(BitcoinWalletError::InvalidEvidence);
        }
        let owned = wallet
            .get_utxo(input.previous_output)
            .ok_or(BitcoinWalletError::InvalidEvidence)?;
        if owned.is_spent {
            return Err(BitcoinWalletError::InvalidEvidence);
        }
    }
    let fee_sats = wallet
        .calculate_fee(&transaction)
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?
        .to_sat();
    if fee_sats == 0 || fee_sats > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    let txid = transaction.compute_txid().to_byte_array();
    let wtxid = transaction.compute_wtxid().to_byte_array();
    let network = wallet.network();
    Ok(BitcoinBroadcastApprovalBinding {
        network,
        txid,
        wtxid,
        fee_sats,
        maximum_fee_sats,
        expires_at_unix,
        commitment: bitcoin_broadcast_approval_commitment(
            network,
            txid,
            wtxid,
            fee_sats,
            maximum_fee_sats,
            expires_at_unix,
        ),
    })
}

/// Derive an exact broadcast approval for a signed native HTLC redeem or
/// refund. Unlike an ordinary wallet spend, the input is the previously
/// verified swap output rather than a descriptor-wallet UTXO.
pub fn derive_bitcoin_htlc_spend_broadcast_approval(
    wallet: &Wallet,
    raw_transaction: &[u8],
    lock: &VerifiedBitcoinLock,
    branch: HtlcSpendBranch,
    maximum_fee_sats: u64,
    expires_at_unix: u64,
) -> Result<BitcoinBroadcastApprovalBinding, BitcoinWalletError> {
    if raw_transaction.len() > MAX_PERSISTED_BROADCAST_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    if maximum_fee_sats == 0 || expires_at_unix == 0 {
        return Err(BitcoinWalletError::InvalidBroadcastApproval);
    }
    let verified = verify_signed_bitcoin_htlc_spend(raw_transaction, lock, branch)?;
    if verified.fee_sats > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    let network = wallet.network();
    let txid = verified.txid.into_bytes();
    Ok(BitcoinBroadcastApprovalBinding {
        network,
        txid,
        wtxid: verified.wtxid,
        fee_sats: verified.fee_sats,
        maximum_fee_sats,
        expires_at_unix,
        commitment: bitcoin_broadcast_approval_commitment(
            network,
            txid,
            verified.wtxid,
            verified.fee_sats,
            maximum_fee_sats,
            expires_at_unix,
        ),
    })
}

pub fn bitcoin_broadcast_approval_commitment(
    network: Network,
    txid: [u8; 32],
    wtxid: [u8; 32],
    fee_sats: u64,
    maximum_fee_sats: u64,
    expires_at_unix: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-bitcoin-broadcast-approval/v1");
    hasher.update(network.magic().to_bytes());
    hasher.update(txid);
    hasher.update(wtxid);
    hasher.update(fee_sats.to_be_bytes());
    hasher.update(maximum_fee_sats.to_be_bytes());
    hasher.update(expires_at_unix.to_be_bytes());
    hasher.finalize().into()
}

/// Persists the complete signed transaction and exact approval binding before
/// the supervisor is allowed to hand bytes to Kyoto. This is idempotent only
/// for identical terms at the expected record revision.
#[allow(
    clippy::too_many_arguments,
    reason = "the persistence boundary keeps wallet/store authority, signed bytes, approval commitment, fee cap, revision, and validity window explicit for auditability"
)]
pub fn persist_prepared_bitcoin_broadcast(
    wallet: &Wallet,
    store: &mut WalletStore,
    raw_transaction: &[u8],
    approval_commitment: [u8; 32],
    maximum_fee_sats: u64,
    expected_revision: u64,
    now_unix: u64,
    expires_at_unix: u64,
) -> Result<PreparedBitcoinBroadcast, BitcoinWalletError> {
    let approval = derive_bitcoin_broadcast_approval(
        wallet,
        raw_transaction,
        maximum_fee_sats,
        expires_at_unix,
    )?;
    persist_approved_bitcoin_broadcast(
        store,
        raw_transaction,
        approval,
        approval_commitment,
        expected_revision,
        now_unix,
    )
}

/// Persist a signed native HTLC spend for the same Kyoto submission path used
/// by ordinary wallet transactions. The exact lock and branch are verified
/// again here before any signed bytes become broadcastable.
#[allow(
    clippy::too_many_arguments,
    reason = "the persistence boundary keeps the verified lock, branch, approval, fee cap, revision, and validity window explicit"
)]
pub fn persist_prepared_bitcoin_htlc_spend_broadcast(
    wallet: &Wallet,
    store: &mut WalletStore,
    raw_transaction: &[u8],
    lock: &VerifiedBitcoinLock,
    branch: HtlcSpendBranch,
    approval_commitment: [u8; 32],
    maximum_fee_sats: u64,
    expected_revision: u64,
    now_unix: u64,
    expires_at_unix: u64,
) -> Result<PreparedBitcoinBroadcast, BitcoinWalletError> {
    let approval = derive_bitcoin_htlc_spend_broadcast_approval(
        wallet,
        raw_transaction,
        lock,
        branch,
        maximum_fee_sats,
        expires_at_unix,
    )?;
    persist_approved_bitcoin_broadcast(
        store,
        raw_transaction,
        approval,
        approval_commitment,
        expected_revision,
        now_unix,
    )
}

fn persist_approved_bitcoin_broadcast(
    store: &mut WalletStore,
    raw_transaction: &[u8],
    approval: BitcoinBroadcastApprovalBinding,
    approval_commitment: [u8; 32],
    expected_revision: u64,
    now_unix: u64,
) -> Result<PreparedBitcoinBroadcast, BitcoinWalletError> {
    if approval_commitment == [0; 32]
        || approval.commitment != approval_commitment
        || approval.expires_at_unix <= now_unix
        || approval
            .expires_at_unix
            .checked_sub(now_unix)
            .is_none_or(|lifetime| lifetime > MAX_BROADCAST_APPROVAL_LIFETIME_SECONDS)
    {
        return Err(BitcoinWalletError::InvalidBroadcastApproval);
    }
    let transaction: Transaction =
        deserialize(raw_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let txid = approval.txid;
    let wtxid = approval.wtxid;
    let existing = store.bitcoin_transaction::<BitcoinTransactionRecord>(&txid)?;
    if existing.as_ref().map_or(0, |stored| stored.revision) != expected_revision {
        return Err(BitcoinWalletError::BroadcastConflict);
    }
    if existing.is_none() {
        let records = store.bitcoin_transactions::<BitcoinTransactionRecord>(
            MAX_TRACKED_BITCOIN_TRANSACTIONS + 1,
        )?;
        if records.len() >= MAX_TRACKED_BITCOIN_TRANSACTIONS {
            return Err(BitcoinWalletError::BitcoinTransactionCapacity);
        }
        for stored in records {
            stored.value.validate()?;
        }
    }
    let mut record = existing.map_or_else(
        || BitcoinTransactionRecord {
            schema_version: BITCOIN_TRANSACTION_RECORD_VERSION,
            txid,
            wtxid,
            input_count: u32::try_from(transaction.input.len()).unwrap_or(u32::MAX),
            output_count: u32::try_from(transaction.output.len()).unwrap_or(u32::MAX),
            input_outpoint_commitment: input_outpoint_commitment(&transaction),
            sent_sats: 0,
            received_sats: 0,
            fee_sats: Some(approval.fee_sats),
            observation: BitcoinChainObservation::AbsentFromCanonicalWalletView,
            raw_transaction: None,
            broadcast: None,
            first_observed_at_unix: None,
            last_changed_at_unix: now_unix,
        },
        |stored| stored.value,
    );
    record.validate()?;
    if record.txid != txid
        || record.wtxid != wtxid
        || record.fee_sats.is_some_and(|fee| fee != approval.fee_sats)
    {
        return Err(BitcoinWalletError::BroadcastConflict);
    }
    if let Some(intent) = &record.broadcast {
        let same_terms = record.raw_transaction.as_deref() == Some(raw_transaction)
            && intent.network == approval.network
            && intent.approval_commitment == approval_commitment
            && intent.fee_sats == approval.fee_sats
            && intent.maximum_fee_sats == approval.maximum_fee_sats
            && intent.expires_at_unix == approval.expires_at_unix;
        if !same_terms {
            return Err(BitcoinWalletError::BroadcastConflict);
        }
        return Ok(PreparedBitcoinBroadcast {
            txid,
            revision: expected_revision,
        });
    }
    if record.raw_transaction.is_some() {
        return Err(BitcoinWalletError::BroadcastConflict);
    }
    record.raw_transaction = Some(raw_transaction.to_vec());
    record.fee_sats = Some(approval.fee_sats);
    record.broadcast = Some(BitcoinBroadcastIntent {
        network: approval.network,
        approval_commitment,
        fee_sats: approval.fee_sats,
        maximum_fee_sats: approval.maximum_fee_sats,
        prepared_at_unix: now_unix,
        expires_at_unix: approval.expires_at_unix,
        phase: BitcoinBroadcastPhase::Prepared,
        attempt_count: 0,
        last_submission_started_at_unix: None,
        last_submitted_at_unix: None,
    });
    record.last_changed_at_unix = now_unix;
    record.validate()?;
    let revision = store.save_bitcoin_transaction(&txid, expected_revision, &record, now_unix)?;
    Ok(PreparedBitcoinBroadcast { txid, revision })
}

fn restart_requires_recovery(state: &KyotoWalletState, wallet: &Wallet) -> bool {
    if state.completed_syncs == 0
        || matches!(
            &state.phase,
            KyotoSyncPhase::RecoveryRequired { .. } | KyotoSyncPhase::Initialized
        )
    {
        return true;
    }
    let wallet_tip = BitcoinCheckpoint::from_wallet(wallet);
    tip_mismatch_requires_recovery(&state.phase, state.last_consistent_checkpoint, wallet_tip)
}

fn tip_mismatch_requires_recovery(
    phase: &KyotoSyncPhase,
    last_consistent_checkpoint: BitcoinCheckpoint,
    wallet_tip: BitcoinCheckpoint,
) -> bool {
    if let KyotoSyncPhase::Reconciling {
        wallet_tip: journaled_tip,
        ..
    } = phase
    {
        return wallet_tip != *journaled_tip;
    }
    // The only safe non-ready mismatch is the exact authenticated
    // `Reconciling` resume above. In particular, a wallet tip ahead of a
    // `Synchronizing` journal means BDK committed immediately before a crash;
    // restarting from that journal requires a recovery scan rather than
    // silently treating the old checkpoint as current.
    wallet_tip != last_consistent_checkpoint
}

fn wallet_recent_checkpoints(
    wallet: &Wallet,
    recovery_checkpoint: BitcoinCheckpoint,
) -> Result<Vec<BitcoinCheckpoint>, BitcoinWalletError> {
    let mut recent = wallet
        .checkpoints()
        .take(MAX_RECENT_BITCOIN_CHECKPOINTS.saturating_sub(1))
        .map(|checkpoint| BitcoinCheckpoint {
            height: checkpoint.height(),
            block_hash: checkpoint.hash().to_byte_array(),
        })
        .collect::<Vec<_>>();
    if !recent.contains(&recovery_checkpoint) {
        recent.push(recovery_checkpoint);
    }
    recent.sort_unstable();
    recent.dedup();
    if recent.len() > MAX_RECENT_BITCOIN_CHECKPOINTS {
        return Err(BitcoinWalletError::CheckpointCapacity);
    }
    Ok(recent)
}

#[cfg(test)]
pub(crate) fn highest_common_checkpoint(
    first: &[BitcoinCheckpoint],
    second: &[BitcoinCheckpoint],
) -> Option<BitcoinCheckpoint> {
    let second = second
        .iter()
        .map(|checkpoint| (checkpoint.height, checkpoint.block_hash))
        .collect::<BTreeMap<_, _>>();
    first
        .iter()
        .rev()
        .find(|checkpoint| second.get(&checkpoint.height) == Some(&checkpoint.block_hash))
        .copied()
}

fn reconcile_transaction_records(
    wallet: &Wallet,
    store: &mut WalletStore,
    now_unix: u64,
) -> Result<u32, BitcoinWalletError> {
    let stored = store
        .bitcoin_transactions::<BitcoinTransactionRecord>(MAX_TRACKED_BITCOIN_TRANSACTIONS + 1)?;
    if stored.len() > MAX_TRACKED_BITCOIN_TRANSACTIONS {
        return Err(BitcoinWalletError::BitcoinTransactionCapacity);
    }
    let mut previous = BTreeMap::new();
    for entity in stored {
        entity.value.validate()?;
        if entity.id.as_slice() != entity.value.txid.as_slice()
            || previous.insert(entity.value.txid, entity).is_some()
        {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
    }

    let mut current = BTreeMap::new();
    for transaction in wallet.transactions() {
        if current.len() == MAX_TRACKED_BITCOIN_TRANSACTIONS {
            return Err(BitcoinWalletError::BitcoinTransactionCapacity);
        }
        let txid = transaction.tx_node.txid.to_byte_array();
        if current.insert(txid, transaction).is_some() {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
    }
    let lifetime_count = previous
        .len()
        .checked_add(
            current
                .keys()
                .filter(|txid| !previous.contains_key(*txid))
                .count(),
        )
        .ok_or(BitcoinWalletError::BitcoinTransactionCapacity)?;
    if lifetime_count > MAX_TRACKED_BITCOIN_TRANSACTIONS {
        return Err(BitcoinWalletError::BitcoinTransactionCapacity);
    }
    let current_count =
        u32::try_from(current.len()).map_err(|_| BitcoinWalletError::BitcoinTransactionCapacity)?;
    let mut saves = Vec::new();
    for (txid, transaction) in current {
        let prior = previous.remove(&txid);
        let raw = transaction.tx_node.tx.as_ref();
        let (sent, received) = wallet.sent_and_received(raw);
        let observation = chain_observation(transaction.chain_position);
        let fee_sats = wallet
            .calculate_fee(raw)
            .ok()
            .map(|fee| fee.to_sat())
            .or_else(|| {
                prior
                    .as_ref()
                    .and_then(|stored| stored.value.broadcast.as_ref())
                    .map(|intent| intent.fee_sats)
            });
        let changed = prior.as_ref().is_none_or(|stored| {
            stored.value.observation != observation
                || stored.value.sent_sats != sent.to_sat()
                || stored.value.received_sats != received.to_sat()
                || stored.value.fee_sats != fee_sats
        });
        let first_observed = prior
            .as_ref()
            .and_then(|stored| stored.value.first_observed_at_unix)
            .or(Some(now_unix));
        let record = BitcoinTransactionRecord {
            schema_version: BITCOIN_TRANSACTION_RECORD_VERSION,
            txid,
            wtxid: raw.compute_wtxid().to_byte_array(),
            input_count: u32::try_from(raw.input.len())
                .map_err(|_| BitcoinWalletError::TransactionTooLarge)?,
            output_count: u32::try_from(raw.output.len())
                .map_err(|_| BitcoinWalletError::TransactionTooLarge)?,
            input_outpoint_commitment: input_outpoint_commitment(raw),
            sent_sats: sent.to_sat(),
            received_sats: received.to_sat(),
            fee_sats,
            observation,
            raw_transaction: prior
                .as_ref()
                .and_then(|stored| stored.value.raw_transaction.clone()),
            broadcast: prior
                .as_ref()
                .and_then(|stored| stored.value.broadcast.clone()),
            first_observed_at_unix: first_observed,
            last_changed_at_unix: if changed {
                now_unix
            } else {
                prior
                    .as_ref()
                    .map_or(now_unix, |stored| stored.value.last_changed_at_unix)
            },
        };
        record.validate()?;
        if prior.as_ref().is_none_or(|stored| stored.value != record) {
            saves.push(EntityBatchSave {
                id: txid.to_vec(),
                expected_revision: prior.as_ref().map_or(0, |stored| stored.revision),
                value: record,
                updated_at_unix: now_unix,
            });
        }
    }
    for (_, stored) in previous {
        let mut record = stored.value;
        if !matches!(
            &record.observation,
            BitcoinChainObservation::AbsentFromCanonicalWalletView
        ) {
            record.observation = BitcoinChainObservation::AbsentFromCanonicalWalletView;
            record.last_changed_at_unix = now_unix;
            record.validate()?;
            saves.push(EntityBatchSave {
                id: stored.id,
                expected_revision: stored.revision,
                value: record,
                updated_at_unix: now_unix,
            });
        }
    }
    for chunk in saves.chunks(MAX_RECONCILIATION_BATCH_SAVES) {
        store.apply_entity_batch(hns_wallet_store::EntityKind::BitcoinTransaction, chunk, &[])?;
    }
    Ok(current_count)
}

fn reconcile_output_records(
    wallet: &Wallet,
    store: &mut WalletStore,
    now_unix: u64,
) -> Result<u32, BitcoinWalletError> {
    let stored = store.bitcoin_utxos::<BitcoinUtxoRecord>(MAX_TRACKED_BITCOIN_OUTPUTS + 1)?;
    if stored.len() > MAX_TRACKED_BITCOIN_OUTPUTS {
        return Err(BitcoinWalletError::BitcoinOutputCapacity);
    }
    let mut previous = BTreeMap::new();
    for entity in stored {
        entity.value.validate()?;
        if entity.id != entity.value.id() || previous.insert(entity.id.clone(), entity).is_some() {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
    }
    let mut current = BTreeMap::new();
    for output in wallet.list_output() {
        if current.len() == MAX_TRACKED_BITCOIN_OUTPUTS {
            return Err(BitcoinWalletError::BitcoinOutputCapacity);
        }
        let txid = output.outpoint.txid.to_byte_array();
        let id = bitcoin_outpoint_id(txid, output.outpoint.vout);
        if current.insert(id, output).is_some() {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
    }
    let lifetime_count = previous
        .len()
        .checked_add(
            current
                .keys()
                .filter(|id| !previous.contains_key(*id))
                .count(),
        )
        .ok_or(BitcoinWalletError::BitcoinOutputCapacity)?;
    if lifetime_count > MAX_TRACKED_BITCOIN_OUTPUTS {
        return Err(BitcoinWalletError::BitcoinOutputCapacity);
    }
    let current_count = current.len();
    let mut saves = Vec::new();
    for (id, output) in current {
        let txid = output.outpoint.txid.to_byte_array();
        let prior = previous.remove(&id);
        let observation = chain_observation(output.chain_position);
        let record = BitcoinUtxoRecord {
            schema_version: BITCOIN_UTXO_RECORD_VERSION,
            txid,
            output_index: output.outpoint.vout,
            value_sats: output.txout.value.to_sat(),
            script_pubkey: output.txout.script_pubkey.to_bytes(),
            keychain: output.keychain,
            derivation_index: output.derivation_index,
            is_spent: output.is_spent,
            observation,
            first_observed_at_unix: prior
                .as_ref()
                .map_or(now_unix, |stored| stored.value.first_observed_at_unix),
            last_changed_at_unix: now_unix,
        };
        record.validate()?;
        let record = if let Some(stored) = &prior {
            if stored.value.schema_version == record.schema_version
                && stored.value.txid == record.txid
                && stored.value.output_index == record.output_index
                && stored.value.value_sats == record.value_sats
                && stored.value.script_pubkey == record.script_pubkey
                && stored.value.keychain == record.keychain
                && stored.value.derivation_index == record.derivation_index
                && stored.value.is_spent == record.is_spent
                && stored.value.observation == record.observation
            {
                stored.value.clone()
            } else {
                record
            }
        } else {
            record
        };
        if prior.as_ref().is_none_or(|stored| stored.value != record) {
            saves.push(EntityBatchSave {
                id,
                expected_revision: prior.as_ref().map_or(0, |stored| stored.revision),
                value: record,
                updated_at_unix: now_unix,
            });
        }
    }
    for (_, stored) in previous {
        let mut record = stored.value;
        if !matches!(
            &record.observation,
            BitcoinChainObservation::AbsentFromCanonicalWalletView
        ) {
            record.observation = BitcoinChainObservation::AbsentFromCanonicalWalletView;
            record.last_changed_at_unix = now_unix;
            saves.push(EntityBatchSave {
                id: stored.id,
                expected_revision: stored.revision,
                value: record,
                updated_at_unix: now_unix,
            });
        }
    }
    for chunk in saves.chunks(MAX_RECONCILIATION_BATCH_SAVES) {
        store.apply_entity_batch(hns_wallet_store::EntityKind::BitcoinUtxo, chunk, &[])?;
    }
    u32::try_from(current_count).map_err(|_| BitcoinWalletError::BitcoinOutputCapacity)
}

fn chain_observation(position: ChainPosition<ConfirmationBlockTime>) -> BitcoinChainObservation {
    match position {
        ChainPosition::Confirmed {
            anchor,
            transitively,
        } => BitcoinChainObservation::Confirmed {
            height: anchor.block_id.height,
            block_hash: anchor.block_id.hash.to_byte_array(),
            confirmation_time_unix: anchor.confirmation_time,
            transitively_confirmed_by: transitively.map(|txid| txid.to_byte_array()),
        },
        ChainPosition::Unconfirmed {
            first_seen,
            last_seen,
        } => BitcoinChainObservation::Unconfirmed {
            first_seen_at_unix: first_seen,
            last_seen_at_unix: last_seen,
        },
    }
}

fn input_outpoint_commitment(transaction: &Transaction) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-bitcoin-input-outpoints/v1");
    hasher.update(
        u64::try_from(transaction.input.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for input in &transaction.input {
        hasher.update(input.previous_output.txid.to_byte_array());
        hasher.update(input.previous_output.vout.to_be_bytes());
    }
    hasher.finalize().into()
}

fn bitcoin_outpoint_id(txid: [u8; 32], output_index: u32) -> Vec<u8> {
    let mut id = Vec::with_capacity(36);
    id.extend_from_slice(&txid);
    id.extend_from_slice(&output_index.to_be_bytes());
    id
}

#[cfg(test)]
mod restart_tests {
    use super::*;

    fn checkpoint(height: u32, byte: u8) -> BitcoinCheckpoint {
        BitcoinCheckpoint {
            height,
            block_hash: [byte; 32],
        }
    }

    #[test]
    fn synchronizing_tip_ahead_requires_recovery_but_exact_reconciliation_resumes() {
        let prior = checkpoint(100, 1);
        let committed = checkpoint(101, 2);
        let synchronizing = KyotoSyncPhase::Synchronizing {
            sequence: 7,
            from: prior,
        };
        assert!(tip_mismatch_requires_recovery(
            &synchronizing,
            prior,
            committed,
        ));

        let reconciling = KyotoSyncPhase::Reconciling {
            sequence: 7,
            wallet_tip: committed,
            common_ancestor: Some(prior),
        };
        assert!(!tip_mismatch_requires_recovery(
            &reconciling,
            prior,
            committed,
        ));
        assert!(tip_mismatch_requires_recovery(
            &reconciling,
            prior,
            checkpoint(102, 3),
        ));

        assert!(!tip_mismatch_requires_recovery(
            &KyotoSyncPhase::Ready,
            committed,
            committed,
        ));
    }

    #[test]
    fn median_time_past_is_the_canonical_middle_header_time() {
        assert_eq!(median_time_past([11, 9, 10]).expect("median"), 10);
        assert_eq!(median_time_past([1, 9, 2, 8, 3]).expect("median"), 3);
        assert!(matches!(
            median_time_past([]),
            Err(BitcoinWalletError::InvalidChainLockContext)
        ));
    }

    #[test]
    fn shutdown_cancellation_is_sticky_and_wakes_an_existing_waiter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cancellation = Arc::new(KyotoCancellation::default());
            let waiter_cancellation = Arc::clone(&cancellation);
            let waiter = tokio::spawn(async move {
                waiter_cancellation.cancelled().await;
            });
            tokio::task::yield_now().await;
            cancellation.request();
            tokio::time::timeout(std::time::Duration::from_millis(50), waiter)
                .await
                .expect("an active sync waiter wakes immediately")
                .expect("waiter completes");
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                cancellation.cancelled(),
            )
            .await
            .expect("a shutdown request remains visible to late waiters");
        });
    }
}
