use std::ops::{Deref, DerefMut};

use bdk_wallet::bitcoin::{Network, bip32::Xpriv};
use bdk_wallet::chain::Merge;
use bdk_wallet::template::Bip84;
use bdk_wallet::{
    ChangeSet, CreateWithPersistError, KeychainKind, LoadWithPersistError, PersistedWallet, Wallet,
    WalletPersister,
};
use bip39::Mnemonic;
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, MAX_RECORD_ID_BYTES, SharedWalletStore,
    StoreError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{BIP39_SEED_BYTES, BitcoinWalletError};

/// Version of the wallet-owned encrypted BDK snapshot envelope.
pub const BDK_WALLET_STATE_FORMAT_VERSION: u16 = 2;
pub const BDK_WALLET_LEGACY_STATE_FORMAT_VERSION: u16 = 1;
pub const BDK_WALLET_CHANGESET_RECORD_VERSION: u16 = 1;
pub const BDK_WALLET_CHANGESET_COMPACTION_INTERVAL: usize = 32;
pub const MAX_BDK_WALLET_CHANGESET_RECORDS: usize = 4_096;
const BDK_WALLET_CHANGESET_ID_DOMAIN: &[u8] = b"hns-wallet-rs/bdk-changeset/v1/";
const BDK_WALLET_JOURNAL_HEAD_MARKER: u8 = 0;
const BDK_WALLET_CHANGESET_MARKER: u8 = 1;
/// Exact BDK changeset serialization contract accepted by this envelope.
pub const BDK_WALLET_CHANGESET_VERSION: [u16; 3] = [3, 1, 0];

/// The strict envelope is encrypted by `WalletStore`; it must never be written
/// to a diagnostic or an unauthenticated sidecar.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBdkWalletState {
    format_version: u16,
    bdk_wallet_version: [u16; 3],
    #[serde(default)]
    compacted_sequence: u64,
    changeset: ChangeSet,
}

impl StoredBdkWalletState {
    fn new(compacted_sequence: u64, changeset: ChangeSet) -> Result<Self, BitcoinWalletError> {
        let state = Self {
            format_version: BDK_WALLET_STATE_FORMAT_VERSION,
            bdk_wallet_version: BDK_WALLET_CHANGESET_VERSION,
            compacted_sequence,
            changeset,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), BitcoinWalletError> {
        if !matches!(
            self.format_version,
            BDK_WALLET_LEGACY_STATE_FORMAT_VERSION | BDK_WALLET_STATE_FORMAT_VERSION
        ) || self.bdk_wallet_version != BDK_WALLET_CHANGESET_VERSION
            || (self.format_version == BDK_WALLET_LEGACY_STATE_FORMAT_VERSION
                && self.compacted_sequence != 0)
        {
            return Err(BitcoinWalletError::UnsupportedBitcoinWalletState);
        }
        if self.changeset.descriptor.is_none()
            || self.changeset.change_descriptor.is_none()
            || self.changeset.network.is_none()
        {
            return Err(BitcoinWalletError::CorruptBitcoinWalletState);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum StoredBdkWalletJournalRecord {
    Head {
        format_version: u16,
        bdk_wallet_version: [u16; 3],
        account_commitment: [u8; 32],
        next_sequence: u64,
    },
    ChangeSet {
        format_version: u16,
        bdk_wallet_version: [u16; 3],
        account_commitment: [u8; 32],
        sequence: u64,
        changeset: Box<ChangeSet>,
    },
}

impl StoredBdkWalletJournalRecord {
    fn validate(&self, account_commitment: [u8; 32]) -> Result<(), BitcoinWalletError> {
        match self {
            Self::Head {
                format_version,
                bdk_wallet_version,
                account_commitment: stored_commitment,
                next_sequence,
            } => {
                if *format_version != BDK_WALLET_CHANGESET_RECORD_VERSION
                    || *bdk_wallet_version != BDK_WALLET_CHANGESET_VERSION
                    || *stored_commitment != account_commitment
                    || *next_sequence == 0
                {
                    return Err(BitcoinWalletError::CorruptBitcoinWalletState);
                }
            }
            Self::ChangeSet {
                format_version,
                bdk_wallet_version,
                account_commitment: stored_commitment,
                sequence,
                changeset,
            } => {
                if *format_version != BDK_WALLET_CHANGESET_RECORD_VERSION
                    || *bdk_wallet_version != BDK_WALLET_CHANGESET_VERSION
                    || *stored_commitment != account_commitment
                    || *sequence == 0
                    || changeset.is_empty()
                {
                    return Err(BitcoinWalletError::CorruptBitcoinWalletState);
                }
            }
        }
        Ok(())
    }

    fn sequence(&self) -> Option<u64> {
        match self {
            Self::Head { .. } => None,
            Self::ChangeSet { sequence, .. } => Some(*sequence),
        }
    }
}

enum PersisterState {
    Uninitialized,
    Initialized {
        snapshot_revision: u64,
        journal_head_revision: u64,
        next_sequence: u64,
        journal_records: usize,
        had_persisted_state: bool,
        aggregate: Box<ChangeSet>,
    },
}

/// BDK persistence adapter backed by an authenticated, encrypted WalletStore
/// snapshot plus bounded incremental changeset journal. It deliberately has no
/// `Debug` implementation.
struct BdkWalletStorePersister {
    store: SharedWalletStore,
    account_id: Vec<u8>,
    now_unix: u64,
    state: PersisterState,
}

impl BdkWalletStorePersister {
    fn new(
        store: SharedWalletStore,
        account_id: &[u8],
        now_unix: u64,
    ) -> Result<Self, BitcoinWalletError> {
        if account_id.is_empty() || account_id.len() > MAX_RECORD_ID_BYTES {
            return Err(StoreError::InvalidRecordId.into());
        }
        Ok(Self {
            store,
            account_id: account_id.to_vec(),
            now_unix,
            state: PersisterState::Uninitialized,
        })
    }

    fn account_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BDK_WALLET_CHANGESET_ID_DOMAIN);
        hasher.update(&self.account_id);
        hasher.finalize().into()
    }

    fn journal_id(account_commitment: [u8; 32], sequence: u64) -> Vec<u8> {
        let mut id = Vec::with_capacity(41);
        id.extend_from_slice(&account_commitment);
        id.push(BDK_WALLET_CHANGESET_MARKER);
        id.extend_from_slice(&sequence.to_be_bytes());
        id
    }

    fn journal_head_id(account_commitment: [u8; 32]) -> Vec<u8> {
        let mut id = Vec::with_capacity(33);
        id.extend_from_slice(&account_commitment);
        id.push(BDK_WALLET_JOURNAL_HEAD_MARKER);
        id
    }

    fn load_state(&self) -> Result<PersisterState, BitcoinWalletError> {
        let account_commitment = self.account_commitment();
        let (snapshot, journal) = self.store.with_store(|store| {
            store.try_with_entity_read_snapshot(|read| {
                let snapshot = read.load_entity::<StoredBdkWalletState>(
                    EntityKind::BitcoinWalletState,
                    &self.account_id,
                )?;
                let journal = read.list_entities_by_id_prefix::<StoredBdkWalletJournalRecord>(
                    EntityKind::BitcoinWalletChangeSet,
                    &account_commitment,
                    MAX_BDK_WALLET_CHANGESET_RECORDS + 2,
                )?;
                Ok::<_, StoreError>((snapshot, journal))
            })
        })?;
        let (snapshot_revision, compacted_sequence, mut aggregate, mut had_persisted_state) =
            match snapshot {
                Some(stored) => {
                    stored.value.validate()?;
                    (
                        stored.revision,
                        stored.value.compacted_sequence,
                        stored.value.changeset,
                        true,
                    )
                }
                None => (0, 0, ChangeSet::default(), false),
            };
        if journal.len() > MAX_BDK_WALLET_CHANGESET_RECORDS + 1 {
            return Err(BitcoinWalletError::CorruptBitcoinWalletState);
        }
        let mut journal = journal;
        journal.sort_by_key(|record| record.value.sequence().unwrap_or(0));
        let mut expected_sequence = compacted_sequence.saturating_add(1);
        let mut active_journal_records = 0_usize;
        let mut total_changeset_records = 0_usize;
        let mut journal_head = None;
        for record in journal {
            record.value.validate(account_commitment)?;
            match record.value {
                StoredBdkWalletJournalRecord::Head { next_sequence, .. } => {
                    if record.id != Self::journal_head_id(account_commitment)
                        || journal_head
                            .replace((record.revision, next_sequence))
                            .is_some()
                    {
                        return Err(BitcoinWalletError::CorruptBitcoinWalletState);
                    }
                }
                StoredBdkWalletJournalRecord::ChangeSet {
                    sequence,
                    changeset,
                    ..
                } => {
                    total_changeset_records = total_changeset_records
                        .checked_add(1)
                        .ok_or(BitcoinWalletError::SequenceOverflow)?;
                    if total_changeset_records > MAX_BDK_WALLET_CHANGESET_RECORDS
                        || record.id != Self::journal_id(account_commitment, sequence)
                    {
                        return Err(BitcoinWalletError::CorruptBitcoinWalletState);
                    }
                    if sequence <= compacted_sequence {
                        continue;
                    }
                    if sequence != expected_sequence {
                        return Err(BitcoinWalletError::CorruptBitcoinWalletState);
                    }
                    Self::reject_immutable_changes(&aggregate, &changeset)?;
                    aggregate.merge(*changeset);
                    expected_sequence = expected_sequence
                        .checked_add(1)
                        .ok_or(BitcoinWalletError::SequenceOverflow)?;
                    active_journal_records = active_journal_records
                        .checked_add(1)
                        .ok_or(BitcoinWalletError::SequenceOverflow)?;
                }
            }
        }
        let journal_head_revision = match journal_head {
            Some((revision, head_next_sequence)) if head_next_sequence == expected_sequence => {
                had_persisted_state = true;
                revision
            }
            Some(_) => return Err(BitcoinWalletError::CorruptBitcoinWalletState),
            None if total_changeset_records == 0 && compacted_sequence == 0 => 0,
            None => return Err(BitcoinWalletError::CorruptBitcoinWalletState),
        };
        if had_persisted_state
            && (aggregate.descriptor.is_none()
                || aggregate.change_descriptor.is_none()
                || aggregate.network.is_none())
        {
            return Err(BitcoinWalletError::CorruptBitcoinWalletState);
        }
        Ok(PersisterState::Initialized {
            snapshot_revision,
            journal_head_revision,
            next_sequence: expected_sequence,
            journal_records: active_journal_records,
            had_persisted_state,
            aggregate: Box::new(aggregate),
        })
    }

    fn reject_immutable_changes(
        aggregate: &ChangeSet,
        changeset: &ChangeSet,
    ) -> Result<(), BitcoinWalletError> {
        if changeset
            .descriptor
            .as_ref()
            .zip(aggregate.descriptor.as_ref())
            .is_some_and(|(next, current)| next != current)
            || changeset
                .change_descriptor
                .as_ref()
                .zip(aggregate.change_descriptor.as_ref())
                .is_some_and(|(next, current)| next != current)
            || changeset
                .network
                .as_ref()
                .zip(aggregate.network.as_ref())
                .is_some_and(|(next, current)| next != current)
        {
            return Err(BitcoinWalletError::BitcoinWalletStateConflict);
        }
        Ok(())
    }

    fn accept_exact_retry(
        &mut self,
        sequence: u64,
        changeset: &ChangeSet,
        candidate: &ChangeSet,
        had_persisted_state: bool,
        stale: StoreError,
    ) -> Result<(), BitcoinWalletError> {
        if !had_persisted_state {
            return Err(BitcoinWalletError::WalletAlreadyExists);
        }
        let account_commitment = self.account_commitment();
        let id = Self::journal_id(account_commitment, sequence);
        let Some(stored) = self.store.with_store(|store| {
            store.bitcoin_wallet_changeset::<StoredBdkWalletJournalRecord>(&id)
        })?
        else {
            return Err(stale.into());
        };
        stored.value.validate(account_commitment)?;
        if !matches!(
            stored.value,
            StoredBdkWalletJournalRecord::ChangeSet {
                sequence: stored_sequence,
                changeset: ref stored_changeset,
                ..
            } if stored_sequence == sequence && stored_changeset.as_ref() == changeset
        ) {
            return Err(stale.into());
        }
        let loaded = self.load_state()?;
        let PersisterState::Initialized { aggregate, .. } = &loaded else {
            return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
        };
        if aggregate.as_ref() != candidate {
            return Err(stale.into());
        }
        self.state = loaded;
        Ok(())
    }

    fn compact(&mut self) -> Result<(), BitcoinWalletError> {
        let (
            snapshot_revision,
            journal_head_revision,
            next_sequence,
            journal_records,
            had_persisted_state,
            aggregate,
        ) = match &self.state {
            PersisterState::Uninitialized => {
                return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
            }
            PersisterState::Initialized {
                snapshot_revision,
                journal_head_revision,
                next_sequence,
                journal_records,
                had_persisted_state,
                aggregate,
            } => (
                *snapshot_revision,
                *journal_head_revision,
                *next_sequence,
                *journal_records,
                *had_persisted_state,
                aggregate.as_ref().clone(),
            ),
        };
        if journal_records < BDK_WALLET_CHANGESET_COMPACTION_INTERVAL {
            return Ok(());
        }
        let through_sequence = next_sequence
            .checked_sub(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        let snapshot = StoredBdkWalletState::new(through_sequence, aggregate.clone())?;
        let next_snapshot_revision = self.store.with_store_mut(|store| {
            store.save_bitcoin_wallet_state(
                &self.account_id,
                snapshot_revision,
                &snapshot,
                self.now_unix,
            )
        })?;
        self.state = PersisterState::Initialized {
            snapshot_revision: next_snapshot_revision,
            journal_head_revision,
            next_sequence,
            journal_records: 0,
            had_persisted_state,
            aggregate: Box::new(aggregate),
        };

        // The snapshot is authoritative before pruning. A crash or pruning
        // failure can only leave redundant authenticated deltas, which the
        // loader ignores at or below `compacted_sequence`.
        let account_commitment = self.account_commitment();
        let redundant = self.store.with_store(|store| {
            store.list_entities_by_id_prefix::<StoredBdkWalletJournalRecord>(
                EntityKind::BitcoinWalletChangeSet,
                &account_commitment,
                MAX_BDK_WALLET_CHANGESET_RECORDS + 2,
            )
        })?;
        let deletes = redundant
            .into_iter()
            .filter(|record| {
                record
                    .value
                    .sequence()
                    .is_some_and(|sequence| sequence <= through_sequence)
            })
            .map(|record| EntityBatchDelete {
                id: record.id,
                expected_revision: record.revision,
            })
            .collect::<Vec<_>>();
        if !deletes.is_empty() {
            self.store.with_store_mut(|store| {
                store.apply_entity_batch::<StoredBdkWalletJournalRecord>(
                    EntityKind::BitcoinWalletChangeSet,
                    &[],
                    &deletes,
                )
            })?;
        }
        Ok(())
    }
}

impl WalletPersister for BdkWalletStorePersister {
    type Error = BitcoinWalletError;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        // Read on every initialization. A cached result would violate BDK's
        // requirement to return all data currently held by the persister.
        persister.state = PersisterState::Uninitialized;
        persister.state = persister.load_state()?;
        let PersisterState::Initialized { aggregate, .. } = &persister.state else {
            return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
        };
        let aggregate = aggregate.as_ref().clone();
        Ok(aggregate)
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        let (journal_head_revision, next_sequence, had_persisted_state, aggregate) =
            match &persister.state {
                PersisterState::Uninitialized => {
                    return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
                }
                PersisterState::Initialized {
                    journal_head_revision,
                    next_sequence,
                    had_persisted_state,
                    aggregate,
                    ..
                } => (
                    *journal_head_revision,
                    *next_sequence,
                    *had_persisted_state,
                    aggregate.as_ref().clone(),
                ),
            };
        Self::reject_immutable_changes(&aggregate, changeset)?;
        let mut candidate = aggregate.clone();
        candidate.merge(changeset.clone());
        if candidate == aggregate {
            return Ok(());
        }
        let account_commitment = persister.account_commitment();
        let id = Self::journal_id(account_commitment, next_sequence);
        let record = StoredBdkWalletJournalRecord::ChangeSet {
            format_version: BDK_WALLET_CHANGESET_RECORD_VERSION,
            bdk_wallet_version: BDK_WALLET_CHANGESET_VERSION,
            account_commitment,
            sequence: next_sequence,
            changeset: Box::new(changeset.clone()),
        };
        record.validate(account_commitment)?;
        let head_id = Self::journal_head_id(account_commitment);
        let next_head_sequence = next_sequence
            .checked_add(1)
            .ok_or(BitcoinWalletError::SequenceOverflow)?;
        let head = StoredBdkWalletJournalRecord::Head {
            format_version: BDK_WALLET_CHANGESET_RECORD_VERSION,
            bdk_wallet_version: BDK_WALLET_CHANGESET_VERSION,
            account_commitment,
            next_sequence: next_head_sequence,
        };
        head.validate(account_commitment)?;
        let saved = persister.store.with_store_mut(|store| {
            store.apply_entity_batch(
                EntityKind::BitcoinWalletChangeSet,
                &[
                    EntityBatchSave {
                        id: head_id,
                        expected_revision: journal_head_revision,
                        value: head,
                        updated_at_unix: persister.now_unix,
                    },
                    EntityBatchSave {
                        id,
                        expected_revision: 0,
                        value: record,
                        updated_at_unix: persister.now_unix,
                    },
                ],
                &[],
            )
        });
        match saved {
            Ok(()) => {
                let PersisterState::Initialized {
                    journal_head_revision,
                    next_sequence,
                    journal_records,
                    had_persisted_state,
                    aggregate,
                    ..
                } = &mut persister.state
                else {
                    return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
                };
                *journal_head_revision = journal_head_revision
                    .checked_add(1)
                    .ok_or(BitcoinWalletError::SequenceOverflow)?;
                *next_sequence = next_head_sequence;
                *journal_records = journal_records
                    .checked_add(1)
                    .ok_or(BitcoinWalletError::SequenceOverflow)?;
                *had_persisted_state = true;
                *aggregate = Box::new(candidate);
                persister.compact()
            }
            Err(stale @ StoreError::StaleRevision { .. }) => persister.accept_exact_retry(
                next_sequence,
                changeset,
                &candidate,
                had_persisted_state,
                stale,
            ),
            Err(error) => Err(error.into()),
        }
    }
}

/// A BDK wallet permanently paired with the encrypted store/account persister
/// that created or loaded it. The wrapper prevents accidentally clearing BDK's
/// staged changes against another wallet database of the same persister type.
pub struct EncryptedPersistedBitcoinWallet {
    wallet: PersistedWallet<BdkWalletStorePersister>,
    persister: BdkWalletStorePersister,
}

impl EncryptedPersistedBitcoinWallet {
    pub fn account_id(&self) -> &[u8] {
        &self.persister.account_id
    }

    pub fn persistence_revision(&self) -> u64 {
        match &self.persister.state {
            PersisterState::Uninitialized => 0,
            PersisterState::Initialized { next_sequence, .. } => next_sequence.saturating_sub(1),
        }
    }

    pub fn persist(&mut self, now_unix: u64) -> Result<bool, BitcoinWalletError> {
        self.persister.now_unix = now_unix;
        self.wallet.persist(&mut self.persister)
    }

    pub(crate) fn shared_store(&self) -> &SharedWalletStore {
        &self.persister.store
    }
}

impl Deref for EncryptedPersistedBitcoinWallet {
    type Target = Wallet;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for EncryptedPersistedBitcoinWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

/// Creates a BIP84 wallet and commits its complete public BDK changeset into
/// the encrypted wallet store before returning. This function never persists
/// the mnemonic or seed; the caller is responsible for the separate protected
/// recovery-seed record required to reconstruct the private signers on load.
pub fn create_persisted_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
    store: SharedWalletStore,
    account_id: &[u8],
    now_unix: u64,
) -> Result<EncryptedPersistedBitcoinWallet, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    create_persisted_descriptor_wallet_from_seed(
        seed.as_slice(),
        network,
        store,
        account_id,
        now_unix,
    )
}

/// Persist a BIP84 wallet derived from an existing encrypted BIP-39 seed.
///
/// Installed HNS wallets persist the seed, not the mnemonic text, after the
/// recovery phrase has been shown. This keeps HNS and Bitcoin under the same
/// wallet recovery authority without storing a duplicate phrase.
pub fn create_persisted_descriptor_wallet_from_seed(
    seed: &[u8],
    network: Network,
    store: SharedWalletStore,
    account_id: &[u8],
    now_unix: u64,
) -> Result<EncryptedPersistedBitcoinWallet, BitcoinWalletError> {
    if seed.len() != BIP39_SEED_BYTES {
        return Err(BitcoinWalletError::KeyDerivation);
    }
    let root = Xpriv::new_master(network, seed).map_err(|_| BitcoinWalletError::KeyDerivation)?;
    let mut persister = BdkWalletStorePersister::new(store, account_id, now_unix)?;
    let wallet = Wallet::create(
        Bip84(root, KeychainKind::External),
        Bip84(root, KeychainKind::Internal),
    )
    .network(network)
    // Persisting the script cache would cause an aggregate snapshot to grow
    // faster without adding authoritative wallet state.
    .create_wallet(&mut persister)
    .map_err(map_create_error)?;
    Ok(EncryptedPersistedBitcoinWallet { wallet, persister })
}

/// Loads only the authenticated encrypted BDK state for `account_id` and
/// reconstructs private signers from the protected mnemonic. Legacy standalone
/// BDK SQLite files are intentionally neither opened nor modified.
pub fn load_persisted_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
    store: SharedWalletStore,
    account_id: &[u8],
    now_unix: u64,
) -> Result<EncryptedPersistedBitcoinWallet, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    load_persisted_descriptor_wallet_from_seed(
        seed.as_slice(),
        network,
        store,
        account_id,
        now_unix,
    )
}

/// Load a BIP84 wallet from its encrypted BDK state and its exact protected
/// BIP-39 seed. See [`create_persisted_descriptor_wallet_from_seed`] for why
/// mobile compositions use this instead of retaining mnemonic text.
pub fn load_persisted_descriptor_wallet_from_seed(
    seed: &[u8],
    network: Network,
    store: SharedWalletStore,
    account_id: &[u8],
    now_unix: u64,
) -> Result<EncryptedPersistedBitcoinWallet, BitcoinWalletError> {
    if seed.len() != BIP39_SEED_BYTES {
        return Err(BitcoinWalletError::KeyDerivation);
    }
    let root = Xpriv::new_master(network, seed).map_err(|_| BitcoinWalletError::KeyDerivation)?;
    let mut persister = BdkWalletStorePersister::new(store, account_id, now_unix)?;
    let wallet = Wallet::load()
        .descriptor(
            KeychainKind::External,
            Some(Bip84(root, KeychainKind::External)),
        )
        .descriptor(
            KeychainKind::Internal,
            Some(Bip84(root, KeychainKind::Internal)),
        )
        .extract_keys()
        .check_network(network)
        .load_wallet(&mut persister)
        .map_err(map_load_error)?
        .ok_or(BitcoinWalletError::WalletNotFound)?;
    Ok(EncryptedPersistedBitcoinWallet { wallet, persister })
}

fn map_create_error(error: CreateWithPersistError<BitcoinWalletError>) -> BitcoinWalletError {
    match error {
        CreateWithPersistError::Persist(error) => error,
        CreateWithPersistError::DataAlreadyExists(_) => BitcoinWalletError::WalletAlreadyExists,
        CreateWithPersistError::Descriptor(_) => BitcoinWalletError::WalletCreationFailed,
    }
}

fn map_load_error(error: LoadWithPersistError<BitcoinWalletError>) -> BitcoinWalletError {
    match error {
        LoadWithPersistError::Persist(error) => error,
        LoadWithPersistError::InvalidChangeSet(_) => BitcoinWalletError::CorruptBitcoinWalletState,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_wallet_store::WalletStore;

    const PASSPHRASE: &str = "correct horse battery staple";
    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PHRASE_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn mnemonic(phrase: &str) -> Mnemonic {
        Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
            .expect("valid deterministic phrase")
    }

    fn shared_store() -> SharedWalletStore {
        SharedWalletStore::new(
            WalletStore::create(":memory:", PASSPHRASE).expect("in-memory wallet store"),
        )
    }

    #[test]
    fn encrypted_persister_roundtrips_and_retains_staged_changes_after_failure() {
        let store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let mut created = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            1,
        )
        .expect("create persisted wallet");
        let first = created.reveal_next_address(KeychainKind::External).address;
        assert!(created.persist(2).expect("persist revealed address"));

        let loaded = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            3,
        )
        .expect("load persisted wallet");
        assert_eq!(
            loaded.peek_address(KeychainKind::External, 0).address,
            first
        );

        let _ = created.reveal_next_address(KeychainKind::External);
        store.lock().expect("lock store");
        assert!(matches!(
            created.persist(4),
            Err(BitcoinWalletError::Store(StoreError::Locked))
        ));
        store.unlock(PASSPHRASE).expect("unlock store");
        assert!(
            created
                .persist(5)
                .expect("staged change survived failed persistence")
        );
    }

    #[test]
    fn protected_bip39_seed_derives_and_reloads_the_same_bip84_wallet() {
        let store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let seed = Zeroizing::new(phrase.to_seed_normalized(""));
        let mut created = create_persisted_descriptor_wallet_from_seed(
            seed.as_slice(),
            Network::Regtest,
            store.clone(),
            b"seed-account",
            1,
        )
        .expect("create from the protected BIP-39 seed");
        let first = created.reveal_next_address(KeychainKind::External).address;
        assert!(created.persist(2).expect("persist revealed address"));

        let loaded = load_persisted_descriptor_wallet_from_seed(
            seed.as_slice(),
            Network::Regtest,
            store,
            b"seed-account",
            3,
        )
        .expect("reload from the protected BIP-39 seed");
        assert_eq!(
            loaded.peek_address(KeychainKind::External, 0).address,
            first
        );
        assert!(matches!(
            create_persisted_descriptor_wallet_from_seed(
                &[0; BIP39_SEED_BYTES - 1],
                Network::Regtest,
                shared_store(),
                b"short-seed",
                1,
            ),
            Err(BitcoinWalletError::KeyDerivation)
        ));
    }

    #[test]
    fn incremental_changesets_compact_and_reload_without_losing_addresses() {
        let store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let account_id = b"compacted-account";
        let mut created = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            account_id,
            1,
        )
        .expect("create persisted wallet");

        let mut addresses = Vec::new();
        for now_unix in 2..=(BDK_WALLET_CHANGESET_COMPACTION_INTERVAL as u64 + 6) {
            addresses.push(created.reveal_next_address(KeychainKind::External).address);
            assert!(created.persist(now_unix).expect("persist address delta"));
        }

        let snapshot = store
            .with_store(|wallet_store| {
                wallet_store.bitcoin_wallet_state::<StoredBdkWalletState>(account_id)
            })
            .expect("read compacted snapshot")
            .expect("compaction produced a snapshot");
        assert_eq!(
            snapshot.value.format_version,
            BDK_WALLET_STATE_FORMAT_VERSION
        );
        assert!(
            snapshot.value.compacted_sequence >= BDK_WALLET_CHANGESET_COMPACTION_INTERVAL as u64
        );
        let account_commitment = created.persister.account_commitment();
        let journal = store
            .with_store(|wallet_store| {
                wallet_store.list_entities_by_id_prefix::<StoredBdkWalletJournalRecord>(
                    EntityKind::BitcoinWalletChangeSet,
                    &account_commitment,
                    BDK_WALLET_CHANGESET_COMPACTION_INTERVAL + 2,
                )
            })
            .expect("list remaining deltas");
        let head = journal
            .iter()
            .find_map(|record| match record.value {
                StoredBdkWalletJournalRecord::Head { next_sequence, .. } => Some(next_sequence),
                StoredBdkWalletJournalRecord::ChangeSet { .. } => None,
            })
            .expect("journal head remains after compaction");
        assert_eq!(head, created.persistence_revision() + 1);
        let remaining_deltas = journal
            .iter()
            .filter(|record| matches!(record.value, StoredBdkWalletJournalRecord::ChangeSet { .. }))
            .count();
        assert!(remaining_deltas < BDK_WALLET_CHANGESET_COMPACTION_INTERVAL);
        assert!(
            journal
                .iter()
                .filter_map(|record| record.value.sequence())
                .all(|sequence| sequence > snapshot.value.compacted_sequence)
        );

        let loaded =
            load_persisted_descriptor_wallet(&phrase, Network::Regtest, store, account_id, 100)
                .expect("reload compacted wallet");
        for (index, address) in addresses.into_iter().enumerate() {
            assert_eq!(
                loaded
                    .peek_address(KeychainKind::External, index as u32)
                    .address,
                address
            );
        }
    }

    #[test]
    fn stale_writer_cannot_reuse_a_sequence_pruned_by_compaction() {
        let store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let account_id = b"compaction-race-account";
        let mut winner = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            account_id,
            1,
        )
        .expect("create persisted wallet");
        let mut stale = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            account_id,
            1,
        )
        .expect("load stale writer before compaction");

        // Make sequence two deliberately different in each writer. The
        // winner then advances through a compaction that prunes that delta.
        let _ = stale.reveal_next_address(KeychainKind::External);
        let _ = winner.reveal_next_address(KeychainKind::External);
        let _ = winner.reveal_next_address(KeychainKind::External);
        assert!(winner.persist(2).expect("persist divergent sequence two"));
        for now_unix in 3..=(BDK_WALLET_CHANGESET_COMPACTION_INTERVAL as u64 + 1) {
            let _ = winner.reveal_next_address(KeychainKind::External);
            assert!(winner.persist(now_unix).expect("advance to compaction"));
        }
        assert!(winner.persistence_revision() > BDK_WALLET_CHANGESET_COMPACTION_INTERVAL as u64);

        let account_commitment = winner.persister.account_commitment();
        let pruned_sequence_id = BdkWalletStorePersister::journal_id(account_commitment, 2);
        assert!(
            store
                .with_store(|wallet_store| wallet_store
                    .bitcoin_wallet_changeset::<StoredBdkWalletJournalRecord>(&pruned_sequence_id))
                .expect("inspect pruned sequence")
                .is_none()
        );

        let winner_revision = winner.persistence_revision();
        assert!(matches!(
            stale.persist(100),
            Err(BitcoinWalletError::Store(StoreError::StaleRevision { .. }))
        ));
        let loaded =
            load_persisted_descriptor_wallet(&phrase, Network::Regtest, store, account_id, 101)
                .expect("reload winning compacted state");
        assert_eq!(loaded.persistence_revision(), winner_revision);
    }

    #[test]
    fn legacy_version_one_snapshot_remains_loadable() {
        let source_store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let source = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            source_store,
            b"legacy-source",
            1,
        )
        .expect("create source wallet");
        let aggregate = match &source.persister.state {
            PersisterState::Initialized { aggregate, .. } => aggregate.as_ref().clone(),
            PersisterState::Uninitialized => panic!("initialized source persister"),
        };

        let legacy_store = shared_store();
        let legacy = StoredBdkWalletState {
            format_version: BDK_WALLET_LEGACY_STATE_FORMAT_VERSION,
            bdk_wallet_version: BDK_WALLET_CHANGESET_VERSION,
            compacted_sequence: 0,
            changeset: aggregate,
        };
        legacy_store
            .with_store_mut(|wallet_store| {
                wallet_store.save_bitcoin_wallet_state(b"legacy-account", 0, &legacy, 2)
            })
            .expect("write legacy version-one snapshot");

        let loaded = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            legacy_store,
            b"legacy-account",
            3,
        )
        .expect("load legacy version-one snapshot");
        assert_eq!(loaded.network(), Network::Regtest);
        assert_eq!(loaded.persistence_revision(), 0);
    }

    #[test]
    fn stale_retry_is_exact_and_descriptors_and_network_are_immutable() {
        let store = shared_store();
        let phrase = mnemonic(PHRASE_A);
        let mut losing_initial =
            BdkWalletStorePersister::new(store.clone(), b"account-initial-race", 1)
                .expect("initial racing persister");
        assert!(
            <BdkWalletStorePersister as WalletPersister>::initialize(&mut losing_initial)
                .expect("initialize absent account")
                .is_empty()
        );
        let winner_initial = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-initial-race",
            1,
        )
        .expect("winning initial create");
        let winner_initial_changeset = match &winner_initial.persister.state {
            PersisterState::Initialized { aggregate, .. } => aggregate.as_ref().clone(),
            PersisterState::Uninitialized => panic!("initialized winning persister"),
        };
        assert!(matches!(
            <BdkWalletStorePersister as WalletPersister>::persist(
                &mut losing_initial,
                &winner_initial_changeset,
            ),
            Err(BitcoinWalletError::WalletAlreadyExists)
        ));

        let mut first = create_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            1,
        )
        .expect("create persisted wallet");
        let aggregate = match &first.persister.state {
            PersisterState::Initialized { aggregate, .. } => aggregate.as_ref().clone(),
            PersisterState::Uninitialized => panic!("initialized persister"),
        };
        let unsupported = StoredBdkWalletState {
            format_version: BDK_WALLET_STATE_FORMAT_VERSION,
            bdk_wallet_version: [3, 2, 0],
            compacted_sequence: 0,
            changeset: aggregate,
        };
        assert!(matches!(
            unsupported.validate(),
            Err(BitcoinWalletError::UnsupportedBitcoinWalletState)
        ));
        let mut exact_retry = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            1,
        )
        .expect("load concurrent wallet");
        let _ = first.reveal_next_address(KeychainKind::External);
        let _ = exact_retry.reveal_next_address(KeychainKind::External);
        assert!(first.persist(2).expect("first writer"));
        assert!(exact_retry.persist(2).expect("exact stale retry"));
        assert_eq!(
            exact_retry.persistence_revision(),
            first.persistence_revision()
        );

        let mut winner = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            3,
        )
        .expect("load winner");
        let mut divergent = load_persisted_descriptor_wallet(
            &phrase,
            Network::Regtest,
            store.clone(),
            b"account-a",
            3,
        )
        .expect("load divergent writer");
        let _ = winner.reveal_next_address(KeychainKind::External);
        let _ = divergent.reveal_next_address(KeychainKind::External);
        let _ = divergent.reveal_next_address(KeychainKind::External);
        assert!(winner.persist(4).expect("winning writer"));
        assert!(matches!(
            divergent.persist(4),
            Err(BitcoinWalletError::Store(StoreError::StaleRevision { .. }))
        ));

        let other = create_persisted_descriptor_wallet(
            &mnemonic(PHRASE_B),
            Network::Regtest,
            store,
            b"account-b",
            5,
        )
        .expect("create other descriptors");
        let other_descriptor = match &other.persister.state {
            PersisterState::Initialized { aggregate, .. } => aggregate
                .descriptor
                .clone()
                .expect("persisted public descriptor"),
            PersisterState::Uninitialized => panic!("initialized persister"),
        };
        let descriptor_change = ChangeSet {
            descriptor: Some(other_descriptor),
            ..ChangeSet::default()
        };
        assert!(matches!(
            <BdkWalletStorePersister as WalletPersister>::persist(
                &mut winner.persister,
                &descriptor_change,
            ),
            Err(BitcoinWalletError::BitcoinWalletStateConflict)
        ));

        let network_change = ChangeSet {
            network: Some(Network::Bitcoin),
            ..ChangeSet::default()
        };
        assert!(matches!(
            <BdkWalletStorePersister as WalletPersister>::persist(
                &mut winner.persister,
                &network_change,
            ),
            Err(BitcoinWalletError::BitcoinWalletStateConflict)
        ));
    }

    #[test]
    fn sync_source_commits_swap_evidence_before_bdk_and_ready() {
        let source = include_str!("runtime.rs");
        let cycle = source
            .split_once("let announced_tip = update")
            .expect("sync update section")
            .1
            .split_once("async fn finish_reconciliation")
            .expect("reconciliation function")
            .0;
        let bdk_commit = cycle
            .find("wallet.persist(now_unix)?;")
            .expect("BDK commit");
        let swap_reconciliation = cycle
            .find("reconcile_bitcoin_htlc_watches")
            .expect("swap evidence reconciliation");
        let reconciling = cycle
            .find("self.durable.state.phase = KyotoSyncPhase::Reconciling")
            .expect("reconciling journal transition");
        let reconciliation = cycle
            .find("self.finish_reconciliation")
            .expect("mirror reconciliation");
        assert!(swap_reconciliation < bdk_commit);
        assert!(bdk_commit < reconciling);
        assert!(reconciling < reconciliation);

        let finish = source
            .split_once("async fn finish_reconciliation")
            .expect("reconciliation function")
            .1
            .split_once("pub async fn minimum_broadcast_fee_rate_sat_vb")
            .expect("end reconciliation function")
            .0;
        let mirrors = finish
            .find("reconcile_transaction_records")
            .expect("transaction mirrors");
        let ready = finish
            .find("self.durable.state.phase = KyotoSyncPhase::Ready")
            .expect("ready transition");
        let ready_commit = finish[ready..]
            .find("self.durable.persist(now_unix)?;")
            .expect("ready commit")
            + ready;
        assert!(mirrors < ready);
        assert!(ready < ready_commit);
    }
}
