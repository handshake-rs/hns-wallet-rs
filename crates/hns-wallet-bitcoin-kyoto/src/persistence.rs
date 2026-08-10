use std::ops::{Deref, DerefMut};

use bdk_wallet::bitcoin::{Network, bip32::Xpriv};
use bdk_wallet::chain::Merge;
use bdk_wallet::template::Bip84;
use bdk_wallet::{
    ChangeSet, CreateWithPersistError, KeychainKind, LoadWithPersistError, PersistedWallet, Wallet,
    WalletPersister,
};
use bip39::Mnemonic;
use hns_wallet_store::{MAX_RECORD_ID_BYTES, SharedWalletStore, StoreError, StoredEntity};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::BitcoinWalletError;

/// Version of the wallet-owned encrypted BDK snapshot envelope.
pub const BDK_WALLET_STATE_FORMAT_VERSION: u16 = 1;
/// Exact BDK changeset serialization contract accepted by this envelope.
pub const BDK_WALLET_CHANGESET_VERSION: [u16; 3] = [3, 1, 0];

/// The strict envelope is encrypted by `WalletStore`; it must never be written
/// to a diagnostic or an unauthenticated sidecar.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBdkWalletState {
    format_version: u16,
    bdk_wallet_version: [u16; 3],
    changeset: ChangeSet,
}

impl StoredBdkWalletState {
    fn new(changeset: ChangeSet) -> Result<Self, BitcoinWalletError> {
        let state = Self {
            format_version: BDK_WALLET_STATE_FORMAT_VERSION,
            bdk_wallet_version: BDK_WALLET_CHANGESET_VERSION,
            changeset,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.format_version != BDK_WALLET_STATE_FORMAT_VERSION
            || self.bdk_wallet_version != BDK_WALLET_CHANGESET_VERSION
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

enum PersisterState {
    Uninitialized,
    Initialized {
        revision: u64,
        aggregate: Box<ChangeSet>,
    },
}

/// BDK persistence adapter backed by one authenticated, encrypted WalletStore
/// record. It deliberately has no `Debug` implementation.
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

    fn load_record(
        &self,
    ) -> Result<Option<StoredEntity<StoredBdkWalletState>>, BitcoinWalletError> {
        self.store
            .with_store(|store| store.bitcoin_wallet_state(&self.account_id))
            .map_err(BitcoinWalletError::from)
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
        candidate: &ChangeSet,
        stale: StoreError,
    ) -> Result<(), BitcoinWalletError> {
        let Some(stored) = self.load_record()? else {
            return Err(stale.into());
        };
        stored.value.validate()?;
        if stored.value.changeset != *candidate {
            return Err(stale.into());
        }
        self.state = PersisterState::Initialized {
            revision: stored.revision,
            aggregate: Box::new(stored.value.changeset),
        };
        Ok(())
    }
}

impl WalletPersister for BdkWalletStorePersister {
    type Error = BitcoinWalletError;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        // Read on every initialization. A cached result would violate BDK's
        // requirement to return all data currently held by the persister.
        persister.state = PersisterState::Uninitialized;
        let Some(stored) = persister.load_record()? else {
            let aggregate = ChangeSet::default();
            persister.state = PersisterState::Initialized {
                revision: 0,
                aggregate: Box::new(aggregate.clone()),
            };
            return Ok(aggregate);
        };
        stored.value.validate()?;
        let aggregate = stored.value.changeset;
        persister.state = PersisterState::Initialized {
            revision: stored.revision,
            aggregate: Box::new(aggregate.clone()),
        };
        Ok(aggregate)
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        let (revision, aggregate) = match &persister.state {
            PersisterState::Uninitialized => {
                return Err(BitcoinWalletError::BitcoinWalletPersisterUninitialized);
            }
            PersisterState::Initialized {
                revision,
                aggregate,
            } => (*revision, aggregate.as_ref().clone()),
        };
        Self::reject_immutable_changes(&aggregate, changeset)?;
        let mut candidate = aggregate.clone();
        candidate.merge(changeset.clone());
        if candidate == aggregate {
            return Ok(());
        }
        let record = StoredBdkWalletState::new(candidate.clone())?;
        let saved = persister.store.with_store_mut(|store| {
            store.save_bitcoin_wallet_state(
                &persister.account_id,
                revision,
                &record,
                persister.now_unix,
            )
        });
        match saved {
            Ok(revision) => {
                persister.state = PersisterState::Initialized {
                    revision,
                    aggregate: Box::new(candidate),
                };
                Ok(())
            }
            // Revision zero means this process initialized against an absent
            // record. Another first writer winning that race is not an
            // idempotent retry: creation remains exclusive and the caller
            // must load the now-existing wallet explicitly.
            Err(StoreError::StaleRevision { .. }) if revision == 0 => {
                Err(BitcoinWalletError::WalletAlreadyExists)
            }
            Err(stale @ StoreError::StaleRevision { .. }) => {
                persister.accept_exact_retry(&candidate, stale)
            }
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
            PersisterState::Initialized { revision, .. } => *revision,
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
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
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
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
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
    fn sync_source_commits_bdk_before_reconciling_and_ready() {
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
        let reconciling = cycle
            .find("self.durable.state.phase = KyotoSyncPhase::Reconciling")
            .expect("reconciling journal transition");
        let reconciliation = cycle
            .find("self.finish_reconciliation")
            .expect("mirror reconciliation");
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
