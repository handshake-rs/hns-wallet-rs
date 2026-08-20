//! Durable wallet-local transaction index derived from verified filtered blocks.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use hns_covenants::{CovenantKind, TransferCovenant};
use hns_header_consensus::Network;
use hns_light_wallet::VerifiedWalletBlock;
use hns_primitives::{Outpoint, TransactionHash as CanonicalTransactionHash};
use hns_transaction::{Transaction, TransactionError};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, SharedWalletStore, StoreError, StoredEntity,
};
use hns_wallet_types::{AccountId, TransactionHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{EncryptedHnsLightAuthority, HnsLightError, HnsNetwork, WalletAddressKey};

/// Version of the encrypted filtered-block index envelope.
pub const HNS_LIGHT_INDEX_FORMAT_VERSION: u16 = 1;
/// Hard bound for the complete address-hash watch set owned by one account.
pub const MAX_HNS_LIGHT_WATCH_SCRIPTS: usize = 8_192;
/// Hard bound for explicit name hashes watched in addition to address hashes.
pub const MAX_HNS_LIGHT_WATCH_NAMES: usize = 4_096;

const SCAN_SUFFIX: &[u8] = b"/hns-light-index/scan";
const TRANSACTION_SUFFIX: &[u8] = b"/hns-light-index/tx/";
const WATCH_DIGEST_DOMAIN: &[u8] = b"hns-wallet-rs/hns-light-watch-set/v1";

/// Complete deterministic bloom-filter input set for one wallet account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsLightWatchSet {
    pub scripts: Vec<WalletAddressKey>,
    pub name_hashes: Vec<[u8; 32]>,
}

impl HnsLightWatchSet {
    /// Canonicalize and validate one bounded watch set.
    pub fn new(
        mut scripts: Vec<WalletAddressKey>,
        mut name_hashes: Vec<[u8; 32]>,
    ) -> Result<Self, HnsLightIndexError> {
        scripts.sort();
        scripts.dedup();
        name_hashes.sort_unstable();
        name_hashes.dedup();
        let watch = Self {
            scripts,
            name_hashes,
        };
        watch.validate()?;
        Ok(watch)
    }

    fn validate(&self) -> Result<(), HnsLightIndexError> {
        if self.scripts.len() > MAX_HNS_LIGHT_WATCH_SCRIPTS
            || self.name_hashes.len() > MAX_HNS_LIGHT_WATCH_NAMES
            || !self.scripts.windows(2).all(|pair| pair[0] < pair[1])
            || !self.name_hashes.windows(2).all(|pair| pair[0] < pair[1])
            || self
                .scripts
                .iter()
                .any(|script| script.version != 0 || !matches!(script.hash.len(), 20 | 32))
        {
            return Err(HnsLightIndexError::InvalidWatchSet);
        }
        Ok(())
    }

    fn digest(&self, network: Network, birthday_height: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(WATCH_DIGEST_DOMAIN);
        hasher.update([network.id()]);
        hasher.update(birthday_height.to_be_bytes());
        hasher.update((self.scripts.len() as u64).to_be_bytes());
        for script in &self.scripts {
            hasher.update([script.version]);
            hasher.update((script.hash.len() as u64).to_be_bytes());
            hasher.update(&script.hash);
        }
        hasher.update((self.name_hashes.len() as u64).to_be_bytes());
        for name_hash in &self.name_hashes {
            hasher.update(name_hash);
        }
        hasher.finalize().into()
    }
}

/// Persisted scan coverage for the exact watch set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsLightScanStatus {
    pub birthday_height: u32,
    pub scanned_height: Option<u32>,
    pub scanned_hash: Option<[u8; 32]>,
    pub watch_digest: [u8; 32],
    pub watched_scripts: usize,
    pub watched_names: usize,
}

/// One transaction whose relevance was established inside a locally verified
/// filtered block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHnsTransactionObservation {
    pub txid: TransactionHash,
    pub transaction: Transaction,
    pub raw: Vec<u8>,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub transaction_index: u32,
    pub block_time: u64,
    pub coinbase: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum StoredHnsLightWalletRecord {
    Scan(StoredHnsLightScan),
    Transaction(StoredHnsLightTransaction),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHnsLightScan {
    format_version: u16,
    network: u8,
    birthday_height: u32,
    watch_set: HnsLightWatchSet,
    watch_digest: [u8; 32],
    scanned_height: Option<u32>,
    scanned_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHnsLightTransaction {
    format_version: u16,
    network: u8,
    txid: [u8; 32],
    raw: Vec<u8>,
    height: u32,
    block_hash: [u8; 32],
    transaction_index: u32,
    block_time: u64,
    coinbase: bool,
}

impl StoredHnsLightTransaction {
    fn decode(
        &self,
        network: Network,
    ) -> Result<VerifiedHnsTransactionObservation, HnsLightIndexError> {
        if self.format_version != HNS_LIGHT_INDEX_FORMAT_VERSION {
            return Err(HnsLightIndexError::UnsupportedFormat);
        }
        if self.network != network.id() {
            return Err(HnsLightIndexError::NetworkMismatch);
        }
        let transaction = Transaction::decode(&self.raw)?;
        if transaction.encode()? != self.raw {
            return Err(HnsLightIndexError::NonCanonicalTransaction);
        }
        let txid = transaction.transaction_hash()?.into_bytes();
        if txid != self.txid || transaction.is_coinbase() != self.coinbase {
            return Err(HnsLightIndexError::CorruptTransactionRecord);
        }
        Ok(VerifiedHnsTransactionObservation {
            txid: TransactionHash::new(txid),
            transaction,
            raw: self.raw.clone(),
            height: self.height,
            block_hash: self.block_hash,
            transaction_index: self.transaction_index,
            block_time: self.block_time,
            coinbase: self.coinbase,
        })
    }
}

/// Encrypted account index whose only confirmed-state input is
/// [`VerifiedWalletBlock`].
pub struct EncryptedHnsLightIndex {
    store: SharedWalletStore,
    account_id: AccountId,
    network: Network,
    scan_revision: u64,
    scan: StoredHnsLightScan,
}

impl EncryptedHnsLightIndex {
    /// Open or initialize the account index. An empty watch set is inert until
    /// the wallet installs its complete public restore set.
    pub fn open_or_create(
        store: SharedWalletStore,
        account_id: AccountId,
        network: HnsNetwork,
        birthday_height: u32,
        now_unix: u64,
    ) -> Result<Self, HnsLightIndexError> {
        let network = consensus_network(network);
        let id = scan_id(account_id);
        let stored: Option<StoredEntity<StoredHnsLightWalletRecord>> =
            store.with_store(|wallet| wallet.hns_light_wallet(&id))?;
        if let Some(stored) = stored {
            let StoredHnsLightWalletRecord::Scan(scan) = stored.value else {
                return Err(HnsLightIndexError::WrongRecordKind);
            };
            validate_scan(&scan, network, birthday_height)?;
            return Ok(Self {
                store,
                account_id,
                network,
                scan_revision: stored.revision,
                scan,
            });
        }
        let watch_set = HnsLightWatchSet::new(Vec::new(), Vec::new())?;
        let scan = StoredHnsLightScan {
            format_version: HNS_LIGHT_INDEX_FORMAT_VERSION,
            network: network.id(),
            birthday_height,
            watch_digest: watch_set.digest(network, birthday_height),
            watch_set,
            scanned_height: None,
            scanned_hash: None,
        };
        store.with_store_mut(|wallet| {
            wallet.save_hns_light_wallet(
                &id,
                0,
                &StoredHnsLightWalletRecord::Scan(scan.clone()),
                now_unix,
            )
        })?;
        Ok(Self {
            store,
            account_id,
            network,
            scan_revision: 1,
            scan,
        })
    }

    /// Install an exact watch set. Any change atomically clears derived
    /// observations and rewinds coverage to the configured birthday.
    pub fn install_watch_set(
        &mut self,
        watch_set: HnsLightWatchSet,
        now_unix: u64,
    ) -> Result<bool, HnsLightIndexError> {
        watch_set.validate()?;
        if watch_set == self.scan.watch_set {
            return Ok(false);
        }
        let existing = self.stored_transactions()?;
        let deletes = existing
            .iter()
            .map(|stored| EntityBatchDelete {
                id: stored.id.clone(),
                expected_revision: stored.revision,
            })
            .collect::<Vec<_>>();
        let next_scan = StoredHnsLightScan {
            format_version: HNS_LIGHT_INDEX_FORMAT_VERSION,
            network: self.network.id(),
            birthday_height: self.scan.birthday_height,
            watch_digest: watch_set.digest(self.network, self.scan.birthday_height),
            watch_set,
            scanned_height: None,
            scanned_hash: None,
        };
        let saves = [EntityBatchSave {
            id: scan_id(self.account_id),
            expected_revision: self.scan_revision,
            value: StoredHnsLightWalletRecord::Scan(next_scan.clone()),
            updated_at_unix: now_unix,
        }];
        self.store.with_store_mut(|wallet| {
            wallet.apply_entity_batch(EntityKind::HnsLightWallet, &saves, &deletes)
        })?;
        self.scan_revision = self
            .scan_revision
            .checked_add(1)
            .ok_or(HnsLightIndexError::RevisionOverflow)?;
        self.scan = next_scan;
        Ok(true)
    }

    /// Exact current coverage metadata.
    #[must_use]
    pub fn status(&self) -> HnsLightScanStatus {
        HnsLightScanStatus {
            birthday_height: self.scan.birthday_height,
            scanned_height: self.scan.scanned_height,
            scanned_hash: self.scan.scanned_hash,
            watch_digest: self.scan.watch_digest,
            watched_scripts: self.scan.watch_set.scripts.len(),
            watched_names: self.scan.watch_set.name_hashes.len(),
        }
    }

    /// Wallet account bound to this index.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Selected Handshake consensus network.
    #[must_use]
    pub const fn consensus_network(&self) -> Network {
        self.network
    }

    /// Exact canonical watch set used to construct peer bloom filters.
    #[must_use]
    pub const fn watch_set(&self) -> &HnsLightWatchSet {
        &self.scan.watch_set
    }

    /// Commit one next-height verified filtered block and every relevant
    /// transaction atomically with the scan head.
    pub fn apply_verified_block(
        &mut self,
        authority: &EncryptedHnsLightAuthority,
        block: &VerifiedWalletBlock,
        now_unix: u64,
    ) -> Result<usize, HnsLightIndexError> {
        if self.scan.watch_set.scripts.is_empty() && self.scan.watch_set.name_hashes.is_empty() {
            return Err(HnsLightIndexError::EmptyWatchSet);
        }
        let entry = block.evidence().header();
        let height = entry.height().get();
        if authority.account_id() != self.account_id
            || authority.consensus_network() != self.network
            || authority.birthday_height() != self.scan.birthday_height
            || height > authority.validated_chain().tip().height().get()
        {
            return Err(HnsLightIndexError::AuthorityMismatch);
        }
        let archived = authority
            .archived_header(height)?
            .ok_or(HnsLightIndexError::MissingAuthorityHeader)?;
        if archived.block_hash() != entry.hash() {
            return Err(HnsLightIndexError::AuthorityMismatch);
        }
        let expected_height = match self.scan.scanned_height {
            Some(previous) => previous
                .checked_add(1)
                .ok_or(HnsLightIndexError::HeightOverflow)?,
            None => self.scan.birthday_height,
        };
        if height != expected_height
            || self
                .scan
                .scanned_hash
                .is_some_and(|previous| entry.previous_block().into_bytes() != previous)
        {
            return Err(HnsLightIndexError::NonContiguousBlock);
        }

        let existing = self.decoded_transactions()?;
        if existing.len() > crate::MAX_HISTORY_RESULTS {
            return Err(HnsLightIndexError::HistoryCapacity);
        }
        let watched_scripts = self
            .scan
            .watch_set
            .scripts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let watched_names = self
            .scan
            .watch_set
            .name_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut watched_outpoints = watched_outputs(&existing, &watched_scripts)?;
        let existing_txids = existing
            .iter()
            .map(|observation| observation.txid.into_bytes())
            .collect::<BTreeSet<_>>();
        let match_positions = block
            .evidence()
            .matches()
            .iter()
            .map(|matched| (matched.hash().into_bytes(), matched.index()))
            .collect::<BTreeMap<_, _>>();
        let mut saves = Vec::new();
        let mut admitted = 0usize;
        for transaction in block.transactions() {
            let canonical_txid = transaction.transaction_hash()?;
            let txid_bytes = canonical_txid.into_bytes();
            let transaction_index = match_positions
                .get(&txid_bytes)
                .copied()
                .ok_or(HnsLightIndexError::EvidenceMismatch)?;
            if existing_txids.contains(&txid_bytes) {
                return Err(HnsLightIndexError::DuplicateConfirmedTransaction);
            }
            let relevant = transaction_relevant(
                transaction,
                &watched_scripts,
                &watched_names,
                &watched_outpoints,
            );
            add_watched_outputs(
                transaction,
                canonical_txid,
                &watched_scripts,
                &mut watched_outpoints,
            )?;
            if !relevant {
                continue;
            }
            let raw = transaction.encode()?;
            let stored = StoredHnsLightTransaction {
                format_version: HNS_LIGHT_INDEX_FORMAT_VERSION,
                network: self.network.id(),
                txid: txid_bytes,
                raw,
                height,
                block_hash: entry.hash().into_bytes(),
                transaction_index,
                block_time: entry.time().get(),
                coinbase: transaction.is_coinbase(),
            };
            saves.push(EntityBatchSave {
                id: transaction_id(self.account_id, txid_bytes),
                expected_revision: 0,
                value: StoredHnsLightWalletRecord::Transaction(stored),
                updated_at_unix: now_unix,
            });
            admitted = admitted
                .checked_add(1)
                .ok_or(HnsLightIndexError::HistoryCapacity)?;
        }
        if existing.len().saturating_add(admitted) > crate::MAX_HISTORY_RESULTS {
            return Err(HnsLightIndexError::HistoryCapacity);
        }
        let next_scan = StoredHnsLightScan {
            scanned_height: Some(height),
            scanned_hash: Some(entry.hash().into_bytes()),
            ..self.scan.clone()
        };
        saves.insert(
            0,
            EntityBatchSave {
                id: scan_id(self.account_id),
                expected_revision: self.scan_revision,
                value: StoredHnsLightWalletRecord::Scan(next_scan.clone()),
                updated_at_unix: now_unix,
            },
        );
        self.store.with_store_mut(|wallet| {
            wallet.apply_entity_batch(EntityKind::HnsLightWallet, &saves, &[])
        })?;
        self.scan_revision = self
            .scan_revision
            .checked_add(1)
            .ok_or(HnsLightIndexError::RevisionOverflow)?;
        self.scan = next_scan;
        Ok(admitted)
    }

    /// Load and authenticate every bounded confirmed observation.
    pub fn transactions(
        &self,
    ) -> Result<Vec<VerifiedHnsTransactionObservation>, HnsLightIndexError> {
        self.decoded_transactions()
    }

    fn stored_transactions(
        &self,
    ) -> Result<Vec<StoredEntity<StoredHnsLightWalletRecord>>, HnsLightIndexError> {
        Ok(self.store.with_store(|wallet| {
            wallet.list_entities_by_id_prefix(
                EntityKind::HnsLightWallet,
                &transaction_prefix(self.account_id),
                crate::MAX_HISTORY_RESULTS,
            )
        })?)
    }

    fn decoded_transactions(
        &self,
    ) -> Result<Vec<VerifiedHnsTransactionObservation>, HnsLightIndexError> {
        let stored = self.stored_transactions()?;
        let mut observations = Vec::with_capacity(stored.len());
        for stored in stored {
            let StoredHnsLightWalletRecord::Transaction(transaction) = stored.value else {
                return Err(HnsLightIndexError::WrongRecordKind);
            };
            if stored.id != transaction_id(self.account_id, transaction.txid) {
                return Err(HnsLightIndexError::CorruptTransactionRecord);
            }
            observations.push(transaction.decode(self.network)?);
        }
        observations.sort_by_key(|observation| (observation.height, observation.transaction_index));
        Ok(observations)
    }
}

fn validate_scan(
    scan: &StoredHnsLightScan,
    network: Network,
    birthday_height: u32,
) -> Result<(), HnsLightIndexError> {
    if scan.format_version != HNS_LIGHT_INDEX_FORMAT_VERSION {
        return Err(HnsLightIndexError::UnsupportedFormat);
    }
    if scan.network != network.id() {
        return Err(HnsLightIndexError::NetworkMismatch);
    }
    if scan.birthday_height != birthday_height {
        return Err(HnsLightIndexError::BirthdayMismatch);
    }
    scan.watch_set.validate()?;
    if scan.watch_digest != scan.watch_set.digest(network, birthday_height)
        || scan.scanned_height.is_some() != scan.scanned_hash.is_some()
        || scan
            .scanned_height
            .is_some_and(|height| height < birthday_height)
    {
        return Err(HnsLightIndexError::CorruptScanState);
    }
    Ok(())
}

fn watched_outputs(
    observations: &[VerifiedHnsTransactionObservation],
    scripts: &BTreeSet<WalletAddressKey>,
) -> Result<HashSet<Outpoint>, HnsLightIndexError> {
    let mut outpoints = HashSet::new();
    for observation in observations {
        let txid = CanonicalTransactionHash::new(observation.txid.into_bytes());
        add_watched_outputs(&observation.transaction, txid, scripts, &mut outpoints)?;
    }
    Ok(outpoints)
}

pub(crate) fn add_watched_outputs(
    transaction: &Transaction,
    txid: CanonicalTransactionHash,
    scripts: &BTreeSet<WalletAddressKey>,
    outpoints: &mut HashSet<Outpoint>,
) -> Result<(), HnsLightIndexError> {
    for (index, output) in transaction.outputs.iter().enumerate() {
        let key = WalletAddressKey {
            version: output.address.version,
            hash: output.address.hash.clone(),
        };
        if scripts.contains(&key) {
            outpoints.insert(Outpoint {
                transaction_hash: txid,
                index: u32::try_from(index).map_err(|_| HnsLightIndexError::TransactionCapacity)?,
            });
        }
    }
    Ok(())
}

pub(crate) fn transaction_relevant(
    transaction: &Transaction,
    scripts: &BTreeSet<WalletAddressKey>,
    names: &BTreeSet<[u8; 32]>,
    watched_outpoints: &HashSet<Outpoint>,
) -> bool {
    transaction
        .inputs
        .iter()
        .any(|input| watched_outpoints.contains(&input.previous_output))
        || transaction.outputs.iter().any(|output| {
            scripts.contains(&WalletAddressKey {
                version: output.address.version,
                hash: output.address.hash.clone(),
            }) || output.covenant.items.iter().any(|item| {
                item.as_slice()
                    .try_into()
                    .is_ok_and(|value: [u8; 32]| names.contains(&value))
            }) || (output.covenant.kind == CovenantKind::Transfer
                && TransferCovenant::try_from(&output.covenant).is_ok_and(|transfer| {
                    scripts.contains(&WalletAddressKey {
                        version: transfer.recipient_version,
                        hash: transfer.recipient_hash,
                    })
                }))
        })
}

fn scan_id(account_id: AccountId) -> Vec<u8> {
    let mut id = Vec::with_capacity(AccountId::LENGTH + SCAN_SUFFIX.len());
    id.extend_from_slice(account_id.as_bytes());
    id.extend_from_slice(SCAN_SUFFIX);
    id
}

fn transaction_prefix(account_id: AccountId) -> Vec<u8> {
    let mut id = Vec::with_capacity(AccountId::LENGTH + TRANSACTION_SUFFIX.len());
    id.extend_from_slice(account_id.as_bytes());
    id.extend_from_slice(TRANSACTION_SUFFIX);
    id
}

fn transaction_id(account_id: AccountId, txid: [u8; 32]) -> Vec<u8> {
    let mut id = transaction_prefix(account_id);
    id.extend_from_slice(&txid);
    id
}

const fn consensus_network(network: HnsNetwork) -> Network {
    match network {
        HnsNetwork::Mainnet => Network::Mainnet,
        HnsNetwork::Testnet => Network::Testnet,
        HnsNetwork::Regtest => Network::Regtest,
        HnsNetwork::Simnet => Network::Simnet,
    }
}

/// Filtered-block index persistence or evidence failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HnsLightIndexError {
    #[error("encrypted wallet store failure: {0}")]
    Store(#[from] StoreError),
    #[error("canonical HNS transaction failure: {0}")]
    Transaction(#[from] TransactionError),
    #[error("unsupported HNS light-index format")]
    UnsupportedFormat,
    #[error("HNS light-index record belongs to another network")]
    NetworkMismatch,
    #[error("HNS light-index birthday differs from the persisted account")]
    BirthdayMismatch,
    #[error("invalid HNS light-index watch set")]
    InvalidWatchSet,
    #[error("HNS light-index entity has the wrong record variant")]
    WrongRecordKind,
    #[error("HNS light-index scan state is corrupt")]
    CorruptScanState,
    #[error("HNS light-index transaction record is corrupt")]
    CorruptTransactionRecord,
    #[error("HNS light-index transaction encoding is noncanonical")]
    NonCanonicalTransaction,
    #[error("HNS light-index watch set is empty")]
    EmptyWatchSet,
    #[error("filtered block is not the next contiguous scan height")]
    NonContiguousBlock,
    #[error("filtered block is not bound to this wallet's validated header authority")]
    AuthorityMismatch,
    #[error("validated header authority does not retain the filtered block height")]
    MissingAuthorityHeader,
    #[error("validated HNS header authority failed: {0}")]
    Authority(#[from] HnsLightError),
    #[error("filtered-block transaction correlation is inconsistent")]
    EvidenceMismatch,
    #[error("confirmed transaction was observed twice")]
    DuplicateConfirmedTransaction,
    #[error("HNS light-index history bound exceeded")]
    HistoryCapacity,
    #[error("HNS transaction output count is excessive")]
    TransactionCapacity,
    #[error("HNS light-index height overflow")]
    HeightOverflow,
    #[error("HNS light-index persistence revision overflow")]
    RevisionOverflow,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic fixtures"
)]
mod tests {
    use blake2::Blake2b;
    use blake2::digest::{Digest as BlakeDigest, consts::U32};
    use hns_covenants::Covenant;
    use hns_header_consensus::Header;
    use hns_light_chain::{ChainLimits, LightChain};
    use hns_light_wallet::WalletBlockEvidence;
    use hns_primitives::{BlockTime, Dollarydoos, MerkleRoot, TreeRoot};
    use hns_transaction::{Address, Output};
    use hns_wallet_store::WalletStore;

    use super::*;

    fn store() -> SharedWalletStore {
        SharedWalletStore::new(
            WalletStore::create(":memory:", "correct horse battery staple").unwrap(),
        )
    }

    fn verified_block(program: &[u8]) -> (VerifiedWalletBlock, Header) {
        let transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: vec![Output {
                value: Dollarydoos::new(42),
                address: Address::new(0, program.to_vec()).unwrap(),
                covenant: Covenant::default(),
            }],
            locktime: 0,
        };
        let txid = transaction.transaction_hash().unwrap();
        let mut leaf = Blake2b::<U32>::new();
        BlakeDigest::update(&mut leaf, [0]);
        BlakeDigest::update(&mut leaf, txid.as_bytes());
        let merkle_root = MerkleRoot::new(leaf.finalize().into());
        let now = BlockTime::new(Network::Regtest.parameters().genesis_time.get() + 100);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        let mut header = Header {
            time: BlockTime::new(chain.tip().time().get() + 1),
            previous_block: chain.tip().hash(),
            tree_root: TreeRoot::new([1; 32]),
            merkle_root,
            bits: Network::Regtest.parameters().pow.bits,
            ..Header::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        let entry = chain.append(&header, now).unwrap();
        let mut payload = header.encode().to_vec();
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.push(1);
        payload.extend_from_slice(txid.as_bytes());
        payload.extend_from_slice(&[1, 1]);
        let mut collector = WalletBlockEvidence::decode_for_header(&payload, entry)
            .unwrap()
            .collect()
            .unwrap();
        collector.admit(transaction).unwrap();
        (collector.finish().unwrap(), header)
    }

    fn authority_for_header(
        store: SharedWalletStore,
        account: AccountId,
        header: Header,
    ) -> EncryptedHnsLightAuthority {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut authority = EncryptedHnsLightAuthority::open_or_create(
            store,
            account,
            HnsNetwork::Regtest,
            1,
            crate::HnsLightFloor::default(),
            BlockTime::new(now),
            ChainLimits::default(),
            hns_light_sync::SyncConfig {
                max_peers: 2,
                minimum_peer_agreement: 1,
                round_timeout_seconds: 10,
                max_peer_failures: 3,
            },
        )
        .unwrap();
        let peer = hns_light_sync::PeerId::new([1; 32]);
        authority.add_peer(peer, 1).unwrap();
        let request = authority.begin_header_round(&[peer], now).unwrap();
        authority
            .submit_header_response(request.generation, peer, vec![header], now)
            .unwrap();
        authority.finish_header_round_and_persist(now).unwrap();
        authority
    }

    #[test]
    fn verified_filtered_block_advances_scan_and_persists_relevant_transaction() {
        let store = store();
        let account = AccountId::new([3; 16]);
        let program = vec![7; 20];
        let mut index = EncryptedHnsLightIndex::open_or_create(
            store.clone(),
            account,
            HnsNetwork::Regtest,
            1,
            1,
        )
        .unwrap();
        index
            .install_watch_set(
                HnsLightWatchSet::new(
                    vec![WalletAddressKey {
                        version: 0,
                        hash: program.clone(),
                    }],
                    Vec::new(),
                )
                .unwrap(),
                2,
            )
            .unwrap();
        let (block, header) = verified_block(&program);
        let authority = authority_for_header(store.clone(), account, header);
        assert_eq!(
            index.apply_verified_block(&authority, &block, 3).unwrap(),
            1
        );
        assert_eq!(index.status().scanned_height, Some(1));
        let transactions = index.transactions().unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].transaction.outputs[0].value.get(), 42);

        let reopened =
            EncryptedHnsLightIndex::open_or_create(store, account, HnsNetwork::Regtest, 1, 4)
                .unwrap();
        assert_eq!(reopened.status(), index.status());
        assert_eq!(
            reopened.transactions().unwrap(),
            index.transactions().unwrap()
        );
    }

    #[test]
    fn watch_set_change_atomically_rewinds_and_clears_derived_history() {
        let store = store();
        let account = AccountId::new([4; 16]);
        let program = vec![8; 20];
        let mut index =
            EncryptedHnsLightIndex::open_or_create(store, account, HnsNetwork::Regtest, 1, 1)
                .unwrap();
        index
            .install_watch_set(
                HnsLightWatchSet::new(
                    vec![WalletAddressKey {
                        version: 0,
                        hash: program.clone(),
                    }],
                    Vec::new(),
                )
                .unwrap(),
                2,
            )
            .unwrap();
        let (block, header) = verified_block(&program);
        let authority = authority_for_header(index.store.clone(), account, header);
        index.apply_verified_block(&authority, &block, 3).unwrap();
        assert!(!index.transactions().unwrap().is_empty());

        index
            .install_watch_set(
                HnsLightWatchSet::new(
                    vec![WalletAddressKey {
                        version: 0,
                        hash: vec![9; 20],
                    }],
                    Vec::new(),
                )
                .unwrap(),
                4,
            )
            .unwrap();
        assert_eq!(index.status().scanned_height, None);
        assert!(index.transactions().unwrap().is_empty());
    }

    #[test]
    fn false_positive_transaction_advances_coverage_without_entering_history() {
        let store = store();
        let account = AccountId::new([5; 16]);
        let mut index =
            EncryptedHnsLightIndex::open_or_create(store, account, HnsNetwork::Regtest, 1, 1)
                .unwrap();
        index
            .install_watch_set(
                HnsLightWatchSet::new(
                    vec![WalletAddressKey {
                        version: 0,
                        hash: vec![10; 20],
                    }],
                    Vec::new(),
                )
                .unwrap(),
                2,
            )
            .unwrap();
        let (block, header) = verified_block(&[11; 20]);
        let authority = authority_for_header(index.store.clone(), account, header);
        assert_eq!(
            index.apply_verified_block(&authority, &block, 3).unwrap(),
            0
        );
        assert_eq!(index.status().scanned_height, Some(1));
        assert!(index.transactions().unwrap().is_empty());
    }
}
