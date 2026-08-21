//! Wallet-owned Handshake header authority persisted in the encrypted store.

use hns_header_consensus::{HEADER_SIZE, Header, HeaderError, Network};
use hns_light_chain::{
    ChainLimits, ChainSnapshotFloor, CurrencyPolicy, CurrentChain, HeaderEntry, LightChain,
    LightChainError,
};
use hns_light_sync::{HeaderRoundRequest, HeaderSync, PeerId, SyncConfig, SyncError, SyncStatus};
use hns_primitives::{BlockTime, Chainwork, Height};
use hns_wallet_store::{EntityBatchSave, EntityKind, SharedWalletStore, StoreError, StoredEntity};
use hns_wallet_types::AccountId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::HnsNetwork;

/// Version of the authenticated encrypted HNS light-chain record envelope.
pub const HNS_LIGHT_CHAIN_FORMAT_VERSION: u16 = 1;

/// Largest genesis-verified header acceleration stream accepted in one wallet
/// bootstrap. Product shells pin their own reviewed checkpoint and may advance
/// this bound in a later release alongside a new bundled checkpoint.
pub const MAX_GENESIS_BOOTSTRAP_HEADERS: u32 = 500_000;

const CHECKPOINT_SUFFIX: &[u8] = b"/hns-light/checkpoint";
const HEADER_SUFFIX: &[u8] = b"/hns-light/header/";

/// Rollback floor that callers retain in platform-protected monotonic storage.
///
/// The encrypted SQLite record authenticates its contents but an old complete
/// database backup can still be authentic. Android Keystore, the extension
/// host, or another product shell retains this small value and supplies it on
/// reopen so an older chain checkpoint is rejected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsLightFloor {
    pub height: u32,
    pub chainwork: [u8; 32],
}

impl HnsLightFloor {
    fn from_entry(entry: HeaderEntry) -> Self {
        Self {
            height: entry.height().get(),
            chainwork: entry.chainwork().to_be_bytes(),
        }
    }

    fn consensus(self) -> ChainSnapshotFloor {
        ChainSnapshotFloor {
            minimum_height: Height::new(self.height),
            minimum_chainwork: Chainwork::from_be_bytes(self.chainwork),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum StoredHnsLightRecord {
    Checkpoint(StoredHnsLightCheckpoint),
    Header(StoredHnsHeader),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHnsLightCheckpoint {
    format_version: u16,
    network: u8,
    birthday_height: u32,
    tip_height: u32,
    tip_hash: [u8; 32],
    floor: HnsLightFloor,
    archived_tip_height: Option<u32>,
    archived_tip_hash: Option<[u8; 32]>,
    consensus_snapshot: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHnsHeader {
    format_version: u16,
    network: u8,
    height: u32,
    block_hash: [u8; 32],
    bytes: Vec<u8>,
}

impl StoredHnsHeader {
    fn new(network: Network, height: u32, header: &Header) -> Self {
        Self {
            format_version: HNS_LIGHT_CHAIN_FORMAT_VERSION,
            network: network.id(),
            height,
            block_hash: header.block_hash().into_bytes(),
            bytes: header.encode().to_vec(),
        }
    }

    fn decode(&self, network: Network, expected_height: u32) -> Result<Header, HnsLightError> {
        if self.format_version != HNS_LIGHT_CHAIN_FORMAT_VERSION {
            return Err(HnsLightError::UnsupportedFormat);
        }
        if self.network != network.id() {
            return Err(HnsLightError::NetworkMismatch);
        }
        if self.height != expected_height || self.bytes.len() != HEADER_SIZE {
            return Err(HnsLightError::CorruptHeaderArchive);
        }
        let header = Header::decode(&self.bytes)?;
        if header.block_hash().into_bytes() != self.block_hash {
            return Err(HnsLightError::CorruptHeaderArchive);
        }
        Ok(header)
    }
}

/// One newly agreed header and the consensus entry needed to verify its
/// filtered-block evidence without trusting the peer that supplied it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedHnsHeader {
    pub header: Header,
    pub entry: HeaderEntry,
}

/// Result of a peer-agreement round committed to the encrypted wallet store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedHeaderRound {
    pub status: SyncStatus,
    pub accepted: Vec<AcceptedHnsHeader>,
}

/// Encrypted, wallet-owned Handshake light-chain authority.
///
/// Peers are transport only. Headers enter this runtime through local proof of
/// work and difficulty validation plus bounded multi-peer agreement. Every
/// accepted extension and its resume checkpoint are committed atomically in
/// one encrypted entity namespace before the in-memory authority advances.
pub struct EncryptedHnsLightAuthority {
    store: SharedWalletStore,
    account_id: AccountId,
    network: Network,
    birthday_height: u32,
    checkpoint_revision: u64,
    archived_tip: Option<(u32, [u8; 32])>,
    sync_config: SyncConfig,
    sync: HeaderSync,
}

impl EncryptedHnsLightAuthority {
    /// Open the account's authenticated chain or create its genesis checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn open_or_create(
        store: SharedWalletStore,
        account_id: AccountId,
        network: HnsNetwork,
        birthday_height: u32,
        caller_floor: HnsLightFloor,
        now: BlockTime,
        chain_limits: ChainLimits,
        sync_config: SyncConfig,
    ) -> Result<Self, HnsLightError> {
        let network = consensus_network(network);
        let checkpoint_id = checkpoint_id(account_id);
        let stored: Option<StoredEntity<StoredHnsLightRecord>> =
            store.with_store(|wallet| wallet.hns_light_chain(&checkpoint_id))?;
        match stored {
            Some(stored) => Self::open_existing(
                store,
                account_id,
                network,
                birthday_height,
                caller_floor,
                sync_config,
                stored,
            ),
            None => {
                if caller_floor != HnsLightFloor::default() {
                    return Err(HnsLightError::MissingCheckpointBelowFloor);
                }
                Self::create(
                    store,
                    account_id,
                    network,
                    birthday_height,
                    now,
                    chain_limits,
                    sync_config,
                )
            }
        }
    }

    fn create(
        store: SharedWalletStore,
        account_id: AccountId,
        network: Network,
        birthday_height: u32,
        now: BlockTime,
        chain_limits: ChainLimits,
        sync_config: SyncConfig,
    ) -> Result<Self, HnsLightError> {
        let sync = HeaderSync::from_genesis(network, now, chain_limits, sync_config)?;
        let archived_tip = (birthday_height == 0).then(|| {
            let tip = sync.chain().tip();
            (0, tip.hash().into_bytes())
        });
        let checkpoint = checkpoint_record(sync.chain(), network, birthday_height, archived_tip)?;
        let mut saves = vec![EntityBatchSave {
            id: checkpoint_id(account_id),
            expected_revision: 0,
            value: StoredHnsLightRecord::Checkpoint(checkpoint),
            updated_at_unix: now.get(),
        }];
        if birthday_height == 0 {
            let genesis = network.parameters().genesis_header();
            saves.push(EntityBatchSave {
                id: header_id(account_id, 0),
                expected_revision: 0,
                value: StoredHnsLightRecord::Header(StoredHnsHeader::new(network, 0, &genesis)),
                updated_at_unix: now.get(),
            });
        }
        store.with_store_mut(|wallet| {
            wallet.apply_entity_batch(EntityKind::HnsLightChain, &saves, &[])
        })?;
        Ok(Self {
            store,
            account_id,
            network,
            birthday_height,
            checkpoint_revision: 1,
            archived_tip,
            sync_config,
            sync,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn open_existing(
        store: SharedWalletStore,
        account_id: AccountId,
        network: Network,
        birthday_height: u32,
        caller_floor: HnsLightFloor,
        sync_config: SyncConfig,
        stored: StoredEntity<StoredHnsLightRecord>,
    ) -> Result<Self, HnsLightError> {
        let StoredHnsLightRecord::Checkpoint(checkpoint) = stored.value else {
            return Err(HnsLightError::WrongRecordKind);
        };
        if checkpoint.format_version != HNS_LIGHT_CHAIN_FORMAT_VERSION {
            return Err(HnsLightError::UnsupportedFormat);
        }
        if checkpoint.network != network.id() {
            return Err(HnsLightError::NetworkMismatch);
        }
        if checkpoint.birthday_height != birthday_height {
            return Err(HnsLightError::BirthdayMismatch);
        }
        let chain = LightChain::decode_authenticated_snapshot(
            &checkpoint.consensus_snapshot,
            network,
            caller_floor.consensus(),
        )?;
        let tip = chain.tip();
        if checkpoint.tip_height != tip.height().get()
            || checkpoint.tip_hash != tip.hash().into_bytes()
            || checkpoint.floor != HnsLightFloor::from_entry(tip)
        {
            return Err(HnsLightError::CorruptCheckpoint);
        }
        let archived_tip = validate_archive_tip(
            &store,
            account_id,
            network,
            birthday_height,
            tip,
            checkpoint.archived_tip_height,
            checkpoint.archived_tip_hash,
        )?;
        Ok(Self {
            store,
            account_id,
            network,
            birthday_height,
            checkpoint_revision: stored.revision,
            archived_tip,
            sync_config,
            sync: HeaderSync::from_chain(chain, sync_config)?,
        })
    }

    /// Wallet account bound to this authority.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Selected Handshake consensus network.
    #[must_use]
    pub const fn consensus_network(&self) -> Network {
        self.network
    }

    /// Earliest height retained for wallet rescans.
    #[must_use]
    pub const fn birthday_height(&self) -> u32 {
        self.birthday_height
    }

    /// Current synchronization summary.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        self.sync.status()
    }

    /// Latest platform rollback floor. The product shell persists this after
    /// every successful nonempty header round.
    #[must_use]
    pub fn rollback_floor(&self) -> HnsLightFloor {
        HnsLightFloor::from_entry(self.sync.chain().tip())
    }

    /// Monotonic authenticated chain revision used to bind wallet-index reads.
    #[must_use]
    pub const fn chain_epoch(&self) -> u64 {
        self.checkpoint_revision
    }

    /// Read-only access to the locally validated chain window.
    #[must_use]
    pub const fn validated_chain(&self) -> &LightChain {
        self.sync.chain()
    }

    /// Add one newly handshaken peer. The peer identity is connection-scoped
    /// and is not chain authority.
    pub fn add_peer(&mut self, id: PeerId, advertised_height: u32) -> Result<(), HnsLightError> {
        self.sync.add_peer(id, advertised_height)?;
        Ok(())
    }

    /// Remove one disconnected peer.
    pub fn remove_peer(&mut self, id: PeerId) -> bool {
        self.sync.remove_peer(id)
    }

    /// Update the height claimed by a connected peer.
    pub fn update_peer_height(
        &mut self,
        id: PeerId,
        advertised_height: u32,
    ) -> Result<(), HnsLightError> {
        self.sync.update_peer_height(id, advertised_height)?;
        Ok(())
    }

    /// Begin a bounded same-locator header agreement round.
    pub fn begin_header_round(
        &mut self,
        selected_peers: &[PeerId],
        now: u64,
    ) -> Result<HeaderRoundRequest, HnsLightError> {
        Ok(self.sync.begin_round(selected_peers, now)?)
    }

    /// Submit one peer's untrusted header response.
    pub fn submit_header_response(
        &mut self,
        generation: u64,
        peer: PeerId,
        headers: Vec<Header>,
        now: u64,
    ) -> Result<(), HnsLightError> {
        self.sync.submit_headers(generation, peer, headers, now)?;
        Ok(())
    }

    /// Finish peer agreement and atomically persist every accepted header plus
    /// the new consensus checkpoint before advancing this in-memory authority.
    pub fn finish_header_round_and_persist(
        &mut self,
        now: u64,
    ) -> Result<PersistedHeaderRound, HnsLightError> {
        let mut candidate = self.sync.clone();
        let outcome = candidate.finish_round_with_headers(now)?;
        let mut entry_chain = self.sync.chain().clone();
        let mut accepted = Vec::with_capacity(outcome.accepted_headers.len());
        for header in &outcome.accepted_headers {
            let entry = entry_chain.append(header, BlockTime::new(now))?;
            accepted.push(AcceptedHnsHeader {
                header: header.clone(),
                entry,
            });
        }
        if entry_chain.tip() != candidate.chain().tip() {
            return Err(HnsLightError::ConsensusStateMismatch);
        }

        if !accepted.is_empty() {
            let archived = accepted
                .iter()
                .filter(|accepted| accepted.entry.height().get() >= self.birthday_height)
                .collect::<Vec<_>>();
            let next_archived_tip =
                archive_extension_tip(self.archived_tip, self.birthday_height, &archived)?;
            let checkpoint = checkpoint_record(
                candidate.chain(),
                self.network,
                self.birthday_height,
                next_archived_tip,
            )?;
            let mut saves = Vec::with_capacity(archived.len() + 1);
            saves.push(EntityBatchSave {
                id: checkpoint_id(self.account_id),
                expected_revision: self.checkpoint_revision,
                value: StoredHnsLightRecord::Checkpoint(checkpoint),
                updated_at_unix: now,
            });
            for accepted in archived {
                let height = accepted.entry.height().get();
                saves.push(EntityBatchSave {
                    id: header_id(self.account_id, height),
                    expected_revision: 0,
                    value: StoredHnsLightRecord::Header(StoredHnsHeader::new(
                        self.network,
                        height,
                        &accepted.header,
                    )),
                    updated_at_unix: now,
                });
            }
            self.store.with_store_mut(|wallet| {
                wallet.apply_entity_batch(EntityKind::HnsLightChain, &saves, &[])
            })?;
            self.checkpoint_revision = self
                .checkpoint_revision
                .checked_add(1)
                .ok_or(HnsLightError::RevisionOverflow)?;
            self.archived_tip = next_archived_tip;
        }

        self.sync = candidate;
        Ok(PersistedHeaderRound {
            status: outcome.status,
            accepted,
        })
    }

    /// Replace a pristine genesis checkpoint with a locally verified header
    /// acceleration stream.
    ///
    /// This is intentionally only a new-wallet path. Every supplied header is
    /// appended from canonical genesis using the normal proof-of-work,
    /// difficulty, and median-time checks; `expected_height` and
    /// `expected_hash` are supplied by the product's reviewed, pinned
    /// checkpoint rather than being taken from the stream. The resulting
    /// synchronizer starts in `HeaderSyncing`, so ordinary direct peers must
    /// still provide fresh agreement before the wallet treats the chain as
    /// current or authorizes value operations.
    ///
    /// A recovery wallet must retain its genuine birthday and scan from there.
    /// It must not use this narrow shortcut to discard historical discovery.
    pub fn bootstrap_from_genesis_headers<I>(
        &mut self,
        headers: I,
        expected_height: u32,
        expected_hash: [u8; 32],
        now: u64,
    ) -> Result<SyncStatus, HnsLightError>
    where
        I: IntoIterator<Item = Header>,
    {
        if expected_height == 0 || expected_height > MAX_GENESIS_BOOTSTRAP_HEADERS {
            return Err(HnsLightError::InvalidBootstrapTarget);
        }
        if self.birthday_height != expected_height {
            return Err(HnsLightError::BootstrapBirthdayMismatch);
        }
        if self.checkpoint_revision != 1
            || self.archived_tip.is_some()
            || self.sync.chain().tip().height() != Height::new(0)
        {
            return Err(HnsLightError::BootstrapUnavailable);
        }

        let mut chain = self.sync.chain().clone();
        let mut count = 0_u32;
        let mut final_header = None;
        for header in headers {
            count = count
                .checked_add(1)
                .ok_or(HnsLightError::BootstrapHeaderCountMismatch)?;
            if count > expected_height {
                return Err(HnsLightError::BootstrapHeaderCountMismatch);
            }
            let entry = chain.append(&header, BlockTime::new(now))?;
            final_header = Some((header, entry));
        }
        let Some((final_header, final_entry)) = final_header else {
            return Err(HnsLightError::BootstrapHeaderCountMismatch);
        };
        if count != expected_height
            || final_entry.height().get() != expected_height
            || final_entry.hash().into_bytes() != expected_hash
        {
            return Err(HnsLightError::BootstrapTargetMismatch);
        }

        let next_archived_tip = Some((expected_height, expected_hash));
        let checkpoint = checkpoint_record(
            &chain,
            self.network,
            self.birthday_height,
            next_archived_tip,
        )?;
        let saves = [
            EntityBatchSave {
                id: checkpoint_id(self.account_id),
                expected_revision: self.checkpoint_revision,
                value: StoredHnsLightRecord::Checkpoint(checkpoint),
                updated_at_unix: now,
            },
            EntityBatchSave {
                id: header_id(self.account_id, expected_height),
                expected_revision: 0,
                value: StoredHnsLightRecord::Header(StoredHnsHeader::new(
                    self.network,
                    expected_height,
                    &final_header,
                )),
                updated_at_unix: now,
            },
        ];
        self.store.with_store_mut(|wallet| {
            wallet.apply_entity_batch(EntityKind::HnsLightChain, &saves, &[])
        })?;

        self.checkpoint_revision = self
            .checkpoint_revision
            .checked_add(1)
            .ok_or(HnsLightError::RevisionOverflow)?;
        self.archived_tip = next_archived_tip;
        self.sync = HeaderSync::from_chain(chain, self.sync_config)?;
        Ok(self.sync.status())
    }

    /// Issue current-chain proof authority only after fresh no-extension peer
    /// agreement and explicit currency policy.
    pub fn require_current(&self, policy: CurrencyPolicy) -> Result<CurrentChain, HnsLightError> {
        Ok(self.sync.require_current(policy)?)
    }

    /// Load and authenticate one retained canonical header for a wallet rescan.
    pub fn archived_header(&self, height: u32) -> Result<Option<Header>, HnsLightError> {
        if height < self.birthday_height
            || self
                .archived_tip
                .is_none_or(|(tip_height, _)| height > tip_height)
        {
            return Ok(None);
        }
        load_header(&self.store, self.account_id, self.network, height).map(Some)
    }
}

fn checkpoint_record(
    chain: &LightChain,
    network: Network,
    birthday_height: u32,
    archived_tip: Option<(u32, [u8; 32])>,
) -> Result<StoredHnsLightCheckpoint, HnsLightError> {
    let tip = chain.tip();
    Ok(StoredHnsLightCheckpoint {
        format_version: HNS_LIGHT_CHAIN_FORMAT_VERSION,
        network: network.id(),
        birthday_height,
        tip_height: tip.height().get(),
        tip_hash: tip.hash().into_bytes(),
        floor: HnsLightFloor::from_entry(tip),
        archived_tip_height: archived_tip.map(|(height, _)| height),
        archived_tip_hash: archived_tip.map(|(_, hash)| hash),
        consensus_snapshot: chain.encode_authenticated_snapshot()?,
    })
}

fn validate_archive_tip(
    store: &SharedWalletStore,
    account_id: AccountId,
    network: Network,
    birthday_height: u32,
    tip: HeaderEntry,
    archived_tip_height: Option<u32>,
    archived_tip_hash: Option<[u8; 32]>,
) -> Result<Option<(u32, [u8; 32])>, HnsLightError> {
    if archived_tip_height.is_some() != archived_tip_hash.is_some() {
        return Err(HnsLightError::CorruptCheckpoint);
    }
    if tip.height().get() < birthday_height {
        if archived_tip_height.is_some() {
            return Err(HnsLightError::CorruptCheckpoint);
        }
        return Ok(None);
    }
    let height = archived_tip_height.ok_or(HnsLightError::CorruptCheckpoint)?;
    let hash = archived_tip_hash.ok_or(HnsLightError::CorruptCheckpoint)?;
    if height != tip.height().get() || hash != tip.hash().into_bytes() {
        return Err(HnsLightError::CorruptCheckpoint);
    }
    let header = load_header(store, account_id, network, height)?;
    if header.block_hash().into_bytes() != hash {
        return Err(HnsLightError::CorruptHeaderArchive);
    }
    Ok(Some((height, hash)))
}

fn archive_extension_tip(
    current: Option<(u32, [u8; 32])>,
    birthday_height: u32,
    archived: &[&AcceptedHnsHeader],
) -> Result<Option<(u32, [u8; 32])>, HnsLightError> {
    if archived.is_empty() {
        return Ok(current);
    }
    let expected_first = current.map_or(birthday_height, |(height, _)| height.saturating_add(1));
    if archived
        .first()
        .is_none_or(|accepted| accepted.entry.height().get() != expected_first)
        || archived.windows(2).any(|pair| {
            pair[1].entry.height().get() != pair[0].entry.height().get().saturating_add(1)
                || pair[1].entry.previous_block() != pair[0].entry.hash()
        })
    {
        return Err(HnsLightError::HeaderArchiveGap);
    }
    let last = archived.last().ok_or(HnsLightError::HeaderArchiveGap)?;
    Ok(Some((
        last.entry.height().get(),
        last.entry.hash().into_bytes(),
    )))
}

fn load_header(
    store: &SharedWalletStore,
    account_id: AccountId,
    network: Network,
    height: u32,
) -> Result<Header, HnsLightError> {
    let id = header_id(account_id, height);
    let stored: Option<StoredEntity<StoredHnsLightRecord>> =
        store.with_store(|wallet| wallet.hns_light_chain(&id))?;
    let stored = stored.ok_or(HnsLightError::MissingArchivedHeader)?;
    let StoredHnsLightRecord::Header(header) = stored.value else {
        return Err(HnsLightError::WrongRecordKind);
    };
    header.decode(network, height)
}

fn checkpoint_id(account_id: AccountId) -> Vec<u8> {
    let mut id = Vec::with_capacity(AccountId::LENGTH + CHECKPOINT_SUFFIX.len());
    id.extend_from_slice(account_id.as_bytes());
    id.extend_from_slice(CHECKPOINT_SUFFIX);
    id
}

fn header_id(account_id: AccountId, height: u32) -> Vec<u8> {
    let mut id = Vec::with_capacity(AccountId::LENGTH + HEADER_SUFFIX.len() + 4);
    id.extend_from_slice(account_id.as_bytes());
    id.extend_from_slice(HEADER_SUFFIX);
    id.extend_from_slice(&height.to_be_bytes());
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

/// Authenticated HNS light-authority persistence or consensus failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HnsLightError {
    #[error("encrypted wallet store failure: {0}")]
    Store(#[from] StoreError),
    #[error("HNS light-chain failure: {0}")]
    Chain(#[from] LightChainError),
    #[error("HNS header-sync failure: {0}")]
    Sync(#[from] SyncError),
    #[error("HNS header decoding failure: {0}")]
    Header(#[from] HeaderError),
    #[error("unsupported HNS light-chain record format")]
    UnsupportedFormat,
    #[error("HNS light-chain record belongs to another network")]
    NetworkMismatch,
    #[error("HNS light-chain birthday differs from the persisted account")]
    BirthdayMismatch,
    #[error("HNS light-chain checkpoint is absent below the caller rollback floor")]
    MissingCheckpointBelowFloor,
    #[error("HNS light-chain entity has the wrong record variant")]
    WrongRecordKind,
    #[error("HNS light-chain checkpoint metadata is inconsistent")]
    CorruptCheckpoint,
    #[error("HNS retained header archive is corrupt")]
    CorruptHeaderArchive,
    #[error("HNS retained header is missing")]
    MissingArchivedHeader,
    #[error("HNS retained header archive has a gap")]
    HeaderArchiveGap,
    #[error("HNS genesis bootstrap target is invalid")]
    InvalidBootstrapTarget,
    #[error("HNS genesis bootstrap is available only for a pristine wallet")]
    BootstrapUnavailable,
    #[error("HNS genesis bootstrap must match the wallet birthday")]
    BootstrapBirthdayMismatch,
    #[error("HNS genesis bootstrap header count does not match its target")]
    BootstrapHeaderCountMismatch,
    #[error("HNS genesis bootstrap does not match its pinned endpoint")]
    BootstrapTargetMismatch,
    #[error("independent header validation disagreed with the selected sync candidate")]
    ConsensusStateMismatch,
    #[error("HNS light-chain persistence revision overflow")]
    RevisionOverflow,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic fixtures"
)]
mod tests {
    use hns_light_sync::SyncState;
    use hns_primitives::{BlockHash, TreeRoot};
    use hns_wallet_store::WalletStore;

    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn store() -> SharedWalletStore {
        SharedWalletStore::new(WalletStore::create(":memory:", PASSPHRASE).unwrap())
    }

    fn config() -> SyncConfig {
        SyncConfig {
            max_peers: 4,
            minimum_peer_agreement: 1,
            round_timeout_seconds: 10,
            max_peer_failures: 3,
        }
    }

    fn peer(value: u8) -> PeerId {
        PeerId::new([value; 32])
    }

    fn mine(previous: HeaderEntry, tree_root: u8) -> Header {
        let mut header = Header {
            time: BlockTime::new(previous.time().get() + 1),
            previous_block: previous.hash(),
            tree_root: TreeRoot::new([tree_root; 32]),
            bits: Network::Regtest.parameters().pow.bits,
            ..Header::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        header
    }

    fn open(
        store: SharedWalletStore,
        account: AccountId,
        birthday: u32,
        floor: HnsLightFloor,
        now: u64,
    ) -> Result<EncryptedHnsLightAuthority, HnsLightError> {
        EncryptedHnsLightAuthority::open_or_create(
            store,
            account,
            HnsNetwork::Regtest,
            birthday,
            floor,
            BlockTime::new(now),
            ChainLimits::default(),
            config(),
        )
    }

    #[test]
    fn genesis_checkpoint_roundtrips_and_requires_fresh_agreement() {
        let store = store();
        let account = AccountId::new([7; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let created = open(store.clone(), account, 0, HnsLightFloor::default(), now).unwrap();
        assert_eq!(created.status().tip.height(), Height::new(0));
        assert!(created.archived_header(0).unwrap().is_some());

        let reopened = open(store, account, 0, created.rollback_floor(), now).unwrap();
        assert_eq!(reopened.status().tip, created.status().tip);
        assert_eq!(reopened.status().state, SyncState::HeaderSyncing);
        assert!(!reopened.status().round_active);
    }

    #[test]
    fn genesis_verified_bootstrap_persists_only_its_birthday_anchor() {
        let store = store();
        let account = AccountId::new([70; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut authority = open(store.clone(), account, 3, HnsLightFloor::default(), now).unwrap();
        let mut fixture_chain = authority.validated_chain().clone();
        let mut headers = Vec::new();
        for marker in 1..=3 {
            let header = mine(fixture_chain.tip(), marker);
            fixture_chain.append(&header, BlockTime::new(now)).unwrap();
            headers.push(header);
        }
        let expected_hash = fixture_chain.tip().hash().into_bytes();

        let status = authority
            .bootstrap_from_genesis_headers(headers.clone(), 3, expected_hash, now)
            .unwrap();
        assert_eq!(status.state, SyncState::HeaderSyncing);
        assert_eq!(status.tip.height(), Height::new(3));
        assert_eq!(authority.chain_epoch(), 2);
        assert_eq!(
            authority.archived_header(3).unwrap().unwrap().block_hash(),
            headers[2].block_hash()
        );
        assert!(authority.archived_header(2).unwrap().is_none());

        let reopened = open(store, account, 3, authority.rollback_floor(), now).unwrap();
        assert_eq!(reopened.status().tip.height(), Height::new(3));
        assert_eq!(reopened.status().state, SyncState::HeaderSyncing);
        assert_eq!(
            reopened.archived_header(3).unwrap().unwrap().block_hash(),
            headers[2].block_hash()
        );
    }

    #[test]
    fn genesis_bootstrap_rejects_unpinned_or_non_pristine_state_without_writing() {
        let store = store();
        let account = AccountId::new([71; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut authority = open(store.clone(), account, 1, HnsLightFloor::default(), now).unwrap();
        let header = mine(authority.status().tip, 1);

        assert!(matches!(
            authority.bootstrap_from_genesis_headers(vec![header.clone()], 1, [0x55; 32], now,),
            Err(HnsLightError::BootstrapTargetMismatch)
        ));
        assert_eq!(authority.status().tip.height(), Height::new(0));
        let reopened = open(store, account, 1, HnsLightFloor::default(), now).unwrap();
        assert_eq!(reopened.status().tip.height(), Height::new(0));

        assert!(matches!(
            authority.bootstrap_from_genesis_headers(vec![header], 1, [0; 32], now,),
            Err(HnsLightError::BootstrapTargetMismatch)
        ));
    }

    #[test]
    fn agreed_extension_and_checkpoint_commit_atomically() {
        let store = store();
        let account = AccountId::new([8; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut first = open(store.clone(), account, 0, HnsLightFloor::default(), now).unwrap();
        let mut stale = open(store.clone(), account, 0, first.rollback_floor(), now).unwrap();
        let extension = mine(first.status().tip, 1);

        for (authority, id) in [(&mut first, peer(1)), (&mut stale, peer(2))] {
            authority.add_peer(id, 1).unwrap();
            let request = authority.begin_header_round(&[id], now).unwrap();
            authority
                .submit_header_response(request.generation, id, vec![extension.clone()], now)
                .unwrap();
        }

        let committed = first.finish_header_round_and_persist(now).unwrap();
        assert_eq!(committed.accepted.len(), 1);
        assert_eq!(committed.status.tip.height(), Height::new(1));
        assert_eq!(
            first.archived_header(1).unwrap().unwrap().block_hash(),
            extension.block_hash()
        );

        assert!(matches!(
            stale.finish_header_round_and_persist(now),
            Err(HnsLightError::Store(StoreError::StaleRevision { .. }))
        ));
        assert_eq!(stale.status().tip.height(), Height::new(0));

        let reopened = open(store, account, 0, first.rollback_floor(), now).unwrap();
        assert_eq!(reopened.status().tip.height(), Height::new(1));
        assert_eq!(
            reopened.archived_header(1).unwrap().unwrap().block_hash(),
            extension.block_hash()
        );
    }

    #[test]
    fn birthday_and_rollback_floor_fail_closed() {
        let store = store();
        let account = AccountId::new([9; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let created = open(store.clone(), account, 50, HnsLightFloor::default(), now).unwrap();
        assert!(created.archived_header(0).unwrap().is_none());
        assert!(matches!(
            open(store.clone(), account, 51, created.rollback_floor(), now),
            Err(HnsLightError::BirthdayMismatch)
        ));

        let impossible_floor = HnsLightFloor {
            height: 1,
            chainwork: [0xff; 32],
        };
        assert!(matches!(
            open(store, account, 50, impossible_floor, now),
            Err(HnsLightError::Chain(LightChainError::SnapshotRollback))
        ));
    }

    #[test]
    fn a_missing_checkpoint_cannot_reset_a_nonzero_platform_floor() {
        let floor = HnsLightFloor {
            height: 100,
            chainwork: [1; 32],
        };
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        assert!(matches!(
            open(store(), AccountId::new([10; 16]), 0, floor, now),
            Err(HnsLightError::MissingCheckpointBelowFloor)
        ));
    }

    #[test]
    fn archived_header_hash_is_bound_to_its_height() {
        let store = store();
        let account = AccountId::new([11; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let authority = open(store.clone(), account, 0, HnsLightFloor::default(), now).unwrap();
        let id = header_id(account, 0);
        let stored: StoredEntity<StoredHnsLightRecord> = store
            .with_store(|wallet| wallet.hns_light_chain(&id))
            .unwrap()
            .unwrap();
        let StoredHnsLightRecord::Header(mut header) = stored.value else {
            unreachable!();
        };
        header.block_hash = BlockHash::new([0x55; 32]).into_bytes();
        store
            .with_store_mut(|wallet| {
                wallet.save_hns_light_chain(
                    &id,
                    stored.revision,
                    &StoredHnsLightRecord::Header(header),
                    now + 1,
                )
            })
            .unwrap();
        assert!(matches!(
            authority.archived_header(0),
            Err(HnsLightError::CorruptHeaderArchive)
        ));
    }
}
