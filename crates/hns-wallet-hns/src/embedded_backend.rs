//! `HnsBackend` backed by wallet-owned verified headers and filtered blocks.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use hns_covenants::{
    Covenant, CovenantKind, FinalizeCovenant, MAX_RESOURCE_SIZE, NameState, TransferCovenant,
};
use hns_header_consensus::Header;
use hns_light_sync::{HeaderRoundRequest, PeerId, SyncError, SyncState};
use hns_light_wallet::{VerifiedWalletBlock, WalletHeaderAnchor};
use hns_p2p_wire::{GetProofPacket, ProofPacket};
use hns_primitives::{Height, NameHash, Outpoint, TreeRoot};
use hns_transaction::{Coin, Output, Transaction};
use hns_wallet_types::{BaseUnits, TransactionHash};
use sha2::{Digest, Sha256};

use crate::light_index::{add_watched_outputs, transaction_relevant};
use crate::{
    ActiveNameOwnerCoinEvidence, ActiveNameOwnerCoinSourceBinding, BlockHashEvidence, ChainTip,
    ConfirmedWalletPage, ConfirmedWalletPageRequest, DEFAULT_FEE_TARGET_BLOCKS,
    DIRECT_WALLET_INDEX_WATCH_SET_INCOMPLETE_MESSAGE, EncryptedHnsLightAuthority,
    EncryptedHnsLightIndex, HistoryEntry, HnsBackend, HnsFeeRateSource, HnsInputCoinEvidence,
    HnsLightWatchSet, HnsNameAction, HnsNameLifecycle, HnsNetwork, HnsTransactionFeeQuote,
    HnsWalletError, IncomingTransferCandidate, IncomingTransferSourceBinding,
    IncomingTransfersPage, IncomingTransfersPageRequest, IndexedWalletCoin, MAX_HISTORY_RESULTS,
    MAX_MEMPOOL_SCAN_RESULTS, MAX_OUTPOINT_SPEND_BATCH, MAX_SCAN_PAGE_RESULTS,
    MempoolSnapshotBinding, MempoolWalletPage, MempoolWalletPageRequest, NameActionContextEvidence,
    NameActionIneligibility, NameEvidence, NameProofResponse, OutpointSpendEntry,
    OutpointSpendEvidence, PersistedHeaderRound, SnapshotBinding, SpendingTransactionEvidence,
    TransactionEvidence, TransactionInclusion, TransactionStatus, VerifiedHnsNameProof,
    VerifiedHnsTransactionObservation, WalletAddressKey, WalletCoin, actual_transaction_fee,
    local_fee_policy_evidence,
};

const MINIMUM_RELAY_FEE_RATE: u64 = 1_000;
// Canonical HSD network wallet defaults. These are deliberately higher than
// the protocol relay floor: a relayable transaction is not necessarily a
// normal miner-targeted wallet transaction.
const MAINNET_NORMAL_FEE_RATE: u64 = 100_000;
const TEST_NETWORK_NORMAL_FEE_RATE: u64 = 20_000;
const MAX_EMBEDDED_FEE_RATE: u64 = u32::MAX as u64;
const CURSOR_BYTES: usize = 36;
const CURSOR_DOMAIN: &[u8] = b"hns-wallet-rs/embedded-backend-cursor/v1";

/// Direct standard-peer network boundary used by the embedded backend.
///
/// Implementations succeed only after the bytes have been written to at least
/// one ready Handshake peer. They do not decide validity or mutate wallet
/// state. A successful write is submission, not peer mempool admission; only
/// a later peer inventory/transaction response may enter the embedded mempool.
pub trait HnsLightNetwork: Send + Sync {
    fn broadcast_transaction(&self, raw: &[u8]) -> Result<usize, HnsWalletError>;
}

#[derive(Clone)]
pub struct EmbeddedHnsBackend {
    inner: Arc<Mutex<EmbeddedState>>,
    network: Arc<dyn HnsLightNetwork>,
}

struct EmbeddedState {
    authority: EncryptedHnsLightAuthority,
    index: EncryptedHnsLightIndex,
    mempool: EmbeddedMempool,
    connected_peers: HashSet<PeerId>,
    peer_fee_rates: HashMap<PeerId, u64>,
}

struct EmbeddedMempool {
    instance_nonce: [u8; 32],
    generation: u64,
    transactions: BTreeMap<[u8; 32], MempoolTransaction>,
}

#[derive(Clone)]
struct MempoolTransaction {
    transaction: Transaction,
    raw: Vec<u8>,
    first_seen_unix: u64,
}

impl EmbeddedHnsBackend {
    /// Pair one exact chain authority and filtered-block index with a direct
    /// peer transport.
    pub fn new(
        authority: EncryptedHnsLightAuthority,
        index: EncryptedHnsLightIndex,
        network: Arc<dyn HnsLightNetwork>,
    ) -> Result<Self, HnsWalletError> {
        if authority.account_id() != index.account_id()
            || authority.consensus_network() != index.consensus_network()
            || authority.birthday_height() > index.status().birthday_height
        {
            return Err(HnsWalletError::InvalidRuntimeConfiguration);
        }
        let mut instance_nonce = [0_u8; 32];
        getrandom::fill(&mut instance_nonce).map_err(|_| HnsWalletError::Randomness)?;
        if instance_nonce == [0; 32] {
            return Err(HnsWalletError::Randomness);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(EmbeddedState {
                authority,
                index,
                mempool: EmbeddedMempool {
                    instance_nonce,
                    generation: 1,
                    transactions: BTreeMap::new(),
                },
                connected_peers: HashSet::new(),
                peer_fee_rates: HashMap::new(),
            })),
            network,
        })
    }

    /// Install the complete public wallet watch set. A changed set rewinds the
    /// derived index and clears the process-local mempool view.
    pub fn install_watch_set(
        &self,
        watch_set: HnsLightWatchSet,
        now_unix: u64,
    ) -> Result<bool, HnsWalletError> {
        let mut state = self.lock()?;
        let changed = state
            .index
            .install_watch_set(watch_set, now_unix)
            .map_err(map_index_error)?;
        if changed {
            state.mempool.transactions.clear();
            advance_mempool_generation(&mut state.mempool)?;
        }
        Ok(changed)
    }

    /// Add exact name hashes to the current direct-wallet watch set without
    /// invalidating already verified script activity.
    ///
    /// This narrower extension is for an explicit, authenticated name-proof
    /// request. Unlike replacing the complete recovery watch set, adding a
    /// name hash does not hand out a previously undiscovered wallet script;
    /// the exact proof remains required before a name can be imported. The
    /// existing verified transaction projection is therefore retained while
    /// the requested proof can be admitted and bound to it.
    pub(crate) fn extend_name_watch_set_without_rewind(
        &self,
        name_hashes: &[[u8; 32]],
        now_unix: u64,
    ) -> Result<bool, HnsWalletError> {
        if name_hashes.is_empty() {
            return Ok(false);
        }
        let mut state = self.lock()?;
        let installed = state.index.watch_set();
        let mut names = installed.name_hashes.clone();
        names.extend_from_slice(name_hashes);
        let extended =
            HnsLightWatchSet::new(installed.scripts.clone(), names).map_err(map_index_error)?;
        let changed = state
            .index
            .extend_watch_set_without_rewind(extended, now_unix)
            .map_err(map_index_error)?;
        if changed {
            state.mempool.transactions.clear();
            advance_mempool_generation(&mut state.mempool)?;
        }
        Ok(changed)
    }

    /// Return the exact names whose current-root proof is absent from this
    /// wallet-owned index. The caller supplies only name hashes already
    /// derived from the encrypted wallet store or from a locally verified
    /// FINALIZE output; no peer or host input can enlarge this query.
    pub(crate) fn name_hashes_missing_current_proofs(
        &self,
        name_hashes: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, HnsWalletError> {
        let state = self.lock()?;
        let binding = current_binding(&state)?;
        let mut missing = Vec::with_capacity(name_hashes.len());
        for name_hash in name_hashes {
            if state
                .index
                .name_proof(*name_hash, binding.tip.tree_root)
                .map_err(map_index_error)?
                .is_none()
            {
                missing.push(*name_hash);
            }
        }
        Ok(missing)
    }

    /// Derive the exact names that must be projected because a locally
    /// authenticated, still-unspent FINALIZE output pays one of this wallet's
    /// installed scripts. This does not infer ownership from a peer name
    /// response: it merely identifies the name hashes for which the ordinary
    /// strict proof refresh is required before snapshot reconciliation.
    pub(crate) fn watched_finalize_name_hashes(&self) -> Result<Vec<[u8; 32]>, HnsWalletError> {
        let state = self.lock()?;
        let binding = current_binding(&state)?;
        let observations = state.index.transactions().map_err(map_index_error)?;
        let rows = confirmed_rows(
            &observations,
            &state.index.watch_set().scripts,
            binding.tip.height,
        )?;
        let mut names = BTreeSet::new();
        for row in rows {
            let ConfirmedRow::Coin(coin) = row else {
                continue;
            };
            let covenant = Covenant::decode(&coin.coin.covenant)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
            if covenant
                .encode()
                .map_err(|_| HnsWalletError::InvalidEvidence)?
                != coin.coin.covenant
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            if covenant.kind != CovenantKind::Finalize {
                continue;
            }
            let finalize = FinalizeCovenant::try_from(&covenant)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
            names.insert(finalize.name_hash.into_bytes());
        }
        Ok(names.into_iter().collect())
    }

    /// Append a locally allocated future change-gap script without rewinding
    /// the verified block index. The light index independently validates the
    /// exact persisted account transition and otherwise returns `false`.
    pub fn extend_locally_allocated_change_watch_set(
        &self,
        account: &crate::HnsAccountRecord,
        now_unix: u64,
    ) -> Result<bool, HnsWalletError> {
        self.lock()?
            .index
            .extend_locally_allocated_change_watch_set(account, now_unix)
            .map_err(map_index_error)
    }

    /// Current authenticated header-sync status owned by this wallet.
    pub fn header_sync_status(&self) -> Result<hns_light_sync::SyncStatus, HnsWalletError> {
        Ok(self.lock()?.authority.status())
    }

    /// Latest local header floor for platform-owned anti-rollback storage.
    pub fn rollback_floor(&self) -> Result<crate::HnsLightFloor, HnsWalletError> {
        Ok(self.lock()?.authority.rollback_floor())
    }

    /// Current durable filtered-block coverage for the installed watch set.
    pub fn light_scan_status(&self) -> Result<crate::HnsLightScanStatus, HnsWalletError> {
        Ok(self.lock()?.index.status())
    }

    /// Exact public watch set from which every peer Bloom filter is built.
    pub fn light_watch_set(&self) -> Result<HnsLightWatchSet, HnsWalletError> {
        Ok(self.lock()?.index.watch_set().clone())
    }

    /// Canonical Bloom-filter elements for the current watch set and every
    /// previously observed wallet outpoint.
    pub fn light_bloom_elements(&self) -> Result<Vec<Vec<u8>>, HnsWalletError> {
        self.lock()?.index.bloom_elements().map_err(map_index_error)
    }

    /// Reconstruct the minimal evidence anchor for one authenticated archived
    /// header without inventing historical chainwork.
    pub fn wallet_header_anchor(&self, height: u32) -> Result<WalletHeaderAnchor, HnsWalletError> {
        let state = self.lock()?;
        if height > state.authority.validated_chain().tip().height().get() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let header = state
            .authority
            .archived_header(height)
            .map_err(map_authority_error)?
            .ok_or(HnsWalletError::InvalidEvidence)?;
        Ok(WalletHeaderAnchor::from_validated_header(
            Height::new(height),
            &header,
        ))
    }

    /// Add one ready standard peer to header agreement.
    pub fn add_header_peer(
        &self,
        id: PeerId,
        advertised_height: u32,
    ) -> Result<(), HnsWalletError> {
        let mut state = self.lock()?;
        state
            .authority
            .add_peer(id, advertised_height)
            .map_err(map_authority_error)?;
        state.connected_peers.insert(id);
        Ok(())
    }

    /// Remove a disconnected header peer.
    pub fn remove_header_peer(&self, id: PeerId) -> Result<bool, HnsWalletError> {
        let mut state = self.lock()?;
        state.connected_peers.remove(&id);
        state.peer_fee_rates.remove(&id);
        Ok(state.authority.remove_peer(id))
    }

    /// Update the advertised height of one connected standard peer.
    pub fn update_header_peer_height(
        &self,
        id: PeerId,
        advertised_height: u32,
    ) -> Result<(), HnsWalletError> {
        self.lock()?
            .authority
            .update_peer_height(id, advertised_height)
            .map_err(map_authority_error)
    }

    /// Begin one same-locator multi-peer header round.
    pub fn begin_header_round(
        &self,
        peers: &[PeerId],
        now_unix: u64,
    ) -> Result<HeaderRoundRequest, HnsWalletError> {
        self.lock()?
            .authority
            .begin_header_round(peers, now_unix)
            .map_err(map_authority_error)
    }

    /// Release an authority round whose connection-local coordinator metadata
    /// no longer exists. Authenticated headers and durable checkpoints are
    /// unchanged because an active round has not committed either.
    pub fn abandon_uncommitted_header_round(&self) -> Result<bool, HnsWalletError> {
        Ok(self.lock()?.authority.abandon_uncommitted_header_round())
    }

    /// Submit one peer's untrusted header response.
    pub fn submit_header_response(
        &self,
        generation: u64,
        peer: PeerId,
        headers: Vec<Header>,
        now_unix: u64,
    ) -> Result<(), HnsWalletError> {
        self.lock()?
            .authority
            .submit_header_response(generation, peer, headers, now_unix)
            .map_err(map_authority_error)
    }

    /// Finish and durably persist one header round.
    pub fn finish_header_round(
        &self,
        now_unix: u64,
    ) -> Result<PersistedHeaderRound, HnsWalletError> {
        self.lock()?
            .authority
            .finish_header_round_and_persist(now_unix)
            .map_err(map_header_round_error)
    }

    /// Finish a header round when agreement is already sufficient, preserving
    /// an incomplete pre-deadline round for later peer responses or expiry.
    pub fn try_finish_header_round(
        &self,
        now_unix: u64,
    ) -> Result<Option<PersistedHeaderRound>, HnsWalletError> {
        match self
            .lock()?
            .authority
            .finish_header_round_and_persist(now_unix)
        {
            Ok(round) => Ok(Some(round)),
            Err(crate::HnsLightError::Sync(SyncError::RoundIncomplete)) => Ok(None),
            // Remote peer availability and agreement failures are typed rather
            // than flattened to `Backend`. The mobile direct-peer coordinator
            // can retain its verified checkpoint, replace the sampled peers,
            // and retry without treating a local wallet or chain validation
            // failure as recoverable.
            Err(error) => Err(map_header_round_error(error)),
        }
    }

    /// Exact standard `getproof` target for a watched name at the current
    /// locally agreed header-tree root.
    pub fn name_proof_request(
        &self,
        name_hash: [u8; 32],
    ) -> Result<GetProofPacket, HnsWalletError> {
        let state = self.lock()?;
        let binding = current_binding(&state)?;
        if state
            .index
            .watch_set()
            .name_hashes
            .binary_search(&name_hash)
            .is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(GetProofPacket {
            root: TreeRoot::new(binding.tip.tree_root),
            key: NameHash::new(name_hash),
        })
    }

    /// Admit a strictly decoded peer proof only after binding it to the
    /// current locally agreed root and installed name watch set.
    pub fn admit_name_proof(
        &self,
        packet: &ProofPacket,
        now_unix: u64,
    ) -> Result<VerifiedHnsNameProof, HnsWalletError> {
        let mut state = self.lock()?;
        let EmbeddedState {
            authority, index, ..
        } = &mut *state;
        index
            .admit_name_proof(authority, packet, now_unix)
            .map_err(map_index_error)
    }

    /// Commit one next-height verified filtered block into the encrypted index.
    pub fn apply_verified_block(
        &self,
        block: &VerifiedWalletBlock,
        now_unix: u64,
    ) -> Result<usize, HnsWalletError> {
        let admitted = self.apply_verified_blocks(std::slice::from_ref(block), now_unix)?;
        debug_assert_eq!(admitted.len(), 1);
        Ok(admitted.into_iter().next().unwrap_or_default())
    }

    /// Commit a consecutive filtered-block batch in one durable wallet-store
    /// transaction. The index verifies every block before it advances durable
    /// coverage, so a failed batch is safely replayed on the next sync.
    pub fn apply_verified_blocks(
        &self,
        blocks: &[VerifiedWalletBlock],
        now_unix: u64,
    ) -> Result<Vec<usize>, HnsWalletError> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }
        let mut state = self.lock()?;
        let EmbeddedState {
            authority,
            index,
            mempool,
            ..
        } = &mut *state;
        let admitted = index
            .apply_verified_block_batch(authority, blocks, now_unix)
            .map_err(map_index_error)?;
        let mut changed = false;
        for block in blocks {
            for transaction in block.transactions() {
                let txid = transaction
                    .transaction_hash()
                    .map_err(|_| HnsWalletError::InvalidEvidence)?
                    .into_bytes();
                changed |= mempool.transactions.remove(&txid).is_some();
            }
        }
        if changed {
            advance_mempool_generation(mempool)?;
        }
        Ok(admitted)
    }

    /// Admit one bloom-matched transaction returned by a connected peer.
    pub fn admit_mempool_transaction(
        &self,
        transaction: Transaction,
        first_seen_unix: u64,
    ) -> Result<Option<TransactionHash>, HnsWalletError> {
        let raw = transaction
            .encode()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let txid = transaction
            .transaction_hash()
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        let mut state = self.lock()?;
        if !mempool_transaction_relevant(&state, &transaction)? {
            return Ok(None);
        }
        admit_mempool(&mut state.mempool, txid, transaction, raw, first_seen_unix)?;
        Ok(Some(TransactionHash::new(txid)))
    }

    /// Update one connected peer's advertised relay floor. Fee estimation uses
    /// the lower median so one high outlier cannot price the wallet offline.
    pub fn observe_peer_fee_rate(
        &self,
        peer: PeerId,
        atomic_units_per_1000_policy_vbytes: i64,
    ) -> Result<(), HnsWalletError> {
        let rate = u64::try_from(atomic_units_per_1000_policy_vbytes)
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        if !(MINIMUM_RELAY_FEE_RATE..=MAX_EMBEDDED_FEE_RATE).contains(&rate) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mut state = self.lock()?;
        if !state.connected_peers.contains(&peer) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        state.peer_fee_rates.insert(peer, rate);
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, EmbeddedState>, HnsWalletError> {
        self.inner
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }
}

impl HnsBackend for EmbeddedHnsBackend {
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
        let state = self.lock()?;
        current_binding(&state)
    }

    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
        self.get_chain_snapshot().map(|binding| binding.tip)
    }

    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let height_u32 = u32::try_from(height).map_err(|_| HnsWalletError::InvalidEvidence)?;
        let block_hash = if height == 0 {
            Some(
                state
                    .authority
                    .consensus_network()
                    .parameters()
                    .genesis_hash
                    .into_bytes(),
            )
        } else {
            state
                .authority
                .archived_header(height_u32)
                .map_err(map_authority_error)?
                .map(|header| header.block_hash().into_bytes())
        };
        Ok(BlockHashEvidence {
            binding,
            height,
            block_hash,
        })
    }

    fn get_confirmed_wallet_page(
        &self,
        request: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError> {
        validate_page_scripts(request.scripts)?;
        if request.limit == 0 || request.limit as usize > MAX_SCAN_PAGE_RESULTS {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let state = self.lock()?;
        let binding = current_binding(&state)?;
        if binding.tip != request.expected_tip
            || request
                .expected_epoch
                .is_some_and(|epoch| epoch != binding.chain_epoch)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        require_watched_scripts(&state.index, request.scripts)?;
        let observations = state.index.transactions().map_err(map_index_error)?;
        let rows = confirmed_rows(&observations, request.scripts, binding.tip.height)?;
        let digest = cursor_digest(b"confirmed", request.scripts, binding, None);
        let offset = decode_cursor(request.cursor, digest, rows.len())?;
        let end = offset
            .saturating_add(request.limit as usize)
            .min(rows.len());
        let mut history = Vec::new();
        let mut utxos = Vec::new();
        for row in &rows[offset..end] {
            match row {
                ConfirmedRow::History(entry) => history.push(*entry),
                ConfirmedRow::Coin(coin) => utxos.push(coin.clone()),
            }
        }
        Ok(ConfirmedWalletPage {
            binding,
            next_cursor: (end < rows.len()).then(|| encode_cursor(digest, end)),
            history,
            utxos,
        })
    }

    fn get_incoming_transfers_page(
        &self,
        request: IncomingTransfersPageRequest<'_>,
    ) -> Result<IncomingTransfersPage, HnsWalletError> {
        validate_page_scripts(request.scripts)?;
        if request.limit == 0 || request.limit as usize > MAX_SCAN_PAGE_RESULTS {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let state = self.lock()?;
        require_binding(&state, request.binding)?;
        require_watched_scripts(&state.index, request.scripts)?;
        let observations = state.index.transactions().map_err(map_index_error)?;
        let entries = incoming_transfers(&observations, request.scripts)?;
        let digest = cursor_digest(b"incoming", request.scripts, request.binding, None);
        let offset = decode_cursor(request.cursor, digest, entries.len())?;
        let examined = request.scripts.len().min(MAX_SCAN_PAGE_RESULTS);
        let end = offset
            .saturating_add(request.limit as usize)
            .min(entries.len());
        Ok(IncomingTransfersPage {
            projection_version: 1,
            binding: request.binding,
            entries: entries[offset..end].to_vec(),
            script_examinations: examined,
            next_cursor: (end < entries.len()).then(|| encode_cursor(digest, end)),
        })
    }

    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError> {
        validate_page_scripts(request.scripts)?;
        if request.limit == 0 || request.limit as usize > MAX_MEMPOOL_SCAN_RESULTS {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let state = self.lock()?;
        require_binding(&state, request.binding)?;
        require_watched_scripts(&state.index, request.scripts)?;
        let mempool_binding = mempool_binding(&state.mempool);
        if request
            .expected_mempool
            .is_some_and(|expected| expected != mempool_binding)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let observations = state.index.transactions().map_err(map_index_error)?;
        let history = mempool_history(&observations, &state.mempool, request.scripts)?;
        let digest = cursor_digest(
            b"mempool",
            request.scripts,
            request.binding,
            Some(mempool_binding),
        );
        let offset = decode_cursor(request.cursor, digest, history.len())?;
        let end = offset
            .saturating_add(request.limit as usize)
            .min(history.len());
        Ok(MempoolWalletPage {
            binding: request.binding,
            mempool: mempool_binding,
            next_cursor: (end < history.len()).then(|| encode_cursor(digest, end)),
            history: history[offset..end].to_vec(),
        })
    }

    fn get_transaction_evidence(
        &self,
        txid: TransactionHash,
        binding: SnapshotBinding,
        expected_mempool: Option<MempoolSnapshotBinding>,
    ) -> Result<TransactionEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let mempool = mempool_binding(&state.mempool);
        if expected_mempool.is_some_and(|expected| expected != mempool) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let observations = state.index.transactions().map_err(map_index_error)?;
        if let Some(observation) = observations.iter().find(|item| item.txid == txid) {
            let confirmations = confirmation_count(binding.tip.height, observation.height)?;
            return Ok(TransactionEvidence {
                binding,
                mempool,
                raw: Some(observation.raw.clone()),
                status: TransactionStatus {
                    in_mempool: false,
                    confirmation_count: confirmations,
                    conflicted: false,
                },
                inclusion: Some(inclusion(observation)),
            });
        }
        if let Some(transaction) = state.mempool.transactions.get(txid.as_bytes()) {
            let conflicted = mempool_transaction_conflicted(
                txid.into_bytes(),
                &transaction.transaction,
                &observations,
                &state.mempool,
            )?;
            return Ok(TransactionEvidence {
                binding,
                mempool,
                raw: Some(transaction.raw.clone()),
                status: TransactionStatus {
                    in_mempool: !conflicted,
                    confirmation_count: 0,
                    conflicted,
                },
                inclusion: None,
            });
        }
        Ok(TransactionEvidence {
            binding,
            mempool,
            raw: None,
            status: TransactionStatus {
                in_mempool: false,
                confirmation_count: 0,
                conflicted: false,
            },
            inclusion: None,
        })
    }

    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[crate::HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError> {
        if outpoints.len() > MAX_OUTPOINT_SPEND_BATCH {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let observations = state.index.transactions().map_err(map_index_error)?;
        let spends = confirmed_spends(&observations)?;
        let entries = outpoints
            .iter()
            .map(|outpoint| {
                let canonical = Outpoint {
                    transaction_hash: hns_primitives::TransactionHash::new(
                        outpoint.transaction.into_bytes(),
                    ),
                    index: outpoint.output_index,
                };
                OutpointSpendEntry {
                    outpoint: *outpoint,
                    spending: spends.get(&canonical).copied(),
                }
            })
            .collect();
        Ok(OutpointSpendEvidence { binding, entries })
    }

    fn broadcast_transaction(&self, raw: &[u8]) -> Result<TransactionHash, HnsWalletError> {
        let transaction =
            Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if transaction
            .encode()
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
            != raw
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let txid = transaction
            .transaction_hash()
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
            .into_bytes();
        {
            let state = self.lock()?;
            if !mempool_transaction_relevant(&state, &transaction)? {
                return Err(HnsWalletError::InvalidPreparedArtifact);
            }
        }
        let written = self.network.broadcast_transaction(raw)?;
        if written == 0 {
            return Err(HnsWalletError::Backend(
                "no ready Handshake peer received the transaction bytes".to_owned(),
            ));
        }
        Ok(TransactionHash::new(txid))
    }

    fn extend_locally_allocated_change_watch_set(
        &self,
        account: &crate::HnsAccountRecord,
        now_unix: u64,
    ) -> Result<bool, HnsWalletError> {
        EmbeddedHnsBackend::extend_locally_allocated_change_watch_set(self, account, now_unix)
    }

    fn quote_transaction_fee(
        &self,
        raw: &[u8],
        input_coins: &[Coin],
        target_blocks: u16,
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        if target_blocks == 0 {
            return Err(HnsWalletError::InvalidFeeQuote);
        }
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let mempool = mempool_binding(&state.mempool);
        if mempool != expected_mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let transaction =
            Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidFeeQuoteTransaction)?;
        if transaction
            .encode()
            .map_err(|_| HnsWalletError::InvalidFeeQuoteTransaction)?
            != raw
        {
            return Err(HnsWalletError::InvalidFeeQuoteTransaction);
        }
        let (fee_rate, fee_rate_samples) = wallet_fee_rate(&state);
        let local = local_fee_policy_evidence(
            &transaction,
            input_coins,
            BaseUnits::new(u128::from(fee_rate)),
        )?;
        let actual_fee = actual_transaction_fee(&transaction, input_coins)?;
        let shortfall = local.minimum_fee.get().saturating_sub(actual_fee.get());
        let txid = transaction
            .transaction_hash()
            .map_err(|_| HnsWalletError::InvalidFeeQuoteTransaction)?;
        Ok(HnsTransactionFeeQuote {
            txid: TransactionHash::new(txid.into_bytes()),
            binding,
            mempool,
            target_blocks,
            rate_atomic_units_per_1000_policy_vbytes: fee_rate,
            rate_sample_count: fee_rate_samples,
            rate_source: if fee_rate_samples == 0 {
                HnsFeeRateSource::NetworkDefault
            } else {
                HnsFeeRateSource::PeerRelay
            },
            transaction_weight: local.transaction_weight,
            transaction_sigops: local.transaction_sigops,
            sigop_adjusted_policy_vbytes: local.policy_virtual_size,
            minimum_policy_fee: local.minimum_fee,
            actual_fee,
            meets_minimum_policy_fee: actual_fee >= local.minimum_fee,
            minimum_policy_fee_shortfall: BaseUnits::new(shortfall),
        })
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<BaseUnits, HnsWalletError> {
        if target_blocks == 0 || target_blocks > DEFAULT_FEE_TARGET_BLOCKS.saturating_mul(168) {
            return Err(HnsWalletError::InvalidFeeQuote);
        }
        let state = self.lock()?;
        Ok(BaseUnits::new(u128::from(wallet_fee_rate(&state).0)))
    }

    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let view = embedded_name_view(&state, name_hash, binding)?;
        let (proof_owner_outpoint, proof_owner_transaction, proof_owner_inclusion) =
            optional_name_owner_fields(view.proof_state.as_ref(), view.proof_owner.as_ref());
        let (current_owner_outpoint, current_owner_transaction, current_owner_inclusion) =
            optional_name_owner_fields(view.current.as_ref(), view.current_owner.as_ref());
        Ok(NameEvidence {
            binding,
            proof: NameProofResponse {
                name_hash,
                tree_root: view.proof.tree_root,
                proof: view.proof.proof,
                proof_height: binding.tip.height,
            },
            proof_state: view.proof.state,
            proof_owner_outpoint,
            proof_owner_transaction,
            proof_owner_inclusion,
            current_state: view.current_raw,
            current_owner_outpoint,
            current_owner_transaction,
            current_owner_inclusion,
            untrusted_current_raw_resource: view
                .current
                .as_ref()
                .map(|current| current.resource_data.clone()),
        })
    }

    fn get_active_name_owner_coin(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        let view = embedded_name_view(&state, name_hash, binding)?;
        active_name_owner_coin(&view, binding)
    }

    fn get_name_action_context(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        embedded_name_action_context(&state, action, name_hash, binding, expected_mempool, false)
    }

    fn get_name_action_context_v2(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let state = self.lock()?;
        require_binding(&state, binding)?;
        embedded_name_action_context(&state, action, name_hash, binding, expected_mempool, true)
    }
}

struct EmbeddedNameView {
    proof: VerifiedHnsNameProof,
    proof_state: Option<NameState>,
    current_raw: Option<Vec<u8>>,
    current: Option<NameState>,
    proof_owner: Option<EmbeddedNameOwner>,
    current_owner: Option<EmbeddedNameOwner>,
}

#[derive(Clone)]
struct EmbeddedNameOwner {
    outpoint: crate::HnsOutpoint,
    transaction: Vec<u8>,
    output: Output,
    inclusion: TransactionInclusion,
    coinbase: bool,
}

#[derive(Clone, Copy)]
struct EmbeddedNameParameters {
    lockup_period: u32,
    renewal_window: u32,
    renewal_period: u32,
    renewal_maturity: u32,
    claim_period: u32,
    bidding_period: u32,
    reveal_period: u32,
    tree_interval: u32,
    transfer_lockup: u32,
    auction_maturity: u32,
    no_reserved: bool,
}

#[derive(Clone)]
enum ConfirmedRow {
    History(HistoryEntry),
    Coin(IndexedWalletCoin),
}

fn current_binding(state: &EmbeddedState) -> Result<SnapshotBinding, HnsWalletError> {
    let status = state.authority.status();
    let scan = state.index.status();
    if status.state != SyncState::HeaderCurrent
        || scan.scanned_height != Some(status.tip.height().get())
        || scan.scanned_hash != Some(status.tip.hash().into_bytes())
    {
        return Err(HnsWalletError::Backend(
            "direct wallet index is not aligned with the authenticated header tip".to_owned(),
        ));
    }
    Ok(SnapshotBinding {
        tip: ChainTip {
            height: u64::from(status.tip.height().get()),
            block_hash: status.tip.hash().into_bytes(),
            tree_root: status.tip.tree_root().into_bytes(),
            median_time_past: state.authority.validated_chain().median_time_past().get(),
        },
        chain_epoch: state.authority.chain_epoch(),
    })
}

fn require_binding(state: &EmbeddedState, expected: SnapshotBinding) -> Result<(), HnsWalletError> {
    if current_binding(state)? != expected {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(())
}

fn require_watched_scripts(
    index: &EncryptedHnsLightIndex,
    requested: &[WalletAddressKey],
) -> Result<(), HnsWalletError> {
    let watched = index.watch_set().scripts.iter().collect::<BTreeSet<_>>();
    if requested.iter().any(|script| !watched.contains(script)) {
        return Err(HnsWalletError::Backend(
            DIRECT_WALLET_INDEX_WATCH_SET_INCOMPLETE_MESSAGE.to_owned(),
        ));
    }
    Ok(())
}

fn validate_page_scripts(scripts: &[WalletAddressKey]) -> Result<(), HnsWalletError> {
    if scripts.is_empty()
        || scripts.len() > crate::MAX_RESTORE_SCRIPTS_PER_QUERY
        || !scripts.windows(2).all(|pair| pair[0] < pair[1])
        || scripts
            .iter()
            .any(|script| script.version != 0 || !matches!(script.hash.len(), 20 | 32))
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn embedded_name_view(
    state: &EmbeddedState,
    name_hash: [u8; 32],
    binding: SnapshotBinding,
) -> Result<EmbeddedNameView, HnsWalletError> {
    let proof = state
        .index
        .name_proof(name_hash, binding.tip.tree_root)
        .map_err(map_index_error)?
        .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)?;
    let observations = state.index.transactions().map_err(map_index_error)?;
    let proof_state = proof
        .state
        .as_deref()
        .map(|raw| {
            NameState::decode(NameHash::new(name_hash), raw)
                .map_err(|_| HnsWalletError::InvalidEvidence)
        })
        .transpose()?;
    let current = project_current_name_state(
        proof_state.clone(),
        name_hash,
        &observations,
        state.index.status().birthday_height,
        state.authority.consensus_network(),
        u32::try_from(binding.tip.height).map_err(|_| HnsWalletError::InvalidEvidence)?,
    )?;
    let current_raw = current
        .as_ref()
        .map(|current| {
            current
                .encode()
                .map_err(|_| HnsWalletError::InvalidEvidence)
        })
        .transpose()?;
    let proof_owner = name_owner_observation(proof_state.as_ref(), &observations)?;
    let current_owner = name_owner_observation(current.as_ref(), &observations)?;
    Ok(EmbeddedNameView {
        proof,
        proof_state,
        current_raw,
        current,
        proof_owner,
        current_owner,
    })
}

fn name_owner_observation(
    state: Option<&NameState>,
    observations: &[VerifiedHnsTransactionObservation],
) -> Result<Option<EmbeddedNameOwner>, HnsWalletError> {
    let Some(state) = state else {
        return Ok(None);
    };
    let Some(owner) = state.owner_outpoint() else {
        return Ok(None);
    };
    let txid = TransactionHash::new(owner.transaction_hash.into_bytes());
    let Some(observation) = observations
        .iter()
        .find(|observation| observation.txid == txid)
    else {
        // A direct wallet deliberately indexes only transactions matching its
        // installed scripts. The authenticated Urkel name state can therefore
        // reference an arbitrary non-wallet owner's historical transaction
        // that is correctly absent here. Retain the state and owner outpoint
        // as watch-only evidence; ownership-sensitive operations still require
        // the full locally verified owner transaction below.
        return Ok(None);
    };
    let output = observation
        .transaction
        .outputs
        .get(owner.index as usize)
        .cloned()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    if output.covenant.item_name_hash(0) != Some(state.name_hash) || !output.covenant.kind.is_name()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(Some(EmbeddedNameOwner {
        outpoint: crate::HnsOutpoint {
            transaction: txid,
            output_index: owner.index,
        },
        transaction: observation.raw.clone(),
        output,
        inclusion: inclusion(observation),
        coinbase: observation.coinbase,
    }))
}

fn optional_name_owner_fields(
    state: Option<&NameState>,
    owner: Option<&EmbeddedNameOwner>,
) -> (
    Option<crate::HnsOutpoint>,
    Option<Vec<u8>>,
    Option<TransactionInclusion>,
) {
    owner.map_or_else(
        || {
            let outpoint =
                state
                    .and_then(NameState::owner_outpoint)
                    .map(|owner| crate::HnsOutpoint {
                        transaction: TransactionHash::new(owner.transaction_hash.into_bytes()),
                        output_index: owner.index,
                    });
            (outpoint, None, None)
        },
        |owner| {
            (
                Some(owner.outpoint),
                Some(owner.transaction.clone()),
                Some(owner.inclusion),
            )
        },
    )
}

fn active_name_owner_coin(
    view: &EmbeddedNameView,
    binding: SnapshotBinding,
) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
    let current_state = view
        .current_raw
        .clone()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let owner = view
        .current_owner
        .as_ref()
        .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)?;
    Ok(ActiveNameOwnerCoinEvidence {
        projection_version: 1,
        binding,
        current_state,
        owner_coin: Coin {
            outpoint: Outpoint {
                transaction_hash: hns_primitives::TransactionHash::new(
                    owner.outpoint.transaction.into_bytes(),
                ),
                index: owner.outpoint.output_index,
            },
            value: owner.output.value,
            height: Height::new(
                u32::try_from(owner.inclusion.height)
                    .map_err(|_| HnsWalletError::InvalidEvidence)?,
            ),
            coinbase: owner.coinbase,
            address: owner.output.address.clone(),
            covenant: owner.output.covenant.clone(),
        },
        inclusion: owner.inclusion,
        source_binding: ActiveNameOwnerCoinSourceBinding::LocallyVerifiedFilteredBlock,
    })
}

fn project_current_name_state(
    mut current: Option<NameState>,
    name_hash: [u8; 32],
    observations: &[VerifiedHnsTransactionObservation],
    scan_birthday: u32,
    network: hns_header_consensus::Network,
    tip_height: u32,
) -> Result<Option<NameState>, HnsWalletError> {
    let parameters = embedded_name_parameters(network);
    let committed_height = name_tree_committed_height(tip_height, parameters.tree_interval)?;
    let first_uncommitted = committed_height
        .checked_add(1)
        .ok_or(HnsWalletError::Arithmetic)?;
    if tip_height != 0 && scan_birthday > first_uncommitted {
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
    }
    for observation in observations
        .iter()
        .filter(|observation| observation.height > committed_height)
    {
        apply_projected_name_transaction(
            &mut current,
            name_hash,
            &observation.transaction,
            observation.height,
            parameters,
        )?;
    }
    if current
        .as_ref()
        .is_some_and(|state| state.name_hash.into_bytes() != name_hash || state.is_null())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(current)
}

fn name_tree_committed_height(tip_height: u32, interval: u32) -> Result<u32, HnsWalletError> {
    if interval == 0 {
        return Err(HnsWalletError::InvalidRuntimeConfiguration);
    }
    if tip_height == 0 {
        return Ok(0);
    }
    let parent = tip_height - 1;
    Ok(parent - parent % interval)
}

fn apply_projected_name_transaction(
    current: &mut Option<NameState>,
    expected_name_hash: [u8; 32],
    transaction: &Transaction,
    height: u32,
    parameters: EmbeddedNameParameters,
) -> Result<(), HnsWalletError> {
    let canonical_txid = transaction
        .transaction_hash()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    for (output_index, output) in transaction.outputs.iter().enumerate() {
        if !output.covenant.kind.is_name() {
            continue;
        }
        let Some(name_hash) = output.covenant.item_name_hash(0) else {
            return Err(HnsWalletError::InvalidEvidence);
        };
        if name_hash.into_bytes() != expected_name_hash {
            continue;
        }
        let output_index =
            u32::try_from(output_index).map_err(|_| HnsWalletError::InvalidEvidence)?;
        let outpoint = Outpoint {
            transaction_hash: canonical_txid,
            index: output_index,
        };
        if output.covenant.kind == CovenantKind::Claim {
            apply_projected_claim(
                current,
                expected_name_hash,
                output,
                outpoint,
                height,
                parameters,
            )?;
            continue;
        }

        let initially_null = current.is_none();
        if initially_null {
            if output.covenant.kind != CovenantKind::Open {
                return Err(HnsWalletError::InvalidEvidence);
            }
            let name = output
                .covenant
                .items
                .get(2)
                .cloned()
                .ok_or(HnsWalletError::InvalidEvidence)?;
            if hns_covenants::hash_name(&name)
                .map_err(|_| HnsWalletError::InvalidEvidence)?
                .into_bytes()
                != expected_name_hash
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            let mut state = NameState::null(NameHash::new(expected_name_hash));
            initialize_projected_name_state(&mut state, name, height);
            *current = Some(state);
        }
        let state = current.as_mut().ok_or(HnsWalletError::InvalidEvidence)?;
        if !initially_null {
            maybe_expire_projected_name(state, height, parameters)?;
        }
        let start = embedded_covenant_u32(&output.covenant, 1)?;
        if !matches!(output.covenant.kind, CovenantKind::Open) && start != state.height.get() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        match output.covenant.kind {
            CovenantKind::Open | CovenantKind::Bid | CovenantKind::Redeem => {}
            CovenantKind::Reveal => {
                if state.owner.is_null() || output.value > state.highest {
                    state.value = state.highest;
                    state.owner = outpoint;
                    state.highest = output.value;
                } else if output.value > state.value {
                    state.value = output.value;
                }
            }
            CovenantKind::Register => {
                state.registered = true;
                state.owner = outpoint;
                if let Some(resource) = output
                    .covenant
                    .items
                    .get(2)
                    .filter(|resource| !resource.is_empty())
                {
                    if resource.len() > MAX_RESOURCE_SIZE {
                        return Err(HnsWalletError::InvalidEvidence);
                    }
                    state.resource_data = resource.clone();
                }
                state.renewal = Height::new(height);
            }
            CovenantKind::Update => {
                state.owner = outpoint;
                if let Some(resource) = output
                    .covenant
                    .items
                    .get(2)
                    .filter(|resource| !resource.is_empty())
                {
                    if resource.len() > MAX_RESOURCE_SIZE {
                        return Err(HnsWalletError::InvalidEvidence);
                    }
                    state.resource_data = resource.clone();
                }
                state.transfer = Height::new(0);
            }
            CovenantKind::Renew => {
                state.owner = outpoint;
                state.transfer = Height::new(0);
                state.renewal = Height::new(height);
                state.renewals = state
                    .renewals
                    .checked_add(1)
                    .ok_or(HnsWalletError::Arithmetic)?;
            }
            CovenantKind::Transfer => {
                TransferCovenant::try_from(&output.covenant)
                    .map_err(|_| HnsWalletError::InvalidEvidence)?;
                state.owner = outpoint;
                state.transfer = Height::new(height);
            }
            CovenantKind::Finalize => {
                let finalize = hns_covenants::FinalizeCovenant::try_from(&output.covenant)
                    .map_err(|_| HnsWalletError::InvalidEvidence)?;
                if finalize.name_hash != state.name_hash
                    || finalize.start_height != state.height
                    || finalize.name != state.name
                    || finalize.weak() != state.weak
                    || finalize.claimed != state.claimed
                    || finalize.renewals != state.renewals
                {
                    return Err(HnsWalletError::InvalidEvidence);
                }
                state.owner = outpoint;
                state.transfer = Height::new(0);
                state.renewal = Height::new(height);
                state.renewals = state
                    .renewals
                    .checked_add(1)
                    .ok_or(HnsWalletError::Arithmetic)?;
            }
            CovenantKind::Revoke => {
                state.revoked = Height::new(height);
                state.transfer = Height::new(0);
                state.resource_data.clear();
            }
            CovenantKind::None | CovenantKind::Claim | CovenantKind::Unknown(_) => {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        state
            .encode()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
    }
    Ok(())
}

fn apply_projected_claim(
    current: &mut Option<NameState>,
    expected_name_hash: [u8; 32],
    output: &Output,
    outpoint: Outpoint,
    height: u32,
    parameters: EmbeddedNameParameters,
) -> Result<(), HnsWalletError> {
    if output.covenant.items.len() != 6 {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let name = output.covenant.items[2].clone();
    if hns_covenants::hash_name(&name)
        .map_err(|_| HnsWalletError::InvalidEvidence)?
        .into_bytes()
        != expected_name_hash
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let state = current.get_or_insert_with(|| NameState::null(NameHash::new(expected_name_hash)));
    if state.is_null() {
        initialize_projected_name_state(state, name.clone(), height);
    }
    if state.name != name {
        return Err(HnsWalletError::InvalidEvidence);
    }
    maybe_expire_projected_name(state, height, parameters)?;
    state.height = Height::new(height);
    state.renewal = Height::new(height);
    state.claimed = Height::new(embedded_covenant_u32(&output.covenant, 5)?);
    state.value = hns_primitives::Dollarydoos::new(0);
    state.owner = outpoint;
    state.highest = hns_primitives::Dollarydoos::new(0);
    state.weak = embedded_covenant_u8(&output.covenant, 3)? & 1 != 0;
    state
        .encode()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(())
}

fn initialize_projected_name_state(state: &mut NameState, name: Vec<u8>, height: u32) {
    state.name = name;
    reset_projected_name_state(state, height);
}

fn reset_projected_name_state(state: &mut NameState, height: u32) {
    state.height = Height::new(height);
    state.renewal = Height::new(height);
    state.owner = Outpoint::NULL;
    state.value = hns_primitives::Dollarydoos::new(0);
    state.highest = hns_primitives::Dollarydoos::new(0);
    state.resource_data.clear();
    state.transfer = Height::new(0);
    state.revoked = Height::new(0);
    state.claimed = Height::new(0);
    state.renewals = 0;
    state.registered = false;
    state.expired = false;
    state.weak = false;
}

fn maybe_expire_projected_name(
    state: &mut NameState,
    height: u32,
    parameters: EmbeddedNameParameters,
) -> Result<bool, HnsWalletError> {
    if !embedded_name_is_expired(state, height, parameters) {
        return Ok(false);
    }
    let resource = std::mem::take(&mut state.resource_data);
    reset_projected_name_state(state, height);
    state.expired = true;
    state.resource_data = resource;
    state
        .encode()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(true)
}

fn embedded_name_lifecycle(
    state: &NameState,
    height: u32,
    parameters: EmbeddedNameParameters,
) -> HnsNameLifecycle {
    if state.revoked.get() != 0 {
        return HnsNameLifecycle::Revoked;
    }
    if state.claimed.get() != 0 {
        if height < state.height.get().saturating_add(parameters.lockup_period) {
            return HnsNameLifecycle::Locked;
        }
        return HnsNameLifecycle::Closed;
    }
    let open_period = parameters.tree_interval.saturating_add(1);
    if height < state.height.get().saturating_add(open_period) {
        HnsNameLifecycle::Opening
    } else if height
        < state
            .height
            .get()
            .saturating_add(open_period)
            .saturating_add(parameters.bidding_period)
    {
        HnsNameLifecycle::Bidding
    } else if height
        < state
            .height
            .get()
            .saturating_add(open_period)
            .saturating_add(parameters.bidding_period)
            .saturating_add(parameters.reveal_period)
    {
        HnsNameLifecycle::Reveal
    } else {
        HnsNameLifecycle::Closed
    }
}

fn embedded_name_is_expired(
    state: &NameState,
    height: u32,
    parameters: EmbeddedNameParameters,
) -> bool {
    if state.revoked.get() != 0 {
        return height
            >= state
                .revoked
                .get()
                .saturating_add(parameters.auction_maturity);
    }
    if embedded_name_lifecycle(state, height, parameters) != HnsNameLifecycle::Closed {
        return false;
    }
    let claimable =
        state.claimed.get() != 0 && !parameters.no_reserved && height < parameters.claim_period;
    if claimable {
        return false;
    }
    height
        >= state
            .renewal
            .get()
            .saturating_add(parameters.renewal_window)
        || state.owner.is_null()
}

fn embedded_covenant_u32(
    covenant: &hns_covenants::Covenant,
    index: usize,
) -> Result<u32, HnsWalletError> {
    covenant
        .items
        .get(index)
        .and_then(|item| item.as_slice().try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(HnsWalletError::InvalidEvidence)
}

fn embedded_covenant_u8(
    covenant: &hns_covenants::Covenant,
    index: usize,
) -> Result<u8, HnsWalletError> {
    covenant
        .items
        .get(index)
        .and_then(|item| (item.len() == 1).then_some(item[0]))
        .ok_or(HnsWalletError::InvalidEvidence)
}

const fn embedded_name_parameters(
    network: hns_header_consensus::Network,
) -> EmbeddedNameParameters {
    match network {
        hns_header_consensus::Network::Mainnet => EmbeddedNameParameters {
            lockup_period: 4_320,
            renewal_window: 105_120,
            renewal_period: 26_208,
            renewal_maturity: 4_320,
            claim_period: 210_240,
            bidding_period: 720,
            reveal_period: 1_440,
            tree_interval: 36,
            transfer_lockup: 288,
            auction_maturity: 4_176,
            no_reserved: false,
        },
        hns_header_consensus::Network::Testnet => EmbeddedNameParameters {
            lockup_period: 36,
            renewal_window: 4_320,
            renewal_period: 1_008,
            renewal_maturity: 144,
            claim_period: 12_960,
            bidding_period: 144,
            reveal_period: 288,
            tree_interval: 36,
            transfer_lockup: 288,
            auction_maturity: 1_008,
            no_reserved: false,
        },
        hns_header_consensus::Network::Regtest => EmbeddedNameParameters {
            lockup_period: 2,
            renewal_window: 5_000,
            renewal_period: 2_500,
            renewal_maturity: 50,
            claim_period: 250_000,
            bidding_period: 5,
            reveal_period: 10,
            tree_interval: 5,
            transfer_lockup: 10,
            auction_maturity: 65,
            no_reserved: false,
        },
        hns_header_consensus::Network::Simnet => EmbeddedNameParameters {
            lockup_period: 1,
            renewal_window: 2_500,
            renewal_period: 1_250,
            renewal_maturity: 25,
            claim_period: 75_000,
            bidding_period: 25,
            reveal_period: 50,
            tree_interval: 2,
            transfer_lockup: 5,
            auction_maturity: 100,
            no_reserved: false,
        },
    }
}

const fn wallet_network(network: hns_header_consensus::Network) -> HnsNetwork {
    match network {
        hns_header_consensus::Network::Mainnet => HnsNetwork::Mainnet,
        hns_header_consensus::Network::Testnet => HnsNetwork::Testnet,
        hns_header_consensus::Network::Regtest => HnsNetwork::Regtest,
        hns_header_consensus::Network::Simnet => HnsNetwork::Simnet,
    }
}

fn embedded_name_action_context(
    state: &EmbeddedState,
    action: HnsNameAction,
    name_hash: [u8; 32],
    binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
    pruning_safe: bool,
) -> Result<NameActionContextEvidence, HnsWalletError> {
    let mempool = mempool_binding(&state.mempool);
    if mempool != expected_mempool {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let view = embedded_name_view(state, name_hash, binding)?;
    let current = view
        .current
        .as_ref()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let current_raw = view
        .current_raw
        .clone()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let owner = view
        .current_owner
        .as_ref()
        .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)?;
    let active_owner = active_name_owner_coin(&view, binding)?;
    let owner_coin = active_owner.owner_coin;
    let candidate_height = u32::try_from(
        binding
            .tip
            .height
            .checked_add(1)
            .ok_or(HnsWalletError::Arithmetic)?,
    )
    .map_err(|_| HnsWalletError::Arithmetic)?;
    let parameters = embedded_name_parameters(state.authority.consensus_network());
    let lifecycle = embedded_name_lifecycle(current, candidate_height, parameters);
    let expired = embedded_name_is_expired(current, candidate_height, parameters);
    let mempool_spender = embedded_mempool_spender(&state.mempool, owner.outpoint)?;
    let owner_kind = owner.output.covenant.kind;
    let mut reasons = Vec::new();
    if !current.registered {
        reasons.push(NameActionIneligibility::NameNotRegistered);
    }
    if expired {
        reasons.push(NameActionIneligibility::NameExpiredAtCandidate);
    }
    if lifecycle != HnsNameLifecycle::Closed {
        reasons.push(NameActionIneligibility::LifecycleNotClosed);
    }

    let mut transfer_height = None;
    let mut transfer_lockup = None;
    let mut finalize_eligible_height = None;
    let mut finalize_mature = None;
    let mut renewal_maturity = None;
    let mut renewal_period = None;
    let mut renewal_block_height = None;
    let mut renewal_block_hash = None;
    let mut renewal_valid_at_candidate = None;
    match action {
        HnsNameAction::Transfer | HnsNameAction::Update => {
            if current.transfer.get() != 0 {
                reasons.push(NameActionIneligibility::TransferAlreadyPending);
            }
            if !matches!(
                owner_kind,
                CovenantKind::Register
                    | CovenantKind::Update
                    | CovenantKind::Renew
                    | CovenantKind::Finalize
            ) {
                reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
        }
        HnsNameAction::Finalize => {
            let transfer = current.transfer.get();
            let eligible = transfer
                .checked_add(parameters.transfer_lockup)
                .ok_or(HnsWalletError::Arithmetic)?;
            let mature = transfer != 0 && candidate_height >= eligible;
            let selected_height = u32::try_from(binding.tip.height)
                .map_err(|_| HnsWalletError::Arithmetic)?
                .saturating_sub(parameters.renewal_maturity.saturating_mul(2));
            let selected_hash = embedded_block_hash(state, selected_height)?;
            let renewal_valid = candidate_height < parameters.renewal_maturity
                || (selected_height
                    <= candidate_height.saturating_sub(parameters.renewal_maturity)
                    && selected_height
                        >= candidate_height.saturating_sub(parameters.renewal_period));
            transfer_height = Some(u64::from(transfer));
            transfer_lockup = Some(parameters.transfer_lockup);
            finalize_eligible_height = Some(u64::from(eligible));
            finalize_mature = Some(mature);
            renewal_maturity = Some(parameters.renewal_maturity);
            renewal_period = Some(parameters.renewal_period);
            renewal_block_height = Some(u64::from(selected_height));
            renewal_block_hash = Some(selected_hash);
            renewal_valid_at_candidate = Some(renewal_valid);
            if transfer == 0 {
                reasons.push(NameActionIneligibility::TransferNotPending);
            } else if !mature {
                reasons.push(NameActionIneligibility::TransferNotMature);
            }
            if owner_kind != CovenantKind::Transfer {
                reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
            if !renewal_valid {
                reasons.push(NameActionIneligibility::RenewalCommitmentInvalid);
            }
        }
    }
    if mempool_spender.is_some() {
        reasons.push(NameActionIneligibility::OwnerSpentInMempool);
    }
    let network = wallet_network(state.authority.consensus_network());
    let (network_id, genesis_hash) = crate::name_workflow::expected_chain_identity(network)?;
    let (owner_transaction, owner_coin) = if pruning_safe {
        (
            Vec::new(),
            Some(HnsInputCoinEvidence::from_canonical_coin(&owner_coin)?),
        )
    } else {
        (owner.transaction.clone(), None)
    };
    Ok(NameActionContextEvidence {
        binding,
        mempool,
        network,
        network_id,
        genesis_hash,
        context_version: if pruning_safe {
            crate::name_workflow::NAME_ACTION_CONTEXT_V2_VERSION
        } else {
            crate::name_workflow::NAME_ACTION_CONTEXT_VERSION
        },
        consensus_profile: crate::name_workflow::NAME_ACTION_CONSENSUS_PROFILE.to_owned(),
        action,
        name_hash,
        current_state: current_raw,
        owner_outpoint: owner.outpoint,
        owner_transaction,
        owner_coin,
        owner_coin_source_binding: pruning_safe
            .then_some(ActiveNameOwnerCoinSourceBinding::LocallyVerifiedFilteredBlock),
        owner_inclusion: owner.inclusion,
        candidate_inclusion_height: u64::from(candidate_height),
        lifecycle,
        action_eligible: reasons.is_empty(),
        ineligibility_reasons: reasons,
        transfer_height,
        transfer_lockup,
        finalize_eligible_height,
        finalize_mature,
        renewal_maturity,
        renewal_period,
        renewal_block_height,
        renewal_block_hash,
        renewal_valid_at_candidate,
        mempool_spender,
    })
}

fn embedded_mempool_spender(
    mempool: &EmbeddedMempool,
    owner: crate::HnsOutpoint,
) -> Result<Option<TransactionHash>, HnsWalletError> {
    let owner = Outpoint {
        transaction_hash: hns_primitives::TransactionHash::new(owner.transaction.into_bytes()),
        index: owner.output_index,
    };
    let mut spender = None;
    for (txid, transaction) in &mempool.transactions {
        if transaction
            .transaction
            .inputs
            .iter()
            .any(|input| input.previous_output == owner)
            && spender.replace(TransactionHash::new(*txid)).is_some()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(spender)
}

fn embedded_block_hash(state: &EmbeddedState, height: u32) -> Result<[u8; 32], HnsWalletError> {
    if height == 0 {
        return Ok(state
            .authority
            .consensus_network()
            .parameters()
            .genesis_hash
            .into_bytes());
    }
    state
        .authority
        .archived_header(height)
        .map_err(map_authority_error)?
        .map(|header| header.block_hash().into_bytes())
        .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)
}

fn wallet_fee_rate(state: &EmbeddedState) -> (u64, usize) {
    let mut rates = state.peer_fee_rates.values().copied().collect::<Vec<_>>();
    let network_default = normal_wallet_fee_rate(state.authority.consensus_network());
    if rates.is_empty() {
        return (network_default, 0);
    }
    rates.sort_unstable();
    let lower_median = rates[(rates.len() - 1) / 2];
    (
        lower_median
            .max(MINIMUM_RELAY_FEE_RATE)
            .max(network_default),
        rates.len(),
    )
}

const fn normal_wallet_fee_rate(network: hns_header_consensus::Network) -> u64 {
    match network {
        hns_header_consensus::Network::Mainnet => MAINNET_NORMAL_FEE_RATE,
        hns_header_consensus::Network::Testnet
        | hns_header_consensus::Network::Regtest
        | hns_header_consensus::Network::Simnet => TEST_NETWORK_NORMAL_FEE_RATE,
    }
}

fn mempool_transaction_relevant(
    state: &EmbeddedState,
    transaction: &Transaction,
) -> Result<bool, HnsWalletError> {
    if transaction.is_coinbase() || transaction.inputs.is_empty() || transaction.outputs.is_empty()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut unique_inputs = HashSet::with_capacity(transaction.inputs.len());
    if transaction.inputs.iter().any(|input| {
        input.previous_output.is_null() || !unique_inputs.insert(input.previous_output)
    }) {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let observations = state.index.transactions().map_err(map_index_error)?;
    let confirmed = confirmed_spends(&observations)?;
    if transaction
        .inputs
        .iter()
        .any(|input| confirmed.contains_key(&input.previous_output))
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let txid = transaction
        .transaction_hash()
        .map_err(|_| HnsWalletError::InvalidEvidence)?
        .into_bytes();
    if state
        .mempool
        .transactions
        .iter()
        .any(|(candidate_txid, candidate)| {
            *candidate_txid != txid
                && candidate.transaction.inputs.iter().any(|input| {
                    transaction
                        .inputs
                        .iter()
                        .any(|current| current.previous_output == input.previous_output)
                })
        })
    {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let watched_scripts = state
        .index
        .watch_set()
        .scripts
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let watched_names = state
        .index
        .watch_set()
        .name_hashes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut watched_outpoints = HashSet::new();
    for observation in &observations {
        add_watched_outputs(
            &observation.transaction,
            hns_primitives::TransactionHash::new(observation.txid.into_bytes()),
            &watched_scripts,
            &mut watched_outpoints,
        )
        .map_err(map_index_error)?;
    }
    for (candidate_txid, candidate) in &state.mempool.transactions {
        add_watched_outputs(
            &candidate.transaction,
            hns_primitives::TransactionHash::new(*candidate_txid),
            &watched_scripts,
            &mut watched_outpoints,
        )
        .map_err(map_index_error)?;
    }
    Ok(transaction_relevant(
        transaction,
        &watched_scripts,
        &watched_names,
        &watched_outpoints,
    ))
}

fn confirmed_rows(
    observations: &[VerifiedHnsTransactionObservation],
    scripts: &[WalletAddressKey],
    tip_height: u64,
) -> Result<Vec<ConfirmedRow>, HnsWalletError> {
    let script_indices = script_indices(scripts)?;
    let outputs = transaction_outputs(observations)?;
    let confirmed_spends = confirmed_spends(observations)?;
    let mut rows = Vec::new();
    for observation in observations {
        let mut touched = BTreeMap::<u32, bool>::new();
        for output in &observation.transaction.outputs {
            if let Some(index) = script_indices.get(&WalletAddressKey {
                version: output.address.version,
                hash: output.address.hash.clone(),
            }) {
                touched.entry(*index).or_insert(false);
            }
        }
        for input in &observation.transaction.inputs {
            if let Some((_, output)) = outputs.get(&input.previous_output)
                && let Some(index) = script_indices.get(&WalletAddressKey {
                    version: output.address.version,
                    hash: output.address.hash.clone(),
                })
            {
                touched.insert(*index, true);
            }
        }
        for (script_index, spent) in touched {
            rows.push(ConfirmedRow::History(HistoryEntry {
                txid: observation.txid,
                height: Some(u64::from(observation.height)),
                block_hash: Some(observation.block_hash),
                transaction_position: Some(observation.transaction_index),
                spent,
                first_seen_unix: Some(observation.block_time),
                script_index,
            }));
        }

        let txid = hns_primitives::TransactionHash::new(observation.txid.into_bytes());
        for (output_index, output) in observation.transaction.outputs.iter().enumerate() {
            let key = WalletAddressKey {
                version: output.address.version,
                hash: output.address.hash.clone(),
            };
            let Some(script_index) = script_indices.get(&key).copied() else {
                continue;
            };
            let output_index =
                u32::try_from(output_index).map_err(|_| HnsWalletError::InvalidEvidence)?;
            let outpoint = Outpoint {
                transaction_hash: txid,
                index: output_index,
            };
            if confirmed_spends.contains_key(&outpoint) {
                continue;
            }
            let confirmation_count = confirmation_count(tip_height, observation.height)?;
            rows.push(ConfirmedRow::Coin(IndexedWalletCoin {
                coin: WalletCoin {
                    outpoint: crate::HnsOutpoint {
                        transaction: observation.txid,
                        output_index,
                    },
                    value: BaseUnits::new(u128::from(output.value.get())),
                    confirmation_count,
                    confirmed_height: Some(observation.height),
                    coinbase: observation.coinbase,
                    covenant: output
                        .covenant
                        .encode()
                        .map_err(|_| HnsWalletError::InvalidEvidence)?,
                    name_locked: output.covenant.kind != CovenantKind::None,
                },
                script_index,
                output_address: key,
            }));
        }
    }
    rows.sort_by_key(confirmed_row_key);
    if rows.len() > MAX_HISTORY_RESULTS.saturating_add(crate::MAX_WALLET_COINS) {
        return Err(HnsWalletError::HistoryLimit);
    }
    Ok(rows)
}

fn confirmed_row_key(row: &ConfirmedRow) -> (u8, [u8; 32], u32, u32) {
    match row {
        ConfirmedRow::History(entry) => (0, entry.txid.into_bytes(), entry.script_index, 0),
        ConfirmedRow::Coin(coin) => (
            1,
            coin.coin.outpoint.transaction.into_bytes(),
            coin.coin.outpoint.output_index,
            coin.script_index,
        ),
    }
}

fn mempool_history(
    observations: &[VerifiedHnsTransactionObservation],
    mempool: &EmbeddedMempool,
    scripts: &[WalletAddressKey],
) -> Result<Vec<HistoryEntry>, HnsWalletError> {
    let script_indices = script_indices(scripts)?;
    let mut outputs = transaction_outputs(observations)?;
    for (txid, item) in &mempool.transactions {
        let canonical = hns_primitives::TransactionHash::new(*txid);
        for (index, output) in item.transaction.outputs.iter().enumerate() {
            outputs.insert(
                Outpoint {
                    transaction_hash: canonical,
                    index: u32::try_from(index).map_err(|_| HnsWalletError::InvalidEvidence)?,
                },
                (None, output.clone()),
            );
        }
    }
    let mut history = Vec::new();
    for (txid, item) in &mempool.transactions {
        let mut touched = BTreeMap::<u32, bool>::new();
        for output in &item.transaction.outputs {
            if let Some(index) = script_indices.get(&WalletAddressKey {
                version: output.address.version,
                hash: output.address.hash.clone(),
            }) {
                touched.entry(*index).or_insert(false);
            }
        }
        for input in &item.transaction.inputs {
            if let Some((_, output)) = outputs.get(&input.previous_output)
                && let Some(index) = script_indices.get(&WalletAddressKey {
                    version: output.address.version,
                    hash: output.address.hash.clone(),
                })
            {
                touched.insert(*index, true);
            }
        }
        for (script_index, spent) in touched {
            history.push(HistoryEntry {
                txid: TransactionHash::new(*txid),
                height: None,
                block_hash: None,
                transaction_position: None,
                spent,
                first_seen_unix: Some(item.first_seen_unix),
                script_index,
            });
        }
    }
    history.sort_by_key(|entry| (entry.txid, entry.script_index));
    if history.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    Ok(history)
}

fn incoming_transfers(
    observations: &[VerifiedHnsTransactionObservation],
    scripts: &[WalletAddressKey],
) -> Result<Vec<IncomingTransferCandidate>, HnsWalletError> {
    let script_indices = script_indices(scripts)?;
    let confirmed_spends = confirmed_spends(observations)?;
    let mut entries = Vec::new();
    for observation in observations {
        let txid = hns_primitives::TransactionHash::new(observation.txid.into_bytes());
        for (output_index, output) in observation.transaction.outputs.iter().enumerate() {
            if output.covenant.kind != CovenantKind::Transfer {
                continue;
            }
            let transfer = TransferCovenant::try_from(&output.covenant)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
            let recipient = WalletAddressKey {
                version: transfer.recipient_version,
                hash: transfer.recipient_hash,
            };
            let Some(script_index) = script_indices.get(&recipient).copied() else {
                continue;
            };
            let output_index =
                u32::try_from(output_index).map_err(|_| HnsWalletError::InvalidEvidence)?;
            let outpoint = Outpoint {
                transaction_hash: txid,
                index: output_index,
            };
            if confirmed_spends.contains_key(&outpoint) {
                continue;
            }
            entries.push(IncomingTransferCandidate {
                script_index,
                recipient,
                name_hash: transfer.name_hash.into_bytes(),
                start_height: transfer.start_height.get(),
                transfer_coin: Coin {
                    outpoint,
                    value: output.value,
                    height: Height::new(observation.height),
                    coinbase: observation.coinbase,
                    address: output.address.clone(),
                    covenant: output.covenant.clone(),
                },
                inclusion: inclusion(observation),
                source_output_count: u32::try_from(observation.transaction.outputs.len())
                    .map_err(|_| HnsWalletError::InvalidEvidence)?,
                source_binding: IncomingTransferSourceBinding::RetainedBodyVerified,
            });
        }
    }
    entries.sort_by_key(|entry| {
        (
            entry.inclusion.height,
            entry.inclusion.transaction_index,
            entry.transfer_coin.outpoint.index,
        )
    });
    Ok(entries)
}

fn script_indices(
    scripts: &[WalletAddressKey],
) -> Result<BTreeMap<WalletAddressKey, u32>, HnsWalletError> {
    scripts
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, script)| {
            u32::try_from(index)
                .map(|index| (script, index))
                .map_err(|_| HnsWalletError::InvalidEvidence)
        })
        .collect()
}

fn transaction_outputs(
    observations: &[VerifiedHnsTransactionObservation],
) -> Result<HashMap<Outpoint, (Option<usize>, hns_transaction::Output)>, HnsWalletError> {
    let mut outputs = HashMap::new();
    for (observation_index, observation) in observations.iter().enumerate() {
        let txid = hns_primitives::TransactionHash::new(observation.txid.into_bytes());
        for (output_index, output) in observation.transaction.outputs.iter().enumerate() {
            let outpoint = Outpoint {
                transaction_hash: txid,
                index: u32::try_from(output_index).map_err(|_| HnsWalletError::InvalidEvidence)?,
            };
            if outputs
                .insert(outpoint, (Some(observation_index), output.clone()))
                .is_some()
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
    }
    Ok(outputs)
}

fn confirmed_spends(
    observations: &[VerifiedHnsTransactionObservation],
) -> Result<HashMap<Outpoint, SpendingTransactionEvidence>, HnsWalletError> {
    let mut spends = HashMap::new();
    for observation in observations {
        for (input_position, input) in observation.transaction.inputs.iter().enumerate() {
            if input.previous_output.is_null() {
                continue;
            }
            let evidence = SpendingTransactionEvidence {
                transaction: observation.txid,
                input_position: u32::try_from(input_position)
                    .map_err(|_| HnsWalletError::InvalidEvidence)?,
                block_hash: observation.block_hash,
                height: u64::from(observation.height),
            };
            if spends.insert(input.previous_output, evidence).is_some() {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
    }
    Ok(spends)
}

fn mempool_transaction_conflicted(
    txid: [u8; 32],
    transaction: &Transaction,
    confirmed: &[VerifiedHnsTransactionObservation],
    mempool: &EmbeddedMempool,
) -> Result<bool, HnsWalletError> {
    let confirmed_spends = confirmed_spends(confirmed)?;
    for input in &transaction.inputs {
        if input.previous_output.is_null() {
            continue;
        }
        if confirmed_spends.contains_key(&input.previous_output) {
            return Ok(true);
        }
        if mempool.transactions.iter().any(|(other_txid, other)| {
            *other_txid != txid
                && other
                    .transaction
                    .inputs
                    .iter()
                    .any(|candidate| candidate.previous_output == input.previous_output)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn confirmation_count(tip_height: u64, height: u32) -> Result<u32, HnsWalletError> {
    tip_height
        .checked_sub(u64::from(height))
        .and_then(|depth| depth.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(HnsWalletError::InvalidEvidence)
}

fn inclusion(observation: &VerifiedHnsTransactionObservation) -> TransactionInclusion {
    TransactionInclusion {
        block_hash: observation.block_hash,
        height: u64::from(observation.height),
        transaction_index: Some(observation.transaction_index),
    }
}

fn mempool_binding(mempool: &EmbeddedMempool) -> MempoolSnapshotBinding {
    MempoolSnapshotBinding {
        instance_nonce: mempool.instance_nonce,
        generation: mempool.generation,
    }
}

fn admit_mempool(
    mempool: &mut EmbeddedMempool,
    txid: [u8; 32],
    transaction: Transaction,
    raw: Vec<u8>,
    first_seen_unix: u64,
) -> Result<(), HnsWalletError> {
    if mempool.transactions.len() >= MAX_MEMPOOL_SCAN_RESULTS
        && !mempool.transactions.contains_key(&txid)
    {
        return Err(HnsWalletError::HistoryLimit);
    }
    if let Some(existing) = mempool.transactions.get(&txid) {
        if existing.raw == raw {
            return Ok(());
        }
        return Err(HnsWalletError::InvalidEvidence);
    }
    mempool.transactions.insert(
        txid,
        MempoolTransaction {
            transaction,
            raw,
            first_seen_unix,
        },
    );
    advance_mempool_generation(mempool)
}

fn advance_mempool_generation(mempool: &mut EmbeddedMempool) -> Result<(), HnsWalletError> {
    mempool.generation = mempool
        .generation
        .checked_add(1)
        .ok_or(HnsWalletError::Arithmetic)?;
    Ok(())
}

fn cursor_digest(
    scope: &[u8],
    scripts: &[WalletAddressKey],
    binding: SnapshotBinding,
    mempool: Option<MempoolSnapshotBinding>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CURSOR_DOMAIN);
    hasher.update((scope.len() as u64).to_be_bytes());
    hasher.update(scope);
    hasher.update(binding.tip.height.to_be_bytes());
    hasher.update(binding.tip.block_hash);
    hasher.update(binding.chain_epoch.to_be_bytes());
    if let Some(mempool) = mempool {
        hasher.update(mempool.instance_nonce);
        hasher.update(mempool.generation.to_be_bytes());
    }
    for script in scripts {
        hasher.update([script.version]);
        hasher.update((script.hash.len() as u64).to_be_bytes());
        hasher.update(&script.hash);
    }
    hasher.finalize().into()
}

fn encode_cursor(digest: [u8; 32], offset: usize) -> Vec<u8> {
    let mut cursor = Vec::with_capacity(CURSOR_BYTES);
    cursor.extend_from_slice(&digest);
    cursor.extend_from_slice(&u32::try_from(offset).unwrap_or(u32::MAX).to_be_bytes());
    cursor
}

fn decode_cursor(
    cursor: Option<&[u8]>,
    expected_digest: [u8; 32],
    row_count: usize,
) -> Result<usize, HnsWalletError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    if cursor.len() != CURSOR_BYTES || cursor[..32] != expected_digest {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let offset = u32::from_be_bytes(
        cursor[32..]
            .try_into()
            .map_err(|_| HnsWalletError::StaleNodeSnapshot)?,
    ) as usize;
    if offset == 0 || offset >= row_count {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(offset)
}

fn map_authority_error(error: impl std::fmt::Display) -> HnsWalletError {
    HnsWalletError::Backend(format!("embedded HNS header authority failed: {error}"))
}

/// Preserve bounded header-quorum availability states across the embedded
/// authority boundary. These are not evidence failures: no unagreed header is
/// persisted, and callers must continue to withhold wallet projections until a
/// later independent peer round succeeds.
fn map_header_round_error(error: crate::HnsLightError) -> HnsWalletError {
    match error {
        crate::HnsLightError::Sync(SyncError::InsufficientResponses) => {
            HnsWalletError::HeaderRoundInsufficientResponses
        }
        crate::HnsLightError::Sync(SyncError::InsufficientAgreement) => {
            HnsWalletError::HeaderRoundInsufficientAgreement
        }
        error => map_authority_error(error),
    }
}

fn map_index_error(error: impl std::fmt::Display) -> HnsWalletError {
    HnsWalletError::Backend(format!("embedded HNS wallet index failed: {error}"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic fixtures"
)]
mod tests {
    use blake2::Blake2b;
    use blake2::digest::{Digest as BlakeDigest, consts::U32};
    use hns_covenants::{Covenant, TransferCovenant, hash_name};
    use hns_header_consensus::Network;
    use hns_light_chain::{ChainLimits, LightChain};
    use hns_light_sync::SyncConfig;
    use hns_light_wallet::WalletBlockEvidence;
    use hns_primitives::{BlockTime, Dollarydoos, MerkleRoot, TreeRoot};
    use hns_transaction::{Address, Input, Output, Witness};
    use hns_wallet_store::{SharedWalletStore, WalletStore};
    use hns_wallet_types::AccountId;

    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[derive(Default)]
    struct RecordingNetwork {
        broadcasts: Mutex<Vec<Vec<u8>>>,
    }

    impl HnsLightNetwork for RecordingNetwork {
        fn broadcast_transaction(&self, raw: &[u8]) -> Result<usize, HnsWalletError> {
            self.broadcasts
                .lock()
                .map_err(|_| HnsWalletError::RuntimePoisoned)?
                .push(raw.to_vec());
            Ok(1)
        }
    }

    fn store() -> SharedWalletStore {
        SharedWalletStore::new(WalletStore::create(":memory:", PASSPHRASE).unwrap())
    }

    #[test]
    fn header_round_peer_agreement_failure_remains_typed() {
        assert!(matches!(
            map_header_round_error(crate::HnsLightError::Sync(SyncError::InsufficientAgreement)),
            HnsWalletError::HeaderRoundInsufficientAgreement
        ));
        assert!(matches!(
            map_header_round_error(crate::HnsLightError::Sync(SyncError::InsufficientResponses)),
            HnsWalletError::HeaderRoundInsufficientResponses
        ));
    }

    fn transaction(previous_output: Outpoint, program: Vec<u8>, value: u64) -> Transaction {
        Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(value),
                address: Address::new(0, program).unwrap(),
                covenant: Covenant::default(),
            }],
            locktime: 0,
        }
    }

    fn verified_block(transaction: Transaction) -> (VerifiedWalletBlock, Header) {
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

    fn verified_block_on_chain(
        chain: &mut LightChain,
        transaction: Transaction,
        tree_root: TreeRoot,
        matched: bool,
        now: BlockTime,
    ) -> (VerifiedWalletBlock, Header) {
        let txid = transaction.transaction_hash().unwrap();
        let mut leaf = Blake2b::<U32>::new();
        BlakeDigest::update(&mut leaf, [0]);
        BlakeDigest::update(&mut leaf, txid.as_bytes());
        let merkle_root = MerkleRoot::new(leaf.finalize().into());
        let mut header = Header {
            time: BlockTime::new(chain.tip().time().get() + 1),
            previous_block: chain.tip().hash(),
            tree_root,
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
        if matched {
            payload.extend_from_slice(txid.as_bytes());
        } else {
            payload.extend_from_slice(merkle_root.as_bytes());
        }
        payload.extend_from_slice(&[1, u8::from(matched)]);
        let mut collector = WalletBlockEvidence::decode_for_header(&payload, entry)
            .unwrap()
            .collect()
            .unwrap();
        if matched {
            collector.admit(transaction).unwrap();
        }
        (collector.finish().unwrap(), header)
    }

    fn inclusion_proof(value: &[u8]) -> hns_urkel_proof::HsdUrkelProof {
        let mut raw = Vec::with_capacity(value.len() + 6);
        raw.extend_from_slice(&(3_u16 << 14).to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(value);
        hns_urkel_proof::HsdUrkelProof::decode_strict(&raw).unwrap()
    }

    fn inclusion_root(key: &[u8; 32], value: &[u8]) -> TreeRoot {
        let mut value_hasher = Blake2b::<U32>::new();
        BlakeDigest::update(&mut value_hasher, value);
        let value_hash: [u8; 32] = value_hasher.finalize().into();
        let mut leaf = Blake2b::<U32>::new();
        BlakeDigest::update(&mut leaf, [0]);
        BlakeDigest::update(&mut leaf, key);
        BlakeDigest::update(&mut leaf, value_hash);
        TreeRoot::new(leaf.finalize().into())
    }

    #[test]
    fn verified_chain_drives_wallet_reads_fee_policy_and_direct_broadcast() {
        let store = store();
        let account = AccountId::new([21; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let authority = EncryptedHnsLightAuthority::open_or_create(
            store.clone(),
            account,
            crate::HnsNetwork::Regtest,
            0,
            crate::HnsLightFloor::default(),
            BlockTime::new(now),
            ChainLimits::default(),
            SyncConfig {
                max_peers: 4,
                minimum_peer_agreement: 1,
                round_timeout_seconds: 10,
                max_peer_failures: 3,
            },
        )
        .unwrap();
        let index = EncryptedHnsLightIndex::open_or_create(
            store,
            account,
            crate::HnsNetwork::Regtest,
            1,
            now,
        )
        .unwrap();
        let network = Arc::new(RecordingNetwork::default());
        let backend = EmbeddedHnsBackend::new(authority, index, network.clone()).unwrap();
        let watched_program = vec![7; 20];
        let scripts = vec![WalletAddressKey {
            version: 0,
            hash: watched_program.clone(),
        }];
        backend
            .install_watch_set(
                HnsLightWatchSet::new(scripts.clone(), Vec::new()).unwrap(),
                now,
            )
            .unwrap();

        let funding = transaction(Outpoint::NULL, watched_program, 42_000);
        let funding_txid = funding.transaction_hash().unwrap();
        let (block, header) = verified_block(funding.clone());
        let peer_one = PeerId::new([1; 32]);
        let peer_two = PeerId::new([2; 32]);
        backend.add_header_peer(peer_one, 1).unwrap();
        backend.add_header_peer(peer_two, 1).unwrap();
        backend.observe_peer_fee_rate(peer_one, 9_000).unwrap();
        backend.observe_peer_fee_rate(peer_two, 2_000).unwrap();
        let request = backend.begin_header_round(&[peer_one], now).unwrap();
        backend
            .submit_header_response(request.generation, peer_one, vec![header], now)
            .unwrap();
        backend.finish_header_round(now).unwrap();
        let anchor = backend.wallet_header_anchor(1).unwrap();
        assert_eq!(anchor.height(), Height::new(1));
        assert_eq!(anchor.hash(), block.evidence().header().hash());
        let current_request = backend.begin_header_round(&[peer_one], now).unwrap();
        backend
            .submit_header_response(current_request.generation, peer_one, Vec::new(), now)
            .unwrap();
        backend.finish_header_round(now).unwrap();
        assert!(matches!(
            backend.get_chain_snapshot(),
            Err(HnsWalletError::Backend(message))
                if message == "direct wallet index is not aligned with the authenticated header tip"
        ));

        assert_eq!(backend.apply_verified_block(&block, now).unwrap(), 1);
        let bloom_elements = backend.light_bloom_elements().unwrap();
        assert!(bloom_elements.contains(&scripts[0].hash));
        assert!(
            bloom_elements.contains(
                &Outpoint {
                    transaction_hash: funding_txid,
                    index: 0,
                }
                .encode()
                .to_vec()
            )
        );
        let binding = backend.get_chain_snapshot().unwrap();
        assert_eq!(binding.tip.height, 1);
        assert_eq!(
            backend.get_block_hash(1, binding).unwrap().block_hash,
            Some(binding.tip.block_hash)
        );
        let confirmed = backend
            .get_confirmed_wallet_page(ConfirmedWalletPageRequest {
                scripts: &scripts,
                expected_tip: binding.tip,
                expected_epoch: Some(binding.chain_epoch),
                cursor: None,
                limit: 256,
            })
            .unwrap();
        assert_eq!(confirmed.history.len(), 1);
        assert_eq!(confirmed.utxos.len(), 1);
        assert_eq!(confirmed.utxos[0].coin.value, BaseUnits::new(42_000));

        let irrelevant = transaction(
            Outpoint {
                transaction_hash: hns_primitives::TransactionHash::new([8; 32]),
                index: 0,
            },
            vec![9; 20],
            1,
        );
        assert_eq!(
            backend.admit_mempool_transaction(irrelevant, now).unwrap(),
            None
        );
        let before_broadcast = backend
            .get_mempool_wallet_page(MempoolWalletPageRequest {
                scripts: &scripts,
                binding,
                expected_mempool: None,
                cursor: None,
                limit: 1_024,
            })
            .unwrap();
        assert!(before_broadcast.history.is_empty());

        let funding_outpoint = Outpoint {
            transaction_hash: funding_txid,
            index: 0,
        };
        let spend = transaction(funding_outpoint, vec![10; 20], 40_000);
        let spend_raw = spend.encode().unwrap();
        let spend_txid = backend.broadcast_transaction(&spend_raw).unwrap();
        assert_eq!(
            network.broadcasts.lock().unwrap().as_slice(),
            std::slice::from_ref(&spend_raw)
        );
        let submitted = backend
            .get_mempool_wallet_page(MempoolWalletPageRequest {
                scripts: &scripts,
                binding,
                expected_mempool: None,
                cursor: None,
                limit: 1_024,
            })
            .unwrap();
        assert!(submitted.history.is_empty());
        assert_eq!(submitted.mempool, before_broadcast.mempool);
        let submitted_evidence = backend
            .get_transaction_evidence(spend_txid, binding, Some(submitted.mempool))
            .unwrap();
        assert!(!submitted_evidence.status.in_mempool);
        assert!(submitted_evidence.raw.is_none());

        assert_eq!(
            backend
                .admit_mempool_transaction(spend.clone(), now)
                .unwrap(),
            Some(spend_txid)
        );
        let mempool = backend
            .get_mempool_wallet_page(MempoolWalletPageRequest {
                scripts: &scripts,
                binding,
                expected_mempool: None,
                cursor: None,
                limit: 1_024,
            })
            .unwrap();
        assert_eq!(mempool.history.len(), 1);
        assert_eq!(mempool.history[0].txid, spend_txid);
        assert!(mempool.history[0].spent);
        assert_ne!(mempool.mempool, before_broadcast.mempool);
        assert!(matches!(
            backend.get_mempool_wallet_page(MempoolWalletPageRequest {
                scripts: &scripts,
                binding,
                expected_mempool: Some(before_broadcast.mempool),
                cursor: None,
                limit: 1_024,
            }),
            Err(HnsWalletError::StaleNodeSnapshot)
        ));

        let confirmed_after_broadcast = backend
            .get_confirmed_wallet_page(ConfirmedWalletPageRequest {
                scripts: &scripts,
                expected_tip: binding.tip,
                expected_epoch: Some(binding.chain_epoch),
                cursor: None,
                limit: 256,
            })
            .unwrap();
        assert_eq!(confirmed_after_broadcast.utxos.len(), 1);
        let evidence = backend
            .get_transaction_evidence(spend_txid, binding, Some(mempool.mempool))
            .unwrap();
        assert!(evidence.status.in_mempool);
        assert_eq!(evidence.raw, Some(spend_raw.clone()));

        let input_coin = Coin {
            outpoint: funding_outpoint,
            value: Dollarydoos::new(42_000),
            height: Height::new(1),
            coinbase: true,
            address: funding.outputs[0].address.clone(),
            covenant: Covenant::default(),
        };
        let quote = backend
            .quote_transaction_fee(
                &spend_raw,
                &[input_coin],
                DEFAULT_FEE_TARGET_BLOCKS,
                binding,
                mempool.mempool,
            )
            .unwrap();
        assert_eq!(quote.rate_atomic_units_per_1000_policy_vbytes, 20_000);
        assert_eq!(quote.rate_sample_count, 2);
        assert_eq!(quote.rate_source, HnsFeeRateSource::PeerRelay);
        assert_eq!(quote.actual_fee, BaseUnits::new(2_000));

        backend.remove_header_peer(peer_two).unwrap();
        assert_eq!(
            backend
                .estimate_fee_rate(DEFAULT_FEE_TARGET_BLOCKS)
                .unwrap(),
            BaseUnits::new(20_000)
        );
    }

    #[test]
    fn direct_wallet_fee_floor_matches_canonical_hsd_network_defaults() {
        assert_eq!(normal_wallet_fee_rate(Network::Mainnet), 100_000);
        assert_eq!(normal_wallet_fee_rate(Network::Testnet), 20_000);
        assert_eq!(normal_wallet_fee_rate(Network::Regtest), 20_000);
        assert_eq!(normal_wallet_fee_rate(Network::Simnet), 20_000);
    }

    #[test]
    fn historical_expiration_resource_flag_does_not_override_current_lifecycle() {
        let name = b"expired-wallet-name".to_vec();
        let name_hash = hash_name(&name).unwrap();
        let state = NameState {
            name_hash,
            name,
            height: Height::new(100),
            renewal: Height::new(100),
            owner: Outpoint {
                transaction_hash: hns_primitives::TransactionHash::new([21; 32]),
                index: 0,
            },
            value: Dollarydoos::new(900_000),
            highest: Dollarydoos::new(900_000),
            resource_data: Vec::new(),
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 0,
            registered: true,
            expired: true,
            weak: false,
        };
        let parameters = embedded_name_parameters(Network::Regtest);
        assert_eq!(
            embedded_name_lifecycle(&state, 101, parameters),
            HnsNameLifecycle::Opening
        );
        // HSD's `expired` bit says resource data survived an earlier expiration
        // reset. Current expiration is derived from the authenticated lifecycle
        // at the candidate height, so a re-registered name can retain this bit
        // without being currently expired.
        assert!(!embedded_name_is_expired(&state, 101, parameters));
    }

    #[test]
    fn agreed_urkel_state_and_verified_post_boundary_transfer_drive_name_actions() {
        let store = store();
        let account = AccountId::new([22; 16]);
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let authority = EncryptedHnsLightAuthority::open_or_create(
            store.clone(),
            account,
            crate::HnsNetwork::Regtest,
            1,
            crate::HnsLightFloor::default(),
            BlockTime::new(now),
            ChainLimits::default(),
            SyncConfig {
                max_peers: 4,
                minimum_peer_agreement: 1,
                round_timeout_seconds: 10,
                max_peer_failures: 3,
            },
        )
        .unwrap();
        let index = EncryptedHnsLightIndex::open_or_create(
            store,
            account,
            crate::HnsNetwork::Regtest,
            1,
            now,
        )
        .unwrap();
        let backend =
            EmbeddedHnsBackend::new(authority, index, Arc::new(RecordingNetwork::default()))
                .unwrap();

        let name = b"wallet-authority".to_vec();
        let name_hash = hash_name(&name).unwrap();
        backend
            .install_watch_set(
                HnsLightWatchSet::new(Vec::new(), vec![name_hash.into_bytes()]).unwrap(),
                now,
            )
            .unwrap();

        let update = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: hns_primitives::TransactionHash::new([31; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(900_000),
                address: Address::new(0, vec![32; 20]).unwrap(),
                covenant: Covenant {
                    kind: CovenantKind::Update,
                    items: vec![
                        name_hash.into_bytes().to_vec(),
                        1_u32.to_le_bytes().to_vec(),
                        Vec::new(),
                    ],
                },
            }],
            locktime: 0,
        };
        let update_txid = update.transaction_hash().unwrap();
        let mut proof_state = NameState {
            name_hash,
            name,
            height: Height::new(1),
            renewal: Height::new(1),
            owner: Outpoint {
                transaction_hash: update_txid,
                index: 0,
            },
            value: Dollarydoos::new(900_000),
            highest: Dollarydoos::new(900_000),
            resource_data: Vec::new(),
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(1),
            renewals: 0,
            registered: true,
            expired: false,
            weak: false,
        };
        let proof_state_raw = proof_state.encode().unwrap();
        let proof_root = inclusion_root(name_hash.as_bytes(), &proof_state_raw);
        let transfer = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: update_txid,
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: proof_state.value,
                address: update.outputs[0].address.clone(),
                covenant: TransferCovenant::new(name_hash, proof_state.height, 0, vec![33; 20])
                    .unwrap()
                    .to_covenant()
                    .unwrap(),
            }],
            locktime: 0,
        };
        let transfer_txid = transfer.transaction_hash().unwrap();

        let mut chain = LightChain::from_genesis(
            Network::Regtest,
            BlockTime::new(now),
            ChainLimits::default(),
        )
        .unwrap();
        let dummy = transaction(
            Outpoint {
                transaction_hash: hns_primitives::TransactionHash::new([34; 32]),
                index: 0,
            },
            vec![35; 20],
            1,
        );
        let mut blocks = Vec::new();
        let mut headers = Vec::new();
        for height in 1_u8..=6 {
            let (candidate, matched) = match height {
                3 => (update.clone(), true),
                6 => (transfer.clone(), true),
                _ => (dummy.clone(), false),
            };
            let tree_root = if height == 6 {
                proof_root
            } else {
                TreeRoot::new([height; 32])
            };
            let (block, header) = verified_block_on_chain(
                &mut chain,
                candidate,
                tree_root,
                matched,
                BlockTime::new(now),
            );
            blocks.push(block);
            headers.push(header);
        }

        let peer = PeerId::new([36; 32]);
        backend.add_header_peer(peer, 1).unwrap();
        let request = backend.begin_header_round(&[peer], now).unwrap();
        backend
            .submit_header_response(request.generation, peer, headers, now)
            .unwrap();
        backend.finish_header_round(now).unwrap();
        let current = backend.begin_header_round(&[peer], now).unwrap();
        backend
            .submit_header_response(current.generation, peer, Vec::new(), now)
            .unwrap();
        backend.finish_header_round(now).unwrap();
        for block in &blocks {
            backend.apply_verified_block(block, now).unwrap();
        }

        let request = backend.name_proof_request(name_hash.into_bytes()).unwrap();
        assert_eq!(request.root, proof_root);
        assert_eq!(request.key, name_hash);
        let packet = ProofPacket {
            root: request.root,
            key: request.key,
            proof: inclusion_proof(&proof_state_raw),
        };
        backend.admit_name_proof(&packet, now).unwrap();

        let binding = backend.get_chain_snapshot().unwrap();
        let evidence = backend
            .get_name_evidence(name_hash.into_bytes(), binding)
            .unwrap();
        assert_eq!(evidence.proof_state, Some(proof_state_raw));
        let current_state =
            NameState::decode(name_hash, evidence.current_state.as_deref().unwrap()).unwrap();
        proof_state.owner = Outpoint {
            transaction_hash: transfer_txid,
            index: 0,
        };
        proof_state.transfer = Height::new(6);
        assert_eq!(current_state, proof_state);
        assert_eq!(
            evidence.current_owner_outpoint.unwrap().transaction,
            TransactionHash::new(transfer_txid.into_bytes())
        );

        let owner = backend
            .get_active_name_owner_coin(name_hash.into_bytes(), binding)
            .unwrap();
        assert_eq!(
            owner.source_binding,
            ActiveNameOwnerCoinSourceBinding::LocallyVerifiedFilteredBlock
        );
        assert_eq!(owner.owner_coin.outpoint.transaction_hash, transfer_txid);
        assert_eq!(owner.inclusion.height, 6);
        assert_eq!(owner.inclusion.transaction_index, Some(0));

        let mempool = backend
            .get_transaction_evidence(
                TransactionHash::new(transfer_txid.into_bytes()),
                binding,
                None,
            )
            .unwrap()
            .mempool;
        let context = backend
            .get_name_action_context_v2(
                HnsNameAction::Finalize,
                name_hash.into_bytes(),
                binding,
                mempool,
            )
            .unwrap();
        assert_eq!(context.owner_transaction, Vec::<u8>::new());
        assert!(context.owner_coin.is_some());
        assert_eq!(
            context.owner_coin_source_binding,
            Some(ActiveNameOwnerCoinSourceBinding::LocallyVerifiedFilteredBlock)
        );
        assert_eq!(context.transfer_height, Some(6));
        assert_eq!(context.finalize_eligible_height, Some(16));
        assert_eq!(context.finalize_mature, Some(false));
        assert_eq!(
            context.ineligibility_reasons,
            vec![NameActionIneligibility::TransferNotMature]
        );
    }
}
