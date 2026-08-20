//! `HnsBackend` backed by wallet-owned verified headers and filtered blocks.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use hns_covenants::{CovenantKind, TransferCovenant};
use hns_header_consensus::Header;
use hns_light_sync::{HeaderRoundRequest, PeerId, SyncState};
use hns_light_wallet::VerifiedWalletBlock;
use hns_primitives::{Height, Outpoint};
use hns_transaction::{Coin, Transaction};
use hns_wallet_types::{BaseUnits, TransactionHash};
use sha2::{Digest, Sha256};

use crate::light_index::{add_watched_outputs, transaction_relevant};
use crate::{
    ActiveNameOwnerCoinEvidence, BlockHashEvidence, ChainTip, ConfirmedWalletPage,
    ConfirmedWalletPageRequest, DEFAULT_FEE_TARGET_BLOCKS, EncryptedHnsLightAuthority,
    EncryptedHnsLightIndex, HistoryEntry, HnsBackend, HnsFeeRateSource, HnsLightWatchSet,
    HnsNameAction, HnsTransactionFeeQuote, HnsWalletError, IncomingTransferCandidate,
    IncomingTransferSourceBinding, IncomingTransfersPage, IncomingTransfersPageRequest,
    IndexedWalletCoin, MAX_HISTORY_RESULTS, MAX_MEMPOOL_SCAN_RESULTS, MAX_OUTPOINT_SPEND_BATCH,
    MAX_SCAN_PAGE_RESULTS, MempoolSnapshotBinding, MempoolWalletPage, MempoolWalletPageRequest,
    NameActionContextEvidence, NameEvidence, OutpointSpendEntry, OutpointSpendEvidence,
    PersistedHeaderRound, SnapshotBinding, SpendingTransactionEvidence, TransactionEvidence,
    TransactionInclusion, TransactionStatus, VerifiedHnsTransactionObservation, WalletAddressKey,
    WalletCoin, actual_transaction_fee, local_fee_policy_evidence,
};

const MINIMUM_RELAY_FEE_RATE: u64 = 1_000;
const MAX_EMBEDDED_FEE_RATE: u64 = u32::MAX as u64;
const CURSOR_BYTES: usize = 36;
const CURSOR_DOMAIN: &[u8] = b"hns-wallet-rs/embedded-backend-cursor/v1";

/// Direct standard-peer network boundary used by the embedded backend.
///
/// Implementations succeed only after the bytes have been written to at least
/// one ready Handshake peer. They do not decide validity or mutate wallet
/// state; the backend decodes, hashes, and records the transaction locally.
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
            || authority.birthday_height() != index.status().birthday_height
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
            .map_err(map_authority_error)
    }

    /// Commit one next-height verified filtered block into the encrypted index.
    pub fn apply_verified_block(
        &self,
        block: &VerifiedWalletBlock,
        now_unix: u64,
    ) -> Result<usize, HnsWalletError> {
        let mut state = self.lock()?;
        let EmbeddedState {
            authority,
            index,
            mempool,
            ..
        } = &mut *state;
        let admitted = index
            .apply_verified_block(authority, block, now_unix)
            .map_err(map_index_error)?;
        let mut changed = false;
        for transaction in block.transactions() {
            let txid = transaction
                .transaction_hash()
                .map_err(|_| HnsWalletError::InvalidEvidence)?
                .into_bytes();
            changed |= mempool.transactions.remove(&txid).is_some();
        }
        if changed {
            advance_mempool_generation(mempool)?;
        }
        Ok(admitted)
    }

    /// Admit one bloom-matched or locally broadcast mempool transaction.
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
                "no ready Handshake peer accepted the transaction bytes".to_owned(),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HnsWalletError::Clock)?
            .as_secs();
        let mut state = self.lock()?;
        admit_mempool(&mut state.mempool, txid, transaction, raw.to_vec(), now)?;
        Ok(TransactionHash::new(txid))
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
        let (fee_rate, fee_rate_samples) = peer_fee_rate(&state);
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
                HnsFeeRateSource::MinimumRelay
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
        Ok(BaseUnits::new(u128::from(peer_fee_rate(&state).0)))
    }

    fn get_name_evidence(
        &self,
        _name_hash: [u8; 32],
        _binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }

    fn get_active_name_owner_coin(
        &self,
        _name_hash: [u8; 32],
        _binding: SnapshotBinding,
    ) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }

    fn get_name_action_context(
        &self,
        _action: HnsNameAction,
        _name_hash: [u8; 32],
        _binding: SnapshotBinding,
        _expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }
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
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
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
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
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

fn peer_fee_rate(state: &EmbeddedState) -> (u64, usize) {
    let mut rates = state.peer_fee_rates.values().copied().collect::<Vec<_>>();
    if rates.is_empty() {
        return (MINIMUM_RELAY_FEE_RATE, 0);
    }
    rates.sort_unstable();
    let lower_median = rates[(rates.len() - 1) / 2];
    (lower_median.max(MINIMUM_RELAY_FEE_RATE), rates.len())
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
    use hns_covenants::Covenant;
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

    #[test]
    fn verified_chain_drives_wallet_reads_fee_policy_and_direct_broadcast() {
        let store = store();
        let account = AccountId::new([21; 16]);
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
        let current_request = backend.begin_header_round(&[peer_one], now).unwrap();
        backend
            .submit_header_response(current_request.generation, peer_one, Vec::new(), now)
            .unwrap();
        backend.finish_header_round(now).unwrap();
        assert!(matches!(
            backend.get_chain_snapshot(),
            Err(HnsWalletError::RuntimeIntegrationUnavailable)
        ));

        assert_eq!(backend.apply_verified_block(&block, now).unwrap(), 1);
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
        assert_eq!(quote.rate_atomic_units_per_1000_policy_vbytes, 2_000);
        assert_eq!(quote.rate_sample_count, 2);
        assert_eq!(quote.rate_source, HnsFeeRateSource::PeerRelay);
        assert_eq!(quote.actual_fee, BaseUnits::new(2_000));

        backend.remove_header_peer(peer_two).unwrap();
        assert_eq!(
            backend
                .estimate_fee_rate(DEFAULT_FEE_TARGET_BLOCKS)
                .unwrap(),
            BaseUnits::new(9_000)
        );
    }
}
