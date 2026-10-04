use std::{collections::HashSet, sync::Arc, time::Duration};

use bitcoin::{
    block::Header,
    hashes::Hash,
    p2p::{
        message_blockdata::GetHeadersMessage,
        message_filter::{CFHeaders, CFilter},
        message_network::VersionMessage,
        ServiceFlags,
    },
    Block, BlockHash, Network, Wtxid,
};
use tokio::{
    select,
    sync::mpsc::{self},
};
use tokio::{
    sync::mpsc::{Receiver, UnboundedReceiver},
    time::MissedTickBehavior,
};

use crate::{
    chain::{
        block_queue::{BlockQueue, ProcessBlockResponse},
        chain::Chain,
        checkpoints::HashCheckpoint,
        CFHeaderChanges, ChainState, FilterCheck, HeaderSyncEffect, IndexedHeader,
    },
    error::FetchBlockError,
    messages::ClientRequest,
    network::{
        peer_map::PeerMap, LastBlockMonitor, MainThreadMessage, PeerId, PeerMessage,
        PeerThreadMessage,
    },
    Config, IndexedBlock, NodeState, Package,
};

use super::{
    client::Client,
    error::NodeError,
    messages::{ClientMessage, Event, Info, SyncUpdate, Warning},
    Dialog,
};
use crate::sync_cache::{CachedSyncBatch, SyncCacheContext, SyncCacheKind, VerifiedSyncCache};

pub(crate) const WTXID_VERSION: u32 = 70016;
const LOOP_TIMEOUT: Duration = Duration::from_millis(10);

type PeerRequirement = usize;

/// A compact block filter node. Nodes download Bitcoin block headers, block filters, and blocks to send relevant events to a client.
#[derive(Debug)]
pub struct Node {
    state: NodeState,
    chain: Chain,
    peer_map: PeerMap,
    required_peers: PeerRequirement,
    dialog: Arc<Dialog>,
    block_queue: BlockQueue,
    client_recv: UnboundedReceiver<ClientMessage>,
    peer_recv: Receiver<PeerThreadMessage>,
    sync_cache: Option<Arc<dyn VerifiedSyncCache>>,
    cache_error: Option<String>,
    cache_restored: bool,
    fresh_filter_peers: HashSet<PeerId>,
    saved_filters: HashSet<BlockHash>,
    pending_filters: Vec<CFilter>,
    pending_filter_bytes: usize,
}

impl Node {
    pub(crate) fn new(network: Network, config: Config) -> (Self, Client) {
        let Config {
            required_peers,
            white_list,
            whitelist_only,
            data_path: _,
            chain_state,
            connection_type,
            peer_timeout_config,
            filter_type,
            block_type,
            sync_cache,
        } = config;
        // Set up a communication channel between the node and client
        let (info_tx, info_rx) = mpsc::channel::<Info>(32);
        let (warn_tx, warn_rx) = mpsc::unbounded_channel::<Warning>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();
        let (ctx, crx) = mpsc::unbounded_channel::<ClientMessage>();
        let client = Client::new(info_rx, warn_rx, event_rx, ctx);
        // A structured way to talk to the client
        let dialog = Arc::new(Dialog::new(info_tx, warn_tx, event_tx));
        // We always assume we are behind
        let state = NodeState::Behind;
        // Configure the peer manager
        let (mtx, mrx) = mpsc::channel::<PeerThreadMessage>(32);
        let peer_map = PeerMap::new(
            mtx,
            network,
            block_type,
            white_list,
            whitelist_only,
            Arc::clone(&dialog),
            connection_type,
            peer_timeout_config,
        );
        // Build the chain
        let chain_state = chain_state.unwrap_or(ChainState::Checkpoint(
            HashCheckpoint::from_genesis(network),
        ));
        let chain = Chain::new(
            network,
            chain_state,
            Arc::clone(&dialog),
            required_peers,
            filter_type,
        );
        let expected_context = SyncCacheContext {
            network,
            checkpoint: chain.checkpoint(),
            required_peers,
            filter_type: filter_type.into(),
        };
        let cache_error = sync_cache.as_ref().and_then(|cache| {
            (cache.context() != expected_context)
                .then(|| "cache verification context does not match this node".to_owned())
        });
        (
            Self {
                state,
                chain,
                peer_map,
                required_peers: required_peers.into(),
                dialog,
                block_queue: BlockQueue::new(),
                client_recv: crx,
                peer_recv: mrx,
                sync_cache,
                cache_error,
                cache_restored: false,
                fresh_filter_peers: HashSet::new(),
                saved_filters: HashSet::new(),
                pending_filters: Vec::with_capacity(64),
                pending_filter_bytes: 0,
            },
            client,
        )
    }

    /// Run the node continuously. Typically run on a separate thread than the underlying application.
    ///
    /// # Errors
    ///
    /// If the node has exhausted all options to find connections.
    pub async fn run(mut self) -> Result<(), NodeError> {
        crate::debug!("Starting node");
        crate::debug!(format!(
            "Configured connection requirement: {} peers",
            self.required_peers
        ));
        self.restore_cache().await?;
        let mut last_block = LastBlockMonitor::new();
        let mut interval = tokio::time::interval(LOOP_TIMEOUT);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if let Some(error) = self.cache_error.take() {
                return Err(NodeError::SyncCache(error));
            }
            // Try to advance the state of the node
            self.advance_state(&mut last_block).await;
            // Connect to more peers if we need them and remove old connections
            self.dispatch().await?;
            // If there are blocks we need in the queue, we should request them of a random peer
            self.get_blocks().await;
            // Either handle a message from a remote peer or from our client
            select! {
                peer = self.peer_recv.recv() => {
                    match peer {
                        Some(peer_thread) => {
                            match peer_thread.message {
                                PeerMessage::Version(version) => {
                                    self.peer_map.set_services(peer_thread.nonce, version.services);
                                    let response = self.handle_version(peer_thread.nonce, version).await?;
                                    self.peer_map.send_message(peer_thread.nonce, response).await;
                                    crate::debug!(format!("[{}]: version", peer_thread.nonce));
                                }
                                PeerMessage::Headers(headers) => {
                                    last_block.reset();
                                    crate::debug!(format!("[{}]: headers", peer_thread.nonce));
                                    match self.handle_headers(peer_thread.nonce, headers).await {
                                        Some(response) => {
                                            self.peer_map.send_message(peer_thread.nonce, response).await;
                                        }
                                        None => continue,
                                    }
                                }
                                PeerMessage::FilterHeaders(cf_headers) => {
                                    crate::debug!(format!("[{}]: filter headers", peer_thread.nonce));
                                    match self.handle_cf_headers(peer_thread.nonce, cf_headers).await {
                                        Some(response) => {
                                            self.peer_map.broadcast(response).await;
                                        }
                                        None => continue,
                                    }
                                }
                                PeerMessage::Filter(filter) => {
                                    match self.handle_filter(peer_thread.nonce, filter).await {
                                        Some(response) => {
                                            self.peer_map.send_message(peer_thread.nonce, response).await;
                                        }
                                        None => continue,
                                    }
                                }
                                PeerMessage::Block(block) => match self.handle_block(peer_thread.nonce, block).await {
                                    Some(response) => {
                                        self.peer_map.send_message(peer_thread.nonce, response).await;
                                    }
                                    None => continue,
                                },
                                PeerMessage::NewBlocks(blocks) => {
                                    crate::debug!(format!("[{}]: inv", peer_thread.nonce));
                                    match self.handle_inventory_blocks(blocks) {
                                        Some(response) => {
                                            self.peer_map.send_message(peer_thread.nonce, response).await;
                                        }
                                        None => continue,
                                    }
                                }
                                PeerMessage::FeeFilter(feerate) => {
                                    self.peer_map.set_broadcast_min(peer_thread.nonce, feerate);
                                }
                            }
                        },
                        _ => continue,
                    }
                },
                message = self.client_recv.recv() => {
                    if let Some(message) = message {
                        match message {
                            ClientMessage::Shutdown => {
                                self.flush_filter_cache();
                                return match self.cache_error.take() {
                                    Some(error) => Err(NodeError::SyncCache(error)),
                                    None => Ok(()),
                                };
                            },
                            ClientMessage::Broadcast(transaction) => {
                                self.broadcast_transaction(transaction).await;
                            },
                            ClientMessage::Rescan(height_opt) => {
                                if let Some(response) = self.rescan(height_opt).await? {
                                    self.peer_map.broadcast(response).await;
                                }
                            },
                            ClientMessage::GetBlock(request) => {
                                let height_opt = self.chain.header_chain.height_of_hash(request.data());
                                if height_opt.is_none() {
                                    let (_, oneshot) = request.into_values();
                                    let err_reponse = oneshot.send(Err(FetchBlockError::UnknownHash));
                                    if err_reponse.is_err() {
                                        self.dialog.send_warning(Warning::ChannelDropped);
                                    }
                                } else {
                                    crate::debug!(
                                        format!("Adding block {} to queue", request.data())
                                    );
                                    self.block_queue.add(request);
                                }
                            },
                            ClientMessage::BestBlock(request) => {
                                let (_, oneshot) = request.into_values();
                                let block_tree = &self.chain.header_chain;
                                let hash = block_tree.tip_hash();
                                let height = block_tree.height();
                                let checkpoint = HashCheckpoint::new(height, hash);
                                let send_result = oneshot.send(checkpoint);
                                if send_result.is_err() {
                                    self.dialog.send_warning(Warning::ChannelDropped);
                                };
                            },
                            ClientMessage::AddPeer(peer) => {
                                self.peer_map.add_trusted_peer(peer);
                            },
                            ClientMessage::GetBroadcastMinFeeRate(request) => {
                                let (_, oneshot) = request.into_values();
                                let fee_rate = self.peer_map.broadcast_min();
                                let send_result = oneshot.send(fee_rate);
                                if send_result.is_err() {
                                    self.dialog.send_warning(Warning::ChannelDropped);
                                };
                            }
                            ClientMessage::GetPeerInfo(request) => {
                                let (_, oneshot) = request.into_values();
                                let peers = self.peer_map.peer_info();
                                let send_result = oneshot.send(peers);
                                if send_result.is_err() {
                                    self.dialog.send_warning(Warning::ChannelDropped);
                                };
                            }
                            ClientMessage::GetHeader(request) => {
                                let (height, oneshot) = request.into_values();
                                let header = self
                                    .chain
                                    .header_chain
                                    .header_at_height(height)
                                    .map(|h| IndexedHeader::new(height, h));
                                if oneshot.send(header).is_err() {
                                    self.dialog.send_warning(Warning::ChannelDropped);
                                };
                            }
                            ClientMessage::HeightOfHash(request) => {
                                let (hash, oneshot) = request.into_values();
                                let height =
                                    self.chain.header_chain.height_of_hash_canonical_only(hash);
                                if oneshot.send(height).is_err() {
                                    self.dialog.send_warning(Warning::ChannelDropped);
                                };
                            }
                            ClientMessage::NoOp => (),
                        }
                    }
                }
                _ = interval.tick() => (),
            }
        }
    }

    // Connect to a new peer if we are not connected to enough
    async fn dispatch(&mut self) -> Result<(), NodeError> {
        self.peer_map.clean().await;
        let live = self.peer_map.live();
        let required = self.next_required_peers();
        // Find more peers when lower than the desired threshold.
        if live < required {
            self.dialog.send_warning(Warning::NeedConnections {
                connected: live,
                required,
            });
            let address = self
                .peer_map
                .next_peer()
                .await
                .ok_or(NodeError::NoReachablePeers)?;
            if self.peer_map.dispatch(address).await.is_err() {
                self.dialog.send_warning(Warning::CouldNotConnect);
            }
        }
        Ok(())
    }

    // If there are blocks in the queue, we should request them of a random peer
    async fn get_blocks(&mut self) {
        if let Some(block_request) = self.pop_block_queue() {
            crate::debug!("Sending block request to random peer");
            self.peer_map.send_random(block_request).await;
        }
    }

    // Broadcast transactions according to the configured policy
    async fn broadcast_transaction(&self, broadcast: ClientRequest<Package, Wtxid>) {
        let target_peers = self.peer_map.active_peer_ids();
        let mut queue = self.peer_map.tx_queue.lock().await;
        let (transaction, oneshot) = broadcast.into_values();
        queue.add_to_queue(transaction, oneshot, target_peers);
        drop(queue);
        crate::debug!("Announcing transaction to every active peer");
        self.peer_map
            .broadcast(MainThreadMessage::BroadcastPending)
            .await;
    }

    // Try to continue with the syncing process
    async fn advance_state(&mut self, last_block: &mut LastBlockMonitor) {
        if self.cache_restored
            && matches!(
                self.state,
                NodeState::HeadersSynced | NodeState::FilterHeadersSynced
            )
        {
            let active = self.peer_map.active_peer_ids();
            let fresh = self
                .fresh_filter_peers
                .iter()
                .filter(|id| active.contains(id))
                .count();
            if fresh < self.required_peers {
                return;
            }
        }
        match self.state {
            // This state is updated upon receiving new block headers
            NodeState::Behind => (),
            NodeState::HeadersSynced => {
                if self.chain.is_cf_headers_synced() {
                    self.state = NodeState::FilterHeadersSynced;
                }
            }
            NodeState::FilterHeadersSynced => {
                if self.chain.is_filters_synced() {
                    self.flush_filter_cache();
                    if self.cache_error.is_some() {
                        return;
                    }
                    self.state = NodeState::FiltersSynced;
                    let update = SyncUpdate::new(
                        HashCheckpoint::new(
                            self.chain.header_chain.height(),
                            self.chain.header_chain.tip_hash(),
                        ),
                        self.chain.last_ten(),
                    );
                    self.dialog.send_event(Event::FiltersSynced(update));
                }
            }
            NodeState::FiltersSynced => {
                if last_block.stale() {
                    self.dialog.send_warning(Warning::PotentialStaleTip);
                    crate::debug!("Disconnecting from remote nodes to find new connections");
                    self.peer_map.broadcast(MainThreadMessage::Disconnect).await;
                    last_block.reset();
                }
            }
        }
    }

    // When syncing headers we are only interested in one peer to start
    fn next_required_peers(&self) -> PeerRequirement {
        match self.state {
            NodeState::Behind => 1,
            _ => self.required_peers,
        }
    }

    // After we receiving some chain-syncing message, we decide what chain of data needs to be
    // requested next.
    async fn next_stateful_message(&mut self) -> Option<MainThreadMessage> {
        if self.state == NodeState::Behind {
            let headers = GetHeadersMessage {
                version: WTXID_VERSION,
                locator_hashes: self.chain.header_chain.locators(),
                stop_hash: BlockHash::all_zeros(),
            };
            return Some(MainThreadMessage::GetHeaders(headers));
        } else if !self.chain.is_cf_headers_synced() {
            return Some(MainThreadMessage::GetFilterHeaders(
                self.chain.next_cf_header_message(),
            ));
        } else if !self.chain.is_filters_synced() {
            return Some(MainThreadMessage::GetFilters(
                self.chain.next_filter_message(),
            ));
        }
        None
    }

    // We accepted a handshake with a peer but we may disconnect if they do not support CBF
    async fn handle_version(
        &mut self,
        nonce: PeerId,
        version_message: VersionMessage,
    ) -> Result<MainThreadMessage, NodeError> {
        if version_message.version < WTXID_VERSION {
            return Ok(MainThreadMessage::Disconnect);
        }
        if (self.sync_cache.is_some() || self.state != NodeState::Behind)
            && (!version_message.services.has(ServiceFlags::COMPACT_FILTERS)
                || !version_message.services.has(ServiceFlags::NETWORK))
        {
            self.dialog.send_warning(Warning::NoCompactFilters);
            return Ok(MainThreadMessage::Disconnect);
        }
        self.peer_map.tried(nonce).await;
        if version_message.services.has(ServiceFlags::COMPACT_FILTERS)
            && version_message.services.has(ServiceFlags::NETWORK)
        {
            self.fresh_filter_peers.insert(nonce);
        }
        // First we signal for ADDRV2 support
        self.peer_map
            .send_message(nonce, MainThreadMessage::SendAddrV2)
            .await;
        // Then for BIP 339 witness transaction broadcast
        self.peer_map
            .send_message(nonce, MainThreadMessage::WtxidRelay)
            .await;
        self.peer_map
            .send_message(nonce, MainThreadMessage::Verack)
            .await;
        self.peer_map
            .send_message(nonce, MainThreadMessage::SendHeaders)
            .await;
        // Request peer addresses unless restricted to the whitelist only.
        if !self.peer_map.whitelist_only {
            crate::debug!("Requesting new addresses");
            self.peer_map
                .send_message(nonce, MainThreadMessage::GetAddr)
                .await;
        }
        // Inform the user we are connected to all required peers
        if self.peer_map.live().eq(&self.required_peers) {
            self.dialog.send_info(Info::ConnectionsMet);
        }
        // Even if we start the node as caught up in terms of height, we need to check for reorgs. So we can send this unconditionally.
        let next_headers = GetHeadersMessage {
            version: WTXID_VERSION,
            locator_hashes: self.chain.header_chain.locators(),
            stop_hash: BlockHash::all_zeros(),
        };
        Ok(MainThreadMessage::GetHeaders(next_headers))
    }

    // We always send headers to our peers, so our next message depends on our state
    async fn handle_headers(
        &mut self,
        peer_id: PeerId,
        headers: Vec<Header>,
    ) -> Option<MainThreadMessage> {
        let saved = self.sync_cache.as_ref().map(|_| headers.clone());
        let previously_known = saved.as_ref().map(|headers| {
            headers
                .iter()
                .filter_map(|header| {
                    let hash = header.block_hash();
                    self.chain.header_chain.contains(hash).then_some(hash)
                })
                .collect::<HashSet<_>>()
        });
        let chain = &mut self.chain;
        let mut changed = false;
        match chain.sync_chain(headers) {
            Ok(effect) => match effect {
                HeaderSyncEffect::Added => {
                    changed = true;
                    if self.state != NodeState::Behind {
                        self.state = NodeState::Behind;
                    }
                    self.chain.send_chain_update();
                }
                HeaderSyncEffect::Empty => {
                    if self.state == NodeState::Behind {
                        self.state = NodeState::HeadersSynced;
                    }
                }
                HeaderSyncEffect::Reorg(reorgs) => {
                    changed = true;
                    if self.state != NodeState::HeadersSynced {
                        self.state = NodeState::HeadersSynced;
                    }
                    self.chain.send_chain_update();
                    self.block_queue.remove(&reorgs);
                }
            },
            Err(e) => {
                // The graph can accept a verified prefix before rejecting
                // a later difficulty transition. Retain that prefix too;
                // otherwise the next valid response could extend an anchor
                // absent from the durable cache.
                if let (Some(headers), Some(known)) = (saved.as_ref(), previously_known.as_ref()) {
                    let accepted = headers
                        .iter()
                        .take_while(|header| self.chain.header_chain.contains(header.block_hash()))
                        .copied()
                        .collect::<Vec<_>>();
                    if accepted
                        .iter()
                        .any(|header| !known.contains(&header.block_hash()))
                    {
                        self.append_cache(CachedSyncBatch::Headers(accepted));
                    }
                }
                self.dialog.send_warning(Warning::UnexpectedSyncError {
                    warning: format!("Unexpected header syncing error: {e}"),
                });
                self.peer_map.ban(peer_id).await;
                return Some(MainThreadMessage::Disconnect);
            }
        }
        if let Some(headers) = saved {
            if changed && !headers.is_empty() {
                self.append_cache(CachedSyncBatch::Headers(headers));
            }
        }
        self.next_stateful_message().await
    }

    // Compact filter headers may result in a number of outcomes, including the need to audit filters.
    async fn handle_cf_headers(
        &mut self,
        peer_id: PeerId,
        cf_headers: CFHeaders,
    ) -> Option<MainThreadMessage> {
        self.chain.send_chain_update();
        let saved = self.sync_cache.as_ref().map(|_| cf_headers.clone());
        match self.chain.sync_cf_headers(peer_id, cf_headers) {
            Ok(potential_message) => match potential_message {
                CFHeaderChanges::AddedToQueue => None,
                CFHeaderChanges::Extended => {
                    if let Some(packet) = saved {
                        self.append_cache(CachedSyncBatch::FilterHeaders(packet));
                    }
                    self.next_stateful_message().await
                }
                CFHeaderChanges::Conflict => {
                    self.dialog.send_warning(Warning::UnexpectedSyncError {
                        warning: "Found a conflict while peers are sending filter headers".into(),
                    });
                    Some(MainThreadMessage::Disconnect)
                }
            },
            Err(e) => {
                self.dialog.send_warning(Warning::UnexpectedSyncError {
                    warning: format!("Compact filter header syncing encountered an error: {e}"),
                });
                self.peer_map.ban(peer_id).await;
                Some(MainThreadMessage::Disconnect)
            }
        }
    }

    // Handle a new compact block filter
    async fn handle_filter(
        &mut self,
        peer_id: PeerId,
        filter: CFilter,
    ) -> Option<MainThreadMessage> {
        let saved = self.sync_cache.as_ref().and_then(|_| {
            (!self.saved_filters.contains(&filter.block_hash)
                && !self
                    .chain
                    .header_chain
                    .is_filter_checked(&filter.block_hash))
            .then(|| filter.clone())
        });
        match self.chain.sync_filter(filter) {
            Ok(potential_message) => {
                let FilterCheck { was_last_in_batch } = potential_message;
                if let Some(packet) = saved {
                    self.pending_filter_bytes += packet.filter.len() + 40;
                    self.saved_filters.insert(packet.block_hash);
                    self.pending_filters.push(packet);
                    if self.pending_filters.len() >= 64
                        || self.pending_filter_bytes >= 2 * 1024 * 1024
                        || was_last_in_batch
                    {
                        self.flush_filter_cache();
                    }
                }
                if was_last_in_batch {
                    self.chain.send_chain_update();
                    if !self.chain.is_filters_synced() {
                        let next_filters = self.chain.next_filter_message();
                        return Some(MainThreadMessage::GetFilters(next_filters));
                    }
                }
                None
            }
            Err(e) => {
                self.dialog.send_warning(Warning::UnexpectedSyncError {
                    warning: format!("Compact filter syncing encountered an error: {e}"),
                });
                self.peer_map.ban(peer_id).await;
                Some(MainThreadMessage::Disconnect)
            }
        }
    }

    fn append_cache(&mut self, batch: CachedSyncBatch) {
        if self.cache_error.is_none() {
            if let Some(cache) = self.sync_cache.as_ref() {
                if let Err(error) = cache.append(&batch) {
                    self.cache_error = Some(error);
                }
            }
        }
    }

    fn flush_filter_cache(&mut self) {
        if !self.pending_filters.is_empty() {
            let batch = core::mem::take(&mut self.pending_filters);
            self.pending_filter_bytes = 0;
            self.append_cache(CachedSyncBatch::Filters(batch));
        }
    }

    async fn restore_cache(&mut self) -> Result<(), NodeError> {
        if let Some(error) = self.cache_error.take() {
            return Err(NodeError::SyncCache(error));
        }
        let Some(cache) = self.sync_cache.clone() else {
            return Ok(());
        };
        // Restore all branch headers first, then their agreed commitments,
        // then only canonical raw filters. No cached wallet-match decision or
        // value authority survives a restart.
        for kind in [
            SyncCacheKind::Headers,
            SyncCacheKind::FilterHeaders,
            SyncCacheKind::Filters,
        ] {
            self.restore_cache_stream(&cache, kind).await?;
        }
        self.chain.send_chain_update();
        Ok(())
    }

    async fn restore_cache_stream(
        &mut self,
        cache: &Arc<dyn VerifiedSyncCache>,
        kind: SyncCacheKind,
    ) -> Result<(), NodeError> {
        let mut index = 0_u32;
        while let Some(batch) = cache.read(kind, index).map_err(NodeError::SyncCache)? {
            if batch.kind() != kind {
                return Err(NodeError::SyncCache("cache record stream mismatch".into()));
            }
            match batch {
                CachedSyncBatch::Headers(headers) => {
                    if headers.is_empty() || headers.len() > 2_000 {
                        return Err(NodeError::SyncCache(
                            "invalid cached block-header batch".into(),
                        ));
                    }
                    self.chain
                        .sync_chain(headers)
                        .map_err(|error| NodeError::SyncCache(error.to_string()))?;
                }
                CachedSyncBatch::FilterHeaders(headers) => {
                    self.chain
                        .restore_filter_headers(headers)
                        .map_err(NodeError::SyncCache)?;
                }
                CachedSyncBatch::Filters(filters) => {
                    if filters.is_empty() || filters.len() > 64 {
                        return Err(NodeError::SyncCache("invalid cached filter batch".into()));
                    }
                    for filter in filters {
                        self.saved_filters.insert(filter.block_hash);
                        self.chain
                            .restore_filter(filter)
                            .map_err(|error| NodeError::SyncCache(error.to_string()))?;
                    }
                }
            }
            self.cache_restored = true;
            // Progress walks the header graph. Keep replay linear in
            // practice rather than walking it after every 64 filters.
            if index % 32 == 0 {
                self.chain.send_chain_update();
            }
            index = index
                .checked_add(1)
                .ok_or_else(|| NodeError::SyncCache("cache stream overflow".into()))?;
            tokio::task::yield_now().await;
        }
        Ok(())
    }

    // Scan a block for transactions.
    async fn handle_block(&mut self, peer_id: PeerId, block: Block) -> Option<MainThreadMessage> {
        let block_hash = block.block_hash();
        let height = match self.chain.header_chain.height_of_hash(block_hash) {
            Some(height) => height,
            None => {
                self.dialog.send_warning(Warning::UnexpectedSyncError {
                    warning: "A block received does not have a known hash".into(),
                });
                self.peer_map.ban(peer_id).await;
                return Some(MainThreadMessage::Disconnect);
            }
        };
        if !block.check_merkle_root() {
            self.dialog.send_warning(Warning::UnexpectedSyncError {
                warning: "A block received does not have a valid merkle root".into(),
            });
            self.peer_map.ban(peer_id).await;
            return Some(MainThreadMessage::Disconnect);
        }
        let process_block_response = self.block_queue.process_block(&block_hash);
        match process_block_response {
            ProcessBlockResponse::Accepted { block_recipient } => {
                self.dialog
                    .send_info(Info::BlockReceived(block.block_hash()));
                let send_err = block_recipient
                    .send(Ok(IndexedBlock::new(height, block)))
                    .is_err();
                if send_err {
                    self.dialog.send_warning(Warning::ChannelDropped);
                };
            }
            ProcessBlockResponse::LateResponse => {
                crate::debug!(format!(
                    "Peer {} responded late to a request for hash {}",
                    peer_id, block_hash
                ));
            }
            ProcessBlockResponse::UnknownHash => {
                crate::debug!(format!(
                    "Peer {} responded with an irrelevant block",
                    peer_id
                ));
            }
        }
        None
    }

    // The block queue holds all the block hashes we may be interested in
    fn pop_block_queue(&mut self) -> Option<MainThreadMessage> {
        if matches!(
            self.state,
            NodeState::FilterHeadersSynced | NodeState::FiltersSynced
        ) {
            let next_block_hash = self.block_queue.pop();
            return next_block_hash.map(MainThreadMessage::GetBlock);
        }
        None
    }

    // A peer announced new blocks with an `inv` instead of `headers`. Bitcoin Core
    // falls back to inv-of-tip, even after BIP-130 `sendheaders`, when more than
    // eight blocks connect in a single announcement round or when a block queued
    // for announcement was reorganized away. Probe the announcing peer with
    // `getheaders` and let the response drive any state changes through the usual
    // `handle_headers` path. Deliberately no `NodeState` mutation, no filter queue
    // changes, no tip assumption, and no `LastBlockMonitor` reset on the inv itself.
    fn handle_inventory_blocks(&mut self, blocks: Vec<BlockHash>) -> Option<MainThreadMessage> {
        // A header sync is already in progress.
        if self.state == NodeState::Behind {
            return None;
        }
        if blocks
            .into_iter()
            .all(|block| self.chain.header_chain.contains(block))
        {
            return None;
        }
        let next_headers = GetHeadersMessage {
            version: WTXID_VERSION,
            locator_hashes: self.chain.header_chain.locators(),
            stop_hash: BlockHash::all_zeros(),
        };
        Some(MainThreadMessage::GetHeaders(next_headers))
    }

    // Clear the filter hash cache and redownload the filters.
    async fn rescan(
        &mut self,
        height_opt: Option<u32>,
    ) -> Result<Option<MainThreadMessage>, NodeError> {
        match self.state {
            NodeState::Behind => Ok(None),
            NodeState::HeadersSynced => Ok(None),
            _ => {
                self.chain.clear_filters();
                if let Some(height) = height_opt {
                    self.chain.header_chain.assume_checked_to(height);
                }
                self.state = NodeState::FilterHeadersSynced;
                self.flush_filter_cache();
                if let Some(error) = self.cache_error.take() {
                    return Err(NodeError::SyncCache(error));
                }
                if let Some(cache) = self.sync_cache.clone() {
                    self.restore_cache_stream(&cache, SyncCacheKind::Filters)
                        .await?;
                    self.chain.send_chain_update();
                }
                if self.chain.is_filters_synced() {
                    return Ok(None);
                }
                Ok(Some(MainThreadMessage::GetFilters(
                    self.chain.next_filter_message(),
                )))
            }
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use bitcoin::{
        bip158::BlockFilter, constants::genesis_block, FilterHash, FilterHeader, ScriptBuf,
    };
    use std::sync::Mutex;

    #[derive(Debug)]
    struct MemoryCache {
        context: SyncCacheContext,
        batches: Mutex<Vec<CachedSyncBatch>>,
    }
    impl VerifiedSyncCache for MemoryCache {
        fn context(&self) -> SyncCacheContext {
            self.context
        }
        fn read(&self, kind: SyncCacheKind, index: u32) -> Result<Option<CachedSyncBatch>, String> {
            Ok(self
                .batches
                .lock()
                .unwrap()
                .iter()
                .filter(|batch| batch.kind() == kind)
                .nth(index as usize)
                .cloned())
        }
        fn append(&self, batch: &CachedSyncBatch) -> Result<(), String> {
            self.batches.lock().unwrap().push(batch.clone());
            Ok(())
        }
    }

    fn new_cache() -> Arc<MemoryCache> {
        Arc::new(MemoryCache {
            context: SyncCacheContext {
                network: Network::Regtest,
                checkpoint: HashCheckpoint::from_genesis(Network::Regtest),
                required_peers: 2,
                filter_type: 0,
            },
            batches: Mutex::new(Vec::new()),
        })
    }

    fn node(cache: Arc<MemoryCache>) -> (Node, Client) {
        crate::builder::Builder::new(Network::Regtest)
            .required_peers(2)
            .verified_sync_cache(cache)
            .build()
    }

    fn headers_and_filters(
        count: u32,
        parent: Header,
        interval: u32,
    ) -> (Vec<Header>, Vec<CFilter>, CFHeaders, ScriptBuf) {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let mut headers = Vec::new();
        let mut filters = Vec::new();
        let mut previous = parent;
        for height in 1..=count {
            let mut block = genesis_block(Network::Regtest);
            block.header.prev_blockhash = previous.block_hash();
            block.header.time = previous.time + interval;
            block.txdata[0].output[0].script_pubkey = if height == 17 {
                script.clone()
            } else {
                ScriptBuf::from_bytes(vec![0x52])
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            block.header.nonce = 0;
            while block.header.validate_pow(block.header.target()).is_err() {
                block.header.nonce += 1;
            }
            let filter = BlockFilter::new_script_filter(&block, |_| Ok(ScriptBuf::new())).unwrap();
            previous = block.header;
            headers.push(block.header);
            filters.push(CFilter {
                filter_type: 0,
                block_hash: block.block_hash(),
                filter: filter.content,
            });
        }
        let commitments = CFHeaders {
            filter_type: 0,
            stop_hash: previous.block_hash(),
            previous_filter_header: FilterHeader::all_zeros(),
            filter_hashes: filters
                .iter()
                .map(|filter| FilterHash::hash(&filter.filter))
                .collect(),
        };
        (headers, filters, commitments, script)
    }

    fn matches(client: &mut Client, script: &ScriptBuf) -> Vec<u32> {
        let mut heights = Vec::new();
        while let Ok(event) = client.event_rx.try_recv() {
            if let Event::IndexedFilter(filter) = event {
                if filter.contains_any(std::iter::once(script)) {
                    heights.push(filter.height());
                }
            }
        }
        heights
    }

    #[tokio::test]
    async fn killed_initial_sync_restores_verified_prefix_and_reruns_matching() {
        let cache = new_cache();
        let (mut original, mut client) = node(cache.clone());
        let (headers, filters, commitments, script) =
            headers_and_filters(120, genesis_block(Network::Regtest).header, 600);
        original.handle_headers(PeerId(1), headers.clone()).await;
        original.chain.next_cf_header_message();
        original
            .handle_cf_headers(PeerId(1), commitments.clone())
            .await;
        original
            .handle_cf_headers(PeerId(1), commitments.clone())
            .await;
        assert!(cache
            .read(SyncCacheKind::FilterHeaders, 0)
            .unwrap()
            .is_none());
        original.handle_cf_headers(PeerId(2), commitments).await;
        assert!(cache
            .read(SyncCacheKind::FilterHeaders, 0)
            .unwrap()
            .is_some());
        original.chain.next_filter_message();
        for filter in filters.iter().take(73) {
            original.handle_filter(PeerId(1), filter.clone()).await;
        }
        assert_eq!(matches(&mut client, &script), vec![17]);
        // Deliberately no Shutdown: the last nine filters may need fetching
        // again, but the committed 64-filter prefix survives process death.
        drop(original);
        drop(client);
        let (mut restored, mut client) = node(cache.clone());
        restored.restore_cache().await.unwrap();
        assert_eq!(restored.chain.header_chain.height(), 120);
        assert!(restored.chain.is_cf_headers_synced());
        assert_eq!(restored.chain.next_filter_message().start_height, 65);
        assert_eq!(matches(&mut client, &script), vec![17]);
        let mut monitor = LastBlockMonitor::new();
        restored.state = NodeState::HeadersSynced;
        restored.advance_state(&mut monitor).await;
        assert_eq!(restored.state, NodeState::HeadersSynced);
        // Fresh peer handshakes are still required to report complete sync.
        for filter in filters.into_iter().skip(64) {
            restored.handle_filter(PeerId(1), filter).await;
        }
        assert!(restored.chain.is_filters_synced());
        restored.state = NodeState::FiltersSynced;
        assert!(restored.rescan(None).await.unwrap().is_none());
        assert_eq!(matches(&mut client, &script), vec![17]);
        // No redundant header response is appended after reconnect.
        restored.handle_headers(PeerId(1), headers).await;
        assert!(cache.read(SyncCacheKind::Headers, 1).unwrap().is_none());
    }

    #[tokio::test]
    async fn cached_out_of_order_tail_does_not_skip_a_missing_filter() {
        let cache = new_cache();
        let (headers, filters, commitments, _) =
            headers_and_filters(5, genesis_block(Network::Regtest).header, 600);
        cache.append(&CachedSyncBatch::Headers(headers)).unwrap();
        cache
            .append(&CachedSyncBatch::FilterHeaders(commitments))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(vec![
                filters[4].clone(),
                filters[0].clone(),
            ]))
            .unwrap();
        let (mut restored, _client) = node(cache);
        restored.restore_cache().await.unwrap();
        let request = restored.chain.next_filter_message();
        assert_eq!(request.start_height, 2);
        assert_eq!(request.stop_hash, filters[3].block_hash);
        assert!(
            !restored
                .chain
                .sync_filter(filters[3].clone())
                .unwrap()
                .was_last_in_batch
        );
        assert!(
            !restored
                .chain
                .sync_filter(filters[1].clone())
                .unwrap()
                .was_last_in_batch
        );
        assert!(
            restored
                .chain
                .sync_filter(filters[2].clone())
                .unwrap()
                .was_last_in_batch
        );
        assert!(restored.chain.is_filters_synced());
    }

    #[tokio::test]
    async fn cached_filter_corruption_and_context_mismatch_fail_closed() {
        let cache = new_cache();
        let (headers, mut filters, commitments, _) =
            headers_and_filters(5, genesis_block(Network::Regtest).header, 600);
        cache.append(&CachedSyncBatch::Headers(headers)).unwrap();
        cache
            .append(&CachedSyncBatch::FilterHeaders(commitments))
            .unwrap();
        filters[0].filter.push(1);
        cache.append(&CachedSyncBatch::Filters(filters)).unwrap();
        let (mut restored, mut client) = node(cache.clone());
        assert!(matches!(
            restored.restore_cache().await,
            Err(NodeError::SyncCache(_))
        ));
        assert!(matches(&mut client, &ScriptBuf::new()).is_empty());
        let (mut wrong_quorum, _client) = crate::builder::Builder::new(Network::Regtest)
            .required_peers(3)
            .verified_sync_cache(cache)
            .build();
        assert!(matches!(
            wrong_quorum.restore_cache().await,
            Err(NodeError::SyncCache(_))
        ));
    }

    #[tokio::test]
    async fn restart_after_reorg_attaches_commitments_to_their_own_branch() {
        let cache = new_cache();
        let anchor = genesis_block(Network::Regtest).header;
        let (old_headers, old_filters, old_commitments, _) = headers_and_filters(5, anchor, 600);
        let (new_headers, new_filters, mut new_commitments, _) =
            headers_and_filters(7, old_headers[0], 601);
        new_commitments.previous_filter_header =
            BlockFilter::new(&old_filters[0].filter).filter_header(&FilterHeader::all_zeros());
        cache
            .append(&CachedSyncBatch::Headers(old_headers))
            .unwrap();
        cache
            .append(&CachedSyncBatch::FilterHeaders(old_commitments))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(old_filters.clone()))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Headers(new_headers))
            .unwrap();
        cache
            .append(&CachedSyncBatch::FilterHeaders(new_commitments))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(new_filters[..2].to_vec()))
            .unwrap();
        let (mut restored, mut client) = node(cache);
        restored.restore_cache().await.unwrap();
        assert_eq!(
            restored.chain.header_chain.tip_hash(),
            new_filters[6].block_hash
        );
        assert_eq!(restored.chain.next_filter_message().start_height, 4);
        let mut replayed = Vec::new();
        while let Ok(event) = client.event_rx.try_recv() {
            if let Event::IndexedFilter(filter) = event {
                replayed.push(filter.block_hash());
            }
        }
        assert_eq!(
            replayed,
            std::iter::once(old_filters[0].block_hash)
                .chain(new_filters[..2].iter().map(|filter| filter.block_hash))
                .collect::<Vec<_>>()
        );
        assert!(old_filters
            .iter()
            .skip(1)
            .all(|filter| !replayed.contains(&filter.block_hash)));
    }

    #[tokio::test]
    async fn verified_prefix_before_a_rejected_header_is_durable() {
        let cache = new_cache();
        let (mut original, _client) = node(cache.clone());
        let anchor = genesis_block(Network::Regtest).header;
        original.chain.header_chain = crate::chain::graph::BlockTree::new(
            crate::chain::graph::Tip {
                hash: anchor.block_hash(),
                height: 0,
                next_work_required: Some(anchor.bits),
            },
            Network::Regtest,
        );
        let (mut headers, _, _, _) =
            headers_and_filters(3, genesis_block(Network::Regtest).header, 600);
        headers[2].bits = bitcoin::CompactTarget::from_consensus(0x207ffffe);
        headers[2].nonce = 0;
        while headers[2].validate_pow(headers[2].target()).is_err() {
            headers[2].nonce += 1;
        }
        assert!(matches!(
            original.handle_headers(PeerId(1), headers).await,
            Some(MainThreadMessage::Disconnect)
        ));
        assert_eq!(original.chain.header_chain.height(), 2);
        drop(original);
        let (mut restored, _client) = node(cache);
        restored.restore_cache().await.unwrap();
        assert_eq!(restored.chain.header_chain.height(), 2);
    }
}
