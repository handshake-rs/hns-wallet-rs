//! Direct standard-peer synchronization for the wallet-owned HNS authority.
//!
//! DNS seeds, address gossip, and connected HSD peers are discovery and data
//! transports only. Headers, partial Merkle trees, transactions, and Urkel
//! proofs cross the wallet's local verification boundaries before they mutate
//! durable state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hns_header_consensus::{Header, Network};
use hns_light_chain::ChainLimits;
use hns_light_p2p::{
    PeerConfig, PeerConnection, PeerError, PeerEvent, PeerMetadata, WalletPeerEvent,
    light_wallet_version,
};
use hns_light_sync::{PeerId, SyncConfig};
use hns_light_wallet::{
    BloomUpdate, HsdBloomFilter, VerifiedWalletBlock, WalletBlockEvidence, WalletHeaderAnchor,
};
use hns_p2p_wire::{
    Inventory, InventoryKind, NetAddress, NetworkMagic, Packet, ProofPacket, SERVICE_BLOOM,
    SERVICE_NETWORK,
};
use hns_primitives::{BlockHash, BlockTime, NameHash, TreeRoot};
use hns_transaction::Transaction;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    EmbeddedHnsBackend, EncryptedHnsLightAuthority, EncryptedHnsLightIndex, HnsLightFloor,
    HnsLightNetwork, HnsNetwork, HnsRuntimeConfig, HnsWalletError, PersistedHeaderRound,
    VerifiedHnsNameProof, derive_hns_light_watch_set,
};
use hns_wallet_store::SharedWalletStore;

const PEER_ID_DOMAIN: &[u8] = b"hns-wallet-rs/direct-peer-id/v1";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DIRECT_PEERS: usize = 64;
const MAX_RESPONSE_EVENTS: usize = 4_096;
const MAX_DISCOVERED_ADDRESSES: usize = 1_024;
const MAX_SCAN_BLOCKS_PER_CALL: u32 = 2_000;
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01;
const BLOOM_GROWTH_RESERVE: usize = 1_024;

/// Native direct-peer policy for one wallet runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsDirectPeerConfig {
    /// Exact Handshake network shared with the local authority and index.
    pub network: HnsNetwork,
    /// User-supplied peers. Non-default ports are allowed here.
    pub static_peers: Vec<SocketAddr>,
    /// Untrusted DNS discovery seeds. Empty disables DNS discovery.
    pub dns_seeds: Vec<String>,
    /// Preferred number of persistent outbound peers.
    pub target_peers: usize,
    /// Independently Merkle-verified views required for every scanned block.
    pub minimum_block_views: usize,
    /// Native TCP connection deadline.
    pub connect_timeout: Duration,
    /// Bounded wait used for explicit mempool polling.
    pub event_poll_timeout: Duration,
    /// Permit loopback/private peers, normally only for regtest and simnet.
    pub allow_private_addresses: bool,
}

impl HnsDirectPeerConfig {
    /// Secure, transport-independent defaults for one network.
    #[must_use]
    pub fn for_network(network: HnsNetwork) -> Self {
        let local = matches!(network, HnsNetwork::Regtest | HnsNetwork::Simnet);
        Self {
            network,
            static_peers: Vec::new(),
            dns_seeds: default_dns_seeds(network)
                .iter()
                .map(|seed| (*seed).to_owned())
                .collect(),
            target_peers: if local { 1 } else { 3 },
            minimum_block_views: if local { 1 } else { 2 },
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            event_poll_timeout: DEFAULT_EVENT_POLL_TIMEOUT,
            allow_private_addresses: local,
        }
    }

    fn validate(&self) -> Result<(), HnsDirectPeerError> {
        if self.target_peers == 0
            || self.target_peers > MAX_DIRECT_PEERS
            || self.minimum_block_views == 0
            || self.minimum_block_views > self.target_peers
            || self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(300)
            || self.event_poll_timeout.is_zero()
            || self.event_poll_timeout > Duration::from_secs(30)
            || self.static_peers.iter().any(|peer| peer.port() == 0)
            || self.dns_seeds.iter().any(|seed| seed.trim().is_empty())
        {
            return Err(HnsDirectPeerError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// One completed version/verack connection registered with the local header
/// authority. The identifier is random and connection-scoped, not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectedHnsPeer {
    pub id: PeerId,
    pub address: SocketAddr,
    pub metadata: PeerMetadata,
}

/// Result of one bounded direct header round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsHeaderRoundProgress {
    /// Agreement was locally validated and durably committed.
    Committed(PersistedHeaderRound),
    /// Fewer than the configured responses arrived before the current call
    /// returned. A later call finishes or expires the same generation.
    AwaitingResponses {
        generation: u64,
        deadline: u64,
        requested: usize,
        submitted: usize,
    },
}

/// Result of one bounded filtered-block scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsBlockScanProgress {
    pub first_height: Option<u32>,
    pub last_height: Option<u32>,
    pub validated_tip_height: u32,
    pub blocks_applied: u32,
    pub transactions_admitted: usize,
    pub peer_views_verified: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingHeaderRound {
    generation: u64,
    deadline: u64,
    requested: usize,
    submitted: usize,
}

#[derive(Debug)]
struct NativePeer {
    address: SocketAddr,
    connection: PeerConnection<TcpStream>,
    deferred_wallet: VecDeque<WalletPeerEvent>,
}

type PeerHandle = Arc<Mutex<NativePeer>>;

/// Persistent native standard-peer pool. This is also the embedded backend's
/// transaction broadcast boundary.
pub struct NativeHnsPeerPool {
    config: HnsDirectPeerConfig,
    peers: Mutex<HashMap<PeerId, PeerHandle>>,
    known_addresses: Mutex<HashSet<SocketAddr>>,
}

impl NativeHnsPeerPool {
    /// Create an empty pool and seed it with explicit user-configured peers.
    pub fn new(config: HnsDirectPeerConfig) -> Result<Self, HnsDirectPeerError> {
        config.validate()?;
        let known_addresses = config.static_peers.iter().copied().collect();
        Ok(Self {
            config,
            peers: Mutex::new(HashMap::new()),
            known_addresses: Mutex::new(known_addresses),
        })
    }

    /// Immutable direct-peer policy.
    #[must_use]
    pub const fn config(&self) -> &HnsDirectPeerConfig {
        &self.config
    }

    /// Number of currently registered ready sessions.
    pub fn peer_count(&self) -> Result<usize, HnsDirectPeerError> {
        Ok(self.lock_peers()?.len())
    }

    /// Resolve configured DNS seeds into untrusted address candidates.
    pub fn discover_dns(&self) -> Result<usize, HnsDirectPeerError> {
        let port = default_peer_port(self.config.network);
        let mut discovered = Vec::new();
        let mut last_error = None;
        for seed in &self.config.dns_seeds {
            match (seed.as_str(), port).to_socket_addrs() {
                Ok(addresses) => {
                    for address in addresses {
                        if self.address_allowed(address, false)
                            && !discovered.contains(&address)
                            && discovered.len() < MAX_DISCOVERED_ADDRESSES
                        {
                            discovered.push(address);
                        }
                    }
                }
                Err(error) => last_error = Some(error.kind()),
            }
        }
        if discovered.is_empty()
            && !self.config.dns_seeds.is_empty()
            && let Some(kind) = last_error
        {
            return Err(HnsDirectPeerError::Io(kind));
        }
        self.add_known_addresses(discovered, false)
    }

    /// Connect, negotiate standard Bloom service, and retain one native peer.
    pub fn connect(
        &self,
        address: SocketAddr,
        local_height: u32,
        now_unix: u64,
    ) -> Result<ConnectedHnsPeer, HnsDirectPeerError> {
        let explicit = self.config.static_peers.contains(&address);
        if !self.address_allowed(address, explicit) {
            return Err(HnsDirectPeerError::AddressNotAllowed);
        }
        {
            let peers = self.lock_peers()?;
            if peers.len() >= self.config.target_peers {
                return Err(HnsDirectPeerError::PeerLimit);
            }
            if peers.values().any(|peer| {
                peer.lock()
                    .map(|peer| peer.address == address)
                    .unwrap_or(true)
            }) {
                return Err(HnsDirectPeerError::DuplicatePeer);
            }
        }
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| HnsDirectPeerError::Randomness)?;
        if nonce == [0; 8] {
            return Err(HnsDirectPeerError::Randomness);
        }
        let local_version = light_wallet_version(address, nonce, local_height, now_unix);
        let mut connection = PeerConnection::connect(
            address,
            PeerConfig::for_wallet_network(network_magic(self.config.network)),
            &local_version,
            now_unix,
            self.config.connect_timeout,
        )?;
        let metadata = connection.complete_handshake(|| now_unix_or(now_unix))?;
        let id = connection_peer_id(self.config.network, address, nonce, &metadata);
        let connected = ConnectedHnsPeer {
            id,
            address,
            metadata: metadata.clone(),
        };
        let peer = Arc::new(Mutex::new(NativePeer {
            address,
            connection,
            deferred_wallet: VecDeque::new(),
        }));
        let mut peers = self.lock_peers()?;
        if peers.len() >= self.config.target_peers {
            return Err(HnsDirectPeerError::PeerLimit);
        }
        if peers.contains_key(&id)
            || peers.values().any(|existing| {
                existing
                    .lock()
                    .map(|existing| existing.address == address)
                    .unwrap_or(true)
            })
        {
            return Err(HnsDirectPeerError::DuplicatePeer);
        }
        peers.insert(id, peer);
        drop(peers);
        self.known_addresses
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
            .insert(address);
        Ok(connected)
    }

    /// Remove and transport-shutdown one connection.
    pub fn disconnect(&self, id: PeerId) -> Result<bool, HnsDirectPeerError> {
        let removed = self.lock_peers()?.remove(&id);
        if let Some(peer) = removed {
            if let Ok(mut peer) = peer.lock() {
                let _ = peer.connection.shutdown();
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn ready_handles(&self) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
        Ok(self
            .lock_peers()?
            .iter()
            .map(|(id, peer)| (*id, Arc::clone(peer)))
            .collect())
    }

    fn candidate_addresses(&self) -> Result<Vec<SocketAddr>, HnsDirectPeerError> {
        let connected = self
            .ready_handles()?
            .into_iter()
            .filter_map(|(_, peer)| peer.lock().ok().map(|peer| peer.address))
            .collect::<HashSet<_>>();
        let target = self.config.target_peers.saturating_sub(connected.len());
        let mut candidates = self
            .known_addresses
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
            .iter()
            .copied()
            .filter(|address| !connected.contains(address))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        Ok(select_diverse_addresses(candidates, target))
    }

    fn add_known_addresses(
        &self,
        addresses: impl IntoIterator<Item = SocketAddr>,
        explicit: bool,
    ) -> Result<usize, HnsDirectPeerError> {
        let mut known = self
            .known_addresses
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?;
        let mut added = 0usize;
        for address in addresses {
            if known.len() >= MAX_DISCOVERED_ADDRESSES || !self.address_allowed(address, explicit) {
                continue;
            }
            added = added.saturating_add(usize::from(known.insert(address)));
        }
        Ok(added)
    }

    fn address_allowed(&self, address: SocketAddr, explicit: bool) -> bool {
        address.port() != 0
            && (explicit || address.port() == default_peer_port(self.config.network))
            && (self.config.allow_private_addresses || is_public_peer_ip(address.ip()))
    }

    fn lock_peers(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<PeerId, PeerHandle>>, HnsDirectPeerError> {
        self.peers
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)
    }
}

impl HnsLightNetwork for NativeHnsPeerPool {
    fn broadcast_transaction(&self, raw: &[u8]) -> Result<usize, HnsWalletError> {
        let transaction = Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
        let handles = self
            .ready_handles()
            .map_err(|error| HnsWalletError::Backend(error.to_string()))?;
        let written = std::thread::scope(|scope| {
            handles
                .into_iter()
                .map(|(_, peer)| {
                    let transaction = transaction.clone();
                    scope.spawn(move || {
                        peer.lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                            .connection
                            .send_wallet_packet(&Packet::Tx(transaction))?;
                        Ok::<_, HnsDirectPeerError>(())
                    })
                })
                .map(|task| usize::from(task.join().is_ok_and(|result| result.is_ok())))
                .sum::<usize>()
        });
        Ok(written)
    }
}

/// Complete wallet-owned direct HNS runtime. Clones share the same backend,
/// persistent connections, and in-flight header-round state.
#[derive(Clone)]
pub struct HnsDirectPeerCoordinator {
    backend: EmbeddedHnsBackend,
    pool: Arc<NativeHnsPeerPool>,
    pending_header: Arc<Mutex<Option<PendingHeaderRound>>>,
}

impl HnsDirectPeerCoordinator {
    /// Assemble the encrypted authority, wallet-only index, and native peer
    /// pool without any RPC node or trusted relay dependency.
    pub fn new(
        authority: EncryptedHnsLightAuthority,
        index: EncryptedHnsLightIndex,
        config: HnsDirectPeerConfig,
    ) -> Result<Self, HnsDirectPeerError> {
        if authority.consensus_network() != consensus_network(config.network)
            || index.consensus_network() != consensus_network(config.network)
        {
            return Err(HnsDirectPeerError::InvalidConfiguration);
        }
        let pool = Arc::new(NativeHnsPeerPool::new(config)?);
        let backend = EmbeddedHnsBackend::new(authority, index, pool.clone())?;
        Ok(Self {
            backend,
            pool,
            pending_header: Arc::new(Mutex::new(None)),
        })
    }

    /// Wallet backend used by send, receive, names, and settlement modules.
    #[must_use]
    pub const fn backend(&self) -> &EmbeddedHnsBackend {
        &self.backend
    }

    /// Latest locally validated chain floor for platform-protected rollback
    /// storage. A host persists this outside the encrypted wallet database
    /// after a successful header round and supplies it on the next open, so an
    /// authentic but older database backup cannot silently roll the wallet's
    /// chain authority backwards.
    pub fn rollback_floor(&self) -> Result<HnsLightFloor, HnsDirectPeerError> {
        self.backend
            .rollback_floor()
            .map_err(HnsDirectPeerError::Wallet)
    }

    /// Shared native peer pool used by the host/mobile runtime.
    #[must_use]
    pub const fn pool(&self) -> &Arc<NativeHnsPeerPool> {
        &self.pool
    }

    /// Connect one explicit or previously discovered peer and register its
    /// connection-scoped identity with local header agreement.
    pub fn connect_peer(
        &self,
        address: SocketAddr,
        now_unix: u64,
    ) -> Result<ConnectedHnsPeer, HnsDirectPeerError> {
        let height = self.backend.header_sync_status()?.tip.height().get();
        let connected = self.pool.connect(address, height, now_unix)?;
        if let Err(error) = self
            .backend
            .add_header_peer(connected.id, connected.metadata.height)
        {
            let _ = self.pool.disconnect(connected.id);
            return Err(error.into());
        }
        Ok(connected)
    }

    /// Resolve DNS seeds and fill the configured persistent outbound target.
    /// Connection attempts run concurrently so one dead address cannot impose
    /// serial timeout latency.
    pub fn connect_available(
        &self,
        now_unix: u64,
    ) -> Result<Vec<ConnectedHnsPeer>, HnsDirectPeerError> {
        let dns_error = self.pool.discover_dns().err();
        let candidates = self.pool.candidate_addresses()?;
        if candidates.is_empty() && self.pool.peer_count()? == 0 {
            return Err(dns_error.unwrap_or(HnsDirectPeerError::NoReadyPeers));
        }
        let attempts = std::thread::scope(|scope| {
            candidates
                .into_iter()
                .map(|address| scope.spawn(move || self.connect_peer(address, now_unix)))
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut connected = Vec::new();
        let mut last_error = None;
        for attempt in attempts {
            match attempt {
                Ok(Ok(peer)) => connected.push(peer),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(HnsDirectPeerError::WorkerPanicked),
            }
        }
        if connected.is_empty()
            && self.pool.peer_count()? == 0
            && let Some(error) = last_error
        {
            return Err(error);
        }
        Ok(connected)
    }

    /// Ask connected standard peers for address gossip and retain only bounded,
    /// network-port-correct candidates. Gossip is never chain authority.
    pub fn discover_from_connected(&self, now_unix: u64) -> Result<usize, HnsDirectPeerError> {
        let handles = self.pool.ready_handles()?;
        let results = std::thread::scope(|scope| {
            handles
                .into_iter()
                .map(|(_, peer)| {
                    scope.spawn(move || {
                        peer.lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                            .request_addresses(now_unix)
                    })
                })
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut addresses = Vec::new();
        for result in results {
            if let Ok(Ok(discovered)) = result {
                addresses.extend(discovered.into_iter().map(|address| address.socket_addr()));
            }
        }
        self.pool.add_known_addresses(addresses, false)
    }

    /// Execute one same-locator multi-peer header round. Peer reads run in
    /// parallel; only the local agreement engine can select and commit a tip.
    pub fn synchronize_headers_once(
        &self,
        now_unix: u64,
    ) -> Result<HnsHeaderRoundProgress, HnsDirectPeerError> {
        let pending = {
            let pending = self.lock_pending_header()?;
            *pending
        };
        if let Some(pending) = pending {
            return self.finish_or_report_header_round(pending, now_unix);
        }
        let handles = self.pool.ready_handles()?;
        if handles.is_empty() {
            return Err(HnsDirectPeerError::NoReadyPeers);
        }
        let ids = handles.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let request = self.backend.begin_header_round(&ids, now_unix)?;
        let mut pending = PendingHeaderRound {
            generation: request.generation,
            deadline: request.deadline,
            requested: ids.len(),
            submitted: 0,
        };
        *self.lock_pending_header()? = Some(pending);
        let responses = std::thread::scope(|scope| {
            handles
                .into_iter()
                .map(|(id, peer)| {
                    let locator = request.packet.locator.clone();
                    let stop = request.packet.stop;
                    scope.spawn(move || {
                        let response = peer
                            .lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)
                            .and_then(|mut peer| peer.request_headers(locator, stop, now_unix));
                        (id, response)
                    })
                })
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut submitted = 0usize;
        let mut failed = Vec::new();
        let mut worker_panicked = false;
        for response in responses {
            match response {
                Ok((id, Ok(headers))) => {
                    if self
                        .backend
                        .submit_header_response(
                            request.generation,
                            id,
                            headers,
                            now_unix_or(now_unix),
                        )
                        .is_ok()
                    {
                        submitted = submitted.saturating_add(1);
                    } else {
                        failed.push(id);
                    }
                }
                Ok((id, Err(_))) => failed.push(id),
                Err(_) => worker_panicked = true,
            }
        }
        pending.submitted = submitted;
        *self.lock_pending_header()? = Some(pending);
        for id in failed {
            self.disconnect_peer(id)?;
        }
        let progress = self.finish_or_report_header_round(pending, now_unix_or(now_unix))?;
        if worker_panicked && matches!(progress, HnsHeaderRoundProgress::AwaitingResponses { .. }) {
            return Err(HnsDirectPeerError::WorkerPanicked);
        }
        Ok(progress)
    }

    /// Fetch the same exact-root/key proof from every available peer in
    /// parallel, then accept the first proof that the local Urkel verifier and
    /// current-root binding admit.
    pub fn synchronize_name_proof(
        &self,
        name_hash: [u8; 32],
        now_unix: u64,
    ) -> Result<VerifiedHnsNameProof, HnsDirectPeerError> {
        let request = self.backend.name_proof_request(name_hash)?;
        let handles = self.pool.ready_handles()?;
        if handles.is_empty() {
            return Err(HnsDirectPeerError::NoReadyPeers);
        }
        let responses = std::thread::scope(|scope| {
            handles
                .into_iter()
                .map(|(id, peer)| {
                    scope.spawn(move || {
                        let response = peer
                            .lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)
                            .and_then(|mut peer| {
                                peer.request_proof(request.root, request.key, now_unix)
                            });
                        (id, response)
                    })
                })
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut failures = Vec::new();
        let mut verified = None;
        for response in responses {
            match response {
                Ok((id, Ok(proof))) => {
                    if let Ok(candidate) =
                        self.backend.admit_name_proof(&proof, now_unix_or(now_unix))
                    {
                        verified.get_or_insert(candidate);
                    } else {
                        failures.push(id);
                    }
                }
                Ok((id, Err(_))) => failures.push(id),
                Err(_) => return Err(HnsDirectPeerError::WorkerPanicked),
            }
        }
        for id in failures {
            self.disconnect_peer(id)?;
        }
        verified.ok_or(HnsDirectPeerError::NoValidNameProof)
    }

    /// Scan a bounded sequential header range using the same Bloom filter on
    /// independent peers. Every view is Merkle-verified against the wallet's
    /// authenticated header archive; their conflict-checked union is then
    /// filtered by the wallet's exact watch set before persistence.
    pub fn scan_wallet_blocks(
        &self,
        max_blocks: u32,
        now_unix: u64,
    ) -> Result<HnsBlockScanProgress, HnsDirectPeerError> {
        if max_blocks == 0 || max_blocks > MAX_SCAN_BLOCKS_PER_CALL {
            return Err(HnsDirectPeerError::InvalidScanLimit);
        }
        let status = self.backend.light_scan_status()?;
        let authority = self.backend.header_sync_status()?;
        let next_height = status
            .scanned_height
            .map_or(status.birthday_height, |height| height.saturating_add(1));
        let tip_height = authority.tip.height().get();
        if next_height > tip_height {
            return Ok(HnsBlockScanProgress {
                first_height: None,
                last_height: status.scanned_height,
                validated_tip_height: tip_height,
                blocks_applied: 0,
                transactions_admitted: 0,
                peer_views_verified: 0,
            });
        }
        let mut handles = self.pool.ready_handles()?;
        if handles.len() < self.pool.config.minimum_block_views {
            return Err(HnsDirectPeerError::InsufficientBlockViews {
                required: self.pool.config.minimum_block_views,
                actual: handles.len(),
            });
        }
        let elements = self.backend.light_bloom_elements()?;
        let filter = wallet_bloom_filter(&elements)?;
        let original_ids = handles.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        handles = install_filter_on_peers(handles, &filter)?;
        let installed_ids = handles.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
        for id in original_ids {
            if !installed_ids.contains(&id) {
                self.disconnect_peer(id)?;
            }
        }
        if handles.len() < self.pool.config.minimum_block_views {
            return Err(HnsDirectPeerError::InsufficientBlockViews {
                required: self.pool.config.minimum_block_views,
                actual: handles.len(),
            });
        }
        let last_height = tip_height.min(
            next_height
                .checked_add(max_blocks.saturating_sub(1))
                .ok_or(HnsDirectPeerError::Arithmetic)?,
        );
        let mut blocks_applied = 0u32;
        let mut transactions_admitted = 0usize;
        let mut peer_views_verified = 0usize;
        for height in next_height..=last_height {
            let anchor = self.backend.wallet_header_anchor(height)?;
            let responses = request_block_views(&handles, anchor, now_unix);
            let mut views = Vec::new();
            let mut survivors = Vec::new();
            let mut failed_ids = Vec::new();
            for ((id, handle), response) in handles.into_iter().zip(responses) {
                match response {
                    Ok(block) => {
                        views.push(block);
                        survivors.push((id, handle));
                    }
                    Err(_) => failed_ids.push(id),
                }
            }
            for id in failed_ids {
                self.disconnect_peer(id)?;
            }
            handles = survivors;
            if views.len() < self.pool.config.minimum_block_views {
                return Err(HnsDirectPeerError::InsufficientBlockViews {
                    required: self.pool.config.minimum_block_views,
                    actual: views.len(),
                });
            }
            peer_views_verified = peer_views_verified.saturating_add(views.len());
            let merged = VerifiedWalletBlock::merge_peer_views(&views)
                .map_err(|error| HnsDirectPeerError::WalletEvidence(error.to_string()))?;
            transactions_admitted = transactions_admitted
                .checked_add(
                    self.backend
                        .apply_verified_block(&merged, now_unix_or(now_unix))?,
                )
                .ok_or(HnsDirectPeerError::Arithmetic)?;
            blocks_applied = blocks_applied
                .checked_add(1)
                .ok_or(HnsDirectPeerError::Arithmetic)?;
        }
        Ok(HnsBlockScanProgress {
            first_height: Some(next_height),
            last_height: Some(last_height),
            validated_tip_height: tip_height,
            blocks_applied,
            transactions_admitted,
            peer_views_verified,
        })
    }

    /// Request standard mempool inventory and admit bounded relevant
    /// transactions plus peer fee floors into the local backend.
    pub fn refresh_mempool(&self, now_unix: u64) -> Result<usize, HnsDirectPeerError> {
        let handles = self.pool.ready_handles()?;
        if handles.is_empty() {
            return Err(HnsDirectPeerError::NoReadyPeers);
        }
        let wait = self.pool.config.event_poll_timeout;
        let results = std::thread::scope(|scope| {
            handles
                .iter()
                .map(|(id, peer)| {
                    let id = *id;
                    let peer = Arc::clone(peer);
                    scope.spawn(move || {
                        let mut peer = peer
                            .lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?;
                        peer.connection.send_wallet_packet(&Packet::Mempool)?;
                        let events = peer.poll_wallet_events(wait, now_unix)?;
                        Ok::<_, HnsDirectPeerError>((id, events))
                    })
                })
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut admitted = 0usize;
        for result in results {
            let (id, events) = result.map_err(|_| HnsDirectPeerError::WorkerPanicked)??;
            admitted = admitted
                .checked_add(self.process_wallet_events(id, events, now_unix)?)
                .ok_or(HnsDirectPeerError::Arithmetic)?;
        }
        Ok(admitted)
    }

    fn process_wallet_events(
        &self,
        id: PeerId,
        events: Vec<WalletPeerEvent>,
        now_unix: u64,
    ) -> Result<usize, HnsDirectPeerError> {
        let mut admitted = 0usize;
        let mut requested = Vec::new();
        for event in events {
            match event {
                WalletPeerEvent::FeeFilter(rate) => {
                    let _ = self.backend.observe_peer_fee_rate(id, rate);
                }
                WalletPeerEvent::Transaction(transaction) => {
                    admitted = admitted.saturating_add(usize::from(
                        self.backend
                            .admit_mempool_transaction(transaction, now_unix)?
                            .is_some(),
                    ));
                }
                WalletPeerEvent::Inventory(inventory) => {
                    requested.extend(
                        inventory
                            .into_iter()
                            .filter(|item| item.kind == InventoryKind::Transaction),
                    );
                }
                WalletPeerEvent::DataRequest(_)
                | WalletPeerEvent::NotFound(_)
                | WalletPeerEvent::MerkleBlock(_) => {}
            }
        }
        if !requested.is_empty()
            && let Some((_, peer)) = self
                .pool
                .ready_handles()?
                .into_iter()
                .find(|(peer_id, _)| *peer_id == id)
        {
            peer.lock()
                .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                .connection
                .send_wallet_packet(&Packet::GetData(requested))?;
        }
        Ok(admitted)
    }

    fn disconnect_peer(&self, id: PeerId) -> Result<(), HnsDirectPeerError> {
        let _ = self.pool.disconnect(id)?;
        let _ = self.backend.remove_header_peer(id)?;
        Ok(())
    }

    fn finish_or_report_header_round(
        &self,
        pending: PendingHeaderRound,
        now_unix: u64,
    ) -> Result<HnsHeaderRoundProgress, HnsDirectPeerError> {
        match self.backend.try_finish_header_round(now_unix) {
            Ok(Some(round)) => {
                *self.lock_pending_header()? = None;
                Ok(HnsHeaderRoundProgress::Committed(round))
            }
            Ok(None) => Ok(HnsHeaderRoundProgress::AwaitingResponses {
                generation: pending.generation,
                deadline: pending.deadline,
                requested: pending.requested,
                submitted: pending.submitted,
            }),
            Err(error) => {
                *self.lock_pending_header()? = None;
                Err(error.into())
            }
        }
    }

    fn lock_pending_header(
        &self,
    ) -> Result<MutexGuard<'_, Option<PendingHeaderRound>>, HnsDirectPeerError> {
        self.pending_header
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)
    }
}

/// Open the direct peer coordinator owned by one encrypted wallet account.
///
/// This is the composition boundary used by installed mobile, browser, and
/// extension wallets: no RPC endpoint, node credential, relay, or external
/// index is accepted. The persisted account is re-authenticated while its
/// complete public watch set is derived, then that exact set is installed into
/// the encrypted filtered-block index before any direct peer scan can begin.
pub fn open_wallet_direct_hns_peer_coordinator(
    store: SharedWalletStore,
    account: &HnsRuntimeConfig,
    peer_config: HnsDirectPeerConfig,
    now_unix: u64,
) -> Result<HnsDirectPeerCoordinator, HnsDirectPeerError> {
    open_wallet_direct_hns_peer_coordinator_with_floor(
        store,
        account,
        peer_config,
        HnsLightFloor::default(),
        now_unix,
    )
}

/// Open the direct coordinator with the platform-held monotonic rollback
/// floor. Installed wallets must use this constructor; the compatibility
/// wrapper above remains for deterministic in-memory callers that have no
/// platform storage boundary.
pub fn open_wallet_direct_hns_peer_coordinator_with_floor(
    store: SharedWalletStore,
    account: &HnsRuntimeConfig,
    peer_config: HnsDirectPeerConfig,
    rollback_floor: HnsLightFloor,
    now_unix: u64,
) -> Result<HnsDirectPeerCoordinator, HnsDirectPeerError> {
    open_wallet_direct_hns_peer_coordinator_with_initializer(
        store,
        account,
        peer_config,
        rollback_floor,
        now_unix,
        |_| Ok(()),
    )
}

/// Open a direct coordinator after replacing a pristine new-wallet genesis
/// checkpoint with a locally verified, product-pinned header acceleration
/// stream. The stream is never peer authority: after it is committed the
/// coordinator remains in header-syncing state and requires fresh direct-peer
/// agreement before it can issue current-chain evidence.
pub fn open_wallet_direct_hns_peer_coordinator_with_floor_and_genesis_bootstrap<I>(
    store: SharedWalletStore,
    account: &HnsRuntimeConfig,
    peer_config: HnsDirectPeerConfig,
    rollback_floor: HnsLightFloor,
    expected_height: u32,
    expected_hash: [u8; 32],
    headers: I,
    now_unix: u64,
) -> Result<HnsDirectPeerCoordinator, HnsDirectPeerError>
where
    I: IntoIterator<Item = Header>,
{
    open_wallet_direct_hns_peer_coordinator_with_initializer(
        store,
        account,
        peer_config,
        rollback_floor,
        now_unix,
        |authority| {
            authority
                .bootstrap_from_genesis_headers(headers, expected_height, expected_hash, now_unix)
                .map(|_| ())
        },
    )
}

fn open_wallet_direct_hns_peer_coordinator_with_initializer<F>(
    store: SharedWalletStore,
    account: &HnsRuntimeConfig,
    peer_config: HnsDirectPeerConfig,
    rollback_floor: HnsLightFloor,
    now_unix: u64,
    initialize_authority: F,
) -> Result<HnsDirectPeerCoordinator, HnsDirectPeerError>
where
    F: FnOnce(&mut EncryptedHnsLightAuthority) -> Result<(), crate::HnsLightError>,
{
    account
        .validate_structure()
        .map_err(HnsDirectPeerError::Wallet)?;
    if peer_config.network != account.network {
        return Err(HnsDirectPeerError::InvalidConfiguration);
    }
    let birthday_height = u32::try_from(account.birthday_height)
        .map_err(|_| HnsDirectPeerError::InvalidConfiguration)?;
    let watch_set = store
        .try_with_store(|wallet| derive_hns_light_watch_set(wallet, account))
        .map_err(HnsDirectPeerError::Wallet)?;
    let sync_config = SyncConfig {
        max_peers: peer_config.target_peers,
        minimum_peer_agreement: peer_config.minimum_block_views,
        round_timeout_seconds: peer_config.connect_timeout.as_secs(),
        max_peer_failures: 3,
    };
    let mut authority = EncryptedHnsLightAuthority::open_or_create(
        store.clone(),
        account.account_id,
        account.network,
        birthday_height,
        rollback_floor,
        BlockTime::new(now_unix),
        ChainLimits::default(),
        sync_config,
    )
    .map_err(|error| HnsDirectPeerError::LightAuthority(error.to_string()))?;
    initialize_authority(&mut authority)
        .map_err(|error| HnsDirectPeerError::LightAuthority(error.to_string()))?;
    let mut index = EncryptedHnsLightIndex::open_or_create(
        store,
        account.account_id,
        account.network,
        birthday_height,
        now_unix,
    )
    .map_err(|error| HnsDirectPeerError::LightIndex(error.to_string()))?;
    index
        .install_watch_set(watch_set, now_unix)
        .map_err(|error| HnsDirectPeerError::LightIndex(error.to_string()))?;
    HnsDirectPeerCoordinator::new(authority, index, peer_config)
}

impl NativePeer {
    fn request_headers(
        &mut self,
        locator: Vec<BlockHash>,
        stop: BlockHash,
        now_unix: u64,
    ) -> Result<Vec<Header>, HnsDirectPeerError> {
        self.connection.request_headers(locator, stop, now_unix)?;
        for _ in 0..MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix_or(now_unix))? {
                PeerEvent::Headers(headers) => return Ok(headers),
                PeerEvent::Wallet(event) => self.defer_wallet(event)?,
                PeerEvent::Addresses(_)
                | PeerEvent::Ignored(_)
                | PeerEvent::Pong(_)
                | PeerEvent::Ready(_) => {}
                PeerEvent::Rejected(reject) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                PeerEvent::Proof(_) | PeerEvent::Send(_) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

    fn request_proof(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        now_unix: u64,
    ) -> Result<ProofPacket, HnsDirectPeerError> {
        self.connection.request_proof(root, key, now_unix)?;
        for _ in 0..MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix_or(now_unix))? {
                PeerEvent::Proof(proof) => return Ok(proof),
                PeerEvent::Wallet(event) => self.defer_wallet(event)?,
                PeerEvent::Addresses(_)
                | PeerEvent::Ignored(_)
                | PeerEvent::Pong(_)
                | PeerEvent::Ready(_) => {}
                PeerEvent::Rejected(reject) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                PeerEvent::Headers(_) | PeerEvent::Send(_) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

    fn request_addresses(&mut self, now_unix: u64) -> Result<Vec<NetAddress>, HnsDirectPeerError> {
        self.connection.request_addresses()?;
        for _ in 0..MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix_or(now_unix))? {
                PeerEvent::Addresses(addresses) => {
                    return Ok(addresses
                        .into_iter()
                        .filter(|address| {
                            address.services & (SERVICE_NETWORK | SERVICE_BLOOM)
                                == SERVICE_NETWORK | SERVICE_BLOOM
                        })
                        .collect());
                }
                PeerEvent::Wallet(event) => self.defer_wallet(event)?,
                PeerEvent::Ignored(_) | PeerEvent::Pong(_) | PeerEvent::Ready(_) => {}
                PeerEvent::Rejected(reject) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                PeerEvent::Headers(_) | PeerEvent::Proof(_) | PeerEvent::Send(_) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

    fn request_filtered_block(
        &mut self,
        anchor: WalletHeaderAnchor,
        now_unix: u64,
    ) -> Result<VerifiedWalletBlock, HnsDirectPeerError> {
        let expected_hash = anchor.hash().into_bytes();
        self.connection
            .send_wallet_packet(&Packet::GetData(vec![Inventory {
                kind: InventoryKind::FilteredBlock,
                hash: expected_hash,
            }]))?;
        let mut collector = None;
        let mut expected_transactions = HashSet::new();
        for _ in 0..MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix_or(now_unix))? {
                PeerEvent::Wallet(WalletPeerEvent::MerkleBlock(payload)) => {
                    if collector.is_some() {
                        return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                    }
                    let evidence = WalletBlockEvidence::decode_for_anchor(&payload, anchor)
                        .map_err(|error| HnsDirectPeerError::WalletEvidence(error.to_string()))?;
                    expected_transactions
                        .extend(evidence.matches().iter().map(|matched| matched.hash()));
                    let block_collector = evidence
                        .collect()
                        .map_err(|error| HnsDirectPeerError::WalletEvidence(error.to_string()))?;
                    if block_collector.remaining() == 0 {
                        return block_collector.finish().map_err(|error| {
                            HnsDirectPeerError::WalletEvidence(error.to_string())
                        });
                    }
                    collector = Some(block_collector);
                }
                PeerEvent::Wallet(WalletPeerEvent::Transaction(transaction)) => {
                    let hash = transaction
                        .transaction_hash()
                        .map_err(|error| HnsDirectPeerError::WalletEvidence(error.to_string()))?;
                    if expected_transactions.remove(&hash) {
                        let remaining = collector
                            .as_mut()
                            .ok_or(HnsDirectPeerError::UnexpectedPeerEvent)?
                            .admit(transaction)
                            .map_err(|error| {
                                HnsDirectPeerError::WalletEvidence(error.to_string())
                            })?;
                        if remaining == 0 {
                            return collector
                                .take()
                                .ok_or(HnsDirectPeerError::UnexpectedPeerEvent)?
                                .finish()
                                .map_err(|error| {
                                    HnsDirectPeerError::WalletEvidence(error.to_string())
                                });
                        }
                    } else {
                        self.defer_wallet(WalletPeerEvent::Transaction(transaction))?;
                    }
                }
                PeerEvent::Wallet(WalletPeerEvent::NotFound(inventory))
                    if inventory.iter().any(|item| {
                        item.kind == InventoryKind::FilteredBlock && item.hash == expected_hash
                    }) =>
                {
                    return Err(HnsDirectPeerError::FilteredBlockUnavailable);
                }
                PeerEvent::Wallet(event) => self.defer_wallet(event)?,
                PeerEvent::Addresses(_)
                | PeerEvent::Ignored(_)
                | PeerEvent::Pong(_)
                | PeerEvent::Ready(_) => {}
                PeerEvent::Rejected(reject) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                PeerEvent::Headers(_) | PeerEvent::Proof(_) | PeerEvent::Send(_) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

    fn poll_wallet_events(
        &mut self,
        timeout: Duration,
        now_unix: u64,
    ) -> Result<Vec<WalletPeerEvent>, HnsDirectPeerError> {
        let original_timeout = self
            .connection
            .transport()
            .read_timeout()
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        self.connection
            .transport_mut()
            .set_read_timeout(Some(timeout))
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        let result = self.poll_wallet_events_inner(now_unix);
        let restore = self
            .connection
            .transport_mut()
            .set_read_timeout(original_timeout)
            .map_err(|error| HnsDirectPeerError::Io(error.kind()));
        match (result, restore) {
            (Ok(events), Ok(())) => Ok(events),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn poll_wallet_events_inner(
        &mut self,
        now_unix: u64,
    ) -> Result<Vec<WalletPeerEvent>, HnsDirectPeerError> {
        let mut events = self.deferred_wallet.drain(..).collect::<Vec<_>>();
        for _ in events.len()..MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix_or(now_unix)) {
                Ok(PeerEvent::Wallet(event)) => events.push(event),
                Ok(
                    PeerEvent::Addresses(_)
                    | PeerEvent::Ignored(_)
                    | PeerEvent::Pong(_)
                    | PeerEvent::Ready(_),
                ) => {}
                Ok(PeerEvent::Rejected(_)) => {}
                Ok(PeerEvent::Headers(_) | PeerEvent::Proof(_) | PeerEvent::Send(_)) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
                Err(PeerError::Io(
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
                )) => return Ok(events),
                Err(error) => return Err(error.into()),
            }
        }
        if events.len() >= MAX_RESPONSE_EVENTS {
            return Err(HnsDirectPeerError::ResponseEventLimit);
        }
        Ok(events)
    }

    fn defer_wallet(&mut self, event: WalletPeerEvent) -> Result<(), HnsDirectPeerError> {
        if self.deferred_wallet.len() >= MAX_RESPONSE_EVENTS {
            return Err(HnsDirectPeerError::ResponseEventLimit);
        }
        self.deferred_wallet.push_back(event);
        Ok(())
    }
}

fn install_filter_on_peers(
    handles: Vec<(PeerId, PeerHandle)>,
    filter: &HsdBloomFilter,
) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
    let results = std::thread::scope(|scope| {
        handles
            .iter()
            .map(|(id, peer)| {
                let id = *id;
                let peer = Arc::clone(peer);
                let packet = filter.load_packet();
                scope.spawn(move || {
                    peer.lock()
                        .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                        .connection
                        .send_wallet_packet(&packet)?;
                    Ok::<_, HnsDirectPeerError>(id)
                })
            })
            .map(|task| task.join())
            .collect::<Vec<_>>()
    });
    let successful = results
        .into_iter()
        .filter_map(|result| result.ok().and_then(Result::ok))
        .collect::<HashSet<_>>();
    Ok(handles
        .into_iter()
        .filter(|(id, _)| successful.contains(id))
        .collect())
}

fn request_block_views(
    handles: &[(PeerId, PeerHandle)],
    anchor: WalletHeaderAnchor,
    now_unix: u64,
) -> Vec<Result<VerifiedWalletBlock, HnsDirectPeerError>> {
    std::thread::scope(|scope| {
        handles
            .iter()
            .map(|(_, peer)| {
                let peer = Arc::clone(peer);
                scope.spawn(move || {
                    peer.lock()
                        .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                        .request_filtered_block(anchor, now_unix)
                })
            })
            .map(|task| {
                task.join()
                    .unwrap_or(Err(HnsDirectPeerError::WorkerPanicked))
            })
            .collect()
    })
}

fn wallet_bloom_filter(elements: &[Vec<u8>]) -> Result<HsdBloomFilter, HnsDirectPeerError> {
    if elements.is_empty() {
        return Err(HnsDirectPeerError::EmptyWatchSet);
    }
    let expected = elements
        .len()
        .checked_add(BLOOM_GROWTH_RESERVE)
        .ok_or(HnsDirectPeerError::Arithmetic)?;
    let mut tweak = [0_u8; 4];
    getrandom::fill(&mut tweak).map_err(|_| HnsDirectPeerError::Randomness)?;
    let mut filter = HsdBloomFilter::from_rate(
        expected,
        BLOOM_FALSE_POSITIVE_RATE,
        u32::from_le_bytes(tweak),
        BloomUpdate::All,
    )
    .map_err(|error| HnsDirectPeerError::Bloom(error.to_string()))?;
    for element in elements {
        filter
            .insert(element)
            .map_err(|error| HnsDirectPeerError::Bloom(error.to_string()))?;
    }
    Ok(filter)
}

fn connection_peer_id(
    network: HnsNetwork,
    address: SocketAddr,
    local_nonce: [u8; 8],
    metadata: &PeerMetadata,
) -> PeerId {
    let mut hasher = Sha256::new();
    hasher.update(PEER_ID_DOMAIN);
    hasher.update([network_id(network)]);
    match address.ip() {
        IpAddr::V4(ip) => hasher.update(ip.to_ipv6_mapped().octets()),
        IpAddr::V6(ip) => hasher.update(ip.octets()),
    }
    hasher.update(address.port().to_be_bytes());
    hasher.update(local_nonce);
    hasher.update(metadata.version.to_be_bytes());
    hasher.update(metadata.services.to_be_bytes());
    hasher.update(metadata.time.to_be_bytes());
    hasher.update(metadata.height.to_be_bytes());
    hasher.update(metadata.agent.as_bytes());
    PeerId::new(hasher.finalize().into())
}

fn select_diverse_addresses(candidates: Vec<SocketAddr>, limit: usize) -> Vec<SocketAddr> {
    let mut selected = Vec::new();
    let mut groups = HashSet::new();
    for address in &candidates {
        if selected.len() >= limit {
            return selected;
        }
        if groups.insert(address_group(*address)) {
            selected.push(*address);
        }
    }
    for address in candidates {
        if selected.len() >= limit {
            break;
        }
        if !selected.contains(&address) {
            selected.push(address);
        }
    }
    selected
}

fn address_group(address: SocketAddr) -> [u8; 4] {
    match address.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            [4, octets[0], octets[1], 0]
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            [6, octets[0], octets[1], octets[2]]
        }
    }
}

fn is_public_peer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && matches!(b, 18 | 19)))
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (octets[0] & 0xfe) == 0xfc
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        || (octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8))
}

const fn network_magic(network: HnsNetwork) -> NetworkMagic {
    match network {
        HnsNetwork::Mainnet => NetworkMagic::Mainnet,
        HnsNetwork::Testnet => NetworkMagic::Testnet,
        HnsNetwork::Regtest => NetworkMagic::Regtest,
        HnsNetwork::Simnet => NetworkMagic::Simnet,
    }
}

const fn consensus_network(network: HnsNetwork) -> Network {
    match network {
        HnsNetwork::Mainnet => Network::Mainnet,
        HnsNetwork::Testnet => Network::Testnet,
        HnsNetwork::Regtest => Network::Regtest,
        HnsNetwork::Simnet => Network::Simnet,
    }
}

const fn network_id(network: HnsNetwork) -> u8 {
    match network {
        HnsNetwork::Mainnet => 0,
        HnsNetwork::Testnet => 1,
        HnsNetwork::Regtest => 2,
        HnsNetwork::Simnet => 3,
    }
}

const fn default_peer_port(network: HnsNetwork) -> u16 {
    match network {
        HnsNetwork::Mainnet => 12_038,
        HnsNetwork::Testnet => 13_038,
        HnsNetwork::Regtest => 14_038,
        HnsNetwork::Simnet => 15_038,
    }
}

const fn default_dns_seeds(network: HnsNetwork) -> &'static [&'static str] {
    match network {
        HnsNetwork::Mainnet => &["hs-mainnet.bcoin.ninja", "seed.htools.work"],
        HnsNetwork::Testnet => &["hs-testnet.bcoin.ninja"],
        HnsNetwork::Regtest | HnsNetwork::Simnet => &[],
    }
}

fn now_unix_or(fallback: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(fallback, |duration| duration.as_secs())
}

/// Direct-peer construction, transport, or locally verified data failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HnsDirectPeerError {
    #[error(transparent)]
    Wallet(#[from] HnsWalletError),
    #[error("wallet-owned HNS light authority could not be opened: {0}")]
    LightAuthority(String),
    #[error("wallet-owned HNS filtered-block index could not be opened: {0}")]
    LightIndex(String),
    #[error("standard Handshake peer failed: {0}")]
    Peer(String),
    #[error("standard Handshake peer I/O failed: {0:?}")]
    Io(std::io::ErrorKind),
    #[error("direct-peer configuration is invalid")]
    InvalidConfiguration,
    #[error("peer address is not allowed by the selected network policy")]
    AddressNotAllowed,
    #[error("the configured direct-peer target is already full")]
    PeerLimit,
    #[error("the peer address or connection identity is already active")]
    DuplicatePeer,
    #[error("no ready standard Handshake peers are connected")]
    NoReadyPeers,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("direct-peer runtime lock is poisoned")]
    RuntimePoisoned,
    #[error("a direct-peer worker panicked")]
    WorkerPanicked,
    #[error("peer response exceeded the bounded event count")]
    ResponseEventLimit,
    #[error("peer returned an event outside the active request")]
    UnexpectedPeerEvent,
    #[error("peer rejected the direct request: {0}")]
    PeerRejected(String),
    #[error("peer could not provide the requested filtered block")]
    FilteredBlockUnavailable,
    #[error("wallet block evidence failed: {0}")]
    WalletEvidence(String),
    #[error("Bloom-filter construction failed: {0}")]
    Bloom(String),
    #[error("the wallet watch set is empty")]
    EmptyWatchSet,
    #[error("filtered-block scan limit is invalid")]
    InvalidScanLimit,
    #[error("only {actual} independent block views are available; {required} required")]
    InsufficientBlockViews { required: usize, actual: usize },
    #[error("no peer supplied a locally valid current-root name proof")]
    NoValidNameProof,
    #[error("checked direct-peer arithmetic failed")]
    Arithmetic,
}

impl From<PeerError> for HnsDirectPeerError {
    fn from(error: PeerError) -> Self {
        match error {
            PeerError::Io(kind) => Self::Io(kind),
            error => Self::Peer(error.to_string()),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic fixtures"
)]
mod tests {
    use super::*;
    use hns_wallet_store::{SecretKind, WalletStore};
    use hns_wallet_types::{AccountId, BaseUnits, WalletId};

    fn direct_wallet_config() -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: WalletId::new([71; 16]),
            account_id: AccountId::new([72; 16]),
            account_derivation_index: 0,
            network: HnsNetwork::Regtest,
            birthday_height: 0,
            restore_lookahead: 1,
            minimum_confirmations: 1,
            dust_threshold: BaseUnits::new(crate::DEFAULT_DUST_THRESHOLD),
            value_operations_enabled: false,
            settlement_enabled: false,
        }
    }

    #[test]
    fn direct_wallet_factory_derives_and_installs_the_persisted_account_watch_set() {
        let config = direct_wallet_config();
        let mut wallet = WalletStore::create(":memory:", "direct wallet test passphrase").unwrap();
        wallet
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[73; 64],
                1,
            )
            .unwrap();
        let account = crate::HnsAccountRecord::initial_non_value(config.clone()).unwrap();
        wallet
            .save_wallet_account(&crate::account_entity_id(&config), 0, &account, 1)
            .unwrap();
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let coordinator = open_wallet_direct_hns_peer_coordinator(
            hns_wallet_store::SharedWalletStore::new(wallet),
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now,
        )
        .unwrap();
        let scan = coordinator.backend().light_scan_status().unwrap();
        assert_eq!(scan.watched_scripts, 4);
        assert_eq!(scan.watched_names, 0);
        assert_eq!(scan.birthday_height, 0);
    }

    #[test]
    fn production_defaults_use_diverse_untrusted_peers() {
        let mainnet = HnsDirectPeerConfig::for_network(HnsNetwork::Mainnet);
        assert_eq!(mainnet.target_peers, 3);
        assert_eq!(mainnet.minimum_block_views, 2);
        assert!(!mainnet.allow_private_addresses);
        assert_eq!(mainnet.dns_seeds, default_dns_seeds(HnsNetwork::Mainnet));
        mainnet.validate().unwrap();

        let regtest = HnsDirectPeerConfig::for_network(HnsNetwork::Regtest);
        assert_eq!(regtest.target_peers, 1);
        assert_eq!(regtest.minimum_block_views, 1);
        assert!(regtest.allow_private_addresses);
        assert!(regtest.dns_seeds.is_empty());
    }

    #[test]
    fn discovered_addresses_are_public_default_port_only() {
        assert!(is_public_peer_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_peer_ip("2606:4700:4700::1111".parse().unwrap()));
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_peer_ip(blocked.parse().unwrap()), "{blocked}");
        }
    }

    #[test]
    fn candidate_selection_prefers_independent_address_groups() {
        let selected = select_diverse_addresses(
            [
                "1.1.1.1:12038",
                "1.1.2.1:12038",
                "8.8.8.8:12038",
                "9.9.9.9:12038",
            ]
            .into_iter()
            .map(|address| address.parse().unwrap())
            .collect(),
            3,
        );
        assert_eq!(selected[0], "1.1.1.1:12038".parse().unwrap());
        assert_eq!(selected[1], "8.8.8.8:12038".parse().unwrap());
        assert_eq!(selected[2], "9.9.9.9:12038".parse().unwrap());
    }

    #[test]
    fn wallet_filter_contains_every_local_authority_element() {
        let elements = vec![vec![1; 20], vec![2; 32], vec![3; 36]];
        let filter = wallet_bloom_filter(&elements).unwrap();
        assert!(elements.iter().all(|element| filter.contains(element)));
        assert_eq!(filter.update(), BloomUpdate::All);
    }
}
