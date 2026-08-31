//! Direct standard-peer synchronization for the wallet-owned HNS authority.
//!
//! DNS seeds, address gossip, and connected HSD peers are discovery and data
//! transports only. Headers, partial Merkle trees, transactions, and Urkel
//! proofs cross the wallet's local verification boundaries before they mutate
//! durable state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hns_covenants::{hash_name, validate_name};
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
use hns_marketplace_protocol::{
    CrossChainMessage, MAX_SHAKESCAPE_MARKET_PAYLOAD, NameMarketHello, NameMarketMessage,
    ShakescapeRegistryVersion,
};
use hns_p2p_experimental::{
    ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION, NegotiatedRegistry,
    Network as ExperimentalNetwork, ProtocolRange, RegistryHello,
    SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD, SHAKESCAPE_EXTENSION_PACKET,
    SHAKESCAPE_EXTENSION_SERVICE, SHAKESCAPE_V1_REGISTRY_FINGERPRINT,
    SHAKESCAPE_V1_REGISTRY_VERSION, ShakescapeExtensionEnvelope,
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
    derive_hns_light_watch_set_with_restore_extension,
};
use hns_wallet_store::SharedWalletStore;

const PEER_ID_DOMAIN: &[u8] = b"hns-wallet-rs/direct-peer-id/v1";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DIRECT_PEERS: usize = 64;
const MAX_RESPONSE_EVENTS: usize = 4_096;
const MAX_DISCOVERED_ADDRESSES: usize = 1_024;
const MAX_SCAN_BLOCKS_PER_CALL: u32 = 2_000;
// Handshake permits large `getdata` vectors, but retaining a modest request
// window bounds memory, a peer's outstanding work, and the amount that must
// be retried after a transport failure. It also removes the per-height round
// trip that made historical wallet scans progress at roughly one block/sec.
const FILTERED_BLOCK_REQUEST_WINDOW: u32 = 64;
// A scan must obtain two full, independently verified views. Prefer peers
// that have recently returned those views quickly, but periodically rotate a
// request through the warm reserve so a changed network path can be measured
// and selected later. A 16-batch cadence limits a known slow reserve's impact
// on a mobile backfill while still refreshing it every 1,024 headers. This
// only changes availability/performance selection; every accepted block still
// requires the configured exact proof quorum.
const BLOCK_SCAN_PEER_EXPLORATION_INTERVAL: usize = 16;
const BLOCK_SCAN_PEER_LATENCY_OLD_WEIGHT: u64 = 3;
const BLOCK_SCAN_PEER_LATENCY_WEIGHT: u64 = BLOCK_SCAN_PEER_LATENCY_OLD_WEIGHT + 1;
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01;
const BLOOM_GROWTH_RESERVE: usize = 1_024;
const SHAKESCAPE_MAX_RESPONSE_EVENTS: usize = 256;
const SHAKESCAPE_MAXIMUM_LIVE_REQUESTS: u16 = 64;
/// A direct index only grows after it has authenticated a trailing-gap
/// discovery. Eight complete extra gaps fit comfortably under the direct
/// watch-set bound for reviewed wallet defaults while preventing unbounded
/// recovery if a corrupted or adversarial account repeatedly lands on a
/// boundary. When recovery is required, the coordinator installs the largest
/// of these bounded frontiers at once: advancing by one gap per historical
/// re-scan makes a legitimate wallet at successive boundaries re-scan the
/// same chain repeatedly.
const MAX_WALLET_WATCH_SET_RESTORE_EXTENSIONS: u32 = 8;

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
    /// Timing for the newly durable scan batch that ended at this progress
    /// point. It contains no peer address or wallet information.
    pub batch_telemetry: Option<HnsBlockScanBatchTelemetry>,
}

/// Local timing breakdown for one atomically persisted filtered-block batch.
///
/// The peer timings identify whether the scan is delivery-bound without
/// exposing a peer address, account, watched script, or transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsBlockScanBatchTelemetry {
    pub first_height: u32,
    pub last_height: u32,
    pub blocks: u32,
    /// Wall time to obtain the independent quorum's full filtered-block views.
    pub peer_fetch_millis: u64,
    /// Fastest successful individual peer-view response in the quorum.
    pub fastest_peer_fetch_millis: u64,
    /// Slowest successful individual peer-view response in the quorum.
    pub slowest_peer_fetch_millis: u64,
    /// Time outside successful peer socket reads, including quorum selection,
    /// worker scheduling, and any failover request. This lets mobile hosts
    /// distinguish device contention from normal peer-delivery latency.
    pub peer_coordination_millis: u64,
    /// Time to merge every independent view into locally verified blocks.
    pub merge_millis: u64,
    /// Time to plan and atomically commit wallet observations and scan head.
    pub commit_millis: u64,
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

/// One direct Shakescape Experimental V2 session owned by the wallet.
///
/// The peer is an ordinary Handshake TCP peer. It is not an RPC endpoint or a
/// trusted marketplace service: registry negotiation binds the wire profile
/// and every offer remains subject to the wallet's independent board and
/// current-lock validation.
pub struct HnsDirectShakescapePeer {
    address: SocketAddr,
    network: HnsNetwork,
    connection: PeerConnection<TcpStream>,
    negotiated: NegotiatedRegistry,
    next_request_id: u64,
}

/// One canonical Shakescape application message received on a negotiated direct
/// peer. Name-market replication and direct HNS/BTC offers share only the
/// socket; they retain separate protocol identities and validation paths.
// `NameMarketMessage` is intentionally carried by value: this is a public
// direct-peer boundary and boxing it would create an unnecessary allocation
// and API change on the hot receive path.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsDirectShakescapeMessage {
    NameMarket {
        request_id: u64,
        message: NameMarketMessage,
    },
    CrossChain {
        envelope: Vec<u8>,
    },
}

/// A wallet-owned, nonblocking TCP admission point for direct Shakescape peers.
///
/// This listener is deliberately narrower than a Handshake node listener. It
/// accepts no chain, wallet-filter, RPC, indexing, or arbitrary experimental
/// traffic. A caller obtains a negotiated [`HnsDirectShakescapePeer`] only after
/// the standard Handshake handshake and the exact Shakescape V1 registry agreement
/// have both completed. The caller remains responsible for deciding when an
/// unlocked wallet may service a bounded board exchange.
pub struct HnsDirectShakescapeListener {
    listener: TcpListener,
    config: HnsDirectPeerConfig,
}

impl HnsDirectShakescapeListener {
    /// Bind one explicit local socket for direct wallet-to-wallet Shakescape
    /// sessions. A port of zero is useful for deterministic local pairing
    /// tests; an installed wallet supplies its user-visible listening port.
    pub fn bind(
        config: HnsDirectPeerConfig,
        address: SocketAddr,
    ) -> Result<Self, HnsDirectPeerError> {
        config.validate()?;
        let listener =
            TcpListener::bind(address).map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        Ok(Self { listener, config })
    }

    /// The actual local address, including a kernel-selected port when zero
    /// was supplied to [`Self::bind`]. This is a transport locator only.
    pub fn local_addr(&self) -> Result<SocketAddr, HnsDirectPeerError> {
        self.listener
            .local_addr()
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))
    }

    /// Accept at most one pending TCP connection and bind it to the direct
    /// Shakescape protocol. `Ok(None)` means there is no pending connection.
    ///
    /// The accepted handshake is bounded by the peer configuration's socket
    /// deadlines. Callers should invoke this from their owned I/O worker and
    /// must not retain a peer after the associated wallet is locked.
    pub fn accept_next(
        &self,
        local_height: u32,
        now_unix: u64,
    ) -> Result<Option<HnsDirectShakescapePeer>, HnsDirectPeerError> {
        let (stream, _) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(HnsDirectPeerError::Io(error.kind())),
        };
        stream
            .set_read_timeout(Some(self.config.connect_timeout))
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        stream
            .set_write_timeout(Some(self.config.connect_timeout))
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        HnsDirectShakescapePeer::accept(&self.config, stream, local_height, now_unix).map(Some)
    }
}

impl HnsDirectShakescapePeer {
    /// Establish the standard peer session and exact Shakescape V1 registry
    /// agreement with one configured direct peer.
    pub fn connect(
        config: &HnsDirectPeerConfig,
        address: SocketAddr,
        local_height: u32,
        now_unix: u64,
    ) -> Result<Self, HnsDirectPeerError> {
        config.validate()?;
        let explicit = config.static_peers.contains(&address);
        if !direct_address_allowed(config, address, explicit) {
            return Err(HnsDirectPeerError::AddressNotAllowed);
        }
        let request_id = nonzero_shakescape_request_id()?;
        let local_version =
            direct_shakescape_version(address, request_id.to_be_bytes(), local_height, now_unix);
        let mut connection = PeerConnection::connect(
            address,
            PeerConfig::for_network(network_magic(config.network)),
            &local_version,
            now_unix,
            config.connect_timeout,
        )?;
        let metadata = connection.complete_handshake(|| now_unix_or(now_unix))?;
        if metadata.services & SHAKESCAPE_EXTENSION_SERVICE.value() == 0 {
            return Err(HnsDirectPeerError::ShakescapePeerNotAdvertised);
        }
        let local_hello = shakescape_registry_hello(config.network)?;
        let outbound = ShakescapeExtensionEnvelope::registry_hello(request_id, &local_hello)
            .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?
            .encode_canonical()
            .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
        connection.send_experimental_packet(SHAKESCAPE_EXTENSION_PACKET.value(), outbound)?;
        let negotiated =
            receive_shakescape_hello_ack(&mut connection, config.network, request_id, now_unix)?;
        Ok(Self {
            address,
            network: config.network,
            connection,
            negotiated,
            next_request_id: request_id.checked_add(1).unwrap_or(1),
        })
    }

    /// Bind one socket accepted by a wallet-hosted listener to the exact
    /// Shakescape V1 atomic-market profile.
    ///
    /// The accepted remote's source port is necessarily ephemeral, so inbound
    /// admission applies the network's public/private-address policy but does
    /// not require the ordinary Handshake listening port. The socket remains a
    /// transport only: every received board record still crosses the wallet's
    /// independent current-chain validation boundary.
    pub fn accept(
        config: &HnsDirectPeerConfig,
        stream: TcpStream,
        local_height: u32,
        now_unix: u64,
    ) -> Result<Self, HnsDirectPeerError> {
        config.validate()?;
        let address = stream
            .peer_addr()
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        if !inbound_shakescape_address_allowed(config, address) {
            return Err(HnsDirectPeerError::AddressNotAllowed);
        }
        let request_id = nonzero_shakescape_request_id()?;
        let local_version =
            direct_shakescape_version(address, request_id.to_be_bytes(), local_height, now_unix);
        let mut connection = PeerConnection::accept(
            stream,
            PeerConfig::for_network(network_magic(config.network)),
            &local_version,
            now_unix,
        )
        .map_err(|error| HnsDirectPeerError::Peer(error.to_string()))?;
        let metadata = connection
            .complete_handshake(|| now_unix_or(now_unix))
            .map_err(|error| HnsDirectPeerError::Peer(error.to_string()))?;
        if metadata.services & SHAKESCAPE_EXTENSION_SERVICE.value() == 0 {
            return Err(HnsDirectPeerError::ShakescapePeerNotAdvertised);
        }
        let negotiated =
            respond_shakescape_registry_hello(&mut connection, config.network, now_unix)?;
        Ok(Self {
            address,
            network: config.network,
            connection,
            negotiated,
            next_request_id: request_id.checked_add(1).unwrap_or(1),
        })
    }

    /// Direct socket peer address. It is a transport locator, never an
    /// authority identifier.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The exact negotiated Shakescape registry evidence for this connection.
    #[must_use]
    pub const fn negotiated_registry(&self) -> &NegotiatedRegistry {
        &self.negotiated
    }

    /// Send one canonical Shakescape name-market message over this negotiated
    /// direct peer session and return its nonzero correlation id.
    pub fn send_name_market(
        &mut self,
        message: &NameMarketMessage,
    ) -> Result<u64, HnsDirectPeerError> {
        let request_id = self.next_request_id;
        self.send_name_market_with_request_id(request_id, message)?;
        self.next_request_id = request_id.checked_add(1).unwrap_or(1);
        Ok(request_id)
    }

    /// Respond to one peer request with the same nonzero correlation id.
    /// This is intentionally separate from [`Self::send_name_market`]: callers
    /// may use it only for protocol-defined response families after locally
    /// validating the original request.
    pub fn send_name_market_with_request_id(
        &mut self,
        request_id: u64,
        message: &NameMarketMessage,
    ) -> Result<(), HnsDirectPeerError> {
        if request_id == 0 {
            return Err(HnsDirectPeerError::Shakescape(
                "Shakescape name-market request id must be nonzero".to_owned(),
            ));
        }
        let payload = message
            .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
            .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
        self.connection
            .send_experimental_packet(SHAKESCAPE_EXTENSION_PACKET.value(), payload)?;
        Ok(())
    }

    /// Receive one canonical name-market message from this direct peer.
    ///
    /// Registry negotiation is complete before this method can return bytes.
    /// Callers must still correlate request ids and validate listing or
    /// cancellation semantics before changing durable board state.
    pub fn receive_name_market(
        &mut self,
        now_unix: u64,
    ) -> Result<(u64, NameMarketMessage), HnsDirectPeerError> {
        match self.receive_shakescape_message(now_unix)? {
            HnsDirectShakescapeMessage::NameMarket {
                request_id,
                message,
            } => Ok((request_id, message)),
            HnsDirectShakescapeMessage::CrossChain { .. } => Err(HnsDirectPeerError::Shakescape(
                "received a cross-chain Shakescape envelope in a name-market-only exchange"
                    .to_owned(),
            )),
        }
    }

    /// Receive one canonical Shakescape application envelope and classify it by
    /// protocol identity. This performs no market admission or swap state
    /// transition; the caller routes the typed message to its local authority.
    pub fn receive_shakescape_message(
        &mut self,
        now_unix: u64,
    ) -> Result<HnsDirectShakescapeMessage, HnsDirectPeerError> {
        for _ in 0..SHAKESCAPE_MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix)? {
                PeerEvent::Experimental {
                    packet_type,
                    payload,
                } if packet_type == SHAKESCAPE_EXTENSION_PACKET.value() => {
                    let envelope = ShakescapeExtensionEnvelope::decode(
                        &payload,
                        MAX_SHAKESCAPE_MARKET_PAYLOAD,
                    )
                    .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
                    if envelope.protocol_id == hns_p2p_experimental::CROSS_CHAIN_MARKET_PROTOCOL_ID
                    {
                        validate_cross_chain_envelope(&payload)?;
                        return Ok(HnsDirectShakescapeMessage::CrossChain { envelope: payload });
                    }
                    let (registry, request_id, message) =
                        NameMarketMessage::decode_envelope(&payload)
                            .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
                    if registry != ShakescapeRegistryVersion::V1 || request_id == 0 {
                        return Err(HnsDirectPeerError::Shakescape(
                            "invalid Shakescape V1 name-market envelope".to_owned(),
                        ));
                    }
                    validate_shakescape_market_hello(self.network, &message)?;
                    return Ok(HnsDirectShakescapeMessage::NameMarket {
                        request_id,
                        message,
                    });
                }
                PeerEvent::Experimental { .. }
                | PeerEvent::Ignored(_)
                | PeerEvent::Addresses(_)
                | PeerEvent::Wallet(_) => {}
                PeerEvent::Rejected(reject) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                PeerEvent::Ready(_)
                | PeerEvent::Send(_)
                | PeerEvent::Headers(_)
                | PeerEvent::Proof(_)
                | PeerEvent::Pong(_) => return Err(HnsDirectPeerError::UnexpectedPeerEvent),
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

    /// Send one exact canonical Shakescape HNS/BTC session envelope over the
    /// already-negotiated direct socket. The peer remains transport only: the
    /// mobile market controller admits the specific message, correlation, and
    /// session state before any durable mutation or HTLC action.
    pub fn send_cross_chain_envelope(&mut self, envelope: &[u8]) -> Result<(), HnsDirectPeerError> {
        validate_cross_chain_envelope(envelope)?;
        self.connection
            .send_experimental_packet(SHAKESCAPE_EXTENSION_PACKET.value(), envelope.to_vec())?;
        Ok(())
    }

    /// Send one canonical cross-chain message under a fresh nonzero
    /// correlation id and return that id. A distinct id is retained even for
    /// inventory messages so every follow-up get/offer exchange is
    /// unambiguous to the direct peer.
    pub fn send_cross_chain_message(
        &mut self,
        message: &CrossChainMessage,
    ) -> Result<u64, HnsDirectPeerError> {
        let request_id = self.next_request_id;
        self.send_cross_chain_message_with_request_id(request_id, message)?;
        self.next_request_id = request_id.checked_add(1).unwrap_or(1);
        Ok(request_id)
    }

    /// Send one canonical cross-chain response under the caller's already
    /// validated request id.
    pub fn send_cross_chain_message_with_request_id(
        &mut self,
        request_id: u64,
        message: &CrossChainMessage,
    ) -> Result<(), HnsDirectPeerError> {
        let envelope = message
            .encode_envelope(request_id)
            .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
        self.send_cross_chain_envelope(&envelope)
    }

    /// Receive one canonical HNS/BTC Shakescape envelope from the direct socket.
    /// This never accepts a generic experimental payload or performs a market
    /// state transition; callers must route it to the persisted market
    /// handshake controller for its exact expected stage.
    pub fn receive_cross_chain_envelope(
        &mut self,
        now_unix: u64,
    ) -> Result<Vec<u8>, HnsDirectPeerError> {
        match self.receive_shakescape_message(now_unix)? {
            HnsDirectShakescapeMessage::CrossChain { envelope } => Ok(envelope),
            HnsDirectShakescapeMessage::NameMarket { .. } => Err(HnsDirectPeerError::Shakescape(
                "received a name-market Shakescape envelope in a cross-chain-only exchange"
                    .to_owned(),
            )),
        }
    }
}

fn nonzero_shakescape_request_id() -> Result<u64, HnsDirectPeerError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| HnsDirectPeerError::Randomness)?;
        let request_id = u64::from_be_bytes(bytes);
        if request_id != 0 {
            return Ok(request_id);
        }
    }
    Err(HnsDirectPeerError::Randomness)
}

/// Construct the standard Handshake peer advertisement for a wallet-hosted
/// Shakescape exchange. The extension service augments, rather than replaces, the
/// mandatory standard `NETWORK` bit: a Shakescape wallet remains a Handshake peer
/// on the ordinary wire and interoperates with peers that enforce the normal
/// service admission rule.
fn direct_shakescape_version(
    remote: SocketAddr,
    nonce: [u8; 8],
    local_height: u32,
    now_unix: u64,
) -> hns_p2p_wire::VersionPacket {
    let mut version = light_wallet_version(remote, nonce, local_height, now_unix);
    version.services = SERVICE_NETWORK | SHAKESCAPE_EXTENSION_SERVICE.value();
    version
}

fn shakescape_registry_hello(network: HnsNetwork) -> Result<RegistryHello, HnsDirectPeerError> {
    let binding = crate::shakedex_network_binding(network)?;
    RegistryHello::shakescape_v1(
        experimental_network(network),
        *binding.genesis.as_bytes(),
        vec![ProtocolRange {
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            minimum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
            maximum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
        }],
        u32::try_from(SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD.min(MAX_SHAKESCAPE_MARKET_PAYLOAD))
            .map_err(|_| HnsDirectPeerError::Arithmetic)?,
        SHAKESCAPE_MAXIMUM_LIVE_REQUESTS,
        0,
    )
    .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))
}

fn receive_shakescape_hello_ack(
    connection: &mut PeerConnection<TcpStream>,
    network: HnsNetwork,
    request_id: u64,
    now_unix: u64,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let local = shakescape_registry_hello(network)?;
    for _ in 0..SHAKESCAPE_MAX_RESPONSE_EVENTS {
        match connection.receive_event(now_unix)? {
            PeerEvent::Experimental {
                packet_type,
                payload,
            } if packet_type == SHAKESCAPE_EXTENSION_PACKET.value() => {
                let (received_request_id, remote) =
                    ShakescapeExtensionEnvelope::decode_registry_hello_ack(&payload)
                        .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
                if received_request_id != request_id {
                    return Err(HnsDirectPeerError::Shakescape(
                        "Shakescape registry hello acknowledgement correlation mismatch".to_owned(),
                    ));
                }
                return exact_shakescape_v1_atomic_market(&local, &remote);
            }
            PeerEvent::Experimental { .. }
            | PeerEvent::Ignored(_)
            | PeerEvent::Addresses(_)
            | PeerEvent::Wallet(_) => {}
            PeerEvent::Rejected(reject) => {
                return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
            }
            PeerEvent::Ready(_)
            | PeerEvent::Send(_)
            | PeerEvent::Headers(_)
            | PeerEvent::Proof(_)
            | PeerEvent::Pong(_) => return Err(HnsDirectPeerError::UnexpectedPeerEvent),
        }
    }
    Err(HnsDirectPeerError::ResponseEventLimit)
}

fn respond_shakescape_registry_hello(
    connection: &mut PeerConnection<TcpStream>,
    network: HnsNetwork,
    now_unix: u64,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let local = shakescape_registry_hello(network)?;
    for _ in 0..SHAKESCAPE_MAX_RESPONSE_EVENTS {
        match connection.receive_event(now_unix)? {
            PeerEvent::Experimental {
                packet_type,
                payload,
            } if packet_type == SHAKESCAPE_EXTENSION_PACKET.value() => {
                let (request_id, remote) =
                    ShakescapeExtensionEnvelope::decode_registry_hello(&payload)
                        .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
                if request_id == 0 {
                    return Err(HnsDirectPeerError::Shakescape(
                        "Shakescape registry hello request id must be nonzero".to_owned(),
                    ));
                }
                let negotiated = exact_shakescape_v1_atomic_market(&local, &remote)?;
                let ack = ShakescapeExtensionEnvelope::registry_hello_ack(request_id, &local)
                    .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?
                    .encode_canonical()
                    .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
                connection
                    .send_experimental_packet(SHAKESCAPE_EXTENSION_PACKET.value(), ack)
                    .map_err(|error| HnsDirectPeerError::Peer(error.to_string()))?;
                return Ok(negotiated);
            }
            PeerEvent::Experimental { .. }
            | PeerEvent::Ignored(_)
            | PeerEvent::Addresses(_)
            | PeerEvent::Wallet(_) => {}
            PeerEvent::Rejected(reject) => {
                return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
            }
            PeerEvent::Ready(_)
            | PeerEvent::Send(_)
            | PeerEvent::Headers(_)
            | PeerEvent::Proof(_)
            | PeerEvent::Pong(_) => return Err(HnsDirectPeerError::UnexpectedPeerEvent),
        }
    }
    Err(HnsDirectPeerError::ResponseEventLimit)
}

fn exact_shakescape_v1_atomic_market(
    local: &RegistryHello,
    remote: &RegistryHello,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let negotiated = NegotiatedRegistry::negotiate(local, remote)
        .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
    if negotiated.registry_version != SHAKESCAPE_V1_REGISTRY_VERSION
        || negotiated.fingerprint != SHAKESCAPE_V1_REGISTRY_FINGERPRINT
        || !negotiated
            .protocols
            .contains(&(ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION))
    {
        return Err(HnsDirectPeerError::Shakescape(
            "Shakescape peer lacks exact V2 atomic-market admission".to_owned(),
        ));
    }
    Ok(negotiated)
}

fn validate_shakescape_market_hello(
    network: HnsNetwork,
    message: &NameMarketMessage,
) -> Result<(), HnsDirectPeerError> {
    let NameMarketMessage::Hello(NameMarketHello {
        hns_magic,
        hns_genesis,
        ..
    }) = message
    else {
        return Ok(());
    };
    let binding = crate::shakedex_network_binding(network)?;
    if *hns_magic != binding.magic || hns_genesis.as_bytes() != binding.genesis.as_bytes() {
        return Err(HnsDirectPeerError::Shakescape(
            "Shakescape name-market hello has wrong Handshake network binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cross_chain_envelope(envelope: &[u8]) -> Result<(), HnsDirectPeerError> {
    if envelope.is_empty() || envelope.len() > MAX_SHAKESCAPE_MARKET_PAYLOAD {
        return Err(HnsDirectPeerError::Shakescape(
            "Shakescape cross-chain envelope exceeds its exact bound".to_owned(),
        ));
    }
    let (request_id, message) = CrossChainMessage::decode_envelope(envelope)
        .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
    let canonical = message
        .encode_envelope(request_id)
        .map_err(|error| HnsDirectPeerError::Shakescape(error.to_string()))?;
    if canonical != envelope {
        return Err(HnsDirectPeerError::Shakescape(
            "Shakescape cross-chain envelope is not canonical".to_owned(),
        ));
    }
    Ok(())
}

const fn experimental_network(network: HnsNetwork) -> ExperimentalNetwork {
    match network {
        HnsNetwork::Mainnet => ExperimentalNetwork::Mainnet,
        HnsNetwork::Testnet => ExperimentalNetwork::Testnet,
        HnsNetwork::Regtest => ExperimentalNetwork::Regtest,
        HnsNetwork::Simnet => ExperimentalNetwork::Simnet,
    }
}

fn direct_address_allowed(
    config: &HnsDirectPeerConfig,
    address: SocketAddr,
    explicit: bool,
) -> bool {
    address.port() != 0
        && (explicit || address.port() == default_peer_port(config.network))
        && (config.allow_private_addresses || is_public_peer_ip(address.ip()))
}

fn inbound_shakescape_address_allowed(config: &HnsDirectPeerConfig, address: SocketAddr) -> bool {
    address.port() != 0 && (config.allow_private_addresses || is_public_peer_ip(address.ip()))
}

type PeerHandle = Arc<Mutex<NativePeer>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanPeerLatency {
    /// A small exponentially weighted moving average. It responds to recent
    /// mobile-network changes without allowing one exceptional request to
    /// permanently exile a peer from future quorum probes.
    ewma_millis: u64,
}

impl ScanPeerLatency {
    const fn initial(sample_millis: u64) -> Self {
        Self {
            ewma_millis: sample_millis,
        }
    }

    fn observe(&mut self, sample_millis: u64) {
        self.ewma_millis = self
            .ewma_millis
            .saturating_mul(BLOCK_SCAN_PEER_LATENCY_OLD_WEIGHT)
            .saturating_add(sample_millis)
            / BLOCK_SCAN_PEER_LATENCY_WEIGHT;
    }
}

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
        let transaction_hash = transaction
            .transaction_hash()
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        let handles = self
            .ready_handles()
            .map_err(|error| HnsWalletError::Backend(error.to_string()))?;
        let results = std::thread::scope(|scope| {
            let tasks = handles
                .into_iter()
                .map(|(_, peer)| {
                    let transaction = transaction.clone();
                    // Reuse the bounded connection deadline for the peer's
                    // inventory round trip. The shorter event-poll interval
                    // is intended for best-effort mempool draining and is too
                    // aggressive for transaction delivery on mobile links.
                    let timeout = self.config.connect_timeout;
                    scope.spawn(move || {
                        peer.lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                            .announce_transaction(transaction, transaction_hash, timeout)
                    })
                })
                .collect::<Vec<_>>();
            tasks
                .into_iter()
                .map(|task| {
                    task.join()
                        .map_err(|_| HnsDirectPeerError::WorkerPanicked)
                        .and_then(|result| result)
                })
                .collect::<Vec<_>>()
        });
        let delivered = results
            .iter()
            .filter(|result| matches!(result, Ok(true)))
            .count();
        if delivered == 0
            && let Some(error) = results.into_iter().find_map(Result::err)
        {
            return Err(HnsWalletError::Backend(error.to_string()));
        }
        Ok(delivered)
    }
}

/// Complete wallet-owned direct HNS runtime. Clones share the same backend,
/// persistent connections, and in-flight header-round state.
#[derive(Clone)]
pub struct HnsDirectPeerCoordinator {
    backend: EmbeddedHnsBackend,
    pool: Arc<NativeHnsPeerPool>,
    config: HnsDirectPeerConfig,
    wallet_watch_set_source: Option<WalletWatchSetSource>,
    pending_header: Arc<Mutex<Option<PendingHeaderRound>>>,
    // The persistent peer pool is deliberately wider than a single header
    // agreement round. `hns_light_sync` requires every selected response to
    // complete a round, so selecting the entire pool would turn optional
    // discovery/failover peers into a much stronger availability requirement.
    // Advance this cursor only for new rounds, retaining the exact selected
    // set while a pending round is still awaiting its deadline.
    next_header_peer_offset: Arc<AtomicUsize>,
    // A wallet scan needs the same exact independent quorum as a header
    // round, not every connected failover peer. Keep a distinct cursor so
    // scan batches rotate through the ready pool without perturbing header
    // agreement selection.
    next_block_peer_offset: Arc<AtomicUsize>,
    // Counts scan-quorum selections independently of the rotating offset.
    // This permits a latency-preferred normal path while retaining a regular
    // deterministic reserve probe.
    block_scan_selection_count: Arc<AtomicUsize>,
    // Ephemeral performance data only: a connection-scoped peer identifier
    // maps to its recent filtered-block response time. It is deliberately not
    // wallet state and is discarded when this coordinator is dropped.
    block_scan_peer_latencies: Arc<Mutex<HashMap<PeerId, ScanPeerLatency>>>,
}

/// Private recovery authority retained only by coordinators created from one
/// unlocked wallet. It lets that coordinator deterministically extend its own
/// public Bloom-filter set after an authenticated trailing-gap discovery.
/// Generic coordinators never receive this capability.
#[derive(Clone)]
struct WalletWatchSetSource {
    store: SharedWalletStore,
    account: HnsRuntimeConfig,
}

impl WalletWatchSetSource {
    /// Re-read the exact account configuration that owns this coordinator's
    /// derivation source. Account policy flags can change when the native
    /// value controller is activated, but the wallet/account/network/birthday
    /// identity must never change underneath a live direct coordinator.
    fn current_account_config(&self) -> Result<HnsRuntimeConfig, HnsDirectPeerError> {
        let expected_id = crate::account_entity_id(&self.account);
        self.store
            .try_with_store(|wallet| {
                let account = wallet
                    .wallet_account::<crate::HnsAccountRecord>(&expected_id)?
                    .ok_or(HnsWalletError::AccountConfigurationMismatch)?;
                if account.id != expected_id
                    || !crate::same_account_identity(&account.value.config, &self.account)
                {
                    return Err(HnsWalletError::AccountConfigurationMismatch);
                }
                account.value.config.validate_structure()?;
                Ok(account.value.config)
            })
            .map_err(HnsDirectPeerError::Wallet)
    }
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
        let pool = Arc::new(NativeHnsPeerPool::new(config.clone())?);
        let backend = EmbeddedHnsBackend::new(authority, index, pool.clone())?;
        Ok(Self {
            backend,
            pool,
            config,
            wallet_watch_set_source: None,
            pending_header: Arc::new(Mutex::new(None)),
            next_header_peer_offset: Arc::new(AtomicUsize::new(0)),
            next_block_peer_offset: Arc::new(AtomicUsize::new(0)),
            block_scan_selection_count: Arc::new(AtomicUsize::new(0)),
            block_scan_peer_latencies: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Wallet backend used by send, receive, names, and settlement modules.
    #[must_use]
    pub const fn backend(&self) -> &EmbeddedHnsBackend {
        &self.backend
    }

    /// Bind one wallet-owned direct Shakescape listener with the exact validated
    /// peer policy already used by this coordinator.
    ///
    /// The listener inherits the selected Handshake network, private-address
    /// policy, deadlines, and peer policy. A caller cannot accidentally bind
    /// a Shakescape transport on a network or policy that differs from the direct
    /// backend providing this wallet's chain and value evidence.
    pub fn bind_shakescape_listener(
        &self,
        address: SocketAddr,
    ) -> Result<HnsDirectShakescapeListener, HnsDirectPeerError> {
        HnsDirectShakescapeListener::bind(self.config.clone(), address)
    }

    /// Connect one direct Shakescape peer with the exact validated peer policy
    /// already used by this coordinator.
    ///
    /// The socket remains an untrusted, explicitly scheduled transport. This
    /// method does not synchronize the wallet, service a board exchange, or
    /// authorize any value operation.
    pub fn connect_shakescape_peer(
        &self,
        address: SocketAddr,
        local_height: u32,
        now_unix: u64,
    ) -> Result<HnsDirectShakescapePeer, HnsDirectPeerError> {
        HnsDirectShakescapePeer::connect(&self.config, address, local_height, now_unix)
    }

    /// Extend the wallet-owned direct watch set to the largest bounded restore
    /// frontier and atomically rewind the filtered-block index if it changed.
    ///
    /// This is valid only for coordinators opened through the wallet factory.
    /// It is idempotent so products can install the complete bounded frontier
    /// before their first activity scan instead of discovering an incomplete
    /// filter only after finalization. The method does not accept scripts from
    /// the host and does not publish any wallet data.
    pub fn extend_wallet_restore_watch_set(
        &self,
        now_unix: u64,
    ) -> Result<bool, HnsDirectPeerError> {
        let source = self
            .wallet_watch_set_source
            .as_ref()
            .ok_or(HnsDirectPeerError::InvalidConfiguration)?;
        // Value activation updates the authenticated account record with its
        // current capability policy. The direct coordinator must not retain a
        // pre-activation copy of that whole record: doing so would turn a
        // legitimate value-runtime transition into an account mismatch and
        // strand a restore scan just when it needs to grow its trailing gap.
        // Re-read the exact same account identity from the shared encrypted
        // store for every extension. The store remains the only derivation
        // authority; this method still accepts neither a host-supplied script
        // nor a replacement account configuration.
        let account = source.current_account_config()?;
        let installed = self
            .backend
            .light_watch_set()
            .map_err(HnsDirectPeerError::Wallet)?;
        let base = source
            .store
            .try_with_store(|wallet| derive_hns_light_watch_set(wallet, &account))
            .map_err(HnsDirectPeerError::Wallet)?;
        let mut largest_candidate = None;
        for extension in 1..=MAX_WALLET_WATCH_SET_RESTORE_EXTENSIONS {
            let candidate = source
                .store
                .try_with_store(|wallet| {
                    derive_hns_light_watch_set_with_restore_extension(wallet, &account, extension)
                })
                .map_err(HnsDirectPeerError::Wallet)?;
            largest_candidate = Some(candidate);
        }
        let candidate = largest_candidate.ok_or(HnsDirectPeerError::Wallet(
            HnsWalletError::ScanCapacityExhausted,
        ))?;
        // A completed recovery can advance only one derivation branch by a
        // non-window-aligned amount. The previously pre-expanded set remains
        // complete in that case even though it is no longer exactly equal to
        // `current base + N whole windows`. Keep that authenticated coverage
        // until the required base actually reaches an unscanned script.
        if installed != base && deterministic_watch_set_covers(&installed, &base, &candidate) {
            return Ok(false);
        }
        if candidate == installed {
            return Ok(false);
        }
        self.backend
            .install_watch_set(candidate, now_unix)
            .map_err(HnsDirectPeerError::Wallet)
    }

    fn with_wallet_watch_set_source(
        mut self,
        store: SharedWalletStore,
        account: HnsRuntimeConfig,
    ) -> Self {
        self.wallet_watch_set_source = Some(WalletWatchSetSource { store, account });
        self
    }

    /// Clone the embedded backend that shares this coordinator's direct peer,
    /// header, filtered-block, and broadcast authority.
    ///
    /// The clone shares one encrypted light index and header authority with
    /// this coordinator. A product that needs later direct synchronization
    /// must retain the coordinator rather than silently substituting an RPC
    /// backend after handing this clone to the value runtime.
    #[must_use]
    pub fn embedded_backend(&self) -> EmbeddedHnsBackend {
        self.backend.clone()
    }

    /// Confirm that this wallet-factory coordinator was opened for the exact
    /// account configuration expected by an adjacent product controller.
    ///
    /// Generic coordinators created with [`Self::new`] deliberately have no
    /// wallet-account source and cannot pass this check. This prevents a
    /// caller from composing a direct backend opened for another account into
    /// a mobile value controller merely because both use the same network.
    pub fn require_wallet_account_config(
        &self,
        expected: &HnsRuntimeConfig,
    ) -> Result<(), HnsDirectPeerError> {
        let source = self
            .wallet_watch_set_source
            .as_ref()
            .ok_or(HnsDirectPeerError::InvalidConfiguration)?;
        // A mobile lifecycle controller deliberately locks the shared store
        // after opening its coordinator. Comparing the immutable factory
        // binding here proves the composition before that controller consumes
        // itself, without attempting a second store read while it is locked.
        // Subsequent restore extensions run only while the value controller is
        // unlocked and re-read the persisted current policy there.
        if source.account != *expected {
            return Err(HnsDirectPeerError::Wallet(
                HnsWalletError::AccountConfigurationMismatch,
            ));
        }
        Ok(())
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
            let tasks = candidates
                .into_iter()
                .map(|address| scope.spawn(move || self.connect_peer(address, now_unix)))
                .collect::<Vec<_>>();
            tasks
                .into_iter()
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
            let tasks = handles
                .into_iter()
                .map(|(_, peer)| {
                    scope.spawn(move || {
                        peer.lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                            .request_addresses(now_unix)
                    })
                })
                .collect::<Vec<_>>();
            tasks
                .into_iter()
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
        let handles = self.header_round_handles()?;
        if handles.is_empty() {
            return Err(HnsDirectPeerError::NoReadyPeers);
        }
        let ids = handles.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let request = self.backend.begin_header_round(&ids, now_unix)?;
        // Some HSD peers do not emit an explicit empty `headers` packet when
        // the first locator hash is already their tip.  Ask from the prior
        // locator instead: a peer at our existing tip must then return the
        // exact known tip before it can prove that no extension follows.  The
        // response is normalized below, so the agreement engine still sees
        // only headers extending its own authenticated base.
        let locator = header_freshness_locator(&request.packet.locator);
        let mut pending = PendingHeaderRound {
            generation: request.generation,
            deadline: request.deadline,
            requested: ids.len(),
            submitted: 0,
        };
        *self.lock_pending_header()? = Some(pending);
        let responses = std::thread::scope(|scope| {
            let tasks = handles
                .into_iter()
                .map(|(id, peer)| {
                    let locator = locator.clone();
                    let stop = request.packet.stop;
                    scope.spawn(move || {
                        let response = peer
                            .lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)
                            .and_then(|mut peer| peer.request_headers(locator, stop, now_unix));
                        (id, response)
                    })
                })
                .collect::<Vec<_>>();
            tasks
                .into_iter()
                .map(|task| task.join())
                .collect::<Vec<_>>()
        });
        let mut submitted = 0usize;
        let mut failed = Vec::new();
        let mut worker_panicked = false;
        for response in responses {
            match response {
                Ok((id, Ok(headers))) => {
                    let headers = normalize_header_freshness_response(headers, request.base_hash);
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
        // Each selected peer request above is synchronous: every worker has
        // either yielded one bounded header response or failed before this
        // point. Keeping an under-filled round open until its wall-clock
        // deadline cannot produce another response; it only stalls mobile
        // recovery for the full I/O timeout before it may rotate to the next
        // independent peer pair. Close that terminal round immediately so
        // the caller can refill and retry while its synchronization lease is
        // still active. A completed quorum retains its actual completion
        // time for normal validation and persistence.
        let finished_at =
            header_round_finished_at(pending, submitted, worker_panicked, now_unix_or(now_unix))?;
        self.finish_or_report_header_round(pending, finished_at)
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
            let tasks = handles
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
                .collect::<Vec<_>>();
            tasks
                .into_iter()
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

    /// Fetch and locally verify one exact Handshake name proof from ordinary
    /// peers. The textual name is validated and hashed inside the wallet
    /// boundary so mobile callers cannot substitute a different proof key.
    pub fn synchronize_name_proof_exact_text(
        &self,
        name: &str,
        now_unix: u64,
    ) -> Result<VerifiedHnsNameProof, HnsDirectPeerError> {
        let name = name.as_bytes();
        if !validate_name(name) {
            return Err(HnsWalletError::InvalidName.into());
        }
        let name_hash = hash_name(name)
            .map_err(|_| HnsWalletError::InvalidName)?
            .into_bytes();
        self.extend_wallet_name_proof_watch_set(name_hash, now_unix)?;
        self.synchronize_name_proof(name_hash, now_unix)
    }

    /// Add one explicit canonical name to a wallet-owned direct index before
    /// asking peers for its exact proof.
    ///
    /// Fresh imports are not present in the persisted known-name list yet, so
    /// they cannot be part of the initial direct watch set.  The proof request
    /// must nevertheless be admitted by that set.  Extend only the name-hash
    /// member while retaining the existing authenticated script scan; the
    /// proof and normal import validation still decide whether the name is
    /// persisted or classified as wallet-controlled.
    fn extend_wallet_name_proof_watch_set(
        &self,
        name_hash: [u8; 32],
        now_unix: u64,
    ) -> Result<(), HnsDirectPeerError> {
        let installed = self
            .backend
            .light_watch_set()
            .map_err(HnsDirectPeerError::Wallet)?;
        if installed.name_hashes.binary_search(&name_hash).is_ok() {
            return Ok(());
        }
        let source = self
            .wallet_watch_set_source
            .as_ref()
            .ok_or(HnsDirectPeerError::InvalidConfiguration)?;
        // The source is intentionally re-read from the unlocked encrypted
        // store. This proves the coordinator still belongs to the selected
        // wallet before it retains any new proof material.
        let account = source.current_account_config()?;
        let persisted = source
            .store
            .try_with_store(|wallet| derive_hns_light_watch_set(wallet, &account))
            .map_err(HnsDirectPeerError::Wallet)?;
        if persisted.name_hashes.binary_search(&name_hash).is_ok() {
            // A persisted name missing from the installed set indicates an
            // incomplete historical index, not a new import. Restore the
            // complete deterministic set and require the normal one-time
            // historical catch-up before using its proof.
            self.backend
                .install_watch_set(persisted, now_unix)
                .map_err(HnsDirectPeerError::Wallet)?;
            return Ok(());
        }
        self.backend
            .extend_name_watch_set_without_rewind(&[name_hash], now_unix)
            .map_err(HnsDirectPeerError::Wallet)?;
        Ok(())
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
        self.scan_wallet_blocks_with_progress(max_blocks, now_unix, |_| {})
    }

    /// Scan a bounded sequential header range and publish only verified,
    /// persisted progress after each applied block. The callback carries no
    /// wallet projection, so hosts can render live catch-up without exposing
    /// balances, history, addresses, names, or spend authority.
    pub fn scan_wallet_blocks_with_progress(
        &self,
        max_blocks: u32,
        now_unix: u64,
        mut on_progress: impl FnMut(HnsBlockScanProgress),
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
                batch_telemetry: None,
            });
        }
        let mut available_handles = self.pool.ready_handles()?;
        if available_handles.len() < self.pool.config.minimum_block_views {
            return Err(HnsDirectPeerError::InsufficientBlockViews {
                required: self.pool.config.minimum_block_views,
                actual: available_handles.len(),
            });
        }
        let elements = self.backend.light_bloom_elements()?;
        let filter = wallet_bloom_filter(&elements)?;
        let original_ids = available_handles
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        available_handles = install_filter_on_peers(available_handles, &filter)?;
        let installed_ids = available_handles
            .iter()
            .map(|(id, _)| *id)
            .collect::<HashSet<_>>();
        for id in original_ids {
            if !installed_ids.contains(&id) {
                self.disconnect_peer(id)?;
            }
        }
        if available_handles.len() < self.pool.config.minimum_block_views {
            return Err(HnsDirectPeerError::InsufficientBlockViews {
                required: self.pool.config.minimum_block_views,
                actual: available_handles.len(),
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
        let mut first_unscanned = next_height;
        let mut last_batch_telemetry = None;
        while first_unscanned <= last_height {
            let batch_last = filtered_block_batch_last(first_unscanned, last_height);
            let anchors = (first_unscanned..=batch_last)
                .map(|height| self.backend.wallet_header_anchor(height))
                .collect::<Result<Vec<_>, _>>()?;
            let mut views = Vec::new();
            let mut attempted_ids = HashSet::new();
            let peer_fetch_started = Instant::now();
            let mut successful_peer_fetches = Vec::new();
            while views.len() < self.pool.config.minimum_block_views {
                let required = self.pool.config.minimum_block_views - views.len();
                let candidates = available_handles
                    .iter()
                    .filter(|(id, _)| !attempted_ids.contains(id))
                    .map(|(id, peer)| (*id, Arc::clone(peer)))
                    .collect::<Vec<_>>();
                if candidates.len() < required {
                    return Err(HnsDirectPeerError::InsufficientBlockViews {
                        required: self.pool.config.minimum_block_views,
                        actual: views.len(),
                    });
                }

                // Request exactly the proof quorum for the normal path. If a
                // selected peer fails, query only the number of already-
                // filtered reserve peers required to restore that quorum; an
                // optional slow peer never delays this batch.
                let selected = self.block_scan_quorum_handles(&candidates, required)?;
                attempted_ids.extend(selected.iter().map(|(id, _)| *id));
                let responses = request_block_view_batches(&selected, &anchors, now_unix);
                let mut failed_ids = HashSet::new();
                for ((id, _), response) in selected.into_iter().zip(responses) {
                    match response.result {
                        Ok(blocks) if blocks.len() == anchors.len() => {
                            self.record_block_scan_peer_latency(id, response.elapsed)?;
                            successful_peer_fetches.push(response.elapsed);
                            views.push(blocks);
                        }
                        Ok(_) | Err(_) => {
                            failed_ids.insert(id);
                        }
                    }
                }
                for id in &failed_ids {
                    self.disconnect_peer(*id)?;
                }
                available_handles.retain(|(id, _)| !failed_ids.contains(id));
            }
            let peer_fetch_millis = duration_millis(peer_fetch_started.elapsed());
            let fastest_peer_fetch_millis = successful_peer_fetches
                .iter()
                .copied()
                .min()
                .map(duration_millis)
                .unwrap_or_default();
            let slowest_peer_fetch_millis = successful_peer_fetches
                .iter()
                .copied()
                .max()
                .map(duration_millis)
                .unwrap_or_default();
            let peer_coordination_millis =
                peer_fetch_millis.saturating_sub(slowest_peer_fetch_millis);

            let merge_started = Instant::now();
            let mut merged_blocks = Vec::with_capacity(anchors.len());
            for index in 0..anchors.len() {
                let block_views = views
                    .iter()
                    .map(|peer_blocks| peer_blocks[index].clone())
                    .collect::<Vec<_>>();
                peer_views_verified = peer_views_verified.saturating_add(block_views.len());
                let merged = VerifiedWalletBlock::merge_peer_views(&block_views)
                    .map_err(|error| HnsDirectPeerError::WalletEvidence(error.to_string()))?;
                merged_blocks.push(merged);
            }
            let merge_millis = duration_millis(merge_started.elapsed());

            let commit_started = Instant::now();
            let admitted_per_block = self
                .backend
                .apply_verified_blocks(&merged_blocks, now_unix_or(now_unix))?;
            let commit_millis = duration_millis(commit_started.elapsed());
            if admitted_per_block.len() != merged_blocks.len() {
                return Err(HnsDirectPeerError::Arithmetic);
            }
            let batch_telemetry = HnsBlockScanBatchTelemetry {
                first_height: first_unscanned,
                last_height: batch_last,
                blocks: u32::try_from(anchors.len()).unwrap_or(u32::MAX),
                peer_fetch_millis,
                fastest_peer_fetch_millis,
                slowest_peer_fetch_millis,
                peer_coordination_millis,
                merge_millis,
                commit_millis,
            };
            last_batch_telemetry = Some(batch_telemetry);
            for (height, admitted) in (first_unscanned..=batch_last).zip(admitted_per_block) {
                transactions_admitted = transactions_admitted
                    .checked_add(admitted)
                    .ok_or(HnsDirectPeerError::Arithmetic)?;
                blocks_applied = blocks_applied
                    .checked_add(1)
                    .ok_or(HnsDirectPeerError::Arithmetic)?;
                on_progress(HnsBlockScanProgress {
                    first_height: Some(next_height),
                    last_height: Some(height),
                    validated_tip_height: tip_height,
                    blocks_applied,
                    transactions_admitted,
                    peer_views_verified,
                    batch_telemetry: (height == batch_last).then_some(batch_telemetry),
                });
            }
            if batch_last == last_height {
                break;
            }
            first_unscanned = batch_last
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
            batch_telemetry: last_batch_telemetry,
        })
    }

    /// Request standard mempool inventory from the responsive exact peer
    /// quorum and admit bounded relevant transactions plus peer fee floors.
    ///
    /// This follows the same availability rule as the historical block scan:
    /// an optional warm reserve must not keep a completed verified chain scan
    /// from publishing its final read snapshot. Every selected response stays
    /// independently transported and locally validated before admission.
    pub fn refresh_mempool(&self, now_unix: u64) -> Result<usize, HnsDirectPeerError> {
        let handles = self.pool.ready_handles()?;
        let required = self.pool.config.minimum_block_views;
        if handles.len() < required {
            return Err(HnsDirectPeerError::InsufficientBlockViews {
                required,
                actual: handles.len(),
            });
        }
        let handles = self.fastest_block_scan_quorum_handles(handles, required)?;
        let wait = self.pool.config.event_poll_timeout;
        let results = std::thread::scope(|scope| {
            let tasks = handles
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
                .collect::<Vec<_>>();
            tasks
                .into_iter()
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
        self.block_scan_peer_latencies
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
            .remove(&id);
        let _ = self.pool.disconnect(id)?;
        let _ = self.backend.remove_header_peer(id)?;
        Ok(())
    }

    /// Select the exact independent quorum required for one header agreement
    /// round. Extra ready peers remain connected for future rotated rounds,
    /// block-view cross-checks, and replacement after a transport failure.
    fn header_round_handles(&self) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
        let handles = self.pool.ready_handles()?;
        let quorum = self.pool.config.minimum_block_views;
        self.rotating_peer_quorum_handles(handles, quorum, &self.next_header_peer_offset)
    }

    /// Select an exact proof quorum from the filter-installed peers for one
    /// block scan batch. Recent response time decides the normal selection;
    /// every sixteenth selection rotates through the reserve to keep
    /// performance observations fresh. The caller retains every unselected handle as a
    /// warm, already-filtered reserve for a later batch or immediate retry.
    fn block_scan_quorum_handles(
        &self,
        handles: &[(PeerId, PeerHandle)],
        requested: usize,
    ) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
        debug_assert!(requested > 0);
        let selection = self
            .block_scan_selection_count
            .fetch_add(1, Ordering::Relaxed);
        let candidates = handles
            .iter()
            .map(|(id, peer)| (*id, Arc::clone(peer)))
            .collect();
        if selection % BLOCK_SCAN_PEER_EXPLORATION_INTERVAL == 0 {
            return self.rotating_peer_quorum_handles(
                candidates,
                requested,
                &self.next_block_peer_offset,
            );
        }
        self.fastest_block_scan_quorum_handles(candidates, requested)
    }

    fn fastest_block_scan_quorum_handles(
        &self,
        handles: Vec<(PeerId, PeerHandle)>,
        requested: usize,
    ) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
        if handles.len() <= requested {
            return Ok(handles);
        }
        let latencies = self
            .block_scan_peer_latencies
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
            .clone();
        let candidates = handles
            .into_iter()
            .map(|(id, peer)| {
                let address = peer
                    .lock()
                    .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                    .address;
                Ok((
                    latencies.get(&id).map(|latency| latency.ewma_millis),
                    address,
                    (id, peer),
                ))
            })
            .collect::<Result<Vec<_>, HnsDirectPeerError>>()?;
        Ok(select_fastest_diverse_peer_quorum(candidates, requested)
            .into_iter()
            .map(|(_, _, (id, peer))| (id, peer))
            .collect())
    }

    fn record_block_scan_peer_latency(
        &self,
        id: PeerId,
        elapsed: Duration,
    ) -> Result<(), HnsDirectPeerError> {
        let sample_millis = duration_millis(elapsed);
        let mut latencies = self
            .block_scan_peer_latencies
            .lock()
            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?;
        latencies
            .entry(id)
            .and_modify(|latency| latency.observe(sample_millis))
            .or_insert_with(|| ScanPeerLatency::initial(sample_millis));
        Ok(())
    }

    fn rotating_peer_quorum_handles(
        &self,
        handles: Vec<(PeerId, PeerHandle)>,
        requested: usize,
        cursor: &AtomicUsize,
    ) -> Result<Vec<(PeerId, PeerHandle)>, HnsDirectPeerError> {
        if handles.len() <= requested {
            return Ok(handles);
        }
        let mut ordered = handles
            .into_iter()
            .map(|(id, peer)| {
                let address = peer
                    .lock()
                    .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?
                    .address;
                Ok((address, id, peer))
            })
            .collect::<Result<Vec<_>, HnsDirectPeerError>>()?;
        ordered.sort_unstable_by_key(|(address, _, _)| *address);
        let offset = cursor.fetch_add(requested, Ordering::Relaxed);
        Ok(select_rotating_peer_quorum(ordered, requested, offset)
            .into_iter()
            .map(|(_, id, peer)| (id, peer))
            .collect())
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

/// Return one bounded quorum from a deterministically ordered ready-peer set,
/// rotating the starting position between fresh header rounds. The caller owns
/// the candidates, so this never mutates membership or connection state.
fn select_rotating_peer_quorum<T>(mut candidates: Vec<T>, quorum: usize, offset: usize) -> Vec<T> {
    debug_assert!(quorum > 0);
    if candidates.len() > quorum {
        let start = offset % candidates.len();
        candidates.rotate_left(start);
        candidates.truncate(quorum);
    }
    candidates
}

/// Select an exact quorum with the lowest recent response times while
/// preferring distinct coarse address groups. A score of `None` means that a
/// connected reserve has not yet completed a request and is explored on the
/// regular rotating selections above. The second pass maintains availability
/// when the ready pool cannot provide enough distinct groups.
fn select_fastest_diverse_peer_quorum<T>(
    mut candidates: Vec<(Option<u64>, SocketAddr, T)>,
    quorum: usize,
) -> Vec<(Option<u64>, SocketAddr, T)> {
    debug_assert!(quorum > 0);
    candidates
        .sort_unstable_by_key(|(latency, address, _)| (latency.unwrap_or(u64::MAX), *address));
    let mut selected = Vec::with_capacity(quorum.min(candidates.len()));
    let mut deferred = Vec::new();
    let mut groups = HashSet::new();
    for candidate @ (_, address, _) in candidates {
        if selected.len() < quorum && groups.insert(address_group(address)) {
            selected.push(candidate);
        } else {
            deferred.push(candidate);
        }
    }
    selected.extend(
        deferred
            .into_iter()
            .take(quorum.saturating_sub(selected.len())),
    );
    selected
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
// These independently authenticated bootstrap inputs are deliberately
// explicit at the public boundary; bundling them would obscure which values a
// product must pin and preserve across restart.
#[allow(clippy::too_many_arguments)]
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
        store.clone(),
        account.account_id,
        account.network,
        birthday_height,
        now_unix,
    )
    .map_err(|error| HnsDirectPeerError::LightIndex(error.to_string()))?;
    let current_account = store
        .try_with_store(|wallet| {
            wallet
                .wallet_account::<crate::HnsAccountRecord>(&crate::account_entity_id(account))
                .map_err(HnsWalletError::from)
        })
        .map_err(HnsDirectPeerError::Wallet)?
        .ok_or(HnsDirectPeerError::Wallet(
            HnsWalletError::AccountConfigurationMismatch,
        ))?;
    if current_account.value.config != *account {
        return Err(HnsDirectPeerError::Wallet(
            HnsWalletError::AccountConfigurationMismatch,
        ));
    }
    // A process can stop after atomically persisting a local change-address
    // allocation but before the adjacent embedded backend extends its Bloom
    // watch set. Heal only that exact forward-only delta before the ordinary
    // restore-set comparison; every historical/restoration delta still takes
    // the rewind path below.
    index
        .extend_locally_allocated_change_watch_set(&current_account.value, now_unix)
        .map_err(|error| HnsDirectPeerError::LightIndex(error.to_string()))?;
    let base_watch_set = store
        .try_with_store(|wallet| derive_hns_light_watch_set(wallet, account))
        .map_err(HnsDirectPeerError::Wallet)?;
    let watch_set = reusable_wallet_watch_set(&store, account, index.watch_set(), base_watch_set)?;
    index
        .install_watch_set(watch_set, now_unix)
        .map_err(|error| HnsDirectPeerError::LightIndex(error.to_string()))?;
    HnsDirectPeerCoordinator::new(authority, index, peer_config)
        .map(|coordinator| coordinator.with_wallet_watch_set_source(store, account.clone()))
}

/// Preserve a complete prior direct watch set across a process restart only if
/// it is exactly a deterministic extension of the selected wallet's current
/// restoration frontier. This allows a started recovery re-scan to survive an
/// Activity/process recreation without trusting an arbitrary persisted filter.
fn reusable_wallet_watch_set(
    store: &SharedWalletStore,
    account: &HnsRuntimeConfig,
    installed: &crate::HnsLightWatchSet,
    base: crate::HnsLightWatchSet,
) -> Result<crate::HnsLightWatchSet, HnsDirectPeerError> {
    if installed == &base {
        return Ok(base);
    }
    let ceiling = store
        .try_with_store(|wallet| {
            derive_hns_light_watch_set_with_restore_extension(
                wallet,
                account,
                MAX_WALLET_WATCH_SET_RESTORE_EXTENSIONS,
            )
        })
        .map_err(HnsDirectPeerError::Wallet)?;
    if deterministic_watch_set_covers(installed, &base, &ceiling) {
        return Ok(installed.clone());
    }
    Ok(base)
}

/// Accept prior coverage only when it contains the complete current base and
/// every retained script is still a wallet-derived member of the bounded
/// restoration ceiling. Known-name membership remains exact: adding or
/// removing an imported name changes compact-filter relevance and requires a
/// deliberate rewind.
fn deterministic_watch_set_covers(
    installed: &crate::HnsLightWatchSet,
    required: &crate::HnsLightWatchSet,
    ceiling: &crate::HnsLightWatchSet,
) -> bool {
    installed.name_hashes == required.name_hashes
        && ceiling.name_hashes == required.name_hashes
        && required
            .scripts
            .iter()
            .all(|script| installed.scripts.binary_search(script).is_ok())
        && installed
            .scripts
            .iter()
            .all(|script| ceiling.scripts.binary_search(script).is_ok())
}

impl NativePeer {
    /// Relay a transaction using the standard Handshake inventory handshake.
    /// A full transaction is sent only after this peer requests the exact
    /// announced hash with `getdata`; HSD disconnects peers that send an
    /// unsolicited `tx` packet.
    fn announce_transaction(
        &mut self,
        transaction: Transaction,
        transaction_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<bool, HnsDirectPeerError> {
        let original_timeout = self
            .connection
            .transport_mut()
            .read_timeout()
            .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
        let result = self.announce_transaction_inner(
            transaction,
            transaction_hash,
            Instant::now() + timeout,
        );
        let restore = self
            .connection
            .transport_mut()
            .set_read_timeout(original_timeout)
            .map_err(|error| HnsDirectPeerError::Io(error.kind()));
        match (result, restore) {
            (Ok(delivered), Ok(())) => Ok(delivered),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn announce_transaction_inner(
        &mut self,
        transaction: Transaction,
        transaction_hash: [u8; 32],
        deadline: Instant,
    ) -> Result<bool, HnsDirectPeerError> {
        let announced = Inventory {
            kind: InventoryKind::Transaction,
            hash: transaction_hash,
        };
        self.connection
            .send_wallet_packet(&Packet::Inv(vec![announced.clone()]))?;
        for _ in 0..MAX_RESPONSE_EVENTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            self.connection
                .transport_mut()
                .set_read_timeout(Some(remaining))
                .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
            match self.connection.receive_event(now_unix_or(0)) {
                Ok(PeerEvent::Wallet(WalletPeerEvent::DataRequest(mut requested))) => {
                    let exact_request = requested.iter().any(|item| item == &announced);
                    requested.retain(|item| item != &announced);
                    if !requested.is_empty() {
                        self.defer_wallet(WalletPeerEvent::DataRequest(requested))?;
                    }
                    if exact_request {
                        self.connection
                            .send_wallet_packet(&Packet::Tx(transaction))?;
                        return Ok(true);
                    }
                }
                Ok(PeerEvent::Wallet(event)) => self.defer_wallet(event)?,
                Ok(
                    PeerEvent::Addresses(_)
                    | PeerEvent::Ignored(_)
                    | PeerEvent::Experimental { .. }
                    | PeerEvent::Pong(_)
                    | PeerEvent::Ready(_),
                ) => {}
                Ok(PeerEvent::Rejected(reject)) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                Ok(PeerEvent::Headers(_) | PeerEvent::Proof(_) | PeerEvent::Send(_)) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
                Err(PeerError::Io(
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
                )) => return Ok(false),
                Err(error) => return Err(error.into()),
            }
        }
        Err(HnsDirectPeerError::ResponseEventLimit)
    }

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
                | PeerEvent::Experimental { .. }
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
                | PeerEvent::Experimental { .. }
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
                PeerEvent::Ignored(_)
                | PeerEvent::Experimental { .. }
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

    /// Request a bounded window of filtered blocks in one standard `getdata`
    /// packet. HSD serializes the corresponding `merkleblock` and matched
    /// transaction messages in inventory order. Consume that ordering
    /// strictly: a response for the wrong authenticated anchor fails closed
    /// rather than being reassociated or accepted speculatively.
    fn request_filtered_blocks(
        &mut self,
        anchors: &[WalletHeaderAnchor],
        now_unix: u64,
    ) -> Result<Vec<VerifiedWalletBlock>, HnsDirectPeerError> {
        if anchors.is_empty() {
            return Ok(Vec::new());
        }
        self.connection
            .send_wallet_packet(&Packet::GetData(filtered_block_inventory(anchors)))?;
        anchors
            .iter()
            .copied()
            .map(|anchor| self.receive_filtered_block(anchor, now_unix))
            .collect()
    }

    /// Receive precisely one filtered-block response already requested by
    /// [`Self::request_filtered_blocks`]. The caller fixes the expected
    /// anchor before reading the peer socket, preventing a peer from choosing
    /// which local height its proof is evaluated against.
    fn receive_filtered_block(
        &mut self,
        anchor: WalletHeaderAnchor,
        now_unix: u64,
    ) -> Result<VerifiedWalletBlock, HnsDirectPeerError> {
        let expected_hash = anchor.hash().into_bytes();
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
                | PeerEvent::Experimental { .. }
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
        // A socket read deadline only bounds an *idle* peer. A peer that
        // continuously sends irrelevant protocol messages can otherwise keep
        // resetting that deadline and retain the final wallet snapshot
        // forever. Bound the complete explicit mempool drain as well. The
        // caller can safely retry on a later synchronization round; mempool
        // data is never required to advance the already verified chain tip.
        let deadline = Instant::now() + timeout;
        let result = self.poll_wallet_events_inner(now_unix, deadline);
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
        deadline: Instant,
    ) -> Result<Vec<WalletPeerEvent>, HnsDirectPeerError> {
        let mut events = self.deferred_wallet.drain(..).collect::<Vec<_>>();
        if events.len() >= MAX_RESPONSE_EVENTS {
            return Err(HnsDirectPeerError::ResponseEventLimit);
        }
        // Count every received wire event, not only wallet messages. Peers
        // are allowed to send ordinary traffic while connected, but it must
        // not turn a bounded wallet refresh into an unbounded drain.
        for _ in 0..MAX_RESPONSE_EVENTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(events);
            }
            self.connection
                .transport_mut()
                .set_read_timeout(Some(remaining))
                .map_err(|error| HnsDirectPeerError::Io(error.kind()))?;
            match self.connection.receive_event(now_unix_or(now_unix)) {
                Ok(PeerEvent::Wallet(event)) => {
                    events.push(event);
                    if events.len() >= MAX_RESPONSE_EVENTS {
                        return Err(HnsDirectPeerError::ResponseEventLimit);
                    }
                }
                Ok(
                    PeerEvent::Addresses(_)
                    | PeerEvent::Ignored(_)
                    | PeerEvent::Experimental { .. }
                    | PeerEvent::Pong(_)
                    | PeerEvent::Ready(_),
                ) => {}
                // A reject received while draining the explicit mempool
                // response may be the peer's policy/consensus response to the
                // transaction written immediately before this refresh. Never
                // discard it: socket completion is not admission, and losing
                // the reject reason makes a permanently invalid signed send
                // look like a propagation delay forever.
                Ok(PeerEvent::Rejected(reject)) => {
                    return Err(HnsDirectPeerError::PeerRejected(format!("{reject:?}")));
                }
                Ok(PeerEvent::Headers(_) | PeerEvent::Proof(_) | PeerEvent::Send(_)) => {
                    return Err(HnsDirectPeerError::UnexpectedPeerEvent);
                }
                Err(PeerError::Io(
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
                )) => return Ok(events),
                Err(error) => return Err(error.into()),
            }
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
        let tasks = handles
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
            .collect::<Vec<_>>();
        tasks
            .into_iter()
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

struct TimedBlockViewBatch {
    elapsed: Duration,
    result: Result<Vec<VerifiedWalletBlock>, HnsDirectPeerError>,
}

fn request_block_view_batches(
    handles: &[(PeerId, PeerHandle)],
    anchors: &[WalletHeaderAnchor],
    now_unix: u64,
) -> Vec<TimedBlockViewBatch> {
    std::thread::scope(|scope| {
        let tasks = handles
            .iter()
            .map(|(_, peer)| {
                let peer = Arc::clone(peer);
                scope.spawn(move || {
                    let started = Instant::now();
                    let result = (|| {
                        let mut peer = peer
                            .lock()
                            .map_err(|_| HnsDirectPeerError::RuntimePoisoned)?;
                        peer.request_filtered_blocks(anchors, now_unix)
                    })();
                    TimedBlockViewBatch {
                        elapsed: started.elapsed(),
                        result,
                    }
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .map(|task| {
                task.join().unwrap_or(TimedBlockViewBatch {
                    elapsed: Duration::ZERO,
                    result: Err(HnsDirectPeerError::WorkerPanicked),
                })
            })
            .collect()
    })
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn filtered_block_inventory(anchors: &[WalletHeaderAnchor]) -> Vec<Inventory> {
    anchors
        .iter()
        .map(|anchor| Inventory {
            kind: InventoryKind::FilteredBlock,
            hash: anchor.hash().into_bytes(),
        })
        .collect()
}

fn filtered_block_batch_last(first_height: u32, tip_height: u32) -> u32 {
    tip_height.min(first_height.saturating_add(FILTERED_BLOCK_REQUEST_WINDOW.saturating_sub(1)))
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

/// Return the only meaningful completion time after one synchronous direct
/// header fan-out. An under-filled round has no outstanding network work, so
/// use its bounded deadline to release the generation for immediate peer
/// replacement instead of making the UI wait for the same deadline again.
fn header_round_finished_at(
    pending: PendingHeaderRound,
    submitted: usize,
    worker_panicked: bool,
    completed_at: u64,
) -> Result<u64, HnsDirectPeerError> {
    if submitted < pending.requested || worker_panicked {
        pending
            .deadline
            .checked_add(1)
            .ok_or(HnsDirectPeerError::Arithmetic)
    } else {
        Ok(completed_at)
    }
}

/// Build a header locator that asks a peer to echo the locally authenticated
/// tip before it supplies any extension.  This preserves an ordinary genesis
/// request, whose locator has no predecessor.
fn header_freshness_locator(locator: &[BlockHash]) -> Vec<BlockHash> {
    if locator.len() > 1 {
        locator[1..].to_vec()
    } else {
        locator.to_vec()
    }
}

/// Strip the peer's echo of the already authenticated base header.  A reply
/// that starts with any other header remains untouched and fails normal local
/// chain validation rather than being mistaken for a current-chain proof.
fn normalize_header_freshness_response(
    mut headers: Vec<Header>,
    base_hash: BlockHash,
) -> Vec<Header> {
    if headers
        .first()
        .is_some_and(|header| header.block_hash() == base_hash)
    {
        headers.remove(0);
    }
    headers
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
    #[error("the standard peer does not advertise the Shakescape extension service")]
    ShakescapePeerNotAdvertised,
    #[error("wallet-native Shakescape negotiation or message validation failed: {0}")]
    Shakescape(String),
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

impl HnsDirectPeerError {
    /// Whether the header quorum was temporarily unavailable over otherwise
    /// ordinary standard Handshake peer connections.
    ///
    /// This condition must not be treated as a local wallet or chain-validity
    /// error: callers should keep the persisted state fail-closed and retry a
    /// later peer round.
    #[must_use]
    pub fn is_temporary_header_agreement_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Wallet(
                HnsWalletError::HeaderRoundInsufficientResponses
                    | HnsWalletError::HeaderRoundInsufficientAgreement
            )
        )
    }
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
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use hns_wallet_store::{SecretKind, WalletStore};
    use hns_wallet_types::{AccountId, BaseUnits, WalletId};

    #[test]
    fn temporary_header_agreement_failures_remain_distinguishable_from_wallet_faults() {
        assert!(
            HnsDirectPeerError::Wallet(HnsWalletError::HeaderRoundInsufficientResponses)
                .is_temporary_header_agreement_unavailable()
        );
        assert!(
            HnsDirectPeerError::Wallet(HnsWalletError::HeaderRoundInsufficientAgreement)
                .is_temporary_header_agreement_unavailable()
        );
        assert!(
            !HnsDirectPeerError::Wallet(HnsWalletError::InvalidEvidence)
                .is_temporary_header_agreement_unavailable()
        );
    }

    #[test]
    fn completed_header_fanout_releases_an_underfilled_round_immediately() {
        let pending = PendingHeaderRound {
            generation: 7,
            deadline: 1_000,
            requested: 2,
            submitted: 0,
        };
        assert_eq!(
            header_round_finished_at(pending, 1, false, 900).expect("underfilled round"),
            1_001
        );
        assert_eq!(
            header_round_finished_at(pending, 2, false, 900).expect("complete round"),
            900
        );
        assert_eq!(
            header_round_finished_at(pending, 2, true, 900).expect("panicked round"),
            1_001
        );
    }

    #[test]
    fn header_freshness_locator_challenges_the_known_tip_through_its_predecessor() {
        let tip = BlockHash::new([1; 32]);
        let previous = BlockHash::new([2; 32]);
        let older = BlockHash::new([3; 32]);
        assert_eq!(
            header_freshness_locator(&[tip, previous, older]),
            vec![previous, older]
        );
        assert_eq!(header_freshness_locator(&[tip]), vec![tip]);
    }

    #[test]
    fn header_freshness_response_strips_only_the_exact_known_tip() {
        let known = Header::default();
        let known_hash = known.block_hash();
        let other = Header {
            nonce: 1,
            ..Header::default()
        };

        assert!(normalize_header_freshness_response(vec![known.clone()], known_hash).is_empty());
        assert_eq!(
            normalize_header_freshness_response(vec![known, other.clone()], known_hash),
            vec![other.clone()]
        );
        assert_eq!(
            normalize_header_freshness_response(vec![other.clone()], known_hash),
            vec![other]
        );
    }

    #[test]
    fn filtered_block_request_windows_are_bounded_contiguous_and_overflow_safe() {
        assert_eq!(filtered_block_batch_last(100, 100), 100);
        assert_eq!(
            filtered_block_batch_last(100, 100 + FILTERED_BLOCK_REQUEST_WINDOW - 1),
            100 + FILTERED_BLOCK_REQUEST_WINDOW - 1
        );
        assert_eq!(
            filtered_block_batch_last(100, 100 + FILTERED_BLOCK_REQUEST_WINDOW),
            100 + FILTERED_BLOCK_REQUEST_WINDOW - 1
        );
        assert_eq!(filtered_block_batch_last(u32::MAX, u32::MAX), u32::MAX);
    }

    #[test]
    fn peer_quorums_are_rotating_and_exact() {
        assert_eq!(
            select_rotating_peer_quorum(vec![0, 1, 2, 3, 4], 2, 0),
            vec![0, 1]
        );
        assert_eq!(
            select_rotating_peer_quorum(vec![0, 1, 2, 3, 4], 2, 2),
            vec![2, 3]
        );
        assert_eq!(
            select_rotating_peer_quorum(vec![0, 1, 2, 3, 4], 2, 4),
            vec![4, 0]
        );
        assert_eq!(select_rotating_peer_quorum(vec![0, 1], 2, 1), vec![0, 1]);
        assert_eq!(
            select_rotating_peer_quorum(vec![0, 1, 2, 3, 4], 1, 3),
            vec![3]
        );
    }

    #[test]
    fn fastest_peer_quorum_prefers_recent_latency_and_address_diversity() {
        let selected = select_fastest_diverse_peer_quorum(
            vec![
                (Some(120), "1.1.1.1:12038".parse().unwrap(), "fast-a"),
                (Some(160), "1.1.1.2:12038".parse().unwrap(), "fast-b"),
                (Some(900), "8.8.8.8:12038".parse().unwrap(), "other-group"),
                (None, "9.9.9.9:12038".parse().unwrap(), "unmeasured"),
            ],
            2,
        );
        let labels = selected
            .into_iter()
            .map(|(_, _, label)| label)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["fast-a", "other-group"]);
    }

    #[test]
    fn fastest_peer_quorum_falls_back_when_address_groups_are_not_available() {
        let selected = select_fastest_diverse_peer_quorum(
            vec![
                (Some(120), "1.1.1.1:12038".parse().unwrap(), "fast-a"),
                (Some(160), "1.1.1.2:12038".parse().unwrap(), "fast-b"),
            ],
            2,
        );
        let labels = selected
            .into_iter()
            .map(|(_, _, label)| label)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["fast-a", "fast-b"]);
    }

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
        let store = hns_wallet_store::SharedWalletStore::new(wallet);
        let coordinator = open_wallet_direct_hns_peer_coordinator(
            store,
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
    fn exact_name_proof_watch_expansion_retains_existing_direct_scan_coverage() {
        let config = direct_wallet_config();
        let mut wallet = WalletStore::create(":memory:", "direct name proof passphrase").unwrap();
        wallet
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[74; 64],
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
        let before = coordinator.backend().light_scan_status().unwrap();
        let name_hash = hash_name(b"24hour").unwrap().into_bytes();
        // No peer is configured for this deterministic fixture, so the proof
        // fetch itself cannot finish. The public exact-text path must still
        // install the fresh name before reaching that transport boundary.
        assert!(
            coordinator
                .synchronize_name_proof_exact_text("24hour", now + 1)
                .is_err()
        );

        let after = coordinator.backend().light_scan_status().unwrap();
        assert_eq!(after.birthday_height, before.birthday_height);
        assert_eq!(after.scanned_height, before.scanned_height);
        assert_eq!(after.scanned_hash, before.scanned_hash);
        assert_eq!(after.watched_scripts, before.watched_scripts);
        assert_eq!(after.watched_names, before.watched_names + 1);
        assert!(
            coordinator
                .backend()
                .light_watch_set()
                .unwrap()
                .name_hashes
                .contains(&name_hash)
        );

        assert!(
            coordinator
                .synchronize_name_proof_exact_text("24hour", now + 2)
                .is_err()
        );
        assert_eq!(
            coordinator
                .backend()
                .light_scan_status()
                .unwrap()
                .watch_digest,
            after.watch_digest
        );
    }

    #[test]
    fn locally_allocated_change_extends_direct_watch_set_without_restore_rewind() {
        let config = direct_wallet_config();
        let mut wallet =
            WalletStore::create(":memory:", "direct wallet change passphrase").unwrap();
        wallet
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[75; 64],
                1,
            )
            .unwrap();
        let account = crate::HnsAccountRecord::initial_non_value(config.clone()).unwrap();
        wallet
            .save_wallet_account(&crate::account_entity_id(&config), 0, &account, 1)
            .unwrap();
        let now = Network::Regtest.parameters().genesis_time.get() + 102;
        let store = hns_wallet_store::SharedWalletStore::new(wallet);
        let coordinator = open_wallet_direct_hns_peer_coordinator(
            store.clone(),
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now,
        )
        .unwrap();
        assert_eq!(
            coordinator
                .backend()
                .light_scan_status()
                .unwrap()
                .watched_scripts,
            4
        );

        let mut stored = store
            .try_with_store(|wallet| {
                wallet
                    .wallet_account::<crate::HnsAccountRecord>(&crate::account_entity_id(&config))
                    .map_err(HnsWalletError::from)
            })
            .unwrap()
            .unwrap();
        stored.value.next_change_index = 1;
        stored.value.internal_scan_end = 1;
        store
            .with_store_mut(|wallet| {
                wallet.save_wallet_account(
                    &crate::account_entity_id(&config),
                    stored.revision,
                    &stored.value,
                    now + 1,
                )
            })
            .unwrap();

        assert!(
            coordinator
                .backend()
                .extend_locally_allocated_change_watch_set(&stored.value, now + 1)
                .unwrap()
        );
        assert_eq!(
            coordinator
                .backend()
                .light_scan_status()
                .unwrap()
                .watched_scripts,
            5
        );
        assert!(
            !coordinator
                .backend()
                .extend_locally_allocated_change_watch_set(&stored.value, now + 2)
                .unwrap()
        );

        let reopened = open_wallet_direct_hns_peer_coordinator(
            store,
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now + 3,
        )
        .unwrap();
        assert_eq!(
            reopened
                .backend()
                .light_scan_status()
                .unwrap()
                .watched_scripts,
            5
        );
    }

    #[test]
    fn direct_wallet_trailing_restore_extension_uses_largest_frontier_and_survives_reopen() {
        let config = direct_wallet_config();
        let mut wallet =
            WalletStore::create(":memory:", "direct wallet extension passphrase").unwrap();
        wallet
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[74; 64],
                1,
            )
            .unwrap();
        let account = crate::HnsAccountRecord::initial_non_value(config.clone()).unwrap();
        wallet
            .save_wallet_account(&crate::account_entity_id(&config), 0, &account, 1)
            .unwrap();
        let now = Network::Regtest.parameters().genesis_time.get() + 101;
        let store = hns_wallet_store::SharedWalletStore::new(wallet);
        let coordinator = open_wallet_direct_hns_peer_coordinator(
            store.clone(),
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now,
        )
        .unwrap();
        assert!(
            coordinator
                .extend_wallet_restore_watch_set(now + 1)
                .expect("extend direct wallet restoration watch set")
        );
        let expanded = coordinator.backend().light_watch_set().unwrap();
        // Four derivation branches each include their initial script plus all
        // eight bounded restoration gaps. This turns a boundary recovery into
        // one re-scan rather than one complete re-scan per gap.
        assert_eq!(expanded.scripts.len(), 36);
        assert!(
            !coordinator
                .extend_wallet_restore_watch_set(now + 2)
                .expect("bounded restoration pre-expansion is idempotent")
        );

        let reopened = open_wallet_direct_hns_peer_coordinator(
            store,
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now + 2,
        )
        .unwrap();
        assert_eq!(reopened.backend().light_watch_set().unwrap(), expanded);
        assert_eq!(
            reopened
                .backend()
                .light_scan_status()
                .unwrap()
                .watched_scripts,
            36
        );
    }

    #[test]
    fn direct_wallet_shifted_branch_frontier_reuses_completed_expansion() {
        let config = direct_wallet_config();
        let mut wallet =
            WalletStore::create(":memory:", "direct wallet shifted frontier passphrase").unwrap();
        wallet
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[76; 64],
                1,
            )
            .unwrap();
        let account = crate::HnsAccountRecord::initial_non_value(config.clone()).unwrap();
        wallet
            .save_wallet_account(&crate::account_entity_id(&config), 0, &account, 1)
            .unwrap();
        let now = Network::Regtest.parameters().genesis_time.get() + 103;
        let store = hns_wallet_store::SharedWalletStore::new(wallet);
        let coordinator = open_wallet_direct_hns_peer_coordinator(
            store.clone(),
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now,
        )
        .unwrap();
        assert!(
            coordinator
                .extend_wallet_restore_watch_set(now + 1)
                .expect("pre-expand direct wallet restoration watch set")
        );
        let expanded = coordinator.backend().light_watch_set().unwrap();

        // Model a synchronized snapshot discovering activity on only one
        // branch. The required base moves by one script, while the previous
        // eight-window expansion still covers it in full.
        let mut stored = store
            .try_with_store(|wallet| {
                wallet
                    .wallet_account::<crate::HnsAccountRecord>(&crate::account_entity_id(&config))
                    .map_err(HnsWalletError::from)
            })
            .unwrap()
            .unwrap();
        stored.value.last_used_external = Some(0);
        stored.value.next_receive_index = 1;
        stored.value.external_scan_end = 1;
        store
            .with_store_mut(|wallet| {
                wallet.save_wallet_account(
                    &crate::account_entity_id(&config),
                    stored.revision,
                    &stored.value,
                    now + 2,
                )
            })
            .unwrap();

        let reopened = open_wallet_direct_hns_peer_coordinator(
            store,
            &config,
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            now + 3,
        )
        .unwrap();
        assert_eq!(reopened.backend().light_watch_set().unwrap(), expanded);
        assert!(
            !reopened
                .extend_wallet_restore_watch_set(now + 4)
                .expect("reuse prior complete restoration coverage")
        );
        assert_eq!(reopened.backend().light_watch_set().unwrap(), expanded);
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
    fn direct_shakescape_registry_is_pinned_to_the_wallet_network_and_atomic_market() {
        let hello = shakescape_registry_hello(HnsNetwork::Regtest).unwrap();
        assert_eq!(hello.network, ExperimentalNetwork::Regtest);
        assert_eq!(
            hello.registry_versions,
            vec![SHAKESCAPE_V1_REGISTRY_VERSION]
        );
        assert_eq!(hello.fingerprint, SHAKESCAPE_V1_REGISTRY_FINGERPRINT);
        assert!(hello.protocols.contains(&ProtocolRange {
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            minimum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
            maximum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
        }));
        assert_eq!(
            hello.maximum_receive_size as usize,
            MAX_SHAKESCAPE_MARKET_PAYLOAD
        );
    }

    #[test]
    fn direct_shakescape_wallet_advertises_standard_network_and_extension_services() {
        let version = direct_shakescape_version(
            "127.0.0.1:12038".parse().unwrap(),
            [9; 8],
            42,
            Network::Regtest.parameters().genesis_time.get() + 1,
        );
        assert_ne!(version.services & SERVICE_NETWORK, 0);
        assert_ne!(version.services & SHAKESCAPE_EXTENSION_SERVICE.value(), 0);
    }

    #[test]
    fn direct_shakescape_wallet_accepts_and_negotiates_an_inbound_wallet_peer() {
        let listener = HnsDirectShakescapeListener::bind(
            HnsDirectPeerConfig::for_network(HnsNetwork::Regtest),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let server = thread::spawn(move || {
            for _ in 0..100 {
                if let Some(peer) = listener.accept_next(42, now).unwrap() {
                    return peer;
                }
                thread::sleep(Duration::from_millis(5));
            }
            panic!("wallet-hosted Shakescape listener did not receive the client")
        });

        let mut client_config = HnsDirectPeerConfig::for_network(HnsNetwork::Regtest);
        client_config.static_peers.push(address);
        let client = HnsDirectShakescapePeer::connect(&client_config, address, 42, now).unwrap();
        let server = server.join().unwrap();

        assert_eq!(client.negotiated_registry(), server.negotiated_registry());
        assert_eq!(client.address(), address);
        assert!(server.address().ip().is_loopback());
    }

    #[test]
    fn transaction_relay_announces_inventory_before_serving_requested_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let now = 1_700_000_000;
        let transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        };
        let transaction_hash = transaction.transaction_hash().unwrap().into_bytes();
        let server = thread::spawn({
            let transaction = transaction.clone();
            move || {
                let (stream, remote) = listener.accept().unwrap();
                let mut version = light_wallet_version(remote, [2; 8], 42, now);
                version.services = SERVICE_NETWORK | SERVICE_BLOOM;
                let mut connection = PeerConnection::accept(
                    stream,
                    PeerConfig::for_network(NetworkMagic::Regtest),
                    &version,
                    now,
                )
                .unwrap();
                connection.complete_handshake(|| now).unwrap();
                let announced = match connection.receive_event(now).unwrap() {
                    PeerEvent::Wallet(WalletPeerEvent::Inventory(items)) => items,
                    event => panic!("expected transaction inventory, received {event:?}"),
                };
                assert_eq!(
                    announced,
                    vec![Inventory {
                        kind: InventoryKind::Transaction,
                        hash: transaction_hash,
                    }]
                );
                connection
                    .send_wallet_packet(&Packet::GetData(announced))
                    .unwrap();
                match connection.receive_event(now).unwrap() {
                    PeerEvent::Wallet(WalletPeerEvent::Transaction(received)) => {
                        assert_eq!(received, transaction);
                    }
                    event => panic!("expected requested transaction, received {event:?}"),
                }
            }
        });

        let mut local_version = light_wallet_version(address, [1; 8], 42, now);
        // The generic accepted-peer test adapter requires NETWORK and wallet
        // packet emission requires negotiated BLOOM in both directions.
        // Production wallet clients continue to advertise no service.
        local_version.services = SERVICE_NETWORK | SERVICE_BLOOM;
        let mut connection = PeerConnection::connect(
            address,
            PeerConfig::for_wallet_network(NetworkMagic::Regtest),
            &local_version,
            now,
            Duration::from_secs(1),
        )
        .unwrap();
        connection.complete_handshake(|| now).unwrap();
        let mut peer = NativePeer {
            address,
            connection,
            deferred_wallet: VecDeque::new(),
        };
        assert!(
            peer.announce_transaction(transaction, transaction_hash, Duration::from_secs(1))
                .unwrap()
        );
        server.join().unwrap();
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
