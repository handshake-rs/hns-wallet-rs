//! Direct standard-peer synchronization for the wallet-owned HNS authority.
//!
//! DNS seeds, address gossip, and connected HSD peers are discovery and data
//! transports only. Headers, partial Merkle trees, transactions, and Urkel
//! proofs cross the wallet's local verification boundaries before they mutate
//! durable state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    CrossChainMessage, DenuoRegistryVersion, MAX_DENUO_MARKET_PAYLOAD, NameMarketHello,
    NameMarketMessage,
};
use hns_p2p_experimental::{
    ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION, DENUO_EXTENSION_MAX_PACKET_PAYLOAD,
    DENUO_EXTENSION_PACKET, DENUO_EXTENSION_SERVICE, DENUO_V2_REGISTRY_FINGERPRINT,
    DENUO_V2_REGISTRY_VERSION, DenuoExtensionEnvelope, NegotiatedRegistry,
    Network as ExperimentalNetwork, ProtocolRange, RegistryHello,
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
const DENUO_MAX_RESPONSE_EVENTS: usize = 256;
const DENUO_MAXIMUM_LIVE_REQUESTS: u16 = 64;

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

/// One direct Denuo Experimental V2 session owned by the wallet.
///
/// The peer is an ordinary Handshake TCP peer. It is not an RPC endpoint or a
/// trusted marketplace service: registry negotiation binds the wire profile
/// and every offer remains subject to the wallet's independent board and
/// current-lock validation.
pub struct HnsDirectDenuoPeer {
    address: SocketAddr,
    network: HnsNetwork,
    connection: PeerConnection<TcpStream>,
    negotiated: NegotiatedRegistry,
    next_request_id: u64,
}

/// One canonical Denuo application message received on a negotiated direct
/// peer. Name-market replication and direct HNS/BTC offers share only the
/// socket; they retain separate protocol identities and validation paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsDirectDenuoMessage {
    NameMarket {
        request_id: u64,
        message: NameMarketMessage,
    },
    CrossChain {
        envelope: Vec<u8>,
    },
}

/// A wallet-owned, nonblocking TCP admission point for direct Denuo peers.
///
/// This listener is deliberately narrower than a Handshake node listener. It
/// accepts no chain, wallet-filter, RPC, indexing, or arbitrary experimental
/// traffic. A caller obtains a negotiated [`HnsDirectDenuoPeer`] only after
/// the standard Handshake handshake and the exact Denuo V2 registry agreement
/// have both completed. The caller remains responsible for deciding when an
/// unlocked wallet may service a bounded board exchange.
pub struct HnsDirectDenuoListener {
    listener: TcpListener,
    config: HnsDirectPeerConfig,
}

impl HnsDirectDenuoListener {
    /// Bind one explicit local socket for direct wallet-to-wallet Denuo
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
    /// Denuo protocol. `Ok(None)` means there is no pending connection.
    ///
    /// The accepted handshake is bounded by the peer configuration's socket
    /// deadlines. Callers should invoke this from their owned I/O worker and
    /// must not retain a peer after the associated wallet is locked.
    pub fn accept_next(
        &self,
        local_height: u32,
        now_unix: u64,
    ) -> Result<Option<HnsDirectDenuoPeer>, HnsDirectPeerError> {
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
        HnsDirectDenuoPeer::accept(&self.config, stream, local_height, now_unix).map(Some)
    }
}

impl HnsDirectDenuoPeer {
    /// Establish the standard peer session and exact Denuo V2 registry
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
        let request_id = nonzero_denuo_request_id()?;
        let local_version =
            direct_denuo_version(address, request_id.to_be_bytes(), local_height, now_unix);
        let mut connection = PeerConnection::connect(
            address,
            PeerConfig::for_network(network_magic(config.network)),
            &local_version,
            now_unix,
            config.connect_timeout,
        )?;
        let metadata = connection.complete_handshake(|| now_unix_or(now_unix))?;
        if metadata.services & DENUO_EXTENSION_SERVICE.value() == 0 {
            return Err(HnsDirectPeerError::DenuoPeerNotAdvertised);
        }
        let local_hello = denuo_registry_hello(config.network)?;
        let outbound = DenuoExtensionEnvelope::registry_hello_v2(request_id, &local_hello)
            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?
            .encode_canonical()
            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
        connection.send_experimental_packet(DENUO_EXTENSION_PACKET.value(), outbound)?;
        let negotiated =
            receive_denuo_hello_ack(&mut connection, config.network, request_id, now_unix)?;
        Ok(Self {
            address,
            network: config.network,
            connection,
            negotiated,
            next_request_id: request_id.checked_add(1).unwrap_or(1),
        })
    }

    /// Bind one socket accepted by a wallet-hosted listener to the exact
    /// Denuo V2 atomic-market profile.
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
        if !inbound_denuo_address_allowed(config, address) {
            return Err(HnsDirectPeerError::AddressNotAllowed);
        }
        let request_id = nonzero_denuo_request_id()?;
        let local_version =
            direct_denuo_version(address, request_id.to_be_bytes(), local_height, now_unix);
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
        if metadata.services & DENUO_EXTENSION_SERVICE.value() == 0 {
            return Err(HnsDirectPeerError::DenuoPeerNotAdvertised);
        }
        let negotiated = respond_denuo_registry_hello(&mut connection, config.network, now_unix)?;
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

    /// The exact negotiated Denuo registry evidence for this connection.
    #[must_use]
    pub const fn negotiated_registry(&self) -> &NegotiatedRegistry {
        &self.negotiated
    }

    /// Send one canonical Denuo name-market message over this negotiated
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
            return Err(HnsDirectPeerError::Denuo(
                "Denuo name-market request id must be nonzero".to_owned(),
            ));
        }
        let payload = message
            .encode_envelope(DenuoRegistryVersion::V2, request_id)
            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
        self.connection
            .send_experimental_packet(DENUO_EXTENSION_PACKET.value(), payload)?;
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
        match self.receive_denuo_message(now_unix)? {
            HnsDirectDenuoMessage::NameMarket {
                request_id,
                message,
            } => Ok((request_id, message)),
            HnsDirectDenuoMessage::CrossChain { .. } => Err(HnsDirectPeerError::Denuo(
                "received a cross-chain Denuo envelope in a name-market-only exchange".to_owned(),
            )),
        }
    }

    /// Receive one canonical Denuo application envelope and classify it by
    /// protocol identity. This performs no market admission or swap state
    /// transition; the caller routes the typed message to its local authority.
    pub fn receive_denuo_message(
        &mut self,
        now_unix: u64,
    ) -> Result<HnsDirectDenuoMessage, HnsDirectPeerError> {
        for _ in 0..DENUO_MAX_RESPONSE_EVENTS {
            match self.connection.receive_event(now_unix)? {
                PeerEvent::Experimental {
                    packet_type,
                    payload,
                } if packet_type == DENUO_EXTENSION_PACKET.value() => {
                    let envelope =
                        DenuoExtensionEnvelope::decode(&payload, MAX_DENUO_MARKET_PAYLOAD)
                            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
                    if envelope.protocol_id == hns_p2p_experimental::CROSS_CHAIN_MARKET_PROTOCOL_ID
                    {
                        validate_cross_chain_envelope(&payload)?;
                        return Ok(HnsDirectDenuoMessage::CrossChain { envelope: payload });
                    }
                    let (registry, request_id, message) =
                        NameMarketMessage::decode_envelope(&payload)
                            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
                    if registry != DenuoRegistryVersion::V2 || request_id == 0 {
                        return Err(HnsDirectPeerError::Denuo(
                            "invalid Denuo V2 name-market envelope".to_owned(),
                        ));
                    }
                    validate_denuo_market_hello(self.network, &message)?;
                    return Ok(HnsDirectDenuoMessage::NameMarket {
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

    /// Send one exact canonical Denuo HNS/BTC session envelope over the
    /// already-negotiated direct socket. The peer remains transport only: the
    /// mobile market controller admits the specific message, correlation, and
    /// session state before any durable mutation or HTLC action.
    pub fn send_cross_chain_envelope(&mut self, envelope: &[u8]) -> Result<(), HnsDirectPeerError> {
        validate_cross_chain_envelope(envelope)?;
        self.connection
            .send_experimental_packet(DENUO_EXTENSION_PACKET.value(), envelope.to_vec())?;
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
            .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
        self.send_cross_chain_envelope(&envelope)
    }

    /// Receive one canonical HNS/BTC Denuo envelope from the direct socket.
    /// This never accepts a generic experimental payload or performs a market
    /// state transition; callers must route it to the persisted market
    /// handshake controller for its exact expected stage.
    pub fn receive_cross_chain_envelope(
        &mut self,
        now_unix: u64,
    ) -> Result<Vec<u8>, HnsDirectPeerError> {
        match self.receive_denuo_message(now_unix)? {
            HnsDirectDenuoMessage::CrossChain { envelope } => Ok(envelope),
            HnsDirectDenuoMessage::NameMarket { .. } => Err(HnsDirectPeerError::Denuo(
                "received a name-market Denuo envelope in a cross-chain-only exchange".to_owned(),
            )),
        }
    }
}

fn nonzero_denuo_request_id() -> Result<u64, HnsDirectPeerError> {
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
/// Denuo exchange. The extension service augments, rather than replaces, the
/// mandatory standard `NETWORK` bit: a Denuo wallet remains a Handshake peer
/// on the ordinary wire and interoperates with peers that enforce the normal
/// service admission rule.
fn direct_denuo_version(
    remote: SocketAddr,
    nonce: [u8; 8],
    local_height: u32,
    now_unix: u64,
) -> hns_p2p_wire::VersionPacket {
    let mut version = light_wallet_version(remote, nonce, local_height, now_unix);
    version.services = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
    version
}

fn denuo_registry_hello(network: HnsNetwork) -> Result<RegistryHello, HnsDirectPeerError> {
    let binding = crate::shakedex_network_binding(network)?;
    RegistryHello::denuo_v2(
        experimental_network(network),
        *binding.genesis.as_bytes(),
        vec![ProtocolRange {
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            minimum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
            maximum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
        }],
        u32::try_from(DENUO_EXTENSION_MAX_PACKET_PAYLOAD.min(MAX_DENUO_MARKET_PAYLOAD))
            .map_err(|_| HnsDirectPeerError::Arithmetic)?,
        DENUO_MAXIMUM_LIVE_REQUESTS,
        0,
    )
    .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))
}

fn receive_denuo_hello_ack(
    connection: &mut PeerConnection<TcpStream>,
    network: HnsNetwork,
    request_id: u64,
    now_unix: u64,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let local = denuo_registry_hello(network)?;
    for _ in 0..DENUO_MAX_RESPONSE_EVENTS {
        match connection.receive_event(now_unix)? {
            PeerEvent::Experimental {
                packet_type,
                payload,
            } if packet_type == DENUO_EXTENSION_PACKET.value() => {
                let (received_request_id, remote) =
                    DenuoExtensionEnvelope::decode_registry_hello_ack_v2(&payload)
                        .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
                if received_request_id != request_id {
                    return Err(HnsDirectPeerError::Denuo(
                        "Denuo registry hello acknowledgement correlation mismatch".to_owned(),
                    ));
                }
                return exact_denuo_v2_atomic_market(&local, &remote);
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

fn respond_denuo_registry_hello(
    connection: &mut PeerConnection<TcpStream>,
    network: HnsNetwork,
    now_unix: u64,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let local = denuo_registry_hello(network)?;
    for _ in 0..DENUO_MAX_RESPONSE_EVENTS {
        match connection.receive_event(now_unix)? {
            PeerEvent::Experimental {
                packet_type,
                payload,
            } if packet_type == DENUO_EXTENSION_PACKET.value() => {
                let (request_id, remote) =
                    DenuoExtensionEnvelope::decode_registry_hello_v2(&payload)
                        .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
                if request_id == 0 {
                    return Err(HnsDirectPeerError::Denuo(
                        "Denuo registry hello request id must be nonzero".to_owned(),
                    ));
                }
                let negotiated = exact_denuo_v2_atomic_market(&local, &remote)?;
                let ack = DenuoExtensionEnvelope::registry_hello_ack_v2(request_id, &local)
                    .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?
                    .encode_canonical()
                    .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
                connection
                    .send_experimental_packet(DENUO_EXTENSION_PACKET.value(), ack)
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

fn exact_denuo_v2_atomic_market(
    local: &RegistryHello,
    remote: &RegistryHello,
) -> Result<NegotiatedRegistry, HnsDirectPeerError> {
    let negotiated = NegotiatedRegistry::negotiate(local, remote)
        .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
    if negotiated.registry_version != DENUO_V2_REGISTRY_VERSION
        || negotiated.fingerprint != DENUO_V2_REGISTRY_FINGERPRINT
        || !negotiated
            .protocols
            .contains(&(ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION))
    {
        return Err(HnsDirectPeerError::Denuo(
            "Denuo peer lacks exact V2 atomic-market admission".to_owned(),
        ));
    }
    Ok(negotiated)
}

fn validate_denuo_market_hello(
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
        return Err(HnsDirectPeerError::Denuo(
            "Denuo name-market hello has wrong Handshake network binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cross_chain_envelope(envelope: &[u8]) -> Result<(), HnsDirectPeerError> {
    if envelope.is_empty() || envelope.len() > MAX_DENUO_MARKET_PAYLOAD {
        return Err(HnsDirectPeerError::Denuo(
            "Denuo cross-chain envelope exceeds its exact bound".to_owned(),
        ));
    }
    let (request_id, message) = CrossChainMessage::decode_envelope(envelope)
        .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
    let canonical = message
        .encode_envelope(request_id)
        .map_err(|error| HnsDirectPeerError::Denuo(error.to_string()))?;
    if canonical != envelope {
        return Err(HnsDirectPeerError::Denuo(
            "Denuo cross-chain envelope is not canonical".to_owned(),
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

fn inbound_denuo_address_allowed(config: &HnsDirectPeerConfig, address: SocketAddr) -> bool {
    address.port() != 0 && (config.allow_private_addresses || is_public_peer_ip(address.ip()))
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
        self.synchronize_name_proof(name_hash, now_unix)
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
                    | PeerEvent::Experimental { .. }
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
    #[error("the standard peer does not advertise the Denuo extension service")]
    DenuoPeerNotAdvertised,
    #[error("wallet-native Denuo negotiation or message validation failed: {0}")]
    Denuo(String),
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
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    fn direct_denuo_registry_is_pinned_to_the_wallet_network_and_atomic_market() {
        let hello = denuo_registry_hello(HnsNetwork::Regtest).unwrap();
        assert_eq!(hello.network, ExperimentalNetwork::Regtest);
        assert_eq!(hello.registry_versions, vec![DENUO_V2_REGISTRY_VERSION]);
        assert_eq!(hello.fingerprint, DENUO_V2_REGISTRY_FINGERPRINT);
        assert!(hello.protocols.contains(&ProtocolRange {
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            minimum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
            maximum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
        }));
        assert_eq!(
            hello.maximum_receive_size as usize,
            MAX_DENUO_MARKET_PAYLOAD
        );
    }

    #[test]
    fn direct_denuo_wallet_advertises_standard_network_and_extension_services() {
        let version = direct_denuo_version(
            "127.0.0.1:12038".parse().unwrap(),
            [9; 8],
            42,
            Network::Regtest.parameters().genesis_time.get() + 1,
        );
        assert_ne!(version.services & SERVICE_NETWORK, 0);
        assert_ne!(version.services & DENUO_EXTENSION_SERVICE.value(), 0);
    }

    #[test]
    fn direct_denuo_wallet_accepts_and_negotiates_an_inbound_wallet_peer() {
        let listener = HnsDirectDenuoListener::bind(
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
            panic!("wallet-hosted Denuo listener did not receive the client")
        });

        let mut client_config = HnsDirectPeerConfig::for_network(HnsNetwork::Regtest);
        client_config.static_peers.push(address);
        let client = HnsDirectDenuoPeer::connect(&client_config, address, 42, now).unwrap();
        let server = server.join().unwrap();

        assert_eq!(client.negotiated_registry(), server.negotiated_registry());
        assert_eq!(client.address(), address);
        assert!(server.address().ip().is_loopback());
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
