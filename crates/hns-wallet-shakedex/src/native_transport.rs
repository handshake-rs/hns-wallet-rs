//! Wallet-owned Shakescape name-market replication over direct Handshake peers.
//!
//! This module intentionally has no relay cursor, endpoint acceptance receipt,
//! RPC call, or indexer dependency. A direct peer only carries canonical,
//! bounded protocol bytes. The receiving wallet independently revalidates each
//! signed listing against its authenticated local HNS view before a board row
//! is committed or later used for a trade.

use hns_marketplace_protocol::{
    MAX_NAME_OFFERS_PER_MESSAGE, MAX_SHAKESCAPE_MARKET_PAYLOAD, NameMarketHello, NameMarketMessage,
    ShakescapeRegistryVersion,
};
use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsDirectPeerError, HnsDirectShakescapePeer, HnsWalletError,
    HnsWalletRuntime,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::ObjectHash;
use thiserror::Error;

use crate::{
    ShakedexError, ShakescapeBoardRuntime, ShakescapeHandoffPreparation,
    board_runtime::CurrentShakescapeBoardOffersResolution, load_shakescape_publication_outbox,
    prepare_next_shakescape_handoff, record_shakescape_handoff_direct_announcement,
};

/// Hard upper bound for one caller-driven direct board exchange. A caller can
/// invoke another exchange later; no peer can make one UI action unbounded.
pub const MAX_DIRECT_SHAKESCAPE_MESSAGES_PER_SYNC: usize = 256;

/// Effects of one direct Shakescape board exchange.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectShakescapeBoardSyncReport {
    pub messages_received: usize,
    pub messages_sent: usize,
    pub inventory_hashes_requested: usize,
    pub offers_admitted: usize,
    pub cancellations_admitted: usize,
    pub marketplace_records_rejected: usize,
}

/// Failure at the wallet-owned direct marketplace boundary.
#[derive(Debug, Error)]
pub enum WalletNativeShakescapeTransportError {
    #[error(transparent)]
    DirectPeer(#[from] HnsDirectPeerError),
    #[error(transparent)]
    Wallet(#[from] HnsWalletError),
    #[error(transparent)]
    Board(#[from] ShakedexError),
    #[error("the requested direct Shakescape exchange message limit is invalid")]
    InvalidMessageLimit,
    #[error("direct Shakescape transport produced an invalid canonical envelope")]
    InvalidEnvelope,
}

/// Same-store direct Shakescape board replicator for one full HNS wallet runtime.
///
/// The runtime owns all authority and persistence. This object owns neither a
/// hidden relay account nor a second board database; the caller supplies an
/// already negotiated [`HnsDirectShakescapePeer`] for the lifetime of one exchange.
pub struct WalletNativeShakescapeTransport<'a, B, C> {
    hns: &'a HnsWalletRuntime<B, C>,
    store: SharedWalletStore,
    board: ShakescapeBoardRuntime<'a, B, C>,
}

impl<'a, B: HnsBackend, C: HnsClock> WalletNativeShakescapeTransport<'a, B, C> {
    pub fn new(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, WalletNativeShakescapeTransportError> {
        Ok(Self {
            hns,
            board: ShakescapeBoardRuntime::new_value(hns, store.clone())?,
            store,
        })
    }

    /// Announce this wallet's direct board and request the peer's inventory.
    /// A peer never becomes authority by answering either request.
    pub fn begin(
        &self,
        peer: &mut HnsDirectShakescapePeer,
    ) -> Result<DirectShakescapeBoardSyncReport, WalletNativeShakescapeTransportError> {
        let mut report = DirectShakescapeBoardSyncReport::default();
        peer.send_name_market(&NameMarketMessage::Hello(self.market_hello()?))?;
        report.messages_sent = report.messages_sent.saturating_add(1);
        peer.send_name_market(&NameMarketMessage::GetOfferInventory)?;
        report.messages_sent = report.messages_sent.saturating_add(1);
        Ok(report)
    }

    /// Admit and announce one due seller publication through a negotiated
    /// wallet peer. The local board admission happens before the socket write,
    /// so a successfully announced record remains available for later direct
    /// inventory exchanges even if that specific peer disappears. The durable
    /// outcome records only this wallet's write; it is not peer acceptance.
    pub fn announce_next_local_publication(
        &self,
        peer: &mut HnsDirectShakescapePeer,
    ) -> Result<Option<ObjectHash>, WalletNativeShakescapeTransportError> {
        let now_unix = self.hns.trusted_now_unix()?;
        let revision = self
            .store
            .try_with_store(load_shakescape_publication_outbox)?
            .revision;
        let preparation = self.store.try_with_store_mut(|store| {
            prepare_next_shakescape_handoff(store, revision, now_unix)
        })?;
        let handoff = match preparation {
            ShakescapeHandoffPreparation::NoDue { .. } => return Ok(None),
            ShakescapeHandoffPreparation::Prepared(handoff)
            | ShakescapeHandoffPreparation::Existing(handoff) => handoff,
        };
        let (registry, request_id, message) =
            NameMarketMessage::decode_envelope(handoff.envelope_bytes())
                .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?;
        if registry != ShakescapeRegistryVersion::V1 || request_id != handoff.request_id() {
            return Err(WalletNativeShakescapeTransportError::InvalidEnvelope);
        }
        match &message {
            NameMarketMessage::Offer(listing) => {
                let hash = ObjectHash::new(
                    listing
                        .listing_hash()
                        .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
                );
                self.board.admit_offer(handoff.envelope_bytes(), hash)?;
            }
            NameMarketMessage::Cancel(cancellation) => {
                let listing_hash = ObjectHash::new(cancellation.listing_hash);
                let cancellation_hash = ObjectHash::new(
                    cancellation
                        .cancellation_hash()
                        .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
                );
                self.board.admit_cancellation(
                    handoff.envelope_bytes(),
                    listing_hash,
                    cancellation_hash,
                )?;
            }
            _ => return Err(WalletNativeShakescapeTransportError::InvalidEnvelope),
        }
        peer.send_name_market_with_request_id(request_id, &message)?;
        let announced = self.store.try_with_store_mut(|store| {
            record_shakescape_handoff_direct_announcement(store, &handoff, now_unix)
        })?;
        Ok(Some(announced.envelope_id()))
    }

    /// Process up to `message_limit` direct messages. The caller controls when
    /// the bounded receive loop runs, which keeps peer I/O out of background
    /// authority transitions and mobile lifecycle surprises.
    pub fn synchronize(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        now_unix: u64,
        message_limit: usize,
    ) -> Result<DirectShakescapeBoardSyncReport, WalletNativeShakescapeTransportError> {
        if message_limit == 0 || message_limit > MAX_DIRECT_SHAKESCAPE_MESSAGES_PER_SYNC {
            return Err(WalletNativeShakescapeTransportError::InvalidMessageLimit);
        }
        let mut report = DirectShakescapeBoardSyncReport::default();
        for _ in 0..message_limit {
            let (request_id, message) = peer.receive_name_market(now_unix)?;
            merge_report(
                &mut report,
                self.handle_received_message(peer, request_id, message)?,
            );
        }
        Ok(report)
    }

    /// Process one already-demultiplexed canonical name-market message. This
    /// lets a mobile peer service name offers alongside direct HNS/BTC Shakescape
    /// traffic without a packet for one protocol being consumed by the other.
    pub fn handle_received_message(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        request_id: u64,
        message: NameMarketMessage,
    ) -> Result<DirectShakescapeBoardSyncReport, WalletNativeShakescapeTransportError> {
        let mut report = DirectShakescapeBoardSyncReport {
            messages_received: 1,
            ..DirectShakescapeBoardSyncReport::default()
        };
        self.handle_message(peer, request_id, message, &mut report)?;
        Ok(report)
    }

    fn handle_message(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        request_id: u64,
        message: NameMarketMessage,
        report: &mut DirectShakescapeBoardSyncReport,
    ) -> Result<(), WalletNativeShakescapeTransportError> {
        match message {
            NameMarketMessage::Hello(_) => {
                peer.send_name_market_with_request_id(
                    request_id,
                    &NameMarketMessage::Hello(self.market_hello()?),
                )?;
                report.messages_sent = report.messages_sent.saturating_add(1);
            }
            NameMarketMessage::GetOfferInventory => {
                let inventory = self.board.current_inventory()?;
                peer.send_name_market_with_request_id(
                    request_id,
                    &NameMarketMessage::OfferInventory(
                        inventory
                            .listing_hashes()
                            .iter()
                            .map(|hash| hash.into_bytes())
                            .collect(),
                    ),
                )?;
                report.messages_sent = report.messages_sent.saturating_add(1);
            }
            NameMarketMessage::OfferInventory(hashes) => {
                for hashes in hashes.chunks(MAX_NAME_OFFERS_PER_MESSAGE) {
                    peer.send_name_market(&NameMarketMessage::GetOffers(hashes.to_vec()))?;
                    report.messages_sent = report.messages_sent.saturating_add(1);
                    report.inventory_hashes_requested = report
                        .inventory_hashes_requested
                        .saturating_add(hashes.len());
                }
            }
            NameMarketMessage::GetOffers(hashes) => {
                self.reply_offers(peer, request_id, hashes, report)?;
            }
            NameMarketMessage::Offers(listings) => {
                for listing in listings {
                    let listing_hash = ObjectHash::new(
                        listing
                            .listing_hash()
                            .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
                    );
                    let envelope = NameMarketMessage::Offer(listing)
                        .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
                        .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?;
                    self.admit_offer(&envelope, listing_hash, report)?;
                }
            }
            NameMarketMessage::GetOffer(listing_hash) => {
                let listing_hash = ObjectHash::new(listing_hash);
                if let Some(current) = self.board.current_offer(listing_hash)? {
                    peer.send_name_market_with_request_id(
                        request_id,
                        &NameMarketMessage::Offer(
                            current.listing().authenticated().canonical().clone(),
                        ),
                    )?;
                    report.messages_sent = report.messages_sent.saturating_add(1);
                }
            }
            NameMarketMessage::Offer(listing) => {
                let listing_hash = ObjectHash::new(
                    listing
                        .listing_hash()
                        .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
                );
                let envelope = NameMarketMessage::Offer(listing)
                    .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
                    .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?;
                self.admit_offer(&envelope, listing_hash, report)?;
            }
            NameMarketMessage::Cancel(cancellation) => {
                let listing_hash = ObjectHash::new(cancellation.listing_hash);
                let cancellation_hash = ObjectHash::new(
                    cancellation
                        .cancellation_hash()
                        .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
                );
                let envelope = NameMarketMessage::Cancel(cancellation)
                    .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
                    .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?;
                match self
                    .board
                    .admit_cancellation(&envelope, listing_hash, cancellation_hash)
                {
                    Ok(_) => {
                        report.cancellations_admitted =
                            report.cancellations_admitted.saturating_add(1)
                    }
                    Err(error) if rejected_marketplace_record(&error) => {
                        report.marketplace_records_rejected =
                            report.marketplace_records_rejected.saturating_add(1);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }

    fn reply_offers(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        request_id: u64,
        hashes: Vec<[u8; 32]>,
        report: &mut DirectShakescapeBoardSyncReport,
    ) -> Result<(), WalletNativeShakescapeTransportError> {
        let hashes = hashes.into_iter().map(ObjectHash::new).collect::<Vec<_>>();
        let CurrentShakescapeBoardOffersResolution::Current(current) =
            self.board.current_offers(&hashes)?
        else {
            return Ok(());
        };
        peer.send_name_market_with_request_id(
            request_id,
            &NameMarketMessage::Offers(
                current
                    .listings()
                    .iter()
                    .map(|listing| listing.authenticated().canonical().clone())
                    .collect(),
            ),
        )?;
        report.messages_sent = report.messages_sent.saturating_add(1);
        Ok(())
    }

    fn admit_offer(
        &self,
        envelope: &[u8],
        listing_hash: ObjectHash,
        report: &mut DirectShakescapeBoardSyncReport,
    ) -> Result<(), WalletNativeShakescapeTransportError> {
        match self.board.admit_offer(envelope, listing_hash) {
            Ok(_) => report.offers_admitted = report.offers_admitted.saturating_add(1),
            Err(error) if rejected_marketplace_record(&error) => {
                report.marketplace_records_rejected =
                    report.marketplace_records_rejected.saturating_add(1);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn market_hello(&self) -> Result<NameMarketHello, WalletNativeShakescapeTransportError> {
        let network = self.hns.shakedex_network()?;
        Ok(NameMarketHello {
            hns_magic: network.magic,
            hns_genesis: network.genesis,
            maximum_payload: u32::try_from(MAX_SHAKESCAPE_MARKET_PAYLOAD)
                .map_err(|_| WalletNativeShakescapeTransportError::InvalidEnvelope)?,
            feature_flags: 0,
        })
    }
}

fn merge_report(into: &mut DirectShakescapeBoardSyncReport, next: DirectShakescapeBoardSyncReport) {
    into.messages_received = into
        .messages_received
        .saturating_add(next.messages_received);
    into.messages_sent = into.messages_sent.saturating_add(next.messages_sent);
    into.inventory_hashes_requested = into
        .inventory_hashes_requested
        .saturating_add(next.inventory_hashes_requested);
    into.offers_admitted = into.offers_admitted.saturating_add(next.offers_admitted);
    into.cancellations_admitted = into
        .cancellations_admitted
        .saturating_add(next.cancellations_admitted);
    into.marketplace_records_rejected = into
        .marketplace_records_rejected
        .saturating_add(next.marketplace_records_rejected);
}

fn rejected_marketplace_record(error: &ShakedexError) -> bool {
    matches!(
        error,
        ShakedexError::InvalidListing
            | ShakedexError::InvalidCancellation
            | ShakedexError::InvalidEvidence
            | ShakedexError::InvalidShakescapeEnvelope
            | ShakedexError::ShakescapeRegistryMismatch
            | ShakedexError::NameMarketReplay
    )
}
