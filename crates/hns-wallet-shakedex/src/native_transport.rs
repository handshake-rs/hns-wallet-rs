//! Wallet-owned Denuo name-market replication over direct Handshake peers.
//!
//! This module intentionally has no relay cursor, endpoint acceptance receipt,
//! RPC call, or indexer dependency. A direct peer only carries canonical,
//! bounded protocol bytes. The receiving wallet independently revalidates each
//! signed listing against its authenticated local HNS view before a board row
//! is committed or later used for a trade.

use hns_marketplace_protocol::{
    DenuoRegistryVersion, MAX_DENUO_MARKET_PAYLOAD, MAX_NAME_OFFERS_PER_MESSAGE, NameMarketHello,
    NameMarketMessage,
};
use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsDirectDenuoPeer, HnsDirectPeerError, HnsWalletError, HnsWalletRuntime,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::ObjectHash;
use thiserror::Error;

use crate::{DenuoBoardRuntime, ShakedexError, board_runtime::CurrentDenuoBoardOffersResolution};

/// Hard upper bound for one caller-driven direct board exchange. A caller can
/// invoke another exchange later; no peer can make one UI action unbounded.
pub const MAX_DIRECT_DENUO_MESSAGES_PER_SYNC: usize = 256;

/// Effects of one direct Denuo board exchange.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectDenuoBoardSyncReport {
    pub messages_received: usize,
    pub messages_sent: usize,
    pub inventory_hashes_requested: usize,
    pub offers_admitted: usize,
    pub cancellations_admitted: usize,
    pub marketplace_records_rejected: usize,
}

/// Failure at the wallet-owned direct marketplace boundary.
#[derive(Debug, Error)]
pub enum WalletNativeDenuoTransportError {
    #[error(transparent)]
    DirectPeer(#[from] HnsDirectPeerError),
    #[error(transparent)]
    Wallet(#[from] HnsWalletError),
    #[error(transparent)]
    Board(#[from] ShakedexError),
    #[error("the requested direct Denuo exchange message limit is invalid")]
    InvalidMessageLimit,
    #[error("direct Denuo transport produced an invalid canonical envelope")]
    InvalidEnvelope,
}

/// Same-store direct Denuo board replicator for one full HNS wallet runtime.
///
/// The runtime owns all authority and persistence. This object owns neither a
/// hidden relay account nor a second board database; the caller supplies an
/// already negotiated [`HnsDirectDenuoPeer`] for the lifetime of one exchange.
pub struct WalletNativeDenuoTransport<'a, B, C> {
    hns: &'a HnsWalletRuntime<B, C>,
    board: DenuoBoardRuntime<'a, B, C>,
}

impl<'a, B: HnsBackend, C: HnsClock> WalletNativeDenuoTransport<'a, B, C> {
    pub fn new(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, WalletNativeDenuoTransportError> {
        Ok(Self {
            hns,
            board: DenuoBoardRuntime::new_value(hns, store)?,
        })
    }

    /// Announce this wallet's direct board and request the peer's inventory.
    /// A peer never becomes authority by answering either request.
    pub fn begin(
        &self,
        peer: &mut HnsDirectDenuoPeer,
    ) -> Result<DirectDenuoBoardSyncReport, WalletNativeDenuoTransportError> {
        let mut report = DirectDenuoBoardSyncReport::default();
        peer.send_name_market(&NameMarketMessage::Hello(self.market_hello()?))?;
        report.messages_sent = report.messages_sent.saturating_add(1);
        peer.send_name_market(&NameMarketMessage::GetOfferInventory)?;
        report.messages_sent = report.messages_sent.saturating_add(1);
        Ok(report)
    }

    /// Process up to `message_limit` direct messages. The caller controls when
    /// the bounded receive loop runs, which keeps peer I/O out of background
    /// authority transitions and mobile lifecycle surprises.
    pub fn synchronize(
        &self,
        peer: &mut HnsDirectDenuoPeer,
        now_unix: u64,
        message_limit: usize,
    ) -> Result<DirectDenuoBoardSyncReport, WalletNativeDenuoTransportError> {
        if message_limit == 0 || message_limit > MAX_DIRECT_DENUO_MESSAGES_PER_SYNC {
            return Err(WalletNativeDenuoTransportError::InvalidMessageLimit);
        }
        let mut report = DirectDenuoBoardSyncReport::default();
        for _ in 0..message_limit {
            let (request_id, message) = peer.receive_name_market(now_unix)?;
            report.messages_received = report.messages_received.saturating_add(1);
            self.handle_message(peer, request_id, message, &mut report)?;
        }
        Ok(report)
    }

    fn handle_message(
        &self,
        peer: &mut HnsDirectDenuoPeer,
        request_id: u64,
        message: NameMarketMessage,
        report: &mut DirectDenuoBoardSyncReport,
    ) -> Result<(), WalletNativeDenuoTransportError> {
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
                            .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?,
                    );
                    let envelope = NameMarketMessage::Offer(listing)
                        .encode_envelope(DenuoRegistryVersion::V2, request_id)
                        .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?;
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
                        .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?,
                );
                let envelope = NameMarketMessage::Offer(listing)
                    .encode_envelope(DenuoRegistryVersion::V2, request_id)
                    .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?;
                self.admit_offer(&envelope, listing_hash, report)?;
            }
            NameMarketMessage::Cancel(cancellation) => {
                let listing_hash = ObjectHash::new(cancellation.listing_hash);
                let cancellation_hash = ObjectHash::new(
                    cancellation
                        .cancellation_hash()
                        .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?,
                );
                let envelope = NameMarketMessage::Cancel(cancellation)
                    .encode_envelope(DenuoRegistryVersion::V2, request_id)
                    .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?;
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
        peer: &mut HnsDirectDenuoPeer,
        request_id: u64,
        hashes: Vec<[u8; 32]>,
        report: &mut DirectDenuoBoardSyncReport,
    ) -> Result<(), WalletNativeDenuoTransportError> {
        let hashes = hashes.into_iter().map(ObjectHash::new).collect::<Vec<_>>();
        let CurrentDenuoBoardOffersResolution::Current(current) =
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
        report: &mut DirectDenuoBoardSyncReport,
    ) -> Result<(), WalletNativeDenuoTransportError> {
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

    fn market_hello(&self) -> Result<NameMarketHello, WalletNativeDenuoTransportError> {
        let network = self.hns.shakedex_network()?;
        Ok(NameMarketHello {
            hns_magic: network.magic,
            hns_genesis: network.genesis,
            maximum_payload: u32::try_from(MAX_DENUO_MARKET_PAYLOAD)
                .map_err(|_| WalletNativeDenuoTransportError::InvalidEnvelope)?,
            feature_flags: 0,
        })
    }
}

fn rejected_marketplace_record(error: &ShakedexError) -> bool {
    matches!(
        error,
        ShakedexError::InvalidListing
            | ShakedexError::InvalidCancellation
            | ShakedexError::InvalidEvidence
            | ShakedexError::InvalidDenuoEnvelope
            | ShakedexError::DenuoRegistryMismatch
            | ShakedexError::NameMarketReplay
    )
}
