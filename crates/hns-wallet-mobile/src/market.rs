//! Persisted direct Denuo HNS/BTC session admission for installed wallets.

use hns_marketplace_protocol::CrossChainMessage;
use hns_wallet_hns::HnsDirectDenuoPeer;
use hns_wallet_market::{
    DenuoDirectOfferAdmission, DenuoDirectOfferCancellationAdmission, DenuoDirectSwapAdmission,
    DenuoDirectSwapPolicy, admit_denuo_direct_offer, admit_denuo_direct_offer_cancellation,
    admit_denuo_direct_offer_take, admit_denuo_direct_swap_hello, admit_denuo_direct_swap_proposal,
    denuo_direct_offer_inventory, load_denuo_direct_offer, validate_denuo_direct_swap_peer_status,
};
use hns_wallet_store::SharedWalletStore;

use crate::MobileWalletError;

/// One wallet-owned bridge from a direct Denuo packet to the existing durable
/// HNS/BTC handshake journal. It exposes neither generic message execution
/// nor a signing authority; HTLC operations stay behind their chain-specific
/// controllers and explicit native approvals.
pub struct MobileDenuoSessionController {
    store: SharedWalletStore,
    policy: DenuoDirectSwapPolicy,
}

/// One locally admitted direct-board or direct-session event. The native
/// controller intentionally exposes no oracle-derived pricing result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileDenuoDirectAdmission {
    Offer(DenuoDirectOfferAdmission),
    OfferCancellation(DenuoDirectOfferCancellationAdmission),
    Swap(DenuoDirectSwapAdmission),
}

/// Bounded effects of one direct HNS/BTC Denuo transport event. Discovery
/// traffic has no settlement authority; `admission` is populated only after a
/// signed offer or session message passes the durable local checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MobileDenuoDirectTransportReport {
    pub messages_received: usize,
    pub messages_sent: usize,
    pub admission: Option<MobileDenuoDirectAdmission>,
}

impl MobileDenuoSessionController {
    pub fn new(store: SharedWalletStore, policy: DenuoDirectSwapPolicy) -> Self {
        Self { store, policy }
    }

    /// Admit exactly one canonical direct-peer fixed-offer or session message.
    /// Inventory/get exchange remains transport-level discovery; only signed
    /// offers, cancellations, takes, proposals, accepted terms, and statuses
    /// are persisted here.
    pub fn admit_direct_envelope(
        &self,
        envelope: &[u8],
        now_unix: u64,
    ) -> Result<Option<MobileDenuoDirectAdmission>, MobileWalletError> {
        let (_, message) = CrossChainMessage::decode_envelope(envelope)
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        let canonical = message
            .encode_envelope(
                CrossChainMessage::decode_envelope(envelope)
                    .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?
                    .0,
            )
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        if canonical != envelope {
            return Err(MobileWalletError::InvalidDenuoSessionMessage);
        }
        self.store
            .try_with_store_mut(|store| match message {
                CrossChainMessage::DirectOffer(_) => {
                    admit_denuo_direct_offer(store, &self.policy.board_policy(), envelope, now_unix)
                        .map(|admission| Some(MobileDenuoDirectAdmission::Offer(admission)))
                }
                CrossChainMessage::CancelDirectOffer(_) => admit_denuo_direct_offer_cancellation(
                    store,
                    &self.policy.board_policy(),
                    envelope,
                    now_unix,
                )
                .map(|admission| Some(MobileDenuoDirectAdmission::OfferCancellation(admission))),
                CrossChainMessage::TakeDirectOffer(_) => {
                    admit_denuo_direct_offer_take(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileDenuoDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapSessionProposal(_) => {
                    admit_denuo_direct_swap_proposal(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileDenuoDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapSessionHello(_) => {
                    admit_denuo_direct_swap_hello(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileDenuoDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapFundingStatus(_)
                | CrossChainMessage::SwapRedeemStatus(_)
                | CrossChainMessage::SwapRefundStatus(_) => {
                    validate_denuo_direct_swap_peer_status(store, &self.policy, envelope, now_unix)
                        .map(|_| None)
                }
                _ => Err(hns_wallet_market::MarketError::InvalidDenuoPeerMessage),
            })
            .map_err(MobileWalletError::from)
    }

    /// Announce the locally retained active-offer inventory to one negotiated
    /// peer. The peer receives only opaque offer identifiers; it cannot learn
    /// a price policy or change which exact signed terms the wallet will use.
    pub fn announce_direct_offer_inventory(
        &self,
        peer: &mut HnsDirectDenuoPeer,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let inventory = self
            .store
            .try_with_store(|store| {
                denuo_direct_offer_inventory(store, &self.policy.board_policy(), now_unix)
            })
            .map_err(MobileWalletError::from)?;
        peer.send_cross_chain_message(&CrossChainMessage::DirectOfferInventory(inventory))?;
        Ok(())
    }

    /// Service one already-received canonical cross-chain envelope. Direct
    /// inventory/get exchange is transport-only. Every offer, cancellation,
    /// take, and session packet still passes through `admit_direct_envelope`
    /// before it can affect durable state.
    pub fn service_direct_envelope(
        &self,
        peer: &mut HnsDirectDenuoPeer,
        envelope: &[u8],
        now_unix: u64,
    ) -> Result<MobileDenuoDirectTransportReport, MobileWalletError> {
        let (request_id, message) = CrossChainMessage::decode_envelope(envelope)
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        let canonical = message
            .encode_envelope(request_id)
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        if canonical != envelope {
            return Err(MobileWalletError::InvalidDenuoSessionMessage);
        }
        let mut report = MobileDenuoDirectTransportReport {
            messages_received: 1,
            messages_sent: 0,
            admission: None,
        };
        match message {
            CrossChainMessage::DirectOfferInventory(offer_ids) => {
                for offer_id in offer_ids {
                    let known = self
                        .store
                        .try_with_store(|store| {
                            load_denuo_direct_offer(store, &self.policy.board_policy(), offer_id)
                        })
                        .map_err(MobileWalletError::from)?
                        .is_some();
                    if !known {
                        peer.send_cross_chain_message(&CrossChainMessage::GetDirectOffer(
                            offer_id,
                        ))?;
                        report.messages_sent = report.messages_sent.saturating_add(1);
                    }
                }
            }
            CrossChainMessage::GetDirectOffer(offer_id) => {
                let offer = self
                    .store
                    .try_with_store(|store| {
                        load_denuo_direct_offer(store, &self.policy.board_policy(), offer_id)
                    })
                    .map_err(MobileWalletError::from)?;
                if let Some(offer) = offer.filter(|offer| offer.is_active_at(now_unix)) {
                    peer.send_cross_chain_message_with_request_id(
                        request_id,
                        &CrossChainMessage::DirectOffer(offer.offer),
                    )?;
                    report.messages_sent = report.messages_sent.saturating_add(1);
                }
            }
            CrossChainMessage::DirectOffer(_)
            | CrossChainMessage::CancelDirectOffer(_)
            | CrossChainMessage::TakeDirectOffer(_)
            | CrossChainMessage::SwapSessionProposal(_)
            | CrossChainMessage::SwapSessionHello(_)
            | CrossChainMessage::SwapFundingStatus(_)
            | CrossChainMessage::SwapRedeemStatus(_)
            | CrossChainMessage::SwapRefundStatus(_) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
            }
        }
        Ok(report)
    }
}
