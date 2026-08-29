//! Persisted direct Denuo HNS/BTC session admission for installed wallets.

use hns_marketplace_protocol::CrossChainMessage;
use hns_wallet_hns::HnsDirectDenuoPeer;
use hns_wallet_market::{
    DenuoBtcForHnsOfferRequest, DenuoDirectOfferAdmission, DenuoDirectOfferCancellationAdmission,
    DenuoDirectSwapAdmission, DenuoDirectSwapPolicy, DenuoLocalDirectOffer,
    admit_denuo_direct_offer, admit_denuo_direct_offer_cancellation, admit_denuo_direct_offer_take,
    admit_denuo_direct_swap_hello, admit_denuo_direct_swap_proposal,
    cancel_denuo_local_direct_offer, create_denuo_btc_for_hns_offer, denuo_direct_offer_inventory,
    list_local_denuo_direct_offers, load_denuo_direct_offer,
    validate_denuo_direct_swap_peer_status,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::WalletId;
use serde::{Deserialize, Serialize};

use crate::MobileWalletError;

/// One wallet-owned bridge from a direct Denuo packet to the existing durable
/// HNS/BTC handshake journal. It exposes neither generic message execution
/// nor a signing authority; HTLC operations stay behind their chain-specific
/// controllers and explicit native approvals.
pub struct MobileDenuoSessionController {
    store: SharedWalletStore,
    policy: DenuoDirectSwapPolicy,
    wallet_id: WalletId,
    pending_offer: Option<PendingBtcForHnsOffer>,
}

const DIRECT_OFFER_APPROVAL_LIFETIME_SECONDS: u64 = 300;
const MIN_DIRECT_OFFER_LIFETIME_SECONDS: u64 = 600;
const MAX_DIRECT_OFFER_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug)]
struct PendingBtcForHnsOffer {
    action_token: [u8; 32],
    nonce: [u8; 32],
    btc_amount_sats: u64,
    hns_amount_dollarydoos: u64,
    bitcoin_fee_reserve_sats: u64,
    offer_expires_at_unix: u64,
    approval_expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBtcForHnsOfferApproval {
    pub action_token: String,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub bitcoin_fee_reserve_sats: u64,
    pub total_bitcoin_commitment_sats: u64,
    pub offer_expires_at_unix: u64,
    pub approval_expires_at_unix: u64,
    pub connected_peer_required_for_announcement: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBtcForHnsOfferSummary {
    pub offer_id: String,
    pub session_id: String,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub bitcoin_fee_reserve_sats: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
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
    pub fn new(
        store: SharedWalletStore,
        policy: DenuoDirectSwapPolicy,
        wallet_id: WalletId,
    ) -> Self {
        Self {
            store,
            policy,
            wallet_id,
            pending_offer: None,
        }
    }

    /// Prepare exact BTC-for-HNS terms for native confirmation. This reserves
    /// nothing durably and signs nothing. Existing active local offers count
    /// against the confirmed balance so multiple listings cannot overcommit it.
    pub fn prepare_btc_for_hns_offer(
        &mut self,
        confirmed_sats: u64,
        btc_amount_sats: u64,
        hns_amount_dollarydoos: u64,
        bitcoin_fee_reserve_sats: u64,
        listing_lifetime_seconds: u64,
        now_unix: u64,
    ) -> Result<MobileBtcForHnsOfferApproval, MobileWalletError> {
        if self.pending_offer.is_some() {
            return Err(MobileWalletError::DirectOfferActionPending);
        }
        if now_unix == 0
            || btc_amount_sats == 0
            || hns_amount_dollarydoos == 0
            || bitcoin_fee_reserve_sats == 0
            || !(MIN_DIRECT_OFFER_LIFETIME_SECONDS..=MAX_DIRECT_OFFER_LIFETIME_SECONDS)
                .contains(&listing_lifetime_seconds)
        {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        let requested = btc_amount_sats
            .checked_add(bitcoin_fee_reserve_sats)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let already_reserved = self
            .store
            .try_with_store(|store| {
                list_local_denuo_direct_offers(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?
            .into_iter()
            .try_fold(0_u64, |sum, offer| {
                let offered = u64::try_from(offer.offer.offered_amount)
                    .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
                sum.checked_add(offered)
                    .and_then(|sum| sum.checked_add(offer.bitcoin_fee_reserve_sats))
                    .ok_or(MobileWalletError::InvalidDirectOfferAction)
            })?;
        if already_reserved
            .checked_add(requested)
            .is_none_or(|total| total > confirmed_sats)
        {
            return Err(MobileWalletError::InsufficientBitcoinForDirectOffer);
        }
        let offer_expires_at_unix = now_unix
            .checked_add(listing_lifetime_seconds)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let approval_expires_at_unix = now_unix
            .checked_add(DIRECT_OFFER_APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let action_token = super::random_nonzero_bytes()?;
        let nonce = super::random_nonzero_bytes()?;
        self.pending_offer = Some(PendingBtcForHnsOffer {
            action_token,
            nonce,
            btc_amount_sats,
            hns_amount_dollarydoos,
            bitcoin_fee_reserve_sats,
            offer_expires_at_unix,
            approval_expires_at_unix,
        });
        Ok(MobileBtcForHnsOfferApproval {
            action_token: super::lowercase_hex(&action_token),
            btc_amount_sats,
            hns_amount_dollarydoos,
            bitcoin_fee_reserve_sats,
            total_bitcoin_commitment_sats: requested,
            offer_expires_at_unix,
            approval_expires_at_unix,
            connected_peer_required_for_announcement: true,
        })
    }

    pub fn approve_btc_for_hns_offer(
        &mut self,
        action_token: &str,
        now_unix: u64,
    ) -> Result<MobileBtcForHnsOfferSummary, MobileWalletError> {
        let pending = self
            .pending_offer
            .take()
            .ok_or(MobileWalletError::NoPendingDirectOfferAction)?;
        if !super::mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidDirectOfferActionToken);
        }
        if now_unix == 0 || now_unix >= pending.approval_expires_at_unix {
            return Err(MobileWalletError::DirectOfferActionExpired);
        }
        let created = self
            .store
            .try_with_store_mut(|store| {
                create_denuo_btc_for_hns_offer(
                    store,
                    &self.policy.board_policy(),
                    DenuoBtcForHnsOfferRequest {
                        wallet_id: self.wallet_id,
                        btc_amount_sats: pending.btc_amount_sats,
                        hns_amount_dollarydoos: pending.hns_amount_dollarydoos,
                        bitcoin_fee_reserve_sats: pending.bitcoin_fee_reserve_sats,
                        created_at_unix: now_unix,
                        expires_at_unix: pending.offer_expires_at_unix,
                        nonce: pending.nonce,
                    },
                )
            })
            .map_err(MobileWalletError::from)?;
        summary(created)
    }

    pub fn reject_btc_for_hns_offer(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_offer
            .take()
            .ok_or(MobileWalletError::NoPendingDirectOfferAction)?;
        if !super::mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidDirectOfferActionToken);
        }
        Ok(())
    }

    pub fn local_btc_for_hns_offers(
        &self,
        now_unix: u64,
    ) -> Result<Vec<MobileBtcForHnsOfferSummary>, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                list_local_denuo_direct_offers(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?
            .into_iter()
            .map(summary)
            .collect()
    }

    pub fn cancel_local_btc_for_hns_offer(
        &mut self,
        offer_id: &str,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let offer_id = decode_offer_id(offer_id)?;
        self.store
            .try_with_store_mut(|store| {
                cancel_denuo_local_direct_offer(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                    offer_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?;
        Ok(())
    }

    pub fn announce_direct_offer_cancellation(
        &self,
        peer: &mut HnsDirectDenuoPeer,
        offer_id: &str,
    ) -> Result<(), MobileWalletError> {
        let offer_id = decode_offer_id(offer_id)?;
        let cancellation = self
            .store
            .try_with_store(|store| {
                load_denuo_direct_offer(store, &self.policy.board_policy(), offer_id)
            })
            .map_err(MobileWalletError::from)?
            .and_then(|record| record.cancellation)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        peer.send_cross_chain_message(&CrossChainMessage::CancelDirectOffer(cancellation))?;
        Ok(())
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

fn summary(offer: DenuoLocalDirectOffer) -> Result<MobileBtcForHnsOfferSummary, MobileWalletError> {
    Ok(MobileBtcForHnsOfferSummary {
        offer_id: super::lowercase_hex(offer.offer.offer_id.as_bytes()),
        session_id: super::lowercase_hex(offer.session_id.as_bytes()),
        btc_amount_sats: u64::try_from(offer.offer.offered_amount)
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?,
        hns_amount_dollarydoos: u64::try_from(offer.offer.received_amount)
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?,
        bitcoin_fee_reserve_sats: offer.bitcoin_fee_reserve_sats,
        created_at_unix: offer.offer.created_at_unix,
        expires_at_unix: offer.offer.expires_at_unix,
    })
}

fn decode_offer_id(encoded: &str) -> Result<[u8; 32], MobileWalletError> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MobileWalletError::InvalidDirectOfferAction);
    }
    let mut offer_id = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        offer_id[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    if offer_id.iter().all(|byte| *byte == 0) {
        return Err(MobileWalletError::InvalidDirectOfferAction);
    }
    Ok(offer_id)
}
