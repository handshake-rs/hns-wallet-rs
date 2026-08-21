//! Persisted direct Denuo HNS/BTC session admission for installed wallets.

use hns_marketplace_protocol::CrossChainMessage;
use hns_wallet_market::{
    DenuoSwapHandshakeAdmission, DenuoSwapHandshakePolicy, admit_denuo_fill_grant,
    admit_denuo_match_request, admit_denuo_swap_hello, admit_denuo_swap_proposal,
    validate_denuo_swap_peer_status,
};
use hns_wallet_store::SharedWalletStore;

use crate::MobileWalletError;

/// One wallet-owned bridge from a direct Denuo packet to the existing durable
/// HNS/BTC handshake journal. It exposes neither generic message execution
/// nor a signing authority; HTLC operations stay behind their chain-specific
/// controllers and explicit native approvals.
pub struct MobileDenuoSessionController {
    store: SharedWalletStore,
    policy: DenuoSwapHandshakePolicy,
}

impl MobileDenuoSessionController {
    pub fn new(store: SharedWalletStore, policy: DenuoSwapHandshakePolicy) -> Self {
        Self { store, policy }
    }

    /// Admit exactly one canonical direct-peer session message. Inventory and
    /// market-intent exchange is intentionally handled by the board controller;
    /// this boundary only accepts bilateral session progression/status frames.
    pub fn admit_direct_envelope(
        &self,
        envelope: &[u8],
        now_unix: u64,
    ) -> Result<Option<DenuoSwapHandshakeAdmission>, MobileWalletError> {
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
                CrossChainMessage::MatchRequest(_) => {
                    admit_denuo_match_request(store, &self.policy, envelope, now_unix).map(Some)
                }
                CrossChainMessage::FillGrant(_) => {
                    admit_denuo_fill_grant(store, &self.policy, envelope, now_unix).map(Some)
                }
                CrossChainMessage::SwapSessionProposal(_) => {
                    admit_denuo_swap_proposal(store, &self.policy, envelope, now_unix).map(Some)
                }
                CrossChainMessage::SwapSessionHello(_) => {
                    admit_denuo_swap_hello(store, &self.policy, envelope, now_unix).map(Some)
                }
                CrossChainMessage::SwapFundingStatus(_)
                | CrossChainMessage::SwapRedeemStatus(_)
                | CrossChainMessage::SwapRefundStatus(_) => {
                    validate_denuo_swap_peer_status(store, &self.policy, envelope, now_unix)
                        .map(|_| None)
                }
                _ => Err(hns_wallet_market::MarketError::InvalidDenuoPeerMessage),
            })
            .map_err(MobileWalletError::from)
    }
}
