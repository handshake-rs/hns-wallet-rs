//! Persisted direct Shakescape HNS/BTC session admission for installed wallets.

use hns_marketplace_protocol::{
    AssetId, CrossChainMessage, FundingState, SignedObjectHeader, SwapAssetSide, SwapFundingStatus,
    SwapSessionHello,
};
use hns_wallet_bitcoin_kyoto::{
    BitcoinHtlcWatchRequest, MIN_HTLC_DUST_SATS, build_shakescape_bitcoin_htlc,
};
use hns_wallet_hns::{DEFAULT_DUST_THRESHOLD, HnsDirectPeerCoordinator, HnsDirectShakescapePeer};
use hns_wallet_market::{
    ShakescapeBtcForHnsOfferRequest, ShakescapeDirectOfferAdmission,
    ShakescapeDirectOfferCancellationAdmission, ShakescapeDirectSwapAdmission,
    ShakescapeDirectSwapPolicy, ShakescapeDirectTakeRequest, ShakescapeHnsForBtcOfferRequest,
    ShakescapeLocalDirectOffer, ShakescapeLocalDirectTake, SwapState, VerifiedEvidence,
    WalletStoreJournal, abandon_pending_local_shakescape_direct_take,
    accept_shakescape_direct_maker_proposal, admit_shakescape_direct_offer,
    admit_shakescape_direct_offer_cancellation, admit_shakescape_direct_offer_take,
    admit_shakescape_direct_swap_hello, admit_shakescape_direct_swap_peer_status,
    admit_shakescape_direct_swap_proposal, admit_shakescape_direct_swap_watch_ready,
    cancel_shakescape_local_direct_offer, create_shakescape_btc_for_hns_offer,
    create_shakescape_direct_maker_proposal, create_shakescape_direct_take,
    create_shakescape_hns_for_btc_offer, is_local_shakescape_direct_maker,
    is_local_shakescape_direct_taker, list_local_shakescape_direct_offer_cancellations,
    list_local_shakescape_direct_offers, list_local_shakescape_direct_takes,
    list_pending_local_shakescape_direct_takes, list_shakescape_executions,
    load_shakescape_direct_offer, load_shakescape_direct_offers, load_shakescape_direct_swap,
    load_shakescape_direct_swaps, load_shakescape_execution, open_shakescape_execution,
    shakescape_execution_workflow_id,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::{TransactionHash, WalletId};
use serde::{Deserialize, Serialize};

use crate::{MobileShakescapeUnfundedBitcoinProof, MobileWalletError};

// Public offer expiry is the deadline for beginning a new negotiation, not
// the lifetime of an already-funded settlement.  Funding locators remain
// hints only (each wallet independently verifies the exact HTLC on-chain), so
// give every newly signed status a bounded replay window beyond the current
// time.  The chain refund deadlines are also retained as a lower bound so a
// slow but still live swap is not cut off by its old listing deadline.
const FUNDING_STATUS_REPLAY_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Settlement spends currently pay their chain fee from the locked output.
/// The advertised lock amount must therefore leave a standard, non-dust
/// receiver output even if the whole agreed fee reserve is needed. Checking
/// the amount and reserve independently admits locks which can be funded but
/// can never be redeemed or refunded.
fn amount_covers_settlement_fee_reserve(asset: AssetId, amount: u64, fee_reserve: u64) -> bool {
    let minimum_output = match asset {
        AssetId::BTC => u128::from(MIN_HTLC_DUST_SATS),
        AssetId::HNS => DEFAULT_DUST_THRESHOLD,
        _ => return false,
    };
    u128::from(amount)
        .checked_sub(u128::from(fee_reserve))
        .is_some_and(|output| output >= minimum_output)
}

/// One wallet-owned bridge from a direct Shakescape packet to the existing durable
/// HNS/BTC handshake journal. It exposes neither generic message execution
/// nor a signing authority; HTLC operations stay behind their chain-specific
/// controllers and explicit native approvals.
pub struct MobileShakescapeSessionController {
    store: SharedWalletStore,
    policy: ShakescapeDirectSwapPolicy,
    wallet_id: WalletId,
    pending_offer: Option<PendingBtcForHnsOffer>,
    pending_hns_offer: Option<PendingHnsForBtcOffer>,
    pending_take: Option<PendingDirectOfferTake>,
}

/// Rust-only authority passed from the accepted Shakescape session controller to
/// the Bitcoin controller. Its fields remain private so Kotlin/Swift cannot
/// replace signed terms, the session identifier, or the reserved fee cap.
pub struct MobileShakescapeBitcoinFundingPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    bitcoin_fee_reserve_sats: u64,
}

pub struct MobileShakescapeHnsFundingPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    hns_fee_reserve_dollarydoos: u64,
}

pub struct MobileShakescapeBitcoinWatchPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
}

/// Exact authenticated Bitcoin lock terms for proving that an expired local
/// first-funding action never produced a durable transaction.
pub struct MobileShakescapeBitcoinAbsencePermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
}

pub struct MobileShakescapeHnsWatchPermit {
    hello: SwapSessionHello,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
}

pub struct MobileShakescapeHnsVerificationPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    funding_transaction: Option<TransactionHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobileShakescapeSettlementAction {
    Redeem,
    Refund,
}

pub struct MobileShakescapeHnsSettlementPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    // Redeems spend the counterparty's lock, so its authenticated funding
    // locator must be fetched and independently verified from chain data.
    // Refunds spend this wallet's own persisted lock and deliberately leave
    // this unset.
    funding_transaction: Option<TransactionHash>,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    preimage: Option<hns_wallet_chain_api::Preimage>,
    action: MobileShakescapeSettlementAction,
    fee_reserve: u64,
}

pub struct MobileShakescapeBitcoinSettlementPermit {
    hello: SwapSessionHello,
    side: SwapAssetSide,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    preimage: Option<hns_wallet_chain_api::Preimage>,
    action: MobileShakescapeSettlementAction,
    fee_reserve: u64,
}

impl MobileShakescapeHnsSettlementPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }
    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }
    pub(crate) const fn funding_transaction(&self) -> Option<TransactionHash> {
        self.funding_transaction
    }
    pub(crate) fn take_preimage(&mut self) -> Option<hns_wallet_chain_api::Preimage> {
        self.preimage.take()
    }
    pub(crate) const fn action(&self) -> MobileShakescapeSettlementAction {
        self.action
    }
    pub(crate) const fn fee_reserve(&self) -> u64 {
        self.fee_reserve
    }
}

impl MobileShakescapeBitcoinSettlementPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }
    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }
    pub(crate) fn take_preimage(&mut self) -> Option<hns_wallet_chain_api::Preimage> {
        self.preimage.take()
    }
    pub(crate) const fn action(&self) -> MobileShakescapeSettlementAction {
        self.action
    }
    pub(crate) const fn fee_reserve(&self) -> u64 {
        self.fee_reserve
    }
}

impl MobileShakescapeHnsVerificationPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }

    pub const fn session_id(&self) -> hns_wallet_types::SessionId {
        hns_wallet_types::SessionId::new(self.hello.swap_session_id)
    }

    pub(crate) const fn funding_transaction(&self) -> Option<TransactionHash> {
        self.funding_transaction
    }
}

impl MobileShakescapeBitcoinWatchPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }
}

impl MobileShakescapeHnsFundingPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }

    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }

    pub(crate) const fn hns_fee_reserve_dollarydoos(&self) -> u64 {
        self.hns_fee_reserve_dollarydoos
    }
}

impl MobileShakescapeBitcoinFundingPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }

    pub(crate) const fn bitcoin_fee_reserve_sats(&self) -> u64 {
        self.bitcoin_fee_reserve_sats
    }
}

impl MobileShakescapeBitcoinAbsencePermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }

    pub(crate) const fn side(&self) -> SwapAssetSide {
        self.side
    }
}

const DIRECT_OFFER_APPROVAL_LIFETIME_SECONDS: u64 = 300;
/// The maker commits this much time to first-chain funding after receiving a
/// take. A take is unusable unless the listing remains valid for this complete
/// interval. Two windows make a newly published offer useful for up to one
/// hour of ordinary board propagation and user review.
const DIRECT_SWAP_FUNDING_WINDOW_SECONDS: u64 = 60 * 60;
const MIN_DIRECT_OFFER_LIFETIME_SECONDS: u64 = 2 * DIRECT_SWAP_FUNDING_WINDOW_SECONDS;
const MAX_DIRECT_OFFER_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Product floor for Bitcoin funding/refund headroom committed by a mobile
/// direct offer participant. Values below this cannot pass the downstream
/// Bitcoin transaction fee policy and therefore must not become signed terms.
pub const MINIMUM_BITCOIN_FEE_RESERVE_SATS: u64 = 1_000;
/// Product floor already used by the Android/iOS native approval surfaces for
/// Handshake value actions. Keeping it in signed swap admission prevents a
/// tiny user-entered cap from creating a funded but non-relayable HTLC spend.
pub const MINIMUM_HNS_FEE_RESERVE_DOLLARYDOOS: u64 = 100_000;

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

#[derive(Clone, Debug)]
struct PendingHnsForBtcOffer {
    action_token: [u8; 32],
    nonce: [u8; 32],
    hns_amount_dollarydoos: u64,
    btc_amount_sats: u64,
    hns_fee_reserve_dollarydoos: u64,
    offer_expires_at_unix: u64,
    approval_expires_at_unix: u64,
}

#[derive(Clone, Debug)]
struct PendingDirectOfferTake {
    action_token: [u8; 32],
    nonce: [u8; 32],
    offer_id: hns_wallet_types::ObjectHash,
    offered_asset: AssetId,
    offered_amount: u64,
    received_asset: AssetId,
    received_amount: u64,
    received_fee_reserve: u64,
    take_expires_at_unix: u64,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileHnsForBtcOfferApproval {
    pub action_token: String,
    pub hns_amount_dollarydoos: u64,
    pub btc_amount_sats: u64,
    pub hns_fee_reserve_dollarydoos: u64,
    pub total_hns_commitment_dollarydoos: u64,
    pub offer_expires_at_unix: u64,
    pub approval_expires_at_unix: u64,
    pub connected_peer_required_for_announcement: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDirectOfferSummary {
    pub offer_id: String,
    pub session_id: String,
    pub maker_sells_hns: bool,
    pub offered_asset: String,
    pub offered_amount: u64,
    pub received_asset: String,
    pub received_amount: u64,
    pub btc_amount_sats: u64,
    pub hns_amount_dollarydoos: u64,
    pub offered_fee_reserve: Option<u64>,
    pub local: bool,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDirectOfferTakeApproval {
    pub action_token: String,
    pub offer: MobileDirectOfferSummary,
    pub received_fee_reserve: u64,
    pub total_received_asset_commitment: u64,
    pub take_expires_at_unix: u64,
    pub approval_expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDirectOfferTakeSummary {
    pub offer_id: String,
    pub session_id: String,
    pub offered_asset: String,
    pub offered_amount: u64,
    pub received_asset: String,
    pub received_amount: u64,
    pub received_fee_reserve: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

/// Non-sensitive durable execution projection for native recovery UI. It
/// contains no transaction bytes, preimage, derivation path, peer endpoint, or
/// private key material; chain actions remain behind explicit approvals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileShakescapeExecutionSummary {
    pub session_id: String,
    pub revision: u64,
    pub state: SwapState,
    pub first_chain: String,
    pub second_chain: String,
    pub offered_asset: String,
    pub offered_amount: u128,
    pub received_asset: String,
    pub received_amount: u128,
    /// This wallet's participant role in the immutable session terms. Native
    /// clients use it to expose funding actions only to the chain owner that
    /// can actually authorize them.
    pub local_role: String,
    pub first_refund_at_unix: u64,
    pub second_refund_at_unix: u64,
    pub first_funding_confirmed: bool,
    pub second_funding_confirmed: bool,
    pub first_redemption_confirmed: bool,
    pub second_redemption_confirmed: bool,
    pub refund_confirmed: bool,
    pub last_verified_at_unix: u64,
    pub failure_reason: Option<String>,
}

/// One locally admitted direct-board or direct-session event. The native
/// controller intentionally exposes no oracle-derived pricing result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileShakescapeDirectAdmission {
    Offer(ShakescapeDirectOfferAdmission),
    OfferCancellation(ShakescapeDirectOfferCancellationAdmission),
    Swap(ShakescapeDirectSwapAdmission),
}

/// Protocol identity of one serviced cross-chain envelope. This intentionally
/// exposes no offer, wallet, transaction, or session identifier; embeddings
/// can use it to diagnose bounded transport progress without logging private
/// market material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileShakescapeDirectMessageKind {
    OfferInventory,
    GetOffer,
    Offer,
    OfferCancellation,
    TakeOffer,
    SessionProposal,
    SessionHello,
    FundingStatus,
    RedeemStatus,
    RefundStatus,
    WatchReady,
}

/// Bounded material emitted during one periodic direct-board reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MobileShakescapeDirectInventoryReport {
    pub active_offers: usize,
    pub cancellations: usize,
    pub pending_takes: usize,
    pub session_envelopes: usize,
}

/// Bounded effects of one direct HNS/BTC Shakescape transport event. Discovery
/// traffic has no settlement authority; `admission` is populated only after a
/// signed offer or session message passes the durable local checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MobileShakescapeDirectTransportReport {
    pub message_kind: MobileShakescapeDirectMessageKind,
    pub messages_received: usize,
    pub messages_sent: usize,
    pub admission: Option<MobileShakescapeDirectAdmission>,
}

impl MobileShakescapeSessionController {
    pub fn new(
        store: SharedWalletStore,
        policy: ShakescapeDirectSwapPolicy,
        wallet_id: WalletId,
    ) -> Self {
        Self {
            store,
            policy,
            wallet_id,
            pending_offer: None,
            pending_hns_offer: None,
            pending_take: None,
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
        if self.pending_offer.is_some()
            || self.pending_hns_offer.is_some()
            || self.pending_take.is_some()
        {
            return Err(MobileWalletError::DirectOfferActionPending);
        }
        if now_unix == 0
            || !amount_covers_settlement_fee_reserve(
                AssetId::BTC,
                btc_amount_sats,
                bitcoin_fee_reserve_sats,
            )
            || u128::from(hns_amount_dollarydoos) < DEFAULT_DUST_THRESHOLD
            || bitcoin_fee_reserve_sats < MINIMUM_BITCOIN_FEE_RESERVE_SATS
            || !(MIN_DIRECT_OFFER_LIFETIME_SECONDS..=MAX_DIRECT_OFFER_LIFETIME_SECONDS)
                .contains(&listing_lifetime_seconds)
        {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        // The advertised amount is the complete HTLC value. The settlement
        // fee reserve is a cap carved out of that value, not additional
        // wallet principal (the validation above guarantees a non-dust
        // receiver output remains after spending the whole reserve).
        let requested = btc_amount_sats;
        let already_reserved = self.reserved_bitcoin_sats(now_unix)?;
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
                create_shakescape_btc_for_hns_offer(
                    store,
                    &self.policy.board_policy(),
                    ShakescapeBtcForHnsOfferRequest {
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
                list_local_shakescape_direct_offers(
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

    pub fn prepare_hns_for_btc_offer(
        &mut self,
        confirmed_dollarydoos: u64,
        hns_amount_dollarydoos: u64,
        btc_amount_sats: u64,
        hns_fee_reserve_dollarydoos: u64,
        listing_lifetime_seconds: u64,
        now_unix: u64,
    ) -> Result<MobileHnsForBtcOfferApproval, MobileWalletError> {
        if self.pending_offer.is_some()
            || self.pending_hns_offer.is_some()
            || self.pending_take.is_some()
        {
            return Err(MobileWalletError::DirectOfferActionPending);
        }
        if now_unix == 0
            || !amount_covers_settlement_fee_reserve(
                AssetId::HNS,
                hns_amount_dollarydoos,
                hns_fee_reserve_dollarydoos,
            )
            || btc_amount_sats < MIN_HTLC_DUST_SATS
            || hns_fee_reserve_dollarydoos < MINIMUM_HNS_FEE_RESERVE_DOLLARYDOOS
            || !(MIN_DIRECT_OFFER_LIFETIME_SECONDS..=MAX_DIRECT_OFFER_LIFETIME_SECONDS)
                .contains(&listing_lifetime_seconds)
        {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        // As on Bitcoin, the fee reserve is included in the advertised HTLC
        // value and must not be counted as a second balance commitment.
        let requested = hns_amount_dollarydoos;
        let already_reserved = self.reserved_hns_dollarydoos(now_unix)?;
        if already_reserved
            .checked_add(requested)
            .is_none_or(|total| total > confirmed_dollarydoos)
        {
            return Err(MobileWalletError::InsufficientHnsForDirectOffer);
        }
        let offer_expires_at_unix = now_unix
            .checked_add(listing_lifetime_seconds)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let approval_expires_at_unix = now_unix
            .checked_add(DIRECT_OFFER_APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let action_token = super::random_nonzero_bytes()?;
        let nonce = super::random_nonzero_bytes()?;
        self.pending_hns_offer = Some(PendingHnsForBtcOffer {
            action_token,
            nonce,
            hns_amount_dollarydoos,
            btc_amount_sats,
            hns_fee_reserve_dollarydoos,
            offer_expires_at_unix,
            approval_expires_at_unix,
        });
        Ok(MobileHnsForBtcOfferApproval {
            action_token: super::lowercase_hex(&action_token),
            hns_amount_dollarydoos,
            btc_amount_sats,
            hns_fee_reserve_dollarydoos,
            total_hns_commitment_dollarydoos: requested,
            offer_expires_at_unix,
            approval_expires_at_unix,
            connected_peer_required_for_announcement: true,
        })
    }

    pub fn approve_hns_for_btc_offer(
        &mut self,
        action_token: &str,
        now_unix: u64,
    ) -> Result<MobileDirectOfferSummary, MobileWalletError> {
        let pending = self
            .pending_hns_offer
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
                create_shakescape_hns_for_btc_offer(
                    store,
                    &self.policy.board_policy(),
                    ShakescapeHnsForBtcOfferRequest {
                        wallet_id: self.wallet_id,
                        hns_amount_dollarydoos: pending.hns_amount_dollarydoos,
                        btc_amount_sats: pending.btc_amount_sats,
                        hns_fee_reserve_dollarydoos: pending.hns_fee_reserve_dollarydoos,
                        created_at_unix: now_unix,
                        expires_at_unix: pending.offer_expires_at_unix,
                        nonce: pending.nonce,
                    },
                )
            })
            .map_err(MobileWalletError::from)?;
        direct_local_offer_summary(created)
    }

    pub fn reject_hns_for_btc_offer(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_hns_offer
            .take()
            .ok_or(MobileWalletError::NoPendingDirectOfferAction)?;
        if !super::mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidDirectOfferActionToken);
        }
        Ok(())
    }

    pub fn local_direct_offers(
        &self,
        now_unix: u64,
    ) -> Result<Vec<MobileDirectOfferSummary>, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                list_local_shakescape_direct_offers(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?
            .into_iter()
            .map(direct_local_offer_summary)
            .collect()
    }

    pub fn available_direct_offers(
        &self,
        now_unix: u64,
    ) -> Result<Vec<MobileDirectOfferSummary>, MobileWalletError> {
        let local_ids = self
            .local_direct_offers(now_unix)?
            .into_iter()
            .map(|offer| offer.offer_id)
            .collect::<std::collections::BTreeSet<_>>();
        self.store
            .try_with_store(|store| {
                load_shakescape_direct_offers(store, &self.policy.board_policy(), now_unix)
            })
            .map_err(MobileWalletError::from)?
            .into_iter()
            .filter(|record| direct_offer_has_funding_horizon(record, now_unix))
            .map(|record| direct_board_offer_summary(record, false))
            .collect::<Result<Vec<_>, _>>()
            .map(|offers| {
                offers
                    .into_iter()
                    .filter(|offer| {
                        !local_ids.contains(&offer.offer_id)
                            && offer.btc_amount_sats >= MIN_HTLC_DUST_SATS
                            && u128::from(offer.hns_amount_dollarydoos) >= DEFAULT_DUST_THRESHOLD
                    })
                    .collect()
            })
    }

    pub fn prepare_direct_offer_take(
        &mut self,
        offer_id: &str,
        confirmed_btc_sats: u64,
        confirmed_hns_dollarydoos: u64,
        received_fee_reserve: u64,
        now_unix: u64,
    ) -> Result<MobileDirectOfferTakeApproval, MobileWalletError> {
        if self.pending_offer.is_some()
            || self.pending_hns_offer.is_some()
            || self.pending_take.is_some()
        {
            return Err(MobileWalletError::DirectOfferActionPending);
        }
        if now_unix == 0 || received_fee_reserve == 0 {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        let offer_id = decode_offer_id(offer_id)?;
        let record = self
            .store
            .try_with_store(|store| {
                load_shakescape_direct_offer(store, &self.policy.board_policy(), offer_id)
            })
            .map_err(MobileWalletError::from)?
            .filter(|record| record.is_active_at(now_unix))
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let offered_amount = u64::try_from(record.offer.offered_amount.get())
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
        let received_amount = u64::try_from(record.offer.received_amount.get())
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
        let bitcoin_amount = match (record.offer.offered_asset, record.offer.received_asset) {
            (AssetId::BTC, AssetId::HNS) => offered_amount,
            (AssetId::HNS, AssetId::BTC) => received_amount,
            _ => return Err(MobileWalletError::InvalidDirectOfferAction),
        };
        if bitcoin_amount < MIN_HTLC_DUST_SATS {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        let hns_amount = match (record.offer.offered_asset, record.offer.received_asset) {
            (AssetId::BTC, AssetId::HNS) => received_amount,
            (AssetId::HNS, AssetId::BTC) => offered_amount,
            _ => return Err(MobileWalletError::InvalidDirectOfferAction),
        };
        if u128::from(hns_amount) < DEFAULT_DUST_THRESHOLD {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        if record.offer.received_asset == AssetId::BTC
            && received_fee_reserve < MINIMUM_BITCOIN_FEE_RESERVE_SATS
        {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        if record.offer.received_asset == AssetId::HNS
            && received_fee_reserve < MINIMUM_HNS_FEE_RESERVE_DOLLARYDOOS
        {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        if !amount_covers_settlement_fee_reserve(
            record.offer.received_asset,
            received_amount,
            received_fee_reserve,
        ) {
            return Err(MobileWalletError::InvalidDirectOfferAction);
        }
        // The received-side amount is the exact value this taker will lock.
        // Its fee reserve is paid from that lock during settlement.
        let total = received_amount;
        let confirmed = match record.offer.received_asset {
            AssetId::BTC => confirmed_btc_sats,
            AssetId::HNS => confirmed_hns_dollarydoos,
            _ => return Err(MobileWalletError::InvalidDirectOfferAction),
        };
        let already_reserved = match record.offer.received_asset {
            AssetId::BTC => self.reserved_bitcoin_sats(now_unix)?,
            AssetId::HNS => self.reserved_hns_dollarydoos(now_unix)?,
            _ => return Err(MobileWalletError::InvalidDirectOfferAction),
        };
        if already_reserved
            .checked_add(total)
            .is_none_or(|required| required > confirmed)
        {
            return Err(match record.offer.received_asset {
                AssetId::BTC => MobileWalletError::InsufficientBitcoinForDirectOffer,
                AssetId::HNS => MobileWalletError::InsufficientHnsForDirectOffer,
                _ => MobileWalletError::InvalidDirectOfferAction,
            });
        }
        let approval_expires_at_unix = now_unix
            .checked_add(DIRECT_OFFER_APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidDirectOfferAction)?;
        let take_expires_at_unix = record.offer.header.expires_at;
        if !direct_offer_has_funding_horizon(&record, now_unix) {
            return Err(MobileWalletError::DirectOfferActionExpired);
        }
        let action_token = super::random_nonzero_bytes()?;
        let nonce = super::random_nonzero_bytes()?;
        let offer_summary = direct_board_offer_summary(record, false)?;
        self.pending_take = Some(PendingDirectOfferTake {
            action_token,
            nonce,
            offer_id: hns_wallet_types::ObjectHash::new(offer_id),
            offered_asset: match offer_summary.offered_asset.as_str() {
                "hns" => AssetId::HNS,
                _ => AssetId::BTC,
            },
            offered_amount,
            received_asset: match offer_summary.received_asset.as_str() {
                "hns" => AssetId::HNS,
                _ => AssetId::BTC,
            },
            received_amount,
            received_fee_reserve,
            take_expires_at_unix,
            approval_expires_at_unix,
        });
        Ok(MobileDirectOfferTakeApproval {
            action_token: super::lowercase_hex(&action_token),
            offer: offer_summary,
            received_fee_reserve,
            total_received_asset_commitment: total,
            take_expires_at_unix,
            approval_expires_at_unix,
        })
    }

    pub fn approve_direct_offer_take(
        &mut self,
        action_token: &str,
        peer: &mut HnsDirectShakescapePeer,
        now_unix: u64,
    ) -> Result<MobileDirectOfferTakeSummary, MobileWalletError> {
        let pending = self
            .pending_take
            .take()
            .ok_or(MobileWalletError::NoPendingDirectOfferAction)?;
        if !super::mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidDirectOfferActionToken);
        }
        if now_unix == 0 || now_unix >= pending.approval_expires_at_unix {
            return Err(MobileWalletError::DirectOfferActionExpired);
        }
        let take = self
            .store
            .try_with_store_mut(|store| {
                create_shakescape_direct_take(
                    store,
                    &self.policy,
                    ShakescapeDirectTakeRequest {
                        wallet_id: self.wallet_id,
                        offer_id: pending.offer_id,
                        received_fee_reserve: pending.received_fee_reserve,
                        created_at_unix: now_unix,
                        expires_at_unix: pending.take_expires_at_unix,
                        nonce: pending.nonce,
                    },
                )
            })
            .map_err(MobileWalletError::from)?;
        // Send the exact envelope retained with the durable take. Re-encoding
        // it under the socket's transient request counter makes recovery
        // ambiguous after reconnects and prevents byte-for-byte retry.
        peer.send_cross_chain_envelope(&take.envelope)?;
        Ok(MobileDirectOfferTakeSummary {
            offer_id: super::lowercase_hex(pending.offer_id.as_bytes()),
            session_id: super::lowercase_hex(take.session_id.as_bytes()),
            offered_asset: asset_name(pending.offered_asset).to_owned(),
            offered_amount: pending.offered_amount,
            received_asset: asset_name(pending.received_asset).to_owned(),
            received_amount: pending.received_amount,
            received_fee_reserve: pending.received_fee_reserve,
            created_at_unix: take.created_at_unix,
            expires_at_unix: take.expires_at_unix,
        })
    }

    pub fn reject_direct_offer_take(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_take
            .take()
            .ok_or(MobileWalletError::NoPendingDirectOfferAction)?;
        if !super::mobile_action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidDirectOfferActionToken);
        }
        Ok(())
    }

    pub fn reserved_hns_dollarydoos(&self, now_unix: u64) -> Result<u64, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                let maker = hns_wallet_market::reserved_local_shakescape_hns_maker_dollarydoos(
                    store,
                    &self.policy,
                    self.wallet_id,
                    now_unix,
                )?;
                let taker = hns_wallet_market::reserved_local_shakescape_taker_amount(
                    store,
                    &self.policy,
                    self.wallet_id,
                    AssetId::HNS,
                    now_unix,
                )?;
                maker
                    .checked_add(taker)
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)
            })
            .map_err(MobileWalletError::from)
    }

    pub fn reserved_bitcoin_sats(&self, now_unix: u64) -> Result<u64, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                let maker = hns_wallet_market::reserved_local_shakescape_btc_maker_sats(
                    store,
                    &self.policy,
                    self.wallet_id,
                    now_unix,
                )?;
                let taker = hns_wallet_market::reserved_local_shakescape_taker_amount(
                    store,
                    &self.policy,
                    self.wallet_id,
                    AssetId::BTC,
                    now_unix,
                )?;
                maker
                    .checked_add(taker)
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)
            })
            .map_err(MobileWalletError::from)
    }

    pub fn durable_executions(
        &self,
    ) -> Result<Vec<MobileShakescapeExecutionSummary>, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                list_shakescape_executions(store, &self.policy)?
                    .into_iter()
                    .map(|session| {
                        let local_role = if hns_wallet_market::is_local_shakescape_direct_maker(
                            store,
                            &self.policy,
                            self.wallet_id,
                            session.id,
                        )? {
                            "maker"
                        } else if hns_wallet_market::is_local_shakescape_direct_taker(
                            store,
                            self.wallet_id,
                            session.id,
                        )? {
                            "taker"
                        } else {
                            return Err(
                                hns_wallet_market::MarketError::CorruptShakescapeDirectSwap,
                            );
                        };
                        execution_summary(session, local_role).map_err(|_| {
                            hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileWalletError::from)
    }

    /// Reconstruct and install every non-terminal session's native HNS HTLC
    /// watch from jointly signed durable terms.
    ///
    /// This method is the authority bridge between the private swap journal
    /// and the public filtered-block client: the platform receives neither a
    /// caller-selected script nor a transaction claimed by the counterparty.
    /// A failed session remains watched because it may already contain funds
    /// that require an authenticated refund; only completed or fully refunded
    /// sessions are terminal for watch purposes.
    pub fn install_active_hns_htlc_watch_set(
        &self,
        coordinator: &HnsDirectPeerCoordinator,
        now_unix: u64,
    ) -> Result<bool, MobileWalletError> {
        if now_unix == 0 {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let policy = self.policy;
        let descriptors = self
            .store
            .try_with_store(|store| {
                let mut descriptors = Vec::new();
                for execution in list_shakescape_executions(store, &policy)? {
                    if matches!(execution.state, SwapState::Completed | SwapState::Refunded)
                        || (execution.first_module != hns_wallet_types::ModuleId::Handshake
                            && execution.second_module != hns_wallet_types::ModuleId::Handshake)
                    {
                        continue;
                    }
                    let record = load_shakescape_direct_swap(store, &policy, execution.id)?
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    let hello = record
                        .hello
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    hello
                        .verify_agreement(policy.network())
                        .map_err(|_| hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    let (side, receiver, refund, commitment) = if hello.offered_asset
                        == AssetId::HNS
                    {
                        (
                            SwapAssetSide::Offered,
                            hello.taker_settlement_public_key,
                            hello.maker_settlement_public_key,
                            hello.offered_lock_commitment,
                        )
                    } else if hello.received_asset == AssetId::HNS {
                        (
                            SwapAssetSide::Received,
                            hello.maker_settlement_public_key,
                            hello.taker_settlement_public_key,
                            hello.received_lock_commitment,
                        )
                    } else {
                        return Err(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap);
                    };
                    let binding = hello
                        .build_hns_htlc(side, receiver, refund)
                        .map_err(|_| hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    if binding.descriptor_hash != commitment {
                        return Err(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap);
                    }
                    descriptors.push(binding.descriptor);
                }
                Ok::<_, hns_wallet_market::MarketError>(descriptors)
            })
            .map_err(MobileWalletError::from)?;
        coordinator
            .install_shakescape_hns_htlc_watch_set(&descriptors, now_unix)
            .map_err(MobileWalletError::DirectHns)
    }

    /// Advance a locally-owned first-chain funding gate after the counterparty
    /// has signed and installed the exact watch. This validates refund safety
    /// and local key ownership, but never constructs, signs, or broadcasts a
    /// funding transaction. Native UI still requires an explicit approval for
    /// the irreversible chain action.
    pub fn advance_local_first_funding_readiness(
        &mut self,
        now_unix: u64,
    ) -> Result<usize, MobileWalletError> {
        if now_unix == 0 {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let candidates = self
            .store
            .try_with_store(|store| {
                let mut candidates = Vec::new();
                for execution in list_shakescape_executions(store, &self.policy)? {
                    if !matches!(
                        execution.state,
                        SwapState::TermsFrozen | SwapState::RefundsPrepared
                    ) {
                        continue;
                    }
                    let Some(record) =
                        load_shakescape_direct_swap(store, &self.policy, execution.id)?
                    else {
                        return Err(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap);
                    };
                    let Some(hello) = record.hello else {
                        return Err(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap);
                    };
                    if record.first_chain_watch_ready.is_some() {
                        candidates.push((execution.id, hello.offered_asset));
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(candidates)
            })
            .map_err(MobileWalletError::from)?;
        let mut advanced = 0usize;
        for (session_id, offered_asset) in candidates {
            let authorized = match offered_asset {
                AssetId::BTC => self
                    .authorize_local_btc_first_funding(session_id, now_unix)
                    .is_ok(),
                AssetId::HNS => self
                    .authorize_local_hns_first_funding(session_id, now_unix)
                    .is_ok(),
                _ => false,
            };
            if authorized {
                advanced = advanced.saturating_add(1);
            }
        }
        Ok(advanced)
    }

    /// Reconcile terminal pre-funding state and the public listing lifecycle.
    ///
    /// Only executions which provably never crossed a chain-specific funding
    /// authorization gate are failed by time. Later states may have an
    /// unobserved broadcast and are deliberately never expired from wall-clock
    /// time alone. Independently, a single-session public offer is retired as
    /// soon as its hello is countersigned, or when its maker proposal expires
    /// without a hello. The signed cancellation tombstone is then propagated
    /// by ordinary inventory reconciliation; anonymous peers never need an
    /// out-of-band cleanup conversation.
    pub fn reconcile_direct_offer_lifecycle(
        &mut self,
        now_unix: u64,
    ) -> Result<usize, MobileWalletError> {
        if now_unix == 0 {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                // Older clients admitted the countersigned hello but did not
                // open the maker's execution workflow. Once the maker retires
                // the consumed public offer, a stateless rendezvous cannot
                // reconstruct that route to redeliver the hello. Recover the
                // workflow directly from the already-authenticated durable
                // record before applying ordinary timeout and listing cleanup.
                let mut recovered = 0usize;
                for record in load_shakescape_direct_swaps(store, &policy)? {
                    let session_id = hns_wallet_types::SessionId::new(record.take.swap_session_id);
                    if record.hello.is_some()
                        && load_shakescape_execution(store, &policy, session_id)?.is_none()
                    {
                        open_shakescape_execution(store, &policy, session_id, now_unix)?;
                        recovered = recovered.saturating_add(1);
                    }
                }
                let mut expired = Vec::new();
                for execution in list_shakescape_executions(store, &policy)? {
                    let expired_second_funder = execution.state == SwapState::FirstFundingPending
                        && execution.first_funding.is_none()
                        && is_local_shakescape_direct_taker(store, self.wallet_id, execution.id)?;
                    if !matches!(
                        execution.state,
                        SwapState::TermsFrozen | SwapState::RefundsPrepared
                    ) && !expired_second_funder
                    {
                        continue;
                    }
                    let record = load_shakescape_direct_swap(store, &policy, execution.id)?
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    let hello = record
                        .hello
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    if now_unix > hello.header.expires_at {
                        expired.push(execution.id);
                    }
                }
                for session_id in &expired {
                    let mut execution =
                        open_shakescape_execution(store, &policy, *session_id, now_unix)?;
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: shakescape_execution_workflow_id(*session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(
                        VerifiedEvidence::TerminalFailure {
                            reason: "funding deadline expired before first-chain authorization"
                                .to_owned(),
                        },
                        now_unix,
                        &mut journal,
                    )?;
                }
                let mut retired_offers = 0usize;
                let active_offers = list_local_shakescape_direct_offers(
                    store,
                    &policy.board_policy(),
                    self.wallet_id,
                    now_unix,
                )?;
                for offer in active_offers {
                    let Some(record) =
                        load_shakescape_direct_swap(store, &policy, offer.session_id)?
                    else {
                        continue;
                    };
                    let negotiation_expired = record.hello.is_none()
                        && (now_unix >= record.take.header.expires_at
                            || record.proposal.as_ref().is_some_and(|proposal| {
                                now_unix >= proposal.terms().header.expires_at
                            }));
                    if record.hello.is_some() || negotiation_expired {
                        cancel_shakescape_local_direct_offer(
                            store,
                            &policy.board_policy(),
                            self.wallet_id,
                            offer.offer.offer_id.into_bytes(),
                            now_unix,
                        )?;
                        retired_offers = retired_offers.saturating_add(1);
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(
                    recovered
                        .saturating_add(expired.len())
                        .saturating_add(retired_offers),
                )
            })
            .map_err(MobileWalletError::from)
    }

    /// Enumerate expired local-maker Bitcoin-first sessions which require an
    /// independent Kyoto absence proof before their reservation can be freed.
    pub fn expired_local_bitcoin_first_funding_permits(
        &self,
        now_unix: u64,
    ) -> Result<Vec<MobileShakescapeBitcoinAbsencePermit>, MobileWalletError> {
        if now_unix == 0 {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let policy = self.policy;
        self.store
            .try_with_store(|store| {
                let mut candidates = Vec::new();
                for execution in list_shakescape_executions(store, &policy)? {
                    if execution.state != SwapState::FirstFundingPending
                        || execution.first_funding.is_some()
                        || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                        || !is_local_shakescape_direct_maker(
                            store,
                            &policy,
                            self.wallet_id,
                            execution.id,
                        )?
                    {
                        continue;
                    }
                    let record = load_shakescape_direct_swap(store, &policy, execution.id)?
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    let hello = record
                        .hello
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    if hello.offered_asset == AssetId::BTC && now_unix > hello.header.expires_at {
                        candidates.push(MobileShakescapeBitcoinAbsencePermit {
                            hello,
                            side: SwapAssetSide::Offered,
                        });
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(candidates)
            })
            .map_err(MobileWalletError::from)
    }

    /// Release one expired local-maker reservation only after the Bitcoin
    /// controller proves the exact signed lock is absent from both its current
    /// chain view and durable broadcast journal.
    pub fn fail_expired_local_bitcoin_first_funding(
        &mut self,
        proof: MobileShakescapeUnfundedBitcoinProof,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                let execution = load_shakescape_execution(store, &policy, proof.session_id)?
                    .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                let record = load_shakescape_direct_swap(store, &policy, proof.session_id)?
                    .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                let binding = build_shakescape_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let expected_terms = BitcoinHtlcWatchRequest {
                    session_id: proof.session_id,
                    htlc: binding.htlc,
                    expected_value_sats: binding.value_sats,
                    minimum_confirmations: hello.offered_minimum_confirmations,
                }
                .terms_commitment()
                .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if execution.state != SwapState::FirstFundingPending
                    || execution.first_funding.is_some()
                    || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                    || hello.offered_asset != AssetId::BTC
                    || now_unix <= hello.header.expires_at
                    || expected_terms != proof.terms_commitment
                    || !is_local_shakescape_direct_maker(
                        store,
                        &policy,
                        self.wallet_id,
                        proof.session_id,
                    )?
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let mut execution =
                    open_shakescape_execution(store, &policy, proof.session_id, now_unix)?;
                let mut journal = WalletStoreJournal {
                    store,
                    workflow_id: shakescape_execution_workflow_id(proof.session_id),
                    updated_at_unix: now_unix,
                };
                execution.apply(
                    VerifiedEvidence::TerminalFailure {
                        reason: "funding deadline expired with verified absence of a Bitcoin lock"
                            .to_owned(),
                    },
                    now_unix,
                    &mut journal,
                )?;
                Ok::<_, hns_wallet_market::MarketError>(())
            })
            .map_err(MobileWalletError::from)
    }

    /// Return only local accepted offers that still reserve funds but have not
    /// reached countersigned terms. These may be safely abandoned by the user.
    pub fn pending_direct_offer_takes(
        &self,
        now_unix: u64,
    ) -> Result<Vec<MobileDirectOfferTakeSummary>, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                list_pending_local_shakescape_direct_takes(
                    store,
                    &self.policy,
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?
            .into_iter()
            .map(direct_take_summary)
            .collect()
    }

    /// Durably abandon one pre-execution acceptance and release its reserved
    /// funds. Terms-frozen/funded swaps are rejected by the market layer.
    pub fn abandon_pending_direct_offer_take(
        &mut self,
        session_id: &str,
        now_unix: u64,
    ) -> Result<MobileDirectOfferTakeSummary, MobileWalletError> {
        let session_id = hns_wallet_types::SessionId::new(decode_offer_id(session_id)?);
        self.store
            .try_with_store_mut(|store| {
                abandon_pending_local_shakescape_direct_take(
                    store,
                    &self.policy,
                    self.wallet_id,
                    session_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)
            .and_then(direct_take_summary)
    }

    /// Identify exact sessions whose first-chain Bitcoin lock still needs
    /// locally verified confirmation. The platform may use this closed set to
    /// query Kyoto after a sync, then feed only checkpoint-bound locks through
    /// `apply_local_verified_bitcoin_funding`.
    pub fn pending_first_bitcoin_funding_sessions(
        &self,
    ) -> Result<Vec<hns_wallet_types::SessionId>, MobileWalletError> {
        self.store
            .try_with_store(|store| list_shakescape_executions(store, &self.policy))
            .map_err(MobileWalletError::from)
            .map(|sessions| {
                sessions
                    .into_iter()
                    .filter(|session| {
                        (session.state == SwapState::FirstFundingPending
                            && session.first_module == hns_wallet_types::ModuleId::Bitcoin)
                            || (session.state == SwapState::SecondFundingPending
                                && session.second_module == hns_wallet_types::ModuleId::Bitcoin)
                    })
                    .map(|session| session.id)
                    .collect()
            })
    }

    /// Return one accepted local-taker session whose first-chain Bitcoin watch
    /// has not yet been durably acknowledged. The caller installs the watch
    /// under the independent Bitcoin controller before completing the permit.
    pub fn next_counterparty_bitcoin_watch(
        &mut self,
        now_unix: u64,
    ) -> Result<Option<MobileShakescapeBitcoinWatchPermit>, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        let candidates = self
            .store
            .try_with_store(|store| {
                let takes = list_local_shakescape_direct_takes(store, &policy, wallet_id)?;
                let mut sessions = Vec::new();
                for take in takes {
                    let record = load_shakescape_direct_swap(store, &policy, take.session_id)?;
                    let execution = hns_wallet_market::load_shakescape_execution(
                        store,
                        &policy,
                        take.session_id,
                    )?;
                    if record.is_some_and(|record| {
                        record.hello.is_some() && record.first_chain_watch_ready.is_none()
                    }) && execution.is_some_and(|execution| {
                        matches!(
                            execution.state,
                            SwapState::TermsFrozen | SwapState::RefundsPrepared
                        )
                    }) {
                        sessions.push(take.session_id);
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(sessions)
            })
            .map_err(MobileWalletError::from)?;
        for session_id in candidates {
            if let Ok(permit) = self.authorize_counterparty_bitcoin_watch(session_id, now_unix) {
                return Ok(Some(permit));
            }
        }
        Ok(None)
    }

    /// Return one local BTC-paying taker session whose first-chain HNS lock
    /// has not yet been acknowledged. HNS evidence can be fetched and fully
    /// verified by transaction id after broadcast, so this preparation only
    /// validates and durably binds the exact descriptor before acknowledgement.
    pub fn next_counterparty_hns_watch(
        &mut self,
        now_unix: u64,
    ) -> Result<Option<MobileShakescapeHnsWatchPermit>, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        let candidate = self
            .store
            .try_with_store(|store| {
                for take in list_local_shakescape_direct_takes(store, &policy, wallet_id)? {
                    let Some(record) =
                        load_shakescape_direct_swap(store, &policy, take.session_id)?
                    else {
                        continue;
                    };
                    let Some(hello) = record.hello else { continue };
                    if record.first_chain_watch_ready.is_none()
                        && hello.offered_asset == AssetId::HNS
                        && hello.received_asset == AssetId::BTC
                    {
                        return Ok(Some((take.session_id, hello)));
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(None)
            })
            .map_err(MobileWalletError::from)?;
        let Some((session_id, hello)) = candidate else {
            return Ok(None);
        };
        hello
            .verify_new_funding_at(policy.network(), now_unix)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let settlement_key = self
            .store
            .try_with_store(|store| {
                hns_wallet_market::derive_local_direct_taker_key(
                    store, &policy, wallet_id, session_id,
                )
                .map(|(key, _)| key)
            })
            .map_err(MobileWalletError::from)?;
        let hns = hello
            .build_hns_htlc(
                SwapAssetSide::Offered,
                hello.taker_settlement_public_key,
                hello.maker_settlement_public_key,
            )
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        if hns.descriptor_hash != hello.offered_lock_commitment
            || hns.descriptor.receiver_public_key != settlement_key.public_key()
        {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        Ok(Some(MobileShakescapeHnsWatchPermit {
            hello,
            settlement_key,
        }))
    }

    pub fn complete_counterparty_hns_watch(
        &mut self,
        permit: MobileShakescapeHnsWatchPermit,
        peer: &mut HnsDirectShakescapePeer,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let hello = permit.hello;
        let mut ready = hns_marketplace_protocol::SwapWatchReady {
            header: hns_marketplace_protocol::SignedObjectHeader {
                version: hello.header.version,
                network: hello.header.network,
                pair: hello.header.pair,
                signer_public_key: [0; 33],
                sequence: hello
                    .header
                    .sequence
                    .checked_add(1)
                    .ok_or(MobileWalletError::InvalidShakescapeSessionMessage)?,
                created_at: now_unix,
                expires_at: hello.header.expires_at,
            },
            swap_session_id: hello.swap_session_id,
            chain: hns_marketplace_protocol::ChainId::HANDSHAKE,
            lock_commitment: hello.offered_lock_commitment,
            minimum_confirmations: hello.offered_minimum_confirmations,
            signature: [0; 64],
        };
        permit
            .settlement_key
            .sign_watch_ready(&mut ready, &hello, now_unix)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let message = CrossChainMessage::SwapWatchReady(ready);
        let envelope = message
            .encode_envelope(0)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        self.store
            .try_with_store_mut(|store| {
                admit_shakescape_direct_swap_watch_ready(store, &self.policy, &envelope, now_unix)
            })
            .map_err(MobileWalletError::from)?;
        peer.send_cross_chain_message(&message)?;
        Ok(())
    }

    pub fn pending_second_hns_funding_verifications(
        &self,
    ) -> Result<Vec<MobileShakescapeHnsVerificationPermit>, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let permits = list_shakescape_executions(store, &policy)?
                    .into_iter()
                    .filter(|session| {
                        (session.state == SwapState::FirstFundingPending
                            && session.first_module == hns_wallet_types::ModuleId::Handshake)
                            // The counterparty does not execute the local
                            // second-funding authorization that advances this
                            // checkpoint.  Its independently verified HNS
                            // locator must be allowed to cross FirstFunded ->
                            // SecondFundingPending -> BothFunded atomically.
                            || (session.state == SwapState::FirstFunded
                                && session.second_module
                                    == hns_wallet_types::ModuleId::Handshake)
                            || (session.state == SwapState::SecondFundingPending
                                && session.second_module == hns_wallet_types::ModuleId::Handshake)
                            // A previous binary may have verified the local
                            // lock before it durably retained a replayable
                            // funding locator. Re-read the same exact lock in
                            // BothFunded so idempotent application can repair
                            // that coordination record after an upgrade.
                            || (session.state == SwapState::BothFunded
                                && (session.first_module
                                    == hns_wallet_types::ModuleId::Handshake
                                    || session.second_module
                                        == hns_wallet_types::ModuleId::Handshake))
                    })
                    .map(|session| {
                        load_shakescape_direct_swap(store, &policy, session.id)?
                            .and_then(|record| {
                                record.hello.clone().map(|hello| {
                                    let side = if hello.offered_asset == AssetId::HNS {
                                        SwapAssetSide::Offered
                                    } else {
                                        SwapAssetSide::Received
                                    };
                                    let funding_transaction = record
                                        .peer_funding_statuses
                                        .iter()
                                        .find(|status| {
                                            status.status.chain
                                                == hns_marketplace_protocol::ChainId::HANDSHAKE
                                        })
                                        .map(|status| {
                                            TransactionHash::new(status.status.transaction_id)
                                        });
                                    let local_maker =
                                        hns_wallet_market::is_local_shakescape_direct_maker(
                                            store, &policy, wallet_id, session.id,
                                        )?;
                                    let local_taker =
                                        hns_wallet_market::is_local_shakescape_direct_taker(
                                            store, wallet_id, session.id,
                                        )?;
                                    if local_maker == local_taker {
                                        return Err(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap);
                                    }
                                    let local_hns_funder = (local_maker
                                        && hello.offered_asset == AssetId::HNS)
                                        || (local_taker && hello.received_asset == AssetId::HNS);
                                    // A remote HNS lock has no trustworthy lookup
                                    // key until its funder supplies an authenticated
                                    // locator. Falling back to this wallet's local
                                    // persisted-workflow lookup before that point is
                                    // both pointless and noisy: no such local
                                    // workflow should exist. A local HNS funder may
                                    // still use the locator-free path to recover an
                                    // already-broadcast workflow after restart.
                                    if !local_hns_funder && funding_transaction.is_none() {
                                        return Ok(None);
                                    }
                                    Ok(Some(MobileShakescapeHnsVerificationPermit {
                                        hello,
                                        side,
                                        funding_transaction,
                                    }))
                                })
                            })
                            .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?
                    })
                    .collect::<Result<Vec<_>, hns_wallet_market::MarketError>>()?;
                Ok::<_, hns_wallet_market::MarketError>(permits.into_iter().flatten().collect())
            })
            .map_err(MobileWalletError::from)
    }

    pub fn pending_hns_spend_verifications(
        &self,
    ) -> Result<Vec<MobileShakescapeHnsVerificationPermit>, MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store(|store| {
                list_shakescape_executions(store, &policy)?
                    .into_iter()
                    .filter(|session| {
                        (session.first_module == hns_wallet_types::ModuleId::Handshake
                            || session.second_module == hns_wallet_types::ModuleId::Handshake)
                            && matches!(
                                session.state,
                                SwapState::BothFunded
                                    | SwapState::FirstRedeemed
                                    | SwapState::SecretObserved
                                    | SwapState::RefundEligible
                                    | SwapState::RefundBroadcast
                            )
                    })
                    .map(|session| {
                        load_shakescape_direct_swap(store, &policy, session.id)?
                            .and_then(|record| {
                                record.hello.clone().map(|hello| {
                                    let side = if hello.offered_asset == AssetId::HNS {
                                        SwapAssetSide::Offered
                                    } else {
                                        SwapAssetSide::Received
                                    };
                                    let funding_transaction = record
                                        .peer_funding_statuses
                                        .iter()
                                        .find(|status| {
                                            status.status.chain
                                                == hns_marketplace_protocol::ChainId::HANDSHAKE
                                        })
                                        .map(|status| {
                                            TransactionHash::new(status.status.transaction_id)
                                        });
                                    MobileShakescapeHnsVerificationPermit {
                                        hello,
                                        side,
                                        funding_transaction,
                                    }
                                })
                            })
                            .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileWalletError::from)
    }

    pub fn pending_bitcoin_spend_sessions(
        &self,
    ) -> Result<Vec<hns_wallet_types::SessionId>, MobileWalletError> {
        self.store
            .try_with_store(|store| list_shakescape_executions(store, &self.policy))
            .map_err(MobileWalletError::from)
            .map(|sessions| {
                sessions
                    .into_iter()
                    .filter(|session| {
                        (session.first_module == hns_wallet_types::ModuleId::Bitcoin
                            || session.second_module == hns_wallet_types::ModuleId::Bitcoin)
                            && matches!(
                                session.state,
                                SwapState::SecretObserved
                                    | SwapState::RefundEligible
                                    | SwapState::RefundBroadcast
                            )
                    })
                    .map(|session| session.id)
                    .collect()
            })
    }

    pub fn cancel_local_btc_for_hns_offer(
        &mut self,
        offer_id: &str,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let offer_id = decode_offer_id(offer_id)?;
        self.store
            .try_with_store_mut(|store| {
                cancel_shakescape_local_direct_offer(
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

    /// Validate both canonical HTLC refund branches and prove this wallet owns
    /// the BTC refund key before allowing first-chain funding preparation.
    /// The durable execution advances through restart-safe checkpoints to
    /// `FirstFundingPending`; retries resume at either checkpoint and return
    /// the same immutable context.
    pub fn authorize_local_btc_first_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileShakescapeBitcoinFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .clone()
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                hello
                    .verify_new_funding_at(policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hello.offered_asset != hns_marketplace_protocol::AssetId::BTC
                    || hello.received_asset != hns_marketplace_protocol::AssetId::HNS
                    || hello.first_funding_chain != hns_marketplace_protocol::ChainId::BITCOIN
                    || hello.swap_session_id != session_id.into_bytes()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let ready = record
                    .first_chain_watch_ready
                    .as_ref()
                    .ok_or(hns_wallet_market::MarketError::InvalidTransition)?;
                ready
                    .verify_for_session(&hello, policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let (maker_key, bitcoin_fee_reserve_sats) =
                    hns_wallet_market::derive_local_btc_for_hns_maker_key(
                        store, &policy, wallet_id, session_id,
                    )?;
                let bitcoin = build_shakescape_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if bitcoin.commitment.into_bytes() != hello.offered_lock_commitment
                    || bitcoin.htlc.refund_public_key != maker_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let mut execution =
                    open_shakescape_execution(store, &policy, session_id, now_unix)?;
                if execution.state == SwapState::TermsFrozen {
                    let workflow_id = shakescape_execution_workflow_id(session_id);
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id,
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::RefundsValidated, now_unix, &mut journal)?;
                }
                if execution.state == SwapState::RefundsPrepared {
                    let workflow_id = shakescape_execution_workflow_id(session_id);
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id,
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::FundingReady, now_unix, &mut journal)?;
                }
                if execution.state != SwapState::FirstFundingPending {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                Ok(MobileShakescapeBitcoinFundingPermit {
                    hello,
                    side: SwapAssetSide::Offered,
                    bitcoin_fee_reserve_sats,
                })
            })
            .map_err(MobileWalletError::from)
    }

    /// Authorize a BTC-paying taker's second-chain lock after the HNS maker's
    /// first-chain lock is independently confirmed.
    pub fn authorize_local_btc_second_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileShakescapeBitcoinFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let mut execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                if execution.state != SwapState::FirstFunded
                    || execution.first_module != hns_wallet_types::ModuleId::Handshake
                    || execution.second_module != hns_wallet_types::ModuleId::Bitcoin
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                hello
                    .verify_agreement(policy.network())
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hello.offered_asset != AssetId::HNS || hello.received_asset != AssetId::BTC {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let (settlement_key, bitcoin_fee_reserve_sats) =
                    hns_wallet_market::derive_local_direct_taker_key(
                        store, &policy, wallet_id, session_id,
                    )?;
                let bitcoin = build_shakescape_bitcoin_htlc(&hello, SwapAssetSide::Received)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if bitcoin.commitment.into_bytes() != hello.received_lock_commitment
                    || bitcoin.htlc.refund_public_key != settlement_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let mut journal = WalletStoreJournal {
                    store,
                    workflow_id: shakescape_execution_workflow_id(session_id),
                    updated_at_unix: now_unix,
                };
                execution.apply(VerifiedEvidence::SecondFundingReady, now_unix, &mut journal)?;
                Ok(MobileShakescapeBitcoinFundingPermit {
                    hello,
                    side: SwapAssetSide::Received,
                    bitcoin_fee_reserve_sats,
                })
            })
            .map_err(MobileWalletError::from)
    }

    /// Prepare the HNS-offering taker's independent Bitcoin watch before the
    /// maker may safely broadcast. This validates the taker's own HNS refund
    /// branch and advances the same durable pre-funding gates without granting
    /// any authority to spend the maker's Bitcoin.
    pub fn authorize_counterparty_bitcoin_watch(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileShakescapeBitcoinWatchPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                hello
                    .verify_new_funding_at(policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hello.offered_asset != hns_marketplace_protocol::AssetId::BTC
                    || hello.received_asset != hns_marketplace_protocol::AssetId::HNS
                    || hello.first_funding_chain != hns_marketplace_protocol::ChainId::BITCOIN
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let (taker_key, _) = hns_wallet_market::derive_local_hns_for_btc_taker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let bitcoin = build_shakescape_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if bitcoin.commitment.into_bytes() != hello.offered_lock_commitment {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment
                    || hns.descriptor.refund_public_key != taker_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let execution = open_shakescape_execution(store, &policy, session_id, now_unix)?;
                if !matches!(
                    execution.state,
                    SwapState::TermsFrozen
                        | SwapState::RefundsPrepared
                        | SwapState::FirstFundingPending
                ) {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                Ok(MobileShakescapeBitcoinWatchPermit {
                    hello,
                    side: SwapAssetSide::Offered,
                    settlement_key: taker_key,
                })
            })
            .map_err(MobileWalletError::from)
    }

    /// Complete the taker's local pre-funding gate only after Kyoto has
    /// durably installed the exact watch. The signed acknowledgement is sent
    /// to the maker and then admitted through the same canonical validator
    /// used for inbound peer traffic.
    pub fn complete_counterparty_bitcoin_watch(
        &mut self,
        permit: MobileShakescapeBitcoinWatchPermit,
        peer: &mut HnsDirectShakescapePeer,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let message = self.confirm_counterparty_bitcoin_watch(permit, now_unix)?;
        peer.send_cross_chain_message(&message)?;
        Ok(())
    }

    /// Persist the locally installed watch and produce its canonical signed
    /// acknowledgement. Transport may retry this returned public message; no
    /// settlement secret or chain evidence is embedded in it.
    pub fn confirm_counterparty_bitcoin_watch(
        &mut self,
        permit: MobileShakescapeBitcoinWatchPermit,
        now_unix: u64,
    ) -> Result<CrossChainMessage, MobileWalletError> {
        let hello = permit.hello;
        let mut ready = hns_marketplace_protocol::SwapWatchReady {
            header: hns_marketplace_protocol::SignedObjectHeader {
                version: hello.header.version,
                network: hello.header.network,
                pair: hello.header.pair,
                signer_public_key: [0; 33],
                sequence: hello
                    .header
                    .sequence
                    .checked_add(1)
                    .ok_or(MobileWalletError::InvalidShakescapeSessionMessage)?,
                created_at: now_unix,
                expires_at: hello.header.expires_at,
            },
            swap_session_id: hello.swap_session_id,
            chain: hello.first_funding_chain,
            lock_commitment: hello.offered_lock_commitment,
            minimum_confirmations: hello.offered_minimum_confirmations,
            signature: [0; 64],
        };
        permit
            .settlement_key
            .sign_watch_ready(&mut ready, &hello, now_unix)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let message = CrossChainMessage::SwapWatchReady(ready);
        let envelope = message
            .encode_envelope(0)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let policy = self.policy;
        let session_id = hns_wallet_types::SessionId::new(hello.swap_session_id);
        self.store
            .try_with_store_mut(|store| {
                admit_shakescape_direct_swap_watch_ready(store, &policy, &envelope, now_unix)?;
                let mut execution =
                    open_shakescape_execution(store, &policy, session_id, now_unix)?;
                if execution.state == SwapState::TermsFrozen {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: shakescape_execution_workflow_id(session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::RefundsValidated, now_unix, &mut journal)?;
                }
                if execution.state == SwapState::RefundsPrepared {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: shakescape_execution_workflow_id(session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::FundingReady, now_unix, &mut journal)?;
                }
                if execution.state != SwapState::FirstFundingPending {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                Ok(())
            })
            .map_err(MobileWalletError::from)?;
        Ok(message)
    }

    /// Advance the atomic-swap journal only from the checkpoint-bound result
    /// returned by the local Kyoto watch. A broadcast receipt or peer status
    /// cannot satisfy this boundary.
    pub fn apply_local_verified_bitcoin_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        lock: hns_wallet_bitcoin_kyoto::VerifiedBitcoinLock,
        now_unix: u64,
    ) -> Result<SwapState, MobileWalletError> {
        self.retain_local_funding_status(
            session_id,
            hns_marketplace_protocol::ChainId::BITCOIN,
            *lock.funding_txid.as_bytes(),
            lock.output_index,
            lock.confirmation_count,
            FundingState::Confirmed,
            now_unix,
        )?;
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                hns_wallet_market::apply_locally_verified_shakescape_funding(
                    store,
                    &policy,
                    session_id,
                    hns_wallet_market::LocallyVerifiedSwapFunding::Bitcoin(lock),
                    now_unix,
                )
                .map(|session| session.state)
            })
            .map_err(MobileWalletError::from)
    }

    pub fn apply_local_verified_hns_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        lock: hns_wallet_chain_api::VerifiedLock,
        now_unix: u64,
    ) -> Result<SwapState, MobileWalletError> {
        self.retain_local_funding_status(
            session_id,
            hns_marketplace_protocol::ChainId::HANDSHAKE,
            *lock.funding_id.as_bytes(),
            // Native HNS HTLC construction always places the exact lock
            // before its optional change output.
            0,
            lock.confirmation_count,
            FundingState::Confirmed,
            now_unix,
        )?;
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                hns_wallet_market::apply_locally_verified_shakescape_funding(
                    store,
                    &policy,
                    session_id,
                    hns_wallet_market::LocallyVerifiedSwapFunding::Hns(lock),
                    now_unix,
                )
                .map(|session| session.state)
            })
            .map_err(MobileWalletError::from)
    }

    /// Announce a locally broadcast funding transaction as a signed locator.
    /// The peer must still retrieve the transaction and prove its exact HTLC,
    /// inclusion, and confirmation count through its own chain backend.
    pub fn announce_local_funding(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        session_id: hns_wallet_types::SessionId,
        transaction_id: [u8; 32],
        output_index: u32,
        now_unix: u64,
    ) -> Result<(), MobileWalletError> {
        let Some(envelope) = self.retain_local_funding_status(
            session_id,
            self.local_funding_chain(session_id)?,
            transaction_id,
            output_index,
            0,
            FundingState::Broadcast,
            now_unix,
        )?
        else {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        };
        peer.send_cross_chain_envelope(&envelope)?;
        Ok(())
    }

    fn local_funding_chain(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<hns_marketplace_protocol::ChainId, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        let (hello, settlement_key) = self
            .store
            .try_with_store(|store| {
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let settlement_key = hns_wallet_market::derive_local_direct_maker_key(
                    store, &policy, wallet_id, session_id,
                )
                .or_else(|_| {
                    hns_wallet_market::derive_local_direct_taker_key(
                        store, &policy, wallet_id, session_id,
                    )
                })?
                .0;
                Ok::<_, hns_wallet_market::MarketError>((hello, settlement_key))
            })
            .map_err(MobileWalletError::from)?;
        if settlement_key.public_key() == hello.maker_settlement_public_key {
            Ok(hello.offered_asset.chain())
        } else if settlement_key.public_key() == hello.taker_settlement_public_key {
            Ok(hello.received_asset.chain())
        } else {
            Err(MobileWalletError::InvalidShakescapeSessionMessage)
        }
    }

    /// Sign and durably retain one local funding locator before attempting
    /// delivery.  Retention makes reconnect replay exact and also lets a
    /// post-confirmation scan recover a locator whose one-shot broadcast
    /// announcement failed.  A locally verified counterparty lock is not
    /// re-signed: only the participant that funds this chain may create it.
    fn retain_local_funding_status(
        &self,
        session_id: hns_wallet_types::SessionId,
        chain: hns_marketplace_protocol::ChainId,
        transaction_id: [u8; 32],
        output_index: u32,
        confirmations: u32,
        state: FundingState,
        now_unix: u64,
    ) -> Result<Option<Vec<u8>>, MobileWalletError> {
        if transaction_id == [0; 32]
            || now_unix == 0
            || (state == FundingState::Confirmed) != (confirmations > 0)
        {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        let (hello, settlement_key, retained_statuses) = self
            .store
            .try_with_store(|store| {
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let settlement_key = hns_wallet_market::derive_local_direct_maker_key(
                    store, &policy, wallet_id, session_id,
                )
                .or_else(|_| {
                    hns_wallet_market::derive_local_direct_taker_key(
                        store, &policy, wallet_id, session_id,
                    )
                })?
                .0;
                Ok::<_, hns_wallet_market::MarketError>((
                    hello,
                    settlement_key,
                    record.peer_funding_statuses,
                ))
            })
            .map_err(MobileWalletError::from)?;
        let local_chain = if settlement_key.public_key() == hello.maker_settlement_public_key {
            hello.offered_asset.chain()
        } else if settlement_key.public_key() == hello.taker_settlement_public_key {
            hello.received_asset.chain()
        } else {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        };
        if chain != local_chain {
            return Ok(None);
        }
        let existing = retained_statuses
            .iter()
            .find(|retained| retained.status.chain == chain);
        if let Some(existing) = existing
            && existing.status.transaction_id == transaction_id
            && existing.status.output_index == output_index
            && existing.status.state == state
            && existing.status.confirmations >= confirmations
            && existing.status.header.expires_at > now_unix
        {
            return CrossChainMessage::SwapFundingStatus(existing.status.clone())
                .encode_envelope(0)
                .map(Some)
                .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let (amount, lock_commitment) = if chain == hello.offered_asset.chain() {
            (hello.offered_amount, hello.offered_lock_commitment)
        } else {
            (hello.received_amount, hello.received_lock_commitment)
        };
        let state_sequence_offset: u64 = match state {
            FundingState::Broadcast => 2,
            FundingState::Seen => 3,
            FundingState::Confirmed => 4,
            FundingState::Reorged => 5,
        };
        let replay_expires_at = now_unix
            .checked_add(FUNDING_STATUS_REPLAY_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidShakescapeSessionMessage)?;
        let sequence = hello
            .header
            .sequence
            .checked_add(state_sequence_offset)
            .ok_or(MobileWalletError::InvalidShakescapeSessionMessage)?
            .max(now_unix)
            .max(
                existing
                    .map(|retained| retained.status.header.sequence.saturating_add(1))
                    .unwrap_or(0),
            );
        let mut status = SwapFundingStatus {
            header: SignedObjectHeader {
                version: hello.header.version,
                network: hello.header.network,
                pair: hello.header.pair,
                signer_public_key: [0; 33],
                sequence,
                created_at: now_unix,
                expires_at: replay_expires_at
                    .max(hello.header.expires_at)
                    .max(hello.offered_refund_deadline.value)
                    .max(hello.received_refund_deadline.value),
            },
            swap_session_id: hello.swap_session_id,
            chain,
            lock_commitment,
            transaction_id,
            output_index,
            amount,
            confirmations,
            state,
            signature: [0; 64],
        };
        settlement_key
            .sign_funding_status(&mut status, &hello, now_unix)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let envelope = CrossChainMessage::SwapFundingStatus(status)
            .encode_envelope(0)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        self.store
            .try_with_store_mut(|store| {
                admit_shakescape_direct_swap_peer_status(store, &policy, &envelope, now_unix)
            })
            .map_err(MobileWalletError::from)?;
        Ok(Some(envelope))
    }

    pub fn apply_local_verified_hns_spend(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        spend: hns_wallet_hns::VerifiedNativeHtlcSpend,
        now_unix: u64,
    ) -> Result<SwapState, MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                let refund = matches!(
                    spend,
                    hns_wallet_hns::VerifiedNativeHtlcSpend::Refund { .. }
                );
                if refund {
                    hns_wallet_market::apply_locally_verified_shakescape_refund(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Hns(spend),
                        now_unix,
                    )
                } else if hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                    .is_some_and(|execution| {
                        execution.second_module == hns_wallet_types::ModuleId::Handshake
                    })
                {
                    hns_wallet_market::apply_locally_verified_shakescape_first_redemption(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Hns(spend),
                        now_unix,
                    )
                } else {
                    hns_wallet_market::apply_locally_verified_shakescape_second_redemption(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Hns(spend),
                        now_unix,
                    )
                }
                .map(|session| session.state)
            })
            .map_err(MobileWalletError::from)
    }

    pub fn apply_local_verified_bitcoin_spend(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        spend: hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpendObservation,
        now_unix: u64,
    ) -> Result<SwapState, MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                let refund =
                    spend.spend.branch == hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Refund;
                if refund {
                    hns_wallet_market::apply_locally_verified_shakescape_refund(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Bitcoin(spend),
                        now_unix,
                    )
                } else if hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                    .is_some_and(|execution| {
                        execution.second_module == hns_wallet_types::ModuleId::Bitcoin
                    })
                {
                    hns_wallet_market::apply_locally_verified_shakescape_first_redemption(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Bitcoin(spend),
                        now_unix,
                    )
                } else {
                    hns_wallet_market::apply_locally_verified_shakescape_second_redemption(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Bitcoin(spend),
                        now_unix,
                    )
                }
                .map(|session| session.state)
            })
            .map_err(MobileWalletError::from)
    }

    /// Authorize the taker's second-chain HNS lock only after the maker's
    /// Bitcoin lock has been independently confirmed and durably journaled.
    pub fn authorize_local_hns_second_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileShakescapeHnsFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                if execution.state != SwapState::FirstFunded
                    || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                    || execution.second_module != hns_wallet_types::ModuleId::Handshake
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                hello
                    .verify_agreement(policy.network())
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let (settlement_key, hns_fee_reserve_dollarydoos) =
                    hns_wallet_market::derive_local_hns_for_btc_taker_key(
                        store, &policy, wallet_id, session_id,
                    )?;
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment
                    || hns.descriptor.refund_public_key != settlement_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let workflow_id = shakescape_execution_workflow_id(session_id);
                let mut execution = execution;
                let mut journal = WalletStoreJournal {
                    store,
                    workflow_id,
                    updated_at_unix: now_unix,
                };
                execution.apply(VerifiedEvidence::SecondFundingReady, now_unix, &mut journal)?;
                Ok(MobileShakescapeHnsFundingPermit {
                    hello,
                    side: SwapAssetSide::Received,
                    settlement_key,
                    hns_fee_reserve_dollarydoos,
                })
            })
            .map_err(MobileWalletError::from)
    }

    /// Authorize an HNS-selling maker's first-chain lock after the BTC taker
    /// has acknowledged the exact first-chain watch.
    pub fn authorize_local_hns_first_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileShakescapeHnsFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .clone()
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                hello
                    .verify_new_funding_at(policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hello.offered_asset != AssetId::HNS || hello.received_asset != AssetId::BTC {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let ready = record
                    .first_chain_watch_ready
                    .as_ref()
                    .ok_or(hns_wallet_market::MarketError::InvalidTransition)?;
                ready
                    .verify_for_session(&hello, policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let (settlement_key, hns_fee_reserve_dollarydoos) =
                    hns_wallet_market::derive_local_direct_maker_key(
                        store, &policy, wallet_id, session_id,
                    )?;
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Offered,
                        hello.taker_settlement_public_key,
                        hello.maker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor_hash != hello.offered_lock_commitment
                    || hns.descriptor.refund_public_key != settlement_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                let mut execution =
                    open_shakescape_execution(store, &policy, session_id, now_unix)?;
                if execution.state == SwapState::TermsFrozen {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: shakescape_execution_workflow_id(session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::RefundsValidated, now_unix, &mut journal)?;
                }
                if execution.state == SwapState::RefundsPrepared {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: shakescape_execution_workflow_id(session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::FundingReady, now_unix, &mut journal)?;
                }
                if execution.state != SwapState::FirstFundingPending {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                Ok(MobileShakescapeHnsFundingPermit {
                    hello,
                    side: SwapAssetSide::Offered,
                    settlement_key,
                    hns_fee_reserve_dollarydoos,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_hns_redeem(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileShakescapeHnsSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let funding_transaction = record
                    .peer_funding_statuses
                    .iter()
                    .find(|status| {
                        status.status.chain == hns_marketplace_protocol::ChainId::HANDSHAKE
                    })
                    .map(|status| TransactionHash::new(status.status.transaction_id))
                    .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let side = if hello.offered_asset == AssetId::HNS {
                    SwapAssetSide::Offered
                } else if hello.received_asset == AssetId::HNS {
                    SwapAssetSide::Received
                } else {
                    return Err(hns_wallet_market::MarketError::InvalidPair);
                };
                let (key, preimage) = match side {
                    SwapAssetSide::Offered => {
                        if execution.state != SwapState::SecretObserved
                            || execution.first_module != hns_wallet_types::ModuleId::Handshake
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        let (key, _) = hns_wallet_market::derive_local_direct_taker_key(
                            store, &policy, wallet_id, session_id,
                        )?;
                        let preimage =
                            hns_wallet_market::load_locally_verified_shakescape_preimage(
                                store, session_id,
                            )?
                            .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                        (key, preimage)
                    }
                    SwapAssetSide::Received => {
                        if execution.state != SwapState::BothFunded
                            || execution.second_module != hns_wallet_types::ModuleId::Handshake
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        let (key, _) = hns_wallet_market::derive_local_direct_maker_key(
                            store, &policy, wallet_id, session_id,
                        )?;
                        let preimage = hns_wallet_market::load_shakescape_direct_maker_preimage(
                            store, session_id,
                        )?
                        .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                        (key, preimage)
                    }
                };
                let hns = hello
                    .build_hns_htlc(
                        side,
                        match side {
                            SwapAssetSide::Offered => hello.taker_settlement_public_key,
                            SwapAssetSide::Received => hello.maker_settlement_public_key,
                        },
                        match side {
                            SwapAssetSide::Offered => hello.maker_settlement_public_key,
                            SwapAssetSide::Received => hello.taker_settlement_public_key,
                        },
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor.receiver_public_key != key.public_key()
                    || hns.descriptor.hashlock
                        != hns_swap::HnsHtlc::hash_preimage(preimage.expose_for_settlement())
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                Ok(MobileShakescapeHnsSettlementPermit {
                    hello,
                    side,
                    funding_transaction: Some(funding_transaction),
                    settlement_key: key,
                    preimage: Some(preimage),
                    action: MobileShakescapeSettlementAction::Redeem,
                    fee_reserve: u64::MAX,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_hns_refund(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileShakescapeHnsSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let side = if hello.offered_asset == AssetId::HNS {
                    SwapAssetSide::Offered
                } else if hello.received_asset == AssetId::HNS {
                    SwapAssetSide::Received
                } else {
                    return Err(hns_wallet_market::MarketError::InvalidPair);
                };
                let hns_module_is_first =
                    execution.first_module == hns_wallet_types::ModuleId::Handshake;
                if (hns_module_is_first
                    && !matches!(
                        execution.state,
                        SwapState::FirstFunded
                            | SwapState::SecondFundingPending
                            | SwapState::BothFunded
                            | SwapState::FirstRedeemed
                            | SwapState::SecretObserved
                    ))
                    || (!hns_module_is_first && execution.state != SwapState::BothFunded)
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let (key, fee_reserve) = match side {
                    SwapAssetSide::Offered => {
                        if execution.first_funding.is_none()
                            || execution.first_module != hns_wallet_types::ModuleId::Handshake
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        hns_wallet_market::derive_local_direct_maker_key(
                            store, &policy, wallet_id, session_id,
                        )?
                    }
                    SwapAssetSide::Received => {
                        if execution.second_funding.is_none()
                            || execution.second_module != hns_wallet_types::ModuleId::Handshake
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        hns_wallet_market::derive_local_direct_taker_key(
                            store, &policy, wallet_id, session_id,
                        )?
                    }
                };
                let hns = hello
                    .build_hns_htlc(
                        side,
                        match side {
                            SwapAssetSide::Offered => hello.taker_settlement_public_key,
                            SwapAssetSide::Received => hello.maker_settlement_public_key,
                        },
                        match side {
                            SwapAssetSide::Offered => hello.maker_settlement_public_key,
                            SwapAssetSide::Received => hello.taker_settlement_public_key,
                        },
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if hns.descriptor.refund_public_key != key.public_key() {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                Ok(MobileShakescapeHnsSettlementPermit {
                    hello,
                    side,
                    funding_transaction: None,
                    settlement_key: key,
                    preimage: None,
                    action: MobileShakescapeSettlementAction::Refund,
                    fee_reserve,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_bitcoin_redeem(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileShakescapeBitcoinSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let side = if hello.offered_asset == AssetId::BTC {
                    SwapAssetSide::Offered
                } else if hello.received_asset == AssetId::BTC {
                    SwapAssetSide::Received
                } else {
                    return Err(hns_wallet_market::MarketError::InvalidPair);
                };
                let (key, preimage) = match side {
                    SwapAssetSide::Offered => {
                        if execution.state != SwapState::SecretObserved
                            || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        let (key, _) = hns_wallet_market::derive_local_direct_taker_key(
                            store, &policy, wallet_id, session_id,
                        )?;
                        let preimage =
                            hns_wallet_market::load_locally_verified_shakescape_preimage(
                                store, session_id,
                            )?
                            .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                        (key, preimage)
                    }
                    SwapAssetSide::Received => {
                        if execution.state != SwapState::BothFunded
                            || execution.second_module != hns_wallet_types::ModuleId::Bitcoin
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        let (key, _) = hns_wallet_market::derive_local_direct_maker_key(
                            store, &policy, wallet_id, session_id,
                        )?;
                        let preimage = hns_wallet_market::load_shakescape_direct_maker_preimage(
                            store, session_id,
                        )?
                        .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                        (key, preimage)
                    }
                };
                let bitcoin = build_shakescape_bitcoin_htlc(&hello, side)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if bitcoin.htlc.receiver_public_key != key.public_key()
                    || bitcoin.htlc.hashlock
                        != hns_swap::HnsHtlc::hash_preimage(preimage.expose_for_settlement())
                {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                Ok(MobileShakescapeBitcoinSettlementPermit {
                    hello,
                    side,
                    settlement_key: key,
                    preimage: Some(preimage),
                    action: MobileShakescapeSettlementAction::Redeem,
                    fee_reserve: u64::MAX,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_bitcoin_refund(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileShakescapeBitcoinSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_shakescape_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let record = load_shakescape_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                let side = if hello.offered_asset == AssetId::BTC {
                    SwapAssetSide::Offered
                } else if hello.received_asset == AssetId::BTC {
                    SwapAssetSide::Received
                } else {
                    return Err(hns_wallet_market::MarketError::InvalidPair);
                };
                let bitcoin_module_is_first =
                    execution.first_module == hns_wallet_types::ModuleId::Bitcoin;
                if (bitcoin_module_is_first
                    && !matches!(
                        execution.state,
                        SwapState::FirstFunded
                            | SwapState::SecondFundingPending
                            | SwapState::BothFunded
                            | SwapState::FirstRedeemed
                            | SwapState::SecretObserved
                    ))
                    || (!bitcoin_module_is_first && execution.state != SwapState::BothFunded)
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let (key, fee_reserve) = match side {
                    SwapAssetSide::Offered => {
                        if execution.first_funding.is_none()
                            || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        hns_wallet_market::derive_local_direct_maker_key(
                            store, &policy, wallet_id, session_id,
                        )?
                    }
                    SwapAssetSide::Received => {
                        if execution.second_funding.is_none()
                            || execution.second_module != hns_wallet_types::ModuleId::Bitcoin
                        {
                            return Err(hns_wallet_market::MarketError::InvalidTransition);
                        }
                        hns_wallet_market::derive_local_direct_taker_key(
                            store, &policy, wallet_id, session_id,
                        )?
                    }
                };
                let bitcoin = build_shakescape_bitcoin_htlc(&hello, side)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidShakescapeDirectSwap)?;
                if bitcoin.htlc.refund_public_key != key.public_key() {
                    return Err(hns_wallet_market::MarketError::InvalidShakescapeDirectSwap);
                }
                Ok(MobileShakescapeBitcoinSettlementPermit {
                    hello,
                    side,
                    settlement_key: key,
                    preimage: None,
                    action: MobileShakescapeSettlementAction::Refund,
                    fee_reserve,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn announce_direct_offer_cancellation(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        offer_id: &str,
    ) -> Result<(), MobileWalletError> {
        let offer_id = decode_offer_id(offer_id)?;
        let cancellation = self
            .store
            .try_with_store(|store| {
                load_shakescape_direct_offer(store, &self.policy.board_policy(), offer_id)
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
    ) -> Result<Option<MobileShakescapeDirectAdmission>, MobileWalletError> {
        let (_, message) = CrossChainMessage::decode_envelope(envelope)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let canonical = message
            .encode_envelope(
                CrossChainMessage::decode_envelope(envelope)
                    .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?
                    .0,
            )
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        if canonical != envelope {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        if let CrossChainMessage::DirectOffer(offer) = &message {
            let (bitcoin_amount, hns_amount) = match (offer.offered_asset, offer.received_asset) {
                (AssetId::BTC, AssetId::HNS) => {
                    (offer.offered_amount.get(), offer.received_amount.get())
                }
                (AssetId::HNS, AssetId::BTC) => {
                    (offer.received_amount.get(), offer.offered_amount.get())
                }
                _ => return Err(MobileWalletError::InvalidShakescapeSessionMessage),
            };
            if bitcoin_amount < u128::from(MIN_HTLC_DUST_SATS)
                || hns_amount < DEFAULT_DUST_THRESHOLD
            {
                return Err(MobileWalletError::InvalidShakescapeSessionMessage);
            }
        }
        self.store
            .try_with_store_mut(|store| match message {
                CrossChainMessage::DirectOffer(_) => admit_shakescape_direct_offer(
                    store,
                    &self.policy.board_policy(),
                    envelope,
                    now_unix,
                )
                .map(|admission| Some(MobileShakescapeDirectAdmission::Offer(admission))),
                CrossChainMessage::CancelDirectOffer(_) => {
                    admit_shakescape_direct_offer_cancellation(
                        store,
                        &self.policy.board_policy(),
                        envelope,
                        now_unix,
                    )
                    .map(|admission| {
                        Some(MobileShakescapeDirectAdmission::OfferCancellation(
                            admission,
                        ))
                    })
                }
                CrossChainMessage::TakeDirectOffer(_) => {
                    admit_shakescape_direct_offer_take(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileShakescapeDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapSessionProposal(_) => {
                    admit_shakescape_direct_swap_proposal(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileShakescapeDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapSessionHello(hello) => {
                    let admission = admit_shakescape_direct_swap_hello(
                        store,
                        &self.policy,
                        envelope,
                        now_unix,
                    )?;
                    // A countersigned hello is the bilateral execution
                    // commitment. The taker opens its workflow while creating
                    // that hello, but the maker only receives it through this
                    // admission path. Open the same idempotent workflow here
                    // so both wallets can independently recover and advance
                    // the first-funding gate after a disconnect or restart.
                    open_shakescape_execution(
                        store,
                        &self.policy,
                        hns_wallet_types::SessionId::new(hello.swap_session_id),
                        now_unix,
                    )?;
                    Ok(Some(MobileShakescapeDirectAdmission::Swap(admission)))
                }
                CrossChainMessage::SwapFundingStatus(_)
                | CrossChainMessage::SwapRedeemStatus(_)
                | CrossChainMessage::SwapRefundStatus(_) => {
                    admit_shakescape_direct_swap_peer_status(
                        store,
                        &self.policy,
                        envelope,
                        now_unix,
                    )
                    .map(|_| None)
                }
                CrossChainMessage::SwapWatchReady(_) => admit_shakescape_direct_swap_watch_ready(
                    store,
                    &self.policy,
                    envelope,
                    now_unix,
                )
                .map(|admission| Some(MobileShakescapeDirectAdmission::Swap(admission))),
                _ => Err(hns_wallet_market::MarketError::InvalidShakescapePeerMessage),
            })
            .map_err(MobileWalletError::from)
    }

    /// Reconcile locally retained board inventory and recover unfunded takes
    /// with one negotiated peer. Offers are announced by opaque identifier;
    /// signed takes are replayed byte-for-byte only while they still reserve
    /// funds and have not reached a countersigned durable execution.
    pub fn announce_direct_offer_inventory(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        now_unix: u64,
    ) -> Result<MobileShakescapeDirectInventoryReport, MobileWalletError> {
        let local_offers = self
            .store
            .try_with_store(|store| {
                let local = list_local_shakescape_direct_offers(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                    now_unix,
                )?;
                local
                    .into_iter()
                    .map(|offer| {
                        load_shakescape_direct_offer(
                            store,
                            &self.policy.board_policy(),
                            offer.offer.offer_id.into_bytes(),
                        )?
                        .map(|record| record.offer)
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectOfferBoard)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileWalletError::from)?;
        let inventory: Vec<_> = local_offers.iter().map(|offer| offer.offer_id).collect();
        let active_offers = inventory.len();
        peer.send_cross_chain_message(&CrossChainMessage::DirectOfferInventory(inventory))?;
        // Inventory/get remains useful for sparse or relay-backed peers, but a
        // mobile foreground transport may already contain a bounded backlog of
        // reconciliation frames. Waiting for the reciprocal GetDirectOffer to
        // traverse both queues can permanently starve a new listing when each
        // side continues to publish periodic recovery state. Replay the exact
        // signed live records immediately after their bounded inventory. Offer
        // admission is content-addressed and idempotent, so a later correlated
        // GetDirectOffer response is harmless while first-contact convergence
        // no longer depends on a round trip.
        for offer in local_offers {
            peer.send_cross_chain_message(&CrossChainMessage::DirectOffer(offer))?;
        }
        // Active offer IDs alone cannot tell a peer that a previously learned
        // offer was cancelled. Replay every still-retained signed tombstone
        // with the periodic inventory so a missed packet or replaced socket
        // converges without waiting for the offer's expiry.
        let cancellations = self
            .store
            .try_with_store(|store| {
                list_local_shakescape_direct_offer_cancellations(
                    store,
                    &self.policy.board_policy(),
                    self.wallet_id,
                )
            })
            .map_err(MobileWalletError::from)?;
        let cancellations: Vec<_> = cancellations
            .into_iter()
            .filter(|cancellation| cancellation.header.expires_at > now_unix)
            .collect();
        let cancellation_count = cancellations.len();
        for cancellation in cancellations {
            peer.send_cross_chain_message(&CrossChainMessage::CancelDirectOffer(cancellation))?;
        }
        let pending_takes = self
            .store
            .try_with_store(|store| {
                list_pending_local_shakescape_direct_takes(
                    store,
                    &self.policy,
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)?;
        let pending_take_count = pending_takes.len();
        for take in pending_takes {
            peer.send_cross_chain_envelope(&take.envelope)?;
        }
        // A take stops being "pending" as soon as the proposal is jointly
        // signed, but delivery is not thereby proven. Either participant may
        // reconnect after the one-shot exchange, so replay the complete
        // canonical handshake retained by every wallet-owned session. This
        // lets either endpoint repair the other's durable state without a
        // stateful rendezvous or out-of-band coordination.
        let session_envelopes = self.direct_swap_handshake_reconciliation_envelopes(now_unix)?;
        let session_envelope_count = session_envelopes.len();
        for envelope in session_envelopes {
            peer.send_cross_chain_envelope(&envelope)?;
        }
        Ok(MobileShakescapeDirectInventoryReport {
            active_offers,
            cancellations: cancellation_count,
            pending_takes: pending_take_count,
            session_envelopes: session_envelope_count,
        })
    }

    fn direct_swap_handshake_reconciliation_envelopes(
        &self,
        now_unix: u64,
    ) -> Result<Vec<Vec<u8>>, MobileWalletError> {
        if now_unix == 0 {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        self.store
            .try_with_store(|store| {
                let mut envelopes = Vec::new();
                for record in load_shakescape_direct_swaps(store, &self.policy)? {
                    let session_id = hns_wallet_types::SessionId::new(record.take.swap_session_id);
                    let local_maker = is_local_shakescape_direct_maker(
                        store,
                        &self.policy,
                        self.wallet_id,
                        session_id,
                    )?;
                    let local_taker =
                        is_local_shakescape_direct_taker(store, self.wallet_id, session_id)?;
                    if local_maker == local_taker {
                        continue;
                    }
                    let Some(hello) = record.hello else { continue };
                    let execution = load_shakescape_execution(store, &self.policy, session_id)?;
                    // The funding deadline prevents new funding; it must not
                    // prevent recovery of a lock which was already authorized
                    // or observed. An untouched agreement is omitted after
                    // expiry so it cannot become perpetual network noise.
                    let recovery_in_progress = execution.as_ref().is_some_and(|execution| {
                        (execution.state == SwapState::FirstFundingPending && local_maker)
                            || matches!(
                                execution.state,
                                SwapState::FirstFunded
                                    | SwapState::SecondFundingPending
                                    | SwapState::BothFunded
                                    | SwapState::FirstRedeemed
                                    | SwapState::SecretObserved
                                    | SwapState::SecondRedeemed
                                    | SwapState::RefundEligible
                                    | SwapState::RefundBroadcast
                            )
                            || (execution.state == SwapState::Failed
                                && (execution.first_funding.is_some()
                                    || execution.second_funding.is_some()))
                    });
                    if now_unix > hello.header.expires_at && !recovery_in_progress {
                        continue;
                    }
                    let request_id = record
                        .proposal_request_id
                        .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                    // The take re-establishes the volatile maker/taker route.
                    envelopes.push(
                        CrossChainMessage::TakeDirectOffer(record.take.clone())
                            .encode_envelope(record.take_request_id)
                            .map_err(|_| {
                                hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                            })?,
                    );
                    // Only the maker replays its proposal. A taker replaying a
                    // maker-authored proposal back to the maker is redundant,
                    // while maker -> taker repairs the precise missing step
                    // needed to re-admit the jointly signed hello.
                    if local_maker {
                        let proposal = record
                            .proposal
                            .clone()
                            .ok_or(hns_wallet_market::MarketError::CorruptShakescapeDirectSwap)?;
                        envelopes.push(
                            CrossChainMessage::SwapSessionProposal(proposal)
                                .encode_envelope(record.take_request_id)
                                .map_err(|_| {
                                    hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                                })?,
                        );
                    }
                    envelopes.push(
                        CrossChainMessage::SwapSessionHello(hello)
                            .encode_envelope(request_id)
                            .map_err(|_| {
                                hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                            })?,
                    );
                    if let Some(ready) = record.first_chain_watch_ready {
                        envelopes.push(
                            CrossChainMessage::SwapWatchReady(ready)
                                .encode_envelope(0)
                                .map_err(|_| {
                                    hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                                })?,
                        );
                    }
                }
                // Funding locators are settlement recovery records, not
                // public listings. Replay every still-valid signed locator
                // even after the original offer/hello listing window closed.
                // Recipients independently retrieve and verify the exact HTLC
                // before advancing any durable execution state.
                for record in load_shakescape_direct_swaps(store, &self.policy)? {
                    for funding in record.peer_funding_statuses {
                        if funding.status.header.expires_at > now_unix {
                            envelopes.push(
                                CrossChainMessage::SwapFundingStatus(funding.status)
                                    .encode_envelope(0)
                                    .map_err(|_| {
                                        hns_wallet_market::MarketError::CorruptShakescapeDirectSwap
                                    })?,
                            );
                        }
                    }
                }
                Ok::<_, hns_wallet_market::MarketError>(envelopes)
            })
            .map_err(MobileWalletError::from)
    }

    /// Service one already-received canonical cross-chain envelope. Direct
    /// inventory/get exchange is transport-only. Every offer, cancellation,
    /// take, and session packet still passes through `admit_direct_envelope`
    /// before it can affect durable state.
    pub fn service_direct_envelope(
        &self,
        peer: &mut HnsDirectShakescapePeer,
        envelope: &[u8],
        now_unix: u64,
    ) -> Result<MobileShakescapeDirectTransportReport, MobileWalletError> {
        let (request_id, message) = CrossChainMessage::decode_envelope(envelope)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        let canonical = message
            .encode_envelope(request_id)
            .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
        if canonical != envelope {
            return Err(MobileWalletError::InvalidShakescapeSessionMessage);
        }
        let message_kind = match &message {
            CrossChainMessage::DirectOfferInventory(_) => {
                MobileShakescapeDirectMessageKind::OfferInventory
            }
            CrossChainMessage::GetDirectOffer(_) => MobileShakescapeDirectMessageKind::GetOffer,
            CrossChainMessage::DirectOffer(_) => MobileShakescapeDirectMessageKind::Offer,
            CrossChainMessage::CancelDirectOffer(_) => {
                MobileShakescapeDirectMessageKind::OfferCancellation
            }
            CrossChainMessage::TakeDirectOffer(_) => MobileShakescapeDirectMessageKind::TakeOffer,
            CrossChainMessage::SwapSessionProposal(_) => {
                MobileShakescapeDirectMessageKind::SessionProposal
            }
            CrossChainMessage::SwapSessionHello(_) => {
                MobileShakescapeDirectMessageKind::SessionHello
            }
            CrossChainMessage::SwapFundingStatus(_) => {
                MobileShakescapeDirectMessageKind::FundingStatus
            }
            CrossChainMessage::SwapRedeemStatus(_) => {
                MobileShakescapeDirectMessageKind::RedeemStatus
            }
            CrossChainMessage::SwapRefundStatus(_) => {
                MobileShakescapeDirectMessageKind::RefundStatus
            }
            CrossChainMessage::SwapWatchReady(_) => MobileShakescapeDirectMessageKind::WatchReady,
        };
        let mut report = MobileShakescapeDirectTransportReport {
            message_kind,
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
                            load_shakescape_direct_offer(
                                store,
                                &self.policy.board_policy(),
                                offer_id,
                            )
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
                        load_shakescape_direct_offer(store, &self.policy.board_policy(), offer_id)
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
            CrossChainMessage::DirectOffer(_) | CrossChainMessage::CancelDirectOffer(_) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
            }
            CrossChainMessage::TakeDirectOffer(ref take) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
                let session_id = hns_wallet_types::SessionId::new(take.swap_session_id);
                let proposal = self.store.try_with_store_mut(|store| {
                    create_shakescape_direct_maker_proposal(
                        store,
                        &self.policy,
                        hns_wallet_market::ShakescapeDirectMakerProposalRequest {
                            wallet_id: self.wallet_id,
                            session_id,
                            now_unix,
                            // A phone may need to wake its independent Bitcoin
                            // controller, install the exact HTLC watch, and
                            // reconnect a transient mobile route before the
                            // first funding gate. Keep this bounded but do not
                            // make ordinary mobile scheduling race ten minutes.
                            funding_window_seconds: DIRECT_SWAP_FUNDING_WINDOW_SECONDS,
                            second_refund_after_seconds: 2 * 60 * 60,
                            refund_safety_margin_seconds: 60 * 60,
                            bitcoin_minimum_confirmations: 1,
                            // Match the native HNS wallet's default local
                            // settlement floor. The verifier independently
                            // raises legacy lower terms to its configured
                            // policy, but new peers should agree on the
                            // stronger threshold before either funds.
                            hns_minimum_confirmations: 2,
                        },
                    )
                });
                match proposal {
                    Ok(proposal) => {
                        let (response_id, response) =
                            CrossChainMessage::decode_envelope(&proposal.envelope)
                                .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
                        peer.send_cross_chain_message_with_request_id(response_id, &response)?;
                        report.messages_sent = report.messages_sent.saturating_add(1);
                    }
                    Err(hns_wallet_market::MarketError::UnknownShakescapeDirectOffer) => {}
                    Err(error) => return Err(MobileWalletError::from(error)),
                }
            }
            CrossChainMessage::SwapSessionProposal(ref proposal) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
                let session_id = hns_wallet_types::SessionId::new(proposal.terms().swap_session_id);
                let accepted = self.store.try_with_store_mut(|store| {
                    accept_shakescape_direct_maker_proposal(
                        store,
                        &self.policy,
                        self.wallet_id,
                        session_id,
                        now_unix,
                    )
                });
                match accepted {
                    Ok(accepted) => {
                        let (response_id, response) =
                            CrossChainMessage::decode_envelope(&accepted.envelope)
                                .map_err(|_| MobileWalletError::InvalidShakescapeSessionMessage)?;
                        peer.send_cross_chain_message_with_request_id(response_id, &response)?;
                        report.messages_sent = report.messages_sent.saturating_add(1);
                    }
                    Err(hns_wallet_market::MarketError::UnknownShakescapeDirectSwap) => {}
                    Err(error) => return Err(MobileWalletError::from(error)),
                }
            }
            CrossChainMessage::SwapSessionHello(_)
            | CrossChainMessage::SwapFundingStatus(_)
            | CrossChainMessage::SwapRedeemStatus(_)
            | CrossChainMessage::SwapRefundStatus(_)
            | CrossChainMessage::SwapWatchReady(_) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
            }
        }
        Ok(report)
    }
}

fn direct_offer_has_funding_horizon(
    record: &hns_wallet_market::ShakescapeDirectOfferRecord,
    now_unix: u64,
) -> bool {
    record.is_active_at(now_unix)
        && now_unix
            .checked_add(DIRECT_SWAP_FUNDING_WINDOW_SECONDS)
            .is_some_and(|funding_expires_at| funding_expires_at <= record.offer.header.expires_at)
}

fn summary(
    offer: ShakescapeLocalDirectOffer,
) -> Result<MobileBtcForHnsOfferSummary, MobileWalletError> {
    Ok(MobileBtcForHnsOfferSummary {
        offer_id: super::lowercase_hex(offer.offer.offer_id.as_bytes()),
        session_id: super::lowercase_hex(offer.offer.session_id.as_bytes()),
        btc_amount_sats: u64::try_from(offer.offer.offered_amount)
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?,
        hns_amount_dollarydoos: u64::try_from(offer.offer.received_amount)
            .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?,
        bitcoin_fee_reserve_sats: offer.bitcoin_fee_reserve_sats,
        created_at_unix: offer.offer.created_at_unix,
        expires_at_unix: offer.offer.expires_at_unix,
    })
}

fn direct_local_offer_summary(
    offer: ShakescapeLocalDirectOffer,
) -> Result<MobileDirectOfferSummary, MobileWalletError> {
    let offered_asset = offer.offer.offered_asset;
    let received_asset = offer.offer.received_asset;
    let offered_amount = u64::try_from(offer.offer.offered_amount)
        .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
    let received_amount = u64::try_from(offer.offer.received_amount)
        .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
    direct_offer_summary(
        offer.offer.offer_id.as_bytes(),
        offer.offer.session_id.as_bytes(),
        offered_asset,
        offered_amount,
        received_asset,
        received_amount,
        Some(offer.offered_fee_reserve),
        true,
        offer.offer.created_at_unix,
        offer.offer.expires_at_unix,
    )
}

fn direct_take_summary(
    take: ShakescapeLocalDirectTake,
) -> Result<MobileDirectOfferTakeSummary, MobileWalletError> {
    Ok(MobileDirectOfferTakeSummary {
        offer_id: super::lowercase_hex(take.offer_id.as_bytes()),
        session_id: super::lowercase_hex(take.session_id.as_bytes()),
        offered_asset: asset_name(take.offered_asset).to_owned(),
        offered_amount: take.offered_amount,
        received_asset: asset_name(take.received_asset).to_owned(),
        received_amount: take.received_amount,
        received_fee_reserve: take.received_fee_reserve,
        created_at_unix: take.created_at_unix,
        expires_at_unix: take.expires_at_unix,
    })
}

fn direct_board_offer_summary(
    record: hns_wallet_market::ShakescapeDirectOfferRecord,
    local: bool,
) -> Result<MobileDirectOfferSummary, MobileWalletError> {
    let offered_amount = u64::try_from(record.offer.offered_amount.get())
        .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
    let received_amount = u64::try_from(record.offer.received_amount.get())
        .map_err(|_| MobileWalletError::InvalidDirectOfferAction)?;
    direct_offer_summary(
        &record.offer.offer_id,
        &record.offer.swap_session_id,
        record.offer.offered_asset,
        offered_amount,
        record.offer.received_asset,
        received_amount,
        None,
        local,
        record.offer.header.created_at,
        record.offer.header.expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn direct_offer_summary(
    offer_id: &[u8; 32],
    session_id: &[u8; 32],
    offered_asset: AssetId,
    offered_amount: u64,
    received_asset: AssetId,
    received_amount: u64,
    offered_fee_reserve: Option<u64>,
    local: bool,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<MobileDirectOfferSummary, MobileWalletError> {
    let (btc_amount_sats, hns_amount_dollarydoos) = match (offered_asset, received_asset) {
        (AssetId::BTC, AssetId::HNS) => (offered_amount, received_amount),
        (AssetId::HNS, AssetId::BTC) => (received_amount, offered_amount),
        _ => return Err(MobileWalletError::InvalidDirectOfferAction),
    };
    Ok(MobileDirectOfferSummary {
        offer_id: super::lowercase_hex(offer_id),
        session_id: super::lowercase_hex(session_id),
        maker_sells_hns: offered_asset == AssetId::HNS,
        offered_asset: asset_name(offered_asset).to_owned(),
        offered_amount,
        received_asset: asset_name(received_asset).to_owned(),
        received_amount,
        btc_amount_sats,
        hns_amount_dollarydoos,
        offered_fee_reserve,
        local,
        created_at_unix,
        expires_at_unix,
    })
}

fn asset_name(asset: AssetId) -> &'static str {
    match asset {
        AssetId::HNS => "hns",
        AssetId::BTC => "btc",
        _ => "unsupported",
    }
}

fn execution_summary(
    session: hns_wallet_market::SwapSession,
    local_role: &str,
) -> Result<MobileShakescapeExecutionSummary, MobileWalletError> {
    let chain = |module| -> Result<String, MobileWalletError> {
        match module {
            hns_wallet_types::ModuleId::Bitcoin => Ok("bitcoin".to_owned()),
            hns_wallet_types::ModuleId::Handshake => Ok("handshake".to_owned()),
            hns_wallet_types::ModuleId::Ethereum => {
                Err(MobileWalletError::InvalidShakescapeSessionMessage)
            }
        }
    };
    let asset = |asset| -> Result<String, MobileWalletError> {
        match asset {
            hns_wallet_types::WalletAsset::Btc => Ok("btc".to_owned()),
            hns_wallet_types::WalletAsset::Hns => Ok("hns".to_owned()),
            hns_wallet_types::WalletAsset::Eth => {
                Err(MobileWalletError::InvalidShakescapeSessionMessage)
            }
        }
    };
    Ok(MobileShakescapeExecutionSummary {
        session_id: super::lowercase_hex(session.id.as_bytes()),
        revision: session.revision,
        state: session.state,
        first_chain: chain(session.first_module)?,
        second_chain: chain(session.second_module)?,
        offered_asset: asset(session.offered.asset)?,
        offered_amount: session.offered.base_units.get(),
        received_asset: asset(session.received.asset)?,
        received_amount: session.received.base_units.get(),
        local_role: local_role.to_owned(),
        first_refund_at_unix: session.timeouts.first_chain_refund_at,
        second_refund_at_unix: session.timeouts.second_chain_refund_at,
        first_funding_confirmed: session.first_funding.is_some(),
        second_funding_confirmed: session.second_funding.is_some(),
        first_redemption_confirmed: session.first_redemption.is_some(),
        second_redemption_confirmed: session.second_redemption.is_some(),
        refund_confirmed: matches!(session.state, SwapState::Refunded),
        last_verified_at_unix: session.last_verified_at_unix,
        failure_reason: session.failure_reason,
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

#[cfg(test)]
mod tests {
    use hns_marketplace_protocol::{ChainId, CrossChainMessage, NetworkBinding};
    use hns_primitives::BlockHash;
    use hns_wallet_market::{
        ShakescapeBtcForHnsMakerProposalRequest, ShakescapeBtcForHnsOfferRequest,
        ShakescapeDirectOfferBoardPolicy, ShakescapeHnsForBtcOfferRequest,
        ShakescapeHnsForBtcTakeRequest, VerifiedEvidence, WalletStoreJournal,
        accept_shakescape_hns_for_btc_maker_proposal, admit_shakescape_direct_offer,
        admit_shakescape_direct_offer_take, admit_shakescape_direct_swap_hello,
        admit_shakescape_direct_swap_proposal, create_shakescape_btc_for_hns_maker_proposal,
        create_shakescape_btc_for_hns_offer, create_shakescape_hns_for_btc_offer,
        create_shakescape_hns_for_btc_take, load_shakescape_direct_offer,
        open_shakescape_execution, shakescape_execution_workflow_id,
    };
    use hns_wallet_store::{RECOVERY_SEED_BYTES, SecretKind, WalletStore};

    use super::*;

    const PASSPHRASE: &str = "mobile direct funding authorization test";
    const START: u64 = 1_700_000_000;

    fn policy() -> ShakescapeDirectSwapPolicy {
        ShakescapeDirectSwapPolicy::new(
            ShakescapeDirectOfferBoardPolicy::new(NetworkBinding {
                hns_magic: 0x5b6e_c393,
                hns_genesis: BlockHash::new([1; 32]),
                counterchain: ChainId::BITCOIN,
                counterchain_network: 1,
                counterchain_genesis: [2; 32],
            })
            .expect("board policy"),
        )
        .expect("swap policy")
    }

    fn seeded_store(wallet_id: WalletId, seed: u8) -> WalletStore {
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("store");
        store
            .put_secret(
                wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[seed; RECOVERY_SEED_BYTES],
                1,
            )
            .expect("seed");
        store
    }

    #[test]
    fn direct_offer_preparation_enforces_both_chain_dust_boundaries() {
        let wallet_id = WalletId::new([0x18; 16]);
        let make_controller = || {
            MobileShakescapeSessionController::new(
                SharedWalletStore::new(seeded_store(wallet_id, 0x28)),
                policy(),
                wallet_id,
            )
        };

        let mut below_bitcoin_dust = make_controller();
        assert!(matches!(
            below_bitcoin_dust.prepare_btc_for_hns_offer(
                100_000,
                MIN_HTLC_DUST_SATS - 1,
                1_000_000,
                1_000,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                START,
            ),
            Err(MobileWalletError::InvalidDirectOfferAction)
        ));

        let mut below_hns_dust = make_controller();
        assert!(matches!(
            below_hns_dust.prepare_hns_for_btc_offer(
                2_000_000,
                u64::try_from(DEFAULT_DUST_THRESHOLD).expect("HNS dust fits u64") - 1,
                MIN_HTLC_DUST_SATS,
                100_000,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                START,
            ),
            Err(MobileWalletError::InvalidDirectOfferAction)
        ));

        let mut below_bitcoin_fee_reserve = make_controller();
        assert!(matches!(
            below_bitcoin_fee_reserve.prepare_btc_for_hns_offer(
                100_000,
                MIN_HTLC_DUST_SATS + MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                1_000_000,
                MINIMUM_BITCOIN_FEE_RESERVE_SATS - 1,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                START,
            ),
            Err(MobileWalletError::InvalidDirectOfferAction)
        ));

        let mut insufficient_settlement_horizon = make_controller();
        assert!(matches!(
            insufficient_settlement_horizon.prepare_btc_for_hns_offer(
                100_000,
                MIN_HTLC_DUST_SATS + MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                1_000_000,
                MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS - 1,
                START,
            ),
            Err(MobileWalletError::InvalidDirectOfferAction)
        ));

        let bitcoin_lock = MIN_HTLC_DUST_SATS + MINIMUM_BITCOIN_FEE_RESERVE_SATS;
        let mut exact_bitcoin_fee_reserve = make_controller();
        let bitcoin_approval = exact_bitcoin_fee_reserve
            .prepare_btc_for_hns_offer(
                bitcoin_lock,
                bitcoin_lock,
                1_000_000,
                MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                START,
            )
            .expect("the exact locked amount covers its included Bitcoin reserve");
        assert_eq!(bitcoin_approval.total_bitcoin_commitment_sats, bitcoin_lock);

        let hns_lock = u64::try_from(DEFAULT_DUST_THRESHOLD).expect("HNS dust fits u64")
            + MINIMUM_HNS_FEE_RESERVE_DOLLARYDOOS;
        let mut exact_boundaries = make_controller();
        let hns_approval = exact_boundaries
            .prepare_hns_for_btc_offer(
                hns_lock,
                hns_lock,
                MIN_HTLC_DUST_SATS,
                MINIMUM_HNS_FEE_RESERVE_DOLLARYDOOS,
                MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                START,
            )
            .expect("the exact locked amount covers its included HNS reserve");
        assert_eq!(hns_approval.total_hns_commitment_dollarydoos, hns_lock);
    }

    #[test]
    fn bitcoin_taker_fee_reserve_has_the_same_product_floor() {
        let policy = policy();
        let maker_id = WalletId::new([0x19; 16]);
        let taker_id = WalletId::new([0x1a; 16]);
        let mut maker = seeded_store(maker_id, 0x29);
        let offer = create_shakescape_hns_for_btc_offer(
            &mut maker,
            &policy.board_policy(),
            ShakescapeHnsForBtcOfferRequest {
                wallet_id: maker_id,
                hns_amount_dollarydoos: 100_546,
                btc_amount_sats: MIN_HTLC_DUST_SATS + MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                hns_fee_reserve_dollarydoos: 50_000,
                created_at_unix: START,
                expires_at_unix: START + MIN_DIRECT_OFFER_LIFETIME_SECONDS,
                nonce: [0x39; 32],
            },
        )
        .expect("HNS-for-BTC offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        let mut taker = MobileShakescapeSessionController::new(
            SharedWalletStore::new(seeded_store(taker_id, 0x2a)),
            policy,
            taker_id,
        );
        taker
            .admit_direct_envelope(&envelope, START)
            .expect("admit offer");
        let offer_id = crate::lowercase_hex(offer.offer.offer_id.as_bytes());

        assert!(matches!(
            taker.prepare_direct_offer_take(
                &offer_id,
                100_000,
                0,
                MINIMUM_BITCOIN_FEE_RESERVE_SATS - 1,
                START + 1,
            ),
            Err(MobileWalletError::InvalidDirectOfferAction)
        ));
        let bitcoin_lock = MIN_HTLC_DUST_SATS + MINIMUM_BITCOIN_FEE_RESERVE_SATS;
        let approval = taker
            .prepare_direct_offer_take(
                &offer_id,
                bitcoin_lock,
                0,
                MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                START + 1,
            )
            .expect("exact received lock covers its included reserve");
        assert_eq!(approval.total_received_asset_commitment, bitcoin_lock);
    }

    #[test]
    fn offers_without_a_complete_funding_window_are_not_actionable() {
        let policy = policy();
        let maker_id = WalletId::new([0x4a; 16]);
        let taker_id = WalletId::new([0x4b; 16]);
        let mut maker = seeded_store(maker_id, 0x5a);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: MIN_HTLC_DUST_SATS,
                hns_amount_dollarydoos: 100_546,
                bitcoin_fee_reserve_sats: MINIMUM_BITCOIN_FEE_RESERVE_SATS,
                created_at_unix: START,
                expires_at_unix: START + DIRECT_SWAP_FUNDING_WINDOW_SECONDS,
                nonce: [0x6a; 32],
            },
        )
        .expect("short-lived protocol offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        let mut taker = MobileShakescapeSessionController::new(
            SharedWalletStore::new(seeded_store(taker_id, 0x5b)),
            policy,
            taker_id,
        );
        taker
            .admit_direct_envelope(&envelope, START)
            .expect("admit offer");

        assert!(taker.available_direct_offers(START + 1).unwrap().is_empty());
        assert!(matches!(
            taker.prepare_direct_offer_take(
                &crate::lowercase_hex(offer.offer.offer_id.as_bytes()),
                0,
                1_000_000,
                100_000,
                START + 1,
            ),
            Err(MobileWalletError::DirectOfferActionExpired)
        ));
    }

    #[test]
    fn countersigned_handshake_replays_after_the_original_delivery_is_lost() {
        let policy = policy();
        let maker_id = WalletId::new([0x1b; 16]);
        let taker_id = WalletId::new([0x1c; 16]);
        let mut maker = seeded_store(maker_id, 0x2b);
        let mut taker = seeded_store(taker_id, 0x2c);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [0x4b; 32],
            },
        )
        .expect("offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        admit_shakescape_direct_offer(&mut taker, &policy.board_policy(), &offer_envelope, START)
            .expect("admit offer");
        let take = create_shakescape_hns_for_btc_take(
            &mut taker,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [0x4c; 32],
            },
        )
        .expect("take");
        admit_shakescape_direct_offer_take(&mut maker, &policy, &take.envelope, START + 10)
            .expect("maker admits take");
        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut maker,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("proposal");
        admit_shakescape_direct_swap_proposal(&mut taker, &policy, &proposal.envelope, START + 20)
            .expect("taker admits proposal");
        let accepted = accept_shakescape_hns_for_btc_maker_proposal(
            &mut taker,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("taker countersigns");
        // Deliberately do not deliver `accepted.envelope` to the maker.
        let shared = SharedWalletStore::new(taker);
        let mut controller = MobileShakescapeSessionController::new(shared, policy, taker_id);
        let permit = controller
            .authorize_counterparty_bitcoin_watch(offer.offer.session_id, START + 31)
            .expect("watch permit");
        let ready = controller
            .confirm_counterparty_bitcoin_watch(permit, START + 31)
            .expect("watch acknowledgement");
        let ready_envelope = ready.encode_envelope(0).expect("ready envelope");

        let replay = controller
            .direct_swap_handshake_reconciliation_envelopes(START + 32)
            .expect("reconciliation envelopes");
        assert_eq!(
            replay,
            vec![
                take.envelope.clone(),
                accepted.envelope.clone(),
                ready_envelope.clone(),
            ]
        );
        let maker_shared = SharedWalletStore::new(maker);
        let maker_controller =
            MobileShakescapeSessionController::new(maker_shared.clone(), policy, maker_id);
        maker_controller
            .admit_direct_envelope(&replay[0], START + 32)
            .expect("replayed take is idempotent");
        maker_controller
            .admit_direct_envelope(&replay[1], START + 32)
            .expect("replayed hello reaches maker");
        maker_controller
            .admit_direct_envelope(&replay[2], START + 32)
            .expect("replayed watch acknowledgement reaches maker");
        maker_shared
            .try_with_store(|maker| {
                let record = load_shakescape_direct_swap(maker, &policy, offer.offer.session_id)?
                    .expect("maker session exists");
                assert!(record.hello.is_some());
                assert!(record.first_chain_watch_ready.is_some());
                Ok::<_, hns_wallet_market::MarketError>(())
            })
            .expect("load maker session");
        let maker_execution = maker_controller
            .durable_executions()
            .expect("maker execution opened by countersigned hello");
        assert_eq!(maker_execution.len(), 1);
        assert_eq!(maker_execution[0].local_role, "maker");
        assert_eq!(maker_execution[0].state, SwapState::TermsFrozen);
        let maker_replay = maker_controller
            .direct_swap_handshake_reconciliation_envelopes(START + 33)
            .expect("maker reconciliation envelopes");
        assert_eq!(
            maker_replay,
            vec![
                take.envelope.clone(),
                proposal.envelope.clone(),
                accepted.envelope,
                ready_envelope,
            ]
        );
        assert!(
            controller
                .direct_swap_handshake_reconciliation_envelopes(START + 621)
                .expect("expired reconciliation")
                .is_empty()
        );
        assert_eq!(
            controller
                .reconcile_direct_offer_lifecycle(START + 621)
                .expect("expire untouched second-funder reservation"),
            1
        );
        assert_eq!(
            controller
                .durable_executions()
                .expect("durable execution after deadline")[0]
                .state,
            SwapState::Failed
        );
        assert_eq!(
            controller
                .reserved_hns_dollarydoos(START + 621)
                .expect("expired taker reservation released"),
            0
        );
    }

    #[test]
    fn expired_maker_proposal_retires_offer_without_counterparty_coordination() {
        let policy = policy();
        let maker_id = WalletId::new([0x1d; 16]);
        let taker_id = WalletId::new([0x1e; 16]);
        let mut maker = seeded_store(maker_id, 0x2d);
        let mut taker = seeded_store(taker_id, 0x2e);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [0x4d; 32],
            },
        )
        .expect("offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        admit_shakescape_direct_offer(&mut taker, &policy.board_policy(), &offer_envelope, START)
            .expect("admit offer");
        let take = create_shakescape_hns_for_btc_take(
            &mut taker,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [0x4e; 32],
            },
        )
        .expect("take");
        admit_shakescape_direct_offer_take(&mut maker, &policy, &take.envelope, START + 10)
            .expect("maker admits take");
        create_shakescape_btc_for_hns_maker_proposal(
            &mut maker,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("maker proposal");
        // The anonymous taker disappears and never returns a countersignature.
        let shared = SharedWalletStore::new(maker);
        let mut controller =
            MobileShakescapeSessionController::new(shared.clone(), policy, maker_id);
        assert_eq!(
            controller
                .reconcile_direct_offer_lifecycle(START + 620)
                .expect("retire expired negotiation"),
            1
        );
        shared
            .try_with_store(|store| {
                assert!(
                    list_local_shakescape_direct_offers(
                        store,
                        &policy.board_policy(),
                        maker_id,
                        START + 620,
                    )?
                    .is_empty()
                );
                assert_eq!(
                    list_local_shakescape_direct_offer_cancellations(
                        store,
                        &policy.board_policy(),
                        maker_id,
                    )?
                    .len(),
                    1
                );
                Ok::<_, hns_wallet_market::MarketError>(())
            })
            .expect("expired offer tombstone");
        assert_eq!(
            controller
                .reserved_bitcoin_sats(START + 620)
                .expect("maker reservation released"),
            0
        );
    }

    #[test]
    fn only_the_local_btc_maker_can_cross_the_durable_first_funding_gate() {
        let policy = policy();
        let maker_id = WalletId::new([0x21; 16]);
        let taker_id = WalletId::new([0x22; 16]);
        let mut maker = seeded_store(maker_id, 0x31);
        let mut taker = seeded_store(taker_id, 0x41);
        let offer = create_shakescape_btc_for_hns_offer(
            &mut maker,
            &policy.board_policy(),
            ShakescapeBtcForHnsOfferRequest {
                wallet_id: maker_id,
                btc_amount_sats: 9_000,
                hns_amount_dollarydoos: 2_000_000,
                bitcoin_fee_reserve_sats: 1_000,
                created_at_unix: START,
                expires_at_unix: START + 10_000,
                nonce: [7; 32],
            },
        )
        .expect("offer");
        let signed_offer = load_shakescape_direct_offer(
            &maker,
            &policy.board_policy(),
            offer.offer.offer_id.into_bytes(),
        )
        .expect("load offer")
        .expect("offer exists")
        .offer;
        let offer_envelope = CrossChainMessage::DirectOffer(signed_offer)
            .encode_envelope(1)
            .expect("offer envelope");
        admit_shakescape_direct_offer(&mut taker, &policy.board_policy(), &offer_envelope, START)
            .expect("admit offer");
        let take = create_shakescape_hns_for_btc_take(
            &mut taker,
            &policy,
            ShakescapeHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [8; 32],
            },
        )
        .expect("take");
        admit_shakescape_direct_offer_take(&mut maker, &policy, &take.envelope, START + 10)
            .expect("maker admits take");
        let proposal = create_shakescape_btc_for_hns_maker_proposal(
            &mut maker,
            &policy,
            ShakescapeBtcForHnsMakerProposalRequest {
                wallet_id: maker_id,
                session_id: offer.offer.session_id,
                now_unix: START + 20,
                funding_window_seconds: 600,
                second_refund_after_seconds: 3_600,
                refund_safety_margin_seconds: 3_600,
                bitcoin_minimum_confirmations: 1,
                hns_minimum_confirmations: 1,
            },
        )
        .expect("proposal");
        admit_shakescape_direct_swap_proposal(&mut taker, &policy, &proposal.envelope, START + 20)
            .expect("taker admits proposal");
        let accepted = accept_shakescape_hns_for_btc_maker_proposal(
            &mut taker,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("accept");
        admit_shakescape_direct_swap_hello(&mut maker, &policy, &accepted.envelope, START + 30)
            .expect("maker admits hello");

        let taker_shared = SharedWalletStore::new(taker);
        let mut taker_controller =
            MobileShakescapeSessionController::new(taker_shared.clone(), policy, taker_id);
        let watch_permit = taker_controller
            .authorize_counterparty_bitcoin_watch(offer.offer.session_id, START + 34)
            .expect("taker watch permit");
        assert_eq!(
            watch_permit.hello().swap_session_id,
            offer.offer.session_id.into_bytes()
        );
        let ready = taker_controller
            .confirm_counterparty_bitcoin_watch(watch_permit, START + 34)
            .expect("persist taker watch readiness");
        let taker_execution = taker_controller
            .durable_executions()
            .expect("taker execution projection")
            .pop()
            .expect("taker execution");
        assert_eq!(taker_execution.local_role, "taker");
        assert_eq!(taker_execution.state, SwapState::FirstFundingPending);
        assert_eq!(
            taker_controller
                .advance_local_first_funding_readiness(START + 34)
                .expect("taker cannot advance maker funding"),
            0
        );
        let ready_envelope = ready.encode_envelope(0).expect("watch-ready envelope");
        admit_shakescape_direct_swap_watch_ready(&mut maker, &policy, &ready_envelope, START + 34)
            .expect("maker admits receiver watch readiness");

        // Simulate termination after only the first durable funding gate.
        let mut interrupted =
            open_shakescape_execution(&mut maker, &policy, offer.offer.session_id, START + 35)
                .expect("execution");
        let mut journal = WalletStoreJournal {
            store: &mut maker,
            workflow_id: shakescape_execution_workflow_id(offer.offer.session_id),
            updated_at_unix: START + 35,
        };
        interrupted
            .apply(VerifiedEvidence::RefundsValidated, START + 35, &mut journal)
            .expect("refund checkpoint");
        assert_eq!(interrupted.state, SwapState::RefundsPrepared);

        let shared = SharedWalletStore::new(maker);
        let mut controller =
            MobileShakescapeSessionController::new(shared.clone(), policy, maker_id);
        assert_eq!(
            controller
                .reconcile_direct_offer_lifecycle(START + 36)
                .expect("retire consumed public offer"),
            1
        );
        shared
            .try_with_store(|store| {
                assert!(
                    list_local_shakescape_direct_offers(
                        store,
                        &policy.board_policy(),
                        maker_id,
                        START + 36,
                    )?
                    .is_empty()
                );
                assert_eq!(
                    list_local_shakescape_direct_offer_cancellations(
                        store,
                        &policy.board_policy(),
                        maker_id,
                    )?
                    .len(),
                    1
                );
                Ok::<_, hns_wallet_market::MarketError>(())
            })
            .expect("consumed offer tombstone");
        assert_eq!(
            controller
                .advance_local_first_funding_readiness(START + 37)
                .expect("advance local maker funding readiness"),
            1
        );
        let resumed = controller.durable_executions().expect("durable executions");
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].state, SwapState::FirstFundingPending);
        assert_eq!(resumed[0].local_role, "maker");
        assert_eq!(
            resumed[0].session_id,
            crate::lowercase_hex(offer.offer.session_id.as_bytes())
        );
        assert_eq!(resumed[0].first_chain, "bitcoin");
        assert!(!resumed[0].first_funding_confirmed);
        let permit = controller
            .authorize_local_btc_first_funding(offer.offer.session_id, START + 40)
            .expect("funding permit");
        assert_eq!(permit.bitcoin_fee_reserve_sats(), 1_000);
        assert_eq!(
            permit.hello().swap_session_id,
            offer.offer.session_id.into_bytes()
        );
        assert_eq!(
            shared
                .try_with_store(|store| {
                    store
                        .load_workflow::<hns_wallet_market::SwapSession>(
                            shakescape_execution_workflow_id(offer.offer.session_id),
                        )
                        .map(|stored| stored.expect("execution").state.state)
                })
                .expect("load state"),
            SwapState::FirstFundingPending
        );
        assert_eq!(
            controller
                .reserved_bitcoin_sats(START + 10_001)
                .expect("reservation survives listing expiry"),
            9_000
        );
        controller
            .authorize_local_btc_first_funding(offer.offer.session_id, START + 41)
            .expect("idempotent permit");
        let binding = build_shakescape_bitcoin_htlc(
            permit.hello(),
            hns_marketplace_protocol::SwapAssetSide::Offered,
        )
        .expect("bitcoin binding");
        let maker_key = shared
            .try_with_store(|store| {
                hns_wallet_market::derive_local_direct_maker_key(
                    store,
                    &policy,
                    maker_id,
                    offer.offer.session_id,
                )
                .map(|(key, _)| key)
            })
            .expect("maker key");
        let mut funding_status = SwapFundingStatus {
            header: SignedObjectHeader {
                version: permit.hello().header.version,
                network: permit.hello().header.network,
                pair: permit.hello().header.pair,
                signer_public_key: [0; 33],
                sequence: permit.hello().header.sequence + 2,
                // The sender is one second ahead of the receiver. Mobile
                // devices with network-synchronized clocks can legitimately
                // have this small offset, and direct delivery can be faster
                // than the skew.
                created_at: START + 50,
                expires_at: permit.hello().header.expires_at,
            },
            swap_session_id: permit.hello().swap_session_id,
            chain: ChainId::BITCOIN,
            lock_commitment: permit.hello().offered_lock_commitment,
            transaction_id: [9; 32],
            output_index: 0,
            amount: permit.hello().offered_amount,
            confirmations: 0,
            state: FundingState::Broadcast,
            signature: [0; 64],
        };
        maker_key
            .sign_funding_status(&mut funding_status, permit.hello(), START + 50)
            .expect("sign funding locator");
        let funding_envelope = CrossChainMessage::SwapFundingStatus(funding_status)
            .encode_envelope(0)
            .expect("funding locator envelope");
        assert_eq!(
            taker_controller
                .admit_direct_envelope(&funding_envelope, START + 49)
                .expect("admit funding locator"),
            None
        );
        taker_shared
            .try_with_store(|store| {
                let record = load_shakescape_direct_swap(store, &policy, offer.offer.session_id)?
                    .expect("session record");
                assert_eq!(record.peer_funding_statuses.len(), 1);
                assert_eq!(
                    record.peer_funding_statuses[0].status.transaction_id,
                    [9; 32]
                );
                Ok::<_, hns_wallet_market::MarketError>(())
            })
            .expect("persisted peer funding locator");
        assert_eq!(
            controller
                .apply_local_verified_bitcoin_funding(
                    offer.offer.session_id,
                    hns_wallet_bitcoin_kyoto::VerifiedBitcoinLock {
                        funding_txid: hns_wallet_types::TransactionHash::new([9; 32]),
                        output_index: 0,
                        value_sats: binding.value_sats,
                        confirmation_count: 1,
                        htlc: binding.htlc.clone(),
                    },
                    START + 50,
                )
                .expect("verified funding"),
            SwapState::FirstFunded
        );
        assert_eq!(
            taker_controller
                .apply_local_verified_bitcoin_funding(
                    offer.offer.session_id,
                    hns_wallet_bitcoin_kyoto::VerifiedBitcoinLock {
                        funding_txid: hns_wallet_types::TransactionHash::new([9; 32]),
                        output_index: 0,
                        value_sats: binding.value_sats,
                        confirmation_count: 1,
                        htlc: binding.htlc.clone(),
                    },
                    START + 50,
                )
                .expect("taker independently verifies funding"),
            SwapState::FirstFunded
        );
        assert!(
            controller
                .pending_second_hns_funding_verifications()
                .expect("maker HNS verification candidates")
                .is_empty(),
            "the BTC maker must wait for the remote HNS transaction locator"
        );
        let local_hns_recovery = taker_controller
            .pending_second_hns_funding_verifications()
            .expect("local HNS recovery candidate");
        assert_eq!(local_hns_recovery.len(), 1);
        assert_eq!(local_hns_recovery[0].funding_transaction(), None);
        let hns_permit = taker_controller
            .authorize_local_hns_second_funding(offer.offer.session_id, START + 51)
            .expect("ordered HNS funding permit");
        assert_eq!(
            hns_permit.hello().swap_session_id,
            offer.offer.session_id.into_bytes()
        );
        assert_eq!(hns_permit.hns_fee_reserve_dollarydoos(), 10_000);
        assert_eq!(
            taker_controller
                .durable_executions()
                .expect("taker execution")[0]
                .state,
            SwapState::SecondFundingPending
        );
        let funded = controller.durable_executions().expect("funded execution");
        assert_eq!(funded[0].state, SwapState::FirstFunded);
        assert!(funded[0].first_funding_confirmed);
        assert_eq!(
            controller
                .reserved_bitcoin_sats(START + 50)
                .expect("funded reservation released"),
            0
        );
        assert!(
            controller
                .authorize_local_btc_first_funding(offer.offer.session_id, START + 621)
                .is_err()
        );

        let hns_binding = hns_permit
            .hello()
            .build_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Received,
                hns_permit.hello().maker_settlement_public_key,
                hns_permit.hello().taker_settlement_public_key,
            )
            .expect("HNS binding");
        let hns_lock = hns_wallet_chain_api::VerifiedLock {
            module: hns_wallet_types::ModuleId::Handshake,
            session_id: offer.offer.session_id,
            funding_id: hns_wallet_types::TransactionHash::new([0x71; 32]),
            amount: hns_wallet_types::Amount::new(
                hns_wallet_types::WalletAsset::Hns,
                u128::from(hns_binding.descriptor.value.get()),
            ),
            hashlock: hns_wallet_types::ObjectHash::new(hns_binding.descriptor.hashlock),
            absolute_timelock: u64::from(hns_binding.descriptor.refund_locktime),
            confirmation_count: 1,
            evidence_hash: hns_wallet_types::ObjectHash::new([0x72; 32]),
        };
        let mut hns_funding_status = SwapFundingStatus {
            header: SignedObjectHeader {
                version: hns_permit.hello().header.version,
                network: hns_permit.hello().header.network,
                pair: hns_permit.hello().header.pair,
                signer_public_key: [0; 33],
                sequence: hns_permit.hello().header.sequence + 2,
                created_at: START + 59,
                expires_at: hns_permit.hello().header.expires_at,
            },
            swap_session_id: hns_permit.hello().swap_session_id,
            chain: ChainId::HANDSHAKE,
            lock_commitment: hns_permit.hello().received_lock_commitment,
            transaction_id: [0x71; 32],
            output_index: 0,
            amount: hns_permit.hello().received_amount,
            confirmations: 0,
            state: FundingState::Broadcast,
            signature: [0; 64],
        };
        hns_permit
            .settlement_key()
            .sign_funding_status(&mut hns_funding_status, hns_permit.hello(), START + 59)
            .expect("sign HNS funding locator");
        let hns_funding_envelope = CrossChainMessage::SwapFundingStatus(hns_funding_status)
            .encode_envelope(0)
            .expect("HNS funding locator envelope");
        assert_eq!(
            controller
                .admit_direct_envelope(&hns_funding_envelope, START + 59)
                .expect("maker admits HNS funding locator"),
            None
        );
        let remote_hns_verification = controller
            .pending_second_hns_funding_verifications()
            .expect("maker remote HNS verification candidate");
        assert_eq!(remote_hns_verification.len(), 1);
        assert_eq!(
            remote_hns_verification[0].funding_transaction(),
            Some(hns_wallet_types::TransactionHash::new([0x71; 32]))
        );
        assert_eq!(
            controller
                .apply_local_verified_hns_funding(
                    offer.offer.session_id,
                    hns_lock.clone(),
                    START + 60,
                )
                .expect("maker verifies HNS funding"),
            SwapState::BothFunded
        );
        assert_eq!(
            taker_controller
                .apply_local_verified_hns_funding(offer.offer.session_id, hns_lock, START + 60,)
                .expect("taker verifies HNS funding"),
            SwapState::BothFunded
        );

        let maker_hns_redeem = controller
            .authorize_local_hns_redeem(offer.offer.session_id)
            .expect("maker HNS redeem permit");
        assert_eq!(
            maker_hns_redeem.action(),
            MobileShakescapeSettlementAction::Redeem
        );
        assert!(maker_hns_redeem.preimage.is_some());
        let known_preimage = *maker_hns_redeem
            .preimage
            .as_ref()
            .expect("maker preimage")
            .expose_for_settlement();
        assert!(
            taker_controller
                .authorize_local_hns_redeem(offer.offer.session_id)
                .is_err()
        );
        let taker_hns_refund = taker_controller
            .authorize_local_hns_refund(offer.offer.session_id)
            .expect("taker HNS refund permit");
        assert_eq!(taker_hns_refund.fee_reserve(), 10_000);
        assert!(
            controller
                .authorize_local_hns_refund(offer.offer.session_id)
                .is_err()
        );
        let maker_bitcoin_refund = controller
            .authorize_local_bitcoin_refund(offer.offer.session_id)
            .expect("maker Bitcoin refund permit");
        assert_eq!(maker_bitcoin_refund.fee_reserve(), 1_000);
        assert!(
            taker_controller
                .authorize_local_bitcoin_refund(offer.offer.session_id)
                .is_err()
        );
        assert!(
            controller
                .authorize_local_bitcoin_redeem(offer.offer.session_id)
                .is_err()
        );
        assert!(
            taker_controller
                .authorize_local_bitcoin_redeem(offer.offer.session_id)
                .is_err()
        );

        assert!(
            controller
                .apply_local_verified_hns_spend(
                    offer.offer.session_id,
                    hns_wallet_hns::VerifiedNativeHtlcSpend::Redeem {
                        transaction: hns_wallet_types::TransactionHash::new([0x81; 32]),
                        confirmation_count: 1,
                        preimage: hns_wallet_chain_api::Preimage::new([0xaa; 32]),
                    },
                    START + 70,
                )
                .is_err()
        );
        let hns_redeem = || hns_wallet_hns::VerifiedNativeHtlcSpend::Redeem {
            transaction: hns_wallet_types::TransactionHash::new([0x82; 32]),
            confirmation_count: 1,
            preimage: hns_wallet_chain_api::Preimage::new(known_preimage),
        };
        assert_eq!(
            controller
                .apply_local_verified_hns_spend(offer.offer.session_id, hns_redeem(), START + 71,)
                .expect("maker verifies HNS redeem"),
            SwapState::SecretObserved
        );
        assert_eq!(
            taker_controller
                .apply_local_verified_hns_spend(offer.offer.session_id, hns_redeem(), START + 71,)
                .expect("taker verifies HNS redeem"),
            SwapState::SecretObserved
        );
        assert!(
            taker_controller
                .authorize_local_hns_refund(offer.offer.session_id)
                .is_err()
        );
        let taker_bitcoin_redeem = taker_controller
            .authorize_local_bitcoin_redeem(offer.offer.session_id)
            .expect("taker Bitcoin redeem permit after secret observation");
        assert_eq!(
            *taker_bitcoin_redeem
                .preimage
                .as_ref()
                .expect("observed preimage")
                .expose_for_settlement(),
            known_preimage
        );
        assert!(
            controller
                .authorize_local_bitcoin_redeem(offer.offer.session_id)
                .is_err()
        );

        let bitcoin_redeem = hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpendObservation {
            spend: hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcChainSpend {
                txid: hns_wallet_types::TransactionHash::new([0x91; 32]),
                wtxid: [0x92; 32],
                branch: hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Redeem,
                revealed_preimage: Some(known_preimage),
            },
            confirmation_count: 1,
        };
        assert_eq!(
            controller
                .apply_local_verified_bitcoin_spend(
                    offer.offer.session_id,
                    bitcoin_redeem,
                    START + 80,
                )
                .expect("maker verifies Bitcoin redeem"),
            SwapState::Completed
        );
        assert_eq!(
            taker_controller
                .apply_local_verified_bitcoin_spend(
                    offer.offer.session_id,
                    bitcoin_redeem,
                    START + 80,
                )
                .expect("taker verifies Bitcoin redeem"),
            SwapState::Completed
        );
        assert!(
            taker_controller
                .authorize_local_bitcoin_redeem(offer.offer.session_id)
                .is_err()
        );
        assert!(
            controller
                .authorize_local_bitcoin_refund(offer.offer.session_id)
                .is_err()
        );
    }
}
