//! Persisted direct Denuo HNS/BTC session admission for installed wallets.

use hns_marketplace_protocol::{CrossChainMessage, SwapAssetSide, SwapSessionHello};
use hns_wallet_bitcoin_kyoto::build_denuo_bitcoin_htlc;
use hns_wallet_hns::HnsDirectDenuoPeer;
use hns_wallet_market::{
    DenuoBtcForHnsOfferRequest, DenuoDirectOfferAdmission, DenuoDirectOfferCancellationAdmission,
    DenuoDirectSwapAdmission, DenuoDirectSwapPolicy, DenuoLocalDirectOffer, SwapState,
    VerifiedEvidence, WalletStoreJournal, admit_denuo_direct_offer,
    admit_denuo_direct_offer_cancellation, admit_denuo_direct_offer_take,
    admit_denuo_direct_swap_hello, admit_denuo_direct_swap_proposal,
    admit_denuo_direct_swap_watch_ready, cancel_denuo_local_direct_offer,
    create_denuo_btc_for_hns_offer, denuo_direct_offer_inventory, denuo_execution_workflow_id,
    list_denuo_executions, list_local_denuo_direct_offers, list_local_denuo_direct_takes,
    load_denuo_direct_offer, load_denuo_direct_swap, open_denuo_execution,
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

/// Rust-only authority passed from the accepted Denuo session controller to
/// the Bitcoin controller. Its fields remain private so Kotlin/Swift cannot
/// replace signed terms, the session identifier, or the reserved fee cap.
pub struct MobileDenuoBitcoinFundingPermit {
    hello: SwapSessionHello,
    bitcoin_fee_reserve_sats: u64,
}

pub struct MobileDenuoHnsFundingPermit {
    hello: SwapSessionHello,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    hns_fee_reserve_dollarydoos: u64,
}

pub struct MobileDenuoBitcoinWatchPermit {
    hello: SwapSessionHello,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
}

pub struct MobileDenuoHnsVerificationPermit {
    hello: SwapSessionHello,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobileDenuoSettlementAction {
    Redeem,
    Refund,
}

pub struct MobileDenuoHnsSettlementPermit {
    hello: SwapSessionHello,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    preimage: Option<hns_wallet_chain_api::Preimage>,
    action: MobileDenuoSettlementAction,
    fee_reserve: u64,
}

pub struct MobileDenuoBitcoinSettlementPermit {
    hello: SwapSessionHello,
    settlement_key: hns_wallet_market::CrossChainSwapKey,
    preimage: Option<hns_wallet_chain_api::Preimage>,
    action: MobileDenuoSettlementAction,
    fee_reserve: u64,
}

impl MobileDenuoHnsSettlementPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }
    pub(crate) fn take_preimage(&mut self) -> Option<hns_wallet_chain_api::Preimage> {
        self.preimage.take()
    }
    pub(crate) const fn action(&self) -> MobileDenuoSettlementAction {
        self.action
    }
    pub(crate) const fn fee_reserve(&self) -> u64 {
        self.fee_reserve
    }
}

impl MobileDenuoBitcoinSettlementPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }
    pub(crate) fn take_preimage(&mut self) -> Option<hns_wallet_chain_api::Preimage> {
        self.preimage.take()
    }
    pub(crate) const fn action(&self) -> MobileDenuoSettlementAction {
        self.action
    }
    pub(crate) const fn fee_reserve(&self) -> u64 {
        self.fee_reserve
    }
}

impl MobileDenuoHnsVerificationPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }

    pub const fn session_id(&self) -> hns_wallet_types::SessionId {
        hns_wallet_types::SessionId::new(self.hello.swap_session_id)
    }
}

impl MobileDenuoBitcoinWatchPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }
}

impl MobileDenuoHnsFundingPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }

    pub(crate) const fn settlement_key(&self) -> &hns_wallet_market::CrossChainSwapKey {
        &self.settlement_key
    }

    pub(crate) const fn hns_fee_reserve_dollarydoos(&self) -> u64 {
        self.hns_fee_reserve_dollarydoos
    }
}

impl MobileDenuoBitcoinFundingPermit {
    pub(crate) const fn hello(&self) -> &SwapSessionHello {
        &self.hello
    }

    pub(crate) const fn bitcoin_fee_reserve_sats(&self) -> u64 {
        self.bitcoin_fee_reserve_sats
    }
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

/// Non-sensitive durable execution projection for native recovery UI. It
/// contains no transaction bytes, preimage, derivation path, peer endpoint, or
/// private key material; chain actions remain behind explicit approvals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileDenuoExecutionSummary {
    pub session_id: String,
    pub revision: u64,
    pub state: SwapState,
    pub first_chain: String,
    pub second_chain: String,
    pub offered_asset: String,
    pub offered_amount: u128,
    pub received_asset: String,
    pub received_amount: u128,
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

    pub fn reserved_bitcoin_sats(&self, now_unix: u64) -> Result<u64, MobileWalletError> {
        self.store
            .try_with_store(|store| {
                hns_wallet_market::reserved_local_denuo_btc_maker_sats(
                    store,
                    &self.policy,
                    self.wallet_id,
                    now_unix,
                )
            })
            .map_err(MobileWalletError::from)
    }

    pub fn durable_executions(
        &self,
    ) -> Result<Vec<MobileDenuoExecutionSummary>, MobileWalletError> {
        self.store
            .try_with_store(|store| list_denuo_executions(store, &self.policy))
            .map_err(MobileWalletError::from)?
            .into_iter()
            .map(execution_summary)
            .collect()
    }

    /// Identify exact sessions whose first-chain Bitcoin lock still needs
    /// locally verified confirmation. The platform may use this closed set to
    /// query Kyoto after a sync, then feed only checkpoint-bound locks through
    /// `apply_local_verified_bitcoin_funding`.
    pub fn pending_first_bitcoin_funding_sessions(
        &self,
    ) -> Result<Vec<hns_wallet_types::SessionId>, MobileWalletError> {
        self.store
            .try_with_store(|store| list_denuo_executions(store, &self.policy))
            .map_err(MobileWalletError::from)
            .map(|sessions| {
                sessions
                    .into_iter()
                    .filter(|session| {
                        session.state == SwapState::FirstFundingPending
                            && session.first_module == hns_wallet_types::ModuleId::Bitcoin
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
    ) -> Result<Option<MobileDenuoBitcoinWatchPermit>, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        let candidates = self
            .store
            .try_with_store(|store| {
                let takes = list_local_denuo_direct_takes(store, &policy, wallet_id)?;
                let mut sessions = Vec::new();
                for take in takes {
                    let record = load_denuo_direct_swap(store, &policy, take.session_id)?;
                    let execution =
                        hns_wallet_market::load_denuo_execution(store, &policy, take.session_id)?;
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

    pub fn pending_second_hns_funding_verifications(
        &self,
    ) -> Result<Vec<MobileDenuoHnsVerificationPermit>, MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store(|store| {
                list_denuo_executions(store, &policy)?
                    .into_iter()
                    .filter(|session| {
                        session.state == SwapState::SecondFundingPending
                            && session.second_module == hns_wallet_types::ModuleId::Handshake
                    })
                    .map(|session| {
                        load_denuo_direct_swap(store, &policy, session.id)?
                            .and_then(|record| record.hello)
                            .map(|hello| MobileDenuoHnsVerificationPermit { hello })
                            .ok_or(hns_wallet_market::MarketError::CorruptDenuoDirectSwap)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileWalletError::from)
    }

    pub fn pending_hns_spend_verifications(
        &self,
    ) -> Result<Vec<MobileDenuoHnsVerificationPermit>, MobileWalletError> {
        let policy = self.policy;
        self.store
            .try_with_store(|store| {
                list_denuo_executions(store, &policy)?
                    .into_iter()
                    .filter(|session| {
                        session.second_module == hns_wallet_types::ModuleId::Handshake
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
                        load_denuo_direct_swap(store, &policy, session.id)?
                            .and_then(|record| record.hello)
                            .map(|hello| MobileDenuoHnsVerificationPermit { hello })
                            .ok_or(hns_wallet_market::MarketError::CorruptDenuoDirectSwap)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileWalletError::from)
    }

    pub fn pending_bitcoin_spend_sessions(
        &self,
    ) -> Result<Vec<hns_wallet_types::SessionId>, MobileWalletError> {
        self.store
            .try_with_store(|store| list_denuo_executions(store, &self.policy))
            .map_err(MobileWalletError::from)
            .map(|sessions| {
                sessions
                    .into_iter()
                    .filter(|session| {
                        session.first_module == hns_wallet_types::ModuleId::Bitcoin
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

    /// Validate both canonical HTLC refund branches and prove this wallet owns
    /// the BTC refund key before allowing first-chain funding preparation.
    /// The durable execution advances through restart-safe checkpoints to
    /// `FirstFundingPending`; retries resume at either checkpoint and return
    /// the same immutable context.
    pub fn authorize_local_btc_first_funding(
        &mut self,
        session_id: hns_wallet_types::SessionId,
        now_unix: u64,
    ) -> Result<MobileDenuoBitcoinFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .clone()
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                hello
                    .verify_new_funding_at(policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hello.offered_asset != hns_marketplace_protocol::AssetId::BTC
                    || hello.received_asset != hns_marketplace_protocol::AssetId::HNS
                    || hello.first_funding_chain != hns_marketplace_protocol::ChainId::BITCOIN
                    || hello.swap_session_id != session_id.into_bytes()
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let ready = record
                    .first_chain_watch_ready
                    .as_ref()
                    .ok_or(hns_wallet_market::MarketError::InvalidTransition)?;
                ready
                    .verify_for_session(&hello, policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                let (maker_key, bitcoin_fee_reserve_sats) =
                    hns_wallet_market::derive_local_btc_for_hns_maker_key(
                        store, &policy, wallet_id, session_id,
                    )?;
                let bitcoin = build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if bitcoin.commitment.into_bytes() != hello.offered_lock_commitment
                    || bitcoin.htlc.refund_public_key != maker_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let mut execution = open_denuo_execution(store, &policy, session_id, now_unix)?;
                if execution.state == SwapState::TermsFrozen {
                    let workflow_id = denuo_execution_workflow_id(session_id);
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id,
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::RefundsValidated, now_unix, &mut journal)?;
                }
                if execution.state == SwapState::RefundsPrepared {
                    let workflow_id = denuo_execution_workflow_id(session_id);
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
                Ok(MobileDenuoBitcoinFundingPermit {
                    hello,
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
    ) -> Result<MobileDenuoBitcoinWatchPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                hello
                    .verify_new_funding_at(policy.network(), now_unix)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hello.offered_asset != hns_marketplace_protocol::AssetId::BTC
                    || hello.received_asset != hns_marketplace_protocol::AssetId::HNS
                    || hello.first_funding_chain != hns_marketplace_protocol::ChainId::BITCOIN
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let (taker_key, _) = hns_wallet_market::derive_local_hns_for_btc_taker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let bitcoin = build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if bitcoin.commitment.into_bytes() != hello.offered_lock_commitment {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment
                    || hns.descriptor.refund_public_key != taker_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let execution = open_denuo_execution(store, &policy, session_id, now_unix)?;
                if !matches!(
                    execution.state,
                    SwapState::TermsFrozen
                        | SwapState::RefundsPrepared
                        | SwapState::FirstFundingPending
                ) {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                Ok(MobileDenuoBitcoinWatchPermit {
                    hello,
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
        permit: MobileDenuoBitcoinWatchPermit,
        peer: &mut HnsDirectDenuoPeer,
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
        permit: MobileDenuoBitcoinWatchPermit,
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
                    .ok_or(MobileWalletError::InvalidDenuoSessionMessage)?,
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
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        let message = CrossChainMessage::SwapWatchReady(ready);
        let envelope = message
            .encode_envelope(0)
            .map_err(|_| MobileWalletError::InvalidDenuoSessionMessage)?;
        let policy = self.policy;
        let session_id = hns_wallet_types::SessionId::new(hello.swap_session_id);
        self.store
            .try_with_store_mut(|store| {
                admit_denuo_direct_swap_watch_ready(store, &policy, &envelope, now_unix)?;
                let mut execution = open_denuo_execution(store, &policy, session_id, now_unix)?;
                if execution.state == SwapState::TermsFrozen {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: denuo_execution_workflow_id(session_id),
                        updated_at_unix: now_unix,
                    };
                    execution.apply(VerifiedEvidence::RefundsValidated, now_unix, &mut journal)?;
                }
                if execution.state == SwapState::RefundsPrepared {
                    let mut journal = WalletStoreJournal {
                        store,
                        workflow_id: denuo_execution_workflow_id(session_id),
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
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                hns_wallet_market::apply_locally_verified_denuo_funding(
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
        let policy = self.policy;
        self.store
            .try_with_store_mut(|store| {
                hns_wallet_market::apply_locally_verified_denuo_funding(
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
                    hns_wallet_market::apply_locally_verified_denuo_refund(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Hns(spend),
                        now_unix,
                    )
                } else {
                    hns_wallet_market::apply_locally_verified_denuo_first_redemption(
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
                    hns_wallet_market::apply_locally_verified_denuo_refund(
                        store,
                        &policy,
                        session_id,
                        hns_wallet_market::LocallyVerifiedSwapSpend::Bitcoin(spend),
                        now_unix,
                    )
                } else {
                    hns_wallet_market::apply_locally_verified_denuo_second_redemption(
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
    ) -> Result<MobileDenuoHnsFundingPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store_mut(|store| {
                let execution =
                    hns_wallet_market::load_denuo_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                if execution.state != SwapState::FirstFunded
                    || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                    || execution.second_module != hns_wallet_types::ModuleId::Handshake
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                hello
                    .verify_agreement(policy.network())
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
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
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hns.descriptor_hash != hello.received_lock_commitment
                    || hns.descriptor.refund_public_key != settlement_key.public_key()
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                let workflow_id = denuo_execution_workflow_id(session_id);
                let mut execution = execution;
                let mut journal = WalletStoreJournal {
                    store,
                    workflow_id,
                    updated_at_unix: now_unix,
                };
                execution.apply(VerifiedEvidence::SecondFundingReady, now_unix, &mut journal)?;
                Ok(MobileDenuoHnsFundingPermit {
                    hello,
                    settlement_key,
                    hns_fee_reserve_dollarydoos,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_hns_redeem(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileDenuoHnsSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_denuo_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                if execution.state != SwapState::BothFunded
                    || execution.second_module != hns_wallet_types::ModuleId::Handshake
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                let (key, _) = hns_wallet_market::derive_local_btc_for_hns_maker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let preimage =
                    hns_wallet_market::load_denuo_btc_for_hns_maker_preimage(store, session_id)?
                        .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hns.descriptor.receiver_public_key != key.public_key()
                    || hns.descriptor.hashlock
                        != hns_swap::HnsHtlc::hash_preimage(preimage.expose_for_settlement())
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                Ok(MobileDenuoHnsSettlementPermit {
                    hello,
                    settlement_key: key,
                    preimage: Some(preimage),
                    action: MobileDenuoSettlementAction::Redeem,
                    fee_reserve: u64::MAX,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_hns_refund(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileDenuoHnsSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_denuo_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                if execution.second_funding.is_none()
                    || execution.second_module != hns_wallet_types::ModuleId::Handshake
                    || execution.state != SwapState::BothFunded
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                let (key, fee_reserve) = hns_wallet_market::derive_local_hns_for_btc_taker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let hns = hello
                    .build_hns_htlc(
                        SwapAssetSide::Received,
                        hello.maker_settlement_public_key,
                        hello.taker_settlement_public_key,
                    )
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if hns.descriptor.refund_public_key != key.public_key() {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                Ok(MobileDenuoHnsSettlementPermit {
                    hello,
                    settlement_key: key,
                    preimage: None,
                    action: MobileDenuoSettlementAction::Refund,
                    fee_reserve,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_bitcoin_redeem(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileDenuoBitcoinSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_denuo_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                if execution.state != SwapState::SecretObserved
                    || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                let (key, _) = hns_wallet_market::derive_local_hns_for_btc_taker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let preimage =
                    hns_wallet_market::load_locally_verified_denuo_preimage(store, session_id)?
                        .ok_or(hns_wallet_market::MarketError::InvalidEvidence)?;
                let bitcoin = build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if bitcoin.htlc.receiver_public_key != key.public_key()
                    || bitcoin.htlc.hashlock
                        != hns_swap::HnsHtlc::hash_preimage(preimage.expose_for_settlement())
                {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                Ok(MobileDenuoBitcoinSettlementPermit {
                    hello,
                    settlement_key: key,
                    preimage: Some(preimage),
                    action: MobileDenuoSettlementAction::Redeem,
                    fee_reserve: u64::MAX,
                })
            })
            .map_err(MobileWalletError::from)
    }

    pub fn authorize_local_bitcoin_refund(
        &self,
        session_id: hns_wallet_types::SessionId,
    ) -> Result<MobileDenuoBitcoinSettlementPermit, MobileWalletError> {
        let policy = self.policy;
        let wallet_id = self.wallet_id;
        self.store
            .try_with_store(|store| {
                let execution =
                    hns_wallet_market::load_denuo_execution(store, &policy, session_id)?
                        .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                if execution.first_funding.is_none()
                    || execution.first_module != hns_wallet_types::ModuleId::Bitcoin
                    || !matches!(
                        execution.state,
                        SwapState::FirstFunded
                            | SwapState::SecondFundingPending
                            | SwapState::BothFunded
                            | SwapState::FirstRedeemed
                            | SwapState::SecretObserved
                    )
                {
                    return Err(hns_wallet_market::MarketError::InvalidTransition);
                }
                let record = load_denuo_direct_swap(store, &policy, session_id)?
                    .ok_or(hns_wallet_market::MarketError::UnknownDenuoDirectSwap)?;
                let hello = record
                    .hello
                    .ok_or(hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                let (key, fee_reserve) = hns_wallet_market::derive_local_btc_for_hns_maker_key(
                    store, &policy, wallet_id, session_id,
                )?;
                let bitcoin = build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Offered)
                    .map_err(|_| hns_wallet_market::MarketError::InvalidDenuoDirectSwap)?;
                if bitcoin.htlc.refund_public_key != key.public_key() {
                    return Err(hns_wallet_market::MarketError::InvalidDenuoDirectSwap);
                }
                Ok(MobileDenuoBitcoinSettlementPermit {
                    hello,
                    settlement_key: key,
                    preimage: None,
                    action: MobileDenuoSettlementAction::Refund,
                    fee_reserve,
                })
            })
            .map_err(MobileWalletError::from)
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
                CrossChainMessage::SwapWatchReady(_) => {
                    admit_denuo_direct_swap_watch_ready(store, &self.policy, envelope, now_unix)
                        .map(|admission| Some(MobileDenuoDirectAdmission::Swap(admission)))
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
            | CrossChainMessage::SwapRefundStatus(_)
            | CrossChainMessage::SwapWatchReady(_) => {
                report.admission = self.admit_direct_envelope(envelope, now_unix)?;
            }
        }
        Ok(report)
    }
}

fn summary(offer: DenuoLocalDirectOffer) -> Result<MobileBtcForHnsOfferSummary, MobileWalletError> {
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

fn execution_summary(
    session: hns_wallet_market::SwapSession,
) -> Result<MobileDenuoExecutionSummary, MobileWalletError> {
    let chain = |module| -> Result<String, MobileWalletError> {
        match module {
            hns_wallet_types::ModuleId::Bitcoin => Ok("bitcoin".to_owned()),
            hns_wallet_types::ModuleId::Handshake => Ok("handshake".to_owned()),
            hns_wallet_types::ModuleId::Ethereum => {
                Err(MobileWalletError::InvalidDenuoSessionMessage)
            }
        }
    };
    let asset = |asset| -> Result<String, MobileWalletError> {
        match asset {
            hns_wallet_types::WalletAsset::Btc => Ok("btc".to_owned()),
            hns_wallet_types::WalletAsset::Hns => Ok("hns".to_owned()),
            hns_wallet_types::WalletAsset::Eth => {
                Err(MobileWalletError::InvalidDenuoSessionMessage)
            }
        }
    };
    Ok(MobileDenuoExecutionSummary {
        session_id: super::lowercase_hex(session.id.as_bytes()),
        revision: session.revision,
        state: session.state,
        first_chain: chain(session.first_module)?,
        second_chain: chain(session.second_module)?,
        offered_asset: asset(session.offered.asset)?,
        offered_amount: session.offered.base_units.get(),
        received_asset: asset(session.received.asset)?,
        received_amount: session.received.base_units.get(),
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
        DenuoBtcForHnsMakerProposalRequest, DenuoBtcForHnsOfferRequest,
        DenuoDirectOfferBoardPolicy, DenuoHnsForBtcTakeRequest, VerifiedEvidence,
        WalletStoreJournal, accept_denuo_hns_for_btc_maker_proposal, admit_denuo_direct_offer,
        admit_denuo_direct_offer_take, admit_denuo_direct_swap_hello,
        admit_denuo_direct_swap_proposal, create_denuo_btc_for_hns_maker_proposal,
        create_denuo_btc_for_hns_offer, create_denuo_hns_for_btc_take, denuo_execution_workflow_id,
        load_denuo_direct_offer, open_denuo_execution,
    };
    use hns_wallet_store::{RECOVERY_SEED_BYTES, SecretKind, WalletStore};

    use super::*;

    const PASSPHRASE: &str = "mobile direct funding authorization test";
    const START: u64 = 1_700_000_000;

    fn policy() -> DenuoDirectSwapPolicy {
        DenuoDirectSwapPolicy::new(
            DenuoDirectOfferBoardPolicy::new(NetworkBinding {
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
    fn only_the_local_btc_maker_can_cross_the_durable_first_funding_gate() {
        let policy = policy();
        let maker_id = WalletId::new([0x21; 16]);
        let taker_id = WalletId::new([0x22; 16]);
        let mut maker = seeded_store(maker_id, 0x31);
        let mut taker = seeded_store(taker_id, 0x41);
        let offer = create_denuo_btc_for_hns_offer(
            &mut maker,
            &policy.board_policy(),
            DenuoBtcForHnsOfferRequest {
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
        let signed_offer = load_denuo_direct_offer(
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
        admit_denuo_direct_offer(&mut taker, &policy.board_policy(), &offer_envelope, START)
            .expect("admit offer");
        let take = create_denuo_hns_for_btc_take(
            &mut taker,
            &policy,
            DenuoHnsForBtcTakeRequest {
                wallet_id: taker_id,
                offer_id: offer.offer.offer_id,
                hns_fee_reserve_dollarydoos: 10_000,
                created_at_unix: START + 10,
                expires_at_unix: START + 10_000,
                nonce: [8; 32],
            },
        )
        .expect("take");
        admit_denuo_direct_offer_take(&mut maker, &policy, &take.envelope, START + 10)
            .expect("maker admits take");
        let proposal = create_denuo_btc_for_hns_maker_proposal(
            &mut maker,
            &policy,
            DenuoBtcForHnsMakerProposalRequest {
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
        admit_denuo_direct_swap_proposal(&mut taker, &policy, &proposal.envelope, START + 20)
            .expect("taker admits proposal");
        let accepted = accept_denuo_hns_for_btc_maker_proposal(
            &mut taker,
            &policy,
            taker_id,
            offer.offer.session_id,
            START + 30,
        )
        .expect("accept");
        admit_denuo_direct_swap_hello(&mut maker, &policy, &accepted.envelope, START + 30)
            .expect("maker admits hello");

        let taker_shared = SharedWalletStore::new(taker);
        let mut taker_controller =
            MobileDenuoSessionController::new(taker_shared.clone(), policy, taker_id);
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
        let ready_envelope = ready.encode_envelope(0).expect("watch-ready envelope");
        admit_denuo_direct_swap_watch_ready(&mut maker, &policy, &ready_envelope, START + 34)
            .expect("maker admits receiver watch readiness");

        // Simulate termination after only the first durable funding gate.
        let mut interrupted =
            open_denuo_execution(&mut maker, &policy, offer.offer.session_id, START + 35)
                .expect("execution");
        let mut journal = WalletStoreJournal {
            store: &mut maker,
            workflow_id: denuo_execution_workflow_id(offer.offer.session_id),
            updated_at_unix: START + 35,
        };
        interrupted
            .apply(VerifiedEvidence::RefundsValidated, START + 35, &mut journal)
            .expect("refund checkpoint");
        assert_eq!(interrupted.state, SwapState::RefundsPrepared);

        let shared = SharedWalletStore::new(maker);
        let mut controller = MobileDenuoSessionController::new(shared.clone(), policy, maker_id);
        let resumed = controller.durable_executions().expect("durable executions");
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].state, SwapState::RefundsPrepared);
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
                            denuo_execution_workflow_id(offer.offer.session_id),
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
            10_000
        );
        controller
            .authorize_local_btc_first_funding(offer.offer.session_id, START + 41)
            .expect("idempotent permit");
        let binding = build_denuo_bitcoin_htlc(
            permit.hello(),
            hns_marketplace_protocol::SwapAssetSide::Offered,
        )
        .expect("bitcoin binding");
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
            MobileDenuoSettlementAction::Redeem
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
            spend: hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpend {
                txid: hns_wallet_types::TransactionHash::new([0x91; 32]),
                wtxid: [0x92; 32],
                fee_sats: 400,
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
