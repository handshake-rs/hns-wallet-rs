//! Direct Kyoto Bitcoin ownership for the installed mobile wallet.
//!
//! This controller deliberately shares the HNS wallet's authenticated store
//! and protected BIP-39 seed. Kyoto peers provide transport only; compact
//! filters, headers, descriptor state, and the restart journal remain local.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network as BitcoinNetwork;
use bdk_wallet::bitcoin::Transaction;
use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::hashes::Hash;
use hns_wallet_bitcoin_kyoto::{
    BIP39_SEED_BYTES, BitcoinBirthdaySource, BitcoinBroadcastReceipt,
    BitcoinBroadcastRecoverySummary, BitcoinCheckpoint, BitcoinHtlcWatchRequest,
    BitcoinTransactionRecord, BitcoinWalletError, EncryptedPersistedBitcoinWallet, HtlcSpendBranch,
    KyotoRuntimeConfig, KyotoShutdownHandle, KyotoSupervisor, KyotoSyncProgressHandle,
    KyotoSyncReceipt, KyotoTipDiscovery, KyotoWalletState, PreparedBitcoinHtlcFunding,
    StoredKyotoWalletState, VerifiedBitcoinLock, authorize_native_send,
    bitcoin_broadcast_recovery_summary, bitcoin_value_runtime_permit,
    build_shakescape_bitcoin_htlc, create_persisted_descriptor_wallet_from_seed,
    initialize_pristine_wallet_at_creation_tip, initialize_pristine_wallet_at_recovery_checkpoint,
    load_bitcoin_htlc_watch, load_persisted_descriptor_wallet_from_seed,
    monitor_kyoto_sync_progress, persist_prepared_bitcoin_broadcast,
    persist_prepared_bitcoin_htlc_spend_broadcast, prepare_bitcoin_htlc_funding_excluding,
    prepare_native_send_excluding, sign_bitcoin_htlc_spend_at_fee_rate_with_settlement_signer,
    unobserved_approved_broadcast_inputs, verify_htlc_funding, verify_signed_bitcoin_htlc_spend,
};
use hns_wallet_hns::{HnsNetwork, HnsRuntimeConfig};
use hns_wallet_store::{SecretKind, SharedWalletStore, WalletStore};
use hns_wallet_types::SessionId;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::{
    MobileShakescapeBitcoinFundingPermit, MobileShakescapeBitcoinSettlementPermit,
    MobileShakescapeBitcoinWatchPermit, MobileShakescapeSettlementAction, MobileWalletError,
};

const BITCOIN_RECOVERY_SCRIPT_INDEX: u32 = 1;
const BITCOIN_SEND_APPROVAL_LIFETIME_SECONDS: u64 = 300;
const MOBILE_ACTION_TOKEN_BYTES: usize = 32;
const BITCOIN_INITIALIZATION_VERSION: u8 = 1;
const BITCOIN_INITIALIZATION_ID_DOMAIN: &[u8] = b"hns-mobile-bitcoin-initialization/v1/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MobileBitcoinWalletOrigin {
    Generated,
    Restored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MobileBitcoinInitialization {
    origin: MobileBitcoinWalletOrigin,
    requested_recovery_height: Option<u32>,
}

impl MobileBitcoinInitialization {
    fn encode(self) -> [u8; 6] {
        let mut encoded = [0_u8; 6];
        encoded[0] = BITCOIN_INITIALIZATION_VERSION;
        encoded[1] = match self.origin {
            MobileBitcoinWalletOrigin::Generated => 1,
            MobileBitcoinWalletOrigin::Restored => 2,
        };
        encoded[2..].copy_from_slice(&self.requested_recovery_height.unwrap_or(0).to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, MobileWalletError> {
        if encoded.len() != 6 || encoded[0] != BITCOIN_INITIALIZATION_VERSION {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let origin = match encoded[1] {
            1 => MobileBitcoinWalletOrigin::Generated,
            2 => MobileBitcoinWalletOrigin::Restored,
            _ => return Err(MobileWalletError::InvalidBitcoinAction),
        };
        let height = u32::from_be_bytes(
            encoded[2..]
                .try_into()
                .map_err(|_| MobileWalletError::InvalidBitcoinAction)?,
        );
        Ok(Self {
            origin,
            requested_recovery_height: (height != 0).then_some(height),
        })
    }
}

fn bitcoin_initialization_id(account_id: &[u8]) -> Vec<u8> {
    let mut id = Vec::with_capacity(BITCOIN_INITIALIZATION_ID_DOMAIN.len() + account_id.len());
    id.extend_from_slice(BITCOIN_INITIALIZATION_ID_DOMAIN);
    id.extend_from_slice(account_id);
    id
}

pub(crate) fn persist_mobile_bitcoin_wallet_origin(
    store: &mut WalletStore,
    account_id: &[u8],
    origin: MobileBitcoinWalletOrigin,
    now_unix: u64,
) -> Result<(), MobileWalletError> {
    let record = MobileBitcoinInitialization {
        origin,
        requested_recovery_height: None,
    };
    store.put_secret(
        &bitcoin_initialization_id(account_id),
        SecretKind::MetadataKey,
        &record.encode(),
        now_unix,
    )?;
    Ok(())
}

/// Configuration for one wallet-owned Kyoto client. `data_dir` is an app
/// private directory, never a server endpoint or a hosted index state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileBitcoinDirectConfig {
    pub network: BitcoinNetwork,
    pub data_dir: PathBuf,
    pub required_peers: u8,
}

impl MobileBitcoinDirectConfig {
    pub fn for_hns_wallet(network: HnsNetwork, data_dir: PathBuf) -> Self {
        let network = Self::bitcoin_network_for_hns(network);
        Self {
            network,
            data_dir,
            required_peers: hns_wallet_bitcoin_kyoto::DEFAULT_REQUIRED_PEERS,
        }
    }

    /// The exact Bitcoin network binding paired with an HNS network by the
    /// installed direct wallet. The identifier and genesis come from the
    /// wallet's own Bitcoin library, not a peer, relay, or price source.
    pub fn direct_shakescape_counterchain(network: HnsNetwork) -> (u64, [u8; 32]) {
        let network = Self::bitcoin_network_for_hns(network);
        let network_id = match network {
            BitcoinNetwork::Bitcoin => 1,
            BitcoinNetwork::Testnet => 2,
            BitcoinNetwork::Regtest => 3,
            BitcoinNetwork::Testnet4 => 4,
            BitcoinNetwork::Signet => 5,
        };
        (
            network_id,
            genesis_block(network).block_hash().to_byte_array(),
        )
    }

    const fn bitcoin_network_for_hns(network: HnsNetwork) -> BitcoinNetwork {
        match network {
            HnsNetwork::Mainnet => BitcoinNetwork::Bitcoin,
            HnsNetwork::Testnet => BitcoinNetwork::Testnet,
            HnsNetwork::Regtest | HnsNetwork::Simnet => BitcoinNetwork::Regtest,
        }
    }

    fn kyoto_config(&self) -> KyotoRuntimeConfig {
        KyotoRuntimeConfig {
            network: self.network,
            data_dir: self.data_dir.clone(),
            required_peers: self.required_peers,
            response_timeout: Duration::from_secs(30),
            supervisor_request_timeout: hns_wallet_bitcoin_kyoto::MAX_KYOTO_REQUEST_TIMEOUT,
            supervisor_sync_timeout: hns_wallet_bitcoin_kyoto::MAX_KYOTO_SYNC_TIMEOUT,
            trusted_peers: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), MobileWalletError> {
        self.kyoto_config().validate()?;
        Ok(())
    }
}

/// Bounded projection for an unlocked direct Bitcoin wallet. The address is
/// generated locally from the encrypted seed; it does not come from a relay
/// or wallet server.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinSnapshot {
    pub network: String,
    pub receive_address: String,
    pub confirmed_sats: u64,
    pub trusted_pending_sats: u64,
    pub untrusted_pending_sats: u64,
    pub immature_sats: u64,
    pub total_sats: u64,
    /// Zero means a full recovery scan. A nonzero value is the earliest
    /// transaction block requested by the user; the durable recovery
    /// checkpoint is its validated predecessor.
    pub birthday_height: u32,
    pub birthday_state: MobileBitcoinBirthdayState,
    pub synchronized_height: u32,
    pub connected_peer_count: u8,
    pub required_peer_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobileBitcoinBirthdayState {
    AwaitingCreationTip,
    RecoveryUnknown,
    RecoveryPendingValidation,
    Validated,
}

/// The only information an installed UI receives before it explicitly
/// approves one exact Bitcoin spend. Its opaque token is process-local and
/// has no signing authority after it is consumed, rejected, expired, or the
/// wallet locks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinSendApproval {
    pub action_token: String,
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub maximum_fee_sats: u64,
    pub expires_at_unix: u64,
}

/// Bounded evidence that the exact persisted transaction was accepted by the
/// wallet-owned Kyoto peer set. This deliberately contains no transaction
/// bytes or private derivation information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinBroadcastReceipt {
    pub txid: String,
    pub wtxid: String,
    pub attempt_count: u16,
    pub submitted_at_unix: Option<u64>,
}

struct PendingMobileBitcoinSend {
    action_token: [u8; MOBILE_ACTION_TOKEN_BYTES],
    prepared: hns_wallet_bitcoin_kyoto::PreparedBitcoinSend,
    maximum_fee_sats: u64,
    expires_at_unix: u64,
}

struct PendingMobileBitcoinHtlcFunding {
    action_token: [u8; MOBILE_ACTION_TOKEN_BYTES],
    session_id: SessionId,
    prepared: PreparedBitcoinHtlcFunding,
    maximum_fee_sats: u64,
    refund_at_unix: u64,
    expires_at_unix: u64,
}

struct PendingMobileBitcoinHtlcSettlement {
    action_token: [u8; MOBILE_ACTION_TOKEN_BYTES],
    session_id: SessionId,
    action: MobileShakescapeSettlementAction,
    branch: HtlcSpendBranch,
    raw_transaction: Vec<u8>,
    lock: VerifiedBitcoinLock,
    maximum_fee_sats: u64,
    expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinHtlcFundingApproval {
    pub action_token: String,
    pub session_id: String,
    pub txid: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub maximum_fee_sats: u64,
    pub refund_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinHtlcFundingReceipt {
    pub session_id: String,
    pub txid: String,
    pub attempt_count: u16,
    pub submitted_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinHtlcSettlementApproval {
    pub action_token: String,
    pub session_id: String,
    pub action: MobileShakescapeSettlementAction,
    pub txid: String,
    pub input_amount_sats: u64,
    pub output_amount_sats: u64,
    pub fee_sats: u64,
    pub maximum_fee_sats: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinHtlcSettlementReceipt {
    pub session_id: String,
    pub action: MobileShakescapeSettlementAction,
    pub txid: String,
    pub attempt_count: u16,
    pub submitted_at_unix: Option<u64>,
}

/// Wallet-owned Kyoto state for the installed HNS/Bitcoin product. It opens
/// only while the shared encrypted store is unlocked and tears down its direct
/// peer node before that store is relocked.
pub struct MobileBitcoinValueController {
    store: SharedWalletStore,
    hns_account: HnsRuntimeConfig,
    config: MobileBitcoinDirectConfig,
    runtime: Option<Runtime>,
    wallet: Option<EncryptedPersistedBitcoinWallet>,
    supervisor: Option<KyotoSupervisor>,
    tip_discovery: Option<KyotoTipDiscovery>,
    initialization: MobileBitcoinInitialization,
    shutdown: Option<MobileBitcoinShutdownHandle>,
    progress: Option<MobileBitcoinSyncProgressHandle>,
    receive_address: Option<String>,
    pending_send: Option<PendingMobileBitcoinSend>,
    pending_htlc_funding: Option<PendingMobileBitcoinHtlcFunding>,
    pending_htlc_settlement: Option<PendingMobileBitcoinHtlcSettlement>,
}

/// Lifecycle-only stop capability for the active direct Bitcoin node.
///
/// This can be retained outside a native controller lock so an app-background
/// teardown does not wait for the full synchronization timeout.
#[derive(Clone, Debug)]
pub struct MobileBitcoinShutdownHandle(Arc<Mutex<KyotoShutdownHandle>>);

impl MobileBitcoinShutdownHandle {
    pub fn request_shutdown(&self) -> Result<(), MobileWalletError> {
        let handle = self
            .0
            .lock()
            .map_err(|_| MobileWalletError::BitcoinRuntimeInactive)?
            .clone();
        handle.request_shutdown().map_err(MobileWalletError::from)
    }

    fn replace(&self, handle: KyotoShutdownHandle) -> Result<(), MobileWalletError> {
        *self
            .0
            .lock()
            .map_err(|_| MobileWalletError::BitcoinRuntimeInactive)? = handle;
        Ok(())
    }
}

/// Bounded public progress suitable for native wallet UI presentation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileBitcoinSyncProgress {
    pub successful_handshakes: u8,
    pub required_peer_count: u8,
    pub connection_failures: u16,
    pub peer_timeouts: u16,
    pub incompatible_peers: u16,
    pub connections_met: bool,
    pub chain_height: Option<u32>,
    pub completion_basis_points: u16,
}

#[derive(Clone, Debug)]
pub struct MobileBitcoinSyncProgressHandle(Arc<Mutex<(KyotoSyncProgressHandle, u8)>>);

impl MobileBitcoinSyncProgressHandle {
    pub fn snapshot(&self) -> MobileBitcoinSyncProgress {
        let Ok(target) = self.0.lock() else {
            return MobileBitcoinSyncProgress::default();
        };
        let progress = target.0.snapshot();
        MobileBitcoinSyncProgress {
            successful_handshakes: progress.successful_handshakes,
            required_peer_count: target.1,
            connection_failures: progress.connection_failures,
            peer_timeouts: progress.peer_timeouts,
            incompatible_peers: progress.incompatible_peers,
            connections_met: progress.connections_met,
            chain_height: progress.chain_height,
            completion_basis_points: progress.completion_basis_points,
        }
    }

    fn new(progress: KyotoSyncProgressHandle, required_peers: u8) -> Self {
        Self(Arc::new(Mutex::new((progress, required_peers))))
    }

    fn replace(
        &self,
        progress: KyotoSyncProgressHandle,
        required_peers: u8,
    ) -> Result<(), MobileWalletError> {
        *self
            .0
            .lock()
            .map_err(|_| MobileWalletError::BitcoinRuntimeInactive)? = (progress, required_peers);
        Ok(())
    }
}

impl MobileBitcoinValueController {
    pub(crate) fn new(
        store: SharedWalletStore,
        hns_account: HnsRuntimeConfig,
        config: MobileBitcoinDirectConfig,
    ) -> Result<Self, MobileWalletError> {
        config.validate()?;
        Ok(Self {
            store,
            hns_account,
            config,
            runtime: None,
            wallet: None,
            supervisor: None,
            tip_discovery: None,
            initialization: MobileBitcoinInitialization {
                origin: MobileBitcoinWalletOrigin::Restored,
                requested_recovery_height: None,
            },
            shutdown: None,
            progress: None,
            receive_address: None,
            pending_send: None,
            pending_htlc_funding: None,
            pending_htlc_settlement: None,
        })
    }

    /// Open or recover the deterministic BIP84 wallet and start its direct
    /// Kyoto client. The caller must have already unlocked the shared HNS
    /// store with the device-held database key.
    pub fn activate(&mut self) -> Result<(), MobileWalletError> {
        if self.is_active() {
            return Ok(());
        }
        self.config.validate()?;
        let now_unix = now_unix()?;
        let seed = self.recovery_seed()?;
        let account_id = self.hns_account.account_id.as_bytes();
        let mut wallet = match load_persisted_descriptor_wallet_from_seed(
            seed.as_slice(),
            self.config.network,
            self.store.clone(),
            account_id,
            now_unix,
        ) {
            Ok(wallet) => wallet,
            Err(BitcoinWalletError::WalletNotFound) => {
                create_persisted_descriptor_wallet_from_seed(
                    seed.as_slice(),
                    self.config.network,
                    self.store.clone(),
                    account_id,
                    now_unix,
                )?
            }
            Err(error) => return Err(error.into()),
        };
        drop(seed);
        let initialization = self.load_initialization()?;
        let durable = match StoredKyotoWalletState::load(&self.store, account_id) {
            Ok(state) => Some(state),
            Err(BitcoinWalletError::BitcoinStateNotFound) => None,
            Err(error) => return Err(error.into()),
        };
        let runtime = Runtime::new().map_err(|_| MobileWalletError::BitcoinRuntimeUnavailable)?;
        let requires_tip_discovery = initialization.requested_recovery_height.is_some()
            || (durable.is_none() && initialization.origin == MobileBitcoinWalletOrigin::Generated);
        if requires_tip_discovery {
            let _entered = runtime.enter();
            let genesis = genesis_block(self.config.network)
                .block_hash()
                .to_byte_array();
            let (tip_discovery, logging) = KyotoTipDiscovery::start(
                self.config.kyoto_config(),
                BitcoinCheckpoint {
                    height: 0,
                    block_hash: genesis,
                },
            )?;
            let shutdown = tip_discovery.shutdown_handle();
            let progress = monitor_kyoto_sync_progress(runtime.handle(), logging);
            self.runtime = Some(runtime);
            self.wallet = Some(wallet);
            self.tip_discovery = Some(tip_discovery);
            self.initialization = initialization;
            self.install_runtime_handles(shutdown, progress)?;
            return Ok(());
        }
        let durable = match durable {
            Some(state) => state,
            None => StoredKyotoWalletState::create(
                &self.store,
                account_id,
                KyotoWalletState::restored_wallet(
                    self.config.network,
                    None,
                    BITCOIN_RECOVERY_SCRIPT_INDEX,
                    now_unix,
                )?,
                now_unix,
            )?,
        };
        if matches!(
            durable.state().birthday.source,
            BitcoinBirthdaySource::NewWalletValidatedTip
        ) && durable.state().completed_syncs == 0
        {
            initialize_pristine_wallet_at_creation_tip(&mut wallet, durable.state(), now_unix)?;
        } else if matches!(
            durable.state().birthday.source,
            BitcoinBirthdaySource::KnownCheckpoint
        ) && durable.state().completed_syncs == 0
        {
            initialize_pristine_wallet_at_recovery_checkpoint(
                &mut wallet,
                durable.state(),
                now_unix,
            )?;
        }
        let (supervisor, logging) = {
            let _entered = runtime.enter();
            KyotoSupervisor::start(&wallet, self.config.kyoto_config(), durable, now_unix)?
        };
        let shutdown = supervisor.shutdown_handle();
        let progress = monitor_kyoto_sync_progress(runtime.handle(), logging);
        self.runtime = Some(runtime);
        self.wallet = Some(wallet);
        self.supervisor = Some(supervisor);
        self.initialization = initialization;
        self.install_runtime_handles(shutdown, progress)?;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.runtime.is_some()
            && self.wallet.is_some()
            && (self.supervisor.is_some() || self.tip_discovery.is_some())
    }

    pub fn shutdown_handle(&self) -> Option<MobileBitcoinShutdownHandle> {
        self.shutdown.clone()
    }

    pub fn sync_progress_handle(&self) -> Option<MobileBitcoinSyncProgressHandle> {
        self.progress.clone()
    }

    /// Reveal and persist one deterministic Bitcoin receive address. This
    /// method performs no network I/O and is safe before the first sync.
    pub fn next_receive_address(&mut self) -> Result<String, MobileWalletError> {
        let now_unix = now_unix()?;
        let wallet = self.wallet_mut()?;
        let address = wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .to_string();
        wallet.persist(now_unix)?;
        self.receive_address = Some(address.clone());
        Ok(address)
    }

    /// Drive one bounded Kyoto cycle and return the resulting local snapshot.
    /// A caller schedules subsequent cycles; no hidden relay worker owns the
    /// wallet's chain authority.
    pub fn synchronize_once(
        &mut self,
    ) -> Result<(KyotoSyncReceipt, MobileBitcoinSnapshot), MobileWalletError> {
        let now_unix = now_unix()?;
        if self.tip_discovery.is_some() {
            self.complete_pending_initialization(now_unix)?;
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let (supervisor, wallet) = match (&mut self.supervisor, &mut self.wallet) {
            (Some(supervisor), Some(wallet)) => (supervisor, wallet),
            _ => return Err(MobileWalletError::BitcoinRuntimeInactive),
        };
        let receipt = runtime.block_on(supervisor.synchronize_once(wallet, now_unix))?;
        let snapshot = self.snapshot()?;
        Ok((receipt, snapshot))
    }

    /// Explicitly replace an incomplete full-scan journal with a validated
    /// Bitcoin birthday. The height names the earliest block that may contain
    /// wallet activity, not the exclusive recovery checkpoint. Existing
    /// scans at or beyond that height are never rewound or relabeled.
    pub fn set_birthday_height(
        &mut self,
        earliest_transaction_height: u32,
    ) -> Result<MobileBitcoinSnapshot, MobileWalletError> {
        if self.pending_send.is_some()
            || self.pending_htlc_funding.is_some()
            || self.pending_htlc_settlement.is_some()
            || earliest_transaction_height == 0
        {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let now_unix = now_unix()?;
        if self.initialization.origin == MobileBitcoinWalletOrigin::Generated {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        if let Some(supervisor) = self.supervisor.as_ref() {
            let state = supervisor.state();
            if !matches!(state.birthday.source, BitcoinBirthdaySource::FullScan)
                || earliest_transaction_height <= state.scanned_checkpoint.height
            {
                return Err(MobileWalletError::InvalidBitcoinAction);
            }
        }
        self.initialization.requested_recovery_height = Some(earliest_transaction_height);
        self.persist_initialization(now_unix)?;
        // Retire any genesis recovery scan and reopen as a header-only tip
        // discovery. The requested height is authenticated later by the first
        // synchronization; this setter itself performs no networking.
        let _ = self.deactivate();
        self.activate()?;
        self.snapshot()
    }

    pub fn snapshot(&self) -> Result<MobileBitcoinSnapshot, MobileWalletError> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let balance = wallet.balance();
        let (birthday_height, birthday_state, synchronized_height, connected_peer_count) =
            if let Some(supervisor) = self.supervisor.as_ref() {
                let state = supervisor.state();
                if matches!(state.birthday.source, BitcoinBirthdaySource::FullScan) {
                    (
                        0,
                        MobileBitcoinBirthdayState::RecoveryUnknown,
                        state.scanned_checkpoint.height,
                        state.connected_peer_count,
                    )
                } else {
                    (
                        state.birthday.checkpoint.height.saturating_add(1),
                        MobileBitcoinBirthdayState::Validated,
                        state.scanned_checkpoint.height,
                        state.connected_peer_count,
                    )
                }
            } else if self.tip_discovery.is_some() {
                match (
                    self.initialization.origin,
                    self.initialization.requested_recovery_height,
                ) {
                    (MobileBitcoinWalletOrigin::Generated, _) => {
                        (0, MobileBitcoinBirthdayState::AwaitingCreationTip, 0, 0)
                    }
                    (MobileBitcoinWalletOrigin::Restored, Some(height)) => (
                        height,
                        MobileBitcoinBirthdayState::RecoveryPendingValidation,
                        0,
                        0,
                    ),
                    (MobileBitcoinWalletOrigin::Restored, None) => {
                        (0, MobileBitcoinBirthdayState::RecoveryUnknown, 0, 0)
                    }
                }
            } else {
                return Err(MobileWalletError::BitcoinRuntimeInactive);
            };
        Ok(MobileBitcoinSnapshot {
            network: bitcoin_network_name(self.config.network).to_owned(),
            receive_address: self.receive_address.clone().unwrap_or_else(|| {
                wallet
                    .peek_address(KeychainKind::External, 0)
                    .address
                    .to_string()
            }),
            confirmed_sats: balance.confirmed.to_sat(),
            trusted_pending_sats: balance.trusted_pending.to_sat(),
            untrusted_pending_sats: balance.untrusted_pending.to_sat(),
            immature_sats: balance.immature.to_sat(),
            total_sats: balance.total().to_sat(),
            birthday_height,
            birthday_state,
            synchronized_height,
            connected_peer_count,
            required_peer_count: self.config.required_peers,
        })
    }

    /// Prepare one exact on-chain Bitcoin payment from the local BIP84 wallet.
    /// This obtains the direct peers' bounded minimum fee rate but does not
    /// sign, persist a broadcast intent, or send transaction bytes.
    pub fn prepare_send(
        &mut self,
        destination: &str,
        amount_sats: u64,
        maximum_fee_sats: u64,
    ) -> Result<MobileBitcoinSendApproval, MobileWalletError> {
        if self.pending_send.is_some()
            || self.pending_htlc_funding.is_some()
            || self.pending_htlc_settlement.is_some()
        {
            return Err(MobileWalletError::BitcoinActionPending);
        }
        if maximum_fee_sats == 0 {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let now_unix = now_unix()?;
        let expires_at_unix = now_unix
            .checked_add(BITCOIN_SEND_APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidBitcoinAction)?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let fee_rate_sat_vb = runtime.block_on(supervisor.minimum_broadcast_fee_rate_sat_vb())?;
        let committed_inputs = self.unobserved_approved_inputs()?;
        let prepared = prepare_native_send_excluding(
            self.wallet_mut()?,
            destination,
            amount_sats,
            fee_rate_sat_vb,
            maximum_fee_sats,
            &committed_inputs,
        )?;
        let action_token = random_nonzero_bytes()?;
        let approval = MobileBitcoinSendApproval {
            action_token: lowercase_hex(&action_token),
            destination: prepared.destination.clone(),
            amount_sats: prepared.amount_sats,
            fee_sats: prepared.fee_sats,
            maximum_fee_sats,
            expires_at_unix,
        };
        self.pending_send = Some(PendingMobileBitcoinSend {
            action_token,
            prepared,
            maximum_fee_sats,
            expires_at_unix,
        });
        Ok(approval)
    }

    /// Consume the one process-local approval, persist the exact signed bytes
    /// before network I/O, then submit only that persisted transaction through
    /// Kyoto. A later failure may leave a durable prepared/submission record;
    /// callers must not assume it is safe to create a replacement transaction.
    pub fn approve_send(
        &mut self,
        action_token: &str,
    ) -> Result<MobileBitcoinBroadcastReceipt, MobileWalletError> {
        self.require_pending_send_token(action_token)?;
        let now_unix = now_unix()?;
        if self
            .pending_send
            .as_ref()
            .is_none_or(|pending| now_unix >= pending.expires_at_unix)
        {
            self.pending_send = None;
            return Err(MobileWalletError::BitcoinActionExpired);
        }
        let permit = bitcoin_value_runtime_permit()?;
        let pending = self
            .pending_send
            .take()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        let mut raw_transaction = Zeroizing::new(authorize_native_send(
            self.wallet
                .as_ref()
                .ok_or(MobileWalletError::BitcoinRuntimeInactive)?,
            &permit,
            pending.prepared,
        )?);
        let transaction: Transaction = deserialize(raw_transaction.as_slice())
            .map_err(|_| MobileWalletError::InvalidBitcoinAction)?;
        let txid = transaction.compute_txid().to_byte_array();
        self.wallet_mut()?.persist(now_unix)?;
        let expected_revision = self.store.try_with_store(|store| {
            store
                .bitcoin_transaction::<BitcoinTransactionRecord>(&txid)
                .map(|record| record.map_or(0, |stored| stored.revision))
        })?;
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let prepared = self.store.try_with_store_mut(|store| {
            persist_prepared_bitcoin_broadcast(
                wallet,
                store,
                raw_transaction.as_slice(),
                hns_wallet_bitcoin_kyoto::derive_bitcoin_broadcast_approval(
                    wallet,
                    raw_transaction.as_slice(),
                    pending.maximum_fee_sats,
                    pending.expires_at_unix,
                )?
                .commitment,
                pending.maximum_fee_sats,
                expected_revision,
                now_unix,
                pending.expires_at_unix,
            )
        })?;
        raw_transaction.fill(0);
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let receipt = runtime.block_on(supervisor.broadcast_prepared_transaction(
            &permit,
            prepared.txid,
            now_unix,
        ))?;
        Ok(mobile_broadcast_receipt(receipt))
    }

    /// Reject the displayed Bitcoin approval without persisting or sending a
    /// transaction. The token is verified exactly like the approve path.
    pub fn reject_send(&mut self, action_token: &str) -> Result<(), MobileWalletError> {
        self.require_pending_send_token(action_token)?;
        self.pending_send = None;
        Ok(())
    }

    /// Prepare the exact first-chain Bitcoin HTLC transaction committed by a
    /// countersigned Shakescape session. The Rust-only permit proves that refund
    /// branches were validated and the durable execution is funding-ready.
    pub fn prepare_shakescape_htlc_funding(
        &mut self,
        permit: MobileShakescapeBitcoinFundingPermit,
        maximum_fee_sats: u64,
    ) -> Result<MobileBitcoinHtlcFundingApproval, MobileWalletError> {
        if self.pending_send.is_some()
            || self.pending_htlc_funding.is_some()
            || self.pending_htlc_settlement.is_some()
        {
            return Err(MobileWalletError::BitcoinActionPending);
        }
        if maximum_fee_sats == 0 || maximum_fee_sats > permit.bitcoin_fee_reserve_sats() {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let now_unix = now_unix()?;
        let hello = permit.hello();
        if now_unix >= hello.header.expires_at {
            return Err(MobileWalletError::BitcoinActionExpired);
        }
        let expires_at_unix = now_unix
            .checked_add(BITCOIN_SEND_APPROVAL_LIFETIME_SECONDS)
            .map(|expires| expires.min(hello.header.expires_at))
            .ok_or(MobileWalletError::InvalidBitcoinAction)?;
        if expires_at_unix <= now_unix {
            return Err(MobileWalletError::BitcoinActionExpired);
        }
        let binding =
            build_shakescape_bitcoin_htlc(hello, hns_marketplace_protocol::SwapAssetSide::Offered)?;
        if binding.commitment.into_bytes() != hello.offered_lock_commitment {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let fee_rate_sat_vb = runtime.block_on(supervisor.minimum_broadcast_fee_rate_sat_vb())?;
        let value_sats = binding.value_sats;
        let committed_inputs = self.unobserved_approved_inputs()?;
        let prepared = prepare_bitcoin_htlc_funding_excluding(
            self.wallet_mut()?,
            &bitcoin_value_runtime_permit()?,
            &binding.htlc,
            value_sats,
            fee_rate_sat_vb,
            maximum_fee_sats,
            &committed_inputs,
        )?;
        match (&mut self.supervisor, &self.wallet) {
            (Some(supervisor), Some(wallet)) => {
                supervisor.register_htlc_watch(
                    wallet,
                    BitcoinHtlcWatchRequest {
                        session_id: SessionId::new(hello.swap_session_id),
                        htlc: binding.htlc,
                        expected_value_sats: value_sats,
                        minimum_confirmations: hello.offered_minimum_confirmations,
                    },
                    now_unix,
                )?;
            }
            _ => return Err(MobileWalletError::BitcoinRuntimeInactive),
        }
        let action_token = random_nonzero_bytes()?;
        let session_id = SessionId::new(hello.swap_session_id);
        let approval = MobileBitcoinHtlcFundingApproval {
            action_token: lowercase_hex(&action_token),
            session_id: lowercase_hex(session_id.as_bytes()),
            txid: lowercase_hex(prepared.txid.as_bytes()),
            amount_sats: prepared.value_sats,
            fee_sats: prepared.fee_sats,
            maximum_fee_sats,
            refund_at_unix: hello.offered_refund_deadline.value,
            expires_at_unix,
        };
        self.pending_htlc_funding = Some(PendingMobileBitcoinHtlcFunding {
            action_token,
            session_id,
            prepared,
            maximum_fee_sats,
            refund_at_unix: hello.offered_refund_deadline.value,
            expires_at_unix,
        });
        Ok(approval)
    }

    /// Register the HNS-offering taker's durable compact-filter watch before
    /// the counterparty broadcasts Bitcoin. This signs and spends nothing.
    pub fn register_counterparty_shakescape_htlc_watch(
        &mut self,
        permit: &MobileShakescapeBitcoinWatchPermit,
    ) -> Result<(), MobileWalletError> {
        let now_unix = now_unix()?;
        let hello = permit.hello();
        let binding =
            build_shakescape_bitcoin_htlc(hello, hns_marketplace_protocol::SwapAssetSide::Offered)?;
        if binding.commitment.into_bytes() != hello.offered_lock_commitment {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        match (&mut self.supervisor, &self.wallet) {
            (Some(supervisor), Some(wallet)) => {
                supervisor.register_htlc_watch(
                    wallet,
                    BitcoinHtlcWatchRequest {
                        session_id: SessionId::new(hello.swap_session_id),
                        htlc: binding.htlc,
                        expected_value_sats: binding.value_sats,
                        minimum_confirmations: hello.offered_minimum_confirmations,
                    },
                    now_unix,
                )?;
                Ok(())
            }
            _ => Err(MobileWalletError::BitcoinRuntimeInactive),
        }
    }

    /// Persist the exact signed HTLC funding bytes before handing their txid
    /// to Kyoto. Chain-confirmed swap state is advanced separately by the
    /// local compact-filter verifier, never by this submission receipt.
    pub fn approve_shakescape_htlc_funding(
        &mut self,
        action_token: &str,
    ) -> Result<MobileBitcoinHtlcFundingReceipt, MobileWalletError> {
        self.require_pending_htlc_funding_token(action_token)?;
        let now_unix = now_unix()?;
        if self
            .pending_htlc_funding
            .as_ref()
            .is_none_or(|pending| now_unix >= pending.expires_at_unix)
        {
            self.pending_htlc_funding = None;
            return Err(MobileWalletError::BitcoinActionExpired);
        }
        let pending = self
            .pending_htlc_funding
            .take()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        let verified = verify_htlc_funding(
            pending.prepared.raw_transaction(),
            &pending.prepared.htlc,
            pending.prepared.value_sats,
            0,
            0,
        )?;
        if verified.funding_txid != pending.prepared.txid
            || pending.refund_at_unix != u64::from(pending.prepared.htlc.refund_locktime)
        {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        self.wallet_mut()?.persist(now_unix)?;
        let txid = pending.prepared.txid.into_bytes();
        let expected_revision = self.store.try_with_store(|store| {
            store
                .bitcoin_transaction::<BitcoinTransactionRecord>(&txid)
                .map(|record| record.map_or(0, |stored| stored.revision))
        })?;
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let approval = hns_wallet_bitcoin_kyoto::derive_bitcoin_broadcast_approval(
            wallet,
            pending.prepared.raw_transaction(),
            pending.maximum_fee_sats,
            pending.expires_at_unix,
        )?;
        let prepared = self.store.try_with_store_mut(|store| {
            persist_prepared_bitcoin_broadcast(
                wallet,
                store,
                pending.prepared.raw_transaction(),
                approval.commitment,
                pending.maximum_fee_sats,
                expected_revision,
                now_unix,
                pending.expires_at_unix,
            )
        })?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let receipt = runtime.block_on(supervisor.broadcast_prepared_transaction(
            &bitcoin_value_runtime_permit()?,
            prepared.txid,
            now_unix,
        ))?;
        Ok(MobileBitcoinHtlcFundingReceipt {
            session_id: lowercase_hex(pending.session_id.as_bytes()),
            txid: lowercase_hex(&receipt.txid),
            attempt_count: receipt.attempt_count,
            submitted_at_unix: receipt.submitted_at_unix,
        })
    }

    pub fn reject_shakescape_htlc_funding(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        self.require_pending_htlc_funding_token(action_token)?;
        self.pending_htlc_funding = None;
        Ok(())
    }

    /// Prepare one receiver or timeout spend of the exact verified Bitcoin
    /// HTLC. The destination is a newly persisted internal wallet address;
    /// only a non-sensitive summary and a process-local token leave Rust.
    pub fn prepare_shakescape_htlc_settlement(
        &mut self,
        mut permit: MobileShakescapeBitcoinSettlementPermit,
        maximum_fee_sats: u64,
    ) -> Result<MobileBitcoinHtlcSettlementApproval, MobileWalletError> {
        if self.pending_send.is_some()
            || self.pending_htlc_funding.is_some()
            || self.pending_htlc_settlement.is_some()
        {
            return Err(MobileWalletError::BitcoinActionPending);
        }
        if maximum_fee_sats == 0 || maximum_fee_sats > permit.fee_reserve() {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let now_unix = now_unix()?;
        let expires_at_unix = now_unix
            .checked_add(BITCOIN_SEND_APPROVAL_LIFETIME_SECONDS)
            .ok_or(MobileWalletError::InvalidBitcoinAction)?;
        let hello = permit.hello().clone();
        let binding = build_shakescape_bitcoin_htlc(
            &hello,
            hns_marketplace_protocol::SwapAssetSide::Offered,
        )?;
        if binding.commitment.into_bytes() != hello.offered_lock_commitment {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let branch = match permit.action() {
            MobileShakescapeSettlementAction::Redeem => HtlcSpendBranch::Redeem,
            MobileShakescapeSettlementAction::Refund => HtlcSpendBranch::Refund,
        };
        let expected_key = match branch {
            HtlcSpendBranch::Redeem => &binding.htlc.receiver_public_key,
            HtlcSpendBranch::Refund => &binding.htlc.refund_public_key,
        };
        if expected_key.as_slice() != permit.settlement_key().public_key() {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let session_id = SessionId::new(hello.swap_session_id);
        let lock = self
            .verified_shakescape_htlc_funding(session_id)?
            .ok_or(MobileWalletError::InvalidBitcoinAction)?;
        if lock.htlc != binding.htlc || lock.value_sats != binding.value_sats {
            return Err(MobileWalletError::InvalidBitcoinAction);
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let fee_rate_sat_vb = runtime.block_on(supervisor.minimum_broadcast_fee_rate_sat_vb())?;
        let chain_context = runtime.block_on(supervisor.validated_chain_lock_context())?;
        let destination = {
            let wallet = self.wallet_mut()?;
            let destination = wallet
                .reveal_next_address(KeychainKind::Internal)
                .address
                .script_pubkey();
            wallet.persist(now_unix)?;
            destination
        };
        let preimage = permit
            .take_preimage()
            .map(|preimage| *preimage.expose_for_settlement());
        let raw_transaction = sign_bitcoin_htlc_spend_at_fee_rate_with_settlement_signer(
            &lock,
            &bitcoin_value_runtime_permit()?,
            destination,
            branch,
            preimage,
            chain_context,
            fee_rate_sat_vb,
            maximum_fee_sats,
            permit.settlement_key(),
        )?;
        let verified = verify_signed_bitcoin_htlc_spend(&raw_transaction, &lock, branch)?;
        let output_amount_sats = lock
            .value_sats
            .checked_sub(verified.fee_sats)
            .ok_or(MobileWalletError::InvalidBitcoinAction)?;
        let action_token = random_nonzero_bytes()?;
        let approval = MobileBitcoinHtlcSettlementApproval {
            action_token: lowercase_hex(&action_token),
            session_id: lowercase_hex(session_id.as_bytes()),
            action: permit.action(),
            txid: lowercase_hex(verified.txid.as_bytes()),
            input_amount_sats: lock.value_sats,
            output_amount_sats,
            fee_sats: verified.fee_sats,
            maximum_fee_sats,
            expires_at_unix,
        };
        self.pending_htlc_settlement = Some(PendingMobileBitcoinHtlcSettlement {
            action_token,
            session_id,
            action: permit.action(),
            branch,
            raw_transaction,
            lock,
            maximum_fee_sats,
            expires_at_unix,
        });
        Ok(approval)
    }

    pub fn approve_shakescape_htlc_settlement(
        &mut self,
        action_token: &str,
    ) -> Result<MobileBitcoinHtlcSettlementReceipt, MobileWalletError> {
        self.require_pending_htlc_settlement_token(action_token)?;
        let now_unix = now_unix()?;
        if self
            .pending_htlc_settlement
            .as_ref()
            .is_none_or(|pending| now_unix >= pending.expires_at_unix)
        {
            self.pending_htlc_settlement = None;
            return Err(MobileWalletError::BitcoinActionExpired);
        }
        let pending = self
            .pending_htlc_settlement
            .take()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let approval = hns_wallet_bitcoin_kyoto::derive_bitcoin_htlc_spend_broadcast_approval(
            wallet,
            &pending.raw_transaction,
            &pending.lock,
            pending.branch,
            pending.maximum_fee_sats,
            pending.expires_at_unix,
        )?;
        let expected_revision = self.store.try_with_store(|store| {
            store
                .bitcoin_transaction::<BitcoinTransactionRecord>(&approval.txid)
                .map(|record| record.map_or(0, |stored| stored.revision))
        })?;
        let prepared = self.store.try_with_store_mut(|store| {
            persist_prepared_bitcoin_htlc_spend_broadcast(
                wallet,
                store,
                &pending.raw_transaction,
                &pending.lock,
                pending.branch,
                approval.commitment,
                pending.maximum_fee_sats,
                expected_revision,
                now_unix,
                pending.expires_at_unix,
            )
        })?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let receipt = runtime.block_on(supervisor.broadcast_prepared_transaction(
            &bitcoin_value_runtime_permit()?,
            prepared.txid,
            now_unix,
        ))?;
        Ok(MobileBitcoinHtlcSettlementReceipt {
            session_id: lowercase_hex(pending.session_id.as_bytes()),
            action: pending.action,
            txid: lowercase_hex(&receipt.txid),
            attempt_count: receipt.attempt_count,
            submitted_at_unix: receipt.submitted_at_unix,
        })
    }

    pub fn reject_shakescape_htlc_settlement(
        &mut self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        self.require_pending_htlc_settlement_token(action_token)?;
        self.pending_htlc_settlement = None;
        Ok(())
    }

    /// Re-submit only exact transactions whose signed bytes and user approval
    /// are already durable. This creates no new transaction and consumes no
    /// new signing authority.
    pub fn resume_approved_broadcasts(&self) -> Result<usize, MobileWalletError> {
        let now_unix = now_unix()?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        runtime
            .block_on(
                supervisor.resume_approved_broadcasts(&bitcoin_value_runtime_permit()?, now_unix),
            )
            .map(|receipts| receipts.len())
            .map_err(MobileWalletError::from)
    }

    /// Return only non-sensitive durable broadcast recovery metadata for
    /// platform status presentation.
    pub fn approved_broadcast_recovery(
        &self,
    ) -> Result<BitcoinBroadcastRecoverySummary, MobileWalletError> {
        let network = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?
            .network();
        self.store
            .try_with_store(|store| bitcoin_broadcast_recovery_summary(store, network))
            .map_err(Into::into)
    }

    /// Return funding evidence only when the durable HTLC watch is reconciled
    /// to this controller's exact current Kyoto checkpoint and has reached the
    /// confirmation threshold signed into the swap session.
    pub fn verified_shakescape_htlc_funding(
        &self,
        session_id: SessionId,
    ) -> Result<Option<VerifiedBitcoinLock>, MobileWalletError> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let checkpoint = supervisor.state().scanned_checkpoint;
        self.store
            .try_with_store(|store| {
                load_bitcoin_htlc_watch(store, wallet.network(), wallet.account_id(), session_id)
                    .map(|watch| watch.and_then(|watch| watch.verified_lock_at(checkpoint)))
            })
            .map_err(MobileWalletError::from)
    }

    pub fn verified_shakescape_htlc_spend(
        &self,
        session_id: SessionId,
    ) -> Result<
        Option<hns_wallet_bitcoin_kyoto::VerifiedBitcoinHtlcSpendObservation>,
        MobileWalletError,
    > {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let checkpoint = supervisor.state().scanned_checkpoint;
        self.store
            .try_with_store(|store| {
                load_bitcoin_htlc_watch(store, wallet.network(), wallet.account_id(), session_id)
                    .map(|watch| watch.and_then(|watch| watch.verified_spend_at(checkpoint)))
            })
            .map_err(MobileWalletError::from)
    }

    /// Stop the direct node before the shared store is relocked. A durable
    /// recovery journal remains in the encrypted store and is reconstructed on
    /// the next unlock.
    pub fn deactivate(&mut self) -> Result<(), MobileWalletError> {
        let supervisor_shutdown = self
            .supervisor
            .take()
            .map(|supervisor| supervisor.shutdown())
            .transpose();
        let discovery_shutdown = self
            .tip_discovery
            .take()
            .map(|discovery| discovery.shutdown())
            .transpose();
        self.wallet.take();
        self.runtime.take();
        self.shutdown.take();
        self.progress.take();
        self.receive_address = None;
        self.pending_send = None;
        self.pending_htlc_funding = None;
        self.pending_htlc_settlement = None;
        supervisor_shutdown.map_err(MobileWalletError::from)?;
        discovery_shutdown.map_err(MobileWalletError::from)?;
        Ok(())
    }

    fn load_initialization(&self) -> Result<MobileBitcoinInitialization, MobileWalletError> {
        let id = bitcoin_initialization_id(self.hns_account.account_id.as_bytes());
        self.store.try_with_store(|store| {
            let encoded = store.get_secret(&id, SecretKind::MetadataKey)?;
            match encoded {
                Some(encoded) => MobileBitcoinInitialization::decode(&encoded),
                // Legacy wallets did not persist origin. Treating them as
                // restored is the only safe migration because an empty
                // balance cannot prove that their addresses are new.
                None => Ok(MobileBitcoinInitialization {
                    origin: MobileBitcoinWalletOrigin::Restored,
                    requested_recovery_height: None,
                }),
            }
        })
    }

    fn persist_initialization(&self, now_unix: u64) -> Result<(), MobileWalletError> {
        let id = bitcoin_initialization_id(self.hns_account.account_id.as_bytes());
        let encoded = self.initialization.encode();
        self.store.try_with_store_mut(|store| {
            store.put_secret(&id, SecretKind::MetadataKey, &encoded, now_unix)
        })?;
        Ok(())
    }

    fn install_runtime_handles(
        &mut self,
        shutdown: KyotoShutdownHandle,
        progress: KyotoSyncProgressHandle,
    ) -> Result<(), MobileWalletError> {
        if let Some(handle) = self.shutdown.as_ref() {
            handle.replace(shutdown)?;
        } else {
            self.shutdown = Some(MobileBitcoinShutdownHandle(Arc::new(Mutex::new(shutdown))));
        }
        if let Some(handle) = self.progress.as_ref() {
            handle.replace(progress, self.config.required_peers)?;
        } else {
            self.progress = Some(MobileBitcoinSyncProgressHandle::new(
                progress,
                self.config.required_peers,
            ));
        }
        Ok(())
    }

    fn complete_pending_initialization(&mut self, now_unix: u64) -> Result<(), MobileWalletError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let discovery = self
            .tip_discovery
            .as_mut()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let discovered = runtime.block_on(discovery.wait_for_validated_tip())?;
        let state = match self.initialization.origin {
            MobileBitcoinWalletOrigin::Generated => {
                KyotoWalletState::new_wallet(discovered, now_unix)?
            }
            MobileBitcoinWalletOrigin::Restored => {
                let requested = self
                    .initialization
                    .requested_recovery_height
                    .ok_or(MobileWalletError::InvalidBitcoinAction)?;
                let checkpoint = runtime.block_on(discovery.validate_recovery_height(requested))?;
                KyotoWalletState::restored_wallet(
                    self.config.network,
                    Some(checkpoint),
                    BITCOIN_RECOVERY_SCRIPT_INDEX,
                    now_unix,
                )?
            }
        };
        let account_id = self.hns_account.account_id.as_bytes();
        let durable = match StoredKyotoWalletState::load(&self.store, account_id) {
            Ok(mut durable) => {
                durable.replace(state, now_unix)?;
                durable
            }
            Err(BitcoinWalletError::BitcoinStateNotFound) => {
                StoredKyotoWalletState::create(&self.store, account_id, state, now_unix)?
            }
            Err(error) => return Err(error.into()),
        };
        self.initialization.requested_recovery_height = None;
        self.persist_initialization(now_unix)?;
        if let Some(discovery) = self.tip_discovery.take() {
            let _ = discovery.shutdown();
        }
        let wallet = self
            .wallet
            .as_mut()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        if self.initialization.origin == MobileBitcoinWalletOrigin::Generated {
            initialize_pristine_wallet_at_creation_tip(wallet, durable.state(), now_unix)?;
        } else {
            initialize_pristine_wallet_at_recovery_checkpoint(wallet, durable.state(), now_unix)?;
        }
        let (supervisor, logging) = {
            let _entered = runtime.enter();
            KyotoSupervisor::start(wallet, self.config.kyoto_config(), durable, now_unix)?
        };
        let shutdown = supervisor.shutdown_handle();
        let progress = monitor_kyoto_sync_progress(runtime.handle(), logging);
        self.supervisor = Some(supervisor);
        self.install_runtime_handles(shutdown, progress)?;
        Ok(())
    }

    fn recovery_seed(&self) -> Result<Zeroizing<Vec<u8>>, MobileWalletError> {
        let seed = self.store.try_with_store(|store| {
            store
                .get_secret(
                    self.hns_account.wallet_id.as_bytes(),
                    SecretKind::RecoverySeed,
                )?
                .ok_or(BitcoinWalletError::MissingRecoverySeed)
        })?;
        if seed.len() != BIP39_SEED_BYTES {
            return Err(BitcoinWalletError::InvalidRecoverySeed.into());
        }
        Ok(seed)
    }

    fn wallet_mut(&mut self) -> Result<&mut EncryptedPersistedBitcoinWallet, MobileWalletError> {
        self.wallet
            .as_mut()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)
    }

    fn unobserved_approved_inputs(
        &self,
    ) -> Result<Vec<bdk_wallet::bitcoin::OutPoint>, MobileWalletError> {
        let network = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?
            .network();
        self.store
            .try_with_store(|store| unobserved_approved_broadcast_inputs(store, network))
            .map_err(Into::into)
    }

    fn require_pending_send_token(&self, action_token: &str) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_send
            .as_ref()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        if !action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidBitcoinActionToken);
        }
        Ok(())
    }

    fn require_pending_htlc_funding_token(
        &self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_htlc_funding
            .as_ref()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        if !action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidBitcoinActionToken);
        }
        Ok(())
    }

    fn require_pending_htlc_settlement_token(
        &self,
        action_token: &str,
    ) -> Result<(), MobileWalletError> {
        let pending = self
            .pending_htlc_settlement
            .as_ref()
            .ok_or(MobileWalletError::NoPendingBitcoinAction)?;
        if !action_token_matches(&pending.action_token, action_token) {
            return Err(MobileWalletError::InvalidBitcoinActionToken);
        }
        Ok(())
    }
}

impl Drop for MobileBitcoinValueController {
    fn drop(&mut self) {
        let _ = self.deactivate();
    }
}

fn now_unix() -> Result<u64, MobileWalletError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MobileWalletError::BitcoinClockUnavailable)
}

fn random_nonzero_bytes<const N: usize>() -> Result<[u8; N], MobileWalletError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; N];
        getrandom::fill(&mut bytes).map_err(|_| MobileWalletError::Randomness)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(MobileWalletError::Randomness)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn action_token_matches(expected: &[u8; MOBILE_ACTION_TOKEN_BYTES], candidate: &str) -> bool {
    if candidate.len() != MOBILE_ACTION_TOKEN_BYTES * 2 {
        return false;
    }
    let mut difference = 0_u8;
    for (index, pair) in candidate.as_bytes().chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let Some(high) = decode(pair[0]) else {
            return false;
        };
        let Some(low) = decode(pair[1]) else {
            return false;
        };
        difference |= expected[index] ^ ((high << 4) | low);
    }
    difference == 0
}

fn mobile_broadcast_receipt(receipt: BitcoinBroadcastReceipt) -> MobileBitcoinBroadcastReceipt {
    MobileBitcoinBroadcastReceipt {
        txid: lowercase_hex(&receipt.txid),
        wtxid: lowercase_hex(&receipt.wtxid),
        attempt_count: receipt.attempt_count,
        submitted_at_unix: receipt.submitted_at_unix,
    }
}

const fn bitcoin_network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "mainnet",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Testnet4 => "testnet4",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_and_restored_initialization_records_roundtrip_exactly() {
        for initialization in [
            MobileBitcoinInitialization {
                origin: MobileBitcoinWalletOrigin::Generated,
                requested_recovery_height: None,
            },
            MobileBitcoinInitialization {
                origin: MobileBitcoinWalletOrigin::Restored,
                requested_recovery_height: Some(964_458),
            },
        ] {
            assert_eq!(
                MobileBitcoinInitialization::decode(&initialization.encode())
                    .expect("initialization record"),
                initialization,
            );
        }
        assert!(MobileBitcoinInitialization::decode(&[1, 3, 0, 0, 0, 0]).is_err());
        assert!(MobileBitcoinInitialization::decode(&[2, 1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn hns_networks_map_to_the_matching_direct_bitcoin_network() {
        let path = PathBuf::from("bitcoin-direct-state");
        assert_eq!(
            MobileBitcoinDirectConfig::for_hns_wallet(HnsNetwork::Mainnet, path.clone()).network,
            BitcoinNetwork::Bitcoin
        );
        assert_eq!(
            MobileBitcoinDirectConfig::for_hns_wallet(HnsNetwork::Testnet, path.clone()).network,
            BitcoinNetwork::Testnet
        );
        assert_eq!(
            MobileBitcoinDirectConfig::for_hns_wallet(HnsNetwork::Regtest, path.clone()).network,
            BitcoinNetwork::Regtest
        );
        assert_eq!(
            MobileBitcoinDirectConfig::for_hns_wallet(HnsNetwork::Simnet, path).network,
            BitcoinNetwork::Regtest
        );
    }
}
