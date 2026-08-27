//! Direct Kyoto Bitcoin ownership for the installed mobile wallet.
//!
//! This controller deliberately shares the HNS wallet's authenticated store
//! and protected BIP-39 seed. Kyoto peers provide transport only; compact
//! filters, headers, descriptor state, and the restart journal remain local.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network as BitcoinNetwork;
use bdk_wallet::bitcoin::Transaction;
use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::hashes::Hash;
use hns_wallet_bitcoin_kyoto::{
    BIP39_SEED_BYTES, BitcoinBroadcastReceipt, BitcoinTransactionRecord, BitcoinWalletError,
    EncryptedPersistedBitcoinWallet, KyotoRuntimeConfig, KyotoShutdownHandle, KyotoSupervisor,
    KyotoSyncProgressHandle, KyotoSyncReceipt, KyotoWalletState, StoredKyotoWalletState,
    authorize_native_send, bitcoin_value_runtime_permit,
    create_persisted_descriptor_wallet_from_seed, load_persisted_descriptor_wallet_from_seed,
    monitor_kyoto_sync_progress, persist_prepared_bitcoin_broadcast, prepare_native_send,
};
use hns_wallet_hns::{HnsNetwork, HnsRuntimeConfig};
use hns_wallet_store::{SecretKind, SharedWalletStore};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::MobileWalletError;

const BITCOIN_RECOVERY_SCRIPT_INDEX: u32 = 1;
const BITCOIN_SEND_APPROVAL_LIFETIME_SECONDS: u64 = 300;
const MOBILE_ACTION_TOKEN_BYTES: usize = 32;

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
    pub fn direct_denuo_counterchain(network: HnsNetwork) -> (u64, [u8; 32]) {
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
    pub synchronized_height: u32,
    pub connected_peer_count: u8,
    pub required_peer_count: u8,
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
    progress: Option<MobileBitcoinSyncProgressHandle>,
    receive_address: Option<String>,
    pending_send: Option<PendingMobileBitcoinSend>,
}

/// Lifecycle-only stop capability for the active direct Bitcoin node.
///
/// This can be retained outside a native controller lock so an app-background
/// teardown does not wait for the full synchronization timeout.
#[derive(Clone, Debug)]
pub struct MobileBitcoinShutdownHandle(KyotoShutdownHandle);

impl MobileBitcoinShutdownHandle {
    pub fn request_shutdown(&self) -> Result<(), MobileWalletError> {
        self.0.request_shutdown().map_err(MobileWalletError::from)
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
pub struct MobileBitcoinSyncProgressHandle(KyotoSyncProgressHandle, u8);

impl MobileBitcoinSyncProgressHandle {
    pub fn snapshot(&self) -> MobileBitcoinSyncProgress {
        let progress = self.0.snapshot();
        MobileBitcoinSyncProgress {
            successful_handshakes: progress.successful_handshakes,
            required_peer_count: self.1,
            connection_failures: progress.connection_failures,
            peer_timeouts: progress.peer_timeouts,
            incompatible_peers: progress.incompatible_peers,
            connections_met: progress.connections_met,
            chain_height: progress.chain_height,
            completion_basis_points: progress.completion_basis_points,
        }
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
            progress: None,
            receive_address: None,
            pending_send: None,
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
        let wallet = match load_persisted_descriptor_wallet_from_seed(
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
        let durable = match StoredKyotoWalletState::load(&self.store, account_id) {
            Ok(state) => state,
            Err(BitcoinWalletError::BitcoinStateNotFound) => StoredKyotoWalletState::create(
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
            Err(error) => return Err(error.into()),
        };
        let runtime = Runtime::new().map_err(|_| MobileWalletError::BitcoinRuntimeUnavailable)?;
        let (supervisor, progress) = {
            let _entered = runtime.enter();
            let (supervisor, logging) =
                KyotoSupervisor::start(&wallet, self.config.kyoto_config(), durable, now_unix)?;
            (
                supervisor,
                MobileBitcoinSyncProgressHandle(
                    monitor_kyoto_sync_progress(logging),
                    self.config.required_peers,
                ),
            )
        };
        self.runtime = Some(runtime);
        self.wallet = Some(wallet);
        self.supervisor = Some(supervisor);
        self.progress = Some(progress);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.runtime.is_some() && self.wallet.is_some() && self.supervisor.is_some()
    }

    pub fn shutdown_handle(&self) -> Option<MobileBitcoinShutdownHandle> {
        self.supervisor
            .as_ref()
            .map(|supervisor| MobileBitcoinShutdownHandle(supervisor.shutdown_handle()))
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

    pub fn snapshot(&self) -> Result<MobileBitcoinSnapshot, MobileWalletError> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(MobileWalletError::BitcoinRuntimeInactive)?;
        let balance = wallet.balance();
        let state = supervisor.state();
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
            synchronized_height: state.scanned_checkpoint.height,
            connected_peer_count: state.connected_peer_count,
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
        if self.pending_send.is_some() {
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
        let prepared = prepare_native_send(
            self.wallet_mut()?,
            destination,
            amount_sats,
            fee_rate_sat_vb,
            maximum_fee_sats,
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

    /// Stop the direct node before the shared store is relocked. A durable
    /// recovery journal remains in the encrypted store and is reconstructed on
    /// the next unlock.
    pub fn deactivate(&mut self) -> Result<(), MobileWalletError> {
        let shutdown = self
            .supervisor
            .take()
            .map(|supervisor| supervisor.shutdown())
            .transpose();
        self.wallet.take();
        self.runtime.take();
        self.progress.take();
        self.receive_address = None;
        self.pending_send = None;
        shutdown.map_err(MobileWalletError::from)?;
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
