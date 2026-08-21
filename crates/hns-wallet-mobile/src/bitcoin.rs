//! Direct Kyoto Bitcoin ownership for the installed mobile wallet.
//!
//! This controller deliberately shares the HNS wallet's authenticated store
//! and protected BIP-39 seed. Kyoto peers provide transport only; compact
//! filters, headers, descriptor state, and the restart journal remain local.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network as BitcoinNetwork;
use hns_wallet_bitcoin_kyoto::{
    BIP39_SEED_BYTES, BitcoinWalletError, EncryptedPersistedBitcoinWallet, KyotoRuntimeConfig,
    KyotoSupervisor, KyotoSyncReceipt, KyotoWalletState, StoredKyotoWalletState,
    create_persisted_descriptor_wallet_from_seed, load_persisted_descriptor_wallet_from_seed,
};
use hns_wallet_hns::{HnsNetwork, HnsRuntimeConfig};
use hns_wallet_store::{SecretKind, SharedWalletStore};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::MobileWalletError;

const BITCOIN_RECOVERY_SCRIPT_INDEX: u32 = 1;

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
        let network = match network {
            HnsNetwork::Mainnet => BitcoinNetwork::Bitcoin,
            HnsNetwork::Testnet => BitcoinNetwork::Testnet,
            HnsNetwork::Regtest | HnsNetwork::Simnet => BitcoinNetwork::Regtest,
        };
        Self {
            network,
            data_dir,
            required_peers: hns_wallet_bitcoin_kyoto::DEFAULT_REQUIRED_PEERS,
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
    receive_address: Option<String>,
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
            receive_address: None,
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
        let supervisor = {
            let _entered = runtime.enter();
            KyotoSupervisor::start(&wallet, self.config.kyoto_config(), durable, now_unix).map(
                |(supervisor, logging)| {
                    // Native shells surface only bounded sync status, never
                    // untrusted peer log strings.
                    drop(logging);
                    supervisor
                },
            )?
        };
        self.runtime = Some(runtime);
        self.wallet = Some(wallet);
        self.supervisor = Some(supervisor);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.runtime.is_some() && self.wallet.is_some() && self.supervisor.is_some()
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
        self.receive_address = None;
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
