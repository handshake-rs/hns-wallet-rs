#![doc = "Kyoto-only Bitcoin wallet integration and native HTLC settlement."]
#![forbid(unsafe_code)]

mod persistence;
mod runtime;
mod swap_key_store;
mod swap_watch;

pub use persistence::*;
pub use runtime::*;
pub use swap_key_store::*;
pub use swap_watch::*;

use core::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bdk_kyoto::builder::{Builder, BuilderExt};
use bdk_kyoto::{LightClient, ScanType, TrustedPeer, state, wallets};
use bdk_wallet::bitcoin::absolute;
use bdk_wallet::bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256,
};
use bdk_wallet::bitcoin::consensus::{deserialize, serialize};
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::script::Builder as ScriptBuilder;
use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1, SecretKey, ecdsa::Signature};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bdk_wallet::bitcoin::{
    Address, Amount as BitcoinAmount, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, bip32::Xpriv, psbt::Psbt, transaction,
};
use bdk_wallet::template::Bip84;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use hns_marketplace_protocol::{
    AssetId, MarketPair, NetworkBinding as DenuoNetworkBinding, SwapAssetSide, SwapSessionHello,
};
use hns_wallet_chain_api::SettlementSigner;
use hns_wallet_types::{
    ChainCapabilities, FeeModel, FinalityModel, HashAlgorithm, LocktimeModel, ObjectHash,
    SessionId, TransactionHash, WalletId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MIN_HTLC_DUST_SATS: u64 = 330;
/// Bitcoin's consensus boundary between height and Unix-time absolute
/// locktimes. Denuo `UnixTime` deadlines must never silently become heights.
pub const BITCOIN_TIMESTAMP_LOCKTIME_THRESHOLD: u64 = 500_000_000;
pub const MAX_HTLC_SCRIPT_BYTES: usize = 256;
pub const MAX_BITCOIN_TRANSACTION_BYTES: usize = 400_000;
/// BIP-39 PBKDF2 output length. The mobile HNS wallet keeps this exact
/// protected seed rather than retaining a recoverable copy of the displayed
/// mnemonic, so the Kyoto wallet must be able to derive BIP84 keys directly
/// from it.
pub const BIP39_SEED_BYTES: usize = 64;
pub const MAX_REQUIRED_PEERS: u8 = 8;
pub const MAX_RECOVERY_SCRIPT_INDEX: u32 = 100_000;
pub const BITCOIN_SWAP_KEY_SCHEME_VERSION: u16 = 1;
pub const MAX_BITCOIN_SWAP_ACCOUNT_INDEX: u32 = 100_000;
pub const MAX_BITCOIN_SWAP_KEY_INDEX: u32 = 100_000;
pub const DEFAULT_REQUIRED_PEERS: u8 = 3;
pub const MAX_KYOTO_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_KYOTO_SYNC_TIMEOUT: Duration = Duration::from_secs(86_400);
/// Domain-separated commitment to an exact Bitcoin P2WSH HTLC as it appears
/// in a signed Denuo HNS/BTC session. It binds the bilateral network, amount,
/// and full witness script—not merely the script hash advertised by a peer.
pub const DENUO_BITCOIN_HTLC_COMMITMENT_DOMAIN: &[u8] = b"hns-wallet-rs/denuo-bitcoin-htlc/v1";
/// Wallet-private HKDF-SHA256 salt for Bitcoin atomic-swap keys. This is not a
/// registered BIP-32 purpose or an interoperable descriptor path.
pub const BITCOIN_SWAP_DERIVATION_DOMAIN: &[u8] = b"hns-wallet-rs/bitcoin-atomic-swap-key/v1";
#[cfg(test)]
const BITCOIN_SWAP_DERIVATION_INFO_TAG: &[u8; 4] = b"HSWP";
const BITCOIN_SWAP_ALLOCATION_DERIVATION_DOMAIN: &[u8] =
    b"hns-wallet-rs/bitcoin-atomic-swap-allocation-key/v1";
const BITCOIN_SWAP_ALLOCATION_DERIVATION_INFO_TAG: &[u8; 4] = b"HSAK";
/// The source contains value-moving primitives, but the complete Kyoto
/// persistence and independent release gate have not passed.
pub const BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = false;

/// The only production synchronization model exposed by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinSynchronizationModel {
    KyotoBip157DirectP2p,
}

pub const fn synchronization_model() -> BitcoinSynchronizationModel {
    BitcoinSynchronizationModel::KyotoBip157DirectP2p
}

pub const fn capabilities() -> ChainCapabilities {
    ChainCapabilities {
        receive: true,
        send: BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED,
        history: true,
        atomic_settlement: BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED,
        hash_algorithm: HashAlgorithm::Sha256,
        locktime_model: LocktimeModel::UnixTime,
        finality_model: FinalityModel::ProofOfWorkConfirmations,
        fee_model: FeeModel::WeightRate,
    }
}

#[derive(Clone, Debug)]
pub struct KyotoRuntimeConfig {
    pub network: Network,
    pub data_dir: PathBuf,
    pub required_peers: u8,
    pub response_timeout: Duration,
    pub supervisor_request_timeout: Duration,
    pub supervisor_sync_timeout: Duration,
    pub trusted_peers: Vec<TrustedPeer>,
}

impl KyotoRuntimeConfig {
    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.data_dir.as_os_str().is_empty()
            || self.required_peers == 0
            || self.required_peers > MAX_REQUIRED_PEERS
            || self.response_timeout.is_zero()
            || self.supervisor_request_timeout.is_zero()
            || self.supervisor_request_timeout > MAX_KYOTO_REQUEST_TIMEOUT
            || self.supervisor_sync_timeout.is_zero()
            || self.supervisor_sync_timeout > MAX_KYOTO_SYNC_TIMEOUT
        {
            return Err(BitcoinWalletError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Builds the actual direct-P2P Kyoto light client. There is intentionally no
/// alternate production backend or runtime selector.
pub fn build_kyoto_client(
    wallet: &Wallet,
    config: KyotoRuntimeConfig,
    scan_type: ScanType,
) -> Result<LightClient<state::Idle, wallets::Single>, BitcoinWalletError> {
    config.validate()?;
    if wallet.network() != config.network {
        return Err(BitcoinWalletError::NetworkMismatch);
    }
    let mut builder = Builder::new(config.network)
        .data_dir(config.data_dir)
        .required_peers(config.required_peers)
        .response_timeout(config.response_timeout);
    if !config.trusted_peers.is_empty() {
        builder = builder.add_peers(config.trusted_peers);
    }
    builder
        .build_with_wallet(wallet, scan_type)
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
}

pub fn parse_recovery_phrase(phrase: &str) -> Result<Mnemonic, BitcoinWalletError> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| BitcoinWalletError::InvalidRecoveryPhrase)
}

/// Script position owned by one locally derived Bitcoin atomic-swap key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinSwapKeyRole {
    Receiver,
    RefundOwner,
}

impl BitcoinSwapKeyRole {
    const fn code(self) -> u32 {
        match self {
            Self::Receiver => 0,
            Self::RefundOwner => 1,
        }
    }
}

/// Numeric coordinates within a complete encrypted Bitcoin swap-key
/// allocation. Wallet, session, and frozen-terms bindings are also required to
/// recover an allocated key; this reference is not sufficient by itself.
///
/// This is deliberately not a BIP-32 path. The HKDF info is the byte sequence
/// `HSWP || coin_type || network_code || account || role || index || counter`,
/// where every integer is an unsigned big-endian `u32`. The final rejection
/// counter is one byte. Mainnet uses coin type/network code `(0, 0)`;
/// testnet3, testnet4, signet, and regtest use coin type `1` and network codes
/// `1`, `2`, `3`, and `4`, respectively.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinSwapKeyReference {
    scheme_version: u16,
    network: Network,
    role: BitcoinSwapKeyRole,
    account_index: u32,
    key_index: u32,
}

impl BitcoinSwapKeyReference {
    pub(crate) fn new(
        network: Network,
        role: BitcoinSwapKeyRole,
        account_index: u32,
        key_index: u32,
    ) -> Result<Self, BitcoinWalletError> {
        let reference = Self {
            scheme_version: BITCOIN_SWAP_KEY_SCHEME_VERSION,
            network,
            role,
            account_index,
            key_index,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(self) -> Result<(), BitcoinWalletError> {
        if self.scheme_version != BITCOIN_SWAP_KEY_SCHEME_VERSION
            || self.account_index > MAX_BITCOIN_SWAP_ACCOUNT_INDEX
            || self.key_index > MAX_BITCOIN_SWAP_KEY_INDEX
        {
            return Err(BitcoinWalletError::InvalidSwapKeyReference);
        }
        Ok(())
    }

    pub const fn scheme_version(self) -> u16 {
        self.scheme_version
    }

    pub const fn network(self) -> Network {
        self.network
    }

    pub const fn role(self) -> BitcoinSwapKeyRole {
        self.role
    }

    pub const fn account_index(self) -> u32 {
        self.account_index
    }

    pub const fn key_index(self) -> u32 {
        self.key_index
    }

    pub const fn coin_type(self) -> u32 {
        match self.network {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => 1,
        }
    }

    pub const fn network_code(self) -> u32 {
        match self.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Testnet4 => 2,
            Network::Signet => 3,
            Network::Regtest => 4,
        }
    }

    #[cfg(test)]
    fn derivation_info(self, counter: u8) -> Result<[u8; 25], BitcoinWalletError> {
        self.validate()?;
        let mut info = [0_u8; 25];
        info[..4].copy_from_slice(BITCOIN_SWAP_DERIVATION_INFO_TAG);
        info[4..8].copy_from_slice(&self.coin_type().to_be_bytes());
        info[8..12].copy_from_slice(&self.network_code().to_be_bytes());
        info[12..16].copy_from_slice(&self.account_index.to_be_bytes());
        info[16..20].copy_from_slice(&self.role.code().to_be_bytes());
        info[20..24].copy_from_slice(&self.key_index.to_be_bytes());
        info[24] = counter;
        Ok(info)
    }
}

/// Public, persistable half of one locally derived Bitcoin atomic-swap key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinSwapPublicKey {
    reference: BitcoinSwapKeyReference,
    public_key: PublicKey,
}

impl BitcoinSwapPublicKey {
    pub const fn reference(&self) -> BitcoinSwapKeyReference {
        self.reference
    }

    pub fn bitcoin_public_key(&self) -> Result<PublicKey, BitcoinWalletError> {
        self.reference.validate()?;
        if !self.public_key.compressed {
            return Err(BitcoinWalletError::InvalidSwapKeyReference);
        }
        Ok(self.public_key)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct BitcoinSwapSecretKey([u8; 32]);

/// In-memory swap-key handle. Its secret bytes are not serializable or
/// accessible through the public API and are zeroized when the handle drops.
pub struct DerivedBitcoinSwapKey {
    public_key: BitcoinSwapPublicKey,
    _secret_key: BitcoinSwapSecretKey,
}

impl DerivedBitcoinSwapKey {
    pub const fn public_key(&self) -> &BitcoinSwapPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for DerivedBitcoinSwapKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedBitcoinSwapKey")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Context-free mnemonic derivation retained for crate-local vectors.
#[cfg(test)]
pub(crate) fn derive_bitcoin_swap_key(
    mnemonic: &Mnemonic,
    reference: BitcoinSwapKeyReference,
) -> Result<DerivedBitcoinSwapKey, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    derive_bitcoin_swap_key_from_seed(seed.as_slice(), reference)
}

#[cfg(test)]
fn derive_bitcoin_swap_key_from_seed(
    seed: &[u8],
    reference: BitcoinSwapKeyReference,
) -> Result<DerivedBitcoinSwapKey, BitcoinWalletError> {
    reference.validate()?;
    if seed.len() != 64 {
        return Err(BitcoinWalletError::InvalidRecoverySeed);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(BITCOIN_SWAP_DERIVATION_DOMAIN), seed);
    for counter in 0_u8..=u8::MAX {
        let info = reference.derivation_info(counter)?;
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| BitcoinWalletError::KeyDerivation)?;
        let Ok(mut secret_key) = SecretKey::from_slice(candidate.as_slice()) else {
            continue;
        };
        let public_key = PublicKey::new(secret_key.public_key(&Secp256k1::new()));
        secret_key.non_secure_erase();
        return Ok(DerivedBitcoinSwapKey {
            public_key: BitcoinSwapPublicKey {
                reference,
                public_key,
            },
            _secret_key: BitcoinSwapSecretKey(*candidate),
        });
    }
    Err(BitcoinWalletError::KeyDerivation)
}

/// Derives the key owned by a durable allocation. The profile, session, and
/// frozen-terms commitment are part of the HKDF context so a copied seed with
/// an independent or rolled-back counter cannot reuse a key for another
/// logical swap.
fn derive_bitcoin_swap_key_from_seed_for_allocation(
    seed: &[u8],
    wallet_id: WalletId,
    session_id: SessionId,
    terms_commitment: ObjectHash,
    reference: BitcoinSwapKeyReference,
) -> Result<DerivedBitcoinSwapKey, BitcoinWalletError> {
    reference.validate()?;
    if seed.len() != 64
        || wallet_id.as_bytes().iter().all(|byte| *byte == 0)
        || session_id.as_bytes().iter().all(|byte| *byte == 0)
        || terms_commitment.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(BitcoinWalletError::InvalidSwapKeyReference);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(BITCOIN_SWAP_ALLOCATION_DERIVATION_DOMAIN), seed);
    for counter in 0_u8..=u8::MAX {
        let mut info = [0_u8; 107];
        info[..4].copy_from_slice(BITCOIN_SWAP_ALLOCATION_DERIVATION_INFO_TAG);
        info[4..20].copy_from_slice(wallet_id.as_bytes());
        info[20..52].copy_from_slice(session_id.as_bytes());
        info[52..84].copy_from_slice(terms_commitment.as_bytes());
        info[84..86].copy_from_slice(&reference.scheme_version().to_be_bytes());
        info[86..90].copy_from_slice(&reference.coin_type().to_be_bytes());
        info[90..94].copy_from_slice(&reference.network_code().to_be_bytes());
        info[94..98].copy_from_slice(&reference.account_index().to_be_bytes());
        info[98..102].copy_from_slice(&reference.role().code().to_be_bytes());
        info[102..106].copy_from_slice(&reference.key_index().to_be_bytes());
        info[106] = counter;
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| BitcoinWalletError::KeyDerivation)?;
        let Ok(mut secret_key) = SecretKey::from_slice(candidate.as_slice()) else {
            continue;
        };
        let public_key = PublicKey::new(secret_key.public_key(&Secp256k1::new()));
        secret_key.non_secure_erase();
        return Ok(DerivedBitcoinSwapKey {
            public_key: BitcoinSwapPublicKey {
                reference,
                public_key,
            },
            _secret_key: BitcoinSwapSecretKey(*candidate),
        });
    }
    Err(BitcoinWalletError::KeyDerivation)
}

pub fn create_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
) -> Result<Wallet, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    create_descriptor_wallet_from_seed(seed.as_slice(), network)
}

/// Create an in-memory BIP84 wallet from the exact protected BIP-39 seed.
///
/// This is the counterpart to [`create_descriptor_wallet`] for installed
/// HNS/mobile wallets: those wallets deliberately retain only the encrypted
/// PBKDF2 output after displaying the recovery phrase. Accepting the seed
/// avoids asking a user to re-enter the phrase or creating a second recovery
/// authority merely to add Bitcoin.
pub fn create_descriptor_wallet_from_seed(
    seed: &[u8],
    network: Network,
) -> Result<Wallet, BitcoinWalletError> {
    if seed.len() != BIP39_SEED_BYTES {
        return Err(BitcoinWalletError::KeyDerivation);
    }
    let root = Xpriv::new_master(network, seed).map_err(|_| BitcoinWalletError::KeyDerivation)?;
    Wallet::create(
        Bip84(root, KeychainKind::External),
        Bip84(root, KeychainKind::Internal),
    )
    .network(network)
    .use_spk_cache(true)
    .create_wallet_no_persist()
    .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))
}

pub fn next_receive_address(wallet: &mut Wallet) -> String {
    wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string()
}

#[derive(Debug)]
pub struct PreparedBitcoinSend {
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    psbt: Psbt,
}

pub fn prepare_native_send(
    wallet: &mut Wallet,
    destination: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    maximum_fee_sats: u64,
) -> Result<PreparedBitcoinSend, BitcoinWalletError> {
    if amount_sats == 0 || fee_rate_sat_vb == 0 {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    let unchecked =
        Address::from_str(destination).map_err(|_| BitcoinWalletError::InvalidDestination)?;
    let address = unchecked
        .require_network(wallet.network())
        .map_err(|_| BitcoinWalletError::NetworkMismatch)?;
    let fee_rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(fee_rate_sat_vb)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(
            address.script_pubkey(),
            BitcoinAmount::from_sat(amount_sats),
        )
        .fee_rate(fee_rate);
    let psbt = builder
        .finish()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let fee_sats = wallet
        .calculate_fee(&psbt.unsigned_tx)
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?
        .to_sat();
    if fee_sats > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    Ok(PreparedBitcoinSend {
        destination: destination.to_owned(),
        amount_sats,
        fee_sats,
        psbt,
    })
}

/// The caller must bind the approval to the prepared destination, amount, fee
/// and serialized PSBT commitment before invoking this signing boundary. The
/// release-qualified value-runtime permit is deliberately unavailable until
/// the Bitcoin value path passes its independent qualification gate.
pub fn authorize_native_send(
    wallet: &Wallet,
    _permit: &BitcoinValueRuntimePermit,
    mut prepared: PreparedBitcoinSend,
) -> Result<Vec<u8>, BitcoinWalletError> {
    let finalized = wallet
        .sign(&mut prepared.psbt, SignOptions::default())
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    if !finalized {
        return Err(BitcoinWalletError::SigningIncomplete);
    }
    let transaction = prepared
        .psbt
        .extract_tx()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let raw = serialize(&transaction);
    if raw.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    Ok(raw)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinHtlc {
    pub hashlock: [u8; 32],
    pub receiver_public_key: Vec<u8>,
    pub refund_public_key: Vec<u8>,
    /// Bitcoin consensus absolute locktime. Values below 500,000,000 are
    /// block heights; values at or above it are Unix timestamps evaluated
    /// against median-time-past.
    pub refund_locktime: u32,
    pub witness_script: Vec<u8>,
    pub script_pubkey: Vec<u8>,
}

/// Exact Bitcoin descriptor and commitment implied by one side of an accepted
/// Denuo HNS/BTC agreement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoBitcoinHtlcBinding {
    pub htlc: BitcoinHtlc,
    pub commitment: ObjectHash,
    pub value_sats: u64,
}

/// A fully signed descriptor-wallet transaction funding one exact native
/// SegWit HTLC. The raw bytes are redacted from `Debug`; callers must persist
/// the enclosing descriptor wallet changes and an approval binding before
/// broadcasting them through Kyoto.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedBitcoinHtlcFunding {
    pub htlc: BitcoinHtlc,
    pub value_sats: u64,
    pub fee_sats: u64,
    pub txid: TransactionHash,
    raw_transaction: Vec<u8>,
}

impl PreparedBitcoinHtlcFunding {
    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }

    pub fn into_raw_transaction(self) -> Vec<u8> {
        self.raw_transaction
    }
}

impl fmt::Debug for PreparedBitcoinHtlcFunding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBitcoinHtlcFunding")
            .field("htlc", &self.htlc)
            .field("value_sats", &self.value_sats)
            .field("fee_sats", &self.fee_sats)
            .field("txid", &self.txid)
            .field("raw_transaction", &"[REDACTED]")
            .finish()
    }
}

/// Build and sign the descriptor-wallet funding transaction for one exact
/// HTLC output. This mutates the BDK wallet's staged change/address state but
/// performs no persistence or network I/O.
pub fn prepare_bitcoin_htlc_funding(
    wallet: &mut Wallet,
    _permit: &BitcoinValueRuntimePermit,
    htlc: &BitcoinHtlc,
    value_sats: u64,
    fee_rate_sat_vb: u64,
    maximum_fee_sats: u64,
) -> Result<PreparedBitcoinHtlcFunding, BitcoinWalletError> {
    htlc.validate()?;
    if value_sats < MIN_HTLC_DUST_SATS || fee_rate_sat_vb == 0 || maximum_fee_sats == 0 {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    let fee_rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(fee_rate_sat_vb)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(htlc.script_pubkey(), BitcoinAmount::from_sat(value_sats))
        .fee_rate(fee_rate);
    let mut psbt = builder
        .finish()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let fee_sats = wallet
        .calculate_fee(&psbt.unsigned_tx)
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?
        .to_sat();
    if fee_sats == 0 || fee_sats > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    if !wallet
        .sign(&mut psbt, SignOptions::default())
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?
    {
        return Err(BitcoinWalletError::SigningIncomplete);
    }
    let transaction = psbt
        .extract_tx()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let raw_transaction = serialize(&transaction);
    if raw_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    let verified = verify_htlc_funding(&raw_transaction, htlc, value_sats, 0, 0)?;
    Ok(PreparedBitcoinHtlcFunding {
        htlc: htlc.clone(),
        value_sats,
        fee_sats,
        txid: verified.funding_txid,
        raw_transaction,
    })
}

impl BitcoinHtlc {
    pub fn new(
        hashlock: [u8; 32],
        receiver_public_key: PublicKey,
        refund_public_key: PublicKey,
        refund_locktime: u32,
    ) -> Result<Self, BitcoinWalletError> {
        if hashlock == [0; 32] || refund_locktime == 0 {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        let witness_script = ScriptBuilder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(hashlock)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&receiver_public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(i64::from(refund_locktime))
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_key(&refund_public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script();
        if witness_script.len() > MAX_HTLC_SCRIPT_BYTES {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        Ok(Self {
            hashlock,
            receiver_public_key: receiver_public_key.to_bytes(),
            refund_public_key: refund_public_key.to_bytes(),
            refund_locktime,
            witness_script: witness_script.into_bytes(),
            script_pubkey: script_pubkey.into_bytes(),
        })
    }

    /// Constructs an HTLC with one locally owned, role-checked swap key and
    /// one counterparty key. This does not sign, fund, or enable settlement.
    pub fn new_with_local_swap_key(
        hashlock: [u8; 32],
        local_key: &DerivedBitcoinSwapKey,
        counterparty_public_key: PublicKey,
        refund_locktime: u32,
    ) -> Result<Self, BitcoinWalletError> {
        let local_public_key = local_key.public_key().bitcoin_public_key()?;
        match local_key.public_key().reference().role() {
            BitcoinSwapKeyRole::Receiver => Self::new(
                hashlock,
                local_public_key,
                counterparty_public_key,
                refund_locktime,
            ),
            BitcoinSwapKeyRole::RefundOwner => Self::new(
                hashlock,
                counterparty_public_key,
                local_public_key,
                refund_locktime,
            ),
        }
    }

    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        let receiver = PublicKey::from_slice(&self.receiver_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let refund = PublicKey::from_slice(&self.refund_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let expected = Self::new(self.hashlock, receiver, refund, self.refund_locktime)?;
        if &expected != self {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        Ok(())
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.script_pubkey.clone())
    }

    pub fn witness_script(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.witness_script.clone())
    }
}

/// Build the Bitcoin HTLC that the signed Denuo terms require for `side`.
/// The party offering that Bitcoin side owns its refund branch; the other
/// settlement key owns the redeem branch. The result's commitment must equal
/// the corresponding lock commitment in the accepted Denuo session before a
/// caller funds, accepts, or spends it.
pub fn build_denuo_bitcoin_htlc(
    hello: &SwapSessionHello,
    side: SwapAssetSide,
) -> Result<DenuoBitcoinHtlcBinding, BitcoinWalletError> {
    let (asset, amount, deadline, receiver_bytes, refund_bytes) = match side {
        SwapAssetSide::Offered => (
            hello.offered_asset,
            hello.offered_amount.get(),
            hello.offered_refund_deadline.value,
            hello.taker_settlement_public_key,
            hello.maker_settlement_public_key,
        ),
        SwapAssetSide::Received => (
            hello.received_asset,
            hello.received_amount.get(),
            hello.received_refund_deadline.value,
            hello.maker_settlement_public_key,
            hello.taker_settlement_public_key,
        ),
    };
    if asset != AssetId::BTC {
        return Err(BitcoinWalletError::InvalidHtlc);
    }
    let value_sats = u64::try_from(amount).map_err(|_| BitcoinWalletError::InvalidAmount)?;
    let refund_locktime = u32::try_from(deadline).map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    if deadline < BITCOIN_TIMESTAMP_LOCKTIME_THRESHOLD {
        return Err(BitcoinWalletError::InvalidHtlc);
    }
    let receiver =
        PublicKey::from_slice(&receiver_bytes).map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    let refund =
        PublicKey::from_slice(&refund_bytes).map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    let htlc = BitcoinHtlc::new(hello.hashlock, receiver, refund, refund_locktime)?;
    let commitment = denuo_bitcoin_htlc_commitment(hello.header.network, &htlc, value_sats)?;
    Ok(DenuoBitcoinHtlcBinding {
        htlc,
        commitment,
        value_sats,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinLock {
    pub funding_txid: TransactionHash,
    pub output_index: u32,
    pub value_sats: u64,
    pub confirmation_count: u32,
    pub htlc: BitcoinHtlc,
}

pub fn verify_htlc_funding(
    raw_transaction: &[u8],
    htlc: &BitcoinHtlc,
    expected_value_sats: u64,
    confirmation_count: u32,
    minimum_confirmations: u32,
) -> Result<VerifiedBitcoinLock, BitcoinWalletError> {
    if raw_transaction.is_empty() || raw_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    if expected_value_sats < MIN_HTLC_DUST_SATS || confirmation_count < minimum_confirmations {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    htlc.validate()?;
    let transaction: Transaction =
        deserialize(raw_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let expected_script = htlc.script_pubkey();
    let mut matching = transaction.output.iter().enumerate().filter(|(_, output)| {
        output.value.to_sat() == expected_value_sats && output.script_pubkey == expected_script
    });
    let (output_index, _) = matching.next().ok_or(BitcoinWalletError::InvalidEvidence)?;
    if matching.next().is_some() {
        return Err(BitcoinWalletError::AmbiguousEvidence);
    }
    let txid = transaction.compute_txid().to_byte_array();
    Ok(VerifiedBitcoinLock {
        funding_txid: TransactionHash::new(txid),
        output_index: u32::try_from(output_index)
            .map_err(|_| BitcoinWalletError::InvalidEvidence)?,
        value_sats: expected_value_sats,
        confirmation_count,
        htlc: htlc.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtlcSpendBranch {
    Redeem,
    Refund,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinHtlcSpend {
    pub txid: TransactionHash,
    pub wtxid: [u8; 32],
    pub fee_sats: u64,
    pub branch: HtlcSpendBranch,
    pub revealed_preimage: Option<[u8; 32]>,
}

/// Locally validated chain state used to decide whether an absolute Bitcoin
/// refund lock can be mined in the next block. BIP113 evaluates time locks
/// against the median time of the preceding eleven blocks, never wall time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinChainLockContext {
    pub next_block_height: u32,
    pub median_time_past: u32,
}

impl BitcoinChainLockContext {
    pub fn validate(self) -> Result<(), BitcoinWalletError> {
        absolute::Height::from_consensus(self.next_block_height)
            .map_err(|_| BitcoinWalletError::InvalidChainLockContext)?;
        Ok(())
    }

    fn permits(self, lock_time: absolute::LockTime) -> bool {
        // Bitcoin Core requires nLockTime to be strictly below the candidate
        // block height or its preceding median-time-past. The transaction
        // itself uses exactly the CLTV argument, so equality is still early.
        match lock_time {
            absolute::LockTime::Blocks(required) => {
                required.to_consensus_u32() < self.next_block_height
            }
            absolute::LockTime::Seconds(required) => {
                required.to_consensus_u32() < self.median_time_past
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinHtlcSpendRequest {
    pub destination: ScriptBuf,
    pub fee_sats: u64,
    pub branch: HtlcSpendBranch,
    pub preimage: Option<[u8; 32]>,
    pub chain_context: BitcoinChainLockContext,
}

/// Constructs a policy-correct unsigned spend using a locally validated Kyoto
/// height/MTP view. A chain-specific signer fills the first witness item after
/// the approval boundary.
pub fn prepare_htlc_spend(
    lock: &VerifiedBitcoinLock,
    destination: ScriptBuf,
    fee_sats: u64,
    branch: HtlcSpendBranch,
    preimage: Option<&[u8; 32]>,
    chain_context: BitcoinChainLockContext,
) -> Result<Transaction, BitcoinWalletError> {
    chain_context.validate()?;
    prepare_htlc_spend_template(
        lock,
        destination,
        fee_sats,
        branch,
        preimage,
        Some(chain_context),
    )
}

fn prepare_htlc_spend_template(
    lock: &VerifiedBitcoinLock,
    destination: ScriptBuf,
    fee_sats: u64,
    branch: HtlcSpendBranch,
    preimage: Option<&[u8; 32]>,
    chain_context: Option<BitcoinChainLockContext>,
) -> Result<Transaction, BitcoinWalletError> {
    lock.htlc.validate()?;
    if fee_sats == 0 || fee_sats >= lock.value_sats {
        return Err(BitcoinWalletError::InvalidFee);
    }
    let output_value = lock
        .value_sats
        .checked_sub(fee_sats)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    if output_value < MIN_HTLC_DUST_SATS {
        return Err(BitcoinWalletError::Dust);
    }
    let (lock_time, sequence, witness_items) = match branch {
        HtlcSpendBranch::Redeem => {
            let secret = preimage.ok_or(BitcoinWalletError::MissingPreimage)?;
            if Sha256::digest(secret).as_slice() != lock.htlc.hashlock {
                return Err(BitcoinWalletError::InvalidPreimage);
            }
            (
                absolute::LockTime::ZERO,
                Sequence::MAX,
                vec![
                    Vec::new(),
                    secret.to_vec(),
                    vec![1],
                    lock.htlc.witness_script.clone(),
                ],
            )
        }
        HtlcSpendBranch::Refund => {
            let lock_time = absolute::LockTime::from_consensus(lock.htlc.refund_locktime);
            if preimage.is_some()
                || chain_context.is_some_and(|context| !context.permits(lock_time))
            {
                return Err(BitcoinWalletError::TimelockNotReached);
            }
            (
                lock_time,
                Sequence::ENABLE_LOCKTIME_NO_RBF,
                vec![Vec::new(), Vec::new(), lock.htlc.witness_script.clone()],
            )
        }
    };
    let outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    let witness = Witness::from_slice(&witness_items);
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness,
        }],
        output: vec![TxOut {
            value: BitcoinAmount::from_sat(output_value),
            script_pubkey: destination,
        }],
    })
}

/// Construct and sign the exact redeem or refund spend with the role-bound,
/// per-session swap key. The first witness element is a canonical DER ECDSA
/// signature with `SIGHASH_ALL`; the existing branch selector, preimage, and
/// witness script remain byte-for-byte unchanged.
pub fn sign_bitcoin_htlc_spend(
    lock: &VerifiedBitcoinLock,
    _permit: &BitcoinValueRuntimePermit,
    request: BitcoinHtlcSpendRequest,
    local_key: &DerivedBitcoinSwapKey,
) -> Result<Vec<u8>, BitcoinWalletError> {
    lock.htlc.validate()?;
    let expected_role = match request.branch {
        HtlcSpendBranch::Redeem => BitcoinSwapKeyRole::Receiver,
        HtlcSpendBranch::Refund => BitcoinSwapKeyRole::RefundOwner,
    };
    if local_key.public_key.reference.role() != expected_role {
        return Err(BitcoinWalletError::InvalidSwapKeyReference);
    }
    let public_key = local_key.public_key.bitcoin_public_key()?;
    let expected_public_key = match request.branch {
        HtlcSpendBranch::Redeem => &lock.htlc.receiver_public_key,
        HtlcSpendBranch::Refund => &lock.htlc.refund_public_key,
    };
    if public_key.to_bytes().as_slice() != expected_public_key {
        return Err(BitcoinWalletError::InvalidSwapKeyReference);
    }

    let transaction = prepare_htlc_spend(
        lock,
        request.destination,
        request.fee_sats,
        request.branch,
        request.preimage.as_ref(),
        request.chain_context,
    )?;
    let sighash_type = EcdsaSighashType::All;
    let sighash = SighashCache::new(&transaction)
        .p2wsh_signature_hash(
            0,
            &lock.htlc.witness_script(),
            BitcoinAmount::from_sat(lock.value_sats),
            sighash_type,
        )
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let message = Message::from_digest(sighash.to_byte_array());
    let mut secret = SecretKey::from_slice(&local_key._secret_key.0)
        .map_err(|_| BitcoinWalletError::InvalidSwapKeyReference)?;
    let secp = Secp256k1::new();
    let signature = secp.sign_ecdsa(&message, &secret);
    secret.non_secure_erase();
    finalize_signed_htlc_spend(
        transaction,
        request.branch,
        sighash.to_byte_array(),
        signature.serialize_compact(),
        &public_key,
    )
}

/// Construct and sign the exact redeem or refund spend with the chain-neutral
/// session signer shared by the HNS and Bitcoin adapters. Only the transaction
/// digest crosses the signer boundary; the scalar remains wallet-owned.
pub fn sign_bitcoin_htlc_spend_with_settlement_signer(
    lock: &VerifiedBitcoinLock,
    _permit: &BitcoinValueRuntimePermit,
    request: BitcoinHtlcSpendRequest,
    signer: &dyn SettlementSigner,
) -> Result<Vec<u8>, BitcoinWalletError> {
    lock.htlc.validate()?;
    let expected_public_key = match request.branch {
        HtlcSpendBranch::Redeem => &lock.htlc.receiver_public_key,
        HtlcSpendBranch::Refund => &lock.htlc.refund_public_key,
    };
    let public_key = PublicKey::from_slice(&signer.compressed_public_key())
        .map_err(|_| BitcoinWalletError::InvalidSwapKeyReference)?;
    if public_key.to_bytes().as_slice() != expected_public_key {
        return Err(BitcoinWalletError::InvalidSwapKeyReference);
    }
    let transaction = prepare_htlc_spend(
        lock,
        request.destination,
        request.fee_sats,
        request.branch,
        request.preimage.as_ref(),
        request.chain_context,
    )?;
    let sighash = SighashCache::new(&transaction)
        .p2wsh_signature_hash(
            0,
            &lock.htlc.witness_script(),
            BitcoinAmount::from_sat(lock.value_sats),
            EcdsaSighashType::All,
        )
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?
        .to_byte_array();
    let signature = signer
        .sign_digest(sighash)
        .map_err(|_| BitcoinWalletError::SigningIncomplete)?;
    finalize_signed_htlc_spend(transaction, request.branch, sighash, signature, &public_key)
}

fn finalize_signed_htlc_spend(
    mut transaction: Transaction,
    branch: HtlcSpendBranch,
    sighash: [u8; 32],
    signature: [u8; 64],
    public_key: &PublicKey,
) -> Result<Vec<u8>, BitcoinWalletError> {
    let signature =
        Signature::from_compact(&signature).map_err(|_| BitcoinWalletError::SigningIncomplete)?;
    let signature_is_high_s = {
        let mut normalized = signature;
        normalized.normalize_s();
        normalized != signature
    };
    if signature_is_high_s {
        return Err(BitcoinWalletError::SigningIncomplete);
    }
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(sighash),
            &signature,
            &public_key.inner,
        )
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let mut signature_bytes = signature.serialize_der().to_vec();
    signature_bytes.push(
        u8::try_from(EcdsaSighashType::All.to_u32())
            .map_err(|_| BitcoinWalletError::InvalidEvidence)?,
    );

    let mut witness = transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let expected_witness_items = match branch {
        HtlcSpendBranch::Redeem => 4,
        HtlcSpendBranch::Refund => 3,
    };
    if witness.len() != expected_witness_items || !witness[0].is_empty() {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    witness[0] = signature_bytes;
    transaction.input[0].witness = Witness::from_slice(&witness);
    let raw_transaction = serialize(&transaction);
    if raw_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    Ok(raw_transaction)
}

/// Re-authenticate a complete native HTLC spend at the durable broadcast
/// boundary. This verifies the exact funding outpoint, branch template,
/// preimage or refund locktime, fee, witness script, signer role, sighash type,
/// and ECDSA signature without treating a Kyoto peer or a caller assertion as
/// authority.
pub fn verify_signed_bitcoin_htlc_spend(
    raw_transaction: &[u8],
    lock: &VerifiedBitcoinLock,
    branch: HtlcSpendBranch,
) -> Result<VerifiedBitcoinHtlcSpend, BitcoinWalletError> {
    if raw_transaction.is_empty() || raw_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    lock.htlc.validate()?;
    let transaction: Transaction =
        deserialize(raw_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    if serialize(&transaction) != raw_transaction
        || transaction.input.len() != 1
        || transaction.output.len() != 1
    {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    let expected_outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    if transaction.input[0].previous_output != expected_outpoint {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    let output_sats = transaction.output[0].value.to_sat();
    let fee_sats = lock
        .value_sats
        .checked_sub(output_sats)
        .filter(|fee| *fee != 0)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    let witness = transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let (preimage, expected_public_key) = match branch {
        HtlcSpendBranch::Redeem => {
            if witness.len() != 4
                || witness[2].as_slice() != [1]
                || witness[3] != lock.htlc.witness_script
            {
                return Err(BitcoinWalletError::InvalidEvidence);
            }
            let preimage = <[u8; 32]>::try_from(witness[1].as_slice())
                .map_err(|_| BitcoinWalletError::InvalidPreimage)?;
            if Sha256::digest(preimage).as_slice() != lock.htlc.hashlock {
                return Err(BitcoinWalletError::InvalidPreimage);
            }
            (Some(preimage), &lock.htlc.receiver_public_key)
        }
        HtlcSpendBranch::Refund => {
            if witness.len() != 3
                || !witness[1].is_empty()
                || witness[2] != lock.htlc.witness_script
            {
                return Err(BitcoinWalletError::InvalidEvidence);
            }
            (None, &lock.htlc.refund_public_key)
        }
    };
    let mut expected = prepare_htlc_spend_template(
        lock,
        transaction.output[0].script_pubkey.clone(),
        fee_sats,
        branch,
        preimage.as_ref(),
        None,
    )?;
    let signature_bytes = witness
        .first()
        .filter(|signature| signature.len() > 1)
        .ok_or(BitcoinWalletError::InvalidEvidence)?;
    let sighash_flag = *signature_bytes
        .last()
        .ok_or(BitcoinWalletError::InvalidEvidence)?;
    if u32::from(sighash_flag) != EcdsaSighashType::All.to_u32() {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    let signature = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1])
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let mut normalized_signature = signature;
    normalized_signature.normalize_s();
    if normalized_signature != signature {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    let public_key = PublicKey::from_slice(expected_public_key)
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let sighash = SighashCache::new(&transaction)
        .p2wsh_signature_hash(
            0,
            &lock.htlc.witness_script(),
            BitcoinAmount::from_sat(lock.value_sats),
            EcdsaSighashType::All,
        )
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature,
            &public_key.inner,
        )
        .map_err(|_| BitcoinWalletError::InvalidEvidence)?;

    expected.input[0].witness = transaction.input[0].witness.clone();
    if expected != transaction {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    Ok(VerifiedBitcoinHtlcSpend {
        txid: TransactionHash::new(transaction.compute_txid().to_byte_array()),
        wtxid: transaction.compute_wtxid().to_byte_array(),
        fee_sats,
        branch,
        revealed_preimage: preimage,
    })
}

/// Extracts a revealed 32-byte preimage only from a transaction which spends
/// the expected funding output and contains the exact committed witness script.
pub fn observe_preimage(
    raw_spending_transaction: &[u8],
    lock: &VerifiedBitcoinLock,
) -> Result<Option<[u8; 32]>, BitcoinWalletError> {
    if raw_spending_transaction.is_empty()
        || raw_spending_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES
    {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    let transaction: Transaction =
        deserialize(raw_spending_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let expected_outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    let mut matching_inputs = transaction
        .input
        .iter()
        .filter(|input| input.previous_output == expected_outpoint);
    let input = matching_inputs
        .next()
        .ok_or(BitcoinWalletError::InvalidEvidence)?;
    if matching_inputs.next().is_some()
        || input.witness.last() != Some(lock.htlc.witness_script.as_slice())
    {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    for item in input.witness.iter() {
        if let Ok(candidate) = <[u8; 32]>::try_from(item) {
            let digest: [u8; 32] = sha256::Hash::hash(&candidate).to_byte_array();
            if digest == lock.htlc.hashlock {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

pub fn htlc_commitment(htlc: &BitcoinHtlc) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-bitcoin-htlc/v1");
    hasher.update(&htlc.witness_script);
    ObjectHash::new(hasher.finalize().into())
}

/// Produce the exact Bitcoin lock commitment which may be placed into the
/// Bitcoin side of a signed Denuo HNS/BTC session. A funding status still
/// carries its independently verified outpoint and amount; this commitment
/// ensures that the outpoint's P2WSH program is for the same hashlock, keys,
/// refund locktime, and chain network that both parties accepted.
pub fn denuo_bitcoin_htlc_commitment(
    network: DenuoNetworkBinding,
    htlc: &BitcoinHtlc,
    value_sats: u64,
) -> Result<ObjectHash, BitcoinWalletError> {
    network
        .validate_for_pair(MarketPair::HNS_BTC)
        .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    htlc.validate()?;
    if value_sats < MIN_HTLC_DUST_SATS {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    let network = network
        .encode()
        .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    let script_length =
        u16::try_from(htlc.witness_script.len()).map_err(|_| BitcoinWalletError::InvalidHtlc)?;
    let mut hasher = Sha256::new();
    hasher.update(DENUO_BITCOIN_HTLC_COMMITMENT_DOMAIN);
    hasher.update(network);
    hasher.update(value_sats.to_le_bytes());
    hasher.update(script_length.to_le_bytes());
    hasher.update(&htlc.witness_script);
    Ok(ObjectHash::new(hasher.finalize().into()))
}

/// Verify a Bitcoin descriptor against the commitment frozen in a Denuo
/// session before funding or accepting a claimed funding transaction.
pub fn verify_denuo_bitcoin_htlc_commitment(
    expected: ObjectHash,
    network: DenuoNetworkBinding,
    htlc: &BitcoinHtlc,
    value_sats: u64,
) -> Result<(), BitcoinWalletError> {
    if denuo_bitcoin_htlc_commitment(network, htlc, value_sats)? != expected {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum BitcoinWalletError {
    #[error("invalid Bitcoin module configuration")]
    InvalidConfiguration,
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("wallet recovery seed is missing")]
    MissingRecoverySeed,
    #[error("wallet recovery seed has an invalid length")]
    InvalidRecoverySeed,
    #[error("Bitcoin key derivation failed")]
    KeyDerivation,
    #[error("Bitcoin atomic-swap key reference is invalid or unbounded")]
    InvalidSwapKeyReference,
    #[error("Bitcoin wallet was not found in persistence")]
    WalletNotFound,
    #[error("Bitcoin wallet persistence already contains an account")]
    WalletAlreadyExists,
    #[error("Bitcoin descriptor wallet creation failed")]
    WalletCreationFailed,
    #[error("Bitcoin wallet persistence was used before initialization")]
    BitcoinWalletPersisterUninitialized,
    #[error("persisted Bitcoin wallet state uses an unsupported format")]
    UnsupportedBitcoinWalletState,
    #[error("persisted Bitcoin wallet state is corrupt")]
    CorruptBitcoinWalletState,
    #[error("persisted Bitcoin wallet descriptor or network is immutable")]
    BitcoinWalletStateConflict,
    #[error("Bitcoin wallet and runtime do not share the same store/account authority")]
    WalletStoreAuthorityMismatch,
    #[error("Bitcoin wallet error: {0}")]
    Wallet(String),
    #[error("Kyoto client error: {0}")]
    Kyoto(String),
    #[error("Kyoto node stopped before completing synchronization")]
    KyotoNodeStopped,
    #[error("Kyoto supervisor operation exceeded its configured timeout")]
    OperationTimedOut,
    #[error("Kyoto supervisor must be discarded and restarted")]
    SupervisorPoisoned,
    #[error("Kyoto wallet state is not at a durable ready checkpoint")]
    RuntimeNotReady,
    #[error("Kyoto does not currently have the required peer quorum")]
    PeerQuorumUnavailable,
    #[error("a Tokio runtime is required to supervise Kyoto")]
    RuntimeUnavailable,
    #[error(transparent)]
    Store(#[from] hns_wallet_store::StoreError),
    #[error("address or wallet network mismatch")]
    NetworkMismatch,
    #[error("invalid destination")]
    InvalidDestination,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("invalid or excessive fee")]
    InvalidFee,
    #[error("fee exceeds approved maximum")]
    FeeLimit,
    #[error("transaction signing was incomplete")]
    SigningIncomplete,
    #[error("transaction exceeds bounded maximum")]
    TransactionTooLarge,
    #[error("invalid HTLC parameters or script")]
    InvalidHtlc,
    #[error("locally validated Bitcoin height/median-time-past context is invalid")]
    InvalidChainLockContext,
    #[error("HTLC output is dust")]
    Dust,
    #[error("required preimage is missing")]
    MissingPreimage,
    #[error("preimage does not match hashlock")]
    InvalidPreimage,
    #[error("refund timelock has not been reached")]
    TimelockNotReached,
    #[error("chain evidence is missing or inconsistent")]
    InvalidEvidence,
    #[error("chain evidence contains multiple possible matches")]
    AmbiguousEvidence,
    #[error("Bitcoin checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("Bitcoin checkpoint does not match the applied wallet update")]
    CheckpointMismatch,
    #[error("Bitcoin wallet birthday is invalid")]
    InvalidBirthday,
    #[error("Bitcoin recovery script index is invalid or unbounded")]
    InvalidRecoveryScriptIndex,
    #[error("Bitcoin runtime state uses an unsupported schema version")]
    UnsupportedStateVersion,
    #[error("Bitcoin runtime state is corrupt or internally inconsistent")]
    CorruptRuntimeState,
    #[error("Bitcoin runtime sequence overflow")]
    SequenceOverflow,
    #[error("Bitcoin checkpoint retention capacity was exceeded")]
    CheckpointCapacity,
    #[error("a reorganization exceeded the retained recovery boundary")]
    DeepReorganization,
    #[error("Bitcoin transaction tracking capacity was exceeded")]
    BitcoinTransactionCapacity,
    #[error("Bitcoin output tracking capacity was exceeded")]
    BitcoinOutputCapacity,
    #[error("Bitcoin scan state was not found")]
    BitcoinStateNotFound,
    #[error("Bitcoin value operations are disabled until release qualification")]
    ValueOperationsDisabled,
    #[error("Bitcoin broadcast approval is invalid")]
    InvalidBroadcastApproval,
    #[error("prepared Bitcoin broadcast conflicts with durable state")]
    BroadcastConflict,
    #[error("Bitcoin HTLC compact-filter watch request is invalid")]
    InvalidSwapWatch,
    #[error("Bitcoin HTLC compact-filter watch conflicts with durable state")]
    SwapWatchConflict,
    #[error("Bitcoin HTLC compact-filter watch capacity reached")]
    SwapWatchCapacity,
    #[error("persisted Bitcoin HTLC compact-filter watch is corrupt")]
    CorruptSwapWatch,
    #[error("prepared Bitcoin broadcast was not found")]
    BroadcastIntentNotFound,
    #[error("Bitcoin transaction is not durably prepared for broadcast")]
    BroadcastNotPrepared,
    #[error("Bitcoin broadcast approval has expired")]
    BroadcastApprovalExpired,
    #[error("Bitcoin broadcast clock moved behind durable approval state")]
    ClockRollbackDetected,
    #[error("Bitcoin broadcast retry interval has not elapsed")]
    BroadcastRetryNotReady,
    #[error("Bitcoin broadcast retry limit was reached")]
    BroadcastAttemptLimit,
    #[error("Kyoto returned a broadcast receipt for a different transaction")]
    BroadcastReceiptMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::bip32::DerivationPath;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use hns_marketplace_protocol::{
        AssetAmount, ChainId, DeadlineKind, MarketPair, SettlementDeadline, SignedObjectHeader,
    };
    use hns_primitives::BlockHash;
    use hns_wallet_chain_api::{SettlementSigner, SettlementSigningError};
    use hns_wallet_store::WalletStore;

    struct TestSettlementSigner(SecretKey);

    impl SettlementSigner for TestSettlementSigner {
        fn compressed_public_key(&self) -> [u8; 33] {
            self.0.public_key(&Secp256k1::new()).serialize()
        }

        fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 64], SettlementSigningError> {
            Ok(Secp256k1::new()
                .sign_ecdsa(&Message::from_digest(digest), &self.0)
                .serialize_compact())
        }
    }

    fn key(byte: u8) -> PublicKey {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("valid deterministic key");
        PublicKey::new(secret.public_key(&Secp256k1::new()))
    }

    fn htlc() -> BitcoinHtlc {
        let preimage = [9_u8; 32];
        BitcoinHtlc::new(Sha256::digest(preimage).into(), key(3), key(4), 500).expect("valid HTLC")
    }

    fn chain_context(next_block_height: u32) -> BitcoinChainLockContext {
        BitcoinChainLockContext {
            next_block_height,
            median_time_past: 500_000_000,
        }
    }

    fn funding(htlc: &BitcoinHtlc, value: u64) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: BitcoinAmount::from_sat(value),
                script_pubkey: htlc.script_pubkey(),
            }],
        }
    }

    fn denuo_network(counterchain_network: u64) -> DenuoNetworkBinding {
        DenuoNetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network,
            counterchain_genesis: [2; 32],
        }
    }

    fn denuo_hello(bitcoin_side: SwapAssetSide) -> SwapSessionHello {
        let (offered_asset, received_asset) = match bitcoin_side {
            SwapAssetSide::Offered => (AssetId::BTC, AssetId::HNS),
            SwapAssetSide::Received => (AssetId::HNS, AssetId::BTC),
        };
        SwapSessionHello {
            header: SignedObjectHeader {
                version: hns_marketplace_protocol::MARKETPLACE_PROTOCOL_VERSION,
                network: denuo_network(1),
                pair: MarketPair::HNS_BTC,
                signer_public_key: key(9).to_bytes().try_into().expect("signer SEC1"),
                sequence: 1,
                created_at: 10,
                expires_at: 900,
            },
            direct_offer_id: [1; 32],
            swap_session_id: [2; 32],
            maker_settlement_public_key: key(3).to_bytes().try_into().expect("maker SEC1"),
            taker_settlement_public_key: key(4).to_bytes().try_into().expect("taker SEC1"),
            offered_asset,
            offered_amount: AssetAmount::new(50_000),
            received_asset,
            received_amount: AssetAmount::new(1_000),
            hashlock: [4; 32],
            first_funding_chain: ChainId::BITCOIN,
            offered_lock_commitment: [0; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 1_800_000_000,
            },
            offered_minimum_confirmations: 2,
            received_lock_commitment: [0; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 1_700_000_000,
            },
            received_minimum_confirmations: 2,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        }
    }

    #[test]
    fn denuo_bitcoin_descriptor_assigns_redeem_and_refund_to_signed_parties() {
        let hello = denuo_hello(SwapAssetSide::Received);
        let binding =
            build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Received).expect("Bitcoin descriptor");
        assert_eq!(binding.value_sats, 1_000);
        assert_eq!(binding.htlc.receiver_public_key, key(3).to_bytes());
        assert_eq!(binding.htlc.refund_public_key, key(4).to_bytes());
        verify_denuo_bitcoin_htlc_commitment(
            binding.commitment,
            hello.header.network,
            &binding.htlc,
            binding.value_sats,
        )
        .expect("same Denuo binding");
        assert!(build_denuo_bitcoin_htlc(&hello, SwapAssetSide::Offered).is_err());
        let mut height_like_deadline = hello;
        height_like_deadline.received_refund_deadline.value = 500;
        assert!(build_denuo_bitcoin_htlc(&height_like_deadline, SwapAssetSide::Received).is_err());
    }

    #[test]
    fn denuo_bitcoin_commitment_binds_network_amount_and_exact_htlc_script() {
        let htlc = htlc();
        let network = denuo_network(1);
        let commitment = denuo_bitcoin_htlc_commitment(network, &htlc, 50_000)
            .expect("canonical Denuo Bitcoin commitment");
        verify_denuo_bitcoin_htlc_commitment(commitment, network, &htlc, 50_000)
            .expect("same descriptor verifies");
        assert!(verify_denuo_bitcoin_htlc_commitment(commitment, network, &htlc, 50_001).is_err());
        assert!(
            verify_denuo_bitcoin_htlc_commitment(commitment, denuo_network(2), &htlc, 50_000,)
                .is_err()
        );
        let changed_script =
            BitcoinHtlc::new(htlc.hashlock, key(3), key(5), 500).expect("different refund key");
        assert!(
            verify_denuo_bitcoin_htlc_commitment(commitment, network, &changed_script, 50_000,)
                .is_err()
        );
    }

    #[test]
    fn swap_key_derivation_has_stable_public_vectors() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("valid phrase");
        let mainnet_reference =
            BitcoinSwapKeyReference::new(Network::Bitcoin, BitcoinSwapKeyRole::Receiver, 0, 0)
                .expect("bounded reference");
        let mainnet =
            derive_bitcoin_swap_key(&mnemonic, mainnet_reference).expect("derived swap key");
        assert_eq!(
            mainnet
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_string(),
            "025e70317534f24fafdbcbd0f8524967de9a5c6f6dc9655872ddb6adba94174bff"
        );
        assert!(format!("{mainnet:?}").contains("[REDACTED]"));

        let regtest_reference =
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::Receiver, 0, 0)
                .expect("bounded reference");
        let regtest =
            derive_bitcoin_swap_key(&mnemonic, regtest_reference).expect("derived swap key");
        assert_eq!(regtest_reference.coin_type(), 1);
        assert_eq!(regtest_reference.network_code(), 4);
        assert_eq!(
            regtest
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_string(),
            "02de93cfd4281366f4308cc0ed7df6753c2bb3bd3e9ef32cc2e22c28f9745277b3"
        );
        assert_ne!(mainnet.public_key(), regtest.public_key());
    }

    #[test]
    fn swap_roles_are_bounded_and_do_not_reuse_bip84_keys() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("valid phrase");
        let receiver_reference =
            BitcoinSwapKeyReference::new(Network::Bitcoin, BitcoinSwapKeyRole::Receiver, 0, 0)
                .expect("bounded reference");
        let refund_reference =
            BitcoinSwapKeyReference::new(Network::Bitcoin, BitcoinSwapKeyRole::RefundOwner, 0, 0)
                .expect("bounded reference");
        let receiver =
            derive_bitcoin_swap_key(&mnemonic, receiver_reference).expect("receiver key");
        let refund = derive_bitcoin_swap_key(&mnemonic, refund_reference).expect("refund key");
        assert_eq!(
            refund
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_string(),
            "03a5f831491d756b0429dbe97b54280091883d16b0a9f79b74e220dfafe823f7af"
        );
        assert_ne!(receiver.public_key(), refund.public_key());

        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        let root = Xpriv::new_master(Network::Bitcoin, seed.as_slice()).expect("BIP84 root");
        for ordinary_path in ["m/84'/0'/0'/0/0", "m/84'/0'/0'/1/0"] {
            let ordinary_path = DerivationPath::from_str(ordinary_path).expect("BIP84 path");
            let ordinary = root
                .derive_priv(&Secp256k1::new(), &ordinary_path)
                .expect("ordinary receive/change key");
            let ordinary_public =
                PublicKey::new(ordinary.private_key.public_key(&Secp256k1::new()));
            assert_ne!(
                receiver
                    .public_key()
                    .bitcoin_public_key()
                    .expect("compressed public key"),
                ordinary_public
            );
        }

        let mut unsupported_reference = receiver_reference;
        unsupported_reference.scheme_version = BITCOIN_SWAP_KEY_SCHEME_VERSION + 1;
        assert!(matches!(
            derive_bitcoin_swap_key(&mnemonic, unsupported_reference),
            Err(BitcoinWalletError::InvalidSwapKeyReference)
        ));

        assert!(matches!(
            BitcoinSwapKeyReference::new(
                Network::Bitcoin,
                BitcoinSwapKeyRole::Receiver,
                MAX_BITCOIN_SWAP_ACCOUNT_INDEX + 1,
                0
            ),
            Err(BitcoinWalletError::InvalidSwapKeyReference)
        ));
        assert!(matches!(
            BitcoinSwapKeyReference::new(
                Network::Bitcoin,
                BitcoinSwapKeyRole::Receiver,
                0,
                MAX_BITCOIN_SWAP_KEY_INDEX + 1
            ),
            Err(BitcoinWalletError::InvalidSwapKeyReference)
        ));
    }

    #[test]
    fn derived_swap_role_is_bound_to_the_htlc_position() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("valid phrase");
        let receiver_reference =
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::Receiver, 7, 42)
                .expect("bounded reference");
        let receiver =
            derive_bitcoin_swap_key(&mnemonic, receiver_reference).expect("receiver key");
        assert_eq!(
            receiver
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_string(),
            "0250713ff8ce00f01a5957b253d1f0f72b6fa56cc3fa1de6b60bbf66a58482118b"
        );

        let preimage = [9_u8; 32];
        let htlc = BitcoinHtlc::new_with_local_swap_key(
            Sha256::digest(preimage).into(),
            &receiver,
            key(4),
            500,
        )
        .expect("role-bound HTLC");
        assert_eq!(
            htlc.receiver_public_key,
            receiver
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_bytes()
        );

        let refund_reference =
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::RefundOwner, 7, 42)
                .expect("bounded reference");
        let refund = derive_bitcoin_swap_key(&mnemonic, refund_reference).expect("refund key");
        let refund_htlc = BitcoinHtlc::new_with_local_swap_key(
            Sha256::digest(preimage).into(),
            &refund,
            key(3),
            500,
        )
        .expect("role-bound HTLC");
        assert_eq!(
            refund_htlc.refund_public_key,
            refund
                .public_key()
                .bitcoin_public_key()
                .expect("compressed public key")
                .to_bytes()
        );
    }

    #[test]
    fn key_roles_are_deterministic_and_network_bound() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("valid phrase");
        let mut first = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        let mut second = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        assert_eq!(
            next_receive_address(&mut first),
            next_receive_address(&mut second)
        );
    }

    #[test]
    fn new_wallet_birthday_does_not_start_at_genesis() {
        let recovery_anchor = BitcoinCheckpoint {
            height: 849_990,
            block_hash: [2; 32],
        };
        let checkpoint = BitcoinCheckpoint {
            height: 850_000,
            block_hash: [1; 32],
        };
        let validated_tip = DiscoveredKyotoTip::testing(
            Network::Bitcoin,
            checkpoint,
            recovery_anchor,
            vec![recovery_anchor, checkpoint],
        );
        let state = KyotoWalletState::new_wallet(validated_tip, 1).expect("validated birthday");
        assert_eq!(state.birthday.checkpoint, checkpoint);
        assert_eq!(state.recovery_checkpoint, recovery_anchor);
        assert_eq!(state.recent_checkpoints, vec![recovery_anchor, checkpoint]);
        assert_eq!(state.scanned_checkpoint, checkpoint);
    }

    #[test]
    fn native_htlc_script_and_funding_are_exact() {
        let htlc = htlc();
        htlc.validate().expect("canonical script");
        let tx = funding(&htlc, 50_000);
        let verified =
            verify_htlc_funding(&serialize(&tx), &htlc, 50_000, 6, 6).expect("verified funding");
        assert_eq!(verified.output_index, 0);
        assert!(verify_htlc_funding(&serialize(&tx), &htlc, 50_001, 6, 6).is_err());
    }

    #[test]
    fn descriptor_wallet_funds_exact_htlc_with_signed_inputs() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("mnemonic");
        let mut wallet = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        let receive = wallet.reveal_next_address(KeychainKind::External).address;
        let funding_transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bdk_wallet::bitcoin::Txid::from_byte_array([42; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: BitcoinAmount::from_sat(100_000),
                script_pubkey: receive.script_pubkey(),
            }],
        };
        wallet.apply_unconfirmed_txs([(funding_transaction, 1)]);
        let htlc = htlc();
        let permit = BitcoinValueRuntimePermit(());
        let prepared = prepare_bitcoin_htlc_funding(&mut wallet, &permit, &htlc, 50_000, 2, 5_000)
            .expect("signed HTLC funding");
        assert!(prepared.fee_sats > 0);
        assert!(format!("{prepared:?}").contains("[REDACTED]"));
        let verified = verify_htlc_funding(prepared.raw_transaction(), &htlc, 50_000, 0, 0)
            .expect("exact funding output");
        assert_eq!(verified.funding_txid, prepared.txid);
        let transaction: Transaction =
            deserialize(prepared.raw_transaction()).expect("funding transaction");
        assert!(
            transaction
                .input
                .iter()
                .all(|input| !input.witness.is_empty())
        );
    }

    #[test]
    fn redeem_reveals_preimage_and_refund_enforces_height() {
        let htlc = htlc();
        let tx = funding(&htlc, 50_000);
        let lock =
            verify_htlc_funding(&serialize(&tx), &htlc, 50_000, 6, 6).expect("verified funding");
        let destination = ScriptBuf::new_p2wpkh(&key(8).wpubkey_hash().expect("compressed"));
        let preimage = [9_u8; 32];
        let redeem = prepare_htlc_spend(
            &lock,
            destination.clone(),
            500,
            HtlcSpendBranch::Redeem,
            Some(&preimage),
            chain_context(400),
        )
        .expect("redeem template");
        assert_eq!(
            observe_preimage(&serialize(&redeem), &lock).expect("valid spend evidence"),
            Some(preimage)
        );
        assert!(matches!(
            prepare_htlc_spend(
                &lock,
                destination.clone(),
                500,
                HtlcSpendBranch::Refund,
                None,
                chain_context(500)
            ),
            Err(BitcoinWalletError::TimelockNotReached)
        ));
        let refund = prepare_htlc_spend(
            &lock,
            destination,
            500,
            HtlcSpendBranch::Refund,
            None,
            chain_context(501),
        )
        .expect("refund template");
        assert_eq!(
            refund.lock_time,
            absolute::LockTime::from_height(500).unwrap()
        );
    }

    #[test]
    fn timestamp_refund_uses_median_time_past_not_wall_time_or_estimated_height() {
        let deadline = 1_800_000_000;
        let htlc = BitcoinHtlc::new(Sha256::digest([9_u8; 32]).into(), key(3), key(4), deadline)
            .expect("timestamp HTLC");
        let lock = verify_htlc_funding(&serialize(&funding(&htlc, 50_000)), &htlc, 50_000, 1, 1)
            .expect("funding lock");
        let destination = ScriptBuf::new_p2wpkh(&key(8).wpubkey_hash().expect("compressed"));
        assert!(matches!(
            prepare_htlc_spend(
                &lock,
                destination.clone(),
                500,
                HtlcSpendBranch::Refund,
                None,
                BitcoinChainLockContext {
                    next_block_height: 900_000,
                    median_time_past: deadline,
                },
            ),
            Err(BitcoinWalletError::TimelockNotReached)
        ));
        let refund = prepare_htlc_spend(
            &lock,
            destination,
            500,
            HtlcSpendBranch::Refund,
            None,
            BitcoinChainLockContext {
                next_block_height: 1,
                median_time_past: deadline + 1,
            },
        )
        .expect("timestamp refund template");
        assert_eq!(
            refund.lock_time,
            absolute::LockTime::from_time(deadline).unwrap()
        );
    }

    #[test]
    fn role_bound_swap_keys_sign_redeem_and_refund_witnesses() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("mnemonic");
        let receiver = derive_bitcoin_swap_key(
            &mnemonic,
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::Receiver, 0, 9)
                .expect("receiver reference"),
        )
        .expect("receiver key");
        let refund = derive_bitcoin_swap_key(
            &mnemonic,
            BitcoinSwapKeyReference::new(Network::Regtest, BitcoinSwapKeyRole::RefundOwner, 0, 10)
                .expect("refund reference"),
        )
        .expect("refund key");
        let preimage = [9_u8; 32];
        let htlc = BitcoinHtlc::new(
            Sha256::digest(preimage).into(),
            receiver
                .public_key()
                .bitcoin_public_key()
                .expect("receiver public key"),
            refund
                .public_key()
                .bitcoin_public_key()
                .expect("refund public key"),
            500,
        )
        .expect("HTLC");
        let lock = verify_htlc_funding(&serialize(&funding(&htlc, 50_000)), &htlc, 50_000, 6, 6)
            .expect("lock");
        let destination = ScriptBuf::new_p2wpkh(&key(8).wpubkey_hash().expect("compressed"));
        let permit = BitcoinValueRuntimePermit(());
        let redeem = sign_bitcoin_htlc_spend(
            &lock,
            &permit,
            BitcoinHtlcSpendRequest {
                destination: destination.clone(),
                fee_sats: 500,
                branch: HtlcSpendBranch::Redeem,
                preimage: Some(preimage),
                chain_context: chain_context(400),
            },
            &receiver,
        )
        .expect("signed redeem");
        let redeem_transaction: Transaction = deserialize(&redeem).expect("redeem transaction");
        assert!(!redeem_transaction.input[0].witness[0].is_empty());
        let verified_redeem =
            verify_signed_bitcoin_htlc_spend(&redeem, &lock, HtlcSpendBranch::Redeem)
                .expect("verify signed redeem");
        assert_eq!(verified_redeem.fee_sats, 500);
        assert_eq!(verified_redeem.revealed_preimage, Some(preimage));
        assert_eq!(
            observe_preimage(&redeem, &lock).expect("redeem evidence"),
            Some(preimage)
        );
        let wallet = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        let approval = derive_bitcoin_htlc_spend_broadcast_approval(
            &wallet,
            &redeem,
            &lock,
            HtlcSpendBranch::Redeem,
            1_000,
            200,
        )
        .expect("HTLC spend approval");
        let mut store = WalletStore::create(":memory:", "htlc-broadcast").expect("store");
        let persisted = persist_prepared_bitcoin_htlc_spend_broadcast(
            &wallet,
            &mut store,
            &redeem,
            &lock,
            HtlcSpendBranch::Redeem,
            approval.commitment,
            1_000,
            0,
            100,
            200,
        )
        .expect("persist HTLC spend");
        assert_eq!(persisted.txid, verified_redeem.txid.into_bytes());
        let stored = store
            .bitcoin_transaction::<BitcoinTransactionRecord>(&persisted.txid)
            .expect("load broadcast")
            .expect("broadcast record");
        assert_eq!(
            stored.value.raw_transaction.as_deref(),
            Some(redeem.as_slice())
        );
        assert_eq!(
            stored
                .value
                .broadcast
                .as_ref()
                .map(|intent| intent.fee_sats),
            Some(500)
        );

        let mut changed_output = redeem_transaction.clone();
        changed_output.output[0].value = BitcoinAmount::from_sat(49_499);
        assert!(
            verify_signed_bitcoin_htlc_spend(
                &serialize(&changed_output),
                &lock,
                HtlcSpendBranch::Redeem,
            )
            .is_err()
        );
        assert!(matches!(
            sign_bitcoin_htlc_spend(
                &lock,
                &permit,
                BitcoinHtlcSpendRequest {
                    destination: destination.clone(),
                    fee_sats: 500,
                    branch: HtlcSpendBranch::Redeem,
                    preimage: Some(preimage),
                    chain_context: chain_context(400),
                },
                &refund,
            ),
            Err(BitcoinWalletError::InvalidSwapKeyReference)
        ));

        let refund_transaction = sign_bitcoin_htlc_spend(
            &lock,
            &permit,
            BitcoinHtlcSpendRequest {
                destination,
                fee_sats: 500,
                branch: HtlcSpendBranch::Refund,
                preimage: None,
                chain_context: chain_context(501),
            },
            &refund,
        )
        .expect("signed refund");
        let refund_transaction: Transaction =
            deserialize(&refund_transaction).expect("refund transaction");
        assert!(!refund_transaction.input[0].witness[0].is_empty());
        assert_eq!(refund_transaction.input[0].witness.len(), 3);
        assert_eq!(
            refund_transaction.lock_time,
            absolute::LockTime::from_height(500).unwrap()
        );
    }

    #[test]
    fn shared_settlement_signer_signs_the_exact_bitcoin_htlc_branch() {
        let signer = TestSettlementSigner(SecretKey::from_slice(&[3; 32]).expect("signer key"));
        let signer_public_key =
            PublicKey::from_slice(&signer.compressed_public_key()).expect("signer public key");
        let preimage = [9_u8; 32];
        let htlc = BitcoinHtlc::new(
            Sha256::digest(preimage).into(),
            signer_public_key,
            key(4),
            500,
        )
        .expect("HTLC");
        let lock = verify_htlc_funding(&serialize(&funding(&htlc, 50_000)), &htlc, 50_000, 1, 1)
            .expect("funding lock");
        let raw = sign_bitcoin_htlc_spend_with_settlement_signer(
            &lock,
            &BitcoinValueRuntimePermit(()),
            BitcoinHtlcSpendRequest {
                destination: ScriptBuf::new_p2wpkh(
                    &key(8).wpubkey_hash().expect("compressed destination"),
                ),
                fee_sats: 500,
                branch: HtlcSpendBranch::Redeem,
                preimage: Some(preimage),
                chain_context: chain_context(501),
            },
            &signer,
        )
        .expect("shared settlement signer spend");
        assert!(verify_signed_bitcoin_htlc_spend(&raw, &lock, HtlcSpendBranch::Redeem).is_ok());
    }

    #[test]
    fn reorg_rewinds_wallet_owned_progress() {
        let first = BitcoinCheckpoint {
            height: 120,
            block_hash: [1; 32],
        };
        let second = BitcoinCheckpoint {
            height: 121,
            block_hash: [2; 32],
        };
        assert_eq!(
            highest_common_checkpoint(&[first, second], &[first]),
            Some(first)
        );
    }
}
