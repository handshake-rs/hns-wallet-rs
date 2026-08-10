#![doc = "Kyoto-only Bitcoin wallet integration and native HTLC settlement."]
#![forbid(unsafe_code)]

mod persistence;
mod runtime;
mod swap_key_store;

pub use persistence::*;
pub use runtime::*;
pub use swap_key_store::*;

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
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
use bdk_wallet::bitcoin::{
    Address, Amount as BitcoinAmount, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, bip32::Xpriv, psbt::Psbt, transaction,
};
use bdk_wallet::template::Bip84;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use hns_wallet_types::{
    ChainCapabilities, FeeModel, FinalityModel, HashAlgorithm, LocktimeModel, ObjectHash,
    SessionId, TransactionHash, WalletId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MIN_HTLC_DUST_SATS: u64 = 330;
pub const MAX_HTLC_SCRIPT_BYTES: usize = 256;
pub const MAX_BITCOIN_TRANSACTION_BYTES: usize = 400_000;
pub const MAX_REQUIRED_PEERS: u8 = 8;
pub const MAX_RECOVERY_SCRIPT_INDEX: u32 = 100_000;
pub const BITCOIN_SWAP_KEY_SCHEME_VERSION: u16 = 1;
pub const MAX_BITCOIN_SWAP_ACCOUNT_INDEX: u32 = 100_000;
pub const MAX_BITCOIN_SWAP_KEY_INDEX: u32 = 100_000;
pub const DEFAULT_REQUIRED_PEERS: u8 = 3;
pub const MAX_KYOTO_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_KYOTO_SYNC_TIMEOUT: Duration = Duration::from_secs(86_400);
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
        locktime_model: LocktimeModel::BlockHeight,
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
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
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
        .fee_rate(fee_rate)
        .only_witness_utxo();
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
    pub refund_height: u32,
    pub witness_script: Vec<u8>,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinHtlc {
    pub fn new(
        hashlock: [u8; 32],
        receiver_public_key: PublicKey,
        refund_public_key: PublicKey,
        refund_height: u32,
    ) -> Result<Self, BitcoinWalletError> {
        if hashlock == [0; 32] || refund_height == 0 {
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
            .push_int(i64::from(refund_height))
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
            refund_height,
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
        refund_height: u32,
    ) -> Result<Self, BitcoinWalletError> {
        let local_public_key = local_key.public_key().bitcoin_public_key()?;
        match local_key.public_key().reference().role() {
            BitcoinSwapKeyRole::Receiver => Self::new(
                hashlock,
                local_public_key,
                counterparty_public_key,
                refund_height,
            ),
            BitcoinSwapKeyRole::RefundOwner => Self::new(
                hashlock,
                counterparty_public_key,
                local_public_key,
                refund_height,
            ),
        }
    }

    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        let receiver = PublicKey::from_slice(&self.receiver_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let refund = PublicKey::from_slice(&self.refund_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let expected = Self::new(self.hashlock, receiver, refund, self.refund_height)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HtlcSpendBranch {
    Redeem,
    Refund,
}

/// Constructs a policy-correct unsigned spend. A chain-specific signer fills
/// the first witness item after the approval boundary.
pub fn prepare_htlc_spend(
    lock: &VerifiedBitcoinLock,
    destination: ScriptBuf,
    fee_sats: u64,
    branch: HtlcSpendBranch,
    preimage: Option<&[u8; 32]>,
    current_height: u32,
) -> Result<Transaction, BitcoinWalletError> {
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
    let (lock_time, sequence, branch_selector, preimage_item) = match branch {
        HtlcSpendBranch::Redeem => {
            let secret = preimage.ok_or(BitcoinWalletError::MissingPreimage)?;
            if Sha256::digest(secret).as_slice() != lock.htlc.hashlock {
                return Err(BitcoinWalletError::InvalidPreimage);
            }
            (
                absolute::LockTime::ZERO,
                Sequence::MAX,
                vec![1],
                secret.to_vec(),
            )
        }
        HtlcSpendBranch::Refund => {
            if preimage.is_some() || current_height < lock.htlc.refund_height {
                return Err(BitcoinWalletError::TimelockNotReached);
            }
            (
                absolute::LockTime::from_height(lock.htlc.refund_height)
                    .map_err(|_| BitcoinWalletError::InvalidHtlc)?,
                Sequence::ENABLE_LOCKTIME_NO_RBF,
                Vec::new(),
                Vec::new(),
            )
        }
    };
    let outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    let witness = Witness::from_slice(&[
        Vec::new(),
        preimage_item,
        branch_selector,
        lock.htlc.witness_script.clone(),
    ]);
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

    fn key(byte: u8) -> PublicKey {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("valid deterministic key");
        PublicKey::new(secret.public_key(&Secp256k1::new()))
    }

    fn htlc() -> BitcoinHtlc {
        let preimage = [9_u8; 32];
        BitcoinHtlc::new(Sha256::digest(preimage).into(), key(3), key(4), 500).expect("valid HTLC")
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
            "020a32c24be2befb82a9a41ef0941379195f3e7112a051f282a304757d821c79a0"
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
            400,
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
                499
            ),
            Err(BitcoinWalletError::TimelockNotReached)
        ));
        let refund =
            prepare_htlc_spend(&lock, destination, 500, HtlcSpendBranch::Refund, None, 500)
                .expect("refund template");
        assert_eq!(
            refund.lock_time,
            absolute::LockTime::from_height(500).unwrap()
        );
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
