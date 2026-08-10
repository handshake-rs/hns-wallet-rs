#![doc = "Narrow native-ETH wallet, Helios evidence policy, and approved HTLC operations."]
#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use hns_wallet_store::{SecretKind, StoreError, WalletStore};
use hns_wallet_types::{
    ChainCapabilities, FeeModel, FinalityModel, HashAlgorithm, LocktimeModel, WalletId,
};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HELIOS_UPSTREAM_REVISION: &str = "43a8c9f3cdda41a6f383c4db41d9a83f102638b1";
pub const MAX_SIGNED_TRANSACTION_BYTES: usize = 131_072;
pub const NATIVE_TRANSFER_GAS: u64 = 21_000;
pub const HTLC_LOCK_GAS_LIMIT: u64 = 180_000;
pub const HTLC_REDEEM_GAS_LIMIT: u64 = 100_000;
pub const HTLC_REFUND_GAS_LIMIT: u64 = 100_000;
/// Helios-backed synchronization has no embedded, independently qualified
/// runtime in this source revision.
pub const ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED: bool = false;
/// Native-ETH signing and broadcast have no qualified product runtime.
pub const ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = false;
/// Cross-chain settlement remains sequenced after fixed-price Shakedex and its
/// independent chain/runtime qualification.
pub const ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED: bool = false;
/// No Ethereum mainnet deployment or value path is approved by this source.
pub const ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED: bool = false;

pub const fn capabilities() -> ChainCapabilities {
    ChainCapabilities {
        receive: true,
        send: ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED && ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED,
        history: ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED,
        atomic_settlement: ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED
            && ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED
            && ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED,
        hash_algorithm: HashAlgorithm::Sha256,
        locktime_model: LocktimeModel::SmartContractTimestamp,
        finality_model: FinalityModel::EthereumFinalizedCheckpoint,
        fee_model: FeeModel::GasAndPriority,
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EthereumAddress([u8; 20]);

impl EthereumAddress {
    pub const ZERO: Self = Self([0; 20]);

    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, EthereumError> {
        let unprefixed = value.strip_prefix("0x").unwrap_or(value);
        if unprefixed.len() != 40 {
            return Err(EthereumError::InvalidAddress);
        }
        let mut bytes = [0_u8; 20];
        hex_decode(unprefixed, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", hex_encode(&self.0))
    }
}

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for EthereumAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EthereumAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct EthereumSecretMaterial([u8; 32]);

pub struct EthereumSecretKey {
    material: EthereumSecretMaterial,
    address: EthereumAddress,
    role: EthereumKeyRole,
}

impl fmt::Debug for EthereumSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EthereumSecretKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EthereumKeyRole {
    Wallet,
    AtomicSwap,
}

/// Opaque authorization for the dormant ordinary native-ETH value runtime.
/// The public acquisition function fails while the immutable release gate is
/// false; the private field prevents callers from fabricating a permit.
pub struct EthereumValueRuntimePermit(());

/// Opaque authorization for the independently gated settlement runtime.
pub struct EthereumSettlementRuntimePermit(());

/// Opaque provenance token for evidence produced by an embedded, qualified
/// Helios runtime. Caller-serialized verification booleans are not this token,
/// and no public constructor or release-flag-based acquisition path exists.
pub struct HeliosEvidenceRuntimePermit(());

pub fn ethereum_value_runtime_permit() -> Result<EthereumValueRuntimePermit, EthereumError> {
    if !ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED {
        return Err(EthereumError::ValueOperationsDisabled);
    }
    if !ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED {
        return Err(EthereumError::SynchronizationUnavailable);
    }
    Ok(EthereumValueRuntimePermit(()))
}

pub fn ethereum_settlement_runtime_permit() -> Result<EthereumSettlementRuntimePermit, EthereumError>
{
    if !ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED {
        return Err(EthereumError::SettlementOperationsDisabled);
    }
    if !ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED {
        return Err(EthereumError::ValueOperationsDisabled);
    }
    if !ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED {
        return Err(EthereumError::SynchronizationUnavailable);
    }
    Ok(EthereumSettlementRuntimePermit(()))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumAccount {
    pub address: EthereumAddress,
    pub role: EthereumKeyRole,
    pub account_index: u32,
    pub address_index: u32,
}

pub fn derive_account_from_store(
    store: &WalletStore,
    wallet_id: WalletId,
    role: EthereumKeyRole,
    account_index: u32,
    address_index: u32,
) -> Result<(EthereumAccount, EthereumSecretKey), EthereumError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(EthereumError::MissingSeed)?;
    derive_account(seed.as_slice(), role, account_index, address_index)
}

pub fn derive_account_from_phrase(
    phrase: &str,
    role: EthereumKeyRole,
    account_index: u32,
    address_index: u32,
) -> Result<(EthereumAccount, EthereumSecretKey), EthereumError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| EthereumError::InvalidRecoveryPhrase)?;
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    derive_account(seed.as_slice(), role, account_index, address_index)
}

fn derive_account(
    seed: &[u8],
    role: EthereumKeyRole,
    account_index: u32,
    address_index: u32,
) -> Result<(EthereumAccount, EthereumSecretKey), EthereumError> {
    let branch = match role {
        EthereumKeyRole::Wallet => 0,
        EthereumKeyRole::AtomicSwap => 1,
    };
    let path = DerivationPath::from_str(&format!(
        "m/44'/60'/{account_index}'/{branch}/{address_index}"
    ))
    .map_err(|_| EthereumError::KeyDerivation)?;
    let root =
        Xpriv::new_master(Network::Bitcoin, seed).map_err(|_| EthereumError::KeyDerivation)?;
    let derived = root
        .derive_priv(&Secp256k1::new(), &path)
        .map_err(|_| EthereumError::KeyDerivation)?;
    let secret_bytes = derived.private_key.secret_bytes();
    let signing =
        SigningKey::from_slice(&secret_bytes).map_err(|_| EthereumError::KeyDerivation)?;
    let address = address_from_verifying_key(&VerifyingKey::from(&signing));
    Ok((
        EthereumAccount {
            address,
            role,
            account_index,
            address_index,
        },
        EthereumSecretKey {
            material: EthereumSecretMaterial(secret_bytes),
            address,
            role,
        },
    ))
}

fn address_from_verifying_key(key: &VerifyingKey) -> EthereumAddress {
    let encoded = key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&digest[12..]);
    EthereumAddress(address)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeliosPolicy {
    pub chain_id: u64,
    pub weak_subjectivity_checkpoint: [u8; 32],
    pub checkpoint_age_limit_seconds: u64,
    pub expected_genesis_validators_root: [u8; 32],
    pub execution_provider_count: u8,
    pub consensus_provider_count: u8,
}

impl HeliosPolicy {
    pub fn validate(&self) -> Result<(), EthereumError> {
        if self.chain_id == 0
            || self.weak_subjectivity_checkpoint == [0; 32]
            || self.expected_genesis_validators_root == [0; 32]
            || self.checkpoint_age_limit_seconds == 0
            || self.execution_provider_count == 0
            || self.consensus_provider_count == 0
        {
            return Err(EthereumError::InvalidHeliosPolicy);
        }
        Ok(())
    }
}

/// Structural fields expected from the selected Helios adapter. Serialization
/// does not confer provenance: authoritative verification additionally requires
/// the opaque [`HeliosEvidenceRuntimePermit`], which has no public acquisition
/// path and can only be minted inside a future embedded verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeliosExecutionEvidence {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub finalized_checkpoint_root: [u8; 32],
    pub consensus_finality_verified: bool,
    pub execution_header_verified: bool,
    pub account_proof_verified: bool,
    pub code_proof_verified: bool,
    pub receipt_proof_verified: bool,
    pub transaction_inclusion_verified: bool,
}

impl HeliosExecutionEvidence {
    fn validate(&self, policy: &HeliosPolicy) -> Result<(), EthereumError> {
        policy.validate()?;
        if self.chain_id != policy.chain_id {
            return Err(EthereumError::ChainIdMismatch);
        }
        if self.block_hash == [0; 32]
            || self.state_root == [0; 32]
            || self.receipts_root == [0; 32]
            || self.finalized_checkpoint_root == [0; 32]
            || !self.consensus_finality_verified
            || !self.execution_header_verified
            || !self.account_proof_verified
            || !self.code_proof_verified
            || !self.receipt_proof_verified
            || !self.transaction_inclusion_verified
        {
            return Err(EthereumError::UnverifiedExecutionEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumHtlcDeploymentPolicy {
    pub chain_id: u64,
    pub contract_address: EthereumAddress,
    pub runtime_code_hash: [u8; 32],
    pub deployment_block: u64,
    pub mainnet_settlement_enabled: bool,
}

impl EthereumHtlcDeploymentPolicy {
    pub fn validate(&self) -> Result<(), EthereumError> {
        if self.chain_id == 0
            || self.contract_address == EthereumAddress::ZERO
            || self.runtime_code_hash == [0; 32]
        {
            return Err(EthereumError::InvalidContractPolicy);
        }
        // Qualification is source authority, never a caller-selected boolean.
        // The legacy field is retained only so old policy records fail closed:
        // setting it cannot enable any network, and chain ID 1 is unavailable
        // regardless of its value in this source revision.
        if self.mainnet_settlement_enabled
            || (self.chain_id == 1 && !ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED)
        {
            return Err(EthereumError::MainnetQualificationRequired);
        }
        Ok(())
    }

    pub fn verify_runtime_code(
        &self,
        chain_id: u64,
        address: EthereumAddress,
        runtime_code: &[u8],
    ) -> Result<(), EthereumError> {
        self.validate()?;
        if chain_id != self.chain_id {
            return Err(EthereumError::ChainIdMismatch);
        }
        if address != self.contract_address || runtime_code.is_empty() {
            return Err(EthereumError::ContractMismatch);
        }
        let actual: [u8; 32] = Keccak256::digest(runtime_code).into();
        if actual != self.runtime_code_hash {
            return Err(EthereumError::BytecodeHashMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedEthereumLock {
    pub swap_id: [u8; 32],
    pub hashlock: [u8; 32],
    pub receiver: EthereumAddress,
    pub refund_address: EthereumAddress,
    pub amount_wei: u128,
    pub timelock_unix: u64,
}

impl ExpectedEthereumLock {
    pub fn validate(&self) -> Result<(), EthereumError> {
        if self.swap_id == [0; 32]
            || self.hashlock == [0; 32]
            || self.receiver == EthereumAddress::ZERO
            || self.refund_address == EthereumAddress::ZERO
            || self.receiver == self.refund_address
            || self.amount_wei == 0
            || self.timelock_unix == 0
        {
            return Err(EthereumError::InvalidHtlc);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLockStatus {
    Locked,
    Redeemed,
    Refunded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumLog {
    pub address: EthereumAddress,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumLockEvidence {
    pub execution: HeliosExecutionEvidence,
    pub transaction_hash: [u8; 32],
    pub transaction_to: EthereumAddress,
    pub transaction_value_wei: u128,
    pub receipt_succeeded: bool,
    pub state: ExpectedEthereumLock,
    pub state_status: ContractLockStatus,
    pub locked_log: EthereumLog,
    pub deployed_runtime_code: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedEthereumLock {
    pub transaction_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub terms: ExpectedEthereumLock,
}

pub fn verify_ethereum_lock(
    _provenance: &HeliosEvidenceRuntimePermit,
    _settlement_permit: &EthereumSettlementRuntimePermit,
    helios: &HeliosPolicy,
    deployment: &EthereumHtlcDeploymentPolicy,
    expected: &ExpectedEthereumLock,
    evidence: &EthereumLockEvidence,
) -> Result<VerifiedEthereumLock, EthereumError> {
    expected.validate()?;
    evidence.execution.validate(helios)?;
    deployment.verify_runtime_code(
        evidence.execution.chain_id,
        evidence.transaction_to,
        &evidence.deployed_runtime_code,
    )?;
    if evidence.execution.block_number < deployment.deployment_block
        || evidence.transaction_hash == [0; 32]
        || evidence.transaction_value_wei != expected.amount_wei
        || !evidence.receipt_succeeded
        || evidence.state_status != ContractLockStatus::Locked
        || &evidence.state != expected
    {
        return Err(EthereumError::InvalidSettlementEvidence);
    }
    verify_locked_log(&evidence.locked_log, deployment.contract_address, expected)?;
    Ok(VerifiedEthereumLock {
        transaction_hash: evidence.transaction_hash,
        block_hash: evidence.execution.block_hash,
        block_number: evidence.execution.block_number,
        terms: expected.clone(),
    })
}

pub fn locked_log(terms: &ExpectedEthereumLock, contract: EthereumAddress) -> EthereumLog {
    let mut receiver_topic = [0_u8; 32];
    receiver_topic[12..].copy_from_slice(terms.receiver.as_bytes());
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&abi_address(terms.refund_address));
    data.extend_from_slice(&abi_u128(terms.amount_wei));
    data.extend_from_slice(&abi_u64(terms.timelock_unix));
    EthereumLog {
        address: contract,
        topics: vec![
            keccak(b"Locked(bytes32,bytes32,address,address,uint256,uint64)"),
            terms.swap_id,
            terms.hashlock,
            receiver_topic,
        ],
        data,
    }
}

fn verify_locked_log(
    actual: &EthereumLog,
    contract: EthereumAddress,
    terms: &ExpectedEthereumLock,
) -> Result<(), EthereumError> {
    if actual != &locked_log(terms, contract) {
        return Err(EthereumError::EventMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EthereumOperationClass {
    NativeValue,
    Settlement,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EthereumHtlcPreimage([u8; 32]);

impl EthereumHtlcPreimage {
    pub fn new(mut bytes: [u8; 32]) -> Self {
        let preimage = Self(bytes);
        bytes.zeroize();
        preimage
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EthereumHtlcPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EthereumHtlcPreimage([REDACTED])")
    }
}

enum EthereumOperation {
    NativeTransfer {
        signer: EthereumAddress,
    },
    HtlcLock(ExpectedEthereumLock),
    HtlcRedeem {
        swap_id: [u8; 32],
        preimage: EthereumHtlcPreimage,
        receiver: EthereumAddress,
    },
    HtlcRefund {
        swap_id: [u8; 32],
        refund_address: EthereumAddress,
    },
}

impl fmt::Debug for EthereumOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeTransfer { .. } => formatter.write_str("NativeTransfer"),
            Self::HtlcLock(_) => formatter.write_str("HtlcLock"),
            Self::HtlcRedeem { .. } => formatter.write_str("HtlcRedeem([REDACTED])"),
            Self::HtlcRefund { .. } => formatter.write_str("HtlcRefund"),
        }
    }
}

/// The permit kind is explicit at the final signing boundary. Both contained
/// permit types are opaque and currently unobtainable through their public
/// acquisition functions.
pub enum EthereumSigningPermit<'a> {
    Value(&'a EthereumValueRuntimePermit),
    Settlement(&'a EthereumSettlementRuntimePermit),
}

#[derive(Debug)]
pub struct PreparedEip1559Transaction {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: EthereumAddress,
    value_wei: u128,
    operation: EthereumOperation,
}

/// Type-state proving that the exact immutable transaction was checked against
/// an approval-supplied maximum fee before signing became reachable.
#[derive(Debug)]
pub struct FeeBoundEip1559Transaction {
    transaction: PreparedEip1559Transaction,
    approved_maximum_fee_wei: u128,
}

/// Opaque, single-owner signed payload for the controlled embedded-broadcast
/// boundary. Encoded bytes are zeroized on drop and deliberately have no public
/// accessor, serializer, cloning implementation, or byte-revealing `Debug`.
pub struct SignedEip1559Transaction {
    encoded: Zeroizing<Vec<u8>>,
    transaction_hash: [u8; 32],
}

impl SignedEip1559Transaction {
    pub const fn encoded_type(&self) -> u8 {
        0x02
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded.len()
    }

    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
}

impl fmt::Debug for SignedEip1559Transaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedEip1559Transaction")
            .field("encoded_type", &self.encoded_type())
            .field("encoded_len", &self.encoded_len())
            .field("transaction_hash", &self.transaction_hash)
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

impl PreparedEip1559Transaction {
    pub fn native_transfer(
        _permit: &EthereumValueRuntimePermit,
        chain_id: u64,
        nonce: u64,
        signer: EthereumAddress,
        to: EthereumAddress,
        value_wei: u128,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Result<Self, EthereumError> {
        let transaction = Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: NATIVE_TRANSFER_GAS,
            to,
            value_wei,
            operation: EthereumOperation::NativeTransfer { signer },
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn htlc_lock(
        _permit: &EthereumSettlementRuntimePermit,
        deployment: &EthereumHtlcDeploymentPolicy,
        nonce: u64,
        terms: ExpectedEthereumLock,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Result<Self, EthereumError> {
        deployment.validate()?;
        terms.validate()?;
        let transaction = Self {
            chain_id: deployment.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: HTLC_LOCK_GAS_LIMIT,
            to: deployment.contract_address,
            value_wei: terms.amount_wei,
            operation: EthereumOperation::HtlcLock(terms),
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn htlc_redeem(
        _permit: &EthereumSettlementRuntimePermit,
        deployment: &EthereumHtlcDeploymentPolicy,
        nonce: u64,
        terms: &ExpectedEthereumLock,
        preimage: EthereumHtlcPreimage,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Result<Self, EthereumError> {
        deployment.validate()?;
        terms.validate()?;
        if sha256(preimage.as_bytes()) != terms.hashlock {
            return Err(EthereumError::InvalidPreimage);
        }
        let transaction = Self {
            chain_id: deployment.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: HTLC_REDEEM_GAS_LIMIT,
            to: deployment.contract_address,
            value_wei: 0,
            operation: EthereumOperation::HtlcRedeem {
                swap_id: terms.swap_id,
                preimage,
                receiver: terms.receiver,
            },
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn htlc_refund(
        _permit: &EthereumSettlementRuntimePermit,
        deployment: &EthereumHtlcDeploymentPolicy,
        nonce: u64,
        terms: &ExpectedEthereumLock,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Result<Self, EthereumError> {
        deployment.validate()?;
        terms.validate()?;
        let transaction = Self {
            chain_id: deployment.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: HTLC_REFUND_GAS_LIMIT,
            to: deployment.contract_address,
            value_wei: 0,
            operation: EthereumOperation::HtlcRefund {
                swap_id: terms.swap_id,
                refund_address: terms.refund_address,
            },
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn maximum_fee_wei(&self) -> Result<u128, EthereumError> {
        self.max_fee_per_gas
            .checked_mul(u128::from(self.gas_limit))
            .ok_or(EthereumError::Arithmetic)
    }

    pub fn bind_fee_limit(
        self,
        maximum_fee_wei: u128,
    ) -> Result<FeeBoundEip1559Transaction, EthereumError> {
        self.validate()?;
        if self.maximum_fee_wei()? > maximum_fee_wei {
            return Err(EthereumError::FeeLimit);
        }
        Ok(FeeBoundEip1559Transaction {
            transaction: self,
            approved_maximum_fee_wei: maximum_fee_wei,
        })
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub const fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    pub const fn to(&self) -> EthereumAddress {
        self.to
    }

    pub const fn value_wei(&self) -> u128 {
        self.value_wei
    }

    fn sign(
        self,
        secret: &EthereumSecretKey,
        approved_maximum_fee_wei: u128,
    ) -> Result<SignedEip1559Transaction, EthereumError> {
        self.validate()?;
        if self.maximum_fee_wei()? > approved_maximum_fee_wei {
            return Err(EthereumError::FeeLimit);
        }
        if secret.role != self.operation.required_role() {
            return Err(EthereumError::SignerRoleMismatch);
        }
        if secret.address != self.operation.required_signer() {
            return Err(EthereumError::SignerAddressMismatch);
        }
        let signing =
            SigningKey::from_slice(&secret.material.0).map_err(|_| EthereumError::Signing)?;
        if address_from_verifying_key(&VerifyingKey::from(&signing)) != secret.address {
            return Err(EthereumError::SignerAddressMismatch);
        }
        let data = self.operation.calldata();
        let unsigned_fields = self.rlp_fields(&data, None);
        let unsigned_rlp = Zeroizing::new(rlp_list(&unsigned_fields));
        let mut signing_payload = Zeroizing::new(Vec::with_capacity(1 + unsigned_rlp.len()));
        signing_payload.push(0x02);
        signing_payload.extend_from_slice(unsigned_rlp.as_slice());
        let digest: Zeroizing<[u8; 32]> =
            Zeroizing::new(Keccak256::digest(signing_payload.as_slice()).into());
        let (signature, recovery) = signing
            .sign_prehash_recoverable(&digest[..])
            .map_err(|_| EthereumError::Signing)?;
        if recovery.is_x_reduced() {
            return Err(EthereumError::Signing);
        }
        let signed_fields = self.rlp_fields(&data, Some((signature, recovery.to_byte())));
        let signed_rlp = Zeroizing::new(rlp_list(&signed_fields));
        let mut encoded = Zeroizing::new(Vec::with_capacity(1 + signed_rlp.len()));
        encoded.push(0x02);
        encoded.extend_from_slice(signed_rlp.as_slice());
        if encoded.len() > MAX_SIGNED_TRANSACTION_BYTES {
            return Err(EthereumError::TransactionTooLarge);
        }
        let transaction_hash = Keccak256::digest(encoded.as_slice()).into();
        Ok(SignedEip1559Transaction {
            encoded,
            transaction_hash,
        })
    }

    fn validate(&self) -> Result<(), EthereumError> {
        if self.chain_id == 1 && !ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED {
            return Err(EthereumError::MainnetQualificationRequired);
        }
        if self.chain_id == 0
            || self.to == EthereumAddress::ZERO
            || self.max_priority_fee_per_gas == 0
            || self.max_fee_per_gas < self.max_priority_fee_per_gas
            || self.gas_limit == 0
        {
            return Err(EthereumError::InvalidTransaction);
        }
        match &self.operation {
            EthereumOperation::NativeTransfer { signer } if *signer == EthereumAddress::ZERO => {
                Err(EthereumError::InvalidAddress)
            }
            EthereumOperation::NativeTransfer { .. } if self.value_wei == 0 => {
                Err(EthereumError::InvalidAmount)
            }
            EthereumOperation::NativeTransfer { .. } if self.gas_limit != NATIVE_TRANSFER_GAS => {
                Err(EthereumError::ArbitraryCalldataForbidden)
            }
            EthereumOperation::HtlcLock(terms)
                if self.value_wei != terms.amount_wei || self.gas_limit != HTLC_LOCK_GAS_LIMIT =>
            {
                Err(EthereumError::InvalidHtlc)
            }
            EthereumOperation::HtlcRedeem { .. }
                if self.value_wei != 0 || self.gas_limit != HTLC_REDEEM_GAS_LIMIT =>
            {
                Err(EthereumError::InvalidHtlc)
            }
            EthereumOperation::HtlcRefund { .. }
                if self.value_wei != 0 || self.gas_limit != HTLC_REFUND_GAS_LIMIT =>
            {
                Err(EthereumError::InvalidHtlc)
            }
            _ => Ok(()),
        }
    }

    fn rlp_fields(
        &self,
        data: &[u8],
        signature: Option<(Signature, u8)>,
    ) -> Zeroizing<Vec<Vec<u8>>> {
        let mut fields = Zeroizing::new(vec![
            rlp_u128(u128::from(self.chain_id)),
            rlp_u128(u128::from(self.nonce)),
            rlp_u128(self.max_priority_fee_per_gas),
            rlp_u128(self.max_fee_per_gas),
            rlp_u128(u128::from(self.gas_limit)),
            rlp_bytes(self.to.as_bytes()),
            rlp_u128(self.value_wei),
            rlp_bytes(data),
            rlp_list(&[]),
        ]);
        if let Some((signature, recovery)) = signature {
            let bytes = signature.to_bytes();
            fields.push(rlp_u128(u128::from(recovery & 1)));
            fields.push(rlp_integer_bytes(&bytes[..32]));
            fields.push(rlp_integer_bytes(&bytes[32..]));
        }
        fields
    }
}

impl FeeBoundEip1559Transaction {
    pub const fn approved_maximum_fee_wei(&self) -> u128 {
        self.approved_maximum_fee_wei
    }

    pub fn sign(
        self,
        permit: EthereumSigningPermit<'_>,
        secret: &EthereumSecretKey,
    ) -> Result<SignedEip1559Transaction, EthereumError> {
        let permitted_class = match permit {
            EthereumSigningPermit::Value(_) => EthereumOperationClass::NativeValue,
            EthereumSigningPermit::Settlement(_) => EthereumOperationClass::Settlement,
        };
        if permitted_class != self.transaction.operation.class() {
            return Err(EthereumError::RuntimePermitMismatch);
        }
        self.transaction.sign(secret, self.approved_maximum_fee_wei)
    }
}

impl EthereumOperation {
    const fn class(&self) -> EthereumOperationClass {
        match self {
            Self::NativeTransfer { .. } => EthereumOperationClass::NativeValue,
            Self::HtlcLock(_) | Self::HtlcRedeem { .. } | Self::HtlcRefund { .. } => {
                EthereumOperationClass::Settlement
            }
        }
    }

    const fn required_role(&self) -> EthereumKeyRole {
        match self {
            Self::NativeTransfer { .. } => EthereumKeyRole::Wallet,
            Self::HtlcLock(_) | Self::HtlcRedeem { .. } | Self::HtlcRefund { .. } => {
                EthereumKeyRole::AtomicSwap
            }
        }
    }

    const fn required_signer(&self) -> EthereumAddress {
        match self {
            Self::NativeTransfer { signer } => *signer,
            Self::HtlcLock(terms) => terms.refund_address,
            Self::HtlcRedeem { receiver, .. } => *receiver,
            Self::HtlcRefund { refund_address, .. } => *refund_address,
        }
    }

    fn calldata(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::NativeTransfer { .. } => Zeroizing::new(Vec::new()),
            Self::HtlcLock(terms) => {
                let mut data = Zeroizing::new(Vec::with_capacity(4 + (5 * 32)));
                data.extend_from_slice(&selector(b"lock(bytes32,bytes32,address,address,uint64)"));
                data.extend_from_slice(&terms.swap_id);
                data.extend_from_slice(&terms.hashlock);
                data.extend_from_slice(&abi_address(terms.receiver));
                data.extend_from_slice(&abi_address(terms.refund_address));
                data.extend_from_slice(&abi_u64(terms.timelock_unix));
                data
            }
            Self::HtlcRedeem {
                swap_id, preimage, ..
            } => {
                let mut data = Zeroizing::new(Vec::with_capacity(4 + (2 * 32)));
                data.extend_from_slice(&selector(b"redeem(bytes32,bytes32)"));
                data.extend_from_slice(swap_id);
                data.extend_from_slice(preimage.as_bytes());
                data
            }
            Self::HtlcRefund { swap_id, .. } => {
                let mut data = Zeroizing::new(Vec::with_capacity(4 + 32));
                data.extend_from_slice(&selector(b"refund(bytes32)"));
                data.extend_from_slice(swap_id);
                data
            }
        }
    }
}

fn selector(signature: &[u8]) -> [u8; 4] {
    let digest = Keccak256::digest(signature);
    digest[..4].try_into().expect("four-byte selector")
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    // SHA-256 is implemented through the RustCrypto digest trait without
    // exposing any Ethereum-generic hashing choice at the public boundary.
    let mut state = sha2::Sha256::new();
    state.update(bytes);
    state.finalize().into()
}

pub fn runtime_code_hash(runtime_code: &[u8]) -> Result<[u8; 32], EthereumError> {
    if runtime_code.is_empty() {
        return Err(EthereumError::BytecodeHashMismatch);
    }
    Ok(Keccak256::digest(runtime_code).into())
}

fn abi_address(address: EthereumAddress) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    encoded[12..].copy_from_slice(address.as_bytes());
    encoded
}

fn abi_u64(value: u64) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    encoded[24..].copy_from_slice(&value.to_be_bytes());
    encoded
}

fn abi_u128(value: u128) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    encoded[16..].copy_from_slice(&value.to_be_bytes());
    encoded
}

fn rlp_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    rlp_integer_bytes(&value.to_be_bytes())
}

fn rlp_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut encoded = rlp_length(bytes.len(), 0x80, 0xb7);
    encoded.extend_from_slice(bytes);
    encoded
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let content_length: usize = fields.iter().map(Vec::len).sum();
    let mut encoded = rlp_length(content_length, 0xc0, 0xf7);
    encoded.reserve(content_length);
    for field in fields {
        encoded.extend_from_slice(field);
    }
    encoded
}

fn rlp_length(length: usize, short_offset: u8, long_offset: u8) -> Vec<u8> {
    if length <= 55 {
        return vec![short_offset + u8::try_from(length).expect("short RLP length")];
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let length_bytes = &bytes[first..];
    let mut encoded =
        vec![long_offset + u8::try_from(length_bytes.len()).expect("platform RLP length width")];
    encoded.extend_from_slice(length_bytes);
    encoded
}

fn hex_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(value: &str, output: &mut [u8]) -> Result<(), EthereumError> {
    if value.len() != output.len() * 2 {
        return Err(EthereumError::InvalidAddress);
    }
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(())
}

fn hex_digit(value: u8) -> Result<u8, EthereumError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(EthereumError::InvalidAddress),
    }
}

#[derive(Debug, Error)]
pub enum EthereumError {
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("wallet seed is missing")]
    MissingSeed,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("invalid Ethereum address")]
    InvalidAddress,
    #[error("invalid Helios synchronization policy")]
    InvalidHeliosPolicy,
    #[error("Ethereum synchronization is unavailable until release qualification")]
    SynchronizationUnavailable,
    #[error("native ETH value operations are disabled until release qualification")]
    ValueOperationsDisabled,
    #[error("Ethereum settlement operations are disabled until release qualification")]
    SettlementOperationsDisabled,
    #[error("Ethereum chain ID mismatch")]
    ChainIdMismatch,
    #[error("execution evidence is not fully proof-verified and finalized")]
    UnverifiedExecutionEvidence,
    #[error("invalid approved-contract policy")]
    InvalidContractPolicy,
    #[error("mainnet qualification has not been completed")]
    MainnetQualificationRequired,
    #[error("unexpected contract address")]
    ContractMismatch,
    #[error("deployed contract bytecode hash mismatch")]
    BytecodeHashMismatch,
    #[error("invalid HTLC terms")]
    InvalidHtlc,
    #[error("invalid settlement transaction, state, or receipt evidence")]
    InvalidSettlementEvidence,
    #[error("settlement event does not match frozen terms")]
    EventMismatch,
    #[error("invalid transaction")]
    InvalidTransaction,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("arbitrary calldata is forbidden")]
    ArbitraryCalldataForbidden,
    #[error("invalid preimage")]
    InvalidPreimage,
    #[error("fee exceeds approved maximum")]
    FeeLimit,
    #[error("runtime permit does not authorize this Ethereum operation")]
    RuntimePermitMismatch,
    #[error("Ethereum signing key role does not authorize this operation")]
    SignerRoleMismatch,
    #[error("Ethereum signing key does not match the bound sender")]
    SignerAddressMismatch,
    #[error("integer arithmetic overflow")]
    Arithmetic,
    #[error("transaction signing failed")]
    Signing,
    #[error("signed transaction exceeds bounded maximum")]
    TransactionTooLarge,
    #[error("encrypted wallet storage failed")]
    Store,
}

impl From<StoreError> for EthereumError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase() -> &'static str {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    }

    fn value_permit() -> EthereumValueRuntimePermit {
        EthereumValueRuntimePermit(())
    }

    fn settlement_permit() -> EthereumSettlementRuntimePermit {
        EthereumSettlementRuntimePermit(())
    }

    fn embedded_helios_provenance_for_test() -> HeliosEvidenceRuntimePermit {
        HeliosEvidenceRuntimePermit(())
    }

    fn deployment(code: &[u8]) -> EthereumHtlcDeploymentPolicy {
        EthereumHtlcDeploymentPolicy {
            chain_id: 31_337,
            contract_address: EthereumAddress::new([7; 20]),
            runtime_code_hash: Keccak256::digest(code).into(),
            deployment_block: 1,
            mainnet_settlement_enabled: false,
        }
    }

    fn helios() -> HeliosPolicy {
        HeliosPolicy {
            chain_id: 31_337,
            weak_subjectivity_checkpoint: [1; 32],
            checkpoint_age_limit_seconds: 86_400,
            expected_genesis_validators_root: [2; 32],
            execution_provider_count: 2,
            consensus_provider_count: 2,
        }
    }

    fn terms() -> ExpectedEthereumLock {
        ExpectedEthereumLock {
            swap_id: [3; 32],
            hashlock: sha256(&[9; 32]),
            receiver: EthereumAddress::new([4; 20]),
            refund_address: EthereumAddress::new([5; 20]),
            amount_wei: 1_000_000_000_000_000,
            timelock_unix: 2_000_000_000,
        }
    }

    #[test]
    fn ethereum_wallet_and_swap_roles_are_separated() {
        let (wallet, _) = derive_account_from_phrase(phrase(), EthereumKeyRole::Wallet, 0, 0)
            .expect("wallet account");
        let (swap, _) = derive_account_from_phrase(phrase(), EthereumKeyRole::AtomicSwap, 0, 0)
            .expect("swap account");
        assert_ne!(wallet.address, swap.address);
        assert_eq!(
            wallet.address.to_string(),
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }

    #[test]
    fn runtime_gates_and_public_permit_acquisition_fail_closed() {
        assert!(!ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED);
        assert!(!ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED);
        assert!(!ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED);
        assert!(!ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED);
        let capabilities = capabilities();
        assert!(capabilities.receive);
        assert!(!capabilities.send);
        assert!(!capabilities.history);
        assert!(!capabilities.atomic_settlement);
        assert!(matches!(
            ethereum_value_runtime_permit(),
            Err(EthereumError::ValueOperationsDisabled)
        ));
        assert!(matches!(
            ethereum_settlement_runtime_permit(),
            Err(EthereumError::SettlementOperationsDisabled)
        ));
    }

    #[test]
    fn signing_requires_an_exact_fee_bound_transaction_and_matching_permit() {
        let permit = value_permit();
        let settlement_permit = settlement_permit();
        let (account, secret) =
            derive_account_from_phrase(phrase(), EthereumKeyRole::Wallet, 0, 0).expect("account");
        let transaction = || {
            PreparedEip1559Transaction::native_transfer(
                &permit,
                31_337,
                0,
                account.address,
                EthereumAddress::new([8; 20]),
                1,
                1_000_000_000,
                2_000_000_000,
            )
            .expect("typed transfer")
        };
        let exact_maximum = transaction().maximum_fee_wei().expect("bounded fee");
        assert!(matches!(
            transaction().bind_fee_limit(exact_maximum - 1),
            Err(EthereumError::FeeLimit)
        ));
        let mismatched_permit = transaction()
            .bind_fee_limit(exact_maximum)
            .expect("exact fee cap is bound");
        assert_eq!(mismatched_permit.approved_maximum_fee_wei(), exact_maximum);
        assert!(matches!(
            mismatched_permit.sign(
                EthereumSigningPermit::Settlement(&settlement_permit),
                &secret
            ),
            Err(EthereumError::RuntimePermitMismatch)
        ));
        let signed = transaction()
            .bind_fee_limit(exact_maximum)
            .expect("exact fee cap is bound")
            .sign(EthereumSigningPermit::Value(&permit), &secret)
            .expect("signed fee-bound transaction");
        assert_eq!(signed.encoded_type(), 0x02);
        assert!(signed.encoded_len() > 1);
        assert_ne!(signed.transaction_hash(), [0; 32]);
        assert!(format!("{signed:?}").contains("[REDACTED]"));
    }

    #[test]
    fn signing_enforces_key_role_and_bound_sender_address() {
        let value_permit = value_permit();
        let settlement_permit = settlement_permit();
        let (wallet, wallet_secret) =
            derive_account_from_phrase(phrase(), EthereumKeyRole::Wallet, 0, 0).expect("wallet");
        let (other_wallet, other_wallet_secret) =
            derive_account_from_phrase(phrase(), EthereumKeyRole::Wallet, 0, 1)
                .expect("other wallet");
        let (swap, swap_secret) =
            derive_account_from_phrase(phrase(), EthereumKeyRole::AtomicSwap, 0, 0).expect("swap");

        let native = PreparedEip1559Transaction::native_transfer(
            &value_permit,
            31_337,
            0,
            swap.address,
            EthereumAddress::new([8; 20]),
            1,
            1_000_000_000,
            2_000_000_000,
        )
        .expect("native transfer")
        .bind_fee_limit(42_000_000_000_000)
        .expect("fee binding");
        assert!(matches!(
            native.sign(EthereumSigningPermit::Value(&value_permit), &swap_secret),
            Err(EthereumError::SignerRoleMismatch)
        ));

        let address_mismatch = PreparedEip1559Transaction::native_transfer(
            &value_permit,
            31_337,
            1,
            wallet.address,
            EthereumAddress::new([8; 20]),
            1,
            1_000_000_000,
            2_000_000_000,
        )
        .expect("native transfer")
        .bind_fee_limit(42_000_000_000_000)
        .expect("fee binding");
        assert_ne!(wallet.address, other_wallet.address);
        assert!(matches!(
            address_mismatch.sign(
                EthereumSigningPermit::Value(&value_permit),
                &other_wallet_secret
            ),
            Err(EthereumError::SignerAddressMismatch)
        ));

        let mut settlement_terms = terms();
        settlement_terms.refund_address = wallet.address;
        let settlement = PreparedEip1559Transaction::htlc_lock(
            &settlement_permit,
            &deployment(&[0x60, 0x00]),
            0,
            settlement_terms,
            1_000_000_000,
            2_000_000_000,
        )
        .expect("settlement lock")
        .bind_fee_limit(360_000_000_000_000)
        .expect("fee binding");
        assert!(matches!(
            settlement.sign(
                EthereumSigningPermit::Settlement(&settlement_permit),
                &wallet_secret
            ),
            Err(EthereumError::SignerRoleMismatch)
        ));
    }

    #[test]
    fn private_settlement_permit_keeps_typed_primitives_testable() {
        let permit = settlement_permit();
        let (swap, secret) =
            derive_account_from_phrase(phrase(), EthereumKeyRole::AtomicSwap, 0, 0).expect("swap");
        let deployment = deployment(&[0x60, 0x00]);

        let mut refund_terms = terms();
        refund_terms.refund_address = swap.address;
        let lock = PreparedEip1559Transaction::htlc_lock(
            &permit,
            &deployment,
            0,
            refund_terms.clone(),
            1_000_000_000,
            2_000_000_000,
        )
        .expect("lock")
        .bind_fee_limit(360_000_000_000_000)
        .expect("lock fee binding")
        .sign(EthereumSigningPermit::Settlement(&permit), &secret)
        .expect("lock signing");
        assert_eq!(lock.encoded_type(), 0x02);

        let mut redeem_terms = terms();
        redeem_terms.receiver = swap.address;
        let preimage = EthereumHtlcPreimage::new([9; 32]);
        assert_eq!(format!("{preimage:?}"), "EthereumHtlcPreimage([REDACTED])");
        let redeem = PreparedEip1559Transaction::htlc_redeem(
            &permit,
            &deployment,
            1,
            &redeem_terms,
            preimage,
            1_000_000_000,
            2_000_000_000,
        )
        .expect("redeem")
        .bind_fee_limit(200_000_000_000_000)
        .expect("redeem fee binding")
        .sign(EthereumSigningPermit::Settlement(&permit), &secret)
        .expect("redeem signing");
        assert_eq!(redeem.encoded_type(), 0x02);

        let refund = PreparedEip1559Transaction::htlc_refund(
            &permit,
            &deployment,
            2,
            &refund_terms,
            1_000_000_000,
            2_000_000_000,
        )
        .expect("refund")
        .bind_fee_limit(200_000_000_000_000)
        .expect("refund fee binding")
        .sign(EthereumSigningPermit::Settlement(&permit), &secret)
        .expect("refund signing");
        assert_eq!(refund.encoded_type(), 0x02);
    }

    #[test]
    fn mainnet_activation_fails_closed_even_with_false_caller_flag() {
        let value_permit = value_permit();
        let mut policy = EthereumHtlcDeploymentPolicy {
            chain_id: 1,
            contract_address: EthereumAddress::new([1; 20]),
            runtime_code_hash: [2; 32],
            deployment_block: 1,
            mainnet_settlement_enabled: false,
        };
        assert!(matches!(
            policy.validate(),
            Err(EthereumError::MainnetQualificationRequired)
        ));
        policy.mainnet_settlement_enabled = true;
        assert!(matches!(
            policy.validate(),
            Err(EthereumError::MainnetQualificationRequired)
        ));
        assert!(matches!(
            PreparedEip1559Transaction::native_transfer(
                &value_permit,
                1,
                0,
                EthereumAddress::new([3; 20]),
                EthereumAddress::new([4; 20]),
                1,
                1_000_000_000,
                2_000_000_000,
            ),
            Err(EthereumError::MainnetQualificationRequired)
        ));
    }

    #[test]
    fn lock_verification_binds_chain_code_state_receipt_and_event() {
        let provenance = embedded_helios_provenance_for_test();
        let settlement_permit = settlement_permit();
        let code = [0x60, 0x00];
        let deployment = deployment(&code);
        let terms = terms();
        let execution = HeliosExecutionEvidence {
            chain_id: 31_337,
            block_number: 10,
            block_hash: [10; 32],
            state_root: [11; 32],
            receipts_root: [12; 32],
            finalized_checkpoint_root: [13; 32],
            consensus_finality_verified: true,
            execution_header_verified: true,
            account_proof_verified: true,
            code_proof_verified: true,
            receipt_proof_verified: true,
            transaction_inclusion_verified: true,
        };
        let evidence = EthereumLockEvidence {
            execution,
            transaction_hash: [14; 32],
            transaction_to: deployment.contract_address,
            transaction_value_wei: terms.amount_wei,
            receipt_succeeded: true,
            state: terms.clone(),
            state_status: ContractLockStatus::Locked,
            locked_log: locked_log(&terms, deployment.contract_address),
            deployed_runtime_code: code.to_vec(),
        };
        verify_ethereum_lock(
            &provenance,
            &settlement_permit,
            &helios(),
            &deployment,
            &terms,
            &evidence,
        )
        .expect("complete verified evidence");
        let mut wrong_chain = evidence.clone();
        wrong_chain.execution.chain_id = 1;
        assert!(matches!(
            verify_ethereum_lock(
                &provenance,
                &settlement_permit,
                &helios(),
                &deployment,
                &terms,
                &wrong_chain
            ),
            Err(EthereumError::ChainIdMismatch)
        ));
        let mut wrong_code = evidence.clone();
        wrong_code.deployed_runtime_code.push(1);
        assert!(matches!(
            verify_ethereum_lock(
                &provenance,
                &settlement_permit,
                &helios(),
                &deployment,
                &terms,
                &wrong_code
            ),
            Err(EthereumError::BytecodeHashMismatch)
        ));
        let mut unfinalized = evidence;
        unfinalized.execution.consensus_finality_verified = false;
        assert!(matches!(
            verify_ethereum_lock(
                &provenance,
                &settlement_permit,
                &helios(),
                &deployment,
                &terms,
                &unfinalized
            ),
            Err(EthereumError::UnverifiedExecutionEvidence)
        ));
    }
}
