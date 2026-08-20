#![doc = "Capability-separated wallet chain interfaces."]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use hns_wallet_types::{
    AccountId, Amount, ApprovalId, BaseUnits, ChainCapabilities, ModuleId, ObjectHash,
    ReceiveTarget, SessionId, SyncStatus, TransactionHash, TransactionSummary,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_OPAQUE_TRANSACTION_BYTES: usize = 1_048_576;
pub const MAX_DESTINATION_BYTES: usize = 512;
pub const MAX_HISTORY_RESULTS: usize = 10_000;

pub trait ChainModule {
    fn module_id(&self) -> ModuleId;
    fn capabilities(&self) -> ChainCapabilities;
    fn sync_status(&self) -> SyncStatus;
    fn balance(&self) -> Result<Amount, ChainError>;
    fn transaction_history(&self) -> Result<Vec<TransactionSummary>, ChainError>;
    fn receive_target(&self) -> Result<ReceiveTarget, ChainError>;
    fn prepare_send(&self, request: SendRequest) -> Result<PreparedSend, ChainError>;
    fn authorize_send(&self, request: AuthorizeSend) -> Result<AuthorizedSend, ChainError>;
    fn broadcast_send(&self, request: BroadcastSend) -> Result<BroadcastReceipt, ChainError>;
}

pub trait UtxoChainModule: ChainModule {
    fn list_utxos(&self) -> Result<Vec<Utxo>, ChainError>;
    fn fee_policy(&self) -> Result<UtxoFeePolicy, ChainError>;
    fn prepare_htlc_lock(&self, request: HtlcLockRequest) -> Result<PreparedHtlcLock, ChainError>;
    fn verify_htlc_lock(
        &self,
        request: VerifyHtlcLockRequest,
    ) -> Result<VerifiedHtlcLock, ChainError>;
    fn prepare_htlc_redeem(
        &self,
        request: HtlcRedeemRequest,
    ) -> Result<PreparedHtlcRedeem, ChainError>;
    fn prepare_htlc_refund(
        &self,
        request: HtlcRefundRequest,
    ) -> Result<PreparedHtlcRefund, ChainError>;
    fn observe_preimage(
        &self,
        request: ObservePreimageRequest,
    ) -> Result<Option<Preimage>, ChainError>;
}

pub trait AccountChainModule: ChainModule {
    fn account_nonce(&self) -> Result<u64, ChainError>;
    fn fee_policy(&self) -> Result<AccountFeePolicy, ChainError>;
    fn prepare_market_lock(
        &self,
        request: MarketLockRequest,
    ) -> Result<PreparedMarketLock, ChainError>;
    fn verify_market_lock(
        &self,
        request: VerifyMarketLockRequest,
    ) -> Result<VerifiedMarketLock, ChainError>;
    fn prepare_market_redeem(
        &self,
        request: MarketRedeemRequest,
    ) -> Result<PreparedMarketRedeem, ChainError>;
    fn prepare_market_refund(
        &self,
        request: MarketRefundRequest,
    ) -> Result<PreparedMarketRefund, ChainError>;
    fn observe_market_preimage(
        &self,
        request: ObservePreimageRequest,
    ) -> Result<Option<Preimage>, ChainError>;
}

pub trait AtomicSettlement {
    fn settlement_capabilities(&self) -> SettlementCapabilities;
    fn prepare_lock(
        &self,
        request: SettlementLockRequest,
    ) -> Result<PreparedSettlementLock, ChainError>;
    fn verify_lock(
        &self,
        request: VerifySettlementLockRequest,
    ) -> Result<VerifiedSettlementLock, ChainError>;
    fn prepare_redeem(
        &self,
        request: SettlementRedeemRequest,
    ) -> Result<PreparedSettlementRedeem, ChainError>;
    fn prepare_refund(
        &self,
        request: SettlementRefundRequest,
    ) -> Result<PreparedSettlementRefund, ChainError>;
    fn observe_secret(&self, request: ObserveSecretRequest)
    -> Result<Option<Preimage>, ChainError>;
}

/// Runtime-owned capability registry. Registration is explicit and rejects a
/// second implementation for the same module instead of silently replacing a
/// funds-bearing backend.
#[derive(Default)]
pub struct ModuleRegistry<'a> {
    chains: BTreeMap<ModuleId, &'a dyn ChainModule>,
    utxo_chains: BTreeMap<ModuleId, &'a dyn UtxoChainModule>,
    account_chains: BTreeMap<ModuleId, &'a dyn AccountChainModule>,
    settlements: BTreeMap<ModuleId, &'a dyn AtomicSettlement>,
}

impl<'a> ModuleRegistry<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_chain<T: ChainModule + 'a>(
        &mut self,
        module: &'a T,
    ) -> Result<(), RegistryError> {
        let id = module.module_id();
        insert_unique(&mut self.chains, id, module)
    }

    pub fn register_utxo<T: UtxoChainModule + 'a>(
        &mut self,
        module: &'a T,
    ) -> Result<(), RegistryError> {
        let id = module.module_id();
        if self.chains.contains_key(&id) || self.utxo_chains.contains_key(&id) {
            return Err(RegistryError::DuplicateModule(id));
        }
        self.chains.insert(id, module);
        self.utxo_chains.insert(id, module);
        Ok(())
    }

    pub fn register_account<T: AccountChainModule + 'a>(
        &mut self,
        module: &'a T,
    ) -> Result<(), RegistryError> {
        let id = module.module_id();
        if self.chains.contains_key(&id) || self.account_chains.contains_key(&id) {
            return Err(RegistryError::DuplicateModule(id));
        }
        self.chains.insert(id, module);
        self.account_chains.insert(id, module);
        Ok(())
    }

    pub fn register_settlement<T: AtomicSettlement + 'a>(
        &mut self,
        module_id: ModuleId,
        settlement: &'a T,
    ) -> Result<(), RegistryError> {
        insert_unique(&mut self.settlements, module_id, settlement)
    }

    pub fn register_utxo_settlement<T: UtxoChainModule + AtomicSettlement + 'a>(
        &mut self,
        module: &'a T,
    ) -> Result<(), RegistryError> {
        let id = module.module_id();
        if self.chains.contains_key(&id)
            || self.utxo_chains.contains_key(&id)
            || self.settlements.contains_key(&id)
        {
            return Err(RegistryError::DuplicateModule(id));
        }
        self.chains.insert(id, module);
        self.utxo_chains.insert(id, module);
        self.settlements.insert(id, module);
        Ok(())
    }

    pub fn chain(&self, module: ModuleId) -> Option<&'a dyn ChainModule> {
        self.chains.get(&module).copied()
    }

    pub fn utxo(&self, module: ModuleId) -> Option<&'a dyn UtxoChainModule> {
        self.utxo_chains.get(&module).copied()
    }

    pub fn account(&self, module: ModuleId) -> Option<&'a dyn AccountChainModule> {
        self.account_chains.get(&module).copied()
    }

    pub fn settlement(&self, module: ModuleId) -> Option<&'a dyn AtomicSettlement> {
        self.settlements.get(&module).copied()
    }
}

fn insert_unique<V: Copy>(
    entries: &mut BTreeMap<ModuleId, V>,
    key: ModuleId,
    value: V,
) -> Result<(), RegistryError> {
    if entries.contains_key(&key) {
        return Err(RegistryError::DuplicateModule(key));
    }
    entries.insert(key, value);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    #[error("module {0:?} is already registered for that capability")]
    DuplicateModule(ModuleId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendRequest {
    pub account: AccountId,
    pub destination: String,
    pub amount: Amount,
    pub maximum_fee: BaseUnits,
    pub request_nonce: u64,
}

impl SendRequest {
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.destination.is_empty() || self.destination.len() > MAX_DESTINATION_BYTES {
            return Err(ChainError::InvalidRequest("invalid destination length"));
        }
        if self.amount.base_units.is_zero() {
            return Err(ChainError::InvalidRequest("amount is zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreparedSend {
    pub module: ModuleId,
    pub amount: Amount,
    pub fee: BaseUnits,
    pub destination: String,
    pub expires_at_unix: u64,
    payload: Vec<u8>,
}

impl core::fmt::Debug for PreparedSend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedSend")
            .field("module", &self.module)
            .field("amount", &self.amount)
            .field("fee", &self.fee)
            .field("destination", &self.destination)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl PreparedSend {
    pub fn new(
        module: ModuleId,
        amount: Amount,
        fee: BaseUnits,
        destination: String,
        expires_at_unix: u64,
        payload: Vec<u8>,
    ) -> Result<Self, ChainError> {
        validate_opaque(&payload)?;
        Ok(Self {
            module,
            amount,
            fee,
            destination,
            expires_at_unix,
            payload,
        })
    }

    pub fn authorization_commitment(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeSend {
    pub prepared: PreparedSend,
    pub approval_id: ApprovalId,
    pub approved_at_unix: u64,
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorizedSend {
    #[zeroize(skip)]
    pub module: ModuleId,
    #[zeroize(skip)]
    pub approval_id: ApprovalId,
    signed_transaction: Vec<u8>,
}

impl core::fmt::Debug for AuthorizedSend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthorizedSend")
            .field("module", &self.module)
            .field("approval_id", &self.approval_id)
            .field("signed_transaction", &"[REDACTED]")
            .finish()
    }
}

impl AuthorizedSend {
    pub fn new(
        module: ModuleId,
        approval_id: ApprovalId,
        signed_transaction: Vec<u8>,
    ) -> Result<Self, ChainError> {
        validate_opaque(&signed_transaction)?;
        Ok(Self {
            module,
            approval_id,
            signed_transaction,
        })
    }

    fn into_transaction(mut self) -> Vec<u8> {
        core::mem::take(&mut self.signed_transaction)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastSend {
    pub authorized: AuthorizedSend,
}

impl BroadcastSend {
    pub fn into_transaction(self) -> Vec<u8> {
        self.authorized.into_transaction()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BroadcastReceipt {
    pub module: ModuleId,
    pub txid: TransactionHash,
    pub accepted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: TransactionHash,
    pub output_index: u32,
    pub value: Amount,
    pub confirmation_count: u32,
    pub spendable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UtxoFeePolicy {
    pub base_units_per_kweight: BaseUnits,
    pub minimum_relay: BaseUnits,
    pub dust_threshold: BaseUnits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountFeePolicy {
    pub base_fee_per_gas: BaseUnits,
    pub priority_fee_per_gas: BaseUnits,
    pub gas_limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettlementCapabilities {
    pub module: ModuleId,
    pub supported: bool,
    pub minimum_confirmations: u32,
    pub maximum_lock_bytes: u32,
}

/// Non-exportable per-session secp256k1 signing authority shared by the two
/// native HTLC adapters. Implementations expose only a compressed public key
/// and a purpose-supplied 32-byte transaction digest; the private scalar never
/// crosses the wallet boundary.
pub trait SettlementSigner {
    fn compressed_public_key(&self) -> [u8; 33];

    /// Return a canonical compact `(r || s)` ECDSA signature. Implementations
    /// must normalize `s` into the lower half of the curve order.
    fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 64], SettlementSigningError>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SettlementSigningError {
    #[error("settlement signing key is invalid")]
    InvalidKey,
    #[error("settlement digest signing failed")]
    SigningFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HtlcLockRequest {
    pub session_id: SessionId,
    pub amount: Amount,
    pub hashlock: ObjectHash,
    pub receiver_key: Vec<u8>,
    pub refund_key: Vec<u8>,
    pub absolute_timelock: u64,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHtlcLock(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyHtlcLockRequest {
    pub expected: SettlementLockExpectation,
    pub funding_transaction: Vec<u8>,
    pub confirmation_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedHtlcLock(pub VerifiedLock);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HtlcRedeemRequest {
    pub session_id: SessionId,
    pub lock: VerifiedLock,
    pub preimage: Preimage,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHtlcRedeem(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HtlcRefundRequest {
    pub session_id: SessionId,
    pub lock: VerifiedLock,
    pub current_chain_time: u64,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHtlcRefund(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketLockRequest(pub SettlementLockRequest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMarketLock(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyMarketLockRequest(pub VerifySettlementLockRequest);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedMarketLock(pub VerifiedLock);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketRedeemRequest(pub SettlementRedeemRequest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMarketRedeem(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketRefundRequest(pub SettlementRefundRequest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMarketRefund(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettlementLockRequest {
    pub session_id: SessionId,
    pub module: ModuleId,
    pub amount: Amount,
    pub hashlock: ObjectHash,
    pub receiver: String,
    pub refund_target: String,
    pub absolute_timelock: u64,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettlementLockExpectation {
    pub session_id: SessionId,
    pub module: ModuleId,
    pub amount: Amount,
    pub hashlock: ObjectHash,
    pub receiver: String,
    pub refund_target: String,
    pub absolute_timelock: u64,
    pub minimum_confirmations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSettlementLock(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifySettlementLockRequest {
    pub expected: SettlementLockExpectation,
    pub transaction_or_receipt: Vec<u8>,
    pub confirmation_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedSettlementLock(pub VerifiedLock);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementRedeemRequest {
    pub session_id: SessionId,
    pub lock: VerifiedLock,
    pub preimage: Preimage,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSettlementRedeem(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettlementRefundRequest {
    pub session_id: SessionId,
    pub lock: VerifiedLock,
    pub current_chain_time: u64,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSettlementRefund(pub PreparedArtifact);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservePreimageRequest {
    pub session_id: SessionId,
    pub hashlock: ObjectHash,
    pub spending_transaction: TransactionHash,
}

pub type ObserveSecretRequest = ObservePreimageRequest;

#[derive(Clone, Eq, PartialEq)]
pub struct PreparedArtifact {
    pub module: ModuleId,
    pub session_id: SessionId,
    pub fee: BaseUnits,
    pub expires_at_unix: u64,
    payload: Vec<u8>,
}

impl core::fmt::Debug for PreparedArtifact {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedArtifact")
            .field("module", &self.module)
            .field("session_id", &self.session_id)
            .field("fee", &self.fee)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl PreparedArtifact {
    pub fn new(
        module: ModuleId,
        session_id: SessionId,
        fee: BaseUnits,
        expires_at_unix: u64,
        payload: Vec<u8>,
    ) -> Result<Self, ChainError> {
        validate_opaque(&payload)?;
        Ok(Self {
            module,
            session_id,
            fee,
            expires_at_unix,
            payload,
        })
    }

    pub fn commitment_bytes(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedLock {
    pub module: ModuleId,
    pub session_id: SessionId,
    pub funding_id: TransactionHash,
    pub amount: Amount,
    pub hashlock: ObjectHash,
    pub absolute_timelock: u64,
    pub confirmation_count: u32,
    pub evidence_hash: ObjectHash,
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Preimage([u8; 32]);

impl Preimage {
    pub const LENGTH: usize = 32;

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes the secret only to a controlled settlement implementation. It
    /// must never cross the Provider API or FFI.
    pub fn expose_for_settlement(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Preimage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Preimage([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ChainError {
    #[error("module is disabled")]
    Disabled,
    #[error("wallet is locked")]
    Locked,
    #[error("module is not synchronized")]
    NotSynchronized,
    #[error("capability is unsupported")]
    Unsupported,
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("approval is missing, stale, or mismatched")]
    ApprovalRequired,
    #[error("fee exceeds the approved maximum")]
    FeeLimit,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("chain evidence is stale, missing, or contradictory")]
    InvalidEvidence,
    #[error("opaque transaction is empty or exceeds the bounded maximum")]
    InvalidTransactionSize,
    #[error("backend failed: {0}")]
    Backend(String),
}

fn validate_opaque(bytes: &[u8]) -> Result<(), ChainError> {
    if bytes.is_empty() || bytes.len() > MAX_OPAQUE_TRANSACTION_BYTES {
        return Err(ChainError::InvalidTransactionSize);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_wallet_types::WalletAsset;

    #[test]
    fn send_requests_are_bounded() {
        let request = SendRequest {
            account: AccountId::default(),
            destination: "x".repeat(MAX_DESTINATION_BYTES + 1),
            amount: Amount::new(WalletAsset::Hns, 1),
            maximum_fee: BaseUnits::new(1),
            request_nonce: 1,
        };
        assert_eq!(
            request.validate(),
            Err(ChainError::InvalidRequest("invalid destination length"))
        );
    }

    #[test]
    fn signed_transaction_is_not_debug_exposed_and_is_bounded() {
        let signed = AuthorizedSend::new(ModuleId::Handshake, ApprovalId::default(), vec![7; 32])
            .expect("bounded transaction");
        assert!(!format!("{signed:?}").contains("7, 7"));
        assert!(
            AuthorizedSend::new(
                ModuleId::Handshake,
                ApprovalId::default(),
                vec![0; MAX_OPAQUE_TRANSACTION_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn preimage_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", Preimage::new([9; 32])),
            "Preimage([REDACTED])"
        );
    }
}
