#![doc = "Handshake wallet key roles, restoration, UTXO selection, and name workflows."]
#![forbid(unsafe_code)]

mod embedded_backend;
mod light_authority;
mod light_index;
mod name_workflow;
mod node_rpc;
mod peer_coordinator;
mod shakedex_funding;
mod shakedex_key;
// The counter boundary stays crate-private until the immutable hns-rs HNSA/HNSR
// signing APIs are available to consume its opaque committed reservations.
#[allow(dead_code)]
mod hnsa_hnsr_publisher;

pub use embedded_backend::{EmbeddedHnsBackend, HnsLightNetwork};
pub use light_authority::{
    AcceptedHnsHeader, EncryptedHnsLightAuthority, HNS_LIGHT_CHAIN_FORMAT_VERSION, HnsLightError,
    HnsLightFloor, PersistedHeaderRound,
};
pub use light_index::{
    EncryptedHnsLightIndex, HNS_LIGHT_INDEX_FORMAT_VERSION, HnsLightIndexError, HnsLightScanStatus,
    HnsLightWatchSet, VerifiedHnsNameProof, VerifiedHnsTransactionObservation,
};
pub use name_workflow::{
    AuthorizedNameOperation, CurrentShakedexLockQuery, HnsNameAction, HnsNameLifecycle,
    NameActionContextEvidence, NameActionIneligibility, NameOperation, NameOperationState,
    PrepareNameFinalize, PrepareNameTransfer, PreparedNameOperation, VerifiedCurrentShakedexLock,
    VerifiedCurrentShakedexLockBatch, VerifiedCurrentShakedexLockEntry,
    VerifiedCurrentShakedexTransfer, VerifiedOutgoingNameTransfer,
};
pub use node_rpc::{HnsNodeRpcBackend, HnsNodeRpcConfig};
pub use peer_coordinator::{
    ConnectedHnsPeer, HnsBlockScanProgress, HnsDirectPeerConfig, HnsDirectPeerCoordinator,
    HnsDirectPeerError, HnsHeaderRoundProgress, NativeHnsPeerPool,
};
pub use shakedex_funding::{
    HnsPreparedShakedexFunding, HnsShakedexChangeReservation,
    HnsShakedexFundingApprovalExpectation, HnsShakedexFundingAuthorization,
    HnsShakedexFundingPurpose, HnsShakedexFundingReservation, HnsShakedexFundingReservationBatch,
    HnsShakedexFundingReservationState, HnsShakedexFundingScope, HnsShakedexTransactionObservation,
    activate_hns_shakedex_funding_reservations, create_hns_shakedex_funding_reservations,
    delete_hns_shakedex_funding_reservations, retain_active_hns_shakedex_funding_reservations,
    validate_hns_shakedex_final_fee_quote_evidence,
    validate_hns_shakedex_finalize_final_fee_quote_evidence,
    validate_hns_shakedex_funding_reservations, validate_persisted_hns_shakedex_fee_quote_evidence,
};
pub use shakedex_key::{
    HnsShakedexKeyAllocation, HnsShakedexKeyAllocationError, HnsShakedexKeyAllocationRequest,
    HnsShakedexSellerTerms, HnsShakedexSigner,
};

use name_workflow::{HnsInputReservationKind, HnsNameWorkflow};

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashSet, btree_map::Entry};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bech32::{Hrp, segwit};
use bip39::{Language, Mnemonic};
use blake2::Blake2bVar;
use blake2::digest::VariableOutput;
use hkdf::Hkdf;
use hns_covenants::{
    Covenant, CovenantKind, FinalizeCovenant, MAX_RESOURCE_SIZE, NameState, TransferCovenant,
    hash_name, validate_name,
};
use hns_primitives::{
    BlockHash, Dollarydoos, Height, NameHash, TransactionHash as CanonicalTransactionHash, TreeRoot,
};
use hns_script::{
    FeeRate, MAX_POLICY_TRANSACTION_SIGOPS, MAX_POLICY_TRANSACTION_WEIGHT, OP_BLAKE160,
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF,
    OP_SHA256, SIGHASH_ALL, minimum_policy_fee, signature_hash, transaction_policy_virtual_size,
    transaction_sigops,
};
use hns_swap::{NetworkBinding, lock_script_hash};
use hns_transaction::{Address, Coin, Input, Outpoint, Output, Transaction, Witness};
use hns_urkel_proof::{ProofKind, UrkelProof};
use hns_wallet_chain_api::{
    AtomicSettlement, AuthorizeSend, AuthorizedSend, BroadcastReceipt, BroadcastSend, ChainError,
    ChainModule, HtlcLockRequest, HtlcRedeemRequest, HtlcRefundRequest, ModuleRegistry,
    ObservePreimageRequest, ObserveSecretRequest, Preimage, PreparedArtifact, PreparedHtlcLock,
    PreparedHtlcRedeem, PreparedHtlcRefund, PreparedSend, PreparedSettlementLock,
    PreparedSettlementRedeem, PreparedSettlementRefund, RegistryError, SendRequest,
    SettlementCapabilities, SettlementLockExpectation, SettlementLockRequest,
    SettlementRedeemRequest, SettlementRefundRequest, Utxo, UtxoChainModule, UtxoFeePolicy,
    VerifiedHtlcLock, VerifiedLock, VerifiedSettlementLock, VerifyHtlcLockRequest,
    VerifySettlementLockRequest,
};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, EntityPrefixSetLease, EntityReadSnapshot,
    SecretKind, SharedWalletStore, SharedWalletStoreGuard, StoreError, StoredEntity,
    StoredWorkflow, WalletStore,
};
use hns_wallet_types::{
    AccountId, Amount, ApprovalId, BaseUnits, ChainCapabilities, DerivationReference, FeeModel,
    FinalityModel, HashAlgorithm, HnsNameReceiveTarget, KeyRole, LocalTransactionStatus,
    LocktimeModel, ModuleId, ObjectHash, ReceiveTarget, SessionId, SignedBaseUnits, SyncPhase,
    SyncStatus, TransactionHash, TransactionSummary, WalletAsset, WalletId, WorkflowId,
    WorkflowKind,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HNS_DERIVATION_DOMAIN: &[u8] = b"hns-wallet-rs/hns-role-key/v1";
pub const HNS_SETTLEMENT_KEY_DOMAIN: &[u8] = b"hns-wallet-rs/hns-settlement-key/v1";
pub const MAX_RESTORE_LOOKAHEAD: u32 = 10_000;
pub const MAX_RESTORE_SCRIPTS_PER_QUERY: usize = 10_000;
/// The coin, dedicated name, and Shakedex lock branches are queried separately
/// so no branch reduces another's bounded lookahead. Persisted address records
/// are nevertheless bounded as one account-owned collection.
pub const MAX_RESTORE_ADDRESS_RECORDS: usize = MAX_RESTORE_SCRIPTS_PER_QUERY * 3;
pub const DEFAULT_RESTORE_LOOKAHEAD: u32 = 100;
pub const MAX_WALLET_COINS: usize = 10_000;
pub const MAX_HISTORY_RESULTS: usize = 10_000;
pub const MAX_RECOVERY_CHECKPOINTS: usize = 288;
pub const MAX_TRANSACTION_INPUTS: usize = 10_000;
pub const PREPARED_ARTIFACT_LIFETIME_SECONDS: u64 = 300;
pub const DEFAULT_DUST_THRESHOLD: u128 = 546;
pub const HNS_LOCKTIME_THRESHOLD: u64 = 500_000_000;
pub const MAX_SCAN_PAGE_RESULTS: usize = 256;
pub const MAX_MEMPOOL_SCAN_RESULTS: usize = 1_024;
pub const MAX_OUTPOINT_SPEND_BATCH: usize = 256;
/// Maximum number of exact name/seller lock queries that may share one
/// selected-account, chain, mempool, and trusted-time observation.
pub const MAX_CURRENT_SHAKEDEX_LOCK_BATCH: usize = 64;
pub const MAX_SCAN_CURSOR_BYTES: usize = 4_096;
pub const MAX_SCAN_PAGES: usize = 128;
/// Incoming TRANSFER pages can return after the first nonempty script, so one
/// candidate on each supported name derivation can require one page per row.
/// The additive term covers pages that consume only the endpoint's bounded
/// batch of empty script prefixes.
const MAX_INCOMING_TRANSFER_PAGES: usize =
    MAX_HISTORY_RESULTS + MAX_RESTORE_SCRIPTS_PER_QUERY.div_ceil(MAX_SCAN_PAGE_RESULTS);
pub const MAX_SNAPSHOT_RESTARTS: usize = 3;
pub const DEFAULT_FEE_TARGET_BLOCKS: u16 = 6;
/// Canonical HSD fee-policy algebra is enabled for the integrated product flow.
/// Final distribution qualification is performed over the assembled product,
/// rather than blocking runtime exercise of this implementation.
pub const HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED: bool = true;
/// Protected Shakedex source/funding reservation and suffix signing are enabled
/// for the integrated product flow.
pub const HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED: bool = true;
/// Concrete HNS value operations are enabled for integrated mainnet testing.
pub const HNS_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = true;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HnsNetwork {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl HnsNetwork {
    const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "hs",
            Self::Testnet => "ts",
            Self::Regtest => "rs",
            Self::Simnet => "ss",
        }
    }
}

/// Explicit chain policy for the one-account native-wallet bootstrap.
///
/// Account derivation, gap limits, confirmation policy, dust policy, and all
/// value gates remain fixed by the reviewed wallet defaults. A product must
/// choose the network and an honest restore birthday instead of inheriting a
/// network-dependent implicit value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsBootstrapPolicy {
    pub network: HnsNetwork,
    pub birthday_height: u64,
}

impl HnsBootstrapPolicy {
    pub const fn new(network: HnsNetwork, birthday_height: u64) -> Self {
        Self {
            network,
            birthday_height,
        }
    }
}

fn shakedex_network_binding(network: HnsNetwork) -> Result<NetworkBinding, HnsWalletError> {
    let (_, genesis_hash) = name_workflow::expected_chain_identity(network)?;
    let magic = match network {
        HnsNetwork::Mainnet => 0x5b6e_f2d3,
        HnsNetwork::Testnet => 0xb152_0dd2,
        HnsNetwork::Regtest => 0xae38_95cf,
        HnsNetwork::Simnet => 0x0e64_8edc,
    };
    Ok(NetworkBinding {
        magic,
        genesis: BlockHash::new(genesis_hash),
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase(String);

impl RecoveryPhrase {
    /// Dedicated high-risk display boundary. Provider and ordinary FFI
    /// operations must never call this method.
    pub fn expose_for_dedicated_display(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryPhrase([REDACTED])")
    }
}

#[derive(Debug)]
pub struct CreatedWallet {
    pub wallet_id: WalletId,
    pub recovery_phrase: RecoveryPhrase,
}

fn generate_24_word_mnemonic() -> Result<Mnemonic, HnsWalletError> {
    Mnemonic::generate_in(Language::English, 24).map_err(|_| HnsWalletError::Randomness)
}

/// Generates the random wallet-local identifier used by the existing create
/// path. Recovery deliberately derives its identifier from the mnemonic
/// instead, preserving the established wallet semantics.
pub fn generate_wallet_id() -> Result<WalletId, HnsWalletError> {
    let mut wallet_id = [0_u8; 16];
    getrandom::fill(&mut wallet_id).map_err(|_| HnsWalletError::Randomness)?;
    Ok(WalletId::new(wallet_id))
}

/// Generates a nonzero random account identifier. This identifier is local
/// profile metadata; on-chain recovery is anchored by the stable account
/// derivation index rather than this random value.
pub fn generate_account_id() -> Result<AccountId, HnsWalletError> {
    for _ in 0..16 {
        let mut account_id = [0_u8; 16];
        getrandom::fill(&mut account_id).map_err(|_| HnsWalletError::Randomness)?;
        if account_id != [0_u8; 16] {
            return Ok(AccountId::new(account_id));
        }
    }
    Err(HnsWalletError::Randomness)
}

fn wallet_id_from_mnemonic(mnemonic: &Mnemonic) -> WalletId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-id/v1");
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    hasher.update(seed.as_slice());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WalletId::new(id)
}

pub fn create_wallet(
    store: &mut WalletStore,
    now_unix: u64,
) -> Result<CreatedWallet, HnsWalletError> {
    let mnemonic = generate_24_word_mnemonic()?;
    let wallet_id = generate_wallet_id()?;
    store_seed(store, wallet_id, &mnemonic, now_unix)?;
    Ok(CreatedWallet {
        wallet_id,
        recovery_phrase: RecoveryPhrase(mnemonic.to_string()),
    })
}

pub fn restore_wallet(
    store: &mut WalletStore,
    phrase: &str,
    now_unix: u64,
) -> Result<WalletId, HnsWalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| HnsWalletError::InvalidRecoveryPhrase)?;
    let wallet_id = wallet_id_from_mnemonic(&mnemonic);
    store_seed(store, wallet_id, &mnemonic, now_unix)?;
    Ok(wallet_id)
}

fn store_seed(
    store: &mut WalletStore,
    wallet_id: WalletId,
    mnemonic: &Mnemonic,
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    store.put_secret(
        wallet_id.as_bytes(),
        SecretKind::RecoverySeed,
        seed.as_slice(),
        now_unix,
    )?;
    Ok(())
}

pub fn derive_hns_public_key(
    store: &WalletStore,
    wallet_id: WalletId,
    reference: DerivationReference,
) -> Result<[u8; 33], HnsWalletError> {
    if !matches!(
        reference.role,
        KeyRole::HnsCoin
            | KeyRole::HnsName
            | KeyRole::HnsShakedex
            | KeyRole::HnsAtomicSwap
            | KeyRole::HnsIdentity
            | KeyRole::HnsDappSession
    ) {
        return Err(HnsWalletError::WrongKeyRole);
    }
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_secret(&seed, reference)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    let encoded = VerifyingKey::from(&signing).to_encoded_point(true);
    encoded
        .as_bytes()
        .try_into()
        .map_err(|_| HnsWalletError::KeyDerivation)
}

fn derive_secret(
    seed: &[u8],
    reference: DerivationReference,
) -> Result<Zeroizing<[u8; 32]>, HnsWalletError> {
    let role = key_role_code(reference.role).ok_or(HnsWalletError::WrongKeyRole)?;
    for counter in 0_u8..=u8::MAX {
        let mut info = Vec::with_capacity(HNS_DERIVATION_DOMAIN.len() + 18);
        info.extend_from_slice(HNS_DERIVATION_DOMAIN);
        info.extend_from_slice(&role.to_be_bytes());
        info.extend_from_slice(&reference.account.to_be_bytes());
        info.extend_from_slice(&reference.change.to_be_bytes());
        info.extend_from_slice(&reference.index.to_be_bytes());
        info.push(counter);
        let hkdf = Hkdf::<Sha256>::new(Some(b"Handshake role separation"), seed);
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if SigningKey::from_slice(candidate.as_slice()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(HnsWalletError::KeyDerivation)
}

const fn key_role_code(role: KeyRole) -> Option<u32> {
    match role {
        KeyRole::HnsCoin => Some(0),
        KeyRole::HnsName => Some(1),
        KeyRole::HnsShakedex => Some(2),
        KeyRole::HnsAtomicSwap => Some(3),
        KeyRole::HnsIdentity => Some(4),
        KeyRole::HnsDappSession => Some(5),
        _ => None,
    }
}

pub fn receive_address(
    network: HnsNetwork,
    compressed_public_key: &[u8; 33],
) -> Result<String, HnsWalletError> {
    let program = public_key_hash(compressed_public_key)?;
    encode_v0_address(network, &program)
}

fn encode_v0_address(network: HnsNetwork, program: &[u8]) -> Result<String, HnsWalletError> {
    let hrp = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::Address)?;
    segwit::encode_v0(hrp, program).map_err(|_| HnsWalletError::Address)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletCoin {
    pub outpoint: HnsOutpoint,
    pub value: BaseUnits,
    pub confirmation_count: u32,
    /// Exact active-chain inclusion height supplied by the confirmed wallet
    /// index. `None` is accepted only while decoding a legacy row; such a row
    /// cannot become transaction input evidence.
    #[serde(default)]
    pub confirmed_height: Option<u32>,
    /// Exact node evidence. Coinbase outputs remain conservatively excluded
    /// until a released canonical maturity policy is wired into selection.
    #[serde(default = "coinbase_evidence_unknown")]
    pub coinbase: bool,
    /// Canonical encoded Handshake covenant. An empty legacy default is never
    /// interpreted as `NONE`; conversion to a consensus coin fails closed.
    #[serde(default)]
    pub covenant: Vec<u8>,
    pub name_locked: bool,
}

const fn coinbase_evidence_unknown() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct HnsOutpoint {
    pub transaction: TransactionHash,
    pub output_index: u32,
}

pub fn select_coins(
    coins: &[WalletCoin],
    target: BaseUnits,
) -> Result<CoinSelection, HnsWalletError> {
    if target.is_zero() || coins.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    let mut candidates: Vec<_> = coins
        .iter()
        .filter(|coin| !coin.name_locked && !coin.coinbase)
        .cloned()
        .collect();
    candidates.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| left.outpoint.cmp(&right.outpoint))
    });
    let mut selected = Vec::new();
    let mut total = BaseUnits::ZERO;
    for coin in candidates {
        total = total
            .checked_add(coin.value)
            .map_err(|_| HnsWalletError::Arithmetic)?;
        selected.push(coin);
        if total >= target {
            let change = total
                .checked_sub(target)
                .map_err(|_| HnsWalletError::Arithmetic)?;
            return Ok(CoinSelection {
                coins: selected,
                total,
                change,
            });
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinSelection {
    pub coins: Vec<WalletCoin>,
    pub total: BaseUnits,
    pub change: BaseUnits,
}

pub const MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE: usize = 256;
pub const MAX_DENUO_NAME_MARKET_ENVELOPE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenuoTransportMessageKind {
    Offer,
    Cancellation,
}

/// Exact durable publication attempt sent to the authenticated local node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoPublicationHandoff {
    pub network_magic: u32,
    pub network_genesis: [u8; 32],
    pub attempt_id: [u8; 32],
    pub record_sequence: u64,
    pub prepared_at_unix: u64,
    pub envelope_id: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub content_id: [u8; 32],
    pub message_kind: DenuoTransportMessageKind,
    pub request_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoPublicationAcceptance {
    pub relay_revision: u64,
    pub kind: DenuoTransportMessageKind,
    pub content_id: [u8; 32],
    pub inserted: bool,
    pub accepted_at_unix: u64,
    pub receipt_bytes: Vec<u8>,
    pub propagation_attempted: usize,
    pub propagation_written: usize,
    pub propagation_failed: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoTransportEvent {
    pub revision: u64,
    pub received_at_unix: u64,
    pub kind: DenuoTransportMessageKind,
    pub content_id: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoTransportEventPage {
    pub instance_nonce: [u8; 32],
    pub cursor_reset: bool,
    pub oldest_revision: u64,
    pub head_revision: u64,
    pub events: Vec<DenuoTransportEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoTransportSnapshotRecord {
    pub kind: DenuoTransportMessageKind,
    pub content_id: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoTransportSnapshotPage {
    pub instance_nonce: [u8; 32],
    pub snapshot_revision: u64,
    pub next_offset: Option<usize>,
    pub records: Vec<DenuoTransportSnapshotRecord>,
}

pub trait HnsBackend {
    /// Returns the current initialized tip and durable chain epoch without
    /// receiving any wallet script identifiers.
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError>;
    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError>;
    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError>;
    /// Pages confirmed history and UTXOs over the complete sorted script set.
    /// The adapter must reject a stale epoch/cursor with `StaleNodeSnapshot`.
    fn get_confirmed_wallet_page(
        &self,
        request: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError>;
    /// Pages active confirmed TRANSFERs whose covenant recipient matches the
    /// complete sorted script set. These rows are derivation-discovery hints
    /// only: their Coin is still locked to the old owner's output address.
    fn get_incoming_transfers_page(
        &self,
        _request: IncomingTransfersPageRequest<'_>,
    ) -> Result<IncomingTransfersPage, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }
    /// Pages mempool history at one node-instance/generation pair, also tied
    /// to the confirmed chain binding and exact script set. The adapter must
    /// reject a stale instance, generation, script set, or cursor.
    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError>;
    /// Returns raw bytes, status, and inclusion from one canonical snapshot.
    /// A pruned node may omit raw bytes, but not the other fields.
    fn get_transaction_evidence(
        &self,
        txid: TransactionHash,
        binding: SnapshotBinding,
        expected_mempool: Option<MempoolSnapshotBinding>,
    ) -> Result<TransactionEvidence, HnsWalletError>;
    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError>;
    fn broadcast_transaction(&self, raw: &[u8]) -> Result<TransactionHash, HnsWalletError>;
    /// Quotes one exact serialized transaction against the complete wallet
    /// reconciliation binding. The ordered coins are exact wallet evidence;
    /// the node resolves the same outpoints and returns policy/rate evidence
    /// for independent local comparison. This method never signs or submits.
    fn quote_transaction_fee(
        &self,
        raw: &[u8],
        input_coins: &[Coin],
        target_blocks: u16,
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError>;
    /// Node estimate in atomic units per 1,000 HSD policy virtual bytes. The
    /// wallet applies it only through pinned canonical sigop-adjusted policy
    /// sizing; the enclosing value gate remains independently unavailable.
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<BaseUnits, HnsWalletError>;
    /// Returns the interval-committed proof view and current name view without
    /// collapsing them. Every field is tied to the supplied snapshot binding.
    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError>;
    /// Returns the exact active UTXO selected by the current NameState without
    /// requiring retained transaction or block bytes. This is trusted-node
    /// discovery evidence, never signing or mutation authority.
    fn get_active_name_owner_coin(
        &self,
        _name_hash: [u8; 32],
        _binding: SnapshotBinding,
    ) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }
    /// Returns candidate-height TRANSFER/FINALIZE policy, exact owner, active
    /// chain, and owner-spender evidence from one authenticated chain/mempool
    /// snapshot. The wallet independently validates every projection.
    fn get_name_action_context(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError>;

    /// Returns the pruning-safe version-2 action context whose active owner
    /// is represented by exact current UTXO evidence rather than retained raw
    /// transaction bytes. The default keeps older backend implementations
    /// source-compatible while failing closed if they are selected for a v2
    /// operation.
    fn get_name_action_context_v2(
        &self,
        _action: HnsNameAction,
        _name_hash: [u8; 32],
        _binding: SnapshotBinding,
        _expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }

    /// Hand one exact durably prepared Denuo publication to the authenticated
    /// local node and require its endpoint-signed acceptance receipt.
    fn publish_denuo_name_market(
        &self,
        _envelope_bytes: &[u8],
        _handoff: DenuoPublicationHandoff,
    ) -> Result<DenuoPublicationAcceptance, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }

    /// Read one process-instance-bound page of untrusted marketplace events.
    fn get_denuo_name_market_events(
        &self,
        _expected_instance_nonce: Option<[u8; 32]>,
        _after_revision: u64,
        _limit: usize,
    ) -> Result<DenuoTransportEventPage, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }

    /// Rebuild from a coherent latest-state snapshot after a node restart or
    /// retained-event-window gap.
    fn get_denuo_name_market_snapshot(
        &self,
        _expected_revision: Option<u64>,
        _offset: usize,
        _limit: usize,
    ) -> Result<DenuoTransportSnapshotPage, HnsWalletError> {
        Err(HnsWalletError::RuntimeIntegrationUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tree_root: [u8; 32],
    /// Median time past of this exact tip. For a candidate transaction this
    /// is the consensus parent time used by Shakedex absolute-lock checks.
    /// A zero from legacy persisted data is non-authoritative until refreshed.
    #[serde(default)]
    pub median_time_past: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotBinding {
    pub tip: ChainTip,
    /// Durable monotonic canonical-chain epoch owned by the node wallet index.
    pub chain_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockHashEvidence {
    pub binding: SnapshotBinding,
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub in_mempool: bool,
    pub confirmation_count: u32,
    pub conflicted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInclusion {
    pub block_hash: [u8; 32],
    pub height: u64,
    /// Exact block transaction position when retained payload permits the node
    /// to derive it. A pruned payload must remain `None`, never invented zero.
    pub transaction_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub txid: TransactionHash,
    pub height: Option<u64>,
    pub block_hash: Option<[u8; 32]>,
    pub transaction_position: Option<u32>,
    pub spent: bool,
    /// Exact block time or mempool admission time. Confirmed header time may
    /// be unavailable and must remain `None`.
    pub first_seen_unix: Option<u64>,
    pub script_index: u32,
}

/// One backend UTXO tied to the index of the requested script. Returning the
/// index instead of wallet derivation data keeps the node boundary watch-only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedWalletCoin {
    pub coin: WalletCoin,
    pub script_index: u32,
    /// Canonical output address observed by the node. It must equal the exact
    /// requested version/hash pair, not merely its hash bytes.
    pub output_address: WalletAddressKey,
}

/// Exact canonical Handshake address input for the node's ScriptId conversion.
/// Restoration derives version-0 20-byte coin/name programs and separated
/// 32-byte Shakedex lock-script programs.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WalletAddressKey {
    pub version: u8,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedWalletPageRequest<'a> {
    pub scripts: &'a [WalletAddressKey],
    pub expected_tip: ChainTip,
    pub expected_epoch: Option<u64>,
    pub cursor: Option<&'a [u8]>,
    pub limit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedWalletPage {
    pub binding: SnapshotBinding,
    pub next_cursor: Option<Vec<u8>>,
    pub history: Vec<HistoryEntry>,
    pub utxos: Vec<IndexedWalletCoin>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingTransfersPageRequest<'a> {
    pub scripts: &'a [WalletAddressKey],
    pub binding: SnapshotBinding,
    pub cursor: Option<&'a [u8]>,
    pub limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncomingTransferSourceBinding {
    RetainedBodyVerified,
    PrunedTrustedNodeProjection,
}

/// One active TRANSFER addressed by covenant to a requested derivation. The
/// embedded Coin remains the old owner's active TRANSFER output and must never
/// be reconciled into the recipient wallet's UTXO set or balance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingTransferCandidate {
    pub script_index: u32,
    pub recipient: WalletAddressKey,
    pub name_hash: [u8; 32],
    pub start_height: u32,
    pub transfer_coin: Coin,
    pub inclusion: TransactionInclusion,
    pub source_output_count: u32,
    pub source_binding: IncomingTransferSourceBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingTransfersPage {
    pub projection_version: u8,
    pub binding: SnapshotBinding,
    pub entries: Vec<IncomingTransferCandidate>,
    pub script_examinations: usize,
    pub next_cursor: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolWalletPageRequest<'a> {
    pub scripts: &'a [WalletAddressKey],
    pub binding: SnapshotBinding,
    /// The adapter must bind this instance/generation pair, the exact sorted
    /// script set, and the cursor into one page query.
    pub expected_mempool: Option<MempoolSnapshotBinding>,
    pub cursor: Option<&'a [u8]>,
    pub limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolSnapshotBinding {
    /// Nonpersistent node-process identity. It prevents a generation counter
    /// reset after restart from being mistaken for the prior mempool view.
    pub instance_nonce: [u8; 32],
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsFeeRateSource {
    MinimumRelay,
    Mempool,
    /// Lower-median relay floor advertised by connected untrusted peers.
    PeerRelay,
}

/// Exact node-resolved HSD policy evidence for one serialized transaction.
/// The transaction bytes remain the durable source artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsTransactionFeeQuote {
    pub txid: TransactionHash,
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub target_blocks: u16,
    pub rate_atomic_units_per_1000_policy_vbytes: u64,
    pub rate_sample_count: usize,
    pub rate_source: HnsFeeRateSource,
    pub transaction_weight: usize,
    pub transaction_sigops: u32,
    pub sigop_adjusted_policy_vbytes: usize,
    pub minimum_policy_fee: BaseUnits,
    pub actual_fee: BaseUnits,
    pub meets_minimum_policy_fee: bool,
    pub minimum_policy_fee_shortfall: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolWalletPage {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub next_cursor: Option<Vec<u8>>,
    pub history: Vec<HistoryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionEvidence {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub raw: Option<Vec<u8>>,
    pub status: TransactionStatus,
    pub inclusion: Option<TransactionInclusion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendEvidence {
    pub binding: SnapshotBinding,
    /// Exactly one echoed entry per requested outpoint, in request order.
    pub entries: Vec<OutpointSpendEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendEntry {
    pub outpoint: HnsOutpoint,
    pub spending: Option<SpendingTransactionEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendingTransactionEvidence {
    pub transaction: TransactionHash,
    pub input_position: u32,
    pub block_hash: [u8; 32],
    pub height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameProofResponse {
    pub name_hash: [u8; 32],
    pub tree_root: [u8; 32],
    pub proof: Vec<u8>,
    pub proof_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameEvidence {
    pub binding: SnapshotBinding,
    pub proof: NameProofResponse,
    /// The interval-committed state bytes. These must exactly equal the bytes
    /// recovered by strict Urkel proof verification.
    pub proof_state: Option<Vec<u8>>,
    /// Node projection that the wallet independently binds to `proof_state`.
    pub proof_owner_outpoint: Option<HnsOutpoint>,
    pub proof_owner_transaction: Option<Vec<u8>>,
    #[serde(default)]
    pub proof_owner_inclusion: Option<TransactionInclusion>,
    /// The node's current canonical view at `binding`. It may differ from the
    /// most recently committed name-tree proof view.
    pub current_state: Option<Vec<u8>>,
    /// Node projection that the wallet independently binds to `current_state`.
    pub current_owner_outpoint: Option<HnsOutpoint>,
    pub current_owner_transaction: Option<Vec<u8>>,
    #[serde(default)]
    pub current_owner_inclusion: Option<TransactionInclusion>,
    /// Legacy field name retained at the RPC/storage boundary. The wallet
    /// accepts these bytes only when they exactly equal canonical
    /// `NameState::resource_data` for `current_state`.
    pub untrusted_current_raw_resource: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveNameOwnerCoinSourceBinding {
    TrustedNodeActiveUtxoProjection,
    /// Coin reconstructed from a transaction proven in a locally validated
    /// filtered block under the wallet's own header authority.
    LocallyVerifiedFilteredBlock,
}

/// Pruning-safe current NameState/owner-Coin projection. The source label
/// distinguishes a trusted node UTXO projection from a Coin reconstructed by
/// the wallet from a Merkle-verified transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveNameOwnerCoinEvidence {
    pub projection_version: u8,
    pub binding: SnapshotBinding,
    pub current_state: Vec<u8>,
    pub owner_coin: Coin,
    pub inclusion: TransactionInclusion,
    pub source_binding: ActiveNameOwnerCoinSourceBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameResourceStatus {
    /// Legacy persisted records remain non-authoritative until reconciliation.
    UnavailableCanonicalBinding,
    NoCurrentState,
    Empty,
    CanonicalDecoded,
    /// Consensus-authenticated bytes that are not a typed DNS Resource.
    CanonicalOpaque,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOwnershipStatus {
    /// Legacy persisted records remain watch-only until fresh reconciliation.
    WatchOnlyCanonicalStateDecoderUnavailable,
    /// Canonical name state was authenticated without an account address set,
    /// so wallet ownership was deliberately not classified.
    WalletContextUnavailable,
    NoCurrentOwner,
    NotWalletOwned,
    WalletOwned {
        derivation: DerivationReference,
    },
    IncomingTransfer {
        recipient_derivation: DerivationReference,
        current_owner: WalletAddressKey,
    },
    OutgoingTransfer {
        owner_derivation: DerivationReference,
        recipient: WalletAddressKey,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalNameStateSummary {
    pub owner_outpoint: Option<HnsOutpoint>,
    pub value: u64,
    pub highest: u64,
    pub start_height: u32,
    pub renewal_height: u32,
    pub transfer_height: u32,
    pub revoked_height: u32,
    pub claimed_height: u32,
    pub renewals: u32,
    pub registered: bool,
    pub expired: bool,
    pub weak: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnownName {
    pub name: Vec<u8>,
    pub name_hash: [u8; 32],
    pub proof_height: u64,
    pub unbound_proof_owner_outpoint: Option<HnsOutpoint>,
    pub unbound_current_owner_outpoint: Option<HnsOutpoint>,
    pub proof_state: Option<Vec<u8>>,
    pub current_state: Option<Vec<u8>>,
    #[serde(default)]
    pub canonical_proof_state: Option<CanonicalNameStateSummary>,
    #[serde(default)]
    pub canonical_current_state: Option<CanonicalNameStateSummary>,
    #[serde(default)]
    pub current_raw_resource: Option<Vec<u8>>,
    pub resource_status: NameResourceStatus,
    pub ownership_status: NameOwnershipStatus,
}

/// Ephemeral proof that the current runtime snapshot binds a canonical name
/// owner output to one persisted `HnsName` derivation. It is deliberately not
/// serializable or cloneable; every value workflow must reacquire it and check
/// that its exact snapshot is still current before preparing an action.
pub struct VerifiedNameOwnership {
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    name: Vec<u8>,
    name_hash: [u8; 32],
    current_state: Vec<u8>,
    owner_outpoint: HnsOutpoint,
    owner_transaction: Vec<u8>,
    owner_output: Output,
    owner_inclusion: TransactionInclusion,
    derivation: DerivationReference,
}

impl fmt::Debug for VerifiedNameOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedNameOwnership")
            .field("binding", &self.binding)
            .field("mempool", &self.mempool)
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("name_hash", &hex::encode(self.name_hash))
            .field("owner_outpoint", &self.owner_outpoint)
            .field("derivation", &self.derivation)
            .finish_non_exhaustive()
    }
}

impl VerifiedNameOwnership {
    pub const fn binding(&self) -> SnapshotBinding {
        self.binding
    }

    pub const fn mempool(&self) -> MempoolSnapshotBinding {
        self.mempool
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub const fn name_hash(&self) -> [u8; 32] {
        self.name_hash
    }

    pub fn current_state(&self) -> &[u8] {
        &self.current_state
    }

    pub const fn owner_outpoint(&self) -> HnsOutpoint {
        self.owner_outpoint
    }

    pub fn owner_transaction(&self) -> &[u8] {
        &self.owner_transaction
    }

    pub fn owner_output(&self) -> &Output {
        &self.owner_output
    }

    pub const fn owner_inclusion(&self) -> TransactionInclusion {
        self.owner_inclusion
    }

    pub const fn derivation(&self) -> DerivationReference {
        self.derivation
    }
}

struct ValidatedNameEvidence {
    known_name: KnownName,
    current: Option<ValidatedCanonicalNameState>,
}

struct ValidatedCanonicalNameState {
    state: NameState,
    summary: CanonicalNameStateSummary,
    owner: Option<ValidatedNameOwner>,
}

struct ValidatedNameOwner {
    outpoint: HnsOutpoint,
    raw_transaction: Vec<u8>,
    output: Output,
    inclusion: TransactionInclusion,
}

pub fn import_known_name<B: HnsBackend>(
    backend: &B,
    name: &[u8],
    binding: SnapshotBinding,
) -> Result<KnownName, HnsWalletError> {
    Ok(validated_name_evidence(backend, name, binding, None)?.known_name)
}

fn validated_name_evidence<B: HnsBackend>(
    backend: &B,
    name: &[u8],
    binding: SnapshotBinding,
    wallet_name_addresses: Option<&[DerivedHnsAddress]>,
) -> Result<ValidatedNameEvidence, HnsWalletError> {
    if !validate_name(name) {
        return Err(HnsWalletError::InvalidName);
    }
    let name_hash = hash_name(name)
        .map_err(|_| HnsWalletError::InvalidName)?
        .into_bytes();
    let evidence = backend.get_name_evidence(name_hash, binding)?;
    if evidence.binding != binding {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let response = &evidence.proof;
    if response.name_hash != name_hash
        || response.tree_root != binding.tip.tree_root
        || response.proof_height != binding.tip.height
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let proof = UrkelProof {
        name_hash: NameHash::new(name_hash),
        kind: if evidence.proof_state.is_some() {
            ProofKind::Inclusion
        } else {
            ProofKind::NonInclusion
        },
        raw: response.proof.clone(),
    };
    let proof_state = proof
        .verify_strict(TreeRoot::new(response.tree_root))
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if proof_state != evidence.proof_state {
        return Err(HnsWalletError::InvalidEvidence);
    }
    if let Some(wallet_name_addresses) = wallet_name_addresses {
        validate_wallet_name_addresses(wallet_name_addresses)?;
    }
    let canonical_proof = validate_canonical_name_state(
        name,
        name_hash,
        evidence.proof_state.as_deref(),
        evidence.proof_owner_outpoint,
        evidence.proof_owner_transaction.as_deref(),
        evidence.proof_owner_inclusion,
    )?;
    let canonical_current = validate_canonical_name_state(
        name,
        name_hash,
        evidence.current_state.as_deref(),
        evidence.current_owner_outpoint,
        evidence.current_owner_transaction.as_deref(),
        evidence.current_owner_inclusion,
    )?;
    let (current_raw_resource, resource_status) = bind_current_name_resource(
        canonical_current.as_ref(),
        evidence.untrusted_current_raw_resource,
    )?;
    let ownership_status =
        classify_name_ownership(canonical_current.as_ref(), wallet_name_addresses)?;
    let known_name = KnownName {
        name: name.to_vec(),
        name_hash,
        proof_height: response.proof_height,
        unbound_proof_owner_outpoint: evidence.proof_owner_outpoint,
        unbound_current_owner_outpoint: evidence.current_owner_outpoint,
        proof_state,
        current_state: evidence.current_state,
        canonical_proof_state: canonical_proof.as_ref().map(|state| state.summary.clone()),
        canonical_current_state: canonical_current
            .as_ref()
            .map(|state| state.summary.clone()),
        current_raw_resource,
        resource_status,
        ownership_status,
    };
    Ok(ValidatedNameEvidence {
        known_name,
        current: canonical_current,
    })
}

fn bind_current_name_resource(
    current: Option<&ValidatedCanonicalNameState>,
    projected: Option<Vec<u8>>,
) -> Result<(Option<Vec<u8>>, NameResourceStatus), HnsWalletError> {
    let canonical = current.map(|current| current.state.resource_data.clone());
    if canonical != projected {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let status = match current {
        None => NameResourceStatus::NoCurrentState,
        Some(current) if current.state.resource_data.is_empty() => NameResourceStatus::Empty,
        Some(current) if current.state.resource().is_ok() => NameResourceStatus::CanonicalDecoded,
        Some(_) => NameResourceStatus::CanonicalOpaque,
    };
    Ok((canonical, status))
}

fn validate_canonical_name_state(
    expected_name: &[u8],
    expected_name_hash: [u8; 32],
    raw_state: Option<&[u8]>,
    owner: Option<HnsOutpoint>,
    raw: Option<&[u8]>,
    inclusion: Option<TransactionInclusion>,
) -> Result<Option<ValidatedCanonicalNameState>, HnsWalletError> {
    let Some(raw_state) = raw_state else {
        if owner.is_some() || raw.is_some() || inclusion.is_some() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        return Ok(None);
    };
    let state = NameState::decode(NameHash::new(expected_name_hash), raw_state)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if state.is_null() || state.name != expected_name {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let canonical_owner = state.owner_outpoint().map(|owner| HnsOutpoint {
        transaction: TransactionHash::new(owner.transaction_hash.into_bytes()),
        output_index: owner.index,
    });
    if canonical_owner != owner {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let validated_owner = match (canonical_owner, raw, inclusion) {
        (None, None, None) => None,
        (Some(owner), Some(raw), Some(inclusion)) => Some(validate_name_owner_transaction(
            &state, owner, raw, inclusion,
        )?),
        _ => return Err(HnsWalletError::InvalidEvidence),
    };
    let summary = CanonicalNameStateSummary {
        owner_outpoint: canonical_owner,
        value: state.value.get(),
        highest: state.highest.get(),
        start_height: state.height.get(),
        renewal_height: state.renewal.get(),
        transfer_height: state.transfer.get(),
        revoked_height: state.revoked.get(),
        claimed_height: state.claimed.get(),
        renewals: state.renewals,
        registered: state.registered,
        expired: state.expired,
        weak: state.weak,
    };
    Ok(Some(ValidatedCanonicalNameState {
        state,
        summary,
        owner: validated_owner,
    }))
}

fn validate_active_name_owner_coin_evidence(
    evidence: &ActiveNameOwnerCoinEvidence,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
) -> Result<NameState, HnsWalletError> {
    let valid_inclusion_shape = match evidence.source_binding {
        ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection => {
            evidence.inclusion.transaction_index.is_none()
        }
        ActiveNameOwnerCoinSourceBinding::LocallyVerifiedFilteredBlock => {
            evidence.inclusion.transaction_index.is_some()
        }
    };
    if evidence.projection_version != 1
        || evidence.binding != binding
        || !valid_inclusion_shape
        || evidence.inclusion.height > binding.tip.height
        || evidence.inclusion.block_hash == [0; 32]
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let state = NameState::decode(NameHash::new(expected_name_hash), &evidence.current_state)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if state.is_null()
        || state.name_hash.into_bytes() != expected_name_hash
        || !validate_name(&state.name)
        || hash_name(&state.name)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes()
            != expected_name_hash
        || state
            .encode()
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            != evidence.current_state
    {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let coin = &evidence.owner_coin;
    if coin.outpoint != state.owner
        || u64::from(coin.height.get()) != evidence.inclusion.height
        || coin.outpoint.is_null()
        || (state.registered && coin.value != state.value)
        || !matches!(
            coin.covenant.kind,
            CovenantKind::Claim
                | CovenantKind::Reveal
                | CovenantKind::Register
                | CovenantKind::Update
                | CovenantKind::Renew
                | CovenantKind::Transfer
                | CovenantKind::Finalize
        )
        || coin.covenant.item_name_hash(0) != Some(state.name_hash)
        || covenant_item_u32(&coin.covenant, 1) != Some(state.height.get())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let valid = match coin.covenant.kind {
        CovenantKind::Claim => {
            coin.coinbase
                && !state.registered
                && coin.covenant.items.len() == 6
                && coin.covenant.items.get(2).map(Vec::as_slice) == Some(state.name.as_slice())
                && covenant_item_u8(&coin.covenant, 3)
                    .is_some_and(|flags| flags & 1 == u8::from(state.weak))
                && covenant_item_32(&coin.covenant, 4).is_some()
                && covenant_item_u32(&coin.covenant, 5) == Some(state.claimed.get())
                && state.renewal == coin.height
        }
        CovenantKind::Reveal => {
            !coin.coinbase
                && !state.registered
                && coin.covenant.items.len() == 3
                && covenant_item_32(&coin.covenant, 2).is_some()
                && coin.value == state.highest
        }
        CovenantKind::Register => {
            !coin.coinbase
                && coin.covenant.items.len() == 4
                && coin.covenant.items.get(2).is_some_and(|data| {
                    data.len() <= MAX_RESOURCE_SIZE
                        && (data.is_empty() || data == &state.resource_data)
                })
                && covenant_item_32(&coin.covenant, 3).is_some()
                && state.registered
                && state.transfer.get() == 0
                && state.renewal == coin.height
        }
        CovenantKind::Update => {
            !coin.coinbase
                && coin.covenant.items.len() == 3
                && coin.covenant.items.get(2).is_some_and(|data| {
                    data.len() <= MAX_RESOURCE_SIZE
                        && (data.is_empty() || data == &state.resource_data)
                })
                && state.registered
                && state.transfer.get() == 0
        }
        CovenantKind::Renew => {
            !coin.coinbase
                && coin.covenant.items.len() == 3
                && covenant_item_32(&coin.covenant, 2).is_some()
                && state.registered
                && state.transfer.get() == 0
                && state.renewal == coin.height
        }
        CovenantKind::Transfer => {
            TransferCovenant::try_from(&coin.covenant).is_ok_and(|transfer| {
                !coin.coinbase
                    && state.registered
                    && transfer.name_hash == state.name_hash
                    && transfer.start_height == state.height
                    && state.transfer.get() != 0
                    && state.transfer == coin.height
            })
        }
        CovenantKind::Finalize => {
            FinalizeCovenant::try_from(&coin.covenant).is_ok_and(|finalize| {
                !coin.coinbase
                    && state.registered
                    && finalize.name_hash == state.name_hash
                    && finalize.start_height == state.height
                    && finalize.name == state.name
                    && finalize.weak() == state.weak
                    && finalize.claimed == state.claimed
                    && finalize
                        .renewals
                        .checked_add(1)
                        .is_some_and(|renewals| renewals == state.renewals)
                    && state.transfer.get() == 0
                    && state.renewal == coin.height
            })
        }
        _ => false,
    };
    if !valid {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(state)
}

fn covenant_item_u8(covenant: &Covenant, index: usize) -> Option<u8> {
    let item = covenant.items.get(index)?;
    (item.len() == 1).then_some(item[0])
}

fn covenant_item_u32(covenant: &Covenant, index: usize) -> Option<u32> {
    covenant
        .items
        .get(index)?
        .as_slice()
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn covenant_item_32(covenant: &Covenant, index: usize) -> Option<[u8; 32]> {
    covenant.items.get(index)?.as_slice().try_into().ok()
}

fn validate_name_owner_transaction(
    state: &NameState,
    owner: HnsOutpoint,
    raw: &[u8],
    inclusion: TransactionInclusion,
) -> Result<ValidatedNameOwner, HnsWalletError> {
    let transaction = decode_transaction_for_id(raw, owner.transaction)?;
    let output = transaction
        .outputs
        .get(owner.output_index as usize)
        .cloned()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    if output.value != state.value
        || output.covenant.item_name_hash(0) != Some(state.name_hash)
        || !output.covenant.kind.is_name()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match output.covenant.kind {
        CovenantKind::Transfer => {
            let transfer = TransferCovenant::try_from(&output.covenant)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
            if state.transfer.get() == 0
                || u64::from(state.transfer.get()) != inclusion.height
                || transfer.start_height != state.height
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        CovenantKind::Finalize => {
            let finalize = FinalizeCovenant::try_from(&output.covenant)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
            if state.transfer.get() != 0
                || finalize.start_height != state.height
                || finalize.name != state.name
                || finalize.claimed != state.claimed
                || finalize.renewals != state.renewals
                || finalize.weak() != state.weak
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        _ if state.transfer.get() != 0 => return Err(HnsWalletError::InvalidEvidence),
        _ => {}
    }
    Ok(ValidatedNameOwner {
        outpoint: owner,
        raw_transaction: raw.to_vec(),
        output,
        inclusion,
    })
}

fn validate_wallet_name_addresses(
    wallet_name_addresses: &[DerivedHnsAddress],
) -> Result<(), HnsWalletError> {
    if wallet_name_addresses.len() > MAX_RESTORE_SCRIPTS_PER_QUERY {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut programs = BTreeSet::new();
    let mut identity = None;
    for address in wallet_name_addresses {
        let current_identity = (address.account_id, address.derivation.account);
        if address.derivation.role != KeyRole::HnsName
            || address.derivation.change != 0
            || address.program.len() != 20
            || !programs.insert(address.program.clone())
            || identity.is_some_and(|expected| expected != current_identity)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        identity = Some(current_identity);
    }
    Ok(())
}

fn wallet_name_derivation(
    address: &Address,
    wallet_name_addresses: &[DerivedHnsAddress],
) -> Option<DerivationReference> {
    (address.version == 0).then_some(())?;
    wallet_name_addresses
        .iter()
        .find(|candidate| candidate.program == address.hash)
        .map(|candidate| candidate.derivation)
}

fn classify_name_ownership(
    current: Option<&ValidatedCanonicalNameState>,
    wallet_name_addresses: Option<&[DerivedHnsAddress]>,
) -> Result<NameOwnershipStatus, HnsWalletError> {
    let Some(wallet_name_addresses) = wallet_name_addresses else {
        return Ok(NameOwnershipStatus::WalletContextUnavailable);
    };
    let Some(current) = current else {
        return Ok(NameOwnershipStatus::NoCurrentOwner);
    };
    let Some(owner) = current.owner.as_ref() else {
        return Ok(NameOwnershipStatus::NoCurrentOwner);
    };
    let owner_derivation = wallet_name_derivation(&owner.output.address, wallet_name_addresses);
    if current.state.transfer.get() == 0 {
        return Ok(
            owner_derivation.map_or(NameOwnershipStatus::NotWalletOwned, |derivation| {
                NameOwnershipStatus::WalletOwned { derivation }
            }),
        );
    }
    let transfer = TransferCovenant::try_from(&owner.output.covenant)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let recipient = WalletAddressKey {
        version: transfer.recipient_version,
        hash: transfer.recipient_hash,
    };
    let recipient_derivation = wallet_name_addresses
        .iter()
        .find(|candidate| recipient.version == 0 && candidate.program == recipient.hash)
        .map(|candidate| candidate.derivation);
    match (owner_derivation, recipient_derivation) {
        (Some(owner_derivation), _) => Ok(NameOwnershipStatus::OutgoingTransfer {
            owner_derivation,
            recipient,
        }),
        (None, Some(recipient_derivation)) => Ok(NameOwnershipStatus::IncomingTransfer {
            recipient_derivation,
            current_owner: WalletAddressKey {
                version: owner.output.address.version,
                hash: owner.output.address.hash.clone(),
            },
        }),
        (None, None) => Ok(NameOwnershipStatus::NotWalletOwned),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsRuntimeConfig {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    /// Stable HD account component. It is deliberately independent of the
    /// random wallet-local `AccountId` and must be backed up with the profile.
    pub account_derivation_index: u32,
    pub network: HnsNetwork,
    pub birthday_height: u64,
    pub restore_lookahead: u32,
    pub minimum_confirmations: u32,
    pub dust_threshold: BaseUnits,
    /// This is an application release-policy switch, not a test-network check.
    pub value_operations_enabled: bool,
    pub settlement_enabled: bool,
}

impl HnsRuntimeConfig {
    /// Builds the fixed, non-value account configuration used by native
    /// create/restore bootstrap. Network and restore birthday are explicit;
    /// all other policy remains at conservative wallet defaults.
    pub fn default_non_value(
        wallet_id: WalletId,
        account_id: AccountId,
        policy: HnsBootstrapPolicy,
    ) -> Result<Self, HnsWalletError> {
        let config = Self {
            wallet_id,
            account_id,
            account_derivation_index: 0,
            network: policy.network,
            birthday_height: policy.birthday_height,
            restore_lookahead: DEFAULT_RESTORE_LOOKAHEAD,
            minimum_confirmations: 2,
            dust_threshold: BaseUnits::new(DEFAULT_DUST_THRESHOLD),
            value_operations_enabled: false,
            settlement_enabled: false,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate inert account identity and bounded scan policy only.
    ///
    /// This deliberately does not validate value-release authority. It exists
    /// so an explicitly recovery-only reader can preserve and authenticate
    /// historical persisted flags without interpreting them as capability.
    /// Calling it does not authorize opening the full runtime, signing,
    /// broadcasting, settlement, provider use, or any value mutation.
    pub fn validate_structure(&self) -> Result<(), HnsWalletError> {
        if self.account_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(HnsWalletError::InvalidRuntimeConfiguration);
        }
        if self.restore_lookahead == 0
            || self.restore_lookahead > MAX_RESTORE_LOOKAHEAD
            || self.restore_lookahead as usize * 2 > MAX_RESTORE_SCRIPTS_PER_QUERY
        {
            return Err(HnsWalletError::InvalidLookahead);
        }
        if self.minimum_confirmations == 0 || self.dust_threshold.is_zero() {
            return Err(HnsWalletError::InvalidRuntimeConfiguration);
        }
        Ok(())
    }

    /// Validate both inert configuration and currently available runtime
    /// authority. Every ordinary and full runtime constructor uses this path.
    pub fn validate(&self) -> Result<(), HnsWalletError> {
        self.validate_structure()?;
        if (self.value_operations_enabled || self.settlement_enabled)
            && (!HNS_VALUE_RUNTIME_RELEASE_QUALIFIED || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED)
        {
            return Err(if self.network == HnsNetwork::Mainnet {
                HnsWalletError::MainnetDisabled
            } else {
                HnsWalletError::RuntimeIntegrationUnavailable
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsAccountRecord {
    pub config: HnsRuntimeConfig,
    pub next_receive_index: u32,
    pub next_change_index: u32,
    /// Next dedicated name-key derivation. This is restoration metadata only;
    /// it does not establish ownership without canonical NameState evidence.
    #[serde(default)]
    pub next_name_index: u32,
    /// Next separated Shakedex seller-key derivation. The protected allocation
    /// high-water remains authoritative and reconciliation may only advance
    /// this restoration projection.
    #[serde(default)]
    pub next_shakedex_index: u32,
    pub external_scan_end: u32,
    pub internal_scan_end: u32,
    /// Inclusive end of the independent `HnsName`, change-zero scan branch.
    #[serde(default)]
    pub name_scan_end: u32,
    /// Inclusive end of the independent `HnsShakedex`, change-zero scan branch.
    #[serde(default)]
    pub shakedex_scan_end: u32,
    /// True only after a complete bounded Shakedex branch scan has committed.
    /// Missing legacy state fails closed until the first successful scan.
    #[serde(default)]
    pub shakedex_scan_complete: bool,
    /// Durable cross-runtime fence set before Shakedex address discovery and
    /// cleared only by the same revision line after a complete scan commits.
    #[serde(default)]
    pub shakedex_scan_in_progress: bool,
    pub last_used_external: Option<u32>,
    pub last_used_internal: Option<u32>,
    #[serde(default)]
    pub last_used_name: Option<u32>,
    #[serde(default)]
    pub last_used_shakedex: Option<u32>,
}

impl HnsAccountRecord {
    /// Constructs an empty account projection for a configuration whose value
    /// and settlement paths are both disabled. No backend or node is touched.
    pub fn initial_non_value(config: HnsRuntimeConfig) -> Result<Self, HnsWalletError> {
        config.validate()?;
        if config.value_operations_enabled || config.settlement_enabled {
            return Err(HnsWalletError::RuntimeIntegrationUnavailable);
        }
        let scan_end = config
            .restore_lookahead
            .checked_sub(1)
            .ok_or(HnsWalletError::InvalidLookahead)?;
        Ok(Self {
            config,
            next_receive_index: 0,
            next_change_index: 0,
            next_name_index: 0,
            next_shakedex_index: 0,
            external_scan_end: scan_end,
            internal_scan_end: scan_end,
            name_scan_end: scan_end,
            shakedex_scan_end: scan_end,
            shakedex_scan_complete: false,
            shakedex_scan_in_progress: false,
            last_used_external: None,
            last_used_internal: None,
            last_used_name: None,
            last_used_shakedex: None,
        })
    }
}

/// Prepared seed plus one exact HNS account for native create or restore.
///
/// The mnemonic remains in a zeroizing BIP-39 value and is omitted from
/// `Debug`. Persistence encrypts the 64-byte recovery seed and the initial
/// account record in one store transaction. This type performs no node I/O and
/// cannot enable value or settlement operations.
pub struct HnsWalletBootstrap {
    mnemonic: Mnemonic,
    wallet_id: WalletId,
    account: HnsAccountRecord,
}

impl HnsWalletBootstrap {
    /// Generates a new 24-word English mnemonic and a random wallet ID.
    pub fn generate(policy: HnsBootstrapPolicy) -> Result<Self, HnsWalletError> {
        let mnemonic = generate_24_word_mnemonic()?;
        let wallet_id = generate_wallet_id()?;
        Self::from_mnemonic(mnemonic, wallet_id, policy)
    }

    /// Parses exactly 24 normalized English BIP-39 words and derives the
    /// recovery wallet ID using the existing `hns-wallet-id/v1` rule.
    pub fn restore(phrase: &str, policy: HnsBootstrapPolicy) -> Result<Self, HnsWalletError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|_| HnsWalletError::InvalidRecoveryPhrase)?;
        if mnemonic.word_count() != 24 {
            return Err(HnsWalletError::InvalidRecoveryPhrase);
        }
        let wallet_id = wallet_id_from_mnemonic(&mnemonic);
        Self::from_mnemonic(mnemonic, wallet_id, policy)
    }

    fn from_mnemonic(
        mnemonic: Mnemonic,
        wallet_id: WalletId,
        policy: HnsBootstrapPolicy,
    ) -> Result<Self, HnsWalletError> {
        let account_id = generate_account_id()?;
        let config = HnsRuntimeConfig::default_non_value(wallet_id, account_id, policy)?;
        let account = HnsAccountRecord::initial_non_value(config)?;
        Ok(Self {
            mnemonic,
            wallet_id,
            account,
        })
    }

    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub fn account_record(&self) -> &HnsAccountRecord {
        &self.account
    }

    /// Atomically writes the immutable seed and initial account. The store
    /// requires both relevant namespaces to be empty, so replaying bootstrap
    /// or encountering seed-only/account-only state fails closed.
    pub fn persist(&self, store: &mut WalletStore, now_unix: u64) -> Result<u64, StoreError> {
        let seed = Zeroizing::new(self.mnemonic.to_seed_normalized(""));
        store.initialize_recovery_seed_and_wallet_account(
            self.wallet_id.as_bytes(),
            seed.as_slice(),
            &account_entity_id(&self.account.config),
            &self.account,
            now_unix,
        )
    }

    /// Converts the mnemonic into the dedicated high-risk display wrapper.
    /// Call this only after durable persistence succeeds.
    pub fn into_recovery_phrase(self) -> RecoveryPhrase {
        RecoveryPhrase(self.mnemonic.to_string())
    }
}

impl fmt::Debug for HnsWalletBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsWalletBootstrap")
            .field("mnemonic", &"[REDACTED]")
            .field("wallet_id", &self.wallet_id)
            .field("account", &self.account)
            .finish()
    }
}

/// Internal validation purpose carried through exact selection and every
/// synchronized-read persistence fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HnsAccountReadMode {
    OrdinaryNonValue,
    PersistedRecoveryReadOnly,
    /// Structure-only selection for a private native lifecycle controller.
    /// This mode can authenticate an account whose persisted release flags are
    /// enabled, but it is rejected by every synchronized-read constructor and
    /// therefore cannot become node, signing, or settlement authority.
    LifecycleStructural,
}

impl HnsAccountReadMode {
    fn validate_config(self, config: &HnsRuntimeConfig) -> Result<(), HnsWalletError> {
        match self {
            Self::OrdinaryNonValue => {
                config.validate()?;
                if config.value_operations_enabled || config.settlement_enabled {
                    return Err(HnsWalletError::RuntimeIntegrationUnavailable);
                }
            }
            Self::PersistedRecoveryReadOnly => {
                config.validate_structure()?;
                if !config.value_operations_enabled && !config.settlement_enabled {
                    return Err(HnsWalletError::InvalidRuntimeConfiguration);
                }
            }
            Self::LifecycleStructural => config.validate_structure()?,
        }
        Ok(())
    }
}

/// Read-only selector for one exact pre-existing HNS account held by the same
/// Arc-backed store/key authority as its caller.
///
/// Selection reads authenticated account records only. It never creates an
/// account, rewrites runtime configuration, contacts a node, restores cached
/// chain authority, signs, or enables a value path.
#[derive(Clone)]
pub struct HnsExistingAccountSelector {
    store: SharedWalletStore,
    expected: HnsRuntimeConfig,
    mode: HnsAccountReadMode,
}

/// Exact authenticated account row and its monotonic entity revision.
///
/// The revision is local wallet evidence only: it proves neither chain state
/// nor a broker lease. Native compositions can join it to their independently
/// held authority and re-read it around dependent use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedHnsAccountRevision {
    pub account: HnsAccountRecord,
    pub revision: u64,
}

impl HnsExistingAccountSelector {
    pub fn new(
        store: SharedWalletStore,
        expected: HnsRuntimeConfig,
    ) -> Result<Self, HnsWalletError> {
        Self::new_with_mode(store, expected, HnsAccountReadMode::OrdinaryNonValue)
    }

    /// Select one exact account for private native create/open/lock lifecycle
    /// control without interpreting persisted value flags as authority.
    ///
    /// The resulting selector can be used by the account-only service runtime,
    /// but synchronized read and full value constructors independently reject
    /// it. This lets an installed wallet remain reopenable while its product-
    /// owned node is unavailable or a release gate is temporarily closed.
    pub fn new_lifecycle(
        store: SharedWalletStore,
        expected: HnsRuntimeConfig,
    ) -> Result<Self, HnsWalletError> {
        Self::new_with_mode(store, expected, HnsAccountReadMode::LifecycleStructural)
    }

    fn new_with_mode(
        store: SharedWalletStore,
        expected: HnsRuntimeConfig,
        mode: HnsAccountReadMode,
    ) -> Result<Self, HnsWalletError> {
        mode.validate_config(&expected)?;
        Ok(Self {
            store,
            expected,
            mode,
        })
    }

    pub fn expected_record_id(&self) -> [u8; 32] {
        account_entity_id(&self.expected)
    }

    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.store.is_same_authority(store)
    }

    const fn mode(&self) -> HnsAccountReadMode {
        self.mode
    }

    /// Re-read and authenticate the selected account on every call. This makes
    /// a restarted service fail closed if product configuration selects a
    /// different account than a persisted provider permission.
    pub fn selected_account(&self) -> Result<HnsAccountRecord, HnsWalletError> {
        Ok(self.selected_account_with_revision()?.account)
    }

    /// Re-read the same exact account selection while retaining the
    /// authenticated entity revision for a native authority-context join.
    pub fn selected_account_with_revision(
        &self,
    ) -> Result<SelectedHnsAccountRevision, HnsWalletError> {
        let expected_id = account_entity_id(&self.expected);
        let (accounts, selected) = self
            .store
            .with_store(|store| {
                if store.is_locked() {
                    return Err(StoreError::Locked);
                }
                Ok((
                    store.list_entities_by_id_prefix::<HnsAccountRecord>(
                        EntityKind::WalletAccount,
                        self.expected.wallet_id.as_bytes(),
                        MAX_HISTORY_RESULTS,
                    )?,
                    store.wallet_account::<HnsAccountRecord>(&expected_id)?,
                ))
            })
            .map_err(|error| match error {
                StoreError::Locked => HnsWalletError::StoreLocked,
                error => HnsWalletError::from(error),
            })?;
        for stored in accounts {
            if stored.id != account_entity_id(&stored.value.config)
                || stored.value.config.wallet_id != self.expected.wallet_id
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            if stored.value.config.account_id != self.expected.account_id
                && stored.value.config.account_derivation_index
                    == self.expected.account_derivation_index
            {
                return Err(HnsWalletError::DuplicateAccountDerivation);
            }
        }
        let selected = selected.ok_or(HnsWalletError::AccountConfigurationMismatch)?;
        if selected.id != expected_id
            || selected.value.config != self.expected
            || selected.revision == 0
        {
            return Err(HnsWalletError::AccountConfigurationMismatch);
        }
        Ok(SelectedHnsAccountRevision {
            account: selected.value,
            revision: selected.revision,
        })
    }
}

/// Exact confirmed-chain and mempool authority for one synchronized account
/// read. The trusted service composition retains this binding internally to
/// prevent mixed-snapshot projections; website/provider JSON must not receive
/// node identity, epoch, tip, or mempool-generation details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsAccountReadBinding {
    pub chain: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
}

/// Complete non-value HNS account projection produced by one bounded wallet
/// reconciliation. All fields are derived from the same chain/mempool binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsAccountReadSnapshot {
    pub account_id: AccountId,
    pub binding: HnsAccountReadBinding,
    pub balance: Amount,
    pub transactions: Vec<TransactionSummary>,
    pub receive_target: ReceiveTarget,
    /// Dedicated change-zero `HnsName` destination at the synchronized
    /// account's exact `next_name_index`. This is not an ordinary HNS payment
    /// address and does not enable a name or value mutation.
    pub name_receive_target: HnsNameReceiveTarget,
    pub known_names: Vec<KnownName>,
}

/// Query-scoped selected-account, network, and trusted-time authority for one
/// Denuo board metadata read or negative cancellation admission.
///
/// This object is deliberately non-cloneable and non-serializable. It proves
/// no current chain state, name ownership, locking coin, publication, signing,
/// or value authority. A related read must consume it through
/// `revalidate_unchanged_account` inside the same entity snapshot. A related
/// write must additionally consume its prefix lease as a guard in the same
/// immediate transaction as that write.
pub struct VerifiedHnsBoardCancellationContext {
    account_id: [u8; 32],
    account: HnsAccountRecord,
    account_revision: u64,
    account_prefix_lease: EntityPrefixSetLease,
    network: NetworkBinding,
    observed_at_unix: u64,
}

fn validate_hns_board_account_snapshot(
    snapshot: &EntityReadSnapshot<'_>,
    account_id: &[u8; 32],
    expected_account: &HnsAccountRecord,
) -> Result<u64, HnsWalletError> {
    let accounts = snapshot.list_entities_by_id_prefix::<HnsAccountRecord>(
        EntityKind::WalletAccount,
        expected_account.config.wallet_id.as_bytes(),
        MAX_HISTORY_RESULTS,
    )?;
    let mut selected_revision = None;
    for stored in accounts {
        if stored.id != account_entity_id(&stored.value.config)
            || stored.value.config.wallet_id != expected_account.config.wallet_id
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        if stored.value.config.account_id != expected_account.config.account_id
            && stored.value.config.account_derivation_index
                == expected_account.config.account_derivation_index
        {
            return Err(HnsWalletError::DuplicateAccountDerivation);
        }
        if stored.id.as_slice() == account_id.as_slice()
            && (stored.value != *expected_account
                || selected_revision.replace(stored.revision).is_some())
        {
            return Err(HnsWalletError::StaleAccountRead);
        }
    }
    selected_revision.ok_or(HnsWalletError::StaleAccountRead)
}

fn capture_hns_board_account_snapshot(
    snapshot: &EntityReadSnapshot<'_>,
    account_id: &[u8; 32],
    expected_account: &HnsAccountRecord,
) -> Result<(u64, EntityPrefixSetLease), HnsWalletError> {
    let revision = validate_hns_board_account_snapshot(snapshot, account_id, expected_account)?;
    let lease = snapshot.entity_prefix_set_lease(
        EntityKind::WalletAccount,
        expected_account.config.wallet_id.as_bytes(),
        MAX_HISTORY_RESULTS,
    )?;
    Ok((revision, lease))
}

impl VerifiedHnsBoardCancellationContext {
    pub const fn network(&self) -> NetworkBinding {
        self.network
    }

    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    /// Consume and revalidate the exact encrypted account prefix set inside a
    /// caller-owned coherent entity snapshot. The refreshed context remains
    /// usable as a read authority or can be consumed as an atomic write guard.
    pub fn revalidate_unchanged_account(
        mut self,
        snapshot: &EntityReadSnapshot<'_>,
    ) -> Result<Self, HnsWalletError> {
        let revision =
            validate_hns_board_account_snapshot(snapshot, &self.account_id, &self.account)?;
        if revision != self.account_revision {
            return Err(HnsWalletError::StaleAccountRead);
        }
        self.account_prefix_lease = snapshot
            .refresh_entity_prefix_set_lease(self.account_prefix_lease)
            .map_err(|error| match error {
                StoreError::StaleEntitySet => HnsWalletError::StaleAccountRead,
                _ => HnsWalletError::from(error),
            })?;
        Ok(self)
    }

    /// Consume this read authority into the ABA-resistant account-set lease
    /// used to guard a related entity batch in the same immediate transaction.
    pub fn into_account_prefix_lease(self) -> EntityPrefixSetLease {
        self.account_prefix_lease
    }

    /// Perform a coherent read-only recheck of the exact selected account row
    /// and revision. This method returns no write guard and is not an atomic
    /// precondition for a later mutation on an independent connection. Writes
    /// must instead consume `revalidate_unchanged_account` and
    /// `into_account_prefix_lease`. The enclosing runtime must separately
    /// require the identical `SharedWalletStore` Arc.
    pub fn verify_unchanged_account(&self, store: &WalletStore) -> Result<(), HnsWalletError> {
        if store.is_locked() {
            return Err(HnsWalletError::StoreLocked);
        }
        store.try_with_entity_read_snapshot(|snapshot| {
            let revision =
                validate_hns_board_account_snapshot(snapshot, &self.account_id, &self.account)?;
            if revision != self.account_revision {
                return Err(HnsWalletError::StaleAccountRead);
            }
            Ok(())
        })
    }
}

impl fmt::Debug for VerifiedHnsBoardCancellationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHnsBoardCancellationContext")
            .field("account", &"[EXACT ACCOUNT FENCE]")
            .field("account_revision", &self.account_revision)
            .field("network", &self.network)
            .field("observed_at_unix", &self.observed_at_unix)
            .finish_non_exhaustive()
    }
}

/// Generalized name for the purpose-minimized account/network/time context
/// shared by closed Denuo board metadata reads and cancellation admission.
pub type VerifiedHnsBoardContext = VerifiedHnsBoardCancellationContext;

/// Synchronized, non-value HNS runtime for product/provider compositions that
/// already own an exact account and one process-local store authority.
///
/// Local encrypted state is staged under short `SharedWalletStore` closures,
/// every node call runs after the closure has returned, and the result commits
/// only after an exact account/entity revision fence is re-authenticated. This
/// type exposes no signing, broadcasting, value, allocation, or settlement
/// method and does not alter either HNS value release gate. Its only mutation
/// outside synchronization is a trusted-native exact-text name import which
/// atomically persists canonical evidence and rotates restoration metadata.
/// Before deriving or
/// transmitting any wallet script identifiers, synchronization obtains a
/// script-free chain binding and binds height-zero evidence to the selected
/// account network.
pub struct HnsAccountReadRuntime<B, C = SystemClock> {
    backend: B,
    clock: C,
    store: SharedWalletStore,
    selector: HnsExistingAccountSelector,
    synchronization: Mutex<()>,
}

impl<B: HnsBackend, C: HnsClock> HnsAccountReadRuntime<B, C> {
    pub fn new(
        backend: B,
        clock: C,
        store: SharedWalletStore,
        selector: HnsExistingAccountSelector,
    ) -> Result<Self, HnsWalletError> {
        if selector.mode() != HnsAccountReadMode::OrdinaryNonValue {
            return Err(HnsWalletError::RuntimeIntegrationUnavailable);
        }
        Self::new_with_selector(backend, clock, store, selector)
    }

    fn new_with_selector(
        backend: B,
        clock: C,
        store: SharedWalletStore,
        selector: HnsExistingAccountSelector,
    ) -> Result<Self, HnsWalletError> {
        if !selector.shares_store_authority(&store) {
            return Err(HnsWalletError::StoreAuthorityMismatch);
        }
        Ok(Self {
            backend,
            clock,
            store,
            selector,
            synchronization: Mutex::new(()),
        })
    }

    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.store.is_same_authority(store) && self.selector.shares_store_authority(store)
    }

    pub fn selected_account(&self) -> Result<HnsAccountRecord, HnsWalletError> {
        self.selector.selected_account()
    }

    /// Return the exact authenticated account row and its monotonic entity
    /// revision without contacting the node.
    pub fn selected_account_with_revision(
        &self,
    ) -> Result<SelectedHnsAccountRevision, HnsWalletError> {
        self.selector.selected_account_with_revision()
    }

    /// Return the configured account network without consulting caller input.
    pub const fn configured_network(&self) -> HnsNetwork {
        self.selector.expected.network
    }

    /// Import one canonical Handshake name from exact native text.
    ///
    /// The input is never trimmed, lowercased, IDNA-converted, normalized, or
    /// split on dots. Invalid text is rejected before any backend method is
    /// called. Wallet ownership is established only from fresh canonical name
    /// evidence and an exact persisted `HnsName` change-zero derivation. The
    /// account derivation high-water and name row commit in one store batch.
    pub fn import_name_exact_text(&self, name: &str) -> Result<KnownName, HnsWalletError> {
        self.import_name_exact_text_bounded(name, MAX_HISTORY_RESULTS)
    }

    /// Exact-text import with a caller-owned persisted-name result bound.
    /// Existing names remain re-importable at the bound; a new row is rejected
    /// before node I/O. Native service/mobile projections use this so a
    /// successful mutation can never become undisplayable afterward.
    pub fn import_name_exact_text_bounded(
        &self,
        name: &str,
        maximum_persisted_names: usize,
    ) -> Result<KnownName, HnsWalletError> {
        let name_bytes = name.as_bytes();
        if !validate_name(name_bytes) {
            return Err(HnsWalletError::InvalidName);
        }
        let name_hash = hash_name(name_bytes)
            .map_err(|_| HnsWalletError::InvalidName)?
            .into_bytes();
        if maximum_persisted_names == 0 || maximum_persisted_names > MAX_HISTORY_RESULTS {
            return Err(HnsWalletError::HistoryLimit);
        }

        let _synchronization = self
            .synchronization
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)?;
        let selected = self.selector.selected_account()?;
        let preparation = self.store.try_with_store(|store| {
            prepare_hns_name_import(store, &selected, name_hash, maximum_persisted_names)
        })?;
        if preparation
            .existing_name
            .as_ref()
            .is_some_and(|stored| stored.value.name.as_slice() != name_bytes)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }

        let binding = self.backend.get_chain_snapshot()?;
        verify_hns_read_chain_identity(&self.backend, selected.config.network, binding)?;
        // Preserve the script-free snapshot/genesis ordering: derive wallet
        // identifiers only after network identity is authenticated, under a
        // second exact account/name fence which returns before node evidence.
        let name_addresses = self
            .store
            .try_with_store(|store| derive_hns_name_import_addresses(store, &preparation))?;
        let imported =
            validated_name_evidence(&self.backend, name_bytes, binding, Some(&name_addresses))?
                .known_name;
        let now_unix = self.clock.now_unix()?;
        if self.selector.selected_account()? != preparation.account.value {
            return Err(HnsWalletError::StaleAccountRead);
        }
        if self.backend.get_chain_snapshot()? != binding {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        self.store.try_with_store_mut(|store| {
            commit_hns_name_import(store, &preparation, &name_addresses, &imported, now_unix)
        })?;
        Ok(imported)
    }

    /// Observe the exact selected account, its Shakedex network binding, and
    /// trusted wall time for one Denuo board metadata operation.
    /// Selected account state is fenced on both sides of the clock call and no
    /// backend or node method is invoked.
    pub fn observe_board_context(&self) -> Result<VerifiedHnsBoardContext, HnsWalletError> {
        let _synchronization = self
            .synchronization
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)?;
        let selected = self.selector.selected_account()?;
        let account_id = account_entity_id(&selected.config);
        let (account_revision, account_prefix_lease) = self.store.try_with_store(|store| {
            if store.is_locked() {
                return Err(HnsWalletError::StoreLocked);
            }
            store.try_with_entity_read_snapshot(|snapshot| {
                capture_hns_board_account_snapshot(snapshot, &account_id, &selected)
            })
        })?;
        let observed_at_unix = self.clock.now_unix()?;
        let selected_after_clock = self.selector.selected_account()?;
        if selected_after_clock != selected {
            return Err(HnsWalletError::StaleAccountRead);
        }
        let context = VerifiedHnsBoardCancellationContext {
            account_id,
            account: selected,
            account_revision,
            account_prefix_lease,
            network: shakedex_network_binding(selected_after_clock.config.network)?,
            observed_at_unix,
        };
        self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                context.revalidate_unchanged_account(snapshot)
            })
        })
    }

    /// Observe the purpose-minimized context used by negative Denuo board
    /// cancellation admission. This preserves the established cancellation
    /// API while sharing the exact account/network/time fencing implementation
    /// with closed board metadata reads.
    pub fn observe_board_cancellation_context(
        &self,
    ) -> Result<VerifiedHnsBoardCancellationContext, HnsWalletError> {
        self.observe_board_context()
    }

    /// Reconcile every currently supported non-value account projection once.
    /// Stale snapshots are surfaced to the caller; this layer never polls.
    pub fn synchronize(&self) -> Result<HnsAccountReadSnapshot, HnsWalletError> {
        let _synchronization = self
            .synchronization
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)?;
        let now_unix = self.clock.now_unix()?;
        let selected = self.selector.selected_account()?;
        let preparation = self
            .store
            .with_store_mut(|store| {
                Ok(prepare_hns_account_read(
                    store,
                    &selected,
                    self.selector.mode(),
                    now_unix,
                ))
            })
            .map_err(map_shared_store_error)??;
        let binding = self.backend.get_chain_snapshot()?;
        verify_hns_read_chain_identity(
            &self.backend,
            preparation.fenced_account.config.network,
            binding,
        )?;
        // Script derivation and every wallet-index query remain after the
        // script-free binding has been authenticated against the account's
        // selected network.
        let scan = scan_hns_account_read(&self.backend, &self.store, &preparation, binding)?;
        let tip = binding.tip;
        let selected_after_scan = self.selector.selected_account()?;
        if selected_after_scan != preparation.fenced_account {
            return Err(HnsWalletError::StaleAccountRead);
        }

        let common_ancestor = hns_read_common_ancestor(
            &self.backend,
            &preparation.recovery,
            scan.binding,
            preparation.fenced_account.config.birthday_height,
        )?;
        let previous_transactions = preparation
            .transactions
            .iter()
            .map(|stored| stored.value.clone())
            .collect::<Vec<_>>();
        let transactions = reconcile_hns_read_transactions(
            &self.backend,
            &scan.history,
            &scan.addresses,
            scan.binding,
            scan.mempool,
            common_ancestor,
            &previous_transactions,
        )?;
        let coins = reconcile_coins(scan.indexed_coins, &scan.addresses, tip.height)?;
        let names = reconcile_hns_read_names(
            &self.backend,
            &preparation.names,
            &scan.addresses,
            &coins,
            scan.binding,
        )?;
        let balance = coins.iter().try_fold(BaseUnits::ZERO, |total, coin| {
            if is_ordinary_hns_spend_candidate(coin) {
                total
                    .checked_add(coin.coin.value)
                    .map_err(|_| HnsWalletError::Arithmetic)
            } else {
                Ok(total)
            }
        })?;
        let receive_target = hns_read_receive_target(&scan.account, &scan.addresses)?;
        let name_receive_target = hns_read_name_receive_target(&scan.account, &scan.addresses)?;
        let checkpoints = hns_read_checkpoints(
            &self.backend,
            scan.binding,
            scan.account.config.birthday_height,
        )?;
        let recovery = HnsRecoveryState {
            checkpoints,
            last_tip: Some(tip),
            last_common_ancestor: common_ancestor,
            last_reconciled_unix: now_unix,
        };
        verify_hns_read_snapshot_current(
            &self.backend,
            &scan.branch_scripts,
            scan.binding,
            scan.mempool,
        )?;
        self.store
            .with_store_mut(|store| {
                Ok(commit_hns_account_read(
                    store,
                    &preparation,
                    &scan.account,
                    &scan.addresses,
                    &coins,
                    &transactions,
                    &names,
                    &recovery,
                    now_unix,
                ))
            })
            .map_err(map_shared_store_error)??;
        if self.selector.selected_account()? != scan.account {
            return Err(HnsWalletError::StaleAccountRead);
        }

        Ok(HnsAccountReadSnapshot {
            account_id: scan.account.config.account_id,
            binding: HnsAccountReadBinding {
                chain: scan.binding,
                mempool: scan.mempool,
            },
            balance: Amount {
                asset: WalletAsset::Hns,
                base_units: balance,
            },
            transactions: transactions
                .into_iter()
                .map(|transaction| transaction.summary)
                .collect(),
            receive_target,
            name_receive_target,
            known_names: names,
        })
    }
}

/// Explicit recovery-only reader for one exact already-persisted HNS account
/// whose historical configuration contains a value or settlement flag.
///
/// The flags remain authenticated identity facts. They are never converted to
/// a permit or capability, and missing or non-exact persisted state fails on
/// selection. This wrapper exposes only exact selection and synchronized read
/// projection; its inner runtime is private, so current Shakedex-lock, Denuo,
/// signing, import/export, workflow, broadcast, and value APIs are unreachable.
/// Synchronization may update WalletAccount scan/index metadata (never its
/// configuration), create or replace derived-address, coin, transaction, name,
/// and recovery-cache rows, and write or clear the durable discovery fence. It
/// cannot create an account, profile, allocation, signer, workflow, or value
/// authority or alter the selected account configuration. Every such cache row
/// is bounded, authenticated, and scoped to that exact existing account.
///
/// ```compile_fail
/// # use hns_wallet_hns::{HnsBackend, HnsClock, HnsPersistedRecoveryReadOnlyRuntime};
/// # fn no_market_authority<B: HnsBackend, C: HnsClock>(
/// #     runtime: &HnsPersistedRecoveryReadOnlyRuntime<B, C>,
/// # ) {
/// let _ = runtime.verify_current_shakedex_lock(b"name", [2_u8; 33]);
/// # }
/// ```
pub struct HnsPersistedRecoveryReadOnlyRuntime<B, C = SystemClock> {
    inner: HnsAccountReadRuntime<B, C>,
}

impl<B: HnsBackend, C: HnsClock> HnsPersistedRecoveryReadOnlyRuntime<B, C> {
    /// Select an exact existing flagged account for recovery reads. Construction
    /// validates structure only and never writes; later selection requires the
    /// complete persisted configuration to match byte-for-byte.
    pub fn new(
        backend: B,
        clock: C,
        store: SharedWalletStore,
        expected: HnsRuntimeConfig,
    ) -> Result<Self, HnsWalletError> {
        let selector = HnsExistingAccountSelector::new_with_mode(
            store.clone(),
            expected,
            HnsAccountReadMode::PersistedRecoveryReadOnly,
        )?;
        Ok(Self {
            inner: HnsAccountReadRuntime::new_with_selector(backend, clock, store, selector)?,
        })
    }

    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.inner.shares_store_authority(store)
    }

    pub fn selected_account(&self) -> Result<HnsAccountRecord, HnsWalletError> {
        self.inner.selected_account()
    }

    pub fn synchronize(&self) -> Result<HnsAccountReadSnapshot, HnsWalletError> {
        self.inner.synchronize()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivedHnsAddress {
    pub account_id: AccountId,
    pub derivation: DerivationReference,
    pub address: String,
    pub program: Vec<u8>,
    pub used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedHnsCoin {
    pub coin: WalletCoin,
    pub derivation: DerivationReference,
    pub address_program: Vec<u8>,
}

impl TrackedHnsCoin {
    /// Reconstruct the exact consensus coin used by script and fee policy.
    /// Legacy rows and any mismatch between projected and canonical evidence
    /// are deliberately unusable until a fresh bound reconciliation replaces
    /// them.
    pub fn to_canonical_coin(&self) -> Result<Coin, HnsWalletError> {
        if self.coin.confirmation_count == 0
            || validate_restore_program(self.derivation, &self.address_program).is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let covenant = decode_canonical_covenant(&self.coin.covenant)?;
        if self.coin.name_locked != !matches!(covenant.kind, CovenantKind::None) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        if self.coin.value.is_zero()
            && (self.derivation.role != KeyRole::HnsName
                || !is_active_name_owner_covenant(covenant.kind))
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        canonical_coin_from_evidence(
            self.coin.outpoint,
            self.coin.value,
            self.coin.confirmed_height,
            self.coin.coinbase,
            0,
            self.address_program.clone(),
            covenant,
        )
    }

    fn to_input_evidence(&self) -> Result<HnsInputCoinEvidence, HnsWalletError> {
        let canonical = self.to_canonical_coin()?;
        HnsInputCoinEvidence::from_canonical_coin(&canonical)
    }
}

/// Serializable, exact input-coin evidence retained beside signed workflows.
/// It carries all fields required by canonical script sigop and fee policy so
/// restart/rebroadcast validation never falls back to a node assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsInputCoinEvidence {
    pub outpoint: HnsOutpoint,
    pub value: BaseUnits,
    #[serde(default)]
    pub confirmed_height: Option<u32>,
    pub coinbase: bool,
    pub address_version: u8,
    pub address_hash: Vec<u8>,
    #[serde(default)]
    pub covenant: Vec<u8>,
}

impl HnsInputCoinEvidence {
    pub fn to_canonical_coin(&self) -> Result<Coin, HnsWalletError> {
        let covenant = decode_canonical_covenant(&self.covenant)?;
        if self.value.is_zero() && !is_active_name_owner_covenant(covenant.kind) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        canonical_coin_from_evidence(
            self.outpoint,
            self.value,
            self.confirmed_height,
            self.coinbase,
            self.address_version,
            self.address_hash.clone(),
            covenant,
        )
    }

    fn from_canonical_coin(coin: &Coin) -> Result<Self, HnsWalletError> {
        if coin.outpoint.is_null() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let covenant = coin
            .covenant
            .encode()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        Ok(Self {
            outpoint: HnsOutpoint {
                transaction: TransactionHash::new(coin.outpoint.transaction_hash.into_bytes()),
                output_index: coin.outpoint.index,
            },
            value: BaseUnits::new(u128::from(coin.value.get())),
            confirmed_height: Some(coin.height.get()),
            coinbase: coin.coinbase,
            address_version: coin.address.version,
            address_hash: coin.address.hash.clone(),
            covenant,
        })
    }
}

const fn is_active_name_owner_covenant(kind: CovenantKind) -> bool {
    matches!(
        kind,
        CovenantKind::Claim
            | CovenantKind::Reveal
            | CovenantKind::Register
            | CovenantKind::Update
            | CovenantKind::Renew
            | CovenantKind::Transfer
            | CovenantKind::Finalize
    )
}

fn decode_canonical_covenant(encoded: &[u8]) -> Result<Covenant, HnsWalletError> {
    if encoded.is_empty() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let covenant = Covenant::decode(encoded).map_err(|_| HnsWalletError::InvalidEvidence)?;
    if covenant
        .encode()
        .map_err(|_| HnsWalletError::InvalidEvidence)?
        != encoded
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(covenant)
}

fn canonical_coin_from_evidence(
    outpoint: HnsOutpoint,
    value: BaseUnits,
    confirmed_height: Option<u32>,
    coinbase: bool,
    address_version: u8,
    address_hash: Vec<u8>,
    covenant: Covenant,
) -> Result<Coin, HnsWalletError> {
    let outpoint = Outpoint {
        transaction_hash: CanonicalTransactionHash::new(outpoint.transaction.into_bytes()),
        index: outpoint.output_index,
    };
    if outpoint.is_null() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let value = u64::try_from(value.get()).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let height = confirmed_height.ok_or(HnsWalletError::InvalidEvidence)?;
    let address =
        Address::new(address_version, address_hash).map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(Coin {
        outpoint,
        value: Dollarydoos::new(value),
        height: Height::new(height),
        coinbase,
        address,
        covenant,
    })
}

pub(crate) fn canonical_input_coins(
    inputs: &[TrackedHnsCoin],
) -> Result<Vec<Coin>, HnsWalletError> {
    if inputs.is_empty() || inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    inputs
        .iter()
        .map(TrackedHnsCoin::to_canonical_coin)
        .collect()
}

fn canonical_evidence_coins(inputs: &[HnsInputCoinEvidence]) -> Result<Vec<Coin>, HnsWalletError> {
    if inputs.is_empty() || inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    inputs
        .iter()
        .map(HnsInputCoinEvidence::to_canonical_coin)
        .collect()
}

fn input_coin_evidence(
    inputs: &[TrackedHnsCoin],
) -> Result<Vec<HnsInputCoinEvidence>, HnsWalletError> {
    if inputs.is_empty() || inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    inputs
        .iter()
        .map(TrackedHnsCoin::to_input_evidence)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsTransactionRecord {
    pub summary: TransactionSummary,
    pub raw: Vec<u8>,
    pub inclusion: Option<TransactionInclusion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsChainCheckpoint {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsRecoveryState {
    pub checkpoints: Vec<HnsChainCheckpoint>,
    pub last_tip: Option<ChainTip>,
    pub last_common_ancestor: Option<u64>,
    pub last_reconciled_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsReconciliationReport {
    pub tip: ChainTip,
    pub common_ancestor: Option<u64>,
    pub reorg_detected: bool,
    pub restored_utxos: usize,
    pub reconciled_transactions: usize,
    pub revalidated_names: usize,
    pub pending_user_actions: Vec<WorkflowId>,
}

pub trait HnsClock: Send + Sync {
    fn now_unix(&self) -> Result<u64, HnsWalletError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl HnsClock for SystemClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HnsWalletError::Clock)
            .map(|duration| duration.as_secs())
    }
}

#[derive(Clone, Debug)]
struct HnsRuntimeCache {
    account: HnsAccountRecord,
    account_revision: u64,
    sync: SyncStatus,
    coins: Vec<TrackedHnsCoin>,
    transactions: Vec<HnsTransactionRecord>,
    binding: Option<SnapshotBinding>,
    mempool_binding: Option<MempoolSnapshotBinding>,
}

struct HnsReadPreparation {
    fenced_account: HnsAccountRecord,
    scan_account: HnsAccountRecord,
    account_revision: u64,
    recovery: HnsRecoveryState,
    recovery_row: Option<StoredEntity<HnsRecoveryState>>,
    coins: Vec<StoredEntity<TrackedHnsCoin>>,
    transactions: Vec<StoredEntity<HnsTransactionRecord>>,
    names: Vec<StoredEntity<KnownName>>,
}

struct HnsNameImportPreparation {
    account: StoredEntity<HnsAccountRecord>,
    names: Vec<StoredEntity<KnownName>>,
    existing_name: Option<StoredEntity<KnownName>>,
}

struct HnsReadScan {
    account: HnsAccountRecord,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    addresses: Vec<DerivedHnsAddress>,
    history: Vec<HistoryEntry>,
    indexed_coins: Vec<IndexedWalletCoin>,
    branch_scripts: [Vec<WalletAddressKey>; 3],
}

type RestoreScanResult = (
    HnsAccountRecord,
    u64,
    SnapshotBinding,
    MempoolSnapshotBinding,
    Vec<DerivedHnsAddress>,
    Vec<HistoryEntry>,
    Vec<IndexedWalletCoin>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsSendStage {
    Prepared,
    Authorized,
    Broadcast,
    Mempool,
    Confirmed,
    Conflicted,
    RequiresRebroadcast,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HnsSpendPlan {
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    request_nonce: u64,
    unsigned_transaction: Vec<u8>,
    inputs: Vec<TrackedHnsCoin>,
    amount: BaseUnits,
    fee: BaseUnits,
    maximum_fee: BaseUnits,
    destination: String,
    expires_at_unix: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct HnsSendWorkflow {
    plan: HnsSpendPlan,
    stage: HnsSendStage,
    transaction: Option<TransactionHash>,
    signed_transaction: Option<Vec<u8>>,
    #[serde(default)]
    fee_quote: Option<HnsTransactionFeeQuote>,
}

impl fmt::Debug for HnsSendWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsSendWorkflow")
            .field("workflow_id", &self.plan.workflow_id)
            .field("stage", &self.stage)
            .field("transaction", &self.transaction)
            .field(
                "signed_transaction",
                &self.signed_transaction.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct HnsSendApproval {
    workflow_id: WorkflowId,
    commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsInputReservation {
    wallet_id: WalletId,
    account_id: AccountId,
    outpoint: HnsOutpoint,
    workflow_id: WorkflowId,
    expires_at_unix: Option<u64>,
    #[serde(default)]
    kind: HnsInputReservationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HnsSettlementAction {
    Lock,
    Redeem,
    Refund,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HnsSettlementStage {
    Prepared,
    Broadcast,
    Mempool,
    Confirmed,
    Conflicted,
    RequiresRebroadcast,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
enum HnsSettlementTerms {
    Lock { request: SettlementLockRequest },
    Redeem { lock: VerifiedLock },
    Refund { lock: VerifiedLock },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HnsVerifiedSettlementRecord {
    expected: SettlementLockExpectation,
    verified: VerifiedLock,
    output_index: u32,
    script: Vec<u8>,
    /// Exact confirmed funding output used for local script/fee policy. A
    /// missing legacy value cannot authorize a settlement spend.
    #[serde(default)]
    funding_coin: Option<HnsInputCoinEvidence>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct HnsPreparedSettlement {
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    session_id: SessionId,
    action: HnsSettlementAction,
    stage: HnsSettlementStage,
    transaction: TransactionHash,
    signed_transaction: Vec<u8>,
    /// Ordered one-for-one with the transaction inputs. Empty legacy evidence
    /// is retained only so decoding succeeds and validation can fail closed.
    #[serde(default)]
    input_coins: Vec<HnsInputCoinEvidence>,
    fee: BaseUnits,
    #[serde(default)]
    maximum_fee: BaseUnits,
    #[serde(default)]
    fee_quote: Option<HnsTransactionFeeQuote>,
    expires_at_unix: u64,
    terms: HnsSettlementTerms,
}

impl fmt::Debug for HnsPreparedSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsPreparedSettlement")
            .field("workflow_id", &self.workflow_id)
            .field("session_id", &self.session_id)
            .field("action", &self.action)
            .field("stage", &self.stage)
            .field("transaction", &self.transaction)
            .field("fee", &self.fee)
            .field("maximum_fee", &self.maximum_fee)
            .field("fee_quote", &self.fee_quote)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("terms", &self.terms)
            .field("signed_transaction", &"[REDACTED]")
            .finish()
    }
}

pub struct HnsWalletRuntime<B, C = SystemClock> {
    backend: B,
    clock: C,
    store: SharedWalletStore,
    cache: RwLock<HnsRuntimeCache>,
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    pub fn open(
        backend: B,
        store: WalletStore,
        config: HnsRuntimeConfig,
        clock: C,
    ) -> Result<Self, HnsWalletError> {
        Self::open_shared(backend, SharedWalletStore::new(store), config, clock)
    }

    /// Open the full HNS runtime over the exact Arc-backed store/key authority
    /// shared with provider, browser-service, and Denuo components.
    ///
    /// The supplied store must already be unlocked. Every clone observes the
    /// same lock transition, and [`Self::shares_store_authority`] lets the
    /// enclosing product reject a separately opened connection even when it
    /// names the same database path.
    pub fn open_shared(
        backend: B,
        store: SharedWalletStore,
        config: HnsRuntimeConfig,
        clock: C,
    ) -> Result<Self, HnsWalletError> {
        config.validate()?;
        if store.is_locked()? {
            return Err(HnsWalletError::StoreLocked);
        }
        let (account, account_revision, coins, transactions) =
            store.try_with_store_mut(|wallet| {
                for stored in wallet.list_entities_by_id_prefix::<HnsAccountRecord>(
                    EntityKind::WalletAccount,
                    config.wallet_id.as_bytes(),
                    MAX_HISTORY_RESULTS,
                )? {
                    if stored.id != account_entity_id(&stored.value.config)
                        || stored.value.config.wallet_id != config.wallet_id
                    {
                        return Err(HnsWalletError::InvalidEvidence);
                    }
                    if stored.value.config.account_id != config.account_id
                        && stored.value.config.account_derivation_index
                            == config.account_derivation_index
                    {
                        return Err(HnsWalletError::DuplicateAccountDerivation);
                    }
                }
                let existing: Option<StoredEntity<HnsAccountRecord>> =
                    wallet.wallet_account(&account_entity_id(&config))?;
                let (account, account_revision) = match existing {
                    Some(mut stored) => {
                        if !same_account_identity(&stored.value.config, &config) {
                            return Err(HnsWalletError::AccountConfigurationMismatch);
                        }
                        if stored.value.config != config {
                            stored.value.config = config;
                            stored.revision = wallet.save_wallet_account(
                                &account_entity_id(&stored.value.config),
                                stored.revision,
                                &stored.value,
                                clock.now_unix()?,
                            )?;
                        }
                        (stored.value, stored.revision)
                    }
                    None => {
                        let external_scan_end = config.restore_lookahead - 1;
                        let account = HnsAccountRecord {
                            config,
                            next_receive_index: 0,
                            next_change_index: 0,
                            next_name_index: 0,
                            next_shakedex_index: 0,
                            external_scan_end,
                            internal_scan_end: external_scan_end,
                            name_scan_end: external_scan_end,
                            shakedex_scan_end: external_scan_end,
                            shakedex_scan_complete: false,
                            shakedex_scan_in_progress: false,
                            last_used_external: None,
                            last_used_internal: None,
                            last_used_name: None,
                            last_used_shakedex: None,
                        };
                        let revision = wallet.save_wallet_account(
                            &account_entity_id(&account.config),
                            0,
                            &account,
                            clock.now_unix()?,
                        )?;
                        (account, revision)
                    }
                };
                let entity_prefix = account_entity_prefix(&account.config);
                let coins = wallet
                    .list_entities_by_id_prefix::<TrackedHnsCoin>(
                        EntityKind::HnsUtxo,
                        &entity_prefix,
                        MAX_WALLET_COINS,
                    )?
                    .into_iter()
                    .map(|entity| entity.value)
                    .collect();
                let transactions = wallet
                    .list_entities_by_id_prefix::<HnsTransactionRecord>(
                        EntityKind::HnsTransaction,
                        &entity_prefix,
                        MAX_HISTORY_RESULTS,
                    )?
                    .into_iter()
                    .map(|entity| entity.value)
                    .collect();
                Ok::<_, HnsWalletError>((account, account_revision, coins, transactions))
            })?;
        Ok(Self {
            backend,
            clock,
            store,
            cache: RwLock::new(HnsRuntimeCache {
                account,
                account_revision,
                sync: SyncStatus {
                    phase: SyncPhase::Starting,
                    validated_height: 0,
                    scanned_height: 0,
                    target_height: None,
                    last_error: None,
                },
                coins,
                transactions,
                binding: None,
                mempool_binding: None,
            }),
        })
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Trusted wall-clock seconds from the exact clock authority retained by
    /// this runtime. Adjacent same-store transports use this instead of
    /// introducing a second independently configurable time source.
    pub fn trusted_now_unix(&self) -> Result<u64, HnsWalletError> {
        self.clock.now_unix()
    }

    /// Exact canonical network binding for adjacent Shakedex/Denuo runtime
    /// composition.
    pub fn shakedex_network(&self) -> Result<NetworkBinding, HnsWalletError> {
        shakedex_network_binding(self.configured_runtime_config()?.network)
    }

    /// Prove that another component retains the identical process-local
    /// database/key authority used by this signing runtime.
    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.store.is_same_authority(store)
    }

    /// Return the account policy retained by this full runtime without
    /// consulting the node or reopening the encrypted store. Product
    /// composition uses this cache-only view while the shared store is locked
    /// to verify that the already-open runtime is the exact requested value
    /// runtime before exposing any service capability.
    pub fn configured_runtime_config(&self) -> Result<HnsRuntimeConfig, HnsWalletError> {
        Ok(self.cache_read()?.account.config.clone())
    }

    /// Reauthenticate the full runtime's cached account against the exact
    /// shared store row before an adjacent product component relies on it.
    /// A store mutation that has not yet been synchronized into the runtime
    /// is reported as stale instead of silently mixing two account revisions.
    pub fn selected_account_with_revision(
        &self,
    ) -> Result<SelectedHnsAccountRevision, HnsWalletError> {
        let (account, cached_revision) = {
            let cache = self.cache_read()?;
            (cache.account.clone(), cache.account_revision)
        };
        let account_id = account_entity_id(&account.config);
        let current_revision = self.store.try_with_store(|store| {
            if store.is_locked() {
                return Err(HnsWalletError::StoreLocked);
            }
            store.try_with_entity_read_snapshot(|snapshot| {
                validate_hns_board_account_snapshot(snapshot, &account_id, &account)
            })
        })?;
        if current_revision != cached_revision {
            return Err(HnsWalletError::StaleAccountRead);
        }
        Ok(SelectedHnsAccountRevision {
            account,
            revision: current_revision,
        })
    }

    /// Observe the exact full-runtime account, Shakedex network, and trusted
    /// time while retaining a refreshable encrypted account-prefix guard.
    /// This is metadata/cancellation authority only; it cannot sign or move
    /// value and must be consumed by an exact same-store board operation.
    pub fn observe_board_context(&self) -> Result<VerifiedHnsBoardContext, HnsWalletError> {
        let selected = self.selected_account_with_revision()?;
        let account_id = account_entity_id(&selected.account.config);
        let (account_revision, account_prefix_lease) = self.store.try_with_store(|store| {
            if store.is_locked() {
                return Err(HnsWalletError::StoreLocked);
            }
            store.try_with_entity_read_snapshot(|snapshot| {
                capture_hns_board_account_snapshot(snapshot, &account_id, &selected.account)
            })
        })?;
        if account_revision != selected.revision {
            return Err(HnsWalletError::StaleAccountRead);
        }
        let observed_at_unix = self.clock.now_unix()?;
        let selected_after_clock = self.selected_account_with_revision()?;
        if selected_after_clock != selected {
            return Err(HnsWalletError::StaleAccountRead);
        }
        let context = VerifiedHnsBoardCancellationContext {
            account_id,
            account: selected.account,
            account_revision,
            account_prefix_lease,
            network: shakedex_network_binding(selected_after_clock.account.config.network)?,
            observed_at_unix,
        };
        self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                context.revalidate_unchanged_account(snapshot)
            })
        })
    }

    /// Preserve the purpose-specific cancellation API while sharing the full
    /// runtime's exact account/network/time fence implementation.
    pub fn observe_board_cancellation_context(
        &self,
    ) -> Result<VerifiedHnsBoardCancellationContext, HnsWalletError> {
        self.observe_board_context()
    }

    pub fn register<'a>(&'a self, registry: &mut ModuleRegistry<'a>) -> Result<(), RegistryError> {
        registry.register_utxo_settlement(self)
    }

    /// Called only after the trusted approval UI has compared the complete
    /// prepared artifact. The stored commitment is encrypted and single-use.
    pub fn register_send_approval(
        &self,
        approval_id: ApprovalId,
        origin: &str,
        prepared: &PreparedSend,
        expires_at_unix: u64,
    ) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let plan: HnsSpendPlan = serde_json::from_slice(prepared.authorization_commitment())
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if prepared.module != ModuleId::Handshake
            || plan.expires_at_unix != prepared.expires_at_unix
            || plan.amount != prepared.amount.base_units
            || plan.fee != prepared.fee
            || plan.destination != prepared.destination
            || expires_at_unix > plan.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let approval = HnsSendApproval {
            workflow_id: plan.workflow_id,
            commitment: Sha256::digest(prepared.authorization_commitment()).into(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&approval)?);
        self.store_lock()?.put_pending_approval(
            approval_id,
            origin,
            &encoded,
            now,
            expires_at_unix,
        )?;
        Ok(())
    }

    pub fn rebroadcast_pending_send(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        let stored = self
            .store_lock()?
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if !matches!(
            stored.state.stage,
            HnsSendStage::Authorized
                | HnsSendStage::Broadcast
                | HnsSendStage::Mempool
                | HnsSendStage::RequiresRebroadcast
        ) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let raw = stored
            .state
            .signed_transaction
            .clone()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let expected = stored
            .state
            .transaction
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let prior_quote = stored
            .state
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let input_coins = canonical_input_coins(&stored.state.plan.inputs)?;
        validate_final_fee_quote(
            &raw,
            &input_coins,
            prior_quote,
            prior_quote.binding,
            prior_quote.mempool,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let quote = self.quote_final_transaction(
            &raw,
            &input_coins,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let submission_started_at = self.clock.now_unix()?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock()?;
            let current = store
                .load_workflow::<HnsSendWorkflow>(workflow_id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let mut state = current.state;
            state.stage = HnsSendStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store.save_workflow(
                workflow_id,
                WorkflowKind::HnsSend,
                current.revision,
                &state,
                true,
                submission_started_at,
            )?;
            (revision, state)
        };
        let actual = self.backend.broadcast_transaction(&raw)?;
        if actual != expected {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let current = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = current.state;
        state.stage = HnsSendStage::Broadcast;
        store.save_workflow(
            workflow_id,
            WorkflowKind::HnsSend,
            current.revision,
            &state,
            true,
            accepted_at,
        )?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid: actual,
            accepted_at_unix: accepted_at,
        })
    }

    pub fn import_name(&self, name: &[u8]) -> Result<KnownName, HnsWalletError> {
        let now = self.clock.now_unix()?;
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let config = cache.account.config.clone();
        drop(cache);
        let wallet_name_addresses = {
            let store = self.store_lock()?;
            persisted_name_addresses(&store, &config)?
        };
        let current =
            validated_name_evidence(&self.backend, name, binding, Some(&wallet_name_addresses))?
                .known_name;
        let id = namespaced_name_id(&config, current.name_hash);
        let mut store = self.store_lock()?;
        if self.cache_read()?.binding != Some(binding) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let revision = store
            .known_name::<KnownName>(&id)?
            .map_or(0, |stored| stored.revision);
        store.save_known_name(&id, revision, &current, now)?;
        Ok(current)
    }

    /// Return the bounded, account-scoped canonical name cache. Every entry is
    /// replaced from fresh node evidence during reconciliation; legacy rows
    /// retain their explicit watch-only status until that succeeds.
    pub fn list_names(&self) -> Result<Vec<KnownName>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let mut names = self
            .store_lock()?
            .list_entities_by_id_prefix::<KnownName>(
                EntityKind::KnownName,
                &account_entity_prefix(&config),
                MAX_HISTORY_RESULTS,
            )?
            .into_iter()
            .map(|stored| stored.value)
            .collect::<Vec<_>>();
        names.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.name_hash.cmp(&right.name_hash))
        });
        Ok(names)
    }

    /// Return the next dedicated name-ownership receive target from the full
    /// runtime's exact synchronized account. This uses the separated
    /// `HnsName`, change-zero branch and can never alias the ordinary payment
    /// receive branch.
    pub fn name_receive_target(&self) -> Result<HnsNameReceiveTarget, HnsWalletError> {
        let cache = self.cache_read()?;
        ensure_ready(&cache).map_err(|_| HnsWalletError::StaleNodeSnapshot)?;
        let account = cache.account.clone();
        drop(cache);
        let derivation = DerivationReference {
            role: KeyRole::HnsName,
            account: account_number(&account),
            change: 0,
            index: account.next_name_index,
        };
        let store = self.store_lock()?;
        let public_key = derive_hns_public_key(&store, account.config.wallet_id, derivation)?;
        let target = HnsNameReceiveTarget {
            module: ModuleId::Handshake,
            account: account.config.account_id,
            display: receive_address(account.config.network, &public_key)?,
            derivation_index: derivation.index,
        };
        target
            .validate()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        Ok(target)
    }

    pub fn get_name(&self, name_hash: [u8; 32]) -> Result<Option<KnownName>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        Ok(self
            .store_lock()?
            .known_name::<KnownName>(&namespaced_name_id(&config, name_hash))?
            .map(|stored| stored.value))
    }

    /// Allocate one immutable seller key from the separated Shakedex role.
    /// This atomically changes protected encrypted key metadata and the
    /// account's restoration projection; it does not enable a value path,
    /// create a listing, reserve funds, sign, or broadcast.
    pub fn allocate_shakedex_key(
        &self,
        request: &HnsShakedexKeyAllocationRequest,
    ) -> Result<HnsShakedexKeyAllocation, HnsShakedexKeyAllocationError> {
        let config = self
            .cache_read()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?
            .account
            .config
            .clone();
        let now_unix = self
            .clock
            .now_unix()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?;
        let mut store = self
            .store_lock()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?;
        let committed =
            shakedex_key::allocate_hns_shakedex_key(&mut store, &config, request, now_unix)?;
        drop(store);
        self.install_loaded_account(committed.account)
            .map_err(HnsShakedexKeyAllocationError::Wallet)?;
        Ok(committed.allocation)
    }

    /// Re-authenticate an immutable public Shakedex key binding after restart.
    pub fn load_shakedex_key_allocation(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<HnsShakedexKeyAllocation>, HnsShakedexKeyAllocationError> {
        let wallet_id = self
            .cache_read()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?
            .account
            .config
            .wallet_id;
        let store = self
            .store_lock()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?;
        shakedex_key::load_hns_shakedex_key_allocation(&store, wallet_id, workflow_id)
    }

    /// Encode the exact version-zero 32-byte script destination committed by
    /// an authenticated seller allocation. This is the only address a product
    /// should pass to the ordinary name TRANSFER workflow for that offer.
    pub fn shakedex_lock_address(
        &self,
        allocation: &HnsShakedexKeyAllocation,
    ) -> Result<String, HnsShakedexKeyAllocationError> {
        {
            let cache = self
                .cache_read()
                .map_err(HnsShakedexKeyAllocationError::Wallet)?;
            shakedex_funding::ensure_shakedex_funding_ready(&cache)
                .map_err(HnsShakedexKeyAllocationError::Wallet)?;
            if cache.account.config.wallet_id != allocation.wallet_id()
                || cache.account.config.account_id != allocation.account_id()
                || cache.account.config.account_derivation_index
                    != allocation.account_derivation_index()
                || cache.account.config.network != allocation.network()
            {
                return Err(HnsShakedexKeyAllocationError::BindingConflict);
            }
        }
        let current = self
            .load_shakedex_key_allocation(allocation.workflow_id())?
            .ok_or(HnsShakedexKeyAllocationError::AllocationNotFound)?;
        if current != *allocation {
            return Err(HnsShakedexKeyAllocationError::BindingConflict);
        }
        encode_v0_address(allocation.network(), allocation.lock_script_hash())
            .map_err(HnsShakedexKeyAllocationError::Wallet)
    }

    /// Project a canonical public address from authenticated Shakedex terms
    /// onto the selected Handshake network. This exposes only the ordinary
    /// bech32 display string; it does not expose a derivation, key, coin, or
    /// signing capability.
    pub fn shakedex_address_display(&self, address: &Address) -> Result<String, HnsWalletError> {
        address
            .validate()
            .map_err(|_| HnsWalletError::InvalidAddress)?;
        let network = self.cache_read()?.account.config.network;
        name_workflow::encode_hns_address(
            network,
            &WalletAddressKey {
                version: address.version,
                hash: address.hash.clone(),
            },
        )
    }

    /// Re-derive a purpose-bound, redacted seller signer after authenticating
    /// the complete protected allocation topology and recovery-seed binding.
    pub fn load_shakedex_signer(
        &self,
        request: &HnsShakedexKeyAllocationRequest,
    ) -> Result<HnsShakedexSigner, HnsShakedexKeyAllocationError> {
        let config = self
            .cache_read()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?
            .account
            .config
            .clone();
        let store = self
            .store_lock()
            .map_err(HnsShakedexKeyAllocationError::Wallet)?;
        shakedex_key::load_hns_shakedex_signer(&store, &config, request)
    }

    /// Bind a protected seller allocation to the exact current, unspent
    /// Shakedex lock and snapshot-authoritative parent median time.
    pub fn verify_allocated_current_shakedex_lock(
        &self,
        request: &HnsShakedexKeyAllocationRequest,
    ) -> Result<VerifiedCurrentShakedexLock, HnsShakedexKeyAllocationError> {
        let allocation = self
            .load_shakedex_key_allocation(request.workflow_id)?
            .ok_or(HnsShakedexKeyAllocationError::AllocationNotFound)?;
        if allocation.name() != request.name
            || allocation.terms_commitment() != request.terms_commitment()?
        {
            return Err(HnsShakedexKeyAllocationError::BindingConflict);
        }
        let signer = self.load_shakedex_signer(request)?;
        self.verify_current_shakedex_lock(request.name.as_slice(), *signer.compressed_public_key())
            .map_err(HnsShakedexKeyAllocationError::Wallet)
    }

    /// Reacquire ephemeral action authority from the exact current snapshot.
    /// Cached `KnownName` ownership is never accepted as authorization.
    pub fn verify_name_ownership(
        &self,
        name: &[u8],
    ) -> Result<VerifiedNameOwnership, HnsWalletError> {
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let mempool = cache
            .mempool_binding
            .ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let config = cache.account.config.clone();
        drop(cache);
        let wallet_name_addresses = {
            let store = self.store_lock()?;
            persisted_name_addresses(&store, &config)?
        };
        let validated =
            validated_name_evidence(&self.backend, name, binding, Some(&wallet_name_addresses))?;
        let cache = self.cache_read()?;
        if cache.binding != Some(binding) || cache.mempool_binding != Some(mempool) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let current = validated.current.ok_or(HnsWalletError::NameNotOwned)?;
        if !current.state.registered
            || current.state.expired
            || current.state.revoked.get() != 0
            || current.state.transfer.get() != 0
        {
            return Err(HnsWalletError::NameNotOwned);
        }
        let derivation = match validated.known_name.ownership_status {
            NameOwnershipStatus::WalletOwned { derivation } => derivation,
            _ => return Err(HnsWalletError::NameNotOwned),
        };
        let owner = current.owner.ok_or(HnsWalletError::NameNotOwned)?;
        Ok(VerifiedNameOwnership {
            binding,
            mempool,
            name: validated.known_name.name,
            name_hash: validated.known_name.name_hash,
            current_state: validated
                .known_name
                .current_state
                .ok_or(HnsWalletError::InvalidEvidence)?,
            owner_outpoint: owner.outpoint,
            owner_transaction: owner.raw_transaction,
            owner_output: owner.output,
            owner_inclusion: owner.inclusion,
            derivation,
        })
    }

    pub fn cancel_prepared_send(&self, workflow_id: WorkflowId) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        let mut store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.state.plan.wallet_id != config.wallet_id
            || stored.state.plan.account_id != config.account_id
            || stored.state.stage != HnsSendStage::Prepared
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = stored.state;
        state.stage = HnsSendStage::Cancelled;
        let deletes = reservation_deletes(&store, &config, workflow_id)?;
        store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            workflow_id,
            WorkflowKind::HnsSend,
            stored.revision,
            &state,
            false,
            now,
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
        Ok(())
    }

    pub fn cancel_prepared_settlement(
        &self,
        artifact: &PreparedArtifact,
    ) -> Result<(), HnsWalletError> {
        if artifact.module != ModuleId::Handshake {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let prepared: HnsPreparedSettlement = serde_json::from_slice(artifact.commitment_bytes())?;
        if prepared.stage != HnsSettlementStage::Prepared
            || prepared.session_id != artifact.session_id
            || prepared.fee != artifact.fee
            || prepared.expires_at_unix != artifact.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        let kind = settlement_workflow_kind(prepared.action);
        let mut store = self.store_lock()?;
        let mut stored = store
            .load_workflow::<HnsPreparedSettlement>(prepared.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != kind
            || stored.state.stage != HnsSettlementStage::Prepared
            || !same_prepared_settlement(&stored.state, &prepared)
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        stored.state.stage = HnsSettlementStage::Cancelled;
        let deletes = if stored.state.action == HnsSettlementAction::Lock {
            reservation_deletes(&store, &config, stored.id)?
        } else {
            Vec::new()
        };
        store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            stored.id,
            kind,
            stored.revision,
            &stored.state,
            false,
            now,
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
        Ok(())
    }

    pub fn settlement_key_target(
        &self,
        session_id: SessionId,
        refund: bool,
    ) -> Result<String, HnsWalletError> {
        let account = self.cache_read()?.account.clone();
        let store = self.store_lock()?;
        derive_settlement_public_key(&store, &account, session_id, refund).map(hex::encode)
    }

    pub fn broadcast_prepared_settlement(
        &self,
        artifact: &PreparedArtifact,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        if artifact.module != ModuleId::Handshake {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let prepared: HnsPreparedSettlement = serde_json::from_slice(artifact.commitment_bytes())?;
        if prepared.session_id != artifact.session_id
            || prepared.stage != HnsSettlementStage::Prepared
            || prepared.fee != artifact.fee
            || prepared.maximum_fee.is_zero()
            || prepared.fee > prepared.maximum_fee
            || prepared.expires_at_unix != artifact.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let artifact_quote = prepared
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        let artifact_input_coins = canonical_evidence_coins(&prepared.input_coins)?;
        validate_final_fee_quote(
            &prepared.signed_transaction,
            &artifact_input_coins,
            artifact_quote,
            artifact_quote.binding,
            artifact_quote.mempool,
            prepared.fee,
            prepared.maximum_fee,
        )?;
        let transaction =
            decode_transaction_for_id(&prepared.signed_transaction, prepared.transaction)?;
        let transaction_id = wallet_transaction_hash(&transaction)?;
        if transaction_id != prepared.transaction {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        if prepared.wallet_id != config.wallet_id || prepared.account_id != config.account_id {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let kind = settlement_workflow_kind(prepared.action);
        let stored = {
            let mut store = self.store_lock()?;
            let mut stored = store
                .load_workflow::<HnsPreparedSettlement>(prepared.workflow_id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if stored.kind != kind || !same_prepared_settlement(&stored.state, &prepared) {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            if stored.state.stage == HnsSettlementStage::Confirmed {
                return Ok(BroadcastReceipt {
                    module: ModuleId::Handshake,
                    txid: stored.state.transaction,
                    accepted_at_unix: now,
                });
            }
            if now >= stored.state.expires_at_unix {
                if stored.state.stage == HnsSettlementStage::Prepared {
                    stored.state.stage = HnsSettlementStage::Expired;
                    let deletes = if stored.state.action == HnsSettlementAction::Lock {
                        reservation_deletes(&store, &config, stored.id)?
                    } else {
                        Vec::new()
                    };
                    store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                        stored.id,
                        kind,
                        stored.revision,
                        &stored.state,
                        false,
                        now,
                        EntityKind::InputReservation,
                        &[],
                        &deletes,
                    )?;
                }
                return Err(HnsWalletError::PreparedArtifactExpired);
            }
            if !matches!(
                stored.state.stage,
                HnsSettlementStage::Prepared
                    | HnsSettlementStage::Broadcast
                    | HnsSettlementStage::Mempool
                    | HnsSettlementStage::RequiresRebroadcast
            ) {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            let input_coins = canonical_evidence_coins(&stored.state.input_coins)?;
            validate_final_fee_quote(
                &stored.state.signed_transaction,
                &input_coins,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.fee,
                stored.state.maximum_fee,
            )?;
            stored
        };
        let input_coins = canonical_evidence_coins(&stored.state.input_coins)?;
        let quote = self.quote_final_transaction(
            &stored.state.signed_transaction,
            &input_coins,
            stored.state.fee,
            stored.state.maximum_fee,
        )?;
        let submission_started_at = self.clock.now_unix()?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock()?;
            let current = store
                .load_workflow::<HnsPreparedSettlement>(stored.id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let activate = current.state.action == HnsSettlementAction::Lock
                && current.state.stage == HnsSettlementStage::Prepared;
            let activation_saves = if activate {
                reservation_activation_saves(&store, &config, current.id, submission_started_at)?
            } else {
                Vec::new()
            };
            let mut state = current.state;
            state.stage = HnsSettlementStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store.save_workflow_with_entity_batch(
                current.id,
                kind,
                current.revision,
                &state,
                true,
                submission_started_at,
                EntityKind::InputReservation,
                &activation_saves,
                &[],
            )?;
            (revision, state)
        };
        let accepted = self
            .backend
            .broadcast_transaction(&stored.state.signed_transaction)?;
        if accepted != stored.state.transaction {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let current = store
            .load_workflow::<HnsPreparedSettlement>(stored.id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = current.state;
        state.stage = HnsSettlementStage::Broadcast;
        store.save_workflow(stored.id, kind, current.revision, &state, true, accepted_at)?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid: accepted,
            accepted_at_unix: accepted_at,
        })
    }

    // These values comprise the complete atomic settlement snapshot and stay
    // explicit to keep the persistence boundary straightforward to audit.
    #[allow(clippy::too_many_arguments)]
    fn persist_prepared_settlement(
        &self,
        session_id: SessionId,
        action: HnsSettlementAction,
        signed_transaction: Vec<u8>,
        input_coins: Vec<HnsInputCoinEvidence>,
        fee: BaseUnits,
        maximum_fee: BaseUnits,
        fee_quote: HnsTransactionFeeQuote,
        terms: HnsSettlementTerms,
        reservation_saves: &[EntityBatchSave<HnsInputReservation>],
        account_save: Option<&EntityBatchSave<HnsAccountRecord>>,
        now_unix: u64,
    ) -> Result<PreparedArtifact, HnsWalletError> {
        let account = self.cache_read()?.account.clone();
        let transaction = Transaction::decode(&signed_transaction)
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        let transaction = wallet_transaction_hash(&transaction)?;
        let canonical_input_coins = canonical_evidence_coins(&input_coins)?;
        validate_final_fee_quote(
            &signed_transaction,
            &canonical_input_coins,
            &fee_quote,
            fee_quote.binding,
            fee_quote.mempool,
            fee,
            maximum_fee,
        )?;
        let workflow_id = settlement_workflow_id(&account.config, session_id, action);
        let expires_at_unix = now_unix
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(HnsWalletError::Arithmetic)?;
        let prepared = HnsPreparedSettlement {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            session_id,
            action,
            stage: HnsSettlementStage::Prepared,
            transaction,
            signed_transaction,
            input_coins,
            fee,
            maximum_fee,
            fee_quote: Some(fee_quote),
            expires_at_unix,
            terms,
        };
        let kind = settlement_workflow_kind(action);
        let artifact = Self::prepared_settlement_artifact(&prepared)?;
        let mut store = self.store_lock()?;
        match store.load_workflow::<HnsPreparedSettlement>(workflow_id)? {
            Some(stored) if stored.state == prepared && stored.kind == kind => {}
            Some(_) => return Err(HnsWalletError::InvalidWorkflow),
            None => {
                if let Some(account_save) = account_save {
                    let (_, next_account_revision) = store
                        .save_workflow_with_account_and_entity_batch(
                            workflow_id,
                            kind,
                            0,
                            &prepared,
                            true,
                            now_unix,
                            account_save,
                            EntityKind::InputReservation,
                            reservation_saves,
                            &[],
                        )?;
                    self.install_committed_account(
                        account_save.expected_revision,
                        next_account_revision,
                        account_save.value.clone(),
                    )?;
                } else {
                    store.save_workflow_with_entity_batch(
                        workflow_id,
                        kind,
                        0,
                        &prepared,
                        true,
                        now_unix,
                        EntityKind::InputReservation,
                        reservation_saves,
                        &[],
                    )?;
                }
            }
        }
        Ok(artifact)
    }

    fn prepare_settlement_spend(
        &self,
        session_id: SessionId,
        lock: VerifiedLock,
        preimage: Option<Preimage>,
        maximum_fee: BaseUnits,
        current_height: Option<u64>,
        action: HnsSettlementAction,
    ) -> Result<PreparedArtifact, ChainError> {
        if lock.module != ModuleId::Handshake
            || lock.session_id != session_id
            || maximum_fee.is_zero()
        {
            return Err(ChainError::InvalidRequest(
                "invalid Handshake settlement spend",
            ));
        }
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        if action == HnsSettlementAction::Refund
            && (current_height != Some(cache.sync.validated_height)
                || cache.sync.validated_height < lock.absolute_timelock)
        {
            return Err(ChainError::InvalidRequest(
                "refund height is not current or mature",
            ));
        }
        let account = cache.account.clone();
        drop(cache);
        let config = account.config.clone();
        let store = self.store_lock().map_err(map_chain_error)?;
        let record = store
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&settlement_entity_id(
                &config, session_id,
            ))
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?
            .value;
        if record.verified != lock {
            return Err(ChainError::InvalidEvidence);
        }
        let refund = action == HnsSettlementAction::Refund;
        let public = derive_settlement_public_key(&store, &account, session_id, refund)
            .map_err(map_chain_error)?;
        let expected_key = if refund {
            decode_compressed_key(&record.expected.refund_target)?
        } else {
            decode_compressed_key(&record.expected.receiver)?
        };
        if public != expected_key {
            return Err(ChainError::InvalidRequest(
                "settlement target is not controlled by this wallet",
            ));
        }
        let receive_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 0,
            index: account.next_receive_index,
        };
        let receive_public = derive_hns_public_key(&store, config.wallet_id, receive_derivation)
            .map_err(map_chain_error)?;
        let destination = Address::new(
            0,
            public_key_hash(&receive_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidEvidence)?;
        let previous_value =
            u64::try_from(lock.amount.base_units.get()).map_err(|_| ChainError::InvalidEvidence)?;
        let funding_coin = record
            .funding_coin
            .clone()
            .ok_or(ChainError::InvalidEvidence)?;
        let canonical_funding_coin = funding_coin.to_canonical_coin().map_err(map_chain_error)?;
        if canonical_funding_coin.outpoint.transaction_hash.as_bytes() != lock.funding_id.as_bytes()
            || canonical_funding_coin.outpoint.index != record.output_index
            || canonical_funding_coin.value.get() != previous_value
            || canonical_funding_coin.coinbase
            || canonical_funding_coin.address.version != 0
            || canonical_funding_coin.address.hash != Sha3_256::digest(&record.script).to_vec()
            || canonical_funding_coin.covenant != Covenant::default()
        {
            return Err(ChainError::InvalidEvidence);
        }
        let input_coins = vec![canonical_funding_coin];
        let sequence = if refund { u32::MAX - 1 } else { u32::MAX };
        let locktime = if refund {
            u32::try_from(lock.absolute_timelock).map_err(|_| ChainError::InvalidEvidence)?
        } else {
            0
        };
        let mut transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: CanonicalTransactionHash::new(lock.funding_id.into_bytes()),
                    index: record.output_index,
                },
                sequence,
                witness: Witness {
                    items: if refund {
                        vec![vec![0; 65], Vec::new(), record.script.clone()]
                    } else {
                        vec![
                            vec![0; 65],
                            vec![0; Preimage::LENGTH],
                            vec![1],
                            record.script.clone(),
                        ]
                    },
                },
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(previous_value),
                address: destination,
                covenant: Covenant::default(),
            }],
            locktime,
        };
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let fee = canonical_policy_minimum_fee(&transaction, &input_coins, fee_rate)
            .map_err(map_chain_error)?;
        if fee > maximum_fee
            || fee.get() >= u128::from(previous_value)
            || u128::from(previous_value) - fee.get() < config.dust_threshold.get()
        {
            return Err(ChainError::FeeLimit);
        }
        transaction.outputs[0].value = Dollarydoos::new(
            previous_value - u64::try_from(fee.get()).map_err(|_| ChainError::Overflow)?,
        );
        let unsigned_transaction = transaction.clone();
        let signed = sign_htlc_spend(
            &store,
            &account,
            transaction,
            session_id,
            &record.script,
            previous_value,
            preimage.as_ref(),
            refund,
        )
        .map_err(map_chain_error)?;
        validate_witness_only_change(&unsigned_transaction, &signed).map_err(map_chain_error)?;
        drop(store);
        let quote = self
            .quote_final_transaction(&signed, &input_coins, fee, maximum_fee)
            .map_err(map_chain_error)?;
        if self.cache_read().map_err(map_chain_error)?.account != account {
            return Err(ChainError::InvalidEvidence);
        }
        let terms = match action {
            HnsSettlementAction::Redeem => HnsSettlementTerms::Redeem { lock },
            HnsSettlementAction::Refund => HnsSettlementTerms::Refund { lock },
            HnsSettlementAction::Lock => {
                return Err(ChainError::InvalidRequest(
                    "invalid settlement spend action",
                ));
            }
        };
        self.persist_prepared_settlement(
            session_id,
            action,
            signed,
            vec![funding_coin],
            fee,
            maximum_fee,
            quote,
            terms,
            &[],
            None,
            now,
        )
        .map_err(map_chain_error)
    }

    pub fn reconcile(&self) -> Result<HnsReconciliationReport, HnsWalletError> {
        let now = self.clock.now_unix()?;
        self.set_sync_phase(SyncPhase::Headers, None)?;
        let tip = self.backend.get_chain_tip()?;
        let (cached_account, cached_account_revision) = {
            let cache = self.cache_read()?;
            (cache.account.clone(), cache.account_revision)
        };
        let mut store = self.store_lock()?;
        let stored_account = store
            .wallet_account::<HnsAccountRecord>(&account_entity_id(&cached_account.config))?
            .ok_or(HnsWalletError::InvalidEvidence)?;
        validate_authoritative_reconcile_account(
            &cached_account,
            cached_account_revision,
            &stored_account.value,
            stored_account.revision,
        )?;
        let stored_account_revision = stored_account.revision;
        let account = stored_account.value;
        let stored_recovery: Option<StoredEntity<HnsRecoveryState>> =
            store.hns_recovery_state(&recovery_entity_id(&account.config))?;
        let (mut recovery, recovery_revision) = stored_recovery
            .map_or((HnsRecoveryState::default(), 0), |stored| {
                (stored.value, stored.revision)
            });
        self.set_sync_phase(SyncPhase::WalletScan, None)?;
        let (
            account,
            account_revision,
            binding,
            mempool_binding,
            addresses,
            history,
            indexed_coins,
        ) = self.restore_scan(&mut store, account, stored_account_revision, tip, now)?;
        let common_ancestor = self.find_common_ancestor(&recovery, binding)?;
        let reorg_detected = recovery.last_tip.is_some()
            && common_ancestor
                != recovery
                    .last_tip
                    .map(|old_tip| old_tip.height.min(tip.height));
        let coins = reconcile_coins(indexed_coins, &addresses, binding.tip.height)?;
        let transactions = self.reconcile_transactions(
            &history,
            &addresses,
            binding,
            mempool_binding,
            common_ancestor,
        )?;
        let revalidated_names = self.revalidate_names(&mut store, binding, now)?;
        persist_reconciled_entities(&mut store, &account.config, &coins, &transactions, now)?;
        let mut pending_user_actions =
            self.reconcile_name_workflows(&mut store, binding, mempool_binding, now)?;
        pending_user_actions.extend(self.reconcile_send_workflows(
            &mut store,
            binding,
            mempool_binding,
            now,
        )?);
        pending_user_actions.extend(self.reconcile_settlement_workflows(
            &mut store,
            binding,
            mempool_binding,
            now,
        )?);
        pending_user_actions.sort();
        pending_user_actions.dedup();
        self.cleanup_input_reservations(
            &mut store,
            &account.config,
            &coins,
            binding,
            mempool_binding,
            now,
        )?;

        recovery.checkpoints = self.refresh_checkpoints(binding)?;
        recovery.last_tip = Some(tip);
        recovery.last_common_ancestor = common_ancestor;
        recovery.last_reconciled_unix = now;
        store.save_hns_recovery_state(
            &recovery_entity_id(&account.config),
            recovery_revision,
            &recovery,
            now,
        )?;

        {
            let mut cache = self.cache_write()?;
            validate_authoritative_reconcile_account(
                &cache.account,
                cache.account_revision,
                &account,
                account_revision,
            )?;
            cache.account = account;
            cache.account_revision = account_revision;
            cache.sync = SyncStatus {
                phase: SyncPhase::Ready,
                validated_height: tip.height,
                scanned_height: tip.height,
                target_height: Some(tip.height),
                last_error: None,
            };
            cache.coins = coins.clone();
            cache.transactions = transactions.clone();
            cache.binding = Some(binding);
            cache.mempool_binding = Some(mempool_binding);
        }
        drop(store);
        Ok(HnsReconciliationReport {
            tip,
            common_ancestor,
            reorg_detected,
            restored_utxos: coins.len(),
            reconciled_transactions: transactions.len(),
            revalidated_names,
            pending_user_actions,
        })
    }

    fn find_common_ancestor(
        &self,
        recovery: &HnsRecoveryState,
        binding: SnapshotBinding,
    ) -> Result<Option<u64>, HnsWalletError> {
        let tip = binding.tip;
        if recovery.last_tip.is_none() {
            return Ok(None);
        }
        for checkpoint in recovery.checkpoints.iter().rev() {
            if checkpoint.height > tip.height {
                continue;
            }
            let evidence = self.backend.get_block_hash(checkpoint.height, binding)?;
            if evidence.binding != binding || evidence.height != checkpoint.height {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            if evidence.block_hash == Some(checkpoint.block_hash) {
                return Ok(Some(checkpoint.height));
            }
        }
        Ok(account_birthday_ancestor(
            self.cache_read()?.account.config.birthday_height,
        ))
    }

    fn refresh_checkpoints(
        &self,
        binding: SnapshotBinding,
    ) -> Result<Vec<HnsChainCheckpoint>, HnsWalletError> {
        let tip = binding.tip;
        let birthday = self.cache_read()?.account.config.birthday_height;
        let start = tip
            .height
            .saturating_sub((MAX_RECOVERY_CHECKPOINTS - 1) as u64)
            .max(birthday);
        let mut checkpoints = Vec::new();
        for height in start..=tip.height {
            let block_hash = if height == tip.height {
                Some(tip.block_hash)
            } else {
                let evidence = self.backend.get_block_hash(height, binding)?;
                if evidence.binding != binding || evidence.height != height {
                    return Err(HnsWalletError::StaleNodeSnapshot);
                }
                evidence.block_hash
            };
            let block_hash = block_hash.ok_or(HnsWalletError::InvalidEvidence)?;
            checkpoints.push(HnsChainCheckpoint { height, block_hash });
        }
        Ok(checkpoints)
    }

    fn set_sync_phase(
        &self,
        phase: SyncPhase,
        last_error: Option<String>,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        cache.sync.phase = phase;
        cache.sync.last_error = last_error;
        Ok(())
    }

    fn change_account_save(
        account: &HnsAccountRecord,
        account_revision: u64,
        used_index: u32,
        now_unix: u64,
    ) -> Result<EntityBatchSave<HnsAccountRecord>, HnsWalletError> {
        if account.next_change_index != used_index {
            return Err(HnsWalletError::StaleAddressReservation);
        }
        let next = used_index
            .checked_add(1)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
        ensure_trailing_gap(Some(used_index), account.config.restore_lookahead)?;
        let mut next_account = account.clone();
        next_account.next_change_index = next;
        next_account.internal_scan_end = next_account.internal_scan_end.max(required_scan_end(
            Some(used_index),
            next_account.internal_scan_end,
            next_account.config.restore_lookahead,
        ));
        Ok(EntityBatchSave {
            id: account_entity_id(&next_account.config).to_vec(),
            expected_revision: account_revision,
            value: next_account,
            updated_at_unix: now_unix,
        })
    }

    fn install_committed_account(
        &self,
        expected_revision: u64,
        next_revision: u64,
        next_account: HnsAccountRecord,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        if cache.account_revision != expected_revision {
            if cache.account_revision == next_revision && cache.account == next_account {
                return Ok(());
            }
            return Err(HnsWalletError::StaleAddressReservation);
        }
        cache.account = next_account;
        cache.account_revision = next_revision;
        Ok(())
    }

    fn install_loaded_account(
        &self,
        loaded: StoredEntity<HnsAccountRecord>,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        if !same_account_identity(&cache.account.config, &loaded.value.config) {
            return Err(HnsWalletError::AccountConfigurationMismatch);
        }
        if loaded.revision < cache.account_revision {
            return Ok(());
        }
        if loaded.revision == cache.account_revision && loaded.value != cache.account {
            return Err(HnsWalletError::AccountConfigurationMismatch);
        }
        cache.account = loaded.value;
        cache.account_revision = loaded.revision;
        Ok(())
    }

    fn prepared_send_from_plan(plan: &HnsSpendPlan) -> Result<PreparedSend, ChainError> {
        let payload = serde_json::to_vec(plan)
            .map_err(|_| ChainError::Backend("prepared send encoding failed".to_owned()))?;
        PreparedSend::new(
            ModuleId::Handshake,
            Amount {
                asset: WalletAsset::Hns,
                base_units: plan.amount,
            },
            plan.fee,
            plan.destination.clone(),
            plan.expires_at_unix,
            payload,
        )
    }

    fn recover_prepared_send(
        stored: &StoredWorkflow<HnsSendWorkflow>,
        request: &SendRequest,
        config: &HnsRuntimeConfig,
        workflow_id: WorkflowId,
        now_unix: u64,
    ) -> Result<PreparedSend, ChainError> {
        let state = &stored.state;
        if stored.kind != WorkflowKind::HnsSend
            || state.stage != HnsSendStage::Prepared
            || state.transaction.is_some()
            || state.signed_transaction.is_some()
            || state.fee_quote.is_some()
            || state.plan.wallet_id != config.wallet_id
            || state.plan.account_id != config.account_id
            || state.plan.workflow_id != workflow_id
            || state.plan.request_nonce != request.request_nonce
            || state.plan.amount != request.amount.base_units
            || state.plan.maximum_fee != request.maximum_fee
            || state.plan.fee > state.plan.maximum_fee
            || state.plan.destination != request.destination
            || state.plan.inputs.is_empty()
            || state
                .plan
                .inputs
                .iter()
                .any(|input| !is_ordinary_hns_derivation(input.derivation))
            || state.plan.expires_at_unix <= now_unix
        {
            return Err(ChainError::InvalidRequest(
                "persisted Handshake send does not match retry",
            ));
        }
        canonical_input_coins(&state.plan.inputs).map_err(|_| ChainError::InvalidEvidence)?;
        Self::prepared_send_from_plan(&state.plan)
    }

    fn prepared_settlement_artifact(
        prepared: &HnsPreparedSettlement,
    ) -> Result<PreparedArtifact, HnsWalletError> {
        let decoded = Transaction::decode(&prepared.signed_transaction)
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if wallet_transaction_hash(&decoded)? != prepared.transaction {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let fee_quote = prepared
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        let input_coins = canonical_evidence_coins(&prepared.input_coins)?;
        validate_final_fee_quote(
            &prepared.signed_transaction,
            &input_coins,
            fee_quote,
            fee_quote.binding,
            fee_quote.mempool,
            prepared.fee,
            prepared.maximum_fee,
        )?;
        let payload = serde_json::to_vec(prepared)?;
        PreparedArtifact::new(
            ModuleId::Handshake,
            prepared.session_id,
            prepared.fee,
            prepared.expires_at_unix,
            payload,
        )
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
    }

    fn restore_scan(
        &self,
        store: &mut WalletStore,
        mut account: HnsAccountRecord,
        expected_account_revision: u64,
        expected_tip: ChainTip,
        now_unix: u64,
    ) -> Result<RestoreScanResult, HnsWalletError> {
        // Fence allocation before the first Shakedex discovery read. A stale
        // concurrent allocator or scan loses this WalletAccount CAS before it
        // can derive or commit a seller key. A failed/crashed scan leaves the
        // fence set; a later scan can take over with a new revision, while key
        // allocation remains fail-closed.
        account.shakedex_scan_in_progress = true;
        let expected_account_revision = store.save_wallet_account(
            &account_entity_id(&account.config),
            expected_account_revision,
            &account,
            now_unix,
        )?;
        let allocated_next = shakedex_key::allocation_next_index(store, &account.config)
            .map_err(map_shakedex_restore_error)?;
        normalize_restore_scan_account(&mut account, allocated_next)?;
        let scan = scan_restore_snapshot(&self.backend, account, expected_tip, None, |account| {
            Ok([
                derive_restore_addresses(store, account, KeyRole::HnsCoin)?,
                derive_restore_addresses(store, account, KeyRole::HnsName)?,
                derive_restore_addresses(store, account, KeyRole::HnsShakedex)?,
            ])
        })?;
        persist_derived_addresses(store, &scan.account.config, &scan.addresses, now_unix)?;
        let account_revision = store.save_wallet_account(
            &account_entity_id(&scan.account.config),
            expected_account_revision,
            &scan.account,
            now_unix,
        )?;
        Ok((
            scan.account,
            account_revision,
            scan.binding,
            scan.mempool,
            scan.addresses,
            scan.history,
            scan.indexed_coins,
        ))
    }

    fn cache_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, HnsRuntimeCache>, HnsWalletError> {
        self.cache
            .read()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }

    fn cache_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, HnsRuntimeCache>, HnsWalletError> {
        self.cache
            .write()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }

    fn store_lock(&self) -> Result<SharedWalletStoreGuard<'_>, HnsWalletError> {
        self.store.runtime_guard().map_err(HnsWalletError::from)
    }

    fn quote_final_transaction_once(
        &self,
        raw: &[u8],
        input_coins: &[Coin],
        expected_fee: BaseUnits,
        maximum_fee: BaseUnits,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let mempool = cache
            .mempool_binding
            .ok_or(HnsWalletError::StaleNodeSnapshot)?;
        drop(cache);
        let quote = self.backend.quote_transaction_fee(
            raw,
            input_coins,
            DEFAULT_FEE_TARGET_BLOCKS,
            binding,
            mempool,
        )?;
        validate_final_fee_quote(
            raw,
            input_coins,
            &quote,
            binding,
            mempool,
            expected_fee,
            maximum_fee,
        )?;
        Ok(quote)
    }

    /// Performs at most one explicit reconciliation and one quote retry. This
    /// is a bounded recovery transition, not a polling loop.
    fn quote_final_transaction(
        &self,
        raw: &[u8],
        input_coins: &[Coin],
        expected_fee: BaseUnits,
        maximum_fee: BaseUnits,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        match self.quote_final_transaction_once(raw, input_coins, expected_fee, maximum_fee) {
            Err(HnsWalletError::StaleNodeSnapshot)
            | Err(HnsWalletError::FeeQuoteInputUnavailable) => {
                self.reconcile()?;
                self.quote_final_transaction_once(raw, input_coins, expected_fee, maximum_fee)
            }
            result => result,
        }
    }
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    fn reconcile_transactions(
        &self,
        history: &[HistoryEntry],
        addresses: &[DerivedHnsAddress],
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        common_ancestor: Option<u64>,
    ) -> Result<Vec<HnsTransactionRecord>, HnsWalletError> {
        let previous = self.cache_read()?.transactions.clone();
        reconcile_hns_read_transactions(
            &self.backend,
            history,
            addresses,
            binding,
            mempool_binding,
            common_ancestor,
            &previous,
        )
    }

    fn revalidate_names(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        now_unix: u64,
    ) -> Result<usize, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let wallet_name_addresses = persisted_name_addresses(store, &config)?;
        let names = store.list_entities_by_id_prefix::<KnownName>(
            EntityKind::KnownName,
            &account_entity_prefix(&config),
            MAX_HISTORY_RESULTS,
        )?;
        let addresses = wallet_name_addresses;
        let current_names = revalidate_hns_read_names(&self.backend, &names, &addresses, binding)?;
        let revisions = names
            .iter()
            .map(|stored| (stored.value.name_hash, stored.revision))
            .collect::<BTreeMap<_, _>>();
        let count = current_names.len();
        for current in current_names {
            let revision = revisions
                .get(&current.name_hash)
                .copied()
                .ok_or(HnsWalletError::InvalidEvidence)?;
            store.save_known_name(
                &namespaced_name_id(&config, current.name_hash),
                revision,
                &current,
                now_unix,
            )?;
        }
        Ok(count)
    }

    fn reconcile_send_workflows(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<Vec<WorkflowId>, HnsWalletError> {
        let workflows = store.list_workflows_complete::<HnsSendWorkflow>(
            WorkflowKind::HnsSend,
            MAX_HISTORY_RESULTS,
        )?;
        let config = self.cache_read()?.account.config.clone();
        let mut pending = Vec::new();
        for stored in workflows {
            if stored.state.plan.wallet_id != config.wallet_id
                || stored.state.plan.account_id != config.account_id
            {
                continue;
            }
            if stored.state.stage == HnsSendStage::Prepared
                && stored.state.plan.expires_at_unix <= now_unix
            {
                let mut state = stored.state;
                state.stage = HnsSendStage::Expired;
                let deletes = reservation_deletes(store, &config, stored.id)?;
                store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                    stored.id,
                    WorkflowKind::HnsSend,
                    stored.revision,
                    &state,
                    false,
                    now_unix,
                    EntityKind::InputReservation,
                    &[],
                    &deletes,
                )?;
                continue;
            }
            let Some(txid) = stored.state.transaction else {
                continue;
            };
            let evidence =
                self.backend
                    .get_transaction_evidence(txid, binding, Some(mempool_binding))?;
            if evidence.binding != binding || evidence.mempool != mempool_binding {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let chain_status = evidence.status;
            let outpoints: Vec<HnsOutpoint> = stored
                .state
                .plan
                .inputs
                .iter()
                .map(|input| input.coin.outpoint)
                .collect();
            let competing_spender =
                has_competing_spender_in_batches(&self.backend, &outpoints, binding, txid)?;
            let next_stage = if chain_status.conflicted || competing_spender {
                HnsSendStage::Conflicted
            } else if chain_status.confirmation_count > 0 {
                HnsSendStage::Confirmed
            } else if chain_status.in_mempool {
                HnsSendStage::Mempool
            } else if matches!(
                stored.state.stage,
                HnsSendStage::Authorized
                    | HnsSendStage::Broadcast
                    | HnsSendStage::Mempool
                    | HnsSendStage::RequiresRebroadcast
            ) {
                pending.push(stored.id);
                HnsSendStage::RequiresRebroadcast
            } else {
                stored.state.stage
            };
            if next_stage != stored.state.stage {
                let mut state = stored.state;
                state.stage = next_stage;
                let deletes = if matches!(
                    next_stage,
                    HnsSendStage::Confirmed | HnsSendStage::Conflicted
                ) {
                    reservation_deletes(store, &config, stored.id)?
                } else {
                    Vec::new()
                };
                store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                    stored.id,
                    WorkflowKind::HnsSend,
                    stored.revision,
                    &state,
                    state.signed_transaction.is_some(),
                    now_unix,
                    EntityKind::InputReservation,
                    &[],
                    &deletes,
                )?;
            }
        }
        Ok(pending)
    }

    fn has_competing_spender(
        &self,
        transaction_id: TransactionHash,
        transaction: &Transaction,
        binding: SnapshotBinding,
    ) -> Result<bool, HnsWalletError> {
        hns_read_has_competing_spender(&self.backend, transaction_id, transaction, binding)
    }

    fn cleanup_input_reservations(
        &self,
        store: &mut WalletStore,
        config: &HnsRuntimeConfig,
        coins: &[TrackedHnsCoin],
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<(), HnsWalletError> {
        let unspent: BTreeSet<HnsOutpoint> = coins
            .iter()
            .filter(|coin| is_ordinary_hns_derivation(coin.derivation))
            .map(|coin| coin.coin.outpoint)
            .collect();
        let mut name_workflows = BTreeMap::new();
        for kind in [WorkflowKind::NameTransfer, WorkflowKind::NameFinalize] {
            for workflow in
                store.list_workflows_complete::<HnsNameWorkflow>(kind, MAX_HISTORY_RESULTS)?
            {
                if workflow.state.plan.wallet_id != config.wallet_id
                    || workflow.state.plan.account_id != config.account_id
                {
                    continue;
                }
                if workflow.state.plan.workflow_id != workflow.id
                    || workflow.state.plan.action.workflow_kind() != kind
                {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
                let mut expected_reservations = BTreeMap::new();
                expected_reservations.insert(
                    workflow.state.plan.source.owner_outpoint,
                    HnsInputReservationKind::Name {
                        name_hash: workflow.state.plan.name_hash,
                    },
                );
                for input in &workflow.state.plan.funding_inputs {
                    if !is_ordinary_hns_spend_candidate(input)
                        || expected_reservations
                            .insert(input.coin.outpoint, HnsInputReservationKind::Ordinary)
                            .is_some()
                    {
                        return Err(HnsWalletError::InvalidWorkflow);
                    }
                }
                let terminal = matches!(
                    workflow.state.stage,
                    NameOperationState::Conflicted
                        | NameOperationState::Expired
                        | NameOperationState::Cancelled
                );
                if name_workflows
                    .insert(workflow.id, (expected_reservations, terminal))
                    .is_some()
                {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
            }
        }
        let reservations = account_input_reservations(store, config)?;
        let mut observed_name_reservations: BTreeMap<WorkflowId, BTreeSet<HnsOutpoint>> =
            BTreeMap::new();
        let mut deletes = Vec::new();
        for stored in reservations {
            if let Some((expected_reservations, terminal)) =
                name_workflows.get(&stored.value.workflow_id)
            {
                if expected_reservations.get(&stored.value.outpoint) != Some(&stored.value.kind) {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
                if !observed_name_reservations
                    .entry(stored.value.workflow_id)
                    .or_default()
                    .insert(stored.value.outpoint)
                {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
                if *terminal {
                    deletes.push(EntityBatchDelete {
                        id: stored.id,
                        expected_revision: stored.revision,
                    });
                }
                continue;
            }
            if matches!(stored.value.kind, HnsInputReservationKind::Name { .. }) {
                deletes.push(EntityBatchDelete {
                    id: stored.id,
                    expected_revision: stored.revision,
                });
                continue;
            }
            // Shakedex value workflows own these reservations explicitly.
            // Generic expiry, UTXO disappearance, and settlement cleanup must
            // never release either their script-controlled source or their
            // ordinary fee/payment suffix after a restart or reorg.
            if stored.value.kind.is_protected_shakedex() {
                continue;
            }
            let expired = stored
                .value
                .expires_at_unix
                .is_some_and(|expiry| expiry <= now_unix);
            let spent = !unspent.contains(&stored.value.outpoint);
            let conflicted = if stored.value.expires_at_unix.is_none() {
                match store.load_workflow::<HnsPreparedSettlement>(stored.value.workflow_id) {
                    Ok(Some(workflow)) => {
                        let evidence = self.backend.get_transaction_evidence(
                            workflow.state.transaction,
                            binding,
                            Some(mempool_binding),
                        )?;
                        if evidence.binding != binding || evidence.mempool != mempool_binding {
                            return Err(HnsWalletError::StaleNodeSnapshot);
                        }
                        evidence.status.conflicted
                    }
                    Ok(None) => true,
                    Err(_) => false,
                }
            } else {
                false
            };
            if expired || spent || conflicted {
                deletes.push(EntityBatchDelete {
                    id: stored.id,
                    expected_revision: stored.revision,
                });
            }
        }
        for (workflow_id, (expected, releases_reservations)) in &name_workflows {
            if !*releases_reservations {
                let observed = observed_name_reservations.get(workflow_id);
                if observed.is_none_or(|observed| {
                    observed.len() != expected.len()
                        || expected.keys().any(|outpoint| !observed.contains(outpoint))
                }) {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
            }
        }
        if !deletes.is_empty() {
            store.apply_entity_batch::<HnsInputReservation>(
                EntityKind::InputReservation,
                &[],
                &deletes,
            )?;
        }
        Ok(())
    }

    fn reconcile_settlement_workflows(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<Vec<WorkflowId>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let mut pending = Vec::new();
        for kind in [WorkflowKind::AtomicSwap, WorkflowKind::Refund] {
            let workflows = store
                .list_workflows_complete::<HnsPreparedSettlement>(kind, MAX_HISTORY_RESULTS)?;
            for mut stored in workflows {
                if stored.state.wallet_id != config.wallet_id
                    || stored.state.account_id != config.account_id
                    || settlement_workflow_kind(stored.state.action) != kind
                {
                    continue;
                }
                let previous_stage = stored.state.stage;
                let next_stage = if previous_stage == HnsSettlementStage::Prepared {
                    let evidence = self.backend.get_transaction_evidence(
                        stored.state.transaction,
                        binding,
                        Some(mempool_binding),
                    )?;
                    if evidence.binding != binding || evidence.mempool != mempool_binding {
                        return Err(HnsWalletError::StaleNodeSnapshot);
                    }
                    if evidence.status.conflicted {
                        HnsSettlementStage::Conflicted
                    } else if evidence.status.confirmation_count > 0 {
                        HnsSettlementStage::Confirmed
                    } else if evidence.status.in_mempool {
                        HnsSettlementStage::Mempool
                    } else if stored.state.expires_at_unix <= now_unix {
                        HnsSettlementStage::Expired
                    } else {
                        previous_stage
                    }
                } else if matches!(
                    previous_stage,
                    HnsSettlementStage::Broadcast
                        | HnsSettlementStage::Mempool
                        | HnsSettlementStage::RequiresRebroadcast
                ) {
                    let evidence = self.backend.get_transaction_evidence(
                        stored.state.transaction,
                        binding,
                        Some(mempool_binding),
                    )?;
                    if evidence.binding != binding || evidence.mempool != mempool_binding {
                        return Err(HnsWalletError::StaleNodeSnapshot);
                    }
                    if evidence.status.conflicted {
                        HnsSettlementStage::Conflicted
                    } else if evidence.status.confirmation_count > 0 {
                        HnsSettlementStage::Confirmed
                    } else if evidence.status.in_mempool {
                        HnsSettlementStage::Mempool
                    } else if stored.state.expires_at_unix <= now_unix {
                        HnsSettlementStage::Expired
                    } else {
                        pending.push(stored.id);
                        HnsSettlementStage::RequiresRebroadcast
                    }
                } else {
                    previous_stage
                };
                let terminal_lock = stored.state.action == HnsSettlementAction::Lock
                    && matches!(
                        next_stage,
                        HnsSettlementStage::Confirmed
                            | HnsSettlementStage::Conflicted
                            | HnsSettlementStage::Expired
                            | HnsSettlementStage::Cancelled
                    );
                if next_stage != previous_stage {
                    stored.state.stage = next_stage;
                    let deletes = if terminal_lock {
                        reservation_deletes(store, &config, stored.id)?
                    } else {
                        Vec::new()
                    };
                    let saves = if stored.state.action == HnsSettlementAction::Lock
                        && previous_stage == HnsSettlementStage::Prepared
                        && next_stage == HnsSettlementStage::Mempool
                    {
                        reservation_activation_saves(store, &config, stored.id, now_unix)?
                    } else {
                        Vec::new()
                    };
                    store.save_workflow_with_entity_batch(
                        stored.id,
                        kind,
                        stored.revision,
                        &stored.state,
                        !matches!(
                            next_stage,
                            HnsSettlementStage::Prepared
                                | HnsSettlementStage::Expired
                                | HnsSettlementStage::Cancelled
                        ),
                        now_unix,
                        EntityKind::InputReservation,
                        &saves,
                        &deletes,
                    )?;
                } else if terminal_lock {
                    release_reservations(store, &config, stored.id)?;
                }
            }
        }
        Ok(pending)
    }
}

fn map_shared_store_error(error: StoreError) -> HnsWalletError {
    match error {
        StoreError::Locked => HnsWalletError::StoreLocked,
        _ => HnsWalletError::Store,
    }
}

fn prepare_hns_name_import(
    store: &WalletStore,
    selected: &HnsAccountRecord,
    name_hash: [u8; 32],
    maximum_persisted_names: usize,
) -> Result<HnsNameImportPreparation, HnsWalletError> {
    if store.is_locked() {
        return Err(HnsWalletError::StoreLocked);
    }
    HnsAccountReadMode::OrdinaryNonValue.validate_config(&selected.config)?;
    let account_id = account_entity_id(&selected.config);
    let account = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::AccountConfigurationMismatch)?;
    if account.id.as_slice() != account_id.as_slice() || account.value != *selected {
        return Err(HnsWalletError::StaleAccountRead);
    }
    let names = store.list_entities_by_id_prefix::<KnownName>(
        EntityKind::KnownName,
        &account_entity_prefix(&selected.config),
        MAX_HISTORY_RESULTS,
    )?;
    let mut existing_name = None;
    let expected_name_id = namespaced_name_id(&selected.config, name_hash);
    let mut unique_hashes = BTreeSet::new();
    let mut unique_names = BTreeSet::new();
    for stored in &names {
        let actual_hash = hash_name(&stored.value.name)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        if stored.id != namespaced_name_id(&selected.config, stored.value.name_hash)
            || stored.value.name_hash != actual_hash
            || !validate_name(&stored.value.name)
            || !unique_hashes.insert(stored.value.name_hash)
            || !unique_names.insert(stored.value.name.clone())
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        if stored.id.as_slice() == expected_name_id.as_slice() {
            existing_name = Some(stored.clone());
        }
    }
    if names.len() > maximum_persisted_names
        || (names.len() == maximum_persisted_names && existing_name.is_none())
    {
        return Err(HnsWalletError::HistoryLimit);
    }
    Ok(HnsNameImportPreparation {
        account,
        names,
        existing_name,
    })
}

fn derive_hns_name_import_addresses(
    store: &WalletStore,
    preparation: &HnsNameImportPreparation,
) -> Result<Vec<DerivedHnsAddress>, HnsWalletError> {
    if store.is_locked() {
        return Err(HnsWalletError::StoreLocked);
    }
    let config = &preparation.account.value.config;
    let account_id = account_entity_id(config);
    let current_account = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::StaleAccountRead)?;
    let current_names = store.list_entities_by_id_prefix::<KnownName>(
        EntityKind::KnownName,
        &account_entity_prefix(config),
        MAX_HISTORY_RESULTS,
    )?;
    if current_account != preparation.account || current_names != preparation.names {
        return Err(HnsWalletError::StaleAccountRead);
    }
    let addresses = derive_restore_addresses(store, &preparation.account.value, KeyRole::HnsName)?;
    validate_wallet_name_addresses(&addresses)?;
    Ok(addresses)
}

fn imported_wallet_derivation(status: &NameOwnershipStatus) -> Option<DerivationReference> {
    match status {
        NameOwnershipStatus::WalletOwned { derivation } => Some(*derivation),
        NameOwnershipStatus::IncomingTransfer {
            recipient_derivation,
            ..
        } => Some(*recipient_derivation),
        NameOwnershipStatus::OutgoingTransfer {
            owner_derivation, ..
        } => Some(*owner_derivation),
        NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable
        | NameOwnershipStatus::WalletContextUnavailable
        | NameOwnershipStatus::NoCurrentOwner
        | NameOwnershipStatus::NotWalletOwned => None,
    }
}

fn rotate_imported_name_derivation(
    account: &mut HnsAccountRecord,
    name_addresses: &[DerivedHnsAddress],
    status: &NameOwnershipStatus,
) -> Result<(), HnsWalletError> {
    let Some(derivation) = imported_wallet_derivation(status) else {
        return Ok(());
    };
    if derivation.role != KeyRole::HnsName
        || derivation.account != account.config.account_derivation_index
        || derivation.change != 0
        || derivation.index > account.name_scan_end
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut exact = name_addresses.iter().filter(|address| {
        address.account_id == account.config.account_id && address.derivation == derivation
    });
    if exact.next().is_none() || exact.next().is_some() {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let last_used = account
        .last_used_name
        .map_or(derivation.index, |current| current.max(derivation.index));
    ensure_trailing_gap(Some(last_used), account.config.restore_lookahead)?;
    let next_index = last_used
        .checked_add(1)
        .filter(|next| *next < MAX_RESTORE_LOOKAHEAD)
        .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    let scan_end = required_scan_end(
        Some(last_used),
        account.name_scan_end,
        account.config.restore_lookahead,
    );
    checked_scan_address_count(&[scan_end])?;
    account.last_used_name = Some(last_used);
    account.next_name_index = account.next_name_index.max(next_index);
    account.name_scan_end = account.name_scan_end.max(scan_end);
    Ok(())
}

fn commit_hns_name_import(
    store: &mut WalletStore,
    preparation: &HnsNameImportPreparation,
    name_addresses: &[DerivedHnsAddress],
    imported: &KnownName,
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    if store.is_locked() {
        return Err(HnsWalletError::StoreLocked);
    }
    if !validate_name(&imported.name) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let imported_hash = hash_name(&imported.name)
        .map_err(|_| HnsWalletError::InvalidEvidence)?
        .into_bytes();
    if imported_hash != imported.name_hash {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let account_id = account_entity_id(&preparation.account.value.config);
    let current_account = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::StaleAccountRead)?;
    let current_names = store.list_entities_by_id_prefix::<KnownName>(
        EntityKind::KnownName,
        &account_entity_prefix(&preparation.account.value.config),
        MAX_HISTORY_RESULTS,
    )?;
    if current_account != preparation.account || current_names != preparation.names {
        return Err(HnsWalletError::StaleAccountRead);
    }

    let name_id = namespaced_name_id(&preparation.account.value.config, imported.name_hash);
    if preparation
        .existing_name
        .as_ref()
        .is_some_and(|stored| stored.id.as_slice() != name_id.as_slice())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut account = preparation.account.value.clone();
    rotate_imported_name_derivation(&mut account, name_addresses, &imported.ownership_status)?;
    let account_save = EntityBatchSave {
        id: preparation.account.id.clone(),
        expected_revision: preparation.account.revision,
        value: account,
        updated_at_unix: now_unix,
    };
    let name_save = EntityBatchSave {
        id: name_id.to_vec(),
        expected_revision: preparation
            .existing_name
            .as_ref()
            .map_or(0, |stored| stored.revision),
        value: imported.clone(),
        updated_at_unix: now_unix,
    };
    store
        .apply_account_and_entity_batch(&account_save, EntityKind::KnownName, &[name_save], &[])
        .map(|_| ())
        .map_err(|error| match error {
            StoreError::Locked => HnsWalletError::StoreLocked,
            StoreError::StaleRevision { .. } => HnsWalletError::StaleAccountRead,
            _ => HnsWalletError::Store,
        })
}

fn prepare_hns_account_read(
    store: &mut WalletStore,
    selected: &HnsAccountRecord,
    mode: HnsAccountReadMode,
    now_unix: u64,
) -> Result<HnsReadPreparation, HnsWalletError> {
    if store.is_locked() {
        return Err(HnsWalletError::StoreLocked);
    }
    mode.validate_config(&selected.config)?;
    let account_id = account_entity_id(&selected.config);
    let stored = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::AccountConfigurationMismatch)?;
    if stored.id.as_slice() != account_id.as_slice() || stored.value != *selected {
        return Err(HnsWalletError::StaleAccountRead);
    }

    // Persist the same crash-safe Shakedex discovery fence used by the full
    // runtime before deriving or querying any separated seller-key script.
    let mut fenced_account = stored.value;
    fenced_account.shakedex_scan_in_progress = true;
    let account_revision =
        store.save_wallet_account(&account_id, stored.revision, &fenced_account, now_unix)?;
    let fenced = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::StaleAccountRead)?;
    if fenced.id.as_slice() != account_id.as_slice()
        || fenced.revision != account_revision
        || fenced.value != fenced_account
    {
        return Err(HnsWalletError::StaleAccountRead);
    }
    let allocated_next = match mode {
        HnsAccountReadMode::OrdinaryNonValue => {
            shakedex_key::allocation_next_index(store, &fenced_account.config)
        }
        HnsAccountReadMode::PersistedRecoveryReadOnly => {
            shakedex_key::allocation_next_index_for_persisted_recovery_read(
                store,
                &fenced_account.config,
            )
        }
        HnsAccountReadMode::LifecycleStructural => {
            return Err(HnsWalletError::RuntimeIntegrationUnavailable);
        }
    }
    .map_err(map_shakedex_restore_error)?;
    let mut scan_account = fenced_account.clone();
    normalize_restore_scan_account(&mut scan_account, allocated_next)?;
    let prefix = account_entity_prefix(&fenced_account.config);
    let recovery_row = store
        .hns_recovery_state::<HnsRecoveryState>(&recovery_entity_id(&fenced_account.config))?;
    let recovery = recovery_row
        .as_ref()
        .map_or_else(HnsRecoveryState::default, |stored| stored.value.clone());
    if recovery.checkpoints.len() > MAX_RECOVERY_CHECKPOINTS
        || !recovery
            .checkpoints
            .windows(2)
            .all(|pair| pair[0].height < pair[1].height)
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let coins = store.list_entities_by_id_prefix::<TrackedHnsCoin>(
        EntityKind::HnsUtxo,
        &prefix,
        MAX_WALLET_COINS,
    )?;
    for stored in &coins {
        let expected = namespaced_outpoint_id(&fenced_account.config, stored.value.coin.outpoint);
        if stored.id.as_slice() != expected.as_slice()
            || stored.value.derivation.account != fenced_account.config.account_derivation_index
            || stored.value.to_canonical_coin().is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    let transactions = store.list_entities_by_id_prefix::<HnsTransactionRecord>(
        EntityKind::HnsTransaction,
        &prefix,
        MAX_HISTORY_RESULTS,
    )?;
    for stored in &transactions {
        let expected = namespaced_transaction_id(&fenced_account.config, stored.value.summary.txid);
        if stored.id.as_slice() != expected.as_slice()
            || stored.value.summary.module != ModuleId::Handshake
            || decode_transaction_for_id(&stored.value.raw, stored.value.summary.txid).is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    let names = store.list_entities_by_id_prefix::<KnownName>(
        EntityKind::KnownName,
        &prefix,
        MAX_HISTORY_RESULTS,
    )?;
    for stored in &names {
        let expected = namespaced_name_id(&fenced_account.config, stored.value.name_hash);
        let actual_hash = hash_name(&stored.value.name)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        if stored.id.as_slice() != expected.as_slice()
            || actual_hash != stored.value.name_hash
            || !validate_name(&stored.value.name)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(HnsReadPreparation {
        fenced_account,
        scan_account,
        account_revision,
        recovery,
        recovery_row,
        coins,
        transactions,
        names,
    })
}

fn verify_hns_read_account_fence(
    store: &WalletStore,
    preparation: &HnsReadPreparation,
) -> Result<(), HnsWalletError> {
    if store.is_locked() {
        return Err(HnsWalletError::StoreLocked);
    }
    let account_id = account_entity_id(&preparation.fenced_account.config);
    let stored = store
        .wallet_account::<HnsAccountRecord>(&account_id)?
        .ok_or(HnsWalletError::StaleAccountRead)?;
    if stored.id.as_slice() != account_id.as_slice()
        || stored.revision != preparation.account_revision
        || stored.value != preparation.fenced_account
    {
        return Err(HnsWalletError::StaleAccountRead);
    }
    Ok(())
}

fn scan_hns_account_read<B: HnsBackend>(
    backend: &B,
    store: &SharedWalletStore,
    preparation: &HnsReadPreparation,
    expected_binding: SnapshotBinding,
) -> Result<HnsReadScan, HnsWalletError> {
    scan_restore_snapshot(
        backend,
        preparation.scan_account.clone(),
        expected_binding.tip,
        Some(expected_binding),
        |account| {
            store
                .with_store(|store| {
                    Ok((|| {
                        verify_hns_read_account_fence(store, preparation)?;
                        Ok([
                            derive_restore_addresses(store, account, KeyRole::HnsCoin)?,
                            derive_restore_addresses(store, account, KeyRole::HnsName)?,
                            derive_restore_addresses(store, account, KeyRole::HnsShakedex)?,
                        ])
                    })())
                })
                .map_err(map_shared_store_error)?
        },
    )
}

fn hns_read_common_ancestor<B: HnsBackend>(
    backend: &B,
    recovery: &HnsRecoveryState,
    binding: SnapshotBinding,
    birthday_height: u64,
) -> Result<Option<u64>, HnsWalletError> {
    if recovery.last_tip.is_none() {
        return Ok(None);
    }
    for checkpoint in recovery.checkpoints.iter().rev() {
        if checkpoint.height > binding.tip.height {
            continue;
        }
        let evidence = backend.get_block_hash(checkpoint.height, binding)?;
        if evidence.binding != binding || evidence.height != checkpoint.height {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        if evidence.block_hash == Some(checkpoint.block_hash) {
            return Ok(Some(checkpoint.height));
        }
    }
    Ok(account_birthday_ancestor(birthday_height))
}

fn verify_hns_read_chain_identity<B: HnsBackend>(
    backend: &B,
    network: HnsNetwork,
    binding: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    let (_, expected_genesis_hash) = name_workflow::expected_chain_identity(network)?;
    let genesis = backend.get_block_hash(0, binding)?;
    if genesis.binding != binding || genesis.height != 0 {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    if genesis.block_hash != Some(expected_genesis_hash) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn hns_read_checkpoints<B: HnsBackend>(
    backend: &B,
    binding: SnapshotBinding,
    birthday_height: u64,
) -> Result<Vec<HnsChainCheckpoint>, HnsWalletError> {
    if birthday_height > binding.tip.height {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let start = binding
        .tip
        .height
        .saturating_sub((MAX_RECOVERY_CHECKPOINTS - 1) as u64)
        .max(birthday_height);
    let mut checkpoints = Vec::new();
    for height in start..=binding.tip.height {
        let block_hash = if height == binding.tip.height {
            Some(binding.tip.block_hash)
        } else {
            let evidence = backend.get_block_hash(height, binding)?;
            if evidence.binding != binding || evidence.height != height {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            evidence.block_hash
        }
        .ok_or(HnsWalletError::InvalidEvidence)?;
        checkpoints.push(HnsChainCheckpoint { height, block_hash });
    }
    Ok(checkpoints)
}

fn hns_read_receive_target(
    account: &HnsAccountRecord,
    addresses: &[DerivedHnsAddress],
) -> Result<ReceiveTarget, HnsWalletError> {
    let address = addresses
        .iter()
        .find(|address| {
            address.account_id == account.config.account_id
                && address.derivation.role == KeyRole::HnsCoin
                && address.derivation.account == account.config.account_derivation_index
                && address.derivation.change == 0
                && address.derivation.index == account.next_receive_index
        })
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let target = ReceiveTarget {
        module: ModuleId::Handshake,
        account: account.config.account_id,
        display: address.address.clone(),
        derivation_index: address.derivation.index,
    };
    target
        .validate()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(target)
}

fn hns_read_name_receive_target(
    account: &HnsAccountRecord,
    addresses: &[DerivedHnsAddress],
) -> Result<HnsNameReceiveTarget, HnsWalletError> {
    let mut matching = addresses.iter().filter(|address| {
        address.account_id == account.config.account_id
            && address.derivation.role == KeyRole::HnsName
            && address.derivation.account == account.config.account_derivation_index
            && address.derivation.change == 0
            && address.derivation.index == account.next_name_index
    });
    let address = matching.next().ok_or(HnsWalletError::InvalidEvidence)?;
    if matching.next().is_some() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let target = HnsNameReceiveTarget {
        module: ModuleId::Handshake,
        account: account.config.account_id,
        display: address.address.clone(),
        derivation_index: address.derivation.index,
    };
    target
        .validate()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(target)
}

fn reconcile_hns_read_transactions<B: HnsBackend>(
    backend: &B,
    history: &[HistoryEntry],
    addresses: &[DerivedHnsAddress],
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    common_ancestor: Option<u64>,
    previous_records: &[HnsTransactionRecord],
) -> Result<Vec<HnsTransactionRecord>, HnsWalletError> {
    let mut history = coalesce_transaction_history(history)?;
    let observed_txids: BTreeSet<TransactionHash> =
        history.iter().map(|entry| entry.txid).collect();
    if addresses.is_empty()
        || addresses.len() > MAX_RESTORE_ADDRESS_RECORDS
        || addresses
            .iter()
            .any(|address| restore_derivation_key(address.derivation).is_err())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let programs: BTreeSet<Vec<u8>> = addresses
        .iter()
        .map(|address| address.program.clone())
        .collect();
    if programs.len() != addresses.len()
        || addresses
            .iter()
            .any(|address| validate_restore_program(address.derivation, &address.program).is_err())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let previous: BTreeMap<TransactionHash, TransactionSummary> = previous_records
        .iter()
        .map(|record| (record.summary.txid, record.summary.clone()))
        .collect();
    for summary in previous.values() {
        if !observed_txids.contains(&summary.txid) {
            history.push(HistoryEntry {
                txid: summary.txid,
                height: summary.block_height,
                block_hash: None,
                transaction_position: None,
                spent: false,
                first_seen_unix: summary.first_seen_unix,
                script_index: 0,
            });
        }
    }
    if history.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let persisted_raw: BTreeMap<TransactionHash, Vec<u8>> = previous_records
        .iter()
        .map(|record| (record.summary.txid, record.raw.clone()))
        .collect();
    let mut raw_cache = BTreeMap::new();
    let mut records = Vec::with_capacity(history.len());
    for entry in &history {
        let evidence = backend.get_transaction_evidence(entry.txid, binding, Some(mempool))?;
        if evidence.binding != binding || evidence.mempool != mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let raw = match evidence.raw {
            Some(raw) => raw,
            None => persisted_raw
                .get(&entry.txid)
                .cloned()
                .ok_or(HnsWalletError::InvalidEvidence)?,
        };
        let transaction = decode_transaction_for_id(&raw, entry.txid)?;
        raw_cache.insert(entry.txid, transaction.clone());
        let competing_spender =
            hns_read_has_competing_spender(backend, entry.txid, &transaction, binding)?;
        validate_inclusion(
            entry,
            evidence.status,
            evidence.inclusion,
            binding.tip,
            observed_txids.contains(&entry.txid),
        )?;
        let (net_amount, fee) = transaction_value_effect(
            backend,
            &transaction,
            &programs,
            &mut raw_cache,
            &persisted_raw,
            binding,
            mempool,
        )?;
        let status = if evidence.status.conflicted || competing_spender {
            LocalTransactionStatus::Conflicted
        } else if evidence.status.confirmation_count > 0 {
            LocalTransactionStatus::Confirmed
        } else if evidence.status.in_mempool {
            LocalTransactionStatus::Mempool
        } else if previous.get(&entry.txid).is_some_and(|old| {
            old.status == LocalTransactionStatus::Confirmed
                && old
                    .block_height
                    .is_some_and(|height| common_ancestor.is_none_or(|ancestor| height > ancestor))
        }) {
            LocalTransactionStatus::Reorged
        } else {
            LocalTransactionStatus::Dropped
        };
        records.push(HnsTransactionRecord {
            summary: TransactionSummary {
                module: ModuleId::Handshake,
                txid: entry.txid,
                status,
                net_amount,
                fee,
                block_height: evidence.inclusion.map(|inclusion| inclusion.height),
                first_seen_unix: entry.first_seen_unix,
                confirmation_count: evidence.status.confirmation_count,
            },
            raw,
            inclusion: evidence.inclusion,
        });
    }
    records.sort_by(|left, right| {
        right
            .summary
            .block_height
            .cmp(&left.summary.block_height)
            .then_with(|| {
                right
                    .summary
                    .first_seen_unix
                    .cmp(&left.summary.first_seen_unix)
            })
            .then_with(|| left.summary.txid.cmp(&right.summary.txid))
    });
    Ok(records)
}

fn hns_read_has_competing_spender<B: HnsBackend>(
    backend: &B,
    transaction_id: TransactionHash,
    transaction: &Transaction,
    binding: SnapshotBinding,
) -> Result<bool, HnsWalletError> {
    let outpoints = transaction
        .inputs
        .iter()
        .filter(|input| !input.previous_output.is_null())
        .map(|input| HnsOutpoint {
            transaction: TransactionHash::new(input.previous_output.transaction_hash.into_bytes()),
            output_index: input.previous_output.index,
        })
        .collect::<Vec<_>>();
    has_competing_spender_in_batches(backend, &outpoints, binding, transaction_id)
}

fn revalidate_hns_read_names<B: HnsBackend>(
    backend: &B,
    stored_names: &[StoredEntity<KnownName>],
    addresses: &[DerivedHnsAddress],
    binding: SnapshotBinding,
) -> Result<Vec<KnownName>, HnsWalletError> {
    reconcile_hns_read_names(backend, stored_names, addresses, &[], binding)
}

fn reconcile_hns_read_names<B: HnsBackend>(
    backend: &B,
    stored_names: &[StoredEntity<KnownName>],
    addresses: &[DerivedHnsAddress],
    coins: &[TrackedHnsCoin],
    binding: SnapshotBinding,
) -> Result<Vec<KnownName>, HnsWalletError> {
    if stored_names.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let wallet_name_addresses = addresses
        .iter()
        .filter(|address| address.derivation.role == KeyRole::HnsName)
        .cloned()
        .collect::<Vec<_>>();
    validate_wallet_name_addresses(&wallet_name_addresses)?;
    let mut discovered = BTreeMap::new();
    for coin in coins {
        if coin.derivation.role != KeyRole::HnsName {
            continue;
        }
        let canonical_coin = coin.to_canonical_coin()?;
        if canonical_coin.covenant.kind != CovenantKind::Finalize {
            continue;
        }
        let address = wallet_name_addresses
            .iter()
            .find(|address| address.derivation == coin.derivation)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if address.program != coin.address_program
            || canonical_coin.address.version != 0
            || canonical_coin.address.hash != address.program
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let finalize = FinalizeCovenant::try_from(&canonical_coin.covenant)
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let name_hash = finalize.name_hash.into_bytes();
        let evidence = backend.get_active_name_owner_coin(name_hash, binding)?;
        let state = validate_active_name_owner_coin_evidence(&evidence, name_hash, binding)?;
        if evidence.owner_coin != canonical_coin
            || state.name != finalize.name
            || state.height != finalize.start_height
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let current_raw_resource = state.resource_data.clone();
        let resource_status = if current_raw_resource.is_empty() {
            NameResourceStatus::Empty
        } else if state.resource().is_ok() {
            NameResourceStatus::CanonicalDecoded
        } else {
            NameResourceStatus::CanonicalOpaque
        };
        let current_owner_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(
                canonical_coin.outpoint.transaction_hash.into_bytes(),
            ),
            output_index: canonical_coin.outpoint.index,
        };
        let known_name = KnownName {
            name: state.name.clone(),
            name_hash,
            proof_height: binding.tip.height,
            unbound_proof_owner_outpoint: None,
            unbound_current_owner_outpoint: Some(current_owner_outpoint),
            proof_state: None,
            current_state: Some(evidence.current_state),
            canonical_proof_state: None,
            canonical_current_state: Some(CanonicalNameStateSummary {
                owner_outpoint: Some(current_owner_outpoint),
                value: state.value.get(),
                highest: state.highest.get(),
                start_height: state.height.get(),
                renewal_height: state.renewal.get(),
                transfer_height: state.transfer.get(),
                revoked_height: state.revoked.get(),
                claimed_height: state.claimed.get(),
                renewals: state.renewals,
                registered: state.registered,
                expired: state.expired,
                weak: state.weak,
            }),
            current_raw_resource: Some(current_raw_resource),
            resource_status,
            ownership_status: NameOwnershipStatus::WalletOwned {
                derivation: coin.derivation,
            },
        };
        if discovered.insert(name_hash, known_name).is_some()
            || discovered.len() > MAX_HISTORY_RESULTS
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }

    let stored_hashes = stored_names
        .iter()
        .map(|stored| stored.value.name_hash)
        .collect::<BTreeSet<_>>();
    if stored_hashes.len() != stored_names.len() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let novel_names = discovered
        .keys()
        .filter(|name_hash| !stored_hashes.contains(*name_hash))
        .count();
    let capacity = stored_names
        .len()
        .checked_add(novel_names)
        .ok_or(HnsWalletError::HistoryLimit)?;
    if capacity > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let mut names = Vec::with_capacity(capacity);
    for stored in stored_names {
        let current = if let Some(discovered) = discovered.remove(&stored.value.name_hash) {
            if discovered.name != stored.value.name {
                return Err(HnsWalletError::InvalidEvidence);
            }
            discovered
        } else {
            validated_name_evidence(
                backend,
                &stored.value.name,
                binding,
                Some(&wallet_name_addresses),
            )?
            .known_name
        };
        if current.name_hash != stored.value.name_hash || current.proof_height != binding.tip.height
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        names.push(current);
    }
    names.extend(discovered.into_values());
    names.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.name_hash.cmp(&right.name_hash))
    });
    Ok(names)
}

fn verify_hns_read_snapshot_current<B: HnsBackend>(
    backend: &B,
    branch_scripts: &[Vec<WalletAddressKey>; 3],
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
) -> Result<(), HnsWalletError> {
    for scripts in branch_scripts {
        if scripts.is_empty() || scripts.len() > MAX_RESTORE_SCRIPTS_PER_QUERY {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let confirmed = backend.get_confirmed_wallet_page(ConfirmedWalletPageRequest {
            scripts,
            expected_tip: binding.tip,
            expected_epoch: Some(binding.chain_epoch),
            cursor: None,
            limit: 1,
        })?;
        if confirmed.binding != binding
            || confirmed
                .history
                .len()
                .saturating_add(confirmed.utxos.len())
                > 1
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let current_mempool = backend.get_mempool_wallet_page(MempoolWalletPageRequest {
            scripts,
            binding,
            expected_mempool: Some(mempool),
            cursor: None,
            limit: 1,
        })?;
        if current_mempool.binding != binding
            || current_mempool.mempool != mempool
            || current_mempool.history.len() > 1
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_hns_account_read(
    store: &mut WalletStore,
    preparation: &HnsReadPreparation,
    account: &HnsAccountRecord,
    addresses: &[DerivedHnsAddress],
    coins: &[TrackedHnsCoin],
    transactions: &[HnsTransactionRecord],
    names: &[KnownName],
    recovery: &HnsRecoveryState,
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    verify_hns_read_account_fence(store, preparation)?;
    let prefix = account_entity_prefix(&preparation.fenced_account.config);
    let current_coins = store.list_entities_by_id_prefix::<TrackedHnsCoin>(
        EntityKind::HnsUtxo,
        &prefix,
        MAX_WALLET_COINS,
    )?;
    let current_transactions = store.list_entities_by_id_prefix::<HnsTransactionRecord>(
        EntityKind::HnsTransaction,
        &prefix,
        MAX_HISTORY_RESULTS,
    )?;
    let current_names = store.list_entities_by_id_prefix::<KnownName>(
        EntityKind::KnownName,
        &prefix,
        MAX_HISTORY_RESULTS,
    )?;
    let current_recovery = store.hns_recovery_state::<HnsRecoveryState>(&recovery_entity_id(
        &preparation.fenced_account.config,
    ))?;
    if current_coins != preparation.coins
        || current_transactions != preparation.transactions
        || current_names != preparation.names
        || current_recovery != preparation.recovery_row
        || !same_account_identity(&account.config, &preparation.fenced_account.config)
        || account.config != preparation.fenced_account.config
        || account.shakedex_scan_in_progress
        || !account.shakedex_scan_complete
    {
        return Err(HnsWalletError::StaleAccountRead);
    }

    // A crash before the final WalletAccount save leaves the durable discovery
    // fence set. A later synchronization re-authenticates every partial entity
    // revision and replaces it from a fresh live snapshot before clearing it.
    persist_derived_addresses(store, &account.config, addresses, now_unix)?;
    persist_reconciled_entities(store, &account.config, coins, transactions, now_unix)?;
    let name_revisions = preparation
        .names
        .iter()
        .map(|stored| (stored.value.name_hash, stored.revision))
        .collect::<BTreeMap<_, _>>();
    let reconciled_name_hashes = names
        .iter()
        .map(|name| name.name_hash)
        .collect::<BTreeSet<_>>();
    if reconciled_name_hashes.len() != names.len()
        || name_revisions
            .keys()
            .any(|name_hash| !reconciled_name_hashes.contains(name_hash))
    {
        return Err(HnsWalletError::StaleAccountRead);
    }
    for name in names {
        // A name found from a bound current FINALIZE has no prior entity and
        // is inserted at revision zero under the existing account/read fence.
        let revision = name_revisions.get(&name.name_hash).copied().unwrap_or(0);
        store.save_known_name(
            &namespaced_name_id(&account.config, name.name_hash),
            revision,
            name,
            now_unix,
        )?;
    }
    let recovery_revision = preparation
        .recovery_row
        .as_ref()
        .map_or(0, |stored| stored.revision);
    store.save_hns_recovery_state(
        &recovery_entity_id(&account.config),
        recovery_revision,
        recovery,
        now_unix,
    )?;
    store.save_wallet_account(
        &account_entity_id(&account.config),
        preparation.account_revision,
        account,
        now_unix,
    )?;
    Ok(())
}

fn account_number(account: &HnsAccountRecord) -> u32 {
    account.config.account_derivation_index
}

fn same_account_identity(left: &HnsRuntimeConfig, right: &HnsRuntimeConfig) -> bool {
    left.wallet_id == right.wallet_id
        && left.account_id == right.account_id
        && left.account_derivation_index == right.account_derivation_index
        && left.network == right.network
        && left.birthday_height == right.birthday_height
}

fn validate_authoritative_reconcile_account(
    cached: &HnsAccountRecord,
    cached_revision: u64,
    authoritative: &HnsAccountRecord,
    authoritative_revision: u64,
) -> Result<(), HnsWalletError> {
    if !same_account_identity(&cached.config, &authoritative.config)
        || cached.config != authoritative.config
    {
        return Err(HnsWalletError::AccountConfigurationMismatch);
    }
    if authoritative_revision < cached_revision
        || (authoritative_revision == cached_revision && authoritative != cached)
        || authoritative.next_receive_index < cached.next_receive_index
        || authoritative.next_change_index < cached.next_change_index
        || authoritative.next_name_index < cached.next_name_index
        || authoritative.next_shakedex_index < cached.next_shakedex_index
        || (cached.shakedex_scan_complete && !authoritative.shakedex_scan_complete)
        || authoritative.external_scan_end < cached.external_scan_end
        || authoritative.internal_scan_end < cached.internal_scan_end
        || authoritative.name_scan_end < cached.name_scan_end
        || authoritative.shakedex_scan_end < cached.shakedex_scan_end
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn account_birthday_ancestor(birthday_height: u64) -> Option<u64> {
    birthday_height.checked_sub(1)
}

fn ensure_trailing_gap(last_used: Option<u32>, gap: u32) -> Result<(), HnsWalletError> {
    if last_used.is_some_and(|index| index.saturating_add(gap) >= MAX_RESTORE_LOOKAHEAD) {
        Err(HnsWalletError::ScanCapacityExhausted)
    } else {
        Ok(())
    }
}

fn required_scan_end(last_used: Option<u32>, current: u32, gap: u32) -> u32 {
    last_used.map_or(current, |index| current.max(index.saturating_add(gap)))
}

fn advance_next_derivation_index(current: u32, last_used: Option<u32>) -> u32 {
    last_used.map_or(current, |last_used| {
        current
            .max(last_used.saturating_add(1))
            .min(MAX_RESTORE_LOOKAHEAD - 1)
    })
}

const HNS_COIN_DERIVATION_TAG: u8 = 0;
const HNS_NAME_DERIVATION_TAG: u8 = 1;
const HNS_SHAKEDEX_DERIVATION_TAG: u8 = 2;

fn restore_derivation_key(
    derivation: DerivationReference,
) -> Result<(u8, u32, u32), HnsWalletError> {
    if derivation.index >= MAX_RESTORE_LOOKAHEAD {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match (derivation.role, derivation.change) {
        (KeyRole::HnsCoin, change) if change <= 1 => {
            Ok((HNS_COIN_DERIVATION_TAG, change, derivation.index))
        }
        (KeyRole::HnsName, 0) => Ok((HNS_NAME_DERIVATION_TAG, 0, derivation.index)),
        (KeyRole::HnsShakedex, 0) => Ok((HNS_SHAKEDEX_DERIVATION_TAG, 0, derivation.index)),
        _ => Err(HnsWalletError::InvalidEvidence),
    }
}

fn validate_restore_program(
    derivation: DerivationReference,
    program: &[u8],
) -> Result<(), HnsWalletError> {
    let (tag, _, _) = restore_derivation_key(derivation)?;
    let expected_length = match tag {
        HNS_COIN_DERIVATION_TAG | HNS_NAME_DERIVATION_TAG => 20,
        HNS_SHAKEDEX_DERIVATION_TAG => 32,
        _ => return Err(HnsWalletError::InvalidEvidence),
    };
    if program.len() != expected_length {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn checked_scan_address_count(scan_ends: &[u32]) -> Result<usize, HnsWalletError> {
    if scan_ends.is_empty() {
        return Err(HnsWalletError::InvalidLookahead);
    }
    let count = scan_ends.iter().try_fold(0_usize, |count, scan_end| {
        if *scan_end >= MAX_RESTORE_LOOKAHEAD {
            return Err(HnsWalletError::ScanCapacityExhausted);
        }
        let branch = usize::try_from(*scan_end)
            .map_err(|_| HnsWalletError::ScanCapacityExhausted)?
            .checked_add(1)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
        count
            .checked_add(branch)
            .ok_or(HnsWalletError::ScanCapacityExhausted)
    })?;
    if count == 0 || count > MAX_RESTORE_SCRIPTS_PER_QUERY {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    Ok(count)
}

fn derive_restore_addresses(
    store: &WalletStore,
    account: &HnsAccountRecord,
    role: KeyRole,
) -> Result<Vec<DerivedHnsAddress>, HnsWalletError> {
    let branches = match role {
        KeyRole::HnsCoin => vec![
            (0, account.external_scan_end),
            (1, account.internal_scan_end),
        ],
        KeyRole::HnsName => vec![(0, account.name_scan_end)],
        KeyRole::HnsShakedex => vec![(0, account.shakedex_scan_end)],
        _ => return Err(HnsWalletError::InvalidEvidence),
    };
    let scan_ends: Vec<u32> = branches.iter().map(|(_, scan_end)| *scan_end).collect();
    let address_count = checked_scan_address_count(&scan_ends)?;
    let mut addresses = Vec::with_capacity(address_count);
    for (change, scan_end) in branches {
        for index in 0..=scan_end {
            let derivation = DerivationReference {
                role,
                account: account_number(account),
                change,
                index,
            };
            let id = derived_address_record_id(&account.config, derivation)?;
            let persisted = store.derived_address::<DerivedHnsAddress>(&id)?;
            let public_key = derive_hns_public_key(store, account.config.wallet_id, derivation)?;
            let program = match role {
                KeyRole::HnsCoin | KeyRole::HnsName => public_key_hash(&public_key)?.to_vec(),
                KeyRole::HnsShakedex => lock_script_hash(&public_key).to_vec(),
                _ => return Err(HnsWalletError::InvalidEvidence),
            };
            let derived = DerivedHnsAddress {
                account_id: account.config.account_id,
                derivation,
                address: encode_v0_address(account.config.network, &program)?,
                program,
                used: persisted.as_ref().is_some_and(|address| address.value.used),
            };
            if let Some(persisted) = persisted
                && (persisted.id != id
                    || persisted.value.account_id != derived.account_id
                    || persisted.value.derivation != derived.derivation
                    || persisted.value.address != derived.address
                    || persisted.value.program != derived.program)
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            addresses.push(derived);
        }
    }
    Ok(addresses)
}

fn validate_disjoint_restore_programs(
    coin_addresses: &[DerivedHnsAddress],
    name_addresses: &[DerivedHnsAddress],
    shakedex_addresses: &[DerivedHnsAddress],
) -> Result<(), HnsWalletError> {
    let combined = coin_addresses
        .len()
        .checked_add(name_addresses.len())
        .and_then(|count| count.checked_add(shakedex_addresses.len()))
        .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    if combined == 0 || combined > MAX_RESTORE_ADDRESS_RECORDS {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut programs = BTreeSet::new();
    for address in coin_addresses
        .iter()
        .chain(name_addresses)
        .chain(shakedex_addresses)
    {
        validate_restore_program(address.derivation, &address.program)?;
        if !programs.insert(address.program.clone()) {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn validate_same_restore_snapshot(
    expected_binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
    actual_binding: SnapshotBinding,
    actual_mempool: MempoolSnapshotBinding,
) -> Result<(), HnsWalletError> {
    if actual_binding != expected_binding || actual_mempool != expected_mempool {
        Err(HnsWalletError::StaleNodeSnapshot)
    } else {
        Ok(())
    }
}

fn map_shakedex_restore_error(error: HnsShakedexKeyAllocationError) -> HnsWalletError {
    match error {
        HnsShakedexKeyAllocationError::MissingRecoverySeed => HnsWalletError::MissingSeed,
        HnsShakedexKeyAllocationError::Store(StoreError::Locked) => HnsWalletError::StoreLocked,
        HnsShakedexKeyAllocationError::Store(_) => HnsWalletError::Store,
        HnsShakedexKeyAllocationError::Wallet(error) => error,
        _ => HnsWalletError::InvalidEvidence,
    }
}

fn normalize_restore_scan_account(
    account: &mut HnsAccountRecord,
    allocated_next: u32,
) -> Result<(), HnsWalletError> {
    if allocated_next >= MAX_RESTORE_LOOKAHEAD {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    account.next_shakedex_index = account.next_shakedex_index.max(allocated_next);
    if account.external_scan_end >= MAX_RESTORE_LOOKAHEAD
        || account.internal_scan_end >= MAX_RESTORE_LOOKAHEAD
        || account.name_scan_end >= MAX_RESTORE_LOOKAHEAD
        || account.shakedex_scan_end >= MAX_RESTORE_LOOKAHEAD
        || account.next_receive_index >= MAX_RESTORE_LOOKAHEAD
        || account.next_change_index >= MAX_RESTORE_LOOKAHEAD
        || account.next_name_index >= MAX_RESTORE_LOOKAHEAD
        || account.next_shakedex_index >= MAX_RESTORE_LOOKAHEAD
    {
        return Err(HnsWalletError::InvalidLookahead);
    }
    let gap = account.config.restore_lookahead;
    if gap == 0 {
        return Err(HnsWalletError::InvalidLookahead);
    }
    let minimum_external_end = account
        .next_receive_index
        .saturating_add(gap - 1)
        .min(MAX_RESTORE_LOOKAHEAD - 1);
    let minimum_internal_end = account
        .next_change_index
        .saturating_add(gap - 1)
        .min(MAX_RESTORE_LOOKAHEAD - 1);
    let minimum_name_end = account
        .next_name_index
        .saturating_add(gap - 1)
        .min(MAX_RESTORE_LOOKAHEAD - 1);
    let minimum_shakedex_end = account
        .next_shakedex_index
        .saturating_add(gap - 1)
        .min(MAX_RESTORE_LOOKAHEAD - 1);
    account.external_scan_end = account.external_scan_end.max(minimum_external_end);
    account.internal_scan_end = account.internal_scan_end.max(minimum_internal_end);
    account.name_scan_end = account.name_scan_end.max(minimum_name_end);
    account.shakedex_scan_end = account.shakedex_scan_end.max(minimum_shakedex_end);
    Ok(())
}

/// One canonical restore scanner shared by the legacy value runtime and the
/// SharedWalletStore read adapter. The address source closure is the only
/// persistence boundary; it must return before this function performs any
/// backend operation.
fn scan_restore_snapshot<B, F>(
    backend: &B,
    mut account: HnsAccountRecord,
    expected_tip: ChainTip,
    initial_binding: Option<SnapshotBinding>,
    mut derive_branches: F,
) -> Result<HnsReadScan, HnsWalletError>
where
    B: HnsBackend,
    F: FnMut(&HnsAccountRecord) -> Result<[Vec<DerivedHnsAddress>; 3], HnsWalletError>,
{
    if initial_binding.is_some_and(|binding| binding.tip != expected_tip) {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let gap = account.config.restore_lookahead;
    let mut expected_binding = initial_binding;
    let mut expected_mempool = None;
    loop {
        let [coin_addresses, name_addresses, shakedex_addresses] = derive_branches(&account)?;
        validate_disjoint_restore_programs(&coin_addresses, &name_addresses, &shakedex_addresses)?;

        let (coin_scripts, coin_index_remap) = sorted_restore_scripts(&coin_addresses)?;
        let (binding, mempool, coin_history, coin_coins) = load_wallet_snapshot(
            backend,
            &coin_scripts,
            &coin_index_remap,
            expected_tip,
            expected_binding,
            expected_mempool,
        )?;
        if expected_binding.is_some_and(|expected| expected != binding)
            || expected_mempool.is_some_and(|expected| expected != mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }

        let (name_scripts, name_index_remap) = sorted_restore_scripts(&name_addresses)?;
        let (name_binding, name_mempool, name_history, name_coins) = load_wallet_snapshot(
            backend,
            &name_scripts,
            &name_index_remap,
            expected_tip,
            Some(binding),
            Some(mempool),
        )?;
        validate_same_restore_snapshot(binding, mempool, name_binding, name_mempool)?;
        let incoming_name_indices =
            load_incoming_transfer_derivations(backend, &name_scripts, &name_index_remap, binding)?;
        let incoming_name_derivations = incoming_name_indices
            .iter()
            .map(|index| {
                let address = name_addresses
                    .get(*index as usize)
                    .ok_or(HnsWalletError::InvalidEvidence)?;
                let key = restore_derivation_key(address.derivation)?;
                if key.0 != HNS_NAME_DERIVATION_TAG || key.1 != 0 {
                    return Err(HnsWalletError::InvalidEvidence);
                }
                Ok(key)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let (shakedex_scripts, shakedex_index_remap) = sorted_restore_scripts(&shakedex_addresses)?;
        let (shakedex_binding, shakedex_mempool, shakedex_history, shakedex_coins) =
            load_wallet_snapshot(
                backend,
                &shakedex_scripts,
                &shakedex_index_remap,
                expected_tip,
                Some(binding),
                Some(mempool),
            )?;
        validate_same_restore_snapshot(binding, mempool, shakedex_binding, shakedex_mempool)?;
        expected_binding = Some(binding);
        expected_mempool = Some(mempool);

        let mut addresses = Vec::new();
        let mut history = Vec::new();
        let mut indexed_coins = Vec::new();
        append_restore_branch(
            &mut addresses,
            &mut history,
            &mut indexed_coins,
            coin_addresses,
            coin_history,
            coin_coins,
        )?;
        append_restore_branch(
            &mut addresses,
            &mut history,
            &mut indexed_coins,
            name_addresses,
            name_history,
            name_coins,
        )?;
        append_restore_branch(
            &mut addresses,
            &mut history,
            &mut indexed_coins,
            shakedex_addresses,
            shakedex_history,
            shakedex_coins,
        )?;

        let mut last_external = None;
        let mut last_internal = None;
        let mut last_name = incoming_name_derivations
            .iter()
            .map(|(_, _, index)| *index)
            .max();
        let mut last_shakedex = None;
        for entry in &history {
            let derivation = addresses
                .get(entry.script_index as usize)
                .ok_or(HnsWalletError::InvalidEvidence)?
                .derivation;
            match restore_derivation_key(derivation)? {
                (HNS_COIN_DERIVATION_TAG, 0, index) => {
                    last_external = Some(last_external.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_COIN_DERIVATION_TAG, 1, index) => {
                    last_internal = Some(last_internal.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_NAME_DERIVATION_TAG, 0, index) => {
                    last_name = Some(last_name.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_SHAKEDEX_DERIVATION_TAG, 0, index) => {
                    last_shakedex = Some(last_shakedex.map_or(index, |last: u32| last.max(index)))
                }
                _ => return Err(HnsWalletError::InvalidEvidence),
            }
        }
        for indexed_coin in &indexed_coins {
            let derivation = addresses
                .get(indexed_coin.script_index as usize)
                .ok_or(HnsWalletError::InvalidEvidence)?
                .derivation;
            match restore_derivation_key(derivation)? {
                (HNS_COIN_DERIVATION_TAG, 0, index) => {
                    last_external = Some(last_external.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_COIN_DERIVATION_TAG, 1, index) => {
                    last_internal = Some(last_internal.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_NAME_DERIVATION_TAG, 0, index) => {
                    last_name = Some(last_name.map_or(index, |last: u32| last.max(index)))
                }
                (HNS_SHAKEDEX_DERIVATION_TAG, 0, index) => {
                    last_shakedex = Some(last_shakedex.map_or(index, |last: u32| last.max(index)))
                }
                _ => return Err(HnsWalletError::InvalidEvidence),
            }
        }
        ensure_trailing_gap(last_external, gap)?;
        ensure_trailing_gap(last_internal, gap)?;
        ensure_trailing_gap(last_name, gap)?;
        ensure_trailing_gap(last_shakedex, gap)?;
        let required_external = required_scan_end(last_external, account.external_scan_end, gap);
        let required_internal = required_scan_end(last_internal, account.internal_scan_end, gap);
        let required_name = required_scan_end(last_name, account.name_scan_end, gap);
        let required_shakedex = required_scan_end(last_shakedex, account.shakedex_scan_end, gap);
        checked_scan_address_count(&[required_external, required_internal])?;
        checked_scan_address_count(&[required_name])?;
        checked_scan_address_count(&[required_shakedex])?;
        if required_external > account.external_scan_end
            || required_internal > account.internal_scan_end
            || required_name > account.name_scan_end
            || required_shakedex > account.shakedex_scan_end
        {
            account.external_scan_end = required_external;
            account.internal_scan_end = required_internal;
            account.name_scan_end = required_name;
            account.shakedex_scan_end = required_shakedex;
            continue;
        }

        let mut used: BTreeSet<(u8, u32, u32)> = history
            .iter()
            .map(|entry| {
                let derivation = addresses
                    .get(entry.script_index as usize)
                    .ok_or(HnsWalletError::InvalidEvidence)?
                    .derivation;
                restore_derivation_key(derivation)
            })
            .collect::<Result<_, _>>()?;
        used.extend(
            indexed_coins
                .iter()
                .map(|coin| {
                    addresses
                        .get(coin.script_index as usize)
                        .ok_or(HnsWalletError::InvalidEvidence)
                        .and_then(|address| restore_derivation_key(address.derivation))
                })
                .collect::<Result<BTreeSet<_>, _>>()?,
        );
        used.extend(incoming_name_derivations);
        for address in &mut addresses {
            address.used = used.contains(&restore_derivation_key(address.derivation)?);
        }
        account.last_used_external = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_COIN_DERIVATION_TAG && *change == 0)
            .map(|(_, _, index)| *index)
            .max();
        account.last_used_internal = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_COIN_DERIVATION_TAG && *change == 1)
            .map(|(_, _, index)| *index)
            .max();
        account.last_used_name = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_NAME_DERIVATION_TAG && *change == 0)
            .map(|(_, _, index)| *index)
            .max();
        account.last_used_shakedex = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_SHAKEDEX_DERIVATION_TAG && *change == 0)
            .map(|(_, _, index)| *index)
            .max();
        account.next_receive_index =
            advance_next_derivation_index(account.next_receive_index, account.last_used_external);
        account.next_change_index =
            advance_next_derivation_index(account.next_change_index, account.last_used_internal);
        account.next_name_index =
            advance_next_derivation_index(account.next_name_index, account.last_used_name);
        account.next_shakedex_index =
            advance_next_derivation_index(account.next_shakedex_index, account.last_used_shakedex);
        account.shakedex_scan_complete = true;
        account.shakedex_scan_in_progress = false;
        history.sort_by_key(|entry| (entry.txid, entry.script_index));
        return Ok(HnsReadScan {
            account,
            binding,
            mempool,
            addresses,
            history,
            indexed_coins,
            branch_scripts: [coin_scripts, name_scripts, shakedex_scripts],
        });
    }
}

fn append_restore_branch(
    addresses: &mut Vec<DerivedHnsAddress>,
    history: &mut Vec<HistoryEntry>,
    indexed_coins: &mut Vec<IndexedWalletCoin>,
    branch_addresses: Vec<DerivedHnsAddress>,
    mut branch_history: Vec<HistoryEntry>,
    mut branch_coins: Vec<IndexedWalletCoin>,
) -> Result<(), HnsWalletError> {
    if branch_addresses.is_empty()
        || branch_addresses.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || addresses
            .len()
            .checked_add(branch_addresses.len())
            .is_none_or(|count| count > MAX_RESTORE_ADDRESS_RECORDS)
        || history
            .len()
            .checked_add(branch_history.len())
            .is_none_or(|count| count > MAX_HISTORY_RESULTS)
        || indexed_coins
            .len()
            .checked_add(branch_coins.len())
            .is_none_or(|count| count > MAX_WALLET_COINS)
    {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let offset =
        u32::try_from(addresses.len()).map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    for entry in &mut branch_history {
        if entry.script_index as usize >= branch_addresses.len() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = entry
            .script_index
            .checked_add(offset)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    }
    for coin in &mut branch_coins {
        if coin.script_index as usize >= branch_addresses.len() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        coin.script_index = coin
            .script_index
            .checked_add(offset)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    }
    addresses.extend(branch_addresses);
    history.extend(branch_history);
    indexed_coins.extend(branch_coins);
    Ok(())
}

fn sorted_restore_scripts(
    addresses: &[DerivedHnsAddress],
) -> Result<(Vec<WalletAddressKey>, Vec<u32>), HnsWalletError> {
    if addresses.is_empty() || addresses.len() > MAX_RESTORE_SCRIPTS_PER_QUERY {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut indexed: Vec<(WalletAddressKey, u32)> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            u32::try_from(index)
                .map(|index| {
                    (
                        WalletAddressKey {
                            version: 0,
                            hash: address.program.clone(),
                        },
                        index,
                    )
                })
                .map_err(|_| HnsWalletError::ScanCapacityExhausted)
        })
        .collect::<Result<_, _>>()?;
    indexed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    if indexed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let scripts = indexed.iter().map(|(script, _)| script.clone()).collect();
    let remap = indexed.into_iter().map(|(_, index)| index).collect();
    Ok((scripts, remap))
}

fn load_wallet_snapshot<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
    expected_tip: ChainTip,
    expected_binding: Option<SnapshotBinding>,
    expected_mempool: Option<MempoolSnapshotBinding>,
) -> Result<
    (
        SnapshotBinding,
        MempoolSnapshotBinding,
        Vec<HistoryEntry>,
        Vec<IndexedWalletCoin>,
    ),
    HnsWalletError,
> {
    for attempt in 0..MAX_SNAPSHOT_RESTARTS {
        match load_wallet_snapshot_once(
            backend,
            scripts,
            index_remap,
            expected_tip,
            expected_binding,
            expected_mempool,
        ) {
            Err(HnsWalletError::StaleNodeSnapshot) if attempt + 1 < MAX_SNAPSHOT_RESTARTS => {}
            result => return result,
        }
    }
    Err(HnsWalletError::StaleNodeSnapshot)
}

fn load_wallet_snapshot_once<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
    expected_tip: ChainTip,
    expected_binding: Option<SnapshotBinding>,
    expected_mempool: Option<MempoolSnapshotBinding>,
) -> Result<
    (
        SnapshotBinding,
        MempoolSnapshotBinding,
        Vec<HistoryEntry>,
        Vec<IndexedWalletCoin>,
    ),
    HnsWalletError,
> {
    if scripts.is_empty()
        || scripts.len() != index_remap.len()
        || scripts.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || !scripts.windows(2).all(|pair| pair[0] < pair[1])
        || scripts
            .iter()
            .any(|script| script.version != 0 || !matches!(script.hash.len(), 20 | 32))
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let limit =
        u32::try_from(MAX_SCAN_PAGE_RESULTS).map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    let mut confirmed_cursor: Option<Vec<u8>> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut binding = expected_binding;
    let mut history = Vec::new();
    let mut utxos = Vec::new();
    for _ in 0..MAX_SCAN_PAGES {
        let page = backend.get_confirmed_wallet_page(ConfirmedWalletPageRequest {
            scripts,
            expected_tip,
            expected_epoch: binding.map(|value: SnapshotBinding| value.chain_epoch),
            cursor: confirmed_cursor.as_deref(),
            limit,
        })?;
        if page.binding.tip != expected_tip
            || binding.is_some_and(|expected| expected != page.binding)
            || page.history.len().saturating_add(page.utxos.len()) > MAX_SCAN_PAGE_RESULTS
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        binding = Some(page.binding);
        append_remapped_history(&mut history, page.history, index_remap, true)?;
        append_remapped_utxos(&mut utxos, page.utxos, scripts, index_remap)?;
        confirmed_cursor = validated_next_cursor(page.next_cursor, &mut seen_cursors)?;
        if confirmed_cursor.is_none() {
            break;
        }
    }
    if confirmed_cursor.is_some() {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let binding = binding.ok_or(HnsWalletError::InvalidEvidence)?;

    let mut mempool_cursor: Option<Vec<u8>> = None;
    let mut mempool_binding = expected_mempool;
    let mempool_limit = u32::try_from(MAX_MEMPOOL_SCAN_RESULTS)
        .map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    seen_cursors.clear();
    for _ in 0..MAX_SCAN_PAGES {
        let page = backend.get_mempool_wallet_page(MempoolWalletPageRequest {
            scripts,
            binding,
            expected_mempool: mempool_binding,
            cursor: mempool_cursor.as_deref(),
            limit: mempool_limit,
        })?;
        if page.binding != binding
            || page.mempool.instance_nonce == [0; 32]
            || mempool_binding.is_some_and(|expected| expected != page.mempool)
            || page.history.len() > MAX_HISTORY_RESULTS
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        mempool_binding = Some(page.mempool);
        append_remapped_history(&mut history, page.history, index_remap, false)?;
        mempool_cursor = validated_next_cursor(page.next_cursor, &mut seen_cursors)?;
        if mempool_cursor.is_none() {
            break;
        }
    }
    if mempool_cursor.is_some() {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mempool_binding = mempool_binding.ok_or(HnsWalletError::InvalidEvidence)?;
    Ok((
        binding,
        mempool_binding,
        bounded_history(history, index_remap.len())?,
        utxos,
    ))
}

fn load_incoming_transfer_derivations<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
    binding: SnapshotBinding,
) -> Result<BTreeSet<u32>, HnsWalletError> {
    if scripts.is_empty()
        || scripts.len() != index_remap.len()
        || scripts.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || !scripts.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let limit =
        u32::try_from(MAX_SCAN_PAGE_RESULTS).map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    let mut outpoints = BTreeSet::new();
    let mut derivations = BTreeSet::new();
    let mut row_count = 0usize;
    for _ in 0..MAX_INCOMING_TRANSFER_PAGES {
        let page = backend.get_incoming_transfers_page(IncomingTransfersPageRequest {
            scripts,
            binding,
            cursor: cursor.as_deref(),
            limit,
        })?;
        if page.projection_version != 1
            || page.binding != binding
            || page.entries.len() > MAX_SCAN_PAGE_RESULTS
            || !(1..=MAX_SCAN_PAGE_RESULTS).contains(&page.script_examinations)
            || page.script_examinations > scripts.len()
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        row_count = row_count
            .checked_add(page.entries.len())
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
        if row_count > MAX_HISTORY_RESULTS {
            return Err(HnsWalletError::ScanCapacityExhausted);
        }
        for entry in page.entries {
            let request_index = entry.script_index as usize;
            let expected_script = scripts
                .get(request_index)
                .ok_or(HnsWalletError::InvalidEvidence)?;
            validate_incoming_transfer_candidate(&entry, expected_script, binding)?;
            let outpoint = HnsOutpoint {
                transaction: TransactionHash::new(
                    entry.transfer_coin.outpoint.transaction_hash.into_bytes(),
                ),
                output_index: entry.transfer_coin.outpoint.index,
            };
            if !outpoints.insert(outpoint) {
                return Err(HnsWalletError::InvalidEvidence);
            }
            derivations.insert(
                *index_remap
                    .get(request_index)
                    .ok_or(HnsWalletError::InvalidEvidence)?,
            );
        }
        cursor = validated_next_cursor(page.next_cursor, &mut seen_cursors)?;
        if cursor.is_none() {
            return Ok(derivations);
        }
    }
    Err(HnsWalletError::ScanCapacityExhausted)
}

fn validate_incoming_transfer_candidate(
    candidate: &IncomingTransferCandidate,
    expected_recipient: &WalletAddressKey,
    binding: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    let transfer = TransferCovenant::try_from(&candidate.transfer_coin.covenant)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if &candidate.recipient != expected_recipient
        || candidate.inclusion.height > binding.tip.height
        || candidate.inclusion.block_hash == [0; 32]
        || candidate.inclusion.transaction_index.is_none()
        || candidate.transfer_coin.outpoint.is_null()
        || candidate.transfer_coin.coinbase
        || u64::from(candidate.transfer_coin.height.get()) != candidate.inclusion.height
        || candidate.source_output_count == 0
        || candidate.transfer_coin.outpoint.index >= candidate.source_output_count
        || transfer.name_hash.into_bytes() != candidate.name_hash
        || transfer.start_height.get() != candidate.start_height
        || transfer.recipient_version != candidate.recipient.version
        || transfer.recipient_hash != candidate.recipient.hash
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn validated_next_cursor(
    cursor: Option<Vec<u8>>,
    seen: &mut BTreeSet<Vec<u8>>,
) -> Result<Option<Vec<u8>>, HnsWalletError> {
    match cursor {
        Some(cursor)
            if cursor.is_empty()
                || cursor.len() > MAX_SCAN_CURSOR_BYTES
                || !seen.insert(cursor.clone()) =>
        {
            Err(HnsWalletError::StaleNodeSnapshot)
        }
        value => Ok(value),
    }
}

fn append_remapped_history(
    output: &mut Vec<HistoryEntry>,
    entries: Vec<HistoryEntry>,
    index_remap: &[u32],
    confirmed: bool,
) -> Result<(), HnsWalletError> {
    if output.len().saturating_add(entries.len()) > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    for mut entry in entries {
        if confirmed
            != (entry.height.is_some()
                && entry.block_hash.is_some()
                && entry.transaction_position.is_some())
            || (!confirmed
                && (entry.height.is_some()
                    || entry.block_hash.is_some()
                    || entry.transaction_position.is_some()
                    || entry.first_seen_unix.is_none()))
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = *index_remap
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        output.push(entry);
    }
    Ok(())
}

fn append_remapped_utxos(
    output: &mut Vec<IndexedWalletCoin>,
    entries: Vec<IndexedWalletCoin>,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
) -> Result<(), HnsWalletError> {
    if output.len().saturating_add(entries.len()) > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    for mut entry in entries {
        let expected_script = scripts
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if &entry.output_address != expected_script {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = *index_remap
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        output.push(entry);
    }
    Ok(())
}

fn validate_spend_evidence(
    evidence: &OutpointSpendEvidence,
    binding: SnapshotBinding,
    expected_outpoints: &[HnsOutpoint],
) -> Result<(), HnsWalletError> {
    if evidence.binding != binding || evidence.entries.len() != expected_outpoints.len() {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    for (entry, expected) in evidence.entries.iter().zip(expected_outpoints) {
        if entry.outpoint != *expected
            || entry.spending.is_some_and(|spending| {
                spending.height > binding.tip.height || spending.block_hash == [0; 32]
            })
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn has_competing_spender_in_batches<B: HnsBackend>(
    backend: &B,
    outpoints: &[HnsOutpoint],
    binding: SnapshotBinding,
    expected_spender: TransactionHash,
) -> Result<bool, HnsWalletError> {
    let mut competing = false;
    for batch in outpoints.chunks(MAX_OUTPOINT_SPEND_BATCH) {
        let evidence = backend.get_outpoint_spend_evidence(batch, binding)?;
        validate_spend_evidence(&evidence, binding, batch)?;
        competing |= evidence.entries.iter().any(|entry| {
            entry
                .spending
                .is_some_and(|spending| spending.transaction != expected_spender)
        });
    }
    Ok(competing)
}

fn public_key_hash(public_key: &[u8; 33]) -> Result<[u8; 20], HnsWalletError> {
    let mut hasher = Blake2bVar::new(20).map_err(|_| HnsWalletError::KeyDerivation)?;
    blake2::digest::Update::update(&mut hasher, public_key);
    let mut output = [0_u8; 20];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| HnsWalletError::KeyDerivation)?;
    Ok(output)
}

fn bounded_history(
    history: Vec<HistoryEntry>,
    script_count: usize,
) -> Result<Vec<HistoryEntry>, HnsWalletError> {
    if history.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let mut unique = BTreeMap::new();
    for entry in history {
        if entry.script_index as usize >= script_count {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let key = (entry.txid, entry.script_index);
        if let Some(previous) = unique.insert(key, entry)
            && previous != entry
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(unique.into_values().collect())
}

fn coalesce_transaction_history(
    history: &[HistoryEntry],
) -> Result<Vec<HistoryEntry>, HnsWalletError> {
    let mut transactions: BTreeMap<TransactionHash, HistoryEntry> = BTreeMap::new();
    for entry in history {
        match transactions.get_mut(&entry.txid) {
            Some(previous) => {
                if previous.height != entry.height
                    || previous.block_hash != entry.block_hash
                    || previous.transaction_position != entry.transaction_position
                    || previous.first_seen_unix != entry.first_seen_unix
                {
                    return Err(HnsWalletError::InvalidEvidence);
                }
                previous.spent |= entry.spent;
                previous.script_index = previous.script_index.min(entry.script_index);
            }
            None => {
                transactions.insert(entry.txid, *entry);
            }
        }
    }
    Ok(transactions.into_values().collect())
}

fn reconcile_coins(
    indexed: Vec<IndexedWalletCoin>,
    addresses: &[DerivedHnsAddress],
    tip_height: u64,
) -> Result<Vec<TrackedHnsCoin>, HnsWalletError> {
    if indexed.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    let mut outpoints = BTreeSet::new();
    let mut coins = Vec::with_capacity(indexed.len());
    for indexed_coin in indexed {
        if !outpoints.insert(indexed_coin.coin.outpoint) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let address = addresses
            .get(indexed_coin.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let confirmed_height = indexed_coin
            .coin
            .confirmed_height
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let confirmed_height = u64::from(confirmed_height);
        let expected_confirmations = tip_height
            .checked_sub(confirmed_height)
            .and_then(|depth| depth.checked_add(1))
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if indexed_coin.coin.confirmation_count != expected_confirmations
            || indexed_coin.output_address.version != 0
            || indexed_coin.output_address.hash.as_slice() != address.program.as_slice()
            || restore_derivation_key(address.derivation).is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let tracked = TrackedHnsCoin {
            coin: indexed_coin.coin,
            derivation: address.derivation,
            address_program: address.program.clone(),
        };
        tracked.to_canonical_coin()?;
        coins.push(tracked);
    }
    coins.sort_by_key(|coin| coin.coin.outpoint);
    Ok(coins)
}

const fn is_ordinary_hns_derivation(derivation: DerivationReference) -> bool {
    matches!(derivation.role, KeyRole::HnsCoin)
}

fn is_ordinary_hns_spend_candidate(coin: &TrackedHnsCoin) -> bool {
    is_ordinary_hns_derivation(coin.derivation) && !coin.coin.name_locked && !coin.coin.coinbase
}

fn decode_transaction_for_id(
    raw: &[u8],
    expected: TransactionHash,
) -> Result<Transaction, HnsWalletError> {
    let transaction = Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let actual = transaction
        .transaction_hash()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if actual.as_bytes() != expected.as_bytes() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(transaction)
}

fn validate_inclusion(
    entry: &HistoryEntry,
    status: TransactionStatus,
    inclusion: Option<TransactionInclusion>,
    tip: ChainTip,
    observed_in_current_history: bool,
) -> Result<(), HnsWalletError> {
    if status.conflicted && (status.in_mempool || status.confirmation_count > 0) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match inclusion {
        Some(inclusion) => {
            if inclusion.height > tip.height
                || (observed_in_current_history && entry.height != Some(inclusion.height))
                || (observed_in_current_history && entry.block_hash != Some(inclusion.block_hash))
                || (observed_in_current_history
                    && inclusion.transaction_index.is_some()
                    && entry.transaction_position != inclusion.transaction_index)
                || status.confirmation_count == 0
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            let expected_confirmations = tip.height - inclusion.height + 1;
            if u64::from(status.confirmation_count) != expected_confirmations {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        None => {
            if (observed_in_current_history && entry.height.is_some())
                || status.confirmation_count > 0
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
    }
    Ok(())
}

fn transaction_value_effect<B: HnsBackend>(
    backend: &B,
    transaction: &Transaction,
    programs: &BTreeSet<Vec<u8>>,
    raw_cache: &mut BTreeMap<TransactionHash, Transaction>,
    persisted_raw: &BTreeMap<TransactionHash, Vec<u8>>,
    binding: SnapshotBinding,
    mempool_binding: MempoolSnapshotBinding,
) -> Result<(SignedBaseUnits, Option<BaseUnits>), HnsWalletError> {
    if transaction.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut received = 0_u128;
    let mut sent = 0_u128;
    let mut total_inputs = 0_u128;
    let mut all_inputs_known = true;
    for output in &transaction.outputs {
        if output.address.version == 0 && programs.contains(&output.address.hash) {
            received = received
                .checked_add(u128::from(output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)?;
        }
    }
    for input in &transaction.inputs {
        if input.previous_output.is_null() {
            all_inputs_known = false;
            continue;
        }
        let parent_id = TransactionHash::new(input.previous_output.transaction_hash.into_bytes());
        if let Entry::Vacant(entry) = raw_cache.entry(parent_id) {
            let evidence =
                backend.get_transaction_evidence(parent_id, binding, Some(mempool_binding))?;
            if evidence.binding != binding || evidence.mempool != mempool_binding {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let raw = match evidence.raw {
                Some(raw) => raw,
                None => match persisted_raw.get(&parent_id) {
                    Some(raw) => raw.clone(),
                    None => {
                        all_inputs_known = false;
                        continue;
                    }
                },
            };
            let parent = decode_transaction_for_id(&raw, parent_id)?;
            entry.insert(parent);
        }
        let parent = raw_cache
            .get(&parent_id)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let Some(previous_output) = parent.outputs.get(input.previous_output.index as usize) else {
            return Err(HnsWalletError::InvalidEvidence);
        };
        total_inputs = total_inputs
            .checked_add(u128::from(previous_output.value.get()))
            .ok_or(HnsWalletError::Arithmetic)?;
        if previous_output.address.version == 0 && programs.contains(&previous_output.address.hash)
        {
            sent = sent
                .checked_add(u128::from(previous_output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)?;
        }
    }
    let (negative, magnitude) = if sent > received {
        (true, sent - received)
    } else {
        (false, received - sent)
    };
    let total_outputs = transaction
        .outputs
        .iter()
        .try_fold(0_u128, |total, output| {
            total
                .checked_add(u128::from(output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)
        })?;
    let fee = if all_inputs_known && total_inputs >= total_outputs {
        Some(BaseUnits::new(total_inputs - total_outputs))
    } else {
        None
    };
    Ok((
        SignedBaseUnits {
            negative,
            magnitude: BaseUnits::new(magnitude),
        },
        fee,
    ))
}

fn persist_reconciled_entities(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    coins: &[TrackedHnsCoin],
    transactions: &[HnsTransactionRecord],
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    let entity_prefix = account_entity_prefix(config);
    let existing_coins = store.list_entities_by_id_prefix::<TrackedHnsCoin>(
        EntityKind::HnsUtxo,
        &entity_prefix,
        MAX_WALLET_COINS,
    )?;
    let mut revisions: BTreeMap<Vec<u8>, u64> = existing_coins
        .iter()
        .map(|entity| (entity.id.clone(), entity.revision))
        .collect();
    for coin in coins {
        let id = namespaced_outpoint_id(config, coin.coin.outpoint);
        let revision = revisions.remove(id.as_slice()).unwrap_or(0);
        store.save_hns_utxo(&id, revision, coin, now_unix)?;
    }
    for (id, revision) in revisions {
        store.delete_hns_utxo(&id, revision)?;
    }

    let existing_transactions = store.list_entities_by_id_prefix::<HnsTransactionRecord>(
        EntityKind::HnsTransaction,
        &entity_prefix,
        MAX_HISTORY_RESULTS,
    )?;
    let mut revisions: BTreeMap<Vec<u8>, u64> = existing_transactions
        .iter()
        .map(|entity| (entity.id.clone(), entity.revision))
        .collect();
    for transaction in transactions {
        let id = namespaced_transaction_id(config, transaction.summary.txid);
        let revision = revisions.remove(id.as_slice()).unwrap_or(0);
        store.save_hns_transaction(&id, revision, transaction, now_unix)?;
    }
    for (id, revision) in revisions {
        store.delete_hns_transaction(&id, revision)?;
    }
    Ok(())
}

fn account_entity_prefix(config: &HnsRuntimeConfig) -> [u8; 32] {
    let mut prefix = [0_u8; 32];
    prefix[..16].copy_from_slice(config.wallet_id.as_bytes());
    prefix[16..].copy_from_slice(config.account_id.as_bytes());
    prefix
}

fn account_entity_id(config: &HnsRuntimeConfig) -> [u8; 32] {
    account_entity_prefix(config)
}

fn recovery_entity_id(config: &HnsRuntimeConfig) -> [u8; 33] {
    let mut id = [0_u8; 33];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32] = 1;
    id
}

fn derived_address_id(config: &HnsRuntimeConfig, change: u32, index: u32) -> [u8; 40] {
    let mut id = [0_u8; 40];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..36].copy_from_slice(&change.to_be_bytes());
    id[36..].copy_from_slice(&index.to_be_bytes());
    id
}

fn name_derived_address_id(config: &HnsRuntimeConfig, change: u32, index: u32) -> [u8; 41] {
    let mut id = [0_u8; 41];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32] = HNS_NAME_DERIVATION_TAG;
    id[33..37].copy_from_slice(&change.to_be_bytes());
    id[37..].copy_from_slice(&index.to_be_bytes());
    id
}

fn name_derived_address_prefix(config: &HnsRuntimeConfig) -> [u8; 33] {
    let mut prefix = [0_u8; 33];
    prefix[..32].copy_from_slice(&account_entity_prefix(config));
    prefix[32] = HNS_NAME_DERIVATION_TAG;
    prefix
}

fn shakedex_derived_address_id(config: &HnsRuntimeConfig, change: u32, index: u32) -> [u8; 41] {
    let mut id = [0_u8; 41];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32] = HNS_SHAKEDEX_DERIVATION_TAG;
    id[33..37].copy_from_slice(&change.to_be_bytes());
    id[37..].copy_from_slice(&index.to_be_bytes());
    id
}

fn derived_address_record_id(
    config: &HnsRuntimeConfig,
    derivation: DerivationReference,
) -> Result<Vec<u8>, HnsWalletError> {
    if derivation.account != config.account_derivation_index {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match restore_derivation_key(derivation)? {
        (HNS_COIN_DERIVATION_TAG, change, index) => {
            Ok(derived_address_id(config, change, index).to_vec())
        }
        (HNS_NAME_DERIVATION_TAG, change, index) => {
            Ok(name_derived_address_id(config, change, index).to_vec())
        }
        (HNS_SHAKEDEX_DERIVATION_TAG, change, index) => {
            Ok(shakedex_derived_address_id(config, change, index).to_vec())
        }
        _ => Err(HnsWalletError::InvalidEvidence),
    }
}

fn namespaced_outpoint_id(config: &HnsRuntimeConfig, outpoint: HnsOutpoint) -> [u8; 68] {
    let mut id = [0_u8; 68];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..64].copy_from_slice(outpoint.transaction.as_bytes());
    id[64..].copy_from_slice(&outpoint.output_index.to_le_bytes());
    id
}

fn namespaced_transaction_id(config: &HnsRuntimeConfig, transaction: TransactionHash) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(transaction.as_bytes());
    id
}

fn namespaced_name_id(config: &HnsRuntimeConfig, name_hash: [u8; 32]) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(&name_hash);
    id
}

fn persisted_name_addresses(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<Vec<DerivedHnsAddress>, HnsWalletError> {
    let mut addresses = Vec::new();
    for stored in store.list_entities_by_id_prefix::<DerivedHnsAddress>(
        EntityKind::DerivedAddress,
        &name_derived_address_prefix(config),
        MAX_RESTORE_SCRIPTS_PER_QUERY,
    )? {
        let expected_id = derived_address_record_id(config, stored.value.derivation)?;
        if stored.id != expected_id
            || stored.value.account_id != config.account_id
            || stored.value.derivation.role != KeyRole::HnsName
            || stored.value.derivation.account != config.account_derivation_index
            || stored.value.derivation.change != 0
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        addresses.push(stored.value);
    }
    addresses.sort_by_key(|address| address.derivation.index);
    validate_wallet_name_addresses(&addresses)?;
    Ok(addresses)
}

fn persist_derived_addresses(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    addresses: &[DerivedHnsAddress],
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    if addresses.is_empty() || addresses.len() > MAX_RESTORE_ADDRESS_RECORDS {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut ids = BTreeSet::new();
    let mut programs = BTreeSet::new();
    for address in addresses {
        if address.account_id != config.account_id
            || validate_restore_program(address.derivation, &address.program).is_err()
            || !programs.insert(address.program.clone())
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let id = derived_address_record_id(config, address.derivation)?;
        if !ids.insert(id.clone()) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let existing = store.derived_address::<DerivedHnsAddress>(&id)?;
        if existing.as_ref().is_some_and(|stored| {
            stored.id != id
                || stored.value.account_id != address.account_id
                || stored.value.derivation != address.derivation
                || stored.value.address != address.address
                || stored.value.program != address.program
        }) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let revision = existing.map_or(0, |stored| stored.revision);
        store.save_derived_address(&id, revision, address, now_unix)?;
    }
    Ok(())
}

fn account_input_reservations(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<Vec<StoredEntity<HnsInputReservation>>, HnsWalletError> {
    let reservations = store.list_entities_by_id_prefix::<HnsInputReservation>(
        EntityKind::InputReservation,
        &account_entity_prefix(config),
        MAX_WALLET_COINS,
    )?;
    for stored in &reservations {
        let expected_id = namespaced_outpoint_id(config, stored.value.outpoint);
        if stored.value.wallet_id != config.wallet_id
            || stored.value.account_id != config.account_id
            || stored.id.as_slice() != expected_id.as_slice()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(reservations)
}

fn available_unreserved_coins(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    coins: Vec<TrackedHnsCoin>,
    now_unix: u64,
) -> Result<Vec<TrackedHnsCoin>, HnsWalletError> {
    let reservations = account_input_reservations(store, config)?;
    let mut reserved = BTreeSet::new();
    let mut expired = Vec::new();
    for stored in reservations {
        if stored
            .value
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now_unix)
            && !stored.value.kind.is_protected_shakedex()
        {
            expired.push(EntityBatchDelete {
                id: stored.id,
                expected_revision: stored.revision,
            });
        } else {
            reserved.insert(stored.value.outpoint);
        }
    }
    if !expired.is_empty() {
        store.apply_entity_batch::<HnsInputReservation>(
            EntityKind::InputReservation,
            &[],
            &expired,
        )?;
    }
    Ok(coins
        .into_iter()
        .filter(|coin| {
            is_ordinary_hns_derivation(coin.derivation) && !reserved.contains(&coin.coin.outpoint)
        })
        .collect())
}

fn reservation_saves(
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    inputs: &[TrackedHnsCoin],
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<Vec<EntityBatchSave<HnsInputReservation>>, HnsWalletError> {
    let mut saves = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !is_ordinary_hns_derivation(input.derivation) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let reservation = HnsInputReservation {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            outpoint: input.coin.outpoint,
            workflow_id,
            expires_at_unix: Some(expires_at_unix),
            kind: HnsInputReservationKind::Ordinary,
        };
        saves.push(EntityBatchSave {
            id: namespaced_outpoint_id(config, input.coin.outpoint).to_vec(),
            expected_revision: 0,
            value: reservation,
            updated_at_unix: now_unix,
        });
    }
    Ok(saves)
}

fn validate_prepared_reservations(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    outpoints: &[HnsOutpoint],
    expires_at_unix: u64,
) -> Result<(), HnsWalletError> {
    if outpoints.is_empty() || outpoints.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let expected: BTreeSet<HnsOutpoint> = outpoints.iter().copied().collect();
    if expected.len() != outpoints.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let reservations = account_input_reservations(store, config)?;
    let matching: Vec<_> = reservations
        .into_iter()
        .filter(|stored| stored.value.workflow_id == workflow_id)
        .collect();
    if matching.len() != expected.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    for stored in matching {
        let expected_id = namespaced_outpoint_id(config, stored.value.outpoint);
        if !expected.contains(&stored.value.outpoint)
            || stored.id.as_slice() != expected_id.as_slice()
            || stored.value.expires_at_unix != Some(expires_at_unix)
            || stored.value.kind != HnsInputReservationKind::Ordinary
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    Ok(())
}

fn reservation_activation_saves(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    now_unix: u64,
) -> Result<Vec<EntityBatchSave<HnsInputReservation>>, HnsWalletError> {
    let reservations = account_input_reservations(store, config)?;
    let mut saves = Vec::new();
    for stored in reservations {
        if stored.value.workflow_id != workflow_id {
            continue;
        }
        if stored.value.kind.is_protected_shakedex() {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut reservation = stored.value;
        reservation.expires_at_unix = None;
        saves.push(EntityBatchSave {
            id: stored.id,
            expected_revision: stored.revision,
            value: reservation,
            updated_at_unix: now_unix,
        });
    }
    Ok(saves)
}

fn reservation_deletes(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
) -> Result<Vec<EntityBatchDelete>, HnsWalletError> {
    let reservations = account_input_reservations(store, config)?;
    let mut deletes = Vec::new();
    for stored in reservations {
        if stored.value.workflow_id == workflow_id {
            if stored.value.kind.is_protected_shakedex() {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            deletes.push(EntityBatchDelete {
                id: stored.id,
                expected_revision: stored.revision,
            });
        }
    }
    Ok(deletes)
}

fn release_reservations(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
) -> Result<(), HnsWalletError> {
    let deletes = reservation_deletes(store, config, workflow_id)?;
    if !deletes.is_empty() {
        store.apply_entity_batch::<HnsInputReservation>(
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
    }
    Ok(())
}

impl<B: HnsBackend, C: HnsClock> ChainModule for HnsWalletRuntime<B, C> {
    fn module_id(&self) -> ModuleId {
        ModuleId::Handshake
    }

    fn capabilities(&self) -> ChainCapabilities {
        let config = self
            .cache_read()
            .map(|cache| cache.account.config.clone())
            .ok();
        ChainCapabilities {
            receive: true,
            send: config.as_ref().is_some_and(|config| {
                HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                    && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                    && config.value_operations_enabled
            }),
            history: true,
            atomic_settlement: config.as_ref().is_some_and(|config| {
                HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                    && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                    && config.settlement_enabled
            }),
            hash_algorithm: HashAlgorithm::Sha256,
            locktime_model: LocktimeModel::BlockHeight,
            finality_model: FinalityModel::ProofOfWorkConfirmations,
            fee_model: FeeModel::WeightRate,
        }
    }

    fn sync_status(&self) -> SyncStatus {
        self.cache_read().map_or(
            SyncStatus {
                phase: SyncPhase::Degraded,
                validated_height: 0,
                scanned_height: 0,
                target_height: None,
                last_error: Some("wallet runtime lock is unavailable".to_owned()),
            },
            |cache| cache.sync.clone(),
        )
    }

    fn balance(&self) -> Result<Amount, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        let total = cache
            .coins
            .iter()
            .try_fold(BaseUnits::ZERO, |total, coin| {
                if !is_ordinary_hns_spend_candidate(coin) {
                    Ok(total)
                } else {
                    total
                        .checked_add(coin.coin.value)
                        .map_err(|_| ChainError::Overflow)
                }
            })?;
        Ok(Amount {
            asset: WalletAsset::Hns,
            base_units: total,
        })
    }

    fn transaction_history(&self) -> Result<Vec<TransactionSummary>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        Ok(cache
            .transactions
            .iter()
            .map(|record| record.summary.clone())
            .collect())
    }

    fn receive_target(&self) -> Result<ReceiveTarget, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        let account = cache.account.clone();
        drop(cache);
        let derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 0,
            index: account.next_receive_index,
        };
        let store = self.store_lock().map_err(map_chain_error)?;
        let public_key = derive_hns_public_key(&store, account.config.wallet_id, derivation)
            .map_err(map_chain_error)?;
        Ok(ReceiveTarget {
            module: ModuleId::Handshake,
            account: account.config.account_id,
            display: receive_address(account.config.network, &public_key)
                .map_err(map_chain_error)?,
            derivation_index: derivation.index,
        })
    }

    fn prepare_send(&self, request: SendRequest) -> Result<PreparedSend, ChainError> {
        request.validate()?;
        if request.request_nonce == 0
            || request.amount.asset != WalletAsset::Hns
            || request.maximum_fee.is_zero()
        {
            return Err(ChainError::InvalidRequest("invalid Handshake send terms"));
        }
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        if !cache.account.config.value_operations_enabled {
            return Err(ChainError::Disabled);
        }
        if request.account != cache.account.config.account_id {
            return Err(ChainError::InvalidRequest("account does not match runtime"));
        }
        let account = cache.account.clone();
        let account_revision = cache.account_revision;
        let coins = cache.coins.clone();
        drop(cache);
        let workflow_id = send_workflow_id(&account.config, request.request_nonce);
        let mut store = self.store_lock().map_err(map_chain_error)?;
        if let Some(stored) = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)
            .map_err(map_chain_error)?
        {
            let prepared =
                Self::recover_prepared_send(&stored, &request, &account.config, workflow_id, now)?;
            let outpoints: Vec<HnsOutpoint> = stored
                .state
                .plan
                .inputs
                .iter()
                .map(|input| input.coin.outpoint)
                .collect();
            validate_prepared_reservations(
                &store,
                &account.config,
                workflow_id,
                &outpoints,
                stored.state.plan.expires_at_unix,
            )
            .map_err(map_chain_error)?;
            let committed_account = store
                .wallet_account::<HnsAccountRecord>(&account_entity_id(&account.config))
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            self.install_loaded_account(committed_account)
                .map_err(map_chain_error)?;
            return Ok(prepared);
        }
        let coins = available_unreserved_coins(&mut store, &account.config, coins, now)
            .map_err(map_chain_error)?;
        let destination = decode_hns_address(account.config.network, &request.destination)
            .map_err(map_chain_error)?;
        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let change_public =
            derive_hns_public_key(&store, account.config.wallet_id, change_derivation)
                .map_err(map_chain_error)?;
        let change = Address::new(
            0,
            public_key_hash(&change_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidRequest("invalid change address"))?;
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let (transaction, selected, fee) = build_unsigned_payment(
            coins,
            destination,
            change,
            request.amount.base_units,
            fee_rate,
            request.maximum_fee,
            account.config.dust_threshold,
        )
        .map_err(map_chain_error)?;
        let expires_at_unix = now
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(ChainError::Overflow)?;
        let plan = HnsSpendPlan {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            request_nonce: request.request_nonce,
            unsigned_transaction: transaction
                .encode()
                .map_err(|_| ChainError::InvalidTransactionSize)?,
            inputs: selected,
            amount: request.amount.base_units,
            fee,
            maximum_fee: request.maximum_fee,
            destination: request.destination.clone(),
            expires_at_unix,
        };
        let workflow = HnsSendWorkflow {
            plan: plan.clone(),
            stage: HnsSendStage::Prepared,
            transaction: None,
            signed_transaction: None,
            fee_quote: None,
        };
        let reservation_saves = reservation_saves(
            &account.config,
            workflow_id,
            &workflow.plan.inputs,
            expires_at_unix,
            now,
        )
        .map_err(map_chain_error)?;
        let account_save =
            Self::change_account_save(&account, account_revision, change_derivation.index, now)
                .map_err(map_chain_error)?;
        let prepared = Self::prepared_send_from_plan(&plan)?;
        let (_, next_account_revision) = store
            .save_workflow_with_account_and_entity_batch(
                workflow_id,
                WorkflowKind::HnsSend,
                0,
                &workflow,
                false,
                now,
                &account_save,
                EntityKind::InputReservation,
                &reservation_saves,
                &[],
            )
            .map_err(map_chain_error)?;
        self.install_committed_account(account_revision, next_account_revision, account_save.value)
            .map_err(map_chain_error)?;
        Ok(prepared)
    }

    fn authorize_send(&self, request: AuthorizeSend) -> Result<AuthorizedSend, ChainError> {
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        if request.prepared.module != ModuleId::Handshake
            || now > request.prepared.expires_at_unix
            || request.approved_at_unix > now
        {
            return Err(ChainError::ApprovalRequired);
        }
        let plan: HnsSpendPlan =
            serde_json::from_slice(request.prepared.authorization_commitment())
                .map_err(|_| ChainError::InvalidRequest("invalid prepared Handshake send"))?;
        if plan.expires_at_unix != request.prepared.expires_at_unix
            || plan.amount != request.prepared.amount.base_units
            || plan.fee != request.prepared.fee
            || plan.destination != request.prepared.destination
        {
            return Err(ChainError::InvalidRequest("prepared send mismatch"));
        }
        let account = self.cache_read().map_err(map_chain_error)?.account.clone();
        if plan.wallet_id != account.config.wallet_id
            || plan.account_id != account.config.account_id
        {
            return Err(ChainError::InvalidEvidence);
        }
        let (pending_approval, signed, txid) = {
            let store = self.store_lock().map_err(map_chain_error)?;
            let pending_approval = store
                .get_pending_approval(request.approval_id, now)
                .map_err(map_chain_error)?
                .ok_or(ChainError::ApprovalRequired)?;
            let approved: HnsSendApproval = serde_json::from_slice(&pending_approval.request_json)
                .map_err(|_| ChainError::ApprovalRequired)?;
            let commitment: [u8; 32] =
                Sha256::digest(request.prepared.authorization_commitment()).into();
            if approved.workflow_id != plan.workflow_id || approved.commitment != commitment {
                return Err(ChainError::ApprovalRequired);
            }
            let stored = store
                .load_workflow::<HnsSendWorkflow>(plan.workflow_id)
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            if stored.state.plan != plan
                || stored.state.stage != HnsSendStage::Prepared
                || stored.state.transaction.is_some()
                || stored.state.signed_transaction.is_some()
                || stored.state.fee_quote.is_some()
            {
                return Err(ChainError::InvalidEvidence);
            }
            let signed = sign_payment_plan(&store, &account, &plan).map_err(map_chain_error)?;
            let transaction =
                validate_signed_payment_plan(&plan, &signed).map_err(map_chain_error)?;
            let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
            (pending_approval, signed, txid)
        };
        let input_coins = canonical_input_coins(&plan.inputs).map_err(map_chain_error)?;
        let quote = self
            .quote_final_transaction(&signed, &input_coins, plan.fee, plan.maximum_fee)
            .map_err(map_chain_error)?;
        let commit_now = self.clock.now_unix().map_err(map_chain_error)?;
        if commit_now >= plan.expires_at_unix {
            return Err(ChainError::ApprovalRequired);
        }
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let stored = store
            .load_workflow::<HnsSendWorkflow>(plan.workflow_id)
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?;
        if stored.state.plan != plan
            || stored.state.stage != HnsSendStage::Prepared
            || stored.state.transaction.is_some()
            || stored.state.signed_transaction.is_some()
            || stored.state.fee_quote.is_some()
        {
            return Err(ChainError::InvalidEvidence);
        }
        let workflow = HnsSendWorkflow {
            plan,
            stage: HnsSendStage::Authorized,
            transaction: Some(txid),
            signed_transaction: Some(signed.clone()),
            fee_quote: Some(quote),
        };
        let reservation_saves = reservation_activation_saves(
            &store,
            &account.config,
            workflow.plan.workflow_id,
            commit_now,
        )
        .map_err(map_chain_error)?;
        let committed = store
            .consume_approval_and_save_workflow_with_entity_batch(
                &pending_approval,
                commit_now,
                workflow.plan.workflow_id,
                WorkflowKind::HnsSend,
                stored.revision,
                &workflow,
                true,
                EntityKind::InputReservation,
                &reservation_saves,
                &[],
            )
            .map_err(map_chain_error)?;
        if committed.is_none() {
            return Err(ChainError::ApprovalRequired);
        }
        AuthorizedSend::new(ModuleId::Handshake, request.approval_id, signed)
    }

    fn broadcast_send(&self, request: BroadcastSend) -> Result<BroadcastReceipt, ChainError> {
        let raw = request.into_transaction();
        let transaction =
            Transaction::decode(&raw).map_err(|_| ChainError::InvalidTransactionSize)?;
        let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
        let config = self
            .cache_read()
            .map_err(map_chain_error)?
            .account
            .config
            .clone();
        let stored = {
            let store = self.store_lock().map_err(map_chain_error)?;
            let workflows = store
                .list_workflows_complete::<HnsSendWorkflow>(
                    WorkflowKind::HnsSend,
                    MAX_HISTORY_RESULTS,
                )
                .map_err(map_chain_error)?;
            let stored = workflows
                .into_iter()
                .find(|workflow| {
                    workflow.state.plan.wallet_id == config.wallet_id
                        && workflow.state.plan.account_id == config.account_id
                        && workflow.state.transaction == Some(txid)
                        && workflow.state.signed_transaction.as_deref() == Some(raw.as_slice())
                })
                .ok_or(ChainError::InvalidEvidence)?;
            if stored.state.stage != HnsSendStage::Authorized {
                return Err(ChainError::InvalidEvidence);
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(ChainError::InvalidEvidence)?;
            let input_coins =
                canonical_input_coins(&stored.state.plan.inputs).map_err(map_chain_error)?;
            validate_final_fee_quote(
                &raw,
                &input_coins,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.plan.fee,
                stored.state.plan.maximum_fee,
            )
            .map_err(map_chain_error)?;
            stored
        };
        let raw = stored
            .state
            .signed_transaction
            .clone()
            .ok_or(ChainError::InvalidEvidence)?;
        let input_coins =
            canonical_input_coins(&stored.state.plan.inputs).map_err(map_chain_error)?;
        let quote = self
            .quote_final_transaction(
                &raw,
                &input_coins,
                stored.state.plan.fee,
                stored.state.plan.maximum_fee,
            )
            .map_err(map_chain_error)?;
        let submission_started_at = self.clock.now_unix().map_err(map_chain_error)?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock().map_err(map_chain_error)?;
            let current = store
                .load_workflow::<HnsSendWorkflow>(stored.id)
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(ChainError::InvalidEvidence);
            }
            let mut state = current.state;
            state.stage = HnsSendStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store
                .save_workflow(
                    stored.id,
                    WorkflowKind::HnsSend,
                    current.revision,
                    &state,
                    true,
                    submission_started_at,
                )
                .map_err(map_chain_error)?;
            (revision, state)
        };
        let accepted = self
            .backend
            .broadcast_transaction(&raw)
            .map_err(map_chain_error)?;
        if accepted != txid {
            return Err(ChainError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix().map_err(map_chain_error)?;
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let current = store
            .load_workflow::<HnsSendWorkflow>(stored.id)
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(ChainError::InvalidEvidence);
        }
        let mut state = current.state;
        state.stage = HnsSendStage::Broadcast;
        store
            .save_workflow(
                stored.id,
                WorkflowKind::HnsSend,
                current.revision,
                &state,
                true,
                accepted_at,
            )
            .map_err(map_chain_error)?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid,
            accepted_at_unix: accepted_at,
        })
    }
}

impl<B: HnsBackend, C: HnsClock> UtxoChainModule for HnsWalletRuntime<B, C> {
    fn list_utxos(&self) -> Result<Vec<Utxo>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        Ok(cache
            .coins
            .iter()
            .map(|coin| Utxo {
                txid: coin.coin.outpoint.transaction,
                output_index: coin.coin.outpoint.output_index,
                value: Amount {
                    asset: WalletAsset::Hns,
                    base_units: coin.coin.value,
                },
                confirmation_count: coin.coin.confirmation_count,
                spendable: is_ordinary_hns_spend_candidate(coin),
            })
            .collect())
    }

    fn fee_policy(&self) -> Result<UtxoFeePolicy, ChainError> {
        let rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let dust = self
            .cache_read()
            .map_err(map_chain_error)?
            .account
            .config
            .dust_threshold;
        Ok(UtxoFeePolicy {
            base_units_per_kweight: rate,
            minimum_relay: rate,
            dust_threshold: dust,
        })
    }

    fn prepare_htlc_lock(&self, request: HtlcLockRequest) -> Result<PreparedHtlcLock, ChainError> {
        self.prepare_lock(SettlementLockRequest {
            session_id: request.session_id,
            module: ModuleId::Handshake,
            amount: request.amount,
            hashlock: request.hashlock,
            receiver: hex::encode(request.receiver_key),
            refund_target: hex::encode(request.refund_key),
            absolute_timelock: request.absolute_timelock,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcLock(prepared.0))
    }

    fn verify_htlc_lock(
        &self,
        request: VerifyHtlcLockRequest,
    ) -> Result<VerifiedHtlcLock, ChainError> {
        self.verify_lock(VerifySettlementLockRequest {
            expected: request.expected,
            transaction_or_receipt: request.funding_transaction,
            confirmation_count: request.confirmation_count,
        })
        .map(|verified| VerifiedHtlcLock(verified.0))
    }

    fn prepare_htlc_redeem(
        &self,
        request: HtlcRedeemRequest,
    ) -> Result<PreparedHtlcRedeem, ChainError> {
        self.prepare_redeem(SettlementRedeemRequest {
            session_id: request.session_id,
            lock: request.lock,
            preimage: request.preimage,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcRedeem(prepared.0))
    }

    fn prepare_htlc_refund(
        &self,
        request: HtlcRefundRequest,
    ) -> Result<PreparedHtlcRefund, ChainError> {
        self.prepare_refund(SettlementRefundRequest {
            session_id: request.session_id,
            lock: request.lock,
            current_chain_time: request.current_chain_time,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcRefund(prepared.0))
    }

    fn observe_preimage(
        &self,
        request: ObservePreimageRequest,
    ) -> Result<Option<Preimage>, ChainError> {
        self.observe_secret(request)
    }
}

impl<B: HnsBackend, C: HnsClock> AtomicSettlement for HnsWalletRuntime<B, C> {
    fn settlement_capabilities(&self) -> SettlementCapabilities {
        let enabled = self.cache_read().is_ok_and(|cache| {
            HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                && cache.account.config.settlement_enabled
        });
        let minimum_confirmations = self
            .cache_read()
            .map_or(0, |cache| cache.account.config.minimum_confirmations);
        SettlementCapabilities {
            module: ModuleId::Handshake,
            supported: enabled,
            minimum_confirmations,
            maximum_lock_bytes: 256,
        }
    }

    fn prepare_lock(
        &self,
        request: SettlementLockRequest,
    ) -> Result<PreparedSettlementLock, ChainError> {
        validate_settlement_request(&request)?;
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let account = cache.account.clone();
        let coins = cache.coins.clone();
        drop(cache);
        let workflow_id = settlement_workflow_id(
            &account.config,
            request.session_id,
            HnsSettlementAction::Lock,
        );
        let mut store = self.store_lock().map_err(map_chain_error)?;
        if let Some(stored) = store
            .load_workflow::<HnsPreparedSettlement>(workflow_id)
            .map_err(map_chain_error)?
        {
            let expected_terms = HnsSettlementTerms::Lock {
                request: request.clone(),
            };
            if stored.kind != settlement_workflow_kind(HnsSettlementAction::Lock)
                || stored.state.wallet_id != account.config.wallet_id
                || stored.state.account_id != account.config.account_id
                || stored.state.workflow_id != workflow_id
                || stored.state.session_id != request.session_id
                || stored.state.action != HnsSettlementAction::Lock
                || stored.state.stage != HnsSettlementStage::Prepared
                || stored.state.terms != expected_terms
                || stored.state.maximum_fee != request.maximum_fee
                || stored.state.fee > stored.state.maximum_fee
                || stored.state.expires_at_unix <= now
            {
                return Err(ChainError::InvalidRequest(
                    "persisted Handshake settlement does not match retry",
                ));
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(ChainError::InvalidEvidence)?;
            let input_coins =
                canonical_evidence_coins(&stored.state.input_coins).map_err(map_chain_error)?;
            validate_final_fee_quote(
                &stored.state.signed_transaction,
                &input_coins,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.fee,
                stored.state.maximum_fee,
            )
            .map_err(map_chain_error)?;
            let artifact =
                Self::prepared_settlement_artifact(&stored.state).map_err(map_chain_error)?;
            let transaction = Transaction::decode(&stored.state.signed_transaction)
                .map_err(|_| ChainError::InvalidEvidence)?;
            let outpoints: Vec<HnsOutpoint> = transaction
                .inputs
                .iter()
                .map(|input| {
                    if input.previous_output.is_null() {
                        return Err(ChainError::InvalidEvidence);
                    }
                    Ok(HnsOutpoint {
                        transaction: TransactionHash::new(
                            input.previous_output.transaction_hash.into_bytes(),
                        ),
                        output_index: input.previous_output.index,
                    })
                })
                .collect::<Result<_, _>>()?;
            validate_prepared_reservations(
                &store,
                &account.config,
                workflow_id,
                &outpoints,
                stored.state.expires_at_unix,
            )
            .map_err(map_chain_error)?;
            let committed_account = store
                .wallet_account::<HnsAccountRecord>(&account_entity_id(&account.config))
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            self.install_loaded_account(committed_account)
                .map_err(map_chain_error)?;
            return Ok(PreparedSettlementLock(artifact));
        }
        let receiver = decode_compressed_key(&request.receiver)?;
        let refund = decode_compressed_key(&request.refund_target)?;
        let script = hns_htlc_script(
            request.hashlock,
            &receiver,
            &refund,
            request.absolute_timelock,
        )?;
        let lock_address = Address::new(0, Sha3_256::digest(&script).to_vec())
            .map_err(|_| ChainError::InvalidRequest("invalid Handshake HTLC address"))?;
        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let coins = available_unreserved_coins(&mut store, &account.config, coins, now)
            .map_err(map_chain_error)?;
        let change_public =
            derive_hns_public_key(&store, account.config.wallet_id, change_derivation)
                .map_err(map_chain_error)?;
        let change = Address::new(
            0,
            public_key_hash(&change_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidRequest("invalid change address"))?;
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let (transaction, selected, fee) = build_unsigned_payment(
            coins,
            lock_address,
            change,
            request.amount.base_units,
            fee_rate,
            request.maximum_fee,
            account.config.dust_threshold,
        )
        .map_err(map_chain_error)?;
        let policy_input_evidence = input_coin_evidence(&selected).map_err(map_chain_error)?;
        let plan = HnsSpendPlan {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            request_nonce: 0,
            unsigned_transaction: transaction
                .encode()
                .map_err(|_| ChainError::InvalidTransactionSize)?,
            inputs: selected,
            amount: request.amount.base_units,
            fee,
            maximum_fee: request.maximum_fee,
            destination: hex::encode(Sha3_256::digest(&script)),
            expires_at_unix: now
                .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
                .ok_or(ChainError::Overflow)?,
        };
        let reservation_saves = reservation_saves(
            &account.config,
            workflow_id,
            &plan.inputs,
            plan.expires_at_unix,
            now,
        )
        .map_err(map_chain_error)?;
        let signed = sign_payment_plan(&store, &account, &plan).map_err(map_chain_error)?;
        validate_signed_payment_plan(&plan, &signed).map_err(map_chain_error)?;
        let input_coins = canonical_input_coins(&plan.inputs).map_err(map_chain_error)?;
        drop(store);
        let quote = self
            .quote_final_transaction(&signed, &input_coins, fee, request.maximum_fee)
            .map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        if cache.account != account {
            return Err(ChainError::InvalidEvidence);
        }
        let account_revision = cache.account_revision;
        drop(cache);
        let account_save =
            Self::change_account_save(&account, account_revision, change_derivation.index, now)
                .map_err(map_chain_error)?;
        let artifact = self
            .persist_prepared_settlement(
                request.session_id,
                HnsSettlementAction::Lock,
                signed,
                policy_input_evidence,
                fee,
                request.maximum_fee,
                quote,
                HnsSettlementTerms::Lock {
                    request: request.clone(),
                },
                &reservation_saves,
                Some(&account_save),
                now,
            )
            .map_err(map_chain_error)?;
        Ok(PreparedSettlementLock(artifact))
    }

    fn verify_lock(
        &self,
        request: VerifySettlementLockRequest,
    ) -> Result<VerifiedSettlementLock, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let configured_minimum = cache.account.config.minimum_confirmations;
        let binding = cache.binding.ok_or(ChainError::NotSynchronized)?;
        let mempool_binding = cache.mempool_binding.ok_or(ChainError::NotSynchronized)?;
        let config = cache.account.config.clone();
        drop(cache);
        if request.expected.module != ModuleId::Handshake
            || request.expected.amount.asset != WalletAsset::Hns
            || request.expected.absolute_timelock == 0
            || request.expected.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
            || request.expected.minimum_confirmations < configured_minimum
            || request.confirmation_count < request.expected.minimum_confirmations
            || request.confirmation_count < configured_minimum
        {
            return Err(ChainError::InvalidEvidence);
        }
        let receiver = decode_compressed_key(&request.expected.receiver)?;
        let refund = decode_compressed_key(&request.expected.refund_target)?;
        let script = hns_htlc_script(
            request.expected.hashlock,
            &receiver,
            &refund,
            request.expected.absolute_timelock,
        )?;
        let program = Sha3_256::digest(&script).to_vec();
        let transaction = Transaction::decode(&request.transaction_or_receipt)
            .map_err(|_| ChainError::InvalidEvidence)?;
        if transaction.is_coinbase() {
            return Err(ChainError::InvalidEvidence);
        }
        let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
        let evidence = self
            .backend
            .get_transaction_evidence(txid, binding, Some(mempool_binding))
            .map_err(map_chain_error)?;
        if evidence.binding != binding
            || evidence.mempool != mempool_binding
            || evidence.raw.as_deref() != Some(request.transaction_or_receipt.as_slice())
        {
            return Err(ChainError::InvalidEvidence);
        }
        let status = evidence.status;
        if status.conflicted || status.confirmation_count != request.confirmation_count {
            return Err(ChainError::InvalidEvidence);
        }
        let inclusion = evidence.inclusion.ok_or(ChainError::InvalidEvidence)?;
        if inclusion.height > binding.tip.height
            || u64::from(status.confirmation_count) != binding.tip.height - inclusion.height + 1
        {
            return Err(ChainError::InvalidEvidence);
        }
        let amount = u64::try_from(request.expected.amount.base_units.get())
            .map_err(|_| ChainError::InvalidEvidence)?;
        let matches: Vec<usize> = transaction
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.value.get() == amount
                    && output.address.version == 0
                    && output.address.hash == program
                    && output.covenant == Covenant::default()
            })
            .map(|(index, _)| index)
            .collect();
        if matches.len() != 1 {
            return Err(ChainError::InvalidEvidence);
        }
        let output_index = u32::try_from(matches[0]).map_err(|_| ChainError::InvalidEvidence)?;
        let funding_output = &transaction.outputs[matches[0]];
        let funding_coin = HnsInputCoinEvidence::from_canonical_coin(&Coin {
            outpoint: Outpoint {
                transaction_hash: CanonicalTransactionHash::new(txid.into_bytes()),
                index: output_index,
            },
            value: funding_output.value,
            height: Height::new(
                u32::try_from(inclusion.height).map_err(|_| ChainError::InvalidEvidence)?,
            ),
            coinbase: false,
            address: funding_output.address.clone(),
            covenant: funding_output.covenant.clone(),
        })
        .map_err(map_chain_error)?;
        let terms =
            serde_json::to_vec(&request.expected).map_err(|_| ChainError::InvalidEvidence)?;
        let mut evidence_hasher = Sha256::new();
        evidence_hasher.update(b"hns-wallet-rs/hns-verified-lock/v1");
        evidence_hasher.update(&request.transaction_or_receipt);
        evidence_hasher.update(inclusion.block_hash);
        evidence_hasher.update(inclusion.height.to_be_bytes());
        evidence_hasher.update(output_index.to_be_bytes());
        evidence_hasher.update(
            u64::try_from(terms.len())
                .map_err(|_| ChainError::InvalidEvidence)?
                .to_be_bytes(),
        );
        evidence_hasher.update(&terms);
        evidence_hasher.update(&script);
        let evidence_hash: [u8; 32] = evidence_hasher.finalize().into();
        let verified = VerifiedLock {
            module: ModuleId::Handshake,
            session_id: request.expected.session_id,
            funding_id: txid,
            amount: request.expected.amount,
            hashlock: request.expected.hashlock,
            absolute_timelock: request.expected.absolute_timelock,
            confirmation_count: request.confirmation_count,
            evidence_hash: ObjectHash::new(evidence_hash),
        };
        let record = HnsVerifiedSettlementRecord {
            expected: request.expected,
            verified: verified.clone(),
            output_index,
            script,
            funding_coin: Some(funding_coin),
        };
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let id = settlement_entity_id(&config, record.expected.session_id);
        match store
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&id)
            .map_err(map_chain_error)?
        {
            Some(stored) if stored.value == record => {
                return Ok(VerifiedSettlementLock(stored.value.verified));
            }
            Some(stored)
                if same_verified_settlement_binding(&stored.value, &record)
                    && record.verified.confirmation_count
                        >= stored.value.verified.confirmation_count =>
            {
                store
                    .save_hns_verified_settlement(&id, stored.revision, &record, now)
                    .map_err(map_chain_error)?;
            }
            Some(_) => return Err(ChainError::InvalidEvidence),
            None => {
                store
                    .save_hns_verified_settlement(&id, 0, &record, now)
                    .map_err(map_chain_error)?;
            }
        }
        Ok(VerifiedSettlementLock(verified))
    }

    fn prepare_redeem(
        &self,
        request: SettlementRedeemRequest,
    ) -> Result<PreparedSettlementRedeem, ChainError> {
        let expected_hash: [u8; 32] =
            Sha256::digest(request.preimage.expose_for_settlement()).into();
        if expected_hash != *request.lock.hashlock.as_bytes() {
            return Err(ChainError::InvalidEvidence);
        }
        self.prepare_settlement_spend(
            request.session_id,
            request.lock,
            Some(request.preimage),
            request.maximum_fee,
            None,
            HnsSettlementAction::Redeem,
        )
        .map(PreparedSettlementRedeem)
    }

    fn prepare_refund(
        &self,
        request: SettlementRefundRequest,
    ) -> Result<PreparedSettlementRefund, ChainError> {
        if request.current_chain_time >= HNS_LOCKTIME_THRESHOLD
            || request.lock.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
            || request.current_chain_time < request.lock.absolute_timelock
        {
            return Err(ChainError::InvalidRequest("refund timelock is not mature"));
        }
        self.prepare_settlement_spend(
            request.session_id,
            request.lock,
            None,
            request.maximum_fee,
            Some(request.current_chain_time),
            HnsSettlementAction::Refund,
        )
        .map(PreparedSettlementRefund)
    }

    fn observe_secret(
        &self,
        request: ObserveSecretRequest,
    ) -> Result<Option<Preimage>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let binding = cache.binding.ok_or(ChainError::NotSynchronized)?;
        let mempool_binding = cache.mempool_binding.ok_or(ChainError::NotSynchronized)?;
        let config = cache.account.config.clone();
        drop(cache);
        let record = self
            .store_lock()
            .map_err(map_chain_error)?
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&settlement_entity_id(
                &config,
                request.session_id,
            ))
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?
            .value;
        if record.expected.session_id != request.session_id
            || record.expected.hashlock != request.hashlock
        {
            return Err(ChainError::InvalidEvidence);
        }
        let evidence = self
            .backend
            .get_transaction_evidence(request.spending_transaction, binding, Some(mempool_binding))
            .map_err(map_chain_error)?;
        if evidence.binding != binding || evidence.mempool != mempool_binding {
            return Err(ChainError::InvalidEvidence);
        }
        let status = evidence.status;
        if status.conflicted || (!status.in_mempool && status.confirmation_count == 0) {
            return Ok(None);
        }
        let raw = evidence.raw.ok_or(ChainError::InvalidEvidence)?;
        let transaction = decode_transaction_for_id(&raw, request.spending_transaction)
            .map_err(map_chain_error)?;
        let expected_outpoint = Outpoint {
            transaction_hash: CanonicalTransactionHash::new(
                record.verified.funding_id.into_bytes(),
            ),
            index: record.output_index,
        };
        let mut matching_input = None;
        for input in &transaction.inputs {
            if input.previous_output != expected_outpoint {
                continue;
            }
            if matching_input.replace(input).is_some() {
                return Err(ChainError::InvalidEvidence);
            }
        }
        let Some(input) = matching_input else {
            return Err(ChainError::InvalidEvidence);
        };
        if input.witness.items.len() != 4
            || input.witness.items[0].len() != 65
            || input.witness.items[1].len() != Preimage::LENGTH
            || input.witness.items[2].is_empty()
            || input.witness.items[3] != record.script
        {
            return Err(ChainError::InvalidEvidence);
        }
        let digest: [u8; 32] = Sha256::digest(&input.witness.items[1]).into();
        if digest != *record.expected.hashlock.as_bytes() {
            return Err(ChainError::InvalidEvidence);
        }
        let bytes: [u8; 32] = input.witness.items[1]
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidEvidence)?;
        Ok(Some(Preimage::new(bytes)))
    }
}

fn ensure_ready(cache: &HnsRuntimeCache) -> Result<(), ChainError> {
    if cache.sync.phase == SyncPhase::Ready
        && cache.sync.validated_height == cache.sync.scanned_height
    {
        Ok(())
    } else {
        Err(ChainError::NotSynchronized)
    }
}

fn map_chain_error<E>(error: E) -> ChainError
where
    HnsWalletError: From<E>,
{
    let error = HnsWalletError::from(error);
    match error {
        HnsWalletError::StoreLocked | HnsWalletError::MissingSeed => ChainError::Locked,
        HnsWalletError::MainnetDisabled | HnsWalletError::RuntimeIntegrationUnavailable => {
            ChainError::Disabled
        }
        HnsWalletError::InvalidAmount
        | HnsWalletError::InvalidAddress
        | HnsWalletError::InvalidPreparedArtifact
        | HnsWalletError::PreparedArtifactExpired
        | HnsWalletError::InvalidRuntimeConfiguration => {
            ChainError::InvalidRequest("invalid Handshake wallet request")
        }
        HnsWalletError::Arithmetic => ChainError::Overflow,
        HnsWalletError::FeeLimit => ChainError::FeeLimit,
        HnsWalletError::InsufficientFunds => {
            ChainError::InvalidRequest("insufficient Handshake funds")
        }
        HnsWalletError::InvalidEvidence
        | HnsWalletError::NameNotOwned
        | HnsWalletError::StaleNodeSnapshot
        | HnsWalletError::FeeQuoteInputUnavailable
        | HnsWalletError::InvalidFeeQuoteTransaction
        | HnsWalletError::InvalidFeeQuote => ChainError::InvalidEvidence,
        HnsWalletError::Store => ChainError::Backend("wallet store failed".to_owned()),
        _ => ChainError::Backend("Handshake wallet runtime failed".to_owned()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HnsLocalFeePolicyEvidence {
    transaction_weight: usize,
    transaction_sigops: u32,
    policy_virtual_size: usize,
    minimum_fee: BaseUnits,
}

fn local_fee_policy_evidence(
    transaction: &Transaction,
    input_coins: &[Coin],
    rate_atomic_units_per_1000_policy_vbytes: BaseUnits,
) -> Result<HnsLocalFeePolicyEvidence, HnsWalletError> {
    if transaction.inputs.is_empty()
        || transaction.is_coinbase()
        || transaction.inputs.len() != input_coins.len()
        || rate_atomic_units_per_1000_policy_vbytes.is_zero()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let transaction_weight = transaction
        .weight()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let transaction_weight_u32 = u32::try_from(transaction_weight)
        .map_err(|_| HnsWalletError::InvalidFeeQuoteTransaction)?;
    let transaction_sigops = transaction_sigops(transaction, input_coins)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if transaction_weight_u32 > MAX_POLICY_TRANSACTION_WEIGHT.get()
        || transaction_sigops > MAX_POLICY_TRANSACTION_SIGOPS.get()
    {
        return Err(HnsWalletError::InvalidFeeQuoteTransaction);
    }
    let policy_virtual_size = transaction_policy_virtual_size(transaction, input_coins)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let rate = u32::try_from(rate_atomic_units_per_1000_policy_vbytes.get())
        .map_err(|_| HnsWalletError::InvalidFeeQuote)?;
    let minimum_fee = minimum_policy_fee(policy_virtual_size, FeeRate::new(rate))
        .map_err(|_| HnsWalletError::Arithmetic)?;
    let policy_virtual_size = usize::try_from(policy_virtual_size.get())
        .map_err(|_| HnsWalletError::InvalidFeeQuoteTransaction)?;
    Ok(HnsLocalFeePolicyEvidence {
        transaction_weight,
        transaction_sigops,
        policy_virtual_size,
        minimum_fee: BaseUnits::new(u128::from(minimum_fee.get())),
    })
}

fn actual_transaction_fee(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<BaseUnits, HnsWalletError> {
    if transaction.inputs.len() != input_coins.len()
        || transaction
            .inputs
            .iter()
            .zip(input_coins)
            .any(|(input, coin)| input.previous_output != coin.outpoint)
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let inputs = input_coins.iter().try_fold(0_u128, |total, coin| {
        total
            .checked_add(u128::from(coin.value.get()))
            .ok_or(HnsWalletError::Arithmetic)
    })?;
    let outputs = transaction
        .outputs
        .iter()
        .try_fold(0_u128, |total, output| {
            total
                .checked_add(u128::from(output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)
        })?;
    let fee = inputs
        .checked_sub(outputs)
        .ok_or(HnsWalletError::InvalidEvidence)?;
    Ok(BaseUnits::new(fee))
}

pub(crate) fn validate_local_fee_quote_evidence(
    transaction: &Transaction,
    input_coins: &[Coin],
    quote: &HnsTransactionFeeQuote,
) -> Result<(), HnsWalletError> {
    let local = local_fee_policy_evidence(
        transaction,
        input_coins,
        BaseUnits::new(u128::from(quote.rate_atomic_units_per_1000_policy_vbytes)),
    )?;
    let actual_fee = actual_transaction_fee(transaction, input_coins)?;
    let shortfall = local.minimum_fee.get().saturating_sub(actual_fee.get());
    if quote.transaction_weight != local.transaction_weight
        || quote.transaction_sigops != local.transaction_sigops
        || quote.sigop_adjusted_policy_vbytes != local.policy_virtual_size
        || quote.minimum_policy_fee != local.minimum_fee
        || quote.actual_fee != actual_fee
        || quote.meets_minimum_policy_fee != (actual_fee >= local.minimum_fee)
        || quote.minimum_policy_fee_shortfall.get() != shortfall
    {
        return Err(HnsWalletError::InvalidFeeQuote);
    }
    Ok(())
}

fn validate_final_fee_quote(
    raw: &[u8],
    input_coins: &[Coin],
    quote: &HnsTransactionFeeQuote,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    validate_final_fee_quote_evidence(
        raw,
        input_coins,
        quote,
        binding,
        mempool,
        expected_fee,
        maximum_fee,
    )?;
    if !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED {
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
    }
    Ok(())
}

fn validate_final_fee_quote_evidence(
    raw: &[u8],
    input_coins: &[Coin],
    quote: &HnsTransactionFeeQuote,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    let transaction =
        Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != raw
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let txid = wallet_transaction_hash(&transaction)?;
    validate_local_fee_quote_evidence(&transaction, input_coins, quote)?;
    if maximum_fee.is_zero()
        || expected_fee > maximum_fee
        || quote.txid != txid
        || quote.binding != binding
        || quote.mempool != mempool
        || quote.target_blocks != DEFAULT_FEE_TARGET_BLOCKS
        || quote.transaction_weight == 0
        || quote.sigop_adjusted_policy_vbytes == 0
        || quote.rate_atomic_units_per_1000_policy_vbytes == 0
        || quote.actual_fee != expected_fee
        || quote.minimum_policy_fee > quote.actual_fee
        || !quote.meets_minimum_policy_fee
        || !quote.minimum_policy_fee_shortfall.is_zero()
    {
        return Err(HnsWalletError::InvalidFeeQuote);
    }
    match quote.rate_source {
        HnsFeeRateSource::MinimumRelay if quote.rate_sample_count == 0 => {}
        HnsFeeRateSource::Mempool | HnsFeeRateSource::PeerRelay if quote.rate_sample_count > 0 => {}
        _ => return Err(HnsWalletError::InvalidFeeQuote),
    }
    Ok(())
}

fn validate_witness_only_change(
    unsigned: &Transaction,
    signed_raw: &[u8],
) -> Result<Transaction, HnsWalletError> {
    let signed =
        Transaction::decode(signed_raw).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if signed
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != signed_raw
        || unsigned.version != signed.version
        || unsigned.outputs != signed.outputs
        || unsigned.locktime != signed.locktime
        || unsigned.inputs.len() != signed.inputs.len()
        || unsigned
            .inputs
            .iter()
            .zip(&signed.inputs)
            .any(|(left, right)| {
                left.previous_output != right.previous_output || left.sequence != right.sequence
            })
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    Ok(signed)
}

fn validate_signed_payment_plan(
    plan: &HnsSpendPlan,
    signed_raw: &[u8],
) -> Result<Transaction, HnsWalletError> {
    let unsigned = Transaction::decode(&plan.unsigned_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    validate_witness_only_change(&unsigned, signed_raw)
}

fn decode_hns_address(network: HnsNetwork, value: &str) -> Result<Address, HnsWalletError> {
    let (hrp, version, program) =
        segwit::decode(value).map_err(|_| HnsWalletError::InvalidAddress)?;
    let expected = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::InvalidAddress)?;
    if hrp != expected {
        return Err(HnsWalletError::InvalidAddress);
    }
    Address::new(version.to_u8(), program).map_err(|_| HnsWalletError::InvalidAddress)
}

fn build_unsigned_payment(
    mut coins: Vec<TrackedHnsCoin>,
    destination: Address,
    change: Address,
    amount: BaseUnits,
    fee_rate: BaseUnits,
    maximum_fee: BaseUnits,
    dust_threshold: BaseUnits,
) -> Result<(Transaction, Vec<TrackedHnsCoin>, BaseUnits), HnsWalletError> {
    let amount = u64::try_from(amount.get()).map_err(|_| HnsWalletError::InvalidAmount)?;
    if amount == 0 || fee_rate.is_zero() || maximum_fee.is_zero() {
        return Err(HnsWalletError::InvalidAmount);
    }
    coins.retain(|coin| is_ordinary_hns_spend_candidate(coin) && coin.coin.confirmation_count > 0);
    coins.sort_by(|left, right| {
        left.coin
            .value
            .cmp(&right.coin.value)
            .then_with(|| left.coin.outpoint.cmp(&right.coin.outpoint))
    });
    let mut selected = Vec::new();
    let mut total = 0_u128;
    for coin in coins {
        total = total
            .checked_add(coin.coin.value.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        selected.push(coin);
        let provisional = unsigned_payment_transaction(
            &selected,
            destination.clone(),
            Some((change.clone(), 1)),
            amount,
        )?;
        let input_coins = canonical_input_coins(&selected)?;
        let change_fee = canonical_policy_minimum_fee(&provisional, &input_coins, fee_rate)?;
        let required = u128::from(amount)
            .checked_add(change_fee.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        if total < required {
            continue;
        }
        let change_value = total - required;
        if change_value >= dust_threshold.get() {
            if change_fee > maximum_fee {
                return Err(HnsWalletError::FeeLimit);
            }
            let change_value =
                u64::try_from(change_value).map_err(|_| HnsWalletError::InvalidAmount)?;
            let transaction = unsigned_payment_transaction(
                &selected,
                destination.clone(),
                Some((change.clone(), change_value)),
                amount,
            )?;
            return Ok((transaction, selected, change_fee));
        }

        let no_change = unsigned_payment_transaction(&selected, destination.clone(), None, amount)?;
        let minimum_fee = canonical_policy_minimum_fee(&no_change, &input_coins, fee_rate)?;
        let actual_fee = BaseUnits::new(total - u128::from(amount));
        if actual_fee >= minimum_fee && actual_fee <= maximum_fee {
            return Ok((no_change, selected, actual_fee));
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

fn unsigned_payment_transaction(
    selected: &[TrackedHnsCoin],
    destination: Address,
    change: Option<(Address, u64)>,
    amount: u64,
) -> Result<Transaction, HnsWalletError> {
    let inputs = selected
        .iter()
        .map(|coin| Input {
            previous_output: Outpoint {
                transaction_hash: CanonicalTransactionHash::new(
                    coin.coin.outpoint.transaction.into_bytes(),
                ),
                index: coin.coin.outpoint.output_index,
            },
            sequence: u32::MAX,
            witness: Witness {
                items: vec![vec![0; 65], vec![0; 33]],
            },
        })
        .collect();
    let mut outputs = vec![Output {
        value: Dollarydoos::new(amount),
        address: destination,
        covenant: Covenant::default(),
    }];
    if let Some((address, value)) = change {
        outputs.push(Output {
            value: Dollarydoos::new(value),
            address,
            covenant: Covenant::default(),
        });
    }
    Ok(Transaction {
        version: 0,
        inputs,
        outputs,
        locktime: 0,
    })
}

fn canonical_policy_minimum_fee(
    transaction: &Transaction,
    input_coins: &[Coin],
    unqualified_node_rate_per_policy_kvb: BaseUnits,
) -> Result<BaseUnits, HnsWalletError> {
    local_fee_policy_evidence(
        transaction,
        input_coins,
        unqualified_node_rate_per_policy_kvb,
    )
    .map(|evidence| evidence.minimum_fee)
}

fn sign_payment_plan(
    store: &WalletStore,
    account: &HnsAccountRecord,
    plan: &HnsSpendPlan,
) -> Result<Vec<u8>, HnsWalletError> {
    let transaction = Transaction::decode(&plan.unsigned_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let expected_roles = vec![KeyRole::HnsCoin; plan.inputs.len()];
    sign_ordered_p2pkh_inputs(store, account, transaction, &plan.inputs, &expected_roles)
}

fn sign_ordered_p2pkh_inputs(
    store: &WalletStore,
    account: &HnsAccountRecord,
    transaction: Transaction,
    inputs: &[TrackedHnsCoin],
    expected_roles: &[KeyRole],
) -> Result<Vec<u8>, HnsWalletError> {
    sign_ordered_p2pkh_inputs_from(store, account, transaction, 0, inputs, expected_roles)
}

fn sign_ordered_p2pkh_inputs_from(
    store: &WalletStore,
    account: &HnsAccountRecord,
    mut transaction: Transaction,
    input_offset: usize,
    inputs: &[TrackedHnsCoin],
    expected_roles: &[KeyRole],
) -> Result<Vec<u8>, HnsWalletError> {
    if inputs.is_empty()
        || input_offset >= transaction.inputs.len()
        || transaction.inputs.len() - input_offset != inputs.len()
        || inputs.len() != expected_roles.len()
        || transaction.inputs.len() > MAX_TRANSACTION_INPUTS
        || inputs.len() > MAX_TRANSACTION_INPUTS
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    for (offset, (coin, expected_role)) in inputs.iter().zip(expected_roles).enumerate() {
        let index = input_offset
            .checked_add(offset)
            .ok_or(HnsWalletError::Arithmetic)?;
        let expected_tag = match *expected_role {
            KeyRole::HnsCoin => HNS_COIN_DERIVATION_TAG,
            KeyRole::HnsName => HNS_NAME_DERIVATION_TAG,
            _ => return Err(HnsWalletError::InvalidPreparedArtifact),
        };
        let (actual_tag, _, _) = restore_derivation_key(coin.derivation)?;
        if coin.derivation.role != *expected_role
            || coin.derivation.account != account_number(account)
            || actual_tag != expected_tag
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let canonical = coin.to_canonical_coin()?;
        if transaction.inputs[index].previous_output != canonical.outpoint
            || canonical.address.version != 0
            || canonical.address.hash != coin.address_program
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let secret = derive_secret(&seed, coin.derivation)?;
        let signing =
            SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
        let public = signing.verifying_key().to_encoded_point(true);
        let public_bytes: [u8; 33] = public
            .as_bytes()
            .try_into()
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if public_key_hash(&public_bytes)?.as_slice() != coin.address_program {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let previous_value = canonical.value.get();
        let script = p2pkh_script(&coin.address_program)?;
        let digest = signature_hash(&transaction, index, &script, previous_value, SIGHASH_ALL)
            .map_err(|_| HnsWalletError::Signing)?;
        let signature: Signature = signing
            .sign_prehash(&digest)
            .map_err(|_| HnsWalletError::Signing)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut encoded = signature.to_bytes().to_vec();
        encoded.push(SIGHASH_ALL as u8);
        transaction.inputs[index].witness = Witness {
            items: vec![encoded, public.as_bytes().to_vec()],
        };
    }
    transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

fn p2pkh_script(program: &[u8]) -> Result<Vec<u8>, HnsWalletError> {
    if program.len() != 20 {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
    script.extend_from_slice(program);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    Ok(script)
}

fn wallet_transaction_hash(transaction: &Transaction) -> Result<TransactionHash, HnsWalletError> {
    transaction
        .transaction_hash()
        .map(|hash| TransactionHash::new(hash.into_bytes()))
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

fn send_workflow_id(config: &HnsRuntimeConfig, request_nonce: u64) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/hns-send-workflow/v1");
    hasher.update(account_entity_prefix(config));
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn ensure_settlement_ready(cache: &HnsRuntimeCache) -> Result<(), ChainError> {
    ensure_ready(cache)?;
    if cache.account.config.settlement_enabled {
        Ok(())
    } else {
        Err(ChainError::Disabled)
    }
}

fn validate_settlement_request(request: &SettlementLockRequest) -> Result<(), ChainError> {
    if request.module != ModuleId::Handshake
        || request.amount.asset != WalletAsset::Hns
        || request.amount.base_units.is_zero()
        || request.maximum_fee.is_zero()
        || request.absolute_timelock == 0
        || request.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
    {
        return Err(ChainError::InvalidRequest(
            "invalid Handshake settlement terms",
        ));
    }
    Ok(())
}

fn decode_compressed_key(value: &str) -> Result<[u8; 33], ChainError> {
    let mut key = [0_u8; 33];
    hex::decode_to_slice(value, &mut key)
        .map_err(|_| ChainError::InvalidRequest("invalid compressed settlement key"))?;
    VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| ChainError::InvalidRequest("invalid compressed settlement key"))?;
    Ok(key)
}

fn hns_htlc_script(
    hashlock: ObjectHash,
    receiver: &[u8; 33],
    refund: &[u8; 33],
    absolute_timelock: u64,
) -> Result<Vec<u8>, ChainError> {
    let timelock = u32::try_from(absolute_timelock)
        .map_err(|_| ChainError::InvalidRequest("Handshake timelock exceeds u32"))?;
    let encoded_timelock = encode_script_number(u64::from(timelock));
    let mut script = Vec::with_capacity(114);
    script.extend_from_slice(&[OP_IF, OP_SHA256, 32]);
    script.extend_from_slice(hashlock.as_bytes());
    script.extend_from_slice(&[OP_EQUALVERIFY, 33]);
    script.extend_from_slice(receiver);
    script.extend_from_slice(&[OP_ELSE, encoded_timelock.len() as u8]);
    script.extend_from_slice(&encoded_timelock);
    script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]);
    script.extend_from_slice(refund);
    script.extend_from_slice(&[OP_ENDIF, OP_CHECKSIG]);
    Ok(script)
}

fn encode_script_number(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut encoded = Vec::new();
    while value > 0 {
        encoded.push(value as u8);
        value >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

fn derive_settlement_secret(
    seed: &[u8],
    account: &HnsAccountRecord,
    session_id: SessionId,
    refund: bool,
) -> Result<Zeroizing<[u8; 32]>, HnsWalletError> {
    let mut context = Sha256::new();
    context.update(HNS_SETTLEMENT_KEY_DOMAIN);
    context.update(account_number(account).to_be_bytes());
    context.update(session_id.as_bytes());
    context.update([u8::from(refund)]);
    let context: [u8; 32] = context.finalize().into();
    for counter in 0_u8..=u8::MAX {
        let mut info = Vec::with_capacity(context.len() + 1);
        info.extend_from_slice(&context);
        info.push(counter);
        let hkdf = Hkdf::<Sha256>::new(Some(b"Handshake atomic settlement role"), seed);
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if SigningKey::from_slice(candidate.as_slice()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(HnsWalletError::KeyDerivation)
}

fn derive_settlement_public_key(
    store: &WalletStore,
    account: &HnsAccountRecord,
    session_id: SessionId,
    refund: bool,
) -> Result<[u8; 33], HnsWalletError> {
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_settlement_secret(&seed, account, session_id, refund)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    signing
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| HnsWalletError::KeyDerivation)
}

fn settlement_workflow_id(
    config: &HnsRuntimeConfig,
    session_id: SessionId,
    action: HnsSettlementAction,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/hns-settlement-workflow/v1");
    hasher.update(account_entity_prefix(config));
    hasher.update(session_id.as_bytes());
    hasher.update([match action {
        HnsSettlementAction::Lock => 0,
        HnsSettlementAction::Redeem => 1,
        HnsSettlementAction::Refund => 2,
    }]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn settlement_workflow_kind(action: HnsSettlementAction) -> WorkflowKind {
    if action == HnsSettlementAction::Refund {
        WorkflowKind::Refund
    } else {
        WorkflowKind::AtomicSwap
    }
}

fn same_prepared_settlement(
    stored: &HnsPreparedSettlement,
    artifact: &HnsPreparedSettlement,
) -> bool {
    stored.wallet_id == artifact.wallet_id
        && stored.account_id == artifact.account_id
        && stored.workflow_id == artifact.workflow_id
        && stored.session_id == artifact.session_id
        && stored.action == artifact.action
        && artifact.stage == HnsSettlementStage::Prepared
        && stored.transaction == artifact.transaction
        && stored.signed_transaction == artifact.signed_transaction
        && stored.input_coins == artifact.input_coins
        && stored.fee == artifact.fee
        && stored.maximum_fee == artifact.maximum_fee
        && stored.expires_at_unix == artifact.expires_at_unix
        && stored.terms == artifact.terms
}

fn same_verified_settlement_binding(
    stored: &HnsVerifiedSettlementRecord,
    candidate: &HnsVerifiedSettlementRecord,
) -> bool {
    stored.expected == candidate.expected
        && stored.output_index == candidate.output_index
        && stored.script == candidate.script
        && stored.funding_coin == candidate.funding_coin
        && stored.verified.module == candidate.verified.module
        && stored.verified.session_id == candidate.verified.session_id
        && stored.verified.funding_id == candidate.verified.funding_id
        && stored.verified.amount == candidate.verified.amount
        && stored.verified.hashlock == candidate.verified.hashlock
        && stored.verified.absolute_timelock == candidate.verified.absolute_timelock
        && stored.verified.evidence_hash == candidate.verified.evidence_hash
}

fn settlement_entity_id(config: &HnsRuntimeConfig, session_id: SessionId) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(session_id.as_bytes());
    id
}

// All parameters contribute directly to the signed HTLC witness and remain
// explicit so callers cannot accidentally reuse a partially bound context.
#[allow(clippy::too_many_arguments)]
fn sign_htlc_spend(
    store: &WalletStore,
    account: &HnsAccountRecord,
    mut transaction: Transaction,
    session_id: SessionId,
    script: &[u8],
    previous_value: u64,
    preimage: Option<&Preimage>,
    refund: bool,
) -> Result<Vec<u8>, HnsWalletError> {
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_settlement_secret(&seed, account, session_id, refund)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    let digest = signature_hash(&transaction, 0, script, previous_value, SIGHASH_ALL)
        .map_err(|_| HnsWalletError::Signing)?;
    let signature: Signature = signing
        .sign_prehash(&digest)
        .map_err(|_| HnsWalletError::Signing)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(SIGHASH_ALL as u8);
    transaction.inputs[0].witness = if refund {
        Witness {
            items: vec![encoded, Vec::new(), script.to_vec()],
        }
    } else {
        let preimage = preimage.ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        Witness {
            items: vec![
                encoded,
                preimage.expose_for_settlement().to_vec(),
                vec![1],
                script.to_vec(),
            ],
        }
    };
    transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

#[derive(Debug, Error)]
pub enum HnsWalletError {
    #[error("wallet store failed")]
    Store,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("wallet recovery seed is unavailable")]
    MissingSeed,
    #[error("key role does not belong to Handshake")]
    WrongKeyRole,
    #[error("deterministic key derivation failed")]
    KeyDerivation,
    #[error("Handshake address encoding failed")]
    Address,
    #[error("invalid Handshake address or network")]
    InvalidAddress,
    #[error("amount or coin count is invalid")]
    InvalidAmount,
    #[error("checked arithmetic failed")]
    Arithmetic,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("fee exceeds the approved maximum")]
    FeeLimit,
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("name proof or ownership evidence is invalid")]
    InvalidEvidence,
    #[error("invalid persisted name workflow")]
    InvalidWorkflow,
    #[error("wallet store must be unlocked")]
    StoreLocked,
    #[error("wallet read runtime does not share the selected store authority")]
    StoreAuthorityMismatch,
    #[error("persisted account configuration does not match")]
    AccountConfigurationMismatch,
    #[error("the selected account or durable read fence changed during synchronization")]
    StaleAccountRead,
    #[error("the HD account component is already assigned in this wallet")]
    DuplicateAccountDerivation,
    #[error("runtime synchronization lock is unavailable")]
    RuntimePoisoned,
    #[error("system clock is unavailable")]
    Clock,
    #[error("restore lookahead or persisted scan progress is invalid")]
    InvalidLookahead,
    #[error("the bounded restore scan cannot preserve a complete trailing gap")]
    ScanCapacityExhausted,
    #[error("the node snapshot, cursor, or mempool generation changed")]
    StaleNodeSnapshot,
    #[error("a fee-quote input is unavailable in the bound node snapshot")]
    FeeQuoteInputUnavailable,
    #[error("the node rejected the transaction as ineligible for a fee quote")]
    InvalidFeeQuoteTransaction,
    #[error("node fee-quote evidence does not match the final transaction")]
    InvalidFeeQuote,
    #[error("the reserved change address was concurrently advanced")]
    StaleAddressReservation,
    #[error("runtime configuration is invalid")]
    InvalidRuntimeConfiguration,
    #[error("mainnet value operations remain disabled by release policy")]
    MainnetDisabled,
    #[error("Handshake value runtime integration has not passed its release gate")]
    RuntimeIntegrationUnavailable,
    #[error("prepared transaction artifact is invalid")]
    InvalidPreparedArtifact,
    #[error("prepared transaction artifact has expired")]
    PreparedArtifactExpired,
    #[error("a fresh trusted approval is required")]
    ApprovalRequired,
    #[error("transaction signing failed")]
    Signing,
    #[error("history result exceeds the configured bound")]
    HistoryLimit,
    #[error("current name owner output is not controlled by this account")]
    NameNotOwned,
    #[error("name transfer is not finalizable before candidate height {eligible_height}")]
    NameFinalizeNotMature { eligible_height: u64 },
    #[error("wallet state encoding failed")]
    Encoding,
    #[error("Handshake backend failed: {0}")]
    Backend(String),
}

impl From<StoreError> for HnsWalletError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

impl From<serde_json::Error> for HnsWalletError {
    fn from(_: serde_json::Error) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{BlockHash, Height, Outpoint as CanonicalOutpoint};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    fn test_runtime_config() -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: WalletId::new([11; 16]),
            account_id: AccountId::new([12; 16]),
            account_derivation_index: 7,
            network: HnsNetwork::Regtest,
            birthday_height: 100,
            restore_lookahead: DEFAULT_RESTORE_LOOKAHEAD,
            minimum_confirmations: 2,
            dust_threshold: BaseUnits::new(DEFAULT_DUST_THRESHOLD),
            value_operations_enabled: false,
            settlement_enabled: false,
        }
    }

    fn twenty_four_word_phrase() -> String {
        Mnemonic::from_entropy(&[0_u8; 32])
            .expect("32-byte BIP-39 entropy")
            .to_string()
    }

    #[test]
    fn native_bootstrap_restores_one_non_value_account_atomically() {
        let phrase = twenty_four_word_phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let policy = HnsBootstrapPolicy::new(HnsNetwork::Regtest, 123);
        let bootstrap = HnsWalletBootstrap::restore(&phrase, policy).expect("prepare restore");

        let mut legacy_store = WalletStore::create(":memory:", "legacy restore passphrase")
            .expect("legacy restore store");
        let legacy_wallet_id =
            restore_wallet(&mut legacy_store, &phrase, 1).expect("legacy restore wallet ID");
        assert_eq!(bootstrap.wallet_id(), legacy_wallet_id);

        let account = bootstrap.account_record();
        assert!(
            account
                .config
                .account_id
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(account.config.account_derivation_index, 0);
        assert_eq!(account.config.network, HnsNetwork::Regtest);
        assert_eq!(account.config.birthday_height, 123);
        assert_eq!(account.config.restore_lookahead, DEFAULT_RESTORE_LOOKAHEAD);
        assert_eq!(account.config.minimum_confirmations, 2);
        assert_eq!(
            account.config.dust_threshold,
            BaseUnits::new(DEFAULT_DUST_THRESHOLD)
        );
        assert!(!account.config.value_operations_enabled);
        assert!(!account.config.settlement_enabled);
        assert_eq!(account.external_scan_end, DEFAULT_RESTORE_LOOKAHEAD - 1);
        assert_eq!(account.internal_scan_end, DEFAULT_RESTORE_LOOKAHEAD - 1);
        assert_eq!(account.name_scan_end, DEFAULT_RESTORE_LOOKAHEAD - 1);
        assert_eq!(account.shakedex_scan_end, DEFAULT_RESTORE_LOOKAHEAD - 1);
        assert!(!account.shakedex_scan_complete);
        assert!(!format!("{bootstrap:?}").contains(&phrase));

        let expected_account = account.clone();
        let mut store = WalletStore::create(":memory:", "native bootstrap passphrase")
            .expect("native bootstrap store");
        assert_eq!(
            bootstrap.persist(&mut store, 5).expect("persist bootstrap"),
            1
        );
        let seed = store
            .get_secret(bootstrap.wallet_id().as_bytes(), SecretKind::RecoverySeed)
            .expect("read seed")
            .expect("seed present");
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase)
            .expect("parse fixture mnemonic");
        assert_eq!(seed.as_slice(), mnemonic.to_seed_normalized("").as_slice());
        let stored = store
            .wallet_account::<HnsAccountRecord>(&account_entity_id(&expected_account.config))
            .expect("read account")
            .expect("account present");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.value, expected_account);

        let displayed = bootstrap
            .into_recovery_phrase()
            .expose_for_dedicated_display();
        assert_eq!(displayed, phrase);
    }

    #[test]
    fn native_bootstrap_requires_24_words_and_rejects_replay() {
        const TWELVE_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let policy = HnsBootstrapPolicy::new(HnsNetwork::Testnet, 456);
        assert!(matches!(
            HnsWalletBootstrap::restore(TWELVE_WORD_PHRASE, policy),
            Err(HnsWalletError::InvalidRecoveryPhrase)
        ));

        // The legacy seed-only API retains its historical support for valid
        // BIP-39 word counts other than 24.
        let mut legacy_store =
            WalletStore::create(":memory:", "legacy twelve-word passphrase").expect("legacy store");
        restore_wallet(&mut legacy_store, TWELVE_WORD_PHRASE, 1)
            .expect("legacy twelve-word restore");

        let phrase = twenty_four_word_phrase();
        let first = HnsWalletBootstrap::restore(&phrase, policy).expect("first bootstrap");
        let second = HnsWalletBootstrap::restore(&phrase, policy).expect("replayed bootstrap");
        let mut store = WalletStore::create(":memory:", "replay bootstrap passphrase")
            .expect("bootstrap store");
        first.persist(&mut store, 2).expect("first persistence");
        assert!(matches!(
            second.persist(&mut store, 3),
            Err(StoreError::BootstrapConflict)
        ));
        let accounts = store
            .wallet_accounts::<HnsAccountRecord>(2)
            .expect("complete account list");
        assert_eq!(accounts.len(), 1);
        assert_eq!(&accounts[0].value, first.account_record());
    }

    #[test]
    fn generated_native_bootstrap_uses_24_words_and_nonzero_account_id() {
        let bootstrap =
            HnsWalletBootstrap::generate(HnsBootstrapPolicy::new(HnsNetwork::Simnet, 0))
                .expect("generated bootstrap");
        assert!(
            bootstrap
                .account_record()
                .config
                .account_id
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        let phrase = bootstrap
            .into_recovery_phrase()
            .expose_for_dedicated_display();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    fn test_derived_address(role: KeyRole, program: u8) -> DerivedHnsAddress {
        let config = test_runtime_config();
        let program_length = if role == KeyRole::HnsShakedex { 32 } else { 20 };
        DerivedHnsAddress {
            account_id: config.account_id,
            derivation: DerivationReference {
                role,
                account: config.account_derivation_index,
                change: 0,
                index: 0,
            },
            address: format!("test-address-{program}"),
            program: vec![program; program_length],
            used: false,
        }
    }

    fn test_snapshot(epoch: u64) -> SnapshotBinding {
        SnapshotBinding {
            tip: ChainTip {
                height: 500,
                block_hash: [21; 32],
                tree_root: [22; 32],
                median_time_past: 1_700_000_000,
            },
            chain_epoch: epoch,
        }
    }

    fn test_mempool(generation: u64) -> MempoolSnapshotBinding {
        MempoolSnapshotBinding {
            instance_nonce: [23; 32],
            generation,
        }
    }

    const PRODUCTION_FOLLOWUP_PASSPHRASE: &str = "correct horse battery staple";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProductionFollowupReadFault {
        Healthy,
        WrongNetwork,
        StaleChain,
        RestartedMempool,
        ChangedAccount,
        LockedStore,
    }

    struct ProductionFollowupReadBackend {
        store: SharedWalletStore,
        account_id: [u8; 32],
        network: HnsNetwork,
        fault: ProductionFollowupReadFault,
        name_history_program: Option<Vec<u8>>,
        incoming_candidates: Vec<IncomingTransferCandidate>,
        finalize_coin: Option<(WalletAddressKey, Coin)>,
        active_owner: Option<([u8; 32], ActiveNameOwnerCoinEvidence)>,
        snapshot_calls: AtomicUsize,
        tip_calls: AtomicUsize,
        confirmed_calls: AtomicUsize,
        mempool_calls: AtomicUsize,
    }

    impl ProductionFollowupReadBackend {
        fn new(
            store: SharedWalletStore,
            config: &HnsRuntimeConfig,
            fault: ProductionFollowupReadFault,
        ) -> Self {
            Self {
                store,
                account_id: account_entity_id(config),
                network: config.network,
                fault,
                name_history_program: None,
                incoming_candidates: Vec::new(),
                finalize_coin: None,
                active_owner: None,
                snapshot_calls: AtomicUsize::new(0),
                tip_calls: AtomicUsize::new(0),
                confirmed_calls: AtomicUsize::new(0),
                mempool_calls: AtomicUsize::new(0),
            }
        }

        fn with_name_history_program(mut self, program: Vec<u8>) -> Self {
            self.name_history_program = Some(program);
            self
        }

        fn with_incoming_candidate(mut self, candidate: IncomingTransferCandidate) -> Self {
            self.incoming_candidates = vec![candidate];
            self
        }

        fn with_incoming_candidates(mut self, candidates: Vec<IncomingTransferCandidate>) -> Self {
            self.incoming_candidates = candidates;
            self
        }

        fn with_finalize_owner(
            mut self,
            script: WalletAddressKey,
            coin: Coin,
            name_hash: [u8; 32],
            evidence: ActiveNameOwnerCoinEvidence,
        ) -> Self {
            self.finalize_coin = Some((script, coin));
            self.active_owner = Some((name_hash, evidence));
            self
        }

        fn binding() -> SnapshotBinding {
            SnapshotBinding {
                tip: ChainTip {
                    height: 1,
                    block_hash: [31; 32],
                    tree_root: [32; 32],
                    median_time_past: 1_700_000_000,
                },
                chain_epoch: 7,
            }
        }

        fn mempool() -> MempoolSnapshotBinding {
            MempoolSnapshotBinding {
                instance_nonce: [33; 32],
                generation: 9,
            }
        }

        fn prove_store_mutex_is_released(&self) -> Result<(), HnsWalletError> {
            let store = self.store.clone();
            let (sender, receiver) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let result = store.with_store(|_| Ok(())).is_ok();
                let _ = sender.send(result);
            });
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(true) => Ok(()),
                Ok(false) => Err(HnsWalletError::Backend(
                    "shared store probe failed during backend I/O".to_owned(),
                )),
                Err(_) => Err(HnsWalletError::Backend(
                    "backend was invoked while the shared store mutex was held".to_owned(),
                )),
            }
        }

        fn fail_if_unexpected(method: &str) -> HnsWalletError {
            HnsWalletError::Backend(format!(
                "unexpected value or evidence method in account read: {method}"
            ))
        }
    }

    impl HnsBackend for ProductionFollowupReadBackend {
        fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            if self.snapshot_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                match self.fault {
                    ProductionFollowupReadFault::ChangedAccount => {
                        self.store
                            .with_store_mut(|store| {
                                let stored = store
                                    .wallet_account::<HnsAccountRecord>(&self.account_id)?
                                    .ok_or(StoreError::CorruptMetadata)?;
                                let mut changed = stored.value;
                                changed.next_receive_index = changed
                                    .next_receive_index
                                    .checked_add(1)
                                    .ok_or(StoreError::RevisionOverflow)?;
                                store
                                    .save_wallet_account(
                                        &self.account_id,
                                        stored.revision,
                                        &changed,
                                        101,
                                    )
                                    .map(|_| ())
                            })
                            .map_err(HnsWalletError::from)?;
                    }
                    ProductionFollowupReadFault::LockedStore => {
                        self.store.lock().map_err(HnsWalletError::from)?;
                    }
                    _ => {}
                }
            }
            Ok(Self::binding())
        }

        fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            self.tip_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Self::binding().tip)
        }

        fn get_block_hash(
            &self,
            height: u64,
            binding: SnapshotBinding,
        ) -> Result<BlockHashEvidence, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            let block_hash = if height == 0 {
                let network = if self.fault == ProductionFollowupReadFault::WrongNetwork {
                    HnsNetwork::Mainnet
                } else {
                    self.network
                };
                name_workflow::expected_chain_identity(network)?.1
            } else if height == binding.tip.height {
                binding.tip.block_hash
            } else {
                [35; 32]
            };
            Ok(BlockHashEvidence {
                binding,
                height,
                block_hash: Some(block_hash),
            })
        }

        fn get_confirmed_wallet_page(
            &self,
            request: ConfirmedWalletPageRequest<'_>,
        ) -> Result<ConfirmedWalletPage, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            let call = self.confirmed_calls.fetch_add(1, Ordering::SeqCst);
            let mut binding = Self::binding();
            if request.expected_tip != binding.tip
                || request.expected_epoch != Some(binding.chain_epoch)
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            if self.fault == ProductionFollowupReadFault::StaleChain && call > 0 {
                binding.chain_epoch += 1;
            }
            let history = self
                .name_history_program
                .as_ref()
                .and_then(|program| {
                    request
                        .scripts
                        .iter()
                        .position(|script| script.hash.as_slice() == program.as_slice())
                })
                .map(|script_index| HistoryEntry {
                    txid: TransactionHash::new([0x71; 32]),
                    height: Some(binding.tip.height),
                    block_hash: Some(binding.tip.block_hash),
                    transaction_position: Some(0),
                    spent: false,
                    first_seen_unix: Some(binding.tip.median_time_past),
                    script_index: u32::try_from(script_index).expect("bounded script index"),
                })
                .into_iter()
                .collect();
            let utxos = self
                .finalize_coin
                .as_ref()
                .and_then(|(expected_script, coin)| {
                    request
                        .scripts
                        .iter()
                        .position(|script| script == expected_script)
                        .map(|script_index| IndexedWalletCoin {
                            coin: WalletCoin {
                                outpoint: HnsOutpoint {
                                    transaction: TransactionHash::new(
                                        coin.outpoint.transaction_hash.into_bytes(),
                                    ),
                                    output_index: coin.outpoint.index,
                                },
                                value: BaseUnits::new(u128::from(coin.value.get())),
                                confirmation_count: u32::try_from(
                                    binding.tip.height - u64::from(coin.height.get()) + 1,
                                )
                                .expect("fixture confirmation count"),
                                confirmed_height: Some(coin.height.get()),
                                coinbase: coin.coinbase,
                                covenant: coin.covenant.encode().expect("fixture covenant"),
                                name_locked: !matches!(coin.covenant.kind, CovenantKind::None),
                            },
                            script_index: u32::try_from(script_index)
                                .expect("bounded fixture script index"),
                            output_address: expected_script.clone(),
                        })
                })
                .into_iter()
                .collect();
            Ok(ConfirmedWalletPage {
                binding,
                next_cursor: None,
                history,
                utxos,
            })
        }

        fn get_incoming_transfers_page(
            &self,
            request: IncomingTransfersPageRequest<'_>,
        ) -> Result<IncomingTransfersPage, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            if request.binding != Self::binding()
                || request.scripts.is_empty()
                || request.limit == 0
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let start = request.cursor.map_or(Ok(0usize), |cursor| {
                let raw: [u8; 4] = cursor
                    .try_into()
                    .map_err(|_| HnsWalletError::StaleNodeSnapshot)?;
                usize::try_from(u32::from_le_bytes(raw))
                    .map_err(|_| HnsWalletError::StaleNodeSnapshot)
            })?;
            if start > self.incoming_candidates.len() {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let selected = self
                .incoming_candidates
                .iter()
                .enumerate()
                .skip(start)
                .find_map(|(candidate_index, candidate)| {
                    request
                        .scripts
                        .iter()
                        .position(|script| script == &candidate.recipient)
                        .map(|script_index| (candidate_index, script_index, candidate))
                });
            let (entries, next_cursor) = selected.map_or_else(
                || (Vec::new(), None),
                |(candidate_index, script_index, candidate)| {
                    let next = candidate_index + 1;
                    (
                        vec![IncomingTransferCandidate {
                            script_index: u32::try_from(script_index)
                                .expect("bounded fixture script index"),
                            ..candidate.clone()
                        }],
                        (next < self.incoming_candidates.len()).then(|| {
                            u32::try_from(next)
                                .expect("bounded fixture continuation")
                                .to_le_bytes()
                                .to_vec()
                        }),
                    )
                },
            );
            Ok(IncomingTransfersPage {
                projection_version: 1,
                binding: request.binding,
                entries,
                script_examinations: request.scripts.len().min(MAX_SCAN_PAGE_RESULTS),
                next_cursor,
            })
        }

        fn get_mempool_wallet_page(
            &self,
            _: MempoolWalletPageRequest<'_>,
        ) -> Result<MempoolWalletPage, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            let call = self.mempool_calls.fetch_add(1, Ordering::SeqCst);
            let mempool =
                if self.fault == ProductionFollowupReadFault::RestartedMempool && call >= 3 {
                    MempoolSnapshotBinding {
                        instance_nonce: [34; 32],
                        generation: 1,
                    }
                } else {
                    Self::mempool()
                };
            Ok(MempoolWalletPage {
                binding: Self::binding(),
                mempool,
                next_cursor: None,
                history: Vec::new(),
            })
        }

        fn get_transaction_evidence(
            &self,
            _: TransactionHash,
            _: SnapshotBinding,
            _: Option<MempoolSnapshotBinding>,
        ) -> Result<TransactionEvidence, HnsWalletError> {
            Err(Self::fail_if_unexpected("get_transaction_evidence"))
        }

        fn get_outpoint_spend_evidence(
            &self,
            _: &[HnsOutpoint],
            _: SnapshotBinding,
        ) -> Result<OutpointSpendEvidence, HnsWalletError> {
            Err(Self::fail_if_unexpected("get_outpoint_spend_evidence"))
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<TransactionHash, HnsWalletError> {
            Err(Self::fail_if_unexpected("broadcast_transaction"))
        }

        fn quote_transaction_fee(
            &self,
            _: &[u8],
            _: &[Coin],
            _: u16,
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
            Err(Self::fail_if_unexpected("quote_transaction_fee"))
        }

        fn estimate_fee_rate(&self, _: u16) -> Result<BaseUnits, HnsWalletError> {
            Err(Self::fail_if_unexpected("estimate_fee_rate"))
        }

        fn get_name_evidence(
            &self,
            _: [u8; 32],
            _: SnapshotBinding,
        ) -> Result<NameEvidence, HnsWalletError> {
            Err(Self::fail_if_unexpected("get_name_evidence"))
        }

        fn get_active_name_owner_coin(
            &self,
            name_hash: [u8; 32],
            binding: SnapshotBinding,
        ) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            let (expected_name_hash, evidence) = self
                .active_owner
                .as_ref()
                .ok_or_else(|| Self::fail_if_unexpected("get_active_name_owner_coin"))?;
            if *expected_name_hash != name_hash || evidence.binding != binding {
                return Err(HnsWalletError::InvalidEvidence);
            }
            Ok(evidence.clone())
        }

        fn get_name_action_context(
            &self,
            _: HnsNameAction,
            _: [u8; 32],
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<NameActionContextEvidence, HnsWalletError> {
            Err(Self::fail_if_unexpected("get_name_action_context"))
        }
    }

    struct NativeNameImportBackend {
        store: SharedWalletStore,
        account_id: [u8; 32],
        network: HnsNetwork,
        evidence: NameEvidence,
        mutate_account_on_evidence: AtomicBool,
        snapshot_calls: AtomicUsize,
        evidence_calls: AtomicUsize,
    }

    impl NativeNameImportBackend {
        fn new(
            store: SharedWalletStore,
            config: &HnsRuntimeConfig,
            evidence: NameEvidence,
        ) -> Self {
            Self {
                store,
                account_id: account_entity_id(config),
                network: config.network,
                evidence,
                mutate_account_on_evidence: AtomicBool::new(false),
                snapshot_calls: AtomicUsize::new(0),
                evidence_calls: AtomicUsize::new(0),
            }
        }

        fn with_stale_account_mutation(self) -> Self {
            self.mutate_account_on_evidence
                .store(true, Ordering::SeqCst);
            self
        }

        fn binding() -> SnapshotBinding {
            SnapshotBinding {
                tip: ChainTip {
                    height: 500,
                    block_hash: [81; 32],
                    tree_root: [0; 32],
                    median_time_past: 1_700_000_000,
                },
                chain_epoch: 12,
            }
        }

        fn prove_store_mutex_is_released(&self) -> Result<(), HnsWalletError> {
            let store = self.store.clone();
            let (sender, receiver) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let result = store.with_store(|_| Ok(())).is_ok();
                let _ = sender.send(result);
            });
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(true) => Ok(()),
                _ => Err(HnsWalletError::Backend(
                    "backend was invoked while the shared store mutex was held".to_owned(),
                )),
            }
        }

        fn unexpected(method: &str) -> HnsWalletError {
            HnsWalletError::Backend(format!(
                "unexpected backend method during native name import: {method}"
            ))
        }
    }

    impl HnsBackend for NativeNameImportBackend {
        fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Self::binding())
        }

        fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
            Err(Self::unexpected("get_chain_tip"))
        }

        fn get_block_hash(
            &self,
            height: u64,
            binding: SnapshotBinding,
        ) -> Result<BlockHashEvidence, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            if height != 0 || binding != Self::binding() {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            Ok(BlockHashEvidence {
                binding,
                height,
                block_hash: Some(name_workflow::expected_chain_identity(self.network)?.1),
            })
        }

        fn get_confirmed_wallet_page(
            &self,
            _: ConfirmedWalletPageRequest<'_>,
        ) -> Result<ConfirmedWalletPage, HnsWalletError> {
            Err(Self::unexpected("get_confirmed_wallet_page"))
        }

        fn get_mempool_wallet_page(
            &self,
            _: MempoolWalletPageRequest<'_>,
        ) -> Result<MempoolWalletPage, HnsWalletError> {
            Err(Self::unexpected("get_mempool_wallet_page"))
        }

        fn get_transaction_evidence(
            &self,
            _: TransactionHash,
            _: SnapshotBinding,
            _: Option<MempoolSnapshotBinding>,
        ) -> Result<TransactionEvidence, HnsWalletError> {
            Err(Self::unexpected("get_transaction_evidence"))
        }

        fn get_outpoint_spend_evidence(
            &self,
            _: &[HnsOutpoint],
            _: SnapshotBinding,
        ) -> Result<OutpointSpendEvidence, HnsWalletError> {
            Err(Self::unexpected("get_outpoint_spend_evidence"))
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<TransactionHash, HnsWalletError> {
            Err(Self::unexpected("broadcast_transaction"))
        }

        fn quote_transaction_fee(
            &self,
            _: &[u8],
            _: &[Coin],
            _: u16,
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
            Err(Self::unexpected("quote_transaction_fee"))
        }

        fn estimate_fee_rate(&self, _: u16) -> Result<BaseUnits, HnsWalletError> {
            Err(Self::unexpected("estimate_fee_rate"))
        }

        fn get_name_evidence(
            &self,
            name_hash: [u8; 32],
            binding: SnapshotBinding,
        ) -> Result<NameEvidence, HnsWalletError> {
            self.prove_store_mutex_is_released()?;
            self.evidence_calls.fetch_add(1, Ordering::SeqCst);
            if name_hash != self.evidence.proof.name_hash || binding != Self::binding() {
                return Err(HnsWalletError::InvalidEvidence);
            }
            if self
                .mutate_account_on_evidence
                .swap(false, Ordering::SeqCst)
            {
                self.store
                    .with_store_mut(|store| {
                        let stored = store
                            .wallet_account::<HnsAccountRecord>(&self.account_id)?
                            .ok_or(StoreError::CorruptMetadata)?;
                        let mut changed = stored.value;
                        changed.next_receive_index = changed
                            .next_receive_index
                            .checked_add(1)
                            .ok_or(StoreError::RevisionOverflow)?;
                        store
                            .save_wallet_account(&self.account_id, stored.revision, &changed, 102)
                            .map(|_| ())
                    })
                    .map_err(HnsWalletError::from)?;
            }
            Ok(self.evidence.clone())
        }

        fn get_name_action_context(
            &self,
            _: HnsNameAction,
            _: [u8; 32],
            _: SnapshotBinding,
            _: MempoolSnapshotBinding,
        ) -> Result<NameActionContextEvidence, HnsWalletError> {
            Err(Self::unexpected("get_name_action_context"))
        }
    }

    #[derive(Clone, Copy)]
    struct ProductionFollowupClock;

    impl HnsClock for ProductionFollowupClock {
        fn now_unix(&self) -> Result<u64, HnsWalletError> {
            Ok(100)
        }
    }

    fn production_followup_read_store() -> (SharedWalletStore, HnsRuntimeConfig) {
        let mut config = test_runtime_config();
        config.birthday_height = 0;
        config.restore_lookahead = 1;
        config.minimum_confirmations = 1;
        let store = production_followup_read_store_for_config(config.clone());
        (store, config)
    }

    fn production_followup_read_store_for_config(config: HnsRuntimeConfig) -> SharedWalletStore {
        let mut store = WalletStore::create(":memory:", PRODUCTION_FOLLOWUP_PASSPHRASE)
            .expect("create synchronized-read store");
        store
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[41; 64],
                1,
            )
            .expect("persist synchronized-read seed");
        let account = HnsAccountRecord {
            config: config.clone(),
            next_receive_index: 0,
            next_change_index: 0,
            next_name_index: 0,
            next_shakedex_index: 0,
            external_scan_end: 0,
            internal_scan_end: 0,
            name_scan_end: 0,
            shakedex_scan_end: 0,
            shakedex_scan_complete: false,
            shakedex_scan_in_progress: false,
            last_used_external: None,
            last_used_internal: None,
            last_used_name: None,
            last_used_shakedex: None,
        };
        store
            .save_wallet_account(&account_entity_id(&config), 0, &account, 1)
            .expect("persist synchronized-read account");
        SharedWalletStore::new(store)
    }

    fn production_followup_read_runtime(
        store: SharedWalletStore,
        config: HnsRuntimeConfig,
        fault: ProductionFollowupReadFault,
    ) -> HnsAccountReadRuntime<ProductionFollowupReadBackend, ProductionFollowupClock> {
        let selector = HnsExistingAccountSelector::new(store.clone(), config.clone())
            .expect("exact synchronized-read selector");
        HnsAccountReadRuntime::new(
            ProductionFollowupReadBackend::new(store.clone(), &config, fault),
            ProductionFollowupClock,
            store,
            selector,
        )
        .expect("synchronized account read runtime")
    }

    #[test]
    fn full_runtime_retains_the_exact_shared_store_and_lock_authority() {
        let (store, config) = production_followup_read_store();
        let runtime = HnsWalletRuntime::open_shared(
            ProductionFollowupReadBackend::new(
                store.clone(),
                &config,
                ProductionFollowupReadFault::Healthy,
            ),
            store.clone(),
            config,
            ProductionFollowupClock,
        )
        .expect("open full runtime over shared authority");

        assert!(runtime.shares_store_authority(&store));
        let (different_store, _) = production_followup_read_store();
        assert!(!runtime.shares_store_authority(&different_store));

        store.lock().expect("lock shared authority");
        assert!(
            runtime
                .store_lock()
                .expect("locked runtime guard")
                .is_locked()
        );
        store
            .unlock(PRODUCTION_FOLLOWUP_PASSPHRASE)
            .expect("unlock shared authority");
        assert!(
            !runtime
                .store_lock()
                .expect("runtime observes shared unlock")
                .is_locked()
        );
    }

    fn zero_value_incoming_candidate(recipient: &DerivedHnsAddress) -> IncomingTransferCandidate {
        zero_value_incoming_candidate_at(recipient, 0)
    }

    fn zero_value_incoming_candidate_at(
        recipient: &DerivedHnsAddress,
        candidate_index: u32,
    ) -> IncomingTransferCandidate {
        let name = format!("alpha{candidate_index}");
        let name_hash = hash_name(name.as_bytes()).expect("incoming name hash");
        let covenant =
            TransferCovenant::new(name_hash, Height::new(0), 0, recipient.program.clone())
                .expect("incoming TRANSFER")
                .to_covenant()
                .expect("incoming TRANSFER covenant");
        IncomingTransferCandidate {
            script_index: 0,
            recipient: WalletAddressKey {
                version: 0,
                hash: recipient.program.clone(),
            },
            name_hash: name_hash.into_bytes(),
            start_height: 0,
            transfer_coin: Coin {
                outpoint: CanonicalOutpoint {
                    transaction_hash: CanonicalTransactionHash::new({
                        let mut transaction = [0x91; 32];
                        transaction[..4].copy_from_slice(&candidate_index.to_le_bytes());
                        transaction
                    }),
                    index: 0,
                },
                value: Dollarydoos::new(0),
                height: Height::new(1),
                coinbase: false,
                address: Address::new(0, vec![0x92; 20]).expect("old-owner address"),
                covenant,
            },
            inclusion: TransactionInclusion {
                block_hash: ProductionFollowupReadBackend::binding().tip.block_hash,
                height: 1,
                transaction_index: Some(0),
            },
            source_output_count: 1,
            source_binding: IncomingTransferSourceBinding::PrunedTrustedNodeProjection,
        }
    }

    fn zero_value_finalize_owner(
        recipient: &DerivedHnsAddress,
    ) -> ([u8; 32], Coin, ActiveNameOwnerCoinEvidence) {
        let name = b"alpha".to_vec();
        let name_hash = hash_name(&name).expect("FINALIZE name hash");
        let outpoint = CanonicalOutpoint {
            transaction_hash: CanonicalTransactionHash::new([0xa1; 32]),
            index: 0,
        };
        let covenant = FinalizeCovenant::new(
            name.clone(),
            Height::new(0),
            false,
            Height::new(0),
            0,
            BlockHash::new([0xa2; 32]),
        )
        .expect("zero-value FINALIZE")
        .to_covenant()
        .expect("zero-value FINALIZE covenant");
        let coin = Coin {
            outpoint,
            value: Dollarydoos::new(0),
            height: Height::new(1),
            coinbase: false,
            address: Address::new(0, recipient.program.clone()).expect("name address"),
            covenant,
        };
        let mut state = NameState::null(name_hash);
        state.name = name;
        state.height = Height::new(0);
        state.renewal = Height::new(1);
        state.owner = outpoint;
        state.value = Dollarydoos::new(0);
        state.highest = Dollarydoos::new(0);
        state.renewals = 1;
        state.registered = true;
        let binding = ProductionFollowupReadBackend::binding();
        let evidence = ActiveNameOwnerCoinEvidence {
            projection_version: 1,
            binding,
            current_state: state.encode().expect("zero-value current NameState"),
            owner_coin: coin.clone(),
            inclusion: TransactionInclusion {
                block_hash: binding.tip.block_hash,
                height: 1,
                transaction_index: None,
            },
            source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
        };
        (name_hash.into_bytes(), coin, evidence)
    }

    fn production_followup_recovery_read_runtime(
        store: SharedWalletStore,
        config: HnsRuntimeConfig,
        fault: ProductionFollowupReadFault,
    ) -> HnsPersistedRecoveryReadOnlyRuntime<ProductionFollowupReadBackend, ProductionFollowupClock>
    {
        HnsPersistedRecoveryReadOnlyRuntime::new(
            ProductionFollowupReadBackend::new(store.clone(), &config, fault),
            ProductionFollowupClock,
            store,
            config,
        )
        .expect("persisted recovery-only read runtime")
    }

    fn canonical_name_view(
        owner_program: Vec<u8>,
        resource_data: Vec<u8>,
        transfer_recipient: Option<Address>,
    ) -> (Vec<u8>, NameState, Transaction, HnsOutpoint) {
        let name = b"alpha".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let mut state = NameState {
            name_hash,
            name: name.clone(),
            height: Height::new(100),
            renewal: Height::new(120),
            owner: CanonicalOutpoint::NULL,
            value: Dollarydoos::new(50_000),
            highest: Dollarydoos::new(60_000),
            resource_data,
            transfer: Height::new(if transfer_recipient.is_some() { 400 } else { 0 }),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 1,
            registered: true,
            expired: false,
            weak: false,
        };
        let covenant = match transfer_recipient {
            Some(recipient) => {
                TransferCovenant::new(name_hash, state.height, recipient.version, recipient.hash)
                    .expect("transfer")
                    .to_covenant()
                    .expect("transfer covenant")
            }
            None => FinalizeCovenant::from_name_state(&state, BlockHash::new([9; 32]))
                .expect("finalize")
                .to_covenant()
                .expect("finalize covenant"),
        };
        let transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: vec![Output {
                value: state.value,
                address: Address::new(0, owner_program).expect("owner address"),
                covenant,
            }],
            locktime: 0,
        };
        let transaction_hash = transaction.transaction_hash().expect("transaction hash");
        state.owner = CanonicalOutpoint {
            transaction_hash,
            index: 0,
        };
        let outpoint = HnsOutpoint {
            transaction: TransactionHash::new(transaction_hash.into_bytes()),
            output_index: 0,
        };
        (name, state, transaction, outpoint)
    }

    fn native_import_evidence(
        name: &[u8],
        current: Option<(NameState, Transaction, HnsOutpoint)>,
    ) -> NameEvidence {
        let binding = NativeNameImportBackend::binding();
        let name_hash = hash_name(name).expect("import name hash").into_bytes();
        let (current_state, current_owner_outpoint, current_owner_transaction, current_inclusion) =
            current.map_or(
                (None, None, None, None),
                |(state, transaction, outpoint)| {
                    let height = u64::from(state.transfer.get().max(1));
                    (
                        Some(state.encode().expect("current name state")),
                        Some(outpoint),
                        Some(transaction.encode().expect("current owner transaction")),
                        Some(TransactionInclusion {
                            block_hash: [82; 32],
                            height,
                            transaction_index: Some(0),
                        }),
                    )
                },
            );
        let current_resource = current_state.as_ref().map(|raw| {
            NameState::decode(NameHash::new(name_hash), raw)
                .expect("decode current import state")
                .resource_data
        });
        NameEvidence {
            binding,
            proof: NameProofResponse {
                name_hash,
                tree_root: binding.tip.tree_root,
                proof: vec![0, 0, 0, 0],
                proof_height: binding.tip.height,
            },
            proof_state: None,
            proof_owner_outpoint: None,
            proof_owner_transaction: None,
            proof_owner_inclusion: None,
            current_state,
            current_owner_outpoint,
            current_owner_transaction,
            current_owner_inclusion: current_inclusion,
            untrusted_current_raw_resource: current_resource,
        }
    }

    fn native_import_store() -> (SharedWalletStore, HnsRuntimeConfig, DerivedHnsAddress) {
        let (store, config) = production_followup_read_store();
        let address = store
            .try_with_store_mut(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .ok_or(HnsWalletError::StaleAccountRead)?
                    .value;
                let addresses = derive_restore_addresses(wallet, &account, KeyRole::HnsName)?;
                persist_derived_addresses(wallet, &config, &addresses, 2)?;
                addresses
                    .into_iter()
                    .next()
                    .ok_or(HnsWalletError::InvalidEvidence)
            })
            .expect("prepare exact name derivation evidence");
        (store, config, address)
    }

    fn native_import_runtime(
        store: SharedWalletStore,
        config: HnsRuntimeConfig,
        evidence: NameEvidence,
        stale_account: bool,
    ) -> HnsAccountReadRuntime<NativeNameImportBackend, ProductionFollowupClock> {
        let selector = HnsExistingAccountSelector::new(store.clone(), config.clone())
            .expect("native import selector");
        let backend = NativeNameImportBackend::new(store.clone(), &config, evidence);
        let backend = if stale_account {
            backend.with_stale_account_mutation()
        } else {
            backend
        };
        HnsAccountReadRuntime::new(backend, ProductionFollowupClock, store, selector)
            .expect("native import runtime")
    }

    fn validate_test_name_view(
        name: &[u8],
        state: &NameState,
        transaction: &Transaction,
        outpoint: HnsOutpoint,
    ) -> Result<ValidatedCanonicalNameState, HnsWalletError> {
        let raw_state = state.encode().expect("name state");
        let raw_transaction = transaction.encode().expect("owner transaction");
        let inclusion_height = u64::from(state.transfer.get().max(1));
        validate_canonical_name_state(
            name,
            state.name_hash.into_bytes(),
            Some(&raw_state),
            Some(outpoint),
            Some(&raw_transaction),
            Some(TransactionInclusion {
                block_hash: [24; 32],
                height: inclusion_height,
                transaction_index: Some(0),
            }),
        )?
        .ok_or(HnsWalletError::InvalidEvidence)
    }

    #[test]
    fn canonical_hns_v2_binds_owner_resource_and_name_role() {
        assert_eq!(
            classify_name_ownership(None, None).expect("context-free classification"),
            NameOwnershipStatus::WalletContextUnavailable
        );
        let address = test_derived_address(KeyRole::HnsName, 31);
        let (name, state, transaction, outpoint) =
            canonical_name_view(address.program.clone(), vec![1], None);
        let current =
            validate_test_name_view(&name, &state, &transaction, outpoint).expect("canonical view");
        assert_eq!(current.summary.owner_outpoint, Some(outpoint));
        assert_eq!(current.summary.value, 50_000);
        assert_eq!(
            classify_name_ownership(Some(&current), Some(std::slice::from_ref(&address)))
                .expect("ownership"),
            NameOwnershipStatus::WalletOwned {
                derivation: address.derivation
            }
        );
        let (resource, status) =
            bind_current_name_resource(Some(&current), Some(vec![1])).expect("canonical resource");
        assert_eq!(resource, Some(vec![1]));
        assert_eq!(status, NameResourceStatus::CanonicalOpaque);

        let coin_role = test_derived_address(KeyRole::HnsCoin, 31);
        assert!(validate_wallet_name_addresses(&[coin_role]).is_err());
    }

    #[test]
    fn native_exact_text_name_import_rejects_before_every_backend_call() {
        let (store, config, _) = native_import_store();
        let evidence = native_import_evidence(b"alpha", None);
        let runtime = native_import_runtime(store.clone(), config.clone(), evidence, false);
        for invalid in [
            "",
            " alpha",
            "alpha ",
            "ALPHA",
            "alpha.",
            "alpha.beta",
            "alph\u{00e1}",
            "alpha\n",
        ] {
            assert!(matches!(
                runtime.import_name_exact_text(invalid),
                Err(HnsWalletError::InvalidName)
            ));
        }
        assert_eq!(runtime.backend.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.backend.evidence_calls.load(Ordering::SeqCst), 0);
        assert!(
            store
                .with_store(|wallet| wallet.list_entities_by_id_prefix::<KnownName>(
                    EntityKind::KnownName,
                    &account_entity_prefix(&config),
                    MAX_HISTORY_RESULTS,
                ))
                .expect("unchanged name store")
                .is_empty()
        );
    }

    #[test]
    fn native_name_import_rejects_same_id_with_different_exact_text_before_backend() {
        let (store, config, _) = native_import_store();
        let alpha_hash = hash_name(b"alpha").expect("alpha hash").into_bytes();
        let corrupt = KnownName {
            name: b"beta".to_vec(),
            name_hash: alpha_hash,
            proof_height: 1,
            unbound_proof_owner_outpoint: None,
            unbound_current_owner_outpoint: None,
            proof_state: None,
            current_state: None,
            canonical_proof_state: None,
            canonical_current_state: None,
            current_raw_resource: None,
            resource_status: NameResourceStatus::NoCurrentState,
            ownership_status: NameOwnershipStatus::NoCurrentOwner,
        };
        store
            .with_store_mut(|wallet| {
                wallet
                    .save_known_name(&namespaced_name_id(&config, alpha_hash), 0, &corrupt, 3)
                    .map(|_| ())
            })
            .expect("inject authenticated corrupt hash/text row");
        let evidence = native_import_evidence(b"alpha", None);
        let runtime = native_import_runtime(store, config, evidence, false);
        assert!(matches!(
            runtime.import_name_exact_text("alpha"),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert_eq!(runtime.backend.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.backend.evidence_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_name_import_rotates_only_exact_wallet_ownership_classes() {
        #[derive(Clone, Copy)]
        enum ImportClass {
            WalletOwned,
            IncomingTransfer,
            OutgoingTransfer,
            NotWalletOwned,
            NoCurrentOwner,
        }

        for class in [
            ImportClass::WalletOwned,
            ImportClass::IncomingTransfer,
            ImportClass::OutgoingTransfer,
            ImportClass::NotWalletOwned,
            ImportClass::NoCurrentOwner,
        ] {
            let (store, config, address) = native_import_store();
            let current = match class {
                ImportClass::WalletOwned => {
                    let (_, state, transaction, outpoint) =
                        canonical_name_view(address.program.clone(), Vec::new(), None);
                    Some((state, transaction, outpoint))
                }
                ImportClass::IncomingTransfer => {
                    let recipient =
                        Address::new(0, address.program.clone()).expect("wallet recipient");
                    let (_, state, transaction, outpoint) =
                        canonical_name_view(vec![91; 20], Vec::new(), Some(recipient));
                    Some((state, transaction, outpoint))
                }
                ImportClass::OutgoingTransfer => {
                    let recipient = Address::new(0, vec![92; 20]).expect("external recipient");
                    let (_, state, transaction, outpoint) =
                        canonical_name_view(address.program.clone(), Vec::new(), Some(recipient));
                    Some((state, transaction, outpoint))
                }
                ImportClass::NotWalletOwned => {
                    let (_, state, transaction, outpoint) =
                        canonical_name_view(vec![93; 20], Vec::new(), None);
                    Some((state, transaction, outpoint))
                }
                ImportClass::NoCurrentOwner => None,
            };
            let evidence = native_import_evidence(b"alpha", current);
            let runtime = native_import_runtime(store.clone(), config.clone(), evidence, false);
            let imported = runtime
                .import_name_exact_text("alpha")
                .expect("exact native name import");
            match class {
                ImportClass::WalletOwned => assert!(matches!(
                    imported.ownership_status,
                    NameOwnershipStatus::WalletOwned { derivation }
                        if derivation == address.derivation
                )),
                ImportClass::IncomingTransfer => assert!(matches!(
                    imported.ownership_status,
                    NameOwnershipStatus::IncomingTransfer {
                        recipient_derivation,
                        ..
                    } if recipient_derivation == address.derivation
                )),
                ImportClass::OutgoingTransfer => assert!(matches!(
                    imported.ownership_status,
                    NameOwnershipStatus::OutgoingTransfer {
                        owner_derivation,
                        ..
                    } if owner_derivation == address.derivation
                )),
                ImportClass::NotWalletOwned => assert_eq!(
                    imported.ownership_status,
                    NameOwnershipStatus::NotWalletOwned
                ),
                ImportClass::NoCurrentOwner => assert_eq!(
                    imported.ownership_status,
                    NameOwnershipStatus::NoCurrentOwner
                ),
            }
            let wallet_bearing = matches!(
                class,
                ImportClass::WalletOwned
                    | ImportClass::IncomingTransfer
                    | ImportClass::OutgoingTransfer
            );
            store
                .with_store(|wallet| {
                    let account = wallet
                        .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                        .ok_or(StoreError::CorruptMetadata)?;
                    assert_eq!(account.value.last_used_name, wallet_bearing.then_some(0));
                    assert_eq!(account.value.next_name_index, u32::from(wallet_bearing));
                    assert_eq!(account.value.name_scan_end, u32::from(wallet_bearing));
                    let stored = wallet
                        .known_name::<KnownName>(&namespaced_name_id(&config, imported.name_hash))?
                        .ok_or(StoreError::CorruptMetadata)?;
                    assert_eq!(stored.value, imported);
                    Ok(())
                })
                .expect("atomic account and name import");
        }
    }

    #[test]
    fn native_name_import_stale_account_cannot_partially_persist_or_rotate() {
        let (store, config, address) = native_import_store();
        let (_, state, transaction, outpoint) =
            canonical_name_view(address.program, Vec::new(), None);
        let evidence = native_import_evidence(b"alpha", Some((state, transaction, outpoint)));
        let runtime = native_import_runtime(store.clone(), config.clone(), evidence, true);
        assert!(matches!(
            runtime.import_name_exact_text("alpha"),
            Err(HnsWalletError::StaleAccountRead)
        ));
        store
            .with_store(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert_eq!(account.value.next_receive_index, 1);
                assert_eq!(account.value.last_used_name, None);
                assert_eq!(account.value.next_name_index, 0);
                assert_eq!(account.value.name_scan_end, 0);
                assert!(
                    wallet
                        .known_name::<KnownName>(&namespaced_name_id(
                            &config,
                            hash_name(b"alpha").expect("hash").into_bytes(),
                        ))?
                        .is_none()
                );
                Ok(())
            })
            .expect("no partial name mutation");
    }

    #[test]
    fn native_name_import_is_bounded_idempotent_and_monotonic_after_restart() {
        let (store, config, address) = native_import_store();
        let (_, state, transaction, outpoint) =
            canonical_name_view(address.program, Vec::new(), None);
        let owned = native_import_evidence(b"alpha", Some((state, transaction, outpoint)));
        let runtime = native_import_runtime(store.clone(), config.clone(), owned, false);
        let first = runtime
            .import_name_exact_text_bounded("alpha", 1)
            .expect("initial bounded import");
        drop(runtime);

        let beta = native_import_evidence(b"beta", None);
        let bounded = native_import_runtime(store.clone(), config.clone(), beta, false);
        assert!(matches!(
            bounded.import_name_exact_text_bounded("beta", 1),
            Err(HnsWalletError::HistoryLimit)
        ));
        assert_eq!(bounded.backend.snapshot_calls.load(Ordering::SeqCst), 0);
        assert_eq!(bounded.backend.evidence_calls.load(Ordering::SeqCst), 0);
        drop(bounded);

        let reused = native_import_evidence(b"alpha", None);
        let restarted = native_import_runtime(store.clone(), config.clone(), reused, false);
        let second = restarted
            .import_name_exact_text_bounded("alpha", 1)
            .expect("idempotent import at the bound after restart");
        assert_eq!(second.name, first.name);
        assert_eq!(second.name_hash, first.name_hash);
        assert_eq!(second.ownership_status, NameOwnershipStatus::NoCurrentOwner);
        store
            .with_store(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert_eq!(account.value.last_used_name, Some(0));
                assert_eq!(account.value.next_name_index, 1);
                assert_eq!(account.value.name_scan_end, 1);
                assert_eq!(
                    wallet
                        .list_entities_by_id_prefix::<KnownName>(
                            EntityKind::KnownName,
                            &account_entity_prefix(&config),
                            MAX_HISTORY_RESULTS,
                        )?
                        .len(),
                    1
                );
                Ok(())
            })
            .expect("monotonic idempotent import state");
    }

    #[test]
    fn canonical_hns_v2_rejects_owner_value_covenant_and_resource_mismatch() {
        let address = test_derived_address(KeyRole::HnsName, 32);
        let (name, state, transaction, outpoint) =
            canonical_name_view(address.program.clone(), Vec::new(), None);
        let raw_state = state.encode().expect("state");
        let raw_transaction = transaction.encode().expect("transaction");
        let wrong_outpoint = HnsOutpoint {
            output_index: 1,
            ..outpoint
        };
        assert!(
            validate_canonical_name_state(
                &name,
                state.name_hash.into_bytes(),
                Some(&raw_state),
                Some(wrong_outpoint),
                Some(&raw_transaction),
                Some(TransactionInclusion {
                    block_hash: [24; 32],
                    height: 1,
                    transaction_index: Some(0),
                }),
            )
            .is_err()
        );

        let mut wrong_value_transaction = transaction.clone();
        wrong_value_transaction.outputs[0].value = Dollarydoos::new(state.value.get() + 1);
        let wrong_value_hash = wrong_value_transaction
            .transaction_hash()
            .expect("wrong-value hash");
        let mut wrong_value_state = state.clone();
        wrong_value_state.owner.transaction_hash = wrong_value_hash;
        assert!(
            validate_test_name_view(
                &name,
                &wrong_value_state,
                &wrong_value_transaction,
                HnsOutpoint {
                    transaction: TransactionHash::new(wrong_value_hash.into_bytes()),
                    output_index: 0,
                },
            )
            .is_err()
        );

        let mut wrong_covenant_transaction = transaction;
        wrong_covenant_transaction.outputs[0].covenant.items[0] = vec![7; 32];
        let wrong_covenant_hash = wrong_covenant_transaction
            .transaction_hash()
            .expect("wrong-covenant hash");
        let mut wrong_covenant_state = state;
        wrong_covenant_state.owner.transaction_hash = wrong_covenant_hash;
        assert!(
            validate_test_name_view(
                &name,
                &wrong_covenant_state,
                &wrong_covenant_transaction,
                HnsOutpoint {
                    transaction: TransactionHash::new(wrong_covenant_hash.into_bytes()),
                    output_index: 0,
                },
            )
            .is_err()
        );

        let (name, state, transaction, outpoint) =
            canonical_name_view(address.program, vec![1], None);
        let current =
            validate_test_name_view(&name, &state, &transaction, outpoint).expect("canonical view");
        assert!(bind_current_name_resource(Some(&current), Some(vec![2])).is_err());
    }

    #[test]
    fn canonical_hns_v2_classifies_incoming_and_outgoing_transfers() {
        let owner = test_derived_address(KeyRole::HnsName, 41);
        let recipient = test_derived_address(KeyRole::HnsName, 42);
        let recipient_address = Address::new(0, recipient.program.clone()).expect("recipient");
        let (name, state, transaction, outpoint) =
            canonical_name_view(owner.program.clone(), Vec::new(), Some(recipient_address));
        let current =
            validate_test_name_view(&name, &state, &transaction, outpoint).expect("transfer view");
        assert_eq!(
            classify_name_ownership(Some(&current), Some(std::slice::from_ref(&owner)))
                .expect("outgoing"),
            NameOwnershipStatus::OutgoingTransfer {
                owner_derivation: owner.derivation,
                recipient: WalletAddressKey {
                    version: 0,
                    hash: recipient.program.clone(),
                },
            }
        );
        assert_eq!(
            classify_name_ownership(Some(&current), Some(std::slice::from_ref(&recipient)))
                .expect("incoming"),
            NameOwnershipStatus::IncomingTransfer {
                recipient_derivation: recipient.derivation,
                current_owner: WalletAddressKey {
                    version: 0,
                    hash: owner.program,
                },
            }
        );
    }

    #[test]
    fn canonical_hns_v2_legacy_cache_requires_fresh_revalidation() {
        let legacy = KnownName {
            name: b"alpha".to_vec(),
            name_hash: [1; 32],
            proof_height: 10,
            unbound_proof_owner_outpoint: None,
            unbound_current_owner_outpoint: None,
            proof_state: None,
            current_state: None,
            canonical_proof_state: None,
            canonical_current_state: None,
            current_raw_resource: None,
            resource_status: NameResourceStatus::UnavailableCanonicalBinding,
            ownership_status: NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable,
        };
        let mut encoded = serde_json::to_value(legacy).expect("legacy cache");
        let object = encoded.as_object_mut().expect("known name object");
        object.remove("canonical_proof_state");
        object.remove("canonical_current_state");
        object.remove("current_raw_resource");
        let decoded: KnownName = serde_json::from_value(encoded).expect("legacy decode");
        assert_eq!(decoded.canonical_proof_state, None);
        assert_eq!(decoded.canonical_current_state, None);
        assert_eq!(decoded.current_raw_resource, None);
        assert_eq!(
            decoded.ownership_status,
            NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable
        );
    }

    #[test]
    fn canonical_hns_v2_persisted_queries_are_complete_and_account_scoped() {
        assert_eq!(
            MAX_RESTORE_SCRIPTS_PER_QUERY,
            hns_wallet_store::MAX_ENTITY_LIST_RESULTS
        );
        let mut store = WalletStore::create(":memory:", "passphrase").expect("store");
        let config = test_runtime_config();
        let mut other_config = config.clone();
        other_config.account_id = AccountId::new([13; 16]);
        other_config.account_derivation_index = 8;
        let address = |config: &HnsRuntimeConfig, role, index, program| DerivedHnsAddress {
            account_id: config.account_id,
            derivation: DerivationReference {
                role,
                account: config.account_derivation_index,
                change: 0,
                index,
            },
            address: format!("test-address-{program}"),
            program: vec![program; 20],
            used: false,
        };
        let coin = address(&config, KeyRole::HnsCoin, 1, 21);
        let name = address(&config, KeyRole::HnsName, 2, 22);
        let other_name = address(&other_config, KeyRole::HnsName, 3, 23);
        for (owner, value) in [
            (&config, coin),
            (&config, name.clone()),
            (&other_config, other_name),
        ] {
            let id = derived_address_record_id(owner, value.derivation).expect("address id");
            store
                .save_derived_address(&id, 0, &value, 1)
                .expect("persist address");
        }
        assert_eq!(
            persisted_name_addresses(&store, &config).expect("scoped name addresses"),
            vec![name]
        );

        let current_name_id = namespaced_name_id(&config, [31; 32]);
        let other_name_id = namespaced_name_id(&other_config, [32; 32]);
        store
            .save_known_name(
                &current_name_id,
                0,
                &serde_json::json!({"name":"current"}),
                2,
            )
            .expect("current name");
        store
            .save_known_name(&other_name_id, 0, &serde_json::json!({"name":"other"}), 2)
            .expect("other name");
        let scoped = store
            .list_entities_by_id_prefix::<serde_json::Value>(
                EntityKind::KnownName,
                &account_entity_prefix(&config),
                MAX_HISTORY_RESULTS,
            )
            .expect("scoped names");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, current_name_id);

        let current_reservation = HnsInputReservation {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            outpoint: HnsOutpoint {
                transaction: TransactionHash::new([41; 32]),
                output_index: 1,
            },
            workflow_id: WorkflowId::new([42; 16]),
            expires_at_unix: Some(10),
            kind: HnsInputReservationKind::Ordinary,
        };
        let other_reservation = HnsInputReservation {
            wallet_id: other_config.wallet_id,
            account_id: other_config.account_id,
            outpoint: HnsOutpoint {
                transaction: TransactionHash::new([43; 32]),
                output_index: 2,
            },
            workflow_id: WorkflowId::new([44; 16]),
            expires_at_unix: Some(10),
            kind: HnsInputReservationKind::Ordinary,
        };
        for (owner, reservation) in [
            (&config, current_reservation.clone()),
            (&other_config, other_reservation),
        ] {
            store
                .save_input_reservation(
                    &namespaced_outpoint_id(owner, reservation.outpoint),
                    0,
                    &reservation,
                    3,
                )
                .expect("reservation");
        }
        assert_eq!(
            account_input_reservations(&store, &config)
                .expect("scoped reservations")
                .into_iter()
                .map(|stored| stored.value)
                .collect::<Vec<_>>(),
            vec![current_reservation]
        );

        for (id, account) in [
            (WorkflowId::new([51; 16]), config.account_id),
            (WorkflowId::new([52; 16]), other_config.account_id),
        ] {
            store
                .save_workflow(
                    id,
                    WorkflowKind::HnsSend,
                    0,
                    &serde_json::json!({"account": account}),
                    false,
                    4,
                )
                .expect("workflow");
        }
        assert_eq!(
            store
                .list_workflows_complete::<serde_json::Value>(
                    WorkflowKind::HnsSend,
                    MAX_HISTORY_RESULTS,
                )
                .expect("complete workflows")
                .len(),
            2
        );
    }

    #[test]
    fn authoritative_reconcile_account_rejects_derivation_rollback() {
        let cached = HnsAccountRecord {
            config: test_runtime_config(),
            next_receive_index: 3,
            next_change_index: 4,
            next_name_index: 5,
            next_shakedex_index: 6,
            external_scan_end: 102,
            internal_scan_end: 103,
            name_scan_end: 104,
            shakedex_scan_end: 105,
            shakedex_scan_complete: true,
            shakedex_scan_in_progress: false,
            last_used_external: Some(2),
            last_used_internal: Some(3),
            last_used_name: Some(4),
            last_used_shakedex: Some(5),
        };
        assert!(validate_authoritative_reconcile_account(&cached, 7, &cached, 7).is_ok());

        let mut advanced = cached.clone();
        advanced.next_change_index = 5;
        advanced.internal_scan_end = 104;
        assert!(validate_authoritative_reconcile_account(&cached, 7, &advanced, 8).is_ok());

        let mut rolled_back = advanced.clone();
        rolled_back.next_receive_index = 2;
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &rolled_back, 8),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &advanced, 6),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &advanced, 7),
            Err(HnsWalletError::InvalidEvidence)
        ));

        let mut mismatched = advanced;
        mismatched.config.minimum_confirmations += 1;
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &mismatched, 8),
            Err(HnsWalletError::AccountConfigurationMismatch)
        ));
    }

    #[test]
    fn legacy_account_state_defaults_the_independent_name_and_shakedex_scans() {
        let account = HnsAccountRecord {
            config: test_runtime_config(),
            next_receive_index: 3,
            next_change_index: 4,
            next_name_index: 8,
            next_shakedex_index: 9,
            external_scan_end: 102,
            internal_scan_end: 103,
            name_scan_end: 107,
            shakedex_scan_end: 108,
            shakedex_scan_complete: true,
            shakedex_scan_in_progress: false,
            last_used_external: Some(2),
            last_used_internal: Some(3),
            last_used_name: Some(7),
            last_used_shakedex: Some(8),
        };
        let mut encoded = serde_json::to_value(account).expect("encode account");
        let object = encoded.as_object_mut().expect("account object");
        object.remove("next_name_index");
        object.remove("name_scan_end");
        object.remove("last_used_name");
        object.remove("next_shakedex_index");
        object.remove("shakedex_scan_end");
        object.remove("shakedex_scan_complete");
        object.remove("shakedex_scan_in_progress");
        object.remove("last_used_shakedex");
        let decoded: HnsAccountRecord =
            serde_json::from_value(encoded).expect("decode legacy account");
        assert_eq!(decoded.next_name_index, 0);
        assert_eq!(decoded.name_scan_end, 0);
        assert_eq!(decoded.last_used_name, None);
        assert_eq!(decoded.next_shakedex_index, 0);
        assert_eq!(decoded.shakedex_scan_end, 0);
        assert!(!decoded.shakedex_scan_complete);
        assert!(!decoded.shakedex_scan_in_progress);
        assert_eq!(decoded.last_used_shakedex, None);
        assert_eq!(decoded.next_receive_index, 3);
        assert_eq!(decoded.external_scan_end, 102);
    }

    #[test]
    fn name_and_shakedex_address_ids_are_role_discriminated_without_changing_coin_ids() {
        let config = test_runtime_config();
        let coin = DerivationReference {
            role: KeyRole::HnsCoin,
            account: config.account_derivation_index,
            change: 0,
            index: 9,
        };
        let name = DerivationReference {
            role: KeyRole::HnsName,
            ..coin
        };
        let shakedex = DerivationReference {
            role: KeyRole::HnsShakedex,
            ..coin
        };
        let coin_id = derived_address_record_id(&config, coin).expect("coin id");
        let name_id = derived_address_record_id(&config, name).expect("name id");
        let shakedex_id =
            derived_address_record_id(&config, shakedex).expect("Shakedex address id");
        assert_eq!(coin_id, derived_address_id(&config, 0, 9).to_vec());
        assert_eq!(coin_id.len(), 40);
        assert_eq!(name_id.len(), 41);
        assert_eq!(shakedex_id.len(), 41);
        assert_ne!(coin_id, name_id);
        assert_ne!(coin_id, shakedex_id);
        assert_ne!(name_id, shakedex_id);
        assert!(
            derived_address_record_id(&config, DerivationReference { change: 1, ..name }).is_err()
        );
        assert!(
            derived_address_record_id(
                &config,
                DerivationReference {
                    change: 1,
                    ..shakedex
                }
            )
            .is_err()
        );
    }

    #[test]
    fn separate_restore_queries_share_one_exact_snapshot() {
        let binding = test_snapshot(4);
        let mempool = test_mempool(5);
        assert!(validate_same_restore_snapshot(binding, mempool, binding, mempool).is_ok());
        assert!(
            validate_same_restore_snapshot(binding, mempool, test_snapshot(6), mempool).is_err()
        );
        assert!(
            validate_same_restore_snapshot(binding, mempool, binding, test_mempool(6)).is_err()
        );
        let restarted = MempoolSnapshotBinding {
            instance_nonce: [24; 32],
            generation: mempool.generation,
        };
        assert!(validate_same_restore_snapshot(binding, mempool, binding, restarted).is_err());
    }

    #[test]
    fn hns_shakedex_legacy_snapshot_time_defaults_fail_closed() {
        let mut encoded = serde_json::to_value(test_snapshot(4).tip).expect("encode tip");
        encoded
            .as_object_mut()
            .expect("tip object")
            .remove("median_time_past");
        let decoded: ChainTip = serde_json::from_value(encoded).expect("decode legacy tip");
        assert_eq!(decoded.median_time_past, 0);
    }

    #[test]
    fn separated_gap_and_next_indexes_never_shrink_after_restart_or_reorg() {
        assert_eq!(required_scan_end(None, 500, 100), 500);
        assert_eq!(required_scan_end(Some(3), 500, 100), 500);
        assert_eq!(required_scan_end(Some(550), 500, 100), 650);
        assert_eq!(advance_next_derivation_index(50, None), 50);
        assert_eq!(advance_next_derivation_index(50, Some(3)), 50);
        assert_eq!(advance_next_derivation_index(50, Some(80)), 81);
        assert_eq!(
            checked_scan_address_count(&[4_999, 4_999]).expect("full coin query"),
            MAX_RESTORE_SCRIPTS_PER_QUERY
        );
        assert_eq!(
            checked_scan_address_count(&[9_999]).expect("full name query"),
            MAX_RESTORE_SCRIPTS_PER_QUERY
        );
        assert!(checked_scan_address_count(&[5_000, 5_000]).is_err());
        assert_eq!(
            MAX_RESTORE_ADDRESS_RECORDS,
            MAX_RESTORE_SCRIPTS_PER_QUERY * 3
        );
    }

    #[test]
    fn name_receive_target_is_role_separated_and_uses_the_exact_current_index() {
        let mut account =
            HnsAccountRecord::initial_non_value(test_runtime_config()).expect("non-value account");
        account.next_receive_index = 3;
        account.next_name_index = 7;
        let address = |role, index, display: &str| DerivedHnsAddress {
            account_id: account.config.account_id,
            derivation: DerivationReference {
                role,
                account: account.config.account_derivation_index,
                change: 0,
                index,
            },
            address: display.to_owned(),
            program: vec![u8::try_from(index).expect("test index"); 20],
            used: false,
        };
        let coin_receive = address(KeyRole::HnsCoin, 3, "coin-receive");
        let coin_at_name_index = address(KeyRole::HnsCoin, 7, "coin-at-name-index");
        let name_seven = address(KeyRole::HnsName, 7, "name-seven");
        let name_eight = address(KeyRole::HnsName, 8, "name-eight");
        let addresses = vec![
            coin_receive,
            coin_at_name_index,
            name_seven.clone(),
            name_eight.clone(),
        ];

        let ordinary = hns_read_receive_target(&account, &addresses).expect("ordinary target");
        let name = hns_read_name_receive_target(&account, &addresses).expect("name target");
        assert_eq!(ordinary.display, "coin-receive");
        assert_eq!(ordinary.derivation_index, 3);
        assert_eq!(name.display, "name-seven");
        assert_eq!(name.derivation_index, 7);
        assert_eq!(name.account, account.config.account_id);
        assert_eq!(name.module, ModuleId::Handshake);

        account.next_name_index = 8;
        let advanced =
            hns_read_name_receive_target(&account, &addresses).expect("advanced name target");
        assert_eq!(advanced.display, "name-eight");
        assert_eq!(advanced.derivation_index, 8);

        account.next_name_index = 6;
        assert!(matches!(
            hns_read_name_receive_target(&account, &addresses),
            Err(HnsWalletError::InvalidEvidence)
        ));
    }

    #[test]
    fn name_receive_target_fails_closed_on_wrong_derivation_or_ambiguous_evidence() {
        let mut account =
            HnsAccountRecord::initial_non_value(test_runtime_config()).expect("non-value account");
        account.next_name_index = 9;
        let valid = DerivedHnsAddress {
            account_id: account.config.account_id,
            derivation: DerivationReference {
                role: KeyRole::HnsName,
                account: account.config.account_derivation_index,
                change: 0,
                index: account.next_name_index,
            },
            address: "name-nine".to_owned(),
            program: vec![9; 20],
            used: false,
        };

        let malformed = vec![
            DerivedHnsAddress {
                derivation: DerivationReference {
                    role: KeyRole::HnsCoin,
                    ..valid.derivation
                },
                ..valid.clone()
            },
            DerivedHnsAddress {
                account_id: AccountId::new([99; 16]),
                ..valid.clone()
            },
            DerivedHnsAddress {
                derivation: DerivationReference {
                    account: valid.derivation.account + 1,
                    ..valid.derivation
                },
                ..valid.clone()
            },
            DerivedHnsAddress {
                derivation: DerivationReference {
                    change: 1,
                    ..valid.derivation
                },
                ..valid.clone()
            },
            DerivedHnsAddress {
                derivation: DerivationReference {
                    index: valid.derivation.index - 1,
                    ..valid.derivation
                },
                ..valid.clone()
            },
            DerivedHnsAddress {
                address: String::new(),
                ..valid.clone()
            },
        ];
        for address in malformed {
            assert!(matches!(
                hns_read_name_receive_target(&account, &[address]),
                Err(HnsWalletError::InvalidEvidence)
            ));
        }
        assert!(matches!(
            hns_read_name_receive_target(&account, &[valid.clone(), valid]),
            Err(HnsWalletError::InvalidEvidence)
        ));
    }

    #[test]
    fn name_and_shakedex_outputs_are_tracked_but_never_ordinary_spend_candidates() {
        for (role, byte) in [(KeyRole::HnsName, 31), (KeyRole::HnsShakedex, 32)] {
            let address = test_derived_address(role, byte);
            let tracked = reconcile_coins(
                vec![IndexedWalletCoin {
                    coin: WalletCoin {
                        outpoint: HnsOutpoint {
                            transaction: TransactionHash::new([byte; 32]),
                            output_index: 1,
                        },
                        value: BaseUnits::new(1_000),
                        confirmation_count: 10,
                        confirmed_height: Some(491),
                        coinbase: false,
                        covenant: Covenant::default().encode().expect("covenant"),
                        name_locked: false,
                    },
                    script_index: 0,
                    output_address: WalletAddressKey {
                        version: 0,
                        hash: address.program.clone(),
                    },
                }],
                &[address],
                500,
            )
            .expect("track separated output");
            assert_eq!(tracked.len(), 1);
            assert_eq!(tracked[0].derivation.role, role);
            assert!(!is_ordinary_hns_spend_candidate(&tracked[0]));
        }
    }

    #[test]
    fn duplicate_programs_and_unsupported_name_branches_fail_closed() {
        let coin = test_derived_address(KeyRole::HnsCoin, 41);
        let name = test_derived_address(KeyRole::HnsName, 41);
        assert!(validate_disjoint_restore_programs(&[coin], &[name], &[]).is_err());
        assert!(
            restore_derivation_key(DerivationReference {
                role: KeyRole::HnsName,
                account: 7,
                change: 1,
                index: 0,
            })
            .is_err()
        );
        assert!(
            restore_derivation_key(DerivationReference {
                role: KeyRole::HnsShakedex,
                account: 7,
                change: 1,
                index: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn coin_selection_excludes_name_locked_outputs_and_is_deterministic() {
        let coins = vec![
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([1; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(7),
                confirmation_count: 1,
                confirmed_height: Some(500),
                coinbase: false,
                covenant: Covenant {
                    kind: CovenantKind::Update,
                    items: Vec::new(),
                }
                .encode()
                .expect("name covenant"),
                name_locked: true,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([2; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(5),
                confirmation_count: 1,
                confirmed_height: Some(500),
                coinbase: false,
                covenant: Covenant::default().encode().expect("covenant"),
                name_locked: false,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([3; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(4),
                confirmation_count: 2,
                confirmed_height: Some(499),
                coinbase: false,
                covenant: Covenant::default().encode().expect("covenant"),
                name_locked: false,
            },
        ];
        let selected = select_coins(&coins, BaseUnits::new(8)).expect("selection");
        assert_eq!(selected.coins.len(), 2);
        assert_eq!(selected.total, BaseUnits::new(9));
        assert_eq!(selected.change, BaseUnits::new(1));
        assert!(
            selected
                .coins
                .iter()
                .all(|coin| !coin.name_locked && !coin.coinbase)
        );
    }

    #[test]
    fn exact_coin_evidence_rejects_legacy_and_mismatched_rows() {
        let covenant = Covenant::default().encode().expect("covenant");
        let tracked = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([61; 32]),
                    output_index: 2,
                },
                value: BaseUnits::new(50_000),
                confirmation_count: 4,
                confirmed_height: Some(497),
                coinbase: false,
                covenant: covenant.clone(),
                name_locked: false,
            },
            derivation: DerivationReference {
                role: KeyRole::HnsCoin,
                account: 7,
                change: 0,
                index: 3,
            },
            address_program: vec![62; 20],
        };
        let canonical = tracked.to_canonical_coin().expect("canonical coin");
        assert_eq!(canonical.height, Height::new(497));
        assert_eq!(canonical.covenant.encode().expect("encode"), covenant);
        assert_eq!(canonical.address.hash, vec![62; 20]);

        let mut legacy = serde_json::to_value(&tracked).expect("tracked coin");
        let coin = legacy
            .get_mut("coin")
            .and_then(serde_json::Value::as_object_mut)
            .expect("coin object");
        coin.remove("confirmed_height");
        coin.remove("covenant");
        let legacy: TrackedHnsCoin = serde_json::from_value(legacy).expect("legacy row decodes");
        assert!(matches!(
            legacy.to_canonical_coin(),
            Err(HnsWalletError::InvalidEvidence)
        ));

        let mut mismatched = tracked;
        mismatched.coin.name_locked = true;
        assert!(matches!(
            mismatched.to_canonical_coin(),
            Err(HnsWalletError::InvalidEvidence)
        ));

        let mut zero_ordinary = mismatched;
        zero_ordinary.coin.name_locked = false;
        zero_ordinary.coin.value = BaseUnits::ZERO;
        assert!(matches!(
            zero_ordinary.to_canonical_coin(),
            Err(HnsWalletError::InvalidEvidence)
        ));
        let mut zero_ordinary_input =
            HnsInputCoinEvidence::from_canonical_coin(&canonical).expect("ordinary input");
        zero_ordinary_input.value = BaseUnits::ZERO;
        assert!(matches!(
            zero_ordinary_input.to_canonical_coin(),
            Err(HnsWalletError::InvalidEvidence)
        ));
        let shakedex_address = test_derived_address(KeyRole::HnsShakedex, 63);
        let zero_shakedex = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([63; 32]),
                    output_index: 0,
                },
                value: BaseUnits::ZERO,
                confirmation_count: 1,
                confirmed_height: Some(500),
                coinbase: false,
                covenant: Covenant::default().encode().expect("NONE covenant"),
                name_locked: false,
            },
            derivation: shakedex_address.derivation,
            address_program: shakedex_address.program,
        };
        assert!(matches!(
            zero_shakedex.to_canonical_coin(),
            Err(HnsWalletError::InvalidEvidence)
        ));
    }

    #[test]
    fn canonical_policy_quote_is_recomputed_from_ordered_input_coins() {
        let input_coin = Coin {
            outpoint: Outpoint {
                transaction_hash: CanonicalTransactionHash::new([71; 32]),
                index: 0,
            },
            value: Dollarydoos::new(100_000),
            height: Height::new(450),
            coinbase: false,
            address: Address::new(0, vec![72; 20]).expect("address"),
            covenant: Covenant::default(),
        };
        let mut transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: input_coin.outpoint,
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![vec![0; 65], vec![0; 33]],
                },
            }],
            outputs: vec![Output {
                value: input_coin.value,
                address: Address::new(0, vec![73; 20]).expect("address"),
                covenant: Covenant::default(),
            }],
            locktime: 0,
        };
        let rate = BaseUnits::new(1_000);
        let fee =
            canonical_policy_minimum_fee(&transaction, std::slice::from_ref(&input_coin), rate)
                .expect("minimum fee");
        transaction.outputs[0].value = Dollarydoos::new(
            input_coin.value.get() - u64::try_from(fee.get()).expect("bounded fee"),
        );
        let local =
            local_fee_policy_evidence(&transaction, std::slice::from_ref(&input_coin), rate)
                .expect("policy evidence");
        let binding = test_snapshot(8);
        let mempool = test_mempool(9);
        let mut quote = HnsTransactionFeeQuote {
            txid: wallet_transaction_hash(&transaction).expect("txid"),
            binding,
            mempool,
            target_blocks: DEFAULT_FEE_TARGET_BLOCKS,
            rate_atomic_units_per_1000_policy_vbytes: 1_000,
            rate_sample_count: 0,
            rate_source: HnsFeeRateSource::MinimumRelay,
            transaction_weight: local.transaction_weight,
            transaction_sigops: local.transaction_sigops,
            sigop_adjusted_policy_vbytes: local.policy_virtual_size,
            minimum_policy_fee: local.minimum_fee,
            actual_fee: fee,
            meets_minimum_policy_fee: true,
            minimum_policy_fee_shortfall: BaseUnits::ZERO,
        };
        assert!(
            validate_local_fee_quote_evidence(
                &transaction,
                std::slice::from_ref(&input_coin),
                &quote,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_final_fee_quote(
                &transaction.encode().expect("transaction"),
                std::slice::from_ref(&input_coin),
                &quote,
                binding,
                mempool,
                fee,
                fee,
            ),
            Err(HnsWalletError::RuntimeIntegrationUnavailable)
        ));
        quote.transaction_sigops = quote.transaction_sigops.saturating_add(1);
        assert!(matches!(
            validate_local_fee_quote_evidence(&transaction, &[input_coin], &quote),
            Err(HnsWalletError::InvalidFeeQuote)
        ));
    }

    #[test]
    fn ordered_p2pkh_signer_enforces_coin_and_name_roles() {
        let mut store = WalletStore::create(":memory:", "passphrase").expect("store");
        let account = HnsAccountRecord {
            config: test_runtime_config(),
            next_receive_index: 0,
            next_change_index: 0,
            next_name_index: 0,
            next_shakedex_index: 0,
            external_scan_end: 99,
            internal_scan_end: 99,
            name_scan_end: 99,
            shakedex_scan_end: 99,
            shakedex_scan_complete: true,
            shakedex_scan_in_progress: false,
            last_used_external: None,
            last_used_internal: None,
            last_used_name: None,
            last_used_shakedex: None,
        };
        store
            .put_secret(
                account.config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[81; 64],
                1,
            )
            .expect("seed");
        let make_coin = |role, index, tx_byte, value| {
            let derivation = DerivationReference {
                role,
                account: account_number(&account),
                change: 0,
                index,
            };
            let public = derive_hns_public_key(&store, account.config.wallet_id, derivation)
                .expect("public key");
            let program = public_key_hash(&public).expect("program").to_vec();
            let covenant = if role == KeyRole::HnsName {
                Covenant {
                    kind: CovenantKind::Update,
                    items: Vec::new(),
                }
            } else {
                Covenant::default()
            };
            TrackedHnsCoin {
                coin: WalletCoin {
                    outpoint: HnsOutpoint {
                        transaction: TransactionHash::new([tx_byte; 32]),
                        output_index: 0,
                    },
                    value: BaseUnits::new(value),
                    confirmation_count: 5,
                    confirmed_height: Some(496),
                    coinbase: false,
                    covenant: covenant.encode().expect("covenant"),
                    name_locked: role == KeyRole::HnsName,
                },
                derivation,
                address_program: program,
            }
        };
        let name = make_coin(KeyRole::HnsName, 1, 82, 50_000);
        let fee = make_coin(KeyRole::HnsCoin, 2, 83, 10_000);
        let inputs = vec![name, fee];
        let transaction = Transaction {
            version: 0,
            inputs: inputs
                .iter()
                .map(|coin| Input {
                    previous_output: coin.to_canonical_coin().expect("coin").outpoint,
                    sequence: u32::MAX,
                    witness: Witness::default(),
                })
                .collect(),
            outputs: vec![Output {
                value: Dollarydoos::new(59_000),
                address: Address::new(0, vec![84; 20]).expect("address"),
                covenant: Covenant::default(),
            }],
            locktime: 0,
        };
        let signed = sign_ordered_p2pkh_inputs(
            &store,
            &account,
            transaction.clone(),
            &inputs,
            &[KeyRole::HnsName, KeyRole::HnsCoin],
        )
        .expect("ordered signing");
        let signed = Transaction::decode(&signed).expect("signed transaction");
        assert!(signed.inputs.iter().all(|input| {
            input.witness.items.len() == 2
                && input.witness.items[0].len() == 65
                && input.witness.items[1].len() == 33
        }));
        assert!(matches!(
            sign_ordered_p2pkh_inputs(
                &store,
                &account,
                transaction,
                &inputs,
                &[KeyRole::HnsCoin, KeyRole::HnsCoin],
            ),
            Err(HnsWalletError::InvalidPreparedArtifact)
        ));
    }

    #[test]
    fn production_followup_account_reads_commit_one_live_binding_without_store_locked_node_io() {
        let (store, config) = production_followup_read_store();
        let runtime = production_followup_read_runtime(
            store.clone(),
            config.clone(),
            ProductionFollowupReadFault::Healthy,
        );

        let snapshot = runtime.synchronize().expect("one synchronized read");
        assert_eq!(snapshot.account_id, config.account_id);
        assert_eq!(
            snapshot.binding.chain,
            ProductionFollowupReadBackend::binding()
        );
        assert_eq!(
            snapshot.binding.mempool,
            ProductionFollowupReadBackend::mempool()
        );
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert!(snapshot.transactions.is_empty());
        assert!(snapshot.known_names.is_empty());
        assert_eq!(snapshot.receive_target.module, ModuleId::Handshake);
        assert_eq!(snapshot.receive_target.account, config.account_id);
        assert_eq!(snapshot.receive_target.derivation_index, 0);
        assert!(snapshot.receive_target.display.starts_with("rs1"));
        assert_eq!(snapshot.name_receive_target.module, ModuleId::Handshake);
        assert_eq!(snapshot.name_receive_target.account, config.account_id);
        assert_eq!(snapshot.name_receive_target.derivation_index, 0);
        assert!(snapshot.name_receive_target.display.starts_with("rs1"));
        assert_ne!(
            snapshot.name_receive_target.display,
            snapshot.receive_target.display
        );
        assert!(!config.value_operations_enabled);
        assert!(!config.settlement_enabled);
        assert_eq!(runtime.backend.snapshot_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.backend.tip_calls.load(Ordering::SeqCst), 0);
        assert!(runtime.backend.confirmed_calls.load(Ordering::SeqCst) > 0);
        assert!(runtime.backend.mempool_calls.load(Ordering::SeqCst) > 0);

        store
            .with_store(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert!(account.value.shakedex_scan_complete);
                assert!(!account.value.shakedex_scan_in_progress);
                let recovery = wallet
                    .hns_recovery_state::<HnsRecoveryState>(&recovery_entity_id(&config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert_eq!(recovery.value.last_tip, Some(snapshot.binding.chain.tip));
                assert_eq!(recovery.value.last_reconciled_unix, 100);
                Ok(())
            })
            .expect("authenticated read commit");
    }

    #[test]
    fn name_history_advances_the_returned_target_to_the_post_scan_index() {
        let (store, config) = production_followup_read_store();
        let account = store
            .with_store(|wallet| {
                wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .map(|stored| stored.value)
                    .ok_or(StoreError::CorruptMetadata)
            })
            .expect("persisted scan account");
        let used_name = store
            .try_with_store(|wallet| {
                derive_restore_addresses(wallet, &account, KeyRole::HnsName)
                    .map(|addresses| addresses.into_iter().next().expect("initial name branch"))
            })
            .expect("derive used name target");
        assert_eq!(used_name.derivation.index, 0);

        let backend = ProductionFollowupReadBackend::new(
            store.clone(),
            &config,
            ProductionFollowupReadFault::Healthy,
        )
        .with_name_history_program(used_name.program.clone());
        let binding = ProductionFollowupReadBackend::binding();
        let scan =
            scan_restore_snapshot(&backend, account, binding.tip, Some(binding), |candidate| {
                store.try_with_store(|wallet| {
                    Ok([
                        derive_restore_addresses(wallet, candidate, KeyRole::HnsCoin)?,
                        derive_restore_addresses(wallet, candidate, KeyRole::HnsName)?,
                        derive_restore_addresses(wallet, candidate, KeyRole::HnsShakedex)?,
                    ])
                })
            })
            .expect("scan name history and extend the trailing gap");

        assert_eq!(scan.account.last_used_name, Some(0));
        assert_eq!(scan.account.next_name_index, 1);
        assert!(scan.account.name_scan_end >= 1);
        let target = hns_read_name_receive_target(&scan.account, &scan.addresses)
            .expect("post-scan name receive target");
        let post_scan_address = scan
            .addresses
            .iter()
            .find(|address| {
                address.derivation.role == KeyRole::HnsName
                    && address.derivation.index == scan.account.next_name_index
            })
            .expect("derived post-scan name address");
        assert_eq!(target.derivation_index, 1);
        assert_eq!(target.display, post_scan_address.address);
        assert_ne!(target.display, used_name.address);
    }

    #[test]
    fn zero_value_incoming_transfer_advances_only_name_key_high_water() {
        let (store, config) = production_followup_read_store();
        let account = store
            .with_store(|wallet| {
                wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .map(|stored| stored.value)
                    .ok_or(StoreError::CorruptMetadata)
            })
            .expect("incoming account");
        let recipient = store
            .try_with_store(|wallet| {
                derive_restore_addresses(wallet, &account, KeyRole::HnsName)
                    .map(|addresses| addresses.into_iter().next().expect("name recipient"))
            })
            .expect("derive incoming recipient");
        let candidate = zero_value_incoming_candidate(&recipient);
        assert_eq!(candidate.transfer_coin.value.get(), 0);
        assert_ne!(candidate.transfer_coin.address.hash, recipient.program);
        let selector = HnsExistingAccountSelector::new(store.clone(), config.clone())
            .expect("incoming selector");
        let backend = ProductionFollowupReadBackend::new(
            store.clone(),
            &config,
            ProductionFollowupReadFault::Healthy,
        )
        .with_incoming_candidate(candidate.clone());
        let runtime =
            HnsAccountReadRuntime::new(backend, ProductionFollowupClock, store.clone(), selector)
                .expect("incoming runtime");

        let snapshot = runtime.synchronize().expect("incoming reconciliation");
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert!(snapshot.transactions.is_empty());
        assert!(snapshot.known_names.is_empty());
        assert_eq!(snapshot.name_receive_target.derivation_index, 1);
        store
            .with_store(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert_eq!(account.value.last_used_name, Some(0));
                assert_eq!(account.value.next_name_index, 1);
                let coins = wallet.list_entities_by_id_prefix::<TrackedHnsCoin>(
                    EntityKind::HnsUtxo,
                    &account_entity_prefix(&config),
                    MAX_WALLET_COINS,
                )?;
                let names = wallet.list_entities_by_id_prefix::<KnownName>(
                    EntityKind::KnownName,
                    &account_entity_prefix(&config),
                    MAX_HISTORY_RESULTS,
                )?;
                assert!(coins.is_empty());
                assert!(names.is_empty());
                assert!(
                    wallet
                        .list_entities_by_id_prefix::<DerivedHnsAddress>(
                            EntityKind::DerivedAddress,
                            &account_entity_prefix(&config),
                            MAX_RESTORE_SCRIPTS_PER_QUERY,
                        )?
                        .iter()
                        .any(|stored| {
                            stored.value.derivation == recipient.derivation && stored.value.used
                        })
                );
                Ok(())
            })
            .expect("incoming high-water commit");
    }

    #[test]
    fn incoming_transfer_pagination_supports_more_than_128_nonempty_name_scripts() {
        let (store, config) = production_followup_read_store();
        let mut account = store
            .with_store(|wallet| {
                wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .map(|stored| stored.value)
                    .ok_or(StoreError::CorruptMetadata)
            })
            .expect("pagination account");
        account.name_scan_end = 128;
        let addresses = store
            .try_with_store(|wallet| derive_restore_addresses(wallet, &account, KeyRole::HnsName))
            .expect("derive 129 name scripts");
        assert_eq!(addresses.len(), 129);
        let candidates = addresses
            .iter()
            .enumerate()
            .map(|(index, address)| {
                zero_value_incoming_candidate_at(
                    address,
                    u32::try_from(index).expect("candidate index"),
                )
            })
            .collect();
        let (scripts, index_remap) = sorted_restore_scripts(&addresses).expect("sorted scripts");
        let backend = ProductionFollowupReadBackend::new(
            store,
            &config,
            ProductionFollowupReadFault::Healthy,
        )
        .with_incoming_candidates(candidates);
        let derivations = load_incoming_transfer_derivations(
            &backend,
            &scripts,
            &index_remap,
            ProductionFollowupReadBackend::binding(),
        )
        .expect("129 nonempty incoming pages");
        assert_eq!(derivations.len(), 129);
        assert_eq!(derivations.first(), Some(&0));
        assert_eq!(derivations.last(), Some(&128));
    }

    #[test]
    fn zero_value_wallet_finalize_requires_exact_active_coin_before_name_insert() {
        let (store, config) = production_followup_read_store();
        let account = store
            .with_store(|wallet| {
                wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .map(|stored| stored.value)
                    .ok_or(StoreError::CorruptMetadata)
            })
            .expect("FINALIZE account");
        let recipient = store
            .try_with_store(|wallet| {
                derive_restore_addresses(wallet, &account, KeyRole::HnsName)
                    .map(|addresses| addresses.into_iter().next().expect("FINALIZE recipient"))
            })
            .expect("derive FINALIZE recipient");
        let (name_hash, coin, evidence) = zero_value_finalize_owner(&recipient);
        assert_eq!(coin.value.get(), 0);
        assert_eq!(
            HnsInputCoinEvidence::from_canonical_coin(&coin)
                .expect("zero FINALIZE input evidence")
                .to_canonical_coin()
                .expect("zero FINALIZE canonical input"),
            coin
        );
        let script = WalletAddressKey {
            version: 0,
            hash: recipient.program.clone(),
        };
        let selector = HnsExistingAccountSelector::new(store.clone(), config.clone())
            .expect("FINALIZE selector");
        let backend = ProductionFollowupReadBackend::new(
            store.clone(),
            &config,
            ProductionFollowupReadFault::Healthy,
        )
        .with_finalize_owner(script, coin.clone(), name_hash, evidence);
        let runtime =
            HnsAccountReadRuntime::new(backend, ProductionFollowupClock, store.clone(), selector)
                .expect("FINALIZE runtime");

        let snapshot = runtime.synchronize().expect("FINALIZE reconciliation");
        assert_eq!(snapshot.balance, Amount::new(WalletAsset::Hns, 0));
        assert_eq!(snapshot.known_names.len(), 1);
        assert_eq!(snapshot.known_names[0].name, b"alpha");
        assert_eq!(snapshot.known_names[0].name_hash, name_hash);
        assert_eq!(snapshot.known_names[0].proof_state, None);
        assert!(matches!(
            snapshot.known_names[0].ownership_status,
            NameOwnershipStatus::WalletOwned { derivation }
                if derivation == recipient.derivation
        ));
        assert_eq!(snapshot.name_receive_target.derivation_index, 1);
        let refreshed = runtime
            .synchronize()
            .expect("persisted FINALIZE rediscovery");
        assert_eq!(refreshed.known_names.len(), 1);
        assert_eq!(refreshed.known_names[0].name_hash, name_hash);
        store
            .with_store(|wallet| {
                let names = wallet.list_entities_by_id_prefix::<KnownName>(
                    EntityKind::KnownName,
                    &account_entity_prefix(&config),
                    MAX_HISTORY_RESULTS,
                )?;
                let coins = wallet.list_entities_by_id_prefix::<TrackedHnsCoin>(
                    EntityKind::HnsUtxo,
                    &account_entity_prefix(&config),
                    MAX_WALLET_COINS,
                )?;
                assert_eq!(names.len(), 1);
                assert_eq!(names[0].revision, 2);
                assert_eq!(coins.len(), 1);
                assert!(coins[0].value.coin.value.is_zero());
                assert_eq!(
                    coins[0].value.to_canonical_coin().expect("zero name Coin"),
                    coin
                );
                Ok(())
            })
            .expect("revision-zero name insertion");
    }

    #[test]
    fn mismatched_active_finalize_coin_fails_before_name_or_coin_commit() {
        let (store, config) = production_followup_read_store();
        let account = store
            .with_store(|wallet| {
                wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&config))?
                    .map(|stored| stored.value)
                    .ok_or(StoreError::CorruptMetadata)
            })
            .expect("mismatch account");
        let recipient = store
            .try_with_store(|wallet| {
                derive_restore_addresses(wallet, &account, KeyRole::HnsName)
                    .map(|addresses| addresses.into_iter().next().expect("mismatch recipient"))
            })
            .expect("derive mismatch recipient");
        let (name_hash, coin, mut evidence) = zero_value_finalize_owner(&recipient);
        evidence.owner_coin.address =
            Address::new(0, vec![0xb1; 20]).expect("mismatched active address");
        let selector = HnsExistingAccountSelector::new(store.clone(), config.clone())
            .expect("mismatch selector");
        let backend = ProductionFollowupReadBackend::new(
            store.clone(),
            &config,
            ProductionFollowupReadFault::Healthy,
        )
        .with_finalize_owner(
            WalletAddressKey {
                version: 0,
                hash: recipient.program,
            },
            coin,
            name_hash,
            evidence,
        );
        let runtime =
            HnsAccountReadRuntime::new(backend, ProductionFollowupClock, store.clone(), selector)
                .expect("mismatch runtime");
        assert!(matches!(
            runtime.synchronize(),
            Err(HnsWalletError::InvalidEvidence)
        ));
        store
            .with_store(|wallet| {
                assert!(
                    wallet
                        .list_entities_by_id_prefix::<KnownName>(
                            EntityKind::KnownName,
                            &account_entity_prefix(&config),
                            MAX_HISTORY_RESULTS,
                        )?
                        .is_empty()
                );
                assert!(
                    wallet
                        .list_entities_by_id_prefix::<TrackedHnsCoin>(
                            EntityKind::HnsUtxo,
                            &account_entity_prefix(&config),
                            MAX_WALLET_COINS,
                        )?
                        .is_empty()
                );
                Ok(())
            })
            .expect("no mismatched authority commit");
    }

    #[test]
    fn production_followup_account_reads_reject_mainnet_genesis_for_regtest_account() {
        let (store, config) = production_followup_read_store();
        assert_eq!(config.network, HnsNetwork::Regtest);
        let runtime = production_followup_read_runtime(
            store,
            config,
            ProductionFollowupReadFault::WrongNetwork,
        );
        assert!(matches!(
            runtime.synchronize(),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert_eq!(runtime.backend.snapshot_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.backend.tip_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.backend.confirmed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.backend.mempool_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn production_followup_account_reads_fail_closed_on_stale_restart_account_and_lock_fences() {
        let (stale_store, stale_config) = production_followup_read_store();
        let stale = production_followup_read_runtime(
            stale_store.clone(),
            stale_config.clone(),
            ProductionFollowupReadFault::StaleChain,
        );
        assert!(matches!(
            stale.synchronize(),
            Err(HnsWalletError::StaleNodeSnapshot)
        ));
        stale_store
            .with_store(|wallet| {
                let account = wallet
                    .wallet_account::<HnsAccountRecord>(&account_entity_id(&stale_config))?
                    .ok_or(StoreError::CorruptMetadata)?;
                assert!(account.value.shakedex_scan_in_progress);
                assert!(!account.value.shakedex_scan_complete);
                Ok(())
            })
            .expect("durable stale scan fence");
        drop(stale);
        let recovered = production_followup_read_runtime(
            stale_store,
            stale_config,
            ProductionFollowupReadFault::Healthy,
        );
        recovered
            .synchronize()
            .expect("fresh process recovers the durable scan fence");

        let (restart_store, restart_config) = production_followup_read_store();
        let restarted_node = production_followup_read_runtime(
            restart_store,
            restart_config,
            ProductionFollowupReadFault::RestartedMempool,
        );
        assert!(matches!(
            restarted_node.synchronize(),
            Err(HnsWalletError::StaleNodeSnapshot)
        ));

        let (changed_store, changed_config) = production_followup_read_store();
        let changed_account = production_followup_read_runtime(
            changed_store,
            changed_config,
            ProductionFollowupReadFault::ChangedAccount,
        );
        assert!(matches!(
            changed_account.synchronize(),
            Err(HnsWalletError::StaleAccountRead)
        ));

        let (locked_store, locked_config) = production_followup_read_store();
        let locked = production_followup_read_runtime(
            locked_store.clone(),
            locked_config,
            ProductionFollowupReadFault::LockedStore,
        );
        assert!(matches!(
            locked.synchronize(),
            Err(HnsWalletError::StoreLocked)
        ));
        assert!(locked_store.is_locked().expect("locked read store"));

        let (selector_store, selector_config) = production_followup_read_store();
        let selector = HnsExistingAccountSelector::new(selector_store, selector_config.clone())
            .expect("selector authority");
        let (different_store, _) = production_followup_read_store();
        assert!(matches!(
            HnsAccountReadRuntime::new(
                ProductionFollowupReadBackend::new(
                    different_store.clone(),
                    &selector_config,
                    ProductionFollowupReadFault::Healthy,
                ),
                ProductionFollowupClock,
                different_store,
                selector,
            ),
            Err(HnsWalletError::StoreAuthorityMismatch)
        ));
    }

    #[test]
    fn persisted_flagged_accounts_reject_ordinary_reads_but_allow_closed_lifecycle() {
        for (network, value_operations_enabled, settlement_enabled) in [
            (HnsNetwork::Mainnet, true, false),
            (HnsNetwork::Mainnet, false, true),
            (HnsNetwork::Testnet, true, false),
            (HnsNetwork::Testnet, false, true),
            (HnsNetwork::Testnet, true, true),
        ] {
            let mut config = test_runtime_config();
            config.network = network;
            config.birthday_height = 0;
            config.restore_lookahead = 1;
            config.minimum_confirmations = 1;
            config.value_operations_enabled = value_operations_enabled;
            config.settlement_enabled = settlement_enabled;
            let store = production_followup_read_store_for_config(config.clone());

            config
                .validate_structure()
                .expect("flagged account structure remains valid");
            if network == HnsNetwork::Mainnet {
                assert!(matches!(
                    config.validate(),
                    Err(HnsWalletError::MainnetDisabled)
                ));
            } else {
                assert!(matches!(
                    config.validate(),
                    Err(HnsWalletError::RuntimeIntegrationUnavailable)
                ));
            }
            assert!(matches!(
                HnsExistingAccountSelector::new(store.clone(), config.clone()),
                Err(HnsWalletError::MainnetDisabled)
                    | Err(HnsWalletError::RuntimeIntegrationUnavailable)
            ));
            let lifecycle =
                HnsExistingAccountSelector::new_lifecycle(store.clone(), config.clone())
                    .expect("structure-only lifecycle selector");
            assert_eq!(
                lifecycle
                    .selected_account()
                    .expect("exact lifecycle account")
                    .config,
                config
            );

            let full_store = WalletStore::create(":memory:", PRODUCTION_FOLLOWUP_PASSPHRASE)
                .expect("create ordinary full-runtime store");
            assert!(matches!(
                HnsWalletRuntime::open(
                    ProductionFollowupReadBackend::new(
                        store.clone(),
                        &config,
                        ProductionFollowupReadFault::Healthy,
                    ),
                    full_store,
                    config.clone(),
                    ProductionFollowupClock,
                ),
                Err(HnsWalletError::MainnetDisabled)
                    | Err(HnsWalletError::RuntimeIntegrationUnavailable)
            ));

            let runtime = production_followup_recovery_read_runtime(
                store.clone(),
                config.clone(),
                ProductionFollowupReadFault::Healthy,
            );
            assert_eq!(
                runtime
                    .selected_account()
                    .expect("exact flagged account")
                    .config,
                config
            );
            let snapshot = runtime.synchronize().expect("recovery-only read");
            assert_eq!(snapshot.account_id, config.account_id);
            drop(runtime);

            let restarted = production_followup_recovery_read_runtime(
                store.clone(),
                config.clone(),
                ProductionFollowupReadFault::Healthy,
            );
            restarted
                .synchronize()
                .expect("restarted recovery-only read");
            assert_eq!(
                restarted
                    .selected_account()
                    .expect("restarted exact account")
                    .config,
                config
            );

            let (different_store, _) = production_followup_read_store();
            assert!(!restarted.shares_store_authority(&different_store));
            assert!(restarted.shares_store_authority(&store));
        }
    }

    #[test]
    fn persisted_flagged_recovery_reads_reject_missing_mismatch_and_live_fence_changes() {
        let recovery_config = || {
            let mut config = test_runtime_config();
            config.network = HnsNetwork::Testnet;
            config.birthday_height = 0;
            config.restore_lookahead = 1;
            config.minimum_confirmations = 1;
            config.value_operations_enabled = true;
            config
        };

        let missing_config = recovery_config();
        let missing_store = SharedWalletStore::new(
            WalletStore::create(":memory:", PRODUCTION_FOLLOWUP_PASSPHRASE)
                .expect("create missing-account store"),
        );
        let missing = production_followup_recovery_read_runtime(
            missing_store,
            missing_config,
            ProductionFollowupReadFault::Healthy,
        );
        assert!(matches!(
            missing.selected_account(),
            Err(HnsWalletError::AccountConfigurationMismatch)
        ));

        let config = recovery_config();
        let mismatch_store = production_followup_read_store_for_config(config.clone());
        let mut mismatched = config.clone();
        mismatched.value_operations_enabled = false;
        mismatched.settlement_enabled = true;
        let mismatch = production_followup_recovery_read_runtime(
            mismatch_store,
            mismatched,
            ProductionFollowupReadFault::Healthy,
        );
        assert!(matches!(
            mismatch.selected_account(),
            Err(HnsWalletError::AccountConfigurationMismatch)
        ));

        for fault in [
            ProductionFollowupReadFault::StaleChain,
            ProductionFollowupReadFault::RestartedMempool,
            ProductionFollowupReadFault::ChangedAccount,
            ProductionFollowupReadFault::LockedStore,
        ] {
            let config = recovery_config();
            let store = production_followup_read_store_for_config(config.clone());
            let runtime = production_followup_recovery_read_runtime(store, config, fault);
            let result = runtime.synchronize();
            match fault {
                ProductionFollowupReadFault::StaleChain
                | ProductionFollowupReadFault::RestartedMempool => {
                    assert!(matches!(result, Err(HnsWalletError::StaleNodeSnapshot)));
                }
                ProductionFollowupReadFault::ChangedAccount => {
                    assert!(matches!(result, Err(HnsWalletError::StaleAccountRead)));
                }
                ProductionFollowupReadFault::LockedStore => {
                    assert!(matches!(result, Err(HnsWalletError::StoreLocked)));
                }
                _ => unreachable!("the recovery fence matrix contains only fault cases"),
            }
        }
    }

    #[test]
    fn hns_shakedex_role_separation_has_stable_recovery_vector() {
        let seed = [7_u8; 64];
        let coin = derive_secret(
            &seed,
            DerivationReference {
                role: KeyRole::HnsCoin,
                account: 0,
                change: 0,
                index: 0,
            },
        )
        .expect("coin key");
        let name = derive_secret(
            &seed,
            DerivationReference {
                role: KeyRole::HnsName,
                account: 0,
                change: 0,
                index: 0,
            },
        )
        .expect("name key");
        let shakedex = derive_secret(
            &seed,
            DerivationReference {
                role: KeyRole::HnsShakedex,
                account: 0,
                change: 0,
                index: 0,
            },
        )
        .expect("Shakedex key");
        assert_ne!(*coin, *name);
        assert_ne!(*coin, *shakedex);
        assert_ne!(*name, *shakedex);
        assert_eq!(
            hex::encode(shakedex.as_slice()),
            "c1f343c505fbf40e41d41b4ad3571fb93c49f7687d197568ab901678a44c4d49"
        );
        let shakedex_signing =
            SigningKey::from_slice(shakedex.as_slice()).expect("Shakedex signing key");
        let shakedex_public: [u8; 33] = shakedex_signing
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed Shakedex key");
        assert_eq!(
            hex::encode(shakedex_public),
            "02479c879e5f2e087a998d5fa57ad1720ab8d56171b13f191beae222ddae20fb4a"
        );
        let shakedex_program = lock_script_hash(&shakedex_public);
        assert_eq!(
            hex::encode(shakedex_program),
            "b1194ad181a74b263cc84b8e80ca9078e32c15e72128c3473700f23c46ed9cca"
        );
        assert_eq!(
            encode_v0_address(HnsNetwork::Regtest, &shakedex_program)
                .expect("Shakedex lock address"),
            "rs1qkyv545vp5a9jv0xgfw8gpj5s0r3jc908yy5vx3ehqrerc3hdnn9qj0j5a4"
        );
        let signing = SigningKey::from_slice(coin.as_slice()).expect("signing key");
        let public: [u8; 33] = VerifyingKey::from(&signing)
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key");
        assert!(
            receive_address(HnsNetwork::Mainnet, &public)
                .expect("mainnet")
                .starts_with("hs1")
        );
        assert!(
            receive_address(HnsNetwork::Regtest, &public)
                .expect("regtest")
                .starts_with("rs1")
        );
    }
}
