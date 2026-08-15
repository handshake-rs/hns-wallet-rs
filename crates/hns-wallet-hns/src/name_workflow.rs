use super::*;

/// Wallet-owned base-name action. Shakedex script-controlled transitions use
/// separate authorities and must not be routed through this P2PKH workflow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsNameAction {
    Transfer,
    Finalize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HnsNameLifecycle {
    Opening,
    Locked,
    Bidding,
    Reveal,
    Closed,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameActionIneligibility {
    NameNotRegistered,
    NameExpiredAtCandidate,
    LifecycleNotClosed,
    TransferAlreadyPending,
    TransferNotPending,
    TransferNotMature,
    OwnerCovenantInvalidForAction,
    RenewalCommitmentInvalid,
    OwnerSpentInMempool,
}

impl NameActionIneligibility {
    pub(super) const fn rank(self) -> u8 {
        match self {
            Self::NameNotRegistered => 0,
            Self::NameExpiredAtCandidate => 1,
            Self::LifecycleNotClosed => 2,
            Self::TransferAlreadyPending => 3,
            Self::TransferNotPending => 4,
            Self::TransferNotMature => 5,
            Self::OwnerCovenantInvalidForAction => 6,
            Self::RenewalCommitmentInvalid => 7,
            Self::OwnerSpentInMempool => 8,
        }
    }
}

impl HnsNameAction {
    pub(super) const fn workflow_kind(self) -> WorkflowKind {
        match self {
            Self::Transfer => WorkflowKind::NameTransfer,
            Self::Finalize => WorkflowKind::NameFinalize,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrepareNameTransfer {
    pub account: AccountId,
    pub request_nonce: u64,
    pub name: Vec<u8>,
    pub recipient: String,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrepareNameFinalize {
    pub account: AccountId,
    pub request_nonce: u64,
    pub name: Vec<u8>,
    /// Optional display expectation only. The authenticated TRANSFER covenant,
    /// never this value, supplies the FINALIZE destination.
    pub expected_recipient: Option<String>,
    pub maximum_fee: BaseUnits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOperationState {
    Prepared,
    Authorized,
    RequiresRebroadcast,
    Broadcast,
    Mempool,
    TransferLocked,
    FinalizeEligible,
    Finalized,
    TransferCancelled,
    ReapprovalRequired,
    Conflicted,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameOperation {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub action: HnsNameAction,
    pub name: Vec<u8>,
    pub name_hash: ObjectHash,
    pub state: NameOperationState,
    pub transaction: Option<TransactionHash>,
    pub recipient: String,
    pub fee: BaseUnits,
    pub maximum_fee: BaseUnits,
    pub transfer_height: Option<u64>,
    pub finalize_eligible_height: Option<u64>,
    pub last_verified_height: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreparedNameOperation {
    pub action: HnsNameAction,
    pub workflow_id: WorkflowId,
    pub name: Vec<u8>,
    pub name_hash: ObjectHash,
    pub recipient: String,
    pub fee: BaseUnits,
    pub maximum_fee: BaseUnits,
    pub expires_at_unix: u64,
    authorization_commitment: Vec<u8>,
}

impl PreparedNameOperation {
    pub fn authorization_commitment(&self) -> &[u8] {
        &self.authorization_commitment
    }
}

impl fmt::Debug for PreparedNameOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNameOperation")
            .field("action", &self.action)
            .field("workflow_id", &self.workflow_id)
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("name_hash", &self.name_hash)
            .field("recipient", &self.recipient)
            .field("fee", &self.fee)
            .field("maximum_fee", &self.maximum_fee)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("authorization_commitment", &"[OPAQUE]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedNameOperation {
    pub action: HnsNameAction,
    pub workflow_id: WorkflowId,
    pub approval_id: ApprovalId,
    pub transaction: TransactionHash,
    signed_transaction: Vec<u8>,
}

impl AuthorizedNameOperation {
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.signed_transaction
    }

    pub fn into_transaction(self) -> Vec<u8> {
        self.signed_transaction
    }
}

impl fmt::Debug for AuthorizedNameOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedNameOperation")
            .field("action", &self.action)
            .field("workflow_id", &self.workflow_id)
            .field("approval_id", &self.approval_id)
            .field("transaction", &self.transaction)
            .field("signed_transaction", &"[REDACTED]")
            .finish()
    }
}

/// Snapshot-bound policy and active-chain evidence returned by the canonical
/// node for one exact owner outpoint and candidate name action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameActionContextEvidence {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub network: HnsNetwork,
    pub network_id: u8,
    pub genesis_hash: [u8; 32],
    pub context_version: u32,
    pub consensus_profile: String,
    pub action: HnsNameAction,
    pub name_hash: [u8; 32],
    pub current_state: Vec<u8>,
    pub owner_outpoint: HnsOutpoint,
    pub owner_transaction: Vec<u8>,
    pub owner_inclusion: TransactionInclusion,
    pub candidate_inclusion_height: u64,
    pub lifecycle: HnsNameLifecycle,
    pub action_eligible: bool,
    pub ineligibility_reasons: Vec<NameActionIneligibility>,
    pub transfer_height: Option<u64>,
    pub transfer_lockup: Option<u32>,
    pub finalize_eligible_height: Option<u64>,
    pub finalize_mature: Option<bool>,
    pub renewal_maturity: Option<u32>,
    pub renewal_period: Option<u32>,
    pub renewal_block_height: Option<u64>,
    pub renewal_block_hash: Option<[u8; 32]>,
    pub renewal_valid_at_candidate: Option<bool>,
    pub mempool_spender: Option<TransactionHash>,
}

/// Ephemeral current-chain authority for one canonical, unspent Shakedex
/// FINALIZE lock. It is deliberately non-cloneable and non-serializable; a
/// restart, reorg, or mempool-generation change requires reacquisition.
pub struct VerifiedCurrentShakedexLock {
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    observed_at_unix: u64,
    descriptor: hns_swap::ShakedexLockDescriptor,
    locking_coin: Coin,
    current_state: NameState,
    board_context: Option<VerifiedHnsBoardContext>,
}

/// Exact caller-owned input for one query-scoped Shakedex lock lookup.
///
/// Construction does not validate the fields. The batch runtime validates
/// every name and compressed seller key, and rejects repeated names even under
/// different seller keys, before it reads the selected account or invokes any
/// node or clock method.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CurrentShakedexLockQuery {
    pub name: Vec<u8>,
    pub seller_public_key: [u8; 33],
}

/// One ordered lock entry retained under a
/// [`VerifiedCurrentShakedexLockBatch`].
///
/// This object deliberately carries no independent chain, mempool, time, or
/// account authority. Callers must keep and fence its non-cloneable parent
/// batch for the complete operation.
pub struct VerifiedCurrentShakedexLockEntry {
    descriptor: hns_swap::ShakedexLockDescriptor,
    locking_coin: Coin,
    current_state: NameState,
}

impl VerifiedCurrentShakedexLockEntry {
    pub const fn descriptor(&self) -> &hns_swap::ShakedexLockDescriptor {
        &self.descriptor
    }

    pub const fn locking_coin(&self) -> &Coin {
        &self.locking_coin
    }

    pub const fn current_name_state(&self) -> &NameState {
        &self.current_state
    }
}

impl fmt::Debug for VerifiedCurrentShakedexLockEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCurrentShakedexLockEntry")
            .field("locking_outpoint", &self.locking_coin.outpoint)
            .field(
                "name_hash",
                &hex::encode(self.current_state.name_hash.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

/// Ephemeral authority for an ordered batch of exact current Shakedex locks.
///
/// The batch is intentionally non-cloneable and non-serializable. All entries
/// share one selected account row/revision, chain/genesis snapshot, mempool
/// instance/generation, and trusted clock observation. A related board read
/// must consume the batch through [`Self::revalidate_unchanged_account`] in
/// the same snapshot. `verify_unchanged_account` is a read-only diagnostic,
/// not an atomic precondition for a later write.
pub struct VerifiedCurrentShakedexLockBatch {
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    context: VerifiedHnsBoardContext,
    locks: Vec<VerifiedCurrentShakedexLockEntry>,
}

impl VerifiedCurrentShakedexLockBatch {
    pub const fn binding(&self) -> SnapshotBinding {
        self.binding
    }

    pub const fn mempool_binding(&self) -> MempoolSnapshotBinding {
        self.mempool
    }

    pub const fn observed_at_unix(&self) -> u64 {
        self.context.observed_at_unix()
    }

    pub const fn network(&self) -> NetworkBinding {
        self.context.network()
    }

    pub fn locks(&self) -> &[VerifiedCurrentShakedexLockEntry] {
        &self.locks
    }

    pub fn len(&self) -> usize {
        self.locks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }

    /// Perform a coherent read-only recheck of the exact selected account row
    /// and revision. This returns no guard for a later write. Identical
    /// shared-store authority must be established separately by the enclosing
    /// runtime.
    pub fn verify_unchanged_account(&self, store: &WalletStore) -> Result<(), HnsWalletError> {
        self.context.verify_unchanged_account(store)
    }

    /// Consume and refresh the exact selected-account set inside the same
    /// coherent snapshot used by a downstream board read.
    pub fn revalidate_unchanged_account(
        mut self,
        snapshot: &EntityReadSnapshot<'_>,
    ) -> Result<Self, HnsWalletError> {
        self.context = self.context.revalidate_unchanged_account(snapshot)?;
        Ok(self)
    }

    fn into_single(self) -> Result<VerifiedCurrentShakedexLock, HnsWalletError> {
        let Self {
            binding,
            mempool,
            context,
            mut locks,
        } = self;
        if locks.len() != 1 {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let lock = locks.pop().ok_or(HnsWalletError::InvalidEvidence)?;
        Ok(VerifiedCurrentShakedexLock {
            binding,
            mempool,
            observed_at_unix: context.observed_at_unix(),
            descriptor: lock.descriptor,
            locking_coin: lock.locking_coin,
            current_state: lock.current_state,
            board_context: Some(context),
        })
    }
}

impl fmt::Debug for VerifiedCurrentShakedexLockBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCurrentShakedexLockBatch")
            .field("binding", &self.binding)
            .field("mempool", &self.mempool)
            .field("context", &self.context)
            .field("locks", &self.locks)
            .finish_non_exhaustive()
    }
}

impl VerifiedCurrentShakedexLock {
    pub const fn binding(&self) -> SnapshotBinding {
        self.binding
    }

    pub const fn mempool_binding(&self) -> MempoolSnapshotBinding {
        self.mempool
    }

    /// Trusted runtime wall time sampled for this exact current-lock query.
    /// Persisted board bytes cannot recreate this observation after restart.
    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub const fn parent_median_time(&self) -> u64 {
        self.binding.tip.median_time_past
    }

    pub const fn descriptor(&self) -> &hns_swap::ShakedexLockDescriptor {
        &self.descriptor
    }

    pub const fn locking_coin(&self) -> &Coin {
        &self.locking_coin
    }

    pub const fn current_name_state(&self) -> &NameState {
        &self.current_state
    }

    /// Consume and refresh the exact selected-account set inside the same
    /// coherent snapshot used by a downstream board read.
    pub fn revalidate_unchanged_account(
        mut self,
        snapshot: &EntityReadSnapshot<'_>,
    ) -> Result<Self, HnsWalletError> {
        let context = self
            .board_context
            .take()
            .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)?;
        self.board_context = Some(context.revalidate_unchanged_account(snapshot)?);
        Ok(self)
    }

    /// Consume the account-read authority into an atomic account-prefix
    /// guard. Value-runtime locks intentionally do not carry this capability.
    pub fn into_account_prefix_lease(mut self) -> Result<EntityPrefixSetLease, HnsWalletError> {
        self.board_context
            .take()
            .map(VerifiedHnsBoardContext::into_account_prefix_lease)
            .ok_or(HnsWalletError::RuntimeIntegrationUnavailable)
    }
}

impl fmt::Debug for VerifiedCurrentShakedexLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCurrentShakedexLock")
            .field("binding", &self.binding)
            .field("mempool", &self.mempool)
            .field("observed_at_unix", &self.observed_at_unix)
            .field("locking_outpoint", &self.locking_coin.outpoint)
            .field(
                "name_hash",
                &hex::encode(self.current_state.name_hash.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

/// Ephemeral current-chain authority for the exact unspent TRANSFER created
/// from a Shakedex lock. It additionally binds the exact active-chain owner
/// inclusion and canonical FINALIZE renewal evidence under the same
/// chain/mempool snapshot.
pub struct VerifiedCurrentShakedexTransfer {
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    descriptor: hns_swap::ShakedexLockDescriptor,
    transfer_transaction: Transaction,
    transfer_coin: Coin,
    owner_inclusion: TransactionInclusion,
    current_state: NameState,
    renewal_block_height: u64,
    renewal_block_hash: [u8; 32],
}

impl VerifiedCurrentShakedexTransfer {
    pub const fn binding(&self) -> SnapshotBinding {
        self.binding
    }

    pub const fn mempool_binding(&self) -> MempoolSnapshotBinding {
        self.mempool
    }

    pub const fn descriptor(&self) -> &hns_swap::ShakedexLockDescriptor {
        &self.descriptor
    }

    pub const fn transfer_transaction(&self) -> &Transaction {
        &self.transfer_transaction
    }

    pub const fn transfer_coin(&self) -> &Coin {
        &self.transfer_coin
    }

    pub const fn owner_inclusion(&self) -> TransactionInclusion {
        self.owner_inclusion
    }

    pub const fn current_name_state(&self) -> &NameState {
        &self.current_state
    }

    pub const fn renewal_block_height(&self) -> u64 {
        self.renewal_block_height
    }

    pub const fn renewal_block_hash(&self) -> [u8; 32] {
        self.renewal_block_hash
    }
}

impl fmt::Debug for VerifiedCurrentShakedexTransfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCurrentShakedexTransfer")
            .field("binding", &self.binding)
            .field("mempool", &self.mempool)
            .field("transfer_outpoint", &self.transfer_coin.outpoint)
            .field("owner_inclusion", &self.owner_inclusion)
            .field(
                "name_hash",
                &hex::encode(self.current_state.name_hash.as_bytes()),
            )
            .field("renewal_block_height", &self.renewal_block_height)
            .field("renewal_block_hash", &hex::encode(self.renewal_block_hash))
            .finish_non_exhaustive()
    }
}

/// Non-serializable authorization to spend one confirmed outgoing TRANSFER.
/// The old owner-address key signs direct FINALIZE; merely being the incoming
/// recipient does not confer signing authority.
pub struct VerifiedOutgoingNameTransfer {
    pub(super) binding: SnapshotBinding,
    pub(super) mempool: MempoolSnapshotBinding,
    pub(super) name: Vec<u8>,
    pub(super) name_hash: [u8; 32],
    pub(super) current_state: Vec<u8>,
    pub(super) owner_outpoint: HnsOutpoint,
    pub(super) owner_transaction: Vec<u8>,
    pub(super) owner_output: Output,
    pub(super) owner_inclusion: TransactionInclusion,
    pub(super) owner_derivation: DerivationReference,
    pub(super) recipient: WalletAddressKey,
    pub(super) context: NameActionContextEvidence,
}

impl fmt::Debug for VerifiedOutgoingNameTransfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedOutgoingNameTransfer")
            .field("binding", &self.binding)
            .field("mempool", &self.mempool)
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("name_hash", &hex::encode(self.name_hash))
            .field("owner_outpoint", &self.owner_outpoint)
            .field("owner_inclusion", &self.owner_inclusion)
            .field("owner_derivation", &self.owner_derivation)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

impl VerifiedOutgoingNameTransfer {
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

    pub const fn owner_outpoint(&self) -> HnsOutpoint {
        self.owner_outpoint
    }

    pub const fn owner_inclusion(&self) -> TransactionInclusion {
        self.owner_inclusion
    }

    pub const fn owner_derivation(&self) -> DerivationReference {
        self.owner_derivation
    }

    pub fn recipient(&self) -> &WalletAddressKey {
        &self.recipient
    }

    pub const fn finalize_eligible_height(&self) -> Option<u64> {
        self.context.finalize_eligible_height
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct HnsNameSourceEvidence {
    pub preparation_binding: SnapshotBinding,
    pub preparation_mempool: MempoolSnapshotBinding,
    pub current_name_state: Vec<u8>,
    pub owner_outpoint: HnsOutpoint,
    pub owner_transaction: Vec<u8>,
    pub owner_inclusion: TransactionInclusion,
    pub owner_derivation: DerivationReference,
    pub action_context: NameActionContextEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct HnsFinalizeTerms {
    pub transfer_height: u64,
    pub finalize_eligible_height: u64,
    pub renewal_maturity: u32,
    pub renewal_period: u32,
    pub renewal_block_height: u64,
    pub renewal_block_hash: [u8; 32],
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct HnsNamePlan {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    pub workflow_id: WorkflowId,
    pub request_nonce: u64,
    pub action: HnsNameAction,
    pub name: Vec<u8>,
    pub name_hash: [u8; 32],
    pub source: HnsNameSourceEvidence,
    pub recipient: WalletAddressKey,
    pub recipient_display: String,
    pub finalize: Option<HnsFinalizeTerms>,
    pub funding_inputs: Vec<TrackedHnsCoin>,
    pub unsigned_transaction: Vec<u8>,
    pub fee_rate: BaseUnits,
    pub fee: BaseUnits,
    pub maximum_fee: BaseUnits,
    pub expires_at_unix: u64,
}

impl fmt::Debug for HnsNamePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsNamePlan")
            .field("workflow_id", &self.workflow_id)
            .field("action", &self.action)
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("name_hash", &hex::encode(self.name_hash))
            .field("owner_outpoint", &self.source.owner_outpoint)
            .field("recipient_display", &self.recipient_display)
            .field("funding_inputs", &self.funding_inputs.len())
            .field("fee", &self.fee)
            .field("maximum_fee", &self.maximum_fee)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct HnsNameWorkflow {
    pub plan: HnsNamePlan,
    pub stage: NameOperationState,
    pub transaction: Option<TransactionHash>,
    pub signed_transaction: Option<Vec<u8>>,
    #[serde(default)]
    pub fee_quote: Option<HnsTransactionFeeQuote>,
    pub last_verified_binding: Option<SnapshotBinding>,
    pub last_verified_inclusion: Option<TransactionInclusion>,
    #[serde(default)]
    pub last_finalize_eligible_height: Option<u64>,
}

impl fmt::Debug for HnsNameWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsNameWorkflow")
            .field("plan", &self.plan)
            .field("stage", &self.stage)
            .field("transaction", &self.transaction)
            .field(
                "signed_transaction",
                &self.signed_transaction.as_ref().map(|_| "[REDACTED]"),
            )
            .field("fee_quote", &self.fee_quote)
            .field("last_verified_binding", &self.last_verified_binding)
            .field("last_verified_inclusion", &self.last_verified_inclusion)
            .field(
                "last_finalize_eligible_height",
                &self.last_finalize_eligible_height,
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct HnsNameApproval {
    pub workflow_id: WorkflowId,
    pub commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(super) enum HnsInputReservationKind {
    #[default]
    Ordinary,
    Name {
        name_hash: [u8; 32],
    },
    ShakedexSource {
        name_hash: [u8; 32],
        purpose: HnsShakedexFundingPurpose,
    },
    ShakedexFunding {
        name_hash: [u8; 32],
        purpose: HnsShakedexFundingPurpose,
    },
}

impl HnsInputReservationKind {
    pub(super) const fn is_protected_shakedex(self) -> bool {
        matches!(
            self,
            Self::ShakedexSource { .. } | Self::ShakedexFunding { .. }
        )
    }
}

pub(super) const NAME_ACTION_CONTEXT_VERSION: u32 = 1;
pub(super) const NAME_ACTION_CONSENSUS_PROFILE: &str = "hns-consensus/name-policy-v1";

fn ensure_name_value_ready(cache: &HnsRuntimeCache) -> Result<(), HnsWalletError> {
    if !HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
        || !cache.account.config.value_operations_enabled
    {
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
    }
    if cache.sync.phase != SyncPhase::Ready
        || cache.sync.validated_height != cache.sync.scanned_height
        || cache.sync.target_height != Some(cache.sync.validated_height)
        || cache.binding.is_none()
        || cache.mempool_binding.is_none()
    {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(())
}

pub(super) fn expected_chain_identity(
    network: HnsNetwork,
) -> Result<(u8, [u8; 32]), HnsWalletError> {
    let (network_id, encoded) = match network {
        HnsNetwork::Mainnet => (
            0,
            "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
        ),
        HnsNetwork::Testnet => (
            1,
            "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
        ),
        HnsNetwork::Regtest => (
            2,
            "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
        ),
        HnsNetwork::Simnet => (
            3,
            "0e648edc9cddb179014658061ea3f666a45cf44881877ae506e6babefbef6992",
        ),
    };
    let mut genesis_hash = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut genesis_hash).map_err(|_| HnsWalletError::Encoding)?;
    Ok((network_id, genesis_hash))
}

fn encode_hns_address(
    network: HnsNetwork,
    address: &WalletAddressKey,
) -> Result<String, HnsWalletError> {
    let hrp = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::Address)?;
    let version = bech32::Fe32::try_from(address.version).map_err(|_| HnsWalletError::Address)?;
    segwit::encode(hrp, version, &address.hash).map_err(|_| HnsWalletError::Address)
}

fn name_workflow_id(
    config: &HnsRuntimeConfig,
    action: HnsNameAction,
    request_nonce: u64,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/hns-name-workflow/v1");
    hasher.update(account_entity_prefix(config));
    hasher.update([match action {
        HnsNameAction::Transfer => 0,
        HnsNameAction::Finalize => 1,
    }]);
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn name_reservation_saves(
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    name_hash: [u8; 32],
    source: &TrackedHnsCoin,
    funding_inputs: &[TrackedHnsCoin],
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<Vec<EntityBatchSave<HnsInputReservation>>, HnsWalletError> {
    if source.derivation.role != KeyRole::HnsName
        || funding_inputs.is_empty()
        || funding_inputs.len() >= MAX_TRANSACTION_INPUTS
        || funding_inputs
            .iter()
            .any(|coin| !is_ordinary_hns_spend_candidate(coin))
    {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let mut inputs = Vec::with_capacity(funding_inputs.len() + 1);
    inputs.push((source, HnsInputReservationKind::Name { name_hash }));
    inputs.extend(
        funding_inputs
            .iter()
            .map(|coin| (coin, HnsInputReservationKind::Ordinary)),
    );
    let mut outpoints = BTreeSet::new();
    let mut saves = Vec::with_capacity(inputs.len());
    for (input, kind) in inputs {
        if !outpoints.insert(input.coin.outpoint) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let reservation = HnsInputReservation {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            outpoint: input.coin.outpoint,
            workflow_id,
            expires_at_unix: Some(expires_at_unix),
            kind,
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

fn validate_name_reservations(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    name_hash: [u8; 32],
    source: HnsOutpoint,
    funding_inputs: &[TrackedHnsCoin],
    expires_at_unix: Option<u64>,
) -> Result<(), HnsWalletError> {
    let mut expected = BTreeMap::new();
    expected.insert(source, HnsInputReservationKind::Name { name_hash });
    for input in funding_inputs {
        if !is_ordinary_hns_spend_candidate(input)
            || expected
                .insert(input.coin.outpoint, HnsInputReservationKind::Ordinary)
                .is_some()
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    if funding_inputs.is_empty() || expected.len() != funding_inputs.len() + 1 {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let matching = account_input_reservations(store, config)?
        .into_iter()
        .filter(|stored| stored.value.workflow_id == workflow_id)
        .collect::<Vec<_>>();
    if matching.len() != expected.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    for stored in matching {
        if expected.get(&stored.value.outpoint) != Some(&stored.value.kind)
            || stored.value.expires_at_unix != expires_at_unix
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    Ok(())
}

fn prepared_name_operation(plan: &HnsNamePlan) -> Result<PreparedNameOperation, HnsWalletError> {
    let authorization_commitment = serde_json::to_vec(plan)?;
    Ok(PreparedNameOperation {
        action: plan.action,
        workflow_id: plan.workflow_id,
        name: plan.name.clone(),
        name_hash: ObjectHash::new(plan.name_hash),
        recipient: plan.recipient_display.clone(),
        fee: plan.fee,
        maximum_fee: plan.maximum_fee,
        expires_at_unix: plan.expires_at_unix,
        authorization_commitment,
    })
}

fn decode_prepared_name_operation(
    prepared: &PreparedNameOperation,
) -> Result<HnsNamePlan, HnsWalletError> {
    let plan: HnsNamePlan = serde_json::from_slice(prepared.authorization_commitment())
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if plan.action != prepared.action
        || plan.workflow_id != prepared.workflow_id
        || plan.name != prepared.name
        || ObjectHash::new(plan.name_hash) != prepared.name_hash
        || plan.recipient_display != prepared.recipient
        || plan.fee != prepared.fee
        || plan.maximum_fee != prepared.maximum_fee
        || plan.expires_at_unix != prepared.expires_at_unix
        || plan.request_nonce == 0
        || plan.maximum_fee.is_zero()
        || plan.fee > plan.maximum_fee
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    Ok(plan)
}

fn tracked_name_source(
    binding: SnapshotBinding,
    owner_outpoint: HnsOutpoint,
    owner_output: &Output,
    owner_inclusion: TransactionInclusion,
    derivation: DerivationReference,
) -> Result<TrackedHnsCoin, HnsWalletError> {
    if derivation.role != KeyRole::HnsName
        || derivation.change != 0
        || owner_output.address.version != 0
        || owner_output.address.hash.len() != 20
        || owner_inclusion.height > binding.tip.height
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let confirmation_count = binding
        .tip
        .height
        .checked_sub(owner_inclusion.height)
        .and_then(|depth| depth.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let confirmed_height =
        u32::try_from(owner_inclusion.height).map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(TrackedHnsCoin {
        coin: WalletCoin {
            outpoint: owner_outpoint,
            value: BaseUnits::new(u128::from(owner_output.value.get())),
            confirmation_count,
            confirmed_height: Some(confirmed_height),
            coinbase: false,
            name_locked: true,
            covenant: owner_output
                .covenant
                .encode()
                .map_err(|_| HnsWalletError::InvalidEvidence)?,
        },
        derivation,
        address_program: owner_output.address.hash.clone(),
    })
}

fn name_source_from_plan(plan: &HnsNamePlan) -> Result<TrackedHnsCoin, HnsWalletError> {
    let transaction = decode_transaction_for_id(
        &plan.source.owner_transaction,
        plan.source.owner_outpoint.transaction,
    )?;
    let output = transaction
        .outputs
        .get(plan.source.owner_outpoint.output_index as usize)
        .ok_or(HnsWalletError::InvalidEvidence)?;
    tracked_name_source(
        plan.source.preparation_binding,
        plan.source.owner_outpoint,
        output,
        plan.source.owner_inclusion,
        plan.source.owner_derivation,
    )
}

fn name_input_sequence(outpoint: HnsOutpoint) -> Input {
    Input {
        previous_output: Outpoint {
            transaction_hash: CanonicalTransactionHash::new(outpoint.transaction.into_bytes()),
            index: outpoint.output_index,
        },
        sequence: u32::MAX,
        witness: Witness {
            items: vec![vec![0; 65], vec![0; 33]],
        },
    }
}

fn build_name_transition_transaction(
    action: HnsNameAction,
    source: &hns_transaction::Coin,
    current_state: &NameState,
    recipient: &Address,
    finalize: Option<&HnsFinalizeTerms>,
    funding_inputs: &[TrackedHnsCoin],
    change: Option<(&Address, u64)>,
) -> Result<(Transaction, Vec<hns_transaction::Coin>), HnsWalletError> {
    if funding_inputs.is_empty() || funding_inputs.len() >= MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InsufficientFunds);
    }
    let mut resolved = Vec::with_capacity(funding_inputs.len() + 1);
    resolved.push(source.clone());
    let mut additional_inputs = Vec::with_capacity(funding_inputs.len());
    for funding in funding_inputs {
        let coin = funding.to_canonical_coin()?;
        if coin.covenant.kind != CovenantKind::None || coin.coinbase {
            return Err(HnsWalletError::InvalidEvidence);
        }
        additional_inputs.push(name_input_sequence(funding.coin.outpoint));
        resolved.push(coin);
    }
    let additional_outputs = change.map_or_else(Vec::new, |(address, value)| {
        vec![Output {
            value: Dollarydoos::new(value),
            address: address.clone(),
            covenant: Covenant::default(),
        }]
    });
    let mut transaction = match action {
        HnsNameAction::Transfer => {
            if finalize.is_some() {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            hns_transaction::build_transfer_transaction(
                source,
                recipient,
                additional_inputs,
                additional_outputs,
            )
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        }
        HnsNameAction::Finalize => {
            let terms = finalize.ok_or(HnsWalletError::InvalidWorkflow)?;
            hns_transaction::build_finalize_transaction(
                source,
                current_state,
                hns_primitives::BlockHash::new(terms.renewal_block_hash),
                additional_inputs,
                additional_outputs,
            )
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        }
    };
    for input in &mut transaction.inputs {
        input.witness = Witness {
            items: vec![vec![0; 65], vec![0; 33]],
        };
    }
    match action {
        HnsNameAction::Transfer => {
            hns_transaction::verify_transfer_at_index_zero(&transaction, source, recipient)
        }
        HnsNameAction::Finalize => hns_transaction::verify_finalize_at_index_zero(
            &transaction,
            source,
            current_state,
            hns_primitives::BlockHash::new(
                finalize
                    .ok_or(HnsWalletError::InvalidWorkflow)?
                    .renewal_block_hash,
            ),
        ),
    }
    .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    hns_transaction::verify_covenant_links(&transaction, &resolved)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    Ok((transaction, resolved))
}

// The arguments are the complete consensus and fee-policy context for one
// name transition and are intentionally kept explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn build_unsigned_name_operation(
    action: HnsNameAction,
    source: &TrackedHnsCoin,
    current_state: &NameState,
    recipient: &Address,
    finalize: Option<&HnsFinalizeTerms>,
    mut candidates: Vec<TrackedHnsCoin>,
    change: &Address,
    minimum_confirmations: u32,
    fee_rate: BaseUnits,
    maximum_fee: BaseUnits,
    dust_threshold: BaseUnits,
) -> Result<(Transaction, Vec<TrackedHnsCoin>, BaseUnits), HnsWalletError> {
    if fee_rate.is_zero() || maximum_fee.is_zero() || dust_threshold.is_zero() {
        return Err(HnsWalletError::InvalidAmount);
    }
    let source_coin = source.to_canonical_coin()?;
    candidates.retain(|coin| {
        is_ordinary_hns_spend_candidate(coin)
            && coin.coin.confirmation_count >= minimum_confirmations
    });
    candidates.sort_by(|left, right| {
        left.coin
            .value
            .cmp(&right.coin.value)
            .then_with(|| left.coin.outpoint.cmp(&right.coin.outpoint))
    });
    let mut selected = Vec::new();
    let mut total = 0_u128;
    for coin in candidates {
        total = total
            .checked_add(coin.coin.value.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        selected.push(coin);
        let (with_change, resolved) = build_name_transition_transaction(
            action,
            &source_coin,
            current_state,
            recipient,
            finalize,
            &selected,
            Some((change, 1)),
        )?;
        let change_fee = canonical_policy_minimum_fee(&with_change, &resolved, fee_rate)?;
        if total >= change_fee.get() {
            let change_value = total - change_fee.get();
            if change_value >= dust_threshold.get() {
                if change_fee > maximum_fee {
                    return Err(HnsWalletError::FeeLimit);
                }
                let change_value =
                    u64::try_from(change_value).map_err(|_| HnsWalletError::InvalidAmount)?;
                let (transaction, final_resolved) = build_name_transition_transaction(
                    action,
                    &source_coin,
                    current_state,
                    recipient,
                    finalize,
                    &selected,
                    Some((change, change_value)),
                )?;
                if canonical_policy_minimum_fee(&transaction, &final_resolved, fee_rate)?
                    != change_fee
                {
                    return Err(HnsWalletError::InvalidEvidence);
                }
                return Ok((transaction, selected, change_fee));
            }
        }

        let (without_change, resolved) = build_name_transition_transaction(
            action,
            &source_coin,
            current_state,
            recipient,
            finalize,
            &selected,
            None,
        )?;
        let minimum_fee = canonical_policy_minimum_fee(&without_change, &resolved, fee_rate)?;
        let actual_fee = BaseUnits::new(total);
        if actual_fee >= minimum_fee && actual_fee <= maximum_fee {
            return Ok((without_change, selected, actual_fee));
        }
        if minimum_fee > maximum_fee {
            return Err(HnsWalletError::FeeLimit);
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

fn name_plan_inputs(
    plan: &HnsNamePlan,
) -> Result<(Vec<TrackedHnsCoin>, Vec<hns_transaction::Coin>), HnsWalletError> {
    let source = name_source_from_plan(plan)?;
    let mut tracked = Vec::with_capacity(plan.funding_inputs.len() + 1);
    tracked.push(source);
    tracked.extend(plan.funding_inputs.iter().cloned());
    let canonical = canonical_input_coins(&tracked)?;
    if canonical.first().is_none_or(|coin| match plan.action {
        HnsNameAction::Transfer => !matches!(
            coin.covenant.kind,
            CovenantKind::Register
                | CovenantKind::Update
                | CovenantKind::Renew
                | CovenantKind::Finalize
        ),
        HnsNameAction::Finalize => coin.covenant.kind != CovenantKind::Transfer,
    }) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    if canonical[1..]
        .iter()
        .any(|coin| coin.coinbase || coin.covenant.kind != CovenantKind::None)
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok((tracked, canonical))
}

fn validate_name_plan_transaction(
    plan: &HnsNamePlan,
    signed_raw: Option<&[u8]>,
) -> Result<(Transaction, Vec<TrackedHnsCoin>, Vec<hns_transaction::Coin>), HnsWalletError> {
    let unsigned = Transaction::decode(&plan.unsigned_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if unsigned
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != plan.unsigned_transaction
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let (tracked, canonical) = name_plan_inputs(plan)?;
    if unsigned.inputs.len() != canonical.len()
        || unsigned
            .inputs
            .iter()
            .zip(&canonical)
            .any(|(input, coin)| input.previous_output != coin.outpoint)
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let recipient = Address::new(plan.recipient.version, plan.recipient.hash.clone())
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let state = NameState::decode(
        NameHash::new(plan.name_hash),
        &plan.source.current_name_state,
    )
    .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    match plan.action {
        HnsNameAction::Transfer => {
            if plan.finalize.is_some() {
                return Err(HnsWalletError::InvalidPreparedArtifact);
            }
            hns_transaction::verify_transfer_at_index_zero(&unsigned, &canonical[0], &recipient)
        }
        HnsNameAction::Finalize => {
            let finalize = plan
                .finalize
                .as_ref()
                .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
            if finalize.transfer_height != plan.source.owner_inclusion.height
                || finalize.renewal_block_height
                    != plan
                        .source
                        .action_context
                        .renewal_block_height
                        .ok_or(HnsWalletError::InvalidPreparedArtifact)?
                || finalize.renewal_block_hash
                    != plan
                        .source
                        .action_context
                        .renewal_block_hash
                        .ok_or(HnsWalletError::InvalidPreparedArtifact)?
            {
                return Err(HnsWalletError::InvalidPreparedArtifact);
            }
            hns_transaction::verify_finalize_at_index_zero(
                &unsigned,
                &canonical[0],
                &state,
                hns_primitives::BlockHash::new(finalize.renewal_block_hash),
            )
        }
    }
    .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    hns_transaction::verify_covenant_links(&unsigned, &canonical)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let actual_fee = actual_transaction_fee(&unsigned, &canonical)?;
    let minimum_fee = canonical_policy_minimum_fee(&unsigned, &canonical, plan.fee_rate)?;
    if actual_fee != plan.fee || actual_fee < minimum_fee || actual_fee > plan.maximum_fee {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let transaction = if let Some(raw) = signed_raw {
        let signed = validate_witness_only_change(&unsigned, raw)?;
        for (index, coin) in canonical.iter().enumerate() {
            hns_script::verify_witness_program(
                &signed,
                index,
                coin,
                hns_script::ScriptFlags::STANDARD,
                &hns_script::K256SignatureVerifier,
            )
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        }
        signed
    } else {
        unsigned
    };
    Ok((transaction, tracked, canonical))
}

// Validation receives each independently authenticated context component so
// no caller-created aggregate can bypass the field-by-field checks below.
#[allow(clippy::too_many_arguments)]
fn validate_name_action_context(
    config: &HnsRuntimeConfig,
    action: HnsNameAction,
    name_hash: [u8; 32],
    owner_outpoint: HnsOutpoint,
    owner_inclusion: TransactionInclusion,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    state: &NameState,
    context: &NameActionContextEvidence,
    require_eligible: bool,
    reject_mempool_spender: bool,
) -> Result<(), HnsWalletError> {
    let (expected_network_id, expected_genesis_hash) = expected_chain_identity(config.network)?;
    let candidate_height = binding
        .tip
        .height
        .checked_add(1)
        .ok_or(HnsWalletError::Arithmetic)?;
    let canonical_state = state
        .encode()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let validated_context = validate_canonical_name_state(
        &state.name,
        name_hash,
        Some(&context.current_state),
        Some(context.owner_outpoint),
        Some(&context.owner_transaction),
        Some(context.owner_inclusion),
    )?
    .ok_or(HnsWalletError::InvalidEvidence)?;
    let owner_kind = validated_context
        .owner
        .as_ref()
        .ok_or(HnsWalletError::InvalidEvidence)?
        .output
        .covenant
        .kind;
    let reasons = &context.ineligibility_reasons;
    if reasons.len() > 9
        || !reasons
            .windows(2)
            .all(|pair| pair[0].rank() < pair[1].rank())
        || context.action_eligible != reasons.is_empty()
        || context.mempool_spender.is_some()
            != reasons.contains(&NameActionIneligibility::OwnerSpentInMempool)
        || (context.lifecycle != HnsNameLifecycle::Closed)
            != reasons.contains(&NameActionIneligibility::LifecycleNotClosed)
        || state.registered == reasons.contains(&NameActionIneligibility::NameNotRegistered)
        || (state.expired && !reasons.contains(&NameActionIneligibility::NameExpiredAtCandidate))
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    if context.binding != binding
        || context.mempool != mempool
        || context.network != config.network
        || context.network_id != expected_network_id
        || context.genesis_hash != expected_genesis_hash
        || context.context_version != NAME_ACTION_CONTEXT_VERSION
        || context.consensus_profile != NAME_ACTION_CONSENSUS_PROFILE
        || context.action != action
        || context.name_hash != name_hash
        || context.current_state != canonical_state
        || context.owner_outpoint != owner_outpoint
        || context.owner_inclusion != owner_inclusion
        || context.candidate_inclusion_height != candidate_height
        || (reject_mempool_spender && context.mempool_spender.is_some())
        || state.name_hash.as_bytes() != &name_hash
        || state.owner_outpoint().is_none_or(|outpoint| {
            outpoint.transaction_hash.as_bytes() != owner_outpoint.transaction.as_bytes()
                || outpoint.index != owner_outpoint.output_index
        })
    {
        return Err(HnsWalletError::InvalidEvidence);
    }

    let mut expected_reasons = Vec::new();
    if !state.registered {
        expected_reasons.push(NameActionIneligibility::NameNotRegistered);
    }
    if reasons.contains(&NameActionIneligibility::NameExpiredAtCandidate) {
        expected_reasons.push(NameActionIneligibility::NameExpiredAtCandidate);
    }
    if context.lifecycle != HnsNameLifecycle::Closed {
        expected_reasons.push(NameActionIneligibility::LifecycleNotClosed);
    }

    let mut finalize_eligible_height = None;
    match action {
        HnsNameAction::Transfer => {
            if context.transfer_height.is_some()
                || context.transfer_lockup.is_some()
                || context.finalize_eligible_height.is_some()
                || context.finalize_mature.is_some()
                || context.renewal_maturity.is_some()
                || context.renewal_period.is_some()
                || context.renewal_block_height.is_some()
                || context.renewal_block_hash.is_some()
                || context.renewal_valid_at_candidate.is_some()
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            if state.transfer.get() != 0 {
                expected_reasons.push(NameActionIneligibility::TransferAlreadyPending);
            }
            if !matches!(
                owner_kind,
                CovenantKind::Register
                    | CovenantKind::Update
                    | CovenantKind::Renew
                    | CovenantKind::Finalize
            ) {
                expected_reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
        }
        HnsNameAction::Finalize => {
            let transfer_height = u64::from(state.transfer.get());
            let lockup = u64::from(
                context
                    .transfer_lockup
                    .filter(|lockup| *lockup > 0)
                    .ok_or(HnsWalletError::InvalidEvidence)?,
            );
            let eligible_height = transfer_height
                .checked_add(lockup)
                .ok_or(HnsWalletError::Arithmetic)?;
            finalize_eligible_height = Some(eligible_height);
            let maturity = u64::from(
                context
                    .renewal_maturity
                    .filter(|maturity| *maturity > 0)
                    .ok_or(HnsWalletError::InvalidEvidence)?,
            );
            let period = u64::from(
                context
                    .renewal_period
                    .filter(|period| u64::from(*period) >= maturity)
                    .ok_or(HnsWalletError::InvalidEvidence)?,
            );
            let renewal_height = context
                .renewal_block_height
                .ok_or(HnsWalletError::InvalidEvidence)?;
            let finalize_mature = transfer_height != 0 && candidate_height >= eligible_height;
            let renewal_valid = candidate_height < maturity
                || (renewal_height <= candidate_height - maturity
                    && renewal_height >= candidate_height.saturating_sub(period));
            if transfer_height == 0
                || transfer_height != owner_inclusion.height
                || context.transfer_height != Some(transfer_height)
                || context.finalize_eligible_height != Some(eligible_height)
                || context.finalize_mature != Some(finalize_mature)
                || renewal_height
                    != binding
                        .tip
                        .height
                        .saturating_sub(maturity.saturating_mul(2))
                || renewal_height > binding.tip.height
                || context.renewal_block_hash.is_none()
                || context.renewal_valid_at_candidate != Some(renewal_valid)
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            if !finalize_mature {
                expected_reasons.push(NameActionIneligibility::TransferNotMature);
            }
            if owner_kind != CovenantKind::Transfer {
                expected_reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
            if !renewal_valid {
                expected_reasons.push(NameActionIneligibility::RenewalCommitmentInvalid);
            }
        }
    }
    if context.mempool_spender.is_some() {
        expected_reasons.push(NameActionIneligibility::OwnerSpentInMempool);
    }
    if reasons != &expected_reasons {
        return Err(HnsWalletError::InvalidEvidence);
    }
    if require_eligible && !context.action_eligible {
        if action == HnsNameAction::Finalize
            && reasons.as_slice() == [NameActionIneligibility::TransferNotMature]
        {
            return Err(HnsWalletError::NameFinalizeNotMature {
                eligible_height: finalize_eligible_height.ok_or(HnsWalletError::InvalidEvidence)?,
            });
        }
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn project_name_operation(
    stored: StoredWorkflow<HnsNameWorkflow>,
    config: &HnsRuntimeConfig,
) -> Result<NameOperation, HnsWalletError> {
    let workflow = stored.state;
    if workflow.plan.wallet_id != config.wallet_id
        || workflow.plan.account_id != config.account_id
        || workflow.plan.action.workflow_kind() != stored.kind
        || workflow.plan.workflow_id != stored.id
    {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let transfer_height = match workflow.plan.action {
        HnsNameAction::Transfer => workflow.last_verified_inclusion.map(|value| value.height),
        HnsNameAction::Finalize => workflow
            .plan
            .finalize
            .as_ref()
            .map(|terms| terms.transfer_height),
    };
    let finalize_eligible_height = workflow
        .plan
        .finalize
        .as_ref()
        .map(|terms| terms.finalize_eligible_height)
        .or(workflow.last_finalize_eligible_height);
    Ok(NameOperation {
        workflow_id: stored.id,
        revision: stored.revision,
        action: workflow.plan.action,
        name: workflow.plan.name,
        name_hash: ObjectHash::new(workflow.plan.name_hash),
        state: workflow.stage,
        transaction: workflow.transaction,
        recipient: workflow.plan.recipient_display,
        fee: workflow.plan.fee,
        maximum_fee: workflow.plan.maximum_fee,
        transfer_height,
        finalize_eligible_height,
        last_verified_height: workflow
            .last_verified_binding
            .unwrap_or(workflow.plan.source.preparation_binding)
            .tip
            .height,
    })
}

fn require_current_owner_unspent<B: HnsBackend>(
    backend: &B,
    owner_outpoint: HnsOutpoint,
    binding: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    let evidence = backend.get_outpoint_spend_evidence(&[owner_outpoint], binding)?;
    validate_spend_evidence(&evidence, binding, &[owner_outpoint])?;
    if evidence.entries[0].spending.is_some() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn canonical_current_name_coin(
    owner: &ValidatedNameOwner,
) -> Result<(Transaction, Coin), HnsWalletError> {
    let transaction =
        decode_transaction_for_id(&owner.raw_transaction, owner.outpoint.transaction)?;
    if transaction.inputs.is_empty()
        || transaction
            .inputs
            .iter()
            .any(|input| input.previous_output.is_null())
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let confirmed_height =
        u32::try_from(owner.inclusion.height).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let coin = canonical_coin_from_evidence(
        owner.outpoint,
        BaseUnits::new(u128::from(owner.output.value.get())),
        Some(confirmed_height),
        false,
        owner.output.address.version,
        owner.output.address.hash.clone(),
        owner.output.covenant.clone(),
    )?;
    Ok((transaction, coin))
}

fn confirmed_transfer_spend_kind<B: HnsBackend>(
    backend: &B,
    transfer_transaction: &Transaction,
    transfer_id: TransactionHash,
    transfer_inclusion: TransactionInclusion,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
) -> Result<Option<CovenantKind>, HnsWalletError> {
    let transfer_output = transfer_transaction
        .outputs
        .first()
        .cloned()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    if transfer_output.covenant.kind != CovenantKind::Transfer {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let transfer_outpoint = HnsOutpoint {
        transaction: transfer_id,
        output_index: 0,
    };
    let spend = backend.get_outpoint_spend_evidence(&[transfer_outpoint], binding)?;
    if spend.binding != binding
        || spend.entries.len() != 1
        || spend.entries[0].outpoint != transfer_outpoint
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let Some(spending) = spend.entries[0].spending else {
        return Ok(None);
    };
    let evidence =
        backend.get_transaction_evidence(spending.transaction, binding, Some(mempool))?;
    let inclusion = evidence.inclusion.ok_or(HnsWalletError::InvalidEvidence)?;
    if evidence.binding != binding
        || evidence.mempool != mempool
        || evidence.status.conflicted
        || evidence.status.in_mempool
        || evidence.status.confirmation_count == 0
        || inclusion.block_hash != spending.block_hash
        || inclusion.height != spending.height
        || inclusion.height > binding.tip.height
        || u64::from(evidence.status.confirmation_count)
            != binding.tip.height - inclusion.height + 1
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let raw = evidence.raw.ok_or(HnsWalletError::InvalidEvidence)?;
    let transaction = decode_transaction_for_id(&raw, spending.transaction)?;
    let position = spending.input_position as usize;
    let input = transaction
        .inputs
        .get(position)
        .cloned()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let output = transaction
        .outputs
        .get(position)
        .cloned()
        .ok_or(HnsWalletError::InvalidEvidence)?;
    let canonical_outpoint = Outpoint {
        transaction_hash: CanonicalTransactionHash::new(transfer_id.into_bytes()),
        index: 0,
    };
    if input.previous_output != canonical_outpoint {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let height =
        u32::try_from(transfer_inclusion.height).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let transfer_coin = hns_transaction::Coin {
        outpoint: canonical_outpoint,
        value: transfer_output.value,
        height: hns_primitives::Height::new(height),
        coinbase: false,
        address: transfer_output.address,
        covenant: transfer_output.covenant,
    };
    let projection = Transaction {
        version: transaction.version,
        inputs: vec![input],
        outputs: vec![output.clone()],
        locktime: transaction.locktime,
    };
    hns_transaction::verify_covenant_links(&projection, &[transfer_coin])
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(Some(output.covenant.kind))
}

fn prepare_current_shakedex_lock_queries(
    queries: &[CurrentShakedexLockQuery],
) -> Result<Vec<WalletAddressKey>, HnsWalletError> {
    if queries.is_empty() || queries.len() > MAX_CURRENT_SHAKEDEX_LOCK_BATCH {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut names = BTreeSet::new();
    let mut scripts = BTreeSet::new();
    for query in queries {
        if !validate_name(&query.name) {
            return Err(HnsWalletError::InvalidName);
        }
        if VerifyingKey::from_sec1_bytes(&query.seller_public_key).is_err()
            || !names.insert(query.name.as_slice())
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        scripts.insert(WalletAddressKey {
            version: 0,
            hash: lock_script_hash(&query.seller_public_key).to_vec(),
        });
    }
    Ok(scripts.into_iter().collect())
}

fn query_shakedex_lock_mempool<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    binding: SnapshotBinding,
    expected_mempool: Option<MempoolSnapshotBinding>,
) -> Result<MempoolSnapshotBinding, HnsWalletError> {
    let page = backend.get_mempool_wallet_page(MempoolWalletPageRequest {
        scripts,
        binding,
        expected_mempool,
        cursor: None,
        limit: 1,
    })?;
    if page.binding != binding
        || page.mempool.instance_nonce == [0; 32]
        || expected_mempool.is_some_and(|expected| page.mempool != expected)
        || page.history.len() > 1
    {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(page.mempool)
}

/// Query-scoped current-lock authority for the non-value account runtime.
///
/// Unlike `HnsWalletRuntime`, this path never restores a cached value-runtime
/// snapshot. It obtains a script-free chain binding, acquires one mempool
/// generation using the sorted, deduplicated exact seller lock-program set,
/// validates canonical NameState/action/spend evidence, and then fences the
/// chain, mempool, and selected encrypted account revision again before
/// returning an ephemeral capability. It signs, broadcasts, and enables
/// nothing.
impl<B: HnsBackend, C: HnsClock> HnsAccountReadRuntime<B, C> {
    /// Reacquire current, unspent authority for an ordered batch of exact
    /// Shakedex locks under one account, chain, mempool, and clock observation.
    ///
    /// Empty, oversized, malformed, or duplicate input is rejected before any
    /// account/store, backend, or clock I/O. Seller lock programs are sorted
    /// and deduplicated into one exact mempool script set. Name/action evidence
    /// remains query-specific, while all owner outpoints are checked by one
    /// ordered spend-evidence request and every shared authority is fenced
    /// again before this non-serializable capability is returned. This method
    /// performs no store write, signing, broadcast, or value operation.
    pub fn verify_current_shakedex_locks(
        &self,
        queries: &[CurrentShakedexLockQuery],
    ) -> Result<VerifiedCurrentShakedexLockBatch, HnsWalletError> {
        let scripts = prepare_current_shakedex_lock_queries(queries)?;
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

        let binding = self.backend.get_chain_snapshot()?;
        verify_hns_read_chain_identity(&self.backend, selected.config.network, binding)?;
        if binding.tip.median_time_past == 0 {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mempool = query_shakedex_lock_mempool(&self.backend, &scripts, binding, None)?;
        let network = shakedex_network_binding(selected.config.network)?;
        let mut locks = Vec::with_capacity(queries.len());
        let mut owner_outpoints = Vec::with_capacity(queries.len());
        for query in queries {
            let validated = validated_name_evidence(&self.backend, &query.name, binding, None)?;
            let current = validated.current.ok_or(HnsWalletError::InvalidEvidence)?;
            let owner = current.owner.ok_or(HnsWalletError::InvalidEvidence)?;
            if owner.output.covenant.kind != CovenantKind::Finalize {
                return Err(HnsWalletError::InvalidEvidence);
            }
            let context = self.backend.get_name_action_context(
                HnsNameAction::Transfer,
                validated.known_name.name_hash,
                binding,
                mempool,
            )?;
            validate_name_action_context(
                &selected.config,
                HnsNameAction::Transfer,
                validated.known_name.name_hash,
                owner.outpoint,
                owner.inclusion,
                binding,
                mempool,
                &current.state,
                &context,
                true,
                true,
            )?;
            let (_, locking_coin) = canonical_current_name_coin(&owner)?;
            let descriptor = hns_swap::ShakedexLockDescriptor::from_locking_coin(
                network,
                &locking_coin,
                query.seller_public_key,
            )
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
            owner_outpoints.push(owner.outpoint);
            locks.push(VerifiedCurrentShakedexLockEntry {
                descriptor,
                locking_coin,
                current_state: current.state,
            });
        }

        let spend = self
            .backend
            .get_outpoint_spend_evidence(&owner_outpoints, binding)?;
        validate_spend_evidence(&spend, binding, &owner_outpoints)?;
        if spend.entries.iter().any(|entry| entry.spending.is_some()) {
            return Err(HnsWalletError::InvalidEvidence);
        }

        // The clock may observe shared product state, so it is sampled before
        // the final exact chain, mempool, and selected-account fences.
        let observed_at_unix = self.clock.now_unix()?;
        if self.backend.get_chain_snapshot()? != binding {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        query_shakedex_lock_mempool(&self.backend, &scripts, binding, Some(mempool))?;
        let context = VerifiedHnsBoardContext {
            account_id,
            account: selected,
            account_revision,
            account_prefix_lease,
            network,
            observed_at_unix,
        };
        let context = self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                context.revalidate_unchanged_account(snapshot)
            })
        })?;

        Ok(VerifiedCurrentShakedexLockBatch {
            binding,
            mempool,
            context,
            locks,
        })
    }

    pub fn verify_current_shakedex_lock(
        &self,
        name: &[u8],
        seller_public_key: [u8; 33],
    ) -> Result<VerifiedCurrentShakedexLock, HnsWalletError> {
        // Bound caller-controlled input before allocating the owned batch DTO.
        if !validate_name(name) {
            return Err(HnsWalletError::InvalidName);
        }
        self.verify_current_shakedex_locks(&[CurrentShakedexLockQuery {
            name: name.to_vec(),
            seller_public_key,
        }])?
        .into_single()
    }
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    fn mark_name_operation_reapproval_required(
        &self,
        plan: &HnsNamePlan,
    ) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsNameWorkflow>(plan.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != plan.action.workflow_kind()
            || stored.state.plan != *plan
            || !matches!(
                stored.state.stage,
                NameOperationState::Prepared
                    | NameOperationState::Authorized
                    | NameOperationState::RequiresRebroadcast
            )
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut workflow = stored.state;
        workflow.stage = NameOperationState::ReapprovalRequired;
        store.save_workflow(
            plan.workflow_id,
            plan.action.workflow_kind(),
            stored.revision,
            &workflow,
            workflow.signed_transaction.is_some(),
            now,
        )?;
        Ok(())
    }

    fn reacquire_name_plan_authority(
        &self,
        plan: &HnsNamePlan,
        required_snapshot: Option<(SnapshotBinding, MempoolSnapshotBinding)>,
    ) -> Result<(SnapshotBinding, MempoolSnapshotBinding), HnsWalletError> {
        if (plan.action == HnsNameAction::Transfer && plan.finalize.is_some())
            || (plan.action == HnsNameAction::Finalize && plan.finalize.is_none())
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        if let Some((binding, mempool)) = required_snapshot {
            let cache = self.cache_read()?;
            if cache.binding != Some(binding) || cache.mempool_binding != Some(mempool) {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
        }
        let source = match plan.action {
            HnsNameAction::Transfer => {
                let authority = self.verify_name_ownership(&plan.name)?;
                let context = self.transfer_action_context(&authority)?;
                if plan.recipient_display
                    != encode_hns_address(
                        self.cache_read()?.account.config.network,
                        &plan.recipient,
                    )?
                {
                    return Err(HnsWalletError::InvalidPreparedArtifact);
                }
                HnsNameSourceEvidence {
                    preparation_binding: authority.binding,
                    preparation_mempool: authority.mempool,
                    current_name_state: authority.current_state,
                    owner_outpoint: authority.owner_outpoint,
                    owner_transaction: authority.owner_transaction,
                    owner_inclusion: authority.owner_inclusion,
                    owner_derivation: authority.derivation,
                    action_context: context,
                }
            }
            HnsNameAction::Finalize => {
                let authority = self.verify_outgoing_name_transfer(&plan.name)?;
                if authority.recipient != plan.recipient {
                    self.mark_name_operation_reapproval_required(plan)?;
                    return Err(HnsWalletError::ApprovalRequired);
                }
                HnsNameSourceEvidence {
                    preparation_binding: authority.binding,
                    preparation_mempool: authority.mempool,
                    current_name_state: authority.current_state,
                    owner_outpoint: authority.owner_outpoint,
                    owner_transaction: authority.owner_transaction,
                    owner_inclusion: authority.owner_inclusion,
                    owner_derivation: authority.owner_derivation,
                    action_context: authority.context,
                }
            }
        };

        if let Some((binding, mempool)) = required_snapshot
            && (source.preparation_binding != binding || source.preparation_mempool != mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        {
            let cache = self.cache_read()?;
            if cache.binding != Some(source.preparation_binding)
                || cache.mempool_binding != Some(source.preparation_mempool)
            {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
        }

        let stable_source_matches = source.current_name_state == plan.source.current_name_state
            && source.owner_outpoint == plan.source.owner_outpoint
            && source.owner_transaction == plan.source.owner_transaction
            && source.owner_inclusion == plan.source.owner_inclusion
            && source.owner_derivation == plan.source.owner_derivation;
        let action_terms_match = match plan.action {
            HnsNameAction::Transfer => plan.finalize.is_none(),
            HnsNameAction::Finalize => {
                let Some(expected) = plan.finalize.as_ref() else {
                    return Err(HnsWalletError::InvalidPreparedArtifact);
                };
                source.action_context.transfer_height == Some(expected.transfer_height)
                    && source.action_context.finalize_eligible_height
                        == Some(expected.finalize_eligible_height)
                    && source.action_context.renewal_maturity == Some(expected.renewal_maturity)
                    && source.action_context.renewal_period == Some(expected.renewal_period)
                    && source.action_context.renewal_block_height
                        == Some(expected.renewal_block_height)
                    && source.action_context.renewal_block_hash == Some(expected.renewal_block_hash)
            }
        };
        if !stable_source_matches || !action_terms_match {
            self.mark_name_operation_reapproval_required(plan)?;
            return Err(HnsWalletError::ApprovalRequired);
        }
        if source.action_context.action != plan.action
            || source.action_context.name_hash != plan.name_hash
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        if source.preparation_binding.tip.height < plan.source.owner_inclusion.height {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok((source.preparation_binding, source.preparation_mempool))
    }

    pub fn authorize_name_operation(
        &self,
        approval_id: ApprovalId,
        prepared: &PreparedNameOperation,
        approved_at_unix: u64,
    ) -> Result<AuthorizedNameOperation, HnsWalletError> {
        let now = self.clock.now_unix()?;
        if now > prepared.expires_at_unix || approved_at_unix > now {
            return Err(HnsWalletError::ApprovalRequired);
        }
        let plan = decode_prepared_name_operation(prepared)?;
        let account = self.cache_read()?.account.clone();
        {
            let cache = self.cache_read()?;
            ensure_name_value_ready(&cache)?;
        }
        if plan.wallet_id != account.config.wallet_id
            || plan.account_id != account.config.account_id
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        self.reacquire_name_plan_authority(&plan, None)?;
        let (pending_approval, signed, transaction_id, canonical) = {
            let store = self.store_lock()?;
            let pending_approval = store
                .get_pending_approval(approval_id, now)?
                .ok_or(HnsWalletError::ApprovalRequired)?;
            let approval: HnsNameApproval = serde_json::from_slice(&pending_approval.request_json)
                .map_err(|_| HnsWalletError::ApprovalRequired)?;
            let commitment: [u8; 32] = Sha256::digest(prepared.authorization_commitment()).into();
            if approval.workflow_id != plan.workflow_id || approval.commitment != commitment {
                return Err(HnsWalletError::ApprovalRequired);
            }
            let stored = store
                .load_workflow::<HnsNameWorkflow>(plan.workflow_id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if stored.kind != plan.action.workflow_kind()
                || stored.state.plan != plan
                || stored.state.stage != NameOperationState::Prepared
                || stored.state.transaction.is_some()
                || stored.state.signed_transaction.is_some()
                || stored.state.fee_quote.is_some()
            {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            validate_name_reservations(
                &store,
                &account.config,
                plan.workflow_id,
                plan.name_hash,
                plan.source.owner_outpoint,
                &plan.funding_inputs,
                Some(plan.expires_at_unix),
            )?;
            let (unsigned, tracked, _) = validate_name_plan_transaction(&plan, None)?;
            let mut roles = Vec::with_capacity(tracked.len());
            roles.push(KeyRole::HnsName);
            roles.resize(tracked.len(), KeyRole::HnsCoin);
            let signed = sign_ordered_p2pkh_inputs(&store, &account, unsigned, &tracked, &roles)?;
            let (signed_transaction, _, canonical) =
                validate_name_plan_transaction(&plan, Some(&signed))?;
            let transaction_id = wallet_transaction_hash(&signed_transaction)?;
            (pending_approval, signed, transaction_id, canonical)
        };
        let quote =
            self.quote_final_transaction(&signed, &canonical, plan.fee, plan.maximum_fee)?;
        let commit_now = self.clock.now_unix()?;
        if commit_now >= plan.expires_at_unix {
            return Err(HnsWalletError::ApprovalRequired);
        }
        self.reacquire_name_plan_authority(&plan, Some((quote.binding, quote.mempool)))?;
        let mut store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsNameWorkflow>(plan.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != plan.action.workflow_kind()
            || stored.state.plan != plan
            || stored.state.stage != NameOperationState::Prepared
            || stored.state.transaction.is_some()
            || stored.state.signed_transaction.is_some()
            || stored.state.fee_quote.is_some()
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        validate_name_reservations(
            &store,
            &account.config,
            plan.workflow_id,
            plan.name_hash,
            plan.source.owner_outpoint,
            &plan.funding_inputs,
            Some(plan.expires_at_unix),
        )?;
        let activation =
            reservation_activation_saves(&store, &account.config, plan.workflow_id, commit_now)?;
        let workflow = HnsNameWorkflow {
            plan,
            stage: NameOperationState::Authorized,
            transaction: Some(transaction_id),
            signed_transaction: Some(signed.clone()),
            fee_quote: Some(quote),
            last_verified_binding: None,
            last_verified_inclusion: None,
            last_finalize_eligible_height: None,
        };
        let committed = store.consume_approval_and_save_workflow_with_entity_batch(
            &pending_approval,
            commit_now,
            workflow.plan.workflow_id,
            workflow.plan.action.workflow_kind(),
            stored.revision,
            &workflow,
            true,
            EntityKind::InputReservation,
            &activation,
            &[],
        )?;
        if committed.is_none() {
            return Err(HnsWalletError::ApprovalRequired);
        }
        Ok(AuthorizedNameOperation {
            action: workflow.plan.action,
            workflow_id: workflow.plan.workflow_id,
            approval_id,
            transaction: transaction_id,
            signed_transaction: signed,
        })
    }

    pub fn broadcast_name_operation(
        &self,
        authorized: &AuthorizedNameOperation,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        let stored = self
            .store_lock()?
            .load_workflow::<HnsNameWorkflow>(authorized.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != authorized.action.workflow_kind()
            || stored.state.stage != NameOperationState::Authorized
            || stored.state.transaction != Some(authorized.transaction)
            || stored.state.signed_transaction.as_deref() != Some(authorized.transaction_bytes())
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        self.reacquire_name_plan_authority(&stored.state.plan, None)?;
        let (_, _, canonical) = validate_name_plan_transaction(
            &stored.state.plan,
            Some(authorized.transaction_bytes()),
        )?;
        let prior_quote = stored
            .state
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        validate_final_fee_quote(
            authorized.transaction_bytes(),
            &canonical,
            prior_quote,
            prior_quote.binding,
            prior_quote.mempool,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let quote = self.quote_final_transaction(
            authorized.transaction_bytes(),
            &canonical,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        self.reacquire_name_plan_authority(
            &stored.state.plan,
            Some((quote.binding, quote.mempool)),
        )?;
        self.submit_name_workflow(stored, quote)
    }

    pub fn rebroadcast_pending_name_operation(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        let stored = self
            .store_lock()?
            .load_workflow::<HnsNameWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != stored.state.plan.action.workflow_kind()
            || !matches!(
                stored.state.stage,
                NameOperationState::Authorized | NameOperationState::RequiresRebroadcast
            )
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let raw = stored
            .state
            .signed_transaction
            .as_deref()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        self.reacquire_name_plan_authority(&stored.state.plan, None)?;
        let (_, _, canonical) = validate_name_plan_transaction(&stored.state.plan, Some(raw))?;
        let prior_quote = stored
            .state
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        validate_final_fee_quote(
            raw,
            &canonical,
            prior_quote,
            prior_quote.binding,
            prior_quote.mempool,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let quote = self.quote_final_transaction(
            raw,
            &canonical,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        self.reacquire_name_plan_authority(
            &stored.state.plan,
            Some((quote.binding, quote.mempool)),
        )?;
        self.submit_name_workflow(stored, quote)
    }

    fn submit_name_workflow(
        &self,
        stored: StoredWorkflow<HnsNameWorkflow>,
        quote: HnsTransactionFeeQuote,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        let raw = stored
            .state
            .signed_transaction
            .clone()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let expected = stored
            .state
            .transaction
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let submission_started_at = self.clock.now_unix()?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock()?;
            let current = store
                .load_workflow::<HnsNameWorkflow>(stored.id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let mut workflow = current.state;
            workflow.stage = NameOperationState::RequiresRebroadcast;
            workflow.fee_quote = Some(quote);
            let revision = store.save_workflow(
                stored.id,
                stored.kind,
                current.revision,
                &workflow,
                true,
                submission_started_at,
            )?;
            (revision, workflow)
        };
        let actual = self.backend.broadcast_transaction(&raw)?;
        if actual != expected {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let accepted_at_unix = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let current = store
            .load_workflow::<HnsNameWorkflow>(stored.id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut workflow = current.state;
        workflow.stage = NameOperationState::Broadcast;
        store.save_workflow(
            stored.id,
            stored.kind,
            current.revision,
            &workflow,
            true,
            accepted_at_unix,
        )?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid: actual,
            accepted_at_unix,
        })
    }

    pub(super) fn reconcile_name_workflows(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        mempool: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<Vec<WorkflowId>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let mut pending = Vec::new();
        for kind in [WorkflowKind::NameTransfer, WorkflowKind::NameFinalize] {
            let workflows =
                store.list_workflows_complete::<HnsNameWorkflow>(kind, MAX_HISTORY_RESULTS)?;
            for stored in workflows {
                if stored.state.plan.wallet_id != config.wallet_id
                    || stored.state.plan.account_id != config.account_id
                {
                    continue;
                }
                if stored.state.plan.action.workflow_kind() != kind
                    || stored.state.plan.workflow_id != stored.id
                {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
                let mut workflow = stored.state;
                let previous_stage = workflow.stage;
                let previous_binding = workflow.last_verified_binding;
                let previous_inclusion = workflow.last_verified_inclusion;
                let previous_finalize_eligible_height = workflow.last_finalize_eligible_height;
                let mut delete_reservations = false;
                let mut action_already_in_mempool = false;

                if workflow.stage == NameOperationState::Prepared {
                    if workflow.plan.expires_at_unix <= now_unix {
                        workflow.stage = NameOperationState::Expired;
                        delete_reservations = true;
                    }
                } else if matches!(
                    workflow.stage,
                    NameOperationState::Authorized
                        | NameOperationState::RequiresRebroadcast
                        | NameOperationState::Broadcast
                        | NameOperationState::Mempool
                        | NameOperationState::TransferLocked
                        | NameOperationState::FinalizeEligible
                        | NameOperationState::Finalized
                        | NameOperationState::TransferCancelled
                        | NameOperationState::ReapprovalRequired
                ) {
                    let transaction_id = workflow
                        .transaction
                        .ok_or(HnsWalletError::InvalidWorkflow)?;
                    let signed = workflow
                        .signed_transaction
                        .as_ref()
                        .ok_or(HnsWalletError::InvalidWorkflow)?;
                    let transaction = decode_transaction_for_id(signed, transaction_id)?;
                    let evidence = self.backend.get_transaction_evidence(
                        transaction_id,
                        binding,
                        Some(mempool),
                    )?;
                    if evidence.binding != binding
                        || evidence.mempool != mempool
                        || evidence.raw.as_ref().is_some_and(|raw| raw != signed)
                        || (evidence.status.conflicted
                            && (evidence.status.in_mempool
                                || evidence.status.confirmation_count > 0))
                    {
                        return Err(HnsWalletError::InvalidEvidence);
                    }
                    let competing =
                        self.has_competing_spender(transaction_id, &transaction, binding)?;
                    if evidence.status.conflicted || competing {
                        workflow.stage = NameOperationState::Conflicted;
                        workflow.last_verified_binding = Some(binding);
                        workflow.last_verified_inclusion = None;
                        delete_reservations = true;
                    } else if evidence.status.confirmation_count > 0 {
                        let inclusion =
                            evidence.inclusion.ok_or(HnsWalletError::InvalidEvidence)?;
                        if inclusion.height > binding.tip.height
                            || u64::from(evidence.status.confirmation_count)
                                != binding.tip.height - inclusion.height + 1
                            || evidence.status.in_mempool
                        {
                            return Err(HnsWalletError::InvalidEvidence);
                        }
                        workflow.last_verified_binding = Some(binding);
                        workflow.last_verified_inclusion = Some(inclusion);
                        match workflow.plan.action {
                            HnsNameAction::Finalize => {
                                workflow.stage = NameOperationState::Finalized;
                            }
                            HnsNameAction::Transfer => {
                                match confirmed_transfer_spend_kind(
                                    &self.backend,
                                    &transaction,
                                    transaction_id,
                                    inclusion,
                                    binding,
                                    mempool,
                                )? {
                                    Some(CovenantKind::Finalize) => {
                                        workflow.stage = NameOperationState::Finalized;
                                    }
                                    Some(
                                        CovenantKind::Update
                                        | CovenantKind::Renew
                                        | CovenantKind::Revoke,
                                    ) => {
                                        workflow.stage = NameOperationState::TransferCancelled;
                                    }
                                    Some(_) => return Err(HnsWalletError::InvalidEvidence),
                                    None => {
                                        let context = self.backend.get_name_action_context(
                                            HnsNameAction::Finalize,
                                            workflow.plan.name_hash,
                                            binding,
                                            mempool,
                                        )?;
                                        let state = NameState::decode(
                                            NameHash::new(workflow.plan.name_hash),
                                            &context.current_state,
                                        )
                                        .map_err(|_| HnsWalletError::InvalidEvidence)?;
                                        validate_name_action_context(
                                            &config,
                                            HnsNameAction::Finalize,
                                            workflow.plan.name_hash,
                                            HnsOutpoint {
                                                transaction: transaction_id,
                                                output_index: 0,
                                            },
                                            inclusion,
                                            binding,
                                            mempool,
                                            &state,
                                            &context,
                                            false,
                                            false,
                                        )?;
                                        if let (Some(height), Some(hash)) = (
                                            context.renewal_block_height,
                                            context.renewal_block_hash,
                                        ) {
                                            let block =
                                                self.backend.get_block_hash(height, binding)?;
                                            if block.binding != binding
                                                || block.height != height
                                                || block.block_hash != Some(hash)
                                            {
                                                return Err(HnsWalletError::InvalidEvidence);
                                            }
                                        }
                                        action_already_in_mempool =
                                            context.mempool_spender.is_some();
                                        workflow.last_finalize_eligible_height =
                                            context.finalize_eligible_height;
                                        let mature_with_bound_spender = context.finalize_mature
                                            == Some(true)
                                            && context.ineligibility_reasons.as_slice()
                                                == [NameActionIneligibility::OwnerSpentInMempool];
                                        workflow.stage = if context.action_eligible
                                            || mature_with_bound_spender
                                        {
                                            NameOperationState::FinalizeEligible
                                        } else {
                                            NameOperationState::TransferLocked
                                        };
                                    }
                                }
                            }
                        }
                    } else if evidence.inclusion.is_some() {
                        return Err(HnsWalletError::InvalidEvidence);
                    } else if evidence.status.in_mempool {
                        workflow.stage = NameOperationState::Mempool;
                        workflow.last_verified_binding = Some(binding);
                        workflow.last_verified_inclusion = None;
                    } else {
                        workflow.last_verified_binding = Some(binding);
                        workflow.last_verified_inclusion = None;
                        workflow.stage = if matches!(
                            previous_stage,
                            NameOperationState::TransferLocked
                                | NameOperationState::FinalizeEligible
                                | NameOperationState::Finalized
                                | NameOperationState::TransferCancelled
                        ) {
                            NameOperationState::ReapprovalRequired
                        } else {
                            NameOperationState::RequiresRebroadcast
                        };
                    }
                }

                if matches!(
                    workflow.stage,
                    NameOperationState::RequiresRebroadcast
                        | NameOperationState::ReapprovalRequired
                ) || (workflow.stage == NameOperationState::FinalizeEligible
                    && !action_already_in_mempool)
                {
                    pending.push(stored.id);
                }
                let changed = workflow.stage != previous_stage
                    || workflow.last_verified_binding != previous_binding
                    || workflow.last_verified_inclusion != previous_inclusion
                    || workflow.last_finalize_eligible_height != previous_finalize_eligible_height;
                if changed {
                    let deletes = if delete_reservations {
                        reservation_deletes(store, &config, stored.id)?
                    } else {
                        Vec::new()
                    };
                    store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                        stored.id,
                        kind,
                        stored.revision,
                        &workflow,
                        workflow.signed_transaction.is_some(),
                        now_unix,
                        EntityKind::InputReservation,
                        &[],
                        &deletes,
                    )?;
                }
            }
        }
        Ok(pending)
    }

    // Persistence captures the full prepared-operation snapshot atomically;
    // retaining explicit fields makes the saved security boundary auditable.
    #[allow(clippy::too_many_arguments)]
    fn persist_prepared_name_operation(
        &self,
        account: HnsAccountRecord,
        account_revision: u64,
        cached_coins: Vec<TrackedHnsCoin>,
        request_nonce: u64,
        action: HnsNameAction,
        name: Vec<u8>,
        name_hash: [u8; 32],
        source_evidence: HnsNameSourceEvidence,
        source: TrackedHnsCoin,
        current_state: NameState,
        recipient: WalletAddressKey,
        recipient_display: String,
        finalize: Option<HnsFinalizeTerms>,
        maximum_fee: BaseUnits,
        now_unix: u64,
    ) -> Result<PreparedNameOperation, HnsWalletError> {
        let config = account.config.clone();
        let workflow_id = name_workflow_id(&config, action, request_nonce);
        {
            let store = self.store_lock()?;
            if let Some(stored) = store.load_workflow::<HnsNameWorkflow>(workflow_id)? {
                let plan = &stored.state.plan;
                if stored.kind != action.workflow_kind()
                    || stored.state.stage != NameOperationState::Prepared
                    || stored.state.transaction.is_some()
                    || stored.state.signed_transaction.is_some()
                    || stored.state.fee_quote.is_some()
                    || plan.wallet_id != config.wallet_id
                    || plan.account_id != config.account_id
                    || plan.workflow_id != workflow_id
                    || plan.request_nonce != request_nonce
                    || plan.action != action
                    || plan.name != name
                    || plan.name_hash != name_hash
                    || plan.source != source_evidence
                    || plan.recipient != recipient
                    || plan.recipient_display != recipient_display
                    || plan.finalize != finalize
                    || plan.maximum_fee != maximum_fee
                    || plan.expires_at_unix <= now_unix
                {
                    return Err(HnsWalletError::InvalidWorkflow);
                }
                validate_name_reservations(
                    &store,
                    &config,
                    workflow_id,
                    name_hash,
                    plan.source.owner_outpoint,
                    &plan.funding_inputs,
                    Some(plan.expires_at_unix),
                )?;
                return prepared_name_operation(plan);
            }
        }

        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let (coins, change) = {
            let mut store = self.store_lock()?;
            let coins = available_unreserved_coins(&mut store, &config, cached_coins, now_unix)?;
            let public = derive_hns_public_key(&store, config.wallet_id, change_derivation)?;
            let change = Address::new(0, public_key_hash(&public)?.to_vec())
                .map_err(|_| HnsWalletError::InvalidAddress)?;
            (coins, change)
        };
        let fee_rate = self.backend.estimate_fee_rate(DEFAULT_FEE_TARGET_BLOCKS)?;
        let recipient_address = Address::new(recipient.version, recipient.hash.clone())
            .map_err(|_| HnsWalletError::InvalidAddress)?;
        let (transaction, funding_inputs, fee) = build_unsigned_name_operation(
            action,
            &source,
            &current_state,
            &recipient_address,
            finalize.as_ref(),
            coins,
            &change,
            config.minimum_confirmations,
            fee_rate,
            maximum_fee,
            config.dust_threshold,
        )?;
        let expires_at_unix = now_unix
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(HnsWalletError::Arithmetic)?;
        let plan = HnsNamePlan {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            workflow_id,
            request_nonce,
            action,
            name,
            name_hash,
            source: source_evidence,
            recipient,
            recipient_display,
            finalize,
            funding_inputs,
            unsigned_transaction: transaction
                .encode()
                .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?,
            fee_rate,
            fee,
            maximum_fee,
            expires_at_unix,
        };
        let prepared = prepared_name_operation(&plan)?;
        let workflow = HnsNameWorkflow {
            plan,
            stage: NameOperationState::Prepared,
            transaction: None,
            signed_transaction: None,
            fee_quote: None,
            last_verified_binding: None,
            last_verified_inclusion: None,
            last_finalize_eligible_height: None,
        };
        let reservations = name_reservation_saves(
            &config,
            workflow_id,
            name_hash,
            &source,
            &workflow.plan.funding_inputs,
            expires_at_unix,
            now_unix,
        )?;
        if self.cache_read()?.binding != Some(workflow.plan.source.preparation_binding)
            || self.cache_read()?.mempool_binding != Some(workflow.plan.source.preparation_mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let uses_change = transaction.outputs.len() > 1;
        let mut store = self.store_lock()?;
        if store
            .load_workflow::<HnsNameWorkflow>(workflow_id)?
            .is_some()
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        if uses_change {
            let account_save = HnsWalletRuntime::<B, C>::change_account_save(
                &account,
                account_revision,
                change_derivation.index,
                now_unix,
            )?;
            let (_, next_account_revision) = store.save_workflow_with_account_and_entity_batch(
                workflow_id,
                action.workflow_kind(),
                0,
                &workflow,
                false,
                now_unix,
                &account_save,
                EntityKind::InputReservation,
                &reservations,
                &[],
            )?;
            self.install_committed_account(
                account_revision,
                next_account_revision,
                account_save.value,
            )?;
        } else {
            store.save_workflow_with_entity_batch(
                workflow_id,
                action.workflow_kind(),
                0,
                &workflow,
                false,
                now_unix,
                EntityKind::InputReservation,
                &reservations,
                &[],
            )?;
        }
        Ok(prepared)
    }

    pub fn prepare_name_transfer(
        &self,
        request: PrepareNameTransfer,
    ) -> Result<PreparedNameOperation, HnsWalletError> {
        if request.request_nonce == 0
            || request.maximum_fee.is_zero()
            || !validate_name(&request.name)
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let cache = self.cache_read()?;
        ensure_name_value_ready(&cache)?;
        if request.account != cache.account.config.account_id {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let account = cache.account.clone();
        let account_revision = cache.account_revision;
        let cached_coins = cache.coins.clone();
        drop(cache);
        let recipient_address = decode_hns_address(account.config.network, &request.recipient)?;
        let recipient = WalletAddressKey {
            version: recipient_address.version,
            hash: recipient_address.hash,
        };
        let recipient_display = encode_hns_address(account.config.network, &recipient)?;
        if recipient_display != request.recipient {
            return Err(HnsWalletError::InvalidAddress);
        }
        let authority = self.verify_name_ownership(&request.name)?;
        let context = self.transfer_action_context(&authority)?;
        let state = NameState::decode(
            NameHash::new(authority.name_hash),
            authority.current_state(),
        )
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let source = tracked_name_source(
            authority.binding,
            authority.owner_outpoint,
            &authority.owner_output,
            authority.owner_inclusion,
            authority.derivation,
        )?;
        let source_evidence = HnsNameSourceEvidence {
            preparation_binding: authority.binding,
            preparation_mempool: authority.mempool,
            current_name_state: authority.current_state,
            owner_outpoint: authority.owner_outpoint,
            owner_transaction: authority.owner_transaction,
            owner_inclusion: authority.owner_inclusion,
            owner_derivation: authority.derivation,
            action_context: context,
        };
        self.persist_prepared_name_operation(
            account,
            account_revision,
            cached_coins,
            request.request_nonce,
            HnsNameAction::Transfer,
            authority.name,
            authority.name_hash,
            source_evidence,
            source,
            state,
            recipient,
            recipient_display,
            None,
            request.maximum_fee,
            now,
        )
    }

    pub fn prepare_name_finalize(
        &self,
        request: PrepareNameFinalize,
    ) -> Result<PreparedNameOperation, HnsWalletError> {
        if request.request_nonce == 0
            || request.maximum_fee.is_zero()
            || !validate_name(&request.name)
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let cache = self.cache_read()?;
        ensure_name_value_ready(&cache)?;
        if request.account != cache.account.config.account_id {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let account = cache.account.clone();
        let account_revision = cache.account_revision;
        let cached_coins = cache.coins.clone();
        drop(cache);
        let authority = self.verify_outgoing_name_transfer(&request.name)?;
        let recipient_display = encode_hns_address(account.config.network, &authority.recipient)?;
        if let Some(expected) = request.expected_recipient {
            let decoded = decode_hns_address(account.config.network, &expected)?;
            let expected_key = WalletAddressKey {
                version: decoded.version,
                hash: decoded.hash,
            };
            if expected != recipient_display || expected_key != authority.recipient {
                return Err(HnsWalletError::InvalidPreparedArtifact);
            }
        }
        let current_state =
            NameState::decode(NameHash::new(authority.name_hash), &authority.current_state)
                .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let source = tracked_name_source(
            authority.binding,
            authority.owner_outpoint,
            &authority.owner_output,
            authority.owner_inclusion,
            authority.owner_derivation,
        )?;
        let finalize = HnsFinalizeTerms {
            transfer_height: authority
                .context
                .transfer_height
                .ok_or(HnsWalletError::InvalidEvidence)?,
            finalize_eligible_height: authority
                .context
                .finalize_eligible_height
                .ok_or(HnsWalletError::InvalidEvidence)?,
            renewal_maturity: authority
                .context
                .renewal_maturity
                .ok_or(HnsWalletError::InvalidEvidence)?,
            renewal_period: authority
                .context
                .renewal_period
                .ok_or(HnsWalletError::InvalidEvidence)?,
            renewal_block_height: authority
                .context
                .renewal_block_height
                .ok_or(HnsWalletError::InvalidEvidence)?,
            renewal_block_hash: authority
                .context
                .renewal_block_hash
                .ok_or(HnsWalletError::InvalidEvidence)?,
        };
        let source_evidence = HnsNameSourceEvidence {
            preparation_binding: authority.binding,
            preparation_mempool: authority.mempool,
            current_name_state: authority.current_state,
            owner_outpoint: authority.owner_outpoint,
            owner_transaction: authority.owner_transaction,
            owner_inclusion: authority.owner_inclusion,
            owner_derivation: authority.owner_derivation,
            action_context: authority.context,
        };
        self.persist_prepared_name_operation(
            account,
            account_revision,
            cached_coins,
            request.request_nonce,
            HnsNameAction::Finalize,
            authority.name,
            authority.name_hash,
            source_evidence,
            source,
            current_state,
            authority.recipient,
            recipient_display,
            Some(finalize),
            request.maximum_fee,
            now,
        )
    }

    // Each value is separately checked against node evidence and cached
    // bindings, so this domain validation boundary intentionally stays flat.
    #[allow(clippy::too_many_arguments)]
    fn require_action_context(
        &self,
        config: &HnsRuntimeConfig,
        action: HnsNameAction,
        name_hash: [u8; 32],
        owner_outpoint: HnsOutpoint,
        owner_inclusion: TransactionInclusion,
        binding: SnapshotBinding,
        mempool: MempoolSnapshotBinding,
        state: &NameState,
        require_eligible: bool,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let context = self
            .backend
            .get_name_action_context(action, name_hash, binding, mempool)?;
        validate_name_action_context(
            config,
            action,
            name_hash,
            owner_outpoint,
            owner_inclusion,
            binding,
            mempool,
            state,
            &context,
            require_eligible,
            true,
        )?;
        if let (Some(height), Some(expected_hash)) =
            (context.renewal_block_height, context.renewal_block_hash)
        {
            let block = self.backend.get_block_hash(height, binding)?;
            if block.binding != binding
                || block.height != height
                || block.block_hash != Some(expected_hash)
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        let cache = self.cache_read()?;
        if cache.binding != Some(binding) || cache.mempool_binding != Some(mempool) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(context)
    }

    fn transfer_action_context(
        &self,
        authority: &VerifiedNameOwnership,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let state = NameState::decode(
            NameHash::new(authority.name_hash),
            authority.current_state(),
        )
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
        self.require_action_context(
            &config,
            HnsNameAction::Transfer,
            authority.name_hash,
            authority.owner_outpoint,
            authority.owner_inclusion,
            authority.binding,
            authority.mempool,
            &state,
            true,
        )
    }

    /// Reacquire current, unspent chain authority for one exact Shakedex lock.
    /// The canonical node supplies NameState, owner, active-chain, mempool, and
    /// MTP evidence; the wallet independently binds the supplied seller key to
    /// the consensus FINALIZE coin's 32-byte lock program.
    pub fn verify_current_shakedex_lock(
        &self,
        name: &[u8],
        seller_public_key: [u8; 33],
    ) -> Result<VerifiedCurrentShakedexLock, HnsWalletError> {
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let mempool = cache
            .mempool_binding
            .ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let config = cache.account.config.clone();
        drop(cache);
        if binding.tip.median_time_past == 0 {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let validated = validated_name_evidence(&self.backend, name, binding, None)?;
        let current = validated.current.ok_or(HnsWalletError::InvalidEvidence)?;
        let owner = current.owner.ok_or(HnsWalletError::InvalidEvidence)?;
        if owner.output.covenant.kind != CovenantKind::Finalize {
            return Err(HnsWalletError::InvalidEvidence);
        }
        self.require_action_context(
            &config,
            HnsNameAction::Transfer,
            validated.known_name.name_hash,
            owner.outpoint,
            owner.inclusion,
            binding,
            mempool,
            &current.state,
            true,
        )?;
        require_current_owner_unspent(&self.backend, owner.outpoint, binding)?;
        let (_, locking_coin) = canonical_current_name_coin(&owner)?;
        let descriptor = hns_swap::ShakedexLockDescriptor::from_locking_coin(
            shakedex_network_binding(config.network)?,
            &locking_coin,
            seller_public_key,
        )
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let cache = self.cache_read()?;
        if cache.binding != Some(binding) || cache.mempool_binding != Some(mempool) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let observed_at_unix = self.clock.now_unix()?;
        Ok(VerifiedCurrentShakedexLock {
            binding,
            mempool,
            observed_at_unix,
            descriptor,
            locking_coin,
            current_state: current.state,
            board_context: None,
        })
    }

    /// Reacquire current, unspent FINALIZE authority for the exact TRANSFER at
    /// output zero that spends a previously authenticated Shakedex lock.
    pub fn verify_current_shakedex_transfer(
        &self,
        descriptor: &hns_swap::ShakedexLockDescriptor,
        expected_transfer: TransactionHash,
    ) -> Result<VerifiedCurrentShakedexTransfer, HnsWalletError> {
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let mempool = cache
            .mempool_binding
            .ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let config = cache.account.config.clone();
        drop(cache);
        let expected_network = shakedex_network_binding(config.network)?;
        descriptor
            .validate()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        if descriptor.network != expected_network
            || expected_transfer.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let validated = validated_name_evidence(&self.backend, &descriptor.name, binding, None)?;
        let current = validated.current.ok_or(HnsWalletError::InvalidEvidence)?;
        let owner = current.owner.ok_or(HnsWalletError::InvalidEvidence)?;
        if owner.output.covenant.kind != CovenantKind::Transfer
            || owner.outpoint.transaction != expected_transfer
            || owner.outpoint.output_index != 0
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let context = self.require_action_context(
            &config,
            HnsNameAction::Finalize,
            validated.known_name.name_hash,
            owner.outpoint,
            owner.inclusion,
            binding,
            mempool,
            &current.state,
            true,
        )?;
        require_current_owner_unspent(&self.backend, owner.outpoint, binding)?;
        let (transfer_transaction, transfer_coin) = canonical_current_name_coin(&owner)?;
        let expected_lock_script = descriptor
            .lock_script_identifier()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let transfer = TransferCovenant::try_from(&transfer_coin.covenant)
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        let expected_name_hash =
            hash_name(&descriptor.name).map_err(|_| HnsWalletError::InvalidEvidence)?;
        if transfer_transaction
            .inputs
            .first()
            .is_none_or(|input| input.previous_output != descriptor.locking_outpoint)
            || transfer_coin.address.version != 0
            || transfer_coin.address.hash.as_slice() != expected_lock_script.as_slice()
            || transfer.name_hash != expected_name_hash
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let renewal_block_height = context
            .renewal_block_height
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let renewal_block_hash = context
            .renewal_block_hash
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let cache = self.cache_read()?;
        if cache.binding != Some(binding) || cache.mempool_binding != Some(mempool) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(VerifiedCurrentShakedexTransfer {
            binding,
            mempool,
            descriptor: descriptor.clone(),
            transfer_transaction,
            transfer_coin,
            owner_inclusion: owner.inclusion,
            current_state: current.state,
            renewal_block_height,
            renewal_block_hash,
        })
    }

    /// Reacquire direct-FINALIZE authority for an exact, confirmed outgoing
    /// TRANSFER. Incoming recipient classification is tracking evidence only.
    pub fn verify_outgoing_name_transfer(
        &self,
        name: &[u8],
    ) -> Result<VerifiedOutgoingNameTransfer, HnsWalletError> {
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
        let current = validated.current.ok_or(HnsWalletError::NameNotOwned)?;
        if !current.state.registered
            || current.state.expired
            || current.state.revoked.get() != 0
            || current.state.transfer.get() == 0
        {
            return Err(HnsWalletError::NameNotOwned);
        }
        let (owner_derivation, recipient) = match &validated.known_name.ownership_status {
            NameOwnershipStatus::OutgoingTransfer {
                owner_derivation,
                recipient,
            } => (*owner_derivation, recipient.clone()),
            _ => return Err(HnsWalletError::NameNotOwned),
        };
        let owner = current.owner.ok_or(HnsWalletError::NameNotOwned)?;
        let owner_inclusion = owner.inclusion;
        let transfer = TransferCovenant::try_from(&owner.output.covenant)
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        if transfer.recipient_version != recipient.version
            || transfer.recipient_hash != recipient.hash
            || u64::from(current.state.transfer.get()) != owner_inclusion.height
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let context = self.require_action_context(
            &config,
            HnsNameAction::Finalize,
            validated.known_name.name_hash,
            owner.outpoint,
            owner_inclusion,
            binding,
            mempool,
            &current.state,
            true,
        )?;
        if self.cache_read()?.binding != Some(binding) {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(VerifiedOutgoingNameTransfer {
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
            owner_inclusion,
            owner_derivation,
            recipient,
            context,
        })
    }

    pub fn list_name_operations(&self) -> Result<Vec<NameOperation>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let store = self.store_lock()?;
        let mut operations = Vec::new();
        for kind in [WorkflowKind::NameTransfer, WorkflowKind::NameFinalize] {
            for stored in
                store.list_workflows_complete::<HnsNameWorkflow>(kind, MAX_HISTORY_RESULTS)?
            {
                if stored.state.plan.wallet_id == config.wallet_id
                    && stored.state.plan.account_id == config.account_id
                {
                    operations.push(project_name_operation(stored, &config)?);
                }
            }
        }
        operations.sort_by_key(|operation| operation.workflow_id);
        Ok(operations)
    }

    pub fn get_name_operation(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<NameOperation>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let Some(stored) = self
            .store_lock()?
            .load_workflow::<HnsNameWorkflow>(workflow_id)?
        else {
            return Ok(None);
        };
        if !matches!(
            stored.kind,
            WorkflowKind::NameTransfer | WorkflowKind::NameFinalize
        ) || stored.state.plan.wallet_id != config.wallet_id
            || stored.state.plan.account_id != config.account_id
        {
            return Ok(None);
        }
        project_name_operation(stored, &config).map(Some)
    }

    /// Store one encrypted, single-use trusted-UI approval for an exact
    /// prepared name artifact.
    pub fn register_name_operation_approval(
        &self,
        approval_id: ApprovalId,
        origin: &str,
        prepared: &PreparedNameOperation,
        expires_at_unix: u64,
    ) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let plan = decode_prepared_name_operation(prepared)?;
        let config = self.cache_read()?.account.config.clone();
        if plan.wallet_id != config.wallet_id
            || plan.account_id != config.account_id
            || expires_at_unix > plan.expires_at_unix
            || expires_at_unix <= now
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsNameWorkflow>(plan.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != plan.action.workflow_kind()
            || stored.state.plan != plan
            || stored.state.stage != NameOperationState::Prepared
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        drop(store);
        let approval = HnsNameApproval {
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

    /// Cancel an unsigned preparation or explicitly abandon a reorged action
    /// that requires new approval. Replacing the latter requires a fresh
    /// request nonce; the old signed bytes remain recorded in the cancelled
    /// workflow and are never reused as authority.
    pub fn cancel_prepared_name_operation(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        let mut store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsNameWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.state.plan.wallet_id != config.wallet_id
            || stored.state.plan.account_id != config.account_id
            || stored.kind != stored.state.plan.action.workflow_kind()
            || !matches!(
                stored.state.stage,
                NameOperationState::Prepared | NameOperationState::ReapprovalRequired
            )
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut workflow = stored.state;
        workflow.stage = NameOperationState::Cancelled;
        let deletes = reservation_deletes(&store, &config, workflow_id)?;
        store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            workflow_id,
            workflow.plan.action.workflow_kind(),
            stored.revision,
            &workflow,
            workflow.signed_transaction.is_some(),
            now,
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Height, Outpoint as CanonicalOutpoint};

    fn account_with_seed() -> (WalletStore, HnsAccountRecord) {
        let config = HnsRuntimeConfig {
            wallet_id: WalletId::new([71; 16]),
            account_id: AccountId::new([72; 16]),
            account_derivation_index: 3,
            network: HnsNetwork::Regtest,
            birthday_height: 1,
            restore_lookahead: DEFAULT_RESTORE_LOOKAHEAD,
            minimum_confirmations: 1,
            dust_threshold: BaseUnits::new(DEFAULT_DUST_THRESHOLD),
            value_operations_enabled: false,
            settlement_enabled: false,
        };
        let mut store = WalletStore::create(":memory:", "passphrase").expect("store");
        store
            .put_secret(
                config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[73; 64],
                1,
            )
            .expect("seed");
        (
            store,
            HnsAccountRecord {
                config,
                next_receive_index: 0,
                next_change_index: 0,
                next_name_index: 1,
                next_shakedex_index: 0,
                external_scan_end: 99,
                internal_scan_end: 99,
                name_scan_end: 99,
                shakedex_scan_end: 99,
                shakedex_scan_complete: true,
                shakedex_scan_in_progress: false,
                last_used_external: None,
                last_used_internal: None,
                last_used_name: Some(0),
                last_used_shakedex: None,
            },
        )
    }

    // Test fixtures keep each coin attribute visible at the call site.
    #[allow(clippy::too_many_arguments)]
    fn tracked_input(
        store: &WalletStore,
        account: &HnsAccountRecord,
        role: KeyRole,
        index: u32,
        outpoint: HnsOutpoint,
        value: u64,
        height: u32,
        covenant: Covenant,
    ) -> TrackedHnsCoin {
        let derivation = DerivationReference {
            role,
            account: account.config.account_derivation_index,
            change: 0,
            index,
        };
        let public =
            derive_hns_public_key(store, account.config.wallet_id, derivation).expect("public key");
        TrackedHnsCoin {
            coin: WalletCoin {
                outpoint,
                value: BaseUnits::new(u128::from(value)),
                confirmation_count: 10,
                confirmed_height: Some(height),
                coinbase: false,
                name_locked: covenant.kind != CovenantKind::None,
                covenant: covenant.encode().expect("covenant"),
            },
            derivation,
            address_program: public_key_hash(&public).expect("program").to_vec(),
        }
    }

    fn owned_name_source(
        store: &WalletStore,
        account: &HnsAccountRecord,
    ) -> (TrackedHnsCoin, NameState, Transaction) {
        let name = b"alpha".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let derivation = DerivationReference {
            role: KeyRole::HnsName,
            account: account.config.account_derivation_index,
            change: 0,
            index: 0,
        };
        let public = derive_hns_public_key(store, account.config.wallet_id, derivation)
            .expect("name public key");
        let program = public_key_hash(&public).expect("name program").to_vec();
        let mut state = NameState {
            name_hash,
            name,
            height: Height::new(100),
            renewal: Height::new(120),
            owner: CanonicalOutpoint::NULL,
            value: Dollarydoos::new(50_000),
            highest: Dollarydoos::new(60_000),
            resource_data: Vec::new(),
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 1,
            registered: true,
            expired: false,
            weak: false,
        };
        let covenant =
            FinalizeCovenant::from_name_state(&state, hns_primitives::BlockHash::new([74; 32]))
                .expect("finalize")
                .to_covenant()
                .expect("finalize covenant");
        let transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: vec![Output {
                value: state.value,
                address: Address::new(0, program.clone()).expect("owner address"),
                covenant: covenant.clone(),
            }],
            locktime: 0,
        };
        let transaction_hash = transaction.transaction_hash().expect("owner txid");
        state.owner = CanonicalOutpoint {
            transaction_hash,
            index: 0,
        };
        let source = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new(transaction_hash.into_bytes()),
                    output_index: 0,
                },
                value: BaseUnits::new(u128::from(state.value.get())),
                confirmation_count: 10,
                confirmed_height: Some(390),
                coinbase: false,
                name_locked: true,
                covenant: covenant.encode().expect("covenant"),
            },
            derivation,
            address_program: program,
        };
        (source, state, transaction)
    }

    #[test]
    fn canonical_hns_v3_name_action_transfer_is_value_preserving_and_fully_signed() {
        let (store, account) = account_with_seed();
        let (source, state, _) = owned_name_source(&store, &account);
        let funding = tracked_input(
            &store,
            &account,
            KeyRole::HnsCoin,
            0,
            HnsOutpoint {
                transaction: TransactionHash::new([75; 32]),
                output_index: 1,
            },
            10_000,
            395,
            Covenant::default(),
        );
        let recipient = Address::new(0, vec![76; 20]).expect("recipient");
        let change = Address::new(0, funding.address_program.clone()).expect("change");
        let (unsigned, selected, fee) = build_unsigned_name_operation(
            HnsNameAction::Transfer,
            &source,
            &state,
            &recipient,
            None,
            vec![funding],
            &change,
            1,
            BaseUnits::new(1_000),
            BaseUnits::new(10_000),
            BaseUnits::new(DEFAULT_DUST_THRESHOLD),
        )
        .expect("unsigned transfer");
        assert_eq!(unsigned.outputs[0].value, state.value);
        assert_eq!(unsigned.outputs[0].address.hash, source.address_program);
        assert_eq!(
            TransferCovenant::try_from(&unsigned.outputs[0].covenant)
                .expect("transfer covenant")
                .recipient_hash,
            recipient.hash
        );
        assert!(fee <= BaseUnits::new(10_000));
        let mut inputs = vec![source.clone()];
        inputs.extend(selected);
        let signed = sign_ordered_p2pkh_inputs(
            &store,
            &account,
            unsigned.clone(),
            &inputs,
            &[KeyRole::HnsName, KeyRole::HnsCoin],
        )
        .expect("signed transfer");
        let signed = validate_witness_only_change(&unsigned, &signed).expect("witness-only");
        let canonical = canonical_input_coins(&inputs).expect("input evidence");
        hns_transaction::verify_covenant_links(&signed, &canonical).expect("covenant linkage");
        for (index, coin) in canonical.iter().enumerate() {
            hns_script::verify_witness_program(
                &signed,
                index,
                coin,
                hns_script::ScriptFlags::STANDARD,
                &hns_script::K256SignatureVerifier,
            )
            .expect("signature");
        }
    }

    #[test]
    fn canonical_hns_v3_name_action_finalize_is_covenant_derived_and_fully_signed() {
        let (store, account) = account_with_seed();
        let (owned, mut state, _) = owned_name_source(&store, &account);
        let recipient = Address::new(0, vec![84; 20]).expect("recipient");
        let transfer_output = hns_transaction::build_transfer_output(
            &owned.to_canonical_coin().expect("owner coin"),
            &recipient,
        )
        .expect("transfer output");
        let transfer_transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: vec![transfer_output.clone()],
            locktime: 0,
        };
        let transfer_hash = transfer_transaction
            .transaction_hash()
            .expect("transfer txid");
        let transfer_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(transfer_hash.into_bytes()),
            output_index: 0,
        };
        state.owner = CanonicalOutpoint {
            transaction_hash: transfer_hash,
            index: 0,
        };
        state.transfer = Height::new(400);
        let transfer_source = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: transfer_outpoint,
                value: BaseUnits::new(u128::from(transfer_output.value.get())),
                confirmation_count: 10,
                confirmed_height: Some(400),
                coinbase: false,
                name_locked: true,
                covenant: transfer_output
                    .covenant
                    .encode()
                    .expect("transfer covenant"),
            },
            derivation: owned.derivation,
            address_program: owned.address_program,
        };
        let funding = tracked_input(
            &store,
            &account,
            KeyRole::HnsCoin,
            0,
            HnsOutpoint {
                transaction: TransactionHash::new([85; 32]),
                output_index: 1,
            },
            10_000,
            405,
            Covenant::default(),
        );
        let change = Address::new(0, funding.address_program.clone()).expect("change");
        let finalize = HnsFinalizeTerms {
            transfer_height: 400,
            finalize_eligible_height: 410,
            renewal_maturity: 50,
            renewal_period: 2_500,
            renewal_block_height: 309,
            renewal_block_hash: [86; 32],
        };
        let (unsigned, selected, fee) = build_unsigned_name_operation(
            HnsNameAction::Finalize,
            &transfer_source,
            &state,
            &recipient,
            Some(&finalize),
            vec![funding],
            &change,
            1,
            BaseUnits::new(1_000),
            BaseUnits::new(10_000),
            BaseUnits::new(DEFAULT_DUST_THRESHOLD),
        )
        .expect("unsigned finalize");
        assert_eq!(unsigned.outputs[0].value, state.value);
        assert_eq!(unsigned.outputs[0].address, recipient);
        assert_eq!(unsigned.outputs[0].covenant.kind, CovenantKind::Finalize);
        assert!(fee <= BaseUnits::new(10_000));
        let mut inputs = vec![transfer_source];
        inputs.extend(selected);
        let signed = sign_ordered_p2pkh_inputs(
            &store,
            &account,
            unsigned.clone(),
            &inputs,
            &[KeyRole::HnsName, KeyRole::HnsCoin],
        )
        .expect("signed finalize");
        let signed = validate_witness_only_change(&unsigned, &signed).expect("witness-only");
        let canonical = canonical_input_coins(&inputs).expect("input evidence");
        hns_transaction::verify_finalize_at_index_zero(
            &signed,
            &canonical[0],
            &state,
            hns_primitives::BlockHash::new(finalize.renewal_block_hash),
        )
        .expect("finalize covenant");
        hns_transaction::verify_covenant_links(&signed, &canonical).expect("covenant linkage");
        for (index, coin) in canonical.iter().enumerate() {
            hns_script::verify_witness_program(
                &signed,
                index,
                coin,
                hns_script::ScriptFlags::STANDARD,
                &hns_script::K256SignatureVerifier,
            )
            .expect("signature");
        }
    }

    #[test]
    fn canonical_hns_v3_name_action_context_binds_maturity_and_renewal_window() {
        let (store, account) = account_with_seed();
        let (owned, mut state, _) = owned_name_source(&store, &account);
        let recipient = Address::new(0, vec![77; 20]).expect("recipient");
        let transfer_output = hns_transaction::build_transfer_output(
            &owned.to_canonical_coin().expect("owner coin"),
            &recipient,
        )
        .expect("transfer output");
        let transfer_transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: vec![transfer_output],
            locktime: 0,
        };
        let transfer_hash = transfer_transaction
            .transaction_hash()
            .expect("transfer txid");
        let owner_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(transfer_hash.into_bytes()),
            output_index: 0,
        };
        state.owner = CanonicalOutpoint {
            transaction_hash: transfer_hash,
            index: 0,
        };
        state.transfer = Height::new(400);
        let binding = SnapshotBinding {
            tip: ChainTip {
                height: 409,
                block_hash: [78; 32],
                tree_root: [79; 32],
                median_time_past: 1_700_000_000,
            },
            chain_epoch: 9,
        };
        let mempool = MempoolSnapshotBinding {
            instance_nonce: [80; 32],
            generation: 10,
        };
        let (_, genesis_hash) = expected_chain_identity(HnsNetwork::Regtest).expect("identity");
        let context = NameActionContextEvidence {
            binding,
            mempool,
            network: HnsNetwork::Regtest,
            network_id: 2,
            genesis_hash,
            context_version: NAME_ACTION_CONTEXT_VERSION,
            consensus_profile: NAME_ACTION_CONSENSUS_PROFILE.to_owned(),
            action: HnsNameAction::Finalize,
            name_hash: state.name_hash.into_bytes(),
            current_state: state.encode().expect("state"),
            owner_outpoint,
            owner_transaction: transfer_transaction.encode().expect("transfer"),
            owner_inclusion: TransactionInclusion {
                block_hash: [81; 32],
                height: 400,
                transaction_index: Some(1),
            },
            candidate_inclusion_height: 410,
            lifecycle: HnsNameLifecycle::Closed,
            action_eligible: true,
            ineligibility_reasons: Vec::new(),
            transfer_height: Some(400),
            transfer_lockup: Some(10),
            finalize_eligible_height: Some(410),
            finalize_mature: Some(true),
            renewal_maturity: Some(50),
            renewal_period: Some(2_500),
            renewal_block_height: Some(309),
            renewal_block_hash: Some([82; 32]),
            renewal_valid_at_candidate: Some(true),
            mempool_spender: None,
        };
        validate_name_action_context(
            &account.config,
            HnsNameAction::Finalize,
            state.name_hash.into_bytes(),
            owner_outpoint,
            context.owner_inclusion,
            binding,
            mempool,
            &state,
            &context,
            true,
            true,
        )
        .expect("eligible context");

        let mut mismatch = context.clone();
        mismatch.finalize_eligible_height = Some(411);
        assert!(
            validate_name_action_context(
                &account.config,
                HnsNameAction::Finalize,
                state.name_hash.into_bytes(),
                owner_outpoint,
                mismatch.owner_inclusion,
                binding,
                mempool,
                &state,
                &mismatch,
                true,
                true,
            )
            .is_err()
        );

        let mut spent = context;
        spent.action_eligible = false;
        spent.ineligibility_reasons = vec![NameActionIneligibility::OwnerSpentInMempool];
        spent.mempool_spender = Some(TransactionHash::new([83; 32]));
        validate_name_action_context(
            &account.config,
            HnsNameAction::Finalize,
            state.name_hash.into_bytes(),
            owner_outpoint,
            spent.owner_inclusion,
            binding,
            mempool,
            &state,
            &spent,
            false,
            false,
        )
        .expect("tracking accepts a bound mempool spender");
        assert!(
            validate_name_action_context(
                &account.config,
                HnsNameAction::Finalize,
                state.name_hash.into_bytes(),
                owner_outpoint,
                spent.owner_inclusion,
                binding,
                mempool,
                &state,
                &spent,
                true,
                true,
            )
            .is_err()
        );
    }
}
