//! Encrypted, monotonic allocation of separated HNS Shakedex seller keys.
//!
//! Allocation records contain only authenticated public recovery bindings. The
//! seller scalar is deterministically re-derived from the exact 64-byte wallet
//! recovery seed after the complete durable topology has been authenticated;
//! it is never persisted or exposed through an arbitrary signing interface.

use core::fmt;

use hns_covenants::{hash_name, validate_name};
use hns_primitives::{BlockHash, Dollarydoos, NameHash};
use hns_swap::{
    FixedPriceListing, ListingCancellation, NetworkBinding, SHAKEDEX_RECOVERY_SIGHASH,
    ShakedexLockDescriptor, SwapError, SwapProof, encode_time_lock, lock_script_hash,
};
use hns_transaction::{Address, Coin, Transaction};
use hns_wallet_store::{
    EntityBatchSave, EntityKind, SecretKind, StoreError, StoredEntity, WalletStore,
};
use hns_wallet_types::{AccountId, DerivationReference, KeyRole, ObjectHash, WalletId, WorkflowId};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    HnsAccountRecord, HnsNetwork, HnsRuntimeConfig, HnsWalletError, MAX_RESTORE_LOOKAHEAD,
    VerifiedCurrentShakedexLock,
};

const ALLOCATION_STORAGE_VERSION: u16 = 1;
const HNS_SHAKEDEX_ROLE_CODE: u32 = 2;
const MAX_HNS_SHAKEDEX_KEY_INDEX: u32 = MAX_RESTORE_LOOKAHEAD - 1;
const MAX_ALLOCATION_ATTEMPTS: usize = 2;

const HIGH_WATER_ID_DOMAIN: &[u8] = b"hns-wallet/hns-shakedex-key/high-water/v1";
const NAMESPACE_ANCHOR_ID_DOMAIN: &[u8] = b"hns-wallet/hns-shakedex-key/namespace-anchor/v1";
const BINDING_ID_DOMAIN: &[u8] = b"hns-wallet/hns-shakedex-key/binding/v1";
const BINDING_CLAIM_ID_DOMAIN: &[u8] = b"hns-wallet/hns-shakedex-key/binding-claim/v1";
const BINDING_COMMITMENT_DOMAIN: &[u8] = b"hns-wallet/hns-shakedex-key/binding-commitment/v1";
const SELLER_TERMS_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet/hns-shakedex-key/seller-terms-commitment/v1";
const RECOVERY_SEED_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet/hns-shakedex-key/recovery-seed-commitment/v1";

/// Canonical economic terms frozen before a Shakedex seller-key allocation.
///
/// Publication timestamps and board sequence numbers are deliberately not
/// economic terms: a seller may republish or cancel the same presign. The
/// payment address, price, consensus deadline, and marketplace fee are bound
/// here and cannot be substituted by any purpose-bound signer method.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsShakedexSellerTerms {
    #[serde(with = "address_serde")]
    pub payment_address: Address,
    #[serde(with = "dollarydoos_serde")]
    pub price: Dollarydoos,
    pub lock_time_seconds: u64,
    #[serde(with = "optional_address_serde")]
    pub fee_address: Option<Address>,
    #[serde(with = "dollarydoos_serde")]
    pub fee: Dollarydoos,
}

impl HnsShakedexSellerTerms {
    pub fn validate(&self) -> Result<(), SwapError> {
        self.payment_address.validate()?;
        if self.price.get() == 0 {
            return Err(SwapError::ZeroPrice);
        }
        encode_time_lock(self.lock_time_seconds)?;
        match (&self.fee_address, self.fee.get()) {
            (None, 0) => {}
            (Some(address), fee) if fee > 0 => address.validate()?,
            _ => return Err(SwapError::InvalidFee),
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<ObjectHash, SwapError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(SELLER_TERMS_COMMITMENT_DOMAIN);
        hash_address(&mut hasher, &self.payment_address);
        hasher.update(self.price.get().to_be_bytes());
        hasher.update(self.lock_time_seconds.to_be_bytes());
        hasher.update(self.fee.get().to_be_bytes());
        match &self.fee_address {
            Some(address) => {
                hasher.update([1]);
                hash_address(&mut hasher, address);
            }
            None => hasher.update([0]),
        }
        Ok(ObjectHash::new(hasher.finalize().into()))
    }

    fn from_proof(proof: &SwapProof) -> Self {
        Self {
            payment_address: proof.payment_address.clone(),
            price: proof.price,
            lock_time_seconds: proof.lock_time_seconds,
            fee_address: proof.fee_address.clone(),
            fee: proof.fee,
        }
    }
}

fn hash_address(hasher: &mut Sha256, address: &Address) {
    hasher.update([address.version]);
    hasher.update((address.hash.len() as u64).to_be_bytes());
    hasher.update(&address.hash);
}

mod address_serde {
    use hns_transaction::Address;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AddressWire {
        version: u8,
        hash: Vec<u8>,
    }

    pub fn serialize<S>(value: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        AddressWire {
            version: value.version,
            hash: value.hash.clone(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AddressWire::deserialize(deserializer)?;
        Address::new(wire.version, wire.hash)
            .map_err(|_| <D::Error as serde::de::Error>::custom("invalid Handshake address"))
    }
}

mod optional_address_serde {
    use hns_transaction::Address;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AddressWire {
        version: u8,
        hash: Vec<u8>,
    }

    pub fn serialize<S>(value: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|address| AddressWire {
                version: address.version,
                hash: address.hash.clone(),
            })
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<AddressWire>::deserialize(deserializer)?
            .map(|wire| {
                Address::new(wire.version, wire.hash).map_err(|_| {
                    <D::Error as serde::de::Error>::custom("invalid Handshake fee address")
                })
            })
            .transpose()
    }
}

mod dollarydoos_serde {
    use hns_primitives::Dollarydoos;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Dollarydoos, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.get())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Dollarydoos, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Dollarydoos::new(u64::deserialize(deserializer)?))
    }
}

mod compressed_public_key_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| {
                <D::Error as serde::de::Error>::custom(
                    "compressed Shakedex public key must contain exactly 33 bytes",
                )
            })
    }
}

/// Immutable caller context for one Shakedex seller-key allocation.
///
/// The wallet computes the canonical commitment itself and binds it to the
/// exact workflow and canonical Handshake name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsShakedexKeyAllocationRequest {
    pub workflow_id: WorkflowId,
    pub name: Vec<u8>,
    pub seller_terms: HnsShakedexSellerTerms,
}

impl HnsShakedexKeyAllocationRequest {
    pub fn terms_commitment(&self) -> Result<ObjectHash, HnsShakedexKeyAllocationError> {
        Ok(self.seller_terms.commitment()?)
    }

    fn validate(&self) -> Result<(), HnsShakedexKeyAllocationError> {
        if self.workflow_id.as_bytes().iter().all(|byte| *byte == 0) || !validate_name(&self.name) {
            return Err(HnsShakedexKeyAllocationError::InvalidRequest);
        }
        let terms_commitment = self.terms_commitment()?;
        if terms_commitment.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(HnsShakedexKeyAllocationError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AllocationContext {
    wallet_id: WalletId,
    account_id: AccountId,
    account_derivation_index: u32,
    network: HnsNetwork,
    network_magic: u32,
    network_genesis: [u8; 32],
}

impl AllocationContext {
    fn from_config(config: &HnsRuntimeConfig) -> Result<Self, HnsShakedexKeyAllocationError> {
        config.validate()?;
        Self::from_structurally_valid_config(config)
    }

    fn from_structurally_valid_config(
        config: &HnsRuntimeConfig,
    ) -> Result<Self, HnsShakedexKeyAllocationError> {
        config.validate_structure()?;
        if config.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || config.account_id.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(HnsShakedexKeyAllocationError::InvalidRequest);
        }
        let network = super::shakedex_network_binding(config.network)?;
        Ok(Self {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            account_derivation_index: config.account_derivation_index,
            network: config.network,
            network_magic: network.magic,
            network_genesis: *network.genesis.as_bytes(),
        })
    }

    fn network_binding(self) -> NetworkBinding {
        NetworkBinding {
            magic: self.network_magic,
            genesis: BlockHash::new(self.network_genesis),
        }
    }

    fn validate_canonical(self) -> Result<(), HnsShakedexKeyAllocationError> {
        if self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.account_id.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        let expected = super::shakedex_network_binding(self.network)
            .map_err(|_| HnsShakedexKeyAllocationError::CorruptAllocation)?;
        if expected.magic != self.network_magic
            || expected.genesis.as_bytes() != &self.network_genesis
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }

    fn matches_config(
        self,
        config: &HnsRuntimeConfig,
    ) -> Result<bool, HnsShakedexKeyAllocationError> {
        Ok(self == Self::from_config(config)?)
    }
}

/// Immutable public recovery binding for one HNS Shakedex workflow.
///
/// The encrypted record deliberately contains no recovery seed or secret
/// scalar. Its derivation reference always uses `HnsShakedex`, the account's
/// stable derivation component, change zero, and the protected high-water
/// index allocated by the same atomic batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsShakedexKeyAllocation {
    storage_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    account_derivation_index: u32,
    network: HnsNetwork,
    network_magic: u32,
    network_genesis: [u8; 32],
    workflow_id: WorkflowId,
    name: Vec<u8>,
    name_hash: [u8; 32],
    terms_commitment: ObjectHash,
    reference: DerivationReference,
    #[serde(with = "compressed_public_key_serde")]
    compressed_public_key: [u8; 33],
    lock_script_hash: [u8; 32],
    recovery_seed_commitment: [u8; 32],
    allocated_at_unix: u64,
}

impl HnsShakedexKeyAllocation {
    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn account_derivation_index(&self) -> u32 {
        self.account_derivation_index
    }

    pub const fn network(&self) -> HnsNetwork {
        self.network
    }

    pub fn network_binding(&self) -> NetworkBinding {
        self.context().network_binding()
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub const fn name_hash(&self) -> NameHash {
        NameHash::new(self.name_hash)
    }

    pub const fn terms_commitment(&self) -> ObjectHash {
        self.terms_commitment
    }

    pub const fn reference(&self) -> DerivationReference {
        self.reference
    }

    pub const fn compressed_public_key(&self) -> &[u8; 33] {
        &self.compressed_public_key
    }

    pub const fn lock_script_hash(&self) -> &[u8; 32] {
        &self.lock_script_hash
    }

    pub const fn allocated_at_unix(&self) -> u64 {
        self.allocated_at_unix
    }

    fn context(&self) -> AllocationContext {
        AllocationContext {
            wallet_id: self.wallet_id,
            account_id: self.account_id,
            account_derivation_index: self.account_derivation_index,
            network: self.network,
            network_magic: self.network_magic,
            network_genesis: self.network_genesis,
        }
    }

    fn validate(&self) -> Result<(), HnsShakedexKeyAllocationError> {
        self.context().validate_canonical()?;
        if self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.workflow_id.as_bytes().iter().all(|byte| *byte == 0)
            || !validate_name(&self.name)
            || self
                .terms_commitment
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
            || self.allocated_at_unix == 0
            || self.reference.role != KeyRole::HnsShakedex
            || self.reference.account != self.account_derivation_index
            || self.reference.change != 0
            || hash_name(&self.name)
                .map(|name_hash| name_hash.as_bytes() != &self.name_hash)
                .unwrap_or(true)
            || lock_script_hash(&self.compressed_public_key) != self.lock_script_hash
            || VerifyingKey::from_sec1_bytes(&self.compressed_public_key).is_err()
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }

    fn matches_request(
        &self,
        config: &HnsRuntimeConfig,
        request: &HnsShakedexKeyAllocationRequest,
    ) -> Result<bool, HnsShakedexKeyAllocationError> {
        Ok(self.context().matches_config(config)?
            && self.workflow_id == request.workflow_id
            && self.name == request.name
            && self.terms_commitment == request.terms_commitment()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnsShakedexKeyHighWater {
    storage_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    account_derivation_index: u32,
    network: HnsNetwork,
    network_magic: u32,
    network_genesis: [u8; 32],
    recovery_seed_commitment: [u8; 32],
    next_key_index: u32,
    last_allocated_at_unix: u64,
}

impl HnsShakedexKeyHighWater {
    fn context(&self) -> AllocationContext {
        AllocationContext {
            wallet_id: self.wallet_id,
            account_id: self.account_id,
            account_derivation_index: self.account_derivation_index,
            network: self.network,
            network_magic: self.network_magic,
            network_genesis: self.network_genesis,
        }
    }

    fn validate(
        &self,
        context: AllocationContext,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        context.validate_canonical()?;
        if self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.context() != context
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
            || self.next_key_index == 0
            || self.next_key_index > MAX_HNS_SHAKEDEX_KEY_INDEX + 1
            || revision == 0
            || revision > u64::from(self.next_key_index)
            || self.last_allocated_at_unix == 0
            || updated_at_unix != self.last_allocated_at_unix
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnsShakedexKeyNamespaceAnchor {
    storage_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    account_derivation_index: u32,
    network: HnsNetwork,
    network_magic: u32,
    network_genesis: [u8; 32],
    recovery_seed_commitment: [u8; 32],
}

impl HnsShakedexKeyNamespaceAnchor {
    fn context(&self) -> AllocationContext {
        AllocationContext {
            wallet_id: self.wallet_id,
            account_id: self.account_id,
            account_derivation_index: self.account_derivation_index,
            network: self.network,
            network_magic: self.network_magic,
            network_genesis: self.network_genesis,
        }
    }

    fn validate(
        &self,
        context: AllocationContext,
        revision: u64,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        context.validate_canonical()?;
        if revision != 1
            || self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.context() != context
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnsShakedexKeyBindingClaim {
    storage_version: u16,
    wallet_id: WalletId,
    workflow_id: WorkflowId,
    binding_commitment: [u8; 32],
}

impl HnsShakedexKeyBindingClaim {
    fn validate(
        &self,
        allocation: &HnsShakedexKeyAllocation,
        revision: u64,
        updated_at_unix: u64,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        if revision != 1
            || updated_at_unix != allocation.allocated_at_unix
            || self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.wallet_id != allocation.wallet_id
            || self.workflow_id != allocation.workflow_id
            || self.binding_commitment != binding_commitment(allocation)?
        {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum HnsShakedexKeyAllocationRecord {
    NamespaceAnchor(HnsShakedexKeyNamespaceAnchor),
    HighWater(HnsShakedexKeyHighWater),
    Binding(HnsShakedexKeyAllocation),
    BindingClaim(HnsShakedexKeyBindingClaim),
}

/// Failures specific to protected HNS Shakedex key allocation and recovery.
/// None of these errors authorizes a value operation or broadcast.
#[derive(Debug, Error)]
pub enum HnsShakedexKeyAllocationError {
    #[error("HNS Shakedex key-allocation request is invalid")]
    InvalidRequest,
    #[error("HNS Shakedex workflow is already bound to different key context")]
    BindingConflict,
    #[error("HNS Shakedex key allocation was not found")]
    AllocationNotFound,
    #[error("HNS Shakedex key-allocation state is corrupt or inconsistent")]
    CorruptAllocation,
    #[error("HNS Shakedex key-allocation index is exhausted")]
    AllocationExhausted,
    #[error("HNS Shakedex key-allocation clock moved behind durable state")]
    ClockRollback,
    #[error("HNS Shakedex key allocation changed concurrently")]
    ConcurrentModification,
    #[error("HNS Shakedex restoration must complete before key allocation")]
    RestorationRequired,
    #[error("HNS Shakedex restoration is in progress")]
    RestorationInProgress,
    #[error("wallet recovery seed is unavailable")]
    MissingRecoverySeed,
    #[error("wallet recovery seed must contain exactly 64 bytes")]
    InvalidRecoverySeed,
    #[error("typed HNS Shakedex object is not bound to this seller key")]
    SigningContextMismatch,
    #[error("HNS Shakedex signature operation failed")]
    SigningFailure,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Wallet(#[from] HnsWalletError),
    #[error(transparent)]
    Swap(#[from] SwapError),
}

/// Durable allocation result plus the WalletAccount revision committed in the
/// same transaction.
pub(super) struct CommittedHnsShakedexKeyAllocation {
    pub allocation: HnsShakedexKeyAllocation,
    pub account: StoredEntity<HnsAccountRecord>,
}

/// Allocate one immutable, role-separated HNS Shakedex seller key.
///
/// The WalletAccount projection, namespace anchor, global account high-water,
/// immutable workflow binding, and binding claim commit in one encrypted
/// transaction. Exact retries return the original allocation without
/// advancing the counter. One stale-revision outcome is reloaded and retried;
/// a second fails closed.
pub(super) fn allocate_hns_shakedex_key(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    request: &HnsShakedexKeyAllocationRequest,
    now_unix: u64,
) -> Result<CommittedHnsShakedexKeyAllocation, HnsShakedexKeyAllocationError> {
    request.validate()?;
    let context = AllocationContext::from_config(config)?;
    if now_unix == 0 {
        return Err(HnsShakedexKeyAllocationError::InvalidRequest);
    }
    if let Some(existing) =
        load_hns_shakedex_key_allocation(store, context.wallet_id, request.workflow_id)?
    {
        let allocation = accept_existing(store, config, request, existing, now_unix)?;
        return Ok(CommittedHnsShakedexKeyAllocation {
            allocation,
            account: load_account(store, config)?,
        });
    }

    for attempt in 0..MAX_ALLOCATION_ATTEMPTS {
        let account = load_allocation_ready_account(store, config)?;
        let high_water = load_high_water(store, context)?;
        let (saves, allocation, next_account) = prepare_allocation_saves(
            store,
            context,
            request,
            now_unix,
            &account.value,
            high_water,
        )?;
        let account_save = EntityBatchSave {
            id: account.id.clone(),
            expected_revision: account.revision,
            value: next_account.clone(),
            updated_at_unix: now_unix,
        };
        match store.apply_account_and_entity_batch(
            &account_save,
            EntityKind::HnsShakedexKeyAllocation,
            &saves,
            &[],
        ) {
            Ok(account_revision) => {
                let signer = load_hns_shakedex_signer(store, config, request)?;
                if signer.compressed_public_key() != allocation.compressed_public_key() {
                    return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
                }
                return Ok(CommittedHnsShakedexKeyAllocation {
                    allocation,
                    account: StoredEntity {
                        kind: EntityKind::WalletAccount,
                        id: account.id,
                        revision: account_revision,
                        value: next_account,
                        updated_at_unix: now_unix,
                    },
                });
            }
            Err(StoreError::StaleRevision { .. }) if attempt == 0 => {
                if let Some(existing) =
                    load_hns_shakedex_key_allocation(store, context.wallet_id, request.workflow_id)?
                {
                    let allocation = accept_existing(store, config, request, existing, now_unix)?;
                    return Ok(CommittedHnsShakedexKeyAllocation {
                        allocation,
                        account: load_account(store, config)?,
                    });
                }
            }
            Err(StoreError::StaleRevision { .. }) => {
                return Err(HnsShakedexKeyAllocationError::ConcurrentModification);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(HnsShakedexKeyAllocationError::ConcurrentModification)
}

fn load_account(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<StoredEntity<HnsAccountRecord>, HnsShakedexKeyAllocationError> {
    let expected_id = super::account_entity_id(config);
    let account = store
        .wallet_account::<HnsAccountRecord>(&expected_id)?
        .ok_or(HnsShakedexKeyAllocationError::CorruptAllocation)?;
    if account.kind != EntityKind::WalletAccount
        || account.id.as_slice() != expected_id.as_slice()
        || account.value.config != *config
        || account.value.next_shakedex_index > MAX_RESTORE_LOOKAHEAD
    {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(account)
}

fn load_allocation_ready_account(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<StoredEntity<HnsAccountRecord>, HnsShakedexKeyAllocationError> {
    let account = load_account(store, config)?;
    if account.value.shakedex_scan_in_progress {
        return Err(HnsShakedexKeyAllocationError::RestorationInProgress);
    }
    if !account.value.shakedex_scan_complete {
        return Err(HnsShakedexKeyAllocationError::RestorationRequired);
    }
    Ok(account)
}

/// Load and authenticate one encrypted public allocation by immutable wallet
/// and workflow identity.
pub(super) fn load_hns_shakedex_key_allocation(
    store: &WalletStore,
    wallet_id: WalletId,
    workflow_id: WorkflowId,
) -> Result<Option<HnsShakedexKeyAllocation>, HnsShakedexKeyAllocationError> {
    if wallet_id.as_bytes().iter().all(|byte| *byte == 0)
        || workflow_id.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(HnsShakedexKeyAllocationError::InvalidRequest);
    }
    let binding_id = binding_record_id(wallet_id, workflow_id);
    let claim_id = binding_claim_record_id(wallet_id, workflow_id);
    let binding = store.load_entity::<HnsShakedexKeyAllocationRecord>(
        EntityKind::HnsShakedexKeyAllocation,
        &binding_id,
    )?;
    let claim = store.load_entity::<HnsShakedexKeyAllocationRecord>(
        EntityKind::HnsShakedexKeyAllocation,
        &claim_id,
    )?;
    let (stored, stored_claim) = match (binding, claim) {
        (None, None) => return Ok(None),
        (Some(binding), Some(claim)) => (binding, claim),
        _ => return Err(HnsShakedexKeyAllocationError::CorruptAllocation),
    };
    if stored.revision != 1 || stored.updated_at_unix == 0 {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    let HnsShakedexKeyAllocationRecord::Binding(allocation) = stored.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    allocation.validate()?;
    if stored.updated_at_unix != allocation.allocated_at_unix
        || allocation.wallet_id != wallet_id
        || allocation.workflow_id != workflow_id
    {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    let HnsShakedexKeyAllocationRecord::BindingClaim(claim) = stored_claim.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    claim.validate(
        &allocation,
        stored_claim.revision,
        stored_claim.updated_at_unix,
    )?;
    validate_allocation_topology(store, &allocation)?;
    Ok(Some(allocation))
}

/// Re-derive an opaque seller signer only after authenticating the complete
/// allocation, claim, namespace anchor, high-water, network binding, seed
/// commitment, compressed public key, and lock-script identifier.
pub(super) fn load_hns_shakedex_signer(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    request: &HnsShakedexKeyAllocationRequest,
) -> Result<HnsShakedexSigner, HnsShakedexKeyAllocationError> {
    request.validate()?;
    let context = AllocationContext::from_config(config)?;
    let allocation =
        load_hns_shakedex_key_allocation(store, context.wallet_id, request.workflow_id)?
            .ok_or(HnsShakedexKeyAllocationError::AllocationNotFound)?;
    if !allocation.matches_request(config, request)? {
        return Err(HnsShakedexKeyAllocationError::BindingConflict);
    }
    let material = derive_key_material(store, context.wallet_id, allocation.reference)?;
    if material.seed_commitment != allocation.recovery_seed_commitment
        || material.compressed_public_key != allocation.compressed_public_key
        || lock_script_hash(&material.compressed_public_key) != allocation.lock_script_hash
    {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(HnsShakedexSigner {
        workflow_id: allocation.workflow_id,
        reference: allocation.reference,
        network: allocation.network_binding(),
        name: allocation.name,
        name_hash: allocation.name_hash,
        terms_commitment: allocation.terms_commitment,
        compressed_public_key: material.compressed_public_key,
        secret: material.secret,
    })
}

/// Return the protected allocation high-water projected as the next available
/// Shakedex restoration index. Absence means no allocated seller key yet.
pub(super) fn allocation_next_index(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<u32, HnsShakedexKeyAllocationError> {
    let context = AllocationContext::from_config(config)?;
    allocation_next_index_for_context(store, context)
}

/// Read an existing protected high-water for the closed persisted-recovery
/// scanner without interpreting historical value flags as allocation
/// authority. This path cannot create, advance, load a signer for, or otherwise
/// mutate an allocation.
pub(super) fn allocation_next_index_for_persisted_recovery_read(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<u32, HnsShakedexKeyAllocationError> {
    let context = AllocationContext::from_structurally_valid_config(config)?;
    allocation_next_index_for_context(store, context)
}

fn allocation_next_index_for_context(
    store: &WalletStore,
    context: AllocationContext,
) -> Result<u32, HnsShakedexKeyAllocationError> {
    let Some(stored) = load_high_water(store, context)? else {
        return Ok(0);
    };
    let HnsShakedexKeyAllocationRecord::HighWater(high_water) = stored.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    if high_water.recovery_seed_commitment != recovery_seed_commitment(store, context.wallet_id)? {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(high_water.next_key_index)
}

fn accept_existing(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    request: &HnsShakedexKeyAllocationRequest,
    allocation: HnsShakedexKeyAllocation,
    now_unix: u64,
) -> Result<HnsShakedexKeyAllocation, HnsShakedexKeyAllocationError> {
    if !allocation.matches_request(config, request)? {
        return Err(HnsShakedexKeyAllocationError::BindingConflict);
    }
    let last_allocated_at_unix = validate_allocation_topology(store, &allocation)?;
    if now_unix < last_allocated_at_unix {
        return Err(HnsShakedexKeyAllocationError::ClockRollback);
    }
    let signer = load_hns_shakedex_signer(store, config, request)?;
    if signer.compressed_public_key() != allocation.compressed_public_key() {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(allocation)
}

fn validate_allocation_topology(
    store: &WalletStore,
    allocation: &HnsShakedexKeyAllocation,
) -> Result<u64, HnsShakedexKeyAllocationError> {
    allocation.validate()?;
    let context = allocation.context();
    let Some(stored) = load_high_water(store, context)? else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    let HnsShakedexKeyAllocationRecord::HighWater(high_water) = stored.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    if allocation.reference.index >= high_water.next_key_index
        || allocation.allocated_at_unix > high_water.last_allocated_at_unix
        || allocation.recovery_seed_commitment != high_water.recovery_seed_commitment
        || allocation.recovery_seed_commitment
            != recovery_seed_commitment(store, allocation.wallet_id)?
    {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(high_water.last_allocated_at_unix)
}

fn load_high_water(
    store: &WalletStore,
    context: AllocationContext,
) -> Result<Option<StoredEntity<HnsShakedexKeyAllocationRecord>>, HnsShakedexKeyAllocationError> {
    context.validate_canonical()?;
    let high_water = store.load_entity::<HnsShakedexKeyAllocationRecord>(
        EntityKind::HnsShakedexKeyAllocation,
        &high_water_record_id(context),
    )?;
    let anchor = store.load_entity::<HnsShakedexKeyAllocationRecord>(
        EntityKind::HnsShakedexKeyAllocation,
        &namespace_anchor_record_id(context),
    )?;
    let (stored, stored_anchor) = match (high_water, anchor) {
        (None, None) => return Ok(None),
        (Some(high_water), Some(anchor)) => (high_water, anchor),
        _ => return Err(HnsShakedexKeyAllocationError::CorruptAllocation),
    };
    let HnsShakedexKeyAllocationRecord::HighWater(high_water) = &stored.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    high_water.validate(context, stored.revision, stored.updated_at_unix)?;
    let HnsShakedexKeyAllocationRecord::NamespaceAnchor(anchor) = &stored_anchor.value else {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    };
    anchor.validate(context, stored_anchor.revision)?;
    if anchor.recovery_seed_commitment != high_water.recovery_seed_commitment {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    Ok(Some(stored))
}

fn prepare_allocation_saves(
    store: &WalletStore,
    context: AllocationContext,
    request: &HnsShakedexKeyAllocationRequest,
    now_unix: u64,
    account: &HnsAccountRecord,
    high_water: Option<StoredEntity<HnsShakedexKeyAllocationRecord>>,
) -> Result<
    (
        Vec<EntityBatchSave<HnsShakedexKeyAllocationRecord>>,
        HnsShakedexKeyAllocation,
        HnsAccountRecord,
    ),
    HnsShakedexKeyAllocationError,
> {
    request.validate()?;
    context.validate_canonical()?;
    if now_unix == 0 {
        return Err(HnsShakedexKeyAllocationError::InvalidRequest);
    }
    if account.config.wallet_id != context.wallet_id
        || account.config.account_id != context.account_id
        || account.config.account_derivation_index != context.account_derivation_index
        || account.config.network != context.network
        || account.next_shakedex_index > MAX_RESTORE_LOOKAHEAD
        || account.shakedex_scan_in_progress
        || !account.shakedex_scan_complete
    {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    let maximum_key_index = MAX_RESTORE_LOOKAHEAD
        .checked_sub(account.config.restore_lookahead)
        .and_then(|limit| limit.checked_sub(1))
        .ok_or(HnsShakedexKeyAllocationError::AllocationExhausted)?;
    let (expected_revision, durable_next_index, last_allocated_at_unix, expected_seed_commitment) =
        match high_water {
            Some(stored) => {
                let HnsShakedexKeyAllocationRecord::HighWater(high_water) = stored.value else {
                    return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
                };
                high_water.validate(context, stored.revision, stored.updated_at_unix)?;
                (
                    stored.revision,
                    high_water.next_key_index,
                    high_water.last_allocated_at_unix,
                    Some(high_water.recovery_seed_commitment),
                )
            }
            None => (0, 0, 0, None),
        };
    let key_index = durable_next_index.max(account.next_shakedex_index);
    if now_unix < last_allocated_at_unix {
        return Err(HnsShakedexKeyAllocationError::ClockRollback);
    }
    if key_index > maximum_key_index {
        return Err(HnsShakedexKeyAllocationError::AllocationExhausted);
    }
    let reference = DerivationReference {
        role: KeyRole::HnsShakedex,
        account: context.account_derivation_index,
        change: 0,
        index: key_index,
    };
    let material = derive_key_material(store, context.wallet_id, reference)?;
    if expected_seed_commitment.is_some_and(|expected| expected != material.seed_commitment) {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    let name_hash =
        hash_name(&request.name).map_err(|_| HnsShakedexKeyAllocationError::InvalidRequest)?;
    let allocation = HnsShakedexKeyAllocation {
        storage_version: ALLOCATION_STORAGE_VERSION,
        wallet_id: context.wallet_id,
        account_id: context.account_id,
        account_derivation_index: context.account_derivation_index,
        network: context.network,
        network_magic: context.network_magic,
        network_genesis: context.network_genesis,
        workflow_id: request.workflow_id,
        name: request.name.clone(),
        name_hash: *name_hash.as_bytes(),
        terms_commitment: request.terms_commitment()?,
        reference,
        compressed_public_key: material.compressed_public_key,
        lock_script_hash: lock_script_hash(&material.compressed_public_key),
        recovery_seed_commitment: material.seed_commitment,
        allocated_at_unix: now_unix,
    };
    allocation.validate()?;
    let next_key_index = key_index
        .checked_add(1)
        .ok_or(HnsShakedexKeyAllocationError::AllocationExhausted)?;
    let next_high_water = HnsShakedexKeyHighWater {
        storage_version: ALLOCATION_STORAGE_VERSION,
        wallet_id: context.wallet_id,
        account_id: context.account_id,
        account_derivation_index: context.account_derivation_index,
        network: context.network,
        network_magic: context.network_magic,
        network_genesis: context.network_genesis,
        recovery_seed_commitment: material.seed_commitment,
        next_key_index,
        last_allocated_at_unix: now_unix,
    };

    let mut saves = Vec::with_capacity(if expected_revision == 0 { 4 } else { 3 });
    if expected_revision == 0 {
        saves.push(EntityBatchSave {
            id: namespace_anchor_record_id(context),
            expected_revision: 0,
            value: HnsShakedexKeyAllocationRecord::NamespaceAnchor(HnsShakedexKeyNamespaceAnchor {
                storage_version: ALLOCATION_STORAGE_VERSION,
                wallet_id: context.wallet_id,
                account_id: context.account_id,
                account_derivation_index: context.account_derivation_index,
                network: context.network,
                network_magic: context.network_magic,
                network_genesis: context.network_genesis,
                recovery_seed_commitment: material.seed_commitment,
            }),
            updated_at_unix: now_unix,
        });
    }
    saves.push(EntityBatchSave {
        id: high_water_record_id(context),
        expected_revision,
        value: HnsShakedexKeyAllocationRecord::HighWater(next_high_water),
        updated_at_unix: now_unix,
    });
    saves.push(EntityBatchSave {
        id: binding_record_id(context.wallet_id, request.workflow_id),
        expected_revision: 0,
        value: HnsShakedexKeyAllocationRecord::Binding(allocation.clone()),
        updated_at_unix: now_unix,
    });
    saves.push(EntityBatchSave {
        id: binding_claim_record_id(context.wallet_id, request.workflow_id),
        expected_revision: 0,
        value: HnsShakedexKeyAllocationRecord::BindingClaim(HnsShakedexKeyBindingClaim {
            storage_version: ALLOCATION_STORAGE_VERSION,
            wallet_id: context.wallet_id,
            workflow_id: request.workflow_id,
            binding_commitment: binding_commitment(&allocation)?,
        }),
        updated_at_unix: now_unix,
    });
    let mut next_account = account.clone();
    next_account.next_shakedex_index = next_key_index;
    next_account.shakedex_scan_end = super::required_scan_end(
        Some(key_index),
        next_account.shakedex_scan_end,
        next_account.config.restore_lookahead,
    );
    if next_account.shakedex_scan_end >= MAX_RESTORE_LOOKAHEAD {
        return Err(HnsShakedexKeyAllocationError::AllocationExhausted);
    }
    Ok((saves, allocation, next_account))
}

struct DerivedKeyMaterial {
    secret: Zeroizing<[u8; 32]>,
    compressed_public_key: [u8; 33],
    seed_commitment: [u8; 32],
}

fn derive_key_material(
    store: &WalletStore,
    wallet_id: WalletId,
    reference: DerivationReference,
) -> Result<DerivedKeyMaterial, HnsShakedexKeyAllocationError> {
    if reference.role != KeyRole::HnsShakedex || reference.change != 0 {
        return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
    }
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(HnsShakedexKeyAllocationError::MissingRecoverySeed)?;
    if seed.len() != 64 {
        return Err(HnsShakedexKeyAllocationError::InvalidRecoverySeed);
    }
    let seed_commitment = recovery_seed_commitment_from_cleartext(wallet_id, seed.as_slice());
    let secret = super::derive_secret(seed.as_slice(), reference)?;
    let signing = SigningKey::from_slice(secret.as_slice())
        .map_err(|_| HnsShakedexKeyAllocationError::CorruptAllocation)?;
    let compressed_public_key = signing.verifying_key().to_encoded_point(true);
    let compressed_public_key = compressed_public_key
        .as_bytes()
        .try_into()
        .map_err(|_| HnsShakedexKeyAllocationError::CorruptAllocation)?;
    Ok(DerivedKeyMaterial {
        secret,
        compressed_public_key,
        seed_commitment,
    })
}

fn recovery_seed_commitment(
    store: &WalletStore,
    wallet_id: WalletId,
) -> Result<[u8; 32], HnsShakedexKeyAllocationError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(HnsShakedexKeyAllocationError::MissingRecoverySeed)?;
    if seed.len() != 64 {
        return Err(HnsShakedexKeyAllocationError::InvalidRecoverySeed);
    }
    Ok(recovery_seed_commitment_from_cleartext(
        wallet_id,
        seed.as_slice(),
    ))
}

fn recovery_seed_commitment_from_cleartext(wallet_id: WalletId, seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_SEED_COMMITMENT_DOMAIN);
    hasher.update(wallet_id.as_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

fn binding_commitment(
    allocation: &HnsShakedexKeyAllocation,
) -> Result<[u8; 32], HnsShakedexKeyAllocationError> {
    allocation.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_COMMITMENT_DOMAIN);
    hasher.update(allocation.storage_version.to_be_bytes());
    hasher.update(allocation.wallet_id.as_bytes());
    hasher.update(allocation.account_id.as_bytes());
    hasher.update(allocation.account_derivation_index.to_be_bytes());
    hasher.update(network_code(allocation.network).to_be_bytes());
    hasher.update(allocation.network_magic.to_be_bytes());
    hasher.update(allocation.network_genesis);
    hasher.update(allocation.workflow_id.as_bytes());
    hasher.update((allocation.name.len() as u64).to_be_bytes());
    hasher.update(&allocation.name);
    hasher.update(allocation.name_hash);
    hasher.update(allocation.terms_commitment.as_bytes());
    hasher.update(HNS_SHAKEDEX_ROLE_CODE.to_be_bytes());
    hasher.update(allocation.reference.account.to_be_bytes());
    hasher.update(allocation.reference.change.to_be_bytes());
    hasher.update(allocation.reference.index.to_be_bytes());
    hasher.update(allocation.compressed_public_key);
    hasher.update(allocation.lock_script_hash);
    hasher.update(allocation.recovery_seed_commitment);
    hasher.update(allocation.allocated_at_unix.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn namespace_anchor_record_id(context: AllocationContext) -> Vec<u8> {
    account_namespace_record_id(NAMESPACE_ANCHOR_ID_DOMAIN, context)
}

fn high_water_record_id(context: AllocationContext) -> Vec<u8> {
    account_namespace_record_id(HIGH_WATER_ID_DOMAIN, context)
}

fn account_namespace_record_id(domain: &[u8], context: AllocationContext) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(ALLOCATION_STORAGE_VERSION.to_be_bytes());
    hasher.update(context.wallet_id.as_bytes());
    hasher.update(context.account_derivation_index.to_be_bytes());
    hasher.finalize().to_vec()
}

fn binding_record_id(wallet_id: WalletId, workflow_id: WorkflowId) -> Vec<u8> {
    workflow_record_id(BINDING_ID_DOMAIN, wallet_id, workflow_id)
}

fn binding_claim_record_id(wallet_id: WalletId, workflow_id: WorkflowId) -> Vec<u8> {
    workflow_record_id(BINDING_CLAIM_ID_DOMAIN, wallet_id, workflow_id)
}

fn workflow_record_id(domain: &[u8], wallet_id: WalletId, workflow_id: WorkflowId) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(ALLOCATION_STORAGE_VERSION.to_be_bytes());
    hasher.update(wallet_id.as_bytes());
    hasher.update(workflow_id.as_bytes());
    hasher.finalize().to_vec()
}

const fn network_code(network: HnsNetwork) -> u32 {
    match network {
        HnsNetwork::Mainnet => 0,
        HnsNetwork::Testnet => 1,
        HnsNetwork::Regtest => 2,
        HnsNetwork::Simnet => 3,
    }
}

/// Opaque, non-cloneable and non-serializable seller authority.
///
/// The handle deliberately offers no scalar accessor and no arbitrary digest
/// signing. Each method validates an exact typed Shakedex object against the
/// authenticated allocation before constructing its protocol-fixed signature.
pub struct HnsShakedexSigner {
    workflow_id: WorkflowId,
    reference: DerivationReference,
    network: NetworkBinding,
    name: Vec<u8>,
    name_hash: [u8; 32],
    terms_commitment: ObjectHash,
    compressed_public_key: [u8; 33],
    secret: Zeroizing<[u8; 32]>,
}

impl HnsShakedexSigner {
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub const fn reference(&self) -> DerivationReference {
        self.reference
    }

    pub const fn terms_commitment(&self) -> ObjectHash {
        self.terms_commitment
    }

    pub const fn compressed_public_key(&self) -> &[u8; 33] {
        &self.compressed_public_key
    }

    pub fn lock_script_hash(&self) -> [u8; 32] {
        lock_script_hash(&self.compressed_public_key)
    }

    /// Sign one exact HIP-0001 seller presign after binding its network, name,
    /// seller key, locking outpoint, and canonical FINALIZE coin.
    pub fn sign_swap_proof(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        proof: &mut SwapProof,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        self.validate_proof_context(proof)?;
        self.validate_current_lock(current_lock)?;
        if proof.locking_outpoint != current_lock.locking_coin().outpoint {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        let signing = self.signing_key()?;
        proof.sign(current_lock.locking_coin(), &signing)?;
        proof.verify_for_network(self.network, current_lock.locking_coin())?;
        Ok(())
    }

    /// Sign one exact fixed-price publication envelope whose embedded presign
    /// has already been authenticated against the current locking coin.
    pub fn sign_fixed_price_listing(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        listing: &mut FixedPriceListing,
        now_unix: u64,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        if now_unix == 0 {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        self.validate_proof_context(&listing.proof)?;
        self.validate_current_lock(current_lock)?;
        listing
            .proof
            .verify_for_network(self.network, current_lock.locking_coin())?;
        let signing = self.signing_key()?;
        listing.sign(&signing)?;
        listing.verify_for_network(self.network, now_unix, current_lock.locking_coin())?;
        Ok(())
    }

    /// Sign a cancellation for the exact supplied listing. The listing must
    /// remain bound to this allocation and its exact canonical locking coin.
    pub fn sign_listing_cancellation(
        &self,
        cancellation: &mut ListingCancellation,
        listing: &FixedPriceListing,
        locking_coin: &Coin,
        now_unix: u64,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        if now_unix == 0 {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        self.validate_proof_context(&listing.proof)?;
        listing.verify_for_network(self.network, listing.created_at, locking_coin)?;
        if cancellation.network != self.network
            || cancellation.seller_public_key != self.compressed_public_key
            || cancellation.listing_hash != listing.listing_hash()?
        {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        let signing = self.signing_key()?;
        cancellation.sign(&signing)?;
        cancellation.verify_for_listing(listing, self.network, now_unix)?;
        Ok(())
    }

    /// Sign and install the fixed-hash-type witness for one exact,
    /// listing-independent Shakedex recovery TRANSFER.
    pub fn sign_current_recovery_transaction(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        transaction: &mut Transaction,
        recovery_recipient: &Address,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        self.validate_current_lock(current_lock)?;
        let descriptor = current_lock.descriptor();
        let locking_coin = current_lock.locking_coin();
        let digest =
            descriptor.recovery_signature_hash(transaction, locking_coin, recovery_recipient)?;
        let signature: Signature = self
            .signing_key()?
            .sign_prehash(&digest)
            .map_err(|_| HnsShakedexKeyAllocationError::SigningFailure)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = SHAKEDEX_RECOVERY_SIGHASH as u8;
        let witness = descriptor.recovery_witness(&encoded)?;
        transaction
            .inputs
            .first_mut()
            .ok_or(HnsShakedexKeyAllocationError::SigningContextMismatch)?
            .witness = witness;
        descriptor.verify_recovery(transaction, locking_coin, recovery_recipient)?;
        Ok(())
    }

    fn validate_current_lock(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        self.validate_lock_descriptor(current_lock.descriptor())?;
        current_lock
            .descriptor()
            .verify_for_network(self.network, current_lock.locking_coin())?;
        Ok(())
    }

    fn signing_key(&self) -> Result<SigningKey, HnsShakedexKeyAllocationError> {
        let signing = SigningKey::from_slice(self.secret.as_slice())
            .map_err(|_| HnsShakedexKeyAllocationError::CorruptAllocation)?;
        if signing.verifying_key().to_encoded_point(true).as_bytes() != self.compressed_public_key {
            return Err(HnsShakedexKeyAllocationError::CorruptAllocation);
        }
        Ok(signing)
    }

    fn validate_proof_context(
        &self,
        proof: &SwapProof,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        proof.validate()?;
        let proof_terms_commitment = HnsShakedexSellerTerms::from_proof(proof).commitment()?;
        if proof.network != self.network
            || proof.name != self.name
            || hash_name(&proof.name)
                .map(|name_hash| name_hash.as_bytes() != &self.name_hash)
                .unwrap_or(true)
            || proof.seller_public_key != self.compressed_public_key
            || proof_terms_commitment != self.terms_commitment
        {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        Ok(())
    }

    fn validate_lock_descriptor(
        &self,
        descriptor: &ShakedexLockDescriptor,
    ) -> Result<(), HnsShakedexKeyAllocationError> {
        descriptor.validate()?;
        if descriptor.network != self.network
            || descriptor.name != self.name
            || hash_name(&descriptor.name)
                .map(|name_hash| name_hash.as_bytes() != &self.name_hash)
                .unwrap_or(true)
            || descriptor.seller_public_key != self.compressed_public_key
        {
            return Err(HnsShakedexKeyAllocationError::SigningContextMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for HnsShakedexSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsShakedexSigner")
            .field("workflow_id", &self.workflow_id)
            .field("reference", &self.reference)
            .field("network", &self.network)
            .field("name_hash", &hex::encode(self.name_hash))
            .field("terms_commitment", &self.terms_commitment)
            .field(
                "compressed_public_key",
                &hex::encode(self.compressed_public_key),
            )
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use hns_wallet_types::BaseUnits;

    use super::*;

    const PASSPHRASE: &str = "targeted HNS Shakedex key allocation test";
    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "hns-wallet-hns-shakedex-key-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create private test directory");
            fs::set_permissions(&path, Permissions::from_mode(0o700))
                .expect("private test directory permissions");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn config() -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: WalletId::new([1; 16]),
            account_id: AccountId::new([2; 16]),
            account_derivation_index: 7,
            network: HnsNetwork::Regtest,
            birthday_height: 0,
            restore_lookahead: 10,
            minimum_confirmations: 1,
            dust_threshold: BaseUnits::new(546),
            value_operations_enabled: false,
            settlement_enabled: false,
        }
    }

    fn account() -> HnsAccountRecord {
        HnsAccountRecord {
            config: config(),
            next_receive_index: 0,
            next_change_index: 0,
            next_name_index: 0,
            next_shakedex_index: 0,
            external_scan_end: 9,
            internal_scan_end: 9,
            name_scan_end: 9,
            shakedex_scan_end: 9,
            shakedex_scan_complete: true,
            shakedex_scan_in_progress: false,
            last_used_external: None,
            last_used_internal: None,
            last_used_name: None,
            last_used_shakedex: None,
        }
    }

    fn request(
        workflow_byte: u8,
        name: &[u8],
        commitment_byte: u8,
    ) -> HnsShakedexKeyAllocationRequest {
        HnsShakedexKeyAllocationRequest {
            workflow_id: WorkflowId::new([workflow_byte; 16]),
            name: name.to_vec(),
            seller_terms: HnsShakedexSellerTerms {
                payment_address: Address::new(0, vec![commitment_byte; 20])
                    .expect("payment address"),
                price: Dollarydoos::new(10_000 + u64::from(commitment_byte)),
                lock_time_seconds: 1_800_000_000,
                fee_address: None,
                fee: Dollarydoos::new(0),
            },
        }
    }

    fn seed_store(store: &mut WalletStore, account: &HnsAccountRecord) {
        store
            .put_secret(
                account.config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[9; 64],
                1,
            )
            .expect("store exact recovery seed");
        store
            .save_wallet_account(
                &super::super::account_entity_id(&account.config),
                0,
                account,
                1,
            )
            .expect("store allocation-ready account");
    }

    #[test]
    fn hns_shakedex_key_allocation_is_monotonic_immutable_recoverable_and_redacted() {
        let directory = TestDirectory::new();
        let database_path = directory.path().join("wallet.sqlite3");
        let account = account();
        let config = account.config.clone();
        let first_request = request(3, b"alpha", 4);
        let second_request = request(5, b"beta", 6);

        let first = {
            let mut store = WalletStore::create(&database_path, PASSPHRASE).expect("create store");
            seed_store(&mut store, &account);
            let stored_account = store
                .wallet_account::<HnsAccountRecord>(&super::super::account_entity_id(&config))
                .expect("load initial account")
                .expect("initial account present");
            let mut required_account = stored_account.value;
            required_account.shakedex_scan_complete = false;
            let required_revision = store
                .save_wallet_account(
                    &super::super::account_entity_id(&config),
                    stored_account.revision,
                    &required_account,
                    2,
                )
                .expect("persist scan-required gate");
            assert!(matches!(
                allocate_hns_shakedex_key(&mut store, &config, &first_request, 3),
                Err(HnsShakedexKeyAllocationError::RestorationRequired)
            ));
            required_account.shakedex_scan_in_progress = true;
            let scanning_revision = store
                .save_wallet_account(
                    &super::super::account_entity_id(&config),
                    required_revision,
                    &required_account,
                    3,
                )
                .expect("persist scanning gate");
            assert!(matches!(
                allocate_hns_shakedex_key(&mut store, &config, &first_request, 4),
                Err(HnsShakedexKeyAllocationError::RestorationInProgress)
            ));
            required_account.shakedex_scan_complete = true;
            required_account.shakedex_scan_in_progress = false;
            store
                .save_wallet_account(
                    &super::super::account_entity_id(&config),
                    scanning_revision,
                    &required_account,
                    4,
                )
                .expect("persist scan-ready gate");
            let first = allocate_hns_shakedex_key(&mut store, &config, &first_request, 10)
                .expect("first allocation")
                .allocation;
            let retry = allocate_hns_shakedex_key(&mut store, &config, &first_request, 11)
                .expect("exact retry")
                .allocation;
            assert_eq!(retry, first);
            assert_eq!(first.reference().index, 0);
            assert_eq!(
                allocation_next_index(&store, &config).expect("high water"),
                1
            );
            assert_eq!(
                store
                    .wallet_account::<HnsAccountRecord>(&super::super::account_entity_id(&config),)
                    .expect("load advanced account")
                    .expect("advanced account present")
                    .value
                    .next_shakedex_index,
                1,
            );
            assert!(matches!(
                store.delete_entity(
                    EntityKind::HnsShakedexKeyAllocation,
                    &binding_record_id(config.wallet_id, first_request.workflow_id),
                    1,
                ),
                Err(StoreError::ProtectedEntity)
            ));

            let second = allocate_hns_shakedex_key(&mut store, &config, &second_request, 12)
                .expect("second allocation")
                .allocation;
            assert_eq!(second.reference().index, 1);
            assert_ne!(
                second.compressed_public_key(),
                first.compressed_public_key()
            );
            assert_eq!(
                allocation_next_index(&store, &config).expect("high water"),
                2
            );

            let rebound = HnsShakedexKeyAllocationRequest {
                seller_terms: HnsShakedexSellerTerms {
                    price: Dollarydoos::new(first_request.seller_terms.price.get() + 1),
                    ..first_request.seller_terms.clone()
                },
                ..first_request.clone()
            };
            assert!(matches!(
                allocate_hns_shakedex_key(&mut store, &config, &rebound, 13),
                Err(HnsShakedexKeyAllocationError::BindingConflict)
            ));
            let stored_account = store
                .wallet_account::<HnsAccountRecord>(&super::super::account_entity_id(&config))
                .expect("load account")
                .expect("account present");
            let mut restored_account = stored_account.value;
            restored_account.next_shakedex_index = 7;
            restored_account.shakedex_scan_end = 16;
            store
                .save_wallet_account(
                    &super::super::account_entity_id(&config),
                    stored_account.revision,
                    &restored_account,
                    13,
                )
                .expect("persist restored high water");
            let restored =
                allocate_hns_shakedex_key(&mut store, &config, &request(7, b"gamma", 8), 14)
                    .expect("allocation advances beyond restored on-chain use")
                    .allocation;
            assert_eq!(restored.reference().index, 7);
            assert_eq!(
                allocation_next_index(&store, &config).expect("high water"),
                8
            );
            first
        };

        let mut reopened = WalletStore::open(&database_path).expect("reopen store");
        reopened.unlock(PASSPHRASE).expect("unlock reopened store");
        let loaded = load_hns_shakedex_key_allocation(
            &reopened,
            config.wallet_id,
            first_request.workflow_id,
        )
        .expect("load allocation")
        .expect("allocation present");
        assert_eq!(loaded, first);
        let signer =
            load_hns_shakedex_signer(&reopened, &config, &first_request).expect("rederive signer");
        assert_eq!(
            signer.compressed_public_key(),
            first.compressed_public_key()
        );
        let debug = format!("{signer:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&hex::encode(signer.secret.as_slice())));
        assert_eq!(
            allocation_next_index(&reopened, &config).expect("high water"),
            8
        );

        let mut proof = SwapProof {
            network: signer.network,
            locking_outpoint: hns_transaction::Outpoint {
                transaction_hash: hns_primitives::TransactionHash::new([11; 32]),
                index: 0,
            },
            name: first_request.name.clone(),
            seller_public_key: *signer.compressed_public_key(),
            payment_address: first_request.seller_terms.payment_address.clone(),
            price: first_request.seller_terms.price,
            lock_time_seconds: first_request.seller_terms.lock_time_seconds,
            signature: None,
            fee_address: first_request.seller_terms.fee_address.clone(),
            fee: first_request.seller_terms.fee,
        };
        signer
            .validate_proof_context(&proof)
            .expect("exact frozen terms");
        proof.price = Dollarydoos::new(proof.price.get() + 1);
        assert!(matches!(
            signer.validate_proof_context(&proof),
            Err(HnsShakedexKeyAllocationError::SigningContextMismatch)
        ));
        proof.price = first_request.seller_terms.price;
        proof.lock_time_seconds += 512;
        assert!(matches!(
            signer.validate_proof_context(&proof),
            Err(HnsShakedexKeyAllocationError::SigningContextMismatch)
        ));
        proof.lock_time_seconds = first_request.seller_terms.lock_time_seconds;
        proof.payment_address = Address::new(0, vec![99; 20]).expect("different payment address");
        assert!(matches!(
            signer.validate_proof_context(&proof),
            Err(HnsShakedexKeyAllocationError::SigningContextMismatch)
        ));
    }

    #[test]
    fn persisted_recovery_high_water_read_is_non_mutating_and_requires_exact_pair() {
        let directory = TestDirectory::new();
        let config = config();
        let account = account();
        let context = AllocationContext::from_config(&config).expect("ordinary context");
        let mut store = WalletStore::create(directory.path().join("source.sqlite3"), PASSPHRASE)
            .expect("create allocation source store");
        seed_store(&mut store, &account);
        allocate_hns_shakedex_key(&mut store, &config, &request(3, b"alpha", 4), 10)
            .expect("create real protected high water");

        let anchor_id = namespace_anchor_record_id(context);
        let high_water_id = high_water_record_id(context);
        let anchor_before = store
            .load_entity::<HnsShakedexKeyAllocationRecord>(
                EntityKind::HnsShakedexKeyAllocation,
                &anchor_id,
            )
            .expect("load namespace anchor")
            .expect("namespace anchor present");
        let high_water_before = store
            .load_entity::<HnsShakedexKeyAllocationRecord>(
                EntityKind::HnsShakedexKeyAllocation,
                &high_water_id,
            )
            .expect("load protected high water")
            .expect("protected high water present");
        let anchor_bytes = serde_json::to_vec(&anchor_before.value).expect("encode anchor");
        let high_water_bytes =
            serde_json::to_vec(&high_water_before.value).expect("encode high water");

        let mut flagged = config.clone();
        flagged.value_operations_enabled = true;
        assert!(matches!(
            allocation_next_index(&store, &flagged),
            Err(HnsShakedexKeyAllocationError::Wallet(
                HnsWalletError::RuntimeIntegrationUnavailable
            ))
        ));
        assert_eq!(
            allocation_next_index_for_persisted_recovery_read(&store, &flagged)
                .expect("authenticate existing high water for recovery scan"),
            1
        );

        let anchor_after = store
            .load_entity::<HnsShakedexKeyAllocationRecord>(
                EntityKind::HnsShakedexKeyAllocation,
                &anchor_id,
            )
            .expect("reload namespace anchor")
            .expect("namespace anchor remains");
        let high_water_after = store
            .load_entity::<HnsShakedexKeyAllocationRecord>(
                EntityKind::HnsShakedexKeyAllocation,
                &high_water_id,
            )
            .expect("reload protected high water")
            .expect("protected high water remains");
        assert_eq!(anchor_after, anchor_before);
        assert_eq!(high_water_after, high_water_before);
        assert_eq!(
            serde_json::to_vec(&anchor_after.value).expect("re-encode anchor"),
            anchor_bytes
        );
        assert_eq!(
            serde_json::to_vec(&high_water_after.value).expect("re-encode high water"),
            high_water_bytes
        );

        let mut missing =
            WalletStore::create(directory.path().join("missing-anchor.sqlite3"), PASSPHRASE)
                .expect("create missing-pair store");
        seed_store(&mut missing, &account);
        missing
            .save_entity(
                EntityKind::HnsShakedexKeyAllocation,
                &high_water_id,
                0,
                &high_water_before.value,
                high_water_before.updated_at_unix,
            )
            .expect("persist high water without anchor");
        assert!(matches!(
            allocation_next_index_for_persisted_recovery_read(&missing, &flagged),
            Err(HnsShakedexKeyAllocationError::CorruptAllocation)
        ));
        assert_eq!(
            missing
                .load_entity::<HnsShakedexKeyAllocationRecord>(
                    EntityKind::HnsShakedexKeyAllocation,
                    &high_water_id,
                )
                .expect("reload missing-pair high water")
                .expect("missing-pair high water remains")
                .value,
            high_water_before.value
        );

        let mut corrupt =
            WalletStore::create(directory.path().join("corrupt-pair.sqlite3"), PASSPHRASE)
                .expect("create corrupt-pair store");
        seed_store(&mut corrupt, &account);
        let corrupt_anchor = match anchor_before.value.clone() {
            HnsShakedexKeyAllocationRecord::NamespaceAnchor(mut anchor) => {
                anchor.recovery_seed_commitment = [0x55; 32];
                HnsShakedexKeyAllocationRecord::NamespaceAnchor(anchor)
            }
            _ => panic!("expected namespace anchor record"),
        };
        corrupt
            .save_entity(
                EntityKind::HnsShakedexKeyAllocation,
                &anchor_id,
                0,
                &corrupt_anchor,
                anchor_before.updated_at_unix,
            )
            .expect("persist corrupt anchor");
        corrupt
            .save_entity(
                EntityKind::HnsShakedexKeyAllocation,
                &high_water_id,
                0,
                &high_water_before.value,
                high_water_before.updated_at_unix,
            )
            .expect("persist paired high water");
        assert!(matches!(
            allocation_next_index_for_persisted_recovery_read(&corrupt, &flagged),
            Err(HnsShakedexKeyAllocationError::CorruptAllocation)
        ));
    }
}
