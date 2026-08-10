//! Encrypted, monotonic allocation of Bitcoin atomic-swap keys.
//!
//! The public allocation, binding claim, namespace anchor, and high-water
//! counter share one encrypted entity namespace and commit in one compare-and-
//! swap batch. Secret key bytes remain derivable only from the wallet recovery
//! seed and never enter an allocation record.

use bdk_wallet::bitcoin::Network;
use hns_wallet_store::{
    EntityBatchSave, EntityKind, SecretKind, StoreError, StoredEntity, WalletStore,
};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    BITCOIN_SWAP_KEY_SCHEME_VERSION, BitcoinSwapKeyReference, BitcoinSwapKeyRole,
    BitcoinSwapPublicKey, BitcoinWalletError, DerivedBitcoinSwapKey,
    MAX_BITCOIN_SWAP_ACCOUNT_INDEX, MAX_BITCOIN_SWAP_KEY_INDEX,
    derive_bitcoin_swap_key_from_seed_for_allocation,
};

const ALLOCATION_STORAGE_VERSION: u16 = 1;
const HIGH_WATER_ID_DOMAIN: &[u8] = b"hns-wallet/bitcoin-swap-key/high-water/v1";
const NAMESPACE_ANCHOR_ID_DOMAIN: &[u8] = b"hns-wallet/bitcoin-swap-key/namespace-anchor/v1";
const BINDING_ID_DOMAIN: &[u8] = b"hns-wallet/bitcoin-swap-key/binding/v1";
const BINDING_CLAIM_ID_DOMAIN: &[u8] = b"hns-wallet/bitcoin-swap-key/binding-claim/v1";
const BINDING_COMMITMENT_DOMAIN: &[u8] = b"hns-wallet/bitcoin-swap-key/binding-commitment/v1";
const RECOVERY_SEED_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet/bitcoin-swap-key/recovery-seed-commitment/v1";
const MAX_ALLOCATION_ATTEMPTS: usize = 2;

/// Binding request for one role-specific Bitcoin swap key.
///
/// `terms_commitment` is an opaque commitment supplied by the settlement
/// layer. That layer remains responsible for constructing it from its complete
/// canonical frozen terms before funding or signing. The allocation ID is
/// scoped by wallet, session, and role, so the same session cannot silently
/// rebind a role to another network, account, or terms commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinSwapKeyAllocationRequest {
    pub wallet_id: WalletId,
    pub session_id: SessionId,
    pub network: Network,
    pub account_index: u32,
    pub role: BitcoinSwapKeyRole,
    pub terms_commitment: ObjectHash,
}

impl BitcoinSwapKeyAllocationRequest {
    fn validate(self) -> Result<(), BitcoinSwapKeyAllocationError> {
        if self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.session_id.as_bytes().iter().all(|byte| *byte == 0)
            || self
                .terms_commitment
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.account_index > MAX_BITCOIN_SWAP_ACCOUNT_INDEX
        {
            return Err(BitcoinSwapKeyAllocationError::InvalidRequest);
        }
        Ok(())
    }
}

/// Immutable public recovery binding for one session/role allocation.
///
/// No seed or secret scalar is stored here. Recovery re-derives the key from
/// the complete wallet/session/terms/reference context and refuses to expose
/// the in-memory secret handle unless the resulting compressed public key
/// exactly matches this encrypted record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinSwapKeyAllocation {
    storage_version: u16,
    wallet_id: WalletId,
    session_id: SessionId,
    reference: BitcoinSwapKeyReference,
    public_key: BitcoinSwapPublicKey,
    recovery_seed_commitment: [u8; 32],
    terms_commitment: ObjectHash,
    allocated_at_unix: u64,
}

impl BitcoinSwapKeyAllocation {
    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn reference(&self) -> BitcoinSwapKeyReference {
        self.reference
    }

    pub const fn public_key(&self) -> &BitcoinSwapPublicKey {
        &self.public_key
    }

    pub const fn terms_commitment(&self) -> ObjectHash {
        self.terms_commitment
    }

    pub const fn allocated_at_unix(&self) -> u64 {
        self.allocated_at_unix
    }

    fn validate(&self) -> Result<(), BitcoinSwapKeyAllocationError> {
        if self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.allocated_at_unix == 0
            || self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.session_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
            || self
                .terms_commitment
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.public_key.reference() != self.reference
        {
            return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
        }
        self.reference
            .validate()
            .map_err(|_| BitcoinSwapKeyAllocationError::CorruptAllocation)?;
        self.public_key
            .bitcoin_public_key()
            .map_err(|_| BitcoinSwapKeyAllocationError::CorruptAllocation)?;
        Ok(())
    }

    fn matches_request(&self, request: BitcoinSwapKeyAllocationRequest) -> bool {
        self.wallet_id == request.wallet_id
            && self.session_id == request.session_id
            && self.reference.network() == request.network
            && self.reference.account_index() == request.account_index
            && self.reference.role() == request.role
            && self.terms_commitment == request.terms_commitment
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinSwapKeyHighWater {
    storage_version: u16,
    wallet_id: WalletId,
    network: Network,
    account_index: u32,
    role: BitcoinSwapKeyRole,
    recovery_seed_commitment: [u8; 32],
    next_key_index: u32,
    last_allocated_at_unix: u64,
}

impl BitcoinSwapKeyHighWater {
    fn validate(
        &self,
        request: BitcoinSwapKeyAllocationRequest,
        revision: u64,
    ) -> Result<(), BitcoinSwapKeyAllocationError> {
        let maximum_next = MAX_BITCOIN_SWAP_KEY_INDEX
            .checked_add(1)
            .ok_or(BitcoinSwapKeyAllocationError::CorruptAllocation)?;
        if self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.wallet_id != request.wallet_id
            || self.network != request.network
            || self.account_index != request.account_index
            || self.role != request.role
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
            || self.next_key_index == 0
            || self.next_key_index > maximum_next
            || revision != u64::from(self.next_key_index)
            || self.last_allocated_at_unix == 0
        {
            return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinSwapKeyNamespaceAnchor {
    storage_version: u16,
    wallet_id: WalletId,
    network: Network,
    account_index: u32,
    role: BitcoinSwapKeyRole,
    recovery_seed_commitment: [u8; 32],
}

impl BitcoinSwapKeyNamespaceAnchor {
    fn validate(
        &self,
        request: BitcoinSwapKeyAllocationRequest,
        revision: u64,
    ) -> Result<(), BitcoinSwapKeyAllocationError> {
        if revision != 1
            || self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.wallet_id != request.wallet_id
            || self.network != request.network
            || self.account_index != request.account_index
            || self.role != request.role
            || self.recovery_seed_commitment.iter().all(|byte| *byte == 0)
        {
            return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinSwapKeyBindingClaim {
    storage_version: u16,
    wallet_id: WalletId,
    session_id: SessionId,
    role: BitcoinSwapKeyRole,
    binding_commitment: [u8; 32],
}

impl BitcoinSwapKeyBindingClaim {
    fn validate(
        &self,
        allocation: &BitcoinSwapKeyAllocation,
        revision: u64,
    ) -> Result<(), BitcoinSwapKeyAllocationError> {
        if revision != 1
            || self.storage_version != ALLOCATION_STORAGE_VERSION
            || self.wallet_id != allocation.wallet_id
            || self.session_id != allocation.session_id
            || self.role != allocation.reference.role()
            || self.binding_commitment != binding_commitment(allocation)?
        {
            return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum BitcoinSwapKeyAllocationRecord {
    NamespaceAnchor(BitcoinSwapKeyNamespaceAnchor),
    HighWater(BitcoinSwapKeyHighWater),
    Binding(BitcoinSwapKeyAllocation),
    BindingClaim(BitcoinSwapKeyBindingClaim),
}

/// Allocation/recovery failures remain distinct from the general Bitcoin
/// runtime gate. None of these errors authorizes value movement.
#[derive(Debug, Error)]
pub enum BitcoinSwapKeyAllocationError {
    #[error("Bitcoin swap-key allocation request is invalid")]
    InvalidRequest,
    #[error("Bitcoin swap-key role is already bound to different session terms")]
    BindingConflict,
    #[error("Bitcoin swap-key allocation was not found")]
    AllocationNotFound,
    #[error("Bitcoin swap-key allocation state is corrupt or inconsistent")]
    CorruptAllocation,
    #[error("Bitcoin swap-key allocation index is exhausted")]
    AllocationExhausted,
    #[error("Bitcoin swap-key allocation clock moved behind durable state")]
    ClockRollback,
    #[error("Bitcoin swap-key allocation changed concurrently")]
    ConcurrentModification,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Bitcoin(#[from] BitcoinWalletError),
}

/// Allocate or recover one immutable role binding.
///
/// A new binding and the monotonic role high-water record commit atomically.
/// Exact retries are idempotent. A single CAS conflict is reloaded once so a
/// competing session can advance the counter without permitting an unbounded
/// retry loop.
pub fn allocate_bitcoin_swap_key(
    store: &mut WalletStore,
    request: BitcoinSwapKeyAllocationRequest,
    now_unix: u64,
) -> Result<BitcoinSwapKeyAllocation, BitcoinSwapKeyAllocationError> {
    request.validate()?;
    if now_unix == 0 {
        return Err(BitcoinSwapKeyAllocationError::InvalidRequest);
    }
    if let Some(existing) = load_bitcoin_swap_key_allocation(
        store,
        request.wallet_id,
        request.session_id,
        request.role,
    )? {
        return accept_existing(store, existing, request, now_unix);
    }

    for attempt in 0..MAX_ALLOCATION_ATTEMPTS {
        let high_water = load_high_water(store, request)?;
        let (saves, allocation) = prepare_allocation_saves(store, request, now_unix, high_water)?;
        match store.apply_entity_batch(EntityKind::BitcoinSwapKeyAllocation, &saves, &[]) {
            Ok(()) => {
                let verified = derive_allocated_bitcoin_swap_key_from_store(store, request)?;
                if verified.public_key() != allocation.public_key() {
                    return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
                }
                return Ok(allocation);
            }
            Err(StoreError::StaleRevision { .. }) if attempt == 0 => {
                if let Some(existing) = load_bitcoin_swap_key_allocation(
                    store,
                    request.wallet_id,
                    request.session_id,
                    request.role,
                )? {
                    return accept_existing(store, existing, request, now_unix);
                }
            }
            Err(StoreError::StaleRevision { .. }) => {
                return Err(BitcoinSwapKeyAllocationError::ConcurrentModification);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(BitcoinSwapKeyAllocationError::ConcurrentModification)
}

/// Load one encrypted public allocation binding by its immutable identity.
pub fn load_bitcoin_swap_key_allocation(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    role: BitcoinSwapKeyRole,
) -> Result<Option<BitcoinSwapKeyAllocation>, BitcoinSwapKeyAllocationError> {
    let binding_id = binding_record_id(wallet_id, session_id, role);
    let claim_id = binding_claim_record_id(wallet_id, session_id, role);
    let binding = store.load_entity::<BitcoinSwapKeyAllocationRecord>(
        EntityKind::BitcoinSwapKeyAllocation,
        &binding_id,
    )?;
    let claim = store.load_entity::<BitcoinSwapKeyAllocationRecord>(
        EntityKind::BitcoinSwapKeyAllocation,
        &claim_id,
    )?;
    let (stored, stored_claim) = match (binding, claim) {
        (None, None) => return Ok(None),
        (Some(binding), Some(claim)) => (binding, claim),
        _ => return Err(BitcoinSwapKeyAllocationError::CorruptAllocation),
    };
    if stored.revision != 1 {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    let BitcoinSwapKeyAllocationRecord::Binding(allocation) = stored.value else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    allocation.validate()?;
    if allocation.wallet_id != wallet_id
        || allocation.session_id != session_id
        || allocation.reference.role() != role
    {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    let BitcoinSwapKeyAllocationRecord::BindingClaim(claim) = stored_claim.value else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    claim.validate(&allocation, stored_claim.revision)?;
    validate_allocation_topology(store, &allocation)?;
    Ok(Some(allocation))
}

/// Re-derive the secret handle only after authenticating the exact durable
/// binding and recomputing its public key.
pub fn derive_allocated_bitcoin_swap_key_from_store(
    store: &WalletStore,
    request: BitcoinSwapKeyAllocationRequest,
) -> Result<DerivedBitcoinSwapKey, BitcoinSwapKeyAllocationError> {
    request.validate()?;
    let allocation = load_bitcoin_swap_key_allocation(
        store,
        request.wallet_id,
        request.session_id,
        request.role,
    )?
    .ok_or(BitcoinSwapKeyAllocationError::AllocationNotFound)?;
    if !allocation.matches_request(request) {
        return Err(BitcoinSwapKeyAllocationError::BindingConflict);
    }
    let (derived, seed_commitment) = derive_swap_key_and_seed_commitment(
        store,
        request.wallet_id,
        request.session_id,
        request.terms_commitment,
        allocation.reference,
    )?;
    if seed_commitment != allocation.recovery_seed_commitment
        || derived.public_key() != allocation.public_key()
    {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    Ok(derived)
}

fn accept_existing(
    store: &WalletStore,
    allocation: BitcoinSwapKeyAllocation,
    request: BitcoinSwapKeyAllocationRequest,
    now_unix: u64,
) -> Result<BitcoinSwapKeyAllocation, BitcoinSwapKeyAllocationError> {
    if !allocation.matches_request(request) {
        return Err(BitcoinSwapKeyAllocationError::BindingConflict);
    }
    let last_allocated_at_unix = validate_allocation_topology(store, &allocation)?;
    if now_unix < last_allocated_at_unix {
        return Err(BitcoinSwapKeyAllocationError::ClockRollback);
    }
    let (derived, seed_commitment) = derive_swap_key_and_seed_commitment(
        store,
        request.wallet_id,
        request.session_id,
        request.terms_commitment,
        allocation.reference,
    )?;
    if seed_commitment != allocation.recovery_seed_commitment
        || derived.public_key() != allocation.public_key()
    {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    Ok(allocation)
}

fn validate_allocation_topology(
    store: &WalletStore,
    allocation: &BitcoinSwapKeyAllocation,
) -> Result<u64, BitcoinSwapKeyAllocationError> {
    let request = BitcoinSwapKeyAllocationRequest {
        wallet_id: allocation.wallet_id,
        session_id: allocation.session_id,
        network: allocation.reference.network(),
        account_index: allocation.reference.account_index(),
        role: allocation.reference.role(),
        terms_commitment: allocation.terms_commitment,
    };
    let Some(stored) = load_high_water(store, request)? else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    let BitcoinSwapKeyAllocationRecord::HighWater(high_water) = stored.value else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    let current_seed_commitment = recovery_seed_commitment(store, allocation.wallet_id)?;
    if allocation.reference.key_index() >= high_water.next_key_index
        || allocation.allocated_at_unix > high_water.last_allocated_at_unix
        || allocation.recovery_seed_commitment != high_water.recovery_seed_commitment
        || allocation.recovery_seed_commitment != current_seed_commitment
    {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    Ok(high_water.last_allocated_at_unix)
}

fn load_high_water(
    store: &WalletStore,
    request: BitcoinSwapKeyAllocationRequest,
) -> Result<Option<StoredEntity<BitcoinSwapKeyAllocationRecord>>, BitcoinSwapKeyAllocationError> {
    let high_water = store.load_entity::<BitcoinSwapKeyAllocationRecord>(
        EntityKind::BitcoinSwapKeyAllocation,
        &high_water_record_id(request),
    )?;
    let anchor = store.load_entity::<BitcoinSwapKeyAllocationRecord>(
        EntityKind::BitcoinSwapKeyAllocation,
        &namespace_anchor_record_id(request),
    )?;
    let (stored, stored_anchor) = match (high_water, anchor) {
        (None, None) => return Ok(None),
        (Some(high_water), Some(anchor)) => (high_water, anchor),
        _ => return Err(BitcoinSwapKeyAllocationError::CorruptAllocation),
    };
    let BitcoinSwapKeyAllocationRecord::HighWater(high_water) = &stored.value else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    high_water.validate(request, stored.revision)?;
    let BitcoinSwapKeyAllocationRecord::NamespaceAnchor(anchor) = &stored_anchor.value else {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    };
    anchor.validate(request, stored_anchor.revision)?;
    if anchor.recovery_seed_commitment != high_water.recovery_seed_commitment {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    Ok(Some(stored))
}

fn derive_swap_key_and_seed_commitment(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    terms_commitment: ObjectHash,
    reference: BitcoinSwapKeyReference,
) -> Result<(DerivedBitcoinSwapKey, [u8; 32]), BitcoinSwapKeyAllocationError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(BitcoinWalletError::MissingRecoverySeed)?;
    if seed.len() != 64 {
        return Err(BitcoinWalletError::InvalidRecoverySeed.into());
    }
    let seed_commitment = recovery_seed_commitment_from_cleartext(wallet_id, seed.as_slice());
    let derived = derive_bitcoin_swap_key_from_seed_for_allocation(
        seed.as_slice(),
        wallet_id,
        session_id,
        terms_commitment,
        reference,
    )?;
    Ok((derived, seed_commitment))
}

fn recovery_seed_commitment(
    store: &WalletStore,
    wallet_id: WalletId,
) -> Result<[u8; 32], BitcoinSwapKeyAllocationError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(BitcoinWalletError::MissingRecoverySeed)?;
    if seed.len() != 64 {
        return Err(BitcoinWalletError::InvalidRecoverySeed.into());
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
    allocation: &BitcoinSwapKeyAllocation,
) -> Result<[u8; 32], BitcoinSwapKeyAllocationError> {
    allocation.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_COMMITMENT_DOMAIN);
    hasher.update(allocation.storage_version.to_be_bytes());
    hasher.update(allocation.wallet_id.as_bytes());
    hasher.update(allocation.session_id.as_bytes());
    hasher.update(allocation.reference.scheme_version().to_be_bytes());
    hasher.update(allocation.reference.network_code().to_be_bytes());
    hasher.update(allocation.reference.account_index().to_be_bytes());
    hasher.update(allocation.reference.role().code().to_be_bytes());
    hasher.update(allocation.reference.key_index().to_be_bytes());
    hasher.update(
        allocation
            .public_key
            .bitcoin_public_key()
            .map_err(|_| BitcoinSwapKeyAllocationError::CorruptAllocation)?
            .to_bytes(),
    );
    hasher.update(allocation.recovery_seed_commitment);
    hasher.update(allocation.terms_commitment.as_bytes());
    hasher.update(allocation.allocated_at_unix.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn prepare_allocation_saves(
    store: &WalletStore,
    request: BitcoinSwapKeyAllocationRequest,
    now_unix: u64,
    high_water: Option<StoredEntity<BitcoinSwapKeyAllocationRecord>>,
) -> Result<
    (
        Vec<EntityBatchSave<BitcoinSwapKeyAllocationRecord>>,
        BitcoinSwapKeyAllocation,
    ),
    BitcoinSwapKeyAllocationError,
> {
    request.validate()?;
    if now_unix == 0 {
        return Err(BitcoinSwapKeyAllocationError::InvalidRequest);
    }
    let (expected_revision, key_index, last_allocated_at_unix, expected_seed_commitment) =
        match high_water {
            Some(stored) => {
                let BitcoinSwapKeyAllocationRecord::HighWater(high_water) = stored.value else {
                    return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
                };
                high_water.validate(request, stored.revision)?;
                (
                    stored.revision,
                    high_water.next_key_index,
                    high_water.last_allocated_at_unix,
                    Some(high_water.recovery_seed_commitment),
                )
            }
            None => (0, 0, 0, None),
        };
    if now_unix < last_allocated_at_unix {
        return Err(BitcoinSwapKeyAllocationError::ClockRollback);
    }
    if key_index > MAX_BITCOIN_SWAP_KEY_INDEX {
        return Err(BitcoinSwapKeyAllocationError::AllocationExhausted);
    }
    let reference = BitcoinSwapKeyReference::new(
        request.network,
        request.role,
        request.account_index,
        key_index,
    )?;
    let (derived, seed_commitment) = derive_swap_key_and_seed_commitment(
        store,
        request.wallet_id,
        request.session_id,
        request.terms_commitment,
        reference,
    )?;
    if expected_seed_commitment.is_some_and(|expected| expected != seed_commitment) {
        return Err(BitcoinSwapKeyAllocationError::CorruptAllocation);
    }
    let allocation = BitcoinSwapKeyAllocation {
        storage_version: ALLOCATION_STORAGE_VERSION,
        wallet_id: request.wallet_id,
        session_id: request.session_id,
        reference,
        public_key: derived.public_key().clone(),
        recovery_seed_commitment: seed_commitment,
        terms_commitment: request.terms_commitment,
        allocated_at_unix: now_unix,
    };
    allocation.validate()?;
    let next_key_index = key_index
        .checked_add(1)
        .ok_or(BitcoinSwapKeyAllocationError::AllocationExhausted)?;
    let next_high_water = BitcoinSwapKeyHighWater {
        storage_version: ALLOCATION_STORAGE_VERSION,
        wallet_id: request.wallet_id,
        network: request.network,
        account_index: request.account_index,
        role: request.role,
        recovery_seed_commitment: seed_commitment,
        next_key_index,
        last_allocated_at_unix: now_unix,
    };
    let mut saves = Vec::with_capacity(if expected_revision == 0 { 4 } else { 3 });
    if expected_revision == 0 {
        saves.push(EntityBatchSave {
            id: namespace_anchor_record_id(request),
            expected_revision: 0,
            value: BitcoinSwapKeyAllocationRecord::NamespaceAnchor(BitcoinSwapKeyNamespaceAnchor {
                storage_version: ALLOCATION_STORAGE_VERSION,
                wallet_id: request.wallet_id,
                network: request.network,
                account_index: request.account_index,
                role: request.role,
                recovery_seed_commitment: seed_commitment,
            }),
            updated_at_unix: now_unix,
        });
    }
    saves.push(EntityBatchSave {
        id: high_water_record_id(request),
        expected_revision,
        value: BitcoinSwapKeyAllocationRecord::HighWater(next_high_water),
        updated_at_unix: now_unix,
    });
    saves.push(EntityBatchSave {
        id: binding_record_id(request.wallet_id, request.session_id, request.role),
        expected_revision: 0,
        value: BitcoinSwapKeyAllocationRecord::Binding(allocation.clone()),
        updated_at_unix: now_unix,
    });
    saves.push(EntityBatchSave {
        id: binding_claim_record_id(request.wallet_id, request.session_id, request.role),
        expected_revision: 0,
        value: BitcoinSwapKeyAllocationRecord::BindingClaim(BitcoinSwapKeyBindingClaim {
            storage_version: ALLOCATION_STORAGE_VERSION,
            wallet_id: request.wallet_id,
            session_id: request.session_id,
            role: request.role,
            binding_commitment: binding_commitment(&allocation)?,
        }),
        updated_at_unix: now_unix,
    });
    Ok((saves, allocation))
}

fn namespace_anchor_record_id(request: BitcoinSwapKeyAllocationRequest) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_ANCHOR_ID_DOMAIN);
    hasher.update(BITCOIN_SWAP_KEY_SCHEME_VERSION.to_be_bytes());
    hasher.update(request.wallet_id.as_bytes());
    hasher.update(request.network_code().to_be_bytes());
    hasher.update(request.account_index.to_be_bytes());
    hasher.update(request.role.code().to_be_bytes());
    hasher.finalize().to_vec()
}

fn high_water_record_id(request: BitcoinSwapKeyAllocationRequest) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(HIGH_WATER_ID_DOMAIN);
    hasher.update(BITCOIN_SWAP_KEY_SCHEME_VERSION.to_be_bytes());
    hasher.update(request.wallet_id.as_bytes());
    hasher.update(request.network_code().to_be_bytes());
    hasher.update(request.account_index.to_be_bytes());
    hasher.update(request.role.code().to_be_bytes());
    hasher.finalize().to_vec()
}

fn binding_record_id(
    wallet_id: WalletId,
    session_id: SessionId,
    role: BitcoinSwapKeyRole,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_ID_DOMAIN);
    hasher.update(BITCOIN_SWAP_KEY_SCHEME_VERSION.to_be_bytes());
    hasher.update(wallet_id.as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(role.code().to_be_bytes());
    hasher.finalize().to_vec()
}

fn binding_claim_record_id(
    wallet_id: WalletId,
    session_id: SessionId,
    role: BitcoinSwapKeyRole,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_CLAIM_ID_DOMAIN);
    hasher.update(BITCOIN_SWAP_KEY_SCHEME_VERSION.to_be_bytes());
    hasher.update(wallet_id.as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(role.code().to_be_bytes());
    hasher.finalize().to_vec()
}

impl BitcoinSwapKeyAllocationRequest {
    const fn network_code(self) -> u32 {
        match self.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Testnet4 => 2,
            Network::Signet => 3,
            Network::Regtest => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Deref, DerefMut};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use hns_wallet_store::{EntityBatchDelete, SecretKind};
    use tempfile::{TempDir, tempdir};

    const PASSPHRASE: &str = "targeted bitcoin swap allocation test";

    struct TestStore {
        store: WalletStore,
        _directory: TempDir,
    }

    impl Deref for TestStore {
        type Target = WalletStore;

        fn deref(&self) -> &Self::Target {
            &self.store
        }
    }

    impl DerefMut for TestStore {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.store
        }
    }

    fn private_tempdir() -> TempDir {
        let directory = tempdir().expect("directory");
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory permissions");
        directory
    }

    fn wallet_id() -> WalletId {
        WalletId::new([1; 16])
    }

    fn request(
        session_byte: u8,
        role: BitcoinSwapKeyRole,
        commitment_byte: u8,
    ) -> BitcoinSwapKeyAllocationRequest {
        request_for(wallet_id(), session_byte, role, commitment_byte)
    }

    fn request_for(
        wallet_id: WalletId,
        session_byte: u8,
        role: BitcoinSwapKeyRole,
        commitment_byte: u8,
    ) -> BitcoinSwapKeyAllocationRequest {
        BitcoinSwapKeyAllocationRequest {
            wallet_id,
            session_id: SessionId::new([session_byte; 32]),
            network: Network::Regtest,
            account_index: 7,
            role,
            terms_commitment: ObjectHash::new([commitment_byte; 32]),
        }
    }

    fn seed_store(store: &mut WalletStore) {
        seed_wallet(store, wallet_id());
    }

    fn seed_wallet(store: &mut WalletStore, wallet_id: WalletId) {
        let mnemonic = super::super::parse_recovery_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("mnemonic");
        let seed = mnemonic.to_seed_normalized("");
        store
            .put_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed, &seed, 1)
            .expect("seed");
    }

    fn empty_store() -> TestStore {
        let directory = private_tempdir();
        let store = WalletStore::create(directory.path().join("wallet.sqlite3"), PASSPHRASE)
            .expect("store");
        TestStore {
            store,
            _directory: directory,
        }
    }

    fn in_memory_store() -> TestStore {
        let mut store = empty_store();
        seed_store(&mut store);
        store
    }

    #[test]
    fn exact_session_retry_is_idempotent_and_clock_bound() {
        let mut store = in_memory_store();
        let original_request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let first = allocate_bitcoin_swap_key(&mut store, original_request, 10).expect("first");
        let retry = allocate_bitcoin_swap_key(&mut store, original_request, 11).expect("retry");
        assert_eq!(first, retry);
        assert_eq!(first.reference().key_index(), 0);

        let high_water = load_high_water(&store, original_request)
            .expect("high water")
            .expect("present");
        assert_eq!(
            high_water.revision, 1,
            "idempotence must not advance the counter"
        );

        allocate_bitcoin_swap_key(&mut store, request(4, BitcoinSwapKeyRole::Receiver, 5), 20)
            .expect("later allocation");
        assert!(matches!(
            allocate_bitcoin_swap_key(&mut store, original_request, 19),
            Err(BitcoinSwapKeyAllocationError::ClockRollback)
        ));
    }

    #[test]
    fn sessions_and_roles_allocate_monotonic_separate_namespaces() {
        let mut store = in_memory_store();
        let first_request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let second_request = request(4, BitcoinSwapKeyRole::Receiver, 5);
        let refund_request = request(2, BitcoinSwapKeyRole::RefundOwner, 3);
        let first = allocate_bitcoin_swap_key(&mut store, first_request, 10).expect("first");
        let second = allocate_bitcoin_swap_key(&mut store, second_request, 11).expect("second");
        let refund = allocate_bitcoin_swap_key(&mut store, refund_request, 12).expect("refund");

        assert_eq!(first.reference().key_index(), 0);
        assert_eq!(second.reference().key_index(), 1);
        assert_eq!(refund.reference().key_index(), 0);
        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(first.public_key(), refund.public_key());
    }

    #[test]
    fn existing_session_role_cannot_be_rebound() {
        let mut store = in_memory_store();
        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        allocate_bitcoin_swap_key(&mut store, request, 10).expect("allocation");
        let conflicting = BitcoinSwapKeyAllocationRequest {
            terms_commitment: ObjectHash::new([8; 32]),
            ..request
        };
        assert!(matches!(
            allocate_bitcoin_swap_key(&mut store, conflicting, 11),
            Err(BitcoinSwapKeyAllocationError::BindingConflict)
        ));
        assert!(matches!(
            derive_allocated_bitcoin_swap_key_from_store(&store, conflicting),
            Err(BitcoinSwapKeyAllocationError::BindingConflict)
        ));
    }

    #[test]
    fn allocation_context_prevents_stale_profile_key_reuse() {
        let exact_request = request(2, BitcoinSwapKeyRole::Receiver, 3);

        let mut first_store = in_memory_store();
        let first = allocate_bitcoin_swap_key(&mut first_store, exact_request, 10)
            .expect("first allocation");
        assert_eq!(
            first
                .public_key()
                .bitcoin_public_key()
                .expect("compressed allocation key")
                .to_string(),
            "03c93cca65310a3c421ab09761fa9ce7ffeae7aa17f3f0974a48536c3ec1d51d9d"
        );

        let mut exact_retry_store = in_memory_store();
        let exact = allocate_bitcoin_swap_key(&mut exact_retry_store, exact_request, 10)
            .expect("same logical allocation");
        assert_eq!(first.public_key(), exact.public_key());

        let mut different_session_store = in_memory_store();
        let different_session = allocate_bitcoin_swap_key(
            &mut different_session_store,
            request(4, BitcoinSwapKeyRole::Receiver, 3),
            10,
        )
        .expect("different session");
        assert_ne!(first.public_key(), different_session.public_key());

        let mut different_terms_store = in_memory_store();
        let different_terms = allocate_bitcoin_swap_key(
            &mut different_terms_store,
            request(2, BitcoinSwapKeyRole::Receiver, 4),
            10,
        )
        .expect("different terms");
        assert_ne!(first.public_key(), different_terms.public_key());

        let other_wallet_id = WalletId::new([9; 16]);
        let mut different_wallet_store = empty_store();
        seed_wallet(&mut different_wallet_store, other_wallet_id);
        let different_wallet = allocate_bitcoin_swap_key(
            &mut different_wallet_store,
            request_for(other_wallet_id, 2, BitcoinSwapKeyRole::Receiver, 3),
            10,
        )
        .expect("different wallet");
        assert_ne!(first.public_key(), different_wallet.public_key());

        for allocation in [
            &first,
            &exact,
            &different_session,
            &different_terms,
            &different_wallet,
        ] {
            assert_eq!(allocation.reference().key_index(), 0);
        }
    }

    #[test]
    fn stale_counter_batch_is_atomic() {
        let mut store = in_memory_store();
        let stale_request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let (stale_saves, _) =
            prepare_allocation_saves(&store, stale_request, 10, None).expect("stale batch");
        let winner_request = request(4, BitcoinSwapKeyRole::Receiver, 5);
        allocate_bitcoin_swap_key(&mut store, winner_request, 10).expect("winner");

        assert!(matches!(
            store.apply_entity_batch(EntityKind::BitcoinSwapKeyAllocation, &stale_saves, &[]),
            Err(StoreError::StaleRevision { .. })
        ));
        assert!(
            load_bitcoin_swap_key_allocation(
                &store,
                stale_request.wallet_id,
                stale_request.session_id,
                stale_request.role
            )
            .expect("load")
            .is_none(),
            "binding write must roll back with the stale high-water write"
        );
    }

    #[test]
    fn malformed_binding_variant_fails_closed() {
        let mut store = in_memory_store();
        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        allocate_bitcoin_swap_key(&mut store, request, 10).expect("allocation");
        let wrong = BitcoinSwapKeyAllocationRecord::HighWater(BitcoinSwapKeyHighWater {
            storage_version: ALLOCATION_STORAGE_VERSION,
            wallet_id: request.wallet_id,
            network: request.network,
            account_index: request.account_index,
            role: request.role,
            recovery_seed_commitment: recovery_seed_commitment(&store, request.wallet_id)
                .expect("seed commitment"),
            next_key_index: 1,
            last_allocated_at_unix: 10,
        });
        store
            .save_entity(
                EntityKind::BitcoinSwapKeyAllocation,
                &binding_record_id(request.wallet_id, request.session_id, request.role),
                1,
                &wrong,
                11,
            )
            .expect("malformed overwrite");
        assert!(matches!(
            load_bitcoin_swap_key_allocation(
                &store,
                request.wallet_id,
                request.session_id,
                request.role
            ),
            Err(BitcoinSwapKeyAllocationError::CorruptAllocation)
        ));
    }

    #[test]
    fn exhausted_high_water_rejects_without_derivation_or_write() {
        let store = in_memory_store();
        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let exhausted_next = MAX_BITCOIN_SWAP_KEY_INDEX + 1;
        let seed_commitment =
            recovery_seed_commitment(&store, request.wallet_id).expect("seed commitment");
        let high_water = StoredEntity {
            kind: EntityKind::BitcoinSwapKeyAllocation,
            id: high_water_record_id(request),
            revision: u64::from(exhausted_next),
            value: BitcoinSwapKeyAllocationRecord::HighWater(BitcoinSwapKeyHighWater {
                storage_version: ALLOCATION_STORAGE_VERSION,
                wallet_id: request.wallet_id,
                network: request.network,
                account_index: request.account_index,
                role: request.role,
                recovery_seed_commitment: seed_commitment,
                next_key_index: exhausted_next,
                last_allocated_at_unix: 10,
            }),
            updated_at_unix: 10,
        };
        assert!(matches!(
            prepare_allocation_saves(&store, request, 11, Some(high_water)),
            Err(BitcoinSwapKeyAllocationError::AllocationExhausted)
        ));
    }

    #[test]
    fn recovery_seed_and_allocation_records_reject_generic_deletion() {
        let mut store = in_memory_store();
        let seed = store
            .get_secret(wallet_id().as_bytes(), SecretKind::RecoverySeed)
            .expect("seed read")
            .expect("seed present");
        store
            .put_secret(
                wallet_id().as_bytes(),
                SecretKind::RecoverySeed,
                seed.as_slice(),
                2,
            )
            .expect("equal seed is idempotent");
        let mut replacement = [7_u8; 64];
        replacement[0] = 8;
        assert!(matches!(
            store.put_secret(
                wallet_id().as_bytes(),
                SecretKind::RecoverySeed,
                &replacement,
                3
            ),
            Err(StoreError::ProtectedSecret)
        ));
        assert!(matches!(
            store.delete_secret(wallet_id().as_bytes()),
            Err(StoreError::ProtectedSecret)
        ));

        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        allocate_bitcoin_swap_key(&mut store, request, 10).expect("allocation");
        let binding_id = binding_record_id(request.wallet_id, request.session_id, request.role);
        assert!(matches!(
            store.delete_entity(EntityKind::BitcoinSwapKeyAllocation, &binding_id, 1),
            Err(StoreError::ProtectedEntity)
        ));
        let saves: Vec<EntityBatchSave<BitcoinSwapKeyAllocationRecord>> = Vec::new();
        assert!(matches!(
            store.apply_entity_batch(
                EntityKind::BitcoinSwapKeyAllocation,
                &saves,
                &[EntityBatchDelete {
                    id: binding_id,
                    expected_revision: 1,
                }],
            ),
            Err(StoreError::ProtectedEntity)
        ));
    }

    #[test]
    fn recovery_rederives_and_authenticates_the_public_key() {
        let mut store = in_memory_store();
        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let allocation = allocate_bitcoin_swap_key(&mut store, request, 10).expect("allocation");
        let derived =
            derive_allocated_bitcoin_swap_key_from_store(&store, request).expect("recovery");
        assert_eq!(derived.public_key(), allocation.public_key());
        assert!(format!("{derived:?}").contains("[REDACTED]"));
    }

    #[cfg(unix)]
    #[test]
    fn allocation_survives_database_reopen() {
        let directory = private_tempdir();
        let path = directory.path().join("wallet.sqlite3");
        let request = request(2, BitcoinSwapKeyRole::Receiver, 3);
        let expected = {
            let mut store = WalletStore::create(&path, PASSPHRASE).expect("create");
            seed_store(&mut store);
            allocate_bitcoin_swap_key(&mut store, request, 10).expect("allocation")
        };
        let mut reopened = WalletStore::open(&path).expect("open");
        reopened.unlock(PASSPHRASE).expect("unlock");
        let loaded = load_bitcoin_swap_key_allocation(
            &reopened,
            request.wallet_id,
            request.session_id,
            request.role,
        )
        .expect("load")
        .expect("allocation");
        assert_eq!(loaded, expected);
        let derived =
            derive_allocated_bitcoin_swap_key_from_store(&reopened, request).expect("rederive");
        assert_eq!(derived.public_key(), expected.public_key());
    }
}
