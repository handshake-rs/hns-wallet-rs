//! Wallet-owned cross-chain settlement authority.
//!
//! A participant allocates one secp256k1 key for one Denuo swap session. The
//! encrypted allocation stores only the immutable public binding. The secret
//! scalar is re-derived from the wallet recovery seed when an in-process
//! signing handle is requested and is never serialized or returned.

use core::fmt;

use hkdf::Hkdf;
use hns_marketplace_protocol::{
    ChainId, MarketPair, MarketplaceError, NetworkBinding, SwapFundingStatus, SwapRedeemStatus,
    SwapRefundStatus, SwapSessionHello, SwapSessionProposal,
};
use hns_wallet_chain_api::{SettlementSigner, SettlementSigningError};
use hns_wallet_store::{EntityKind, RECOVERY_SEED_BYTES, SecretKind, StoreError, WalletStore};
use hns_wallet_types::{ObjectHash, SessionId, WalletId};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const STORAGE_VERSION: u16 = 1;
const RECORD_ID_DOMAIN: &[u8] = b"hns-wallet/cross-chain-swap-key/record/v1\0";
const CONTEXT_DOMAIN: &[u8] = b"hns-wallet/cross-chain-swap-key/context/v1\0";
const RECOVERY_SEED_COMMITMENT_DOMAIN: &[u8] =
    b"hns-wallet/cross-chain-swap-key/recovery-seed/v1\0";
const DERIVATION_SALT: &[u8] = b"hns-wallet/cross-chain-swap-key/hkdf-sha256/v1\0";
const DERIVATION_INFO_DOMAIN: &[u8] = b"hns-wallet/cross-chain-swap-key/scalar/v1\0";
const MAX_DERIVATION_ATTEMPTS: u32 = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedCompressedPublicKey([u8; 33]);

impl Serialize for PersistedCompressedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for PersistedCompressedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 66 {
            return Err(serde::de::Error::custom(
                "compressed public key must be 33 bytes",
            ));
        }
        let mut public_key = [0_u8; 33];
        hex::decode_to_slice(encoded, &mut public_key).map_err(serde::de::Error::custom)?;
        Ok(Self(public_key))
    }
}

/// The local participant represented by one settlement authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapParticipant {
    Maker,
    Taker,
}

impl SwapParticipant {
    const fn code(self) -> u8 {
        match self {
            Self::Maker => 0,
            Self::Taker => 1,
        }
    }

    const fn funding_chain(self, hello: &SwapSessionHello) -> ChainId {
        match self {
            Self::Maker => hello.offered_asset.chain(),
            Self::Taker => hello.received_asset.chain(),
        }
    }

    const fn redeem_chain(self, hello: &SwapSessionHello) -> ChainId {
        match self {
            Self::Maker => hello.received_asset.chain(),
            Self::Taker => hello.offered_asset.chain(),
        }
    }
}

/// Immutable context used to allocate and recover a participant's key.
///
/// The record identity is wallet/session/participant. `network` and
/// `intent_id` are immutable binding data: retrying that identity with either
/// changed fails instead of silently reusing the key in another market.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossChainSwapKeyRequest {
    pub wallet_id: WalletId,
    pub session_id: SessionId,
    pub participant: SwapParticipant,
    pub network: NetworkBinding,
    pub intent_id: ObjectHash,
}

impl CrossChainSwapKeyRequest {
    fn validate(self) -> Result<Vec<u8>, CrossChainSwapKeyError> {
        if is_zero(self.wallet_id.as_bytes())
            || is_zero(self.session_id.as_bytes())
            || is_zero(self.intent_id.as_bytes())
        {
            return Err(CrossChainSwapKeyError::InvalidRequest);
        }
        self.network
            .validate_for_pair(MarketPair::HNS_BTC)
            .map_err(|_| CrossChainSwapKeyError::InvalidRequest)?;
        self.network
            .encode()
            .map_err(|_| CrossChainSwapKeyError::InvalidRequest)
    }
}

/// Encrypted public recovery binding for one wallet/session/participant key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossChainSwapKeyAllocation {
    storage_version: u16,
    wallet_id: WalletId,
    session_id: SessionId,
    participant: SwapParticipant,
    network_encoding: Vec<u8>,
    intent_id: ObjectHash,
    context_commitment: ObjectHash,
    compressed_public_key: PersistedCompressedPublicKey,
    recovery_seed_commitment: [u8; 32],
    allocated_at_unix: u64,
}

impl CrossChainSwapKeyAllocation {
    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn participant(&self) -> SwapParticipant {
        self.participant
    }

    pub const fn intent_id(&self) -> ObjectHash {
        self.intent_id
    }

    pub const fn context_commitment(&self) -> ObjectHash {
        self.context_commitment
    }

    pub const fn compressed_public_key(&self) -> [u8; 33] {
        self.compressed_public_key.0
    }

    pub const fn allocated_at_unix(&self) -> u64 {
        self.allocated_at_unix
    }

    pub fn network(&self) -> Result<NetworkBinding, CrossChainSwapKeyError> {
        NetworkBinding::decode(&self.network_encoding)
            .map_err(|_| CrossChainSwapKeyError::CorruptAllocation)
    }

    fn request(&self) -> Result<CrossChainSwapKeyRequest, CrossChainSwapKeyError> {
        Ok(CrossChainSwapKeyRequest {
            wallet_id: self.wallet_id,
            session_id: self.session_id,
            participant: self.participant,
            network: self.network()?,
            intent_id: self.intent_id,
        })
    }

    fn validate(&self) -> Result<(), CrossChainSwapKeyError> {
        if self.storage_version != STORAGE_VERSION
            || self.allocated_at_unix == 0
            || self.recovery_seed_commitment == [0; 32]
            || VerifyingKey::from_sec1_bytes(&self.compressed_public_key.0).is_err()
        {
            return Err(CrossChainSwapKeyError::CorruptAllocation);
        }
        let request = self.request()?;
        let expected_network = request
            .validate()
            .map_err(|_| CrossChainSwapKeyError::CorruptAllocation)?;
        if self.network_encoding != expected_network
            || self.context_commitment != context_commitment(request, &self.network_encoding)
        {
            return Err(CrossChainSwapKeyError::CorruptAllocation);
        }
        Ok(())
    }

    fn matches_request(&self, request: CrossChainSwapKeyRequest, network_encoding: &[u8]) -> bool {
        self.wallet_id == request.wallet_id
            && self.session_id == request.session_id
            && self.participant == request.participant
            && self.network_encoding == network_encoding
            && self.intent_id == request.intent_id
            && self.context_commitment == context_commitment(request, network_encoding)
    }
}

/// In-memory, non-exportable settlement signing handle.
pub struct CrossChainSwapKey {
    request: CrossChainSwapKeyRequest,
    compressed_public_key: [u8; 33],
    secret: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for CrossChainSwapKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossChainSwapKey")
            .field("wallet_id", &self.request.wallet_id)
            .field("session_id", &self.request.session_id)
            .field("participant", &self.request.participant)
            .field("compressed_public_key", &self.compressed_public_key)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CrossChainSwapKey {
    pub const fn request(&self) -> CrossChainSwapKeyRequest {
        self.request
    }

    pub const fn participant(&self) -> SwapParticipant {
        self.request.participant
    }

    pub const fn public_key(&self) -> [u8; 33] {
        self.compressed_public_key
    }

    /// Sign complete maker terms without exporting the settlement scalar.
    pub fn into_maker_proposal(
        &self,
        hello: SwapSessionHello,
    ) -> Result<SwapSessionProposal, CrossChainSwapKeyError> {
        self.validate_hello_identity(&hello, SwapParticipant::Maker)?;
        hello
            .into_maker_proposal(&self.secret)
            .map_err(CrossChainSwapKeyError::Protocol)
    }

    /// Verify and countersign complete taker terms without exporting the
    /// settlement scalar.
    pub fn accept_taker(
        &self,
        proposal: SwapSessionProposal,
        now_unix: u64,
    ) -> Result<SwapSessionHello, CrossChainSwapKeyError> {
        self.validate_hello_identity(proposal.terms(), SwapParticipant::Taker)?;
        proposal
            .accept_taker(self.request.network, now_unix, &self.secret)
            .map_err(CrossChainSwapKeyError::Protocol)
    }

    /// Sign a locally derived funding observation for the chain this
    /// participant is required to fund, then re-verify it against the accepted
    /// session before it may be sent to a Denuo peer.
    pub fn sign_funding_status(
        &self,
        status: &mut SwapFundingStatus,
        hello: &SwapSessionHello,
        now_unix: u64,
    ) -> Result<(), CrossChainSwapKeyError> {
        self.validate_accepted_hello(hello)?;
        if status.chain != self.request.participant.funding_chain(hello) {
            return Err(CrossChainSwapKeyError::WrongParticipant);
        }
        status.sign(&self.secret)?;
        status.verify_for_session(hello, self.request.network, now_unix)?;
        Ok(())
    }

    /// Sign a locally verified redeem observation for the chain this
    /// participant can redeem.
    pub fn sign_redeem_status(
        &self,
        status: &mut SwapRedeemStatus,
        hello: &SwapSessionHello,
        now_unix: u64,
    ) -> Result<(), CrossChainSwapKeyError> {
        self.validate_accepted_hello(hello)?;
        if status.chain != self.request.participant.redeem_chain(hello) {
            return Err(CrossChainSwapKeyError::WrongParticipant);
        }
        status.sign(&self.secret)?;
        status.verify_for_session(hello, self.request.network, now_unix)?;
        Ok(())
    }

    /// Sign a locally verified refund observation for the chain this
    /// participant originally funded.
    pub fn sign_refund_status(
        &self,
        status: &mut SwapRefundStatus,
        hello: &SwapSessionHello,
        now_unix: u64,
    ) -> Result<(), CrossChainSwapKeyError> {
        self.validate_accepted_hello(hello)?;
        if status.chain != self.request.participant.funding_chain(hello) {
            return Err(CrossChainSwapKeyError::WrongParticipant);
        }
        status.sign(&self.secret)?;
        status.verify_for_session(hello, self.request.network, now_unix)?;
        Ok(())
    }

    fn validate_hello_identity(
        &self,
        hello: &SwapSessionHello,
        expected_participant: SwapParticipant,
    ) -> Result<(), CrossChainSwapKeyError> {
        if self.request.participant != expected_participant {
            return Err(CrossChainSwapKeyError::WrongParticipant);
        }
        let expected_public_key = match expected_participant {
            SwapParticipant::Maker => hello.maker_settlement_public_key,
            SwapParticipant::Taker => hello.taker_settlement_public_key,
        };
        if hello.swap_session_id != self.request.session_id.into_bytes()
            || hello.header.network != self.request.network
            || expected_public_key != self.compressed_public_key
        {
            return Err(CrossChainSwapKeyError::SessionMismatch);
        }
        Ok(())
    }

    fn validate_accepted_hello(
        &self,
        hello: &SwapSessionHello,
    ) -> Result<(), CrossChainSwapKeyError> {
        self.validate_hello_identity(hello, self.request.participant)?;
        hello.verify_agreement(self.request.network)?;
        Ok(())
    }
}

impl SettlementSigner for CrossChainSwapKey {
    fn compressed_public_key(&self) -> [u8; 33] {
        self.compressed_public_key
    }

    fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 64], SettlementSigningError> {
        let signing = SigningKey::from_bytes((&*self.secret).into())
            .map_err(|_| SettlementSigningError::InvalidKey)?;
        let signature: Signature = signing
            .sign_prehash(&digest)
            .map_err(|_| SettlementSigningError::SigningFailed)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().into())
    }
}

#[derive(Debug, Error)]
pub enum CrossChainSwapKeyError {
    #[error("cross-chain settlement-key request is invalid")]
    InvalidRequest,
    #[error("this wallet/session/participant key is already bound to different swap context")]
    BindingConflict,
    #[error("cross-chain settlement-key allocation was not found")]
    AllocationNotFound,
    #[error("cross-chain settlement-key allocation is corrupt or inconsistent")]
    CorruptAllocation,
    #[error("cross-chain settlement-key derivation failed")]
    DerivationFailed,
    #[error("cross-chain settlement-key allocation clock moved behind durable state")]
    ClockRollback,
    #[error("cross-chain settlement-key allocation changed concurrently")]
    ConcurrentModification,
    #[error("settlement operation is not authorized for this swap participant")]
    WrongParticipant,
    #[error("settlement operation is bound to another swap session")]
    SessionMismatch,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Protocol(#[from] MarketplaceError),
}

/// Allocate an immutable public binding. Exact retries are idempotent and
/// re-derive the secret to prove the encrypted record still matches the
/// wallet recovery seed.
pub fn allocate_cross_chain_swap_key(
    store: &mut WalletStore,
    request: CrossChainSwapKeyRequest,
    now_unix: u64,
) -> Result<CrossChainSwapKeyAllocation, CrossChainSwapKeyError> {
    let network_encoding = request.validate()?;
    if now_unix == 0 {
        return Err(CrossChainSwapKeyError::InvalidRequest);
    }
    if let Some(existing) = load_cross_chain_swap_key_allocation(
        store,
        request.wallet_id,
        request.session_id,
        request.participant,
    )? {
        return accept_existing(store, existing, request, &network_encoding, now_unix);
    }

    let (key, recovery_seed_commitment) = derive_key_from_store(store, request, &network_encoding)?;
    let allocation = CrossChainSwapKeyAllocation {
        storage_version: STORAGE_VERSION,
        wallet_id: request.wallet_id,
        session_id: request.session_id,
        participant: request.participant,
        network_encoding,
        intent_id: request.intent_id,
        context_commitment: context_commitment(request, &request.network.encode()?),
        compressed_public_key: PersistedCompressedPublicKey(key.public_key()),
        recovery_seed_commitment,
        allocated_at_unix: now_unix,
    };
    allocation.validate()?;
    let id = allocation_record_id(request.wallet_id, request.session_id, request.participant);
    match store.save_entity(
        EntityKind::CrossChainSwapKeyAllocation,
        &id,
        0,
        &allocation,
        now_unix,
    ) {
        Ok(1) => Ok(allocation),
        Ok(_) => Err(CrossChainSwapKeyError::CorruptAllocation),
        Err(StoreError::StaleRevision { .. }) => {
            let existing = load_cross_chain_swap_key_allocation(
                store,
                request.wallet_id,
                request.session_id,
                request.participant,
            )?
            .ok_or(CrossChainSwapKeyError::ConcurrentModification)?;
            accept_existing(
                store,
                existing,
                request,
                &request.network.encode()?,
                now_unix,
            )
        }
        Err(error) => Err(error.into()),
    }
}

/// Load and authenticate one public allocation by immutable identity.
pub fn load_cross_chain_swap_key_allocation(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    participant: SwapParticipant,
) -> Result<Option<CrossChainSwapKeyAllocation>, CrossChainSwapKeyError> {
    if is_zero(wallet_id.as_bytes()) || is_zero(session_id.as_bytes()) {
        return Err(CrossChainSwapKeyError::InvalidRequest);
    }
    let id = allocation_record_id(wallet_id, session_id, participant);
    let Some(stored) = store
        .load_entity::<CrossChainSwapKeyAllocation>(EntityKind::CrossChainSwapKeyAllocation, &id)?
    else {
        return Ok(None);
    };
    if stored.revision != 1
        || stored.updated_at_unix != stored.value.allocated_at_unix
        || stored.value.wallet_id != wallet_id
        || stored.value.session_id != session_id
        || stored.value.participant != participant
    {
        return Err(CrossChainSwapKeyError::CorruptAllocation);
    }
    stored.value.validate()?;
    let current_seed_commitment = recovery_seed_commitment(store, wallet_id)?;
    if current_seed_commitment != stored.value.recovery_seed_commitment {
        return Err(CrossChainSwapKeyError::CorruptAllocation);
    }
    Ok(Some(stored.value))
}

/// Recover the non-exportable signing handle only after re-authenticating the
/// complete persisted context and matching its compressed public key.
pub fn derive_cross_chain_swap_key_from_store(
    store: &WalletStore,
    request: CrossChainSwapKeyRequest,
) -> Result<CrossChainSwapKey, CrossChainSwapKeyError> {
    let network_encoding = request.validate()?;
    let allocation = load_cross_chain_swap_key_allocation(
        store,
        request.wallet_id,
        request.session_id,
        request.participant,
    )?
    .ok_or(CrossChainSwapKeyError::AllocationNotFound)?;
    if !allocation.matches_request(request, &network_encoding) {
        return Err(CrossChainSwapKeyError::BindingConflict);
    }
    let (key, seed_commitment) = derive_key_from_store(store, request, &network_encoding)?;
    if key.public_key() != allocation.compressed_public_key.0
        || seed_commitment != allocation.recovery_seed_commitment
    {
        return Err(CrossChainSwapKeyError::CorruptAllocation);
    }
    Ok(key)
}

fn accept_existing(
    store: &WalletStore,
    allocation: CrossChainSwapKeyAllocation,
    request: CrossChainSwapKeyRequest,
    network_encoding: &[u8],
    now_unix: u64,
) -> Result<CrossChainSwapKeyAllocation, CrossChainSwapKeyError> {
    if !allocation.matches_request(request, network_encoding) {
        return Err(CrossChainSwapKeyError::BindingConflict);
    }
    if now_unix < allocation.allocated_at_unix {
        return Err(CrossChainSwapKeyError::ClockRollback);
    }
    let (key, seed_commitment) = derive_key_from_store(store, request, network_encoding)?;
    if key.public_key() != allocation.compressed_public_key.0
        || seed_commitment != allocation.recovery_seed_commitment
    {
        return Err(CrossChainSwapKeyError::CorruptAllocation);
    }
    Ok(allocation)
}

fn derive_key_from_store(
    store: &WalletStore,
    request: CrossChainSwapKeyRequest,
    network_encoding: &[u8],
) -> Result<(CrossChainSwapKey, [u8; 32]), CrossChainSwapKeyError> {
    let seed = store
        .get_secret(request.wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(CrossChainSwapKeyError::DerivationFailed)?;
    if seed.len() != RECOVERY_SEED_BYTES {
        return Err(CrossChainSwapKeyError::DerivationFailed);
    }
    let seed_commitment = recovery_seed_commitment_from_cleartext(request.wallet_id, &seed);
    let context = context_commitment(request, network_encoding);
    let hkdf = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), &seed);
    for attempt in 0..MAX_DERIVATION_ATTEMPTS {
        let mut info = Vec::with_capacity(DERIVATION_INFO_DOMAIN.len() + 32 + 4);
        info.extend_from_slice(DERIVATION_INFO_DOMAIN);
        info.extend_from_slice(context.as_bytes());
        info.extend_from_slice(&attempt.to_be_bytes());
        let mut secret = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, &mut *secret)
            .map_err(|_| CrossChainSwapKeyError::DerivationFailed)?;
        if let Ok(signing) = SigningKey::from_bytes((&*secret).into()) {
            let compressed_public_key = signing
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| CrossChainSwapKeyError::DerivationFailed)?;
            return Ok((
                CrossChainSwapKey {
                    request,
                    compressed_public_key,
                    secret,
                },
                seed_commitment,
            ));
        }
    }
    Err(CrossChainSwapKeyError::DerivationFailed)
}

fn recovery_seed_commitment(
    store: &WalletStore,
    wallet_id: WalletId,
) -> Result<[u8; 32], CrossChainSwapKeyError> {
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(CrossChainSwapKeyError::DerivationFailed)?;
    if seed.len() != RECOVERY_SEED_BYTES {
        return Err(CrossChainSwapKeyError::DerivationFailed);
    }
    Ok(recovery_seed_commitment_from_cleartext(wallet_id, &seed))
}

fn recovery_seed_commitment_from_cleartext(wallet_id: WalletId, seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_SEED_COMMITMENT_DOMAIN);
    hasher.update(wallet_id.as_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

fn context_commitment(request: CrossChainSwapKeyRequest, network_encoding: &[u8]) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_DOMAIN);
    hasher.update(STORAGE_VERSION.to_be_bytes());
    hasher.update(request.wallet_id.as_bytes());
    hasher.update(request.session_id.as_bytes());
    hasher.update([request.participant.code()]);
    hasher.update(request.intent_id.as_bytes());
    hasher.update(network_encoding);
    ObjectHash::new(hasher.finalize().into())
}

fn allocation_record_id(
    wallet_id: WalletId,
    session_id: SessionId,
    participant: SwapParticipant,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_ID_DOMAIN);
    hasher.update(STORAGE_VERSION.to_be_bytes());
    hasher.update(wallet_id.as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update([participant.code()]);
    hasher.finalize().into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use hns_marketplace_protocol::{
        AssetAmount, AssetId, ChainId, DeadlineKind, MARKETPLACE_PROTOCOL_VERSION,
        SettlementDeadline, SignedObjectHeader,
    };
    use hns_primitives::BlockHash;

    use super::*;

    const PASSPHRASE: &str = "targeted cross-chain settlement key test";

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn request(wallet: u8, participant: SwapParticipant) -> CrossChainSwapKeyRequest {
        CrossChainSwapKeyRequest {
            wallet_id: WalletId::new([wallet; 16]),
            session_id: SessionId::new([12; 32]),
            participant,
            network: network(),
            intent_id: ObjectHash::new([11; 32]),
        }
    }

    fn store_with_seed(request: CrossChainSwapKeyRequest, seed: u8) -> WalletStore {
        let mut store = WalletStore::create(":memory:", PASSPHRASE).expect("wallet store");
        store
            .put_secret(
                request.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[seed; RECOVERY_SEED_BYTES],
                1,
            )
            .expect("recovery seed");
        store
    }

    fn header(network: NetworkBinding) -> SignedObjectHeader {
        let identity = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("identity key");
        SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network,
            pair: MarketPair::HNS_BTC,
            signer_public_key: identity
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .expect("compressed identity"),
            sequence: 3,
            created_at: 100,
            expires_at: 150,
        }
    }

    #[test]
    fn allocation_is_idempotent_bound_and_recoverable() {
        let request = request(3, SwapParticipant::Maker);
        let mut store = store_with_seed(request, 21);
        let allocated = allocate_cross_chain_swap_key(&mut store, request, 10).expect("allocation");
        let retry = allocate_cross_chain_swap_key(&mut store, request, 11).expect("retry");
        assert_eq!(retry, allocated);

        let recovered =
            derive_cross_chain_swap_key_from_store(&store, request).expect("recovered key");
        assert_eq!(recovered.public_key(), allocated.compressed_public_key());
        assert!(format!("{recovered:?}").contains("<redacted>"));
        let signature = recovered.sign_digest([42; 32]).expect("digest signature");
        let signature = Signature::from_slice(&signature).expect("compact signature");
        assert!(signature.normalize_s().is_none(), "signature must be low-S");

        let id = allocation_record_id(request.wallet_id, request.session_id, request.participant);
        assert!(matches!(
            store.delete_entity(EntityKind::CrossChainSwapKeyAllocation, &id, 1),
            Err(StoreError::ProtectedEntity)
        ));

        let conflicting = CrossChainSwapKeyRequest {
            intent_id: ObjectHash::new([99; 32]),
            ..request
        };
        assert!(matches!(
            allocate_cross_chain_swap_key(&mut store, conflicting, 12),
            Err(CrossChainSwapKeyError::BindingConflict)
        ));
        assert!(matches!(
            allocate_cross_chain_swap_key(&mut store, request, 9),
            Err(CrossChainSwapKeyError::ClockRollback)
        ));
    }

    #[test]
    fn allocation_survives_database_reopen() {
        let request = request(4, SwapParticipant::Taker);
        let path = unique_database_path();
        let allocated = {
            let mut store = WalletStore::create(&path, PASSPHRASE).expect("create store");
            store
                .put_secret(
                    request.wallet_id.as_bytes(),
                    SecretKind::RecoverySeed,
                    &[22; RECOVERY_SEED_BYTES],
                    1,
                )
                .expect("recovery seed");
            allocate_cross_chain_swap_key(&mut store, request, 10).expect("allocation")
        };
        {
            let mut reopened = WalletStore::open(&path).expect("open store");
            reopened.unlock(PASSPHRASE).expect("unlock store");
            let recovered = derive_cross_chain_swap_key_from_store(&reopened, request)
                .expect("recover after reopen");
            assert_eq!(recovered.public_key(), allocated.compressed_public_key());
        }
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn two_wallets_sign_one_bilateral_session_with_the_same_chain_keys() {
        let maker_request = request(31, SwapParticipant::Maker);
        let taker_request = request(41, SwapParticipant::Taker);
        let mut maker_store = store_with_seed(maker_request, 51);
        let mut taker_store = store_with_seed(taker_request, 61);
        allocate_cross_chain_swap_key(&mut maker_store, maker_request, 10)
            .expect("maker allocation");
        allocate_cross_chain_swap_key(&mut taker_store, taker_request, 10)
            .expect("taker allocation");
        let maker =
            derive_cross_chain_swap_key_from_store(&maker_store, maker_request).expect("maker key");
        let taker =
            derive_cross_chain_swap_key_from_store(&taker_store, taker_request).expect("taker key");

        let mut hello = SwapSessionHello {
            header: header(network()),
            fill_grant_hash: [10; 32],
            swap_session_id: maker_request.session_id.into_bytes(),
            maker_settlement_public_key: maker.public_key(),
            taker_settlement_public_key: taker.public_key(),
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(1_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(10_000),
            price_round_hash: [13; 32],
            hashlock: [14; 32],
            first_funding_chain: ChainId::HANDSHAKE,
            offered_lock_commitment: [0; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 500,
            },
            offered_minimum_confirmations: 2,
            received_lock_commitment: [15; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 300,
            },
            received_minimum_confirmations: 2,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        };
        let hns = hello
            .build_and_bind_hns_htlc(
                hns_marketplace_protocol::SwapAssetSide::Offered,
                taker.public_key(),
                maker.public_key(),
            )
            .expect("HNS descriptor");
        assert_eq!(hns.descriptor.receiver_public_key, taker.public_key());
        assert_eq!(hns.descriptor.refund_public_key, maker.public_key());

        let proposal = maker.into_maker_proposal(hello).expect("maker proposal");
        let accepted = taker.accept_taker(proposal, 128).expect("taker acceptance");
        accepted
            .verify_agreement(network())
            .expect("bilateral agreement");
    }

    fn unique_database_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-wallet-cross-chain-key-{}-{nanos}.sqlite",
            std::process::id()
        ))
    }
}
