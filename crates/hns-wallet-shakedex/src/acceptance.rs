use hns_swap::NetworkBinding;
use hns_wallet_types::ObjectHash;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ShakedexError, ShakescapeOutboxMessageKind};

/// Draft-defined HRM/HNSA resource profile bound into relay acceptance receipts.
///
/// HNSA has not assigned an application profile number for this use. The
/// caller must therefore supply its own non-zero profile identifier and must
/// not present this string or a receipt as an official HNSA application
/// object.
pub const HNSA_NAMED_SERVICE_RESOURCE_PROFILE: &str = "hns.named-service/v1";
/// Maximum accepted size of one endpoint-signed relay receipt.
pub const MAX_SHAKESCAPE_PUBLICATION_ACCEPTANCE_BYTES: usize = 768;

const ACCEPTANCE_MAGIC: &[u8; 4] = b"HDRA";
const ACCEPTANCE_VERSION: u16 = 1;
const RELAY_ACCEPTED_OUTCOME: u8 = 1;
const ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] = b"hns-wallet-shakescape-name-market-acceptance-v1\0";
const ACCEPTANCE_ID_DOMAIN: &[u8] = b"hns-wallet-shakescape-name-market-acceptance-id-v1\0";
const POLICY_FINGERPRINT_DOMAIN: &[u8] = b"hns-wallet-shakescape-publication-policy-v1\0";
const MAX_RECEIPT_LIFETIME_SECONDS: u32 = 7 * 24 * 60 * 60;

/// Exact HRM root material that authorized the named relay endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeHrmRootBinding {
    pub subject: ObjectHash,
    pub sequence: u64,
    pub envelope_hash: ObjectHash,
    pub chain_height: u64,
    pub chain_work_be: [u8; 32],
    pub chain_anchor: ObjectHash,
}

/// Exact HNSA service and endpoint delegation material used for relay handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeHnsaEndpointBinding {
    pub canonical_service_name: Vec<u8>,
    /// Caller-owned, non-zero application profile identifier. No official
    /// HNSA identifier is currently assigned to the wallet profile.
    pub application_profile_id: u16,
    pub service_resource_id: ObjectHash,
    pub service_delegation_id: ObjectHash,
    pub service_generation: u64,
    pub endpoint_delegation_id: ObjectHash,
    pub endpoint_sequence: u64,
    pub endpoint_public_key: [u8; 33],
    pub effective_not_before_unix: u64,
    pub effective_expires_at_unix: u64,
}

/// Immutable policy against which one Shakescape relay acceptance is checked.
///
/// This policy and its receipts are wallet-defined transport evidence. They
/// do not establish HNSA profile registration, board inclusion, listing
/// currentness, chain authority, quote authority, or permission to move value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapePublicationAcceptancePolicy {
    network_magic: u32,
    network_genesis: ObjectHash,
    hrm: ShakescapeHrmRootBinding,
    hnsa: ShakescapeHnsaEndpointBinding,
    maximum_receipt_lifetime_seconds: u32,
    fingerprint: ObjectHash,
}

impl ShakescapePublicationAcceptancePolicy {
    pub fn new(
        network: NetworkBinding,
        hrm: ShakescapeHrmRootBinding,
        hnsa: ShakescapeHnsaEndpointBinding,
        maximum_receipt_lifetime_seconds: u32,
    ) -> Result<Self, ShakedexError> {
        let mut policy = Self {
            network_magic: network.magic,
            network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
            hrm,
            hnsa,
            maximum_receipt_lifetime_seconds,
            fingerprint: ObjectHash::default(),
        };
        policy.validate_fields()?;
        policy.fingerprint = policy.compute_fingerprint();
        Ok(policy)
    }

    pub const fn fingerprint(&self) -> ObjectHash {
        self.fingerprint
    }

    pub const fn network(&self) -> NetworkBinding {
        NetworkBinding {
            magic: self.network_magic,
            genesis: hns_primitives::BlockHash::new(self.network_genesis.into_bytes()),
        }
    }

    pub const fn hrm(&self) -> &ShakescapeHrmRootBinding {
        &self.hrm
    }

    pub const fn hnsa(&self) -> &ShakescapeHnsaEndpointBinding {
        &self.hnsa
    }

    pub const fn maximum_receipt_lifetime_seconds(&self) -> u32 {
        self.maximum_receipt_lifetime_seconds
    }

    fn validate_fields(&self) -> Result<(), ShakedexError> {
        let endpoint_key_is_valid =
            VerifyingKey::from_sec1_bytes(&self.hnsa.endpoint_public_key).is_ok();
        if is_zero(self.network_genesis)
            || is_zero(self.hrm.subject)
            || is_zero(self.hrm.envelope_hash)
            || is_zero(self.hrm.chain_anchor)
            || is_zero(self.hnsa.service_resource_id)
            || is_zero(self.hnsa.service_delegation_id)
            || is_zero(self.hnsa.endpoint_delegation_id)
            || !is_canonical_service_name(&self.hnsa.canonical_service_name)
            || self.hnsa.application_profile_id == 0
            || self.hnsa.service_generation == 0
            || self.hnsa.endpoint_sequence == 0
            || !endpoint_key_is_valid
            || self.hnsa.effective_not_before_unix >= self.hnsa.effective_expires_at_unix
            || !(1..=MAX_RECEIPT_LIFETIME_SECONDS).contains(&self.maximum_receipt_lifetime_seconds)
        {
            return Err(ShakedexError::InvalidShakescapePublicationAcceptancePolicy);
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> ObjectHash {
        let mut encoded = Vec::with_capacity(320);
        encoded.extend_from_slice(POLICY_FINGERPRINT_DOMAIN);
        encoded.extend_from_slice(HNSA_NAMED_SERVICE_RESOURCE_PROFILE.as_bytes());
        encoded.push(0);
        self.encode_material(&mut encoded);
        ObjectHash::new(Sha256::digest(encoded).into())
    }

    fn encode_material(&self, encoded: &mut Vec<u8>) {
        put_u32(encoded, self.network_magic);
        put_hash(encoded, self.network_genesis);
        put_hash(encoded, self.hrm.subject);
        put_u64(encoded, self.hrm.sequence);
        put_hash(encoded, self.hrm.envelope_hash);
        put_u64(encoded, self.hrm.chain_height);
        encoded.extend_from_slice(&self.hrm.chain_work_be);
        put_hash(encoded, self.hrm.chain_anchor);
        encoded.push(self.hnsa.canonical_service_name.len() as u8);
        encoded.extend_from_slice(&self.hnsa.canonical_service_name);
        put_u16(encoded, self.hnsa.application_profile_id);
        put_hash(encoded, self.hnsa.service_resource_id);
        put_hash(encoded, self.hnsa.service_delegation_id);
        put_u64(encoded, self.hnsa.service_generation);
        put_hash(encoded, self.hnsa.endpoint_delegation_id);
        put_u64(encoded, self.hnsa.endpoint_sequence);
        encoded.extend_from_slice(&self.hnsa.endpoint_public_key);
        put_u64(encoded, self.hnsa.effective_not_before_unix);
        put_u64(encoded, self.hnsa.effective_expires_at_unix);
        put_u32(encoded, self.maximum_receipt_lifetime_seconds);
    }
}

/// Stable, non-secret summary of a durable accepted handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakescapePublicationAcceptanceSnapshot {
    pub outbox_revision: u64,
    pub envelope_id: ObjectHash,
    pub content_id: ObjectHash,
    pub message_kind: ShakescapeOutboxMessageKind,
    pub request_id: u64,
    pub attempt_id: ObjectHash,
    pub receipt_id: ObjectHash,
    pub policy_fingerprint: ObjectHash,
    pub accepted_at_unix: u64,
    pub receipt_expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedShakescapePublicationAcceptance {
    pub receipt_id: ObjectHash,
    pub policy_fingerprint: ObjectHash,
    pub accepted_at_unix: u64,
    pub receipt_expires_at_unix: u64,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct ShakescapeAcceptanceExpectation {
    pub network_magic: u32,
    pub network_genesis: ObjectHash,
    pub attempt_id: ObjectHash,
    pub record_sequence: u64,
    pub prepared_at_unix: u64,
    pub envelope_id: ObjectHash,
    pub envelope_digest: ObjectHash,
    pub content_id: ObjectHash,
    pub message_kind: ShakescapeOutboxMessageKind,
    pub request_id: u64,
}

#[derive(Clone)]
struct ParsedAcceptance {
    policy: ShakescapePublicationAcceptancePolicy,
    policy_fingerprint: ObjectHash,
    attempt_id: ObjectHash,
    record_sequence: u64,
    prepared_at_unix: u64,
    envelope_id: ObjectHash,
    envelope_digest: ObjectHash,
    content_id: ObjectHash,
    message_kind: ShakescapeOutboxMessageKind,
    request_id: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signature: Vec<u8>,
}

pub(crate) fn validate_shakescape_publication_acceptance(
    policy: &ShakescapePublicationAcceptancePolicy,
    expected: ShakescapeAcceptanceExpectation,
    receipt_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<PersistedShakescapePublicationAcceptance, ShakedexError> {
    let parsed = parse_and_verify(receipt_bytes)?;
    if &parsed.policy != policy
        || parsed.policy_fingerprint != policy.fingerprint
        || parsed.policy.network_magic != expected.network_magic
        || parsed.policy.network_genesis != expected.network_genesis
        || parsed.attempt_id != expected.attempt_id
        || parsed.record_sequence != expected.record_sequence
        || parsed.prepared_at_unix != expected.prepared_at_unix
        || parsed.envelope_id != expected.envelope_id
        || parsed.envelope_digest != expected.envelope_digest
        || parsed.content_id != expected.content_id
        || parsed.message_kind != expected.message_kind
        || parsed.request_id != expected.request_id
        || parsed.issued_at_unix != accepted_at_unix
        || accepted_at_unix < expected.prepared_at_unix
    {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    persisted_acceptance(parsed, receipt_bytes)
}

pub(crate) fn validate_persisted_shakescape_publication_acceptance(
    persisted: &PersistedShakescapePublicationAcceptance,
) -> Result<ShakescapeAcceptanceExpectation, ShakedexError> {
    let parsed = parse_and_verify(&persisted.receipt_bytes)
        .map_err(|_| ShakedexError::CorruptShakescapeOutbox)?;
    let recomputed = persisted_acceptance(parsed.clone(), &persisted.receipt_bytes)
        .map_err(|_| ShakedexError::CorruptShakescapeOutbox)?;
    if &recomputed != persisted {
        return Err(ShakedexError::CorruptShakescapeOutbox);
    }
    Ok(ShakescapeAcceptanceExpectation {
        network_magic: parsed.policy.network_magic,
        network_genesis: parsed.policy.network_genesis,
        attempt_id: parsed.attempt_id,
        record_sequence: parsed.record_sequence,
        prepared_at_unix: parsed.prepared_at_unix,
        envelope_id: parsed.envelope_id,
        envelope_digest: parsed.envelope_digest,
        content_id: parsed.content_id,
        message_kind: parsed.message_kind,
        request_id: parsed.request_id,
    })
}

fn persisted_acceptance(
    parsed: ParsedAcceptance,
    receipt_bytes: &[u8],
) -> Result<PersistedShakescapePublicationAcceptance, ShakedexError> {
    validate_receipt_window(&parsed)?;
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_ID_DOMAIN);
    hasher.update(receipt_bytes);
    Ok(PersistedShakescapePublicationAcceptance {
        receipt_id: ObjectHash::new(hasher.finalize().into()),
        policy_fingerprint: parsed.policy_fingerprint,
        accepted_at_unix: parsed.issued_at_unix,
        receipt_expires_at_unix: parsed.expires_at_unix,
        receipt_bytes: receipt_bytes.to_vec(),
    })
}

fn validate_receipt_window(parsed: &ParsedAcceptance) -> Result<(), ShakedexError> {
    let maximum_expiry = parsed
        .issued_at_unix
        .checked_add(u64::from(parsed.policy.maximum_receipt_lifetime_seconds))
        .ok_or(ShakedexError::InvalidShakescapePublicationAcceptance)?;
    if parsed.expires_at_unix <= parsed.issued_at_unix
        || parsed.issued_at_unix < parsed.policy.hnsa.effective_not_before_unix
        || parsed.expires_at_unix > parsed.policy.hnsa.effective_expires_at_unix
        || parsed.expires_at_unix > maximum_expiry
    {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    Ok(())
}

fn parse_and_verify(receipt_bytes: &[u8]) -> Result<ParsedAcceptance, ShakedexError> {
    if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_SHAKESCAPE_PUBLICATION_ACCEPTANCE_BYTES
    {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    let mut decoder = Decoder::new(receipt_bytes);
    if decoder.take(4)? != ACCEPTANCE_MAGIC
        || decoder.u16()? != ACCEPTANCE_VERSION
        || decoder.u8()? != RELAY_ACCEPTED_OUTCOME
    {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    let network_magic = decoder.u32()?;
    let network_genesis = decoder.hash()?;
    let hrm = ShakescapeHrmRootBinding {
        subject: decoder.hash()?,
        sequence: decoder.u64()?,
        envelope_hash: decoder.hash()?,
        chain_height: decoder.u64()?,
        chain_work_be: decoder.array()?,
        chain_anchor: decoder.hash()?,
    };
    let name_length = usize::from(decoder.u8()?);
    let canonical_service_name = decoder.take(name_length)?.to_vec();
    let hnsa = ShakescapeHnsaEndpointBinding {
        canonical_service_name,
        application_profile_id: decoder.u16()?,
        service_resource_id: decoder.hash()?,
        service_delegation_id: decoder.hash()?,
        service_generation: decoder.u64()?,
        endpoint_delegation_id: decoder.hash()?,
        endpoint_sequence: decoder.u64()?,
        endpoint_public_key: decoder.array()?,
        effective_not_before_unix: decoder.u64()?,
        effective_expires_at_unix: decoder.u64()?,
    };
    let maximum_receipt_lifetime_seconds = decoder.u32()?;
    let policy = ShakescapePublicationAcceptancePolicy::new(
        NetworkBinding {
            magic: network_magic,
            genesis: hns_primitives::BlockHash::new(network_genesis.into_bytes()),
        },
        hrm,
        hnsa,
        maximum_receipt_lifetime_seconds,
    )
    .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)?;
    let policy_fingerprint = decoder.hash()?;
    let attempt_id = decoder.hash()?;
    let record_sequence = decoder.u64()?;
    let prepared_at_unix = decoder.u64()?;
    let envelope_id = decoder.hash()?;
    let envelope_digest = decoder.hash()?;
    let content_id = decoder.hash()?;
    let message_kind = match decoder.u8()? {
        1 => ShakescapeOutboxMessageKind::Offer,
        2 => ShakescapeOutboxMessageKind::Cancellation,
        _ => return Err(ShakedexError::InvalidShakescapePublicationAcceptance),
    };
    let request_id = decoder.u64()?;
    let issued_at_unix = decoder.u64()?;
    let expires_at_unix = decoder.u64()?;
    let signed_body_length = decoder.position();
    let signature_length = usize::from(decoder.u16()?);
    let signature = decoder.take(signature_length)?.to_vec();
    if !decoder.is_finished() {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    let parsed = ParsedAcceptance {
        policy,
        policy_fingerprint,
        attempt_id,
        record_sequence,
        prepared_at_unix,
        envelope_id,
        envelope_digest,
        content_id,
        message_kind,
        request_id,
        issued_at_unix,
        expires_at_unix,
        signature,
    };
    let canonical_body = encode_unsigned(&parsed);
    let mut canonical_receipt = canonical_body.clone();
    put_u16(
        &mut canonical_receipt,
        parsed
            .signature
            .len()
            .try_into()
            .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)?,
    );
    canonical_receipt.extend_from_slice(&parsed.signature);
    if canonical_body.len() != signed_body_length
        || canonical_receipt != receipt_bytes
        || parsed.policy_fingerprint != parsed.policy.fingerprint
    {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    let signature = Signature::from_der(&parsed.signature)
        .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)?;
    if signature.normalize_s().is_some() || signature.to_der().as_bytes() != parsed.signature {
        return Err(ShakedexError::InvalidShakescapePublicationAcceptance);
    }
    let key = VerifyingKey::from_sec1_bytes(&parsed.policy.hnsa.endpoint_public_key)
        .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)?;
    let digest = acceptance_digest(&canonical_body);
    key.verify_prehash(&digest, &signature)
        .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)?;
    Ok(parsed)
}

fn encode_unsigned(parsed: &ParsedAcceptance) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(ACCEPTANCE_MAGIC);
    put_u16(&mut encoded, ACCEPTANCE_VERSION);
    encoded.push(RELAY_ACCEPTED_OUTCOME);
    parsed.policy.encode_material(&mut encoded);
    put_hash(&mut encoded, parsed.policy_fingerprint);
    put_hash(&mut encoded, parsed.attempt_id);
    put_u64(&mut encoded, parsed.record_sequence);
    put_u64(&mut encoded, parsed.prepared_at_unix);
    put_hash(&mut encoded, parsed.envelope_id);
    put_hash(&mut encoded, parsed.envelope_digest);
    put_hash(&mut encoded, parsed.content_id);
    encoded.push(match parsed.message_kind {
        ShakescapeOutboxMessageKind::Offer => 1,
        ShakescapeOutboxMessageKind::Cancellation => 2,
    });
    put_u64(&mut encoded, parsed.request_id);
    put_u64(&mut encoded, parsed.issued_at_unix);
    put_u64(&mut encoded, parsed.expires_at_unix);
    encoded
}

fn acceptance_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_SIGNATURE_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn is_canonical_service_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.first() != Some(&b'-')
        && name.last() != Some(&b'-')
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_zero(hash: ObjectHash) -> bool {
    hash.into_bytes() == [0; 32]
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: ObjectHash) {
    output.extend_from_slice(&value.into_bytes());
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ShakedexError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ShakedexError::InvalidShakescapePublicationAcceptance)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ShakedexError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ShakedexError::InvalidShakescapePublicationAcceptance)
    }

    fn u8(&mut self) -> Result<u8, ShakedexError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ShakedexError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ShakedexError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ShakedexError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn hash(&mut self) -> Result<ObjectHash, ShakedexError> {
        self.array().map(ObjectHash::new)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
pub(crate) fn signed_acceptance_for_test(
    policy: &ShakescapePublicationAcceptancePolicy,
    expected: ShakescapeAcceptanceExpectation,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signing_key: &k256::ecdsa::SigningKey,
) -> Vec<u8> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let mut parsed = ParsedAcceptance {
        policy: policy.clone(),
        policy_fingerprint: policy.fingerprint,
        attempt_id: expected.attempt_id,
        record_sequence: expected.record_sequence,
        prepared_at_unix: expected.prepared_at_unix,
        envelope_id: expected.envelope_id,
        envelope_digest: expected.envelope_digest,
        content_id: expected.content_id,
        message_kind: expected.message_kind,
        request_id: expected.request_id,
        issued_at_unix,
        expires_at_unix,
        signature: Vec::new(),
    };
    let body = encode_unsigned(&parsed);
    let signature: Signature = signing_key
        .sign_prehash(&acceptance_digest(&body))
        .expect("test endpoint signature");
    let signature = signature.normalize_s().unwrap_or(signature).to_der();
    parsed.signature = signature.as_bytes().to_vec();
    let mut receipt = body;
    put_u16(
        &mut receipt,
        parsed
            .signature
            .len()
            .try_into()
            .expect("DER signature length"),
    );
    receipt.extend_from_slice(&parsed.signature);
    receipt
}
