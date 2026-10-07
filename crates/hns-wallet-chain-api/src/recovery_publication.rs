//! Public contract recovery records for chain-bound swap funding.
//!
//! Publication plans are not chain evidence. Funding adapters must commit the
//! marker in the funding transaction and require that its inputs descend from
//! seed-owned transactions carrying every frame. Recovered terms must be
//! checked against the independently verified funded output before settlement.

use hns_marketplace_protocol::{
    AssetId, ChainId, MarketPair, NetworkBinding, SwapAssetSide, SwapSessionHello,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const FRAME_MAGIC: [u8; 2] = *b"SR";
const MARKER_MAGIC: [u8; 4] = *b"SRF1";
const COMMITMENT_DOMAIN: &[u8] = b"shakescape/chain-swap-recovery/v1\0";
const FRAME_HEADER_BYTES: usize = 4;
const TERMS_BYTES: usize = 204;
pub const SWAP_RECOVERY_MARKER_BYTES: usize = 37;
pub const MAX_SWAP_RECOVERY_FRAMES: usize = 24;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SwapRecoveryPublicationError {
    #[error("swap recovery publication has an unsupported chain")]
    UnsupportedChain,
    #[error("swap recovery publication has invalid public terms or network")]
    InvalidAgreement,
    #[error("swap recovery publication exceeds its bounded chain capacity")]
    Capacity,
    #[error("swap recovery publication is incomplete, changed, or noncanonical")]
    InvalidPublication,
}

/// Public data sufficient to rebuild both exact contracts and the seed-derived
/// authorities. Network binding is supplied by the independently authenticated
/// wallet chains and is included in the funding marker's commitment.
/// No offer journal, seed, signing scalar, or preimage is serialized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapRecoveryTerms {
    pub network: NetworkBinding,
    pub session_id: [u8; 32],
    pub direct_offer_id: [u8; 32],
    pub maker_public_key: [u8; 33],
    pub taker_public_key: [u8; 33],
    pub hashlock: [u8; 32],
    pub offered_asset: AssetId,
    pub offered_amount: u64,
    pub received_amount: u64,
    pub offered_refund_at: u64,
    pub received_refund_at: u64,
    pub offered_minimum_confirmations: u32,
    pub received_minimum_confirmations: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwapRecoveryHtlcParameters {
    pub chain: ChainId,
    pub amount: u64,
    pub hashlock: [u8; 32],
    pub receiver_public_key: [u8; 33],
    pub refund_public_key: [u8; 33],
    pub refund_at: u64,
    pub minimum_confirmations: u32,
}

impl SwapRecoveryTerms {
    pub fn from_hello(
        hello: &SwapSessionHello,
        expected_network: NetworkBinding,
    ) -> Result<Self, SwapRecoveryPublicationError> {
        hello
            .verify_agreement(expected_network)
            .map_err(|_| SwapRecoveryPublicationError::InvalidAgreement)?;
        let value = Self {
            network: expected_network,
            session_id: hello.swap_session_id,
            direct_offer_id: hello.direct_offer_id,
            maker_public_key: hello.maker_settlement_public_key,
            taker_public_key: hello.taker_settlement_public_key,
            hashlock: hello.hashlock,
            offered_asset: hello.offered_asset,
            offered_amount: u64::try_from(hello.offered_amount.get())
                .map_err(|_| SwapRecoveryPublicationError::InvalidAgreement)?,
            received_amount: u64::try_from(hello.received_amount.get())
                .map_err(|_| SwapRecoveryPublicationError::InvalidAgreement)?,
            offered_refund_at: hello.offered_refund_deadline.value,
            received_refund_at: hello.received_refund_deadline.value,
            offered_minimum_confirmations: hello.offered_minimum_confirmations,
            received_minimum_confirmations: hello.received_minimum_confirmations,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SwapRecoveryPublicationError> {
        self.network
            .validate_for_pair(MarketPair::HNS_BTC)
            .map_err(|_| SwapRecoveryPublicationError::InvalidAgreement)?;
        if self.network.counterchain != ChainId::BITCOIN
            || !matches!(self.offered_asset, AssetId::HNS | AssetId::BTC)
            || self.session_id == [0; 32]
            || self.direct_offer_id == [0; 32]
            || self.hashlock == [0; 32]
            || self.maker_public_key == self.taker_public_key
            || self.offered_amount == 0
            || self.received_amount == 0
            || self.offered_refund_at <= self.received_refund_at
            || self.received_refund_at < 500_000_000
            || self.offered_minimum_confirmations == 0
            || self.received_minimum_confirmations == 0
            || k256::PublicKey::from_sec1_bytes(&self.maker_public_key).is_err()
            || k256::PublicKey::from_sec1_bytes(&self.taker_public_key).is_err()
        {
            return Err(SwapRecoveryPublicationError::InvalidAgreement);
        }
        Ok(())
    }

    pub fn htlc(&self, side: SwapAssetSide) -> SwapRecoveryHtlcParameters {
        match side {
            SwapAssetSide::Offered => SwapRecoveryHtlcParameters {
                chain: self.offered_asset.chain(),
                amount: self.offered_amount,
                hashlock: self.hashlock,
                receiver_public_key: self.taker_public_key,
                refund_public_key: self.maker_public_key,
                refund_at: self.offered_refund_at,
                minimum_confirmations: self.offered_minimum_confirmations,
            },
            SwapAssetSide::Received => SwapRecoveryHtlcParameters {
                chain: if self.offered_asset == AssetId::HNS {
                    ChainId::BITCOIN
                } else {
                    ChainId::HANDSHAKE
                },
                amount: self.received_amount,
                hashlock: self.hashlock,
                receiver_public_key: self.maker_public_key,
                refund_public_key: self.taker_public_key,
                refund_at: self.received_refund_at,
                minimum_confirmations: self.received_minimum_confirmations,
            },
        }
    }

    fn encode(&self) -> Result<Vec<u8>, SwapRecoveryPublicationError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(TERMS_BYTES);
        bytes.extend_from_slice(&[1, u8::from(self.offered_asset == AssetId::BTC)]);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.direct_offer_id);
        bytes.extend_from_slice(&self.maker_public_key);
        bytes.extend_from_slice(&self.taker_public_key);
        bytes.extend_from_slice(&self.hashlock);
        for value in [
            self.offered_amount,
            self.received_amount,
            self.offered_refund_at,
            self.received_refund_at,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.offered_minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&self.received_minimum_confirmations.to_be_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8], network: NetworkBinding) -> Result<Self, SwapRecoveryPublicationError> {
        if bytes.len() != TERMS_BYTES || bytes[0] != 1 || bytes[1] > 1 {
            return Err(SwapRecoveryPublicationError::InvalidPublication);
        }
        let mut offset = 2;
        let value = Self {
            network,
            session_id: take(bytes, &mut offset)?,
            direct_offer_id: take(bytes, &mut offset)?,
            maker_public_key: take(bytes, &mut offset)?,
            taker_public_key: take(bytes, &mut offset)?,
            hashlock: take(bytes, &mut offset)?,
            offered_asset: if bytes[1] == 0 {
                AssetId::HNS
            } else {
                AssetId::BTC
            },
            offered_amount: u64::from_be_bytes(take(bytes, &mut offset)?),
            received_amount: u64::from_be_bytes(take(bytes, &mut offset)?),
            offered_refund_at: u64::from_be_bytes(take(bytes, &mut offset)?),
            received_refund_at: u64::from_be_bytes(take(bytes, &mut offset)?),
            offered_minimum_confirmations: u32::from_be_bytes(take(bytes, &mut offset)?),
            received_minimum_confirmations: u32::from_be_bytes(take(bytes, &mut offset)?),
        };
        value.validate()?;
        Ok(value)
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], SwapRecoveryPublicationError> {
    let end = offset
        .checked_add(N)
        .ok_or(SwapRecoveryPublicationError::InvalidPublication)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SwapRecoveryPublicationError::InvalidPublication)?
        .try_into()
        .map_err(|_| SwapRecoveryPublicationError::InvalidPublication)?;
    *offset = end;
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapRecoveryPublication {
    terms: SwapRecoveryTerms,
    side: SwapAssetSide,
    frames: Vec<Vec<u8>>,
    marker: [u8; SWAP_RECOVERY_MARKER_BYTES],
}

impl SwapRecoveryPublication {
    pub fn new(
        hello: &SwapSessionHello,
        side: SwapAssetSide,
        expected_network: NetworkBinding,
    ) -> Result<Self, SwapRecoveryPublicationError> {
        Self::from_terms(
            SwapRecoveryTerms::from_hello(hello, expected_network)?,
            side,
        )
    }

    pub fn from_terms(
        terms: SwapRecoveryTerms,
        side: SwapAssetSide,
    ) -> Result<Self, SwapRecoveryPublicationError> {
        let payload_bytes = frame_data_limit(terms.htlc(side).chain)? - FRAME_HEADER_BYTES;
        let encoded = terms.encode()?;
        let count = encoded.len().div_ceil(payload_bytes);
        if count == 0 || count > MAX_SWAP_RECOVERY_FRAMES {
            return Err(SwapRecoveryPublicationError::Capacity);
        }
        let count_byte = u8::try_from(count).map_err(|_| SwapRecoveryPublicationError::Capacity)?;
        let frames = encoded
            .chunks(payload_bytes)
            .zip(0u8..count_byte)
            .map(|(payload, index)| {
                let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
                frame.extend_from_slice(&FRAME_MAGIC);
                frame.push(index);
                frame.push(count_byte);
                frame.extend_from_slice(payload);
                frame
            })
            .collect();
        let mut marker = [0; SWAP_RECOVERY_MARKER_BYTES];
        marker[..4].copy_from_slice(&MARKER_MAGIC);
        marker[4] = side_code(side);
        marker[5..].copy_from_slice(&commitment(&encoded, side, terms.network)?);
        Ok(Self {
            terms,
            side,
            frames,
            marker,
        })
    }

    /// Decode data extracted from an ordered transaction ancestor chain.
    /// Callers must additionally verify the transactions, their ancestry, and
    /// the exact funded output against independently authenticated chain data.
    pub fn decode(
        expected_network: NetworkBinding,
        expected_chain: ChainId,
        marker: &[u8],
        frames: &[Vec<u8>],
    ) -> Result<Self, SwapRecoveryPublicationError> {
        let limit = frame_data_limit(expected_chain)?;
        if marker.len() != SWAP_RECOVERY_MARKER_BYTES
            || marker[..4] != MARKER_MAGIC
            || frames.is_empty()
            || frames.len() > MAX_SWAP_RECOVERY_FRAMES
        {
            return Err(SwapRecoveryPublicationError::InvalidPublication);
        }
        let side = match marker[4] {
            0 => SwapAssetSide::Offered,
            1 => SwapAssetSide::Received,
            _ => return Err(SwapRecoveryPublicationError::InvalidPublication),
        };
        let mut encoded = Vec::with_capacity(frames.len() * (limit - FRAME_HEADER_BYTES));
        for (index, frame) in frames.iter().enumerate() {
            if frame.len() <= FRAME_HEADER_BYTES
                || frame.len() > limit
                || frame[..2] != FRAME_MAGIC
                || usize::from(frame[2]) != index
                || usize::from(frame[3]) != frames.len()
                || (index + 1 < frames.len() && frame.len() != limit)
            {
                return Err(SwapRecoveryPublicationError::InvalidPublication);
            }
            encoded.extend_from_slice(&frame[FRAME_HEADER_BYTES..]);
        }
        if marker[5..] != commitment(&encoded, side, expected_network)? {
            return Err(SwapRecoveryPublicationError::InvalidPublication);
        }
        let terms = SwapRecoveryTerms::decode(&encoded, expected_network)?;
        let publication = Self::from_terms(terms, side)?;
        if publication.chain() != expected_chain
            || publication.marker.as_slice() != marker
            || publication.frames != frames
        {
            return Err(SwapRecoveryPublicationError::InvalidPublication);
        }
        Ok(publication)
    }

    pub fn terms(&self) -> &SwapRecoveryTerms {
        &self.terms
    }
    pub const fn side(&self) -> SwapAssetSide {
        self.side
    }
    pub fn chain(&self) -> ChainId {
        self.terms.htlc(self.side).chain
    }
    pub fn frames(&self) -> &[Vec<u8>] {
        &self.frames
    }
    pub const fn marker(&self) -> &[u8; SWAP_RECOVERY_MARKER_BYTES] {
        &self.marker
    }
}

fn frame_data_limit(chain: ChainId) -> Result<usize, SwapRecoveryPublicationError> {
    match chain {
        ChainId::BITCOIN => Ok(80),
        ChainId::HANDSHAKE => Ok(40),
        _ => Err(SwapRecoveryPublicationError::UnsupportedChain),
    }
}
const fn side_code(side: SwapAssetSide) -> u8 {
    match side {
        SwapAssetSide::Offered => 0,
        SwapAssetSide::Received => 1,
    }
}
fn commitment(
    encoded: &[u8],
    side: SwapAssetSide,
    network: NetworkBinding,
) -> Result<[u8; 32], SwapRecoveryPublicationError> {
    let mut hash = Sha256::new();
    hash.update(COMMITMENT_DOMAIN);
    hash.update([side_code(side)]);
    hash.update(
        network
            .encode()
            .map_err(|_| SwapRecoveryPublicationError::InvalidAgreement)?,
    );
    hash.update(encoded);
    Ok(hash.finalize().into())
}
