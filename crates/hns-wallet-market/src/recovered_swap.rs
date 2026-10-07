//! Settlement-only recovery candidates. They cannot authorize fresh funding or
//! replace jointly signed offers. Each chain runtime re-verifies their exact
//! funded output, unspentness and maturity before any approval can be signed.
use super::*;
use crate::{CrossChainSwapKeyError, SwapParticipant, recover_cross_chain_swap_key_allocation};
use hns_marketplace_protocol::NetworkBinding;
use hns_wallet_chain_api::{SwapRecoveryPublication, SwapRecoveryTerms};
use hns_wallet_types::TransactionHash;

const PREFIX: &[u8] = b"shakescape/recovered-settlement/v1\0";
const MAX_RECOVERED_SWAPS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveredSwapSettlement {
    pub transaction: TransactionHash,
    pub state: SwapState,
    pub verified_at_unix: u64,
    pub current: bool,
}

fn settlement_id(
    wallet_id: WalletId,
    session_id: SessionId,
    module: ModuleId,
) -> Result<Vec<u8>, MarketError> {
    let mut id = b"shakescape/recovered-spend/v1\0".to_vec();
    id.extend_from_slice(wallet_id.as_bytes());
    id.extend_from_slice(session_id.as_bytes());
    id.push(match module {
        ModuleId::Handshake => 0,
        ModuleId::Bitcoin => 1,
        _ => return Err(MarketError::InvalidPair),
    });
    Ok(id)
}

pub fn load_recovered_swap_settlement(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    module: ModuleId,
) -> Result<Option<RecoveredSwapSettlement>, MarketError> {
    Ok(store
        .load_entity::<RecoveredSwapSettlement>(
            EntityKind::SwapSession,
            &settlement_id(wallet_id, session_id, module)?,
        )?
        .map(|row| row.value)
        .filter(|record| record.current))
}

/// Retain the previous observation while revoking its current-chain status.
pub fn invalidate_recovered_swap_settlement(
    store: &mut WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    module: ModuleId,
    now_unix: u64,
) -> Result<(), MarketError> {
    if now_unix == 0 {
        return Err(MarketError::InvalidEvidence);
    }
    let id = settlement_id(wallet_id, session_id, module)?;
    if let Some(mut row) =
        store.load_entity::<RecoveredSwapSettlement>(EntityKind::SwapSession, &id)?
        && row.value.current
    {
        row.value.current = false;
        store.save_entity(
            EntityKind::SwapSession,
            &id,
            row.revision,
            &row.value,
            now_unix,
        )?;
    }
    Ok(())
}

/// Called only after the native chain runtime verifies the exact contract spend.
pub fn apply_recovered_swap_spend(
    store: &mut WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    network: NetworkBinding,
    spend: LocallyVerifiedSwapSpend,
    now_unix: u64,
) -> Result<SwapState, MarketError> {
    let candidate = load_recovered_swap_candidate(store, wallet_id, session_id, network)?
        .ok_or(MarketError::UnknownShakescapeDirectSwap)?;
    let publication = candidate.publication(network)?;
    let (module, chain, transaction, confirmations, refund, preimage) = match spend {
        LocallyVerifiedSwapSpend::Hns(hns_wallet_hns::VerifiedNativeHtlcSpend::Refund {
            transaction,
            confirmation_count,
        }) => (
            ModuleId::Handshake,
            ChainId::HANDSHAKE,
            transaction,
            confirmation_count,
            true,
            None,
        ),
        LocallyVerifiedSwapSpend::Hns(hns_wallet_hns::VerifiedNativeHtlcSpend::Redeem {
            transaction,
            confirmation_count,
            preimage,
        }) => (
            ModuleId::Handshake,
            ChainId::HANDSHAKE,
            transaction,
            confirmation_count,
            false,
            Some(*preimage.expose_for_settlement()),
        ),
        LocallyVerifiedSwapSpend::Bitcoin(observation) => (
            ModuleId::Bitcoin,
            ChainId::BITCOIN,
            observation.spend.txid,
            observation.confirmation_count,
            observation.spend.branch == hns_wallet_bitcoin_kyoto::HtlcSpendBranch::Refund,
            observation.spend.revealed_preimage,
        ),
    };
    let side = if publication.terms().offered_asset.chain() == chain {
        SwapAssetSide::Offered
    } else {
        SwapAssetSide::Received
    };
    let parameters = publication.terms().htlc(side);
    if confirmations < parameters.minimum_confirmations
        || now_unix == 0
        || transaction.into_bytes() == [0; 32]
    {
        return Err(MarketError::InvalidEvidence);
    }
    if !refund {
        let preimage = preimage.ok_or(MarketError::InvalidEvidence)?;
        if Sha256::digest(preimage).as_slice() != parameters.hashlock {
            return Err(MarketError::InvalidEvidence);
        }
    }
    let state = if refund {
        SwapState::Refunded
    } else if side == publication.side() && candidate.participant == SwapParticipant::Taker {
        SwapState::SecretObserved
    } else {
        SwapState::FirstRedeemed
    };
    let id = settlement_id(wallet_id, session_id, module)?;
    let existing = store.load_entity::<RecoveredSwapSettlement>(EntityKind::SwapSession, &id)?;
    if existing.as_ref().is_some_and(|row| {
        row.value.current && row.value.transaction == transaction && row.value.state == state
    }) {
        return Ok(state);
    }
    let revision = existing.map_or(0, |row| row.revision);
    if !refund {
        let preimage = preimage.ok_or(MarketError::InvalidEvidence)?;
        // This is a public preimage independently observed by the native chain
        // runtime, not authority to expose a newly derived maker secret.
        store.put_secret(
            &shakescape_observed_preimage_id(session_id),
            SecretKind::HtlcPreimage,
            &preimage,
            now_unix,
        )?;
    }
    store.save_entity(
        EntityKind::SwapSession,
        &id,
        revision,
        &RecoveredSwapSettlement {
            transaction,
            state,
            verified_at_unix: now_unix,
            current: true,
        },
        now_unix,
    )?;
    Ok(state)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveredSwapCandidate {
    pub wallet_id: WalletId,
    pub session_id: SessionId,
    pub participant: SwapParticipant,
    pub funding_transaction: TransactionHash,
    pub output_index: u32,
    network_encoding: Vec<u8>,
    chain: u16,
    marker: Vec<u8>,
    frames: Vec<Vec<u8>>,
}

impl RecoveredSwapCandidate {
    pub fn publication(
        &self,
        expected_network: NetworkBinding,
    ) -> Result<SwapRecoveryPublication, MarketError> {
        if self.network_encoding
            != expected_network
                .encode()
                .map_err(|_| MarketError::InvalidEvidence)?
        {
            return Err(MarketError::InvalidEvidence);
        }
        let chain = match self.chain {
            0 => ChainId::HANDSHAKE,
            1 => ChainId::BITCOIN,
            _ => return Err(MarketError::InvalidEvidence),
        };
        let publication =
            SwapRecoveryPublication::decode(expected_network, chain, &self.marker, &self.frames)
                .map_err(|_| MarketError::InvalidEvidence)?;
        let expected_side = match self.participant {
            SwapParticipant::Maker => SwapAssetSide::Offered,
            SwapParticipant::Taker => SwapAssetSide::Received,
        };
        if publication.side() != expected_side
            || publication.terms().session_id != self.session_id.into_bytes()
            || self.funding_transaction.into_bytes() == [0; 32]
        {
            return Err(MarketError::InvalidEvidence);
        }
        Ok(publication)
    }
}

fn prefix(wallet_id: WalletId) -> Vec<u8> {
    let mut id = PREFIX.to_vec();
    id.extend_from_slice(wallet_id.as_bytes());
    id
}
fn id(wallet_id: WalletId, session_id: SessionId) -> Vec<u8> {
    let mut id = prefix(wallet_id);
    id.extend_from_slice(session_id.as_bytes());
    id
}

/// Match a structurally reconstructed chain contract to the restored seed and
/// retain its exact locator for independent settlement verification. A wrong
/// seed is an unrelated candidate, not an error that can interrupt wallet sync.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit seed authority, public terms, chain locator and time"
)]
pub fn retain_recovered_swap_candidate(
    store: &mut WalletStore,
    wallet_id: WalletId,
    terms: &SwapRecoveryTerms,
    side: SwapAssetSide,
    funding_transaction: TransactionHash,
    output_index: u32,
    expected_network: NetworkBinding,
    now_unix: u64,
) -> Result<Option<RecoveredSwapCandidate>, MarketError> {
    let allocation = match recover_cross_chain_swap_key_allocation(
        store,
        wallet_id,
        terms,
        expected_network,
        now_unix,
    ) {
        Ok(allocation) => allocation,
        Err(CrossChainSwapKeyError::WrongParticipant) => return Ok(None),
        Err(CrossChainSwapKeyError::Store(error)) => return Err(error.into()),
        Err(_) => return Err(MarketError::InvalidEvidence),
    };
    let own_side = match allocation.participant() {
        SwapParticipant::Maker => SwapAssetSide::Offered,
        SwapParticipant::Taker => SwapAssetSide::Received,
    };
    if side != own_side {
        return Ok(None);
    }
    let publication = SwapRecoveryPublication::from_terms(terms.clone(), side)
        .map_err(|_| MarketError::InvalidEvidence)?;
    let candidate = RecoveredSwapCandidate {
        wallet_id,
        session_id: SessionId::new(terms.session_id),
        participant: allocation.participant(),
        funding_transaction,
        output_index,
        network_encoding: expected_network
            .encode()
            .map_err(|_| MarketError::InvalidEvidence)?,
        chain: if publication.chain() == ChainId::HANDSHAKE {
            0
        } else {
            1
        },
        marker: publication.marker().to_vec(),
        frames: publication.frames().to_vec(),
    };
    candidate.publication(expected_network)?;
    let entity_id = id(wallet_id, candidate.session_id);
    if let Some(existing) =
        store.load_entity::<RecoveredSwapCandidate>(EntityKind::SwapSession, &entity_id)?
    {
        if existing.value != candidate {
            return Err(MarketError::InvalidEvidence);
        }
        return Ok(Some(existing.value));
    }
    if list_recovered_swap_candidates(store, wallet_id, expected_network)?.len()
        >= MAX_RECOVERED_SWAPS
    {
        return Err(MarketError::InvalidEvidence);
    }
    if allocation.participant() == SwapParticipant::Maker {
        let preimage = crate::direct_offer::derive_maker_preimage(
            store,
            wallet_id,
            candidate.session_id,
            terms.direct_offer_id,
        )?;
        if Sha256::digest(preimage.expose_for_settlement()).as_slice() == terms.hashlock {
            store.put_secret(
                &crate::direct_offer::maker_preimage_record_id(candidate.session_id),
                SecretKind::HtlcPreimage,
                preimage.expose_for_settlement(),
                now_unix,
            )?;
        }
    }
    store.save_entity(EntityKind::SwapSession, &entity_id, 0, &candidate, now_unix)?;
    Ok(Some(candidate))
}

pub fn load_recovered_swap_candidate(
    store: &WalletStore,
    wallet_id: WalletId,
    session_id: SessionId,
    expected_network: NetworkBinding,
) -> Result<Option<RecoveredSwapCandidate>, MarketError> {
    store
        .load_entity::<RecoveredSwapCandidate>(EntityKind::SwapSession, &id(wallet_id, session_id))?
        .map(|row| {
            if row.value.wallet_id != wallet_id || row.value.session_id != session_id {
                return Err(MarketError::InvalidEvidence);
            }
            row.value.publication(expected_network)?;
            Ok(row.value)
        })
        .transpose()
}

pub fn list_recovered_swap_candidates(
    store: &WalletStore,
    wallet_id: WalletId,
    expected_network: NetworkBinding,
) -> Result<Vec<RecoveredSwapCandidate>, MarketError> {
    let rows = store.list_entities_by_id_prefix::<RecoveredSwapCandidate>(
        EntityKind::SwapSession,
        &prefix(wallet_id),
        MAX_RECOVERED_SWAPS + 1,
    )?;
    if rows.len() > MAX_RECOVERED_SWAPS {
        return Err(MarketError::InvalidEvidence);
    }
    rows.into_iter()
        .map(|row| {
            if row.id != id(wallet_id, row.value.session_id) || row.value.wallet_id != wallet_id {
                return Err(MarketError::InvalidEvidence);
            }
            row.value.publication(expected_network)?;
            Ok(row.value)
        })
        .collect()
}
