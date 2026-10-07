//! Standard single-null-data HNS publication ancestors for seed-only recovery.
use super::*;
use hns_marketplace_protocol::{ChainId, SwapAssetSide};
use hns_wallet_chain_api::{SwapRecoveryPublication, SwapRecoveryTerms};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct HnsRecoveryAncestor {
    pub raw: Vec<u8>,
    pub inputs: Vec<HnsInputCoinEvidence>,
    pub fee: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct HnsRecoveryPackage {
    pub network_encoding: Vec<u8>,
    pub ancestors: Vec<HnsRecoveryAncestor>,
}

/// Publication parents are not confirmed coins. Height zero is used only as
/// the canonical signing/fee-policy container's placeholder; the serialized
/// evidence retains `None`. These coins must never establish chain maturity.
/// Callers validate each exact parent output through the complete package.
pub(crate) fn canonical_package_inputs(
    inputs: &[HnsInputCoinEvidence],
) -> Result<Vec<Coin>, HnsWalletError> {
    if inputs.is_empty() || inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    inputs
        .iter()
        .map(|input| {
            if input.confirmed_height.is_some() {
                return input.to_canonical_coin();
            }
            let covenant = decode_canonical_covenant(&input.covenant)?;
            if input.coinbase
                || input.address_version != 0
                || input.address_hash.len() != 20
                || covenant != Covenant::default()
                || input.value.is_zero()
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            canonical_coin_from_evidence(
                input.outpoint,
                input.value,
                Some(0),
                false,
                input.address_version,
                input.address_hash.clone(),
                covenant,
            )
        })
        .collect()
}

pub(crate) fn validate_prepared_publication(
    prepared: &HnsPreparedSettlement,
) -> Result<(), HnsWalletError> {
    let Some(package) = &prepared.recovery_publication else {
        return Ok(());
    };
    let network = hns_marketplace_protocol::NetworkBinding::decode(&package.network_encoding)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let raws = package
        .ancestors
        .iter()
        .map(|ancestor| ancestor.raw.clone())
        .collect::<Vec<_>>();
    let recovered =
        recover_hns_contract_from_ancestors(network, &prepared.signed_transaction, &raws)?;
    let HnsSettlementTerms::Lock { request } = &prepared.terms else {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    };
    let descriptor = recovered.descriptor;
    if recovered.terms.session_id != prepared.session_id.into_bytes()
        || request.hashlock.into_bytes() != descriptor.hashlock
        || request.amount.base_units.get() != u128::from(descriptor.value.get())
        || request.absolute_timelock != u64::from(descriptor.refund_locktime)
        || request.receiver != hex::encode(descriptor.receiver_public_key)
        || request.refund_target != hex::encode(descriptor.refund_public_key)
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    for (index, ancestor) in package.ancestors.iter().enumerate() {
        let tx = Transaction::decode(&ancestor.raw)
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if index == 0
            && ancestor
                .inputs
                .iter()
                .any(|input| input.confirmed_height.is_none())
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let coins = canonical_package_inputs(&ancestor.inputs)?;
        validate_standard_input_authorizations(&tx, &coins)?;
        if actual_transaction_fee(&tx, &coins)? != ancestor.fee {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let child_inputs = package
            .ancestors
            .get(index + 1)
            .map_or(&prepared.input_coins, |next| &next.inputs);
        if child_inputs.len() != 1 {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let evidence = &child_inputs[0];
        let output = tx
            .outputs
            .get(evidence.outpoint.output_index as usize)
            .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        if evidence.outpoint.transaction != wallet_transaction_hash(&tx)?
            || evidence.value.get() != u128::from(output.value.get())
            || evidence.address_version != output.address.version
            || evidence.address_hash != output.address.hash
            || evidence.covenant
                != output
                    .covenant
                    .encode()
                    .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
            || evidence.coinbase
            || evidence.confirmed_height.is_some()
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
    }
    if prepared.approved_fee()? > prepared.maximum_fee {
        return Err(HnsWalletError::FeeLimit);
    }
    Ok(())
}

pub struct HnsRecoverableFundingPlan {
    pub(crate) raw: Vec<u8>,
    pub(crate) inputs: Vec<HnsInputCoinEvidence>,
    pub(crate) initial_inputs: Vec<TrackedHnsCoin>,
    pub(crate) fee: BaseUnits,
    pub(crate) ancestors: Vec<HnsRecoveryAncestor>,
}

impl HnsRecoverableFundingPlan {
    pub fn funding_transaction(&self) -> &[u8] {
        &self.raw
    }
    pub fn publication_transactions(&self) -> impl Iterator<Item = &[u8]> {
        self.ancestors
            .iter()
            .map(|ancestor| ancestor.raw.as_slice())
    }
}

/// Structural match only. The runtime must verify inclusion, current unspent
/// output and maturity independently before permitting a settlement spend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsRecoveryContract {
    pub terms: SwapRecoveryTerms,
    pub side: SwapAssetSide,
    pub descriptor: HnsHtlc,
    pub funding_id: TransactionHash,
    pub output_index: u32,
    pub publication_anchor_program: Vec<u8>,
}

/// Ordinary internal address zero is discoverable after restoring only the seed.
pub fn hns_recovery_anchor_program(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
) -> Result<Vec<u8>, HnsWalletError> {
    let mut config = config.clone();
    config.value_operations_enabled = false;
    config.settlement_enabled = false;
    let account = HnsAccountRecord::initial_non_value(config)?;
    let reference = DerivationReference {
        role: KeyRole::HnsCoin,
        account: account_number(&account),
        change: 1,
        index: 0,
    };
    let public = derive_hns_account_public_key(store, &account, reference)?;
    Ok(public_key_hash(&public)?.to_vec())
}

pub fn build_recovered_hns_htlc(
    terms: &SwapRecoveryTerms,
    side: SwapAssetSide,
) -> Result<HnsHtlc, HnsWalletError> {
    terms
        .validate()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let params = terms.htlc(side);
    if params.chain != ChainId::HANDSHAKE {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let descriptor = HnsHtlc {
        network: NetworkBinding {
            magic: terms.network.hns_magic,
            genesis: terms.network.hns_genesis,
        },
        value: Dollarydoos::new(params.amount),
        hashlock: params.hashlock,
        receiver_public_key: params.receiver_public_key,
        refund_public_key: params.refund_public_key,
        refund_locktime: hns_swap::encode_time_lock_not_before(params.refund_at)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .encoded,
    };
    descriptor
        .validate()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    Ok(descriptor)
}

fn data(tx: &Transaction) -> Result<Vec<u8>, HnsWalletError> {
    let mut found = None;
    for output in &tx.outputs {
        if output.address.version != 31 {
            continue;
        }
        if found.is_some()
            || output.value.get() != 0
            || output.covenant != Covenant::default()
            || output.address.hash.len() > 40
            || output.address.hash.len() < 2
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        found = Some(output.address.hash.clone());
    }
    found.ok_or(HnsWalletError::InvalidEvidence)
}

pub fn discover_hns_recovery_contracts(
    expected_network: hns_marketplace_protocol::NetworkBinding,
    transactions: &[Vec<u8>],
) -> Result<Vec<HnsRecoveryContract>, HnsWalletError> {
    if transactions.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let mut graph = BTreeMap::new();
    for raw in transactions {
        let tx = Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
        graph.insert(wallet_transaction_hash(&tx)?, tx);
    }
    let mut contracts = Vec::new();
    for funding in graph.values() {
        let Ok(marker) = data(funding) else {
            continue;
        };
        if marker.len() != hns_wallet_chain_api::SWAP_RECOVERY_MARKER_BYTES
            || !marker.starts_with(b"SRF1")
        {
            continue;
        }
        let mut child = funding;
        let mut ancestors = Vec::new();
        for _ in 0..hns_wallet_chain_api::MAX_SWAP_RECOVERY_FRAMES {
            if child.inputs.len() != 1 {
                break;
            }
            let id = TransactionHash::new(
                child.inputs[0]
                    .previous_output
                    .transaction_hash
                    .into_bytes(),
            );
            let Some(parent) = graph.get(&id) else {
                break;
            };
            let Ok(frame) = data(parent) else {
                break;
            };
            if frame.len() < 4 || !frame.starts_with(b"SR") {
                break;
            }
            ancestors.push(
                parent
                    .encode()
                    .map_err(|_| HnsWalletError::InvalidEvidence)?,
            );
            if frame[2] == 0 {
                break;
            }
            child = parent;
        }
        ancestors.reverse();
        let raw = funding
            .encode()
            .map_err(|_| HnsWalletError::InvalidEvidence)?;
        if let Ok(contract) =
            recover_hns_contract_from_ancestors(expected_network, &raw, &ancestors)
        {
            contracts.push(contract);
        }
    }
    Ok(contracts)
}

pub fn recover_hns_contract_from_ancestors(
    expected_network: hns_marketplace_protocol::NetworkBinding,
    funding_raw: &[u8],
    ancestor_raws: &[Vec<u8>],
) -> Result<HnsRecoveryContract, HnsWalletError> {
    if ancestor_raws.is_empty()
        || ancestor_raws.len() > hns_wallet_chain_api::MAX_SWAP_RECOVERY_FRAMES
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let funding = Transaction::decode(funding_raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let ancestors = ancestor_raws
        .iter()
        .map(|raw| {
            let tx = Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
            if tx.is_coinbase() || tx.inputs.is_empty() {
                return Err(HnsWalletError::InvalidEvidence);
            }
            Ok(tx)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let frames = ancestors.iter().map(data).collect::<Result<Vec<_>, _>>()?;
    let mut publication_anchor_program = None;
    for (parent, child) in ancestors
        .iter()
        .zip(ancestors.iter().skip(1).chain(std::iter::once(&funding)))
    {
        if child.inputs.len() != 1
            || child.inputs[0].previous_output.transaction_hash
                != parent
                    .transaction_hash()
                    .map_err(|_| HnsWalletError::InvalidEvidence)?
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let output = parent
            .outputs
            .get(child.inputs[0].previous_output.index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if output.address.version != 0
            || output.address.hash.len() != 20
            || output.value.get() == 0
            || output.covenant != Covenant::default()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        // Authenticate every child with the exact parent's ordinary wallet
        // coin. Height zero is only a signing container, never chain maturity.
        let coin = Coin {
            outpoint: child.inputs[0].previous_output,
            value: output.value,
            height: Height::new(0),
            coinbase: false,
            address: output.address.clone(),
            covenant: output.covenant.clone(),
        };
        validate_standard_input_authorizations(child, &[coin])?;
        if publication_anchor_program
            .as_ref()
            .is_some_and(|program| program != &output.address.hash)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        publication_anchor_program = Some(output.address.hash.clone());
    }
    let publication = SwapRecoveryPublication::decode(
        expected_network,
        ChainId::HANDSHAKE,
        &data(&funding)?,
        &frames,
    )
    .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let descriptor = build_recovered_hns_htlc(publication.terms(), publication.side())?;
    let output = descriptor
        .funding_output()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    let mut matches = funding
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, candidate)| **candidate == output);
    let (index, _) = matches.next().ok_or(HnsWalletError::InvalidEvidence)?;
    if matches.next().is_some() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(HnsRecoveryContract {
        terms: publication.terms().clone(),
        side: publication.side(),
        descriptor,
        funding_id: wallet_transaction_hash(&funding)?,
        output_index: index as u32,
        publication_anchor_program: publication_anchor_program
            .ok_or(HnsWalletError::InvalidEvidence)?,
    })
}

fn sign_owned_inputs(
    store: &WalletStore,
    account: &HnsAccountRecord,
    mut tx: Transaction,
    inputs: &[HnsInputCoinEvidence],
    derivations: &[DerivationReference],
) -> Result<Vec<u8>, HnsWalletError> {
    if tx.inputs.len() != inputs.len() || inputs.len() != derivations.len() || inputs.is_empty() {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    let canonical = canonical_package_inputs(inputs)?;
    for (index, (coin, derivation)) in canonical.iter().zip(derivations).enumerate() {
        if derivation.role != KeyRole::HnsCoin
            || derivation.account != account_number(account)
            || coin.address.version != 0
            || coin.address.hash.len() != 20
            || coin.covenant != Covenant::default()
            || tx.inputs[index].previous_output != coin.outpoint
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let secret = derive_account_secret(&seed, account.config.network, *derivation)?;
        let key =
            SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
        let public = key.verifying_key().to_encoded_point(true);
        let public_bytes: [u8; 33] = public
            .as_bytes()
            .try_into()
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if public_key_hash(&public_bytes)?.as_slice() != coin.address.hash {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let digest = signature_hash(
            &tx,
            index,
            &p2pkh_script(&coin.address.hash)?,
            coin.value.get(),
            SIGHASH_ALL,
        )
        .map_err(|_| HnsWalletError::Signing)?;
        let signature: Signature = key
            .sign_prehash(&digest)
            .map_err(|_| HnsWalletError::Signing)?;
        let mut signature = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec();
        signature.push(SIGHASH_ALL as u8);
        tx.inputs[index].witness.items = vec![signature, public.as_bytes().to_vec()];
    }
    validate_standard_input_authorizations(&tx, &canonical)?;
    tx.encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact account, public agreement and total fee boundary"
)]
pub fn prepare_hns_recoverable_funding(
    store: &WalletStore,
    account: &HnsAccountRecord,
    coins: Vec<TrackedHnsCoin>,
    publication: &SwapRecoveryPublication,
    fee_rate: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<HnsRecoverableFundingPlan, HnsWalletError> {
    let network = direct_shakescape_network_binding(account.config.network)?;
    if publication.chain() != ChainId::HANDSHAKE
        || publication.terms().network.hns_magic != network.magic
        || publication.terms().network.hns_genesis != network.genesis
        || maximum_fee.is_zero()
        || fee_rate.is_zero()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let descriptor = build_recovered_hns_htlc(publication.terms(), publication.side())?;
    let required = u128::from(descriptor.value.get())
        .checked_add(maximum_fee.get())
        .and_then(|value| value.checked_add(account.config.dust_threshold.get()))
        .ok_or(HnsWalletError::Arithmetic)?;
    let mut initial_inputs = Vec::new();
    let mut total = 0u128;
    for coin in coins
        .into_iter()
        .filter(is_confirmed_ordinary_hns_spend_candidate)
    {
        total = total
            .checked_add(coin.coin.value.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        initial_inputs.push(coin);
        if total >= required {
            break;
        }
    }
    if total < required {
        return Err(HnsWalletError::InsufficientFunds);
    }
    let anchor_derivation = DerivationReference {
        role: KeyRole::HnsCoin,
        account: account_number(account),
        change: 1,
        index: 0,
    };
    let anchor_public = derive_hns_account_public_key(store, account, anchor_derivation)?;
    let anchor = Address::new(0, public_key_hash(&anchor_public)?.to_vec())
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let mut inputs = input_coin_evidence(&initial_inputs)?;
    let mut derivations = initial_inputs
        .iter()
        .map(|coin| coin.derivation)
        .collect::<Vec<_>>();
    let mut ancestors = Vec::new();
    let mut aggregate_fee = 0u128;
    for (index, payload) in publication
        .frames()
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(publication.marker().as_slice()))
        .enumerate()
    {
        let final_funding = index == publication.frames().len();
        let coins = canonical_package_inputs(&inputs)?;
        let mut outputs = Vec::new();
        if final_funding {
            outputs.push(
                descriptor
                    .funding_output()
                    .map_err(|_| HnsWalletError::InvalidEvidence)?,
            );
        }
        let anchor_index = outputs.len();
        outputs.push(Output {
            value: Dollarydoos::new(1),
            address: anchor.clone(),
            covenant: Covenant::default(),
        });
        outputs.push(Output {
            value: Dollarydoos::new(0),
            address: Address::new(31, payload.to_vec())
                .map_err(|_| HnsWalletError::InvalidEvidence)?,
            covenant: Covenant::default(),
        });
        let mut tx = Transaction {
            version: 0,
            locktime: 0,
            outputs,
            inputs: coins
                .iter()
                .map(|coin| Input {
                    previous_output: coin.outpoint,
                    sequence: u32::MAX,
                    witness: Witness {
                        items: vec![vec![0; 65], vec![0; 33]],
                    },
                })
                .collect(),
        };
        let fee = canonical_policy_minimum_fee(&tx, &coins, fee_rate)?;
        aggregate_fee = aggregate_fee
            .checked_add(fee.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        if aggregate_fee > maximum_fee.get() {
            return Err(HnsWalletError::FeeLimit);
        }
        let locked = if final_funding {
            u128::from(descriptor.value.get())
        } else {
            0
        };
        let anchor_value = total
            .checked_sub(fee.get())
            .and_then(|value| value.checked_sub(locked))
            .ok_or(HnsWalletError::InsufficientFunds)?;
        if anchor_value < account.config.dust_threshold.get() {
            return Err(HnsWalletError::InsufficientFunds);
        }
        tx.outputs[anchor_index].value =
            Dollarydoos::new(u64::try_from(anchor_value).map_err(|_| HnsWalletError::Arithmetic)?);
        let raw = sign_owned_inputs(store, account, tx, &inputs, &derivations)?;
        if final_funding {
            let raws = ancestors
                .iter()
                .map(|ancestor: &HnsRecoveryAncestor| ancestor.raw.clone())
                .collect::<Vec<_>>();
            recover_hns_contract_from_ancestors(publication.terms().network, &raw, &raws)?;
            return Ok(HnsRecoverableFundingPlan {
                raw,
                inputs,
                initial_inputs,
                fee,
                ancestors,
            });
        }
        let tx = Transaction::decode(&raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
        let txid = wallet_transaction_hash(&tx)?;
        ancestors.push(HnsRecoveryAncestor { raw, inputs, fee });
        inputs = vec![HnsInputCoinEvidence {
            outpoint: HnsOutpoint {
                transaction: txid,
                output_index: anchor_index as u32,
            },
            value: BaseUnits::new(anchor_value),
            confirmed_height: None,
            coinbase: false,
            address_version: 0,
            address_hash: anchor.hash.clone(),
            covenant: Covenant::default()
                .encode()
                .map_err(|_| HnsWalletError::InvalidEvidence)?,
        }];
        derivations = vec![anchor_derivation];
        total = anchor_value;
    }
    Err(HnsWalletError::InvalidPreparedArtifact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_marketplace_protocol::AssetId;

    fn public_key(byte: u8) -> [u8; 33] {
        SigningKey::from_slice(&[byte; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn fixture(
        side: SwapAssetSide,
    ) -> (
        WalletStore,
        HnsAccountRecord,
        TrackedHnsCoin,
        SwapRecoveryPublication,
    ) {
        let config = HnsRuntimeConfig::default_non_value(
            WalletId::new([7; 16]),
            AccountId::new([8; 16]),
            HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0),
        )
        .unwrap();
        let account = HnsAccountRecord::initial_non_value(config).unwrap();
        let mut store = WalletStore::create(":memory:", "hns-publication-test").unwrap();
        store
            .put_secret(
                account.config.wallet_id.as_bytes(),
                SecretKind::RecoverySeed,
                &[7; 64],
                1,
            )
            .unwrap();
        let derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: 0,
            change: 0,
            index: 0,
        };
        let public = derive_hns_account_public_key(&store, &account, derivation).unwrap();
        let coin = TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([9; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(1_000_000),
                confirmation_count: 2,
                confirmed_height: Some(1),
                coinbase: false,
                covenant: Covenant::default().encode().unwrap(),
                name_locked: false,
            },
            derivation,
            address_program: public_key_hash(&public).unwrap().to_vec(),
        };
        let hns_network = direct_shakescape_network_binding(account.config.network).unwrap();
        let terms = SwapRecoveryTerms {
            network: hns_marketplace_protocol::NetworkBinding {
                hns_magic: hns_network.magic,
                hns_genesis: hns_network.genesis,
                counterchain: ChainId::BITCOIN,
                counterchain_network: 3,
                counterchain_genesis: [2; 32],
            },
            session_id: [1; 32],
            direct_offer_id: [2; 32],
            maker_public_key: public_key(3),
            taker_public_key: public_key(4),
            hashlock: [5; 32],
            offered_asset: if side == SwapAssetSide::Offered {
                AssetId::HNS
            } else {
                AssetId::BTC
            },
            offered_amount: 50_000,
            received_amount: 50_000,
            offered_refund_at: 1_800_010_000,
            received_refund_at: 1_800_000_000,
            offered_minimum_confirmations: 2,
            received_minimum_confirmations: 2,
        };
        (
            store,
            account,
            coin,
            SwapRecoveryPublication::from_terms(terms, side).unwrap(),
        )
    }

    #[test]
    fn hns_funding_publishes_recoverable_ancestors_for_both_offer_directions() {
        for side in [SwapAssetSide::Offered, SwapAssetSide::Received] {
            let (store, account, coin, publication) = fixture(side);
            let package = prepare_hns_recoverable_funding(
                &store,
                &account,
                vec![coin],
                &publication,
                BaseUnits::new(1_000),
                BaseUnits::new(10_000),
            )
            .unwrap();
            assert_eq!(package.ancestors.len(), 6);
            let mut total_fee = package.fee.get();
            let anchor_derivation = DerivationReference {
                role: KeyRole::HnsCoin,
                account: 0,
                change: 1,
                index: 0,
            };
            let mut restored = WalletStore::create(":memory:", "fresh-seed-only").unwrap();
            restored
                .put_secret(
                    account.config.wallet_id.as_bytes(),
                    SecretKind::RecoverySeed,
                    &[7; 64],
                    1,
                )
                .unwrap();
            let recovered_public =
                derive_hns_account_public_key(&restored, &account, anchor_derivation).unwrap();
            for ancestor in &package.ancestors {
                total_fee += ancestor.fee.get();
                let tx = Transaction::decode(&ancestor.raw).unwrap();
                assert_eq!(
                    tx.outputs
                        .iter()
                        .filter(|output| output.address.version == 31)
                        .count(),
                    1
                );
                assert!(
                    tx.outputs
                        .iter()
                        .all(|output| output.address.version == 31
                            || output.address.hash.len() == 20)
                );
                assert_eq!(
                    tx.outputs[0].address.hash,
                    public_key_hash(&recovered_public).unwrap()
                );
                validate_standard_input_authorizations(
                    &tx,
                    &canonical_package_inputs(&ancestor.inputs).unwrap(),
                )
                .unwrap();
            }
            assert!(total_fee <= 10_000);
            let raws = package
                .ancestors
                .iter()
                .map(|ancestor| ancestor.raw.clone())
                .collect::<Vec<_>>();
            let recovered = recover_hns_contract_from_ancestors(
                publication.terms().network,
                &package.raw,
                &raws,
            )
            .unwrap();
            assert_eq!(recovered.terms, *publication.terms());
            assert_eq!(recovered.side, side);
            let mut unsigned = Transaction::decode(&package.raw).unwrap();
            unsigned.inputs[0].witness = Witness::default();
            assert!(
                recover_hns_contract_from_ancestors(
                    publication.terms().network,
                    &unsigned.encode().unwrap(),
                    &raws
                )
                .is_err()
            );
            assert_eq!(
                recovered.publication_anchor_program,
                hns_recovery_anchor_program(&restored, &account.config).unwrap()
            );
            let mut graph = raws.clone();
            graph.push(package.raw.clone());
            assert_eq!(
                discover_hns_recovery_contracts(publication.terms().network, &graph).unwrap(),
                vec![recovered]
            );
            assert!(
                recover_hns_contract_from_ancestors(
                    publication.terms().network,
                    &package.raw,
                    &raws[1..]
                )
                .is_err()
            );
            let mut changed = raws.clone();
            let mut first = Transaction::decode(&changed[0]).unwrap();
            first.outputs[0].value = Dollarydoos::new(1);
            changed[0] = first.encode().unwrap();
            assert!(
                recover_hns_contract_from_ancestors(
                    publication.terms().network,
                    &package.raw,
                    &changed
                )
                .is_err()
            );
            let mut network = publication.terms().network;
            network.counterchain_genesis[0] ^= 1;
            assert!(recover_hns_contract_from_ancestors(network, &package.raw, &raws).is_err());
        }
    }

    #[test]
    fn hns_recovery_funding_rejects_excessive_total_fee_and_wrong_network() {
        let (store, account, coin, publication) = fixture(SwapAssetSide::Offered);
        assert!(matches!(
            prepare_hns_recoverable_funding(
                &store,
                &account,
                vec![coin.clone()],
                &publication,
                BaseUnits::new(1_000),
                BaseUnits::new(100)
            ),
            Err(HnsWalletError::FeeLimit)
        ));
        let mut wrong_terms = publication.terms().clone();
        wrong_terms.network.hns_genesis = BlockHash::new([99; 32]);
        let wrong = SwapRecoveryPublication::from_terms(wrong_terms, publication.side()).unwrap();
        assert!(
            prepare_hns_recoverable_funding(
                &store,
                &account,
                vec![coin],
                &wrong,
                BaseUnits::new(1_000),
                BaseUnits::new(10_000)
            )
            .is_err()
        );
    }
}
