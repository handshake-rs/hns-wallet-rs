//! Chain-visible swap terms. Preparation does not insert unbroadcast
//! transactions into the live wallet. Every publication output is an ordinary
//! descriptor-wallet coin; only the final descendant locks value in an HTLC.

use super::*;
use bdk_wallet::chain::Indexer;
use bdk_wallet::signer::SignerOrdering;
use hns_marketplace_protocol::ChainId;
use hns_wallet_chain_api::{SwapRecoveryPublication, SwapRecoveryTerms};

pub struct PreparedBitcoinRecoverableFunding {
    pub funding: PreparedBitcoinHtlcFunding,
    /// Total fee of the publication ancestors and final funding transaction.
    pub aggregate_fee_sats: u64,
    publication_transactions: Vec<Vec<u8>>,
}

impl fmt::Debug for PreparedBitcoinRecoverableFunding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBitcoinRecoverableFunding")
            .field("funding", &self.funding)
            .field("aggregate_fee_sats", &self.aggregate_fee_sats)
            .field(
                "publication_transaction_count",
                &self.publication_transactions.len(),
            )
            .finish()
    }
}

impl PreparedBitcoinRecoverableFunding {
    pub fn publication_transactions(&self) -> &[Vec<u8>] {
        &self.publication_transactions
    }
}

/// Commit the approved package in ancestor order. A failed commit can leave
/// only approved ordinary-wallet publications, never a funding transaction
/// without its complete durable ancestors. The final record consumes the
/// existing cross-chain guard at the same boundary as ordinary HTLC funding.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit approval, fee, time and cross-chain authority boundary"
)]
pub fn persist_bitcoin_recoverable_funding(
    wallet: &Wallet,
    store: &mut hns_wallet_store::WalletStore,
    package: &PreparedBitcoinRecoverableFunding,
    maximum_fee_sats: u64,
    now_unix: u64,
    expires_at_unix: u64,
    guard: Option<BitcoinBroadcastAuthorizationGuard>,
) -> Result<Vec<PreparedBitcoinBroadcast>, BitcoinWalletError> {
    if package.aggregate_fee_sats > maximum_fee_sats || now_unix >= expires_at_unix {
        return Err(BitcoinWalletError::InvalidBroadcastApproval);
    }
    let funding_expiry = guard.as_ref().map_or(expires_at_unix, |guard| {
        expires_at_unix.min(guard.expires_at_unix())
    });
    let mut plan = planning_wallet(wallet)?;
    let raws = package
        .publication_transactions
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(package.funding.raw_transaction()));
    // Check the entire sequence and aggregate accounting before any write.
    let mut bindings = Vec::new();
    let mut total = 0u64;
    for (index, raw) in raws.enumerate() {
        let expiry = if index == package.publication_transactions.len() {
            funding_expiry
        } else {
            expires_at_unix
        };
        let approval = derive_bitcoin_broadcast_approval(&plan, raw, maximum_fee_sats, expiry)?;
        total = total
            .checked_add(approval.fee_sats)
            .ok_or(BitcoinWalletError::FeeLimit)?;
        bindings.push(approval);
        let tx: Transaction = deserialize(raw).map_err(|_| recovery_error())?;
        plan.apply_unconfirmed_txs([(tx, now_unix)]);
    }
    if total != package.aggregate_fee_sats || total > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    let mut plan = planning_wallet(wallet)?;
    let mut prepared = Vec::new();
    let mut guard = guard;
    for (index, (raw, approval)) in package
        .publication_transactions
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(package.funding.raw_transaction()))
        .zip(bindings)
        .enumerate()
    {
        let revision = store
            .bitcoin_transaction::<BitcoinTransactionRecord>(&approval.txid)?
            .map_or(0, |record| record.revision);
        let is_funding = index == package.publication_transactions.len();
        let committed = if is_funding && guard.is_some() {
            crate::persist_guarded_prepared_bitcoin_broadcast(
                &plan,
                store,
                raw,
                approval.commitment,
                maximum_fee_sats,
                revision,
                now_unix,
                approval.expires_at_unix,
                guard.take().unwrap(),
            )?
        } else {
            persist_prepared_bitcoin_broadcast(
                &plan,
                store,
                raw,
                approval.commitment,
                maximum_fee_sats,
                revision,
                now_unix,
                approval.expires_at_unix,
            )?
        };
        prepared.push(committed);
        let tx: Transaction = deserialize(raw).map_err(|_| recovery_error())?;
        plan.apply_unconfirmed_txs([(tx, now_unix)]);
    }
    Ok(prepared)
}

/// A structural recovery match, not proof of inclusion, unspentness, maturity,
/// or wallet ownership. The caller must obtain those from its verified chain
/// view and match a participant key derived from the restored seed.
#[derive(Clone, Debug)]
pub struct BitcoinRecoveryContract {
    pub terms: SwapRecoveryTerms,
    pub side: SwapAssetSide,
    pub lock: VerifiedBitcoinLock,
    pub publication_anchor_script: ScriptBuf,
}

fn recovery_error() -> BitcoinWalletError {
    BitcoinWalletError::InvalidEvidence
}

fn check_network(
    network: Network,
    binding: ShakescapeNetworkBinding,
) -> Result<(), BitcoinWalletError> {
    let id = match network {
        Network::Bitcoin => 1,
        Network::Testnet => 2,
        Network::Regtest => 3,
        Network::Testnet4 => 4,
        Network::Signet => 5,
    };
    if binding.counterchain != ChainId::BITCOIN
        || binding.counterchain_network != id
        || binding.counterchain_genesis
            != bdk_wallet::bitcoin::blockdata::constants::genesis_block(network)
                .block_hash()
                .to_byte_array()
    {
        return Err(BitcoinWalletError::NetworkMismatch);
    }
    Ok(())
}

pub fn build_recovered_bitcoin_htlc(
    terms: &SwapRecoveryTerms,
    side: SwapAssetSide,
) -> Result<BitcoinHtlc, BitcoinWalletError> {
    terms.validate().map_err(|_| recovery_error())?;
    let params = terms.htlc(side);
    if params.chain != ChainId::BITCOIN {
        return Err(recovery_error());
    }
    BitcoinHtlc::new(
        params.hashlock,
        PublicKey::from_slice(&params.receiver_public_key).map_err(|_| recovery_error())?,
        PublicKey::from_slice(&params.refund_public_key).map_err(|_| recovery_error())?,
        u32::try_from(params.refund_at).map_err(|_| recovery_error())?,
    )
}

/// Snapshot public wallet state and share in-process signing handles. No secret
/// key or seed is exported, and no tentative ancestor alters the live balance.
fn planning_wallet(wallet: &Wallet) -> Result<Wallet, BitcoinWalletError> {
    let snapshot = bdk_wallet::ChangeSet {
        descriptor: Some(wallet.public_descriptor(KeychainKind::External).clone()),
        change_descriptor: Some(wallet.public_descriptor(KeychainKind::Internal).clone()),
        network: Some(wallet.network()),
        local_chain: wallet.local_chain().initial_changeset(),
        tx_graph: wallet.tx_graph().initial_changeset(),
        indexer: wallet.spk_index().initial_changeset(),
        ..Default::default()
    };
    let mut copy = Wallet::load()
        .load_wallet_no_persist(snapshot)
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?
        .ok_or(BitcoinWalletError::WalletNotFound)?;
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        for (ordering, signer) in wallet
            .get_signers(keychain)
            .signers()
            .into_iter()
            .enumerate()
        {
            copy.add_signer(
                keychain,
                SignerOrdering(ordering),
                std::sync::Arc::clone(signer),
            );
        }
    }
    for outpoint in wallet.list_locked_outpoints() {
        copy.lock_outpoint(outpoint);
    }
    Ok(copy)
}

fn signed_transaction(
    wallet: &Wallet,
    mut psbt: Psbt,
) -> Result<(Transaction, u64), BitcoinWalletError> {
    let fee = wallet
        .calculate_fee(&psbt.unsigned_tx)
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?
        .to_sat();
    if !wallet
        .sign(&mut psbt, SignOptions::default())
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?
    {
        return Err(BitcoinWalletError::SigningIncomplete);
    }
    let tx = psbt
        .extract_tx()
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?;
    if serialize(&tx).len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    Ok((tx, fee))
}

/// Build one ordinary-wallet ancestor per standard 80-byte data frame, followed
/// by funding that spends the last ancestor and commits the entire publication.
/// The single aggregate fee limit includes every transaction. No network I/O.
pub fn prepare_bitcoin_recoverable_htlc_funding(
    wallet: &mut Wallet,
    _permit: &BitcoinValueRuntimePermit,
    publication: &SwapRecoveryPublication,
    fee_rate_sat_vb: u64,
    maximum_fee_sats: u64,
    unspendable: &[OutPoint],
) -> Result<PreparedBitcoinRecoverableFunding, BitcoinWalletError> {
    check_network(wallet.network(), publication.terms().network)?;
    if publication.chain() != ChainId::BITCOIN || fee_rate_sat_vb == 0 || maximum_fee_sats == 0 {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    let htlc = build_recovered_bitcoin_htlc(publication.terms(), publication.side())?;
    let value = publication.terms().htlc(publication.side()).amount;
    if value < MIN_HTLC_DUST_SATS {
        return Err(BitcoinWalletError::Dust);
    }
    let required = value
        .checked_add(maximum_fee_sats)
        .ok_or(BitcoinWalletError::InvalidAmount)?;
    let mut selected = Vec::new();
    let mut available = 0u64;
    for coin in wallet.list_unspent() {
        if !coin.chain_position.is_confirmed()
            || unspendable.contains(&coin.outpoint)
            || wallet
                .list_locked_outpoints()
                .any(|locked| locked == coin.outpoint)
        {
            continue;
        }
        selected.push(coin.outpoint);
        available = available
            .checked_add(coin.txout.value.to_sat())
            .ok_or(BitcoinWalletError::InvalidAmount)?;
        if available >= required {
            break;
        }
    }
    if available < required {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    // The only live preparation change is revealing the seed-owned anchor.
    // Its index must be persisted with the displayed approval.
    let _ = wallet
        .reveal_addresses_to(KeychainKind::Internal, 0)
        .count();
    // A fixed ordinary address is always inside a standard seed restore's
    // initial window, including after arbitrarily many rejected preparations.
    let anchor = wallet
        .peek_address(KeychainKind::Internal, 0)
        .address
        .script_pubkey();
    let mut plan = planning_wallet(wallet)?;
    let rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(fee_rate_sat_vb)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    let mut transactions = Vec::new();
    let mut aggregate_fee = 0u64;
    for frame in publication.frames() {
        let data = bdk_wallet::bitcoin::script::PushBytesBuf::try_from(frame.clone())
            .map_err(|_| recovery_error())?;
        let mut builder = plan.build_tx();
        builder
            .add_utxos(&selected)
            .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?;
        builder
            .manually_selected_only()
            .drain_to(anchor.clone())
            .add_data(&data)
            .fee_rate(rate);
        let psbt = builder
            .finish()
            .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?;
        let (tx, fee) = signed_transaction(&plan, psbt)?;
        aggregate_fee = aggregate_fee
            .checked_add(fee)
            .ok_or(BitcoinWalletError::FeeLimit)?;
        if aggregate_fee >= maximum_fee_sats {
            return Err(BitcoinWalletError::FeeLimit);
        }
        let vout = tx
            .output
            .iter()
            .position(|out| out.script_pubkey == anchor)
            .ok_or_else(recovery_error)?;
        selected = vec![OutPoint {
            txid: tx.compute_txid(),
            vout: vout as u32,
        }];
        transactions.push(serialize(&tx));
        plan.apply_unconfirmed_txs([(tx, 1)]);
    }
    let marker = bdk_wallet::bitcoin::script::PushBytesBuf::try_from(publication.marker().to_vec())
        .map_err(|_| recovery_error())?;
    let mut builder = plan.build_tx();
    builder
        .add_utxos(&selected)
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?;
    builder
        .manually_selected_only()
        .drain_to(anchor)
        .add_recipient(htlc.script_pubkey(), BitcoinAmount::from_sat(value))
        .add_data(&marker)
        .fee_rate(rate);
    let psbt = builder
        .finish()
        .map_err(|err| BitcoinWalletError::Wallet(err.to_string()))?;
    let (tx, fee) = signed_transaction(&plan, psbt)?;
    aggregate_fee = aggregate_fee
        .checked_add(fee)
        .ok_or(BitcoinWalletError::FeeLimit)?;
    if aggregate_fee > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    let raw = serialize(&tx);
    let contract = recover_bitcoin_contract_from_ancestors(
        wallet.network(),
        publication.terms().network,
        &raw,
        &transactions,
    )?;
    Ok(PreparedBitcoinRecoverableFunding {
        funding: PreparedBitcoinHtlcFunding {
            htlc,
            value_sats: value,
            fee_sats: fee,
            txid: contract.lock.funding_txid,
            raw_transaction: raw,
        },
        aggregate_fee_sats: aggregate_fee,
        publication_transactions: transactions,
    })
}

pub(crate) fn is_recoverable_funding_transaction(tx: &Transaction) -> bool {
    transaction_data(tx).is_ok_and(|data| {
        data.len() == hns_wallet_chain_api::SWAP_RECOVERY_MARKER_BYTES && data.starts_with(b"SRF1")
    })
}

/// Extract exactly one canonical standard zero-valued OP_RETURN output.
fn transaction_data(tx: &Transaction) -> Result<Vec<u8>, BitcoinWalletError> {
    use bdk_wallet::bitcoin::script::Instruction;
    let mut found = None;
    for output in &tx.output {
        if !output.script_pubkey.is_op_return() {
            continue;
        }
        if output.value != BitcoinAmount::ZERO || found.is_some() {
            return Err(recovery_error());
        }
        let mut instructions = output.script_pubkey.instructions_minimal();
        match (
            instructions.next(),
            instructions.next(),
            instructions.next(),
        ) {
            (Some(Ok(Instruction::Op(op))), Some(Ok(Instruction::PushBytes(data))), None)
                if op == bdk_wallet::bitcoin::opcodes::all::OP_RETURN && data.len() <= 80 =>
            {
                found = Some(data.as_bytes().to_vec());
            }
            _ => return Err(recovery_error()),
        }
    }
    found.ok_or_else(recovery_error)
}

/// Recover exact terms from the final transaction and its ordered publication
/// ancestors. Transaction input hashes bind every byte of the frames. Merely
/// supplying detached frames or unrelated transactions never establishes a
/// match. Inclusion and current spend state remain the chain verifier's job.
pub fn recover_bitcoin_contract_from_ancestors(
    network: Network,
    expected_network: ShakescapeNetworkBinding,
    funding_raw: &[u8],
    ancestor_raws: &[Vec<u8>],
) -> Result<BitcoinRecoveryContract, BitcoinWalletError> {
    check_network(network, expected_network)?;
    if ancestor_raws.is_empty()
        || ancestor_raws.len() > hns_wallet_chain_api::MAX_SWAP_RECOVERY_FRAMES
        || funding_raw.len() > MAX_BITCOIN_TRANSACTION_BYTES
    {
        return Err(recovery_error());
    }
    let funding: Transaction = deserialize(funding_raw).map_err(|_| recovery_error())?;
    let mut ancestors = Vec::new();
    let mut frames = Vec::new();
    for raw in ancestor_raws {
        if raw.len() > MAX_BITCOIN_TRANSACTION_BYTES {
            return Err(recovery_error());
        }
        let tx: Transaction = deserialize(raw).map_err(|_| recovery_error())?;
        if tx.input.is_empty() || tx.is_coinbase() {
            return Err(recovery_error());
        }
        frames.push(transaction_data(&tx)?);
        ancestors.push(tx);
    }
    let mut publication_anchor_script = None;
    for (parent, child) in ancestors
        .iter()
        .zip(ancestors.iter().skip(1).chain(std::iter::once(&funding)))
    {
        if child.input.len() != 1 || child.input[0].previous_output.txid != parent.compute_txid() {
            return Err(recovery_error());
        }
        let output = parent
            .output
            .get(child.input[0].previous_output.vout as usize)
            .ok_or_else(recovery_error)?;
        if !output.script_pubkey.is_p2wpkh() || output.value.to_sat() < MIN_HTLC_DUST_SATS {
            return Err(recovery_error());
        }
        let input = &child.input[0];
        let witness = input.witness.to_vec();
        if !input.script_sig.is_empty() || witness.len() != 2 || witness[1].len() != 33 {
            return Err(recovery_error());
        }
        let public = PublicKey::from_slice(&witness[1]).map_err(|_| recovery_error())?;
        if ScriptBuf::new_p2wpkh(&public.wpubkey_hash().map_err(|_| recovery_error())?)
            != output.script_pubkey
        {
            return Err(recovery_error());
        }
        let der = witness[0]
            .strip_suffix(&[EcdsaSighashType::All.to_u32() as u8])
            .ok_or_else(recovery_error)?;
        let signature = Signature::from_der(der).map_err(|_| recovery_error())?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err(recovery_error());
        }
        let digest = SighashCache::new(child)
            .p2wpkh_signature_hash(
                0,
                &output.script_pubkey,
                output.value,
                EcdsaSighashType::All,
            )
            .map_err(|_| recovery_error())?;
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(digest.to_byte_array()),
                &signature,
                &public.inner,
            )
            .map_err(|_| recovery_error())?;
        if publication_anchor_script
            .as_ref()
            .is_some_and(|script| script != &output.script_pubkey)
        {
            return Err(recovery_error());
        }
        publication_anchor_script = Some(output.script_pubkey.clone());
    }
    let publication = SwapRecoveryPublication::decode(
        expected_network,
        ChainId::BITCOIN,
        &transaction_data(&funding)?,
        &frames,
    )
    .map_err(|_| recovery_error())?;
    let htlc = build_recovered_bitcoin_htlc(publication.terms(), publication.side())?;
    let lock = verify_htlc_funding(
        funding_raw,
        &htlc,
        publication.terms().htlc(publication.side()).amount,
        0,
        0,
    )?;
    Ok(BitcoinRecoveryContract {
        terms: publication.terms().clone(),
        side: publication.side(),
        lock,
        publication_anchor_script: publication_anchor_script.ok_or_else(recovery_error)?,
    })
}

/// Discover chain-bound publications in the wallet's scanned transaction graph.
/// Ordinary seed-owned ancestor outputs make these transactions visible to a
/// normal descriptor scan. No offer ID, session ID, file, or peer reply is an
/// input. Malformed/unrelated records are ignored rather than blocking sync.
pub fn discover_bitcoin_recovery_contracts(
    wallet: &Wallet,
    expected_network: ShakescapeNetworkBinding,
) -> Result<Vec<BitcoinRecoveryContract>, BitcoinWalletError> {
    check_network(wallet.network(), expected_network)?;
    let mut contracts = Vec::new();
    for node in wallet.tx_graph().full_txs() {
        let Ok(marker) = transaction_data(&node.tx) else {
            continue;
        };
        if marker.len() != hns_wallet_chain_api::SWAP_RECOVERY_MARKER_BYTES
            || !marker.starts_with(b"SRF1")
        {
            continue;
        }
        let mut child = std::sync::Arc::clone(&node.tx);
        let mut ancestors = Vec::new();
        for _ in 0..hns_wallet_chain_api::MAX_SWAP_RECOVERY_FRAMES {
            if child.input.len() != 1 {
                break;
            }
            let Some(parent) = wallet
                .tx_graph()
                .get_tx(child.input[0].previous_output.txid)
            else {
                break;
            };
            let Ok(frame) = transaction_data(&parent) else {
                break;
            };
            if frame.len() < 4 || !frame.starts_with(b"SR") {
                break;
            }
            ancestors.push(serialize(parent.as_ref()));
            if frame[2] == 0 {
                break;
            }
            child = parent;
        }
        ancestors.reverse();
        if let Ok(contract) = recover_bitcoin_contract_from_ancestors(
            wallet.network(),
            expected_network,
            &serialize(node.tx.as_ref()),
            &ancestors,
        ) && contract.publication_anchor_script
            == wallet
                .peek_address(KeychainKind::Internal, 0)
                .address
                .script_pubkey()
        {
            contracts.push(contract);
        }
    }
    Ok(contracts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxUpdate};

    fn public_key(byte: u8) -> [u8; 33] {
        PublicKey::new(bdk_wallet::bitcoin::secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).unwrap(),
        ))
        .to_bytes()
        .try_into()
        .unwrap()
    }

    fn fixture(side: SwapAssetSide) -> (Wallet, SwapRecoveryPublication) {
        let network = Network::Regtest;
        let genesis =
            bdk_wallet::bitcoin::blockdata::constants::genesis_block(network).block_hash();
        let binding = ShakescapeNetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: hns_primitives::BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 3,
            counterchain_genesis: genesis.to_byte_array(),
        };
        let terms = SwapRecoveryTerms {
            network: binding,
            session_id: [1; 32],
            direct_offer_id: [2; 32],
            maker_public_key: public_key(3),
            taker_public_key: public_key(4),
            hashlock: [5; 32],
            offered_asset: if side == SwapAssetSide::Offered {
                AssetId::BTC
            } else {
                AssetId::HNS
            },
            offered_amount: 50_000,
            received_amount: 50_000,
            offered_refund_at: 1_800_010_000,
            received_refund_at: 1_800_000_000,
            offered_minimum_confirmations: 2,
            received_minimum_confirmations: 2,
        };
        let publication = SwapRecoveryPublication::from_terms(terms, side).unwrap();
        let mut wallet = create_descriptor_wallet_from_seed(&[7; 64], network).unwrap();
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        let deposit = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bdk_wallet::bitcoin::Txid::from_byte_array([8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: BitcoinAmount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let mut update = TxUpdate::default();
        update.anchors.insert((
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 0,
                    hash: genesis,
                },
                confirmation_time: 1,
            },
            deposit.compute_txid(),
        ));
        update.txs.push(std::sync::Arc::new(deposit));
        wallet
            .apply_update(bdk_wallet::Update {
                tx_update: update,
                ..Default::default()
            })
            .unwrap();
        (wallet, publication)
    }

    #[test]
    fn published_funding_recovers_both_offer_directions_without_changing_live_balance() {
        for side in [SwapAssetSide::Offered, SwapAssetSide::Received] {
            let (mut wallet, publication) = fixture(side);
            let before = wallet.balance();
            let package = prepare_bitcoin_recoverable_htlc_funding(
                &mut wallet,
                &BitcoinValueRuntimePermit(()),
                &publication,
                1,
                1_000,
                &[],
            )
            .expect("standard recovery ancestry within fee reserve");
            assert_eq!(wallet.balance(), before);
            assert_eq!(package.publication_transactions().len(), 3);
            assert!(package.aggregate_fee_sats > package.funding.fee_sats);
            assert!(package.aggregate_fee_sats <= 1_000);
            let recovered = recover_bitcoin_contract_from_ancestors(
                wallet.network(),
                publication.terms().network,
                package.funding.raw_transaction(),
                package.publication_transactions(),
            )
            .unwrap();
            assert_eq!(recovered.terms, *publication.terms());
            assert_eq!(recovered.side, side);
            let mut unsigned: Transaction = deserialize(package.funding.raw_transaction()).unwrap();
            unsigned.input[0].witness = Witness::new();
            assert!(
                recover_bitcoin_contract_from_ancestors(
                    wallet.network(),
                    publication.terms().network,
                    &serialize(&unsigned),
                    package.publication_transactions()
                )
                .is_err()
            );
            let mut seed_only =
                create_descriptor_wallet_from_seed(&[7; 64], wallet.network()).unwrap();
            let _ = seed_only
                .reveal_addresses_to(KeychainKind::Internal, 0)
                .count();
            for raw in package
                .publication_transactions()
                .iter()
                .map(Vec::as_slice)
                .chain(std::iter::once(package.funding.raw_transaction()))
            {
                seed_only.apply_unconfirmed_txs([(deserialize::<Transaction>(raw).unwrap(), 1)]);
            }
            let discovered =
                discover_bitcoin_recovery_contracts(&seed_only, publication.terms().network)
                    .unwrap();
            assert_eq!(discovered.len(), 1);
            assert_eq!(discovered[0].terms, *publication.terms());
            let mut unrelated =
                create_descriptor_wallet_from_seed(&[8; 64], wallet.network()).unwrap();
            for raw in package
                .publication_transactions()
                .iter()
                .map(Vec::as_slice)
                .chain(std::iter::once(package.funding.raw_transaction()))
            {
                unrelated.apply_unconfirmed_txs([(deserialize::<Transaction>(raw).unwrap(), 1)]);
            }
            assert!(
                discover_bitcoin_recovery_contracts(&unrelated, publication.terms().network)
                    .unwrap()
                    .is_empty()
            );
            let mut store =
                hns_wallet_store::WalletStore::create(":memory:", "recovery-package-test").unwrap();
            let committed = persist_bitcoin_recoverable_funding(
                &wallet, &mut store, &package, 1_000, 1, 300, None,
            )
            .unwrap();
            assert_eq!(committed.len(), 4);
            assert_eq!(
                committed.last().unwrap().txid,
                package.funding.txid.into_bytes()
            );
            let mut records = store
                .bitcoin_transactions::<BitcoinTransactionRecord>(100)
                .unwrap()
                .into_iter()
                .map(|row| row.value)
                .collect::<Vec<_>>();
            assert_eq!(
                records
                    .iter()
                    .find(|record| record.txid == package.funding.txid.into_bytes())
                    .unwrap()
                    .broadcast
                    .as_ref()
                    .unwrap()
                    .expires_at_unix,
                300
            );
            records.reverse();
            let resumed = crate::runtime::approved_broadcast_order(&records).unwrap();
            assert_eq!(
                resumed.iter().map(|(txid, _)| *txid).collect::<Vec<_>>(),
                committed
                    .iter()
                    .map(|prepared| prepared.txid)
                    .collect::<Vec<_>>()
            );
            // Every interrupted prefix holds only ordinary wallet outputs;
            // importing its chain transactions into a seed-only wallet finds
            // its surviving anchor without any swap metadata.
            for prefix_len in 1..=package.publication_transactions().len() {
                let mut restored =
                    create_descriptor_wallet_from_seed(&[7; 64], wallet.network()).unwrap();
                let _ = restored
                    .reveal_addresses_to(KeychainKind::Internal, 0)
                    .count();
                for raw in &package.publication_transactions()[..prefix_len] {
                    let tx: Transaction = deserialize(raw).unwrap();
                    assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
                    assert!(tx.output.iter().all(
                        |out| out.script_pubkey.is_p2wpkh() || out.script_pubkey.is_op_return()
                    ));
                    restored.apply_unconfirmed_txs([(tx, 1)]);
                }
                assert_eq!(restored.list_unspent().count(), 1);
                assert!(restored.balance().total().to_sat() > 50_000);
            }
            let mut changed = package.publication_transactions().to_vec();
            let mut first: Transaction = deserialize(&changed[0]).unwrap();
            first.output[0].value = BitcoinAmount::from_sat(1);
            changed[0] = serialize(&first);
            assert!(
                recover_bitcoin_contract_from_ancestors(
                    wallet.network(),
                    publication.terms().network,
                    package.funding.raw_transaction(),
                    &changed
                )
                .is_err()
            );
            let mut detached: Transaction = deserialize(package.funding.raw_transaction()).unwrap();
            detached.input[0].previous_output.txid =
                bdk_wallet::bitcoin::Txid::from_byte_array([99; 32]);
            assert!(
                recover_bitcoin_contract_from_ancestors(
                    wallet.network(),
                    publication.terms().network,
                    &serialize(&detached),
                    package.publication_transactions()
                )
                .is_err()
            );
            assert!(
                recover_bitcoin_contract_from_ancestors(
                    wallet.network(),
                    publication.terms().network,
                    package.funding.raw_transaction(),
                    &package.publication_transactions()[1..]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn recovery_funding_respects_reserved_inputs_and_aggregate_fee_limit() {
        let (mut wallet, publication) = fixture(SwapAssetSide::Offered);
        let input = wallet.list_unspent().next().unwrap().outpoint;
        assert!(
            prepare_bitcoin_recoverable_htlc_funding(
                &mut wallet,
                &BitcoinValueRuntimePermit(()),
                &publication,
                1,
                1_000,
                &[input]
            )
            .is_err()
        );
        assert!(matches!(
            prepare_bitcoin_recoverable_htlc_funding(
                &mut wallet,
                &BitcoinValueRuntimePermit(()),
                &publication,
                1,
                100,
                &[]
            ),
            Err(BitcoinWalletError::FeeLimit)
        ));
        wallet.lock_outpoint(input);
        assert!(
            prepare_bitcoin_recoverable_htlc_funding(
                &mut wallet,
                &BitcoinValueRuntimePermit(()),
                &publication,
                1,
                1_000,
                &[]
            )
            .is_err()
        );
    }
}
