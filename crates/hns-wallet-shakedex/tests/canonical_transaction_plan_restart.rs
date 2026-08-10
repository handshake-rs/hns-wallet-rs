#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{Covenant, FinalizeCovenant, NameState, hash_name};
use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash as CanonicalTransactionHash};
use hns_script::{
    OP_BLAKE160, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, SIGHASH_ALL, SIGHASH_NONE, signature_hash,
};
use hns_swap::{
    FixedPriceListing, NetworkBinding, SHAKEDEX_RECOVERY_SIGHASH, SwapProof, lock_script_hash,
};
use hns_transaction::{Address, Coin, Input, Outpoint, Output, Transaction, Witness};
use hns_wallet_hns::{
    HnsOutpoint, HnsShakedexFundingPurpose, HnsShakedexFundingReservation, TrackedHnsCoin,
    WalletCoin,
};
use hns_wallet_shakedex::{
    BuyerLockPlan, BuyerLockPlanState, SellerLockPlan, SellerLockPlanState, ShakedexError,
    ShakedexValueAction, ShakedexValueStage, ShakedexValueWorkflow, SuppliedShakedexLock,
    VerifiedShakedexTransfer, list_buyer_lock_plans, list_seller_lock_plans, load_buyer_lock_plan,
    load_seller_lock_plan, prepare_buyer_fulfillment, prepare_script_finalize,
    prepare_seller_recovery, save_buyer_lock_plan, save_seller_lock_plan,
    shakedex_value_workflow_id, verify_fixed_price_listing, verify_signed_buyer_fulfillment,
    verify_signed_script_finalize, verify_signed_seller_recovery,
};
use hns_wallet_store::WalletStore;
use hns_wallet_types::{
    AccountId, BaseUnits, DerivationReference, KeyRole, ObjectHash, TransactionHash, WalletId,
    WorkflowId,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};

const ACTIVE_TIME: u64 = 1_800_000_200;
const TRANSACTION_FEE: u64 = 1_000;

fn listing_fixture() -> (FixedPriceListing, Coin, SigningKey) {
    let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
    let seller_public_key: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed seller key");
    let network = NetworkBinding {
        magic: 0x5b6e_c393,
        genesis: BlockHash::new([0x11; 32]),
    };
    let mut proof = SwapProof {
        network,
        locking_outpoint: Outpoint {
            transaction_hash: CanonicalTransactionHash::new([0x22; 32]),
            index: 7,
        },
        name: b"market-name".to_vec(),
        seller_public_key,
        payment_address: Address::new(0, vec![0x33; 20]).expect("payment address"),
        price: Dollarydoos::new(12_345_678),
        lock_time_seconds: 1_800_000_000,
        signature: None,
        fee_address: Some(Address::new(0, vec![0x44; 20]).expect("market fee address")),
        fee: Dollarydoos::new(25_000),
    };
    let locking_coin = Coin {
        outpoint: proof.locking_outpoint,
        value: Dollarydoos::new(900_000),
        height: Height::new(123),
        coinbase: false,
        address: Address::new(0, lock_script_hash(&seller_public_key).to_vec())
            .expect("lock address"),
        covenant: FinalizeCovenant::new(
            proof.name.clone(),
            Height::new(1),
            false,
            Height::new(0),
            0,
            BlockHash::new([0x55; 32]),
        )
        .expect("finalize covenant")
        .to_covenant()
        .expect("canonical covenant"),
    };
    proof
        .sign(&locking_coin, &signing_key)
        .expect("seller presign");
    let mut listing = FixedPriceListing {
        proof,
        created_at: ACTIVE_TIME - 100,
        expires_at: ACTIVE_TIME + 3_500,
        sequence: 42,
        signature: None,
    };
    listing.sign(&signing_key).expect("listing signature");
    (listing, locking_coin, signing_key)
}

fn public_key_hash(key: &SigningKey) -> ([u8; 33], [u8; 20]) {
    let public_key: [u8; 33] = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed public key");
    let mut hasher = Blake2bVar::new(20).expect("Blake2b-160");
    hasher.update(&public_key);
    let mut program = [0_u8; 20];
    hasher
        .finalize_variable(&mut program)
        .expect("Blake2b-160 output");
    (public_key, program)
}

fn funding_coin(tag: u8, key: &SigningKey, value: u64) -> Coin {
    let (_, program) = public_key_hash(key);
    Coin {
        outpoint: Outpoint {
            transaction_hash: CanonicalTransactionHash::new([tag; 32]),
            index: u32::from(tag),
        },
        value: Dollarydoos::new(value),
        height: Height::new(150),
        coinbase: false,
        address: Address::new(0, program.to_vec()).expect("funding address"),
        covenant: Covenant::default(),
    }
}

fn unsigned_input(coin: &Coin) -> Input {
    Input {
        previous_output: coin.outpoint,
        sequence: u32::MAX,
        witness: Witness::default(),
    }
}

fn ordinary_output(address: Address, value: u64) -> Output {
    Output {
        value: Dollarydoos::new(value),
        address,
        covenant: Covenant::default(),
    }
}

fn sign_p2pkh_input(transaction: &mut Transaction, index: usize, coin: &Coin, key: &SigningKey) {
    sign_p2pkh_input_with_sighash(transaction, index, coin, key, SIGHASH_ALL);
}

fn sign_p2pkh_input_with_sighash(
    transaction: &mut Transaction,
    index: usize,
    coin: &Coin,
    key: &SigningKey,
    sighash_type: u32,
) {
    let (public_key, program) = public_key_hash(key);
    assert_eq!(coin.address.hash, program);
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
    script.extend_from_slice(&program);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    let digest = signature_hash(transaction, index, &script, coin.value.get(), sighash_type)
        .expect("P2PKH signature hash");
    let signature: Signature = key.sign_prehash(&digest).expect("P2PKH signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(sighash_type as u8);
    transaction.inputs[index].witness = Witness {
        items: vec![encoded, public_key.to_vec()],
    };
}

fn compact_recovery_signature(key: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let signature: Signature = key.sign_prehash(digest).expect("recovery signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut encoded = [0_u8; 65];
    encoded[..64].copy_from_slice(&signature.to_bytes());
    encoded[64] = SHAKEDEX_RECOVERY_SIGHASH as u8;
    encoded
}

struct TestWalletDirectory(PathBuf);

impl Drop for TestWalletDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_store() -> (TestWalletDirectory, PathBuf, WalletStore) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "hns-wallet-shakedex-transaction-plan-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).expect("test wallet directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("private test wallet directory");
    let database = directory.join("wallet.sqlite3");
    let store = WalletStore::create(&database, "canonical-plan-test-passphrase")
        .expect("encrypted wallet store");
    (TestWalletDirectory(directory), database, store)
}

#[test]
fn hns_shakedex_transaction_plan_restart_cas() {
    let (listing, locking_coin, seller_key) = listing_fixture();
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let listing_bytes = listing.encode().expect("listing bytes");
    let verified_listing = verify_fixed_price_listing(
        &listing_bytes,
        listing_hash,
        listing.network(),
        ACTIVE_TIME,
        &locking_coin,
    )
    .expect("verified listing");
    let supplied_lock = SuppliedShakedexLock::verify(
        listing.network(),
        locking_coin.clone(),
        *verified_listing.seller_public_key(),
    )
    .expect("supplied lock structure");

    let buyer_key = SigningKey::from_slice(&[0x41; 32]).expect("buyer key");
    let (_, buyer_program) = public_key_hash(&buyer_key);
    let buyer_recipient = Address::new(0, buyer_program.to_vec()).expect("buyer recipient");
    let buyer_coin = funding_coin(0x61, &buyer_key, 13_000_000);
    let buyer_change = ordinary_output(buyer_recipient.clone(), 628_322);
    let prepared_fulfillment = prepare_buyer_fulfillment(
        &verified_listing,
        &supplied_lock,
        ACTIVE_TIME,
        ACTIVE_TIME,
        buyer_recipient.clone(),
        vec![unsigned_input(&buyer_coin)],
        vec![buyer_coin.clone()],
        vec![buyer_change],
        TRANSACTION_FEE,
    )
    .expect("canonical buyer fulfillment");
    let mut fulfillment = Transaction::decode(prepared_fulfillment.transaction_bytes())
        .expect("fulfillment transaction");
    sign_p2pkh_input(&mut fulfillment, 1, &buyer_coin, &buyer_key);
    let fulfillment_bytes = fulfillment.encode().expect("signed fulfillment bytes");
    let verified_fulfillment = prepared_fulfillment
        .verify_signed(&fulfillment_bytes)
        .expect("fully verified fulfillment");
    let mut non_all_fulfillment =
        Transaction::decode(prepared_fulfillment.transaction_bytes()).expect("fulfillment");
    sign_p2pkh_input_with_sighash(
        &mut non_all_fulfillment,
        1,
        &buyer_coin,
        &buyer_key,
        SIGHASH_NONE,
    );
    assert!(
        prepared_fulfillment
            .verify_signed(
                &non_all_fulfillment
                    .encode()
                    .expect("non-ALL fulfillment bytes")
            )
            .is_err()
    );
    let mut nonordinary_fulfillment =
        Transaction::decode(prepared_fulfillment.transaction_bytes()).expect("fulfillment");
    let buyer_output_index = 1 + usize::from(verified_listing.proof().fee.get() > 0);
    nonordinary_fulfillment.outputs[buyer_output_index].address =
        Address::new(0, vec![0x78; 32]).expect("nonordinary output address");
    sign_p2pkh_input(&mut nonordinary_fulfillment, 1, &buyer_coin, &buyer_key);
    assert!(
        verify_signed_buyer_fulfillment(
            verified_listing.authenticated(),
            &supplied_lock,
            &buyer_recipient,
            std::slice::from_ref(&buyer_coin),
            TRANSACTION_FEE,
            &nonordinary_fulfillment
                .encode()
                .expect("nonordinary fulfillment bytes"),
        )
        .is_err()
    );
    assert!(
        prepare_buyer_fulfillment(
            &verified_listing,
            &supplied_lock,
            verified_listing.expires_at_unix(),
            ACTIVE_TIME,
            buyer_recipient.clone(),
            vec![unsigned_input(&buyer_coin)],
            vec![buyer_coin.clone()],
            vec![ordinary_output(buyer_recipient.clone(), 628_322)],
            TRANSACTION_FEE,
        )
        .is_err()
    );
    let wrong_recipient = Address::new(0, vec![0x77; 20]).expect("wrong recipient");
    assert!(
        verify_signed_buyer_fulfillment(
            verified_listing.authenticated(),
            &supplied_lock,
            &wrong_recipient,
            std::slice::from_ref(&buyer_coin),
            TRANSACTION_FEE,
            &fulfillment_bytes,
        )
        .is_err()
    );

    let recovery_key = SigningKey::from_slice(&[0x51; 32]).expect("recovery funding key");
    let (_, recovery_program) = public_key_hash(&recovery_key);
    let recovery_recipient =
        Address::new(0, recovery_program.to_vec()).expect("recovery recipient");
    let recovery_coin = funding_coin(0x62, &recovery_key, 100_000);
    let prepared_recovery = prepare_seller_recovery(
        &supplied_lock,
        recovery_recipient.clone(),
        vec![unsigned_input(&recovery_coin)],
        vec![recovery_coin.clone()],
        vec![ordinary_output(recovery_recipient.clone(), 99_000)],
        TRANSACTION_FEE,
    )
    .expect("canonical recovery");
    let seller_signature =
        compact_recovery_signature(&seller_key, prepared_recovery.recovery_signature_hash());
    let seller_authorized = prepared_recovery
        .install_seller_signature(&seller_signature)
        .expect("seller-authorized recovery");
    let mut recovery =
        Transaction::decode(seller_authorized.transaction_bytes()).expect("recovery transaction");
    sign_p2pkh_input(&mut recovery, 1, &recovery_coin, &recovery_key);
    let recovery_bytes = recovery.encode().expect("signed recovery bytes");
    let verified_recovery = seller_authorized
        .verify_signed(&recovery_bytes)
        .expect("fully verified recovery");
    assert!(
        verify_signed_seller_recovery(
            &supplied_lock,
            &wrong_recipient,
            std::slice::from_ref(&recovery_coin),
            TRANSACTION_FEE,
            &recovery_bytes,
        )
        .is_err()
    );

    let transfer_output = fulfillment.outputs[0].clone();
    let transfer_coin = Coin {
        outpoint: Outpoint {
            transaction_hash: fulfillment.transaction_hash().expect("fulfillment txid"),
            index: 0,
        },
        value: transfer_output.value,
        height: Height::new(200),
        coinbase: false,
        address: transfer_output.address,
        covenant: transfer_output.covenant,
    };
    let mut current_state = NameState::null(hash_name(b"market-name").expect("name hash"));
    current_state.name = b"market-name".to_vec();
    current_state.height = Height::new(1);
    current_state.owner = transfer_coin.outpoint;
    current_state.value = transfer_coin.value;
    current_state.transfer = transfer_coin.height;
    current_state.registered = true;
    let finalize_coin = funding_coin(0x63, &buyer_key, 100_000);
    let prepared_finalize = prepare_script_finalize(
        &supplied_lock,
        VerifiedShakedexTransfer::Fulfillment(&verified_fulfillment),
        transfer_coin.clone(),
        current_state.clone(),
        BlockHash::new([0x66; 32]),
        buyer_recipient.clone(),
        vec![unsigned_input(&finalize_coin)],
        vec![finalize_coin.clone()],
        vec![ordinary_output(buyer_recipient.clone(), 99_000)],
        TRANSACTION_FEE,
    )
    .expect("script-controlled FINALIZE");
    let mut unrelated_transfer_coin = transfer_coin.clone();
    unrelated_transfer_coin.outpoint.transaction_hash = CanonicalTransactionHash::new([0x79; 32]);
    let mut unrelated_transfer_state = current_state.clone();
    unrelated_transfer_state.owner = unrelated_transfer_coin.outpoint;
    assert!(
        prepare_script_finalize(
            &supplied_lock,
            VerifiedShakedexTransfer::Fulfillment(&verified_fulfillment),
            unrelated_transfer_coin,
            unrelated_transfer_state,
            BlockHash::new([0x66; 32]),
            buyer_recipient.clone(),
            vec![unsigned_input(&finalize_coin)],
            vec![finalize_coin.clone()],
            vec![ordinary_output(buyer_recipient.clone(), 99_000)],
            TRANSACTION_FEE,
        )
        .is_err()
    );
    let mut finalize =
        Transaction::decode(prepared_finalize.transaction_bytes()).expect("FINALIZE transaction");
    sign_p2pkh_input(&mut finalize, 1, &finalize_coin, &buyer_key);
    let finalize_bytes = finalize.encode().expect("signed FINALIZE bytes");
    let finalized = prepared_finalize
        .verify_signed(&finalize_bytes)
        .expect("fully verified script FINALIZE");
    assert_eq!(finalized.recipient(), &buyer_recipient);
    assert_eq!(
        verify_signed_script_finalize(
            &supplied_lock,
            VerifiedShakedexTransfer::Fulfillment(&verified_fulfillment),
            &transfer_coin,
            &current_state,
            BlockHash::new([0x66; 32]),
            &buyer_recipient,
            std::slice::from_ref(&finalize_coin),
            TRANSACTION_FEE,
            &finalize_bytes,
        )
        .expect("stateless FINALIZE reauthentication")
        .transaction(),
        finalized.transaction()
    );
    current_state.height = Height::new(2);
    assert!(
        prepare_script_finalize(
            &supplied_lock,
            VerifiedShakedexTransfer::Fulfillment(&verified_fulfillment),
            transfer_coin,
            current_state,
            BlockHash::new([0x66; 32]),
            buyer_recipient.clone(),
            vec![unsigned_input(&finalize_coin)],
            vec![finalize_coin.clone()],
            vec![ordinary_output(buyer_recipient.clone(), 99_000)],
            TRANSACTION_FEE,
        )
        .is_err()
    );

    let wallet_id = WalletId::new([0x71; 16]);
    let account_id = AccountId::new([0x72; 16]);
    let seller_workflow = WorkflowId::new([0x73; 16]);
    let buyer_workflow = WorkflowId::new([0x74; 16]);
    let seller_locked = SellerLockPlan::locked(
        wallet_id,
        account_id,
        seller_workflow,
        listing.network(),
        &locking_coin,
        *verified_listing.seller_public_key(),
    )
    .expect("seller lock plan");
    let seller_recovery = seller_locked
        .with_recovery(&verified_recovery, std::slice::from_ref(&recovery_coin))
        .expect("seller recovery plan");
    let buyer_offer = BuyerLockPlan::offer_verified(
        wallet_id,
        account_id,
        buyer_workflow,
        &verified_listing,
        &locking_coin,
    )
    .expect("buyer offer plan");
    let value_workflow_id =
        shakedex_value_workflow_id(buyer_workflow, ShakedexValueAction::BuyerFulfillment);
    let tracked_buyer_coin = TrackedHnsCoin {
        coin: WalletCoin {
            outpoint: HnsOutpoint {
                transaction: TransactionHash::new(
                    buyer_coin.outpoint.transaction_hash.into_bytes(),
                ),
                output_index: buyer_coin.outpoint.index,
            },
            value: BaseUnits::new(u128::from(buyer_coin.value.get())),
            confirmation_count: 10,
            confirmed_height: Some(buyer_coin.height.get()),
            coinbase: buyer_coin.coinbase,
            covenant: buyer_coin.covenant.encode().expect("buyer covenant"),
            name_locked: false,
        },
        derivation: DerivationReference {
            role: KeyRole::HnsCoin,
            account: 7,
            change: 0,
            index: 1,
        },
        address_program: buyer_coin.address.hash.clone(),
    };
    let funding_reservation: HnsShakedexFundingReservation =
        serde_json::from_value(serde_json::json!({
            "wallet_id": wallet_id,
            "account_id": account_id,
            "workflow_id": value_workflow_id,
            "purpose": HnsShakedexFundingPurpose::BuyerFulfillment,
            "name_hash": hash_name(b"market-name").expect("name hash").into_bytes(),
            "source_outpoint": HnsOutpoint {
                transaction: TransactionHash::new(
                    locking_coin.outpoint.transaction_hash.into_bytes(),
                ),
                output_index: locking_coin.outpoint.index,
            },
            "funding_inputs": [tracked_buyer_coin],
            "expires_at_unix": verified_listing.expires_at_unix(),
        }))
        .expect("persisted funding reservation evidence");
    let value_workflow = ShakedexValueWorkflow::prepared_buyer_fulfillment(
        buyer_offer.clone(),
        &prepared_fulfillment,
        funding_reservation,
        BaseUnits::new(2_000),
        2,
        verified_listing.expires_at_unix(),
    )
    .expect("aggregate buyer fulfillment workflow");
    assert_eq!(value_workflow.workflow_id(), value_workflow_id);
    assert_ne!(value_workflow.workflow_id(), buyer_workflow);
    assert_eq!(value_workflow.parent_workflow_id(), buyer_workflow);
    assert_eq!(value_workflow.stage(), ShakedexValueStage::Prepared);
    assert_eq!(
        value_workflow.recipient().expect("recipient"),
        buyer_recipient
    );
    let restarted_value: ShakedexValueWorkflow =
        serde_json::from_slice(&serde_json::to_vec(&value_workflow).expect("aggregate encoding"))
            .expect("aggregate restart decode");
    restarted_value
        .validate()
        .expect("aggregate restart validation");
    assert_eq!(restarted_value, value_workflow);
    let buyer_fulfillment = buyer_offer
        .with_fulfillment(&verified_fulfillment, std::slice::from_ref(&buyer_coin))
        .expect("buyer fulfillment plan");

    let (_cleanup, database, mut store) = test_store();
    assert_eq!(
        save_seller_lock_plan(&mut store, 0, &seller_locked, ACTIVE_TIME)
            .expect("persist seller lock"),
        1
    );
    assert_eq!(
        save_seller_lock_plan(&mut store, 1, &seller_recovery, ACTIVE_TIME + 1)
            .expect("persist seller recovery"),
        2
    );
    assert_eq!(
        save_seller_lock_plan(&mut store, 1, &seller_recovery, ACTIVE_TIME + 2)
            .expect("idempotent seller retry"),
        2
    );
    assert!(matches!(
        save_seller_lock_plan(&mut store, 2, &seller_locked, ACTIVE_TIME + 2),
        Err(ShakedexError::InvalidTransition)
    ));
    assert_eq!(
        save_buyer_lock_plan(&mut store, 0, &buyer_offer, ACTIVE_TIME)
            .expect("persist buyer offer"),
        1
    );
    assert_eq!(
        save_buyer_lock_plan(&mut store, 1, &buyer_fulfillment, ACTIVE_TIME + 1)
            .expect("persist buyer fulfillment"),
        2
    );
    assert_eq!(
        save_buyer_lock_plan(&mut store, 1, &buyer_fulfillment, ACTIVE_TIME + 2)
            .expect("idempotent buyer retry"),
        2
    );
    drop(store);

    let mut reopened = WalletStore::open(&database).expect("reopen encrypted store");
    reopened
        .unlock("canonical-plan-test-passphrase")
        .expect("unlock encrypted store");
    let loaded_seller = load_seller_lock_plan(&reopened, seller_workflow)
        .expect("load seller plan")
        .expect("seller plan exists");
    assert_eq!(loaded_seller.revision, 2);
    assert_eq!(
        loaded_seller.plan.state(),
        SellerLockPlanState::RecoveryPrepared
    );
    assert_eq!(loaded_seller.plan.name(), b"market-name");
    assert_eq!(
        loaded_seller.plan.recovery_transaction(),
        Some(verified_recovery.transaction())
    );
    assert_eq!(
        loaded_seller.plan.recovery_transaction_bytes(),
        Some(recovery_bytes.as_slice())
    );
    assert_eq!(
        loaded_seller
            .plan
            .recovery_recipient()
            .expect("loaded recovery recipient"),
        Some(recovery_recipient)
    );
    assert_eq!(
        loaded_seller.plan.recovery_fee_base_units(),
        Some(TRANSACTION_FEE)
    );
    let loaded_buyer = load_buyer_lock_plan(&reopened, buyer_workflow)
        .expect("load buyer plan")
        .expect("buyer plan exists");
    assert_eq!(loaded_buyer.revision, 2);
    assert_eq!(
        loaded_buyer.plan.state(),
        BuyerLockPlanState::FulfillmentPrepared
    );
    assert_eq!(loaded_buyer.plan.listing_hash(), listing_hash);
    assert_eq!(
        loaded_buyer.plan.fulfillment_transaction(),
        Some(verified_fulfillment.transaction())
    );
    assert_eq!(
        loaded_buyer.plan.fulfillment_transaction_bytes(),
        Some(fulfillment_bytes.as_slice())
    );
    assert_eq!(
        loaded_buyer
            .plan
            .fulfillment_recipient()
            .expect("loaded fulfillment recipient"),
        Some(buyer_recipient)
    );
    assert_eq!(
        loaded_buyer.plan.fulfillment_fee_base_units(),
        Some(TRANSACTION_FEE)
    );
    assert_eq!(
        list_seller_lock_plans(&reopened)
            .expect("complete seller recovery list")
            .len(),
        1
    );
    assert_eq!(
        list_buyer_lock_plans(&reopened)
            .expect("complete buyer recovery list")
            .len(),
        1
    );
}
