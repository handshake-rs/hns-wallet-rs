#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{FinalizeCovenant, NameState, hash_name};
use hns_marketplace_protocol::{DenuoRegistryVersion, NameMarketMessage};
use hns_primitives::{
    BlockHash, Dollarydoos, Height, Outpoint as CanonicalOutpoint,
    TransactionHash as CanonicalTransactionHash,
};
use hns_swap::{
    FixedPriceListing, ListingCancellation, NetworkBinding, SwapProof, lock_script_hash,
};
use hns_transaction::{Address, Coin, Input, Outpoint, Output, Transaction, Witness};
use hns_wallet_hns::{
    BlockHashEvidence, ChainTip, ConfirmedWalletPage, ConfirmedWalletPageRequest,
    HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED, HNS_VALUE_RUNTIME_RELEASE_QUALIFIED,
    HnsAccountReadRuntime, HnsAccountRecord, HnsBackend, HnsBootstrapPolicy, HnsClock,
    HnsExistingAccountSelector, HnsNameAction, HnsNameLifecycle, HnsNetwork, HnsOutpoint,
    HnsRuntimeConfig, HnsTransactionFeeQuote, HnsWalletBootstrap, HnsWalletError,
    MempoolSnapshotBinding, MempoolWalletPage, MempoolWalletPageRequest, NameActionContextEvidence,
    NameEvidence, NameProofResponse, OutpointSpendEntry, OutpointSpendEvidence, SnapshotBinding,
    SpendingTransactionEvidence, TransactionEvidence,
};
use hns_wallet_shakedex::{
    DenuoBoardCancellationAdmission, DenuoBoardOfferAdmission, DenuoBoardRuntime,
    SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED, SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED,
    SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED, ShakedexError, load_name_market_board,
};
use hns_wallet_store::{SharedWalletStore, WalletStore};
use hns_wallet_types::{AccountId, BaseUnits, ObjectHash, TransactionHash};
use k256::ecdsa::SigningKey;

const PASSPHRASE: &str = "board runtime restart passphrase";
const NOW_UNIX: u64 = 1_800_000_200;
const REGTEST_GENESIS: &str = "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5";

#[derive(Clone, Copy)]
struct TestClock;

impl HnsClock for TestClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        Ok(NOW_UNIX)
    }
}

#[derive(Clone, Copy)]
struct LateClock;

impl HnsClock for LateClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        Ok(NOW_UNIX + 5_000)
    }
}

struct AccountMutatingClock {
    store: SharedWalletStore,
    account_id: [u8; 32],
    called: AtomicBool,
}

impl HnsClock for AccountMutatingClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        if self.called.swap(true, Ordering::SeqCst) {
            return Err(HnsWalletError::RuntimePoisoned);
        }
        self.store.try_with_store_mut(|wallet| {
            let stored = wallet
                .wallet_account::<HnsAccountRecord>(&self.account_id)?
                .ok_or(HnsWalletError::StaleAccountRead)?;
            let mut changed = stored.value;
            changed.next_receive_index = changed
                .next_receive_index
                .checked_add(1)
                .ok_or(HnsWalletError::InvalidEvidence)?;
            wallet
                .save_wallet_account(&stored.id, stored.revision, &changed, NOW_UNIX)
                .map(|_| ())
                .map_err(HnsWalletError::from)
        })?;
        Ok(NOW_UNIX)
    }
}

struct MarketFixture {
    name: Vec<u8>,
    name_hash: [u8; 32],
    signing_key: SigningKey,
    network: NetworkBinding,
    locking_coin: Coin,
    owner_outpoint: HnsOutpoint,
    owner_transaction: Vec<u8>,
    owner_inclusion: hns_wallet_hns::TransactionInclusion,
    state: Vec<u8>,
    proof: Vec<u8>,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
}

impl MarketFixture {
    fn new() -> Self {
        let name = b"authority-board".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key: [u8; 33] = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let genesis = BlockHash::from_hex(REGTEST_GENESIS).expect("regtest genesis");
        let network = NetworkBinding {
            magic: 0xae38_95cf,
            genesis,
        };
        let mut state = NameState {
            name_hash,
            name: name.clone(),
            height: Height::new(1),
            renewal: Height::new(100),
            owner: CanonicalOutpoint::NULL,
            value: Dollarydoos::new(900_000),
            highest: Dollarydoos::new(900_000),
            resource_data: Vec::new(),
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 0,
            registered: true,
            expired: false,
            weak: false,
        };
        let covenant = FinalizeCovenant::new(
            name.clone(),
            state.height,
            state.weak,
            state.claimed,
            state.renewals,
            BlockHash::new([0x55; 32]),
        )
        .expect("finalize covenant")
        .to_covenant()
        .expect("canonical covenant");
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: CanonicalTransactionHash::new([0x42; 32]),
                    index: 1,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: state.value,
                address: Address::new(0, lock_script_hash(&seller_public_key).to_vec())
                    .expect("lock address"),
                covenant,
            }],
            locktime: 0,
        };
        let transaction_hash = transaction
            .transaction_hash()
            .expect("owner transaction hash");
        state.owner = CanonicalOutpoint {
            transaction_hash,
            index: 0,
        };
        let owner_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(transaction_hash.into_bytes()),
            output_index: 0,
        };
        let owner_inclusion = hns_wallet_hns::TransactionInclusion {
            block_hash: [0x61; 32],
            height: 123,
            transaction_index: Some(2),
        };
        let state = state.encode().expect("name state");
        let proof = inclusion_proof(&state);
        let tree_root = inclusion_root(name_hash.as_bytes(), &state);
        let binding = SnapshotBinding {
            tip: ChainTip {
                height: 500,
                block_hash: [0x62; 32],
                tree_root,
                median_time_past: NOW_UNIX - 20,
            },
            chain_epoch: 7,
        };
        let mempool = MempoolSnapshotBinding {
            instance_nonce: [0x63; 32],
            generation: 9,
        };
        let owner_transaction = transaction.encode().expect("owner transaction");
        let locking_coin = Coin {
            outpoint: Outpoint {
                transaction_hash,
                index: 0,
            },
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: transaction.outputs[0].address.clone(),
            covenant: transaction.outputs[0].covenant.clone(),
        };
        Self {
            name,
            name_hash: name_hash.into_bytes(),
            signing_key,
            network,
            locking_coin,
            owner_outpoint,
            owner_transaction,
            owner_inclusion,
            state,
            proof,
            binding,
            mempool,
        }
    }

    fn listing(&self, sequence: u64, price: u64) -> FixedPriceListing {
        let seller_public_key = self.signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key: [u8; 33] = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let mut proof = SwapProof {
            network: self.network,
            locking_outpoint: self.locking_coin.outpoint,
            name: self.name.clone(),
            seller_public_key,
            payment_address: Address::new(0, vec![0x71; 20]).expect("payment address"),
            price: Dollarydoos::new(price),
            lock_time_seconds: NOW_UNIX - 100,
            signature: None,
            fee_address: None,
            fee: Dollarydoos::new(0),
        };
        proof
            .sign(&self.locking_coin, &self.signing_key)
            .expect("signed proof");
        let mut listing = FixedPriceListing {
            proof,
            created_at: NOW_UNIX - 60,
            expires_at: NOW_UNIX + 3_600,
            sequence,
            signature: None,
        };
        listing.sign(&self.signing_key).expect("signed listing");
        listing
    }

    fn offer(&self, sequence: u64, request_id: u64, price: u64) -> (Vec<u8>, ObjectHash) {
        let listing = self.listing(sequence, price);
        let hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
        let envelope = NameMarketMessage::Offer(listing)
            .encode_envelope(DenuoRegistryVersion::V2, request_id)
            .expect("offer envelope");
        (envelope, hash)
    }

    fn cancellation(
        &self,
        listing: &FixedPriceListing,
        sequence: u64,
        request_id: u64,
    ) -> (ListingCancellation, Vec<u8>, ObjectHash) {
        let mut cancellation = ListingCancellation::for_listing(
            listing,
            NOW_UNIX - 1,
            listing.expires_at + 600,
            sequence,
        )
        .expect("cancellation terms");
        cancellation
            .sign(&self.signing_key)
            .expect("signed cancellation");
        let (envelope, cancellation_hash) =
            Self::cancellation_envelope(&cancellation, DenuoRegistryVersion::V2, request_id);
        (cancellation, envelope, cancellation_hash)
    }

    fn cancellation_envelope(
        cancellation: &ListingCancellation,
        registry: DenuoRegistryVersion,
        request_id: u64,
    ) -> (Vec<u8>, ObjectHash) {
        let cancellation_hash =
            ObjectHash::new(cancellation.cancellation_hash().expect("cancellation hash"));
        let envelope = NameMarketMessage::Cancel(cancellation.clone())
            .encode_envelope(registry, request_id)
            .expect("cancellation envelope");
        (envelope, cancellation_hash)
    }
}

#[derive(Clone)]
struct BackendControl {
    spent: Arc<AtomicBool>,
    restart_mempool_on_fence: Arc<AtomicBool>,
    reject_queries: Arc<AtomicBool>,
    query_count: Arc<AtomicU64>,
}

impl BackendControl {
    fn new() -> Self {
        Self {
            spent: Arc::new(AtomicBool::new(false)),
            restart_mempool_on_fence: Arc::new(AtomicBool::new(false)),
            reject_queries: Arc::new(AtomicBool::new(false)),
            query_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

struct TestBackend {
    market: Arc<MarketFixture>,
    control: BackendControl,
}

impl TestBackend {
    fn unexpected(method: &str) -> HnsWalletError {
        HnsWalletError::Backend(format!("unexpected board test backend call: {method}"))
    }

    fn record_query(&self, method: &str) -> Result<(), HnsWalletError> {
        self.control.query_count.fetch_add(1, Ordering::SeqCst);
        if self.control.reject_queries.load(Ordering::SeqCst) {
            return Err(Self::unexpected(method));
        }
        Ok(())
    }
}

impl HnsBackend for TestBackend {
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
        self.record_query("get_chain_snapshot")?;
        Ok(self.market.binding)
    }

    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
        self.record_query("get_chain_tip")?;
        Ok(self.market.binding.tip)
    }

    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError> {
        self.record_query("get_block_hash")?;
        if binding != self.market.binding {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let block_hash = match height {
            0 => self.market.network.genesis.into_bytes(),
            value if value == binding.tip.height => binding.tip.block_hash,
            _ => [0x64; 32],
        };
        Ok(BlockHashEvidence {
            binding,
            height,
            block_hash: Some(block_hash),
        })
    }

    fn get_confirmed_wallet_page(
        &self,
        _: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError> {
        self.record_query("get_confirmed_wallet_page")?;
        Err(Self::unexpected("get_confirmed_wallet_page"))
    }

    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError> {
        self.record_query("get_mempool_wallet_page")?;
        let seller_public_key = self
            .market
            .signing_key
            .verifying_key()
            .to_encoded_point(true);
        let expected = lock_script_hash(
            seller_public_key
                .as_bytes()
                .try_into()
                .expect("compressed seller key"),
        );
        if request.binding != self.market.binding
            || request.scripts.len() != 1
            || request.scripts[0].version != 0
            || request.scripts[0].hash.as_slice() != expected
            || request.cursor.is_some()
            || request.limit != 1
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mut mempool = self.market.mempool;
        if request.expected_mempool.is_some()
            && self.control.restart_mempool_on_fence.load(Ordering::SeqCst)
        {
            mempool.instance_nonce = [0x65; 32];
            mempool.generation = 1;
        }
        Ok(MempoolWalletPage {
            binding: self.market.binding,
            mempool,
            next_cursor: None,
            history: Vec::new(),
        })
    }

    fn get_transaction_evidence(
        &self,
        _: TransactionHash,
        _: SnapshotBinding,
        _: Option<MempoolSnapshotBinding>,
    ) -> Result<TransactionEvidence, HnsWalletError> {
        self.record_query("get_transaction_evidence")?;
        Err(Self::unexpected("get_transaction_evidence"))
    }

    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError> {
        self.record_query("get_outpoint_spend_evidence")?;
        if binding != self.market.binding || outpoints != [self.market.owner_outpoint] {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let spending =
            self.control
                .spent
                .load(Ordering::SeqCst)
                .then_some(SpendingTransactionEvidence {
                    transaction: TransactionHash::new([0x66; 32]),
                    input_position: 0,
                    block_hash: [0x67; 32],
                    height: binding.tip.height,
                });
        Ok(OutpointSpendEvidence {
            binding,
            entries: vec![OutpointSpendEntry {
                outpoint: self.market.owner_outpoint,
                spending,
            }],
        })
    }

    fn broadcast_transaction(&self, _: &[u8]) -> Result<TransactionHash, HnsWalletError> {
        self.record_query("broadcast_transaction")?;
        Err(Self::unexpected("broadcast_transaction"))
    }

    fn quote_transaction_fee(
        &self,
        _: &[u8],
        _: &[Coin],
        _: u16,
        _: SnapshotBinding,
        _: MempoolSnapshotBinding,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        self.record_query("quote_transaction_fee")?;
        Err(Self::unexpected("quote_transaction_fee"))
    }

    fn estimate_fee_rate(&self, _: u16) -> Result<BaseUnits, HnsWalletError> {
        self.record_query("estimate_fee_rate")?;
        Err(Self::unexpected("estimate_fee_rate"))
    }

    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError> {
        self.record_query("get_name_evidence")?;
        if name_hash != self.market.name_hash || binding != self.market.binding {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(NameEvidence {
            binding,
            proof: NameProofResponse {
                name_hash,
                tree_root: binding.tip.tree_root,
                proof: self.market.proof.clone(),
                proof_height: binding.tip.height,
            },
            proof_state: Some(self.market.state.clone()),
            proof_owner_outpoint: Some(self.market.owner_outpoint),
            proof_owner_transaction: Some(self.market.owner_transaction.clone()),
            proof_owner_inclusion: Some(self.market.owner_inclusion),
            current_state: Some(self.market.state.clone()),
            current_owner_outpoint: Some(self.market.owner_outpoint),
            current_owner_transaction: Some(self.market.owner_transaction.clone()),
            current_owner_inclusion: Some(self.market.owner_inclusion),
            untrusted_current_raw_resource: Some(Vec::new()),
        })
    }

    fn get_name_action_context(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        self.record_query("get_name_action_context")?;
        if action != HnsNameAction::Transfer
            || name_hash != self.market.name_hash
            || binding != self.market.binding
            || mempool != self.market.mempool
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(NameActionContextEvidence {
            binding,
            mempool,
            network: hns_wallet_hns::HnsNetwork::Regtest,
            network_id: 2,
            genesis_hash: self.market.network.genesis.into_bytes(),
            context_version: 1,
            consensus_profile: "hns-consensus/name-policy-v1".to_owned(),
            action,
            name_hash,
            current_state: self.market.state.clone(),
            owner_outpoint: self.market.owner_outpoint,
            owner_transaction: self.market.owner_transaction.clone(),
            owner_inclusion: self.market.owner_inclusion,
            candidate_inclusion_height: binding.tip.height + 1,
            lifecycle: HnsNameLifecycle::Closed,
            action_eligible: true,
            ineligibility_reasons: Vec::new(),
            transfer_height: None,
            transfer_lockup: None,
            finalize_eligible_height: None,
            finalize_mature: None,
            renewal_maturity: None,
            renewal_period: None,
            renewal_block_height: None,
            renewal_block_hash: None,
            renewal_valid_at_candidate: None,
            mempool_spender: None,
        })
    }
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("BLAKE2b output buffer");
    output
}

fn cancellation_envelope_with_invalid_signature(encoded: &[u8]) -> Vec<u8> {
    const DENUO_ENVELOPE_OVERHEAD: usize = 26;
    const CANCELLATION_SIGNATURE_OFFSET: usize = 128;
    const CANCELLATION_HASH_SIZE: usize = 32;
    const CANCELLATION_HASH_DOMAIN: &[u8] = b"hns-rs/hns-swap/listing-cancellation/v1/hash";

    let mut tampered = encoded.to_vec();
    let hash_start = tampered
        .len()
        .checked_sub(CANCELLATION_HASH_SIZE)
        .expect("cancellation envelope hash");
    let signature_index = DENUO_ENVELOPE_OVERHEAD + CANCELLATION_SIGNATURE_OFFSET;
    assert!(signature_index < hash_start);
    tampered[signature_index] ^= 1;
    let hash = blake2b_256(&[
        CANCELLATION_HASH_DOMAIN,
        &tampered[DENUO_ENVELOPE_OVERHEAD..hash_start],
    ]);
    tampered[hash_start..].copy_from_slice(&hash);
    tampered
}

fn inclusion_proof(value: &[u8]) -> Vec<u8> {
    let mut proof = Vec::with_capacity(value.len() + 6);
    proof.extend_from_slice(&(3_u16 << 14).to_le_bytes());
    proof.extend_from_slice(&0_u16.to_le_bytes());
    proof.extend_from_slice(
        &u16::try_from(value.len())
            .expect("bounded name state")
            .to_le_bytes(),
    );
    proof.extend_from_slice(value);
    proof
}

fn inclusion_root(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let value_hash = blake2b_256(&[value]);
    blake2b_256(&[&[0], key, &value_hash])
}

fn create_store(path: impl AsRef<Path>) -> (SharedWalletStore, HnsRuntimeConfig) {
    let mut store = WalletStore::create(path, PASSPHRASE).expect("wallet store");
    let bootstrap = HnsWalletBootstrap::generate(HnsBootstrapPolicy::new(
        hns_wallet_hns::HnsNetwork::Regtest,
        0,
    ))
    .expect("non-value HNS account");
    let config = bootstrap.account_record().config.clone();
    bootstrap
        .persist(&mut store, NOW_UNIX - 1)
        .expect("persist non-value account");
    (SharedWalletStore::new(store), config)
}

fn runtime(
    store: SharedWalletStore,
    config: HnsRuntimeConfig,
    market: Arc<MarketFixture>,
    control: BackendControl,
) -> HnsAccountReadRuntime<TestBackend, TestClock> {
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    HnsAccountReadRuntime::new(TestBackend { market, control }, TestClock, store, selector)
        .expect("account read runtime")
}

fn late_runtime(
    store: SharedWalletStore,
    config: HnsRuntimeConfig,
    market: Arc<MarketFixture>,
    control: BackendControl,
) -> HnsAccountReadRuntime<TestBackend, LateClock> {
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    HnsAccountReadRuntime::new(TestBackend { market, control }, LateClock, store, selector)
        .expect("late account read runtime")
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let parent = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "hns-wallet-denuo-board-runtime-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("test directory");
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn authority_bound_board_exact_retry_survives_restart_without_revision_bump() {
    let directory = TestDirectory::new();
    let database = directory.0.join("wallet.sqlite3");
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    let (envelope, listing_hash) = market.offer(1, 41, 12_345_678);
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = DenuoBoardRuntime::new(&hns, store.clone()).expect("shared store authority");

    assert!(matches!(
        board.admit_offer(&envelope, listing_hash),
        Ok(DenuoBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    assert!(matches!(
        board.admit_offer(&envelope, listing_hash),
        Ok(DenuoBoardOfferAdmission::Existing { revision: 1, .. })
    ));
    let current = board
        .current_offer(listing_hash)
        .expect("fresh board authority")
        .expect("current offer");
    assert_eq!(current.board_revision(), 1);
    assert_eq!(current.listing().listing_hash(), listing_hash);
    assert_eq!(
        current.current_lock().locking_coin().outpoint,
        market.locking_coin.outpoint
    );
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("board")
            .revision,
        1
    );
    drop(board);
    drop(hns);
    drop(store);

    let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
    reopened.unlock(PASSPHRASE).expect("unlock restarted store");
    let restarted_store = SharedWalletStore::new(reopened);
    let restarted_hns = runtime(
        restarted_store.clone(),
        config,
        market,
        BackendControl::new(),
    );
    let restarted = DenuoBoardRuntime::new(&restarted_hns, restarted_store)
        .expect("restarted shared authority");
    assert!(matches!(
        restarted.admit_offer(&envelope, listing_hash),
        Ok(DenuoBoardOfferAdmission::Existing { revision: 1, .. })
    ));
    assert_eq!(
        restarted
            .current_offer(listing_hash)
            .expect("restart reacquisition")
            .expect("current after restart")
            .board_revision(),
        1
    );
}

#[test]
fn board_conflicts_spends_stale_mempool_and_unrelated_stores_fail_closed() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market.clone(), control.clone());
    let unrelated = SharedWalletStore::new(
        WalletStore::create(":memory:", "unrelated board store").expect("unrelated store"),
    );
    assert!(matches!(
        DenuoBoardRuntime::new(&hns, unrelated),
        Err(ShakedexError::StoreAuthorityMismatch)
    ));
    let board = DenuoBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    let (first, first_hash) = market.offer(5, 51, 12_345_678);
    assert!(matches!(
        board.admit_offer(&first, first_hash),
        Ok(DenuoBoardOfferAdmission::Inserted { revision: 1, .. })
    ));

    let (equivocation, equivocation_hash) = market.offer(5, 52, 12_345_679);
    assert!(matches!(
        board.admit_offer(&equivocation, equivocation_hash),
        Err(ShakedexError::NameMarketReplay)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged board")
            .revision,
        1
    );

    let (update, update_hash) = market.offer(6, 53, 12_345_680);
    control.spent.store(true, Ordering::SeqCst);
    assert!(matches!(
        board.admit_offer(&update, update_hash),
        Err(ShakedexError::InvalidEvidence)
    ));
    assert!(matches!(
        board.current_offer(first_hash),
        Err(ShakedexError::InvalidEvidence)
    ));
    control.spent.store(false, Ordering::SeqCst);

    control
        .restart_mempool_on_fence
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        board.admit_offer(&update, update_hash),
        Err(ShakedexError::InvalidEvidence)
    ));
    control
        .restart_mempool_on_fence
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        board.admit_offer(&update, update_hash),
        Ok(DenuoBoardOfferAdmission::Updated { revision: 2, .. })
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("updated board")
            .revision,
        2
    );
    assert!(
        board
            .current_offer(first_hash)
            .expect("replaced offer lookup")
            .is_none()
    );
    let current_update = board
        .current_offer(update_hash)
        .expect("updated offer authority")
        .expect("updated offer");
    assert_eq!(current_update.board_revision(), 2);
    assert_eq!(current_update.listing().listing_hash(), update_hash);
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "a release-gate flip requires explicit review of this authority boundary"
)]
fn signed_cancellation_tombstone_survives_spend_restart_and_expiry_without_node_queries() {
    let directory = TestDirectory::new();
    let database = directory.0.join("wallet.sqlite3");
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(7, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(DenuoRegistryVersion::V2, 70)
        .expect("offer envelope");
    let (cancellation, cancellation_envelope, cancellation_hash) =
        market.cancellation(&listing, 8, 71);
    let retry_envelope = NameMarketMessage::Cancel(cancellation)
        .encode_envelope(DenuoRegistryVersion::V2, 72)
        .expect("retry cancellation envelope");
    let control = BackendControl::new();
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = DenuoBoardRuntime::new(&hns, store.clone()).expect("shared store authority");

    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(DenuoBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let node_queries_after_offer = control.query_count.load(Ordering::SeqCst);
    assert!(node_queries_after_offer > 0);
    control.spent.store(true, Ordering::SeqCst);
    control.reject_queries.store(true, Ordering::SeqCst);

    let applied = board
        .admit_cancellation(&cancellation_envelope, listing_hash, cancellation_hash)
        .expect("negative tombstone after lock spend");
    assert!(matches!(
        applied,
        DenuoBoardCancellationAdmission::Applied { revision: 2, .. }
    ));
    assert_eq!(applied.request_id(), 71);
    assert_eq!(applied.listing_hash(), listing_hash);
    assert_eq!(applied.cancellation_hash(), cancellation_hash);
    assert_eq!(applied.revision(), 2);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        node_queries_after_offer
    );
    let persisted = store
        .try_with_store(load_name_market_board)
        .expect("cancelled board");
    let persisted_offer = persisted.board.offer(listing_hash).expect("target row");
    assert_eq!(persisted.revision, 2);
    assert_eq!(
        persisted_offer.status,
        hns_wallet_shakedex::BoardOfferStatus::Cancelled
    );
    assert_eq!(persisted_offer.cancellation_hash, Some(cancellation_hash));
    assert!(
        board
            .current_offer(listing_hash)
            .expect("cancelled lookup")
            .is_none()
    );

    let existing = board
        .admit_cancellation(&retry_envelope, listing_hash, cancellation_hash)
        .expect("exact cancellation retry");
    assert!(matches!(
        existing,
        DenuoBoardCancellationAdmission::Existing { revision: 2, .. }
    ));
    assert_eq!(existing.request_id(), 72);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        node_queries_after_offer
    );
    drop(board);
    drop(hns);
    drop(store);

    let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
    reopened.unlock(PASSPHRASE).expect("unlock restarted store");
    let restarted_store = SharedWalletStore::new(reopened);
    let restarted_control = BackendControl::new();
    restarted_control
        .reject_queries
        .store(true, Ordering::SeqCst);
    let restarted_hns = late_runtime(
        restarted_store.clone(),
        config.clone(),
        market.clone(),
        restarted_control.clone(),
    );
    let restarted = DenuoBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    assert!(matches!(
        restarted.admit_cancellation(&retry_envelope, listing_hash, cancellation_hash),
        Ok(DenuoBoardCancellationAdmission::Existing { revision: 2, .. })
    ));
    assert!(
        restarted
            .current_offer(listing_hash)
            .expect("cancelled restart lookup")
            .is_none()
    );
    assert_eq!(restarted_control.query_count.load(Ordering::SeqCst), 0);

    drop(restarted);
    drop(restarted_hns);
    let mut other_network_config = config;
    other_network_config.network = HnsNetwork::Testnet;
    restarted_store
        .try_with_store_mut(|wallet| {
            let mut accounts = wallet.wallet_accounts::<HnsAccountRecord>(2)?;
            let stored = accounts.pop().expect("selected account row");
            assert!(accounts.is_empty());
            let mut changed = stored.value;
            changed.config.network = other_network_config.network;
            wallet
                .save_wallet_account(&stored.id, stored.revision, &changed, NOW_UNIX)
                .map(|_| ())
        })
        .expect("move selected account to another network");
    let other_network_control = BackendControl::new();
    other_network_control
        .reject_queries
        .store(true, Ordering::SeqCst);
    let other_network_hns = late_runtime(
        restarted_store.clone(),
        other_network_config,
        market,
        other_network_control.clone(),
    );
    let other_network_board = DenuoBoardRuntime::new(&other_network_hns, restarted_store.clone())
        .expect("other-network board");
    assert!(matches!(
        other_network_board.admit_cancellation(&retry_envelope, listing_hash, cancellation_hash,),
        Err(ShakedexError::InvalidCancellation)
    ));
    assert_eq!(other_network_control.query_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        restarted_store
            .try_with_store(load_name_market_board)
            .expect("cross-network retry leaves board unchanged")
            .revision,
        2
    );

    assert!(!HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
    assert!(!HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
    assert!(!SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
    assert!(!SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED);
    assert!(!SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
}

#[test]
fn cancellation_admission_rejects_wrong_identity_absence_and_expired_initial_mutation() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(10, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(DenuoRegistryVersion::V2, 80)
        .expect("offer envelope");
    let (base_cancellation, cancellation_envelope, cancellation_hash) =
        market.cancellation(&listing, 11, 81);
    let control = BackendControl::new();
    let (store, config) = create_store(":memory:");
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = DenuoBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(DenuoBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let node_queries_after_offer = control.query_count.load(Ordering::SeqCst);
    control.reject_queries.store(true, Ordering::SeqCst);

    assert!(matches!(
        board.admit_cancellation(
            &cancellation_envelope,
            ObjectHash::new([0x81; 32]),
            cancellation_hash,
        ),
        Err(ShakedexError::InvalidCancellation)
    ));
    assert!(matches!(
        board.admit_cancellation(
            &cancellation_envelope,
            listing_hash,
            ObjectHash::new([0x82; 32]),
        ),
        Err(ShakedexError::InvalidCancellation)
    ));
    let (wrong_registry, _) =
        MarketFixture::cancellation_envelope(&base_cancellation, DenuoRegistryVersion::V1, 81);
    assert!(matches!(
        board.admit_cancellation(&wrong_registry, listing_hash, cancellation_hash),
        Err(ShakedexError::DenuoRegistryMismatch)
    ));
    assert!(matches!(
        board.admit_cancellation(&offer, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidDenuoEnvelope)
    ));
    let invalid_signature = cancellation_envelope_with_invalid_signature(&cancellation_envelope);
    assert!(matches!(
        board.admit_cancellation(&invalid_signature, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidDenuoEnvelope)
    ));

    let mut wrong_network = base_cancellation.clone();
    wrong_network.network.magic ^= 1;
    wrong_network.signature = None;
    wrong_network
        .sign(&market.signing_key)
        .expect("wrong-network signature");
    let (wrong_network_envelope, wrong_network_hash) =
        MarketFixture::cancellation_envelope(&wrong_network, DenuoRegistryVersion::V2, 83);
    assert!(matches!(
        board.admit_cancellation(&wrong_network_envelope, listing_hash, wrong_network_hash,),
        Err(ShakedexError::InvalidCancellation)
    ));

    let wrong_seller_key = SigningKey::from_slice(&[0x44; 32]).expect("wrong seller key");
    let wrong_seller_public_key: [u8; 33] = wrong_seller_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("wrong compressed seller key");
    let mut wrong_seller = base_cancellation.clone();
    wrong_seller.seller_public_key = wrong_seller_public_key;
    wrong_seller.signature = None;
    wrong_seller
        .sign(&wrong_seller_key)
        .expect("wrong-seller signature");
    let (wrong_seller_envelope, wrong_seller_hash) =
        MarketFixture::cancellation_envelope(&wrong_seller, DenuoRegistryVersion::V2, 84);
    assert!(matches!(
        board.admit_cancellation(&wrong_seller_envelope, listing_hash, wrong_seller_hash),
        Err(ShakedexError::InvalidCancellation)
    ));

    let mut not_yet_active = base_cancellation.clone();
    not_yet_active.created_at = NOW_UNIX + 100;
    not_yet_active.signature = None;
    not_yet_active
        .sign(&market.signing_key)
        .expect("future cancellation signature");
    let (not_yet_active_envelope, not_yet_active_hash) =
        MarketFixture::cancellation_envelope(&not_yet_active, DenuoRegistryVersion::V2, 85);
    assert!(matches!(
        board.admit_cancellation(&not_yet_active_envelope, listing_hash, not_yet_active_hash,),
        Err(ShakedexError::InvalidCancellation)
    ));
    let absent_listing = market.listing(12, 12_345_679);
    let absent_hash = ObjectHash::new(absent_listing.listing_hash().expect("absent hash"));
    let (_, absent_cancellation, absent_cancellation_hash) =
        market.cancellation(&absent_listing, 13, 82);
    assert!(matches!(
        board.admit_cancellation(&absent_cancellation, absent_hash, absent_cancellation_hash,),
        Err(ShakedexError::InvalidCancellation)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged board")
            .revision,
        1
    );
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        node_queries_after_offer
    );
    drop(board);
    drop(hns);

    let late_control = BackendControl::new();
    late_control.reject_queries.store(true, Ordering::SeqCst);
    let late_hns = late_runtime(store.clone(), config, market, late_control.clone());
    let late_board =
        DenuoBoardRuntime::new(&late_hns, store.clone()).expect("late shared authority");
    assert!(matches!(
        late_board.admit_cancellation(&cancellation_envelope, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidCancellation)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("still unchanged board")
            .revision,
        1
    );
    assert_eq!(late_control.query_count.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_sequence_conflicts_and_tombstone_watermark_survive_restart() {
    let directory = TestDirectory::new();
    let database = directory.0.join("wallet.sqlite3");
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(20, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(DenuoRegistryVersion::V2, 90)
        .expect("offer envelope");
    let (base_cancellation, zero_id_cancellation, cancellation_hash) =
        market.cancellation(&listing, 23, 0);
    let control = BackendControl::new();
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = DenuoBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(DenuoBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let node_queries_after_offer = control.query_count.load(Ordering::SeqCst);
    control.reject_queries.store(true, Ordering::SeqCst);
    let zero_id = board
        .admit_cancellation(&zero_id_cancellation, listing_hash, cancellation_hash)
        .expect("zero-ID offline cancellation");
    assert!(matches!(
        zero_id,
        DenuoBoardCancellationAdmission::Applied { revision: 2, .. }
    ));
    assert_eq!(zero_id.request_id(), 0);

    let mut same_sequence = base_cancellation.clone();
    same_sequence.created_at = NOW_UNIX - 2;
    same_sequence.expires_at += 1;
    same_sequence.signature = None;
    same_sequence
        .sign(&market.signing_key)
        .expect("same-sequence conflict signature");
    let (same_sequence_envelope, same_sequence_hash) =
        MarketFixture::cancellation_envelope(&same_sequence, DenuoRegistryVersion::V2, 91);
    assert!(matches!(
        board.admit_cancellation(&same_sequence_envelope, listing_hash, same_sequence_hash,),
        Err(ShakedexError::NameMarketReplay)
    ));

    let (_, lower_sequence_envelope, lower_sequence_hash) = market.cancellation(&listing, 22, 92);
    assert!(matches!(
        board.admit_cancellation(&lower_sequence_envelope, listing_hash, lower_sequence_hash,),
        Err(ShakedexError::NameMarketReplay)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged conflicts")
            .revision,
        2
    );

    let (_, higher_sequence_envelope, higher_sequence_hash) = market.cancellation(&listing, 24, 93);
    assert!(matches!(
        board.admit_cancellation(
            &higher_sequence_envelope,
            listing_hash,
            higher_sequence_hash,
        ),
        Ok(DenuoBoardCancellationAdmission::Applied { revision: 3, .. })
    ));
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        node_queries_after_offer
    );
    drop(board);
    drop(hns);
    drop(store);

    let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
    reopened.unlock(PASSPHRASE).expect("unlock restarted store");
    let restarted_store = SharedWalletStore::new(reopened);
    let restarted_control = BackendControl::new();
    let restarted_hns = runtime(
        restarted_store.clone(),
        config,
        market.clone(),
        restarted_control,
    );
    let restarted = DenuoBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    let replayed_listing = market.listing(24, 12_345_679);
    let replayed_hash = ObjectHash::new(
        replayed_listing
            .listing_hash()
            .expect("replayed listing hash"),
    );
    let replayed_offer = NameMarketMessage::Offer(replayed_listing)
        .encode_envelope(DenuoRegistryVersion::V2, 94)
        .expect("replayed offer envelope");
    assert!(matches!(
        restarted.admit_offer(&replayed_offer, replayed_hash),
        Err(ShakedexError::NameMarketReplay)
    ));
    assert_eq!(
        restarted_store
            .try_with_store(load_name_market_board)
            .expect("durable higher watermark")
            .revision,
        3
    );
}

#[test]
fn board_cancellation_context_fences_full_wallet_account_selection_without_node_calls() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market, control.clone());
    let context = hns
        .observe_board_cancellation_context()
        .expect("account/network/time context");
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);

    let mut duplicate = hns.selected_account().expect("selected account");
    let duplicate_account_id = AccountId::new([0x93; 16]);
    duplicate.config.account_id = duplicate_account_id;
    let mut duplicate_record_id = [0_u8; 32];
    duplicate_record_id[..16].copy_from_slice(duplicate.config.wallet_id.as_bytes());
    duplicate_record_id[16..].copy_from_slice(duplicate_account_id.as_bytes());
    store
        .try_with_store_mut(|wallet| {
            wallet
                .save_wallet_account(&duplicate_record_id, 0, &duplicate, NOW_UNIX)
                .map(|_| ())
        })
        .expect("inject duplicate-derivation wallet-scoped row");
    assert!(matches!(
        store.try_with_store(|wallet| context.verify_unchanged_account(wallet)),
        Err(HnsWalletError::DuplicateAccountDerivation)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}

#[test]
fn board_cancellation_context_rejects_malformed_wallet_scoped_account_row() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market, control.clone());
    let context = hns
        .observe_board_cancellation_context()
        .expect("account/network/time context");

    let mut malformed = hns.selected_account().expect("selected account");
    malformed.config.account_id = AccountId::new([0x94; 16]);
    malformed.config.account_derivation_index += 1;
    let mut malformed_record_id = [0x95_u8; 32];
    malformed_record_id[..16].copy_from_slice(malformed.config.wallet_id.as_bytes());
    store
        .try_with_store_mut(|wallet| {
            wallet
                .save_wallet_account(&malformed_record_id, 0, &malformed, NOW_UNIX)
                .map(|_| ())
        })
        .expect("inject malformed wallet-scoped row");
    assert!(matches!(
        store.try_with_store(|wallet| context.verify_unchanged_account(wallet)),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}

#[test]
fn board_cancellation_context_fences_account_mutation_during_clock_observation() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let mut account_id = [0_u8; 32];
    account_id[..16].copy_from_slice(config.wallet_id.as_bytes());
    account_id[16..].copy_from_slice(config.account_id.as_bytes());
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    let clock = AccountMutatingClock {
        store: store.clone(),
        account_id,
        called: AtomicBool::new(false),
    };
    let hns = HnsAccountReadRuntime::new(
        TestBackend {
            market,
            control: control.clone(),
        },
        clock,
        store,
        selector,
    )
    .expect("account read runtime");

    assert!(matches!(
        hns.observe_board_cancellation_context(),
        Err(HnsWalletError::StaleAccountRead)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}

#[test]
fn board_cancellation_context_rejects_changed_exact_account_revision() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market, control.clone());
    let context = hns
        .observe_board_cancellation_context()
        .expect("account/network/time context");
    store
        .try_with_store_mut(|wallet| {
            let mut accounts = wallet.wallet_accounts::<HnsAccountRecord>(2)?;
            let stored = accounts.pop().expect("selected account row");
            assert!(accounts.is_empty());
            let mut changed = stored.value;
            changed.next_receive_index += 1;
            wallet
                .save_wallet_account(&stored.id, stored.revision, &changed, NOW_UNIX)
                .map(|_| ())
        })
        .expect("advance exact account revision");
    assert!(matches!(
        store.try_with_store(|wallet| context.verify_unchanged_account(wallet)),
        Err(HnsWalletError::StaleAccountRead)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}
