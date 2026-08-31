use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{FinalizeCovenant, NameState, hash_name};
use hns_marketplace_protocol::{NameMarketHello, NameMarketMessage, ShakescapeRegistryVersion};
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
    CurrentShakedexLockQuery, HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED,
    HNS_VALUE_RUNTIME_RELEASE_QUALIFIED, HnsAccountReadRuntime, HnsAccountRecord, HnsBackend,
    HnsBootstrapPolicy, HnsClock, HnsExistingAccountSelector, HnsNameAction, HnsNameLifecycle,
    HnsNetwork, HnsOutpoint, HnsRuntimeConfig, HnsTransactionFeeQuote, HnsWalletBootstrap,
    HnsWalletError, MAX_CURRENT_SHAKEDEX_LOCK_BATCH, MempoolSnapshotBinding, MempoolWalletPage,
    MempoolWalletPageRequest, NameActionContextEvidence, NameEvidence, NameProofResponse,
    OutpointSpendEntry, OutpointSpendEvidence, SnapshotBinding, SpendingTransactionEvidence,
    TransactionEvidence, WalletAddressKey,
};
use hns_wallet_shakedex::{
    SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED, SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED,
    SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED, ShakedexError, ShakescapeBoardCancellationAdmission,
    ShakescapeBoardOfferAdmission, ShakescapeBoardOfferResponsePlan,
    ShakescapeBoardOffersResponsePlan, ShakescapeBoardRuntime, ShakescapeNameMarketRequest,
    encode_shakescape_request, load_name_market_board, prepare_shakescape_board_inventory_response,
    prepare_shakescape_board_offer_response, prepare_shakescape_board_offers_response,
    save_name_market_board, verify_fixed_price_listing,
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

#[derive(Clone, Copy)]
struct EarlyClock;

impl HnsClock for EarlyClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        Ok(NOW_UNIX - 120)
    }
}

#[derive(Clone)]
struct CountingClock {
    calls: Arc<AtomicU64>,
}

impl HnsClock for CountingClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(NOW_UNIX)
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
            .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
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
            Self::cancellation_envelope(&cancellation, ShakescapeRegistryVersion::V1, request_id);
        (cancellation, envelope, cancellation_hash)
    }

    fn cancellation_envelope(
        cancellation: &ListingCancellation,
        registry: ShakescapeRegistryVersion,
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

type QueryHook = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
struct BackendControl {
    spent: Arc<AtomicBool>,
    restart_chain_on_fence: Arc<AtomicBool>,
    chain_snapshot_count: Arc<AtomicU64>,
    restart_mempool_on_fence: Arc<AtomicBool>,
    mempool_query_count: Arc<AtomicU64>,
    spend_query_count: Arc<AtomicU64>,
    reject_queries: Arc<AtomicBool>,
    query_count: Arc<AtomicU64>,
    query_hook: Arc<Mutex<Option<QueryHook>>>,
}

impl BackendControl {
    fn new() -> Self {
        Self {
            spent: Arc::new(AtomicBool::new(false)),
            restart_chain_on_fence: Arc::new(AtomicBool::new(false)),
            chain_snapshot_count: Arc::new(AtomicU64::new(0)),
            restart_mempool_on_fence: Arc::new(AtomicBool::new(false)),
            mempool_query_count: Arc::new(AtomicU64::new(0)),
            spend_query_count: Arc::new(AtomicU64::new(0)),
            reject_queries: Arc::new(AtomicBool::new(false)),
            query_count: Arc::new(AtomicU64::new(0)),
            query_hook: Arc::new(Mutex::new(None)),
        }
    }

    fn install_query_hook(&self, hook: impl FnOnce() + Send + 'static) {
        let mut installed = self.query_hook.lock().expect("query hook mutex");
        assert!(installed.replace(Box::new(hook)).is_none());
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
        let hook = self
            .control
            .query_hook
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)?
            .take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(())
    }
}

impl HnsBackend for TestBackend {
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
        self.record_query("get_chain_snapshot")?;
        let snapshot_index = self
            .control
            .chain_snapshot_count
            .fetch_add(1, Ordering::SeqCst);
        if self.control.restart_chain_on_fence.load(Ordering::SeqCst) && snapshot_index % 2 == 1 {
            let mut restarted = self.market.binding;
            restarted.tip.block_hash[0] ^= 1;
            return Ok(restarted);
        }
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
        self.control
            .mempool_query_count
            .fetch_add(1, Ordering::SeqCst);
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
        self.control
            .spend_query_count
            .fetch_add(1, Ordering::SeqCst);
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
            owner_coin: None,
            owner_coin_source_binding: None,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchBackendFault {
    Healthy,
    ZeroMempoolNonce,
    SpendWrongLength,
    SpendWrongOrder,
    SpendWrongEcho,
    SpendOneEntry,
}

struct BatchMarketFixture {
    name: Vec<u8>,
    name_hash: [u8; 32],
    signing_key: SigningKey,
    seller_public_key: [u8; 33],
    locking_coin: Coin,
    owner_outpoint: HnsOutpoint,
    owner_transaction: Vec<u8>,
    owner_inclusion: hns_wallet_hns::TransactionInclusion,
    state: Vec<u8>,
}

impl BatchMarketFixture {
    fn new(name: &[u8], signing_key: SigningKey, tag: u8) -> Self {
        let seller_public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed batch seller key");
        let name_hash = hash_name(name).expect("batch name hash");
        let value = Dollarydoos::new(900_000 + u64::from(tag));
        let mut state = NameState {
            name_hash,
            name: name.to_vec(),
            height: Height::new(u32::from(tag)),
            renewal: Height::new(100),
            owner: CanonicalOutpoint::NULL,
            value,
            highest: value,
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
            name.to_vec(),
            state.height,
            state.weak,
            state.claimed,
            state.renewals,
            BlockHash::new([tag.wrapping_add(40); 32]),
        )
        .expect("batch finalize covenant")
        .to_covenant()
        .expect("batch canonical covenant");
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: CanonicalTransactionHash::new([tag; 32]),
                    index: 1,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value,
                address: Address::new(0, lock_script_hash(&seller_public_key).to_vec())
                    .expect("batch lock address"),
                covenant,
            }],
            locktime: 0,
        };
        let transaction_hash = transaction.transaction_hash().expect("batch owner hash");
        state.owner = CanonicalOutpoint {
            transaction_hash,
            index: 0,
        };
        let owner_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(transaction_hash.into_bytes()),
            output_index: 0,
        };
        let owner_inclusion = hns_wallet_hns::TransactionInclusion {
            block_hash: [tag.wrapping_add(80); 32],
            height: 120 + u64::from(tag),
            transaction_index: Some(u32::from(tag)),
        };
        let locking_coin = Coin {
            outpoint: Outpoint {
                transaction_hash,
                index: 0,
            },
            value,
            height: Height::new(
                u32::try_from(owner_inclusion.height).expect("bounded inclusion height"),
            ),
            coinbase: false,
            address: transaction.outputs[0].address.clone(),
            covenant: transaction.outputs[0].covenant.clone(),
        };
        Self {
            name: name.to_vec(),
            name_hash: name_hash.into_bytes(),
            signing_key,
            seller_public_key,
            locking_coin,
            owner_outpoint,
            owner_transaction: transaction.encode().expect("batch owner transaction"),
            owner_inclusion,
            state: state.encode().expect("batch name state"),
        }
    }

    fn listing(&self, network: NetworkBinding, sequence: u64, price: u64) -> FixedPriceListing {
        let mut proof = SwapProof {
            network,
            locking_outpoint: self.locking_coin.outpoint,
            name: self.name.clone(),
            seller_public_key: self.seller_public_key,
            payment_address: Address::new(0, vec![0xb0; 20]).expect("batch payment address"),
            price: Dollarydoos::new(price),
            lock_time_seconds: NOW_UNIX - 100,
            signature: None,
            fee_address: None,
            fee: Dollarydoos::new(0),
        };
        proof
            .sign(&self.locking_coin, &self.signing_key)
            .expect("signed batch proof");
        let mut listing = FixedPriceListing {
            proof,
            created_at: NOW_UNIX - 60,
            expires_at: NOW_UNIX + 3_600,
            sequence,
            signature: None,
        };
        listing
            .sign(&self.signing_key)
            .expect("signed batch listing");
        listing
    }
}

struct CurrentLockBatchFixture {
    markets: Vec<BatchMarketFixture>,
    network: NetworkBinding,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
}

impl CurrentLockBatchFixture {
    fn new() -> Self {
        let shared_key = SigningKey::from_slice(&[0x41; 32]).expect("shared batch seller key");
        let distinct_key = SigningKey::from_slice(&[0x42; 32]).expect("distinct batch seller key");
        let markets = vec![
            BatchMarketFixture::new(b"batch-alpha", shared_key.clone(), 1),
            BatchMarketFixture::new(b"batch-beta", distinct_key, 2),
            BatchMarketFixture::new(b"batch-gamma", shared_key, 3),
        ];
        let genesis = BlockHash::from_hex(REGTEST_GENESIS).expect("regtest genesis");
        Self {
            markets,
            network: NetworkBinding {
                magic: 0xae38_95cf,
                genesis,
            },
            binding: SnapshotBinding {
                tip: ChainTip {
                    height: 500,
                    block_hash: [0x91; 32],
                    // An empty-tree proof is valid for every queried key. The
                    // separately authenticated current view supplies each
                    // post-proof canonical NameState.
                    tree_root: [0; 32],
                    median_time_past: NOW_UNIX - 20,
                },
                chain_epoch: 17,
            },
            mempool: MempoolSnapshotBinding {
                instance_nonce: [0x92; 32],
                generation: 19,
            },
        }
    }

    fn market(&self, name_hash: [u8; 32]) -> Option<&BatchMarketFixture> {
        self.markets
            .iter()
            .find(|market| market.name_hash == name_hash)
    }

    fn expected_scripts(&self) -> Vec<WalletAddressKey> {
        self.markets
            .iter()
            .map(|market| WalletAddressKey {
                version: 0,
                hash: lock_script_hash(&market.seller_public_key).to_vec(),
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Default)]
struct BatchBackendObservations {
    chain_calls: AtomicU64,
    genesis_calls: AtomicU64,
    mempool_calls: AtomicU64,
    name_calls: AtomicU64,
    context_calls: AtomicU64,
    spend_calls: AtomicU64,
    mempool_scripts: Mutex<Vec<Vec<WalletAddressKey>>>,
    name_order: Mutex<Vec<[u8; 32]>>,
    context_order: Mutex<Vec<[u8; 32]>>,
    spend_outpoints: Mutex<Vec<Vec<HnsOutpoint>>>,
    query_hook: Mutex<Option<QueryHook>>,
}

impl BatchBackendObservations {
    fn install_query_hook(&self, hook: impl FnOnce() + Send + 'static) {
        let mut installed = self.query_hook.lock().expect("batch query hook mutex");
        assert!(installed.replace(Box::new(hook)).is_none());
    }
}

struct CurrentLockBatchBackend {
    fixture: Arc<CurrentLockBatchFixture>,
    observations: Arc<BatchBackendObservations>,
    fault: BatchBackendFault,
}

impl CurrentLockBatchBackend {
    fn unexpected(method: &str) -> HnsWalletError {
        HnsWalletError::Backend(format!("unexpected lock batch backend call: {method}"))
    }
}

impl HnsBackend for CurrentLockBatchBackend {
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
        self.observations.chain_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.fixture.binding)
    }

    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
        Err(Self::unexpected("get_chain_tip"))
    }

    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError> {
        self.observations
            .genesis_calls
            .fetch_add(1, Ordering::SeqCst);
        if height != 0 || binding != self.fixture.binding {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(BlockHashEvidence {
            binding,
            height,
            block_hash: Some(self.fixture.network.genesis.into_bytes()),
        })
    }

    fn get_confirmed_wallet_page(
        &self,
        _: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError> {
        Err(Self::unexpected("get_confirmed_wallet_page"))
    }

    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError> {
        let call = self
            .observations
            .mempool_calls
            .fetch_add(1, Ordering::SeqCst);
        self.observations
            .mempool_scripts
            .lock()
            .expect("mempool-script observations")
            .push(request.scripts.to_vec());
        let expected_mempool = match call {
            0 => None,
            1 => Some(self.fixture.mempool),
            _ => return Err(HnsWalletError::InvalidEvidence),
        };
        if request.binding != self.fixture.binding
            || request.scripts != self.fixture.expected_scripts()
            || request.expected_mempool != expected_mempool
            || request.cursor.is_some()
            || request.limit != 1
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mempool = if self.fault == BatchBackendFault::ZeroMempoolNonce {
            MempoolSnapshotBinding {
                instance_nonce: [0; 32],
                generation: self.fixture.mempool.generation,
            }
        } else {
            self.fixture.mempool
        };
        Ok(MempoolWalletPage {
            binding: self.fixture.binding,
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
        Err(Self::unexpected("get_transaction_evidence"))
    }

    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError> {
        self.observations.spend_calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .spend_outpoints
            .lock()
            .expect("spend observations")
            .push(outpoints.to_vec());
        if binding != self.fixture.binding
            || outpoints.iter().any(|outpoint| {
                !self
                    .fixture
                    .markets
                    .iter()
                    .any(|market| market.owner_outpoint == *outpoint)
            })
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mut entries: Vec<_> = outpoints
            .iter()
            .copied()
            .map(|outpoint| OutpointSpendEntry {
                outpoint,
                spending: None,
            })
            .collect();
        match self.fault {
            BatchBackendFault::SpendWrongLength => {
                entries.pop();
            }
            BatchBackendFault::SpendWrongOrder => entries.swap(0, 1),
            BatchBackendFault::SpendWrongEcho => {
                entries[0].outpoint.output_index ^= 1;
            }
            BatchBackendFault::SpendOneEntry => {
                entries[1].spending = Some(SpendingTransactionEvidence {
                    transaction: TransactionHash::new([0xa1; 32]),
                    input_position: 0,
                    block_hash: [0xa2; 32],
                    height: binding.tip.height,
                });
            }
            BatchBackendFault::Healthy | BatchBackendFault::ZeroMempoolNonce => {}
        }
        Ok(OutpointSpendEvidence { binding, entries })
    }

    fn broadcast_transaction(&self, _: &[u8]) -> Result<TransactionHash, HnsWalletError> {
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
        Err(Self::unexpected("quote_transaction_fee"))
    }

    fn estimate_fee_rate(&self, _: u16) -> Result<BaseUnits, HnsWalletError> {
        Err(Self::unexpected("estimate_fee_rate"))
    }

    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError> {
        let hook = self
            .observations
            .query_hook
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)?
            .take();
        if let Some(hook) = hook {
            hook();
        }
        self.observations.name_calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .name_order
            .lock()
            .expect("name observations")
            .push(name_hash);
        let market = self
            .fixture
            .market(name_hash)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if binding != self.fixture.binding {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(NameEvidence {
            binding,
            proof: NameProofResponse {
                name_hash,
                tree_root: binding.tip.tree_root,
                proof: vec![0, 0, 0, 0],
                proof_height: binding.tip.height,
            },
            proof_state: None,
            proof_owner_outpoint: None,
            proof_owner_transaction: None,
            proof_owner_inclusion: None,
            current_state: Some(market.state.clone()),
            current_owner_outpoint: Some(market.owner_outpoint),
            current_owner_transaction: Some(market.owner_transaction.clone()),
            current_owner_inclusion: Some(market.owner_inclusion),
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
        self.observations
            .context_calls
            .fetch_add(1, Ordering::SeqCst);
        self.observations
            .context_order
            .lock()
            .expect("context observations")
            .push(name_hash);
        let market = self
            .fixture
            .market(name_hash)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if action != HnsNameAction::Transfer
            || binding != self.fixture.binding
            || mempool != self.fixture.mempool
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(NameActionContextEvidence {
            binding,
            mempool,
            network: HnsNetwork::Regtest,
            network_id: 2,
            genesis_hash: self.fixture.network.genesis.into_bytes(),
            context_version: 1,
            consensus_profile: "hns-consensus/name-policy-v1".to_owned(),
            action,
            name_hash,
            current_state: market.state.clone(),
            owner_outpoint: market.owner_outpoint,
            owner_transaction: market.owner_transaction.clone(),
            owner_coin: None,
            owner_coin_source_binding: None,
            owner_inclusion: market.owner_inclusion,
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
    const SHAKESCAPE_ENVELOPE_OVERHEAD: usize = 26;
    const CANCELLATION_SIGNATURE_OFFSET: usize = 128;
    const CANCELLATION_HASH_SIZE: usize = 32;
    const CANCELLATION_HASH_DOMAIN: &[u8] = b"hns-rs/hns-swap/listing-cancellation/v1/hash";

    let mut tampered = encoded.to_vec();
    let hash_start = tampered
        .len()
        .checked_sub(CANCELLATION_HASH_SIZE)
        .expect("cancellation envelope hash");
    let signature_index = SHAKESCAPE_ENVELOPE_OVERHEAD + CANCELLATION_SIGNATURE_OFFSET;
    assert!(signature_index < hash_start);
    tampered[signature_index] ^= 1;
    let hash = blake2b_256(&[
        CANCELLATION_HASH_DOMAIN,
        &tampered[SHAKESCAPE_ENVELOPE_OVERHEAD..hash_start],
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

fn counting_runtime(
    store: SharedWalletStore,
    config: HnsRuntimeConfig,
    market: Arc<MarketFixture>,
    control: BackendControl,
    clock_calls: Arc<AtomicU64>,
) -> HnsAccountReadRuntime<TestBackend, CountingClock> {
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    HnsAccountReadRuntime::new(
        TestBackend { market, control },
        CountingClock { calls: clock_calls },
        store,
        selector,
    )
    .expect("counting account read runtime")
}

fn current_lock_batch_runtime(
    store: SharedWalletStore,
    config: HnsRuntimeConfig,
    fixture: Arc<CurrentLockBatchFixture>,
    observations: Arc<BatchBackendObservations>,
    fault: BatchBackendFault,
    clock_calls: Arc<AtomicU64>,
) -> HnsAccountReadRuntime<CurrentLockBatchBackend, CountingClock> {
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("batch exact non-value account selector");
    HnsAccountReadRuntime::new(
        CurrentLockBatchBackend {
            fixture,
            observations,
            fault,
        },
        CountingClock { calls: clock_calls },
        store,
        selector,
    )
    .expect("current-lock batch runtime")
}

fn current_lock_batch_queries(fixture: &CurrentLockBatchFixture) -> Vec<CurrentShakedexLockQuery> {
    [2_usize, 0, 1]
        .into_iter()
        .map(|index| CurrentShakedexLockQuery {
            name: fixture.markets[index].name.clone(),
            seller_public_key: fixture.markets[index].seller_public_key,
        })
        .collect()
}

fn persist_batch_listings(
    store: &SharedWalletStore,
    network: NetworkBinding,
    listings: &[(FixedPriceListing, Coin)],
) -> (u64, Vec<ObjectHash>) {
    let mut hashes = Vec::with_capacity(listings.len());
    let mut verified = Vec::with_capacity(listings.len());
    for (listing, locking_coin) in listings {
        let hash = ObjectHash::new(listing.listing_hash().expect("batch listing hash"));
        let listing = verify_fixed_price_listing(
            &listing.encode().expect("batch listing bytes"),
            hash,
            network,
            NOW_UNIX,
            locking_coin,
        )
        .expect("verified batch listing");
        hashes.push(hash);
        verified.push(listing);
    }
    let revision = store
        .try_with_store_mut(|wallet| {
            let mut stored = load_name_market_board(wallet)?;
            for listing in &verified {
                assert!(stored.board.apply_offer(listing)?);
            }
            save_name_market_board(wallet, stored.revision, &stored.board, NOW_UNIX)
        })
        .expect("persist batch board listings");
    (revision, hashes)
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

fn early_runtime(
    store: SharedWalletStore,
    config: HnsRuntimeConfig,
    market: Arc<MarketFixture>,
    control: BackendControl,
) -> HnsAccountReadRuntime<TestBackend, EarlyClock> {
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    HnsAccountReadRuntime::new(TestBackend { market, control }, EarlyClock, store, selector)
        .expect("early account read runtime")
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
            "hns-wallet-shakescape-board-runtime-{}-{unique}",
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
fn current_lock_batch_rejects_all_bad_input_before_store_backend_or_clock_io() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    let clock_calls = Arc::new(AtomicU64::new(0));
    let (store, config) = create_store(":memory:");
    let hns = counting_runtime(
        store.clone(),
        config,
        market.clone(),
        control.clone(),
        clock_calls.clone(),
    );
    let seller_public_key: [u8; 33] = market
        .signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed seller key");
    let valid = CurrentShakedexLockQuery {
        name: market.name.clone(),
        seller_public_key,
    };
    let oversized = vec![valid.clone(); MAX_CURRENT_SHAKEDEX_LOCK_BATCH + 1];
    let invalid_name = CurrentShakedexLockQuery {
        name: b"invalid.name".to_vec(),
        seller_public_key,
    };
    let invalid_key = CurrentShakedexLockQuery {
        name: market.name.clone(),
        seller_public_key: [0; 33],
    };
    let duplicate = [valid.clone(), valid];
    let alternate_key = SigningKey::from_slice(&[0x32; 32]).expect("alternate seller key");
    let same_name_alternate_seller = [
        duplicate[0].clone(),
        CurrentShakedexLockQuery {
            name: market.name.clone(),
            seller_public_key: alternate_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .expect("alternate compressed seller key"),
        },
    ];

    // A locked store makes an accidental account/store read observable in the
    // returned error, while the backend and clock counters cover the remaining
    // external boundaries.
    store.lock().expect("lock shared wallet store");
    assert!(matches!(
        hns.verify_current_shakedex_locks(&[]),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_locks(&oversized),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_locks(&[invalid_name]),
        Err(HnsWalletError::InvalidName)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_locks(&[invalid_key]),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_locks(&duplicate),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_locks(&same_name_alternate_seller),
        Err(HnsWalletError::InvalidEvidence)
    ));
    assert!(matches!(
        hns.verify_current_shakedex_lock(&[b'a'; 64], seller_public_key),
        Err(HnsWalletError::InvalidName)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn current_lock_batch_retains_one_fenced_authority_without_store_writes() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    let clock_calls = Arc::new(AtomicU64::new(0));
    let (store, config) = create_store(":memory:");
    let account_id = {
        let mut id = [0_u8; 32];
        id[..16].copy_from_slice(config.wallet_id.as_bytes());
        id[16..].copy_from_slice(config.account_id.as_bytes());
        id
    };
    let revision_before = store
        .try_with_store(|wallet| {
            wallet
                .wallet_account::<HnsAccountRecord>(&account_id)?
                .map(|stored| stored.revision)
                .ok_or(HnsWalletError::StaleAccountRead)
        })
        .expect("initial account revision");
    let hns = counting_runtime(
        store.clone(),
        config,
        market.clone(),
        control.clone(),
        clock_calls.clone(),
    );
    let seller_public_key: [u8; 33] = market
        .signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed seller key");
    let batch = hns
        .verify_current_shakedex_locks(&[CurrentShakedexLockQuery {
            name: market.name.clone(),
            seller_public_key,
        }])
        .expect("coherent current-lock batch");

    assert_eq!(batch.len(), 1);
    assert!(!batch.is_empty());
    assert_eq!(batch.binding(), market.binding);
    assert_eq!(batch.mempool_binding(), market.mempool);
    assert_eq!(batch.observed_at_unix(), NOW_UNIX);
    assert_eq!(batch.network(), market.network);
    assert_eq!(batch.locks()[0].descriptor().name, market.name);
    assert_eq!(
        batch.locks()[0].descriptor().seller_public_key,
        seller_public_key
    );
    assert_eq!(
        batch.locks()[0].locking_coin().outpoint,
        market.locking_coin.outpoint
    );
    store
        .try_with_store(|wallet| batch.verify_unchanged_account(wallet))
        .expect("unchanged account fence");
    let revision_after = store
        .try_with_store(|wallet| {
            wallet
                .wallet_account::<HnsAccountRecord>(&account_id)?
                .map(|stored| stored.revision)
                .ok_or(HnsWalletError::StaleAccountRead)
        })
        .expect("final account revision");
    assert_eq!(revision_after, revision_before);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.chain_snapshot_count.load(Ordering::SeqCst), 2);
    assert_eq!(control.mempool_query_count.load(Ordering::SeqCst), 2);
    assert_eq!(control.spend_query_count.load(Ordering::SeqCst), 1);
    assert_eq!(control.query_count.load(Ordering::SeqCst), 8);
}

#[test]
fn three_current_locks_share_one_ordered_deduplicated_snapshot_authority() {
    let fixture = Arc::new(CurrentLockBatchFixture::new());
    let observations = Arc::new(BatchBackendObservations::default());
    let clock_calls = Arc::new(AtomicU64::new(0));
    let (store, config) = create_store(":memory:");
    let runtime = current_lock_batch_runtime(
        store.clone(),
        config,
        fixture.clone(),
        observations.clone(),
        BatchBackendFault::Healthy,
        clock_calls.clone(),
    );
    let queries = current_lock_batch_queries(&fixture);
    let expected_name_hashes: Vec<_> = queries
        .iter()
        .map(|query| {
            hash_name(&query.name)
                .expect("query name hash")
                .into_bytes()
        })
        .collect();
    let expected_outpoints: Vec<_> = expected_name_hashes
        .iter()
        .map(|name_hash| {
            fixture
                .market(*name_hash)
                .expect("query fixture")
                .owner_outpoint
        })
        .collect();

    let batch = runtime
        .verify_current_shakedex_locks(&queries)
        .expect("three-lock coherent batch");
    assert_eq!(batch.len(), 3);
    assert_eq!(batch.binding(), fixture.binding);
    assert_eq!(batch.mempool_binding(), fixture.mempool);
    assert_eq!(batch.observed_at_unix(), NOW_UNIX);
    assert_eq!(batch.network(), fixture.network);
    for (lock, query) in batch.locks().iter().zip(&queries) {
        let market = fixture
            .market(
                hash_name(&query.name)
                    .expect("ordered name hash")
                    .into_bytes(),
            )
            .expect("ordered market fixture");
        assert_eq!(lock.descriptor().name, query.name);
        assert_eq!(lock.descriptor().seller_public_key, query.seller_public_key);
        assert_eq!(lock.locking_coin(), &market.locking_coin);
    }
    store
        .try_with_store(|wallet| batch.verify_unchanged_account(wallet))
        .expect("batch account authority remains current");

    let expected_scripts = fixture.expected_scripts();
    assert_eq!(
        expected_scripts.len(),
        2,
        "the shared seller key is deduped"
    );
    assert!(expected_scripts.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        *observations
            .mempool_scripts
            .lock()
            .expect("mempool script observations"),
        vec![expected_scripts.clone(), expected_scripts]
    );
    assert_eq!(
        *observations
            .name_order
            .lock()
            .expect("name call observations"),
        expected_name_hashes
    );
    assert_eq!(
        *observations
            .context_order
            .lock()
            .expect("context call observations"),
        expected_name_hashes
    );
    assert_eq!(
        *observations
            .spend_outpoints
            .lock()
            .expect("spend call observations"),
        vec![expected_outpoints]
    );
    assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observations.genesis_calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observations.name_calls.load(Ordering::SeqCst), 3);
    assert_eq!(observations.context_calls.load(Ordering::SeqCst), 3);
    assert_eq!(observations.spend_calls.load(Ordering::SeqCst), 1);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn current_lock_batch_rejects_zero_mempool_nonce_and_hostile_spend_batches() {
    for (fault, expected_stale) in [
        (BatchBackendFault::ZeroMempoolNonce, true),
        (BatchBackendFault::SpendWrongLength, true),
        (BatchBackendFault::SpendWrongOrder, false),
        (BatchBackendFault::SpendWrongEcho, false),
        (BatchBackendFault::SpendOneEntry, false),
    ] {
        let fixture = Arc::new(CurrentLockBatchFixture::new());
        let observations = Arc::new(BatchBackendObservations::default());
        let clock_calls = Arc::new(AtomicU64::new(0));
        let (store, config) = create_store(":memory:");
        let runtime = current_lock_batch_runtime(
            store,
            config,
            fixture.clone(),
            observations.clone(),
            fault,
            clock_calls.clone(),
        );
        let result = runtime.verify_current_shakedex_locks(&current_lock_batch_queries(&fixture));
        if expected_stale {
            assert!(
                matches!(result, Err(HnsWalletError::StaleNodeSnapshot)),
                "unexpected {fault:?} result: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(HnsWalletError::InvalidEvidence)),
                "unexpected {fault:?} result: {result:?}"
            );
        }
        assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
        assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 1);
        if fault == BatchBackendFault::ZeroMempoolNonce {
            assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 1);
            assert_eq!(observations.name_calls.load(Ordering::SeqCst), 0);
            assert_eq!(observations.context_calls.load(Ordering::SeqCst), 0);
            assert_eq!(observations.spend_calls.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 1);
            assert_eq!(observations.name_calls.load(Ordering::SeqCst), 3);
            assert_eq!(observations.context_calls.load(Ordering::SeqCst), 3);
            assert_eq!(observations.spend_calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn batch_offers_response_rejects_over_64_pre_io_and_represents_all_absent_without_wire_bytes() {
    let fixture = Arc::new(CurrentLockBatchFixture::new());
    let observations = Arc::new(BatchBackendObservations::default());
    let clock_calls = Arc::new(AtomicU64::new(0));
    let (store, config) = create_store(":memory:");
    let hns = current_lock_batch_runtime(
        store.clone(),
        config,
        fixture.clone(),
        observations.clone(),
        BatchBackendFault::Healthy,
        clock_calls.clone(),
    );
    let board =
        ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared batch store authority");
    let oversized_hashes = (1_u8..=65)
        .map(|byte| ObjectHash::new([byte; 32]))
        .collect();
    let oversized = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        180,
        &ShakescapeNameMarketRequest::Offers(oversized_hashes),
    )
    .expect("protocol-valid 65-hash GetOffers request");
    let one_hash = ObjectHash::new([0xef; 32]);
    let valid = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        186,
        &ShakescapeNameMarketRequest::Offers(vec![one_hash]),
    )
    .expect("canonical one-hash GetOffers request");
    let mut wrong_registry = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        187,
        &ShakescapeNameMarketRequest::Offers(vec![one_hash]),
    )
    .expect("canonical GetOffers request before registry corruption");
    wrong_registry[4] = 2;
    let inventory = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        188,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("wrong inventory request family");
    let response = NameMarketMessage::Offers(vec![fixture.markets[0].listing(
        fixture.network,
        188,
        18_800,
    )])
    .encode_envelope(ShakescapeRegistryVersion::V1, 188)
    .expect("wrong Offers response family");
    let mut zero_id = valid.clone();
    const REQUEST_ID_OFFSET: usize = 4 + (5 * core::mem::size_of::<u16>());
    zero_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + core::mem::size_of::<u64>()]
        .copy_from_slice(&0_u64.to_le_bytes());
    let mut trailing = valid;
    trailing.push(0);

    store.lock().expect("lock store before pre-I/O rejection");
    assert!(matches!(
        prepare_shakescape_board_offers_response(&oversized, &board),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    for rejected in [
        inventory.as_slice(),
        response.as_slice(),
        zero_id.as_slice(),
        trailing.as_slice(),
        &[0x01, 0x02, 0x03],
    ] {
        assert!(matches!(
            prepare_shakescape_board_offers_response(rejected, &board),
            Err(ShakedexError::InvalidShakescapeEnvelope)
        ));
    }
    assert!(matches!(
        prepare_shakescape_board_offers_response(&wrong_registry, &board),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    store
        .unlock(PASSPHRASE)
        .expect("unlock store after rejection");
    assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.name_calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);

    let missing_hash = ObjectHash::new([0xf0; 32]);
    let missing = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        181,
        &ShakescapeNameMarketRequest::Offers(vec![missing_hash]),
    )
    .expect("missing GetOffers request");
    let absent = prepare_shakescape_board_offers_response(&missing, &board)
        .expect("typed all-absent response plan");
    assert!(matches!(
        absent,
        ShakescapeBoardOffersResponsePlan::Absent {
            request_id: 181,
            requested_count: 1,
            board_revision: 0,
        }
    ));
    assert_eq!(absent.request_id(), 181);
    assert_eq!(absent.requested_count(), 1);
    assert_eq!(absent.returned_count(), 0);
    assert_eq!(absent.board_revision(), 0);
    assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.name_calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("read-only absent board")
            .revision,
        0
    );
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "a release-gate flip requires explicit review of this coherent batch boundary"
)]
fn batch_offers_response_preserves_sorted_request_subset_and_tombstones_without_writes() {
    let fixture = Arc::new(CurrentLockBatchFixture::new());
    let listings: Vec<_> = fixture
        .markets
        .iter()
        .enumerate()
        .map(|(index, market)| {
            (
                market.listing(
                    fixture.network,
                    200 + u64::try_from(index).expect("bounded listing index"),
                    20_000 + u64::try_from(index).expect("bounded listing index"),
                ),
                market.locking_coin.clone(),
            )
        })
        .collect();
    let (store, config) = create_store(":memory:");
    let (revision, listing_hashes) = persist_batch_listings(&store, fixture.network, &listings);
    assert_eq!(revision, 1);
    let missing_hash = ObjectHash::new([0xfe; 32]);
    assert!(!listing_hashes.contains(&missing_hash));
    let mut requested_hashes = listing_hashes.clone();
    requested_hashes.push(missing_hash);
    requested_hashes.sort_unstable();
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        182,
        &ShakescapeNameMarketRequest::Offers(requested_hashes.clone()),
    )
    .expect("sorted GetOffers request");
    let expected_name_order: Vec<_> = requested_hashes
        .iter()
        .filter_map(|requested_hash| {
            listing_hashes
                .iter()
                .position(|listing_hash| listing_hash == requested_hash)
                .map(|index| fixture.markets[index].name_hash)
        })
        .collect();

    let observations = Arc::new(BatchBackendObservations::default());
    let clock_calls = Arc::new(AtomicU64::new(0));
    let hns = current_lock_batch_runtime(
        store.clone(),
        config.clone(),
        fixture.clone(),
        observations.clone(),
        BatchBackendFault::Healthy,
        clock_calls.clone(),
    );
    let board =
        ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared batch store authority");
    let plan = prepare_shakescape_board_offers_response(&request, &board)
        .expect("coherent current offers response plan");
    assert_eq!(plan.request_id(), 182);
    assert_eq!(plan.requested_count(), 4);
    assert_eq!(plan.returned_count(), 3);
    assert_eq!(plan.board_revision(), 1);
    let ShakescapeBoardOffersResponsePlan::Current(prepared) = &plan else {
        panic!("expected current batch response plan");
    };
    assert_eq!(prepared.request_id(), 182);
    assert_eq!(prepared.requested_count(), 4);
    assert_eq!(prepared.returned_count(), 3);
    assert_eq!(prepared.board_revision(), 1);
    assert_eq!(
        *observations
            .name_order
            .lock()
            .expect("batch response name order"),
        expected_name_order
    );
    assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observations.genesis_calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observations.name_calls.load(Ordering::SeqCst), 3);
    assert_eq!(observations.context_calls.load(Ordering::SeqCst), 3);
    assert_eq!(observations.spend_calls.load(Ordering::SeqCst), 1);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("read-only current batch board")
            .revision,
        1
    );

    let mut cancellation =
        ListingCancellation::for_listing(&listings[0].0, NOW_UNIX - 1, NOW_UNIX + 4_000, 300)
            .expect("batch cancellation terms");
    cancellation
        .sign(&fixture.markets[0].signing_key)
        .expect("signed batch cancellation");
    let cancellation_hash = ObjectHash::new(
        cancellation
            .cancellation_hash()
            .expect("batch cancellation hash"),
    );
    let cancellation_envelope = NameMarketMessage::Cancel(cancellation)
        .encode_envelope(ShakescapeRegistryVersion::V1, 183)
        .expect("batch cancellation envelope");
    board
        .admit_cancellation(&cancellation_envelope, listing_hashes[0], cancellation_hash)
        .expect("persist batch cancellation tombstone");
    drop(plan);
    drop(board);
    drop(hns);

    let tombstone_observations = Arc::new(BatchBackendObservations::default());
    let tombstone_clock_calls = Arc::new(AtomicU64::new(0));
    let tombstone_hns = current_lock_batch_runtime(
        store.clone(),
        config,
        fixture,
        tombstone_observations.clone(),
        BatchBackendFault::Healthy,
        tombstone_clock_calls.clone(),
    );
    let tombstone_board = ShakescapeBoardRuntime::new(&tombstone_hns, store.clone())
        .expect("tombstone shared batch store authority");
    let tombstoned = prepare_shakescape_board_offers_response(&request, &tombstone_board)
        .expect("coherent subset after tombstone");
    assert_eq!(tombstoned.requested_count(), 4);
    assert_eq!(tombstoned.returned_count(), 2);
    assert_eq!(tombstoned.board_revision(), 2);
    assert_eq!(tombstone_observations.name_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        tombstone_observations.context_calls.load(Ordering::SeqCst),
        2
    );
    assert_eq!(tombstone_observations.spend_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tombstone_clock_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("read-only tombstone batch board")
            .revision,
        2
    );

    assert!(HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
    assert!(HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
}

#[test]
fn batch_offers_response_rejects_duplicate_active_names_before_backend_or_clock() {
    let fixture = Arc::new(CurrentLockBatchFixture::new());
    let first = &fixture.markets[0];
    let alternate = BatchMarketFixture::new(
        &first.name,
        SigningKey::from_slice(&[0x44; 32]).expect("alternate batch seller"),
        9,
    );
    let listings = vec![
        (
            first.listing(fixture.network, 400, 40_000),
            first.locking_coin.clone(),
        ),
        (
            alternate.listing(fixture.network, 401, 40_001),
            alternate.locking_coin.clone(),
        ),
    ];
    let (store, config) = create_store(":memory:");
    let (revision, mut hashes) = persist_batch_listings(&store, fixture.network, &listings);
    hashes.sort_unstable();
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        184,
        &ShakescapeNameMarketRequest::Offers(hashes),
    )
    .expect("same-name distinct-seller GetOffers request");
    let observations = Arc::new(BatchBackendObservations::default());
    let clock_calls = Arc::new(AtomicU64::new(0));
    let hns = current_lock_batch_runtime(
        store.clone(),
        config,
        fixture,
        observations.clone(),
        BatchBackendFault::Healthy,
        clock_calls.clone(),
    );
    let board =
        ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared batch store authority");

    assert!(matches!(
        prepare_shakescape_board_offers_response(&request, &board),
        Err(ShakedexError::InvalidEvidence)
    ));
    assert_eq!(observations.chain_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.mempool_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.name_calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged duplicate-name board")
            .revision,
        revision
    );
}

#[test]
fn batch_offers_response_fences_board_revision_and_listing_expiry() {
    let fixture = Arc::new(CurrentLockBatchFixture::new());
    let listings: Vec<_> = fixture
        .markets
        .iter()
        .enumerate()
        .map(|(index, market)| {
            (
                market.listing(
                    fixture.network,
                    500 + u64::try_from(index).expect("bounded listing index"),
                    50_000 + u64::try_from(index).expect("bounded listing index"),
                ),
                market.locking_coin.clone(),
            )
        })
        .collect();
    let (store, config) = create_store(":memory:");
    let (revision, mut listing_hashes) = persist_batch_listings(&store, fixture.network, &listings);
    listing_hashes.sort_unstable();
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        185,
        &ShakescapeNameMarketRequest::Offers(listing_hashes),
    )
    .expect("board-fenced GetOffers request");
    let observations = Arc::new(BatchBackendObservations::default());
    let clock_calls = Arc::new(AtomicU64::new(0));
    let hns = current_lock_batch_runtime(
        store.clone(),
        config.clone(),
        fixture.clone(),
        observations.clone(),
        BatchBackendFault::Healthy,
        clock_calls,
    );
    let board =
        ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared batch store authority");
    let hook_store = store.clone();
    observations.install_query_hook(move || {
        hook_store
            .try_with_store_mut(|wallet| {
                let stored = load_name_market_board(wallet)?;
                save_name_market_board(wallet, stored.revision, &stored.board, NOW_UNIX).map(|_| ())
            })
            .expect("advance unrelated board revision during batch query");
    });
    assert!(matches!(
        prepare_shakescape_board_offers_response(&request, &board),
        Err(ShakedexError::StaleRevision)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("mutated board revision")
            .revision,
        revision + 1
    );
    drop(board);
    drop(hns);

    let late_observations = Arc::new(BatchBackendObservations::default());
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("late batch exact non-value account selector");
    let late_hns = HnsAccountReadRuntime::new(
        CurrentLockBatchBackend {
            fixture,
            observations: late_observations.clone(),
            fault: BatchBackendFault::Healthy,
        },
        LateClock,
        store.clone(),
        selector,
    )
    .expect("late current-lock batch runtime");
    let late_board =
        ShakescapeBoardRuntime::new(&late_hns, store).expect("late shared batch store authority");
    assert!(matches!(
        prepare_shakescape_board_offers_response(&request, &late_board),
        Err(ShakedexError::InvalidListing)
    ));
    assert_eq!(late_observations.chain_calls.load(Ordering::SeqCst), 2);
    assert_eq!(late_observations.mempool_calls.load(Ordering::SeqCst), 2);
    assert_eq!(late_observations.name_calls.load(Ordering::SeqCst), 3);
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
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");

    assert!(matches!(
        board.admit_offer(&envelope, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    assert!(matches!(
        board.admit_offer(&envelope, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Existing { revision: 1, .. })
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
    let restarted = ShakescapeBoardRuntime::new(&restarted_hns, restarted_store)
        .expect("restarted shared authority");
    assert!(matches!(
        restarted.admit_offer(&envelope, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Existing { revision: 1, .. })
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
        ShakescapeBoardRuntime::new(&hns, unrelated),
        Err(ShakedexError::StoreAuthorityMismatch)
    ));
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    let (first, first_hash) = market.offer(5, 51, 12_345_678);
    assert!(matches!(
        board.admit_offer(&first, first_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
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
        Ok(ShakescapeBoardOfferAdmission::Updated { revision: 2, .. })
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
    reason = "a release-gate flip requires explicit review of this closed inventory boundary"
)]
fn inventory_response_plan_is_read_only_restart_safe_and_hides_cancelled_rows_without_queries() {
    let directory = TestDirectory::new();
    let database = directory.0.join("wallet.sqlite3");
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(28, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(ShakescapeRegistryVersion::V1, 130)
        .expect("offer envelope");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        131,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("GetOfferInventory request");
    let (_, cancellation, cancellation_hash) = market.cancellation(&listing, 29, 132);
    let control = BackendControl::new();
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let queries_after_admission = control.query_count.load(Ordering::SeqCst);
    let plan = prepare_shakescape_board_inventory_response(&request, &board)
        .expect("closed current inventory plan");
    assert_eq!(plan.request_id(), 131);
    assert_eq!(plan.board_revision(), 1);
    assert_eq!(plan.listing_count(), 1);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        queries_after_admission
    );
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("read-only inventory")
            .revision,
        1
    );
    let repeated = prepare_shakescape_board_inventory_response(&request, &board)
        .expect("exact repeated inventory plan");
    assert_eq!(repeated.listing_count(), 1);
    assert_eq!(repeated.board_revision(), 1);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        queries_after_admission
    );
    drop(repeated);
    drop(plan);
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
    let restarted_hns = runtime(
        restarted_store.clone(),
        config,
        market,
        restarted_control.clone(),
    );
    let restarted = ShakescapeBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    let restarted_plan = prepare_shakescape_board_inventory_response(&request, &restarted)
        .expect("fresh restart inventory plan");
    assert_eq!(restarted_plan.board_revision(), 1);
    assert_eq!(restarted_plan.listing_count(), 1);
    assert_eq!(restarted_control.query_count.load(Ordering::SeqCst), 0);

    restarted
        .admit_cancellation(&cancellation, listing_hash, cancellation_hash)
        .expect("cancel target");
    let cancelled = prepare_shakescape_board_inventory_response(&request, &restarted)
        .expect("cancelled inventory plan");
    assert_eq!(cancelled.board_revision(), 2);
    assert_eq!(cancelled.listing_count(), 0);
    assert_eq!(restarted_control.query_count.load(Ordering::SeqCst), 0);

    assert!(HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
    assert!(HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
}

#[test]
fn inventory_response_plan_accepts_empty_and_filters_expired_or_wrong_network_rows() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, mut config) = create_store(":memory:");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        133,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("GetOfferInventory request");
    let empty_hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let empty_board =
        ShakescapeBoardRuntime::new(&empty_hns, store.clone()).expect("shared store authority");
    let empty = prepare_shakescape_board_inventory_response(&request, &empty_board)
        .expect("canonical empty inventory");
    assert_eq!(empty.board_revision(), 0);
    assert_eq!(empty.listing_count(), 0);
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
    drop(empty);
    drop(empty_board);
    drop(empty_hns);

    control.reject_queries.store(false, Ordering::SeqCst);
    let admitting_hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let admitting_board =
        ShakescapeBoardRuntime::new(&admitting_hns, store.clone()).expect("shared store authority");
    let (offer, listing_hash) = market.offer(30, 134, 12_345_678);
    admitting_board
        .admit_offer(&offer, listing_hash)
        .expect("admit active offer");
    drop(admitting_board);
    drop(admitting_hns);
    let queries_after_admission = control.query_count.load(Ordering::SeqCst);

    control.reject_queries.store(true, Ordering::SeqCst);
    let early_hns = early_runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let early_board =
        ShakescapeBoardRuntime::new(&early_hns, store.clone()).expect("early shared authority");
    let future = prepare_shakescape_board_inventory_response(&request, &early_board)
        .expect("not-yet-active row omitted");
    assert_eq!(future.board_revision(), 1);
    assert_eq!(future.listing_count(), 0);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        queries_after_admission
    );
    drop(future);
    drop(early_board);
    drop(early_hns);

    let late_hns = late_runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let late_board =
        ShakescapeBoardRuntime::new(&late_hns, store.clone()).expect("late shared authority");
    let expired = prepare_shakescape_board_inventory_response(&request, &late_board)
        .expect("expired row omitted");
    assert_eq!(expired.board_revision(), 1);
    assert_eq!(expired.listing_count(), 0);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        queries_after_admission
    );
    drop(expired);
    drop(late_board);
    drop(late_hns);

    config.network = HnsNetwork::Testnet;
    store
        .try_with_store_mut(|wallet| {
            let mut accounts = wallet.wallet_accounts::<HnsAccountRecord>(2)?;
            let stored = accounts.pop().expect("selected account row");
            assert!(accounts.is_empty());
            let mut changed = stored.value;
            changed.config.network = HnsNetwork::Testnet;
            wallet
                .save_wallet_account(&stored.id, stored.revision, &changed, NOW_UNIX)
                .map(|_| ())
        })
        .expect("move selected account to another network");
    let other_network_hns = runtime(store.clone(), config, market, control.clone());
    let other_network_board = ShakescapeBoardRuntime::new(&other_network_hns, store)
        .expect("other-network shared authority");
    let other_network = prepare_shakescape_board_inventory_response(&request, &other_network_board)
        .expect("wrong-network row omitted");
    assert_eq!(other_network.board_revision(), 1);
    assert_eq!(other_network.listing_count(), 0);
    assert_eq!(
        control.query_count.load(Ordering::SeqCst),
        queries_after_admission
    );
}

#[test]
fn inventory_response_plan_rejects_every_other_family_before_context_or_backend_access() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(32, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let hello = NameMarketMessage::Hello(NameMarketHello {
        hns_magic: market.network.magic,
        hns_genesis: market.network.genesis,
        maximum_payload: 1_024,
        feature_flags: 0,
    })
    .encode_envelope(ShakescapeRegistryVersion::V1, 0)
    .expect("zero-ID hello family");
    let (_, cancellation, _) = market.cancellation(&listing, 33, 0);
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let clock_calls = Arc::new(AtomicU64::new(0));
    let (store, config) = create_store(":memory:");
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    let hns = HnsAccountReadRuntime::new(
        TestBackend {
            market: market.clone(),
            control: control.clone(),
        },
        CountingClock {
            calls: clock_calls.clone(),
        },
        store.clone(),
        selector,
    )
    .expect("counted account read runtime");
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    let offer = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        135,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("GetOffer request");
    let offers = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        136,
        &ShakescapeNameMarketRequest::Offers(vec![listing_hash]),
    )
    .expect("GetOffers request");
    let mut wrong_registry = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        137,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("canonical GetOfferInventory request before registry corruption");
    wrong_registry[4] = 2;
    let mut zero_id = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        138,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("canonical nonzero GetOfferInventory request");
    const REQUEST_ID_OFFSET: usize = 4 + (5 * core::mem::size_of::<u16>());
    zero_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + core::mem::size_of::<u64>()]
        .copy_from_slice(&0_u64.to_le_bytes());
    let mut trailing = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        139,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("canonical GetOfferInventory before trailing byte");
    trailing.push(0);
    let batch_response = NameMarketMessage::Offers(vec![listing.clone()])
        .encode_envelope(ShakescapeRegistryVersion::V1, 140)
        .expect("batch response family");
    let offer_response = NameMarketMessage::Offer(listing)
        .encode_envelope(ShakescapeRegistryVersion::V1, 141)
        .expect("offer response family");
    let inventory_response = NameMarketMessage::OfferInventory(vec![listing_hash.into_bytes()])
        .encode_envelope(ShakescapeRegistryVersion::V1, 142)
        .expect("inventory response family");

    for rejected in [
        hello.as_slice(),
        offer.as_slice(),
        offers.as_slice(),
        batch_response.as_slice(),
        offer_response.as_slice(),
        inventory_response.as_slice(),
        cancellation.as_slice(),
        zero_id.as_slice(),
        trailing.as_slice(),
        &[0x01, 0x02, 0x03],
    ] {
        assert!(matches!(
            prepare_shakescape_board_inventory_response(rejected, &board),
            Err(ShakedexError::InvalidShakescapeEnvelope)
        ));
    }
    assert!(matches!(
        prepare_shakescape_board_inventory_response(&wrong_registry, &board),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("untouched board")
            .revision,
        0
    );
}

#[test]
fn inventory_response_plan_fences_account_mutation_during_clock_without_backend_access() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let mut account_id = [0_u8; 32];
    account_id[..16].copy_from_slice(config.wallet_id.as_bytes());
    account_id[16..].copy_from_slice(config.account_id.as_bytes());
    let selector = HnsExistingAccountSelector::new(store.clone(), config)
        .expect("exact non-value account selector");
    let hns = HnsAccountReadRuntime::new(
        TestBackend {
            market,
            control: control.clone(),
        },
        AccountMutatingClock {
            store: store.clone(),
            account_id,
            called: AtomicBool::new(false),
        },
        store.clone(),
        selector,
    )
    .expect("account-mutating read runtime");
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        143,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("GetOfferInventory request");
    assert!(matches!(
        prepare_shakescape_board_inventory_response(&request, &board),
        Err(ShakedexError::HnsIntegration)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged board after account race")
            .revision,
        0
    );
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "a release-gate flip requires explicit review of this closed read boundary"
)]
fn single_offer_response_plan_reacquires_after_restart_and_hides_cancelled_rows_without_queries() {
    let directory = TestDirectory::new();
    let database = directory.0.join("wallet.sqlite3");
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(30, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(ShakescapeRegistryVersion::V1, 140)
        .expect("offer envelope");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        139,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("GetOffer request");
    let (_, cancellation, cancellation_hash) = market.cancellation(&listing, 31, 141);
    let control = BackendControl::new();
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let queries_after_admission = control.query_count.load(Ordering::SeqCst);
    let plan = prepare_shakescape_board_offer_response(&request, &board)
        .expect("closed current response plan");
    let queries_after_plan = control.query_count.load(Ordering::SeqCst);
    assert!(queries_after_plan > queries_after_admission);
    assert_eq!(plan.request_id(), 139);
    assert_eq!(plan.listing_hash(), listing_hash);
    assert_eq!(plan.board_revision(), Some(1));
    let ShakescapeBoardOfferResponsePlan::Current(prepared) = &plan else {
        panic!("expected current response plan");
    };
    assert_eq!(prepared.request_id(), 139);
    assert_eq!(prepared.listing_hash(), listing_hash);
    assert_eq!(prepared.board_revision(), 1);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("read-only plan")
            .revision,
        1
    );
    let repeated = prepare_shakescape_board_offer_response(&request, &board)
        .expect("exact repeated response plan");
    assert!(matches!(
        repeated,
        ShakescapeBoardOfferResponsePlan::Current(_)
    ));
    assert!(control.query_count.load(Ordering::SeqCst) > queries_after_plan);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("repeated read-only plan")
            .revision,
        1
    );
    drop(repeated);
    drop(plan);
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
        market,
        restarted_control.clone(),
    );
    let restarted = ShakescapeBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    assert_eq!(restarted_control.query_count.load(Ordering::SeqCst), 0);
    let restarted_plan = prepare_shakescape_board_offer_response(&request, &restarted)
        .expect("fresh restart response plan");
    assert!(matches!(
        restarted_plan,
        ShakescapeBoardOfferResponsePlan::Current(_)
    ));
    let queries_after_restart_plan = restarted_control.query_count.load(Ordering::SeqCst);
    assert!(queries_after_restart_plan > 0);

    let missing_hash = ObjectHash::new([0x77; 32]);
    let missing_request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        142,
        &ShakescapeNameMarketRequest::Offer(missing_hash),
    )
    .expect("missing GetOffer request");
    let missing = prepare_shakescape_board_offer_response(&missing_request, &restarted)
        .expect("missing response plan");
    assert!(matches!(
        missing,
        ShakescapeBoardOfferResponsePlan::Absent {
            request_id: 142,
            listing_hash: hash,
        } if hash == missing_hash
    ));
    assert_eq!(
        restarted_control.query_count.load(Ordering::SeqCst),
        queries_after_restart_plan
    );

    restarted
        .admit_cancellation(&cancellation, listing_hash, cancellation_hash)
        .expect("cancel target");
    let queries_after_cancellation = restarted_control.query_count.load(Ordering::SeqCst);
    let cancelled = prepare_shakescape_board_offer_response(&request, &restarted)
        .expect("cancelled response plan");
    assert!(matches!(
        cancelled,
        ShakescapeBoardOfferResponsePlan::Absent {
            request_id: 139,
            listing_hash: hash,
        } if hash == listing_hash
    ));
    assert_eq!(
        restarted_control.query_count.load(Ordering::SeqCst),
        queries_after_cancellation
    );

    assert!(HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
    assert!(HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
}

#[test]
fn single_offer_response_plan_rejects_every_other_request_family_before_node_queries() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(40, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let hello = NameMarketMessage::Hello(NameMarketHello {
        hns_magic: market.network.magic,
        hns_genesis: market.network.genesis,
        maximum_payload: 1_024,
        feature_flags: 0,
    })
    .encode_envelope(ShakescapeRegistryVersion::V1, 0)
    .expect("zero-ID hello family");
    let (_, cancellation, _) = market.cancellation(&listing, 41, 0);
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market, control.clone());
    let board = ShakescapeBoardRuntime::new(&hns, store).expect("shared store authority");
    let inventory = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        150,
        &ShakescapeNameMarketRequest::Inventory,
    )
    .expect("inventory request");
    let offers = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        151,
        &ShakescapeNameMarketRequest::Offers(vec![listing_hash]),
    )
    .expect("multi-offer request family");
    let mut wrong_registry = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        152,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("canonical GetOffer request before registry corruption");
    wrong_registry[4] = 2;
    let mut zero_id = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        155,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("canonical nonzero GetOffer request");
    const REQUEST_ID_OFFSET: usize = 4 + (5 * core::mem::size_of::<u16>());
    zero_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + core::mem::size_of::<u64>()]
        .copy_from_slice(&0_u64.to_le_bytes());
    let mut trailing = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        156,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("canonical GetOffer before trailing byte");
    trailing.push(0);
    let batch_response = NameMarketMessage::Offers(vec![listing.clone()])
        .encode_envelope(ShakescapeRegistryVersion::V1, 157)
        .expect("batch response family");
    let offer_response = NameMarketMessage::Offer(listing)
        .encode_envelope(ShakescapeRegistryVersion::V1, 153)
        .expect("offer response family");
    let inventory_response = NameMarketMessage::OfferInventory(vec![listing_hash.into_bytes()])
        .encode_envelope(ShakescapeRegistryVersion::V1, 154)
        .expect("inventory response family");

    for rejected in [
        hello.as_slice(),
        inventory.as_slice(),
        offers.as_slice(),
        batch_response.as_slice(),
        offer_response.as_slice(),
        inventory_response.as_slice(),
        cancellation.as_slice(),
        zero_id.as_slice(),
        trailing.as_slice(),
        &[0x01, 0x02, 0x03],
    ] {
        assert!(matches!(
            prepare_shakescape_board_offer_response(rejected, &board),
            Err(ShakedexError::InvalidShakescapeEnvelope)
        ));
    }
    assert!(matches!(
        prepare_shakescape_board_offer_response(&wrong_registry, &board),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}

#[test]
fn single_offer_response_plan_fails_on_spend_stale_mempool_board_replacement_and_expiry() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(50, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing)
        .encode_envelope(ShakescapeRegistryVersion::V1, 160)
        .expect("offer envelope");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        161,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("GetOffer request");
    let control = BackendControl::new();
    let (store, config) = create_store(":memory:");
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));

    control.restart_chain_on_fence.store(true, Ordering::SeqCst);
    assert!(matches!(
        prepare_shakescape_board_offer_response(&request, &board),
        Err(ShakedexError::InvalidEvidence)
    ));
    control
        .restart_chain_on_fence
        .store(false, Ordering::SeqCst);

    control.spent.store(true, Ordering::SeqCst);
    assert!(matches!(
        prepare_shakescape_board_offer_response(&request, &board),
        Err(ShakedexError::InvalidEvidence)
    ));
    control.spent.store(false, Ordering::SeqCst);
    control
        .restart_mempool_on_fence
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        prepare_shakescape_board_offer_response(&request, &board),
        Err(ShakedexError::InvalidEvidence)
    ));
    control
        .restart_mempool_on_fence
        .store(false, Ordering::SeqCst);

    let replacement = market.listing(51, 12_345_679);
    let replacement_hash = ObjectHash::new(replacement.listing_hash().expect("replacement hash"));
    let verified_replacement = verify_fixed_price_listing(
        &replacement.encode().expect("replacement bytes"),
        replacement_hash,
        market.network,
        NOW_UNIX,
        &market.locking_coin,
    )
    .expect("verified replacement");
    let (expected_revision, replacement_board) = store
        .try_with_store(|wallet| {
            let mut stored = load_name_market_board(wallet)?;
            stored.board.apply_offer(&verified_replacement)?;
            Ok::<_, ShakedexError>((stored.revision, stored.board))
        })
        .expect("stage replacement board");
    let hook_store = store.clone();
    control.install_query_hook(move || {
        hook_store
            .try_with_store_mut(|wallet| {
                save_name_market_board(wallet, expected_revision, &replacement_board, NOW_UNIX)
                    .map(|_| ())
            })
            .expect("replace board during current-lock reacquisition");
    });
    assert!(matches!(
        prepare_shakescape_board_offer_response(&request, &board),
        Err(ShakedexError::StaleRevision)
    ));
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("replacement committed")
            .revision,
        2
    );
    drop(board);
    drop(hns);

    let late_control = BackendControl::new();
    let late_hns = late_runtime(store.clone(), config.clone(), market.clone(), late_control);
    let late_board =
        ShakescapeBoardRuntime::new(&late_hns, store.clone()).expect("late shared authority");
    let replacement_request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        162,
        &ShakescapeNameMarketRequest::Offer(replacement_hash),
    )
    .expect("expired replacement request");
    assert!(matches!(
        prepare_shakescape_board_offer_response(&replacement_request, &late_board),
        Err(ShakedexError::InvalidListing)
    ));
    drop(late_board);
    drop(late_hns);

    let mut other_network_config = config;
    other_network_config.network = HnsNetwork::Testnet;
    store
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
    let other_network_hns = runtime(
        store.clone(),
        other_network_config,
        market,
        other_network_control.clone(),
    );
    let other_network_board = ShakescapeBoardRuntime::new(&other_network_hns, store)
        .expect("other-network shared authority");
    assert!(matches!(
        prepare_shakescape_board_offer_response(&replacement_request, &other_network_board),
        Err(ShakedexError::InvalidEvidence)
    ));
    assert!(other_network_control.query_count.load(Ordering::SeqCst) > 0);
}

#[test]
fn single_offer_response_plan_fences_account_mutation_during_clock_observation() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(60, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing)
        .encode_envelope(ShakescapeRegistryVersion::V1, 170)
        .expect("offer envelope");
    let request = encode_shakescape_request(
        ShakescapeRegistryVersion::V1,
        171,
        &ShakescapeNameMarketRequest::Offer(listing_hash),
    )
    .expect("GetOffer request");
    let control = BackendControl::new();
    let (store, config) = create_store(":memory:");
    let admitting_hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let admitting_board =
        ShakescapeBoardRuntime::new(&admitting_hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        admitting_board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    drop(admitting_board);
    drop(admitting_hns);

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
    let mutating_hns = HnsAccountReadRuntime::new(
        TestBackend {
            market,
            control: control.clone(),
        },
        clock,
        store.clone(),
        selector,
    )
    .expect("account-mutating read runtime");
    let mutating_board =
        ShakescapeBoardRuntime::new(&mutating_hns, store.clone()).expect("shared store authority");

    assert!(matches!(
        prepare_shakescape_board_offer_response(&request, &mutating_board),
        Err(ShakedexError::HnsIntegration)
    ));
    assert!(control.query_count.load(Ordering::SeqCst) > 0);
    assert_eq!(
        store
            .try_with_store(load_name_market_board)
            .expect("unchanged board after account race")
            .revision,
        1
    );
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
        .encode_envelope(ShakescapeRegistryVersion::V1, 70)
        .expect("offer envelope");
    let (cancellation, cancellation_envelope, cancellation_hash) =
        market.cancellation(&listing, 8, 71);
    let retry_envelope = NameMarketMessage::Cancel(cancellation)
        .encode_envelope(ShakescapeRegistryVersion::V1, 72)
        .expect("retry cancellation envelope");
    let control = BackendControl::new();
    let (store, config) = create_store(&database);
    let hns = runtime(
        store.clone(),
        config.clone(),
        market.clone(),
        control.clone(),
    );
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");

    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
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
        ShakescapeBoardCancellationAdmission::Applied { revision: 2, .. }
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
        ShakescapeBoardCancellationAdmission::Existing { revision: 2, .. }
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
    let restarted = ShakescapeBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    assert!(matches!(
        restarted.admit_cancellation(&retry_envelope, listing_hash, cancellation_hash),
        Ok(ShakescapeBoardCancellationAdmission::Existing { revision: 2, .. })
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
    let other_network_board =
        ShakescapeBoardRuntime::new(&other_network_hns, restarted_store.clone())
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

    assert!(HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED);
    assert!(HNS_VALUE_RUNTIME_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_SHAKESCAPE_V1_RELEASE_QUALIFIED);
    assert!(SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
}

#[test]
fn cancellation_admission_rejects_wrong_identity_absence_and_expired_initial_mutation() {
    let market = Arc::new(MarketFixture::new());
    let listing = market.listing(10, 12_345_678);
    let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
    let offer = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(ShakescapeRegistryVersion::V1, 80)
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
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
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
    let (mut wrong_registry, _) =
        MarketFixture::cancellation_envelope(&base_cancellation, ShakescapeRegistryVersion::V1, 81);
    wrong_registry[4] = 2;
    assert!(matches!(
        board.admit_cancellation(&wrong_registry, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    assert!(matches!(
        board.admit_cancellation(&offer, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));
    let invalid_signature = cancellation_envelope_with_invalid_signature(&cancellation_envelope);
    assert!(matches!(
        board.admit_cancellation(&invalid_signature, listing_hash, cancellation_hash),
        Err(ShakedexError::InvalidShakescapeEnvelope)
    ));

    let mut wrong_network = base_cancellation.clone();
    wrong_network.network.magic ^= 1;
    wrong_network.signature = None;
    wrong_network
        .sign(&market.signing_key)
        .expect("wrong-network signature");
    let (wrong_network_envelope, wrong_network_hash) =
        MarketFixture::cancellation_envelope(&wrong_network, ShakescapeRegistryVersion::V1, 83);
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
        MarketFixture::cancellation_envelope(&wrong_seller, ShakescapeRegistryVersion::V1, 84);
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
        MarketFixture::cancellation_envelope(&not_yet_active, ShakescapeRegistryVersion::V1, 85);
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
        ShakescapeBoardRuntime::new(&late_hns, store.clone()).expect("late shared authority");
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
        .encode_envelope(ShakescapeRegistryVersion::V1, 90)
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
    let board = ShakescapeBoardRuntime::new(&hns, store.clone()).expect("shared store authority");
    assert!(matches!(
        board.admit_offer(&offer, listing_hash),
        Ok(ShakescapeBoardOfferAdmission::Inserted { revision: 1, .. })
    ));
    let node_queries_after_offer = control.query_count.load(Ordering::SeqCst);
    control.reject_queries.store(true, Ordering::SeqCst);
    let zero_id = board
        .admit_cancellation(&zero_id_cancellation, listing_hash, cancellation_hash)
        .expect("zero-ID offline cancellation");
    assert!(matches!(
        zero_id,
        ShakescapeBoardCancellationAdmission::Applied { revision: 2, .. }
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
        MarketFixture::cancellation_envelope(&same_sequence, ShakescapeRegistryVersion::V1, 91);
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
        Ok(ShakescapeBoardCancellationAdmission::Applied { revision: 3, .. })
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
    let restarted = ShakescapeBoardRuntime::new(&restarted_hns, restarted_store.clone())
        .expect("restarted shared authority");
    let replayed_listing = market.listing(24, 12_345_679);
    let replayed_hash = ObjectHash::new(
        replayed_listing
            .listing_hash()
            .expect("replayed listing hash"),
    );
    let replayed_offer = NameMarketMessage::Offer(replayed_listing)
        .encode_envelope(ShakescapeRegistryVersion::V1, 94)
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

#[test]
fn board_context_revalidation_rejects_same_metadata_account_aba() {
    let market = Arc::new(MarketFixture::new());
    let control = BackendControl::new();
    control.reject_queries.store(true, Ordering::SeqCst);
    let (store, config) = create_store(":memory:");
    let hns = runtime(store.clone(), config, market, control.clone());
    let context = hns
        .observe_board_context()
        .expect("account-set lease context");
    store
        .try_with_store_mut(|wallet| {
            let mut accounts = wallet.wallet_accounts::<HnsAccountRecord>(2)?;
            let stored = accounts.pop().expect("selected account row");
            assert!(accounts.is_empty());
            assert!(wallet.delete_wallet_account(&stored.id, stored.revision)?);
            assert_eq!(
                wallet.save_wallet_account(&stored.id, 0, &stored.value, stored.updated_at_unix,)?,
                stored.revision
            );
            Ok::<_, hns_wallet_store::StoreError>(())
        })
        .expect("delete and recreate exact account metadata");

    assert!(matches!(
        store.try_with_store(|wallet| {
            wallet.try_with_entity_read_snapshot(|snapshot| {
                context.revalidate_unchanged_account(snapshot)
            })
        }),
        Err(HnsWalletError::StaleAccountRead)
    ));
    assert_eq!(control.query_count.load(Ordering::SeqCst), 0);
}
