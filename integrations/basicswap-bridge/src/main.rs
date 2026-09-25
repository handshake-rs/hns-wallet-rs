#![forbid(unsafe_code)]

//! Private, length-framed HNS settlement pipe for a locally launched BasicSwap.
//! No website, TCP listener, raw signing key, or generic transaction command
//! crosses this boundary. The wallet database must already contain one HNS
//! account; BasicSwap owns its own offer and bid database.

use std::env;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hns_swap::HnsHtlc;
use hns_wallet_chain_api::Preimage;
use hns_wallet_ffi::ApprovalSummary;
use hns_wallet_hns::{
    HnsAccountRecord, HnsBootstrapPolicy, HnsNetwork, HnsNodeRpcBackend, HnsNodeRpcConfig,
    HnsWalletBootstrap, HnsWalletRuntime, SystemClock, VerifiedNativeHtlcSpend,
};
use hns_wallet_provider::{
    APPROVAL_LIFETIME_SECONDS, ApprovedCall, Origin, ProviderMethod, SelectedNamespace,
};
use hns_wallet_service::{
    PersistentHnsValueConfig, PersistentHnsValueRuntime, TRUSTED_NATIVE_HNS_VALUE_ORIGIN,
    TrustedNativeHnsValueAction, WalletService,
};
use hns_wallet_store::{SecretKind, SharedWalletStore, StoreError, WalletStore};
use hns_wallet_types::{
    AccountId, ApprovalId, ApprovalKind, BaseUnits, ModuleId, SessionId, TransactionHash,
    WalletAsset,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PROTOCOL_VERSION: u16 = 2;
const MAX_FRAME_BYTES: usize = 65_536;
const MAX_AUTHORIZATION_FILE_BYTES: u64 = 4_098;
const SESSION_DOMAIN: &[u8] = b"basicswap/hns-wallet-bridge/session/v2\0";
const SEED_FINGERPRINT_DOMAIN: &[u8] = b"basicswap/hns-wallet-bridge/seed-fingerprint/v1\0";

type NativeValueService =
    WalletService<SharedWalletStore, PersistentHnsValueRuntime<HnsNodeRpcBackend, SystemClock>>;
type BridgeResult<T> = Result<T, &'static str>;

struct StoreGuard(SharedWalletStore);

impl Drop for StoreGuard {
    fn drop(&mut self) {
        let _ = self.0.lock();
    }
}

struct BridgeRuntime {
    service: NativeValueService,
    account_id: AccountId,
    wallet_id: String,
    seed_fingerprint: String,
    network: HnsNetwork,
    pending_send: Option<PendingSend>,
    _store: StoreGuard,
}

struct PendingSend {
    token: [u8; 16],
    action: TrustedNativeHnsValueAction,
}

impl Drop for BridgeRuntime {
    fn drop(&mut self) {
        if let Some(pending) = self.pending_send.take() {
            let _ = self
                .service
                .discard_trusted_native_hns_value_action(pending.action);
        }
    }
}

impl BridgeRuntime {
    fn open(
        database: &PathBuf,
        endpoint: SocketAddr,
        authorization: &str,
        passphrase: &str,
    ) -> BridgeResult<Self> {
        let mut raw_store = WalletStore::open(database).map_err(|_| "wallet_open_failed")?;
        raw_store
            .unlock(passphrase)
            .map_err(|_| "wallet_open_failed")?;
        let accounts = raw_store
            .wallet_accounts::<HnsAccountRecord>(2)
            .map_err(|_| "wallet_open_failed")?;
        if accounts.len() != 1 {
            raw_store.lock();
            return Err("wallet_account_count");
        }
        let mut config = accounts[0].value.config.clone();
        raw_store
            .validate_single_recovery_seed(config.wallet_id.as_bytes())
            .map_err(|_| "wallet_open_failed")?;
        let seed_fingerprint = seed_fingerprint(&raw_store, config.wallet_id.as_bytes())?;
        config.value_operations_enabled = true;
        config.settlement_enabled = true;
        let wallet_id = hex::encode(config.wallet_id.as_bytes());
        let account_id = config.account_id;
        let network = config.network;
        let store = StoreGuard(SharedWalletStore::new(raw_store));
        let node_config = HnsNodeRpcConfig::new(endpoint, authorization.to_owned())
            .map_err(|_| "node_config_invalid")?;
        let backend = HnsNodeRpcBackend::new(node_config).map_err(|_| "node_config_invalid")?;
        let runtime = HnsWalletRuntime::open_shared(backend, store.0.clone(), config, SystemClock)
            .map_err(|_| "wallet_runtime_failed")?;
        store.0.lock().map_err(|_| "wallet_lock_failed")?;
        let service = WalletService::new_persistent_hns_value(
            store.0.clone(),
            PersistentHnsValueConfig {
                runtime,
                account_label: "BasicSwap HNS".to_owned(),
                shakedex: None,
            },
        )
        .map_err(|_| "wallet_runtime_failed")?;
        store
            .0
            .unlock(passphrase)
            .map_err(|_| "wallet_open_failed")?;
        Ok(Self {
            service,
            account_id,
            wallet_id,
            seed_fingerprint,
            network,
            pending_send: None,
            _store: store,
        })
    }

    fn synchronize(&self) -> BridgeResult<()> {
        self.service
            .synchronize_trusted_native_hns_value()
            .map(|_| ())
            .map_err(|_| "wallet_sync_failed")
    }

    fn verify_lock(
        &self,
        session: SessionId,
        descriptor: HnsHtlc,
        funding_id: TransactionHash,
        confirmations: u32,
    ) -> BridgeResult<Option<hns_wallet_chain_api::VerifiedLock>> {
        self.service
            .verify_trusted_native_hns_htlc_lock(session, descriptor, funding_id, confirmations)
            .map_err(|_| "lock_verification_failed")
    }
}

fn seed_fingerprint(store: &WalletStore, wallet_id: &[u8]) -> BridgeResult<String> {
    let seed = store
        .get_secret(wallet_id, SecretKind::RecoverySeed)
        .map_err(|_| "seed_identity_failed")?
        .ok_or("seed_identity_failed")?;
    if seed.len() != 64 {
        return Err("seed_identity_failed");
    }
    let mut hasher = Sha256::new();
    hasher.update(SEED_FINGERPRINT_DOMAIN);
    hasher.update(seed.as_slice());
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    version: u16,
    sequence: u64,
    request: Request,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    version: u16,
    sequence: u64,
    passphrase: String,
    recovery_phrase: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Unlock {
        passphrase: String,
    },
    ChangePassphrase {
        old_passphrase: String,
        new_passphrase: String,
    },
    Lock {},
    Sync {},
    Receive {},
    Snapshot {},
    Identity {},
    Key {
        offer_id: String,
        session_nonce: String,
        refund: bool,
    },
    PrepareSend {
        recipient: String,
        amount: u64,
        maximum_fee: u64,
    },
    ApproveSend {
        token: String,
    },
    RejectSend {
        token: String,
    },
    Fund {
        terms: Terms,
        maximum_fee: u64,
    },
    SubmittedFunding {
        terms: Terms,
    },
    VerifyLock {
        terms: Terms,
        funding_id: String,
        confirmations: u32,
    },
    Redeem {
        terms: Terms,
        funding_id: String,
        confirmations: u32,
        preimage: String,
        maximum_fee: u64,
    },
    Refund {
        terms: Terms,
        funding_id: String,
        confirmations: u32,
        maximum_fee: u64,
    },
    SubmittedSpend {
        terms: Terms,
        funding_id: String,
        refund: bool,
    },
    ObserveSpend {
        terms: Terms,
        funding_id: String,
        confirmations: u32,
    },
    Rebroadcast {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Terms {
    offer_id: String,
    bid_id: String,
    session_nonce: String,
    descriptor: String,
    descriptor_hash: String,
}

impl Terms {
    fn validated(&self) -> BridgeResult<(SessionId, HnsHtlc)> {
        parse_hex::<28>(&self.bid_id, "bid_id_invalid")?;
        let session = session_id(&self.offer_id, &self.session_nonce)?;
        let raw = hex::decode(&self.descriptor).map_err(|_| "descriptor_invalid")?;
        let descriptor = HnsHtlc::decode(&raw).map_err(|_| "descriptor_invalid")?;
        let hash = parse_hex::<32>(&self.descriptor_hash, "descriptor_hash_invalid")?;
        if descriptor
            .descriptor_hash()
            .map_err(|_| "descriptor_invalid")?
            != hash
        {
            return Err("descriptor_hash_mismatch");
        }
        Ok((session, descriptor))
    }
}

#[derive(Serialize)]
struct ResponseEnvelope {
    version: u16,
    sequence: u64,
    ok: bool,
    result: Option<Value>,
    error: Option<&'static str>,
}

fn parse_hex<const N: usize>(value: &str, error: &'static str) -> BridgeResult<[u8; N]> {
    if value.len() != N * 2 {
        return Err(error);
    }
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| error)?;
    Ok(bytes)
}

fn session_id(offer_id: &str, session_nonce: &str) -> BridgeResult<SessionId> {
    let offer = parse_hex::<28>(offer_id, "offer_id_invalid")?;
    let nonce = parse_hex::<32>(session_nonce, "session_nonce_invalid")?;
    if nonce == [0; 32] {
        return Err("session_nonce_invalid");
    }
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(offer);
    hasher.update(nonce);
    Ok(SessionId::new(hasher.finalize().into()))
}

fn transaction_id(value: &str) -> BridgeResult<TransactionHash> {
    Ok(TransactionHash::new(parse_hex::<32>(
        value,
        "transaction_id_invalid",
    )?))
}

fn fee(value: u64) -> BridgeResult<BaseUnits> {
    if value == 0 {
        return Err("maximum_fee_invalid");
    }
    Ok(BaseUnits::new(u128::from(value)))
}

fn random_nonzero<const N: usize>() -> BridgeResult<[u8; N]> {
    for _ in 0..8 {
        let mut value = [0_u8; N];
        getrandom::fill(&mut value).map_err(|_| "randomness_unavailable")?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err("randomness_unavailable")
}

fn token_matches(expected: &[u8; 16], candidate: &str) -> bool {
    if candidate.len() != 32 {
        return false;
    }
    let Ok(actual) = parse_hex::<16>(candidate, "send_token_invalid") else {
        return false;
    };
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(actual) {
        difference |= left ^ right;
    }
    difference == 0
}

fn check_wallet_key(
    bridge: &BridgeRuntime,
    session: SessionId,
    descriptor: &HnsHtlc,
    refund: bool,
) -> BridgeResult<()> {
    let expected = bridge
        .service
        .trusted_native_hns_settlement_key_target(session, refund)
        .map_err(|_| "wallet_key_unavailable")?;
    let actual = if refund {
        descriptor.refund_public_key
    } else {
        descriptor.receiver_public_key
    };
    if expected != hex::encode(actual) {
        return Err("descriptor_wallet_key_mismatch");
    }
    Ok(())
}

fn handle(
    state: &mut Option<BridgeRuntime>,
    database: &PathBuf,
    endpoint: SocketAddr,
    authorization: &str,
    request: Request,
) -> BridgeResult<Value> {
    if let Request::Unlock { passphrase } = request {
        if state.is_some() {
            return Err("already_unlocked");
        }
        let passphrase = Zeroizing::new(passphrase);
        *state = Some(BridgeRuntime::open(
            database,
            endpoint,
            authorization,
            passphrase.as_str(),
        )?);
        return Ok(json!({"unlocked": true}));
    }
    if matches!(request, Request::Lock {}) {
        if state.take().is_none() {
            return Err("wallet_locked");
        }
        return Ok(json!({"unlocked": false}));
    }
    if let Request::ChangePassphrase {
        old_passphrase,
        new_passphrase,
    } = request
    {
        let old_passphrase = Zeroizing::new(old_passphrase);
        let new_passphrase = Zeroizing::new(new_passphrase);
        let bridge = state.as_mut().ok_or("wallet_locked")?;
        if bridge.pending_send.is_some() {
            return Err("send_review_pending");
        }
        let result = bridge
            ._store
            .0
            .change_passphrase(&old_passphrase, &new_passphrase);
        // Drop any ciphertext leases cached by the runtime. A fresh unlock
        // constructs a new service with the new key.
        state.take();
        return match result {
            Ok(()) => Ok(json!({"changed": true, "unlocked": false})),
            Err(StoreError::PassphraseChangedCheckpointPending) => {
                Err("passphrase_changed_checkpoint_pending")
            }
            Err(_) => Err("passphrase_change_failed"),
        };
    }
    let bridge = state.as_mut().ok_or("wallet_locked")?;
    match request {
        Request::Unlock { .. } | Request::Lock {} | Request::ChangePassphrase { .. } => {
            unreachable!()
        }
        Request::Identity {} => Ok(json!({
            "wallet_id": bridge.wallet_id,
            "seed_fingerprint": bridge.seed_fingerprint,
            "network": bridge.network,
        })),
        Request::Sync {} => {
            bridge.synchronize()?;
            Ok(json!({"synchronized": true}))
        }
        Request::Receive {} => {
            let target = bridge
                .service
                .local_trusted_native_hns_value_receive_target()
                .map_err(|_| "wallet_receive_failed")?;
            if target.module != ModuleId::Handshake {
                return Err("wallet_receive_failed");
            }
            Ok(json!({"address": target.display, "derivation_index": target.derivation_index}))
        }
        Request::Snapshot {} => {
            let snapshot = bridge
                .service
                .synchronize_trusted_native_hns_value()
                .map_err(|_| "wallet_sync_failed")?;
            if snapshot.balance.asset != WalletAsset::Hns
                || snapshot.receive_target.module != ModuleId::Handshake
            {
                return Err("wallet_sync_failed");
            }
            Ok(json!({
                "balance": snapshot.balance.base_units.get().to_string(),
                "receive_address": snapshot.receive_target.display,
            }))
        }
        Request::PrepareSend {
            recipient,
            amount,
            maximum_fee,
        } => {
            if amount == 0 || maximum_fee == 0 || recipient.len() > 128 {
                return Err("send_terms_invalid");
            }
            if let Some(pending) = bridge.pending_send.take() {
                bridge
                    .service
                    .discard_trusted_native_hns_value_action(pending.action)
                    .map_err(|_| "send_discard_failed")?;
            }
            let token = random_nonzero::<16>()?;
            let approval_id = ApprovalId::new(random_nonzero::<16>()?);
            let request_nonce = u64::from_be_bytes(random_nonzero::<8>()?);
            let now = bridge
                .service
                .trusted_native_hns_value_now_unix()
                .map_err(|_| "send_clock_unavailable")?;
            let expires_at_unix = now
                .checked_add(APPROVAL_LIFETIME_SECONDS)
                .ok_or("send_clock_unavailable")?;
            let call = ApprovedCall {
                origin: Origin::parse(TRUSTED_NATIVE_HNS_VALUE_ORIGIN)
                    .map_err(|_| "send_origin_invalid")?,
                namespace: SelectedNamespace::Hns,
                method: ProviderMethod::HnsSend,
                params: json!({
                    "account": bridge.account_id,
                    "recipient": recipient,
                    "amount": amount.to_string(),
                    "maximumFee": maximum_fee.to_string(),
                }),
                request_nonce,
            };
            let action = bridge
                .service
                .prepare_trusted_native_hns_value_action(
                    approval_id,
                    ApprovalKind::Send,
                    call,
                    expires_at_unix,
                )
                .map_err(|_| "send_preparation_failed")?;
            let ApprovalSummary::Send {
                amount: prepared_amount,
                recipient: prepared_recipient,
                maximum_fee: prepared_fee,
                chain: ModuleId::Handshake,
                ..
            } = action.summary()
            else {
                let _ = bridge
                    .service
                    .discard_trusted_native_hns_value_action(action);
                return Err("send_summary_invalid");
            };
            if prepared_amount.asset != WalletAsset::Hns
                || prepared_amount.base_units.get() != u128::from(amount)
                || prepared_fee.asset != WalletAsset::Hns
                || prepared_fee.base_units.get() != u128::from(maximum_fee)
                || prepared_recipient != &recipient
            {
                let _ = bridge
                    .service
                    .discard_trusted_native_hns_value_action(action);
                return Err("send_summary_invalid");
            }
            bridge.pending_send = Some(PendingSend { token, action });
            Ok(json!({
                "token": hex::encode(token),
                "recipient": recipient,
                "amount": amount.to_string(),
                "maximum_fee": maximum_fee.to_string(),
                "expires_at_unix": expires_at_unix,
            }))
        }
        Request::ApproveSend { token } => {
            let pending = bridge.pending_send.as_ref().ok_or("send_not_pending")?;
            if !token_matches(&pending.token, &token) {
                return Err("send_token_invalid");
            }
            let pending = bridge.pending_send.take().ok_or("send_not_pending")?;
            let receipt = bridge
                .service
                .execute_trusted_native_hns_value_action(pending.action)
                .map_err(|_| "send_broadcast_failed")?;
            let txid = receipt
                .get("txid")
                .and_then(Value::as_str)
                .ok_or("send_receipt_invalid")?;
            parse_hex::<32>(txid, "send_receipt_invalid")?;
            Ok(json!({"transaction_id": txid}))
        }
        Request::RejectSend { token } => {
            let pending = bridge.pending_send.as_ref().ok_or("send_not_pending")?;
            if !token_matches(&pending.token, &token) {
                return Err("send_token_invalid");
            }
            let pending = bridge.pending_send.take().ok_or("send_not_pending")?;
            bridge
                .service
                .discard_trusted_native_hns_value_action(pending.action)
                .map_err(|_| "send_discard_failed")?;
            Ok(json!({"rejected": true}))
        }
        Request::Key {
            offer_id,
            session_nonce,
            refund,
        } => {
            let session = session_id(&offer_id, &session_nonce)?;
            let public_key = bridge
                .service
                .trusted_native_hns_settlement_key_target(session, refund)
                .map_err(|_| "wallet_key_unavailable")?;
            Ok(json!({"public_key": public_key}))
        }
        Request::Fund { terms, maximum_fee } => {
            let (session, descriptor) = terms.validated()?;
            check_wallet_key(bridge, session, &descriptor, true)?;
            if let Some(transaction) = bridge
                .service
                .submitted_trusted_native_hns_htlc_lock_transaction_id(session, descriptor)
                .map_err(|_| "funding_recovery_failed")?
            {
                return Ok(
                    json!({"transaction_id": hex::encode(transaction.as_bytes()), "output_index": 0, "recovered": true}),
                );
            }
            bridge.synchronize()?;
            let prepared = bridge
                .service
                .prepare_trusted_native_hns_htlc_lock(session, descriptor, fee(maximum_fee)?)
                .map_err(|_| "funding_preparation_failed")?;
            let receipt = bridge
                .service
                .broadcast_trusted_native_hns_settlement(&prepared.0)
                .map_err(|_| "funding_broadcast_failed")?;
            Ok(
                json!({"transaction_id": hex::encode(receipt.txid.as_bytes()), "output_index": 0, "recovered": false}),
            )
        }
        Request::SubmittedFunding { terms } => {
            let (session, descriptor) = terms.validated()?;
            check_wallet_key(bridge, session, &descriptor, true)?;
            let transaction = bridge
                .service
                .submitted_trusted_native_hns_htlc_lock_transaction_id(session, descriptor)
                .map_err(|_| "funding_recovery_failed")?;
            Ok(json!({"transaction_id": transaction.map(|id| hex::encode(id.as_bytes()))}))
        }
        Request::VerifyLock {
            terms,
            funding_id,
            confirmations,
        } => {
            let (session, descriptor) = terms.validated()?;
            bridge.synchronize()?;
            let verified = bridge.verify_lock(
                session,
                descriptor,
                transaction_id(&funding_id)?,
                confirmations,
            )?;
            Ok(json!({"verified": verified.is_some()}))
        }
        Request::Redeem {
            terms,
            funding_id,
            confirmations,
            preimage,
            maximum_fee,
        } => {
            let (session, descriptor) = terms.validated()?;
            check_wallet_key(bridge, session, &descriptor, false)?;
            let preimage = Zeroizing::new(preimage);
            let secret_bytes = Zeroizing::new(parse_hex::<32>(&preimage, "preimage_invalid")?);
            if HnsHtlc::hash_preimage(&secret_bytes) != descriptor.hashlock {
                return Err("preimage_hash_mismatch");
            }
            let secret = Preimage::new(*secret_bytes);
            let funding_id = transaction_id(&funding_id)?;
            if let Some(transaction) = bridge
                .service
                .submitted_trusted_native_hns_htlc_spend_transaction_id(
                    session, descriptor, funding_id, false,
                )
                .map_err(|_| "redeem_recovery_failed")?
            {
                return Ok(
                    json!({"transaction_id": hex::encode(transaction.as_bytes()), "recovered": true}),
                );
            }
            bridge.synchronize()?;
            let lock = bridge
                .verify_lock(session, descriptor, funding_id, confirmations)?
                .ok_or("lock_unconfirmed")?;
            let prepared = bridge
                .service
                .prepare_trusted_native_hns_htlc_redeem_with_wallet_key(
                    session,
                    descriptor,
                    lock,
                    secret,
                    fee(maximum_fee)?,
                )
                .map_err(|_| "redeem_preparation_failed")?;
            let receipt = bridge
                .service
                .broadcast_trusted_native_hns_settlement(&prepared.0)
                .map_err(|_| "redeem_broadcast_failed")?;
            Ok(json!({"transaction_id": hex::encode(receipt.txid.as_bytes()), "recovered": false}))
        }
        Request::Refund {
            terms,
            funding_id,
            confirmations,
            maximum_fee,
        } => {
            let (session, descriptor) = terms.validated()?;
            check_wallet_key(bridge, session, &descriptor, true)?;
            let funding_id = transaction_id(&funding_id)?;
            if let Some(transaction) = bridge
                .service
                .submitted_trusted_native_hns_htlc_spend_transaction_id(
                    session, descriptor, funding_id, true,
                )
                .map_err(|_| "refund_recovery_failed")?
            {
                return Ok(
                    json!({"transaction_id": hex::encode(transaction.as_bytes()), "recovered": true}),
                );
            }
            bridge.synchronize()?;
            let lock = bridge
                .verify_lock(session, descriptor, funding_id, confirmations)?
                .ok_or("lock_unconfirmed")?;
            let prepared = bridge
                .service
                .prepare_trusted_native_hns_htlc_refund_with_wallet_key(
                    session,
                    descriptor,
                    lock,
                    fee(maximum_fee)?,
                )
                .map_err(|_| "refund_preparation_failed")?;
            let receipt = bridge
                .service
                .broadcast_trusted_native_hns_settlement(&prepared.0)
                .map_err(|_| "refund_broadcast_failed")?;
            Ok(json!({"transaction_id": hex::encode(receipt.txid.as_bytes()), "recovered": false}))
        }
        Request::SubmittedSpend {
            terms,
            funding_id,
            refund,
        } => {
            let (session, descriptor) = terms.validated()?;
            check_wallet_key(bridge, session, &descriptor, refund)?;
            let transaction = bridge
                .service
                .submitted_trusted_native_hns_htlc_spend_transaction_id(
                    session,
                    descriptor,
                    transaction_id(&funding_id)?,
                    refund,
                )
                .map_err(|_| "spend_recovery_failed")?;
            Ok(json!({"transaction_id": transaction.map(|id| hex::encode(id.as_bytes()))}))
        }
        Request::ObserveSpend {
            terms,
            funding_id,
            confirmations,
        } => {
            let (session, descriptor) = terms.validated()?;
            bridge.synchronize()?;
            let lock = bridge
                .verify_lock(
                    session,
                    descriptor,
                    transaction_id(&funding_id)?,
                    confirmations,
                )?
                .ok_or("lock_unconfirmed")?;
            let spend = bridge
                .service
                .verify_trusted_native_hns_htlc_spend(session, descriptor, lock)
                .map_err(|_| "spend_verification_failed")?;
            match spend {
                None => Ok(json!({"observed": false})),
                Some(VerifiedNativeHtlcSpend::Refund {
                    transaction,
                    confirmation_count,
                }) => Ok(
                    json!({"observed": true, "branch": "refund", "transaction_id": hex::encode(transaction.as_bytes()), "confirmations": confirmation_count}),
                ),
                Some(VerifiedNativeHtlcSpend::Redeem {
                    transaction,
                    confirmation_count,
                    preimage,
                }) => Ok(
                    json!({"observed": true, "branch": "redeem", "transaction_id": hex::encode(transaction.as_bytes()), "confirmations": confirmation_count, "preimage": hex::encode(preimage.expose_for_settlement())}),
                ),
            }
        }
        Request::Rebroadcast {} => {
            bridge.synchronize()?;
            let count = bridge
                .service
                .rebroadcast_trusted_native_hns_settlements()
                .map_err(|_| "rebroadcast_failed")?;
            Ok(json!({"count": count}))
        }
    }
}

fn read_frame(input: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut length = [0_u8; 4];
    if input.read(&mut length[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut length[1..])?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    input.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn write_frame(output: &mut impl Write, response: &ResponseEnvelope) -> io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(response)?);
    let length = u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    output.write_all(&length.to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

fn read_private_authorization(path: &PathBuf) -> io::Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let parent = path
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let file = std::fs::File::from(descriptor);
        let metadata = file.metadata()?;
        let current_uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file()
            || metadata.uid() != current_uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_AUTHORIZATION_FILE_BYTES
            || !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != current_uid
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe HNS authorization file boundary",
            ));
        }
        let mut authorization = Zeroizing::new(String::new());
        file.take(MAX_AUTHORIZATION_FILE_BYTES + 1)
            .read_to_string(&mut authorization)?;
        if authorization.len() as u64 > MAX_AUTHORIZATION_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HNS authorization file exceeds limit",
            ));
        }
        Ok(authorization)
    }
    #[cfg(not(unix))]
    {
        Ok(Zeroizing::new(std::fs::read_to_string(path)?))
    }
}

fn run_initializer(arguments: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 8
        || arguments[2] != "--database"
        || arguments[4] != "--network"
        || arguments[6] != "--restore-height"
    {
        return Err("usage: hns-wallet-basicswap-bridge --initialize --database PATH --network mainnet|testnet|regtest|simnet --restore-height HEIGHT".into());
    }
    let database = PathBuf::from(&arguments[3]);
    let network = match arguments[5].to_str() {
        Some("mainnet") => HnsNetwork::Mainnet,
        Some("testnet") => HnsNetwork::Testnet,
        Some("regtest") => HnsNetwork::Regtest,
        Some("simnet") => HnsNetwork::Simnet,
        _ => return Err("invalid HNS bootstrap network".into()),
    };
    let birthday: u64 = arguments[7].to_string_lossy().parse()?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let frame = read_frame(&mut input)?.ok_or("missing HNS bootstrap request")?;
    let request: BootstrapRequest = serde_json::from_slice(&frame)?;
    if request.version != PROTOCOL_VERSION || request.sequence != 1 {
        return Err("HNS bootstrap protocol mismatch".into());
    }
    let passphrase = Zeroizing::new(request.passphrase);
    let phrase = request.recovery_phrase.map(Zeroizing::new);
    let policy = HnsBootstrapPolicy::new(network, birthday);
    let bootstrap = match phrase.as_deref() {
        Some(value) => HnsWalletBootstrap::restore(value, policy),
        None => HnsWalletBootstrap::generate(policy),
    }
    .map_err(|_| "HNS bootstrap seed invalid")?;
    let wallet_id = hex::encode(bootstrap.wallet_id().as_bytes());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (store, _) = WalletStore::create_with_initializer(&database, &passphrase, |store| {
        bootstrap.persist(store, now)
    })
    .map_err(|_| "HNS bootstrap store creation failed")?;
    let fingerprint = seed_fingerprint(&store, bootstrap.wallet_id().as_bytes())?;
    drop(store);
    let result = match phrase {
        Some(_) => {
            json!({"created": false, "wallet_id": wallet_id, "seed_fingerprint": fingerprint})
        }
        None => json!({
            "created": true,
            "wallet_id": wallet_id,
            "seed_fingerprint": fingerprint,
            "recovery_phrase": bootstrap.into_recovery_phrase().expose_for_dedicated_display(),
        }),
    };
    write_frame(
        &mut output,
        &ResponseEnvelope {
            version: PROTOCOL_VERSION,
            sequence: 1,
            ok: true,
            result: Some(result),
            error: None,
        },
    )?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|option| option == "--initialize")
    {
        return run_initializer(&arguments);
    }
    if arguments.len() != 7
        || arguments[1] != "--database"
        || arguments[3] != "--rpc-endpoint"
        || arguments[5] != "--rpc-authorization-file"
    {
        return Err("usage: hns-wallet-basicswap-bridge --database PATH --rpc-endpoint LOOPBACK:PORT --rpc-authorization-file PATH".into());
    }
    let database = PathBuf::from(&arguments[2]);
    let endpoint: SocketAddr = arguments[4].to_string_lossy().parse()?;
    if !endpoint.ip().is_loopback() {
        return Err("node endpoint must be loopback".into());
    }
    let authorization = read_private_authorization(&PathBuf::from(&arguments[6]))?;
    let authorization = authorization.strip_suffix('\n').unwrap_or(&authorization);
    let authorization = authorization.strip_suffix('\r').unwrap_or(authorization);
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut state = None;
    let mut next_sequence = 1_u64;
    while let Some(frame) = read_frame(&mut input)? {
        let request: RequestEnvelope = serde_json::from_slice(&frame)?;
        if request.version != PROTOCOL_VERSION || request.sequence != next_sequence {
            return Err("bridge protocol sequence mismatch".into());
        }
        next_sequence = next_sequence.checked_add(1).ok_or("sequence exhausted")?;
        let result = handle(
            &mut state,
            &database,
            endpoint,
            authorization,
            request.request,
        );
        let response = match result {
            Ok(value) => ResponseEnvelope {
                version: PROTOCOL_VERSION,
                sequence: request.sequence,
                ok: true,
                result: Some(value),
                error: None,
            },
            Err(code) => ResponseEnvelope {
                version: PROTOCOL_VERSION,
                sequence: request.sequence,
                ok: false,
                result: None,
                error: Some(code),
            },
        };
        write_frame(&mut output, &response)?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("HNS bridge stopped: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_stable_and_distinct_by_nonce_and_offer() {
        let offer = "11".repeat(28);
        let nonce = "22".repeat(32);
        let first = session_id(&offer, &nonce).expect("session");
        assert_eq!(
            hex::encode(first.as_bytes()),
            "7ffd6d488a58e6a55b2e74e1aa655aa82982ab26c40091d549b1308874385cd3"
        );
        assert_eq!(first, session_id(&offer, &nonce).expect("retry"));
        assert_ne!(
            first,
            session_id(&offer, &"23".repeat(32)).expect("other nonce")
        );
        assert_ne!(
            first,
            session_id(&"12".repeat(28), &nonce).expect("other offer")
        );
        assert!(session_id("00", &nonce).is_err());
        assert!(session_id(&offer, &"00".repeat(32)).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_frames() {
        let unknown =
            br#"{"version":2,"sequence":1,"request":{"operation":"sync","unexpected":1}}"#;
        assert!(serde_json::from_slice::<RequestEnvelope>(unknown).is_err());
        let mut frame = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        frame.push(0);
        assert!(read_frame(&mut frame.as_slice()).is_err());
    }
}
