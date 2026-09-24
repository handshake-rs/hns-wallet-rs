#![forbid(unsafe_code)]

//! Private, length-framed HNS settlement pipe for a locally launched BasicSwap.
//! No website, TCP listener, raw signing key, or generic transaction command
//! crosses this boundary. The wallet database must already contain one HNS
//! account; BasicSwap owns its own offer and bid database.

use std::env;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use hns_swap::HnsHtlc;
use hns_wallet_chain_api::Preimage;
use hns_wallet_hns::{
    HnsAccountRecord, HnsNodeRpcBackend, HnsNodeRpcConfig, HnsWalletRuntime, SystemClock,
    VerifiedNativeHtlcSpend,
};
use hns_wallet_service::{PersistentHnsValueConfig, PersistentHnsValueRuntime, WalletService};
use hns_wallet_store::{SharedWalletStore, WalletStore};
use hns_wallet_types::{BaseUnits, SessionId, TransactionHash};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME_BYTES: usize = 65_536;
const MAX_AUTHORIZATION_FILE_BYTES: u64 = 4_098;
const SESSION_DOMAIN: &[u8] = b"basicswap/hns-wallet-bridge/session/v1\0";

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
    _store: StoreGuard,
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
        config.value_operations_enabled = true;
        config.settlement_enabled = true;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    version: u16,
    sequence: u64,
    request: Request,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Unlock {
        passphrase: String,
    },
    Lock {},
    Sync {},
    Key {
        offer_id: String,
        bid_id: String,
        refund: bool,
    },
    Fund {
        terms: Terms,
        maximum_fee: u64,
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
    descriptor: String,
    descriptor_hash: String,
}

impl Terms {
    fn validated(&self) -> BridgeResult<(SessionId, HnsHtlc)> {
        let session = session_id(&self.offer_id, &self.bid_id)?;
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

fn session_id(offer_id: &str, bid_id: &str) -> BridgeResult<SessionId> {
    let offer = parse_hex::<28>(offer_id, "offer_id_invalid")?;
    let bid = parse_hex::<28>(bid_id, "bid_id_invalid")?;
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(offer);
    hasher.update(bid);
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
    let bridge = state.as_ref().ok_or("wallet_locked")?;
    match request {
        Request::Unlock { .. } | Request::Lock {} => unreachable!(),
        Request::Sync {} => {
            bridge.synchronize()?;
            Ok(json!({"synchronized": true}))
        }
        Request::Key {
            offer_id,
            bid_id,
            refund,
        } => {
            let session = session_id(&offer_id, &bid_id)?;
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().collect::<Vec<_>>();
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
    fn session_id_is_stable_and_distinct_by_bid_and_offer() {
        let offer = "11".repeat(28);
        let bid = "22".repeat(28);
        let first = session_id(&offer, &bid).expect("session");
        assert_eq!(
            hex::encode(first.as_bytes()),
            "25993e216776141c0e1e4f68712c48b71b954fabbc98cb47c1c960f5a3196777"
        );
        assert_eq!(first, session_id(&offer, &bid).expect("retry"));
        assert_ne!(
            first,
            session_id(&offer, &"23".repeat(28)).expect("other bid")
        );
        assert_ne!(
            first,
            session_id(&"12".repeat(28), &bid).expect("other offer")
        );
        assert!(session_id("00", &bid).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_frames() {
        let unknown =
            br#"{"version":1,"sequence":1,"request":{"operation":"sync","unexpected":1}}"#;
        assert!(serde_json::from_slice::<RequestEnvelope>(unknown).is_err());
        let mut frame = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        frame.push(0);
        assert!(read_frame(&mut frame.as_slice()).is_err());
    }
}
