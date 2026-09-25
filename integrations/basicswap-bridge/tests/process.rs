#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hns_swap::HnsHtlc;
use hns_wallet_hns::direct_shakescape_network_binding;
use hns_wallet_hns::{HnsBootstrapPolicy, HnsNetwork, HnsWalletBootstrap};
use hns_wallet_store::WalletStore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn private_directory() -> tempfile::TempDir {
    let parent = std::env::var_os("HNS_WALLET_STORE_TEST_TMPDIR")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let directory = tempfile::tempdir_in(parent).expect("private test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
    }
    directory
}

fn child_at(database: &Path, authorization_file: &Path, endpoint: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hns-wallet-basicswap-bridge"))
        .args([
            "--database",
            database.to_str().expect("database path"),
            "--rpc-endpoint",
            endpoint,
            "--rpc-authorization-file",
            authorization_file.to_str().expect("auth path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(
            if std::env::var_os("BASICSWAP_HSRD_REGTEST_RPC").is_some() {
                Stdio::inherit()
            } else {
                Stdio::null()
            },
        )
        .spawn()
        .expect("spawn bridge")
}

fn child(database: &Path, authorization_file: &Path) -> Child {
    child_at(database, authorization_file, "127.0.0.1:24192")
}

fn exchange(child: &mut Child, sequence: u64, request: Value) -> Value {
    let bytes = serde_json::to_vec(&json!({
        "version": 2,
        "sequence": sequence,
        "request": request,
    }))
    .expect("request JSON");
    let input = child.stdin.as_mut().expect("child input");
    input
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .expect("frame length");
    input.write_all(&bytes).expect("frame body");
    input.flush().expect("flush request");
    let output = child.stdout.as_mut().expect("child output");
    let mut length = [0_u8; 4];
    output.read_exact(&mut length).expect("response length");
    let length = u32::from_le_bytes(length) as usize;
    assert!(length > 0 && length <= 65_536);
    let mut body = vec![0_u8; length];
    output.read_exact(&mut body).expect("response body");
    let response: Value = serde_json::from_slice(&body).expect("response JSON");
    assert_eq!(response["version"], 2);
    assert_eq!(response["sequence"], sequence);
    response
}

fn initialize(database: &Path, recovery_phrase: Option<&str>) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hns-wallet-basicswap-bridge"))
        .args([
            "--initialize",
            "--database",
            database.to_str().expect("database path"),
            "--network",
            "regtest",
            "--restore-height",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start initializer");
    let bytes = serde_json::to_vec(&json!({
        "version": 2,
        "sequence": 1,
        "passphrase": "test passphrase",
        "recovery_phrase": recovery_phrase,
    }))
    .expect("bootstrap request");
    let input = child.stdin.as_mut().expect("bootstrap input");
    input
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .expect("bootstrap frame length");
    input.write_all(&bytes).expect("bootstrap frame body");
    input.flush().expect("bootstrap flush");
    let output = child.stdout.as_mut().expect("bootstrap output");
    let mut length = [0_u8; 4];
    output
        .read_exact(&mut length)
        .expect("bootstrap response length");
    let mut body = vec![0_u8; u32::from_le_bytes(length) as usize];
    output
        .read_exact(&mut body)
        .expect("bootstrap response body");
    drop(child.stdin.take());
    assert!(child.wait().expect("bootstrap exit").success());
    let response: Value = serde_json::from_slice(&body).expect("bootstrap response JSON");
    assert_eq!(response["version"], 2);
    assert_eq!(response["sequence"], 1);
    assert_eq!(response["ok"], true);
    response["result"].clone()
}

#[test]
fn initializer_creates_and_restores_private_hns_account() {
    let directory = private_directory();
    let database = directory.path().join("created.db");
    let restored_database = directory.path().join("restored.db");
    let created = initialize(&database, None);
    assert_eq!(created["created"], true);
    let phrase = created["recovery_phrase"]
        .as_str()
        .expect("recovery phrase");
    assert_eq!(phrase.split_whitespace().count(), 24);
    let restored = initialize(&restored_database, Some(phrase));
    assert_eq!(restored["created"], false);
    assert_eq!(restored.get("recovery_phrase"), None);
    assert_eq!(restored["seed_fingerprint"], created["seed_fingerprint"]);

    let authorization_file = directory.path().join("hsrd-auth");
    std::fs::write(&authorization_file, "Basic test\n").expect("auth file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&authorization_file, std::fs::Permissions::from_mode(0o600))
            .expect("private auth file");
    }
    for (wallet, expected) in [(&database, &created), (&restored_database, &restored)] {
        let mut bridge = child(wallet, &authorization_file);
        assert_eq!(
            exchange(
                &mut bridge,
                1,
                json!({"operation": "unlock", "passphrase": "test passphrase"}),
            )["ok"],
            true
        );
        let identity = exchange(&mut bridge, 2, json!({"operation": "identity"}));
        assert_eq!(identity["ok"], true);
        assert_eq!(identity["result"]["wallet_id"], expected["wallet_id"]);
        assert_eq!(
            identity["result"]["seed_fingerprint"],
            created["seed_fingerprint"]
        );
        assert_eq!(identity["result"]["network"], "regtest");
        let key = exchange(
            &mut bridge,
            3,
            json!({
                "operation": "key", "offer_id": "11".repeat(28),
                "session_nonce": "22".repeat(32), "refund": false,
            }),
        );
        assert_eq!(key["ok"], true, "{key}");
        drop(bridge.stdin.take());
        assert!(bridge.wait().expect("bridge exit").success());
    }
}

fn mine_regtest(address: &str, count: u32) {
    let cli = std::env::var("BASICSWAP_HSD_CLI").expect("HSD CLI path");
    let prefix = std::env::var("BASICSWAP_HSD_REGTEST_PREFIX").expect("HSD data prefix");
    let port =
        std::env::var("BASICSWAP_HSD_REGTEST_RPC_PORT").unwrap_or_else(|_| "14037".to_owned());
    let output = Command::new(cli)
        .arg("--network=regtest")
        .arg(format!("--prefix={prefix}"))
        .arg(format!("--http-port={port}"))
        .args(["rpc", "generatetoaddress", &count.to_string(), address])
        .output()
        .expect("run HSD miner");
    assert!(output.status.success(), "HSD regtest mining failed");
}

fn send_regtest(address: &str, amount: &str) {
    let cli = std::env::var("BASICSWAP_HSW_CLI").expect("HSD wallet CLI path");
    let prefix = std::env::var("BASICSWAP_HSD_REGTEST_PREFIX").expect("HSD data prefix");
    let port =
        std::env::var("BASICSWAP_HSW_REGTEST_RPC_PORT").unwrap_or_else(|_| "14039".to_owned());
    let output = Command::new(cli)
        .arg("--network=regtest")
        .arg(format!("--prefix={prefix}"))
        .arg(format!("--http-port={port}"))
        .args(["send", address, amount])
        .output()
        .expect("run HSD wallet");
    assert!(output.status.success(), "HSD regtest payment failed");
}

#[test]
fn encrypted_wallet_pipe_reopens_same_session_key() {
    let directory = private_directory();
    let database = directory.path().join("wallet.db");
    let authorization_file = directory.path().join("hsrd-auth");
    std::fs::write(&authorization_file, "Basic test\n").expect("auth file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&authorization_file, std::fs::Permissions::from_mode(0o600))
            .expect("private auth file");
    }
    let bootstrap = HnsWalletBootstrap::generate(HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0))
        .expect("bootstrap");
    let mut store = WalletStore::create(&database, "test passphrase").expect("store");
    bootstrap.persist(&mut store, 1).expect("persist account");
    drop(store);

    let key_request = json!({
        "operation": "key",
        "offer_id": "11".repeat(28),
        "session_nonce": "22".repeat(32),
        "refund": false,
    });
    let mut first = child(&database, &authorization_file);
    assert_eq!(
        exchange(&mut first, 1, json!({"operation": "sync"}))["error"],
        "wallet_locked"
    );
    assert_eq!(
        exchange(
            &mut first,
            2,
            json!({"operation": "unlock", "passphrase": "wrong"}),
        )["error"],
        "wallet_open_failed"
    );
    assert_eq!(
        exchange(
            &mut first,
            3,
            json!({"operation": "unlock", "passphrase": "test passphrase"}),
        )["result"]["unlocked"],
        true
    );
    let receive = exchange(&mut first, 4, json!({"operation": "receive"}));
    let address = receive["result"]["address"]
        .as_str()
        .expect("HNS receive address");
    assert!(address.starts_with("rs1q"));
    assert_eq!(receive["result"]["derivation_index"], 0);
    let key = exchange(&mut first, 5, key_request.clone())["result"]["public_key"]
        .as_str()
        .expect("receiver key")
        .to_owned();
    let refund = exchange(
        &mut first,
        6,
        json!({
            "operation": "key",
            "offer_id": "11".repeat(28),
            "session_nonce": "22".repeat(32),
            "refund": true,
        }),
    )["result"]["public_key"]
        .as_str()
        .expect("refund key")
        .to_owned();
    assert_eq!(key.len(), 66);
    assert_ne!(key, refund);
    drop(first.stdin.take());
    assert!(first.wait().expect("first exit").success());

    let mut restarted = child(&database, &authorization_file);
    assert_eq!(
        exchange(
            &mut restarted,
            1,
            json!({"operation": "unlock", "passphrase": "test passphrase"}),
        )["ok"],
        true
    );
    assert_eq!(
        exchange(&mut restarted, 2, key_request)["result"]["public_key"],
        key
    );
    drop(restarted.stdin.take());
    assert!(restarted.wait().expect("restart exit").success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&authorization_file, std::fs::Permissions::from_mode(0o644))
            .expect("insecure auth file mode");
        let mut rejected = child(&database, &authorization_file);
        drop(rejected.stdin.take());
        assert!(!rejected.wait().expect("unsafe auth exit").success());

        std::fs::set_permissions(&authorization_file, std::fs::Permissions::from_mode(0o600))
            .expect("restore private auth mode");
        let authorization_link = directory.path().join("hsrd-auth-link");
        std::os::unix::fs::symlink(&authorization_file, &authorization_link)
            .expect("authorization symlink");
        let mut rejected = child(&database, &authorization_link);
        drop(rejected.stdin.take());
        assert!(!rejected.wait().expect("symlink auth exit").success());
    }
}

#[test]
#[ignore = "requires isolated HSD and hsrd regtest processes with --wallet-index"]
fn funded_lock_uses_real_hsrd_wallet_index() {
    let endpoint = std::env::var("BASICSWAP_HSRD_REGTEST_RPC").expect("regtest RPC endpoint");
    let authorization_file =
        std::env::var("BASICSWAP_HSRD_REGTEST_AUTH_FILE").expect("regtest RPC authorization file");
    let directory = private_directory();
    let database = directory.path().join("wallet.db");
    let bootstrap = HnsWalletBootstrap::generate(HnsBootstrapPolicy::new(HnsNetwork::Regtest, 0))
        .expect("bootstrap");
    let mut store = WalletStore::create(&database, "test passphrase").expect("store");
    bootstrap.persist(&mut store, 1).expect("persist account");
    drop(store);

    let mut bridge = child_at(&database, Path::new(&authorization_file), &endpoint);
    assert_eq!(
        exchange(
            &mut bridge,
            1,
            json!({"operation": "unlock", "passphrase": "test passphrase"}),
        )["ok"],
        true
    );
    let snapshot = exchange(&mut bridge, 2, json!({"operation": "snapshot"}));
    assert_eq!(snapshot["ok"], true, "{snapshot}");
    assert_eq!(snapshot["result"]["balance"], "0");
    let address = snapshot["result"]["receive_address"]
        .as_str()
        .expect("receive address");
    assert!(address.starts_with("rs1q"));

    let miner_address = std::env::var("BASICSWAP_HSD_MINER_ADDRESS").expect("miner address");
    mine_regtest(&miner_address, 4);
    send_regtest(address, "10");
    mine_regtest(&miner_address, 2);
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut sequence = 3;
    loop {
        let current = exchange(&mut bridge, sequence, json!({"operation": "snapshot"}));
        sequence += 1;
        if current["ok"] == true
            && current["result"]["balance"]
                .as_str()
                .and_then(|balance| balance.parse::<u64>().ok())
                .is_some_and(|balance| balance > 1_000_000)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "wallet funding not indexed: {current}"
        );
        thread::sleep(Duration::from_secs(1));
    }

    let offer_id = "11".repeat(28);
    let bid_id = "22".repeat(28);
    let session_nonce = "33".repeat(32);
    let receiver = exchange(
        &mut bridge,
        sequence,
        json!({
            "operation": "key", "offer_id": offer_id,
            "session_nonce": session_nonce, "refund": false,
        }),
    );
    sequence += 1;
    let refund = exchange(
        &mut bridge,
        sequence,
        json!({
            "operation": "key", "offer_id": offer_id,
            "session_nonce": session_nonce, "refund": true,
        }),
    );
    sequence += 1;
    assert_eq!(receiver["ok"], true, "{receiver}");
    assert_eq!(refund["ok"], true, "{refund}");
    let receiver_key = hex::decode(receiver["result"]["public_key"].as_str().expect("receiver"))
        .expect("receiver key hex");
    let refund_key = hex::decode(refund["result"]["public_key"].as_str().expect("refund"))
        .expect("refund key hex");
    let preimage = [7_u8; 32];
    let hashlock: [u8; 32] = Sha256::digest(preimage).into();
    let network = direct_shakescape_network_binding(HnsNetwork::Regtest).expect("network");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let refund_locktime = 0x8000_0000 | (((now + 86_400 + 511) / 512) as u32);
    let mut descriptor_bytes = Vec::with_capacity(148);
    descriptor_bytes.extend_from_slice(&1_u16.to_le_bytes());
    descriptor_bytes.extend_from_slice(&network.magic.to_le_bytes());
    descriptor_bytes.extend_from_slice(network.genesis.as_bytes());
    descriptor_bytes.extend_from_slice(&1_000_000_u64.to_le_bytes());
    descriptor_bytes.extend_from_slice(&hashlock);
    descriptor_bytes.extend_from_slice(&receiver_key);
    descriptor_bytes.extend_from_slice(&refund_key);
    descriptor_bytes.extend_from_slice(&refund_locktime.to_le_bytes());
    let descriptor = HnsHtlc::decode(&descriptor_bytes).expect("canonical descriptor");
    let terms = json!({
        "offer_id": offer_id,
        "bid_id": bid_id,
        "session_nonce": session_nonce,
        "descriptor": hex::encode(descriptor_bytes),
        "descriptor_hash": hex::encode(descriptor.descriptor_hash().expect("hash")),
    });
    let before_funding = exchange(
        &mut bridge,
        sequence,
        json!({"operation": "submitted_funding", "terms": terms.clone()}),
    );
    sequence += 1;
    assert_eq!(before_funding["result"]["transaction_id"], Value::Null);
    let funded = exchange(
        &mut bridge,
        sequence,
        json!({
            "operation": "fund", "terms": terms.clone(), "maximum_fee": 100_000,
        }),
    );
    sequence += 1;
    assert_eq!(funded["ok"], true, "{funded}");
    let funding_id = funded["result"]["transaction_id"]
        .as_str()
        .expect("funding ID")
        .to_owned();
    assert_eq!(funded["result"]["output_index"], 0);
    let submitted_funding = exchange(
        &mut bridge,
        sequence,
        json!({"operation": "submitted_funding", "terms": terms.clone()}),
    );
    sequence += 1;
    assert_eq!(submitted_funding["result"]["transaction_id"], funding_id);
    mine_regtest(&miner_address, 2);

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let verified = exchange(
            &mut bridge,
            sequence,
            json!({
                "operation": "verify_lock", "terms": terms.clone(),
                "funding_id": funding_id, "confirmations": 2,
            }),
        );
        sequence += 1;
        if verified["ok"] == true && verified["result"]["verified"] == true {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "HNS lock not verified: {verified}"
        );
        thread::sleep(Duration::from_secs(1));
    }

    let redeemed = exchange(
        &mut bridge,
        sequence,
        json!({
            "operation": "redeem", "terms": terms.clone(),
            "funding_id": funding_id, "confirmations": 2,
            "preimage": hex::encode(preimage), "maximum_fee": 100_000,
        }),
    );
    sequence += 1;
    assert_eq!(redeemed["ok"], true, "{redeemed}");
    let submitted_spend = exchange(
        &mut bridge,
        sequence,
        json!({
            "operation": "submitted_spend", "terms": terms.clone(),
            "funding_id": funding_id, "refund": false,
        }),
    );
    sequence += 1;
    assert_eq!(
        submitted_spend["result"]["transaction_id"],
        redeemed["result"]["transaction_id"]
    );
    mine_regtest(&miner_address, 2);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let spent = exchange(
            &mut bridge,
            sequence,
            json!({
                "operation": "observe_spend", "terms": terms.clone(),
                "funding_id": funding_id, "confirmations": 2,
            }),
        );
        sequence += 1;
        if spent["ok"] == true && spent["result"]["observed"] == true {
            assert_eq!(spent["result"]["branch"], "redeem");
            assert_eq!(spent["result"]["preimage"], hex::encode(preimage));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "HNS redeem not observed: {spent}"
        );
        thread::sleep(Duration::from_secs(1));
    }
    drop(bridge.stdin.take());
    assert!(bridge.wait().expect("bridge exit").success());

    let mut restarted = child_at(&database, Path::new(&authorization_file), &endpoint);
    assert_eq!(
        exchange(
            &mut restarted,
            1,
            json!({"operation": "unlock", "passphrase": "test passphrase"}),
        )["ok"],
        true
    );
    let recovered = exchange(
        &mut restarted,
        2,
        json!({
            "operation": "observe_spend", "terms": terms,
            "funding_id": funding_id, "confirmations": 2,
        }),
    );
    assert_eq!(recovered["ok"], true, "{recovered}");
    assert_eq!(recovered["result"]["branch"], "redeem");
    assert_eq!(recovered["result"]["preimage"], hex::encode(preimage));
    drop(restarted.stdin.take());
    assert!(restarted.wait().expect("restarted bridge exit").success());
}
