#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use hns_wallet_hns::{HnsBootstrapPolicy, HnsNetwork, HnsWalletBootstrap};
use hns_wallet_store::WalletStore;
use serde_json::{Value, json};

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

fn child(database: &Path, authorization_file: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_hns-wallet-basicswap-bridge"))
        .args([
            "--database",
            database.to_str().expect("database path"),
            "--rpc-endpoint",
            "127.0.0.1:24192",
            "--rpc-authorization-file",
            authorization_file.to_str().expect("auth path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bridge")
}

fn exchange(child: &mut Child, sequence: u64, request: Value) -> Value {
    let bytes = serde_json::to_vec(&json!({
        "version": 1,
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
    assert_eq!(response["version"], 1);
    assert_eq!(response["sequence"], sequence);
    response
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
        "bid_id": "22".repeat(28),
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
    let key = exchange(&mut first, 4, key_request.clone())["result"]["public_key"]
        .as_str()
        .expect("receiver key")
        .to_owned();
    let refund = exchange(
        &mut first,
        5,
        json!({
            "operation": "key",
            "offer_id": "11".repeat(28),
            "bid_id": "22".repeat(28),
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
