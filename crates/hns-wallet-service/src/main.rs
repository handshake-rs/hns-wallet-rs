#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hns_wallet_ffi::{LENGTH_PREFIX_BYTES, declared_payload_len};
use hns_wallet_service::WalletService;
use hns_wallet_store::{SharedWalletStore, WalletStore};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = wallet_database_path()?;
    let store = SharedWalletStore::new(WalletStore::open(database_path)?);
    let mut service = WalletService::new_persistent_control(store)?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        match input.read(&mut prefix[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        input.read_exact(&mut prefix[1..])?;
        let length = declared_payload_len(prefix)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(LENGTH_PREFIX_BYTES + length));
        frame.extend_from_slice(&prefix);
        frame.resize(LENGTH_PREFIX_BYTES + length, 0);
        input.read_exact(&mut frame[LENGTH_PREFIX_BYTES..])?;
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let response = service.process_frame(frame.as_slice(), now_unix_ms)?;
        output.write_all(&response)?;
        output.flush()?;
    }
}

fn wallet_database_path() -> io::Result<PathBuf> {
    let mut arguments = std::env::args_os().skip(1);
    let flag = arguments.next();
    let path = arguments.next().ok_or_else(invalid_arguments)?;
    if flag.as_deref() != Some(OsStr::new("--database"))
        || path.is_empty()
        || arguments.next().is_some()
    {
        return Err(invalid_arguments());
    }
    Ok(PathBuf::from(path))
}

fn invalid_arguments() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidInput,
        "usage: hns-wallet-service --database <existing-wallet-database>",
    )
}
