//! Synchronous authenticated loopback adapter for hns-node-rs wallet RPC v1.
//!
//! The adapter is deliberately small and dependency-light: it speaks one
//! HTTP/1.1 request per loopback TCP connection, validates the complete wire
//! envelope, and never holds signing material or delegates signing to the
//! node.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use blake2::Blake2bVar;
use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use hns_covenants::{
    Covenant, CovenantKind, MAX_COVENANT_ITEM_SIZE, MAX_COVENANT_ITEMS, MAX_NAME_STATE_SIZE,
    NameState,
};
use hns_marketplace_protocol::{
    DenuoPublicationAcceptanceExpectation, DenuoPublicationMessageKind,
    MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES, verify_denuo_publication_acceptance,
};
use hns_primitives::{Dollarydoos, Height, NameHash, TransactionHash as CanonicalTransactionHash};
use hns_transaction::{Address, Coin, MAX_TRANSACTION_RAW_SIZE, Outpoint, Output, Transaction};
use hns_wallet_types::{BaseUnits, TransactionHash};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ActiveNameOwnerCoinEvidence, ActiveNameOwnerCoinSourceBinding, BlockHashEvidence, ChainTip,
    ConfirmedWalletPage, ConfirmedWalletPageRequest, DenuoPublicationAcceptance,
    DenuoPublicationHandoff, DenuoTransportEvent, DenuoTransportEventPage,
    DenuoTransportMessageKind, DenuoTransportSnapshotPage, DenuoTransportSnapshotRecord,
    HistoryEntry, HnsBackend, HnsFeeRateSource, HnsInputCoinEvidence, HnsNameAction,
    HnsNameLifecycle, HnsNetwork, HnsOutpoint, HnsTransactionFeeQuote, HnsWalletError,
    IncomingTransferCandidate, IncomingTransferSourceBinding, IncomingTransfersPage,
    IncomingTransfersPageRequest, IndexedWalletCoin, MAX_DENUO_NAME_MARKET_ENVELOPE_BYTES,
    MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE, MAX_HISTORY_RESULTS, MAX_MEMPOOL_SCAN_RESULTS,
    MAX_OUTPOINT_SPEND_BATCH, MAX_RESTORE_SCRIPTS_PER_QUERY, MAX_SCAN_CURSOR_BYTES,
    MAX_SCAN_PAGE_RESULTS, MempoolSnapshotBinding, MempoolWalletPage, MempoolWalletPageRequest,
    NameActionContextEvidence, NameActionIneligibility, NameEvidence, NameProofResponse,
    OutpointSpendEntry, OutpointSpendEvidence, SnapshotBinding, SpendingTransactionEvidence,
    TransactionEvidence, TransactionInclusion, TransactionStatus, WalletAddressKey, WalletCoin,
};

const WALLET_RPC_API_VERSION: u16 = 1;
const WALLET_RPC_PATH: &str = "/api/v1/wallet";
const MAX_AUTHORIZATION_BYTES: usize = 4_096;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_ENVELOPE_OVERHEAD: usize = 16 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = MAX_RESPONSE_RESULT_BYTES + MAX_RESPONSE_ENVELOPE_OVERHEAD;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_FEE_TARGET_BLOCKS: u16 = 1_008;
const MAX_FEE_SAMPLES: usize = 4_096;
const MAX_MEMPOOL_RELATIONS: usize = 4_096;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const INCOMING_TRANSFER_PROJECTION_VERSION: u8 = 1;
const ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION: u8 = 1;
const DENUO_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-outbox-envelope-v1\0";

/// Trusted local configuration for the authenticated wallet RPC boundary.
///
/// There is intentionally no URL, hostname, proxy, redirect, or TLS option.
/// The endpoint is an explicit loopback socket address and the exact
/// Authorization value is zeroized on drop and redacted from `Debug`.
#[derive(Clone)]
pub struct HnsNodeRpcConfig {
    endpoint: SocketAddr,
    authorization: Zeroizing<String>,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl HnsNodeRpcConfig {
    pub fn new(
        endpoint: SocketAddr,
        authorization: impl Into<String>,
    ) -> Result<Self, HnsWalletError> {
        let config = Self {
            endpoint,
            authorization: Zeroizing::new(authorization.into()),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, HnsWalletError> {
        self.connect_timeout = connect_timeout;
        self.read_timeout = read_timeout;
        self.write_timeout = write_timeout;
        self.validate()?;
        Ok(self)
    }

    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    fn validate(&self) -> Result<(), HnsWalletError> {
        if !self.endpoint.ip().is_loopback()
            || self.endpoint.port() == 0
            || self.connect_timeout.is_zero()
            || self.read_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self.connect_timeout > MAX_TIMEOUT
            || self.read_timeout > MAX_TIMEOUT
            || self.write_timeout > MAX_TIMEOUT
        {
            return Err(configuration_error());
        }
        let authorization = self.authorization.as_bytes();
        if authorization.is_empty()
            || authorization.len() > MAX_AUTHORIZATION_BYTES
            || authorization[0] == b' '
            || authorization[authorization.len() - 1] == b' '
            || authorization
                .iter()
                .any(|byte| !(0x20..=0x7e).contains(byte))
        {
            return Err(configuration_error());
        }
        Ok(())
    }
}

impl fmt::Debug for HnsNodeRpcConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsNodeRpcConfig")
            .field("endpoint", &self.endpoint)
            .field("authorization", &"[REDACTED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .finish()
    }
}

/// Concrete synchronous hns-node-rs wallet RPC v1 backend.
pub struct HnsNodeRpcBackend {
    config: HnsNodeRpcConfig,
    next_request_id: AtomicU64,
}

impl HnsNodeRpcBackend {
    pub fn new(config: HnsNodeRpcConfig) -> Result<Self, HnsWalletError> {
        config.validate()?;
        Ok(Self {
            config,
            next_request_id: AtomicU64::new(1),
        })
    }

    pub const fn config(&self) -> &HnsNodeRpcConfig {
        &self.config
    }

    fn require_active_block_hash(
        &self,
        height: u64,
        block_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<(), HnsWalletError> {
        let evidence = self.get_block_hash(height, binding)?;
        if evidence.binding != binding
            || evidence.height != height
            || evidence.block_hash != Some(block_hash)
        {
            return Err(protocol_error());
        }
        Ok(())
    }

    fn rpc<T: DeserializeOwned>(&self, call: Value) -> Result<T, HnsWalletError> {
        let sequence = self
            .next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| protocol_error())?;
        let request_id = format!("hns-wallet-{sequence}");
        if request_id.len() > MAX_REQUEST_ID_BYTES {
            return Err(protocol_error());
        }
        let request = RpcRequest {
            api_version: WALLET_RPC_API_VERSION,
            request_id: &request_id,
            call: &call,
        };
        let mut body = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| protocol_error())?);
        if body.is_empty() || body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(protocol_error());
        }
        let response = self.post(body.as_slice())?;
        body.zeroize();

        if response.status == 401 {
            if !response.body.is_empty() {
                return Err(protocol_error());
            }
            return Err(backend_error("node wallet RPC authorization rejected"));
        }
        if response.status == 404 && response.content_type.as_deref() != Some("application/json") {
            return Err(backend_error("node wallet RPC route is unavailable"));
        }
        if response.status == 429 {
            if response.body != b"RPC concurrent request limit exceeded" {
                return Err(protocol_error());
            }
            return Err(backend_error("node wallet RPC is busy"));
        }
        if response.status == 504 {
            if response.body != b"RPC request execution timed out" {
                return Err(protocol_error());
            }
            return Err(backend_error("node wallet RPC timed out"));
        }
        if response.status == 413 && response.content_type.as_deref() != Some("application/json") {
            return Err(backend_error(
                "node wallet RPC request exceeded listener bounds",
            ));
        }
        if response.content_type.as_deref() != Some("application/json") {
            return Err(protocol_error());
        }
        if response.body.first() != Some(&b'{') || response.body.last() != Some(&b'}') {
            return Err(protocol_error());
        }

        let envelope: RpcResponseEnvelope =
            serde_json::from_slice(&response.body).map_err(|_| protocol_error())?;
        if envelope.api_version != WALLET_RPC_API_VERSION
            || envelope.request_id.as_deref() != Some(request_id.as_str())
            || envelope.result.0.is_some() == envelope.error.0.is_some()
        {
            return Err(protocol_error());
        }
        if response.status == 200 {
            if envelope.error.0.is_some() {
                return Err(protocol_error());
            }
            let result = envelope.result.0.ok_or_else(protocol_error)?;
            let encoded_result = serde_json::to_vec(&result).map_err(|_| protocol_error())?;
            if encoded_result.len() > MAX_RESPONSE_RESULT_BYTES {
                return Err(protocol_error());
            }
            let typed: TypedRpcResponseEnvelope<T> =
                serde_json::from_slice(&response.body).map_err(|_| protocol_error())?;
            if typed.api_version != WALLET_RPC_API_VERSION
                || typed.request_id.as_deref() != Some(request_id.as_str())
                || typed.result.0.is_some() == typed.error.0.is_some()
                || typed.error.0.is_some()
            {
                return Err(protocol_error());
            }
            return typed.result.0.ok_or_else(protocol_error);
        }
        if envelope.result.0.is_some() {
            return Err(protocol_error());
        }
        let error = envelope.error.0.ok_or_else(protocol_error)?;
        validate_rpc_error(response.status, &error)?;
        if error.code == "stale_snapshot" {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        if error.code == "chain_uninitialized" {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        if error.code == "name_state_missing" {
            return Err(HnsWalletError::NameNotOwned);
        }
        if error.code == "invalid_cursor" {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        if error.code == "fee_quote_input_unavailable" {
            return Err(HnsWalletError::FeeQuoteInputUnavailable);
        }
        if error.code == "invalid_fee_quote_transaction" {
            return Err(HnsWalletError::InvalidFeeQuoteTransaction);
        }
        Err(backend_error(error_code_message(&error.code)))
    }

    fn post(&self, body: &[u8]) -> Result<HttpResponse, HnsWalletError> {
        let mut stream =
            TcpStream::connect_timeout(&self.config.endpoint, self.config.connect_timeout)
                .map_err(|_| transport_error())?;
        stream.set_nodelay(true).map_err(|_| transport_error())?;

        let host = self.config.endpoint.to_string();
        let mut request = Zeroizing::new(Vec::with_capacity(
            body.len() + self.config.authorization.len() + host.len() + 256,
        ));
        request.extend_from_slice(b"POST ");
        request.extend_from_slice(WALLET_RPC_PATH.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(b"\r\nAuthorization: ");
        request.extend_from_slice(self.config.authorization.as_bytes());
        request.extend_from_slice(b"\r\nContent-Type: application/json\r\n");
        request.extend_from_slice(b"Accept: application/json\r\n");
        request.extend_from_slice(b"Accept-Encoding: identity\r\nContent-Length: ");
        request.extend_from_slice(body.len().to_string().as_bytes());
        request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        request.extend_from_slice(body);
        write_all_deadline(&mut stream, request.as_slice(), self.config.write_timeout)?;
        request.zeroize();
        read_http_response(&mut stream, self.config.read_timeout)
    }
}

impl fmt::Debug for HnsNodeRpcBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsNodeRpcBackend")
            .field("config", &self.config)
            .field("next_request_id", &"[NONSECRET COUNTER]")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest<'a> {
    api_version: u16,
    request_id: &'a str,
    call: &'a Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcResponseEnvelope {
    api_version: u16,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    result: Present<Value>,
    #[serde(default)]
    error: Present<RpcWireError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
struct TypedRpcResponseEnvelope<T> {
    api_version: u16,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    result: Present<T>,
    #[serde(default)]
    error: Present<RpcWireError>,
}

struct Present<T>(Option<T>);

impl<T> Default for Present<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Present<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcWireError {
    code: String,
    message: String,
    retryable: bool,
}

struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn write_all_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    timeout: Duration,
) -> Result<(), HnsWalletError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(configuration_error)?;
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(transport_error)?;
        if remaining.is_zero() {
            return Err(transport_error());
        }
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| transport_error())?;
        match stream.write(bytes) {
            Ok(0) => return Err(transport_error()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(transport_error()),
        }
    }
    stream.flush().map_err(|_| transport_error())
}

fn read_deadline(
    stream: &mut TcpStream,
    destination: &mut [u8],
    deadline: Instant,
) -> Result<usize, HnsWalletError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(transport_error)?;
        if remaining.is_zero() {
            return Err(transport_error());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| transport_error())?;
        match stream.read(destination) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Ok(read) => return Ok(read),
            Err(_) => return Err(transport_error()),
        }
    }
}

fn read_http_response(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<HttpResponse, HnsWalletError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(configuration_error)?;
    let mut received = Vec::with_capacity(4_096);
    let header_end = loop {
        if let Some(position) = find_header_end(&received) {
            break position;
        }
        if received.len() >= MAX_RESPONSE_HEADER_BYTES {
            return Err(protocol_error());
        }
        let mut chunk = [0_u8; 4_096];
        let read = read_deadline(stream, &mut chunk, deadline)?;
        if read == 0 {
            return Err(protocol_error());
        }
        if received.len().saturating_add(read) > MAX_RESPONSE_HEADER_BYTES + MAX_RESPONSE_BODY_BYTES
        {
            return Err(protocol_error());
        }
        received.extend_from_slice(&chunk[..read]);
    };
    if header_end > MAX_RESPONSE_HEADER_BYTES {
        return Err(protocol_error());
    }
    let parsed = parse_response_head(&received[..header_end])?;
    if parsed.content_length > MAX_RESPONSE_BODY_BYTES {
        return Err(protocol_error());
    }
    let body_start = header_end + 4;
    let total_length = body_start
        .checked_add(parsed.content_length)
        .ok_or_else(protocol_error)?;
    if received.len() > total_length {
        return Err(protocol_error());
    }
    received
        .try_reserve_exact(total_length.saturating_sub(received.len()))
        .map_err(|_| protocol_error())?;
    while received.len() < total_length {
        let mut chunk = [0_u8; 8_192];
        let remaining = total_length - received.len();
        let chunk_length = remaining.min(chunk.len());
        let read = read_deadline(stream, &mut chunk[..chunk_length], deadline)?;
        if read == 0 {
            return Err(protocol_error());
        }
        received.extend_from_slice(&chunk[..read]);
    }
    let mut trailing = [0_u8; 1];
    if read_deadline(stream, &mut trailing, deadline)? != 0 {
        return Err(protocol_error());
    }
    let body = received.split_off(body_start);
    if body.len() != parsed.content_length {
        return Err(protocol_error());
    }
    Ok(HttpResponse {
        status: parsed.status,
        content_type: parsed.content_type,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

struct ParsedResponseHead {
    status: u16,
    content_length: usize,
    content_type: Option<String>,
}

fn parse_response_head(bytes: &[u8]) -> Result<ParsedResponseHead, HnsWalletError> {
    let head = std::str::from_utf8(bytes).map_err(|_| protocol_error())?;
    if head.contains('\0') {
        return Err(protocol_error());
    }
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(protocol_error)?;
    let mut status_parts = status_line.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(protocol_error());
    }
    let status_text = status_parts.next().ok_or_else(protocol_error)?;
    let reason = status_parts.next().ok_or_else(protocol_error)?;
    if status_text.len() != 3
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
        || reason.is_empty()
        || reason.starts_with(' ')
        || reason.ends_with(' ')
        || reason.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
    {
        return Err(protocol_error());
    }
    let status = status_text.parse::<u16>().map_err(|_| protocol_error())?;
    if !(200..=599).contains(&status) || (300..=399).contains(&status) || status == 101 {
        return Err(protocol_error());
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() || line.starts_with(&[' ', '\t'][..]) {
            return Err(protocol_error());
        }
        let (name, raw_value) = line.split_once(':').ok_or_else(protocol_error)?;
        if name.is_empty()
            || !name.bytes().all(is_header_name_byte)
            || raw_value
                .bytes()
                .any(|byte| byte != b'\t' && !(0x20..=0x7e).contains(&byte))
        {
            return Err(protocol_error());
        }
        let name = name.to_ascii_lowercase();
        let value = raw_value.trim_matches(&[' ', '\t'][..]).to_owned();
        if headers.insert(name, value).is_some() {
            return Err(protocol_error());
        }
    }
    for forbidden in [
        "transfer-encoding",
        "upgrade",
        "content-encoding",
        "trailer",
        "content-range",
    ] {
        if headers.contains_key(forbidden) {
            return Err(protocol_error());
        }
    }
    if headers
        .get("connection")
        .is_some_and(|value| !value.eq_ignore_ascii_case("close"))
    {
        return Err(protocol_error());
    }
    let length = headers.get("content-length").ok_or_else(protocol_error)?;
    if length.is_empty()
        || !length.bytes().all(|byte| byte.is_ascii_digit())
        || (length.len() > 1 && length.starts_with('0'))
    {
        return Err(protocol_error());
    }
    let content_length = length.parse::<usize>().map_err(|_| protocol_error())?;
    let content_type = headers
        .get("content-type")
        .map(|value| value.to_ascii_lowercase());
    Ok(ParsedResponseHead {
        status,
        content_length,
        content_type,
    })
}

const fn is_header_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn configuration_error() -> HnsWalletError {
    backend_error("invalid node wallet RPC configuration")
}

fn transport_error() -> HnsWalletError {
    backend_error("node wallet RPC transport failed")
}

fn protocol_error() -> HnsWalletError {
    backend_error("node wallet RPC protocol violation")
}

fn backend_error(message: &'static str) -> HnsWalletError {
    HnsWalletError::Backend(message.to_owned())
}

fn error_code_message(code: &str) -> &'static str {
    match code {
        "authentication_required" => "node wallet RPC authentication is not configured",
        "wallet_profile_required" => "node wallet index profile is unavailable",
        "runtime_unavailable" => "node wallet runtime is unavailable",
        "invalid_request"
        | "invalid_request_id"
        | "unsupported_api_version"
        | "invalid_params"
        | "invalid_bounds" => "node wallet RPC rejected adapter parameters",
        "response_projection_limit" | "result_limit" => "node wallet RPC result limit reached",
        "internal_projection_failure" | "owner_output_missing" | "backend_inconsistent" => {
            "node wallet RPC returned inconsistent evidence"
        }
        "index_unavailable" => "node wallet index is unavailable",
        "backend_unavailable" => "node wallet backend is unavailable",
        "payload_pruned" => "node wallet transaction payload is pruned",
        "unknown_contract" | "invalid_contract" | "contract_registry_full" => {
            "node local tracked-contract profile is unavailable"
        }
        "name_has_no_owner" | "name_state_missing" => "node name evidence has no owner",
        "chain_uninitialized" => "node active chain is not initialized",
        "transaction_orphan" => "node rejected an orphan transaction",
        "transaction_rejected" => "node rejected the transaction",
        "denuo_name_market_rejected" => "node rejected the Denuo name-market publication or cursor",
        "invalid_fee_quote_transaction" => "node rejected the fee quote transaction",
        "fee_quote_input_unavailable" => "node could not resolve a fee quote input",
        _ => "node wallet RPC returned an unknown error",
    }
}

fn validate_rpc_error(status: u16, error: &RpcWireError) -> Result<(), HnsWalletError> {
    let expected = match error.code.as_str() {
        "authentication_required" => (503, false),
        "wallet_profile_required" => (503, false),
        "runtime_unavailable" => (503, true),
        "invalid_request" => (400, false),
        "invalid_request_id" => (400, false),
        "unsupported_api_version" => (400, false),
        "invalid_params" => (400, false),
        "invalid_cursor" => (400, false),
        "invalid_bounds" => (400, false),
        "response_projection_limit" => (413, true),
        "result_limit" => (413, true),
        "internal_projection_failure" => (500, true),
        "owner_output_missing" => (500, false),
        "backend_inconsistent" => (500, false),
        "index_unavailable" => (503, false),
        "backend_unavailable" => (503, true),
        "payload_pruned" => (410, false),
        "unknown_contract" => (404, false),
        "name_has_no_owner" => (404, false),
        "name_state_missing" => (404, false),
        "chain_uninitialized" => (409, true),
        "invalid_contract" => (409, false),
        "stale_snapshot" => (409, true),
        "transaction_orphan" => (409, true),
        "denuo_name_market_rejected" => (409, true),
        "fee_quote_input_unavailable" => (409, true),
        "contract_registry_full" => (507, false),
        "transaction_rejected" => (422, false),
        "invalid_fee_quote_transaction" => (422, false),
        _ => return Err(protocol_error()),
    };
    if status != expected.0 || error.retryable != expected.1 {
        return Err(protocol_error());
    }
    if error.code == "transaction_rejected" {
        if error.message.chars().count() > 256 {
            return Err(protocol_error());
        }
        return Ok(());
    }
    let message_is_valid = match error.code.as_str() {
        "authentication_required" => {
            error.message
                == "wallet RPC is unavailable unless the listener has configured authentication"
        }
        "wallet_profile_required" => {
            error.message == "wallet RPC requires the durable wallet index profile"
        }
        "runtime_unavailable" => {
            error.message == "wallet RPC requires the canonical native-sync runtime"
        }
        "invalid_request" => error.message == "wallet RPC request is malformed",
        "invalid_request_id" => error.message == "wallet RPC request_id exceeds 128 bytes",
        "unsupported_api_version" => error.message == "wallet RPC supports only api_version 1",
        "invalid_params" => matches!(
            error.message.as_str(),
            "outpoints must contain 1..=256 entries"
                | "raw transaction is not canonical"
                | "wallet RPC page limit must be between 1 and 256"
                | "wallet RPC mempool scan_limit must be between 1 and 1024"
                | "script_ids must contain 1..=10000 entries"
                | "identity must contain exactly 32 bytes"
                | "raw transaction hexadecimal length is invalid"
                | "opaque cursor hexadecimal length is invalid"
                | "identity must contain exactly 64 hexadecimal characters"
                | "raw transaction is not hexadecimal"
                | "opaque cursor is not hexadecimal"
                | "identity is not hexadecimal"
                | "opaque cursor is malformed"
        ),
        "invalid_cursor" => {
            error.message == "the opaque continuation does not belong to this query"
        }
        "invalid_bounds" => error.message == "the request violates a wallet RPC collection bound",
        "response_projection_limit" => {
            error.message
                == "wallet RPC result exceeds the 8 MiB wire budget; use a smaller page where applicable"
        }
        "result_limit" => {
            error.message == "the bounded mempool result contains too many relevant items"
        }
        "internal_projection_failure" => {
            error.message == "wallet RPC could not encode its bounded response"
        }
        "owner_output_missing" => {
            error.message == "the indexed owner transaction does not contain its selected output"
        }
        "backend_inconsistent" => {
            error.message == "wallet index evidence is inconsistent with the active chain"
        }
        "index_unavailable" => error.message == "the required optional wallet index is not enabled",
        "backend_unavailable" => {
            error.message == "the canonical wallet backend is temporarily unavailable"
        }
        "payload_pruned" => error.message == "the confirmed transaction payload has been pruned",
        "unknown_contract" => error.message == "the tracked-contract registration is unknown",
        "name_has_no_owner" => error.message == "the current name state has no owner",
        "name_state_missing" => {
            error.message == "the requested name has no current active-chain state"
        }
        "chain_uninitialized" => {
            error.message == "name-action context requires an initialized active chain"
        }
        "invalid_contract" => {
            error.message == "the tracked-contract registration is invalid or conflicts"
        }
        "stale_snapshot" => {
            error.message
                == "the bound lifecycle, chain, or mempool generation changed; restart this reconciliation"
        }
        "transaction_orphan" => {
            error.message == "the transaction has unresolved inputs and was not relayed as accepted"
        }
        "denuo_name_market_rejected" => {
            error.message == "the local Denuo V2 relay rejected the publication or event cursor"
        }
        "fee_quote_input_unavailable" => {
            error.message
                == "an input coin is unavailable in the bound active chain and mempool snapshot"
        }
        "contract_registry_full" => {
            error.message == "the append-only tracked-contract registry is full"
        }
        "invalid_fee_quote_transaction" => {
            error.message == "the raw transaction is not eligible for a Handshake fee quote"
        }
        _ => false,
    };
    if !message_is_valid {
        return Err(protocol_error());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireTip {
    hash: String,
    height: u32,
    tree_root: String,
    median_time_past: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum WireRequiredNullableTip {
    Initialized(WireTip),
    Uninitialized(()),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireChainSnapshot {
    chain_epoch: u64,
    tip: WireRequiredNullableTip,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireOutpoint {
    txid: String,
    index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireAddress {
    version: u8,
    hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireCovenant {
    kind: u8,
    items: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireOutput {
    value: u64,
    address: WireAddress,
    covenant: WireCovenant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireCoin {
    outpoint: WireOutpoint,
    value: u64,
    height: u32,
    coinbase: bool,
    address: WireAddress,
    covenant: WireCovenant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireInclusion {
    block_hash: String,
    height: u32,
    transaction_index: Option<u32>,
    confirmations: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBlockHashResponse {
    chain_epoch: u64,
    tip: Option<WireTip>,
    height: u32,
    hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfirmedHistory {
    script_index: usize,
    txid: String,
    block_hash: String,
    height: u32,
    transaction_position: u32,
    block_time: Option<u64>,
    received: bool,
    spent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfirmedUtxo {
    script_index: usize,
    coin: WireCoin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfirmedPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    history: Vec<WireConfirmedHistory>,
    utxos: Vec<WireConfirmedUtxo>,
    script_examinations: usize,
    continuation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIncomingTransferInclusion {
    block_hash: String,
    height: u32,
    transaction_index: u32,
    confirmations: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIncomingTransfer {
    script_index: usize,
    recipient: WireAddress,
    name_hash: String,
    start_height: u32,
    transfer_coin: WireCoin,
    inclusion: WireIncomingTransferInclusion,
    source_output_count: u32,
    source_binding: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIncomingTransfersPage {
    projection_version: u8,
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireIncomingTransfer>,
    script_examinations: usize,
    continuation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMempoolOutput {
    script_index: usize,
    outpoint: WireOutpoint,
    value: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMempoolSpend {
    script_index: usize,
    outpoint: WireOutpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMempoolActivity {
    txid: String,
    admitted_at: u64,
    received: Vec<WireMempoolOutput>,
    spent: Vec<WireMempoolSpend>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMempoolPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    instance_nonce: String,
    generation: u64,
    entries: Vec<WireMempoolActivity>,
    continuation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTransactionEvidence {
    chain_epoch: u64,
    mempool_instance_nonce: String,
    mempool_generation: u64,
    tip: Option<WireTip>,
    status: String,
    inclusion: Option<WireInclusion>,
    payload: String,
    transaction_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSpendingTransaction {
    txid: String,
    input_position: u32,
    block_hash: String,
    height: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutpointSpendingEntry {
    outpoint: WireOutpoint,
    spending: Option<WireSpendingTransaction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutpointSpendingEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireOutpointSpendingEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBroadcastResult {
    txid: String,
    newly_admitted: bool,
    attempted_peers: usize,
    queued_peers: usize,
    failed_peers: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoPropagation {
    attempted: usize,
    written: usize,
    failed: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoPublicationAcceptance {
    revision: u64,
    kind: String,
    content_hash: String,
    inserted: bool,
    accepted_at_unix: u64,
    acceptance_receipt_hex: String,
    propagation: WireDenuoPropagation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoEvent {
    revision: u64,
    received_at_unix: u64,
    kind: String,
    content_hash: String,
    envelope_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoEventPage {
    instance_nonce: String,
    cursor_reset: bool,
    oldest_revision: u64,
    head_revision: u64,
    events: Vec<WireDenuoEvent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoSnapshotRecord {
    kind: String,
    content_hash: String,
    envelope_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoSnapshotPage {
    instance_nonce: String,
    snapshot_revision: u64,
    next_offset: Option<usize>,
    records: Vec<WireDenuoSnapshotRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFeeEstimate {
    target_blocks: u32,
    atomic_units_per_kvb: u64,
    sampled_transactions: usize,
    source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTransactionFeeQuote {
    txid: String,
    chain_epoch: u64,
    tip: Option<WireTip>,
    mempool_instance_nonce: String,
    mempool_generation: u64,
    target_blocks: u32,
    rate_atomic_units_per_1000_policy_vbytes: u64,
    rate_sample_count: usize,
    rate_source: String,
    transaction_weight: usize,
    transaction_sigops: u32,
    sigop_adjusted_policy_vbytes: usize,
    minimum_policy_fee_atomic_units: u64,
    actual_fee_atomic_units: u64,
    meets_minimum_policy_fee: bool,
    minimum_policy_fee_shortfall_atomic_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WireNameState {
    name_hash: String,
    name_hex: String,
    height: u32,
    renewal: u32,
    owner: WireOutpoint,
    value: u64,
    highest: u64,
    data_hex: String,
    transfer: u32,
    revoked: u32,
    claimed: u32,
    renewals: u32,
    registered: bool,
    expired: bool,
    weak: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireActiveNameOwnerCoin {
    projection_version: u8,
    chain_epoch: u64,
    tip: WireTip,
    current_state_hex: String,
    current_state: WireNameState,
    owner_coin: WireCoin,
    inclusion: WireInclusion,
    source_binding: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameProof {
    root: String,
    name_hash: String,
    kind: String,
    proof_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameOwner {
    name_state: WireNameState,
    owner: WireOutpoint,
    transaction_hex: String,
    owner_output: WireOutput,
    inclusion: WireInclusion,
}

struct ValidatedWireNameOwner {
    outpoint: HnsOutpoint,
    raw_transaction: Vec<u8>,
    output: Output,
    inclusion: TransactionInclusion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    current_state_hex: Option<String>,
    proof_state_hex: Option<String>,
    current_state: Option<WireNameState>,
    proof_state: Option<WireNameState>,
    proof: WireNameProof,
    current_owner: Option<WireNameOwner>,
    proof_owner: Option<WireNameOwner>,
    data_semantics: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionChainIdentity {
    network: HnsNetwork,
    network_id: u8,
    genesis_hash: String,
    consensus_profile: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionMempool {
    instance_nonce: String,
    generation: u64,
    owner_spender_txid: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionTransfer {
    lockup_blocks: u32,
    current_transfer_height: Option<u32>,
    finalize_maturity_height: Option<u32>,
    finalize_eligible_at_candidate: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionRenewal {
    maturity_blocks: u32,
    period_blocks: u32,
    hsd_selected_height: u32,
    hsd_selected_hash: String,
    valid_at_candidate: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionEligibility {
    eligible: bool,
    reasons: Vec<NameActionIneligibility>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionContext {
    context_version: u8,
    action: HnsNameAction,
    chain_identity: WireNameActionChainIdentity,
    chain_epoch: u64,
    tip: WireTip,
    candidate_inclusion_height: u32,
    mempool: WireNameActionMempool,
    name_hash: String,
    current_state_hex: String,
    current_state: WireNameState,
    owner: WireNameOwner,
    lifecycle: HnsNameLifecycle,
    transfer: WireNameActionTransfer,
    renewal: WireNameActionRenewal,
    eligibility: WireNameActionEligibility,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionActiveOwnerCoin {
    projection_version: u8,
    owner_coin: WireCoin,
    inclusion: WireInclusion,
    source_binding: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNameActionContextV2 {
    context_version: u8,
    action: HnsNameAction,
    chain_identity: WireNameActionChainIdentity,
    chain_epoch: u64,
    tip: WireTip,
    candidate_inclusion_height: u32,
    mempool: WireNameActionMempool,
    name_hash: String,
    current_state_hex: String,
    current_state: WireNameState,
    active_owner: WireNameActionActiveOwnerCoin,
    lifecycle: HnsNameLifecycle,
    transfer: WireNameActionTransfer,
    renewal: WireNameActionRenewal,
    eligibility: WireNameActionEligibility,
}

struct ScriptQuery {
    encoded_ids: Vec<String>,
    node_to_request: Vec<u32>,
}

fn script_query(scripts: &[WalletAddressKey]) -> Result<ScriptQuery, HnsWalletError> {
    if scripts.is_empty()
        || scripts.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || !scripts.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(protocol_error());
    }
    let mut indexed = Vec::new();
    indexed
        .try_reserve_exact(scripts.len())
        .map_err(|_| protocol_error())?;
    for (request_index, script) in scripts.iter().enumerate() {
        Address::new(script.version, script.hash.clone()).map_err(|_| protocol_error())?;
        let hash_length = u8::try_from(script.hash.len()).map_err(|_| protocol_error())?;
        let mut canonical = Vec::with_capacity(script.hash.len() + 2);
        canonical.push(script.version);
        canonical.push(hash_length);
        canonical.extend_from_slice(&script.hash);
        let mut hasher = Blake2bVar::new(32).map_err(|_| protocol_error())?;
        BlakeUpdate::update(&mut hasher, &canonical);
        let mut script_id = [0_u8; 32];
        hasher
            .finalize_variable(&mut script_id)
            .map_err(|_| protocol_error())?;
        indexed.push((
            script_id,
            u32::try_from(request_index).map_err(|_| protocol_error())?,
        ));
    }
    indexed.sort_by_key(|entry| entry.0);
    if indexed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(protocol_error());
    }
    Ok(ScriptQuery {
        encoded_ids: indexed
            .iter()
            .map(|(script_id, _)| hex::encode(script_id))
            .collect(),
        node_to_request: indexed
            .into_iter()
            .map(|(_, request_index)| request_index)
            .collect(),
    })
}

fn decode_lower_hex(encoded: &str, maximum: usize) -> Result<Vec<u8>, HnsWalletError> {
    if !encoded.len().is_multiple_of(2)
        || encoded.len() > maximum.saturating_mul(2)
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(protocol_error());
    }
    hex::decode(encoded).map_err(|_| protocol_error())
}

fn decode_hex_32(encoded: &str) -> Result<[u8; 32], HnsWalletError> {
    decode_lower_hex(encoded, 32)?
        .try_into()
        .map_err(|_| protocol_error())
}

fn decode_cursor(encoded: Option<String>) -> Result<Option<Vec<u8>>, HnsWalletError> {
    encoded
        .map(|cursor| {
            let decoded = decode_lower_hex(&cursor, MAX_SCAN_CURSOR_BYTES)?;
            if decoded.is_empty() {
                return Err(protocol_error());
            }
            Ok(decoded)
        })
        .transpose()
}

fn encode_cursor(cursor: Option<&[u8]>) -> Result<Option<String>, HnsWalletError> {
    cursor
        .map(|cursor| {
            if cursor.is_empty() || cursor.len() > MAX_SCAN_CURSOR_BYTES {
                return Err(protocol_error());
            }
            Ok(hex::encode(cursor))
        })
        .transpose()
}

fn chain_tip(wire: WireTip) -> Result<ChainTip, HnsWalletError> {
    if wire.median_time_past == 0 {
        return Err(protocol_error());
    }
    Ok(ChainTip {
        height: u64::from(wire.height),
        block_hash: decode_hex_32(&wire.hash)?,
        tree_root: decode_hex_32(&wire.tree_root)?,
        median_time_past: wire.median_time_past,
    })
}

fn chain_snapshot(wire: WireChainSnapshot) -> Result<SnapshotBinding, HnsWalletError> {
    let tip = match wire.tip {
        WireRequiredNullableTip::Initialized(tip) => tip,
        WireRequiredNullableTip::Uninitialized(()) => {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
    };
    Ok(SnapshotBinding {
        tip: chain_tip(tip)?,
        chain_epoch: wire.chain_epoch,
    })
}

fn snapshot_binding(
    chain_epoch: u64,
    tip: Option<WireTip>,
) -> Result<SnapshotBinding, HnsWalletError> {
    let tip = tip.ok_or_else(protocol_error)?;
    Ok(SnapshotBinding {
        tip: chain_tip(tip)?,
        chain_epoch,
    })
}

fn require_binding(
    chain_epoch: u64,
    tip: Option<WireTip>,
    expected: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    if snapshot_binding(chain_epoch, tip)? != expected {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_incoming_page_metadata(
    projection_version: u8,
    chain_epoch: u64,
    tip: Option<WireTip>,
    entry_count: usize,
    script_examinations: usize,
    script_count: usize,
    limit: u32,
    binding: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    require_binding(chain_epoch, tip, binding)?;
    if projection_version != INCOMING_TRANSFER_PROJECTION_VERSION
        || entry_count > limit as usize
        || !(1..=MAX_SCAN_PAGE_RESULTS).contains(&script_examinations)
        || script_examinations > script_count
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn incoming_transfer_source_binding(
    source: &str,
) -> Result<IncomingTransferSourceBinding, HnsWalletError> {
    match source {
        "retained_body_verified" => Ok(IncomingTransferSourceBinding::RetainedBodyVerified),
        "pruned_trusted_node_projection" => {
            Ok(IncomingTransferSourceBinding::PrunedTrustedNodeProjection)
        }
        _ => Err(protocol_error()),
    }
}

fn validate_active_name_owner_metadata(
    projection_version: u8,
    chain_epoch: u64,
    tip: WireTip,
    source_binding: &str,
    binding: SnapshotBinding,
) -> Result<(), HnsWalletError> {
    require_binding(chain_epoch, Some(tip), binding)?;
    if projection_version != ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION
        || source_binding != "trusted_node_active_utxo_projection"
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn hns_outpoint(wire: &WireOutpoint) -> Result<HnsOutpoint, HnsWalletError> {
    Ok(HnsOutpoint {
        transaction: TransactionHash::new(decode_hex_32(&wire.txid)?),
        output_index: wire.index,
    })
}

fn wire_address(wire: &WireAddress) -> Result<Address, HnsWalletError> {
    let hash = decode_lower_hex(&wire.hash, 40)?;
    Address::new(wire.version, hash).map_err(|_| protocol_error())
}

fn wallet_address(wire: &WireAddress) -> Result<WalletAddressKey, HnsWalletError> {
    let address = wire_address(wire)?;
    Ok(WalletAddressKey {
        version: address.version,
        hash: address.hash,
    })
}

fn wire_covenant(wire: &WireCovenant) -> Result<Covenant, HnsWalletError> {
    if wire.items.len() > MAX_COVENANT_ITEMS {
        return Err(protocol_error());
    }
    let mut items = Vec::new();
    items
        .try_reserve_exact(wire.items.len())
        .map_err(|_| protocol_error())?;
    for encoded in &wire.items {
        items.push(decode_lower_hex(encoded, MAX_COVENANT_ITEM_SIZE)?);
    }
    let covenant = Covenant {
        kind: CovenantKind::from_u8(wire.kind),
        items,
    };
    covenant.encode().map_err(|_| protocol_error())?;
    Ok(covenant)
}

fn wire_output(wire: &WireOutput) -> Result<Output, HnsWalletError> {
    let output = Output {
        value: Dollarydoos::new(wire.value),
        address: wire_address(&wire.address)?,
        covenant: wire_covenant(&wire.covenant)?,
    };
    output.encode().map_err(|_| protocol_error())?;
    Ok(output)
}

fn wire_coin(wire: &WireCoin) -> Result<Coin, HnsWalletError> {
    let outpoint = hns_outpoint(&wire.outpoint)?;
    let outpoint = Outpoint {
        transaction_hash: CanonicalTransactionHash::new(outpoint.transaction.into_bytes()),
        index: outpoint.output_index,
    };
    let coin = Coin {
        outpoint,
        value: Dollarydoos::new(wire.value),
        height: Height::new(wire.height),
        coinbase: wire.coinbase,
        address: wire_address(&wire.address)?,
        covenant: wire_covenant(&wire.covenant)?,
    };
    if coin.outpoint.is_null() {
        return Err(protocol_error());
    }
    Ok(coin)
}

fn canonical_transaction(
    encoded: &str,
    expected: Option<TransactionHash>,
) -> Result<(Vec<u8>, Transaction), HnsWalletError> {
    let raw = decode_lower_hex(encoded, MAX_TRANSACTION_RAW_SIZE.min(1_000_000))?;
    let transaction = Transaction::decode(&raw).map_err(|_| protocol_error())?;
    if transaction.encode().map_err(|_| protocol_error())? != raw {
        return Err(protocol_error());
    }
    if let Some(expected) = expected {
        let actual = transaction
            .transaction_hash()
            .map_err(|_| protocol_error())?;
        if actual.as_bytes() != expected.as_bytes() {
            return Err(protocol_error());
        }
    }
    Ok((raw, transaction))
}

fn inclusion(wire: WireInclusion, tip: ChainTip) -> Result<TransactionInclusion, HnsWalletError> {
    let height = u64::from(wire.height);
    if height > tip.height || u64::from(wire.confirmations) != tip.height - height + 1 {
        return Err(protocol_error());
    }
    Ok(TransactionInclusion {
        block_hash: decode_hex_32(&wire.block_hash)?,
        height,
        transaction_index: wire.transaction_index,
    })
}

fn expected_mempool_json(binding: MempoolSnapshotBinding) -> Value {
    serde_json::json!({
        "instance_nonce": hex::encode(binding.instance_nonce),
        "generation": binding.generation,
    })
}

fn denuo_message_kind(kind: DenuoTransportMessageKind) -> DenuoPublicationMessageKind {
    match kind {
        DenuoTransportMessageKind::Offer => DenuoPublicationMessageKind::Offer,
        DenuoTransportMessageKind::Cancellation => DenuoPublicationMessageKind::Cancellation,
    }
}

fn denuo_kind_name(kind: DenuoTransportMessageKind) -> &'static str {
    match kind {
        DenuoTransportMessageKind::Offer => "offer",
        DenuoTransportMessageKind::Cancellation => "cancellation",
    }
}

fn decode_denuo_kind(kind: &str) -> Result<DenuoTransportMessageKind, HnsWalletError> {
    match kind {
        "offer" => Ok(DenuoTransportMessageKind::Offer),
        "cancellation" => Ok(DenuoTransportMessageKind::Cancellation),
        _ => Err(protocol_error()),
    }
}

fn denuo_expectation(handoff: DenuoPublicationHandoff) -> DenuoPublicationAcceptanceExpectation {
    DenuoPublicationAcceptanceExpectation {
        network_magic: handoff.network_magic,
        network_genesis: handoff.network_genesis,
        attempt_id: handoff.attempt_id,
        record_sequence: handoff.record_sequence,
        prepared_at_unix: handoff.prepared_at_unix,
        envelope_id: handoff.envelope_id,
        envelope_digest: handoff.envelope_digest,
        content_id: handoff.content_id,
        message_kind: denuo_message_kind(handoff.message_kind),
        request_id: handoff.request_id,
    }
}

impl HnsBackend for HnsNodeRpcBackend {
    fn get_chain_snapshot(&self) -> Result<SnapshotBinding, HnsWalletError> {
        let response: WireChainSnapshot = self.rpc(serde_json::json!({
            "method": "chain_snapshot",
        }))?;
        chain_snapshot(response)
    }

    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError> {
        let response: Option<WireTip> = self.rpc(serde_json::json!({
            "method": "chain_tip",
        }))?;
        chain_tip(response.ok_or_else(protocol_error)?)
    }

    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError> {
        let height = u32::try_from(height).map_err(|_| protocol_error())?;
        let response: WireBlockHashResponse = self.rpc(serde_json::json!({
            "method": "block_hash",
            "params": {
                "height": height,
                "expected_chain_epoch": binding.chain_epoch,
            },
        }))?;
        require_binding(response.chain_epoch, response.tip, binding)?;
        if response.height != height {
            return Err(protocol_error());
        }
        Ok(BlockHashEvidence {
            binding,
            height: u64::from(response.height),
            block_hash: response.hash.map(|hash| decode_hex_32(&hash)).transpose()?,
        })
    }

    fn get_confirmed_wallet_page(
        &self,
        request: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError> {
        if request.limit == 0 || request.limit as usize > MAX_SCAN_PAGE_RESULTS {
            return Err(protocol_error());
        }
        let query = script_query(request.scripts)?;
        let response: WireConfirmedPage = self.rpc(serde_json::json!({
            "method": "confirmed_scripts_page",
            "params": {
                "script_ids": query.encoded_ids,
                "cursor": encode_cursor(request.cursor)?,
                "limit": request.limit,
            },
        }))?;
        let binding = snapshot_binding(response.chain_epoch, response.tip)?;
        if binding.tip != request.expected_tip
            || request
                .expected_epoch
                .is_some_and(|epoch| epoch != binding.chain_epoch)
            || !(1..=MAX_SCAN_PAGE_RESULTS).contains(&response.script_examinations)
            || response.history.len() > request.limit as usize
            || response.utxos.len() > request.limit as usize
            || (!response.history.is_empty() && !response.utxos.is_empty())
            || (!response.history.is_empty() && response.continuation.is_none())
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let next_cursor = decode_cursor(response.continuation)?;
        let mut history_keys = BTreeSet::new();
        let mut history = Vec::new();
        history
            .try_reserve_exact(response.history.len())
            .map_err(|_| protocol_error())?;
        for row in response.history {
            let request_index = *query
                .node_to_request
                .get(row.script_index)
                .ok_or_else(protocol_error)?;
            let txid = TransactionHash::new(decode_hex_32(&row.txid)?);
            let block_hash = decode_hex_32(&row.block_hash)?;
            if !row.received && !row.spent
                || u64::from(row.height) > binding.tip.height
                || !history_keys.insert((txid, request_index))
            {
                return Err(protocol_error());
            }
            history.push(HistoryEntry {
                txid,
                height: Some(u64::from(row.height)),
                block_hash: Some(block_hash),
                transaction_position: Some(row.transaction_position),
                spent: row.spent,
                first_seen_unix: row.block_time,
                script_index: request_index,
            });
        }
        let mut outpoints = BTreeSet::new();
        let mut utxos = Vec::new();
        utxos
            .try_reserve_exact(response.utxos.len())
            .map_err(|_| protocol_error())?;
        for row in response.utxos {
            let request_index = *query
                .node_to_request
                .get(row.script_index)
                .ok_or_else(protocol_error)?;
            let expected_address = request
                .scripts
                .get(request_index as usize)
                .ok_or_else(protocol_error)?;
            let output_address = wallet_address(&row.coin.address)?;
            let covenant = wire_covenant(&row.coin.covenant)?;
            let covenant_bytes = covenant.encode().map_err(|_| protocol_error())?;
            let outpoint = hns_outpoint(&row.coin.outpoint)?;
            let height = u64::from(row.coin.height);
            if &output_address != expected_address
                || height > binding.tip.height
                || !outpoints.insert(outpoint)
            {
                return Err(protocol_error());
            }
            let confirmation_count =
                u32::try_from(binding.tip.height - height + 1).map_err(|_| protocol_error())?;
            utxos.push(IndexedWalletCoin {
                coin: WalletCoin {
                    outpoint,
                    value: BaseUnits::new(u128::from(row.coin.value)),
                    confirmation_count,
                    confirmed_height: Some(row.coin.height),
                    coinbase: row.coin.coinbase,
                    covenant: covenant_bytes,
                    name_locked: !matches!(covenant.kind, CovenantKind::None),
                },
                script_index: request_index,
                output_address,
            });
        }
        if history.len().saturating_add(utxos.len()) > request.limit as usize {
            return Err(protocol_error());
        }
        Ok(ConfirmedWalletPage {
            binding,
            next_cursor,
            history,
            utxos,
        })
    }

    fn get_incoming_transfers_page(
        &self,
        request: IncomingTransfersPageRequest<'_>,
    ) -> Result<IncomingTransfersPage, HnsWalletError> {
        if request.limit == 0 || request.limit as usize > MAX_SCAN_PAGE_RESULTS {
            return Err(protocol_error());
        }
        let query = script_query(request.scripts)?;
        let response: WireIncomingTransfersPage = self.rpc(serde_json::json!({
            "method": "incoming_transfers_page",
            "params": {
                "script_ids": query.encoded_ids,
                "expected_chain_epoch": request.binding.chain_epoch,
                "cursor": encode_cursor(request.cursor)?,
                "limit": request.limit,
            },
        }))?;
        validate_incoming_page_metadata(
            response.projection_version,
            response.chain_epoch,
            response.tip,
            response.entries.len(),
            response.script_examinations,
            request.scripts.len(),
            request.limit,
            request.binding,
        )?;

        let next_cursor = decode_cursor(response.continuation)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(response.entries.len())
            .map_err(|_| protocol_error())?;
        let mut page_script_index = None;
        let mut previous_order = None;
        let mut unique_outpoints = BTreeSet::new();
        for row in response.entries {
            let request_index = *query
                .node_to_request
                .get(row.script_index)
                .ok_or_else(protocol_error)?;
            let expected_recipient = request
                .scripts
                .get(request_index as usize)
                .ok_or_else(protocol_error)?;
            let recipient = wallet_address(&row.recipient)?;
            let name_hash = decode_hex_32(&row.name_hash)?;
            let transfer_coin = wire_coin(&row.transfer_coin)?;
            let transaction_index = row.inclusion.transaction_index;
            let inclusion = inclusion(
                WireInclusion {
                    block_hash: row.inclusion.block_hash,
                    height: row.inclusion.height,
                    transaction_index: Some(transaction_index),
                    confirmations: row.inclusion.confirmations,
                },
                request.binding.tip,
            )?;
            let transfer = hns_covenants::TransferCovenant::try_from(&transfer_coin.covenant)
                .map_err(|_| protocol_error())?;
            let outpoint = HnsOutpoint {
                transaction: TransactionHash::new(
                    transfer_coin.outpoint.transaction_hash.into_bytes(),
                ),
                output_index: transfer_coin.outpoint.index,
            };
            let order = (
                inclusion.height,
                transaction_index,
                outpoint.transaction,
                outpoint.output_index,
            );
            if &recipient != expected_recipient
                || transfer.name_hash.into_bytes() != name_hash
                || transfer.start_height.get() != row.start_height
                || transfer.recipient_version != recipient.version
                || transfer.recipient_hash != recipient.hash
                || transfer_coin.coinbase
                || u64::from(transfer_coin.height.get()) != inclusion.height
                || row.source_output_count == 0
                || transfer_coin.outpoint.index >= row.source_output_count
                || !unique_outpoints.insert(outpoint)
                || previous_order.is_some_and(|previous| previous >= order)
                || page_script_index.is_some_and(|index| index != request_index)
            {
                return Err(protocol_error());
            }
            previous_order = Some(order);
            page_script_index = Some(request_index);
            let source_binding = incoming_transfer_source_binding(&row.source_binding)?;
            entries.push(IncomingTransferCandidate {
                script_index: request_index,
                recipient,
                name_hash,
                start_height: row.start_height,
                transfer_coin,
                inclusion,
                source_output_count: row.source_output_count,
                source_binding,
            });
        }
        Ok(IncomingTransfersPage {
            projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
            binding: request.binding,
            entries,
            script_examinations: response.script_examinations,
            next_cursor,
        })
    }

    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError> {
        if request.limit == 0 || request.limit as usize > MAX_MEMPOOL_SCAN_RESULTS {
            return Err(protocol_error());
        }
        let query = script_query(request.scripts)?;
        let response: WireMempoolPage = self.rpc(serde_json::json!({
            "method": "mempool_scripts_page",
            "params": {
                "script_ids": query.encoded_ids,
                "expected_chain_epoch": request.binding.chain_epoch,
                "cursor": encode_cursor(request.cursor)?,
                "scan_limit": request.limit,
            },
        }))?;
        require_binding(response.chain_epoch, response.tip, request.binding)?;
        if response.entries.len() > request.limit as usize {
            return Err(protocol_error());
        }
        let mempool = MempoolSnapshotBinding {
            instance_nonce: decode_hex_32(&response.instance_nonce)?,
            generation: response.generation,
        };
        if mempool.instance_nonce == [0; 32]
            || request
                .expected_mempool
                .is_some_and(|expected| expected != mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let next_cursor = decode_cursor(response.continuation)?;
        let mut previous_txid = None;
        let mut relation_count = 0_usize;
        let mut histories: BTreeMap<(TransactionHash, u32), HistoryEntry> = BTreeMap::new();
        for activity in response.entries {
            let txid = TransactionHash::new(decode_hex_32(&activity.txid)?);
            if previous_txid.is_some_and(|previous| previous >= txid)
                || activity.received.is_empty() && activity.spent.is_empty()
            {
                return Err(protocol_error());
            }
            previous_txid = Some(txid);
            relation_count = relation_count
                .checked_add(activity.received.len())
                .and_then(|count| count.checked_add(activity.spent.len()))
                .ok_or_else(protocol_error)?;
            if relation_count > MAX_MEMPOOL_RELATIONS {
                return Err(protocol_error());
            }
            let mut received_relations = BTreeSet::new();
            for received in activity.received {
                let request_index = *query
                    .node_to_request
                    .get(received.script_index)
                    .ok_or_else(protocol_error)?;
                let outpoint = hns_outpoint(&received.outpoint)?;
                if outpoint.transaction != txid
                    || !received_relations.insert((request_index, outpoint))
                {
                    return Err(protocol_error());
                }
                let entry = histories
                    .entry((txid, request_index))
                    .or_insert(HistoryEntry {
                        txid,
                        height: None,
                        block_hash: None,
                        transaction_position: None,
                        spent: false,
                        first_seen_unix: Some(activity.admitted_at),
                        script_index: request_index,
                    });
                if entry.first_seen_unix != Some(activity.admitted_at) {
                    return Err(protocol_error());
                }
                let _ = received.value;
            }
            let mut spent_relations = BTreeSet::new();
            for spent in activity.spent {
                let request_index = *query
                    .node_to_request
                    .get(spent.script_index)
                    .ok_or_else(protocol_error)?;
                let outpoint = hns_outpoint(&spent.outpoint)?;
                if !spent_relations.insert((request_index, outpoint)) {
                    return Err(protocol_error());
                }
                let entry = histories
                    .entry((txid, request_index))
                    .or_insert(HistoryEntry {
                        txid,
                        height: None,
                        block_hash: None,
                        transaction_position: None,
                        spent: true,
                        first_seen_unix: Some(activity.admitted_at),
                        script_index: request_index,
                    });
                if entry.first_seen_unix != Some(activity.admitted_at) {
                    return Err(protocol_error());
                }
                entry.spent = true;
            }
        }
        if histories.len() > MAX_HISTORY_RESULTS {
            return Err(protocol_error());
        }
        Ok(MempoolWalletPage {
            binding: request.binding,
            mempool,
            next_cursor,
            history: histories.into_values().collect(),
        })
    }

    fn get_transaction_evidence(
        &self,
        txid: TransactionHash,
        binding: SnapshotBinding,
        expected_mempool: Option<MempoolSnapshotBinding>,
    ) -> Result<TransactionEvidence, HnsWalletError> {
        let response: WireTransactionEvidence = self.rpc(serde_json::json!({
            "method": "transaction_evidence",
            "params": {
                "txid": hex::encode(txid.as_bytes()),
                "expected_chain_epoch": binding.chain_epoch,
                "expected_mempool": expected_mempool.map(expected_mempool_json),
            },
        }))?;
        require_binding(response.chain_epoch, response.tip, binding)?;
        let mempool = MempoolSnapshotBinding {
            instance_nonce: decode_hex_32(&response.mempool_instance_nonce)?,
            generation: response.mempool_generation,
        };
        if mempool.instance_nonce == [0; 32]
            || expected_mempool.is_some_and(|expected| expected != mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let inclusion = response
            .inclusion
            .map(|wire| inclusion(wire, binding.tip))
            .transpose()?;
        if let Some(confirmed) = inclusion {
            self.require_active_block_hash(confirmed.height, confirmed.block_hash, binding)?;
        }
        let raw = response
            .transaction_hex
            .as_deref()
            .map(|encoded| canonical_transaction(encoded, Some(txid)).map(|value| value.0))
            .transpose()?;
        let status = match response.status.as_str() {
            "mempool" if response.payload == "retained" && inclusion.is_none() && raw.is_some() => {
                TransactionStatus {
                    in_mempool: true,
                    confirmation_count: 0,
                    conflicted: false,
                }
            }
            "unknown" if response.payload == "absent" && inclusion.is_none() && raw.is_none() => {
                TransactionStatus {
                    in_mempool: false,
                    confirmation_count: 0,
                    conflicted: false,
                }
            }
            "confirmed" => {
                let confirmed = inclusion.ok_or_else(protocol_error)?;
                let retained = response.payload == "retained"
                    && raw.is_some()
                    && confirmed.transaction_index.is_some();
                let pruned = response.payload == "pruned"
                    && raw.is_none()
                    && confirmed.transaction_index.is_none();
                if !retained && !pruned {
                    return Err(protocol_error());
                }
                TransactionStatus {
                    in_mempool: false,
                    confirmation_count: u32::try_from(binding.tip.height - confirmed.height + 1)
                        .map_err(|_| protocol_error())?,
                    conflicted: false,
                }
            }
            _ => return Err(protocol_error()),
        };
        Ok(TransactionEvidence {
            binding,
            mempool,
            raw,
            status,
            inclusion,
        })
    }

    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError> {
        if outpoints.is_empty() {
            return Ok(OutpointSpendEvidence {
                binding,
                entries: Vec::new(),
            });
        }
        if outpoints.len() > MAX_OUTPOINT_SPEND_BATCH {
            return Err(protocol_error());
        }
        let params: Vec<Value> = outpoints
            .iter()
            .map(|outpoint| {
                serde_json::json!({
                    "txid": hex::encode(outpoint.transaction.as_bytes()),
                    "output_index": outpoint.output_index,
                })
            })
            .collect();
        let response: WireOutpointSpendingEvidence = self.rpc(serde_json::json!({
            "method": "spending_transactions",
            "params": {
                "outpoints": params,
                "expected_chain_epoch": binding.chain_epoch,
            },
        }))?;
        require_binding(response.chain_epoch, response.tip, binding)?;
        if response.entries.len() != outpoints.len() {
            return Err(protocol_error());
        }
        let mut entries = Vec::new();
        let mut active_blocks = BTreeMap::new();
        entries
            .try_reserve_exact(response.entries.len())
            .map_err(|_| protocol_error())?;
        for (wire, expected) in response.entries.into_iter().zip(outpoints) {
            let echoed = hns_outpoint(&wire.outpoint)?;
            if echoed != *expected {
                return Err(protocol_error());
            }
            let spending = wire
                .spending
                .map(|spending| {
                    let height = u64::from(spending.height);
                    if height > binding.tip.height {
                        return Err(protocol_error());
                    }
                    let block_hash = decode_hex_32(&spending.block_hash)?;
                    if active_blocks
                        .insert(height, block_hash)
                        .is_some_and(|previous| previous != block_hash)
                    {
                        return Err(protocol_error());
                    }
                    Ok(SpendingTransactionEvidence {
                        transaction: TransactionHash::new(decode_hex_32(&spending.txid)?),
                        input_position: spending.input_position,
                        block_hash,
                        height,
                    })
                })
                .transpose()?;
            entries.push(OutpointSpendEntry {
                outpoint: echoed,
                spending,
            });
        }
        for (height, block_hash) in active_blocks {
            self.require_active_block_hash(height, block_hash, binding)?;
        }
        Ok(OutpointSpendEvidence { binding, entries })
    }

    fn broadcast_transaction(&self, raw: &[u8]) -> Result<TransactionHash, HnsWalletError> {
        if raw.is_empty() || raw.len() > 1_000_000 {
            return Err(protocol_error());
        }
        let transaction = Transaction::decode(raw).map_err(|_| protocol_error())?;
        if transaction.encode().map_err(|_| protocol_error())? != raw {
            return Err(protocol_error());
        }
        let expected = transaction
            .transaction_hash()
            .map_err(|_| protocol_error())?;
        let expected = TransactionHash::new(expected.into_bytes());
        let response: WireBroadcastResult = self.rpc(serde_json::json!({
            "method": "broadcast_transaction",
            "params": {
                "transaction_hex": hex::encode(raw),
            },
        }))?;
        let returned = TransactionHash::new(decode_hex_32(&response.txid)?);
        if returned != expected
            || response.queued_peers.checked_add(response.failed_peers)
                != Some(response.attempted_peers)
        {
            return Err(protocol_error());
        }
        let _ = response.newly_admitted;
        Ok(returned)
    }

    fn publish_denuo_name_market(
        &self,
        envelope_bytes: &[u8],
        handoff: DenuoPublicationHandoff,
    ) -> Result<DenuoPublicationAcceptance, HnsWalletError> {
        if envelope_bytes.is_empty()
            || envelope_bytes.len() > MAX_DENUO_NAME_MARKET_ENVELOPE_BYTES
            || handoff.network_genesis == [0; 32]
            || handoff.attempt_id == [0; 32]
            || handoff.record_sequence == 0
            || handoff.envelope_id == [0; 32]
            || handoff.envelope_digest == [0; 32]
            || handoff.content_id == [0; 32]
            || handoff.request_id == 0
        {
            return Err(protocol_error());
        }
        let mut envelope_id = Sha256::new();
        Digest::update(&mut envelope_id, DENUO_OUTBOX_ENVELOPE_ID_DOMAIN);
        Digest::update(&mut envelope_id, envelope_bytes);
        if <[u8; 32]>::from(envelope_id.finalize()) != handoff.envelope_id
            || <[u8; 32]>::from(Sha256::digest(envelope_bytes)) != handoff.envelope_digest
        {
            return Err(protocol_error());
        }
        let response: WireDenuoPublicationAcceptance = self.rpc(serde_json::json!({
            "method": "denuo_name_market_publish",
            "params": {
                "envelope_hex": hex::encode(envelope_bytes),
                "handoff": {
                    "network_magic": handoff.network_magic,
                    "network_genesis": hex::encode(handoff.network_genesis),
                    "attempt_id": hex::encode(handoff.attempt_id),
                    "record_sequence": handoff.record_sequence,
                    "prepared_at_unix": handoff.prepared_at_unix,
                    "envelope_id": hex::encode(handoff.envelope_id),
                    "envelope_digest": hex::encode(handoff.envelope_digest),
                    "content_id": hex::encode(handoff.content_id),
                    "message_kind": denuo_kind_name(handoff.message_kind),
                    "request_id": handoff.request_id,
                }
            },
        }))?;
        let kind = decode_denuo_kind(&response.kind)?;
        let content_id = decode_hex_32(&response.content_hash)?;
        let receipt_bytes = decode_lower_hex(
            &response.acceptance_receipt_hex,
            MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES,
        )?;
        let verified =
            verify_denuo_publication_acceptance(&receipt_bytes).map_err(|_| protocol_error())?;
        if response.revision == 0
            || kind != handoff.message_kind
            || content_id != handoff.content_id
            || response.accepted_at_unix < handoff.prepared_at_unix
            || response
                .propagation
                .written
                .checked_add(response.propagation.failed)
                != Some(response.propagation.attempted)
            || verified.expectation() != denuo_expectation(handoff)
            || verified.issued_at_unix() != response.accepted_at_unix
        {
            return Err(protocol_error());
        }
        Ok(DenuoPublicationAcceptance {
            relay_revision: response.revision,
            kind,
            content_id,
            inserted: response.inserted,
            accepted_at_unix: response.accepted_at_unix,
            receipt_bytes,
            propagation_attempted: response.propagation.attempted,
            propagation_written: response.propagation.written,
            propagation_failed: response.propagation.failed,
        })
    }

    fn get_denuo_name_market_events(
        &self,
        expected_instance_nonce: Option<[u8; 32]>,
        after_revision: u64,
        limit: usize,
    ) -> Result<DenuoTransportEventPage, HnsWalletError> {
        if limit == 0 || limit > MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE {
            return Err(protocol_error());
        }
        let response: WireDenuoEventPage = self.rpc(serde_json::json!({
            "method": "denuo_name_market_events",
            "params": {
                "expected_instance_nonce": expected_instance_nonce.map(hex::encode),
                "after_revision": after_revision,
                "limit": limit,
            },
        }))?;
        let instance_nonce = decode_hex_32(&response.instance_nonce)?;
        if instance_nonce == [0; 32]
            || response.events.len() > limit
            || response.oldest_revision > response.head_revision.saturating_add(1)
            || (!response.cursor_reset && after_revision > response.head_revision)
            || response.cursor_reset
                != expected_instance_nonce.is_some_and(|expected| expected != instance_nonce)
        {
            return Err(protocol_error());
        }
        let mut previous = after_revision;
        let mut events = Vec::new();
        events
            .try_reserve_exact(response.events.len())
            .map_err(|_| protocol_error())?;
        for wire in response.events {
            if wire.revision <= previous
                || wire.revision < response.oldest_revision
                || wire.revision > response.head_revision
            {
                return Err(protocol_error());
            }
            previous = wire.revision;
            let envelope_bytes =
                decode_lower_hex(&wire.envelope_hex, MAX_DENUO_NAME_MARKET_ENVELOPE_BYTES)?;
            if envelope_bytes.is_empty() {
                return Err(protocol_error());
            }
            events.push(DenuoTransportEvent {
                revision: wire.revision,
                received_at_unix: wire.received_at_unix,
                kind: decode_denuo_kind(&wire.kind)?,
                content_id: decode_hex_32(&wire.content_hash)?,
                envelope_bytes,
            });
        }
        Ok(DenuoTransportEventPage {
            instance_nonce,
            cursor_reset: response.cursor_reset,
            oldest_revision: response.oldest_revision,
            head_revision: response.head_revision,
            events,
        })
    }

    fn get_denuo_name_market_snapshot(
        &self,
        expected_revision: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<DenuoTransportSnapshotPage, HnsWalletError> {
        if limit == 0 || limit > MAX_DENUO_NAME_MARKET_TRANSPORT_PAGE {
            return Err(protocol_error());
        }
        let response: WireDenuoSnapshotPage = self.rpc(serde_json::json!({
            "method": "denuo_name_market_snapshot",
            "params": {
                "expected_revision": expected_revision,
                "offset": offset,
                "limit": limit,
            },
        }))?;
        let instance_nonce = decode_hex_32(&response.instance_nonce)?;
        if instance_nonce == [0; 32]
            || expected_revision.is_some_and(|expected| expected != response.snapshot_revision)
            || response.records.len() > limit
            || response.next_offset.is_some_and(|next| {
                next != offset.saturating_add(response.records.len()) || next <= offset
            })
        {
            return Err(protocol_error());
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(response.records.len())
            .map_err(|_| protocol_error())?;
        for wire in response.records {
            let envelope_bytes =
                decode_lower_hex(&wire.envelope_hex, MAX_DENUO_NAME_MARKET_ENVELOPE_BYTES)?;
            if envelope_bytes.is_empty() {
                return Err(protocol_error());
            }
            records.push(DenuoTransportSnapshotRecord {
                kind: decode_denuo_kind(&wire.kind)?,
                content_id: decode_hex_32(&wire.content_hash)?,
                envelope_bytes,
            });
        }
        Ok(DenuoTransportSnapshotPage {
            instance_nonce,
            snapshot_revision: response.snapshot_revision,
            next_offset: response.next_offset,
            records,
        })
    }

    fn quote_transaction_fee(
        &self,
        raw: &[u8],
        input_coins: &[hns_transaction::Coin],
        target_blocks: u16,
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        if raw.is_empty()
            || raw.len() > MAX_TRANSACTION_RAW_SIZE.min(1_000_000)
            || target_blocks == 0
            || target_blocks > MAX_FEE_TARGET_BLOCKS
            || expected_mempool.instance_nonce == [0; 32]
        {
            return Err(protocol_error());
        }
        let transaction = Transaction::decode(raw).map_err(|_| protocol_error())?;
        if transaction.encode().map_err(|_| protocol_error())? != raw {
            return Err(protocol_error());
        }
        let transaction_weight = transaction.weight().map_err(|_| protocol_error())?;
        let expected_txid = transaction
            .transaction_hash()
            .map_err(|_| protocol_error())?;
        let expected_txid = TransactionHash::new(expected_txid.into_bytes());
        let response: WireTransactionFeeQuote = self.rpc(serde_json::json!({
            "method": "quote_transaction_fee",
            "params": {
                "transaction_hex": hex::encode(raw),
                "target_blocks": target_blocks,
                "expected_chain_epoch": binding.chain_epoch,
                "expected_mempool": expected_mempool_json(expected_mempool),
            },
        }))?;
        require_binding(response.chain_epoch, response.tip, binding)?;
        let mempool = MempoolSnapshotBinding {
            instance_nonce: decode_hex_32(&response.mempool_instance_nonce)?,
            generation: response.mempool_generation,
        };
        if mempool != expected_mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let rate_source = match response.rate_source.as_str() {
            "minimum_relay" if response.rate_sample_count == 0 => HnsFeeRateSource::MinimumRelay,
            "mempool" if response.rate_sample_count > 0 => HnsFeeRateSource::Mempool,
            _ => return Err(protocol_error()),
        };
        let minimum_policy_fee =
            BaseUnits::new(u128::from(response.minimum_policy_fee_atomic_units));
        let actual_fee = BaseUnits::new(u128::from(response.actual_fee_atomic_units));
        let minimum_policy_fee_shortfall = BaseUnits::new(u128::from(
            response.minimum_policy_fee_shortfall_atomic_units,
        ));
        let expected_shortfall = minimum_policy_fee.get().saturating_sub(actual_fee.get());
        if TransactionHash::new(decode_hex_32(&response.txid)?) != expected_txid
            || response.target_blocks != u32::from(target_blocks)
            || response.rate_atomic_units_per_1000_policy_vbytes < 1_000
            || response.rate_sample_count > MAX_FEE_SAMPLES
            || response.transaction_weight != transaction_weight
            || response.transaction_weight == 0
            || response.sigop_adjusted_policy_vbytes == 0
            || response.meets_minimum_policy_fee != (actual_fee >= minimum_policy_fee)
            || minimum_policy_fee_shortfall.get() != expected_shortfall
        {
            return Err(protocol_error());
        }
        let quote = HnsTransactionFeeQuote {
            txid: expected_txid,
            binding,
            mempool,
            target_blocks,
            rate_atomic_units_per_1000_policy_vbytes: response
                .rate_atomic_units_per_1000_policy_vbytes,
            rate_sample_count: response.rate_sample_count,
            rate_source,
            transaction_weight: response.transaction_weight,
            transaction_sigops: response.transaction_sigops,
            sigop_adjusted_policy_vbytes: response.sigop_adjusted_policy_vbytes,
            minimum_policy_fee,
            actual_fee,
            meets_minimum_policy_fee: response.meets_minimum_policy_fee,
            minimum_policy_fee_shortfall,
        };
        super::validate_local_fee_quote_evidence(&transaction, input_coins, &quote)?;
        Ok(quote)
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<BaseUnits, HnsWalletError> {
        if target_blocks == 0 || target_blocks > MAX_FEE_TARGET_BLOCKS {
            return Err(protocol_error());
        }
        let response: WireFeeEstimate = self.rpc(serde_json::json!({
            "method": "estimate_fee_rate",
            "params": {
                "target_blocks": target_blocks,
            },
        }))?;
        let valid_source = match response.source.as_str() {
            "minimum_relay" => response.sampled_transactions == 0,
            "mempool" => response.sampled_transactions > 0,
            _ => false,
        };
        if response.target_blocks != u32::from(target_blocks)
            || response.atomic_units_per_kvb < 1_000
            || response.sampled_transactions > MAX_FEE_SAMPLES
            || !valid_source
        {
            return Err(protocol_error());
        }
        Ok(BaseUnits::new(u128::from(response.atomic_units_per_kvb)))
    }

    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError> {
        let response: WireNameEvidence = self.rpc(serde_json::json!({
            "method": "name_evidence",
            "params": {
                "name_hash": hex::encode(name_hash),
                "expected_chain_epoch": binding.chain_epoch,
            },
        }))?;
        require_binding(response.chain_epoch, response.tip.clone(), binding)?;
        validated_name_response(self, response, name_hash, binding)
    }

    fn get_active_name_owner_coin(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<ActiveNameOwnerCoinEvidence, HnsWalletError> {
        let response: WireActiveNameOwnerCoin = self.rpc(serde_json::json!({
            "method": "active_name_owner_coin",
            "params": {
                "name_hash": hex::encode(name_hash),
                "expected_chain_epoch": binding.chain_epoch,
            },
        }))?;
        validate_active_name_owner_metadata(
            response.projection_version,
            response.chain_epoch,
            response.tip.clone(),
            &response.source_binding,
            binding,
        )?;
        let (current_state, _) = decode_projected_name_state(
            &response.current_state_hex,
            &response.current_state,
            name_hash,
        )?;
        let owner_coin = wire_coin(&response.owner_coin)?;
        let inclusion = inclusion(response.inclusion, binding.tip)?;
        let evidence = ActiveNameOwnerCoinEvidence {
            projection_version: response.projection_version,
            binding,
            current_state,
            owner_coin,
            inclusion,
            source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
        };
        super::validate_active_name_owner_coin_evidence(&evidence, name_hash, binding)?;
        self.require_active_block_hash(inclusion.height, inclusion.block_hash, binding)?;
        Ok(evidence)
    }

    fn get_name_action_context(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let response: WireNameActionContext = self.rpc(serde_json::json!({
            "method": "name_action_context",
            "params": {
                "action": action,
                "name_hash": hex::encode(name_hash),
                "expected_chain_epoch": binding.chain_epoch,
                "expected_mempool": expected_mempool_json(expected_mempool),
            },
        }))?;
        validated_name_action_response(self, response, action, name_hash, binding, expected_mempool)
    }

    fn get_name_action_context_v2(
        &self,
        action: HnsNameAction,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<NameActionContextEvidence, HnsWalletError> {
        let response: WireNameActionContextV2 = self.rpc(serde_json::json!({
            "method": "name_action_context_v2",
            "params": {
                "action": action,
                "name_hash": hex::encode(name_hash),
                "expected_chain_epoch": binding.chain_epoch,
                "expected_mempool": expected_mempool_json(expected_mempool),
            },
        }))?;
        validated_name_action_v2_response(
            self,
            response,
            action,
            name_hash,
            binding,
            expected_mempool,
        )
    }
}

struct WireNameActionCommon {
    context_version: u8,
    action: HnsNameAction,
    chain_identity: WireNameActionChainIdentity,
    chain_epoch: u64,
    tip: WireTip,
    candidate_inclusion_height: u32,
    mempool: WireNameActionMempool,
    name_hash: String,
    current_state_hex: String,
    current_state: WireNameState,
    lifecycle: HnsNameLifecycle,
    transfer: WireNameActionTransfer,
    renewal: WireNameActionRenewal,
    eligibility: WireNameActionEligibility,
}

impl WireNameActionContext {
    fn into_parts(self) -> (WireNameActionCommon, WireNameOwner) {
        (
            WireNameActionCommon {
                context_version: self.context_version,
                action: self.action,
                chain_identity: self.chain_identity,
                chain_epoch: self.chain_epoch,
                tip: self.tip,
                candidate_inclusion_height: self.candidate_inclusion_height,
                mempool: self.mempool,
                name_hash: self.name_hash,
                current_state_hex: self.current_state_hex,
                current_state: self.current_state,
                lifecycle: self.lifecycle,
                transfer: self.transfer,
                renewal: self.renewal,
                eligibility: self.eligibility,
            },
            self.owner,
        )
    }
}

impl WireNameActionContextV2 {
    fn into_parts(self) -> (WireNameActionCommon, WireNameActionActiveOwnerCoin) {
        (
            WireNameActionCommon {
                context_version: self.context_version,
                action: self.action,
                chain_identity: self.chain_identity,
                chain_epoch: self.chain_epoch,
                tip: self.tip,
                candidate_inclusion_height: self.candidate_inclusion_height,
                mempool: self.mempool,
                name_hash: self.name_hash,
                current_state_hex: self.current_state_hex,
                current_state: self.current_state,
                lifecycle: self.lifecycle,
                transfer: self.transfer,
                renewal: self.renewal,
                eligibility: self.eligibility,
            },
            self.active_owner,
        )
    }
}

struct ValidatedWireNameActionHeader {
    candidate_height: u64,
    mempool: MempoolSnapshotBinding,
    mempool_spender: Option<TransactionHash>,
    current_state: Vec<u8>,
    canonical_state: NameState,
}

fn validate_wire_name_action_header(
    response: &WireNameActionCommon,
    expected_context_version: u8,
    expected_action: HnsNameAction,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
) -> Result<ValidatedWireNameActionHeader, HnsWalletError> {
    require_binding(response.chain_epoch, Some(response.tip.clone()), binding)?;
    let candidate_height = binding
        .tip
        .height
        .checked_add(1)
        .ok_or_else(protocol_error)?;
    if response.context_version != expected_context_version
        || response.action != expected_action
        || decode_hex_32(&response.name_hash)? != expected_name_hash
        || u64::from(response.candidate_inclusion_height) != candidate_height
    {
        return Err(protocol_error());
    }

    let mempool = MempoolSnapshotBinding {
        instance_nonce: decode_hex_32(&response.mempool.instance_nonce)?,
        generation: response.mempool.generation,
    };
    if mempool.instance_nonce == [0; 32] || mempool != expected_mempool {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let mempool_spender = response
        .mempool
        .owner_spender_txid
        .as_deref()
        .map(decode_hex_32)
        .transpose()?
        .map(TransactionHash::new);
    let (current_state, canonical_state) = decode_projected_name_state(
        &response.current_state_hex,
        &response.current_state,
        expected_name_hash,
    )?;
    Ok(ValidatedWireNameActionHeader {
        candidate_height,
        mempool,
        mempool_spender,
        current_state,
        canonical_state,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_validated_name_action_response(
    response: WireNameActionCommon,
    header: ValidatedWireNameActionHeader,
    expected_action: HnsNameAction,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
    owner_outpoint: HnsOutpoint,
    owner_transaction: Vec<u8>,
    owner_coin: Option<HnsInputCoinEvidence>,
    owner_inclusion: TransactionInclusion,
    owner_kind: CovenantKind,
) -> Result<NameActionContextEvidence, HnsWalletError> {
    let owner_coin_source_binding = owner_coin
        .as_ref()
        .map(|_| ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection);
    let transfer_height = (header.canonical_state.transfer.get() != 0)
        .then_some(header.canonical_state.transfer.get());
    let expected_finalize_height = transfer_height
        .map(|height| {
            height
                .checked_add(response.transfer.lockup_blocks)
                .ok_or_else(protocol_error)
        })
        .transpose()?;
    let expected_finalize_eligible = expected_finalize_height
        .is_some_and(|height| response.candidate_inclusion_height >= height);
    if response.transfer.lockup_blocks == 0
        || response.transfer.current_transfer_height != transfer_height
        || response.transfer.finalize_maturity_height != expected_finalize_height
        || response.transfer.finalize_eligible_at_candidate != expected_finalize_eligible
    {
        return Err(protocol_error());
    }

    let renewal = &response.renewal;
    if renewal.maturity_blocks == 0 || renewal.period_blocks < renewal.maturity_blocks {
        return Err(protocol_error());
    }
    let selected_height = response
        .tip
        .height
        .saturating_sub(renewal.maturity_blocks.saturating_mul(2));
    let renewal_valid = response.candidate_inclusion_height < renewal.maturity_blocks
        || (renewal.hsd_selected_height
            <= response.candidate_inclusion_height - renewal.maturity_blocks
            && renewal.hsd_selected_height
                >= response
                    .candidate_inclusion_height
                    .saturating_sub(renewal.period_blocks));
    let renewal_hash = decode_hex_32(&renewal.hsd_selected_hash)?;
    if renewal.hsd_selected_height != selected_height || renewal.valid_at_candidate != renewal_valid
    {
        return Err(protocol_error());
    }

    let reasons = &response.eligibility.reasons;
    if reasons.len() > 9
        || !reasons
            .windows(2)
            .all(|pair| pair[0].rank() < pair[1].rank())
        || response.eligibility.eligible != reasons.is_empty()
    {
        return Err(protocol_error());
    }
    let expired_at_candidate = reasons.contains(&NameActionIneligibility::NameExpiredAtCandidate);
    let mut expected_reasons = Vec::new();
    if !header.canonical_state.registered {
        expected_reasons.push(NameActionIneligibility::NameNotRegistered);
    }
    if expired_at_candidate {
        expected_reasons.push(NameActionIneligibility::NameExpiredAtCandidate);
    }
    if response.lifecycle != HnsNameLifecycle::Closed {
        expected_reasons.push(NameActionIneligibility::LifecycleNotClosed);
    }
    match expected_action {
        HnsNameAction::Transfer => {
            if transfer_height.is_some() {
                expected_reasons.push(NameActionIneligibility::TransferAlreadyPending);
            }
            if !matches!(
                owner_kind,
                CovenantKind::Register
                    | CovenantKind::Update
                    | CovenantKind::Renew
                    | CovenantKind::Finalize
            ) {
                expected_reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
        }
        HnsNameAction::Finalize => {
            if transfer_height.is_none() {
                expected_reasons.push(NameActionIneligibility::TransferNotPending);
            } else if !expected_finalize_eligible {
                expected_reasons.push(NameActionIneligibility::TransferNotMature);
            }
            if owner_kind != CovenantKind::Transfer {
                expected_reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
            if !renewal_valid {
                expected_reasons.push(NameActionIneligibility::RenewalCommitmentInvalid);
            }
        }
    }
    if header.mempool_spender.is_some() {
        expected_reasons.push(NameActionIneligibility::OwnerSpentInMempool);
    }
    if reasons != &expected_reasons {
        return Err(protocol_error());
    }

    let genesis_hash = decode_hex_32(&response.chain_identity.genesis_hash)?;
    let common = NameActionContextEvidence {
        binding,
        mempool: header.mempool,
        network: response.chain_identity.network,
        network_id: response.chain_identity.network_id,
        genesis_hash,
        context_version: u32::from(response.context_version),
        consensus_profile: response.chain_identity.consensus_profile,
        action: response.action,
        name_hash: expected_name_hash,
        current_state: header.current_state,
        owner_outpoint,
        owner_transaction,
        owner_coin,
        owner_coin_source_binding,
        owner_inclusion,
        candidate_inclusion_height: header.candidate_height,
        lifecycle: response.lifecycle,
        action_eligible: response.eligibility.eligible,
        ineligibility_reasons: response.eligibility.reasons,
        transfer_height: None,
        transfer_lockup: None,
        finalize_eligible_height: None,
        finalize_mature: None,
        renewal_maturity: None,
        renewal_period: None,
        renewal_block_height: None,
        renewal_block_hash: None,
        renewal_valid_at_candidate: None,
        mempool_spender: header.mempool_spender,
    };
    Ok(match expected_action {
        HnsNameAction::Transfer => common,
        HnsNameAction::Finalize => NameActionContextEvidence {
            transfer_height: response.transfer.current_transfer_height.map(u64::from),
            transfer_lockup: Some(response.transfer.lockup_blocks),
            finalize_eligible_height: response.transfer.finalize_maturity_height.map(u64::from),
            finalize_mature: Some(response.transfer.finalize_eligible_at_candidate),
            renewal_maturity: Some(renewal.maturity_blocks),
            renewal_period: Some(renewal.period_blocks),
            renewal_block_height: Some(u64::from(renewal.hsd_selected_height)),
            renewal_block_hash: Some(renewal_hash),
            renewal_valid_at_candidate: Some(renewal_valid),
            ..common
        },
    })
}

fn validated_name_action_response(
    backend: &HnsNodeRpcBackend,
    response: WireNameActionContext,
    expected_action: HnsNameAction,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
) -> Result<NameActionContextEvidence, HnsWalletError> {
    let (response, owner) = response.into_parts();
    let header = validate_wire_name_action_header(
        &response,
        1,
        expected_action,
        expected_name_hash,
        binding,
        expected_mempool,
    )?;
    let owner = validate_name_owner(
        backend,
        owner,
        &response.current_state,
        &header.canonical_state,
        binding,
    )?;
    let owner_kind = owner.output.covenant.kind;
    finish_validated_name_action_response(
        response,
        header,
        expected_action,
        expected_name_hash,
        binding,
        owner.outpoint,
        owner.raw_transaction,
        None,
        owner.inclusion,
        owner_kind,
    )
}

struct ValidatedWireNameActionOwnerV2 {
    outpoint: HnsOutpoint,
    coin: HnsInputCoinEvidence,
    inclusion: TransactionInclusion,
    kind: CovenantKind,
}

fn validate_wire_name_action_owner_v2(
    active_owner: WireNameActionActiveOwnerCoin,
    current_state: &[u8],
    canonical_state: &NameState,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
) -> Result<ValidatedWireNameActionOwnerV2, HnsWalletError> {
    if active_owner.projection_version != ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION
        || active_owner.source_binding != "trusted_node_active_utxo_projection"
    {
        return Err(protocol_error());
    }
    let owner_coin = wire_coin(&active_owner.owner_coin)?;
    let owner_inclusion = inclusion(active_owner.inclusion, binding.tip)?;
    let active_evidence = ActiveNameOwnerCoinEvidence {
        projection_version: active_owner.projection_version,
        binding,
        current_state: current_state.to_vec(),
        owner_coin: owner_coin.clone(),
        inclusion: owner_inclusion,
        source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
    };
    let validated_state = super::validate_active_name_owner_coin_evidence(
        &active_evidence,
        expected_name_hash,
        binding,
    )?;
    if &validated_state != canonical_state {
        return Err(protocol_error());
    }
    let outpoint = HnsOutpoint {
        transaction: TransactionHash::new(owner_coin.outpoint.transaction_hash.into_bytes()),
        output_index: owner_coin.outpoint.index,
    };
    let kind = owner_coin.covenant.kind;
    let coin = HnsInputCoinEvidence::from_canonical_coin(&owner_coin)?;
    Ok(ValidatedWireNameActionOwnerV2 {
        outpoint,
        coin,
        inclusion: owner_inclusion,
        kind,
    })
}

fn validated_name_action_v2_response(
    backend: &HnsNodeRpcBackend,
    response: WireNameActionContextV2,
    expected_action: HnsNameAction,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
) -> Result<NameActionContextEvidence, HnsWalletError> {
    let (response, active_owner) = response.into_parts();
    let header = validate_wire_name_action_header(
        &response,
        2,
        expected_action,
        expected_name_hash,
        binding,
        expected_mempool,
    )?;
    let owner = validate_wire_name_action_owner_v2(
        active_owner,
        &header.current_state,
        &header.canonical_state,
        expected_name_hash,
        binding,
    )?;
    backend.require_active_block_hash(
        owner.inclusion.height,
        owner.inclusion.block_hash,
        binding,
    )?;
    finish_validated_name_action_response(
        response,
        header,
        expected_action,
        expected_name_hash,
        binding,
        owner.outpoint,
        Vec::new(),
        Some(owner.coin),
        owner.inclusion,
        owner.kind,
    )
}

fn validated_name_response(
    backend: &HnsNodeRpcBackend,
    response: WireNameEvidence,
    expected_name_hash: [u8; 32],
    binding: SnapshotBinding,
) -> Result<NameEvidence, HnsWalletError> {
    if response.data_semantics != "projected_data_hex_is_resource_bytes_not_encoded_name_state"
        || response.current_state_hex.is_some() != response.current_state.is_some()
        || response.proof_state_hex.is_some() != response.proof_state.is_some()
        || response.current_owner.is_some() && response.current_state.is_none()
        || response.proof_owner.is_some() && response.proof_state.is_none()
    {
        return Err(protocol_error());
    }
    let canonical_current = response
        .current_state_hex
        .as_deref()
        .zip(response.current_state.as_ref())
        .map(|(raw, projected)| decode_projected_name_state(raw, projected, expected_name_hash))
        .transpose()?;
    let canonical_proof = response
        .proof_state_hex
        .as_deref()
        .zip(response.proof_state.as_ref())
        .map(|(raw, projected)| decode_projected_name_state(raw, projected, expected_name_hash))
        .transpose()?;
    let current_resource = canonical_current
        .as_ref()
        .map(|(_, state)| state.resource_data.clone());
    let (current_owner_outpoint, current_owner_transaction, current_owner_inclusion) = response
        .current_owner
        .map(|owner| {
            validate_name_owner(
                backend,
                owner,
                response.current_state.as_ref().ok_or_else(protocol_error)?,
                &canonical_current.as_ref().ok_or_else(protocol_error)?.1,
                binding,
            )
        })
        .transpose()?
        .map_or((None, None, None), |owner| {
            (
                Some(owner.outpoint),
                Some(owner.raw_transaction),
                Some(owner.inclusion),
            )
        });
    let (proof_owner_outpoint, proof_owner_transaction, proof_owner_inclusion) = response
        .proof_owner
        .map(|owner| {
            validate_name_owner(
                backend,
                owner,
                response.proof_state.as_ref().ok_or_else(protocol_error)?,
                &canonical_proof.as_ref().ok_or_else(protocol_error)?.1,
                binding,
            )
        })
        .transpose()?
        .map_or((None, None, None), |owner| {
            (
                Some(owner.outpoint),
                Some(owner.raw_transaction),
                Some(owner.inclusion),
            )
        });

    let current_state = canonical_current.map(|(raw, _)| raw);
    let proof_state = canonical_proof.map(|(raw, _)| raw);
    let proof_name_hash = decode_hex_32(&response.proof.name_hash)?;
    let proof_root = decode_hex_32(&response.proof.root)?;
    let proof = decode_lower_hex(&response.proof.proof_hex, 1_000_000)?;
    let valid_kind = match response.proof.kind.as_str() {
        "inclusion" => proof_state.is_some(),
        "non_inclusion" => proof_state.is_none(),
        _ => false,
    };
    if proof_name_hash != expected_name_hash
        || proof_root != binding.tip.tree_root
        || proof.is_empty()
        || !valid_kind
    {
        return Err(protocol_error());
    }
    Ok(NameEvidence {
        binding,
        proof: NameProofResponse {
            name_hash: expected_name_hash,
            tree_root: proof_root,
            proof,
            proof_height: binding.tip.height,
        },
        proof_state,
        proof_owner_outpoint,
        proof_owner_transaction,
        proof_owner_inclusion,
        current_state,
        current_owner_outpoint,
        current_owner_transaction,
        current_owner_inclusion,
        untrusted_current_raw_resource: current_resource,
    })
}

fn decode_projected_name_state(
    encoded: &str,
    state: &WireNameState,
    expected_name_hash: [u8; 32],
) -> Result<(Vec<u8>, NameState), HnsWalletError> {
    let raw = decode_lower_hex(encoded, MAX_NAME_STATE_SIZE)?;
    let canonical =
        NameState::decode(NameHash::new(expected_name_hash), &raw).map_err(|_| protocol_error())?;
    let projected_owner = hns_outpoint(&state.owner)?;
    let canonical_owner = HnsOutpoint {
        transaction: TransactionHash::new(canonical.owner.transaction_hash.into_bytes()),
        output_index: canonical.owner.index,
    };
    if decode_hex_32(&state.name_hash)? != expected_name_hash
        || decode_lower_hex(&state.name_hex, 63)? != canonical.name
        || state.height != canonical.height.get()
        || state.renewal != canonical.renewal.get()
        || projected_owner != canonical_owner
        || state.value != canonical.value.get()
        || state.highest != canonical.highest.get()
        || decode_lower_hex(&state.data_hex, 512)? != canonical.resource_data
        || state.transfer != canonical.transfer.get()
        || state.revoked != canonical.revoked.get()
        || state.claimed != canonical.claimed.get()
        || state.renewals != canonical.renewals
        || state.registered != canonical.registered
        || state.expired != canonical.expired
        || state.weak != canonical.weak
    {
        return Err(protocol_error());
    }
    Ok((raw, canonical))
}

fn validate_name_owner(
    backend: &HnsNodeRpcBackend,
    owner: WireNameOwner,
    expected_state: &WireNameState,
    canonical_state: &NameState,
    binding: SnapshotBinding,
) -> Result<ValidatedWireNameOwner, HnsWalletError> {
    if &owner.name_state != expected_state || owner.owner != owner.name_state.owner {
        return Err(protocol_error());
    }
    let outpoint = hns_outpoint(&owner.owner)?;
    let canonical_outpoint = canonical_state
        .owner_outpoint()
        .map(|canonical| HnsOutpoint {
            transaction: TransactionHash::new(canonical.transaction_hash.into_bytes()),
            output_index: canonical.index,
        })
        .ok_or_else(protocol_error)?;
    if outpoint != canonical_outpoint {
        return Err(protocol_error());
    }
    let (raw, transaction) =
        canonical_transaction(&owner.transaction_hex, Some(outpoint.transaction))?;
    let output = wire_output(&owner.owner_output)?;
    if transaction.outputs.get(outpoint.output_index as usize) != Some(&output) {
        return Err(protocol_error());
    }
    let inclusion = inclusion(owner.inclusion, binding.tip)?;
    if inclusion.transaction_index.is_none() {
        return Err(protocol_error());
    }
    validate_name_owner_inclusion(canonical_state, output.covenant.kind, inclusion.height)?;
    backend.require_active_block_hash(inclusion.height, inclusion.block_hash, binding)?;
    Ok(ValidatedWireNameOwner {
        outpoint,
        raw_transaction: raw,
        output,
        inclusion,
    })
}

fn validate_name_owner_inclusion(
    canonical_state: &NameState,
    owner_covenant: CovenantKind,
    inclusion_height: u64,
) -> Result<(), HnsWalletError> {
    let transfer_height = u64::from(canonical_state.transfer.get());
    match owner_covenant {
        CovenantKind::Transfer if transfer_height != 0 && transfer_height == inclusion_height => {
            Ok(())
        }
        CovenantKind::Transfer => Err(protocol_error()),
        _ if transfer_height != 0 => Err(protocol_error()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_covenants::hash_name;
    use hns_primitives::{Height, Outpoint};

    #[test]
    fn chain_snapshot_wire_schema_is_closed_and_uninitialized_tip_is_stale() {
        let response = serde_json::json!({
            "chain_epoch": 9,
            "tip": {
                "hash": hex::encode([1; 32]),
                "height": 42,
                "tree_root": hex::encode([2; 32]),
                "median_time_past": 1_800_000_000_u64,
            },
        });
        let parsed: WireChainSnapshot =
            serde_json::from_value(response.clone()).expect("strict chain snapshot");
        assert_eq!(
            chain_snapshot(parsed).expect("initialized chain snapshot"),
            SnapshotBinding {
                tip: ChainTip {
                    height: 42,
                    block_hash: [1; 32],
                    tree_root: [2; 32],
                    median_time_past: 1_800_000_000,
                },
                chain_epoch: 9,
            }
        );

        let mut missing_tip = response.clone();
        missing_tip
            .as_object_mut()
            .expect("snapshot object")
            .remove("tip");
        assert!(serde_json::from_value::<WireChainSnapshot>(missing_tip).is_err());

        let mut null_tip = response.clone();
        null_tip["tip"] = serde_json::Value::Null;
        let null_tip = serde_json::from_value::<WireChainSnapshot>(null_tip)
            .expect("uninitialized chain snapshot shape");
        assert!(matches!(
            chain_snapshot(null_tip),
            Err(HnsWalletError::StaleNodeSnapshot)
        ));

        let mut extra_field = response;
        extra_field["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WireChainSnapshot>(extra_field).is_err());
    }

    #[test]
    fn incoming_and_active_projection_metadata_is_strictly_bound_and_closed() {
        let binding = SnapshotBinding {
            tip: ChainTip {
                height: 42,
                block_hash: [1; 32],
                tree_root: [2; 32],
                median_time_past: 1_800_000_000,
            },
            chain_epoch: 9,
        };
        let wire_tip = || WireTip {
            hash: hex::encode(binding.tip.block_hash),
            height: u32::try_from(binding.tip.height).expect("tip height"),
            tree_root: hex::encode(binding.tip.tree_root),
            median_time_past: binding.tip.median_time_past,
        };
        assert!(
            validate_incoming_page_metadata(1, 9, Some(wire_tip()), 1, 1, 1, 1, binding).is_ok()
        );
        for invalid in [
            validate_incoming_page_metadata(2, 9, Some(wire_tip()), 1, 1, 1, 1, binding),
            validate_incoming_page_metadata(1, 10, Some(wire_tip()), 1, 1, 1, 1, binding),
            validate_incoming_page_metadata(1, 9, Some(wire_tip()), 2, 1, 1, 1, binding),
            validate_incoming_page_metadata(1, 9, Some(wire_tip()), 0, 0, 1, 1, binding),
            validate_incoming_page_metadata(1, 9, Some(wire_tip()), 0, 2, 1, 1, binding),
        ] {
            assert!(invalid.is_err());
        }
        let mut wrong_tip = wire_tip();
        wrong_tip.hash = hex::encode([3; 32]);
        assert!(
            validate_incoming_page_metadata(1, 9, Some(wrong_tip), 0, 1, 1, 1, binding).is_err()
        );
        assert_eq!(
            incoming_transfer_source_binding("retained_body_verified").expect("retained source"),
            IncomingTransferSourceBinding::RetainedBodyVerified
        );
        assert_eq!(
            incoming_transfer_source_binding("pruned_trusted_node_projection")
                .expect("pruned source"),
            IncomingTransferSourceBinding::PrunedTrustedNodeProjection
        );
        assert!(incoming_transfer_source_binding("archive_verified").is_err());

        assert!(
            validate_active_name_owner_metadata(
                1,
                9,
                wire_tip(),
                "trusted_node_active_utxo_projection",
                binding,
            )
            .is_ok()
        );
        assert!(
            validate_active_name_owner_metadata(
                2,
                9,
                wire_tip(),
                "trusted_node_active_utxo_projection",
                binding,
            )
            .is_err()
        );
        assert!(
            validate_active_name_owner_metadata(
                1,
                9,
                wire_tip(),
                "retained_body_verified",
                binding
            )
            .is_err()
        );

        let incoming = serde_json::json!({
            "projection_version": 1,
            "chain_epoch": 9,
            "tip": {
                "hash": hex::encode(binding.tip.block_hash),
                "height": 42,
                "tree_root": hex::encode(binding.tip.tree_root),
                "median_time_past": binding.tip.median_time_past,
            },
            "entries": [],
            "script_examinations": 1,
            "continuation": null,
        });
        assert!(serde_json::from_value::<WireIncomingTransfersPage>(incoming.clone()).is_ok());
        let mut extended = incoming;
        extended
            .as_object_mut()
            .expect("incoming object")
            .insert("unbound_extension".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<WireIncomingTransfersPage>(extended).is_err());

        let active = serde_json::json!({
            "projection_version": 1,
            "chain_epoch": 9,
            "tip": {
                "hash": hex::encode(binding.tip.block_hash),
                "height": 42,
                "tree_root": hex::encode(binding.tip.tree_root),
                "median_time_past": binding.tip.median_time_past,
            },
            "current_state_hex": "00",
            "current_state": {
                "name_hash": "11".repeat(32),
                "name_hex": "616c706861",
                "height": 0,
                "renewal": 1,
                "owner": {"txid": "22".repeat(32), "index": 0},
                "value": 0,
                "highest": 0,
                "data_hex": "",
                "transfer": 0,
                "revoked": 0,
                "claimed": 0,
                "renewals": 1,
                "registered": true,
                "expired": false,
                "weak": false,
            },
            "owner_coin": {
                "outpoint": {"txid": "22".repeat(32), "index": 0},
                "value": 0,
                "height": 1,
                "coinbase": false,
                "address": {"version": 0, "hash": "33".repeat(20)},
                "covenant": {"kind": 10, "items": []},
            },
            "inclusion": {
                "block_hash": "44".repeat(32),
                "height": 1,
                "transaction_index": null,
                "confirmations": 42,
            },
            "source_binding": "trusted_node_active_utxo_projection",
        });
        assert!(serde_json::from_value::<WireActiveNameOwnerCoin>(active.clone()).is_ok());
        let mut extended = active;
        extended
            .as_object_mut()
            .expect("active object")
            .insert("unbound_extension".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<WireActiveNameOwnerCoin>(extended).is_err());
    }

    #[test]
    fn canonical_hns_v2_node_projection_must_equal_raw_name_state() {
        let name = b"alpha".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let state = NameState {
            name_hash,
            name: name.clone(),
            height: Height::new(10),
            renewal: Height::new(11),
            owner: Outpoint::NULL,
            value: Dollarydoos::new(12),
            highest: Dollarydoos::new(13),
            resource_data: vec![1],
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 2,
            registered: true,
            expired: false,
            weak: true,
        };
        let raw = state.encode().expect("name state");
        let projection = WireNameState {
            name_hash: hex::encode(name_hash.as_bytes()),
            name_hex: hex::encode(name),
            height: 10,
            renewal: 11,
            owner: WireOutpoint {
                txid: hex::encode([0; 32]),
                index: u32::MAX,
            },
            value: 12,
            highest: 13,
            data_hex: hex::encode([1]),
            transfer: 0,
            revoked: 0,
            claimed: 0,
            renewals: 2,
            registered: true,
            expired: false,
            weak: true,
        };
        let encoded = hex::encode(&raw);
        assert!(decode_projected_name_state(&encoded, &projection, name_hash.into_bytes()).is_ok());

        let mut mismatches = Vec::new();
        let mut mismatch = projection.clone();
        mismatch.value += 1;
        mismatches.push(mismatch);
        let mut mismatch = projection.clone();
        mismatch.data_hex = hex::encode([2]);
        mismatches.push(mismatch);
        let mut mismatch = projection.clone();
        mismatch.owner.index = 0;
        mismatches.push(mismatch);
        let mut mismatch = projection.clone();
        mismatch.transfer = 1;
        mismatches.push(mismatch);
        let mut mismatch = projection.clone();
        mismatch.registered = false;
        mismatches.push(mismatch);
        let mut mismatch = projection;
        mismatch.renewals += 1;
        mismatches.push(mismatch);
        assert!(mismatches.into_iter().all(|projection| {
            decode_projected_name_state(&encoded, &projection, name_hash.into_bytes()).is_err()
        }));
    }

    #[test]
    fn canonical_hns_v2_transfer_height_must_match_owner_inclusion() {
        let mut state = NameState::null(NameHash::new([1; 32]));
        state.transfer = Height::new(42);
        assert!(validate_name_owner_inclusion(&state, CovenantKind::Transfer, 42).is_ok());
        assert!(validate_name_owner_inclusion(&state, CovenantKind::Transfer, 41).is_err());
        assert!(validate_name_owner_inclusion(&state, CovenantKind::Finalize, 42).is_err());

        state.transfer = Height::new(0);
        assert!(validate_name_owner_inclusion(&state, CovenantKind::Finalize, 42).is_ok());
        assert!(validate_name_owner_inclusion(&state, CovenantKind::Transfer, 0).is_err());
    }

    #[test]
    fn name_action_v2_owner_projection_is_canonical_and_pruning_safe() {
        let name = b"alpha".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let owner_txid = CanonicalTransactionHash::new([2; 32]);
        let state = NameState {
            name_hash,
            name,
            height: Height::new(100),
            renewal: Height::new(120),
            owner: Outpoint {
                transaction_hash: owner_txid,
                index: 0,
            },
            value: Dollarydoos::new(50_000),
            highest: Dollarydoos::new(60_000),
            resource_data: Vec::new(),
            transfer: Height::new(400),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 1,
            registered: true,
            expired: false,
            weak: false,
        };
        let current_state = state.encode().expect("canonical state");
        let transfer =
            hns_covenants::TransferCovenant::new(name_hash, state.height, 0, vec![9; 20])
                .expect("transfer")
                .to_covenant()
                .expect("transfer covenant");
        let binding = SnapshotBinding {
            chain_epoch: 9,
            tip: ChainTip {
                height: 409,
                block_hash: [4; 32],
                tree_root: [5; 32],
                median_time_past: 1_700_000_000,
            },
        };
        let active = serde_json::json!({
            "projection_version": 1,
            "owner_coin": {
                "outpoint": {"txid": hex::encode(owner_txid.as_bytes()), "index": 0},
                "value": 50_000,
                "height": 400,
                "coinbase": false,
                "address": {"version": 0, "hash": hex::encode([7; 20])},
                "covenant": {
                    "kind": transfer.kind.as_u8(),
                    "items": transfer.items.iter().map(hex::encode).collect::<Vec<_>>()
                }
            },
            "inclusion": {
                "block_hash": hex::encode([8; 32]),
                "height": 400,
                "transaction_index": null,
                "confirmations": 10
            },
            "source_binding": "trusted_node_active_utxo_projection"
        });
        let validated = validate_wire_name_action_owner_v2(
            serde_json::from_value(active.clone()).expect("wire owner"),
            &current_state,
            &state,
            name_hash.into_bytes(),
            binding,
        )
        .expect("valid v2 owner");
        assert_eq!(validated.outpoint.output_index, 0);
        assert_eq!(validated.inclusion.transaction_index, None);
        assert_eq!(validated.kind, CovenantKind::Transfer);
        assert_eq!(
            validated.coin.to_canonical_coin().expect("coin").height,
            Height::new(400)
        );

        let mut invented_position = active.clone();
        invented_position["inclusion"]["transaction_index"] = serde_json::json!(0);
        assert!(
            validate_wire_name_action_owner_v2(
                serde_json::from_value(invented_position).expect("wire owner"),
                &current_state,
                &state,
                name_hash.into_bytes(),
                binding,
            )
            .is_err()
        );
        let mut wrong_source = active.clone();
        wrong_source["source_binding"] = serde_json::json!("retained_body_verified");
        assert!(
            validate_wire_name_action_owner_v2(
                serde_json::from_value(wrong_source).expect("wire owner"),
                &current_state,
                &state,
                name_hash.into_bytes(),
                binding,
            )
            .is_err()
        );
        let mut wrong_value = active;
        wrong_value["owner_coin"]["value"] = serde_json::json!(50_001);
        assert!(
            validate_wire_name_action_owner_v2(
                serde_json::from_value(wrong_value).expect("wire owner"),
                &current_state,
                &state,
                name_hash.into_bytes(),
                binding,
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_hns_v3_name_action_wire_schema_is_closed() {
        let projected_state = serde_json::json!({
            "name_hash": hex::encode([1; 32]),
            "name_hex": hex::encode(b"alpha"),
            "height": 100,
            "renewal": 120,
            "owner": {"txid": hex::encode([2; 32]), "index": 0},
            "value": 50_000,
            "highest": 60_000,
            "data_hex": "",
            "transfer": 400,
            "revoked": 0,
            "claimed": 0,
            "renewals": 1,
            "registered": true,
            "expired": false,
            "weak": false
        });
        let response = serde_json::json!({
            "context_version": 1,
            "action": "finalize",
            "chain_identity": {
                "network": "regtest",
                "network_id": 2,
                "genesis_hash": hex::encode([3; 32]),
                "consensus_profile": "hns-consensus/name-policy-v1"
            },
            "chain_epoch": 9,
            "tip": {
                "hash": hex::encode([4; 32]),
                "height": 409,
                "tree_root": hex::encode([5; 32]),
                "median_time_past": 1_700_000_000_u64
            },
            "candidate_inclusion_height": 410,
            "mempool": {
                "instance_nonce": hex::encode([6; 32]),
                "generation": 10,
                "owner_spender_txid": null
            },
            "name_hash": hex::encode([1; 32]),
            "current_state_hex": "00",
            "current_state": projected_state.clone(),
            "owner": {
                "name_state": projected_state,
                "owner": {"txid": hex::encode([2; 32]), "index": 0},
                "transaction_hex": "00",
                "owner_output": {
                    "value": 50_000,
                    "address": {"version": 0, "hash": hex::encode([7; 20])},
                    "covenant": {"kind": 9, "items": []}
                },
                "inclusion": {
                    "block_hash": hex::encode([8; 32]),
                    "height": 400,
                    "transaction_index": 1,
                    "confirmations": 10
                }
            },
            "lifecycle": "closed",
            "transfer": {
                "lockup_blocks": 11,
                "current_transfer_height": 400,
                "finalize_maturity_height": 411,
                "finalize_eligible_at_candidate": false
            },
            "renewal": {
                "maturity_blocks": 50,
                "period_blocks": 2500,
                "hsd_selected_height": 309,
                "hsd_selected_hash": hex::encode([9; 32]),
                "valid_at_candidate": true
            },
            "eligibility": {
                "eligible": false,
                "reasons": ["transfer_not_mature"]
            }
        });
        let parsed: WireNameActionContext =
            serde_json::from_value(response.clone()).expect("closed response schema");
        assert_eq!(parsed.action, HnsNameAction::Finalize);
        assert_eq!(parsed.lifecycle, HnsNameLifecycle::Closed);
        assert_eq!(parsed.tip.median_time_past, 1_700_000_000);
        assert_eq!(
            parsed.eligibility.reasons,
            vec![NameActionIneligibility::TransferNotMature]
        );

        let mut response_v2 = response.clone();
        response_v2["context_version"] = serde_json::json!(2);
        response_v2
            .as_object_mut()
            .expect("context object")
            .remove("owner");
        response_v2["active_owner"] = serde_json::json!({
            "projection_version": 1,
            "owner_coin": {
                "outpoint": {"txid": hex::encode([2; 32]), "index": 0},
                "value": 50_000,
                "height": 400,
                "coinbase": false,
                "address": {"version": 0, "hash": hex::encode([7; 20])},
                "covenant": {"kind": 9, "items": []}
            },
            "inclusion": {
                "block_hash": hex::encode([8; 32]),
                "height": 400,
                "transaction_index": null,
                "confirmations": 10
            },
            "source_binding": "trusted_node_active_utxo_projection"
        });
        let parsed_v2: WireNameActionContextV2 =
            serde_json::from_value(response_v2.clone()).expect("closed v2 response schema");
        assert_eq!(parsed_v2.context_version, 2);
        assert_eq!(parsed_v2.active_owner.projection_version, 1);
        assert!(parsed_v2.active_owner.inclusion.transaction_index.is_none());

        let mut v2_with_legacy_owner = response_v2.clone();
        v2_with_legacy_owner["owner"] = serde_json::json!({});
        assert!(serde_json::from_value::<WireNameActionContextV2>(v2_with_legacy_owner).is_err());
        let mut v2_extended_owner = response_v2;
        v2_extended_owner["active_owner"]["unbound_extension"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WireNameActionContextV2>(v2_extended_owner).is_err());

        let mut missing_median_time = response.clone();
        missing_median_time["tip"]
            .as_object_mut()
            .expect("tip object")
            .remove("median_time_past");
        assert!(serde_json::from_value::<WireNameActionContext>(missing_median_time).is_err());

        let mut unknown_reason = response.clone();
        unknown_reason["eligibility"]["reasons"][0] = serde_json::json!("unknown_reason");
        assert!(serde_json::from_value::<WireNameActionContext>(unknown_reason).is_err());
        let mut extra_field = response;
        extra_field["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WireNameActionContext>(extra_field).is_err());
    }
}
