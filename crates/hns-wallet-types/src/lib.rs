#![doc = "Wallet-local semantics which are not canonical chain or wire types."]
#![forbid(unsafe_code)]

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// The complete canonical website-provider method vocabulary in stable enum
/// order. Availability is negotiated separately.
pub const PROVIDER_METHOD_WIRE_NAMES: [&str; 43] = [
    "wallet_getCapabilities",
    "wallet_getEnabledModules",
    "wallet_enableModule",
    "wallet_disableModule",
    "wallet_requestPermissions",
    "wallet_getPermissions",
    "wallet_revokePermissions",
    "wallet_lock",
    "wallet_getStatus",
    "hns_requestAccounts",
    "hns_accounts",
    "hns_getBalance",
    "hns_getTransactions",
    "hns_getReceiveAddress",
    "hns_send",
    "hns_getNames",
    "hns_getName",
    "hns_importKnownName",
    "hns_transferName",
    "hns_finalizeName",
    "hns_signTypedMessage",
    "asset_getAccount",
    "asset_getBalance",
    "asset_getTransactions",
    "asset_getReceiveTarget",
    "asset_send",
    "nameMarket_listOffers",
    "nameMarket_createFixedPriceOffer",
    "nameMarket_cancelOffer",
    "nameMarket_acceptOffer",
    "nameMarket_getSession",
    "nameMarket_finalizePurchase",
    "nameMarket_recoverName",
    "swap_getSupportedPairs",
    "swap_getPriceRound",
    "swap_listMarketIntents",
    "swap_publishMarketIntent",
    "swap_cancelMarketIntent",
    "swap_requestMatch",
    "swap_acceptFill",
    "swap_getSession",
    "swap_redeem",
    "swap_refund",
];

macro_rules! semantic_id {
    ($name:ident, $size:expr) => {
        #[derive(
            Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name([u8; $size]);

        impl $name {
            pub const LENGTH: usize = $size;

            pub const fn new(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }
    };
}

semantic_id!(WalletId, 16);
semantic_id!(AccountId, 16);
semantic_id!(ApprovalId, 16);
semantic_id!(PermissionId, 16);
semantic_id!(WorkflowId, 16);
semantic_id!(SessionId, 32);
semantic_id!(ObjectHash, 32);
semantic_id!(TransactionHash, 32);

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_wire_id(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let first = bytes[index];
        let second = bytes[index + 1];
        let third = bytes[index + 2];
        encoded.push(BASE64URL_ALPHABET[(first >> 2) as usize] as char);
        encoded.push(BASE64URL_ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        encoded.push(BASE64URL_ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        encoded.push(BASE64URL_ALPHABET[(third & 0x3f) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let first = bytes[index];
            encoded.push(BASE64URL_ALPHABET[(first >> 2) as usize] as char);
            encoded.push(BASE64URL_ALPHABET[((first & 0x03) << 4) as usize] as char);
        }
        2 => {
            let first = bytes[index];
            let second = bytes[index + 1];
            encoded.push(BASE64URL_ALPHABET[(first >> 2) as usize] as char);
            encoded
                .push(BASE64URL_ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
            encoded.push(BASE64URL_ALPHABET[((second & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }
    encoded
}

fn decode_wire_id(encoded: &str, bytes: &mut [u8]) -> Result<(), WireIdError> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let input = encoded.as_bytes();
    let mut input_index = 0;
    let mut output_index = 0;
    while input_index + 4 <= input.len() {
        let first = value(input[input_index]).ok_or(WireIdError::NonCanonical)?;
        let second = value(input[input_index + 1]).ok_or(WireIdError::NonCanonical)?;
        let third = value(input[input_index + 2]).ok_or(WireIdError::NonCanonical)?;
        let fourth = value(input[input_index + 3]).ok_or(WireIdError::NonCanonical)?;
        if output_index + 3 > bytes.len() {
            return Err(WireIdError::NonCanonical);
        }
        bytes[output_index] = (first << 2) | (second >> 4);
        bytes[output_index + 1] = (second << 4) | (third >> 2);
        bytes[output_index + 2] = (third << 6) | fourth;
        input_index += 4;
        output_index += 3;
    }
    match input.len() - input_index {
        2 => {
            let first = value(input[input_index]).ok_or(WireIdError::NonCanonical)?;
            let second = value(input[input_index + 1]).ok_or(WireIdError::NonCanonical)?;
            if second & 0x0f != 0 || output_index >= bytes.len() {
                return Err(WireIdError::NonCanonical);
            }
            bytes[output_index] = (first << 2) | (second >> 4);
            output_index += 1;
        }
        3 => {
            let first = value(input[input_index]).ok_or(WireIdError::NonCanonical)?;
            let second = value(input[input_index + 1]).ok_or(WireIdError::NonCanonical)?;
            let third = value(input[input_index + 2]).ok_or(WireIdError::NonCanonical)?;
            if third & 0x03 != 0 || output_index + 2 > bytes.len() {
                return Err(WireIdError::NonCanonical);
            }
            bytes[output_index] = (first << 2) | (second >> 4);
            bytes[output_index + 1] = (second << 4) | (third >> 2);
            output_index += 2;
        }
        0 => {}
        _ => return Err(WireIdError::NonCanonical),
    }
    if output_index != bytes.len() {
        return Err(WireIdError::NonCanonical);
    }
    Ok(())
}

macro_rules! wire_id {
    ($name:ident, $size:expr) => {
        /// Canonical non-zero identifier used only by the wallet service wire
        /// protocol. Its JSON representation is fixed-width unpadded base64url;
        /// persisted wallet identifiers deliberately retain their existing
        /// serialization.
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const LENGTH: usize = $size;
            pub const ENCODED_LENGTH: usize = ($size * 4_usize).div_ceil(3);

            pub fn from_bytes(bytes: [u8; $size]) -> Result<Self, WireIdError> {
                if bytes == [0_u8; $size] {
                    return Err(WireIdError::Zero);
                }
                Ok(Self(bytes))
            }

            pub fn parse(encoded: &str) -> Result<Self, WireIdError> {
                if encoded.len() != Self::ENCODED_LENGTH {
                    return Err(WireIdError::NonCanonical);
                }
                let mut bytes = [0_u8; $size];
                decode_wire_id(encoded, &mut bytes)?;
                Self::from_bytes(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}(<redacted>)", stringify!($name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("<redacted>")
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode_wire_id(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let encoded = <&str>::deserialize(deserializer)?;
                Self::parse(encoded).map_err(serde::de::Error::custom)
            }
        }
    };
}

wire_id!(HostSessionId, 32);
wire_id!(WalletServiceSessionId, 32);
wire_id!(WalletSessionId, 32);
wire_id!(HostAuthorityHandleId, 32);
wire_id!(BrowserRuntimeSessionId, 16);
wire_id!(ProviderAuthorityFingerprint, 32);
wire_id!(ProviderRequestId, 16);
wire_id!(ProviderApprovalId, 16);

/// A wallet-local module selector. Canonical marketplace wire identifiers live
/// in `hns-rs`; this enum selects an installed wallet implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleId {
    Handshake,
    Bitcoin,
    Ethereum,
}

impl ModuleId {
    pub const fn asset(self) -> WalletAsset {
        match self {
            Self::Handshake => WalletAsset::Hns,
            Self::Bitcoin => WalletAsset::Btc,
            Self::Ethereum => WalletAsset::Eth,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WalletAsset {
    Hns,
    Btc,
    Eth,
}

/// Integer base units serialized as a decimal string so JavaScript cannot lose
/// precision.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BaseUnits(u128);

impl BaseUnits {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AmountError::Underflow)
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Serialize for BaseUnits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for BaseUnits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        text.parse::<u128>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AmountError {
    #[error("amount overflow")]
    Overflow,
    #[error("amount underflow")]
    Underflow,
    #[error("amount asset mismatch")]
    AssetMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Amount {
    pub asset: WalletAsset,
    pub base_units: BaseUnits,
}

impl Amount {
    pub const fn new(asset: WalletAsset, base_units: u128) -> Self {
        Self {
            asset,
            base_units: BaseUnits::new(base_units),
        }
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        if self.asset != other.asset {
            return Err(AmountError::AssetMismatch);
        }
        Ok(Self {
            asset: self.asset,
            base_units: self.base_units.checked_add(other.base_units)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    Disabled,
    Starting,
    Headers,
    Filters,
    WalletScan,
    Ready,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncStatus {
    pub phase: SyncPhase,
    pub validated_height: u64,
    pub scanned_height: u64,
    pub target_height: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTransactionStatus {
    Prepared,
    Authorized,
    Broadcast,
    Mempool,
    Confirmed,
    Replaced,
    Conflicted,
    Reorged,
    Dropped,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub module: ModuleId,
    pub txid: TransactionHash,
    pub status: LocalTransactionStatus,
    pub net_amount: SignedBaseUnits,
    pub fee: Option<BaseUnits>,
    pub block_height: Option<u64>,
    pub first_seen_unix: Option<u64>,
    pub confirmation_count: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedBaseUnits {
    pub negative: bool,
    pub magnitude: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiveTarget {
    pub module: ModuleId,
    pub account: AccountId,
    pub display: String,
    pub derivation_index: u32,
}

impl ReceiveTarget {
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.display.is_empty() || self.display.len() > 512 {
            return Err(TypeError::InvalidLength {
                field: "receive target",
                maximum: 512,
            });
        }
        Ok(())
    }
}

/// Dedicated Handshake name-owner receive target.
///
/// This is intentionally a different type from [`ReceiveTarget`]: a name
/// owner must be derived from the `HnsName` branch and must never be reused as
/// an ordinary HNS coin receive target. The HNS runtime is responsible for
/// enforcing that role, account, change-zero, and synchronized-index binding
/// before constructing this projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsNameReceiveTarget {
    pub module: ModuleId,
    pub account: AccountId,
    pub display: String,
    pub derivation_index: u32,
}

impl HnsNameReceiveTarget {
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.module != ModuleId::Handshake {
            return Err(TypeError::InvalidModule {
                field: "HNS name receive target",
                expected: "handshake",
            });
        }
        if self.display.is_empty() || self.display.len() > 512 {
            return Err(TypeError::InvalidLength {
                field: "HNS name receive target",
                maximum: 512,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivationReference {
    pub role: KeyRole,
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    HnsCoin,
    HnsName,
    HnsShakedex,
    HnsAtomicSwap,
    HnsIdentity,
    HnsDappSession,
    BitcoinWallet,
    BitcoinAtomicSwap,
    EthereumWallet,
    EthereumAtomicSwap,
    MetadataEncryption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainCapabilities {
    pub receive: bool,
    pub send: bool,
    pub history: bool,
    pub atomic_settlement: bool,
    pub hash_algorithm: HashAlgorithm,
    pub locktime_model: LocktimeModel,
    pub finality_model: FinalityModel,
    pub fee_model: FeeModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Keccak256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocktimeModel {
    None,
    BlockHeight,
    UnixTime,
    SmartContractTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityModel {
    ProofOfWorkConfirmations,
    EthereumFinalizedCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeModel {
    WeightRate,
    GasAndPriority,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCapability {
    Accounts,
    Balance,
    Transactions,
    ReceiveTarget,
    Send,
    Names,
    NameTransfer,
    NameFinalize,
    TypedIdentitySignature,
    NameMarket,
    CrossChainMarket,
    SwapSettlement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Permission,
    ModuleEnablement,
    Send,
    NameTransfer,
    NameFinalize,
    TypedSignature,
    NameMarketOffer,
    NameMarketPurchase,
    MarketIntent,
    FillAcceptance,
    SwapRedeem,
    SwapRefund,
    RecoveryPhraseDisplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    HnsSend,
    NameTransfer,
    NameFinalize,
    ShakedexSeller,
    ShakedexBuyer,
    ShakedexSellerPlan,
    ShakedexBuyerPlan,
    ShakedexValue,
    MarketIntent,
    FillReservation,
    AtomicSwap,
    Refund,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedWorkflowReference {
    pub id: WorkflowId,
    pub kind: WorkflowKind,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TypeError {
    #[error("{field} is empty or exceeds {maximum} bytes")]
    InvalidLength { field: &'static str, maximum: usize },
    #[error("{field} must use the {expected} module")]
    InvalidModule {
        field: &'static str,
        expected: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireIdError {
    #[error("wire identifier must use fixed-width unpadded base64url")]
    NonCanonical,
    #[error("wire identifier cannot be the all-zero sentinel")]
    Zero,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_units_are_json_strings_and_checked() {
        let maximum = BaseUnits::new(u128::MAX);
        assert_eq!(
            serde_json::to_string(&maximum).expect("serialize"),
            format!("\"{}\"", u128::MAX)
        );
        assert_eq!(
            serde_json::from_str::<BaseUnits>("\"42\"").expect("deserialize"),
            BaseUnits::new(42)
        );
        assert_eq!(
            maximum.checked_add(BaseUnits::new(1)),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn module_assets_cannot_be_confused() {
        assert_eq!(ModuleId::Handshake.asset(), WalletAsset::Hns);
        assert_eq!(ModuleId::Bitcoin.asset(), WalletAsset::Btc);
        assert_eq!(ModuleId::Ethereum.asset(), WalletAsset::Eth);
        assert_eq!(
            Amount::new(WalletAsset::Hns, 1).checked_add(Amount::new(WalletAsset::Btc, 1)),
            Err(AmountError::AssetMismatch)
        );
    }

    #[test]
    fn hns_name_receive_target_is_a_bounded_distinct_dto() {
        let target = HnsNameReceiveTarget {
            module: ModuleId::Handshake,
            account: AccountId::new([7; 16]),
            display: "rs1qnameowner".to_owned(),
            derivation_index: 9,
        };
        target.validate().expect("bounded name receive target");
        let encoded = serde_json::to_vec(&target).expect("encode name receive target");
        assert_eq!(
            serde_json::from_slice::<HnsNameReceiveTarget>(&encoded)
                .expect("decode name receive target"),
            target
        );
        assert!(
            HnsNameReceiveTarget {
                display: String::new(),
                ..target.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            HnsNameReceiveTarget {
                display: "x".repeat(513),
                ..target.clone()
            }
            .validate()
            .is_err()
        );
        HnsNameReceiveTarget {
            display: "x".repeat(512),
            ..target
        }
        .validate()
        .expect("maximum-length name receive target");
        assert!(matches!(
            HnsNameReceiveTarget {
                module: ModuleId::Bitcoin,
                account: AccountId::new([7; 16]),
                display: "bc1qnotahnsnameowner".to_owned(),
                derivation_index: 9,
            }
            .validate(),
            Err(TypeError::InvalidModule {
                field: "HNS name receive target",
                expected: "handshake",
            })
        ));
    }

    #[test]
    fn service_wire_ids_have_one_canonical_non_zero_encoding() {
        let id = ProviderRequestId::from_bytes([1_u8; 16]).expect("non-zero identifier");
        let encoded = serde_json::to_string(&id).expect("serialize");
        assert_eq!(encoded, "\"AQEBAQEBAQEBAQEBAQEBAQ\"");
        assert_eq!(
            serde_json::from_str::<ProviderRequestId>(&encoded).expect("deserialize"),
            id
        );
        assert!(serde_json::from_str::<ProviderRequestId>("\"AQEBAQEBAQEBAQEBAQEBAg\"").is_ok());
        assert!(serde_json::from_str::<ProviderRequestId>("\"AQEBAQEBAQEBAQEBAQEBAR\"").is_err());
        assert!(serde_json::from_str::<ProviderRequestId>("\"AQEBAQEBAQEBAQEBAQEBAQ==\"").is_err());
        assert!(ProviderRequestId::from_bytes([0_u8; 16]).is_err());
        assert!(!format!("{id:?}").contains("AQEBA"));
        assert_eq!(format!("{id}"), "<redacted>");
    }
}
