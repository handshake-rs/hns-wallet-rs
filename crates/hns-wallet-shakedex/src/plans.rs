use hns_covenants::{Covenant, hash_name};
use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash as CanonicalTransactionHash};
use hns_swap::NetworkBinding;
use hns_transaction::{Address, Coin, Outpoint};
use hns_wallet_store::{StoredWorkflow, WalletStore};
use hns_wallet_types::{
    AccountId, ObjectHash, TransactionHash, WalletId, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};

use crate::{
    AuthenticatedFixedPriceListing, ShakedexError, SuppliedShakedexLock, VerifiedBuyerFulfillment,
    VerifiedFixedPriceListing, VerifiedSellerRecovery, authenticate_fixed_price_listing,
    verify_signed_buyer_fulfillment, verify_signed_seller_recovery,
};

const SHAKEDEX_TRANSACTION_PLAN_SCHEMA_VERSION: u16 = 1;
pub const MAX_SHAKEDEX_TRANSACTION_PLANS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkEvidence {
    magic: u32,
    genesis: ObjectHash,
}

impl NetworkEvidence {
    fn from_network(network: NetworkBinding) -> Self {
        Self {
            magic: network.magic,
            genesis: ObjectHash::new(*network.genesis.as_bytes()),
        }
    }

    fn to_network(&self) -> NetworkBinding {
        NetworkBinding {
            magic: self.magic,
            genesis: BlockHash::new(self.genesis.into_bytes()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressEvidence {
    version: u8,
    hash: Vec<u8>,
}

impl AddressEvidence {
    pub(crate) fn from_address(address: &Address) -> Result<Self, ShakedexError> {
        address
            .validate()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        Ok(Self {
            version: address.version,
            hash: address.hash.clone(),
        })
    }

    pub(crate) fn to_address(&self) -> Result<Address, ShakedexError> {
        Address::new(self.version, self.hash.clone()).map_err(|_| ShakedexError::InvalidEvidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoinEvidence {
    transaction: TransactionHash,
    output_index: u32,
    value_base_units: u64,
    height: u32,
    coinbase: bool,
    address: AddressEvidence,
    covenant: Vec<u8>,
}

impl CoinEvidence {
    pub(crate) fn from_coin(coin: &Coin) -> Result<Self, ShakedexError> {
        if coin.outpoint.is_null() || coin.value.get() == 0 {
            return Err(ShakedexError::InvalidEvidence);
        }
        let covenant = coin
            .covenant
            .encode()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        Ok(Self {
            transaction: TransactionHash::new(coin.outpoint.transaction_hash.into_bytes()),
            output_index: coin.outpoint.index,
            value_base_units: coin.value.get(),
            height: coin.height.get(),
            coinbase: coin.coinbase,
            address: AddressEvidence::from_address(&coin.address)?,
            covenant,
        })
    }

    pub(crate) fn to_coin(&self) -> Result<Coin, ShakedexError> {
        if self.value_base_units == 0 {
            return Err(ShakedexError::InvalidEvidence);
        }
        let covenant =
            Covenant::decode(&self.covenant).map_err(|_| ShakedexError::InvalidEvidence)?;
        if covenant
            .encode()
            .map_err(|_| ShakedexError::InvalidEvidence)?
            != self.covenant
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let coin = Coin {
            outpoint: Outpoint {
                transaction_hash: CanonicalTransactionHash::new(self.transaction.into_bytes()),
                index: self.output_index,
            },
            value: Dollarydoos::new(self.value_base_units),
            height: Height::new(self.height),
            coinbase: self.coinbase,
            address: self.address.to_address()?,
            covenant,
        };
        if coin.outpoint.is_null() {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(coin)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SellerLockPlanState {
    Locked,
    RecoveryPrepared,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "state")]
enum PersistedSellerLockPlanState {
    Locked,
    RecoveryPrepared {
        recipient: AddressEvidence,
        funding_input_coins: Vec<CoinEvidence>,
        transaction: TransactionHash,
        transaction_bytes: Vec<u8>,
        fee_base_units: u64,
    },
}

/// Restart-safe seller lock/recovery evidence. It is deliberately not a
/// broadcast API and does not establish that the supplied locking coin is
/// current or unspent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SellerLockPlan {
    schema_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    network: NetworkEvidence,
    name: Vec<u8>,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    locking_coin: CoinEvidence,
    state: PersistedSellerLockPlanState,
}

impl SellerLockPlan {
    pub fn locked(
        wallet_id: WalletId,
        account_id: AccountId,
        workflow_id: WorkflowId,
        network: NetworkBinding,
        locking_coin: &Coin,
        seller_public_key: [u8; 33],
    ) -> Result<Self, ShakedexError> {
        let supplied_lock =
            SuppliedShakedexLock::verify(network, locking_coin.clone(), seller_public_key)?;
        let name = supplied_lock.descriptor().name.clone();
        let plan = Self {
            schema_version: SHAKEDEX_TRANSACTION_PLAN_SCHEMA_VERSION,
            wallet_id,
            account_id,
            workflow_id,
            network: NetworkEvidence::from_network(network),
            name_hash: ObjectHash::new(
                hash_name(&name)
                    .map_err(|_| ShakedexError::InvalidEvidence)?
                    .into_bytes(),
            ),
            name,
            seller_public_key: seller_public_key.to_vec(),
            locking_coin: CoinEvidence::from_coin(locking_coin)?,
            state: PersistedSellerLockPlanState::Locked,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn with_recovery(
        &self,
        recovery: &VerifiedSellerRecovery,
        funding_input_coins: &[Coin],
    ) -> Result<Self, ShakedexError> {
        if self.state() != SellerLockPlanState::Locked {
            return Err(ShakedexError::InvalidTransition);
        }
        let (supplied_lock, _) = self.validate_lock()?;
        let verified = verify_signed_seller_recovery(
            &supplied_lock,
            recovery.recipient(),
            funding_input_coins,
            recovery.fee_base_units(),
            recovery.transaction_bytes(),
        )?;
        if verified.transaction() != recovery.transaction() {
            return Err(ShakedexError::InvalidEvidence);
        }
        let mut next = self.clone();
        next.state = PersistedSellerLockPlanState::RecoveryPrepared {
            recipient: AddressEvidence::from_address(recovery.recipient())?,
            funding_input_coins: funding_input_coins
                .iter()
                .map(CoinEvidence::from_coin)
                .collect::<Result<_, _>>()?,
            transaction: recovery.transaction(),
            transaction_bytes: recovery.transaction_bytes().to_vec(),
            fee_base_units: recovery.fee_base_units(),
        };
        next.validate()?;
        Ok(next)
    }

    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub const fn name_hash(&self) -> ObjectHash {
        self.name_hash
    }

    pub(crate) fn locking_coin(&self) -> Result<Coin, ShakedexError> {
        self.locking_coin.to_coin()
    }

    pub fn recovery_transaction(&self) -> Option<TransactionHash> {
        match &self.state {
            PersistedSellerLockPlanState::RecoveryPrepared { transaction, .. } => {
                Some(*transaction)
            }
            PersistedSellerLockPlanState::Locked => None,
        }
    }

    pub fn recovery_transaction_bytes(&self) -> Option<&[u8]> {
        match &self.state {
            PersistedSellerLockPlanState::RecoveryPrepared {
                transaction_bytes, ..
            } => Some(transaction_bytes),
            PersistedSellerLockPlanState::Locked => None,
        }
    }

    pub fn recovery_recipient(&self) -> Result<Option<Address>, ShakedexError> {
        match &self.state {
            PersistedSellerLockPlanState::RecoveryPrepared { recipient, .. } => {
                recipient.to_address().map(Some)
            }
            PersistedSellerLockPlanState::Locked => Ok(None),
        }
    }

    pub fn recovery_fee_base_units(&self) -> Option<u64> {
        match &self.state {
            PersistedSellerLockPlanState::RecoveryPrepared { fee_base_units, .. } => {
                Some(*fee_base_units)
            }
            PersistedSellerLockPlanState::Locked => None,
        }
    }

    pub fn supplied_lock(&self) -> Result<SuppliedShakedexLock, ShakedexError> {
        self.validate_lock().map(|(supplied_lock, _)| supplied_lock)
    }

    pub fn recovery_funding_input_coins(&self) -> Result<Option<Vec<Coin>>, ShakedexError> {
        match &self.state {
            PersistedSellerLockPlanState::RecoveryPrepared {
                funding_input_coins,
                ..
            } => decode_coins(funding_input_coins).map(Some),
            PersistedSellerLockPlanState::Locked => Ok(None),
        }
    }

    pub fn state(&self) -> SellerLockPlanState {
        match &self.state {
            PersistedSellerLockPlanState::Locked => SellerLockPlanState::Locked,
            PersistedSellerLockPlanState::RecoveryPrepared { .. } => {
                SellerLockPlanState::RecoveryPrepared
            }
        }
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        let (supplied_lock, _) = self.validate_lock()?;
        if let PersistedSellerLockPlanState::RecoveryPrepared {
            recipient,
            funding_input_coins,
            transaction,
            transaction_bytes,
            fee_base_units,
        } = &self.state
        {
            let recipient = recipient.to_address()?;
            let funding = decode_coins(funding_input_coins)?;
            let verified = verify_signed_seller_recovery(
                &supplied_lock,
                &recipient,
                &funding,
                *fee_base_units,
                transaction_bytes,
            )?;
            if verified.transaction() != *transaction {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
        Ok(())
    }

    fn validate_lock(&self) -> Result<(SuppliedShakedexLock, Coin), ShakedexError> {
        if self.schema_version != SHAKEDEX_TRANSACTION_PLAN_SCHEMA_VERSION
            || self.seller_public_key.len() != 33
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let seller_public_key: [u8; 33] = self
            .seller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let coin = self.locking_coin.to_coin()?;
        let supplied_lock = SuppliedShakedexLock::verify(
            self.network.to_network(),
            coin.clone(),
            seller_public_key,
        )?;
        if supplied_lock.descriptor().name.as_slice() != self.name
            || hash_name(&self.name)
                .map_err(|_| ShakedexError::InvalidEvidence)?
                .as_bytes()
                != self.name_hash.as_bytes()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok((supplied_lock, coin))
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.wallet_id == other.wallet_id
            && self.account_id == other.account_id
            && self.workflow_id == other.workflow_id
            && self.network == other.network
            && self.name == other.name
            && self.name_hash == other.name_hash
            && self.seller_public_key == other.seller_public_key
            && self.locking_coin == other.locking_coin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuyerLockPlanState {
    OfferVerified,
    FulfillmentPrepared,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "state")]
enum PersistedBuyerLockPlanState {
    OfferVerified,
    FulfillmentPrepared {
        recipient: AddressEvidence,
        funding_input_coins: Vec<CoinEvidence>,
        transaction: TransactionHash,
        transaction_bytes: Vec<u8>,
        fee_base_units: u64,
    },
}

/// Restart-safe buyer offer/fulfillment evidence. Listing and transaction
/// signatures are reauthenticated on every load, without claiming fresh
/// current/unspent chain authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuyerLockPlan {
    schema_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    network: NetworkEvidence,
    name: Vec<u8>,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    locking_coin: CoinEvidence,
    listing_hash: ObjectHash,
    listing_bytes: Vec<u8>,
    verified_at_unix: u64,
    state: PersistedBuyerLockPlanState,
}

impl BuyerLockPlan {
    pub fn offer_verified(
        wallet_id: WalletId,
        account_id: AccountId,
        workflow_id: WorkflowId,
        listing: &VerifiedFixedPriceListing,
        locking_coin: &Coin,
    ) -> Result<Self, ShakedexError> {
        let plan = Self {
            schema_version: SHAKEDEX_TRANSACTION_PLAN_SCHEMA_VERSION,
            wallet_id,
            account_id,
            workflow_id,
            network: NetworkEvidence::from_network(listing.network()),
            name: listing.name().to_vec(),
            name_hash: listing.name_hash()?,
            seller_public_key: listing.seller_public_key().to_vec(),
            locking_coin: CoinEvidence::from_coin(locking_coin)?,
            listing_hash: listing.listing_hash(),
            listing_bytes: listing.encoded().to_vec(),
            verified_at_unix: listing.verified_at_unix(),
            state: PersistedBuyerLockPlanState::OfferVerified,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn with_fulfillment(
        &self,
        fulfillment: &VerifiedBuyerFulfillment,
        funding_input_coins: &[Coin],
    ) -> Result<Self, ShakedexError> {
        if self.state() != BuyerLockPlanState::OfferVerified {
            return Err(ShakedexError::InvalidTransition);
        }
        let (listing, supplied_lock) = self.validate_listing_and_lock()?;
        let verified = verify_signed_buyer_fulfillment(
            &listing,
            &supplied_lock,
            fulfillment.recipient(),
            funding_input_coins,
            fulfillment.fee_base_units(),
            fulfillment.transaction_bytes(),
        )?;
        if verified.transaction() != fulfillment.transaction() {
            return Err(ShakedexError::InvalidEvidence);
        }
        let mut next = self.clone();
        next.state = PersistedBuyerLockPlanState::FulfillmentPrepared {
            recipient: AddressEvidence::from_address(fulfillment.recipient())?,
            funding_input_coins: funding_input_coins
                .iter()
                .map(CoinEvidence::from_coin)
                .collect::<Result<_, _>>()?,
            transaction: fulfillment.transaction(),
            transaction_bytes: fulfillment.transaction_bytes().to_vec(),
            fee_base_units: fulfillment.fee_base_units(),
        };
        next.validate()?;
        Ok(next)
    }

    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub(crate) const fn name_hash(&self) -> ObjectHash {
        self.name_hash
    }

    pub(crate) fn locking_coin(&self) -> Result<Coin, ShakedexError> {
        self.locking_coin.to_coin()
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        self.listing_hash
    }

    pub fn listing_bytes(&self) -> &[u8] {
        &self.listing_bytes
    }

    pub const fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    pub fn fulfillment_transaction(&self) -> Option<TransactionHash> {
        match &self.state {
            PersistedBuyerLockPlanState::FulfillmentPrepared { transaction, .. } => {
                Some(*transaction)
            }
            PersistedBuyerLockPlanState::OfferVerified => None,
        }
    }

    pub fn fulfillment_transaction_bytes(&self) -> Option<&[u8]> {
        match &self.state {
            PersistedBuyerLockPlanState::FulfillmentPrepared {
                transaction_bytes, ..
            } => Some(transaction_bytes),
            PersistedBuyerLockPlanState::OfferVerified => None,
        }
    }

    pub fn fulfillment_recipient(&self) -> Result<Option<Address>, ShakedexError> {
        match &self.state {
            PersistedBuyerLockPlanState::FulfillmentPrepared { recipient, .. } => {
                recipient.to_address().map(Some)
            }
            PersistedBuyerLockPlanState::OfferVerified => Ok(None),
        }
    }

    pub fn fulfillment_fee_base_units(&self) -> Option<u64> {
        match &self.state {
            PersistedBuyerLockPlanState::FulfillmentPrepared { fee_base_units, .. } => {
                Some(*fee_base_units)
            }
            PersistedBuyerLockPlanState::OfferVerified => None,
        }
    }

    pub fn supplied_lock(&self) -> Result<SuppliedShakedexLock, ShakedexError> {
        self.validate_listing_and_lock()
            .map(|(_, supplied_lock)| supplied_lock)
    }

    pub fn authenticated_listing(&self) -> Result<AuthenticatedFixedPriceListing, ShakedexError> {
        self.validate_listing_and_lock().map(|(listing, _)| listing)
    }

    pub fn fulfillment_funding_input_coins(&self) -> Result<Option<Vec<Coin>>, ShakedexError> {
        match &self.state {
            PersistedBuyerLockPlanState::FulfillmentPrepared {
                funding_input_coins,
                ..
            } => decode_coins(funding_input_coins).map(Some),
            PersistedBuyerLockPlanState::OfferVerified => Ok(None),
        }
    }

    pub fn state(&self) -> BuyerLockPlanState {
        match &self.state {
            PersistedBuyerLockPlanState::OfferVerified => BuyerLockPlanState::OfferVerified,
            PersistedBuyerLockPlanState::FulfillmentPrepared { .. } => {
                BuyerLockPlanState::FulfillmentPrepared
            }
        }
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        let (listing, supplied_lock) = self.validate_listing_and_lock()?;
        if let PersistedBuyerLockPlanState::FulfillmentPrepared {
            recipient,
            funding_input_coins,
            transaction,
            transaction_bytes,
            fee_base_units,
        } = &self.state
        {
            let recipient = recipient.to_address()?;
            let funding = decode_coins(funding_input_coins)?;
            let verified = verify_signed_buyer_fulfillment(
                &listing,
                &supplied_lock,
                &recipient,
                &funding,
                *fee_base_units,
                transaction_bytes,
            )?;
            if verified.transaction() != *transaction {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
        Ok(())
    }

    fn validate_listing_and_lock(
        &self,
    ) -> Result<(AuthenticatedFixedPriceListing, SuppliedShakedexLock), ShakedexError> {
        if self.schema_version != SHAKEDEX_TRANSACTION_PLAN_SCHEMA_VERSION
            || self.seller_public_key.len() != 33
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let listing = authenticate_fixed_price_listing(&self.listing_bytes, self.listing_hash)?;
        let seller_public_key: [u8; 33] = self
            .seller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let coin = self.locking_coin.to_coin()?;
        let network = self.network.to_network();
        crate::verify_fixed_price_listing(
            &self.listing_bytes,
            self.listing_hash,
            network,
            self.verified_at_unix,
            &coin,
        )?;
        let supplied_lock = SuppliedShakedexLock::verify(network, coin.clone(), seller_public_key)?;
        listing
            .proof()
            .verify_for_network(network, &coin)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        if listing.network() != network
            || listing.name() != self.name
            || listing.name_hash()? != self.name_hash
            || listing.seller_public_key().as_slice() != self.seller_public_key
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok((listing, supplied_lock))
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.wallet_id == other.wallet_id
            && self.account_id == other.account_id
            && self.workflow_id == other.workflow_id
            && self.network == other.network
            && self.name == other.name
            && self.name_hash == other.name_hash
            && self.seller_public_key == other.seller_public_key
            && self.locking_coin == other.locking_coin
            && self.listing_hash == other.listing_hash
            && self.listing_bytes == other.listing_bytes
            && self.verified_at_unix == other.verified_at_unix
    }
}

pub struct StoredSellerLockPlan {
    pub revision: u64,
    pub plan: SellerLockPlan,
}

pub struct StoredBuyerLockPlan {
    pub revision: u64,
    pub plan: BuyerLockPlan,
}

pub fn save_seller_lock_plan(
    store: &mut WalletStore,
    expected_revision: u64,
    plan: &SellerLockPlan,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    plan.validate()?;
    if let Some(revision) = validate_seller_save_transition(store, expected_revision, plan)? {
        return Ok(revision);
    }
    store
        .save_workflow(
            plan.workflow_id,
            WorkflowKind::ShakedexSellerPlan,
            expected_revision,
            plan,
            plan.state() == SellerLockPlanState::RecoveryPrepared,
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}

pub fn save_buyer_lock_plan(
    store: &mut WalletStore,
    expected_revision: u64,
    plan: &BuyerLockPlan,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    plan.validate()?;
    if let Some(revision) = validate_buyer_save_transition(store, expected_revision, plan)? {
        return Ok(revision);
    }
    store
        .save_workflow(
            plan.workflow_id,
            WorkflowKind::ShakedexBuyerPlan,
            expected_revision,
            plan,
            plan.state() == BuyerLockPlanState::FulfillmentPrepared,
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}

fn validate_seller_save_transition(
    store: &WalletStore,
    expected_revision: u64,
    plan: &SellerLockPlan,
) -> Result<Option<u64>, ShakedexError> {
    let Some(current) = load_seller_lock_plan(store, plan.workflow_id)? else {
        if expected_revision != 0 {
            return Err(ShakedexError::StaleRevision);
        }
        if plan.state() != SellerLockPlanState::Locked {
            return Err(ShakedexError::InvalidTransition);
        }
        return Ok(None);
    };
    if current.plan == *plan
        && (expected_revision == current.revision
            || expected_revision.checked_add(1) == Some(current.revision))
    {
        return Ok(Some(current.revision));
    }
    if current.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    if !current.plan.same_identity(plan) {
        return Err(ShakedexError::InvalidEvidence);
    }
    if current.plan.state() != SellerLockPlanState::Locked
        || plan.state() != SellerLockPlanState::RecoveryPrepared
    {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(None)
}

fn validate_buyer_save_transition(
    store: &WalletStore,
    expected_revision: u64,
    plan: &BuyerLockPlan,
) -> Result<Option<u64>, ShakedexError> {
    let Some(current) = load_buyer_lock_plan(store, plan.workflow_id)? else {
        if expected_revision != 0 {
            return Err(ShakedexError::StaleRevision);
        }
        if plan.state() != BuyerLockPlanState::OfferVerified {
            return Err(ShakedexError::InvalidTransition);
        }
        return Ok(None);
    };
    if current.plan == *plan
        && (expected_revision == current.revision
            || expected_revision.checked_add(1) == Some(current.revision))
    {
        return Ok(Some(current.revision));
    }
    if current.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    if !current.plan.same_identity(plan) {
        return Err(ShakedexError::InvalidEvidence);
    }
    if current.plan.state() != BuyerLockPlanState::OfferVerified
        || plan.state() != BuyerLockPlanState::FulfillmentPrepared
    {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(None)
}

pub fn load_seller_lock_plan(
    store: &WalletStore,
    workflow_id: WorkflowId,
) -> Result<Option<StoredSellerLockPlan>, ShakedexError> {
    store
        .load_workflow::<SellerLockPlan>(workflow_id)?
        .map(validate_stored_seller)
        .transpose()
}

pub fn load_buyer_lock_plan(
    store: &WalletStore,
    workflow_id: WorkflowId,
) -> Result<Option<StoredBuyerLockPlan>, ShakedexError> {
    store
        .load_workflow::<BuyerLockPlan>(workflow_id)?
        .map(validate_stored_buyer)
        .transpose()
}

pub fn list_seller_lock_plans(
    store: &WalletStore,
) -> Result<Vec<StoredSellerLockPlan>, ShakedexError> {
    store
        .list_workflows_complete::<SellerLockPlan>(
            WorkflowKind::ShakedexSellerPlan,
            MAX_SHAKEDEX_TRANSACTION_PLANS,
        )?
        .into_iter()
        .map(validate_stored_seller)
        .collect()
}

pub fn list_buyer_lock_plans(
    store: &WalletStore,
) -> Result<Vec<StoredBuyerLockPlan>, ShakedexError> {
    store
        .list_workflows_complete::<BuyerLockPlan>(
            WorkflowKind::ShakedexBuyerPlan,
            MAX_SHAKEDEX_TRANSACTION_PLANS,
        )?
        .into_iter()
        .map(validate_stored_buyer)
        .collect()
}

fn validate_stored_seller(
    stored: StoredWorkflow<SellerLockPlan>,
) -> Result<StoredSellerLockPlan, ShakedexError> {
    if stored.kind != WorkflowKind::ShakedexSellerPlan
        || stored.id != stored.state.workflow_id
        || stored.irreversible_broadcast_prepared
            != (stored.state.state() == SellerLockPlanState::RecoveryPrepared)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    stored.state.validate()?;
    Ok(StoredSellerLockPlan {
        revision: stored.revision,
        plan: stored.state,
    })
}

fn validate_stored_buyer(
    stored: StoredWorkflow<BuyerLockPlan>,
) -> Result<StoredBuyerLockPlan, ShakedexError> {
    if stored.kind != WorkflowKind::ShakedexBuyerPlan
        || stored.id != stored.state.workflow_id
        || stored.irreversible_broadcast_prepared
            != (stored.state.state() == BuyerLockPlanState::FulfillmentPrepared)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    stored.state.validate()?;
    Ok(StoredBuyerLockPlan {
        revision: stored.revision,
        plan: stored.state,
    })
}

fn decode_coins(encoded: &[CoinEvidence]) -> Result<Vec<Coin>, ShakedexError> {
    if encoded.is_empty() || encoded.len() > crate::MAX_SHAKEDEX_FUNDING_INPUTS {
        return Err(ShakedexError::InvalidEvidence);
    }
    encoded.iter().map(CoinEvidence::to_coin).collect()
}
