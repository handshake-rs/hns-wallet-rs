use hns_covenants::{hash_name, validate_name};
use hns_marketplace_protocol::ShakescapeRegistryVersion;
use hns_primitives::Dollarydoos;
use hns_swap::{FixedPriceListing, ListingCancellation, SwapProof};
use hns_transaction::Address;
use hns_wallet_hns::{
    HnsBackend, HnsClock, HnsShakedexKeyAllocationRequest, HnsShakedexSellerTerms, HnsWalletRuntime,
};
use hns_wallet_store::{SharedWalletStore, StoredWorkflow, WalletStore};
use hns_wallet_types::{AccountId, BaseUnits, ObjectHash, WalletId, WorkflowId, WorkflowKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::outbox::{
    enqueue_shakescape_cancellation_and_save_workflow, enqueue_shakescape_offer_and_save_workflow,
};
use crate::{
    ShakedexError, ShakescapeOutboxState, authenticate_fixed_price_listing,
    authenticate_listing_cancellation, decode_shakescape_authenticated_cancellation,
    decode_shakescape_authenticated_offer, encode_shakescape_cancellation, encode_shakescape_offer,
    load_shakescape_publication_outbox, shakescape_outbox_envelope_id, verify_fixed_price_listing,
    verify_listing_cancellation,
};

const SELLER_OFFER_SCHEMA_VERSION: u16 = 1;
pub const MAX_SELLER_OFFER_WORKFLOWS: usize = 10_000;
pub const MIN_SELLER_LISTING_LIFETIME_SECONDS: u64 = 10 * 60;
pub const MAX_SELLER_LISTING_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
const LOCKTIME_SAFETY_SECONDS: u64 = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakedexSellerPolicy {
    pub marketplace_fee_address: Option<Address>,
    pub marketplace_fee: BaseUnits,
}

impl ShakedexSellerPolicy {
    pub fn no_marketplace_fee() -> Self {
        Self {
            marketplace_fee_address: None,
            marketplace_fee: BaseUnits::ZERO,
        }
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        match (&self.marketplace_fee_address, self.marketplace_fee.get()) {
            (None, 0) => Ok(()),
            (Some(address), fee) if fee > 0 && fee <= u128::from(u64::MAX) => address
                .validate()
                .map_err(|_| ShakedexError::InvalidEvidence),
            _ => Err(ShakedexError::InvalidEvidence),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareSellerOffer {
    pub name: Vec<u8>,
    pub price: BaseUnits,
    pub request_nonce: u64,
    pub listing_lifetime_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SellerOfferStage {
    NameLockRequired,
    PublicationQueued,
    CancellationQueued,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedSellerListing {
    listing_hash: ObjectHash,
    listing_bytes: Vec<u8>,
    request_id: u64,
    envelope_id: ObjectHash,
    envelope_bytes: Vec<u8>,
    queued_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedSellerCancellation {
    cancellation_hash: ObjectHash,
    cancellation_bytes: Vec<u8>,
    request_id: u64,
    envelope_id: ObjectHash,
    envelope_bytes: Vec<u8>,
    queued_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SellerOfferWorkflow {
    schema_version: u16,
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    request_nonce: u64,
    allocation_request: HnsShakedexKeyAllocationRequest,
    lock_address: String,
    listing_lifetime_seconds: u64,
    created_at_unix: u64,
    stage: SellerOfferStage,
    queued_listing: Option<QueuedSellerListing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queued_cancellation: Option<QueuedSellerCancellation>,
}

impl SellerOfferWorkflow {
    fn validate(&self) -> Result<(), ShakedexError> {
        if self.schema_version != SELLER_OFFER_SCHEMA_VERSION
            || self.wallet_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.account_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.workflow_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.request_nonce == 0
            || self.allocation_request.workflow_id != self.workflow_id
            || !validate_name(&self.allocation_request.name)
            || self.lock_address.is_empty()
            || self.lock_address.len() > 128
            || !self.lock_address.is_ascii()
            || !valid_listing_lifetime(self.listing_lifetime_seconds)
            || self.created_at_unix == 0
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.allocation_request
            .seller_terms
            .validate()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        if seller_offer_workflow_id(
            self.wallet_id,
            self.account_id,
            &self.allocation_request.name,
            self.request_nonce,
        )? != self.workflow_id
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        match (self.stage, &self.queued_listing, &self.queued_cancellation) {
            (SellerOfferStage::NameLockRequired, None, None) => Ok(()),
            (SellerOfferStage::PublicationQueued, Some(queued), None) => {
                validate_queued_listing(self, queued).map(|_| ())
            }
            (
                SellerOfferStage::CancellationQueued,
                Some(queued_listing),
                Some(queued_cancellation),
            ) => {
                let listing = validate_queued_listing(self, queued_listing)?;
                let cancellation = authenticate_listing_cancellation(
                    &queued_cancellation.cancellation_bytes,
                    queued_listing.listing_hash,
                    queued_cancellation.cancellation_hash,
                )?;
                let (request_id, envelope_cancellation) =
                    decode_shakescape_authenticated_cancellation(
                        &queued_cancellation.envelope_bytes,
                        ShakescapeRegistryVersion::V1,
                        queued_listing.listing_hash,
                        queued_cancellation.cancellation_hash,
                    )?;
                if request_id != queued_cancellation.request_id
                    || envelope_cancellation.encoded() != cancellation.encoded()
                    || cancellation.seller_public_key() != listing.seller_public_key()
                    || cancellation.sequence() != listing.sequence().saturating_add(1)
                    || cancellation.created_at_unix() < listing.created_at_unix()
                    || cancellation.expires_at_unix() < listing.expires_at_unix()
                    || queued_cancellation.queued_at_unix != cancellation.created_at_unix()
                    || shakescape_outbox_envelope_id(&queued_cancellation.envelope_bytes)?
                        != queued_cancellation.envelope_id
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
                Ok(())
            }
            _ => Err(ShakedexError::InvalidEvidence),
        }
    }
}

fn validate_queued_listing(
    workflow: &SellerOfferWorkflow,
    queued: &QueuedSellerListing,
) -> Result<crate::AuthenticatedFixedPriceListing, ShakedexError> {
    let listing = authenticate_fixed_price_listing(&queued.listing_bytes, queued.listing_hash)?;
    let (request_id, envelope_listing) = decode_shakescape_authenticated_offer(
        &queued.envelope_bytes,
        ShakescapeRegistryVersion::V1,
        queued.listing_hash,
    )?;
    if request_id != queued.request_id
        || envelope_listing.encoded() != listing.encoded()
        || listing.name() != workflow.allocation_request.name
        || listing.price_base_units() != workflow.allocation_request.seller_terms.price.get()
        || listing.proof().payment_address
            != workflow.allocation_request.seller_terms.payment_address
        || listing.proof().lock_time_seconds
            != workflow.allocation_request.seller_terms.lock_time_seconds
        || listing.proof().fee_address != workflow.allocation_request.seller_terms.fee_address
        || listing.proof().fee != workflow.allocation_request.seller_terms.fee
        || listing.expires_at_unix()
            != listing
                .created_at_unix()
                .checked_add(workflow.listing_lifetime_seconds)
                .ok_or(ShakedexError::Invariant)?
        || listing.sequence() != 1
        || queued.queued_at_unix != listing.created_at_unix()
        || shakescape_outbox_envelope_id(&queued.envelope_bytes)? != queued.envelope_id
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(listing)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SellerOfferPreview {
    pub revision: u64,
    pub workflow_id: WorkflowId,
    pub request_nonce: u64,
    pub stage: SellerOfferStage,
    pub name: Vec<u8>,
    pub price: BaseUnits,
    pub lock_address: String,
    pub listing_lifetime_seconds: u64,
    pub listing_hash: Option<ObjectHash>,
    pub cancellation_hash: Option<ObjectHash>,
    pub publication_state: Option<ShakescapeOutboxState>,
}

pub(crate) struct SellerOfferRuntime<'a, B, C> {
    hns: &'a HnsWalletRuntime<B, C>,
    store: SharedWalletStore,
}

impl<'a, B: HnsBackend, C: HnsClock> SellerOfferRuntime<'a, B, C> {
    pub(crate) fn new(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(Self { hns, store })
    }

    pub(crate) fn prepare(
        &self,
        request: PrepareSellerOffer,
        policy: &ShakedexSellerPolicy,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        policy.validate()?;
        if request.request_nonce == 0
            || !validate_name(&request.name)
            || request.price.is_zero()
            || request.price.get() > u128::from(u64::MAX)
            || !valid_listing_lifetime(request.listing_lifetime_seconds)
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let config = self.hns.configured_runtime_config()?;
        let workflow_id = seller_offer_workflow_id(
            config.wallet_id,
            config.account_id,
            &request.name,
            request.request_nonce,
        )?;
        if let Some(stored) = self.load(workflow_id)? {
            validate_exact_request(&stored.state, &request, policy)?;
            return self.preview(stored);
        }
        let now_unix = self.hns.shakedex_now_unix()?;
        let payment_address = self.hns.shakedex_payment_receive_address()?;
        let terms = HnsShakedexSellerTerms {
            payment_address,
            price: Dollarydoos::new(
                u64::try_from(request.price.get()).map_err(|_| ShakedexError::InvalidEvidence)?,
            ),
            lock_time_seconds: now_unix.saturating_sub(LOCKTIME_SAFETY_SECONDS),
            fee_address: policy.marketplace_fee_address.clone(),
            fee: Dollarydoos::new(
                u64::try_from(policy.marketplace_fee.get())
                    .map_err(|_| ShakedexError::InvalidEvidence)?,
            ),
        };
        let allocation_request = HnsShakedexKeyAllocationRequest {
            workflow_id,
            name: request.name,
            seller_terms: terms,
        };
        let allocation = self
            .hns
            .allocate_shakedex_key(&allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let lock_address = self
            .hns
            .shakedex_lock_address(&allocation)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let workflow = SellerOfferWorkflow {
            schema_version: SELLER_OFFER_SCHEMA_VERSION,
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            workflow_id,
            request_nonce: request.request_nonce,
            allocation_request,
            lock_address,
            listing_lifetime_seconds: request.listing_lifetime_seconds,
            created_at_unix: now_unix,
            stage: SellerOfferStage::NameLockRequired,
            queued_listing: None,
            queued_cancellation: None,
        };
        workflow.validate()?;
        let revision = self.store.try_with_store_mut(|store| {
            store
                .save_workflow(
                    workflow_id,
                    WorkflowKind::ShakedexSellerOffer,
                    0,
                    &workflow,
                    false,
                    now_unix,
                )
                .map_err(ShakedexError::from)
        })?;
        self.preview(StoredSellerOffer {
            revision,
            state: workflow,
        })
    }

    pub(crate) fn queue_listing(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        let stored = self
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        if stored.state.stage != SellerOfferStage::NameLockRequired {
            return self.preview(stored);
        }
        let current_lock = self
            .hns
            .verify_allocated_current_shakedex_lock(&stored.state.allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let signer = self
            .hns
            .load_shakedex_signer(&stored.state.allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let now_unix = self.hns.shakedex_now_unix()?;
        let terms = &stored.state.allocation_request.seller_terms;
        let mut proof = SwapProof {
            network: current_lock.descriptor().network,
            locking_outpoint: current_lock.locking_coin().outpoint,
            name: stored.state.allocation_request.name.clone(),
            seller_public_key: *signer.compressed_public_key(),
            payment_address: terms.payment_address.clone(),
            price: terms.price,
            lock_time_seconds: terms.lock_time_seconds,
            signature: None,
            fee_address: terms.fee_address.clone(),
            fee: terms.fee,
        };
        signer
            .sign_swap_proof(&current_lock, &mut proof)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let expires_at = now_unix
            .checked_add(stored.state.listing_lifetime_seconds)
            .ok_or(ShakedexError::Invariant)?;
        let mut listing = FixedPriceListing {
            proof,
            created_at: now_unix,
            expires_at,
            sequence: 1,
            signature: None,
        };
        signer
            .sign_fixed_price_listing(&current_lock, &mut listing, now_unix)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let listing_bytes = listing
            .encode()
            .map_err(|_| ShakedexError::InvalidListing)?;
        let listing_hash = ObjectHash::new(
            listing
                .listing_hash()
                .map_err(|_| ShakedexError::InvalidListing)?,
        );
        let verified = verify_fixed_price_listing(
            &listing_bytes,
            listing_hash,
            current_lock.descriptor().network,
            now_unix,
            current_lock.locking_coin(),
        )?;
        let request_id = seller_offer_request_id(workflow_id, listing_hash);
        let envelope_bytes = encode_shakescape_offer(
            ShakescapeRegistryVersion::V1,
            request_id,
            verified.authenticated(),
        )?;
        let envelope_id = shakescape_outbox_envelope_id(&envelope_bytes)?;
        let mut next = stored.state.clone();
        next.stage = SellerOfferStage::PublicationQueued;
        next.queued_listing = Some(QueuedSellerListing {
            listing_hash,
            listing_bytes,
            request_id,
            envelope_id,
            envelope_bytes: envelope_bytes.clone(),
            queued_at_unix: now_unix,
        });
        next.validate()?;
        let (revision, _, committed_envelope_id) = self.store.try_with_store_mut(|store| {
            let current =
                load_seller_offer(store, workflow_id)?.ok_or(ShakedexError::InvalidTransition)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(ShakedexError::StaleRevision);
            }
            enqueue_shakescape_offer_and_save_workflow(
                store,
                workflow_id,
                stored.revision,
                &next,
                &envelope_bytes,
                verified.authenticated(),
                now_unix,
            )
        })?;
        if committed_envelope_id != envelope_id {
            return Err(ShakedexError::Invariant);
        }
        self.preview(StoredSellerOffer {
            revision,
            state: next,
        })
    }

    pub(crate) fn queue_cancellation(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<SellerOfferPreview, ShakedexError> {
        let stored = self
            .load(workflow_id)?
            .ok_or(ShakedexError::InvalidTransition)?;
        if stored.state.stage == SellerOfferStage::CancellationQueued {
            return self.preview(stored);
        }
        if stored.state.stage != SellerOfferStage::PublicationQueued {
            return Err(ShakedexError::InvalidTransition);
        }
        let queued_listing = stored
            .state
            .queued_listing
            .as_ref()
            .ok_or(ShakedexError::InvalidEvidence)?;
        let listing = validate_queued_listing(&stored.state, queued_listing)?;
        let current_lock = self
            .hns
            .verify_allocated_current_shakedex_lock(&stored.state.allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let signer = self
            .hns
            .load_shakedex_signer(&stored.state.allocation_request)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let now_unix = self.hns.shakedex_now_unix()?;
        let sequence = listing
            .sequence()
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        let mut cancellation = ListingCancellation::for_listing(
            listing.canonical(),
            now_unix,
            listing.expires_at_unix(),
            sequence,
        )
        .map_err(|_| ShakedexError::InvalidCancellation)?;
        signer
            .sign_listing_cancellation(
                &mut cancellation,
                listing.canonical(),
                current_lock.locking_coin(),
                now_unix,
            )
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        let cancellation_bytes = cancellation
            .encode()
            .map_err(|_| ShakedexError::InvalidCancellation)?;
        let verified = verify_listing_cancellation(
            &cancellation_bytes,
            &listing,
            current_lock.descriptor().network,
            now_unix,
        )?;
        let cancellation_hash = verified.cancellation_hash();
        let request_id = seller_cancellation_request_id(workflow_id, cancellation_hash);
        let envelope_bytes =
            encode_shakescape_cancellation(ShakescapeRegistryVersion::V1, request_id, &verified)?;
        let envelope_id = shakescape_outbox_envelope_id(&envelope_bytes)?;
        let mut next = stored.state.clone();
        next.stage = SellerOfferStage::CancellationQueued;
        next.queued_cancellation = Some(QueuedSellerCancellation {
            cancellation_hash,
            cancellation_bytes,
            request_id,
            envelope_id,
            envelope_bytes: envelope_bytes.clone(),
            queued_at_unix: now_unix,
        });
        next.validate()?;
        let (revision, _, committed_envelope_id) = self.store.try_with_store_mut(|store| {
            let current =
                load_seller_offer(store, workflow_id)?.ok_or(ShakedexError::InvalidTransition)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(ShakedexError::StaleRevision);
            }
            enqueue_shakescape_cancellation_and_save_workflow(
                store,
                workflow_id,
                stored.revision,
                &next,
                &envelope_bytes,
                &verified,
                now_unix,
            )
        })?;
        if committed_envelope_id != envelope_id {
            return Err(ShakedexError::Invariant);
        }
        self.preview(StoredSellerOffer {
            revision,
            state: next,
        })
    }

    pub(crate) fn load_preview(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<SellerOfferPreview>, ShakedexError> {
        self.load(workflow_id)?
            .map(|stored| self.preview(stored))
            .transpose()
    }

    pub(crate) fn allocation_request(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<HnsShakedexKeyAllocationRequest, ShakedexError> {
        self.load(workflow_id)?
            .map(|stored| stored.state.allocation_request)
            .ok_or(ShakedexError::InvalidTransition)
    }

    pub(crate) fn list_previews(&self) -> Result<Vec<SellerOfferPreview>, ShakedexError> {
        let stored = self.store.try_with_store(|store| {
            store
                .list_workflows_complete::<SellerOfferWorkflow>(
                    WorkflowKind::ShakedexSellerOffer,
                    MAX_SELLER_OFFER_WORKFLOWS,
                )
                .map_err(ShakedexError::from)
        })?;
        stored
            .into_iter()
            .map(validate_stored_seller_offer)
            .map(|stored| stored.and_then(|stored| self.preview(stored)))
            .collect()
    }

    fn load(&self, workflow_id: WorkflowId) -> Result<Option<StoredSellerOffer>, ShakedexError> {
        self.store
            .try_with_store(|store| load_seller_offer(store, workflow_id))
    }

    fn preview(&self, stored: StoredSellerOffer) -> Result<SellerOfferPreview, ShakedexError> {
        stored.state.validate()?;
        let outbox = self
            .store
            .try_with_store(load_shakescape_publication_outbox)?;
        let listing_hash = stored
            .state
            .queued_listing
            .as_ref()
            .map(|queued| queued.listing_hash);
        let cancellation_hash = stored
            .state
            .queued_cancellation
            .as_ref()
            .map(|queued| queued.cancellation_hash);
        let publication_state = match &stored.state.queued_cancellation {
            Some(queued) => outbox.outbox.state(queued.envelope_id),
            None => stored
                .state
                .queued_listing
                .as_ref()
                .and_then(|queued| outbox.outbox.state(queued.envelope_id)),
        };
        Ok(SellerOfferPreview {
            revision: stored.revision,
            workflow_id: stored.state.workflow_id,
            request_nonce: stored.state.request_nonce,
            stage: stored.state.stage,
            name: stored.state.allocation_request.name,
            price: BaseUnits::new(u128::from(
                stored.state.allocation_request.seller_terms.price.get(),
            )),
            lock_address: stored.state.lock_address,
            listing_lifetime_seconds: stored.state.listing_lifetime_seconds,
            listing_hash,
            cancellation_hash,
            publication_state,
        })
    }
}

struct StoredSellerOffer {
    revision: u64,
    state: SellerOfferWorkflow,
}

fn load_seller_offer(
    store: &WalletStore,
    workflow_id: WorkflowId,
) -> Result<Option<StoredSellerOffer>, ShakedexError> {
    store
        .load_workflow::<SellerOfferWorkflow>(workflow_id)?
        .map(validate_stored_seller_offer)
        .transpose()
}

fn validate_stored_seller_offer(
    stored: StoredWorkflow<SellerOfferWorkflow>,
) -> Result<StoredSellerOffer, ShakedexError> {
    if stored.kind != WorkflowKind::ShakedexSellerOffer
        || stored.id != stored.state.workflow_id
        || stored.irreversible_broadcast_prepared
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    stored.state.validate()?;
    Ok(StoredSellerOffer {
        revision: stored.revision,
        state: stored.state,
    })
}

fn validate_exact_request(
    workflow: &SellerOfferWorkflow,
    request: &PrepareSellerOffer,
    policy: &ShakedexSellerPolicy,
) -> Result<(), ShakedexError> {
    let terms = &workflow.allocation_request.seller_terms;
    if workflow.request_nonce != request.request_nonce
        || workflow.allocation_request.name != request.name
        || terms.price.get() as u128 != request.price.get()
        || workflow.listing_lifetime_seconds != request.listing_lifetime_seconds
        || terms.fee_address != policy.marketplace_fee_address
        || u128::from(terms.fee.get()) != policy.marketplace_fee.get()
    {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(())
}

fn valid_listing_lifetime(lifetime: u64) -> bool {
    (MIN_SELLER_LISTING_LIFETIME_SECONDS..=MAX_SELLER_LISTING_LIFETIME_SECONDS).contains(&lifetime)
}

pub fn seller_offer_workflow_id(
    wallet_id: WalletId,
    account_id: AccountId,
    name: &[u8],
    request_nonce: u64,
) -> Result<WorkflowId, ShakedexError> {
    let name_hash = hash_name(name).map_err(|_| ShakedexError::InvalidName)?;
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-seller-offer/v1");
    hasher.update(wallet_id.as_bytes());
    hasher.update(account_id.as_bytes());
    hasher.update(name_hash.as_bytes());
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(WorkflowId::new(id))
}

fn seller_offer_request_id(workflow_id: WorkflowId, listing_hash: ObjectHash) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-seller-offer-request/v1");
    hasher.update(workflow_id.as_bytes());
    hasher.update(listing_hash.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_bytes = [0_u8; 8];
    request_bytes.copy_from_slice(&digest[..8]);
    let request_id = u64::from_be_bytes(request_bytes);
    request_id.max(1)
}

fn seller_cancellation_request_id(workflow_id: WorkflowId, cancellation_hash: ObjectHash) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-seller-cancellation-request/v1");
    hasher.update(workflow_id.as_bytes());
    hasher.update(cancellation_hash.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_bytes = [0_u8; 8];
    request_bytes.copy_from_slice(&digest[..8]);
    let request_id = u64::from_be_bytes(request_bytes);
    request_id.max(1)
}
