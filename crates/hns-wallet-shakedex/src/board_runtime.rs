use std::collections::BTreeSet;

use hns_marketplace_protocol::{NameMarketMessage, ShakescapeRegistryVersion};
use hns_wallet_hns::{
    CurrentShakedexLockQuery, HnsAccountReadRuntime, HnsBackend, HnsClock, HnsWalletRuntime,
    MAX_CURRENT_SHAKEDEX_LOCK_BATCH, SystemClock, VerifiedCurrentShakedexLock,
    VerifiedCurrentShakedexLockBatch, VerifiedHnsBoardContext,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::ObjectHash;

use crate::board::{
    load_name_market_board_offers, load_name_market_board_offers_from_snapshot,
    load_name_market_board_state_from_snapshot, save_loaded_name_market_board_with_guard,
};
use crate::{
    AuthenticatedFixedPriceListing, BoardOfferStatus, ShakedexError, VerifiedFixedPriceListing,
    authenticate_fixed_price_listing, decode_shakescape_authenticated_cancellation,
    decode_shakescape_authenticated_offer, verify_authenticated_fixed_price_listing,
    verify_authenticated_listing_cancellation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakescapeBoardOfferAdmission {
    Inserted {
        request_id: u64,
        listing_hash: ObjectHash,
        revision: u64,
    },
    Updated {
        request_id: u64,
        listing_hash: ObjectHash,
        revision: u64,
    },
    Existing {
        request_id: u64,
        listing_hash: ObjectHash,
        revision: u64,
    },
}

impl ShakescapeBoardOfferAdmission {
    pub const fn request_id(self) -> u64 {
        match self {
            Self::Inserted { request_id, .. }
            | Self::Updated { request_id, .. }
            | Self::Existing { request_id, .. } => request_id,
        }
    }

    pub const fn listing_hash(self) -> ObjectHash {
        match self {
            Self::Inserted { listing_hash, .. }
            | Self::Updated { listing_hash, .. }
            | Self::Existing { listing_hash, .. } => listing_hash,
        }
    }

    pub const fn revision(self) -> u64 {
        match self {
            Self::Inserted { revision, .. }
            | Self::Updated { revision, .. }
            | Self::Existing { revision, .. } => revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakescapeBoardCancellationAdmission {
    Applied {
        request_id: u64,
        listing_hash: ObjectHash,
        cancellation_hash: ObjectHash,
        revision: u64,
    },
    Existing {
        request_id: u64,
        listing_hash: ObjectHash,
        cancellation_hash: ObjectHash,
        revision: u64,
    },
}

impl ShakescapeBoardCancellationAdmission {
    pub const fn request_id(self) -> u64 {
        match self {
            Self::Applied { request_id, .. } | Self::Existing { request_id, .. } => request_id,
        }
    }

    pub const fn listing_hash(self) -> ObjectHash {
        match self {
            Self::Applied { listing_hash, .. } | Self::Existing { listing_hash, .. } => {
                listing_hash
            }
        }
    }

    pub const fn cancellation_hash(self) -> ObjectHash {
        match self {
            Self::Applied {
                cancellation_hash, ..
            }
            | Self::Existing {
                cancellation_hash, ..
            } => cancellation_hash,
        }
    }

    pub const fn revision(self) -> u64 {
        match self {
            Self::Applied { revision, .. } | Self::Existing { revision, .. } => revision,
        }
    }
}

/// Fresh non-serializable authority for one still-active persisted board
/// offer. A restart or later use must call `current_offer` again.
pub struct CurrentShakescapeBoardOffer {
    board_revision: u64,
    listing: VerifiedFixedPriceListing,
    current_lock: VerifiedCurrentShakedexLock,
}

impl CurrentShakescapeBoardOffer {
    pub const fn board_revision(&self) -> u64 {
        self.board_revision
    }

    pub const fn listing(&self) -> &VerifiedFixedPriceListing {
        &self.listing
    }

    pub const fn current_lock(&self) -> &VerifiedCurrentShakedexLock {
        &self.current_lock
    }
}

impl core::fmt::Debug for CurrentShakescapeBoardOffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentShakescapeBoardOffer")
            .field("board_revision", &self.board_revision)
            .field("listing_hash", &self.listing.listing_hash())
            .field("current_lock", &self.current_lock)
            .finish_non_exhaustive()
    }
}

/// Closed point-in-time view of the active board inventory under one exact
/// selected-account/network/trusted-time context.
///
/// The hashes and account context remain crate-private so this object cannot
/// be mistaken for a transport response or current-lock/value authority.
pub(crate) struct CurrentShakescapeBoardInventory {
    board_revision: u64,
    listing_hashes: Vec<ObjectHash>,
    _context: VerifiedHnsBoardContext,
}

impl CurrentShakescapeBoardInventory {
    pub(crate) const fn board_revision(&self) -> u64 {
        self.board_revision
    }

    pub(crate) fn listing_hashes(&self) -> &[ObjectHash] {
        &self.listing_hashes
    }
}

/// Closed query-scoped view of a nonempty subset of requested board offers
/// under one coherent account, chain, mempool, network, and clock authority.
///
/// Request hashes, listings, and current locks remain crate-private. Keeping
/// the non-cloneable batch alive prevents an individual listing from being
/// mistaken for independent current-lock or value authority.
pub(crate) struct CurrentShakescapeBoardOffers {
    board_revision: u64,
    requested_listing_hashes: Vec<ObjectHash>,
    listings: Vec<VerifiedFixedPriceListing>,
    _current_locks: VerifiedCurrentShakedexLockBatch,
}

pub(crate) enum CurrentShakescapeBoardOffersResolution {
    Absent { board_revision: u64 },
    Current(Box<CurrentShakescapeBoardOffers>),
}

impl CurrentShakescapeBoardOffers {
    pub(crate) const fn board_revision(&self) -> u64 {
        self.board_revision
    }

    pub(crate) fn requested_listing_hashes(&self) -> &[ObjectHash] {
        &self.requested_listing_hashes
    }

    pub(crate) fn listings(&self) -> &[VerifiedFixedPriceListing] {
        &self.listings
    }
}

/// Offline Shakescape board composition bound to one exact HNS account read
/// runtime and its identical Arc-backed encrypted store authority.
///
/// This type performs no transport I/O and does not consult or alter any
/// release gate. Admission authenticates the canonical V2 envelope first,
/// then obtains current name/coin/network/time authority from the read
/// runtime, and only then commits the board reducer through one store CAS.
/// Cancellation admission is a separate negative-authority path: it binds an
/// authenticated tombstone to the exact persisted listing plus selected
/// account network/time, but deliberately performs no current-lock query.
enum ShakescapeHnsRuntime<'a, B, C> {
    AccountRead(&'a HnsAccountReadRuntime<B, C>),
    Value(&'a HnsWalletRuntime<B, C>),
}

impl<B: HnsBackend, C: HnsClock> ShakescapeHnsRuntime<'_, B, C> {
    fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        match self {
            Self::AccountRead(runtime) => runtime.shares_store_authority(store),
            Self::Value(runtime) => runtime.shares_store_authority(store),
        }
    }

    fn observe_board_context(&self) -> Result<VerifiedHnsBoardContext, ShakedexError> {
        match self {
            Self::AccountRead(runtime) => runtime.observe_board_context().map_err(Into::into),
            Self::Value(runtime) => runtime.observe_board_context().map_err(Into::into),
        }
    }

    fn observe_board_cancellation_context(
        &self,
    ) -> Result<hns_wallet_hns::VerifiedHnsBoardCancellationContext, ShakedexError> {
        match self {
            Self::AccountRead(runtime) => runtime
                .observe_board_cancellation_context()
                .map_err(Into::into),
            Self::Value(runtime) => runtime
                .observe_board_cancellation_context()
                .map_err(Into::into),
        }
    }

    fn verify_current_shakedex_lock(
        &self,
        name: &[u8],
        seller_public_key: [u8; 33],
    ) -> Result<VerifiedCurrentShakedexLock, ShakedexError> {
        match self {
            Self::AccountRead(runtime) => runtime
                .verify_current_shakedex_lock(name, seller_public_key)
                .map_err(Into::into),
            Self::Value(runtime) => runtime
                .verify_current_shakedex_lock(name, seller_public_key)
                .map_err(Into::into),
        }
    }

    fn verify_current_shakedex_locks(
        &self,
        queries: &[CurrentShakedexLockQuery],
    ) -> Result<VerifiedCurrentShakedexLockBatch, ShakedexError> {
        match self {
            Self::AccountRead(runtime) => runtime
                .verify_current_shakedex_locks(queries)
                .map_err(Into::into),
            Self::Value(runtime) => runtime
                .verify_current_shakedex_locks(queries)
                .map_err(Into::into),
        }
    }
}

pub struct ShakescapeBoardRuntime<'a, B, C = SystemClock> {
    hns: ShakescapeHnsRuntime<'a, B, C>,
    store: SharedWalletStore,
}

impl<'a, B: HnsBackend, C: HnsClock> ShakescapeBoardRuntime<'a, B, C> {
    pub fn new(
        hns: &'a HnsAccountReadRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(Self {
            hns: ShakescapeHnsRuntime::AccountRead(hns),
            store,
        })
    }

    /// Compose board admission, discovery, and current-offer reacquisition
    /// directly with the exact full signing runtime. This avoids a second
    /// mutable account cache or independently opened database connection in
    /// the production value service.
    pub fn new_value(
        hns: &'a HnsWalletRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(Self {
            hns: ShakescapeHnsRuntime::Value(hns),
            store,
        })
    }

    pub fn shares_store_authority(&self, store: &SharedWalletStore) -> bool {
        self.store.is_same_authority(store) && self.hns.shares_store_authority(store)
    }

    /// Admit one exact canonical V2 offer after fresh current-lock validation.
    /// Exact retries return `Existing` without writing or advancing revision;
    /// same-identity sequence conflicts are rejected by the board reducer.
    pub fn admit_offer(
        &self,
        envelope: &[u8],
        expected_hash: ObjectHash,
    ) -> Result<ShakescapeBoardOfferAdmission, ShakedexError> {
        self.require_store_authority()?;
        let (request_id, authenticated) = decode_shakescape_authenticated_offer(
            envelope,
            ShakescapeRegistryVersion::V1,
            expected_hash,
        )?;
        let (listing, current_lock) = self.bind_current_listing(authenticated)?;
        let listing_hash = listing.listing_hash();
        let network = listing.network();
        let name_hash = listing.name_hash()?;
        let seller_public_key = listing.seller_public_key().to_vec();
        let updated_at_unix = listing.verified_at_unix();

        self.store.try_with_store_mut(move |store| {
            let (current_lock, loaded) = store.try_with_entity_read_snapshot(|snapshot| {
                let current_lock = current_lock.revalidate_unchanged_account(snapshot)?;
                let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
                Ok::<_, ShakedexError>((current_lock, loaded))
            })?;
            let mut board = loaded.board.clone();
            let replaced_identity = board.offers().iter().any(|offer| {
                offer.network_magic == network.magic
                    && offer.network_genesis.as_bytes() == network.genesis.as_bytes()
                    && offer.name_hash == name_hash
                    && offer.seller_public_key == seller_public_key
            });
            if !board.apply_offer(&listing)? {
                return Ok(ShakescapeBoardOfferAdmission::Existing {
                    request_id,
                    listing_hash,
                    revision: loaded.logical_revision,
                });
            }
            let account_prefix_lease = current_lock.into_account_prefix_lease()?;
            let revision = save_loaded_name_market_board_with_guard(
                store,
                loaded.logical_revision,
                &board,
                updated_at_unix,
                loaded,
                account_prefix_lease,
            )?;
            if replaced_identity {
                Ok(ShakescapeBoardOfferAdmission::Updated {
                    request_id,
                    listing_hash,
                    revision,
                })
            } else {
                Ok(ShakescapeBoardOfferAdmission::Inserted {
                    request_id,
                    listing_hash,
                    revision,
                })
            }
        })
    }

    /// Admit one exact canonical V2 cancellation as a durable negative
    /// tombstone. The signed cancellation remains admissible after the target
    /// lock is spent or otherwise unavailable; this path never queries a node
    /// and does not make the cached listing current or usable for value.
    ///
    /// An exact already-persisted tombstone returns `Existing` without a write,
    /// including after its signed horizon, because no new authority is being
    /// accepted. Every initial or changed tombstone must be active at the
    /// runtime-owned clock observation and advance the board watermark.
    pub fn admit_cancellation(
        &self,
        envelope: &[u8],
        expected_listing_hash: ObjectHash,
        expected_cancellation_hash: ObjectHash,
    ) -> Result<ShakescapeBoardCancellationAdmission, ShakedexError> {
        self.require_store_authority()?;
        let (request_id, authenticated) = decode_shakescape_authenticated_cancellation(
            envelope,
            ShakescapeRegistryVersion::V1,
            expected_listing_hash,
            expected_cancellation_hash,
        )?;
        let context = self.hns.observe_board_cancellation_context()?;

        self.store.try_with_store_mut(move |store| {
            let (context, loaded) = store.try_with_entity_read_snapshot(|snapshot| {
                let context = context.revalidate_unchanged_account(snapshot)?;
                let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
                Ok::<_, ShakedexError>((context, loaded))
            })?;
            let mut board = loaded.board.clone();
            let persisted = board
                .offer(expected_listing_hash)
                .cloned()
                .ok_or(ShakedexError::InvalidCancellation)?;
            let listing =
                authenticate_fixed_price_listing(&persisted.listing_bytes, expected_listing_hash)?;
            if listing.network() != context.network() {
                return Err(ShakedexError::InvalidCancellation);
            }

            if persisted.status == BoardOfferStatus::Cancelled
                && persisted.cancellation_hash == Some(expected_cancellation_hash)
                && persisted.cancellation_bytes.as_deref() == Some(authenticated.encoded())
                && persisted.cancellation_sequence == Some(authenticated.sequence())
            {
                return Ok(ShakescapeBoardCancellationAdmission::Existing {
                    request_id,
                    listing_hash: expected_listing_hash,
                    cancellation_hash: expected_cancellation_hash,
                    revision: loaded.logical_revision,
                });
            }

            let cancellation = verify_authenticated_listing_cancellation(
                authenticated,
                &listing,
                context.network(),
                context.observed_at_unix(),
            )?;
            if !board.apply_cancellation(&cancellation)? {
                return Ok(ShakescapeBoardCancellationAdmission::Existing {
                    request_id,
                    listing_hash: expected_listing_hash,
                    cancellation_hash: expected_cancellation_hash,
                    revision: loaded.logical_revision,
                });
            }
            let observed_at_unix = context.observed_at_unix();
            let account_prefix_lease = context.into_account_prefix_lease();
            let revision = save_loaded_name_market_board_with_guard(
                store,
                loaded.logical_revision,
                &board,
                observed_at_unix,
                loaded,
                account_prefix_lease,
            )?;
            Ok(ShakescapeBoardCancellationAdmission::Applied {
                request_id,
                listing_hash: expected_listing_hash,
                cancellation_hash: expected_cancellation_hash,
                revision,
            })
        })
    }

    /// Remove active rows absent from one coherent node latest-state snapshot
    /// while retaining signed cancellation tombstones and sequence watermarks.
    pub(crate) fn reconcile_transport_snapshot(
        &self,
        active_listing_hashes: &BTreeSet<ObjectHash>,
    ) -> Result<u64, ShakedexError> {
        self.require_store_authority()?;
        let context = self.hns.observe_board_cancellation_context()?;
        self.store.try_with_store_mut(|store| {
            let (context, loaded) = store.try_with_entity_read_snapshot(|snapshot| {
                let context = context.revalidate_unchanged_account(snapshot)?;
                let loaded = load_name_market_board_state_from_snapshot(snapshot)?;
                Ok::<_, ShakedexError>((context, loaded))
            })?;
            let mut board = loaded.board.clone();
            if !board.retain_transport_active_listings(context.network(), active_listing_hashes)? {
                return Ok(loaded.logical_revision);
            }
            let updated_at_unix = context.observed_at_unix();
            let account_prefix_lease = context.into_account_prefix_lease();
            save_loaded_name_market_board_with_guard(
                store,
                loaded.logical_revision,
                &board,
                updated_at_unix,
                loaded,
                account_prefix_lease,
            )
        })
    }

    /// Re-authenticate a persisted active offer and reacquire its exact
    /// current, unspent lock before returning it to a later value boundary.
    /// The board row/revision is fenced again after all node queries.
    pub fn current_offer(
        &self,
        listing_hash: ObjectHash,
    ) -> Result<Option<CurrentShakescapeBoardOffer>, ShakedexError> {
        self.require_store_authority()?;
        let (board_revision, persisted) = self.store.try_with_store(|store| {
            let mut stored = load_name_market_board_offers(store, &[listing_hash])?;
            let persisted = stored.offers.pop().flatten();
            Ok::<_, ShakedexError>((stored.revision, persisted))
        })?;
        let Some(persisted) = persisted else {
            return Ok(None);
        };
        if persisted.status != BoardOfferStatus::Active {
            return Ok(None);
        }
        let authenticated = crate::authenticate_fixed_price_listing(
            &persisted.listing_bytes,
            persisted.listing_hash,
        )?;
        let (listing, current_lock) = self.bind_current_listing(authenticated)?;

        let current_lock = self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                let current_lock = current_lock.revalidate_unchanged_account(snapshot)?;
                let current =
                    load_name_market_board_offers_from_snapshot(snapshot, &[listing_hash])?;
                if current.revision != board_revision
                    || current.offers.len() != 1
                    || current.offers[0].as_ref() != Some(&persisted)
                {
                    return Err(ShakedexError::StaleRevision);
                }
                Ok::<_, ShakedexError>(current_lock)
            })
        })?;
        Ok(Some(CurrentShakescapeBoardOffer {
            board_revision,
            listing,
            current_lock,
        }))
    }

    /// Capture active, in-window hashes for the exact currently selected HNS
    /// network without consulting a node or changing persisted state.
    ///
    /// Inventory is discovery metadata only. The retained account context is
    /// not chain, current-lock, publication, transport, or value authority.
    /// Any later response emitter must reacquire and fence a fresh view.
    pub(crate) fn current_inventory(
        &self,
    ) -> Result<CurrentShakescapeBoardInventory, ShakedexError> {
        self.require_store_authority()?;
        let context = self.hns.observe_board_context()?;
        let (context, board_revision, listing_hashes) = self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                let context = context.revalidate_unchanged_account(snapshot)?;
                let stored = load_name_market_board_state_from_snapshot(snapshot)?;
                let network = context.network();
                let now_unix = context.observed_at_unix();
                let listing_hashes = stored
                    .board
                    .offers()
                    .iter()
                    .filter(|offer| {
                        offer.network_magic == network.magic
                            && offer.network_genesis.as_bytes() == network.genesis.as_bytes()
                            && offer.status == BoardOfferStatus::Active
                            && offer.created_at_unix <= now_unix
                            && now_unix < offer.expires_at_unix
                    })
                    .map(|offer| offer.listing_hash)
                    .collect();
                Ok::<_, ShakedexError>((context, stored.logical_revision, listing_hashes))
            })
        })?;
        Ok(CurrentShakescapeBoardInventory {
            board_revision,
            listing_hashes,
            _context: context,
        })
    }

    /// Resolve one canonical, bounded `GetOffers` hash set against the board,
    /// then verify every returned active row through one coherent HNS
    /// current-lock batch.
    ///
    /// Missing and cancelled rows are omitted. If every requested row is
    /// absent or cancelled, an explicit revision-bound absence snapshot is
    /// returned without node or clock access; callers must not invent an
    /// invalid empty wire `Offers` response. Any active row that is malformed,
    /// expired, on another network, duplicated by underlying name, or no
    /// longer backed by its exact unspent lock makes the whole plan fail
    /// closed. The actual response payload shape is preflighted before node
    /// access, and the selected account plus every requested board row/revision
    /// is fenced again after all external reads.
    pub(crate) fn current_offers(
        &self,
        listing_hashes: &[ObjectHash],
    ) -> Result<CurrentShakescapeBoardOffersResolution, ShakedexError> {
        validate_current_offer_request_hashes(listing_hashes)?;
        self.require_store_authority()?;
        let (board_revision, requested_rows) = self.store.try_with_store(|store| {
            let stored = load_name_market_board_offers(store, listing_hashes)?;
            Ok::<_, ShakedexError>((stored.revision, stored.offers))
        })?;

        let mut authenticated = Vec::with_capacity(requested_rows.len());
        for persisted in requested_rows.iter().flatten() {
            if persisted.status != BoardOfferStatus::Active {
                continue;
            }
            authenticated.push(authenticate_fixed_price_listing(
                &persisted.listing_bytes,
                persisted.listing_hash,
            )?);
        }
        if authenticated.is_empty() {
            return Ok(CurrentShakescapeBoardOffersResolution::Absent { board_revision });
        }

        // The type-5 envelope has an aggregate payload bound in addition to
        // its 64-row bound. Reject an unencodable candidate set before making
        // any node or clock call. The nonzero probe ID has the same wire width
        // as the exact request ID and the bytes are immediately discarded.
        let response_probe = NameMarketMessage::Offers(
            authenticated
                .iter()
                .map(|listing| listing.canonical().clone())
                .collect(),
        )
        .encode_envelope(ShakescapeRegistryVersion::V1, 1)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
        drop(response_probe);

        let queries: Vec<_> = authenticated
            .iter()
            .map(|listing| CurrentShakedexLockQuery {
                name: listing.name().to_vec(),
                seller_public_key: *listing.seller_public_key(),
            })
            .collect();
        let current_locks = self.hns.verify_current_shakedex_locks(&queries)?;
        if current_locks.len() != authenticated.len() {
            return Err(ShakedexError::InvalidEvidence);
        }
        let mut listings = Vec::with_capacity(authenticated.len());
        for (authenticated, current_lock) in authenticated.into_iter().zip(current_locks.locks()) {
            let listing = verify_authenticated_fixed_price_listing(
                authenticated,
                current_locks.network(),
                current_locks.observed_at_unix(),
                current_lock.locking_coin(),
            )?;
            if listing.lock_descriptor()? != *current_lock.descriptor() {
                return Err(ShakedexError::InvalidListing);
            }
            listings.push(listing);
        }

        let current_locks = self.store.try_with_store(|store| {
            store.try_with_entity_read_snapshot(|snapshot| {
                let current_locks = current_locks.revalidate_unchanged_account(snapshot)?;
                let current =
                    load_name_market_board_offers_from_snapshot(snapshot, listing_hashes)?;
                if current.revision != board_revision || current.offers != requested_rows {
                    return Err(ShakedexError::StaleRevision);
                }
                Ok::<_, ShakedexError>(current_locks)
            })
        })?;

        Ok(CurrentShakescapeBoardOffersResolution::Current(Box::new(
            CurrentShakescapeBoardOffers {
                board_revision,
                requested_listing_hashes: listing_hashes.to_vec(),
                listings,
                _current_locks: current_locks,
            },
        )))
    }

    fn require_store_authority(&self) -> Result<(), ShakedexError> {
        if !self.hns.shares_store_authority(&self.store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(())
    }

    fn bind_current_listing(
        &self,
        authenticated: AuthenticatedFixedPriceListing,
    ) -> Result<(VerifiedFixedPriceListing, VerifiedCurrentShakedexLock), ShakedexError> {
        let current_lock = self.hns.verify_current_shakedex_lock(
            authenticated.name(),
            *authenticated.seller_public_key(),
        )?;
        let listing = verify_authenticated_fixed_price_listing(
            authenticated,
            current_lock.descriptor().network,
            current_lock.observed_at_unix(),
            current_lock.locking_coin(),
        )?;
        if &listing.lock_descriptor()? != current_lock.descriptor() {
            return Err(ShakedexError::InvalidListing);
        }
        Ok((listing, current_lock))
    }
}

fn validate_current_offer_request_hashes(
    listing_hashes: &[ObjectHash],
) -> Result<(), ShakedexError> {
    if listing_hashes.is_empty()
        || listing_hashes.len() > MAX_CURRENT_SHAKEDEX_LOCK_BATCH
        || listing_hashes
            .iter()
            .any(|listing_hash| *listing_hash.as_bytes() == [0; 32])
        || listing_hashes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ShakedexError::InvalidShakescapeEnvelope);
    }
    Ok(())
}
