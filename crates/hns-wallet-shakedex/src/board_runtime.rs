use hns_marketplace_protocol::DenuoRegistryVersion;
use hns_wallet_hns::{
    HnsAccountReadRuntime, HnsBackend, HnsClock, SystemClock, VerifiedCurrentShakedexLock,
    VerifiedHnsBoardContext,
};
use hns_wallet_store::SharedWalletStore;
use hns_wallet_types::ObjectHash;

use crate::{
    AuthenticatedFixedPriceListing, BoardOfferStatus, ShakedexError, VerifiedFixedPriceListing,
    authenticate_fixed_price_listing, decode_denuo_authenticated_cancellation,
    decode_denuo_authenticated_offer, load_name_market_board, save_name_market_board,
    verify_authenticated_fixed_price_listing, verify_authenticated_listing_cancellation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoBoardOfferAdmission {
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

impl DenuoBoardOfferAdmission {
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
pub enum DenuoBoardCancellationAdmission {
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

impl DenuoBoardCancellationAdmission {
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
pub struct CurrentDenuoBoardOffer {
    board_revision: u64,
    listing: VerifiedFixedPriceListing,
    current_lock: VerifiedCurrentShakedexLock,
}

impl CurrentDenuoBoardOffer {
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

impl core::fmt::Debug for CurrentDenuoBoardOffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentDenuoBoardOffer")
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
pub(crate) struct CurrentDenuoBoardInventory {
    board_revision: u64,
    listing_hashes: Vec<ObjectHash>,
    _context: VerifiedHnsBoardContext,
}

impl CurrentDenuoBoardInventory {
    pub(crate) const fn board_revision(&self) -> u64 {
        self.board_revision
    }

    pub(crate) fn listing_hashes(&self) -> &[ObjectHash] {
        &self.listing_hashes
    }
}

/// Offline Denuo board composition bound to one exact HNS account read
/// runtime and its identical Arc-backed encrypted store authority.
///
/// This type performs no transport I/O and does not consult or alter any
/// release gate. Admission authenticates the canonical V2 envelope first,
/// then obtains current name/coin/network/time authority from the read
/// runtime, and only then commits the board reducer through one store CAS.
/// Cancellation admission is a separate negative-authority path: it binds an
/// authenticated tombstone to the exact persisted listing plus selected
/// account network/time, but deliberately performs no current-lock query.
pub struct DenuoBoardRuntime<'a, B, C = SystemClock> {
    hns: &'a HnsAccountReadRuntime<B, C>,
    store: SharedWalletStore,
}

impl<'a, B: HnsBackend, C: HnsClock> DenuoBoardRuntime<'a, B, C> {
    pub fn new(
        hns: &'a HnsAccountReadRuntime<B, C>,
        store: SharedWalletStore,
    ) -> Result<Self, ShakedexError> {
        if !hns.shares_store_authority(&store) {
            return Err(ShakedexError::StoreAuthorityMismatch);
        }
        Ok(Self { hns, store })
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
    ) -> Result<DenuoBoardOfferAdmission, ShakedexError> {
        self.require_store_authority()?;
        let (request_id, authenticated) =
            decode_denuo_authenticated_offer(envelope, DenuoRegistryVersion::V2, expected_hash)?;
        let (listing, _current_lock) = self.bind_current_listing(authenticated)?;
        let listing_hash = listing.listing_hash();
        let network = listing.network();
        let name_hash = listing.name_hash()?;
        let seller_public_key = listing.seller_public_key().to_vec();
        let updated_at_unix = listing.verified_at_unix();

        self.store.try_with_store_mut(|store| {
            let mut stored = load_name_market_board(store)?;
            let replaced_identity = stored.board.offers().iter().any(|offer| {
                offer.network_magic == network.magic
                    && offer.network_genesis.as_bytes() == network.genesis.as_bytes()
                    && offer.name_hash == name_hash
                    && offer.seller_public_key == seller_public_key
            });
            if !stored.board.apply_offer(&listing)? {
                return Ok(DenuoBoardOfferAdmission::Existing {
                    request_id,
                    listing_hash,
                    revision: stored.revision,
                });
            }
            let revision =
                save_name_market_board(store, stored.revision, &stored.board, updated_at_unix)?;
            if replaced_identity {
                Ok(DenuoBoardOfferAdmission::Updated {
                    request_id,
                    listing_hash,
                    revision,
                })
            } else {
                Ok(DenuoBoardOfferAdmission::Inserted {
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
    ) -> Result<DenuoBoardCancellationAdmission, ShakedexError> {
        self.require_store_authority()?;
        let (request_id, authenticated) = decode_denuo_authenticated_cancellation(
            envelope,
            DenuoRegistryVersion::V2,
            expected_listing_hash,
            expected_cancellation_hash,
        )?;
        let context = self.hns.observe_board_cancellation_context()?;

        self.store.try_with_store_mut(move |store| {
            context.verify_unchanged_account(store)?;
            let mut stored = load_name_market_board(store)?;
            let persisted = stored
                .board
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
                return Ok(DenuoBoardCancellationAdmission::Existing {
                    request_id,
                    listing_hash: expected_listing_hash,
                    cancellation_hash: expected_cancellation_hash,
                    revision: stored.revision,
                });
            }

            let cancellation = verify_authenticated_listing_cancellation(
                authenticated,
                &listing,
                context.network(),
                context.observed_at_unix(),
            )?;
            if !stored.board.apply_cancellation(&cancellation)? {
                return Ok(DenuoBoardCancellationAdmission::Existing {
                    request_id,
                    listing_hash: expected_listing_hash,
                    cancellation_hash: expected_cancellation_hash,
                    revision: stored.revision,
                });
            }
            let revision = save_name_market_board(
                store,
                stored.revision,
                &stored.board,
                context.observed_at_unix(),
            )?;
            Ok(DenuoBoardCancellationAdmission::Applied {
                request_id,
                listing_hash: expected_listing_hash,
                cancellation_hash: expected_cancellation_hash,
                revision,
            })
        })
    }

    /// Re-authenticate a persisted active offer and reacquire its exact
    /// current, unspent lock before returning it to a later value boundary.
    /// The board row/revision is fenced again after all node queries.
    pub fn current_offer(
        &self,
        listing_hash: ObjectHash,
    ) -> Result<Option<CurrentDenuoBoardOffer>, ShakedexError> {
        self.require_store_authority()?;
        let (board_revision, persisted) = self.store.try_with_store(|store| {
            let stored = load_name_market_board(store)?;
            Ok::<_, ShakedexError>((stored.revision, stored.board.offer(listing_hash).cloned()))
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

        self.store.try_with_store(|store| {
            let current = load_name_market_board(store)?;
            if current.revision != board_revision
                || current.board.offer(listing_hash) != Some(&persisted)
            {
                return Err(ShakedexError::StaleRevision);
            }
            Ok(())
        })?;
        Ok(Some(CurrentDenuoBoardOffer {
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
    pub(crate) fn current_inventory(&self) -> Result<CurrentDenuoBoardInventory, ShakedexError> {
        self.require_store_authority()?;
        let context = self.hns.observe_board_context()?;
        let (board_revision, listing_hashes) = self.store.try_with_store(|store| {
            context.verify_unchanged_account(store)?;
            let stored = load_name_market_board(store)?;
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
            Ok::<_, ShakedexError>((stored.revision, listing_hashes))
        })?;
        Ok(CurrentDenuoBoardInventory {
            board_revision,
            listing_hashes,
            _context: context,
        })
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
