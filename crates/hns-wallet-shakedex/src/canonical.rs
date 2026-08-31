use hns_marketplace_protocol::{NameMarketMessage, ShakescapeRegistryVersion};
use hns_swap::{
    FixedPriceListing, ListingCancellation, MAX_FIXED_PRICE_LISTING_SIZE,
    MAX_LISTING_CANCELLATION_SIZE, NetworkBinding, ShakedexLockDescriptor, SwapProof,
};
use hns_transaction::{Coin, Outpoint};
use hns_wallet_types::ObjectHash;

use crate::ShakedexError;

/// A canonical listing whose envelope signature and exact content identity
/// are authenticated. It can be reconstructed from persisted canonical bytes
/// after expiry or a lock spend, but it is not purchase authority.
pub struct AuthenticatedFixedPriceListing {
    listing: FixedPriceListing,
    encoded: Vec<u8>,
    listing_hash: ObjectHash,
}

impl AuthenticatedFixedPriceListing {
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        self.listing_hash
    }

    pub const fn network(&self) -> NetworkBinding {
        self.listing.network()
    }

    pub fn name(&self) -> &[u8] {
        &self.listing.proof.name
    }

    pub fn name_hash(&self) -> Result<ObjectHash, ShakedexError> {
        self.listing
            .name_hash()
            .map(|hash| ObjectHash::new(*hash.as_bytes()))
            .map_err(|_| ShakedexError::InvalidListing)
    }

    pub const fn seller_public_key(&self) -> &[u8; 33] {
        self.listing.seller_public_key()
    }

    pub const fn sequence(&self) -> u64 {
        self.listing.sequence
    }

    pub const fn created_at_unix(&self) -> u64 {
        self.listing.created_at
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.listing.expires_at
    }

    pub const fn locking_outpoint(&self) -> Outpoint {
        self.listing.proof.locking_outpoint
    }

    pub const fn price_base_units(&self) -> u64 {
        self.listing.proof.price.get()
    }

    pub fn lock_descriptor(&self) -> Result<ShakedexLockDescriptor, ShakedexError> {
        self.listing
            .proof
            .lock_descriptor()
            .map_err(|_| ShakedexError::InvalidListing)
    }

    pub const fn proof(&self) -> &SwapProof {
        &self.listing.proof
    }

    pub(crate) const fn canonical(&self) -> &FixedPriceListing {
        &self.listing
    }
}

/// A canonical cancellation whose seller signature, exact target hash, and
/// exact content identity are authenticated. It is only a safe lookup phase:
/// the target listing, selected network, and signed time window still require
/// independent verification before this object can mutate a board.
pub struct AuthenticatedListingCancellation {
    cancellation: ListingCancellation,
    encoded: Vec<u8>,
    cancellation_hash: ObjectHash,
}

impl AuthenticatedListingCancellation {
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn cancellation_hash(&self) -> ObjectHash {
        self.cancellation_hash
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        ObjectHash::new(self.cancellation.listing_hash)
    }

    pub const fn network(&self) -> NetworkBinding {
        self.cancellation.network
    }

    pub const fn seller_public_key(&self) -> &[u8; 33] {
        &self.cancellation.seller_public_key
    }

    pub const fn sequence(&self) -> u64 {
        self.cancellation.sequence
    }

    pub const fn created_at_unix(&self) -> u64 {
        self.cancellation.created_at
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.cancellation.expires_at
    }

    pub(crate) const fn canonical(&self) -> &ListingCancellation {
        &self.cancellation
    }
}

/// A signed listing additionally verified against one exact Shakedex locking
/// coin, network, and wall-clock boundary. This type does not prove that the
/// supplied coin is current or unspent; a value runtime must obtain it from
/// fresh authenticated chain evidence.
pub struct VerifiedFixedPriceListing {
    authenticated: AuthenticatedFixedPriceListing,
    verified_at_unix: u64,
}

impl VerifiedFixedPriceListing {
    pub const fn authenticated(&self) -> &AuthenticatedFixedPriceListing {
        &self.authenticated
    }

    pub fn encoded(&self) -> &[u8] {
        self.authenticated.encoded()
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        self.authenticated.listing_hash()
    }

    pub const fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    pub const fn network(&self) -> NetworkBinding {
        self.authenticated.network()
    }

    pub fn name(&self) -> &[u8] {
        self.authenticated.name()
    }

    pub fn name_hash(&self) -> Result<ObjectHash, ShakedexError> {
        self.authenticated.name_hash()
    }

    pub const fn seller_public_key(&self) -> &[u8; 33] {
        self.authenticated.seller_public_key()
    }

    pub const fn sequence(&self) -> u64 {
        self.authenticated.sequence()
    }

    pub const fn created_at_unix(&self) -> u64 {
        self.authenticated.created_at_unix()
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.authenticated.expires_at_unix()
    }

    pub const fn locking_outpoint(&self) -> Outpoint {
        self.authenticated.locking_outpoint()
    }

    pub const fn price_base_units(&self) -> u64 {
        self.authenticated.price_base_units()
    }

    pub fn lock_descriptor(&self) -> Result<ShakedexLockDescriptor, ShakedexError> {
        self.authenticated.lock_descriptor()
    }

    pub const fn proof(&self) -> &SwapProof {
        self.authenticated.proof()
    }
}

/// A cancellation authenticated against one exact signed listing. The target
/// listing can be reconstructed after restart, fulfillment, recovery, or
/// expiry without coin evidence; receipt still enforces the cancellation's
/// own signed time window.
pub struct VerifiedListingCancellation {
    cancellation: ListingCancellation,
    encoded: Vec<u8>,
    cancellation_hash: ObjectHash,
}

impl VerifiedListingCancellation {
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn cancellation_hash(&self) -> ObjectHash {
        self.cancellation_hash
    }

    pub const fn listing_hash(&self) -> ObjectHash {
        ObjectHash::new(self.cancellation.listing_hash)
    }

    pub const fn sequence(&self) -> u64 {
        self.cancellation.sequence
    }

    pub const fn created_at_unix(&self) -> u64 {
        self.cancellation.created_at
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.cancellation.expires_at
    }

    pub(crate) const fn canonical(&self) -> &ListingCancellation {
        &self.cancellation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShakescapeNameMarketRequest {
    Inventory,
    Offers(Vec<ObjectHash>),
    Offer(ObjectHash),
}

pub fn authenticate_fixed_price_listing(
    encoded: &[u8],
    expected_hash: ObjectHash,
) -> Result<AuthenticatedFixedPriceListing, ShakedexError> {
    if encoded.is_empty() || encoded.len() > MAX_FIXED_PRICE_LISTING_SIZE {
        return Err(ShakedexError::InvalidListing);
    }
    let listing = FixedPriceListing::decode(encoded).map_err(|_| ShakedexError::InvalidListing)?;
    authenticated_listing_from_canonical(listing, expected_hash)
}

pub fn verify_fixed_price_listing(
    encoded: &[u8],
    expected_hash: ObjectHash,
    expected_network: NetworkBinding,
    now_unix: u64,
    locking_coin: &Coin,
) -> Result<VerifiedFixedPriceListing, ShakedexError> {
    let authenticated = authenticate_fixed_price_listing(encoded, expected_hash)?;
    verified_listing_from_authenticated(authenticated, expected_network, now_unix, locking_coin)
}

/// Complete current coin/network/time verification for an already
/// authenticated canonical listing. The caller must still obtain
/// `locking_coin` from fresh current-chain authority rather than persistence.
pub fn verify_authenticated_fixed_price_listing(
    authenticated: AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
    locking_coin: &Coin,
) -> Result<VerifiedFixedPriceListing, ShakedexError> {
    verified_listing_from_authenticated(authenticated, expected_network, now_unix, locking_coin)
}

fn authenticated_listing_from_canonical(
    listing: FixedPriceListing,
    expected_hash: ObjectHash,
) -> Result<AuthenticatedFixedPriceListing, ShakedexError> {
    let listing_hash = ObjectHash::new(
        listing
            .listing_hash()
            .map_err(|_| ShakedexError::InvalidListing)?,
    );
    if listing_hash != expected_hash {
        return Err(ShakedexError::InvalidListing);
    }
    let encoded = listing
        .encode()
        .map_err(|_| ShakedexError::InvalidListing)?;
    Ok(AuthenticatedFixedPriceListing {
        listing,
        encoded,
        listing_hash,
    })
}

fn verified_listing_from_authenticated(
    authenticated: AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
    locking_coin: &Coin,
) -> Result<VerifiedFixedPriceListing, ShakedexError> {
    authenticated
        .canonical()
        .verify_for_network(expected_network, now_unix, locking_coin)
        .map_err(|_| ShakedexError::InvalidListing)?;
    Ok(VerifiedFixedPriceListing {
        authenticated,
        verified_at_unix: now_unix,
    })
}

pub fn verify_listing_cancellation(
    encoded: &[u8],
    listing: &AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
) -> Result<VerifiedListingCancellation, ShakedexError> {
    if encoded.is_empty() || encoded.len() > MAX_LISTING_CANCELLATION_SIZE {
        return Err(ShakedexError::InvalidCancellation);
    }
    let cancellation =
        ListingCancellation::decode(encoded).map_err(|_| ShakedexError::InvalidCancellation)?;
    verified_cancellation_from_canonical(cancellation, listing, expected_network, now_unix)
}

/// Authenticate canonical cancellation bytes against both externally expected
/// content identities without treating the result as listing/time authority.
pub fn authenticate_listing_cancellation(
    encoded: &[u8],
    expected_listing_hash: ObjectHash,
    expected_cancellation_hash: ObjectHash,
) -> Result<AuthenticatedListingCancellation, ShakedexError> {
    if encoded.is_empty() || encoded.len() > MAX_LISTING_CANCELLATION_SIZE {
        return Err(ShakedexError::InvalidCancellation);
    }
    let cancellation =
        ListingCancellation::decode(encoded).map_err(|_| ShakedexError::InvalidCancellation)?;
    authenticated_cancellation_from_canonical(
        cancellation,
        expected_listing_hash,
        expected_cancellation_hash,
    )
}

/// Bind an authenticated cancellation to one exact authenticated listing,
/// selected network, and trusted wall-clock observation.
pub fn verify_authenticated_listing_cancellation(
    authenticated: AuthenticatedListingCancellation,
    listing: &AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
) -> Result<VerifiedListingCancellation, ShakedexError> {
    authenticated
        .canonical()
        .verify_for_listing(listing.canonical(), expected_network, now_unix)
        .map_err(|_| ShakedexError::InvalidCancellation)?;
    Ok(VerifiedListingCancellation {
        cancellation: authenticated.cancellation,
        encoded: authenticated.encoded,
        cancellation_hash: authenticated.cancellation_hash,
    })
}

fn authenticated_cancellation_from_canonical(
    cancellation: ListingCancellation,
    expected_listing_hash: ObjectHash,
    expected_cancellation_hash: ObjectHash,
) -> Result<AuthenticatedListingCancellation, ShakedexError> {
    let listing_hash = ObjectHash::new(cancellation.listing_hash);
    let cancellation_hash = ObjectHash::new(
        cancellation
            .cancellation_hash()
            .map_err(|_| ShakedexError::InvalidCancellation)?,
    );
    if listing_hash != expected_listing_hash || cancellation_hash != expected_cancellation_hash {
        return Err(ShakedexError::InvalidCancellation);
    }
    let encoded = cancellation
        .encode()
        .map_err(|_| ShakedexError::InvalidCancellation)?;
    Ok(AuthenticatedListingCancellation {
        cancellation,
        encoded,
        cancellation_hash,
    })
}

fn verified_cancellation_from_canonical(
    cancellation: ListingCancellation,
    listing: &AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
) -> Result<VerifiedListingCancellation, ShakedexError> {
    let cancellation_hash = ObjectHash::new(
        cancellation
            .cancellation_hash()
            .map_err(|_| ShakedexError::InvalidCancellation)?,
    );
    let authenticated = authenticated_cancellation_from_canonical(
        cancellation,
        ObjectHash::new(
            listing
                .canonical()
                .listing_hash()
                .map_err(|_| ShakedexError::InvalidListing)?,
        ),
        cancellation_hash,
    )?;
    verify_authenticated_listing_cancellation(authenticated, listing, expected_network, now_unix)
}

pub fn encode_shakescape_offer(
    registry: ShakescapeRegistryVersion,
    request_id: u64,
    listing: &AuthenticatedFixedPriceListing,
) -> Result<Vec<u8>, ShakedexError> {
    NameMarketMessage::Offer(listing.canonical().clone())
        .encode_envelope(registry, request_id)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)
}

pub fn decode_shakescape_offer(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
    expected_hash: ObjectHash,
    expected_network: NetworkBinding,
    now_unix: u64,
    locking_coin: &Coin,
) -> Result<(u64, VerifiedFixedPriceListing), ShakedexError> {
    let (request_id, authenticated) =
        decode_shakescape_authenticated_offer(encoded, expected_registry, expected_hash)?;
    let listing = verify_authenticated_fixed_price_listing(
        authenticated,
        expected_network,
        now_unix,
        locking_coin,
    )?;
    Ok((request_id, listing))
}

/// Decode one canonical Shakescape offer and authenticate its signed listing plus
/// exact content hash without accepting caller-supplied chain facts. This is
/// the safe first phase for runtimes that must query the listing's current
/// locking coin before completing time/network verification.
pub fn decode_shakescape_authenticated_offer(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
    expected_hash: ObjectHash,
) -> Result<(u64, AuthenticatedFixedPriceListing), ShakedexError> {
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(encoded)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
    if registry != expected_registry {
        return Err(ShakedexError::ShakescapeRegistryMismatch);
    }
    let NameMarketMessage::Offer(listing) = message else {
        return Err(ShakedexError::InvalidShakescapeEnvelope);
    };
    Ok((
        request_id,
        authenticated_listing_from_canonical(listing, expected_hash)?,
    ))
}

pub fn encode_shakescape_cancellation(
    registry: ShakescapeRegistryVersion,
    request_id: u64,
    cancellation: &VerifiedListingCancellation,
) -> Result<Vec<u8>, ShakedexError> {
    NameMarketMessage::Cancel(cancellation.canonical().clone())
        .encode_envelope(registry, request_id)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)
}

pub fn decode_shakescape_cancellation(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
    listing: &AuthenticatedFixedPriceListing,
    expected_network: NetworkBinding,
    now_unix: u64,
) -> Result<(u64, VerifiedListingCancellation), ShakedexError> {
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(encoded)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
    if registry != expected_registry {
        return Err(ShakedexError::ShakescapeRegistryMismatch);
    }
    let NameMarketMessage::Cancel(cancellation) = message else {
        return Err(ShakedexError::InvalidShakescapeEnvelope);
    };
    let cancellation_hash = ObjectHash::new(
        cancellation
            .cancellation_hash()
            .map_err(|_| ShakedexError::InvalidCancellation)?,
    );
    let authenticated = authenticated_cancellation_from_canonical(
        cancellation,
        listing.listing_hash(),
        cancellation_hash,
    )?;
    let cancellation = verify_authenticated_listing_cancellation(
        authenticated,
        listing,
        expected_network,
        now_unix,
    )?;
    Ok((request_id, cancellation))
}

/// Decode one canonical Shakescape cancellation and authenticate its signature,
/// exact listing target, and exact cancellation content hash. The returned
/// object is intentionally not listing-, network-, or time-verified.
pub fn decode_shakescape_authenticated_cancellation(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
    expected_listing_hash: ObjectHash,
    expected_cancellation_hash: ObjectHash,
) -> Result<(u64, AuthenticatedListingCancellation), ShakedexError> {
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(encoded)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
    if registry != expected_registry {
        return Err(ShakedexError::ShakescapeRegistryMismatch);
    }
    let NameMarketMessage::Cancel(cancellation) = message else {
        return Err(ShakedexError::InvalidShakescapeEnvelope);
    };
    let cancellation = authenticated_cancellation_from_canonical(
        cancellation,
        expected_listing_hash,
        expected_cancellation_hash,
    )?;
    Ok((request_id, cancellation))
}

pub fn encode_shakescape_inventory(
    registry: ShakescapeRegistryVersion,
    request_id: u64,
    hashes: &[ObjectHash],
) -> Result<Vec<u8>, ShakedexError> {
    NameMarketMessage::OfferInventory(hashes.iter().copied().map(ObjectHash::into_bytes).collect())
        .encode_envelope(registry, request_id)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)
}

pub fn decode_shakescape_inventory(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
) -> Result<(u64, Vec<ObjectHash>), ShakedexError> {
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(encoded)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
    if registry != expected_registry {
        return Err(ShakedexError::ShakescapeRegistryMismatch);
    }
    let NameMarketMessage::OfferInventory(hashes) = message else {
        return Err(ShakedexError::InvalidShakescapeEnvelope);
    };
    Ok((
        request_id,
        hashes.into_iter().map(ObjectHash::new).collect(),
    ))
}

pub fn encode_shakescape_request(
    registry: ShakescapeRegistryVersion,
    request_id: u64,
    request: &ShakescapeNameMarketRequest,
) -> Result<Vec<u8>, ShakedexError> {
    let message = match request {
        ShakescapeNameMarketRequest::Inventory => NameMarketMessage::GetOfferInventory,
        ShakescapeNameMarketRequest::Offers(hashes) => NameMarketMessage::GetOffers(
            hashes.iter().copied().map(ObjectHash::into_bytes).collect(),
        ),
        ShakescapeNameMarketRequest::Offer(hash) => NameMarketMessage::GetOffer(hash.into_bytes()),
    };
    message
        .encode_envelope(registry, request_id)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)
}

pub fn decode_shakescape_request(
    encoded: &[u8],
    expected_registry: ShakescapeRegistryVersion,
) -> Result<(u64, ShakescapeNameMarketRequest), ShakedexError> {
    let (registry, request_id, message) = NameMarketMessage::decode_envelope(encoded)
        .map_err(|_| ShakedexError::InvalidShakescapeEnvelope)?;
    if registry != expected_registry {
        return Err(ShakedexError::ShakescapeRegistryMismatch);
    }
    let request = match message {
        NameMarketMessage::GetOfferInventory => ShakescapeNameMarketRequest::Inventory,
        NameMarketMessage::GetOffers(hashes) => {
            ShakescapeNameMarketRequest::Offers(hashes.into_iter().map(ObjectHash::new).collect())
        }
        NameMarketMessage::GetOffer(hash) => {
            ShakescapeNameMarketRequest::Offer(ObjectHash::new(hash))
        }
        _ => return Err(ShakedexError::InvalidShakescapeEnvelope),
    };
    Ok((request_id, request))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    use hns_covenants::FinalizeCovenant;
    use hns_marketplace_protocol::ShakescapeRegistryVersion;
    use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash};
    use hns_swap::{
        FixedPriceListing, ListingCancellation, NetworkBinding, SwapProof, lock_script_hash,
    };
    use hns_transaction::{Address, Coin, Outpoint};
    #[cfg(unix)]
    use hns_wallet_store::WalletStore;
    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::{
        BoardOfferStatus, NameMarketBoard, ShakedexError, load_name_market_board,
        save_name_market_board,
    };

    const ACTIVE_TIME: u64 = 1_800_000_200;

    fn listing_fixture(sequence: u64) -> (FixedPriceListing, Coin, SigningKey) {
        let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed seller key");
        let network = NetworkBinding {
            magic: 0x5b6e_c393,
            genesis: BlockHash::new([0x11; 32]),
        };
        let mut proof = SwapProof {
            network,
            locking_outpoint: Outpoint {
                transaction_hash: TransactionHash::new([0x22; 32]),
                index: 7,
            },
            name: b"market-name".to_vec(),
            seller_public_key,
            payment_address: Address::new(0, vec![0x33; 20]).expect("payment address"),
            price: Dollarydoos::new(12_345_678),
            lock_time_seconds: 1_800_000_000,
            signature: None,
            fee_address: Some(Address::new(0, vec![0x44; 20]).expect("fee address")),
            fee: Dollarydoos::new(25_000),
        };
        let coin = Coin {
            outpoint: proof.locking_outpoint,
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&proof.seller_public_key).to_vec())
                .expect("lock address"),
            covenant: FinalizeCovenant::new(
                proof.name.clone(),
                Height::new(1),
                false,
                Height::new(0),
                0,
                BlockHash::new([0x55; 32]),
            )
            .expect("finalize covenant")
            .to_covenant()
            .expect("canonical covenant"),
        };
        proof
            .sign(&coin, &signing_key)
            .expect("signed Shakedex proof");
        let mut listing = FixedPriceListing {
            proof,
            created_at: 1_800_000_100,
            expires_at: 1_800_003_700,
            sequence,
            signature: None,
        };
        listing
            .sign(&signing_key)
            .expect("signed fixed-price listing");
        (listing, coin, signing_key)
    }

    #[cfg(unix)]
    struct TestWalletDirectory(PathBuf);

    #[cfg(unix)]
    impl Drop for TestWalletDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn encrypted_board_restart(board: &NameMarketBoard) -> NameMarketBoard {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let parent = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = parent.join(format!(
            "hns-wallet-shakedex-board-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("test wallet directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private test wallet directory");
        let _cleanup = TestWalletDirectory(directory.clone());
        let database = directory.join("wallet.sqlite3");
        let mut store =
            WalletStore::create(&database, "shakedex-board-test-passphrase").expect("wallet store");
        let revision = save_name_market_board(&mut store, 0, board, ACTIVE_TIME)
            .expect("initial encrypted board CAS");
        assert_eq!(revision, 1);
        assert!(matches!(
            save_name_market_board(&mut store, 0, board, ACTIVE_TIME + 1),
            Err(ShakedexError::StaleRevision)
        ));
        drop(store);

        let mut reopened = WalletStore::open(&database).expect("reopen wallet store");
        reopened
            .unlock("shakedex-board-test-passphrase")
            .expect("unlock wallet store");
        let stored = load_name_market_board(&reopened).expect("load encrypted board");
        assert_eq!(stored.revision, 1);
        assert_eq!(&stored.board, board);
        stored.board
    }

    #[cfg(not(unix))]
    fn encrypted_board_restart(board: &NameMarketBoard) -> NameMarketBoard {
        board.clone()
    }

    #[test]
    fn canonical_shakedex_fixed_price_shakescape_board_restart_and_tombstone() {
        let (listing, coin, signing_key) = listing_fixture(42);
        let network = listing.network();
        let listing_hash = ObjectHash::new(listing.listing_hash().expect("listing hash"));
        let listing_bytes = listing.encode().expect("listing encoding");
        let verified =
            verify_fixed_price_listing(&listing_bytes, listing_hash, network, ACTIVE_TIME, &coin)
                .expect("fixed-price protocol verification");
        assert_eq!(verified.price_base_units(), 12_345_678);
        assert_eq!(verified.locking_outpoint(), coin.outpoint);
        assert!(verified.lock_descriptor().is_ok());

        assert!(matches!(
            verify_fixed_price_listing(
                &listing_bytes,
                ObjectHash::new([0x99; 32]),
                network,
                ACTIVE_TIME,
                &coin,
            ),
            Err(ShakedexError::InvalidListing)
        ));
        let mut wrong_coin = coin.clone();
        wrong_coin.outpoint.index += 1;
        assert!(matches!(
            verify_fixed_price_listing(
                &listing_bytes,
                listing_hash,
                network,
                ACTIVE_TIME,
                &wrong_coin,
            ),
            Err(ShakedexError::InvalidListing)
        ));
        assert!(matches!(
            verify_fixed_price_listing(
                &listing_bytes,
                listing_hash,
                network,
                listing.expires_at,
                &coin,
            ),
            Err(ShakedexError::InvalidListing)
        ));

        let offer_envelope =
            encode_shakescape_offer(ShakescapeRegistryVersion::V1, 77, verified.authenticated())
                .expect("offer envelope");
        let (request_id, discovered) = decode_shakescape_offer(
            &offer_envelope,
            ShakescapeRegistryVersion::V1,
            listing_hash,
            network,
            ACTIVE_TIME,
            &coin,
        )
        .expect("verified Shakescape offer");
        assert_eq!(request_id, 77);
        let mut wrong_registry_envelope = offer_envelope.clone();
        wrong_registry_envelope[4] = 2;
        assert!(matches!(
            decode_shakescape_offer(
                &wrong_registry_envelope,
                ShakescapeRegistryVersion::V1,
                listing_hash,
                network,
                ACTIVE_TIME,
                &coin,
            ),
            Err(ShakedexError::InvalidShakescapeEnvelope)
        ));

        let mut board = NameMarketBoard::default();
        assert!(board.apply_offer(&discovered).expect("new offer"));
        assert!(!board.apply_offer(&discovered).expect("idempotent offer"));
        assert_eq!(board.active_inventory(ACTIVE_TIME).unwrap(), [listing_hash]);

        let inventory_envelope = encode_shakescape_inventory(
            ShakescapeRegistryVersion::V1,
            78,
            &board.active_inventory(ACTIVE_TIME).unwrap(),
        )
        .expect("inventory envelope");
        assert_eq!(
            decode_shakescape_inventory(&inventory_envelope, ShakescapeRegistryVersion::V1)
                .expect("inventory"),
            (78, vec![listing_hash])
        );
        for request in [
            ShakescapeNameMarketRequest::Inventory,
            ShakescapeNameMarketRequest::Offers(vec![listing_hash]),
            ShakescapeNameMarketRequest::Offer(listing_hash),
        ] {
            let encoded = encode_shakescape_request(ShakescapeRegistryVersion::V1, 79, &request)
                .expect("request envelope");
            assert_eq!(
                decode_shakescape_request(&encoded, ShakescapeRegistryVersion::V1)
                    .expect("request envelope"),
                (79, request)
            );
        }

        let mut cancellation = ListingCancellation::for_listing(
            &listing,
            ACTIVE_TIME + 1,
            listing.expires_at + 600,
            43,
        )
        .expect("cancellation terms");
        cancellation
            .sign(&signing_key)
            .expect("signed cancellation");
        let cancellation_bytes = cancellation.encode().expect("cancellation encoding");
        let verified_cancellation = verify_listing_cancellation(
            &cancellation_bytes,
            discovered.authenticated(),
            network,
            ACTIVE_TIME + 2,
        )
        .expect("verified cancellation");
        let cancellation_envelope = encode_shakescape_cancellation(
            ShakescapeRegistryVersion::V1,
            80,
            &verified_cancellation,
        )
        .expect("cancellation envelope");
        let cancellation_hash = verified_cancellation.cancellation_hash();
        let (authenticated_request_id, authenticated_cancellation) =
            decode_shakescape_authenticated_cancellation(
                &cancellation_envelope,
                ShakescapeRegistryVersion::V1,
                listing_hash,
                cancellation_hash,
            )
            .expect("authenticated cancellation lookup phase");
        assert_eq!(authenticated_request_id, 80);
        assert_eq!(authenticated_cancellation.listing_hash(), listing_hash);
        assert_eq!(
            authenticated_cancellation.cancellation_hash(),
            cancellation_hash
        );
        assert_eq!(authenticated_cancellation.network(), network);
        assert_eq!(authenticated_cancellation.sequence(), 43);
        assert!(matches!(
            decode_shakescape_authenticated_cancellation(
                &cancellation_envelope,
                ShakescapeRegistryVersion::V1,
                ObjectHash::new([0x91; 32]),
                cancellation_hash,
            ),
            Err(ShakedexError::InvalidCancellation)
        ));
        assert!(matches!(
            decode_shakescape_authenticated_cancellation(
                &cancellation_envelope,
                ShakescapeRegistryVersion::V1,
                listing_hash,
                ObjectHash::new([0x92; 32]),
            ),
            Err(ShakedexError::InvalidCancellation)
        ));
        let phase_verified = verify_authenticated_listing_cancellation(
            authenticated_cancellation,
            discovered.authenticated(),
            network,
            ACTIVE_TIME + 2,
        )
        .expect("listing/time-bound cancellation phase");
        assert_eq!(phase_verified.cancellation_hash(), cancellation_hash);
        let mut restarted = encrypted_board_restart(&board);
        restarted.validate().expect("canonical restored board");
        let persisted_offer = restarted.offer(listing_hash).expect("persisted offer");
        let persisted_listing = authenticate_fixed_price_listing(
            &persisted_offer.listing_bytes,
            persisted_offer.listing_hash,
        )
        .expect("restart listing authentication");
        let (request_id, decoded_cancellation) = decode_shakescape_cancellation(
            &cancellation_envelope,
            ShakescapeRegistryVersion::V1,
            &persisted_listing,
            network,
            ACTIVE_TIME + 2,
        )
        .expect("Shakescape cancellation after restart");
        assert_eq!(request_id, 80);
        assert!(
            restarted
                .apply_cancellation(&decoded_cancellation)
                .expect("new tombstone")
        );
        assert!(
            !restarted
                .apply_cancellation(&decoded_cancellation)
                .expect("idempotent tombstone")
        );
        assert!(
            restarted
                .active_inventory(ACTIVE_TIME + 2)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            restarted
                .offer(listing_hash)
                .expect("cancelled offer")
                .status,
            BoardOfferStatus::Cancelled
        );

        let (replayed_listing, _, _) = listing_fixture(43);
        let replayed_bytes = replayed_listing.encode().expect("replayed encoding");
        let replayed = verify_fixed_price_listing(
            &replayed_bytes,
            ObjectHash::new(replayed_listing.listing_hash().unwrap()),
            network,
            ACTIVE_TIME,
            &coin,
        )
        .expect("otherwise valid replay");
        assert!(matches!(
            restarted.apply_offer(&replayed),
            Err(ShakedexError::NameMarketReplay)
        ));

        let (new_listing, _, _) = listing_fixture(44);
        let new_bytes = new_listing.encode().expect("replacement encoding");
        let replacement = verify_fixed_price_listing(
            &new_bytes,
            ObjectHash::new(new_listing.listing_hash().unwrap()),
            network,
            ACTIVE_TIME,
            &coin,
        )
        .expect("newer listing");
        assert!(restarted.apply_offer(&replacement).expect("new sequence"));
        assert_eq!(
            restarted.active_inventory(ACTIVE_TIME).unwrap(),
            [replacement.listing_hash()]
        );
    }
}
