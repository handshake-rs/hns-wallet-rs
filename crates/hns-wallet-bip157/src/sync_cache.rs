//! Authenticated, wallet-owned storage for verified synchronization bytes.
//!
//! A provider must authenticate records and bind them to the exact network,
//! starting checkpoint, filter type and peer requirement. In particular,
//! filter headers may be stored only after the live node has obtained its
//! configured independent-peer agreement. An ordinary untrusted file cache
//! does not satisfy this interface's contract.

use std::fmt::Debug;

use bitcoin::{
    block::Header,
    p2p::message_filter::{CFHeaders, CFilter},
    Network,
};

use crate::HashCheckpoint;

/// Independent record streams, replayed in this order after a restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncCacheKind {
    /// Locally validated Bitcoin block-header batches.
    Headers,
    /// Compact-filter headers accepted by the configured peer quorum.
    FilterHeaders,
    /// Raw filters whose hashes matched those agreed commitments.
    Filters,
}

/// The immutable verification context of one cache namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCacheContext {
    /// Bitcoin network, including its genesis identity.
    pub network: Network,
    /// Honest starting checkpoint supplied by the wallet.
    pub checkpoint: HashCheckpoint,
    /// Number of independent peers required for filter-header admission.
    pub required_peers: u8,
    /// Selected BIP157 filter type.
    pub filter_type: u8,
}

/// A bounded batch of public synchronization bytes, never wallet keys,
/// matched-script flags, spend authority, or a wallet scan checkpoint.
#[derive(Clone, Debug)]
pub enum CachedSyncBatch {
    /// A normally validated block-header response.
    Headers(Vec<Header>),
    /// An exact, already agreed compact-filter-header response.
    FilterHeaders(CFHeaders),
    /// Raw filters; wallet matching runs again on replay.
    Filters(Vec<CFilter>),
}

impl CachedSyncBatch {
    /// Record stream containing this batch.
    pub const fn kind(&self) -> SyncCacheKind {
        match self {
            Self::Headers(_) => SyncCacheKind::Headers,
            Self::FilterHeaders(_) => SyncCacheKind::FilterHeaders,
            Self::Filters(_) => SyncCacheKind::Filters,
        }
    }
}

/// Authenticated cache boundary implemented by the owning product.
///
/// Appends must be atomic: after process loss a reader sees either the old
/// stream or the whole new record. Records must remain contiguous, and a
/// failed authentication or context mismatch must be returned as an error,
/// never treated as an empty cache. Reads and appends are bounded synchronous
/// store operations; the node yields between replay batches.
pub trait VerifiedSyncCache: Debug + Send + Sync {
    /// Exact context authenticated by the provider's namespace and records.
    fn context(&self) -> SyncCacheContext;
    /// Read one record; `None` is exclusively the end of this stream.
    fn read(&self, kind: SyncCacheKind, index: u32) -> Result<Option<CachedSyncBatch>, String>;
    /// Atomically append a batch already accepted by the live node.
    fn append(&self, batch: &CachedSyncBatch) -> Result<(), String>;
}
