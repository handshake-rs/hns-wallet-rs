//! Restartable public synchronization evidence, authenticated by WalletStore.
//! The cache contains no wallet-match decisions and never changes the birthday.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use bip157::sync_cache::{CachedSyncBatch, SyncCacheContext, SyncCacheKind, VerifiedSyncCache};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message_filter::CFilter;
use hns_wallet_store::{EntityBatchSave, EntityKind, SharedWalletStore, WalletStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::BitcoinWalletError;

const VERSION: u16 = 1;
const CHUNK_BYTES: usize = 512 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_STREAM_BATCHES: u32 = 65_536;
const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DOMAIN: &[u8] = b"hns-wallet-rs/verified-bitcoin-sync-cache/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum CacheRecord {
    Head {
        version: u16,
        namespace: [u8; 32],
        counts: [u32; 3],
        bytes: u64,
    },
    Batch {
        namespace: [u8; 32],
        stream: u8,
        index: u32,
        bytes: u32,
        digest: [u8; 32],
    },
    Chunk {
        namespace: [u8; 32],
        stream: u8,
        index: u32,
        chunk: u32,
        data: String,
    },
}

/// The starting checkpoint and peer quorum are part of the authenticated
/// namespace. A different account, network, birthday or quorum cannot reuse
/// evidence admitted under another verification context.
pub(crate) struct EncryptedSyncCache {
    store: SharedWalletStore,
    context: SyncCacheContext,
    namespace: [u8; 32],
}

impl fmt::Debug for EncryptedSyncCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSyncCache")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl EncryptedSyncCache {
    pub(crate) fn new(
        store: SharedWalletStore,
        account_id: &[u8],
        context: SyncCacheContext,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update((account_id.len() as u64).to_le_bytes());
        hash.update(account_id);
        hash.update(context.network.to_string().as_bytes());
        hash.update(context.checkpoint.height.to_le_bytes());
        hash.update(serialize(&context.checkpoint.hash));
        hash.update([context.required_peers, context.filter_type]);
        Self {
            store,
            context,
            namespace: hash.finalize().into(),
        }
    }

    fn id(&self, tag: u8, stream: u8, index: u32, chunk: u32) -> Vec<u8> {
        let mut id = self.namespace.to_vec();
        id.extend([tag, stream]);
        id.extend(index.to_le_bytes());
        id.extend(chunk.to_le_bytes());
        id
    }

    fn head(&self, store: &WalletStore) -> Result<(u64, [u32; 3], u64), BitcoinWalletError> {
        let Some(record) = store.bitcoin_header::<CacheRecord>(&self.id(0, 0, 0, 0))? else {
            if !store
                .list_entities_by_id_prefix::<CacheRecord>(
                    EntityKind::BitcoinHeader,
                    &self.namespace,
                    1,
                )?
                .is_empty()
            {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
            return Ok((0, [0; 3], 0));
        };
        match record.value {
            CacheRecord::Head {
                version,
                namespace,
                counts,
                bytes,
            } if version == VERSION
                && namespace == self.namespace
                && counts.iter().all(|count| *count <= MAX_STREAM_BATCHES)
                && bytes <= MAX_CACHE_BYTES =>
            {
                Ok((record.revision, counts, bytes))
            }
            _ => Err(BitcoinWalletError::CorruptRuntimeState),
        }
    }

    fn read_batch(
        &self,
        kind: SyncCacheKind,
        index: u32,
    ) -> Result<Option<CachedSyncBatch>, BitcoinWalletError> {
        self.store.try_with_store(|store| {
            let stream = stream(kind);
            let (_, counts, _) = self.head(store)?;
            if index >= counts[usize::from(stream)] {
                return Ok(None);
            }
            let record = store
                .bitcoin_header::<CacheRecord>(&self.id(1, stream, index, 0))?
                .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
            let (bytes, digest) = match record.value {
                CacheRecord::Batch {
                    namespace,
                    stream: saved_stream,
                    index: saved_index,
                    bytes,
                    digest,
                } if namespace == self.namespace
                    && saved_stream == stream
                    && saved_index == index
                    && bytes > 0
                    && bytes as usize <= MAX_BATCH_BYTES =>
                {
                    (bytes as usize, digest)
                }
                _ => return Err(BitcoinWalletError::CorruptRuntimeState),
            };
            let mut payload = Vec::with_capacity(bytes);
            for chunk in 0..bytes.div_ceil(CHUNK_BYTES) as u32 {
                let record = store
                    .bitcoin_header::<CacheRecord>(&self.id(2, stream, index, chunk))?
                    .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
                let data = match record.value {
                    CacheRecord::Chunk {
                        namespace,
                        stream: saved_stream,
                        index: saved_index,
                        chunk: saved_chunk,
                        data,
                    } if namespace == self.namespace
                        && saved_stream == stream
                        && saved_index == index
                        && saved_chunk == chunk
                        && data.len() <= CHUNK_BYTES.div_ceil(3) * 4 =>
                    {
                        data
                    }
                    _ => return Err(BitcoinWalletError::CorruptRuntimeState),
                };
                let decoded = STANDARD
                    .decode(data)
                    .map_err(|_| BitcoinWalletError::CorruptRuntimeState)?;
                let expected = (bytes - payload.len()).min(CHUNK_BYTES);
                if decoded.len() != expected {
                    return Err(BitcoinWalletError::CorruptRuntimeState);
                }
                payload.extend(decoded);
            }
            if <[u8; 32]>::from(Sha256::digest(&payload)) != digest {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
            let batch = match kind {
                SyncCacheKind::Headers => CachedSyncBatch::Headers(
                    deserialize(&payload).map_err(|_| BitcoinWalletError::CorruptRuntimeState)?,
                ),
                SyncCacheKind::FilterHeaders => CachedSyncBatch::FilterHeaders(
                    deserialize(&payload).map_err(|_| BitcoinWalletError::CorruptRuntimeState)?,
                ),
                SyncCacheKind::Filters => CachedSyncBatch::Filters(decode_filters(&payload)?),
            };
            validate_batch(&batch)?;
            Ok(Some(batch))
        })
    }

    fn append_batch(&self, batch: &CachedSyncBatch) -> Result<(), BitcoinWalletError> {
        validate_batch(batch)?;
        let payload = match batch {
            CachedSyncBatch::Headers(value) => serialize(value),
            CachedSyncBatch::FilterHeaders(value) => serialize(value),
            CachedSyncBatch::Filters(value) => {
                let mut bytes = (value.len() as u32).to_le_bytes().to_vec();
                for filter in value {
                    let packet = serialize(filter);
                    bytes.extend((packet.len() as u32).to_le_bytes());
                    bytes.extend(packet);
                }
                bytes
            }
        };
        if payload.len() > MAX_BATCH_BYTES {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
        let stream = stream(batch.kind());
        self.store.try_with_store_mut(|store| {
            let (revision, mut counts, total_bytes) = self.head(store)?;
            let index = counts[usize::from(stream)];
            if index >= MAX_STREAM_BATCHES {
                return Err(BitcoinWalletError::CorruptRuntimeState);
            }
            let total_bytes = total_bytes
                .checked_add(payload.len() as u64)
                .filter(|bytes| *bytes <= MAX_CACHE_BYTES)
                .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
            counts[usize::from(stream)] += 1;
            // One SQLite transaction advances the head and creates every
            // immutable chunk. A killed process can expose neither a gap nor
            // a head pointing at a partially persisted response.
            let mut saves = vec![
                EntityBatchSave {
                    id: self.id(0, 0, 0, 0),
                    expected_revision: revision,
                    value: CacheRecord::Head {
                        version: VERSION,
                        namespace: self.namespace,
                        counts,
                        bytes: total_bytes,
                    },
                    updated_at_unix: 0,
                },
                EntityBatchSave {
                    id: self.id(1, stream, index, 0),
                    expected_revision: 0,
                    value: CacheRecord::Batch {
                        namespace: self.namespace,
                        stream,
                        index,
                        bytes: payload.len() as u32,
                        digest: Sha256::digest(&payload).into(),
                    },
                    updated_at_unix: 0,
                },
            ];
            for (chunk, data) in payload.chunks(CHUNK_BYTES).enumerate() {
                saves.push(EntityBatchSave {
                    id: self.id(2, stream, index, chunk as u32),
                    expected_revision: 0,
                    value: CacheRecord::Chunk {
                        namespace: self.namespace,
                        stream,
                        index,
                        chunk: chunk as u32,
                        data: STANDARD.encode(data),
                    },
                    updated_at_unix: 0,
                });
            }
            store.apply_entity_batch(EntityKind::BitcoinHeader, &saves, &[])?;
            Ok(())
        })
    }
}

impl VerifiedSyncCache for EncryptedSyncCache {
    fn context(&self) -> SyncCacheContext {
        self.context
    }
    fn read(&self, kind: SyncCacheKind, index: u32) -> Result<Option<CachedSyncBatch>, String> {
        self.read_batch(kind, index)
            .map_err(|error| error.to_string())
    }
    fn append(&self, batch: &CachedSyncBatch) -> Result<(), String> {
        self.append_batch(batch).map_err(|error| error.to_string())
    }
}

fn stream(kind: SyncCacheKind) -> u8 {
    match kind {
        SyncCacheKind::Headers => 0,
        SyncCacheKind::FilterHeaders => 1,
        SyncCacheKind::Filters => 2,
    }
}

fn decode_filters(mut bytes: &[u8]) -> Result<Vec<CFilter>, BitcoinWalletError> {
    fn length(bytes: &mut &[u8]) -> Result<usize, BitcoinWalletError> {
        let prefix = bytes
            .get(..4)
            .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
        let value = u32::from_le_bytes(
            prefix
                .try_into()
                .map_err(|_| BitcoinWalletError::CorruptRuntimeState)?,
        ) as usize;
        *bytes = &bytes[4..];
        Ok(value)
    }
    let count = length(&mut bytes)?;
    if count == 0 || count > 64 {
        return Err(BitcoinWalletError::CorruptRuntimeState);
    }
    let mut filters = Vec::with_capacity(count);
    for _ in 0..count {
        let len = length(&mut bytes)?;
        let packet = bytes
            .get(..len)
            .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
        filters.push(deserialize(packet).map_err(|_| BitcoinWalletError::CorruptRuntimeState)?);
        bytes = &bytes[len..];
    }
    if !bytes.is_empty() {
        return Err(BitcoinWalletError::CorruptRuntimeState);
    }
    Ok(filters)
}

fn validate_batch(batch: &CachedSyncBatch) -> Result<(), BitcoinWalletError> {
    let valid = match batch {
        CachedSyncBatch::Headers(headers) => !headers.is_empty() && headers.len() <= 2_000,
        CachedSyncBatch::FilterHeaders(headers) => {
            !headers.filter_hashes.is_empty() && headers.filter_hashes.len() <= 2_000
        }
        CachedSyncBatch::Filters(filters) => {
            !filters.is_empty()
                && filters.len() <= 64
                && filters
                    .iter()
                    .try_fold(4_usize, |total, filter| {
                        total.checked_add(filter.filter.len())?.checked_add(64)
                    })
                    .is_some_and(|bytes| bytes <= MAX_BATCH_BYTES)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(BitcoinWalletError::CorruptRuntimeState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip157::HashCheckpoint;
    use bitcoin::{Network, constants::genesis_block};

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn context() -> SyncCacheContext {
        SyncCacheContext {
            network: Network::Regtest,
            checkpoint: HashCheckpoint::from_genesis(Network::Regtest),
            required_peers: 2,
            filter_type: 0,
        }
    }

    fn open(path: &std::path::Path) -> SharedWalletStore {
        let mut store = WalletStore::open(path).unwrap();
        store.unlock("cache test passphrase").unwrap();
        SharedWalletStore::new(store)
    }

    #[test]
    fn partial_transport_cache_survives_closed_database_and_separates_contexts() {
        let dir = private_dir();
        let path = dir.path().join("wallet.sqlite");
        let store =
            SharedWalletStore::new(WalletStore::create(&path, "cache test passphrase").unwrap());
        let cache = EncryptedSyncCache::new(store, b"account", context());
        let filter = CFilter {
            filter_type: 0,
            block_hash: context().checkpoint.hash,
            filter: vec![7; CHUNK_BYTES + 37],
        };
        cache
            .append(&CachedSyncBatch::Headers(vec![
                genesis_block(Network::Regtest).header,
            ]))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(vec![filter.clone()]))
            .unwrap();
        drop(cache);
        let store = open(&path);
        let restored = EncryptedSyncCache::new(store.clone(), b"account", context());
        assert!(
            matches!(restored.read(SyncCacheKind::Headers, 0).unwrap(), Some(CachedSyncBatch::Headers(headers)) if headers == vec![genesis_block(Network::Regtest).header])
        );
        assert!(
            matches!(restored.read(SyncCacheKind::Filters, 0).unwrap(), Some(CachedSyncBatch::Filters(filters)) if filters == vec![filter])
        );
        assert!(restored.read(SyncCacheKind::Filters, 1).unwrap().is_none());
        let mut other_context = context();
        other_context.required_peers = 3;
        assert!(
            EncryptedSyncCache::new(store.clone(), b"account", other_context)
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        other_context = context();
        other_context.checkpoint.height += 1;
        assert!(
            EncryptedSyncCache::new(store.clone(), b"account", other_context)
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        other_context = context();
        other_context.network = Network::Bitcoin;
        assert!(
            EncryptedSyncCache::new(store.clone(), b"account", other_context)
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            EncryptedSyncCache::new(store.clone(), b"other account", context())
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        store.lock().unwrap();
        assert!(restored.read(SyncCacheKind::Headers, 0).is_err());
    }

    #[test]
    fn missing_or_rebound_record_is_an_error_and_is_preserved() {
        let dir = private_dir();
        let store = SharedWalletStore::new(
            WalletStore::create(dir.path().join("wallet.sqlite"), "cache test passphrase").unwrap(),
        );
        let cache = EncryptedSyncCache::new(store.clone(), b"account", context());
        cache
            .append(&CachedSyncBatch::Headers(vec![
                genesis_block(Network::Regtest).header,
            ]))
            .unwrap();
        let id = cache.id(2, 0, 0, 0);
        store
            .with_store_mut(|store| store.delete_bitcoin_header(&id, 1))
            .unwrap();
        assert!(cache.read(SyncCacheKind::Headers, 0).is_err());
        assert!(
            cache
                .append(&CachedSyncBatch::Headers(vec![
                    genesis_block(Network::Regtest).header
                ]))
                .is_ok()
        );
        let id = cache.id(1, 0, 1, 0);
        let bad = CacheRecord::Batch {
            namespace: [0; 32],
            stream: 0,
            index: 1,
            bytes: 81,
            digest: [0; 32],
        };
        store
            .with_store_mut(|store| store.save_bitcoin_header(&id, 1, &bad, 0))
            .unwrap();
        assert!(cache.read(SyncCacheKind::Headers, 1).is_err());
        assert!(
            store
                .with_store(|store| store.bitcoin_header::<CacheRecord>(&id))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn invalid_or_overlarge_batch_cannot_advance_head() {
        let dir = private_dir();
        let store = SharedWalletStore::new(
            WalletStore::create(dir.path().join("wallet.sqlite"), "cache test passphrase").unwrap(),
        );
        let cache = EncryptedSyncCache::new(store, b"account", context());
        assert!(cache.append(&CachedSyncBatch::Headers(vec![])).is_err());
        assert!(
            cache
                .append(&CachedSyncBatch::Filters(vec![CFilter {
                    filter_type: 0,
                    block_hash: context().checkpoint.hash,
                    filter: vec![0; MAX_BATCH_BYTES]
                }]))
                .is_err()
        );
        assert!(cache.read(SyncCacheKind::Headers, 0).unwrap().is_none());
        assert!(cache.read(SyncCacheKind::Filters, 0).unwrap().is_none());
    }
}
