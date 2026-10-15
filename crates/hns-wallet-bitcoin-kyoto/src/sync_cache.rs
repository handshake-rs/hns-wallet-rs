//! Restartable public synchronization evidence, authenticated by WalletStore.
//! The cache contains no wallet-match decisions and never changes the birthday.

use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bip157::sync_cache::{CachedSyncBatch, SyncCacheContext, SyncCacheKind, VerifiedSyncCache};
use bitcoin::consensus::{deserialize, deserialize_partial, encode::VarInt, serialize};
use bitcoin::p2p::message_filter::CFilter;
use hns_wallet_store::{EntityBatchSave, EntityKind, SharedWalletStore, WalletStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::BitcoinWalletError;

const VERSION: u16 = 1;
const CHUNK_BYTES: usize = 512 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_STREAM_BATCHES: u32 = 65_536;
// Older wallets may already have a large authenticated prefix. Keep it
// readable, but bound new on-device cache growth to a practical size.
const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_NEW_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const DOMAIN: &[u8] = b"hns-wallet-rs/verified-bitcoin-sync-cache/v1";
const RECOVERY_DOMAIN: &[u8] = b"hns-wallet-rs/verified-bitcoin-sync-cache/recovery/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRecoveryRecord {
    base_namespace: [u8; 32],
    epoch: u32,
    prefix_counts: [u32; 3],
}

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
    base_namespace: [u8; 32],
    recovery_id: Vec<u8>,
    epoch: u32,
    prefix_counts: [u32; 3],
    retired: AtomicBool,
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
    ) -> Result<Self, BitcoinWalletError> {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update((account_id.len() as u64).to_le_bytes());
        hash.update(account_id);
        hash.update(context.network.to_string().as_bytes());
        hash.update(context.checkpoint.height.to_le_bytes());
        hash.update(serialize(&context.checkpoint.hash));
        hash.update([context.required_peers, context.filter_type]);
        let base_namespace: [u8; 32] = hash.finalize().into();
        let mut recovery_hash = Sha256::new();
        recovery_hash.update(RECOVERY_DOMAIN);
        recovery_hash.update(base_namespace);
        let recovery_id = recovery_hash.finalize().to_vec();
        let (epoch, prefix_counts) = store.try_with_store(|store| {
            match store.bitcoin_header::<CacheRecoveryRecord>(&recovery_id)? {
                None => Ok((0, [0; 3])),
                Some(record)
                    if record.value.base_namespace == base_namespace
                        && record.value.epoch > 0
                        && record
                            .value
                            .prefix_counts
                            .iter()
                            .all(|count| *count <= MAX_STREAM_BATCHES) =>
                {
                    Ok((record.value.epoch, record.value.prefix_counts))
                }
                Some(_) => Err(BitcoinWalletError::CorruptRuntimeState),
            }
        })?;
        let namespace = if epoch == 0 {
            base_namespace
        } else {
            let mut hash = Sha256::new();
            hash.update(RECOVERY_DOMAIN);
            hash.update(base_namespace);
            hash.update(epoch.to_le_bytes());
            hash.finalize().into()
        };
        Ok(Self {
            store,
            context,
            namespace,
            base_namespace,
            recovery_id,
            epoch,
            prefix_counts,
            retired: AtomicBool::new(false),
        })
    }

    fn retire_corrupt_epoch(
        &self,
        kind: SyncCacheKind,
        index: u32,
    ) -> Result<(), BitcoinWalletError> {
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        self.store.try_with_store_mut(|store| {
            let saved = store.bitcoin_header::<CacheRecoveryRecord>(&self.recovery_id)?;
            let revision = saved.as_ref().map_or(0, |record| record.revision);
            let current_epoch = match saved {
                None => 0,
                Some(record) if record.value.base_namespace == self.base_namespace => {
                    record.value.epoch
                }
                Some(_) => return Err(BitcoinWalletError::CorruptRuntimeState),
            };
            if current_epoch == self.epoch {
                // The original namespace remains immutable evidence. Keep its
                // verified prefix and put replacement batches in a new suffix
                // namespace, so one damaged tail does not force a full scan.
                let mut prefix_counts = if self.epoch == 0 {
                    match self.head(store) {
                        Ok((_, counts, _)) => counts,
                        Err(BitcoinWalletError::CorruptRuntimeState) => [0; 3],
                        Err(error) => return Err(error),
                    }
                } else {
                    self.prefix_counts
                };
                let affected_stream = usize::from(stream(kind));
                if index < prefix_counts[affected_stream] {
                    prefix_counts[affected_stream] = index;
                    // Later streams depend on commitments in earlier streams.
                    // If an earlier stream was damaged, replay them from peers.
                    for count in &mut prefix_counts[affected_stream + 1..] {
                        *count = 0;
                    }
                }
                let next_epoch = current_epoch
                    .checked_add(1)
                    .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
                store.save_bitcoin_header(
                    &self.recovery_id,
                    revision,
                    &CacheRecoveryRecord {
                        base_namespace: self.base_namespace,
                        epoch: next_epoch,
                        prefix_counts,
                    },
                    0,
                )?;
            }
            Ok(())
        })?;
        self.retired.store(true, Ordering::Release);
        Ok(())
    }

    fn id_for(namespace: [u8; 32], tag: u8, stream: u8, index: u32, chunk: u32) -> Vec<u8> {
        let mut id = namespace.to_vec();
        id.extend([tag, stream]);
        id.extend(index.to_le_bytes());
        id.extend(chunk.to_le_bytes());
        id
    }

    fn id(&self, tag: u8, stream: u8, index: u32, chunk: u32) -> Vec<u8> {
        Self::id_for(self.namespace, tag, stream, index, chunk)
    }

    fn head(&self, store: &WalletStore) -> Result<(u64, [u32; 3], u64), BitcoinWalletError> {
        self.head_for(store, self.namespace)
    }

    fn head_for(
        &self,
        store: &WalletStore,
        namespace: [u8; 32],
    ) -> Result<(u64, [u32; 3], u64), BitcoinWalletError> {
        let Some(record) =
            store.bitcoin_header::<CacheRecord>(&Self::id_for(namespace, 0, 0, 0, 0))?
        else {
            if !store
                .list_entities_by_id_prefix::<CacheRecord>(
                    EntityKind::BitcoinHeader,
                    &namespace,
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
                namespace: saved_namespace,
                counts,
                bytes,
            } if version == VERSION
                && saved_namespace == namespace
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
            let prefix = self.prefix_counts[usize::from(stream)];
            let (namespace, local_index) = if index < prefix {
                (self.base_namespace, index)
            } else {
                (self.namespace, index - prefix)
            };
            let (_, counts, _) = self.head_for(store, namespace)?;
            if local_index >= counts[usize::from(stream)] {
                return Ok(None);
            }
            let record = store
                .bitcoin_header::<CacheRecord>(&Self::id_for(namespace, 1, stream, local_index, 0))?
                .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
            let (bytes, digest) = match record.value {
                CacheRecord::Batch {
                    namespace: saved_namespace,
                    stream: saved_stream,
                    index: saved_index,
                    bytes,
                    digest,
                } if saved_namespace == namespace
                    && saved_stream == stream
                    && saved_index == local_index
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
                    .bitcoin_header::<CacheRecord>(&Self::id_for(
                        namespace,
                        2,
                        stream,
                        local_index,
                        chunk,
                    ))?
                    .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
                let data = match record.value {
                    CacheRecord::Chunk {
                        namespace: saved_namespace,
                        stream: saved_stream,
                        index: saved_index,
                        chunk: saved_chunk,
                        data,
                    } if saved_namespace == namespace
                        && saved_stream == stream
                        && saved_index == local_index
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
        if self.retired.load(Ordering::Acquire) {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
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
            let Some(next_total_bytes) = total_bytes
                .checked_add(payload.len() as u64)
                .filter(|bytes| *bytes <= MAX_NEW_CACHE_BYTES)
            else {
                // The cache is optional transport evidence. Once its bounded
                // prefix is full, the live node still verifies the remaining
                // responses and can resume from that prefix after a restart.
                return Ok(());
            };
            let index = counts[usize::from(stream)];
            if index >= MAX_STREAM_BATCHES {
                return Ok(());
            }
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
                        bytes: next_total_bytes,
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
        match self.read_batch(kind, index) {
            Err(BitcoinWalletError::CorruptRuntimeState) => {
                self.retire_corrupt_epoch(kind, index)
                    .map_err(|error| format!("corrupt cache could not be retired: {error}"))?;
                Err(BitcoinWalletError::CorruptRuntimeState.to_string())
            }
            result => result.map_err(|error| error.to_string()),
        }
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
        // CFilter ends with a length-prefixed byte vector. The consensus
        // decoder allocates from that declared length before discovering that
        // a truncated packet has no such bytes. Validate it against the
        // authenticated packet boundary first, even for a small cache batch.
        let encoded_filter = packet
            .get(33..)
            .ok_or(BitcoinWalletError::CorruptRuntimeState)?;
        let (VarInt(filter_len), prefix_len) = deserialize_partial(encoded_filter)
            .map_err(|_| BitcoinWalletError::CorruptRuntimeState)?;
        let filter_len =
            usize::try_from(filter_len).map_err(|_| BitcoinWalletError::CorruptRuntimeState)?;
        if filter_len != encoded_filter.len().saturating_sub(prefix_len) {
            return Err(BitcoinWalletError::CorruptRuntimeState);
        }
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
        let cache = EncryptedSyncCache::new(store, b"account", context()).unwrap();
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
        let restored = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
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
                .unwrap()
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        other_context = context();
        other_context.checkpoint.height += 1;
        assert!(
            EncryptedSyncCache::new(store.clone(), b"account", other_context)
                .unwrap()
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        other_context = context();
        other_context.network = Network::Bitcoin;
        assert!(
            EncryptedSyncCache::new(store.clone(), b"account", other_context)
                .unwrap()
                .read(SyncCacheKind::Headers, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            EncryptedSyncCache::new(store.clone(), b"other account", context())
                .unwrap()
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
        let cache = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        cache
            .append(&CachedSyncBatch::Headers(vec![
                genesis_block(Network::Regtest).header,
            ]))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(vec![CFilter {
                filter_type: 0,
                block_hash: context().checkpoint.hash,
                filter: vec![1, 2, 3],
            }]))
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
                .is_err()
        );
        let rebuilt = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        assert!(rebuilt.read(SyncCacheKind::Headers, 0).unwrap().is_none());
        assert!(rebuilt.read(SyncCacheKind::Filters, 0).unwrap().is_none());
        rebuilt
            .append(&CachedSyncBatch::Headers(vec![
                genesis_block(Network::Regtest).header,
            ]))
            .unwrap();
        let id = rebuilt.id(1, 0, 0, 0);
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
        assert!(rebuilt.read(SyncCacheKind::Headers, 0).is_err());
        let again = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        assert!(again.read(SyncCacheKind::Headers, 0).unwrap().is_none());
        assert!(
            store
                .with_store(|store| store.bitcoin_header::<CacheRecord>(&id))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn corrupt_filter_tail_keeps_verified_prefix_for_replay() {
        let dir = private_dir();
        let path = dir.path().join("wallet.sqlite");
        let store =
            SharedWalletStore::new(WalletStore::create(&path, "cache test passphrase").unwrap());
        let cache = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        let first = CFilter {
            filter_type: 0,
            block_hash: context().checkpoint.hash,
            filter: vec![1, 2, 3],
        };
        let second = CFilter {
            filter_type: 0,
            block_hash: context().checkpoint.hash,
            filter: vec![4, 5, 6],
        };
        cache
            .append(&CachedSyncBatch::Filters(vec![first.clone()]))
            .unwrap();
        cache
            .append(&CachedSyncBatch::Filters(vec![second.clone()]))
            .unwrap();
        let bad_id = cache.id(1, 2, 1, 0);
        store
            .with_store_mut(|store| {
                store.save_bitcoin_header(
                    &bad_id,
                    1,
                    &CacheRecord::Batch {
                        namespace: [0; 32],
                        stream: 2,
                        index: 1,
                        bytes: 81,
                        digest: [0; 32],
                    },
                    0,
                )
            })
            .unwrap();
        assert!(cache.read(SyncCacheKind::Filters, 1).is_err());

        drop(cache);
        drop(store);
        let store = open(&path);
        let rebuilt = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        assert!(
            matches!(rebuilt.read(SyncCacheKind::Filters, 0).unwrap(), Some(CachedSyncBatch::Filters(filters)) if filters == vec![first])
        );
        assert!(rebuilt.read(SyncCacheKind::Filters, 1).unwrap().is_none());
        rebuilt
            .append(&CachedSyncBatch::Filters(vec![second.clone()]))
            .unwrap();
        assert!(
            matches!(rebuilt.read(SyncCacheKind::Filters, 1).unwrap(), Some(CachedSyncBatch::Filters(filters)) if filters == vec![second])
        );
        assert!(
            store
                .with_store(|store| store.bitcoin_header::<CacheRecord>(&bad_id))
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
        let cache = EncryptedSyncCache::new(store, b"account", context()).unwrap();
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

    #[test]
    fn full_legacy_cache_remains_readable_without_blocking_live_filters() {
        let dir = private_dir();
        let store = SharedWalletStore::new(
            WalletStore::create(dir.path().join("wallet.sqlite"), "cache test passphrase").unwrap(),
        );
        let cache = EncryptedSyncCache::new(store.clone(), b"account", context()).unwrap();
        store
            .with_store_mut(|store| {
                store.save_bitcoin_header(
                    &cache.id(0, 0, 0, 0),
                    0,
                    &CacheRecord::Head {
                        version: VERSION,
                        namespace: cache.namespace,
                        counts: [0; 3],
                        bytes: MAX_CACHE_BYTES,
                    },
                    0,
                )
            })
            .unwrap();
        let filter = CachedSyncBatch::Filters(vec![CFilter {
            filter_type: 0,
            block_hash: context().checkpoint.hash,
            filter: vec![1, 2, 3],
        }]);
        cache.append(&filter).unwrap();
        assert!(cache.read(SyncCacheKind::Filters, 0).unwrap().is_none());
        assert_eq!(
            store.try_with_store(|store| cache.head(store)).unwrap().2,
            MAX_CACHE_BYTES
        );
    }

    #[test]
    fn malformed_cached_filter_length_is_rejected_before_allocation() {
        let mut packet = vec![0; 33];
        packet.extend(serialize(&VarInt(u64::MAX)));
        let mut batch = 1_u32.to_le_bytes().to_vec();
        batch.extend((packet.len() as u32).to_le_bytes());
        batch.extend(packet);
        assert!(decode_filters(&batch).is_err());
    }
}
