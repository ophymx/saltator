//! Raft log storage and state machine for the metadata group, backed by the
//! node-local KV engine (Meta keyspace, shard 0).
//!
//! M0 note: KV calls are made inline from async context. RocksDB point ops
//! are microsecond-scale; revisit with `spawn_blocking`/io offload when the
//! generic shard runtime lands (M1, `saltator-shard`).

// StorageError is openraft's type and fixed by the trait signatures.
#![allow(clippy::result_large_err)]

use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine, Snapshot,
};
use openraft::{
    Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};

use saltator_store::{key, table_bounds, Keyspace, KvEngine, WriteBatch};

use crate::types::{MetaCommand, MetaResponse, NodeId, TypeConfig};

const META_SHARD: u16 = 0;
const T_LOG: u8 = 0;
const T_RAFT: u8 = 1;
const T_SM: u8 = 2;
const T_SM_META: u8 = 3;

const K_VOTE: &[u8] = b"vote";
const K_COMMITTED: &[u8] = b"committed";
const K_LAST_PURGED: &[u8] = b"last_purged";
const K_LAST_APPLIED: &[u8] = b"last_applied";
const K_MEMBERSHIP: &[u8] = b"membership";
const K_SNAPSHOT: &[u8] = b"snapshot";
const K_SNAPSHOT_SEQ: &[u8] = b"snapshot_seq";

fn log_key(index: u64) -> Vec<u8> {
    key(Keyspace::Meta, META_SHARD, T_LOG, &index.to_be_bytes())
}

fn raft_key(k: &[u8]) -> Vec<u8> {
    key(Keyspace::Meta, META_SHARD, T_RAFT, k)
}

fn sm_key(k: &[u8]) -> Vec<u8> {
    key(Keyspace::Meta, META_SHARD, T_SM, k)
}

fn sm_meta_key(k: &[u8]) -> Vec<u8> {
    key(Keyspace::Meta, META_SHARD, T_SM_META, k)
}

fn read_err(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read(&e).into()
}

fn write_err(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write(&e).into()
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, StorageError<NodeId>> {
    postcard::to_stdvec(v).map_err(write_err)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError<NodeId>> {
    postcard::from_bytes(bytes).map_err(read_err)
}

/// Serialized full-state snapshot (postcard, `CODEC_VERSION`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotContent {
    last_applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, crate::types::Node>,
    kv: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, crate::types::Node>,
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Log storage
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MetaLogStore {
    engine: Arc<dyn KvEngine>,
}

impl MetaLogStore {
    pub fn new(engine: Arc<dyn KvEngine>) -> Self {
        Self { engine }
    }

    fn get_meta<T: for<'de> Deserialize<'de>>(
        &self,
        k: &[u8],
    ) -> Result<Option<T>, StorageError<NodeId>> {
        match self.engine.get(&raft_key(k)).map_err(read_err)? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn last_log_id(&self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        let (start, end) = table_bounds(Keyspace::Meta, META_SHARD, T_LOG);
        match self.engine.last_in_range(&start, &end).map_err(read_err)? {
            Some((_, v)) => {
                let entry: Entry<TypeConfig> = decode(&v)?;
                Ok(Some(entry.log_id))
            }
            None => Ok(None),
        }
    }
}

impl RaftLogReader<TypeConfig> for MetaLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&i) => i,
            std::ops::Bound::Excluded(&i) => i + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&i) => i + 1,
            std::ops::Bound::Excluded(&i) => i,
            std::ops::Bound::Unbounded => u64::MAX,
        };
        let end_key = if end == u64::MAX {
            table_bounds(Keyspace::Meta, META_SHARD, T_LOG).1
        } else {
            log_key(end)
        };
        let raw = self
            .engine
            .range(&log_key(start), &end_key)
            .map_err(read_err)?;
        raw.into_iter().map(|(_, v)| decode(&v)).collect()
    }
}

impl RaftLogStorage<TypeConfig> for MetaLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> = self.get_meta(K_LAST_PURGED)?.flatten();
        let last = self.last_log_id()?.or(last_purged);
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.engine
            .put(&raft_key(K_VOTE), &encode(vote)?)
            .map_err(write_err)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        self.get_meta(K_VOTE)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.engine
            .put(&raft_key(K_COMMITTED), &encode(&committed)?)
            .map_err(write_err)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.get_meta(K_COMMITTED)?.flatten())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let mut wb = WriteBatch::new();
        for entry in entries {
            wb.put(log_key(entry.log_id.index), encode(&entry)?);
        }
        let res = self.engine.write_batch(wb).map_err(write_err);
        // write_batch is fsynced-on-return, so completion is accurate here.
        callback.log_io_completed(
            res.as_ref()
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
        );
        res
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Delete everything from log_id.index (inclusive) to the end.
        let (_, end) = table_bounds(Keyspace::Meta, META_SHARD, T_LOG);
        let mut wb = WriteBatch::new();
        wb.delete_range(log_key(log_id.index), end);
        self.engine.write_batch(wb).map_err(write_err)
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Delete everything up to and including log_id.index.
        let (start, _) = table_bounds(Keyspace::Meta, META_SHARD, T_LOG);
        let mut wb = WriteBatch::new();
        wb.put(raft_key(K_LAST_PURGED), encode(&Some(log_id))?);
        wb.delete_range(start, log_key(log_id.index + 1));
        self.engine.write_batch(wb).map_err(write_err)
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MetaStateMachine {
    engine: Arc<dyn KvEngine>,
}

impl MetaStateMachine {
    pub fn new(engine: Arc<dyn KvEngine>) -> Self {
        Self { engine }
    }

    /// Read a key from the applied state (used by the read path after a
    /// linearizability check at the Raft layer).
    pub fn get(&self, k: &str) -> Result<Option<Vec<u8>>, StorageError<NodeId>> {
        self.engine.get(&sm_key(k.as_bytes())).map_err(read_err)
    }

    pub fn last_applied(&self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        match self
            .engine
            .get(&sm_meta_key(K_LAST_APPLIED))
            .map_err(read_err)?
        {
            Some(b) => decode(&b),
            None => Ok(None),
        }
    }

    fn membership(
        &self,
    ) -> Result<StoredMembership<NodeId, crate::types::Node>, StorageError<NodeId>> {
        match self
            .engine
            .get(&sm_meta_key(K_MEMBERSHIP))
            .map_err(read_err)?
        {
            Some(b) => decode(&b),
            None => Ok(StoredMembership::default()),
        }
    }

    fn next_snapshot_seq(&self) -> Result<u64, StorageError<NodeId>> {
        let seq = match self
            .engine
            .get(&sm_meta_key(K_SNAPSHOT_SEQ))
            .map_err(read_err)?
        {
            Some(b) => decode::<u64>(&b)? + 1,
            None => 1,
        };
        self.engine
            .put(&sm_meta_key(K_SNAPSHOT_SEQ), &encode(&seq)?)
            .map_err(write_err)?;
        Ok(seq)
    }
}

impl RaftSnapshotBuilder<TypeConfig> for MetaStateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let last_applied = self.last_applied()?;
        let membership = self.membership()?;

        let (start, end) = table_bounds(Keyspace::Meta, META_SHARD, T_SM);
        let kv: Vec<(Vec<u8>, Vec<u8>)> = self
            .engine
            .range(&start, &end)
            .map_err(read_err)?
            .into_iter()
            // strip the storage prefix; snapshot carries logical keys
            .map(|(k, v)| (k[4..].to_vec(), v))
            .collect();

        let content = SnapshotContent {
            last_applied,
            membership: membership.clone(),
            kv,
        };
        let data = encode(&content)?;

        let seq = self.next_snapshot_seq()?;
        let snapshot_id = match last_applied {
            Some(l) => format!("{}-{}-{}", l.leader_id, l.index, seq),
            None => format!("none-{seq}"),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership: membership,
            snapshot_id,
        };

        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        self.engine
            .put(&sm_meta_key(K_SNAPSHOT), &encode(&stored)?)
            .map_err(write_err)?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for MetaStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, crate::types::Node>,
        ),
        StorageError<NodeId>,
    > {
        Ok((self.last_applied()?, self.membership()?))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<MetaResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let mut responses = Vec::new();
        let mut wb = WriteBatch::new();
        let mut last: Option<LogId<NodeId>> = None;

        for entry in entries {
            last = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(MetaResponse { previous: None }),
                EntryPayload::Normal(cmd) => {
                    let previous = match cmd {
                        MetaCommand::Set { key: k, value } => {
                            let prev = self.get(&k)?;
                            wb.put(sm_key(k.as_bytes()), value);
                            prev
                        }
                        MetaCommand::Delete { key: k } => {
                            let prev = self.get(&k)?;
                            wb.delete(sm_key(k.as_bytes()));
                            prev
                        }
                    };
                    responses.push(MetaResponse { previous });
                }
                EntryPayload::Membership(m) => {
                    let stored = StoredMembership::new(Some(entry.log_id), m);
                    wb.put(sm_meta_key(K_MEMBERSHIP), encode(&stored)?);
                    responses.push(MetaResponse { previous: None });
                }
            }
        }

        if let Some(l) = last {
            wb.put(sm_meta_key(K_LAST_APPLIED), encode(&Some(l))?);
        }
        // Data + last_applied land in ONE batch: apply is atomic per call.
        self.engine.write_batch(wb).map_err(write_err)?;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, crate::types::Node>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let content: SnapshotContent = decode(&data)?;

        let (start, end) = table_bounds(Keyspace::Meta, META_SHARD, T_SM);
        let mut wb = WriteBatch::new();
        wb.delete_range(start, end);
        for (k, v) in content.kv {
            wb.put(sm_key(&k), v);
        }
        wb.put(sm_meta_key(K_LAST_APPLIED), encode(&meta.last_log_id)?);
        wb.put(sm_meta_key(K_MEMBERSHIP), encode(&meta.last_membership)?);
        wb.put(
            sm_meta_key(K_SNAPSHOT),
            encode(&StoredSnapshot {
                meta: meta.clone(),
                data,
            })?,
        );
        self.engine.write_batch(wb).map_err(write_err)
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        match self
            .engine
            .get(&sm_meta_key(K_SNAPSHOT))
            .map_err(read_err)?
        {
            Some(b) => {
                let stored: StoredSnapshot = decode(&b)?;
                Ok(Some(Snapshot {
                    meta: stored.meta,
                    snapshot: Box::new(Cursor::new(stored.data)),
                }))
            }
            None => Ok(None),
        }
    }
}
